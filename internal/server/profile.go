package server

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Cong0707/sso/internal/model"
	"github.com/Cong0707/sso/internal/security"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"gorm.io/gorm"
)

func (s *Server) profile(c *gin.Context) {
	user := s.user(c)
	data := publicUser(user)
	data["bindings"] = s.userBindingViews(user.ID)
	c.JSON(http.StatusOK, gin.H{"success": true, "data": data})
}

func (s *Server) updateProfile(c *gin.Context) {
	var input struct {
		DisplayName          *string `json:"display_name"`
		Locale               *string `json:"locale"`
		SecurityEmailEnabled *bool   `json:"security_email_enabled"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		s.serveError(c, http.StatusBadRequest, "请求格式错误")
		return
	}
	user := s.user(c)
	previousLocale := user.Locale
	previousLocaleSource := user.LocaleSource
	updates := make(map[string]any, 3)
	if input.DisplayName != nil {
		displayName := strings.TrimSpace(*input.DisplayName)
		if len(displayName) > 100 {
			s.serveError(c, http.StatusBadRequest, "资料字段格式不正确")
			return
		}
		updates["display_name"] = displayName
		user.DisplayName = displayName
	}
	if input.Locale != nil {
		locale := normalizeProfileLocale(*input.Locale)
		updates["locale"] = locale
		updates["locale_source"] = model.LocaleSourceUser
		user.Locale = locale
		user.LocaleSource = model.LocaleSourceUser
	}
	if input.SecurityEmailEnabled != nil {
		updates["security_email_enabled"] = *input.SecurityEmailEnabled
		user.SecurityEmailEnabled = *input.SecurityEmailEnabled
	}
	localeChanged := input.Locale != nil && (user.Locale != previousLocale || user.LocaleSource != previousLocaleSource)
	if err := s.DB.Transaction(func(tx *gorm.DB) error {
		if len(updates) > 0 {
			if err := tx.Model(&model.User{}).Where("id = ?", user.ID).Updates(updates).Error; err != nil {
				return err
			}
		}
		if localeChanged {
			return s.recordLifecycleEvent(tx, user.ID, "profile.updated", map[string]any{"locale": user.Locale})
		}
		return nil
	}); err != nil {
		s.serveError(c, http.StatusInternalServerError, "保存资料失败")
		return
	}
	s.audit(c, "profile.updated", user.ID, "")
	c.JSON(http.StatusOK, gin.H{"success": true, "data": publicUser(user)})
}

func (s *Server) prepareProfileEmail(c *gin.Context) {
	var input struct {
		Email string `json:"email"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		s.serveError(c, http.StatusBadRequest, "请求格式错误")
		return
	}
	user := s.user(c)
	email := strings.ToLower(strings.TrimSpace(input.Email))
	if !validEmail(email) {
		s.serveError(c, http.StatusBadRequest, "邮箱格式不正确")
		return
	}
	if !s.enforceRateLimitPair(c, "profile_email", email, s.Cfg.RateLimitEmail, time.Hour) {
		return
	}
	var existing model.UserEmail
	if err := s.DB.Where("normalized_email = ?", email).First(&existing).Error; err == nil {
		if existing.UserID != user.ID {
			s.serveError(c, http.StatusConflict, "邮箱已被使用")
			return
		}
		s.serveError(c, http.StatusConflict, "邮箱已经绑定")
		return
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		s.serveError(c, http.StatusInternalServerError, "读取邮箱绑定失败")
		return
	}
	code, err := numericCode()
	if err != nil {
		s.serveError(c, http.StatusInternalServerError, "生成验证码失败")
		return
	}
	now := time.Now()
	userID := user.ID
	raw, _, err := s.createAuthFlow(model.AuthFlow{Purpose: "profile_email_verify", UserID: &userID, Email: email, Locale: user.Locale, VerificationCodeHash: security.HMACToken(s.Cfg.MasterKey, code), LastSentAt: &now, ExpiresAt: now.Add(10 * time.Minute)})
	if err != nil {
		s.serveError(c, http.StatusInternalServerError, "创建邮箱验证流程失败")
		return
	}
	if err := s.deliverVerificationCode(email, code, user.Locale); err != nil {
		s.serveError(c, http.StatusServiceUnavailable, err.Error())
		return
	}
	data := s.verificationResponse(code)
	data["flow_token"] = raw
	c.JSON(http.StatusOK, gin.H{"success": true, "data": data})
}

func normalizeProfileLocale(value string) string {
	if locale, ok := supportedLocale(value); ok {
		return locale
	}
	return "zhCN"
}

func (s *Server) completeProfileEmail(c *gin.Context) {
	var input struct {
		FlowToken string `json:"flow_token"`
		Code      string `json:"code"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		s.serveError(c, http.StatusBadRequest, "请求格式错误")
		return
	}
	flow, err := s.loadAuthFlow(input.FlowToken, "profile_email_verify")
	if err != nil || flow.UserID == nil || *flow.UserID != s.user(c).ID {
		s.serveError(c, http.StatusBadRequest, "邮箱验证流程已过期")
		return
	}
	if flow.Attempts >= 8 || !security.ConstantTimeHMACMatch(s.Cfg.MasterKey, flow.VerificationCodeHash, strings.TrimSpace(input.Code)) {
		_ = s.DB.Model(&flow).UpdateColumn("attempts", gorm.Expr("attempts + 1")).Error
		s.serveError(c, http.StatusUnauthorized, "邮箱验证码无效")
		return
	}
	now := time.Now()
	user := s.user(c)
	err = s.DB.Transaction(func(tx *gorm.DB) error {
		result := tx.Model(&model.AuthFlow{}).Where("id = ? AND used_at IS NULL", flow.ID).Update("used_at", &now)
		if result.Error != nil || result.RowsAffected != 1 {
			return fmt.Errorf("邮箱验证流程已被使用")
		}
		var email model.UserEmail
		if err := tx.Where("normalized_email = ?", flow.Email).First(&email).Error; err == nil {
			if email.UserID != user.ID {
				return fmt.Errorf("邮箱已被使用")
			}
		} else if errors.Is(err, gorm.ErrRecordNotFound) {
			email = model.UserEmail{UserID: user.ID, Email: flow.Email, NormalizedEmail: flow.Email, VerifiedAt: &now}
			if err := tx.Create(&email).Error; err != nil {
				return err
			}
		} else {
			return err
		}
		return tx.Where("user_id = ? AND kind = ? AND normalized_identifier = ?", user.ID, "email", flow.Email).
			Delete(&model.LegacyLoginIdentifier{}).Error
	})
	if err != nil {
		s.serveError(c, http.StatusConflict, "邮箱已被使用")
		return
	}
	s.audit(c, "email.bound", user.ID, flow.Email)
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func (s *Server) deleteOwnEmailBinding(c *gin.Context) {
	s.deleteOwnBinding(c, true)
}

func (s *Server) deleteOwnUpstreamBinding(c *gin.Context) {
	s.deleteOwnBinding(c, false)
}

func (s *Server) deleteOwnBinding(c *gin.Context, email bool) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		s.serveError(c, http.StatusBadRequest, "绑定信息无效")
		return
	}
	userID := s.user(c).ID
	err = s.DB.Transaction(func(tx *gorm.DB) error {
		if email {
			return s.deleteEmailBinding(tx, userID, id, false)
		}
		return s.deleteUpstreamBinding(tx, userID, id, false)
	})
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			s.serveError(c, http.StatusNotFound, "绑定不存在")
			return
		}
		if err.Error() == "账号必须保留至少一个绑定" {
			s.serveError(c, http.StatusConflict, err.Error())
			return
		}
		s.serveError(c, http.StatusInternalServerError, "解绑失败")
		return
	}
	s.audit(c, "binding.deleted", userID, fmt.Sprintf("type=%s", map[bool]string{true: "email", false: "upstream"}[email]))
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func (s *Server) changePassword(c *gin.Context) {
	var input struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		s.serveError(c, http.StatusBadRequest, "请求格式错误")
		return
	}
	user := s.user(c)
	if user.PasswordConfigured && !security.VerifyPassword(user.PasswordHash, input.CurrentPassword) {
		s.serveError(c, http.StatusUnauthorized, "当前密码错误")
		return
	}
	if message := validatePassword(input.NewPassword); message != "" {
		s.serveError(c, http.StatusBadRequest, message)
		return
	}
	hash, err := security.HashPassword(input.NewPassword)
	if err != nil {
		s.serveError(c, http.StatusInternalServerError, "密码处理失败")
		return
	}
	currentSession := s.session(c)
	err = s.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(user).Updates(map[string]any{"password_hash": hash, "password_configured": true}).Error; err != nil {
			return err
		}
		now := time.Now()
		return tx.Model(&model.Session{}).Where("user_id = ? AND id <> ? AND revoked_at IS NULL", user.ID, currentSession.ID).Update("revoked_at", &now).Error
	})
	if err != nil {
		s.serveError(c, http.StatusInternalServerError, "修改密码失败")
		return
	}
	action := "password.changed"
	if !user.PasswordConfigured {
		action = "password.configured"
	}
	user.PasswordConfigured = true
	s.audit(c, action, user.ID, "")
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func (s *Server) setupMFA(c *gin.Context) {
	user := s.user(c)
	if user.MFAEnabled {
		s.serveError(c, http.StatusConflict, "请先验证并停用当前 MFA，再重新设置")
		return
	}
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "xem SSO", AccountName: user.Username})
	if err != nil {
		s.serveError(c, http.StatusInternalServerError, "生成 MFA 密钥失败")
		return
	}
	encrypted, err := security.Encrypt(s.Cfg.MasterKey, key.Secret())
	if err != nil {
		s.serveError(c, http.StatusInternalServerError, "保存 MFA 密钥失败")
		return
	}
	if err := s.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("user_id = ?", user.ID).Delete(&model.MFABackupCode{}).Error; err != nil {
			return err
		}
		return tx.Model(user).Updates(map[string]any{"mfa_secret_encrypted": encrypted, "mfa_enabled": false, "mfa_backup_code_hashes": "[]"}).Error
	}); err != nil {
		s.serveError(c, http.StatusInternalServerError, "保存 MFA 密钥失败")
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"secret": key.Secret(), "otpauth_url": key.URL()}})
}

func (s *Server) enableMFA(c *gin.Context) {
	var input struct {
		Code string `json:"code"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		s.serveError(c, http.StatusBadRequest, "请求格式错误")
		return
	}
	user := s.user(c)
	secret, err := security.Decrypt(s.Cfg.MasterKey, user.MFASecretEncrypted)
	if err != nil || !totp.Validate(strings.TrimSpace(input.Code), secret) {
		s.serveError(c, http.StatusBadRequest, "验证码无效")
		return
	}
	codes := make([]string, 10)
	backupRecords := make([]model.MFABackupCode, 10)
	for index := range codes {
		raw, tokenErr := security.RandomToken(7)
		if tokenErr != nil {
			s.serveError(c, http.StatusInternalServerError, "生成备用码失败")
			return
		}
		codes[index] = strings.ToUpper(raw[:10])
		backupRecords[index] = model.MFABackupCode{UserID: user.ID, CodeHash: security.HashToken(codes[index])}
	}
	if err := s.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("user_id = ?", user.ID).Delete(&model.MFABackupCode{}).Error; err != nil {
			return err
		}
		if err := tx.Create(&backupRecords).Error; err != nil {
			return err
		}
		return tx.Model(user).Updates(map[string]any{"mfa_enabled": true, "mfa_backup_code_hashes": "[]"}).Error
	}); err != nil {
		s.serveError(c, http.StatusInternalServerError, "启用 MFA 失败")
		return
	}
	user.MFAEnabled = true
	s.audit(c, "mfa.enabled", user.ID, "")
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"backup_codes": codes}})
}

func (s *Server) disableMFA(c *gin.Context) {
	var input struct {
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		s.serveError(c, http.StatusBadRequest, "请求格式错误")
		return
	}
	user := s.user(c)
	if (user.PasswordConfigured && !security.VerifyPassword(user.PasswordHash, input.Password)) || !s.verifyMFA(user, strings.TrimSpace(input.Code)) {
		s.serveError(c, http.StatusUnauthorized, "密码或验证码错误")
		return
	}
	if err := s.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("user_id = ?", user.ID).Delete(&model.MFABackupCode{}).Error; err != nil {
			return err
		}
		return tx.Model(user).Updates(map[string]any{"mfa_enabled": false, "mfa_secret_encrypted": "", "mfa_backup_code_hashes": "[]"}).Error
	}); err != nil {
		s.serveError(c, http.StatusInternalServerError, "停用 MFA 失败")
		return
	}
	user.MFAEnabled = false
	s.audit(c, "mfa.disabled", user.ID, "")
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func (s *Server) listSessions(c *gin.Context) {
	var sessions []model.Session
	if err := s.DB.Where("user_id = ? AND revoked_at IS NULL AND expires_at > ?", s.user(c).ID, time.Now()).Order("last_seen_at DESC").Find(&sessions).Error; err != nil {
		s.serveError(c, http.StatusInternalServerError, "读取登录设备失败")
		return
	}
	current := s.session(c).ID
	items := make([]gin.H, 0, len(sessions))
	for _, session := range sessions {
		items = append(items, gin.H{"id": session.ID, "device_name": session.DeviceName, "ip": session.IP, "user_agent": session.UserAgent, "last_seen_at": session.LastSeenAt, "created_at": session.CreatedAt, "current": session.ID == current})
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": items})
}

func (s *Server) revokeSession(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		s.serveError(c, http.StatusBadRequest, "会话编号无效")
		return
	}
	if id == s.session(c).ID {
		s.serveError(c, http.StatusBadRequest, "请使用退出登录结束当前会话")
		return
	}
	now := time.Now()
	result := s.DB.Model(&model.Session{}).Where("id = ? AND user_id = ? AND revoked_at IS NULL", id, s.user(c).ID).Update("revoked_at", &now)
	if result.Error != nil {
		s.serveError(c, http.StatusInternalServerError, "撤销会话失败")
		return
	}
	if result.RowsAffected == 0 {
		s.serveError(c, http.StatusNotFound, "会话不存在")
		return
	}
	s.audit(c, "session.revoked", s.user(c).ID, strconv.FormatUint(id, 10))
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func (s *Server) listPATs(c *gin.Context) {
	var tokens []model.PersonalAccessToken
	if err := s.DB.Where("user_id = ? AND revoked_at IS NULL", s.user(c).ID).Order("created_at DESC").Find(&tokens).Error; err != nil {
		s.serveError(c, http.StatusInternalServerError, "读取令牌失败")
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": tokens})
}

func (s *Server) createPAT(c *gin.Context) {
	var input struct {
		Name      string     `json:"name"`
		Scopes    string     `json:"scopes"`
		ExpiresAt *time.Time `json:"expires_at"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		s.serveError(c, http.StatusBadRequest, "请求格式错误")
		return
	}
	input.Name = strings.TrimSpace(input.Name)
	if input.Name == "" || len(input.Name) > 100 {
		s.serveError(c, http.StatusBadRequest, "令牌名称需为 1-100 个字符")
		return
	}
	raw, err := security.RandomToken(32)
	if err != nil {
		s.serveError(c, http.StatusInternalServerError, "生成令牌失败")
		return
	}
	raw = "sso_pat_" + raw
	scopes := strings.TrimSpace(input.Scopes)
	if scopes == "" {
		scopes = "profile"
	}
	allowedScopes := map[string]bool{
		"profile": true, "profile:write": true, "apps:read": true, "apps:write": true,
		"grants:read": true, "grants:write": true, "audit:read": true,
	}
	canonicalScopes := make([]string, 0)
	seenScopes := make(map[string]bool)
	for _, scope := range strings.Fields(scopes) {
		if !allowedScopes[scope] {
			s.serveError(c, http.StatusBadRequest, "PAT Scope 无效")
			return
		}
		if !seenScopes[scope] {
			seenScopes[scope] = true
			canonicalScopes = append(canonicalScopes, scope)
		}
	}
	scopes = strings.Join(canonicalScopes, " ")
	token := model.PersonalAccessToken{UserID: s.user(c).ID, Name: input.Name, Prefix: raw[:16], TokenHash: security.HashToken(raw), Scopes: scopes, ExpiresAt: input.ExpiresAt}
	if err := s.DB.Create(&token).Error; err != nil {
		s.serveError(c, http.StatusInternalServerError, "创建令牌失败")
		return
	}
	s.audit(c, "pat.created", s.user(c).ID, token.Prefix)
	c.JSON(http.StatusCreated, gin.H{"success": true, "data": gin.H{"token": token, "plain_token": raw}})
}

func (s *Server) revokePAT(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		s.serveError(c, http.StatusBadRequest, "令牌编号无效")
		return
	}
	now := time.Now()
	result := s.DB.Model(&model.PersonalAccessToken{}).Where("id = ? AND user_id = ? AND revoked_at IS NULL", id, s.user(c).ID).Update("revoked_at", &now)
	if result.Error != nil {
		s.serveError(c, http.StatusInternalServerError, "撤销令牌失败")
		return
	}
	if result.RowsAffected == 0 {
		s.serveError(c, http.StatusNotFound, "令牌不存在")
		return
	}
	s.audit(c, "pat.revoked", s.user(c).ID, strconv.FormatUint(id, 10))
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func (s *Server) listAudit(c *gin.Context) {
	var events []model.AuditEvent
	if err := s.DB.Where("user_id = ?", s.user(c).ID).Order("created_at DESC").Limit(100).Find(&events).Error; err != nil {
		s.serveError(c, http.StatusInternalServerError, "读取安全活动失败")
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": events})
}

func (s *Server) exportData(c *gin.Context) {
	user := s.user(c)
	var apps []model.OAuthApplication
	var grants []model.Grant
	var logs []model.AuthorizationLog
	var events []model.AuditEvent
	var identities []model.UpstreamIdentity
	var emails []model.UserEmail
	s.DB.Where("owner_id = ?", user.ID).Find(&apps)
	s.DB.Preload("App").Where("user_id = ?", user.ID).Find(&grants)
	s.DB.Preload("App").Where("user_id = ?", user.ID).Find(&logs)
	s.DB.Where("user_id = ?", user.ID).Find(&events)
	s.DB.Preload("Provider").Where("user_id = ?", user.ID).Find(&identities)
	s.DB.Where("user_id = ?", user.ID).Find(&emails)
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=sso-export-%d.json", user.ID))
	c.JSON(http.StatusOK, gin.H{"exported_at": time.Now(), "profile": publicUser(user), "emails": emails, "applications": apps, "grants": grants, "authorization_logs": logs, "security_events": events, "upstream_identities": identities})
}

func (s *Server) deleteAccount(c *gin.Context) {
	var input struct {
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&input); err != nil || (s.user(c).PasswordConfigured && !security.VerifyPassword(s.user(c).PasswordHash, input.Password)) {
		s.serveError(c, http.StatusUnauthorized, "密码错误")
		return
	}
	user := s.user(c)
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		now := time.Now()
		if err := tx.Model(user).Updates(map[string]any{"status": "deactivated", "deactivated_at": &now}).Error; err != nil {
			return err
		}
		if err := tx.Model(&model.Session{}).Where("user_id = ? AND revoked_at IS NULL", user.ID).Update("revoked_at", &now).Error; err != nil {
			return err
		}
		if err := tx.Model(&model.PersonalAccessToken{}).Where("user_id = ? AND revoked_at IS NULL", user.ID).Update("revoked_at", &now).Error; err != nil {
			return err
		}
		if err := tx.Model(&model.Grant{}).Where("user_id = ? AND revoked_at IS NULL", user.ID).Update("revoked_at", &now).Error; err != nil {
			return err
		}
		if err := tx.Model(&model.OAuthApplication{}).Where("owner_id = ? AND disabled_at IS NULL", user.ID).Update("disabled_at", &now).Error; err != nil {
			return err
		}
		if err := revokeOAuthTokens(tx, "user_id = ? OR app_id IN (?)", user.ID, tx.Model(&model.OAuthApplication{}).Select("id").Where("owner_id = ?", user.ID)); err != nil {
			return err
		}
		if err := s.recordLifecycleEvent(tx, user.ID, "account.deactivated", nil); err != nil {
			return err
		}
		return tx.Create(&model.AuditEvent{UserID: user.ID, Action: "account.deactivated", IP: clientIP(c), UserAgent: c.Request.UserAgent()}).Error
	})
	if err != nil {
		s.serveError(c, http.StatusInternalServerError, "注销账户失败")
		return
	}
	s.revokeCurrentSession(c)
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func (s *Server) startAccountMerge(c *gin.Context) {
	var input struct {
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&input); err != nil || (s.user(c).PasswordConfigured && !security.VerifyPassword(s.user(c).PasswordHash, input.Password)) {
		s.serveError(c, http.StatusUnauthorized, "密码错误")
		return
	}
	userID := s.user(c).ID
	sessionID := s.session(c).ID
	raw, _, err := s.createAuthFlow(model.AuthFlow{Purpose: "merge_start", SourceUserID: &userID, SessionID: &sessionID, ExpiresAt: time.Now().Add(10 * time.Minute)})
	if err != nil {
		s.serveError(c, http.StatusInternalServerError, "创建账号合并流程失败")
		return
	}
	s.audit(c, "account.merge_started", userID, "")
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"merge_token": raw, "login_url": "/login?merge_token=" + raw}})
}

func (s *Server) uploadAvatar(c *gin.Context) {
	file, header, err := c.Request.FormFile("avatar")
	if err != nil {
		s.serveError(c, http.StatusBadRequest, "请选择头像文件")
		return
	}
	defer file.Close()
	if header.Size > 2*1024*1024 {
		s.serveError(c, http.StatusBadRequest, "头像不能超过 2MB")
		return
	}
	data, err := io.ReadAll(io.LimitReader(file, 2*1024*1024+1))
	if err != nil || len(data) > 2*1024*1024 {
		s.serveError(c, http.StatusBadRequest, "读取头像失败")
		return
	}
	mime := http.DetectContentType(data)
	ext := ""
	switch mime {
	case "image/jpeg":
		ext = ".jpg"
	case "image/png":
		ext = ".png"
	case "image/webp":
		ext = ".webp"
	default:
		s.serveError(c, http.StatusBadRequest, "仅支持 JPG、PNG 或 WebP")
		return
	}
	dir := filepath.Join(s.Cfg.DataDir, "media", "avatars")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		s.serveError(c, http.StatusInternalServerError, "创建头像目录失败")
		return
	}
	name := uuid.NewString() + ext
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
		s.serveError(c, http.StatusInternalServerError, "保存头像失败")
		return
	}
	avatarURL := "/media/avatars/" + name
	if err := s.DB.Model(s.user(c)).Update("avatar_url", avatarURL).Error; err != nil {
		s.serveError(c, http.StatusInternalServerError, "更新头像失败")
		return
	}
	s.user(c).AvatarURL = avatarURL
	s.audit(c, "profile.avatar_updated", s.user(c).ID, "")
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"avatar_url": avatarURL}})
}

func (s *Server) avatarFile(c *gin.Context) {
	name := filepath.Base(c.Param("file"))
	if name == "." || name == "" {
		c.Status(http.StatusNotFound)
		return
	}
	path := filepath.Join(s.Cfg.DataDir, "media", "avatars", name)
	if _, err := os.Stat(path); err != nil {
		c.Status(http.StatusNotFound)
		return
	}
	c.File(path)
}
