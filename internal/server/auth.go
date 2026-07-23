package server

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/Cong0707/sso/internal/model"
	"github.com/Cong0707/sso/internal/security"
	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp/totp"
	"gorm.io/gorm"
)

var usernamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{2,31}$`)

func (s *Server) identify(c *gin.Context) {
	var input struct {
		Email        string `json:"email"`
		CaptchaToken string `json:"captcha_token"`
		MergeToken   string `json:"merge_token"`
		Locale       string `json:"locale"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		s.serveError(c, http.StatusBadRequest, "请求格式错误")
		return
	}
	email := strings.ToLower(strings.TrimSpace(input.Email))
	if !validEmail(email) {
		s.serveError(c, http.StatusBadRequest, "请输入有效的邮箱")
		return
	}
	if !s.enforceRateLimitPair(c, "identify", email, s.Cfg.RateLimitIdentify, time.Minute) {
		return
	}
	if err := s.verifyCaptcha(input.CaptchaToken, clientIP(c)); err != nil {
		s.serveError(c, http.StatusBadRequest, err.Error())
		return
	}
	var sourceUserID *uint64
	var sourceSessionID *uint64
	if strings.TrimSpace(input.MergeToken) != "" {
		mergeFlow, err := s.loadAuthFlow(input.MergeToken, "merge_start")
		if err != nil || mergeFlow.SourceUserID == nil || !s.mergeSessionMatches(c, &mergeFlow) {
			s.serveError(c, http.StatusBadRequest, "账号合并请求已过期")
			return
		}
		sourceUserID = mergeFlow.SourceUserID
		sourceSessionID = mergeFlow.SessionID
	}
	user, err := s.findUserByEmail(email)
	mode := "login"
	var userID *uint64
	username := ""
	if errors.Is(err, gorm.ErrRecordNotFound) {
		if sourceUserID != nil {
			s.serveError(c, http.StatusNotFound, "要合并的账号不存在")
			return
		}
		if !s.settingBool(settingRegistrationEnabled, s.Cfg.RegistrationEnabled) {
			s.serveError(c, http.StatusForbidden, "注册已关闭")
			return
		}
		mode = "register"
	} else if err != nil {
		s.serveError(c, http.StatusInternalServerError, "读取账号失败")
		return
	} else {
		if user.Status != "active" {
			s.serveError(c, http.StatusForbidden, accountStatusMessage(user.Status))
			return
		}
		if !user.PasswordConfigured {
			s.serveError(c, http.StatusBadRequest, "该账号尚未设置密码，请使用已绑定的第三方登录方式")
			return
		}
		userID = &user.ID
	}
	raw, flow, err := s.createAuthFlow(model.AuthFlow{
		Purpose: "identify_" + mode, Identifier: email, Email: email, Username: username,
		Locale: requestLocale(input.Locale, c.GetHeader("Accept-Language")), UserID: userID,
		SourceUserID: sourceUserID, SessionID: sourceSessionID, ExpiresAt: time.Now().Add(10 * time.Minute),
	})
	if err != nil {
		s.serveError(c, http.StatusInternalServerError, "创建认证流程失败")
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{
		"flow_token": raw, "mode": mode, "mfa_required": userID != nil && user.MFAEnabled,
		"email": flow.Email,
	}})
}

func (s *Server) registerPrepare(c *gin.Context) {
	var input struct {
		FlowToken       string `json:"flow_token"`
		Username        string `json:"username"`
		Password        string `json:"password"`
		ConfirmPassword string `json:"confirm_password"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		s.serveError(c, http.StatusBadRequest, "请求格式错误")
		return
	}
	flow, err := s.loadAuthFlow(input.FlowToken, "identify_register")
	if err != nil {
		s.serveError(c, http.StatusBadRequest, "注册流程已过期，请返回重试")
		return
	}
	input.Username = strings.TrimSpace(input.Username)
	if !usernamePattern.MatchString(input.Username) {
		s.serveError(c, http.StatusBadRequest, "用户名需为 3-32 位字母、数字、下划线或连字符")
		return
	}
	if !s.enforceRateLimitPair(c, "registration_email", flow.Email, s.Cfg.RateLimitEmail, time.Hour) {
		return
	}
	if input.Password != input.ConfirmPassword {
		s.serveError(c, http.StatusBadRequest, "两次输入的密码不一致")
		return
	}
	if message := validatePassword(input.Password); message != "" {
		s.serveError(c, http.StatusBadRequest, message)
		return
	}
	var count int64
	if err := s.DB.Model(&model.UserEmail{}).Where("normalized_email = ?", flow.Email).Count(&count).Error; err != nil || count > 0 {
		s.serveError(c, http.StatusConflict, "邮箱已被使用")
		return
	}
	if err := s.DB.Model(&model.User{}).Where("LOWER(username) = ?", strings.ToLower(input.Username)).Count(&count).Error; err != nil || count > 0 {
		s.serveError(c, http.StatusConflict, "用户名已被使用")
		return
	}
	passwordHash, err := security.HashPassword(input.Password)
	if err != nil {
		s.serveError(c, http.StatusInternalServerError, "密码处理失败")
		return
	}
	code, err := numericCode()
	if err != nil {
		s.serveError(c, http.StatusInternalServerError, "生成验证码失败")
		return
	}
	now := time.Now()
	updates := map[string]any{
		"purpose": "register_verify", "username": input.Username, "password_hash": passwordHash,
		"verification_code_hash": security.HMACToken(s.Cfg.MasterKey, code), "last_sent_at": &now,
		"attempts": 0, "expires_at": now.Add(10 * time.Minute),
	}
	if err := s.DB.Model(&flow).Updates(updates).Error; err != nil {
		s.serveError(c, http.StatusInternalServerError, "保存注册流程失败")
		return
	}
	if err := s.deliverVerificationCode(flow.Email, code, flow.Locale); err != nil {
		_ = s.DB.Model(&flow).Updates(map[string]any{
			"purpose": "identify_register", "username": "", "password_hash": "",
			"verification_code_hash": "", "last_sent_at": nil, "attempts": 0,
			"expires_at": time.Now().Add(10 * time.Minute),
		}).Error
		s.serveError(c, http.StatusServiceUnavailable, err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": s.verificationResponse(code)})
}

func (s *Server) registerComplete(c *gin.Context) {
	var input struct {
		FlowToken string `json:"flow_token"`
		Code      string `json:"code"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		s.serveError(c, http.StatusBadRequest, "请求格式错误")
		return
	}
	flow, err := s.loadAuthFlow(input.FlowToken, "register_verify")
	if err != nil {
		s.serveError(c, http.StatusBadRequest, "邮箱验证流程已过期")
		return
	}
	if flow.Attempts >= 8 || !security.ConstantTimeHMACMatch(s.Cfg.MasterKey, flow.VerificationCodeHash, strings.TrimSpace(input.Code)) {
		_ = s.DB.Model(&flow).UpdateColumn("attempts", gorm.Expr("attempts + 1")).Error
		s.serveError(c, http.StatusUnauthorized, "邮箱验证码无效")
		return
	}
	var user model.User
	now := time.Now()
	err = s.DB.Transaction(func(tx *gorm.DB) error {
		result := tx.Model(&model.AuthFlow{}).Where("id = ? AND used_at IS NULL", flow.ID).Update("used_at", &now)
		if result.Error != nil || result.RowsAffected != 1 {
			return errors.New("注册流程已被使用")
		}
		var count int64
		if err := tx.Model(&model.User{}).Count(&count).Error; err != nil {
			return err
		}
		role := "user"
		if count == 0 {
			role = "admin"
		}
		user = model.User{
			Username: flow.Username, PasswordHash: flow.PasswordHash,
			PasswordConfigured: true, DisplayName: flow.Username, Locale: requestLocale(flow.Locale, ""),
			SecurityEmailEnabled: true, Role: role, Status: "active",
		}
		if err := tx.Create(&user).Error; err != nil {
			return err
		}
		email := model.UserEmail{UserID: user.ID, Email: flow.Email, NormalizedEmail: flow.Email, VerifiedAt: &now}
		if err := tx.Create(&email).Error; err != nil {
			return err
		}
		return tx.Create(&model.AuditEvent{UserID: user.ID, Action: "account.registered", IP: clientIP(c), UserAgent: c.Request.UserAgent()}).Error
	})
	if err != nil {
		s.serveError(c, http.StatusConflict, "用户名或邮箱已被使用")
		return
	}
	session, err := s.createSession(c, &user)
	if err != nil {
		s.serveError(c, http.StatusInternalServerError, "创建登录会话失败")
		return
	}
	c.JSON(http.StatusCreated, gin.H{"success": true, "data": gin.H{"user": publicUser(&user), "csrf_token": session.CSRFToken}})
}

func (s *Server) loginPassword(c *gin.Context) {
	var input struct {
		FlowToken string `json:"flow_token"`
		Password  string `json:"password"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		s.serveError(c, http.StatusBadRequest, "请求格式错误")
		return
	}
	flow, err := s.loadAuthFlow(input.FlowToken, "identify_login")
	if err != nil || flow.UserID == nil || (flow.SourceUserID != nil && !s.mergeSessionMatches(c, &flow)) {
		s.serveError(c, http.StatusBadRequest, "登录流程已过期，请返回重试")
		return
	}
	if !s.enforceRateLimitPair(c, "password_login", fmt.Sprintf("user:%d", *flow.UserID), s.Cfg.RateLimitLogin, 5*time.Minute) {
		return
	}
	var user model.User
	if s.DB.First(&user, *flow.UserID).Error != nil || user.Status != "active" || !user.PasswordConfigured || !security.VerifyPassword(user.PasswordHash, input.Password) {
		_ = s.DB.Model(&flow).UpdateColumn("attempts", gorm.Expr("attempts + 1")).Error
		s.audit(c, "login.failed", *flow.UserID, "")
		s.serveError(c, http.StatusUnauthorized, "密码错误")
		return
	}
	if flow.Attempts >= 8 {
		s.serveError(c, http.StatusTooManyRequests, "失败次数过多，请重新开始登录")
		return
	}
	if strings.HasPrefix(user.PasswordHash, "$2a$") || strings.HasPrefix(user.PasswordHash, "$2b$") || strings.HasPrefix(user.PasswordHash, "$2y$") {
		if upgraded, hashErr := security.HashPassword(input.Password); hashErr == nil {
			_ = s.DB.Model(&user).Update("password_hash", upgraded).Error
		}
	}
	if user.MFAEnabled {
		if err := s.DB.Model(&flow).Updates(map[string]any{"purpose": "login_mfa", "attempts": 0, "expires_at": time.Now().Add(5 * time.Minute)}).Error; err != nil {
			s.serveError(c, http.StatusInternalServerError, "保存二次验证流程失败")
			return
		}
		c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"mfa_required": true}})
		return
	}
	s.finishPasswordLogin(c, &flow, &user)
}

func (s *Server) loginMFA(c *gin.Context) {
	var input struct {
		FlowToken string `json:"flow_token"`
		Code      string `json:"code"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		s.serveError(c, http.StatusBadRequest, "请求格式错误")
		return
	}
	flow, err := s.loadAuthFlow(input.FlowToken, "login_mfa")
	if err != nil || flow.UserID == nil || (flow.SourceUserID != nil && !s.mergeSessionMatches(c, &flow)) {
		s.serveError(c, http.StatusBadRequest, "二次验证流程已过期")
		return
	}
	if !s.enforceRateLimitPair(c, "mfa_login", fmt.Sprintf("user:%d", *flow.UserID), s.Cfg.RateLimitLogin, 5*time.Minute) {
		return
	}
	var user model.User
	if s.DB.First(&user, *flow.UserID).Error != nil || user.Status != "active" || !s.verifyMFA(&user, strings.TrimSpace(input.Code)) {
		_ = s.DB.Model(&flow).UpdateColumn("attempts", gorm.Expr("attempts + 1")).Error
		s.audit(c, "login.mfa_failed", *flow.UserID, "")
		s.serveError(c, http.StatusUnauthorized, "二次验证码无效")
		return
	}
	s.finishPasswordLogin(c, &flow, &user)
}

func (s *Server) finishPasswordLogin(c *gin.Context, flow *model.AuthFlow, user *model.User) {
	now := time.Now()
	result := s.DB.Model(&model.AuthFlow{}).Where("id = ? AND used_at IS NULL", flow.ID).Update("used_at", &now)
	if result.Error != nil || result.RowsAffected != 1 {
		s.serveError(c, http.StatusConflict, "认证流程已被使用")
		return
	}
	merged := false
	if flow.SourceUserID != nil {
		if *flow.SourceUserID == user.ID {
			_, currentSession, sessionErr := s.sessionUser(c)
			if sessionErr != nil {
				s.serveError(c, http.StatusUnauthorized, "原登录会话已失效")
				return
			}
			s.audit(c, "account.merge_cancelled_same_account", user.ID, "")
			c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"user": publicUser(user), "csrf_token": currentSession.CSRFToken, "merged": false}})
			return
		}
		target, didMerge, err := s.mergeAccounts(*flow.SourceUserID, user.ID)
		if err != nil {
			s.serveError(c, http.StatusConflict, err.Error())
			return
		}
		if didMerge {
			user = &target
			merged = true
		}
	}
	user.LastLoginAt = &now
	_ = s.DB.Model(user).Update("last_login_at", &now).Error
	session, err := s.createSession(c, user)
	if err != nil {
		s.serveError(c, http.StatusInternalServerError, "创建登录会话失败")
		return
	}
	s.audit(c, "login.succeeded", user.ID, "")
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"user": publicUser(user), "csrf_token": session.CSRFToken, "merged": merged}})
}

func (s *Server) resendVerificationCode(c *gin.Context) {
	var input struct {
		FlowToken string `json:"flow_token"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		s.serveError(c, http.StatusBadRequest, "请求格式错误")
		return
	}
	flow, err := s.loadAuthFlow(input.FlowToken, "register_verify")
	if err != nil {
		s.serveError(c, http.StatusBadRequest, "邮箱验证流程已过期")
		return
	}
	if !s.enforceRateLimitPair(c, "verification_resend", flow.Email, s.Cfg.RateLimitEmail, time.Hour) {
		return
	}
	if flow.LastSentAt != nil && time.Since(*flow.LastSentAt) < time.Minute {
		s.serveError(c, http.StatusTooManyRequests, "请等待 60 秒后重试")
		return
	}
	code, err := numericCode()
	if err != nil {
		s.serveError(c, http.StatusInternalServerError, "生成验证码失败")
		return
	}
	now := time.Now()
	oldHash, oldSentAt, oldAttempts, oldExpiry := flow.VerificationCodeHash, flow.LastSentAt, flow.Attempts, flow.ExpiresAt
	if err := s.DB.Model(&flow).Updates(map[string]any{"verification_code_hash": security.HMACToken(s.Cfg.MasterKey, code), "last_sent_at": &now, "attempts": 0, "expires_at": now.Add(10 * time.Minute)}).Error; err != nil {
		s.serveError(c, http.StatusInternalServerError, "保存验证码失败")
		return
	}
	if err := s.deliverVerificationCode(flow.Email, code, flow.Locale); err != nil {
		_ = s.DB.Model(&flow).Updates(map[string]any{"verification_code_hash": oldHash, "last_sent_at": oldSentAt, "attempts": oldAttempts, "expires_at": oldExpiry}).Error
		s.serveError(c, http.StatusServiceUnavailable, err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": s.verificationResponse(code)})
}

func (s *Server) createAuthFlow(flow model.AuthFlow) (string, model.AuthFlow, error) {
	raw, err := security.RandomToken(32)
	if err != nil {
		return "", flow, err
	}
	flow.TokenHash = security.HashToken(raw)
	if flow.ExpiresAt.IsZero() {
		flow.ExpiresAt = time.Now().Add(10 * time.Minute)
	}
	err = s.DB.Create(&flow).Error
	return raw, flow, err
}

func (s *Server) loadAuthFlow(raw string, purpose string) (model.AuthFlow, error) {
	var flow model.AuthFlow
	if strings.TrimSpace(raw) == "" {
		return flow, gorm.ErrRecordNotFound
	}
	err := s.DB.Where("token_hash = ? AND purpose = ? AND used_at IS NULL AND expires_at > ?", security.HashToken(raw), purpose, time.Now()).First(&flow).Error
	return flow, err
}

func (s *Server) mergeSessionMatches(c *gin.Context, flow *model.AuthFlow) bool {
	if flow.SessionID == nil || flow.SourceUserID == nil {
		return false
	}
	user, session, err := s.sessionUser(c)
	return err == nil && session.ID == *flow.SessionID && user.ID == *flow.SourceUserID
}

func numericCode() (string, error) {
	value, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", value.Int64()), nil
}

func (s *Server) deliverVerificationCode(email, code, locale string) error {
	if err := s.sendVerificationEmail(email, code, locale); err != nil {
		if s.Cfg.EmailDebug {
			return nil
		}
		return err
	}
	return nil
}

func (s *Server) verificationResponse(code string) gin.H {
	data := gin.H{"resend_after": 60, "expires_in": 600}
	if s.Cfg.EmailDebug {
		data["debug_code"] = code
	}
	return data
}

func accountStatusMessage(status string) string {
	switch status {
	case "deactivated":
		return "账号已注销，无法登录"
	case "merged":
		return "账号已合并，请使用合并后的账号登录"
	default:
		return "账号不可用"
	}
}

func (s *Server) verifyMFA(user *model.User, code string) bool {
	secret, err := security.Decrypt(s.Cfg.MasterKey, user.MFASecretEncrypted)
	if err == nil && totp.Validate(code, secret) {
		return true
	}
	var hashes []string
	if json.Unmarshal([]byte(user.MFABackupCodeHashes), &hashes) != nil {
		return false
	}
	for index, hash := range hashes {
		if security.ConstantTimeTokenMatch(hash, strings.ToUpper(code)) {
			hashes = append(hashes[:index], hashes[index+1:]...)
			encoded, _ := json.Marshal(hashes)
			_ = s.DB.Model(user).Update("mfa_backup_code_hashes", string(encoded)).Error
			return true
		}
	}
	return false
}

func (s *Server) logout(c *gin.Context) {
	user := s.user(c)
	s.revokeCurrentSession(c)
	s.audit(c, "logout", user.ID, "")
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func (s *Server) logoutAll(c *gin.Context) {
	user := s.user(c)
	current := s.session(c)
	now := time.Now()
	if err := s.DB.Model(&model.Session{}).Where("user_id = ? AND id <> ? AND revoked_at IS NULL", user.ID, current.ID).Update("revoked_at", &now).Error; err != nil {
		s.serveError(c, http.StatusInternalServerError, "退出设备失败")
		return
	}
	s.audit(c, "session.others_revoked", user.ID, "")
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func validEmail(value string) bool {
	if len(value) < 3 || len(value) > 254 || strings.Count(value, "@") != 1 {
		return false
	}
	parts := strings.Split(value, "@")
	return parts[0] != "" && strings.Contains(parts[1], ".") && !strings.ContainsAny(value, " \t\r\n")
}

func validatePassword(value string) string {
	if len(value) < 8 || len(value) > 128 {
		return "密码需为 8-128 位"
	}
	var hasLetter, hasDigit bool
	for _, char := range value {
		if char >= '0' && char <= '9' {
			hasDigit = true
		}
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') {
			hasLetter = true
		}
	}
	if !hasLetter || !hasDigit {
		return "密码需要同时包含字母和数字"
	}
	return ""
}
