package server

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Cong0707/sso/internal/model"
	"github.com/Cong0707/sso/internal/security"
	"github.com/Cong0707/sso/internal/upstream"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func pagination(c *gin.Context) (int, int) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}
	return page, pageSize
}

func (s *Server) adminListUsers(c *gin.Context) {
	page, pageSize := pagination(c)
	query := s.DB.Model(&model.User{})
	if q := strings.ToLower(strings.TrimSpace(c.Query("q"))); q != "" {
		like := "%" + q + "%"
		query = query.Where("LOWER(username) LIKE ? OR LOWER(display_name) LIKE ? OR EXISTS (SELECT 1 FROM user_emails WHERE user_emails.user_id = users.id AND user_emails.normalized_email LIKE ?) OR EXISTS (SELECT 1 FROM legacy_login_identifiers WHERE legacy_login_identifiers.user_id = users.id AND legacy_login_identifiers.normalized_identifier LIKE ?)", like, like, like, like)
	}
	if status := strings.TrimSpace(c.Query("status")); status != "" && status != "all" {
		query = query.Where("status = ?", status)
	}
	if role := strings.TrimSpace(c.Query("role")); role != "" && role != "all" {
		query = query.Where("role = ?", role)
	}
	var total int64
	if err := query.Count(&total).Error; err != nil {
		s.serveError(c, http.StatusInternalServerError, "读取用户数量失败")
		return
	}
	sortColumns := map[string]string{"id": "id", "username": "username", "status": "status", "role": "role", "created_at": "created_at", "last_login_at": "last_login_at"}
	sortColumn := sortColumns[c.DefaultQuery("sort", "id")]
	if sortColumn == "" {
		sortColumn = "id"
	}
	sortOrder := strings.ToUpper(c.DefaultQuery("order", "ASC"))
	if sortOrder != "DESC" {
		sortOrder = "ASC"
	}
	var users []model.User
	if err := query.Order(sortColumn + " " + sortOrder).Offset((page - 1) * pageSize).Limit(pageSize).Find(&users).Error; err != nil {
		s.serveError(c, http.StatusInternalServerError, "读取用户列表失败")
		return
	}
	items := make([]gin.H, 0, len(users))
	for index := range users {
		var emailCount, identityCount int64
		_ = s.DB.Model(&model.UserEmail{}).Where("user_id = ?", users[index].ID).Count(&emailCount).Error
		_ = s.DB.Model(&model.UpstreamIdentity{}).Where("user_id = ?", users[index].ID).Count(&identityCount).Error
		item := publicUser(&users[index])
		item["email_count"] = emailCount
		item["identity_count"] = identityCount
		item["binding_count"] = emailCount + identityCount
		item["deactivated_at"] = users[index].DeactivatedAt
		item["merged_into_user_id"] = users[index].MergedIntoUserID
		items = append(items, item)
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"items": items, "page": page, "page_size": pageSize, "total": total}})
}

func (s *Server) adminGetUser(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		s.serveError(c, http.StatusBadRequest, "用户编号无效")
		return
	}
	var user model.User
	if err := s.DB.First(&user, id).Error; err != nil {
		s.serveError(c, http.StatusNotFound, "用户不存在")
		return
	}
	data := publicUser(&user)
	data["bindings"] = s.userBindingViews(user.ID)
	data["deactivated_at"] = user.DeactivatedAt
	data["merged_into_user_id"] = user.MergedIntoUserID
	c.JSON(http.StatusOK, gin.H{"success": true, "data": data})
}

func (s *Server) adminUpdateUser(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		s.serveError(c, http.StatusBadRequest, "用户编号无效")
		return
	}
	var input struct {
		Username    *string `json:"username"`
		DisplayName *string `json:"display_name"`
		Password    *string `json:"password"`
		Role        *string `json:"role"`
		Status      *string `json:"status"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		s.serveError(c, http.StatusBadRequest, "请求格式错误")
		return
	}
	var user model.User
	if s.DB.First(&user, id).Error != nil {
		s.serveError(c, http.StatusNotFound, "用户不存在")
		return
	}
	updates := map[string]any{}
	if input.Username != nil {
		username := strings.TrimSpace(*input.Username)
		if !usernamePattern.MatchString(username) {
			s.serveError(c, http.StatusBadRequest, "用户名需为 3-32 位字母、数字、下划线或连字符")
			return
		}
		updates["username"] = username
	}
	if input.DisplayName != nil {
		displayName := strings.TrimSpace(*input.DisplayName)
		if len(displayName) > 100 {
			s.serveError(c, http.StatusBadRequest, "显示名称不能超过 100 个字符")
			return
		}
		updates["display_name"] = displayName
	}
	if input.Password != nil && *input.Password != "" {
		if message := validatePassword(*input.Password); message != "" {
			s.serveError(c, http.StatusBadRequest, message)
			return
		}
		hash, hashErr := security.HashPassword(*input.Password)
		if hashErr != nil {
			s.serveError(c, http.StatusInternalServerError, "密码处理失败")
			return
		}
		updates["password_hash"] = hash
		updates["password_configured"] = true
	}
	if input.Role != nil {
		if *input.Role != "user" && *input.Role != "admin" {
			s.serveError(c, http.StatusBadRequest, "角色无效")
			return
		}
		if user.Role == "admin" && *input.Role != "admin" {
			var admins int64
			_ = s.DB.Model(&model.User{}).Where("role = ? AND status = ?", "admin", "active").Count(&admins).Error
			if admins <= 1 {
				s.serveError(c, http.StatusConflict, "不能移除最后一个有效管理员")
				return
			}
		}
		updates["role"] = *input.Role
	}
	if input.Status != nil {
		if *input.Status != "active" && *input.Status != "deactivated" {
			s.serveError(c, http.StatusBadRequest, "状态只能设为正常或注销")
			return
		}
		if user.ID == s.user(c).ID && *input.Status != "active" {
			s.serveError(c, http.StatusConflict, "不能在当前会话中注销自己")
			return
		}
		if user.Status == "merged" && *input.Status != "merged" {
			s.serveError(c, http.StatusConflict, "已合并的原账号只能用于审计，不能重新启用")
			return
		}
		updates["status"] = *input.Status
		if *input.Status == "deactivated" {
			now := time.Now()
			updates["deactivated_at"] = &now
		} else {
			updates["deactivated_at"] = nil
			updates["merged_into_user_id"] = nil
		}
	}
	if len(updates) == 0 {
		s.serveError(c, http.StatusBadRequest, "没有可更新的字段")
		return
	}
	err = s.DB.Transaction(func(tx *gorm.DB) error {
		if updateErr := tx.Model(&user).Updates(updates).Error; updateErr != nil {
			return updateErr
		}
		if input.Password != nil && *input.Password != "" || input.Status != nil && *input.Status == "deactivated" {
			now := time.Now()
			if err := tx.Model(&model.Session{}).Where("user_id = ? AND revoked_at IS NULL", user.ID).Update("revoked_at", &now).Error; err != nil {
				return err
			}
		}
		if input.Status != nil && *input.Status == "deactivated" {
			now := time.Now()
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
		}
		if input.Status != nil && *input.Status != user.Status {
			eventType := "account.reactivated"
			if *input.Status == "deactivated" {
				eventType = "account.deactivated"
			}
			if err := s.recordLifecycleEvent(tx, user.ID, eventType, nil); err != nil {
				return err
			}
		}
		if input.Role != nil && *input.Role != user.Role {
			if err := s.recordLifecycleEvent(tx, user.ID, "account.role_changed", map[string]any{"role": *input.Role}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") || strings.Contains(strings.ToLower(err.Error()), "duplicate") {
			s.serveError(c, http.StatusConflict, "用户名已被使用")
			return
		}
		s.serveError(c, http.StatusInternalServerError, "更新用户失败")
		return
	}
	s.audit(c, "admin.user_updated", s.user(c).ID, fmt.Sprintf("target_user_id=%d", user.ID))
	c.JSON(http.StatusOK, gin.H{"success": true})
}

type userBindingView struct {
	Kind        string     `json:"kind"`
	DisplayName string     `json:"display_name"`
	Identifier  string     `json:"identifier"`
	AccountName string     `json:"account_name,omitempty"`
	Email       string     `json:"email,omitempty"`
	BindingType string     `json:"binding_type"`
	BindingID   uint64     `json:"binding_id"`
	Verified    bool       `json:"verified"`
	CreatedAt   time.Time  `json:"created_at"`
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`
}

func (s *Server) userBindingViews(userID uint64) []userBindingView {
	items := make([]userBindingView, 0)
	emailQuery := s.DB.Where("user_id = ?", userID)
	identityQuery := s.DB.Preload("Provider").Where("user_id = ?", userID)
	var emails []model.UserEmail
	_ = emailQuery.Order("id ASC").Find(&emails).Error
	for _, email := range emails {
		items = append(items, userBindingView{
			Kind: "email", DisplayName: "邮箱", Identifier: email.Email, BindingType: "email", BindingID: email.ID,
			Verified: true, CreatedAt: email.CreatedAt,
		})
	}
	var identities []model.UpstreamIdentity
	_ = identityQuery.Order("id ASC").Find(&identities).Error
	for _, identity := range identities {
		var lastLoginAt *time.Time
		if !identity.LastLoginAt.IsZero() {
			value := identity.LastLoginAt
			lastLoginAt = &value
		}
		items = append(items, userBindingView{
			Kind: identity.Provider.Kind, DisplayName: identity.Provider.DisplayName, Identifier: identity.ExternalID,
			AccountName: identity.ExternalName, Email: identity.ExternalEmail, BindingType: "upstream", BindingID: identity.ID,
			Verified: true, CreatedAt: identity.CreatedAt, LastLoginAt: lastLoginAt,
		})
	}
	return items
}

func (s *Server) adminResetMFA(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		s.serveError(c, http.StatusBadRequest, "用户编号无效")
		return
	}
	var user model.User
	if s.DB.First(&user, id).Error != nil {
		s.serveError(c, http.StatusNotFound, "用户不存在")
		return
	}
	err = s.DB.Transaction(func(tx *gorm.DB) error {
		if deleteErr := tx.Where("user_id = ?", user.ID).Delete(&model.MFABackupCode{}).Error; deleteErr != nil {
			return deleteErr
		}
		if updateErr := tx.Model(&user).Updates(map[string]any{"mfa_enabled": false, "mfa_secret_encrypted": "", "mfa_backup_code_hashes": "[]"}).Error; updateErr != nil {
			return updateErr
		}
		now := time.Now()
		return tx.Model(&model.Session{}).Where("user_id = ? AND revoked_at IS NULL", user.ID).Update("revoked_at", &now).Error
	})
	if err != nil {
		s.serveError(c, http.StatusInternalServerError, "重置 MFA 失败")
		return
	}
	s.audit(c, "admin.mfa_reset", s.user(c).ID, fmt.Sprintf("target_user_id=%d", user.ID))
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func (s *Server) adminListChannels(c *gin.Context) {
	var emailCount int64
	_ = s.DB.Model(&model.UserEmail{}).Count(&emailCount).Error
	items := []gin.H{{"kind": "email", "display_name": "邮箱", "bindings": emailCount}}
	var providers []model.UpstreamProvider
	_ = s.DB.Order("id ASC").Find(&providers).Error
	for _, provider := range providers {
		var total int64
		_ = s.DB.Model(&model.UpstreamIdentity{}).Where("provider_id = ?", provider.ID).Count(&total).Error
		items = append(items, gin.H{"kind": provider.Kind, "display_name": provider.DisplayName, "provider_id": provider.ID, "enabled": provider.Enabled, "configured": providerConfigured(provider), "bindings": total})
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": items})
}

func (s *Server) adminListChannelBindings(c *gin.Context) {
	kind := strings.ToLower(c.Param("kind"))
	page, pageSize := pagination(c)
	if kind == "email" {
		query := s.DB.Model(&model.UserEmail{})
		var total int64
		_ = query.Count(&total).Error
		var records []model.UserEmail
		if err := query.Order("id ASC").Offset((page - 1) * pageSize).Limit(pageSize).Find(&records).Error; err != nil {
			s.serveError(c, http.StatusInternalServerError, "读取邮箱绑定失败")
			return
		}
		items := make([]gin.H, 0, len(records))
		for _, record := range records {
			var user model.User
			_ = s.DB.First(&user, record.UserID).Error
			items = append(items, gin.H{"id": record.ID, "user": publicUser(&user), "email": record.Email, "verified_at": record.VerifiedAt, "created_at": record.CreatedAt})
		}
		c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"items": items, "page": page, "page_size": pageSize, "total": total}})
		return
	}
	var provider model.UpstreamProvider
	if s.DB.Where("kind = ?", kind).First(&provider).Error != nil {
		s.serveError(c, http.StatusNotFound, "登录渠道不存在")
		return
	}
	query := s.DB.Model(&model.UpstreamIdentity{}).Where("provider_id = ?", provider.ID)
	var total int64
	_ = query.Count(&total).Error
	var records []model.UpstreamIdentity
	if err := query.Order("id ASC").Offset((page - 1) * pageSize).Limit(pageSize).Find(&records).Error; err != nil {
		s.serveError(c, http.StatusInternalServerError, "读取渠道绑定失败")
		return
	}
	items := make([]gin.H, 0, len(records))
	for _, record := range records {
		var user model.User
		_ = s.DB.First(&user, record.UserID).Error
		items = append(items, gin.H{"id": record.ID, "user": publicUser(&user), "external_id": record.ExternalID, "external_name": record.ExternalName, "external_email": record.ExternalEmail, "verified_at": record.VerifiedAt, "last_login_at": record.LastLoginAt, "created_at": record.CreatedAt})
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"items": items, "page": page, "page_size": pageSize, "total": total}})
}

func (s *Server) adminDeleteEmailBinding(c *gin.Context) {
	s.adminDeleteBinding(c, true)
}

func (s *Server) adminDeleteUpstreamBinding(c *gin.Context) {
	s.adminDeleteBinding(c, false)
}

func (s *Server) adminDeleteBinding(c *gin.Context, email bool) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		s.serveError(c, http.StatusBadRequest, "绑定信息无效")
		return
	}
	var userID uint64
	if email {
		var record model.UserEmail
		if s.DB.First(&record, id).Error != nil {
			s.serveError(c, http.StatusNotFound, "邮箱绑定不存在")
			return
		}
		userID = record.UserID
		if err := s.DB.Transaction(func(tx *gorm.DB) error { return s.deleteEmailBinding(tx, userID, id, true) }); err != nil {
			s.serveError(c, http.StatusInternalServerError, "删除邮箱绑定失败")
			return
		}
	} else {
		var record model.UpstreamIdentity
		if s.DB.First(&record, id).Error != nil {
			s.serveError(c, http.StatusNotFound, "第三方绑定不存在")
			return
		}
		userID = record.UserID
		if err := s.DB.Transaction(func(tx *gorm.DB) error { return s.deleteUpstreamBinding(tx, userID, id, true) }); err != nil {
			s.serveError(c, http.StatusInternalServerError, "删除第三方绑定失败")
			return
		}
	}
	s.audit(c, "admin.binding_deleted", s.user(c).ID, fmt.Sprintf("target_user_id=%d", userID))
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func (s *Server) adminGetSettings(c *gin.Context) {
	data := gin.H{
		settingRegistrationEnabled: s.settingBool(settingRegistrationEnabled, s.Cfg.RegistrationEnabled),
		settingSMTPHost:            s.setting(settingSMTPHost, ""), settingSMTPPort: s.setting(settingSMTPPort, "587"),
		settingSMTPUsername: s.setting(settingSMTPUsername, ""), settingSMTPFrom: s.setting(settingSMTPFrom, ""),
		settingCaptchaMode: s.setting(settingCaptchaMode, "none"), settingTurnstileSiteKey: s.setting(settingTurnstileSiteKey, ""),
		settingCAPSiteKey: s.setting(settingCAPSiteKey, ""), settingCAPServerURL: s.setting(settingCAPServerURL, "http://cap:3000"),
		"smtp_password_configured":    s.settingConfigured(settingSMTPPassword),
		"turnstile_secret_configured": s.settingConfigured(settingTurnstileSecretKey),
		"cap_secret_configured":       s.settingConfigured(settingCAPSecretKey),
		"email_debug":                 s.Cfg.EmailDebug,
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": data})
}

func (s *Server) adminUpdateSettings(c *gin.Context) {
	var input map[string]any
	if err := c.ShouldBindJSON(&input); err != nil {
		s.serveError(c, http.StatusBadRequest, "请求格式错误")
		return
	}
	allowed := map[string]bool{
		settingRegistrationEnabled: true, settingSMTPHost: true, settingSMTPPort: true, settingSMTPUsername: true,
		settingSMTPPassword: true, settingSMTPFrom: true, settingCaptchaMode: true, settingTurnstileSiteKey: true,
		settingTurnstileSecretKey: true, settingCAPSiteKey: true, settingCAPSecretKey: true, settingCAPServerURL: true,
	}
	values := map[string]string{}
	for key, value := range input {
		if !allowed[key] {
			s.serveError(c, http.StatusBadRequest, "包含不支持的设置项: "+key)
			return
		}
		switch typed := value.(type) {
		case string:
			values[key] = strings.TrimSpace(typed)
		case bool:
			values[key] = strconv.FormatBool(typed)
		default:
			s.serveError(c, http.StatusBadRequest, "设置值格式无效: "+key)
			return
		}
	}
	mode := values[settingCaptchaMode]
	if mode == "" {
		mode = s.setting(settingCaptchaMode, "none")
	}
	if err := validateCaptchaSettings(mode, values, s.setting); err != nil {
		s.serveError(c, http.StatusBadRequest, err.Error())
		return
	}
	if port := values[settingSMTPPort]; port != "" {
		parsed, err := strconv.Atoi(port)
		if err != nil || parsed < 1 || parsed > 65535 {
			s.serveError(c, http.StatusBadRequest, "SMTP 端口无效")
			return
		}
	}
	if err := s.DB.Transaction(func(tx *gorm.DB) error {
		for key, value := range values {
			if err := s.saveSetting(tx, key, value); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		s.serveError(c, http.StatusInternalServerError, "保存系统设置失败")
		return
	}
	s.audit(c, "admin.settings_updated", s.user(c).ID, strings.Join(mapKeys(values), ","))
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func mapKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	return keys
}

func (s *Server) adminTestEmail(c *gin.Context) {
	var input struct {
		Email string `json:"email"`
	}
	if err := c.ShouldBindJSON(&input); err != nil || !validEmail(strings.ToLower(strings.TrimSpace(input.Email))) {
		s.serveError(c, http.StatusBadRequest, "测试邮箱无效")
		return
	}
	if err := s.sendVerificationEmail(input.Email, "123456", s.user(c).Locale); err != nil {
		s.serveError(c, http.StatusBadGateway, "测试邮件发送失败: "+err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func (s *Server) adminListProviders(c *gin.Context) {
	var providers []model.UpstreamProvider
	if err := s.DB.Order("id ASC").Find(&providers).Error; err != nil {
		s.serveError(c, http.StatusInternalServerError, "读取 Provider 失败")
		return
	}
	items := make([]gin.H, 0, len(providers))
	for _, provider := range providers {
		items = append(items, gin.H{
			"id": provider.ID, "kind": provider.Kind, "display_name": provider.DisplayName, "client_id": provider.ClientID,
			"issuer_url": provider.IssuerURL, "authorization_url": provider.AuthorizationURL, "token_url": provider.TokenURL,
			"user_info_url": provider.UserInfoURL, "email_info_url": provider.EmailInfoURL, "scopes": provider.Scopes,
			"enabled": provider.Enabled, "secret_configured": provider.ClientSecretEncrypted != "",
			"callback_url": s.Cfg.Issuer + "/oauth/upstream/" + provider.Kind + "/callback",
		})
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": items})
}

func (s *Server) adminUpdateProvider(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		s.serveError(c, http.StatusBadRequest, "Provider 编号无效")
		return
	}
	var provider model.UpstreamProvider
	if s.DB.First(&provider, id).Error != nil {
		s.serveError(c, http.StatusNotFound, "Provider 不存在")
		return
	}
	var input struct {
		DisplayName      string `json:"display_name"`
		ClientID         string `json:"client_id"`
		ClientSecret     string `json:"client_secret"`
		IssuerURL        string `json:"issuer_url"`
		AuthorizationURL string `json:"authorization_url"`
		TokenURL         string `json:"token_url"`
		UserInfoURL      string `json:"user_info_url"`
		EmailInfoURL     string `json:"email_info_url"`
		Scopes           string `json:"scopes"`
		Enabled          bool   `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		s.serveError(c, http.StatusBadRequest, "请求格式错误")
		return
	}
	if strings.TrimSpace(input.DisplayName) == "" || len(input.DisplayName) > 64 {
		s.serveError(c, http.StatusBadRequest, "显示名称无效")
		return
	}
	for _, rawURL := range []string{input.IssuerURL, input.AuthorizationURL, input.TokenURL, input.UserInfoURL, input.EmailInfoURL} {
		if !validateURL(rawURL, true) {
			s.serveError(c, http.StatusBadRequest, "Provider URL 无效")
			return
		}
	}
	updates := map[string]any{
		"display_name": strings.TrimSpace(input.DisplayName), "client_id": strings.TrimSpace(input.ClientID),
		"issuer_url": strings.TrimRight(strings.TrimSpace(input.IssuerURL), "/"), "authorization_url": strings.TrimSpace(input.AuthorizationURL),
		"token_url": strings.TrimSpace(input.TokenURL), "user_info_url": strings.TrimSpace(input.UserInfoURL),
		"email_info_url": strings.TrimSpace(input.EmailInfoURL), "scopes": strings.TrimSpace(input.Scopes), "enabled": input.Enabled,
	}
	if input.ClientSecret != "" {
		encrypted, err := security.Encrypt(s.Cfg.MasterKey, input.ClientSecret)
		if err != nil {
			s.serveError(c, http.StatusInternalServerError, "加密 Provider 密钥失败")
			return
		}
		updates["client_secret_encrypted"] = encrypted
		provider.ClientSecretEncrypted = encrypted
	}
	provider.ClientID = strings.TrimSpace(input.ClientID)
	if input.Enabled && !providerConfigured(provider) {
		s.serveError(c, http.StatusBadRequest, "启用前必须完整配置客户端凭据")
		return
	}
	if err := s.DB.Model(&provider).Updates(updates).Error; err != nil {
		s.serveError(c, http.StatusInternalServerError, "保存 Provider 失败")
		return
	}
	s.audit(c, "admin.provider_updated", s.user(c).ID, provider.Kind)
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func (s *Server) adminTestProvider(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		s.serveError(c, http.StatusBadRequest, "Provider 编号无效")
		return
	}
	var providerRecord model.UpstreamProvider
	if s.DB.First(&providerRecord, id).Error != nil || !providerConfigured(providerRecord) {
		s.serveError(c, http.StatusBadRequest, "Provider 尚未完整配置")
		return
	}
	if providerRecord.Kind == "telegram" {
		c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"configured": true}})
		return
	}
	provider, err := s.buildUpstreamProvider(providerRecord)
	if err != nil {
		s.serveError(c, http.StatusBadGateway, "Provider 初始化失败: "+err.Error())
		return
	}
	_, err = provider.AuthorizationURL(c.Request.Context(), upstream.AuthorizationRequest{RedirectURL: s.Cfg.Issuer + "/oauth/upstream/" + providerRecord.Kind + "/callback", State: "configuration-test", CodeChallenge: "configuration-test", CodeChallengeMethod: "S256"})
	if err != nil {
		s.serveError(c, http.StatusBadGateway, "Provider 连接测试失败: "+err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"configured": true}})
}
