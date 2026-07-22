package server

import (
	"encoding/json"
	"errors"
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

type registerRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (s *Server) register(c *gin.Context) {
	if !s.Cfg.RegistrationEnabled {
		s.serveError(c, http.StatusForbidden, "注册已关闭")
		return
	}
	var input registerRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		s.serveError(c, http.StatusBadRequest, "请求格式错误")
		return
	}
	input.Username = strings.TrimSpace(input.Username)
	input.Email = strings.ToLower(strings.TrimSpace(input.Email))
	if !usernamePattern.MatchString(input.Username) {
		s.serveError(c, http.StatusBadRequest, "用户名需为 3-32 位字母、数字、下划线或连字符")
		return
	}
	if !validEmail(input.Email) {
		s.serveError(c, http.StatusBadRequest, "邮箱格式不正确")
		return
	}
	if message := validatePassword(input.Password); message != "" {
		s.serveError(c, http.StatusBadRequest, message)
		return
	}
	passwordHash, err := security.HashPassword(input.Password)
	if err != nil {
		s.serveError(c, http.StatusInternalServerError, "密码处理失败")
		return
	}

	var user model.User
	err = s.DB.Transaction(func(tx *gorm.DB) error {
		var count int64
		if err := tx.Model(&model.User{}).Count(&count).Error; err != nil {
			return err
		}
		role := "user"
		if count == 0 {
			role = "admin"
		}
		user = model.User{Username: input.Username, Email: input.Email, PasswordHash: passwordHash, PasswordConfigured: true, DisplayName: input.Username, Locale: "zh-CN", SecurityEmailEnabled: true, Role: role, Status: "active"}
		if err := tx.Create(&user).Error; err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "unique") || strings.Contains(strings.ToLower(err.Error()), "duplicate") {
				return errors.New("用户名或邮箱已被使用")
			}
			return err
		}
		return tx.Create(&model.AuditEvent{UserID: user.ID, Action: "account.registered", IP: clientIP(c), UserAgent: c.Request.UserAgent()}).Error
	})
	if err != nil {
		s.serveError(c, http.StatusConflict, err.Error())
		return
	}
	session, err := s.createSession(c, &user)
	if err != nil {
		s.serveError(c, http.StatusInternalServerError, "创建登录会话失败")
		return
	}
	c.JSON(http.StatusCreated, gin.H{"success": true, "data": gin.H{"user": publicUser(&user), "csrf_token": session.CSRFToken}})
}

type loginRequest struct {
	Identifier string `json:"identifier"`
	Password   string `json:"password"`
	Code       string `json:"code"`
}

func (s *Server) login(c *gin.Context) {
	var input loginRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		s.serveError(c, http.StatusBadRequest, "请求格式错误")
		return
	}
	identifier := strings.ToLower(strings.TrimSpace(input.Identifier))
	var user model.User
	if err := s.DB.Where("LOWER(username) = ? OR LOWER(email) = ?", identifier, identifier).First(&user).Error; err != nil || !user.PasswordConfigured || !security.VerifyPassword(user.PasswordHash, input.Password) {
		if user.ID != 0 {
			s.audit(c, "login.failed", user.ID, "")
		}
		s.serveError(c, http.StatusUnauthorized, "用户名、邮箱或密码错误")
		return
	}
	if user.Status != "active" {
		s.serveError(c, http.StatusForbidden, "账号不可用")
		return
	}
	if strings.HasPrefix(user.PasswordHash, "$2a$") || strings.HasPrefix(user.PasswordHash, "$2b$") || strings.HasPrefix(user.PasswordHash, "$2y$") {
		if upgraded, hashErr := security.HashPassword(input.Password); hashErr == nil {
			_ = s.DB.Model(&user).Update("password_hash", upgraded).Error
			user.PasswordHash = upgraded
		}
	}
	if user.MFAEnabled {
		if strings.TrimSpace(input.Code) == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "请输入二次验证码", "data": gin.H{"mfa_required": true}})
			return
		}
		if !s.verifyMFA(&user, strings.TrimSpace(input.Code)) {
			s.audit(c, "login.mfa_failed", user.ID, "")
			c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "二次验证码无效", "data": gin.H{"mfa_required": true}})
			return
		}
	}

	now := time.Now()
	user.LastLoginAt = &now
	s.DB.Model(&user).Update("last_login_at", &now)
	session, err := s.createSession(c, &user)
	if err != nil {
		s.serveError(c, http.StatusInternalServerError, "创建登录会话失败")
		return
	}
	s.audit(c, "login.succeeded", user.ID, "")
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"user": publicUser(&user), "csrf_token": session.CSRFToken}})
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
			s.DB.Model(user).Update("mfa_backup_code_hashes", string(encoded))
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
