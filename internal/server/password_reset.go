package server

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Cong0707/sso/internal/model"
	"github.com/Cong0707/sso/internal/security"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func (s *Server) passwordResetPrepare(c *gin.Context) {
	var input struct {
		Email        string `json:"email"`
		CaptchaToken string `json:"captcha_token"`
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
	if !s.enforceRateLimitPair(c, "password_reset", email, s.Cfg.RateLimitEmail, time.Hour) {
		return
	}
	if err := s.verifyCaptcha(input.CaptchaToken, clientIP(c)); err != nil {
		s.serveError(c, http.StatusBadRequest, err.Error())
		return
	}

	var user model.User
	findErr := s.DB.
		Joins("JOIN user_emails ON user_emails.user_id = users.id").
		Where("user_emails.normalized_email = ? AND users.status = ?", email, "active").
		Order("user_emails.id ASC").
		First(&user).Error
	if findErr != nil && !errors.Is(findErr, gorm.ErrRecordNotFound) {
		s.serveError(c, http.StatusInternalServerError, "创建密码重置流程失败")
		return
	}

	code, err := numericCode()
	if err != nil {
		s.serveError(c, http.StatusInternalServerError, "创建密码重置流程失败")
		return
	}
	now := time.Now()
	var userID *uint64
	if findErr == nil {
		userID = &user.ID
	}
	raw, flow, err := s.createAuthFlow(model.AuthFlow{
		Purpose:              "password_reset",
		Identifier:           email,
		Email:                email,
		Locale:               requestLocale(input.Locale, c.GetHeader("Accept-Language")),
		UserID:               userID,
		VerificationCodeHash: security.HMACToken(s.Cfg.MasterKey, code),
		LastSentAt:           &now,
		ExpiresAt:            now.Add(10 * time.Minute),
	})
	if err != nil {
		s.serveError(c, http.StatusInternalServerError, "创建密码重置流程失败")
		return
	}
	data := gin.H{"flow_token": raw, "resend_after": 60, "expires_in": 600}
	if userID != nil {
		if err := s.sendPasswordResetEmail(email, code, flow.Locale); err != nil {
			if !s.Cfg.EmailDebug {
				_ = s.DB.Model(&flow).Update("used_at", &now).Error
			}
		}
		if s.Cfg.EmailDebug {
			data["debug_code"] = code
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "如果该邮箱对应可用账号，密码重置验证码已发送",
		"data":    data,
	})
}

func (s *Server) passwordResetComplete(c *gin.Context) {
	var input struct {
		FlowToken       string `json:"flow_token"`
		Code            string `json:"code"`
		NewPassword     string `json:"new_password"`
		ConfirmPassword string `json:"confirm_password"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		s.serveError(c, http.StatusBadRequest, "请求格式错误")
		return
	}
	if input.NewPassword != input.ConfirmPassword {
		s.serveError(c, http.StatusBadRequest, "两次输入的密码不一致")
		return
	}
	if message := validatePassword(input.NewPassword); message != "" {
		s.serveError(c, http.StatusBadRequest, message)
		return
	}
	flow, err := s.loadAuthFlow(input.FlowToken, "password_reset")
	if err != nil {
		s.serveError(c, http.StatusBadRequest, "密码重置流程已过期")
		return
	}
	attempt := s.DB.Model(&model.AuthFlow{}).
		Where("id = ? AND purpose = ? AND used_at IS NULL AND expires_at > ? AND attempts < ?", flow.ID, "password_reset", time.Now(), 8).
		UpdateColumn("attempts", gorm.Expr("attempts + 1"))
	if attempt.Error != nil {
		s.serveError(c, http.StatusInternalServerError, "验证密码重置流程失败")
		return
	}
	if attempt.RowsAffected != 1 || flow.UserID == nil || !security.ConstantTimeHMACMatch(s.Cfg.MasterKey, flow.VerificationCodeHash, strings.TrimSpace(input.Code)) {
		s.serveError(c, http.StatusUnauthorized, "验证码无效或账号不可用")
		return
	}
	passwordHash, err := security.HashPassword(input.NewPassword)
	if err != nil {
		s.serveError(c, http.StatusInternalServerError, "密码处理失败")
		return
	}
	now := time.Now()
	err = s.DB.Transaction(func(tx *gorm.DB) error {
		var user model.User
		if err := tx.Where("id = ? AND status = ?", *flow.UserID, "active").First(&user).Error; err != nil {
			return err
		}
		var verifiedEmailCount int64
		if err := tx.Model(&model.UserEmail{}).
			Where("user_id = ? AND normalized_email = ?", user.ID, flow.Email).
			Count(&verifiedEmailCount).Error; err != nil || verifiedEmailCount != 1 {
			if err != nil {
				return err
			}
			return errors.New("verified reset email is no longer bound")
		}
		claim := tx.Model(&model.AuthFlow{}).
			Where("id = ? AND used_at IS NULL", flow.ID).
			Update("used_at", &now)
		if claim.Error != nil || claim.RowsAffected != 1 {
			return errors.New("password reset flow already used")
		}
		if err := tx.Model(&user).Updates(map[string]any{
			"password_hash":       passwordHash,
			"password_configured": true,
		}).Error; err != nil {
			return err
		}
		if err := tx.Model(&model.Session{}).
			Where("user_id = ? AND revoked_at IS NULL", user.ID).
			Update("revoked_at", &now).Error; err != nil {
			return err
		}
		if err := tx.Model(&model.PersonalAccessToken{}).
			Where("user_id = ? AND revoked_at IS NULL", user.ID).
			Update("revoked_at", &now).Error; err != nil {
			return err
		}
		if err := revokeOAuthTokens(tx, "user_id = ?", user.ID); err != nil {
			return err
		}
		if err := tx.Model(&model.AuthFlow{}).
			Where("user_id = ? AND purpose = ? AND used_at IS NULL", user.ID, "password_reset").
			Update("used_at", &now).Error; err != nil {
			return err
		}
		return tx.Create(&model.AuditEvent{
			UserID: user.ID, Action: "password.reset",
			IP: clientIP(c), UserAgent: c.Request.UserAgent(),
		}).Error
	})
	if err != nil {
		s.serveError(c, http.StatusConflict, "密码重置流程已失效，请重新开始")
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true})
}
