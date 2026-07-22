package server

import (
	"net/http"
	"time"

	"github.com/Cong0707/sso/internal/model"
	"github.com/Cong0707/sso/internal/security"
	"github.com/Cong0707/sso/internal/upstream"
	"github.com/gin-gonic/gin"
)

type telegramLoginRequest struct {
	ID        int64  `json:"id"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Username  string `json:"username"`
	PhotoURL  string `json:"photo_url"`
	AuthDate  int64  `json:"auth_date"`
	Hash      string `json:"hash"`
}

func (s *Server) telegramLogin(c *gin.Context) {
	var input telegramLoginRequest
	if err := c.ShouldBindJSON(&input); err != nil || input.ID == 0 || input.Hash == "" {
		s.serveError(c, http.StatusBadRequest, "Telegram 登录数据无效")
		return
	}
	var provider model.UpstreamProvider
	if err := s.DB.Where("kind = ? AND enabled = ?", "telegram", true).First(&provider).Error; err != nil {
		s.serveError(c, http.StatusNotFound, "Telegram 未配置")
		return
	}
	botToken, err := security.Decrypt(s.Cfg.MasterKey, provider.ClientSecretEncrypted)
	if err != nil {
		s.serveError(c, http.StatusInternalServerError, "Telegram 密钥不可用")
		return
	}
	identity, err := upstream.VerifyTelegram(botToken, upstream.TelegramPayload{
		ID: input.ID, FirstName: input.FirstName, LastName: input.LastName, Username: input.Username,
		PhotoURL: input.PhotoURL, AuthDate: input.AuthDate, Hash: input.Hash,
	}, time.Now())
	if err != nil {
		s.serveError(c, http.StatusUnauthorized, "Telegram 登录数据无效")
		return
	}
	user, err := s.resolveUpstreamUser(provider, identity)
	if err != nil {
		s.serveError(c, http.StatusConflict, err.Error())
		return
	}
	if user.Status != "active" {
		s.serveError(c, http.StatusForbidden, "账号不可用")
		return
	}
	if _, err := s.createSession(c, &user); err != nil {
		s.serveError(c, http.StatusInternalServerError, "创建登录会话失败")
		return
	}
	s.audit(c, "upstream.login.telegram", user.ID, identity.Subject)
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"user": publicUser(&user)}})
}

func (s *Server) resolveUpstreamUser(provider model.UpstreamProvider, identity upstream.Identity) (model.User, error) {
	var relation model.UpstreamIdentity
	if err := s.DB.Where("provider_id = ? AND external_id = ?", provider.ID, identity.Subject).First(&relation).Error; err == nil {
		var user model.User
		if userErr := s.DB.First(&user, relation.UserID).Error; userErr != nil {
			return model.User{}, userErr
		}
		return user, nil
	}
	user, err := s.provisionUpstreamUser(provider, identity)
	if err != nil {
		return model.User{}, err
	}
	if err := s.DB.Create(&model.UpstreamIdentity{UserID: user.ID, ProviderID: provider.ID, ExternalID: identity.Subject, ExternalName: identity.Name, ExternalEmail: identity.Email, LastLoginAt: time.Now()}).Error; err != nil {
		return model.User{}, err
	}
	return user, nil
}
