package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Cong0707/sso/internal/model"
	"github.com/Cong0707/sso/internal/security"
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
	if err := c.ShouldBindJSON(&input); err != nil || input.ID == 0 || input.Hash == "" || time.Since(time.Unix(input.AuthDate, 0)) > 24*time.Hour {
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
	values := map[string]string{"auth_date": strconv.FormatInt(input.AuthDate, 10), "id": strconv.FormatInt(input.ID, 10), "first_name": input.FirstName, "last_name": input.LastName, "photo_url": input.PhotoURL, "username": input.Username}
	parts := make([]string, 0, len(values))
	for key, value := range values {
		if value != "" {
			parts = append(parts, key+"="+value)
		}
	}
	sort.Strings(parts)
	secretKey := sha256.Sum256([]byte(botToken))
	mac := hmac.New(sha256.New, secretKey[:])
	_, _ = mac.Write([]byte(strings.Join(parts, "\n")))
	expected := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(strings.ToLower(input.Hash))) {
		s.serveError(c, http.StatusUnauthorized, "Telegram 签名校验失败")
		return
	}
	identity := upstreamIdentityData{ID: strconv.FormatInt(input.ID, 10), Name: strings.TrimSpace(strings.TrimSpace(input.FirstName + " " + input.LastName)), Avatar: input.PhotoURL}
	if identity.Name == "" {
		identity.Name = input.Username
	}
	user, err := s.resolveUpstreamUser(provider, identity)
	if err != nil {
		s.serveError(c, http.StatusConflict, err.Error())
		return
	}
	if _, err := s.createSession(c, &user); err != nil {
		s.serveError(c, http.StatusInternalServerError, "创建登录会话失败")
		return
	}
	s.audit(c, "upstream.login.telegram", user.ID, identity.ID)
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"user": publicUser(&user)}})
}

func (s *Server) resolveUpstreamUser(provider model.UpstreamProvider, identity upstreamIdentityData) (model.User, error) {
	var relation model.UpstreamIdentity
	if err := s.DB.Where("provider_id = ? AND external_id = ?", provider.ID, identity.ID).First(&relation).Error; err == nil {
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
	if err := s.DB.Create(&model.UpstreamIdentity{UserID: user.ID, ProviderID: provider.ID, ExternalID: identity.ID, ExternalName: identity.Name, ExternalEmail: identity.Email, LastLoginAt: time.Now()}).Error; err != nil {
		return model.User{}, err
	}
	return user, nil
}
