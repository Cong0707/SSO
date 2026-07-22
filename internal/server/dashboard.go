package server

import (
	"net/http"
	"time"

	"github.com/Cong0707/sso/internal/model"
	"github.com/gin-gonic/gin"
)

func (s *Server) dashboard(c *gin.Context) {
	userID := s.user(c).ID
	var apps, grants, devices, providers int64
	s.DB.Model(&model.OAuthApplication{}).Where("owner_id = ? AND disabled_at IS NULL", userID).Count(&apps)
	s.DB.Model(&model.AuthorizationLog{}).Where("user_id = ? AND status = ?", userID, "approved").Count(&grants)
	s.DB.Model(&model.Session{}).Where("user_id = ? AND revoked_at IS NULL AND expires_at > ?", userID, time.Now()).Count(&devices)
	s.DB.Model(&model.UpstreamProvider{}).Where("enabled = ? AND disabled_at IS NULL", true).Count(&providers)
	var recent []model.AuthorizationLog
	s.DB.Preload("App").Where("user_id = ?", userID).Order("created_at DESC").Limit(5).Find(&recent)
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"apps": apps, "authorizations": grants, "devices": devices, "providers": providers, "recent_authorizations": recent}})
}
