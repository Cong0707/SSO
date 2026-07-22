package server

import (
	"net/http"
	"strings"
	"time"

	"github.com/Cong0707/sso/internal/model"
	"github.com/Cong0707/sso/internal/security"
	"github.com/gin-gonic/gin"
)

func (s *Server) dashboard(c *gin.Context) {
	userID := s.user(c).ID
	var apps, grants, invites, providers int64
	s.DB.Model(&model.OAuthApplication{}).Where("owner_id = ? AND disabled_at IS NULL", userID).Count(&apps)
	s.DB.Model(&model.AuthorizationLog{}).Where("user_id = ? AND status = ?", userID, "approved").Count(&grants)
	s.DB.Model(&model.InviteCode{}).Where("creator_id = ? AND disabled_at IS NULL", userID).Count(&invites)
	s.DB.Model(&model.UpstreamProvider{}).Where("enabled = ? AND disabled_at IS NULL", true).Count(&providers)
	var recent []model.AuthorizationLog
	s.DB.Preload("App").Where("user_id = ?", userID).Order("created_at DESC").Limit(5).Find(&recent)
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"apps": apps, "authorizations": grants, "invites": invites, "providers": providers, "recent_authorizations": recent}})
}

func (s *Server) listInvites(c *gin.Context) {
	var invites []model.InviteCode
	if err := s.DB.Where("creator_id = ?", s.user(c).ID).Order("created_at DESC").Find(&invites).Error; err != nil {
		s.serveError(c, http.StatusInternalServerError, "读取邀请码失败")
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": invites})
}

func (s *Server) createInvite(c *gin.Context) {
	var input struct {
		MaxUses   int        `json:"max_uses"`
		ExpiresAt *time.Time `json:"expires_at"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		s.serveError(c, http.StatusBadRequest, "请求格式错误")
		return
	}
	if input.MaxUses < 0 || input.MaxUses > 10000 {
		s.serveError(c, http.StatusBadRequest, "使用次数需为 0-10000")
		return
	}
	code, err := security.RandomToken(12)
	if err != nil {
		s.serveError(c, http.StatusInternalServerError, "生成邀请码失败")
		return
	}
	code = "FZ-" + strings.ToUpper(code)
	invite := model.InviteCode{CreatorID: s.user(c).ID, Prefix: code[:8], CodeHash: security.HashToken(code), MaxUses: input.MaxUses, ExpiresAt: input.ExpiresAt}
	if err := s.DB.Create(&invite).Error; err != nil {
		s.serveError(c, http.StatusInternalServerError, "创建邀请码失败")
		return
	}
	s.audit(c, "invite.created", s.user(c).ID, invite.Prefix)
	c.JSON(http.StatusCreated, gin.H{"success": true, "data": gin.H{"invite": invite, "code": code}})
}
