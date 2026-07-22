package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Cong0707/sso/internal/model"
	"github.com/Cong0707/sso/internal/security"
	"github.com/gin-gonic/gin"
)

type appRequest struct {
	Name        string `json:"name"`
	Homepage    string `json:"homepage"`
	Description string `json:"description"`
	RedirectURI string `json:"redirect_uri"`
	LogoURL     string `json:"logo_url"`
	Public      bool   `json:"public"`
}

func (s *Server) listApps(c *gin.Context) {
	var apps []model.OAuthApplication
	if err := s.DB.Where("owner_id = ?", s.user(c).ID).Order("created_at DESC").Find(&apps).Error; err != nil {
		s.serveError(c, http.StatusInternalServerError, "读取应用失败")
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": apps})
}

func (s *Server) getApp(c *gin.Context) {
	app, ok := s.findOwnedApp(c)
	if !ok {
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": app})
}

func (s *Server) createApp(c *gin.Context) {
	var input appRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		s.serveError(c, http.StatusBadRequest, "请求格式错误")
		return
	}
	input.Name = strings.TrimSpace(input.Name)
	input.Homepage = strings.TrimSpace(input.Homepage)
	input.RedirectURI = strings.TrimSpace(input.RedirectURI)
	input.LogoURL = strings.TrimSpace(input.LogoURL)
	if len(input.Name) < 2 || len(input.Name) > 120 {
		s.serveError(c, http.StatusBadRequest, "应用名需为 2-120 个字符")
		return
	}
	if !validateURL(input.Homepage, true) || !validateURL(input.RedirectURI, false) || !validateURL(input.LogoURL, true) {
		s.serveError(c, http.StatusBadRequest, "主页、回调地址或图标地址格式不正确")
		return
	}
	clientID, err := security.RandomToken(18)
	if err != nil {
		s.serveError(c, http.StatusInternalServerError, "生成客户端标识失败")
		return
	}
	clientID = "sso_" + clientID
	secret, err := security.RandomToken(32)
	if err != nil {
		s.serveError(c, http.StatusInternalServerError, "生成客户端密钥失败")
		return
	}
	sum := sha256.Sum256([]byte(secret))
	app := model.OAuthApplication{OwnerID: s.user(c).ID, Name: input.Name, Homepage: input.Homepage, Description: input.Description, RedirectURI: input.RedirectURI, LogoURL: input.LogoURL, ClientID: clientID, ClientSecretHash: hex.EncodeToString(sum[:]), Public: input.Public, AllowedScopes: "openid profile email"}
	if err := s.DB.Create(&app).Error; err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") || strings.Contains(strings.ToLower(err.Error()), "duplicate") {
			s.serveError(c, http.StatusConflict, "应用名已存在")
			return
		}
		s.serveError(c, http.StatusInternalServerError, "创建应用失败")
		return
	}
	s.audit(c, "oauth_app.created", s.user(c).ID, app.ClientID)
	c.JSON(http.StatusCreated, gin.H{"success": true, "data": gin.H{"app": app, "client_secret": secret}})
}

func (s *Server) updateApp(c *gin.Context) {
	app, ok := s.findOwnedApp(c)
	if !ok {
		return
	}
	var input appRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		s.serveError(c, http.StatusBadRequest, "请求格式错误")
		return
	}
	input.Name = strings.TrimSpace(input.Name)
	input.Homepage = strings.TrimSpace(input.Homepage)
	input.RedirectURI = strings.TrimSpace(input.RedirectURI)
	input.LogoURL = strings.TrimSpace(input.LogoURL)
	if len(input.Name) < 2 || len(input.Name) > 120 || !validateURL(input.Homepage, true) || !validateURL(input.RedirectURI, false) || !validateURL(input.LogoURL, true) {
		s.serveError(c, http.StatusBadRequest, "应用字段格式不正确")
		return
	}
	app.Name, app.Homepage, app.Description, app.RedirectURI, app.LogoURL, app.Public = input.Name, input.Homepage, input.Description, input.RedirectURI, input.LogoURL, input.Public
	if err := s.DB.Save(app).Error; err != nil {
		s.serveError(c, http.StatusInternalServerError, "更新应用失败")
		return
	}
	s.audit(c, "oauth_app.updated", s.user(c).ID, app.ClientID)
	c.JSON(http.StatusOK, gin.H{"success": true, "data": app})
}

func (s *Server) deleteApp(c *gin.Context) {
	app, ok := s.findOwnedApp(c)
	if !ok {
		return
	}
	if err := s.DB.Delete(app).Error; err != nil {
		s.serveError(c, http.StatusInternalServerError, "删除应用失败")
		return
	}
	s.audit(c, "oauth_app.deleted", s.user(c).ID, app.ClientID)
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func (s *Server) rotateAppSecret(c *gin.Context) {
	app, ok := s.findOwnedApp(c)
	if !ok {
		return
	}
	secret, err := security.RandomToken(32)
	if err != nil {
		s.serveError(c, http.StatusInternalServerError, "生成客户端密钥失败")
		return
	}
	sum := sha256.Sum256([]byte(secret))
	app.ClientSecretHash = hex.EncodeToString(sum[:])
	if err := s.DB.Save(app).Error; err != nil {
		s.serveError(c, http.StatusInternalServerError, "轮换客户端密钥失败")
		return
	}
	s.audit(c, "oauth_app.secret_rotated", s.user(c).ID, app.ClientID)
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"client_secret": secret}})
}

func (s *Server) findOwnedApp(c *gin.Context) (*model.OAuthApplication, bool) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		s.serveError(c, http.StatusBadRequest, "应用编号无效")
		return nil, false
	}
	var app model.OAuthApplication
	if err := s.DB.Where("id = ? AND owner_id = ?", id, s.user(c).ID).First(&app).Error; err != nil {
		s.serveError(c, http.StatusNotFound, "应用不存在")
		return nil, false
	}
	return &app, true
}

func (s *Server) listAuthorizations(c *gin.Context) {
	var logs []model.AuthorizationLog
	if err := s.DB.Preload("App").Where("user_id = ?", s.user(c).ID).Order("created_at DESC").Limit(100).Find(&logs).Error; err != nil {
		s.serveError(c, http.StatusInternalServerError, "读取授权日志失败")
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": logs})
}

func (s *Server) listGrants(c *gin.Context) {
	var grants []model.Grant
	if err := s.DB.Preload("App").Where("user_id = ? AND revoked_at IS NULL", s.user(c).ID).Order("created_at DESC").Find(&grants).Error; err != nil {
		s.serveError(c, http.StatusInternalServerError, "读取授权应用失败")
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": grants})
}

func (s *Server) revokeGrant(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		s.serveError(c, http.StatusBadRequest, "授权编号无效")
		return
	}
	now := time.Now()
	result := s.DB.Model(&model.Grant{}).Where("id = ? AND user_id = ? AND revoked_at IS NULL", id, s.user(c).ID).Update("revoked_at", &now)
	if result.Error != nil {
		s.serveError(c, http.StatusInternalServerError, "撤销授权失败")
		return
	}
	if result.RowsAffected == 0 {
		s.serveError(c, http.StatusNotFound, "授权不存在")
		return
	}
	s.audit(c, "oauth_grant.revoked", s.user(c).ID, strconv.FormatUint(id, 10))
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func splitScopes(raw string) []string {
	var scopes []string
	if strings.HasPrefix(strings.TrimSpace(raw), "[") {
		_ = json.Unmarshal([]byte(raw), &scopes)
	} else {
		scopes = strings.Fields(strings.ReplaceAll(raw, ",", " "))
	}
	return scopes
}
