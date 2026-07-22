package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Cong0707/sso/internal/config"
	"github.com/Cong0707/sso/internal/model"
	"github.com/Cong0707/sso/internal/security"
	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4"
	oauthErrors "github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/generates"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"
	"gorm.io/gorm"
)

const sessionCookie = "sso_session"

type Server struct {
	Cfg       config.Config
	DB        *gorm.DB
	OAuth     *server.Server
	Clients   *clientStore
	Tokens    oauth2.TokenStore
	OIDCKey   *rsa.PrivateKey
	OIDCKeyID string
}

func New(cfg config.Config, db *gorm.DB) (*Server, error) {
	tokenStore, err := store.NewFileTokenStore(cfg.OAuthTokenDB)
	if err != nil {
		return nil, fmt.Errorf("open OAuth token store: %w", err)
	}
	key, err := loadSigningKey(filepath.Join(filepath.Dir(cfg.DatabaseDSN), "oidc-signing.pem"))
	if err != nil {
		return nil, err
	}

	publicKeyDER := x509.MarshalPKCS1PublicKey(&key.PublicKey)
	keyHash := sha256.Sum256(publicKeyDER)
	app := &Server{Cfg: cfg, DB: db, Clients: &clientStore{db: db}, Tokens: tokenStore, OIDCKey: key, OIDCKeyID: "sso-" + base64.RawURLEncoding.EncodeToString(keyHash[:8])}
	manager := manage.NewDefaultManager()
	manager.SetAuthorizeCodeExp(5 * time.Minute)
	manager.SetAuthorizeCodeTokenCfg(&manage.Config{AccessTokenExp: 15 * time.Minute, RefreshTokenExp: 30 * 24 * time.Hour, IsGenerateRefresh: true})
	manager.SetRefreshTokenCfg(&manage.RefreshingConfig{AccessTokenExp: 15 * time.Minute, RefreshTokenExp: 30 * 24 * time.Hour, IsGenerateRefresh: true, IsRemoveAccess: true, IsRemoveRefreshing: true})
	manager.MapAuthorizeGenerate(generates.NewAuthorizeGenerate())
	manager.MapAccessGenerate(generates.NewAccessGenerate())
	manager.MapClientStorage(app.Clients)
	manager.MapTokenStorage(tokenStore)
	manager.SetValidateURIHandler(func(registered, requested string) error {
		if registered != requested {
			return oauthErrors.ErrInvalidRedirectURI
		}
		return nil
	})
	manager.SetExtractExtensionHandler(func(req *oauth2.TokenGenerateRequest, token oauth2.ExtendableTokenInfo) {
		if req.Request != nil {
			if nonce := req.Request.FormValue("nonce"); nonce != "" {
				token.GetExtension().Set("nonce", nonce)
			}
			if req.Request.FormValue("response_type") != "" {
				token.GetExtension().Set("auth_time", strconv.FormatInt(time.Now().Unix(), 10))
			}
		}
	})

	oauthServer := server.NewServer(server.NewConfig(), manager)
	oauthServer.Config.ForcePKCE = true
	oauthServer.SetAllowedResponseType(oauth2.Code)
	oauthServer.SetAllowedGrantType(oauth2.AuthorizationCode, oauth2.Refreshing)
	oauthServer.SetClientInfoHandler(clientInfoHandler)
	oauthServer.SetUserAuthorizationHandler(app.oauthUserAuthorization)
	oauthServer.SetClientAuthorizedHandler(app.oauthClientAuthorized)
	oauthServer.SetClientScopeHandler(app.oauthClientScope)
	oauthServer.SetExtensionFieldsHandler(app.oidcExtensionFields)
	oauthServer.SetInternalErrorHandler(func(err error) (response *oauthErrors.Response) {
		return &oauthErrors.Response{Error: err}
	})
	app.OAuth = oauthServer

	if err := seedProviders(db, cfg); err != nil {
		return nil, err
	}
	return app, nil
}

func (s *Server) Router() *gin.Engine {
	router := gin.New()
	router.Use(gin.Logger(), gin.Recovery(), s.requestContext)
	router.GET("/healthz", s.health)
	router.GET("/.well-known/openid-configuration", s.oidcDiscovery)
	router.GET("/oauth/jwks.json", s.jwks)
	router.GET("/oauth/authorize", s.oauthAuthorize)
	router.POST("/oauth/authorize", s.oauthAuthorize)
	router.POST("/oauth/token", s.oauthToken)
	router.POST("/oauth/revoke", s.oauthRevoke)
	router.GET("/oauth/userinfo", s.oauthUserInfo)
	router.POST("/oauth/userinfo", s.oauthUserInfo)
	router.GET("/oauth/upstream/:kind/start", s.upstreamStart)
	router.GET("/oauth/upstream/:kind/callback", s.upstreamCallback)
	router.GET("/verify-email", s.verifyEmail)
	router.GET("/media/avatars/:file", s.avatarFile)

	api := router.Group("/api")
	api.GET("/auth/me", s.currentUser)
	api.POST("/auth/register", s.register)
	api.POST("/auth/login", s.login)
	api.POST("/auth/telegram", s.telegramLogin)
	api.POST("/auth/logout", s.requireAuth, s.requireSession, s.requireCSRF, s.logout)
	api.POST("/auth/logout-all", s.requireAuth, s.requireSession, s.requireCSRF, s.logoutAll)
	api.GET("/oauth/consent", s.requireAuth, s.oauthConsentInfo)
	api.POST("/oauth/consent", s.requireAuth, s.requireCSRF, s.oauthConsent)
	api.GET("/dashboard", s.requireAuth, s.dashboard)
	api.GET("/apps", s.requireAuth, s.listApps)
	api.POST("/apps", s.requireAuth, s.requireCSRF, s.createApp)
	api.GET("/apps/:id", s.requireAuth, s.getApp)
	api.PATCH("/apps/:id", s.requireAuth, s.requireCSRF, s.updateApp)
	api.DELETE("/apps/:id", s.requireAuth, s.requireCSRF, s.deleteApp)
	api.POST("/apps/:id/rotate-secret", s.requireAuth, s.requireCSRF, s.rotateAppSecret)
	api.GET("/authorizations", s.requireAuth, s.listAuthorizations)
	api.GET("/grants", s.requireAuth, s.listGrants)
	api.DELETE("/grants/:id", s.requireAuth, s.requireCSRF, s.revokeGrant)
	api.GET("/profile", s.requireAuth, s.profile)
	api.PATCH("/profile", s.requireAuth, s.requireCSRF, s.updateProfile)
	api.POST("/profile/avatar", s.requireAuth, s.requireSession, s.requireCSRF, s.uploadAvatar)
	api.POST("/profile/email-verification", s.requireAuth, s.requireSession, s.requireCSRF, s.sendEmailVerification)
	api.POST("/profile/password", s.requireAuth, s.requireSession, s.requireCSRF, s.changePassword)
	api.POST("/profile/mfa/setup", s.requireAuth, s.requireSession, s.requireCSRF, s.setupMFA)
	api.POST("/profile/mfa/enable", s.requireAuth, s.requireSession, s.requireCSRF, s.enableMFA)
	api.POST("/profile/mfa/disable", s.requireAuth, s.requireSession, s.requireCSRF, s.disableMFA)
	api.GET("/profile/sessions", s.requireAuth, s.requireSession, s.listSessions)
	api.DELETE("/profile/sessions/:id", s.requireAuth, s.requireSession, s.requireCSRF, s.revokeSession)
	api.GET("/profile/tokens", s.requireAuth, s.listPATs)
	api.POST("/profile/tokens", s.requireAuth, s.requireSession, s.requireCSRF, s.createPAT)
	api.DELETE("/profile/tokens/:id", s.requireAuth, s.requireSession, s.requireCSRF, s.revokePAT)
	api.GET("/profile/audit", s.requireAuth, s.listAudit)
	api.GET("/profile/export", s.requireAuth, s.exportData)
	api.DELETE("/profile", s.requireAuth, s.requireSession, s.requireCSRF, s.deleteAccount)
	api.GET("/providers", s.listProviders)
	api.GET("/invites", s.requireAuth, s.listInvites)
	api.POST("/invites", s.requireAuth, s.requireCSRF, s.createInvite)

	router.NoRoute(s.serveWeb)
	return router
}

func (s *Server) requestContext(c *gin.Context) {
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("X-Frame-Options", "DENY")
	c.Header("Referrer-Policy", "same-origin")
	c.Header("Content-Security-Policy", "default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline'; script-src 'self'")
	c.Next()
}

func (s *Server) health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok", "service": "sso"})
}

func (s *Server) serveWeb(c *gin.Context) {
	path := c.Request.URL.Path
	if strings.HasPrefix(path, "/api/") || strings.HasPrefix(path, "/oauth/") {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "message": "接口不存在"})
		return
	}
	if path == "/" || strings.HasPrefix(path, "/dashboard") || strings.HasPrefix(path, "/apps") || strings.HasPrefix(path, "/authorizations") || strings.HasPrefix(path, "/grants") || strings.HasPrefix(path, "/profile") || strings.HasPrefix(path, "/consent") || strings.HasPrefix(path, "/login") || strings.HasPrefix(path, "/register") {
		path = "/index.html"
	}
	file := filepath.Join(s.Cfg.WebDir, filepath.Clean(strings.TrimPrefix(path, "/")))
	if stat, err := os.Stat(file); err == nil && !stat.IsDir() {
		c.File(file)
		return
	}
	index := filepath.Join(s.Cfg.WebDir, "index.html")
	if _, err := os.Stat(index); err == nil {
		c.File(index)
		return
	}
	c.String(http.StatusNotFound, "SSO frontend is not built. Run npm install && npm run build in web/.")
}

func (s *Server) currentUser(c *gin.Context) {
	user, session, err := s.sessionUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "未登录"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"user": publicUser(user), "csrf_token": session.CSRFToken}})
}

func (s *Server) requireAuth(c *gin.Context) {
	user, session, err := s.sessionUser(c)
	if err != nil {
		patUser, pat, patErr := s.patUser(c)
		if patErr != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "登录已失效"})
			c.Abort()
			return
		}
		c.Set("user", patUser)
		c.Set("pat", pat)
		c.Next()
		return
	}
	c.Set("user", user)
	c.Set("session", session)
	c.Next()
}

func (s *Server) requireSession(c *gin.Context) {
	if _, ok := c.Get("session"); !ok {
		c.JSON(http.StatusForbidden, gin.H{"success": false, "message": "此操作需要浏览器登录会话"})
		c.Abort()
		return
	}
	c.Next()
}

func (s *Server) requireCSRF(c *gin.Context) {
	if _, ok := c.Get("pat"); ok {
		c.Next()
		return
	}
	session, ok := c.MustGet("session").(*model.Session)
	if !ok || session.CSRFToken == "" || c.GetHeader("X-CSRF-Token") != session.CSRFToken {
		c.JSON(http.StatusForbidden, gin.H{"success": false, "message": "CSRF 校验失败"})
		c.Abort()
		return
	}
	c.Next()
}

func (s *Server) patUser(c *gin.Context) (*model.User, *model.PersonalAccessToken, error) {
	authorization := c.GetHeader("Authorization")
	if !strings.HasPrefix(authorization, "Bearer sso_pat_") {
		return nil, nil, errors.New("missing PAT")
	}
	raw := strings.TrimPrefix(authorization, "Bearer ")
	var pat model.PersonalAccessToken
	if err := s.DB.Where("token_hash = ? AND revoked_at IS NULL", security.HashToken(raw)).First(&pat).Error; err != nil {
		return nil, nil, err
	}
	if pat.ExpiresAt != nil && pat.ExpiresAt.Before(time.Now()) {
		return nil, nil, errors.New("expired PAT")
	}
	var user model.User
	if err := s.DB.First(&user, pat.UserID).Error; err != nil || user.Status != "active" {
		return nil, nil, errors.New("invalid PAT user")
	}
	now := time.Now()
	_ = s.DB.Model(&pat).Update("last_used_at", &now).Error
	return &user, &pat, nil
}

func (s *Server) sessionUser(c *gin.Context) (*model.User, *model.Session, error) {
	raw, err := c.Cookie(sessionCookie)
	if err != nil || raw == "" {
		return nil, nil, errors.New("missing session")
	}
	var session model.Session
	if err := s.DB.Where("token_hash = ? AND revoked_at IS NULL", security.HashToken(raw)).First(&session).Error; err != nil {
		return nil, nil, err
	}
	if session.ExpiresAt.Before(time.Now()) {
		now := time.Now()
		s.DB.Model(&session).Update("revoked_at", &now)
		return nil, nil, errors.New("expired session")
	}
	var user model.User
	if err := s.DB.First(&user, session.UserID).Error; err != nil || user.Status != "active" {
		return nil, nil, errors.New("invalid user")
	}
	s.DB.Model(&session).Updates(map[string]any{"last_seen_at": time.Now(), "ip": clientIP(c), "user_agent": c.Request.UserAgent()})
	return &user, &session, nil
}

func (s *Server) createSession(c *gin.Context, user *model.User) (model.Session, error) {
	token, err := security.RandomToken(32)
	if err != nil {
		return model.Session{}, err
	}
	csrf, err := security.RandomToken(24)
	if err != nil {
		return model.Session{}, err
	}
	now := time.Now()
	session := model.Session{UserID: user.ID, TokenHash: security.HashToken(token), CSRFToken: csrf, DeviceName: deviceName(c.Request.UserAgent()), IP: clientIP(c), UserAgent: c.Request.UserAgent(), LastSeenAt: now, ExpiresAt: now.Add(s.Cfg.SessionTTL)}
	if err := s.DB.Create(&session).Error; err != nil {
		return model.Session{}, err
	}
	cookie := &http.Cookie{Name: sessionCookie, Value: token, Path: "/", HttpOnly: true, Secure: s.Cfg.CookieSecure, SameSite: http.SameSiteLaxMode, Expires: session.ExpiresAt}
	http.SetCookie(c.Writer, cookie)
	return session, nil
}

func (s *Server) revokeCurrentSession(c *gin.Context) {
	if session, ok := c.Get("session"); ok {
		now := time.Now()
		s.DB.Model(session.(*model.Session)).Update("revoked_at", &now)
	}
	cookie := &http.Cookie{Name: sessionCookie, Value: "", Path: "/", HttpOnly: true, Secure: s.Cfg.CookieSecure, SameSite: http.SameSiteLaxMode, MaxAge: -1}
	http.SetCookie(c.Writer, cookie)
}

func (s *Server) user(c *gin.Context) *model.User       { return c.MustGet("user").(*model.User) }
func (s *Server) session(c *gin.Context) *model.Session { return c.MustGet("session").(*model.Session) }
func publicUser(user *model.User) gin.H {
	return gin.H{"id": user.ID, "username": user.Username, "email": user.Email, "display_name": user.DisplayName, "avatar_url": user.AvatarURL, "locale": user.Locale, "email_verified": user.EmailVerifiedAt != nil, "mfa_enabled": user.MFAEnabled, "role": user.Role, "security_email_enabled": user.SecurityEmailEnabled, "created_at": user.CreatedAt, "last_login_at": user.LastLoginAt}
}
func clientIP(c *gin.Context) string {
	if forwarded := c.GetHeader("X-Forwarded-For"); forwarded != "" {
		return strings.TrimSpace(strings.Split(forwarded, ",")[0])
	}
	return c.ClientIP()
}
func deviceName(userAgent string) string {
	if userAgent == "" {
		return "未知设备"
	}
	if strings.Contains(userAgent, "Windows") {
		return "Windows 浏览器"
	}
	if strings.Contains(userAgent, "Mac OS") {
		return "macOS 浏览器"
	}
	if strings.Contains(userAgent, "Android") {
		return "Android 浏览器"
	}
	if strings.Contains(userAgent, "iPhone") {
		return "iPhone 浏览器"
	}
	return "浏览器设备"
}

func loadSigningKey(path string) (*rsa.PrivateKey, error) {
	if data, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, errors.New("invalid OIDC signing key")
		}
		key, parseErr := x509.ParsePKCS1PrivateKey(block.Bytes)
		if parseErr != nil {
			return nil, fmt.Errorf("parse OIDC signing key: %w", parseErr)
		}
		return key, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate OIDC signing key: %w", err)
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

func (s *Server) audit(c *gin.Context, action string, userID uint64, metadata string) {
	_ = s.DB.Create(&model.AuditEvent{UserID: userID, Action: action, IP: clientIP(c), UserAgent: c.Request.UserAgent(), Metadata: metadata}).Error
}

func idString(id uint64) string { return strconv.FormatUint(id, 10) }

func (s *Server) serveError(c *gin.Context, status int, message string) {
	c.JSON(status, gin.H{"success": false, "message": message})
}

func validateURL(raw string, allowEmpty bool) bool {
	if strings.TrimSpace(raw) == "" {
		return allowEmpty
	}
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && u.Fragment == ""
}
