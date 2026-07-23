package server

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/Cong0707/sso/internal/config"
	"github.com/Cong0707/sso/internal/model"
	"github.com/Cong0707/sso/internal/security"
	"github.com/Cong0707/sso/internal/upstream"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type providerSeed struct {
	Kind         string
	Name         string
	ClientID     string
	Secret       string
	Issuer       string
	AuthURL      string
	TokenURL     string
	UserInfoURL  string
	EmailInfoURL string
	Scopes       string
}

func seedProviders(db *gorm.DB, cfg config.Config) error {
	seeds := []providerSeed{
		{Kind: "github", Name: "GitHub", ClientID: os.Getenv("SSO_GITHUB_CLIENT_ID"), Secret: os.Getenv("SSO_GITHUB_CLIENT_SECRET"), AuthURL: "https://github.com/login/oauth/authorize", TokenURL: "https://github.com/login/oauth/access_token", UserInfoURL: "https://api.github.com/user", EmailInfoURL: "https://api.github.com/user/emails", Scopes: "read:user user:email"},
		{Kind: "discord", Name: "Discord", ClientID: os.Getenv("SSO_DISCORD_CLIENT_ID"), Secret: os.Getenv("SSO_DISCORD_CLIENT_SECRET"), AuthURL: "https://discord.com/oauth2/authorize", TokenURL: "https://discord.com/api/oauth2/token", UserInfoURL: "https://discord.com/api/users/@me", Scopes: "identify email"},
		{Kind: "oidc", Name: "OIDC", ClientID: os.Getenv("SSO_OIDC_CLIENT_ID"), Secret: os.Getenv("SSO_OIDC_CLIENT_SECRET"), Issuer: strings.TrimRight(os.Getenv("SSO_OIDC_ISSUER"), "/"), Scopes: "openid profile email"},
		{Kind: "linuxdo", Name: "LinuxDO", ClientID: os.Getenv("SSO_LINUXDO_CLIENT_ID"), Secret: os.Getenv("SSO_LINUXDO_CLIENT_SECRET"), AuthURL: "https://connect.linux.do/oauth2/authorize", TokenURL: "https://connect.linux.do/oauth2/token", UserInfoURL: "https://connect.linux.do/api/user", Scopes: "user"},
		{Kind: "telegram", Name: "Telegram", Secret: os.Getenv("SSO_TELEGRAM_BOT_TOKEN")},
		{Kind: "wechat", Name: "微信", ClientID: os.Getenv("SSO_WECHAT_CLIENT_ID"), Secret: os.Getenv("SSO_WECHAT_CLIENT_SECRET"), AuthURL: "https://open.weixin.qq.com/connect/qrconnect", TokenURL: "https://api.weixin.qq.com/sns/oauth2/access_token", UserInfoURL: "https://api.weixin.qq.com/sns/userinfo", Scopes: "snsapi_login"},
	}
	for _, seed := range seeds {
		var provider model.UpstreamProvider
		if err := db.Where("kind = ?", seed.Kind).Limit(1).Find(&provider).Error; err != nil {
			return err
		}
		isNew := provider.ID == 0
		if isNew {
			provider = model.UpstreamProvider{Kind: seed.Kind}
		}
		provider.DisplayName = seed.Name
		if seed.ClientID != "" {
			provider.ClientID = seed.ClientID
		}
		if seed.Secret != "" {
			encrypted, err := security.Encrypt(cfg.MasterKey, seed.Secret)
			if err != nil {
				return err
			}
			provider.ClientSecretEncrypted = encrypted
		}
		if seed.Issuer != "" {
			provider.IssuerURL = seed.Issuer
		}
		if seed.AuthURL != "" {
			provider.AuthorizationURL = seed.AuthURL
		}
		if seed.TokenURL != "" {
			provider.TokenURL = seed.TokenURL
		}
		if seed.UserInfoURL != "" {
			provider.UserInfoURL = seed.UserInfoURL
		}
		if seed.EmailInfoURL != "" {
			provider.EmailInfoURL = seed.EmailInfoURL
		}
		provider.Scopes = seed.Scopes
		provider.Enabled = provider.ClientID != "" && provider.ClientSecretEncrypted != "" && seed.Kind != "telegram"
		if seed.Kind == "telegram" {
			provider.Enabled = provider.ClientSecretEncrypted != ""
		}
		var err error
		if isNew {
			err = db.Create(&provider).Error
		} else {
			err = db.Save(&provider).Error
		}
		if err != nil {
			return fmt.Errorf("seed provider %s: %w", seed.Kind, err)
		}
	}
	return nil
}

func (s *Server) listProviders(c *gin.Context) {
	var providers []model.UpstreamProvider
	if err := s.DB.Where("enabled = ? AND disabled_at IS NULL", true).Order("id ASC").Find(&providers).Error; err != nil {
		s.serveError(c, http.StatusInternalServerError, "读取上游接入商失败")
		return
	}
	var identities []model.UpstreamIdentity
	userID := uint64(0)
	if user, _, err := s.sessionUser(c); err == nil {
		userID = user.ID
	}
	_ = s.DB.Where("user_id = ?", userID).Find(&identities).Error
	bound := map[uint64]bool{}
	for _, identity := range identities {
		bound[identity.ProviderID] = true
	}
	items := make([]gin.H, 0, len(providers))
	for _, provider := range providers {
		if !providerConfigured(provider) || provider.Kind == "telegram" {
			continue
		}
		items = append(items, gin.H{
			"id": provider.ID, "kind": provider.Kind, "display_name": provider.DisplayName,
			"enabled": provider.Enabled, "configured": providerConfigured(provider), "bound": bound[provider.ID],
		})
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": items})
}

func (s *Server) upstreamStart(c *gin.Context) {
	kind := strings.ToLower(c.Param("kind"))
	var providerRecord model.UpstreamProvider
	if err := s.DB.Where("kind = ? AND enabled = ?", kind, true).First(&providerRecord).Error; err != nil {
		s.serveError(c, http.StatusNotFound, "该登录方式未配置")
		return
	}
	if kind == "telegram" {
		s.serveError(c, http.StatusNotImplemented, "Telegram 需要配置 Login Widget 后从登录页发起")
		return
	}
	provider, err := s.buildUpstreamProvider(providerRecord)
	if err != nil {
		s.serveError(c, http.StatusBadGateway, "上游登录配置无效")
		return
	}
	state, err := security.RandomToken(32)
	if err != nil {
		s.serveError(c, http.StatusInternalServerError, "生成登录状态失败")
		return
	}
	verifier, err := security.RandomToken(48)
	if err != nil {
		s.serveError(c, http.StatusInternalServerError, "生成 PKCE 参数失败")
		return
	}
	challenge := sha256.Sum256([]byte(verifier))
	redirectURL := s.Cfg.Issuer + "/oauth/upstream/" + providerRecord.Kind + "/callback"
	authorizationURL, err := provider.AuthorizationURL(c.Request.Context(), upstream.AuthorizationRequest{
		RedirectURL: redirectURL, State: state,
		CodeChallenge: base64.RawURLEncoding.EncodeToString(challenge[:]), CodeChallengeMethod: "S256",
	})
	if err != nil {
		s.serveError(c, http.StatusBadGateway, "读取上游授权地址失败")
		return
	}
	encryptedVerifier, err := security.Encrypt(s.Cfg.MasterKey, verifier)
	if err != nil {
		s.serveError(c, http.StatusInternalServerError, "保存 PKCE 参数失败")
		return
	}
	var sessionID *uint64
	if _, session, sessionErr := s.sessionUser(c); sessionErr == nil {
		sessionID = &session.ID
	}
	stateRecord := model.UpstreamOAuthState{
		ProviderID: providerRecord.ID, SessionID: sessionID, TokenHash: security.HashToken(state),
		CodeVerifierEncrypted: encryptedVerifier, ReturnTo: safeReturnTo(c.Query("return_to")), ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	if err := s.DB.Create(&stateRecord).Error; err != nil {
		s.serveError(c, http.StatusInternalServerError, "保存登录状态失败")
		return
	}
	c.Redirect(http.StatusFound, authorizationURL)
}

func (s *Server) upstreamCallback(c *gin.Context) {
	if providerError := c.Query("error"); providerError != "" {
		c.Redirect(http.StatusFound, "/login?oauth_error="+url.QueryEscape(providerError))
		return
	}
	stateRaw := c.Query("state")
	var state model.UpstreamOAuthState
	if stateRaw == "" || s.DB.Where("token_hash = ? AND used_at IS NULL", security.HashToken(stateRaw)).First(&state).Error != nil || state.ExpiresAt.Before(time.Now()) {
		c.Redirect(http.StatusFound, "/login?oauth_error=invalid_state")
		return
	}
	now := time.Now()
	result := s.DB.Model(&model.UpstreamOAuthState{}).Where("id = ? AND used_at IS NULL", state.ID).Update("used_at", &now)
	if result.Error != nil || result.RowsAffected != 1 {
		c.Redirect(http.StatusFound, "/login?oauth_error=state_already_used")
		return
	}
	var providerRecord model.UpstreamProvider
	if s.DB.First(&providerRecord, state.ProviderID).Error != nil || !providerRecord.Enabled || providerRecord.Kind != strings.ToLower(c.Param("kind")) {
		c.Redirect(http.StatusFound, "/login?oauth_error=provider_mismatch")
		return
	}
	provider, err := s.buildUpstreamProvider(providerRecord)
	if err != nil {
		c.Redirect(http.StatusFound, "/login?oauth_error=provider_configuration_failed")
		return
	}
	verifier, err := security.Decrypt(s.Cfg.MasterKey, state.CodeVerifierEncrypted)
	if err != nil {
		c.Redirect(http.StatusFound, "/login?oauth_error=pkce_failed")
		return
	}
	identityData, err := provider.Exchange(c.Request.Context(), upstream.CallbackRequest{
		RedirectURL: s.Cfg.Issuer + "/oauth/upstream/" + providerRecord.Kind + "/callback",
		Code:        c.Query("code"), CodeVerifier: verifier,
	})
	if err != nil {
		c.Redirect(http.StatusFound, "/login?oauth_error=upstream_exchange_failed")
		return
	}
	var user model.User
	if state.SessionID != nil {
		var session model.Session
		if s.DB.Where("id = ? AND revoked_at IS NULL AND expires_at > ?", *state.SessionID, time.Now()).First(&session).Error != nil || s.DB.First(&user, session.UserID).Error != nil {
			c.Redirect(http.StatusFound, "/login?oauth_error=session_expired")
			return
		}
	} else {
		var existing model.UpstreamIdentity
		identityErr := s.DB.Where("provider_id = ? AND external_id = ?", providerRecord.ID, identityData.Subject).First(&existing).Error
		if identityErr == nil {
			if s.DB.First(&user, existing.UserID).Error != nil {
				c.Redirect(http.StatusFound, "/login?oauth_error=user_missing")
				return
			}
		} else if !errors.Is(identityErr, gorm.ErrRecordNotFound) {
			c.Redirect(http.StatusFound, "/login?oauth_error=identity_lookup_failed")
			return
		} else {
			if identityData.EmailVerified && validEmail(identityData.Email) {
				_ = s.DB.Where("LOWER(email) = ?", strings.ToLower(identityData.Email)).First(&user).Error
			}
			if user.ID == 0 {
				user, err = s.provisionUpstreamUser(providerRecord, identityData)
				if err != nil {
					c.Redirect(http.StatusFound, "/login?oauth_error=provision_failed")
					return
				}
			}
		}
	}
	if user.ID == 0 || user.Status != "active" {
		c.Redirect(http.StatusFound, "/login?oauth_error=account_unavailable")
		return
	}
	var conflict model.UpstreamIdentity
	if err := s.DB.Where("provider_id = ? AND external_id = ?", providerRecord.ID, identityData.Subject).First(&conflict).Error; err == nil && conflict.UserID != user.ID {
		c.Redirect(http.StatusFound, "/profile?oauth_error=already_bound")
		return
	}
	var userProviderIdentity model.UpstreamIdentity
	if err := s.DB.Where("provider_id = ? AND user_id = ?", providerRecord.ID, user.ID).First(&userProviderIdentity).Error; err == nil && userProviderIdentity.ExternalID != identityData.Subject {
		c.Redirect(http.StatusFound, "/profile?oauth_error=provider_already_bound")
		return
	}
	externalName := strings.TrimSpace(identityData.Name)
	if externalName == "" {
		externalName = strings.TrimSpace(identityData.Username)
	}
	identity := model.UpstreamIdentity{
		UserID: user.ID, ProviderID: providerRecord.ID, ExternalID: identityData.Subject,
		ExternalName: externalName, ExternalEmail: strings.ToLower(strings.TrimSpace(identityData.Email)), LastLoginAt: now,
	}
	if err := s.DB.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "provider_id"}, {Name: "external_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"external_name", "external_email", "last_login_at", "updated_at"}),
	}).Create(&identity).Error; err != nil {
		c.Redirect(http.StatusFound, "/login?oauth_error=bind_failed")
		return
	}
	if err := s.syncUpstreamProfile(&user, identityData); err != nil {
		c.Redirect(http.StatusFound, "/login?oauth_error=profile_sync_failed")
		return
	}
	user.LastLoginAt = &now
	_ = s.DB.Model(&user).Update("last_login_at", &now).Error
	if state.SessionID == nil {
		if _, err := s.createSession(c, &user); err != nil {
			c.Redirect(http.StatusFound, "/login?oauth_error=session_failed")
			return
		}
	}
	s.audit(c, "upstream.login."+providerRecord.Kind, user.ID, identityData.Subject)
	c.Redirect(http.StatusFound, state.ReturnTo)
}

func (s *Server) buildUpstreamProvider(provider model.UpstreamProvider) (upstream.Provider, error) {
	secret, err := security.Decrypt(s.Cfg.MasterKey, provider.ClientSecretEncrypted)
	if err != nil {
		return nil, err
	}
	return s.UpstreamProviders.Build(upstream.Config{
		Kind: provider.Kind, DisplayName: provider.DisplayName, ClientID: provider.ClientID, ClientSecret: secret,
		IssuerURL: provider.IssuerURL, AuthorizationURL: provider.AuthorizationURL, TokenURL: provider.TokenURL,
		UserInfoURL: provider.UserInfoURL, EmailInfoURL: provider.EmailInfoURL, Scopes: strings.Fields(provider.Scopes),
	})
}

func providerConfigured(provider model.UpstreamProvider) bool {
	if provider.Kind == "telegram" {
		return provider.ClientSecretEncrypted != ""
	}
	return provider.ClientID != "" && provider.ClientSecretEncrypted != ""
}

func (s *Server) provisionUpstreamUser(provider model.UpstreamProvider, identity upstream.Identity) (model.User, error) {
	usernameSource := identity.Username
	if usernameSource == "" {
		usernameSource = identity.Name
	}
	username := uniqueUsernameBase(usernameSource, provider.Kind, identity.Subject)
	base := username
	for index := 0; ; index++ {
		var count int64
		s.DB.Model(&model.User{}).Where("LOWER(username) = ?", strings.ToLower(username)).Count(&count)
		if count == 0 {
			break
		}
		username = fmt.Sprintf("%s%d", base, index+1)
	}
	email := strings.ToLower(strings.TrimSpace(identity.Email))
	if !identity.EmailVerified || !validEmail(email) {
		email = fmt.Sprintf("%s-%s@users.invalid", provider.Kind, security.HashToken(identity.Subject)[:16])
	}
	randomPassword, err := security.RandomToken(32)
	if err != nil {
		return model.User{}, err
	}
	hash, err := security.HashPassword(randomPassword + "A1")
	if err != nil {
		return model.User{}, err
	}
	displayName := strings.TrimSpace(identity.Name)
	if displayName == "" {
		displayName = strings.TrimSpace(identity.Username)
	}
	if displayName == "" {
		displayName = username
	}
	user := model.User{
		Username: username, Email: email, PasswordHash: hash, PasswordConfigured: false,
		DisplayName: displayName, AvatarURL: strings.TrimSpace(identity.AvatarURL), Locale: "zh-CN",
		SecurityEmailEnabled: true, Role: "user", Status: "active",
	}
	if identity.EmailVerified && validEmail(email) {
		now := time.Now()
		user.EmailVerifiedAt = &now
	}
	if err := s.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&user).Error; err != nil {
			return err
		}
		return tx.Model(&user).Update("password_configured", false).Error
	}); err != nil {
		return model.User{}, err
	}
	user.PasswordConfigured = false
	return user, nil
}

func (s *Server) syncUpstreamProfile(user *model.User, identity upstream.Identity) error {
	updates := map[string]any{}
	if strings.TrimSpace(user.DisplayName) == "" {
		if name := strings.TrimSpace(identity.Name); name != "" {
			updates["display_name"] = name
		} else if username := strings.TrimSpace(identity.Username); username != "" {
			updates["display_name"] = username
		}
	}
	if strings.TrimSpace(user.AvatarURL) == "" && strings.TrimSpace(identity.AvatarURL) != "" {
		updates["avatar_url"] = strings.TrimSpace(identity.AvatarURL)
	}
	if strings.HasSuffix(strings.ToLower(user.Email), "@users.invalid") && identity.EmailVerified && validEmail(identity.Email) {
		verifiedEmail := strings.ToLower(strings.TrimSpace(identity.Email))
		var count int64
		if err := s.DB.Model(&model.User{}).Where("LOWER(email) = ? AND id <> ?", verifiedEmail, user.ID).Count(&count).Error; err != nil {
			return err
		}
		if count == 0 {
			now := time.Now()
			updates["email"] = verifiedEmail
			updates["email_verified_at"] = &now
		}
	}
	if len(updates) == 0 {
		return nil
	}
	if err := s.DB.Model(user).Updates(updates).Error; err != nil {
		return err
	}
	return s.DB.First(user, user.ID).Error
}

var usernameSanitizer = regexp.MustCompile(`[^a-zA-Z0-9_-]+`)

func uniqueUsernameBase(name, provider, id string) string {
	value := strings.Trim(usernameSanitizer.ReplaceAllString(name, "_"), "_-")
	if len(value) < 3 {
		value = provider + "_" + strings.Trim(usernameSanitizer.ReplaceAllString(id, ""), "_-")
	}
	if len(value) > 24 {
		value = value[:24]
	}
	if len(value) < 3 {
		value = provider + "_user"
	}
	return value
}

func safeReturnTo(value string) string {
	if value == "" || !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") {
		return "/dashboard"
	}
	return value
}
