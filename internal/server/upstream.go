package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/Cong0707/sso/internal/config"
	"github.com/Cong0707/sso/internal/model"
	"github.com/Cong0707/sso/internal/security"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type providerSeed struct {
	Kind        string
	Name        string
	ClientID    string
	Secret      string
	Issuer      string
	AuthURL     string
	TokenURL    string
	UserInfoURL string
	Scopes      string
}

func seedProviders(db *gorm.DB, cfg config.Config) error {
	seeds := []providerSeed{
		{Kind: "github", Name: "GitHub", ClientID: os.Getenv("SSO_GITHUB_CLIENT_ID"), Secret: os.Getenv("SSO_GITHUB_CLIENT_SECRET"), AuthURL: "https://github.com/login/oauth/authorize", TokenURL: "https://github.com/login/oauth/access_token", UserInfoURL: "https://api.github.com/user", Scopes: "read:user user:email"},
		{Kind: "discord", Name: "Discord", ClientID: os.Getenv("SSO_DISCORD_CLIENT_ID"), Secret: os.Getenv("SSO_DISCORD_CLIENT_SECRET"), AuthURL: "https://discord.com/oauth2/authorize", TokenURL: "https://discord.com/api/oauth2/token", UserInfoURL: "https://discord.com/api/users/@me", Scopes: "identify email"},
		{Kind: "oidc", Name: "OIDC", ClientID: os.Getenv("SSO_OIDC_CLIENT_ID"), Secret: os.Getenv("SSO_OIDC_CLIENT_SECRET"), Issuer: strings.TrimRight(os.Getenv("SSO_OIDC_ISSUER"), "/"), Scopes: "openid profile email"},
		{Kind: "linuxdo", Name: "LinuxDO", ClientID: os.Getenv("SSO_LINUXDO_CLIENT_ID"), Secret: os.Getenv("SSO_LINUXDO_CLIENT_SECRET"), AuthURL: "https://connect.linux.do/oauth2/authorize", TokenURL: "https://connect.linux.do/oauth2/token", UserInfoURL: "https://connect.linux.do/api/user", Scopes: "user"},
		{Kind: "telegram", Name: "Telegram", Secret: os.Getenv("SSO_TELEGRAM_BOT_TOKEN")},
		{Kind: "wechat", Name: "微信", ClientID: os.Getenv("SSO_WECHAT_CLIENT_ID"), Secret: os.Getenv("SSO_WECHAT_CLIENT_SECRET"), AuthURL: "https://open.weixin.qq.com/connect/qrconnect", TokenURL: "https://api.weixin.qq.com/sns/oauth2/access_token", UserInfoURL: "https://api.weixin.qq.com/sns/userinfo", Scopes: "snsapi_login"},
	}
	for _, seed := range seeds {
		var provider model.UpstreamProvider
		err := db.Where("kind = ?", seed.Kind).Limit(1).Find(&provider).Error
		isNew := provider.ID == 0
		if err != nil {
			return err
		}
		if isNew {
			provider = model.UpstreamProvider{Kind: seed.Kind}
		}
		provider.DisplayName = seed.Name
		if seed.ClientID != "" {
			provider.ClientID = seed.ClientID
		}
		if seed.Secret != "" {
			encrypted, encryptErr := security.Encrypt(cfg.MasterKey, seed.Secret)
			if encryptErr != nil {
				return encryptErr
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
		provider.Scopes = seed.Scopes
		provider.Enabled = provider.ClientID != "" && provider.ClientSecretEncrypted != "" && seed.Kind != "telegram"
		if seed.Kind == "telegram" {
			provider.Enabled = provider.ClientSecretEncrypted != ""
		}
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
	if err := s.DB.Order("id ASC").Find(&providers).Error; err != nil {
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
		items = append(items, gin.H{"id": provider.ID, "kind": provider.Kind, "display_name": provider.DisplayName, "enabled": provider.Enabled, "configured": provider.ClientID != "" || provider.ClientSecretEncrypted != "", "bound": bound[provider.ID]})
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": items})
}

func (s *Server) upstreamStart(c *gin.Context) {
	kind := strings.ToLower(c.Param("kind"))
	var provider model.UpstreamProvider
	if err := s.DB.Where("kind = ? AND enabled = ?", kind, true).First(&provider).Error; err != nil {
		s.serveError(c, http.StatusNotFound, "该登录方式未配置")
		return
	}
	if kind == "telegram" {
		s.serveError(c, http.StatusNotImplemented, "该接入商需要专用登录协议，当前尚未启用")
		return
	}
	if kind == "wechat" {
		state, err := security.RandomToken(32)
		if err != nil {
			s.serveError(c, http.StatusInternalServerError, "生成登录状态失败")
			return
		}
		returnTo := safeReturnTo(c.Query("return_to"))
		var sessionID *uint64
		if _, session, sessionErr := s.sessionUser(c); sessionErr == nil {
			sessionID = &session.ID
		}
		stateRecord := model.UpstreamOAuthState{ProviderID: provider.ID, SessionID: sessionID, TokenHash: security.HashToken(state), ReturnTo: returnTo, ExpiresAt: time.Now().Add(10 * time.Minute)}
		if err := s.DB.Create(&stateRecord).Error; err != nil {
			s.serveError(c, http.StatusInternalServerError, "保存登录状态失败")
			return
		}
		redirectURI := s.Cfg.Issuer + "/oauth/upstream/wechat/callback"
		wechatURL := provider.AuthorizationURL + "?appid=" + url.QueryEscape(provider.ClientID) + "&redirect_uri=" + url.QueryEscape(redirectURI) + "&response_type=code&scope=snsapi_login&state=" + url.QueryEscape(state) + "#wechat_redirect"
		c.Redirect(http.StatusFound, wechatURL)
		return
	}
	if kind == "oidc" {
		if err := discoverOIDC(c.Request.Context(), &provider); err != nil {
			s.serveError(c, http.StatusBadGateway, "读取 OIDC 发现文档失败")
			return
		}
	}
	secret, err := security.Decrypt(s.Cfg.MasterKey, provider.ClientSecretEncrypted)
	if err != nil {
		s.serveError(c, http.StatusInternalServerError, "读取上游密钥失败")
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
	encryptedVerifier, err := security.Encrypt(s.Cfg.MasterKey, verifier)
	if err != nil {
		s.serveError(c, http.StatusInternalServerError, "保存 PKCE 参数失败")
		return
	}
	returnTo := safeReturnTo(c.Query("return_to"))
	var sessionID *uint64
	if _, session, sessionErr := s.sessionUser(c); sessionErr == nil {
		sessionID = &session.ID
	}
	stateRecord := model.UpstreamOAuthState{ProviderID: provider.ID, SessionID: sessionID, TokenHash: security.HashToken(state), CodeVerifierEncrypted: encryptedVerifier, ReturnTo: returnTo, ExpiresAt: time.Now().Add(10 * time.Minute)}
	if err := s.DB.Create(&stateRecord).Error; err != nil {
		s.serveError(c, http.StatusInternalServerError, "保存登录状态失败")
		return
	}
	challenge := sha256.Sum256([]byte(verifier))
	config := oauth2.Config{ClientID: provider.ClientID, ClientSecret: secret, RedirectURL: s.Cfg.Issuer + "/oauth/upstream/" + provider.Kind + "/callback", Scopes: strings.Fields(provider.Scopes), Endpoint: oauth2.Endpoint{AuthURL: provider.AuthorizationURL, TokenURL: provider.TokenURL}}
	authURL := config.AuthCodeURL(state, oauth2.SetAuthURLParam("code_challenge", base64.RawURLEncoding.EncodeToString(challenge[:])), oauth2.SetAuthURLParam("code_challenge_method", "S256"))
	c.Redirect(http.StatusFound, authURL)
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
	if s.DB.Model(&state).Update("used_at", &now).Error != nil {
		c.Redirect(http.StatusFound, "/login?oauth_error=state_update_failed")
		return
	}
	var provider model.UpstreamProvider
	if s.DB.First(&provider, state.ProviderID).Error != nil || provider.Kind != strings.ToLower(c.Param("kind")) {
		c.Redirect(http.StatusFound, "/login?oauth_error=provider_mismatch")
		return
	}
	if provider.Kind == "oidc" {
		if err := discoverOIDC(c.Request.Context(), &provider); err != nil {
			c.Redirect(http.StatusFound, "/login?oauth_error=oidc_discovery_failed")
			return
		}
	}
	secret, err := security.Decrypt(s.Cfg.MasterKey, provider.ClientSecretEncrypted)
	if err != nil {
		c.Redirect(http.StatusFound, "/login?oauth_error=provider_secret_failed")
		return
	}
	httpClient := &http.Client{Timeout: 15 * time.Second}
	ctx := context.WithValue(c.Request.Context(), oauth2.HTTPClient, httpClient)
	var accessToken, openID string
	if provider.Kind == "wechat" {
		accessToken, openID, err = exchangeWeChat(ctx, provider, secret, c.Query("code"))
	} else {
		verifier, verifierErr := security.Decrypt(s.Cfg.MasterKey, state.CodeVerifierEncrypted)
		if verifierErr != nil {
			c.Redirect(http.StatusFound, "/login?oauth_error=pkce_failed")
			return
		}
		config := oauth2.Config{ClientID: provider.ClientID, ClientSecret: secret, RedirectURL: s.Cfg.Issuer + "/oauth/upstream/" + provider.Kind + "/callback", Scopes: strings.Fields(provider.Scopes), Endpoint: oauth2.Endpoint{AuthURL: provider.AuthorizationURL, TokenURL: provider.TokenURL}}
		token, exchangeErr := config.Exchange(ctx, c.Query("code"), oauth2.SetAuthURLParam("code_verifier", verifier))
		if exchangeErr == nil {
			accessToken = token.AccessToken
		} else {
			err = exchangeErr
		}
	}
	if err != nil {
		c.Redirect(http.StatusFound, "/login?oauth_error=token_exchange_failed")
		return
	}
	var identityData upstreamIdentityData
	if provider.Kind == "wechat" {
		identityData, err = fetchWeChatIdentity(ctx, provider, accessToken, openID)
	} else {
		identityData, err = fetchUpstreamIdentity(ctx, httpClient, provider, accessToken)
	}
	if err != nil {
		c.Redirect(http.StatusFound, "/login?oauth_error=userinfo_failed")
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
		identityErr := s.DB.Where("provider_id = ? AND external_id = ?", provider.ID, identityData.ID).First(&existing).Error
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
				user, err = s.provisionUpstreamUser(provider, identityData)
				if err != nil {
					c.Redirect(http.StatusFound, "/login?oauth_error=provision_failed")
					return
				}
			}
		}
	}
	var conflict model.UpstreamIdentity
	if err := s.DB.Where("provider_id = ? AND external_id = ?", provider.ID, identityData.ID).First(&conflict).Error; err == nil && conflict.UserID != user.ID {
		c.Redirect(http.StatusFound, "/profile?oauth_error=already_bound")
		return
	}
	identity := model.UpstreamIdentity{UserID: user.ID, ProviderID: provider.ID, ExternalID: identityData.ID, ExternalName: identityData.Name, ExternalEmail: identityData.Email, LastLoginAt: now}
	if err := s.DB.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "provider_id"}, {Name: "external_id"}}, DoUpdates: clause.AssignmentColumns([]string{"external_name", "external_email", "last_login_at", "updated_at"})}).Create(&identity).Error; err != nil {
		c.Redirect(http.StatusFound, "/login?oauth_error=bind_failed")
		return
	}
	if state.SessionID == nil {
		if _, err := s.createSession(c, &user); err != nil {
			c.Redirect(http.StatusFound, "/login?oauth_error=session_failed")
			return
		}
	}
	s.audit(c, "upstream.login."+provider.Kind, user.ID, identityData.ID)
	c.Redirect(http.StatusFound, state.ReturnTo)
}

type upstreamIdentityData struct {
	ID            string
	Name          string
	Email         string
	Avatar        string
	EmailVerified bool
}

func fetchUpstreamIdentity(ctx context.Context, client *http.Client, provider model.UpstreamProvider, accessToken string) (upstreamIdentityData, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, provider.UserInfoURL, nil)
	if err != nil {
		return upstreamIdentityData{}, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "FZ-SSO/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return upstreamIdentityData{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return upstreamIdentityData{}, fmt.Errorf("userinfo status %d", resp.StatusCode)
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 1<<20))
	decoder.UseNumber()
	var raw map[string]any
	if err := decoder.Decode(&raw); err != nil {
		return upstreamIdentityData{}, err
	}
	id := firstString(raw, "sub", "id", "user_id")
	name := firstString(raw, "preferred_username", "username", "login", "global_name", "name")
	email := firstString(raw, "email")
	avatar := firstString(raw, "picture", "avatar_url", "avatar")
	verified, _ := raw["email_verified"].(bool)
	if provider.Kind == "github" && email != "" {
		verified = true
	}
	if id == "" {
		return upstreamIdentityData{}, errors.New("missing upstream subject")
	}
	return upstreamIdentityData{ID: id, Name: name, Email: email, Avatar: avatar, EmailVerified: verified}, nil
}

func exchangeWeChat(ctx context.Context, provider model.UpstreamProvider, secret, code string) (string, string, error) {
	requestURL := provider.TokenURL + "?appid=" + url.QueryEscape(provider.ClientID) + "&secret=" + url.QueryEscape(secret) + "&code=" + url.QueryEscape(code) + "&grant_type=authorization_code"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return "", "", err
	}
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	var result struct {
		AccessToken  string `json:"access_token"`
		OpenID       string `json:"openid"`
		ErrorCode    int    `json:"errcode"`
		ErrorMessage string `json:"errmsg"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&result); err != nil {
		return "", "", err
	}
	if result.AccessToken == "" || result.OpenID == "" {
		return "", "", fmt.Errorf("wechat token error %d: %s", result.ErrorCode, result.ErrorMessage)
	}
	return result.AccessToken, result.OpenID, nil
}

func fetchWeChatIdentity(ctx context.Context, provider model.UpstreamProvider, accessToken, openID string) (upstreamIdentityData, error) {
	requestURL := provider.UserInfoURL + "?access_token=" + url.QueryEscape(accessToken) + "&openid=" + url.QueryEscape(openID) + "&lang=zh_CN"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return upstreamIdentityData{}, err
	}
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return upstreamIdentityData{}, err
	}
	defer resp.Body.Close()
	var result struct {
		OpenID       string `json:"openid"`
		Nickname     string `json:"nickname"`
		HeadImageURL string `json:"headimgurl"`
		ErrorCode    int    `json:"errcode"`
		ErrorMessage string `json:"errmsg"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&result); err != nil {
		return upstreamIdentityData{}, err
	}
	if result.OpenID == "" {
		return upstreamIdentityData{}, fmt.Errorf("wechat userinfo error %d: %s", result.ErrorCode, result.ErrorMessage)
	}
	return upstreamIdentityData{ID: result.OpenID, Name: result.Nickname, Avatar: result.HeadImageURL}, nil
}

func (s *Server) provisionUpstreamUser(provider model.UpstreamProvider, identity upstreamIdentityData) (model.User, error) {
	username := uniqueUsernameBase(identity.Name, provider.Kind, identity.ID)
	base := username
	for index := 0; ; index++ {
		var count int64
		s.DB.Model(&model.User{}).Where("LOWER(username) = ?", strings.ToLower(username)).Count(&count)
		if count == 0 {
			break
		}
		username = fmt.Sprintf("%s%d", base, index+1)
	}
	email := strings.ToLower(identity.Email)
	if !identity.EmailVerified || !validEmail(email) {
		email = fmt.Sprintf("%s-%s@users.invalid", provider.Kind, security.HashToken(identity.ID)[:16])
	}
	randomPassword, err := security.RandomToken(32)
	if err != nil {
		return model.User{}, err
	}
	hash, err := security.HashPassword(randomPassword + "A1")
	if err != nil {
		return model.User{}, err
	}
	user := model.User{Username: username, Email: email, PasswordHash: hash, DisplayName: identity.Name, AvatarURL: identity.Avatar, Locale: "zh-CN", SecurityEmailEnabled: true, Role: "user", Status: "active"}
	if identity.EmailVerified {
		now := time.Now()
		user.EmailVerifiedAt = &now
	}
	if err := s.DB.Create(&user).Error; err != nil {
		return model.User{}, err
	}
	return user, nil
}

func discoverOIDC(ctx context.Context, provider *model.UpstreamProvider) error {
	if provider.IssuerURL == "" {
		return errors.New("OIDC issuer missing")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(provider.IssuerURL, "/")+"/.well-known/openid-configuration", nil)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("discovery status %d", resp.StatusCode)
	}
	var doc struct {
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
		UserInfoEndpoint      string `json:"userinfo_endpoint"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
		return err
	}
	if !absoluteHTTPSOrLocal(doc.AuthorizationEndpoint) || !absoluteHTTPSOrLocal(doc.TokenEndpoint) || !absoluteHTTPSOrLocal(doc.UserInfoEndpoint) {
		return errors.New("invalid OIDC endpoints")
	}
	provider.AuthorizationURL = doc.AuthorizationEndpoint
	provider.TokenURL = doc.TokenEndpoint
	provider.UserInfoURL = doc.UserInfoEndpoint
	return nil
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

func firstString(values map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := values[key]; ok {
			switch typed := value.(type) {
			case string:
				if typed != "" {
					return typed
				}
			case json.Number:
				return typed.String()
			case float64:
				return fmt.Sprintf("%.0f", typed)
			}
		}
	}
	return ""
}

func safeReturnTo(value string) string {
	if value == "" || !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") {
		return "/dashboard"
	}
	return value
}

func absoluteHTTPSOrLocal(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	return u.Scheme == "https" || (u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost"))
}
