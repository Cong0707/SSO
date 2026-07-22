package server

import (
	"encoding/base64"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Cong0707/sso/internal/model"
	"github.com/Cong0707/sso/internal/security"
	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4"
	oauthErrors "github.com/go-oauth2/oauth2/v4/errors"
	"github.com/golang-jwt/jwt/v5"
)

var defaultScopes = []string{"openid", "profile", "email"}

func clientInfoHandler(r *http.Request) (string, string, error) {
	if id, secret, ok := r.BasicAuth(); ok && id != "" {
		return id, secret, nil
	}
	if err := r.ParseForm(); err != nil {
		return "", "", oauthErrors.ErrInvalidRequest
	}
	id := r.Form.Get("client_id")
	if id == "" {
		return "", "", oauthErrors.ErrInvalidClient
	}
	return id, r.Form.Get("client_secret"), nil
}

func (s *Server) oauthClientAuthorized(clientID string, grant oauth2.GrantType) (bool, error) {
	var app model.OAuthApplication
	if err := s.DB.Where("client_id = ? AND disabled_at IS NULL", clientID).First(&app).Error; err != nil {
		return false, nil
	}
	return grant == oauth2.AuthorizationCode || grant == oauth2.Refreshing, nil
}

func (s *Server) oauthClientScope(tgr *oauth2.TokenGenerateRequest) (bool, error) {
	var app model.OAuthApplication
	if err := s.DB.Where("client_id = ? AND disabled_at IS NULL", tgr.ClientID).First(&app).Error; err != nil {
		return false, nil
	}
	allowed := make(map[string]bool)
	for _, scope := range splitScopes(app.AllowedScopes) {
		allowed[scope] = true
	}
	for _, scope := range strings.Fields(tgr.Scope) {
		if scope == "" || !allowed[scope] {
			return false, nil
		}
	}
	return true, nil
}

func (s *Server) oauthUserAuthorization(_ http.ResponseWriter, r *http.Request) (string, error) {
	_, session, err := s.sessionUserRequest(r)
	if err != nil || session == nil {
		return "", oauthErrors.ErrAccessDenied
	}
	return strconv.FormatUint(session.UserID, 10), nil
}

func (s *Server) oauthAuthorize(c *gin.Context) {
	r := c.Request
	request, err := s.OAuth.ValidationAuthorizeRequest(r)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": err.Error()})
		return
	}
	var app model.OAuthApplication
	if err := s.DB.Where("client_id = ? AND disabled_at IS NULL", request.ClientID).First(&app).Error; err != nil || app.RedirectURI != request.RedirectURI {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "redirect_uri 不匹配"})
		return
	}
	if !scopeSubset(request.Scope, splitScopes(app.AllowedScopes)) {
		c.Redirect(http.StatusFound, addOAuthError(app.RedirectURI, request.State, "invalid_scope"))
		return
	}
	user, _, sessionErr := s.sessionUser(c)
	if sessionErr != nil || user == nil {
		c.Redirect(http.StatusFound, "/login?redirect="+url.QueryEscape(r.URL.String()))
		return
	}
	promptConsent := r.URL.Query().Get("prompt") == "consent"
	var grant model.Grant
	grantErr := s.DB.Where("user_id = ? AND app_id = ? AND revoked_at IS NULL", user.ID, app.ID).Limit(1).Find(&grant).Error
	if grantErr != nil {
		s.serveError(c, http.StatusInternalServerError, "读取授权状态失败")
		return
	}
	if (grant.ID == 0 || !scopeSubset(request.Scope, splitScopes(grant.Scopes)) || promptConsent) && r.URL.Query().Get("consent") != "1" {
		if r.URL.Query().Get("prompt") == "none" {
			c.Redirect(http.StatusFound, addOAuthError(app.RedirectURI, request.State, "consent_required"))
			return
		}
		c.Redirect(http.StatusFound, "/consent?request="+url.QueryEscape(r.URL.String()))
		return
	}
	if err := s.OAuth.HandleAuthorizeRequest(c.Writer, r); err != nil {
		return
	}
	status := "approved"
	scope := request.Scope
	_ = s.DB.Create(&model.AuthorizationLog{AppID: app.ID, UserID: user.ID, Action: "authorize", Scopes: scope, IP: clientIP(c), Status: status}).Error
}

func (s *Server) oauthConsentInfo(c *gin.Context) {
	raw := c.Query("request")
	if raw == "" {
		s.serveError(c, http.StatusBadRequest, "缺少授权请求")
		return
	}
	u, err := url.Parse(raw)
	if err != nil || u.Path != "/oauth/authorize" {
		s.serveError(c, http.StatusBadRequest, "授权请求无效")
		return
	}
	var app model.OAuthApplication
	if err := s.DB.Where("client_id = ? AND disabled_at IS NULL", u.Query().Get("client_id")).First(&app).Error; err != nil {
		s.serveError(c, http.StatusBadRequest, "应用不存在")
		return
	}
	scopes := strings.Fields(u.Query().Get("scope"))
	if len(scopes) == 0 {
		scopes = defaultScopes
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"app": gin.H{"id": app.ID, "name": app.Name, "description": app.Description, "logo_url": app.LogoURL, "homepage": app.Homepage}, "scopes": scopes, "request": raw}})
}

func (s *Server) oauthConsent(c *gin.Context) {
	var input struct {
		Request  string `json:"request"`
		Approved bool   `json:"approved"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		s.serveError(c, http.StatusBadRequest, "请求格式错误")
		return
	}
	u, err := url.Parse(input.Request)
	if err != nil || u.Path != "/oauth/authorize" {
		s.serveError(c, http.StatusBadRequest, "授权请求无效")
		return
	}
	var app model.OAuthApplication
	if err := s.DB.Where("client_id = ? AND disabled_at IS NULL", u.Query().Get("client_id")).First(&app).Error; err != nil || app.RedirectURI != u.Query().Get("redirect_uri") {
		s.serveError(c, http.StatusBadRequest, "应用授权请求无效")
		return
	}
	user := s.user(c)
	scopes := strings.Fields(u.Query().Get("scope"))
	if len(scopes) == 0 {
		scopes = defaultScopes
	}
	if !scopeSubset(strings.Join(scopes, " "), splitScopes(app.AllowedScopes)) {
		s.serveError(c, http.StatusBadRequest, "授权范围无效")
		return
	}
	if !input.Approved {
		_ = s.DB.Create(&model.AuthorizationLog{AppID: app.ID, UserID: user.ID, Action: "authorize", Scopes: strings.Join(scopes, " "), IP: clientIP(c), Status: "denied"}).Error
		c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"redirect_url": addOAuthError(app.RedirectURI, u.Query().Get("state"), "access_denied")}})
		return
	}
	var grant model.Grant
	if err := s.DB.Where("user_id = ? AND app_id = ?", user.ID, app.ID).Limit(1).Find(&grant).Error; err == nil && grant.ID == 0 {
		grant = model.Grant{UserID: user.ID, AppID: app.ID, Scopes: strings.Join(scopes, " ")}
		if err := s.DB.Create(&grant).Error; err != nil {
			s.serveError(c, http.StatusInternalServerError, "保存授权失败")
			return
		}
	} else if err != nil {
		s.serveError(c, http.StatusInternalServerError, "读取授权失败")
		return
	} else {
		grant.Scopes = mergeScopes(splitScopes(grant.Scopes), scopes)
		grant.RevokedAt = nil
		if err := s.DB.Save(&grant).Error; err != nil {
			s.serveError(c, http.StatusInternalServerError, "更新授权失败")
			return
		}
	}
	query := u.Query()
	query.Set("consent", "1")
	u.RawQuery = query.Encode()
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"redirect_url": u.String()}})
}

func (s *Server) oauthToken(c *gin.Context) {
	if err := s.OAuth.HandleTokenRequest(c.Writer, c.Request); err != nil {
		return
	}
}

func (s *Server) oauthRevoke(c *gin.Context) {
	if err := c.Request.ParseForm(); err != nil {
		c.Status(http.StatusOK)
		return
	}
	token := c.Request.Form.Get("token")
	hint := c.Request.Form.Get("token_type_hint")
	if token == "" {
		c.Status(http.StatusOK)
		return
	}
	if hint == "refresh_token" {
		_ = s.OAuth.Manager.RemoveRefreshToken(c.Request.Context(), token)
	} else if err := s.OAuth.Manager.RemoveAccessToken(c.Request.Context(), token); err != nil {
		_ = s.OAuth.Manager.RemoveRefreshToken(c.Request.Context(), token)
	}
	c.Status(http.StatusOK)
}

func (s *Server) oauthUserInfo(c *gin.Context) {
	info, err := s.OAuth.ValidationBearerToken(c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}
	var user model.User
	if err := s.DB.First(&user, info.GetUserID()).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}
	claims := gin.H{"sub": strconv.FormatUint(user.ID, 10)}
	allowed := make(map[string]bool)
	for _, scope := range strings.Fields(info.GetScope()) {
		allowed[scope] = true
	}
	if allowed["profile"] {
		claims["name"] = user.DisplayName
		claims["preferred_username"] = user.Username
		claims["picture"] = user.AvatarURL
		claims["locale"] = user.Locale
	}
	if allowed["email"] {
		claims["email"] = user.Email
		claims["email_verified"] = user.EmailVerifiedAt != nil
	}
	c.JSON(http.StatusOK, claims)
}

func (s *Server) oidcExtensionFields(info oauth2.TokenInfo) map[string]interface{} {
	if !scopeContains(info.GetScope(), "openid") {
		return nil
	}
	userID := info.GetUserID()
	var user model.User
	if err := s.DB.First(&user, userID).Error; err != nil {
		return nil
	}
	now := time.Now()
	authTime := now.Unix()
	claims := jwt.MapClaims{"iss": s.Cfg.Issuer, "sub": userID, "aud": info.GetClientID(), "iat": now.Unix(), "exp": now.Add(15 * time.Minute).Unix(), "name": user.DisplayName, "preferred_username": user.Username, "email": user.Email, "email_verified": user.EmailVerifiedAt != nil}
	if extended, ok := info.(oauth2.ExtendableTokenInfo); ok {
		if nonce := extended.GetExtension().Get("nonce"); nonce != "" {
			claims["nonce"] = nonce
		}
		if raw := extended.GetExtension().Get("auth_time"); raw != "" {
			if parsed, err := strconv.ParseInt(raw, 10, 64); err == nil {
				authTime = parsed
			}
		}
	}
	claims["auth_time"] = authTime
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.OIDCKeyID
	signed, err := token.SignedString(s.OIDCKey)
	if err != nil {
		return nil
	}
	return map[string]interface{}{"id_token": signed}
}

func (s *Server) oidcDiscovery(c *gin.Context) {
	issuer := s.Cfg.Issuer
	c.JSON(http.StatusOK, gin.H{"issuer": issuer, "authorization_endpoint": issuer + "/oauth/authorize", "token_endpoint": issuer + "/oauth/token", "userinfo_endpoint": issuer + "/oauth/userinfo", "jwks_uri": issuer + "/oauth/jwks.json", "revocation_endpoint": issuer + "/oauth/revoke", "scopes_supported": defaultScopes, "response_types_supported": []string{"code"}, "grant_types_supported": []string{"authorization_code", "refresh_token"}, "subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"RS256"}, "code_challenge_methods_supported": []string{"S256", "plain"}})
}

func (s *Server) jwks(c *gin.Context) {
	modulus := base64.RawURLEncoding.EncodeToString(s.OIDCKey.PublicKey.N.Bytes())
	exponent := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(s.OIDCKey.PublicKey.E)).Bytes())
	c.JSON(http.StatusOK, gin.H{"keys": []gin.H{{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": s.OIDCKeyID, "n": modulus, "e": exponent}}})
}

func (s *Server) sessionUserRequest(r *http.Request) (*model.User, *model.Session, error) {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil, nil, err
	}
	var session model.Session
	if err := s.DB.Where("token_hash = ? AND revoked_at IS NULL", security.HashToken(cookie.Value)).First(&session).Error; err != nil || session.ExpiresAt.Before(time.Now()) {
		return nil, nil, oauthErrors.ErrAccessDenied
	}
	var user model.User
	if err := s.DB.First(&user, session.UserID).Error; err != nil {
		return nil, nil, err
	}
	return &user, &session, nil
}

func scopeSubset(raw string, allowed []string) bool {
	set := map[string]bool{}
	for _, item := range allowed {
		set[item] = true
	}
	for _, item := range strings.Fields(raw) {
		if item != "" && !set[item] {
			return false
		}
	}
	return true
}
func scopeContains(raw, wanted string) bool {
	for _, item := range strings.Fields(raw) {
		if item == wanted {
			return true
		}
	}
	return false
}
func mergeScopes(old, added []string) string {
	seen := map[string]bool{}
	values := make([]string, 0, len(old)+len(added))
	for _, item := range append(old, added...) {
		if item != "" && !seen[item] {
			seen[item] = true
			values = append(values, item)
		}
	}
	return strings.Join(values, " ")
}
func addOAuthError(raw, state, code string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	q := u.Query()
	q.Set("error", code)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	return u.String()
}
