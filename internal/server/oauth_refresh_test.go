package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Cong0707/sso/internal/config"
	"github.com/Cong0707/sso/internal/model"
	"github.com/Cong0707/sso/internal/security"
	"github.com/gin-gonic/gin"
	oauthModels "github.com/go-oauth2/oauth2/v4/models"
	"gorm.io/gorm"
)

func TestOAuthRefreshWithBasicAuthClaimsTokenBeforeExchange(t *testing.T) {
	gin.SetMode(gin.TestMode)
	temp := t.TempDir()
	cfg := config.Config{
		Issuer:             "http://issuer.invalid",
		DatabaseDriver:     "sqlite",
		DatabaseDSN:        filepath.Join(temp, "sso.db"),
		DataDir:            temp,
		OIDCSigningKeyFile: filepath.Join(temp, "oidc-signing.pem"),
		AllowKeyGeneration: true,
		SessionTTL:         time.Hour,
		MasterKey:          bytes.Repeat([]byte{0x61}, 32),
	}
	db, err := model.Open(cfg)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("get database handle: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	application, err := New(cfg, db)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	t.Cleanup(func() { _ = application.Close() })

	user := model.User{
		Username: "basic-refresh-user", PasswordHash: "unused", PasswordConfigured: true,
		Locale: "zhCN", Role: "user", Status: "active",
	}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	clientSecret := "basic-refresh-secret"
	secretHash := sha256.Sum256([]byte(clientSecret))
	app := model.OAuthApplication{
		OwnerID: user.ID, Name: "Basic refresh client", RedirectURI: "https://client.example/callback",
		ClientID: "basic-refresh-client", ClientSecretHash: hex.EncodeToString(secretHash[:]),
		AllowedScopes: "openid profile email",
	}
	if err := db.Create(&app).Error; err != nil {
		t.Fatalf("create app: %v", err)
	}
	grant := model.Grant{UserID: user.ID, AppID: app.ID, Scopes: "openid profile"}
	if err := db.Create(&grant).Error; err != nil {
		t.Fatalf("create grant: %v", err)
	}

	const refreshToken = "basic-refresh-token"
	token := oauthModels.NewToken()
	token.SetClientID(app.ClientID)
	token.SetUserID(idString(user.ID))
	token.SetScope("openid profile")
	token.SetAccess("basic-old-access-token")
	token.SetAccessCreateAt(time.Now())
	token.SetAccessExpiresIn(time.Hour)
	token.SetRefresh(refreshToken)
	token.SetRefreshCreateAt(time.Now())
	token.SetRefreshExpiresIn(30 * 24 * time.Hour)
	if err := application.Tokens.Create(context.Background(), token); err != nil {
		t.Fatalf("create token: %v", err)
	}

	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}}
	request := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(app.ClientID, clientSecret)
	recorder := httptest.NewRecorder()
	application.Router().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("refresh failed: status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	var record model.OAuthTokenRecord
	if err := db.Where("refresh_hash = ?", security.HashToken(refreshToken)).First(&record).Error; err != nil {
		t.Fatalf("load refresh token record: %v", err)
	}
	if record.RefreshConsumedAt == nil {
		t.Fatal("HTTP Basic refresh skipped the atomic refresh-token claim")
	}
}

func TestOAuthRevokeWithBasicAuthParsesFormToken(t *testing.T) {
	application, db, app, clientSecret, user := newOAuthTokenTestServer(t, 0x62)
	refreshToken := createOAuthTokenRecord(t, application, user.ID, app.ClientID, "revoke-old-access", "revoke-refresh", time.Now(), time.Hour)

	form := url.Values{"token": {refreshToken}, "token_type_hint": {"refresh_token"}}
	request := httptest.NewRequest(http.MethodPost, "/oauth/revoke", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(app.ClientID, clientSecret)
	recorder := httptest.NewRecorder()
	application.Router().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("revoke failed: status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	var record model.OAuthTokenRecord
	if err := db.Where("refresh_hash = ?", security.HashToken(refreshToken)).First(&record).Error; err != nil {
		t.Fatalf("load refresh token record: %v", err)
	}
	if record.RevokedAt == nil {
		t.Fatal("HTTP Basic revoke skipped the form token and left the refresh token active")
	}
}

func TestOAuthIntrospectRejectsExpiredAccessTokenWithLiveRefresh(t *testing.T) {
	application, _, app, clientSecret, user := newOAuthTokenTestServer(t, 0x63)
	accessToken := "expired-access-token"
	createOAuthTokenRecord(t, application, user.ID, app.ClientID, accessToken, "live-refresh-token", time.Now().Add(-2*time.Hour), time.Hour)

	form := url.Values{"token": {accessToken}}
	request := httptest.NewRequest(http.MethodPost, "/oauth/introspect", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(app.ClientID, clientSecret)
	recorder := httptest.NewRecorder()
	application.Router().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("introspection failed: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Active bool `json:"active"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode introspection response: %v", err)
	}
	if response.Active {
		t.Fatal("expired access token was reported active while its refresh token was still live")
	}
}

func newOAuthTokenTestServer(t *testing.T, keyByte byte) (*Server, *gorm.DB, model.OAuthApplication, string, model.User) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	temp := t.TempDir()
	cfg := config.Config{
		Issuer:             "http://issuer.invalid",
		DatabaseDriver:     "sqlite",
		DatabaseDSN:        filepath.Join(temp, "sso.db"),
		DataDir:            temp,
		OIDCSigningKeyFile: filepath.Join(temp, "oidc-signing.pem"),
		AllowKeyGeneration: true,
		SessionTTL:         time.Hour,
		MasterKey:          bytes.Repeat([]byte{keyByte}, 32),
	}
	db, err := model.Open(cfg)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("get database handle: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	application, err := New(cfg, db)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	t.Cleanup(func() { _ = application.Close() })

	user := model.User{
		Username: "oauth-token-user", PasswordHash: "unused", PasswordConfigured: true,
		Locale: "zhCN", Role: "user", Status: "active",
	}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	clientSecret := "oauth-token-secret"
	secretHash := sha256.Sum256([]byte(clientSecret))
	app := model.OAuthApplication{
		OwnerID: user.ID, Name: "OAuth token client", RedirectURI: "https://client.example/callback",
		ClientID: "oauth-token-client", ClientSecretHash: hex.EncodeToString(secretHash[:]),
		AllowedScopes: "openid profile email",
	}
	if err := db.Create(&app).Error; err != nil {
		t.Fatalf("create app: %v", err)
	}
	grant := model.Grant{UserID: user.ID, AppID: app.ID, Scopes: "openid profile"}
	if err := db.Create(&grant).Error; err != nil {
		t.Fatalf("create grant: %v", err)
	}
	return application, db, app, clientSecret, user
}

func createOAuthTokenRecord(t *testing.T, application *Server, userID uint64, clientID, accessToken, refreshToken string, accessCreatedAt time.Time, accessExpiresIn time.Duration) string {
	t.Helper()
	token := oauthModels.NewToken()
	token.SetClientID(clientID)
	token.SetUserID(idString(userID))
	token.SetScope("openid profile")
	token.SetAccess(accessToken)
	token.SetAccessCreateAt(accessCreatedAt)
	token.SetAccessExpiresIn(accessExpiresIn)
	token.SetRefresh(refreshToken)
	token.SetRefreshCreateAt(time.Now())
	token.SetRefreshExpiresIn(30 * 24 * time.Hour)
	if err := application.Tokens.Create(context.Background(), token); err != nil {
		t.Fatalf("create token: %v", err)
	}
	return refreshToken
}
