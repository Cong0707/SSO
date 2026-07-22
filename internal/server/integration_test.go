package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Cong0707/sso/internal/config"
	"github.com/Cong0707/sso/internal/model"
	"github.com/gin-gonic/gin"
	"net/http/httptest"
)

func TestRegistrationAndOIDCAuthorizationCodeFlow(t *testing.T) {
	gin.SetMode(gin.TestMode)
	temp := t.TempDir()
	cfg := config.Config{
		Addr:                ":0",
		Issuer:              "http://issuer.invalid",
		DatabaseDriver:      "sqlite",
		DatabaseDSN:         filepath.Join(temp, "sso.db"),
		OAuthTokenDB:        ":memory:",
		WebDir:              filepath.Join(temp, "web"),
		SessionTTL:          24 * time.Hour,
		RegistrationEnabled: true,
		MasterKey:           bytes.Repeat([]byte{0x41}, 32),
	}
	db, err := model.Open(cfg)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("get database connection: %v", err)
	}
	defer sqlDB.Close()
	application, err := New(cfg, db)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	httpServer := httptest.NewServer(application.Router())
	defer httpServer.Close()
	application.Cfg.Issuer = httpServer.URL

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookie jar: %v", err)
	}
	client := &http.Client{Jar: jar, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}

	register := doJSON(t, client, http.MethodPost, httpServer.URL+"/api/auth/register", "", map[string]any{"username": "alice", "email": "alice@example.com", "password": "Password123"})
	csrf := nestedString(t, register, "data", "csrf_token")
	if nestedString(t, register, "data", "user", "username") != "alice" {
		t.Fatal("registration returned an unexpected user")
	}

	created := doJSON(t, client, http.MethodPost, httpServer.URL+"/api/apps", csrf, map[string]any{"name": "Integration App", "homepage": "http://client.example", "description": "test", "redirect_uri": "http://client.example/callback", "logo_url": "", "public": false})
	clientID := nestedString(t, created, "data", "app", "client_id")
	clientSecret := nestedString(t, created, "data", "client_secret")
	pat := doJSON(t, client, http.MethodPost, httpServer.URL+"/api/profile/tokens", csrf, map[string]any{"name": "integration"})
	plainPAT := nestedString(t, pat, "data", "plain_token")
	patRequest, _ := http.NewRequest(http.MethodGet, httpServer.URL+"/api/profile", nil)
	patRequest.Header.Set("Authorization", "Bearer "+plainPAT)
	patProfile := doRawRequest(t, client, patRequest)
	defer patProfile.Body.Close()
	if patProfile.StatusCode != http.StatusOK {
		t.Fatalf("PAT profile status = %d", patProfile.StatusCode)
	}

	verifier := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~abc"
	challengeBytes := sha256.Sum256([]byte(verifier))
	query := url.Values{"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {"http://client.example/callback"}, "scope": {"openid profile email"}, "state": {"state-123"}, "nonce": {"nonce-123"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(challengeBytes[:])}, "code_challenge_method": {"S256"}}
	authorizeURL := httpServer.URL + "/oauth/authorize?" + query.Encode()
	first := doRequest(t, client, http.MethodGet, authorizeURL, "", nil, "")
	if first.StatusCode != http.StatusFound {
		t.Fatalf("authorize status = %d", first.StatusCode)
	}
	consentLocation := first.Header.Get("Location")
	consentURL, err := url.Parse(consentLocation)
	if err != nil {
		t.Fatalf("parse consent location: %v", err)
	}
	originalRequest := consentURL.Query().Get("request")
	if originalRequest == "" {
		t.Fatalf("missing consent request in %q", consentLocation)
	}

	consentInfo := doRequest(t, client, http.MethodGet, httpServer.URL+"/api/oauth/consent?request="+url.QueryEscape(originalRequest), "", nil, "")
	if consentInfo.StatusCode != http.StatusOK {
		t.Fatalf("consent info status = %d", consentInfo.StatusCode)
	}
	consentInfo.Body.Close()
	decision := doJSON(t, client, http.MethodPost, httpServer.URL+"/api/oauth/consent", csrf, map[string]any{"request": originalRequest, "approved": true})
	approvedURL := nestedString(t, decision, "data", "redirect_url")
	approved := doRequest(t, client, http.MethodGet, httpServer.URL+approvedURL, "", nil, "")
	if approved.StatusCode != http.StatusFound {
		t.Fatalf("approved authorize status = %d", approved.StatusCode)
	}
	callback, err := url.Parse(approved.Header.Get("Location"))
	approved.Body.Close()
	if err != nil {
		t.Fatalf("parse callback: %v", err)
	}
	code := callback.Query().Get("code")
	if code == "" || callback.Query().Get("state") != "state-123" {
		t.Fatalf("invalid callback %q", callback.String())
	}

	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {clientID}, "client_secret": {clientSecret}, "code": {code}, "redirect_uri": {"http://client.example/callback"}, "code_verifier": {verifier}}
	tokenResponse := doRequest(t, client, http.MethodPost, httpServer.URL+"/oauth/token", "", strings.NewReader(form.Encode()), "application/x-www-form-urlencoded")
	defer tokenResponse.Body.Close()
	var token map[string]any
	if err := json.NewDecoder(tokenResponse.Body).Decode(&token); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if tokenResponse.StatusCode != http.StatusOK {
		t.Fatalf("token status = %d response = %#v", tokenResponse.StatusCode, token)
	}
	access, _ := token["access_token"].(string)
	idToken, _ := token["id_token"].(string)
	if access == "" || idToken == "" {
		t.Fatalf("missing tokens in %#v", token)
	}

	userinfoRequest, _ := http.NewRequest(http.MethodGet, httpServer.URL+"/oauth/userinfo", nil)
	userinfoRequest.Header.Set("Authorization", "Bearer "+access)
	userinfo := doRawRequest(t, client, userinfoRequest)
	defer userinfo.Body.Close()
	var claims map[string]any
	if err := json.NewDecoder(userinfo.Body).Decode(&claims); err != nil {
		t.Fatalf("decode userinfo: %v", err)
	}
	if userinfo.StatusCode != http.StatusOK || claims["preferred_username"] != "alice" {
		t.Fatalf("unexpected userinfo status=%d claims=%#v", userinfo.StatusCode, claims)
	}
}

func doJSON(t *testing.T, client *http.Client, method, endpoint, csrf string, body any) map[string]any {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	response := doRequest(t, client, method, endpoint, csrf, bytes.NewReader(encoded), "application/json")
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("decode response status=%d body=%q: %v", response.StatusCode, data, err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		t.Fatalf("request %s %s status=%d response=%#v", method, endpoint, response.StatusCode, payload)
	}
	return payload
}

func doRequest(t *testing.T, client *http.Client, method, endpoint, csrf string, body io.Reader, contentType string) *http.Response {
	t.Helper()
	request, err := http.NewRequest(method, endpoint, body)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if csrf != "" {
		request.Header.Set("X-CSRF-Token", csrf)
	}
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	return doRawRequest(t, client, request)
}

func doRawRequest(t *testing.T, client *http.Client, request *http.Request) *http.Response {
	t.Helper()
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("request %s %s: %v", request.Method, request.URL, err)
	}
	return response
}

func nestedString(t *testing.T, value map[string]any, path ...string) string {
	t.Helper()
	var current any = value
	for _, key := range path {
		object, ok := current.(map[string]any)
		if !ok {
			t.Fatalf("path %v traversed non-object %#v", path, current)
		}
		current = object[key]
	}
	text, ok := current.(string)
	if !ok {
		t.Fatalf("path %v is not a string: %#v", path, current)
	}
	return text
}
