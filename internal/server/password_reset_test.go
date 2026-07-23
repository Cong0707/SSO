package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Cong0707/sso/internal/config"
	"github.com/Cong0707/sso/internal/model"
	"github.com/Cong0707/sso/internal/security"
)

func TestPasswordResetChangesPasswordAndRevokesCredentials(t *testing.T) {
	db := openTestDatabase(t)
	oldHash, err := security.HashPassword("OldPassword123")
	if err != nil {
		t.Fatal(err)
	}
	user := model.User{
		Username: "reset-user", PasswordHash: oldHash, PasswordConfigured: true,
		Locale: "zhCN", Role: "user", Status: "active",
	}
	if err := db.Create(&user).Error; err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	email := model.UserEmail{
		UserID: user.ID, Email: "reset@example.com",
		NormalizedEmail: "reset@example.com", VerifiedAt: &now,
	}
	if err := db.Create(&email).Error; err != nil {
		t.Fatal(err)
	}
	session := model.Session{
		UserID: user.ID, TokenHash: security.HashToken("old-session"), CSRFToken: "csrf",
		LastSeenAt: now, ExpiresAt: now.Add(time.Hour),
	}
	if err := db.Create(&session).Error; err != nil {
		t.Fatal(err)
	}
	pat := model.PersonalAccessToken{
		UserID: user.ID, Name: "old-pat", Prefix: "sso_pat_old",
		TokenHash: security.HashToken("sso_pat_old-token"), Scopes: "profile",
	}
	if err := db.Create(&pat).Error; err != nil {
		t.Fatal(err)
	}
	oauthToken := model.OAuthTokenRecord{
		UserID: user.ID, ClientID: "reset-client", TokenFamilyID: "reset-family",
		AccessHash: security.HashToken("old-oauth-access"), PayloadEncrypted: "unused",
		ExpiresAt: now.Add(time.Hour),
	}
	if err := db.Create(&oauthToken).Error; err != nil {
		t.Fatal(err)
	}

	application := &Server{DB: db, Cfg: config.Config{
		MasterKey: bytes.Repeat([]byte{0x81}, 32), EmailDebug: true,
	}}
	httpServer := httptest.NewServer(application.Router())
	t.Cleanup(httpServer.Close)
	client := httpServer.Client()

	prepared := doJSON(t, client, http.MethodPost, httpServer.URL+"/api/auth/password-reset/prepare", "", map[string]any{
		"email": "RESET@example.com", "locale": "zhCN",
	})
	flowToken := nestedString(t, prepared, "data", "flow_token")
	code := nestedString(t, prepared, "data", "debug_code")
	if flowToken == "" || code == "" {
		t.Fatalf("password reset did not return local debug flow: %#v", prepared)
	}
	doJSON(t, client, http.MethodPost, httpServer.URL+"/api/auth/password-reset/complete", "", map[string]any{
		"flow_token": flowToken, "code": code,
		"new_password": "NewPassword456", "confirm_password": "NewPassword456",
	})

	var updated model.User
	if err := db.First(&updated, user.ID).Error; err != nil {
		t.Fatal(err)
	}
	if !security.VerifyPassword(updated.PasswordHash, "NewPassword456") || security.VerifyPassword(updated.PasswordHash, "OldPassword123") {
		t.Fatal("password reset did not replace the password hash")
	}
	if err := db.First(&session, session.ID).Error; err != nil || session.RevokedAt == nil {
		t.Fatalf("password reset left session active: session=%#v err=%v", session, err)
	}
	if err := db.First(&pat, pat.ID).Error; err != nil || pat.RevokedAt == nil {
		t.Fatalf("password reset left PAT active: pat=%#v err=%v", pat, err)
	}
	if err := db.First(&oauthToken, oauthToken.ID).Error; err != nil || oauthToken.RevokedAt == nil {
		t.Fatalf("password reset left OAuth token active: token=%#v err=%v", oauthToken, err)
	}
}

func TestPasswordResetPrepareDoesNotRevealUnknownEmail(t *testing.T) {
	db := openTestDatabase(t)
	application := &Server{DB: db, Cfg: config.Config{
		MasterKey: bytes.Repeat([]byte{0x82}, 32), EmailDebug: true,
	}}
	httpServer := httptest.NewServer(application.Router())
	t.Cleanup(httpServer.Close)

	prepared := doJSON(t, httpServer.Client(), http.MethodPost, httpServer.URL+"/api/auth/password-reset/prepare", "", map[string]any{
		"email": "missing@example.com", "locale": "zhCN",
	})
	if nestedString(t, prepared, "data", "flow_token") == "" {
		t.Fatalf("unknown email did not receive the generic reset flow response: %#v", prepared)
	}
	data := prepared["data"].(map[string]any)
	if _, leaked := data["debug_code"]; leaked {
		t.Fatalf("unknown email response exposed a debug reset code: %#v", prepared)
	}
}
