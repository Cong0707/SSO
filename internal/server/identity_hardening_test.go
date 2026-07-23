package server

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Cong0707/sso/internal/config"
	"github.com/Cong0707/sso/internal/model"
	"github.com/Cong0707/sso/internal/security"
	"github.com/Cong0707/sso/internal/upstream"
	"github.com/gin-gonic/gin"
)

func TestRegistrationDisabledBlocksNewUpstreamUser(t *testing.T) {
	db := openTestDatabase(t)
	if err := db.Create(&model.SystemSetting{Key: settingRegistrationEnabled, Value: "false"}).Error; err != nil {
		t.Fatal(err)
	}
	application := &Server{DB: db, Cfg: config.Config{MasterKey: bytes.Repeat([]byte{0x71}, 32)}}
	_, err := application.provisionUpstreamUser(model.UpstreamProvider{Kind: "github"}, upstream.Identity{Subject: "new-subject", Username: "new-user"}, "zhCN")
	if err == nil {
		t.Fatal("registration-disabled SSO provisioned a new upstream-only account")
	}
}

func TestMFASetupCannotReplaceEnabledFactor(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := openTestDatabase(t)
	masterKey := bytes.Repeat([]byte{0x72}, 32)
	oldSecret, err := security.Encrypt(masterKey, "JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatal(err)
	}
	user := model.User{Username: "mfa-owner", PasswordHash: "unused", PasswordConfigured: true, Locale: "zhCN", Role: "user", Status: "active", MFAEnabled: true, MFASecretEncrypted: oldSecret}
	if err := db.Create(&user).Error; err != nil {
		t.Fatal(err)
	}
	rawSession := "mfa-session"
	session := model.Session{UserID: user.ID, TokenHash: security.HashToken(rawSession), CSRFToken: "csrf", LastSeenAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}
	if err := db.Create(&session).Error; err != nil {
		t.Fatal(err)
	}
	application := &Server{DB: db, Cfg: config.Config{MasterKey: masterKey, SessionTTL: time.Hour}}
	request := httptest.NewRequest(http.MethodPost, "/api/profile/mfa/setup", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookie, Value: rawSession})
	request.Header.Set("X-CSRF-Token", session.CSRFToken)
	recorder := httptest.NewRecorder()
	application.Router().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("unexpected MFA replacement response: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var stored model.User
	if err := db.First(&stored, user.ID).Error; err != nil {
		t.Fatal(err)
	}
	if !stored.MFAEnabled || stored.MFASecretEncrypted != oldSecret {
		t.Fatal("rejected MFA replacement changed the active factor")
	}
}

func TestAdminResetMFADeletesBackupCodes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := openTestDatabase(t)
	admin := model.User{Username: "admin-user", PasswordHash: "unused", PasswordConfigured: true, Locale: "zhCN", Role: "admin", Status: "active"}
	target := model.User{Username: "target-user", PasswordHash: "unused", PasswordConfigured: true, Locale: "zhCN", Role: "user", Status: "active", MFAEnabled: true, MFASecretEncrypted: "encrypted"}
	if err := db.Create(&admin).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&target).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&model.MFABackupCode{UserID: target.ID, CodeHash: security.HashToken("BACKUP-CODE")}).Error; err != nil {
		t.Fatal(err)
	}
	rawSession := "admin-session"
	session := model.Session{UserID: admin.ID, TokenHash: security.HashToken(rawSession), CSRFToken: "csrf", LastSeenAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}
	if err := db.Create(&session).Error; err != nil {
		t.Fatal(err)
	}
	application := &Server{DB: db, Cfg: config.Config{SessionTTL: time.Hour}}
	request := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/admin/users/%d/mfa", target.ID), nil)
	request.AddCookie(&http.Cookie{Name: sessionCookie, Value: rawSession})
	request.Header.Set("X-CSRF-Token", session.CSRFToken)
	recorder := httptest.NewRecorder()
	application.Router().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("admin MFA reset failed: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var count int64
	if err := db.Model(&model.MFABackupCode{}).Where("user_id = ?", target.ID).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("admin MFA reset left %d backup-code rows", count)
	}
}

func TestMergeTransfersBackupCodesWithAdoptedMFA(t *testing.T) {
	db := openTestDatabase(t)
	application := &Server{DB: db}
	target := model.User{Username: "merge-target", PasswordHash: "unused", PasswordConfigured: true, Locale: "zhCN", Role: "user", Status: "active"}
	source := model.User{Username: "merge-source", PasswordHash: "unused", PasswordConfigured: true, Locale: "zhCN", Role: "user", Status: "active", MFAEnabled: true, MFASecretEncrypted: "source-secret"}
	if err := db.Create(&target).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&source).Error; err != nil {
		t.Fatal(err)
	}
	code := model.MFABackupCode{UserID: source.ID, CodeHash: security.HashToken("SOURCE-CODE")}
	if err := db.Create(&code).Error; err != nil {
		t.Fatal(err)
	}
	merged, _, err := application.mergeAccounts(target.ID, source.ID)
	if err != nil {
		t.Fatal(err)
	}
	var stored model.MFABackupCode
	if err := db.First(&stored, code.ID).Error; err != nil {
		t.Fatal(err)
	}
	if !merged.MFAEnabled || stored.UserID != merged.ID {
		t.Fatalf("MFA backup code was not moved to canonical user: merged=%#v code=%#v", merged, stored)
	}
}

func TestOIDCMultipleEmailsExposeDeterministicStandardEmailClaim(t *testing.T) {
	db := openTestDatabase(t)
	application := &Server{DB: db}
	user := model.User{Username: "multi-email-claim", PasswordHash: "unused", PasswordConfigured: true, Locale: "zhCN", Role: "user", Status: "active"}
	if err := db.Create(&user).Error; err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	emails := []model.UserEmail{{UserID: user.ID, Email: "first@example.com", NormalizedEmail: "first@example.com", VerifiedAt: &now}, {UserID: user.ID, Email: "second@example.com", NormalizedEmail: "second@example.com", VerifiedAt: &now}}
	if err := db.Create(&emails).Error; err != nil {
		t.Fatal(err)
	}
	claims := application.emailClaims(user.ID)
	if claims["email"] != "first@example.com" || claims["email_verified"] != true {
		t.Fatalf("unexpected email claims: %#v", claims)
	}
}
