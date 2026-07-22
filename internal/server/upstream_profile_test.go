package server

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Cong0707/sso/internal/config"
	"github.com/Cong0707/sso/internal/model"
	"github.com/Cong0707/sso/internal/upstream"
	oauthModels "github.com/go-oauth2/oauth2/v4/models"
	"gorm.io/gorm"
)

func TestProvisionUpstreamUserImportsProfileAndAllowsLaterUserEdits(t *testing.T) {
	db := openTestDatabase(t)
	application := &Server{DB: db}
	provider := model.UpstreamProvider{Kind: "github"}
	identity := upstream.Identity{
		Subject: "42", Username: "octocat", Name: "The Octocat", Email: "octocat@example.com",
		AvatarURL: "https://avatars.example/octocat.png", EmailVerified: true,
	}
	user, err := application.provisionUpstreamUser(provider, identity)
	if err != nil {
		t.Fatalf("provision upstream user: %v", err)
	}
	if user.Username != "octocat" || user.DisplayName != "The Octocat" || user.Email != "octocat@example.com" || user.AvatarURL == "" {
		t.Fatalf("profile was not imported: %#v", user)
	}
	if user.PasswordConfigured {
		t.Fatal("upstream-created account must require the user to configure a local password")
	}

	user.DisplayName = "Custom Name"
	user.Email = "custom@example.com"
	user.AvatarURL = "https://cdn.example/custom.png"
	if err := db.Save(&user).Error; err != nil {
		t.Fatalf("save user edits: %v", err)
	}
	changed := identity
	changed.Name = "Changed Upstream Name"
	changed.Email = "changed@example.com"
	changed.AvatarURL = "https://avatars.example/changed.png"
	if err := application.syncUpstreamProfile(&user, changed); err != nil {
		t.Fatalf("sync upstream profile: %v", err)
	}
	if user.DisplayName != "Custom Name" || user.Email != "custom@example.com" || user.AvatarURL != "https://cdn.example/custom.png" {
		t.Fatalf("user edits were overwritten: %#v", user)
	}
}

func TestSyncUpstreamProfileReplacesPlaceholderWithVerifiedEmail(t *testing.T) {
	db := openTestDatabase(t)
	application := &Server{DB: db}
	provider := model.UpstreamProvider{Kind: "discord"}
	user, err := application.provisionUpstreamUser(provider, upstream.Identity{Subject: "100", Username: "user100"})
	if err != nil {
		t.Fatalf("provision placeholder user: %v", err)
	}
	if !strings.HasSuffix(user.Email, "@users.invalid") {
		t.Fatalf("expected placeholder email, got %q", user.Email)
	}
	if err := application.syncUpstreamProfile(&user, upstream.Identity{Subject: "100", Email: "verified@example.com", EmailVerified: true}); err != nil {
		t.Fatalf("sync verified email: %v", err)
	}
	if user.Email != "verified@example.com" || user.EmailVerifiedAt == nil {
		t.Fatalf("verified email was not imported: %#v", user)
	}
}

func TestDatabaseTokenStoreEncryptsPayloadAndSharesLookupState(t *testing.T) {
	db := openTestDatabase(t)
	key := bytes.Repeat([]byte{0x31}, 32)
	store := newDatabaseTokenStore(db, key)
	token := oauthModels.NewToken()
	token.SetClientID("client")
	token.SetUserID("user")
	token.SetAccess("access-secret")
	token.SetAccessCreateAt(time.Now())
	token.SetAccessExpiresIn(time.Hour)
	token.SetRefresh("refresh-secret")
	token.SetRefreshCreateAt(time.Now())
	token.SetRefreshExpiresIn(24 * time.Hour)
	if err := store.Create(context.Background(), token); err != nil {
		t.Fatalf("create token: %v", err)
	}
	var record model.OAuthTokenRecord
	if err := db.First(&record).Error; err != nil {
		t.Fatalf("read token record: %v", err)
	}
	if strings.Contains(record.PayloadEncrypted, "access-secret") || record.AccessHash == "access-secret" || record.RefreshHash == "refresh-secret" {
		t.Fatalf("raw token leaked into persistence: %#v", record)
	}
	loaded, err := store.GetByAccess(context.Background(), "access-secret")
	if err != nil || loaded == nil || loaded.GetUserID() != "user" {
		t.Fatalf("load token: info=%#v err=%v", loaded, err)
	}
	if err := store.RemoveByRefresh(context.Background(), "refresh-secret"); err != nil {
		t.Fatalf("remove refresh token: %v", err)
	}
	loaded, err = store.GetByAccess(context.Background(), "access-secret")
	if err != nil || loaded != nil {
		t.Fatalf("token should have been removed: info=%#v err=%v", loaded, err)
	}
}

func openTestDatabase(t *testing.T) *gorm.DB {
	t.Helper()
	cfg := config.Config{DatabaseDriver: "sqlite", DatabaseDSN: filepath.Join(t.TempDir(), "test.db")}
	db, err := model.Open(cfg)
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("get test database handle: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	return db
}
