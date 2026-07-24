package model

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

type nullableEmailBinding struct {
	ID              uint64 `gorm:"primaryKey"`
	CreatedAt       time.Time
	UpdatedAt       time.Time
	UserID          uint64     `gorm:"not null;index"`
	Email           string     `gorm:"size:254;not null"`
	NormalizedEmail string     `gorm:"size:254;uniqueIndex;not null"`
	VerifiedAt      *time.Time `gorm:"index"`
}

func (nullableEmailBinding) TableName() string { return "user_emails" }

type nullableUpstreamBinding struct {
	ID            uint64 `gorm:"primaryKey"`
	CreatedAt     time.Time
	UpdatedAt     time.Time
	UserID        uint64 `gorm:"not null;index"`
	ProviderID    uint64 `gorm:"not null;uniqueIndex:idx_provider_external"`
	ExternalID    string `gorm:"size:255;not null;uniqueIndex:idx_provider_external"`
	ExternalName  string
	ExternalEmail string
	Metadata      string
	VerifiedAt    *time.Time `gorm:"index"`
	LastLoginAt   time.Time
}

func (nullableUpstreamBinding) TableName() string { return "upstream_identities" }

func TestMigrateMovesUnverifiedEmailsAndEnforcesVerifiedBindings(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "schema-v2.db")), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })

	if err := db.AutoMigrate(&User{}, &UpstreamProvider{}, &nullableEmailBinding{}, &nullableUpstreamBinding{}, &SchemaMigration{}); err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&SchemaMigration{Version: 2, AppliedAt: time.Now().UTC()}).Error; err != nil {
		t.Fatal(err)
	}
	user := User{Username: "legacy-user", PasswordHash: "hash", PasswordConfigured: true, Locale: "zhCN", Role: "user", Status: "active"}
	if err := db.Create(&user).Error; err != nil {
		t.Fatal(err)
	}
	provider := UpstreamProvider{Kind: "github", DisplayName: "GitHub"}
	if err := db.Create(&provider).Error; err != nil {
		t.Fatal(err)
	}
	createdAt := time.Now().UTC().Add(-time.Hour)
	email := nullableEmailBinding{CreatedAt: createdAt, UserID: user.ID, Email: "legacy@example.com", NormalizedEmail: "legacy@example.com"}
	if err := db.Create(&email).Error; err != nil {
		t.Fatal(err)
	}
	identity := nullableUpstreamBinding{CreatedAt: createdAt, UserID: user.ID, ProviderID: provider.ID, ExternalID: "legacy-subject", LastLoginAt: createdAt}
	if err := db.Create(&identity).Error; err != nil {
		t.Fatal(err)
	}

	if err := Migrate(db); err != nil {
		t.Fatalf("migrate schema v2: %v", err)
	}
	var emailCount int64
	if err := db.Model(&UserEmail{}).Where("id = ?", email.ID).Count(&emailCount).Error; err != nil || emailCount != 0 {
		t.Fatalf("unverified email remained a binding: count=%d err=%v", emailCount, err)
	}
	var legacy LegacyLoginIdentifier
	if err := db.Where("user_id = ? AND normalized_identifier = ?", user.ID, email.NormalizedEmail).First(&legacy).Error; err != nil {
		t.Fatalf("unverified email was not preserved as a legacy identifier: %v", err)
	}
	var migratedIdentity UpstreamIdentity
	if err := db.First(&migratedIdentity, identity.ID).Error; err != nil || migratedIdentity.VerifiedAt == nil {
		t.Fatalf("upstream identity was not marked verified: identity=%#v err=%v", migratedIdentity, err)
	}
	if err := db.Create(&UserEmail{UserID: user.ID, Email: "new@example.com", NormalizedEmail: "new@example.com"}).Error; err == nil {
		t.Fatal("database accepted an email binding without verification time")
	}
	if err := db.Create(&UpstreamIdentity{UserID: user.ID, ProviderID: provider.ID, ExternalID: "new-subject", LastLoginAt: time.Now()}).Error; err == nil {
		t.Fatal("database accepted an upstream binding without verification time")
	}
	if err := SchemaReady(db); err != nil {
		t.Fatalf("schema v4 is not ready: %v", err)
	}
}

func TestMigrateLocaleSourcesUsesOnlyExplicitLifecycleEvents(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "locale-v3.db")), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	if err := db.AutoMigrate(&User{}, &AuditEvent{}, &LifecycleEvent{}, &IdentityMigrationMapping{}); err != nil {
		t.Fatal(err)
	}
	users := []User{
		{Username: "mapped-unknown", PasswordHash: "hash", Locale: "en", LocaleSource: LocaleSourceUnknown, Role: "user", Status: "active"},
		{Username: "mapped-explicit", PasswordHash: "hash", Locale: "zhCN", LocaleSource: LocaleSourceUnknown, Role: "user", Status: "active"},
		{Username: "mapped-browser", PasswordHash: "hash", Locale: "ja", LocaleSource: LocaleSourceBrowser, Role: "user", Status: "active"},
		{Username: "mapped-browser-repair", PasswordHash: "hash", Locale: "fr", LocaleSource: LocaleSourceUser, Role: "user", Status: "active"},
		{Username: "mapped-browser-with-later-choice", PasswordHash: "hash", Locale: "fr", LocaleSource: LocaleSourceUser, Role: "user", Status: "active"},
		{Username: "native", PasswordHash: "hash", Locale: "ja", LocaleSource: LocaleSourceUnknown, Role: "user", Status: "active"},
	}
	if err := db.Create(&users).Error; err != nil {
		t.Fatal(err)
	}
	mappedAt := time.Now().UTC().Add(-time.Hour)
	mappings := []IdentityMigrationMapping{
		{CreatedAt: mappedAt, BatchID: "batch", SourceSystem: "new-api", SourceUserID: 1, SSOUserID: users[0].ID},
		{CreatedAt: mappedAt, BatchID: "batch", SourceSystem: "new-api", SourceUserID: 2, SSOUserID: users[1].ID},
		{CreatedAt: mappedAt, BatchID: "batch", SourceSystem: "new-api", SourceUserID: 3, SSOUserID: users[2].ID},
		{CreatedAt: mappedAt, BatchID: "batch", SourceSystem: "new-api", SourceUserID: 4, SSOUserID: users[3].ID},
		{CreatedAt: mappedAt, BatchID: "batch", SourceSystem: "new-api", SourceUserID: 5, SSOUserID: users[4].ID},
	}
	if err := db.Create(&mappings).Error; err != nil {
		t.Fatal(err)
	}
	// A generic profile audit is not proof that the user selected a language.
	if err := db.Create(&AuditEvent{CreatedAt: time.Now().UTC(), UserID: users[0].ID, Action: "profile.updated"}).Error; err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	events := []LifecycleEvent{
		{
			ID: "locale-event-explicit", CreatedAt: now, UserID: users[1].ID, IdentityVersion: 2,
			Type: "profile.updated", Payload: `{"locale":"zhCN","locale_source":"user"}`, NextAttemptAt: now,
		},
		{
			ID: "locale-event-browser", CreatedAt: now, UserID: users[2].ID, IdentityVersion: 2,
			Type: "profile.updated", Payload: `{"locale":"ja","locale_source":"browser"}`, NextAttemptAt: now,
		},
		{
			ID: "locale-event-browser-repair", CreatedAt: now, UserID: users[3].ID, IdentityVersion: 2,
			Type: "profile.updated", Payload: `{"locale":"fr","locale_source":"browser"}`, NextAttemptAt: now,
		},
		{
			ID: "locale-event-browser-later-choice", CreatedAt: now, UserID: users[4].ID, IdentityVersion: 2,
			Type: "profile.updated", Payload: `{"locale":"fr","locale_source":"browser"}`, NextAttemptAt: now,
		},
	}
	if err := db.Create(&events).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&AuditEvent{CreatedAt: now.Add(time.Second), UserID: users[1].ID, Action: "profile.updated"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&AuditEvent{CreatedAt: now.Add(time.Second), UserID: users[3].ID, Action: "profile.locale_initialized", Metadata: "source=browser"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&AuditEvent{CreatedAt: now.Add(time.Second), UserID: users[4].ID, Action: "profile.locale_initialized", Metadata: "source=browser"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&LifecycleEvent{
		ID: "locale-event-later-choice", CreatedAt: now.Add(2 * time.Second), UserID: users[4].ID, IdentityVersion: 3,
		Type: "profile.updated", Payload: `{"locale":"en","locale_source":"user"}`, NextAttemptAt: now.Add(2 * time.Second),
	}).Error; err != nil {
		t.Fatal(err)
	}
	if err := migrateLocaleSources(db); err != nil {
		t.Fatal(err)
	}
	var reloaded []User
	if err := db.Order("id ASC").Find(&reloaded).Error; err != nil {
		t.Fatal(err)
	}
	if reloaded[0].LocaleSource != LocaleSourceUnknown || reloaded[1].LocaleSource != LocaleSourceUser || reloaded[2].LocaleSource != LocaleSourceBrowser || reloaded[3].LocaleSource != LocaleSourceBrowser || reloaded[4].LocaleSource != LocaleSourceUser || reloaded[5].LocaleSource != LocaleSourceUnknown {
		t.Fatalf("unexpected locale sources after migration: %#v", reloaded)
	}
	if reloaded[0].Locale != "en" || reloaded[1].Locale != "zhCN" || reloaded[2].Locale != "ja" || reloaded[3].Locale != "fr" || reloaded[4].Locale != "fr" || reloaded[5].Locale != "ja" {
		t.Fatalf("migration rewrote existing locale values: %#v", reloaded)
	}
}
