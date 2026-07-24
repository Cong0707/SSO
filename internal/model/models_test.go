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
		t.Fatalf("schema v3 is not ready: %v", err)
	}
}
