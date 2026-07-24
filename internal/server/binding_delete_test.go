package server

import (
	"testing"
	"time"

	"github.com/Cong0707/sso/internal/model"
	"gorm.io/gorm"
)

func TestFindUserByEmailTreatsEveryEmailEqually(t *testing.T) {
	db := openTestDatabase(t)
	application := &Server{DB: db}
	user := model.User{Username: "multi-email", PasswordHash: "hash", PasswordConfigured: true, Locale: "zh-CN", Role: "user", Status: "active"}
	if err := db.Create(&user).Error; err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	emails := []model.UserEmail{
		{UserID: user.ID, Email: "first@example.com", NormalizedEmail: "first@example.com", VerifiedAt: &now},
		{UserID: user.ID, Email: "second@example.com", NormalizedEmail: "second@example.com", VerifiedAt: &now},
	}
	if err := db.Create(&emails).Error; err != nil {
		t.Fatal(err)
	}
	for _, email := range emails {
		found, err := application.findUserByEmail(email.Email)
		if err != nil || found.ID != user.ID {
			t.Fatalf("email %q did not resolve equally: user=%#v err=%v", email.Email, found, err)
		}
	}
}

func TestDeleteEmailBindingRemovesOnlyRequestedRecord(t *testing.T) {
	db := openTestDatabase(t)
	application := &Server{DB: db}
	now := time.Now()
	user := model.User{Username: "email-owner", PasswordHash: "hash", PasswordConfigured: true, Locale: "zh-CN", Role: "user", Status: "active"}
	if err := db.Create(&user).Error; err != nil {
		t.Fatal(err)
	}
	first := model.UserEmail{UserID: user.ID, Email: "first@example.com", NormalizedEmail: "first@example.com", VerifiedAt: &now}
	second := model.UserEmail{UserID: user.ID, Email: "second@example.com", NormalizedEmail: "second@example.com", VerifiedAt: &now}
	if err := db.Create(&first).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&second).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Transaction(func(tx *gorm.DB) error { return application.deleteEmailBinding(tx, user.ID, first.ID, false) }); err != nil {
		t.Fatalf("delete email binding: %v", err)
	}
	var count int64
	db.Model(&model.UserEmail{}).Where("id = ?", first.ID).Count(&count)
	if count != 0 {
		t.Fatalf("deleted email still exists: %d", count)
	}
	if err := db.First(&second, second.ID).Error; err != nil {
		t.Fatalf("unrelated email binding changed: %#v err=%v", second, err)
	}
}

func TestUserCannotDeleteLastBinding(t *testing.T) {
	db := openTestDatabase(t)
	application := &Server{DB: db}
	user := model.User{Username: "provider-only", PasswordHash: "hash", PasswordConfigured: false, Locale: "zh-CN", Role: "user", Status: "active"}
	if err := db.Create(&user).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Model(&user).Update("password_configured", false).Error; err != nil {
		t.Fatal(err)
	}
	provider := model.UpstreamProvider{Kind: "github-delete", DisplayName: "GitHub"}
	if err := db.Create(&provider).Error; err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	identity := model.UpstreamIdentity{UserID: user.ID, ProviderID: provider.ID, ExternalID: "only-login", VerifiedAt: &now, LastLoginAt: now}
	if err := db.Create(&identity).Error; err != nil {
		t.Fatal(err)
	}
	err := db.Transaction(func(tx *gorm.DB) error { return application.deleteUpstreamBinding(tx, user.ID, identity.ID, false) })
	if err == nil || err.Error() != "账号必须保留至少一个绑定" {
		t.Fatalf("unexpected removal result: %v", err)
	}
	var count int64
	db.Model(&model.UpstreamIdentity{}).Where("id = ?", identity.ID).Count(&count)
	if count != 1 {
		t.Fatalf("last login binding was deleted")
	}
}

func TestAdminCanDeleteLastBinding(t *testing.T) {
	db := openTestDatabase(t)
	application := &Server{DB: db}
	user := model.User{Username: "admin-delete", PasswordHash: "hash", PasswordConfigured: true, Locale: "zh-CN", Role: "user", Status: "active"}
	if err := db.Create(&user).Error; err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	email := model.UserEmail{UserID: user.ID, Email: "only@example.com", NormalizedEmail: "only@example.com", VerifiedAt: &now}
	if err := db.Create(&email).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Transaction(func(tx *gorm.DB) error { return application.deleteEmailBinding(tx, user.ID, email.ID, true) }); err != nil {
		t.Fatalf("admin delete last binding: %v", err)
	}
	var count int64
	db.Model(&model.UserEmail{}).Where("id = ?", email.ID).Count(&count)
	if count != 0 {
		t.Fatalf("last binding still exists: %d", count)
	}
}
