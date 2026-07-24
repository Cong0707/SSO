package server

import (
	"errors"
	"testing"
	"time"

	"github.com/Cong0707/sso/internal/model"
)

func TestLegacyIdentifiersRequireUnambiguousAccountSelection(t *testing.T) {
	db := openTestDatabase(t)
	first := model.User{Username: "LegacyUser", PasswordHash: "hash", PasswordConfigured: true, Locale: "zhCN", Role: "user", Status: "active"}
	second := model.User{Username: "legacyuser", PasswordHash: "hash", PasswordConfigured: true, Locale: "zhCN", Role: "user", Status: "active"}
	if err := db.Create(&first).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&second).Error; err != nil {
		t.Fatal(err)
	}
	aliases := []model.LegacyLoginIdentifier{
		{UserID: first.ID, Kind: "email", Identifier: "shared@example.com", NormalizedIdentifier: "shared@example.com", SourceSystem: "new-api", SourceUserID: 1},
		{UserID: second.ID, Kind: "email", Identifier: "SHARED@example.com", NormalizedIdentifier: "shared@example.com", SourceSystem: "new-api", SourceUserID: 2},
	}
	if err := db.Create(&aliases).Error; err != nil {
		t.Fatal(err)
	}
	application := &Server{DB: db}

	resolved, err := application.findUserByIdentifier("LegacyUser")
	if err != nil || resolved.ID != first.ID {
		t.Fatalf("exact username did not resolve first account: user=%#v err=%v", resolved, err)
	}
	resolved, err = application.findUserByIdentifier("legacyuser")
	if err != nil || resolved.ID != second.ID {
		t.Fatalf("exact username did not resolve second account: user=%#v err=%v", resolved, err)
	}
	if _, err := application.findUserByIdentifier("shared@example.com"); !errors.Is(err, errAmbiguousIdentifier) {
		t.Fatalf("shared legacy email did not require username selection: %v", err)
	}
	if _, err := application.findUserByIdentifier("LEGACYUSER"); !errors.Is(err, errAmbiguousIdentifier) {
		t.Fatalf("case-folded username collision did not require exact casing: %v", err)
	}

	if err := db.Model(&second).Update("status", "deactivated").Error; err != nil {
		t.Fatal(err)
	}
	resolved, err = application.findUserByIdentifier("shared@example.com")
	if err != nil || resolved.ID != first.ID {
		t.Fatalf("single active legacy email account did not resolve: user=%#v err=%v", resolved, err)
	}
	if err := db.Model(&second).Update("status", "active").Error; err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	verified := model.UserEmail{UserID: first.ID, Email: "shared@example.com", NormalizedEmail: "shared@example.com", VerifiedAt: &now}
	if err := db.Create(&verified).Error; err != nil {
		t.Fatal(err)
	}
	resolved, err = application.findUserByIdentifier("shared@example.com")
	if err != nil || resolved.ID != first.ID {
		t.Fatalf("verified email did not override ambiguous legacy aliases: user=%#v err=%v", resolved, err)
	}
}
