package server

import (
	"testing"
	"time"

	"github.com/Cong0707/sso/internal/model"
)

func TestUserBindingViewsUnifiesEmailAndUpstreamIdentities(t *testing.T) {
	db := openTestDatabase(t)
	application := &Server{DB: db}
	user := model.User{Username: "binding-user", PasswordHash: "hash", PasswordConfigured: true, Locale: "zh-CN", Role: "user", Status: "active"}
	if err := db.Create(&user).Error; err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	email := model.UserEmail{UserID: user.ID, Email: "first@example.com", NormalizedEmail: "first@example.com", VerifiedAt: &now}
	if err := db.Create(&email).Error; err != nil {
		t.Fatal(err)
	}
	provider := model.UpstreamProvider{Kind: "github", DisplayName: "GitHub"}
	if err := db.Create(&provider).Error; err != nil {
		t.Fatal(err)
	}
	identity := model.UpstreamIdentity{UserID: user.ID, ProviderID: provider.ID, ExternalID: "12301923", ExternalName: "octocat", ExternalEmail: "octocat@example.com", VerifiedAt: &now, LastLoginAt: now}
	if err := db.Create(&identity).Error; err != nil {
		t.Fatal(err)
	}

	bindings := application.userBindingViews(user.ID)
	if len(bindings) != 2 {
		t.Fatalf("expected two unified bindings, got %#v", bindings)
	}
	if bindings[0].BindingType != "email" || bindings[0].Identifier != "first@example.com" || !bindings[0].Verified {
		t.Fatalf("unexpected email binding: %#v", bindings[0])
	}
	if bindings[1].BindingType != "upstream" || bindings[1].Kind != "github" || bindings[1].DisplayName != "GitHub" || bindings[1].Identifier != "12301923" || bindings[1].AccountName != "octocat" {
		t.Fatalf("unexpected upstream binding: %#v", bindings[1])
	}
}
