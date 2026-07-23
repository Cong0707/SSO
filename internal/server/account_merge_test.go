package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Cong0707/sso/internal/config"
	"github.com/Cong0707/sso/internal/model"
	"github.com/Cong0707/sso/internal/security"
	"github.com/gin-gonic/gin"
)

func TestMergeAccountsPreservesSourceAndMovesBindings(t *testing.T) {
	db := openTestDatabase(t)
	application := &Server{DB: db}
	first := model.User{Username: "first", Email: "first@example.com", PasswordHash: "hash", PasswordConfigured: true, DisplayName: "First", Locale: "zh-CN", Role: "user", Status: "active"}
	second := model.User{Username: "second", Email: "second@example.com", PasswordHash: "hash", PasswordConfigured: true, DisplayName: "Second", Locale: "zh-CN", Role: "admin", Status: "active"}
	if err := db.Create(&first).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&second).Error; err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	emails := []model.UserEmail{
		{UserID: first.ID, OriginalUserID: first.ID, Email: "first@example.com", NormalizedEmail: "first@example.com", Primary: true, VerifiedAt: &now},
		{UserID: second.ID, OriginalUserID: second.ID, Email: "second@example.com", NormalizedEmail: "second@example.com", Primary: true, VerifiedAt: &now},
	}
	if err := db.Create(&emails).Error; err != nil {
		t.Fatal(err)
	}
	provider := model.UpstreamProvider{Kind: "github", DisplayName: "GitHub"}
	if err := db.Create(&provider).Error; err != nil {
		t.Fatal(err)
	}
	identities := []model.UpstreamIdentity{
		{UserID: first.ID, OriginalUserID: first.ID, ProviderID: provider.ID, ExternalID: "github-1", LastLoginAt: now},
		{UserID: second.ID, OriginalUserID: second.ID, ProviderID: provider.ID, ExternalID: "github-2", LastLoginAt: now},
	}
	if err := db.Create(&identities).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&model.Session{UserID: first.ID, TokenHash: "session-1", CSRFToken: "csrf", LastSeenAt: now, ExpiresAt: now.Add(time.Hour)}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&model.Session{UserID: second.ID, TokenHash: "session-2", CSRFToken: "csrf", LastSeenAt: now, ExpiresAt: now.Add(time.Hour)}).Error; err != nil {
		t.Fatal(err)
	}

	target, merged, err := application.mergeAccounts(second.ID, first.ID)
	if err != nil || !merged || target.ID != first.ID || target.Role != "admin" {
		t.Fatalf("unexpected merge result: target=%#v merged=%v err=%v", target, merged, err)
	}
	var source model.User
	if err := db.First(&source, second.ID).Error; err != nil || source.Status != "merged" || source.MergedIntoUserID == nil || *source.MergedIntoUserID != first.ID {
		t.Fatalf("source account was not retained as merged: source=%#v err=%v", source, err)
	}
	var movedEmails, movedIdentities int64
	_ = db.Model(&model.UserEmail{}).Where("user_id = ?", first.ID).Count(&movedEmails).Error
	_ = db.Model(&model.UpstreamIdentity{}).Where("user_id = ?", first.ID).Count(&movedIdentities).Error
	if movedEmails != 2 || movedIdentities != 2 {
		t.Fatalf("bindings were not combined: emails=%d identities=%d", movedEmails, movedIdentities)
	}
	var originalEmail model.UserEmail
	if err := db.Where("normalized_email = ?", "second@example.com").First(&originalEmail).Error; err != nil || originalEmail.OriginalUserID != second.ID {
		t.Fatalf("binding provenance was lost: email=%#v err=%v", originalEmail, err)
	}
	var activeSessions int64
	_ = db.Model(&model.Session{}).Where("user_id IN ? AND revoked_at IS NULL", []uint64{first.ID, second.ID}).Count(&activeSessions).Error
	if activeSessions != 0 {
		t.Fatalf("merge did not revoke old sessions: %d", activeSessions)
	}
}

func TestMergeFlowRequiresTheStartingBrowserSession(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := openTestDatabase(t)
	application := &Server{DB: db, Cfg: config.Config{SessionTTL: time.Hour}}
	user := model.User{Username: "merge-user", PasswordHash: "hash", PasswordConfigured: true, Locale: "zh-CN", Role: "user", Status: "active"}
	if err := db.Create(&user).Error; err != nil {
		t.Fatal(err)
	}
	rawSession := "merge-session-token"
	session := model.Session{UserID: user.ID, TokenHash: security.HashToken(rawSession), CSRFToken: "csrf", LastSeenAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}
	if err := db.Create(&session).Error; err != nil {
		t.Fatal(err)
	}
	flow := model.AuthFlow{SourceUserID: &user.ID, SessionID: &session.ID}

	validContext, _ := gin.CreateTestContext(httptest.NewRecorder())
	validContext.Request = httptest.NewRequest("POST", "/api/auth/identify", nil)
	validContext.Request.AddCookie(&http.Cookie{Name: sessionCookie, Value: rawSession})
	if !application.mergeSessionMatches(validContext, &flow) {
		t.Fatal("the starting browser session should be accepted")
	}

	otherContext, _ := gin.CreateTestContext(httptest.NewRecorder())
	otherContext.Request = httptest.NewRequest("POST", "/api/auth/identify", nil)
	if application.mergeSessionMatches(otherContext, &flow) {
		t.Fatal("a different browser without the starting session must be rejected")
	}
}
