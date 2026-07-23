package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Cong0707/sso/internal/config"
	"github.com/Cong0707/sso/internal/model"
	"github.com/Cong0707/sso/internal/security"
	"gorm.io/gorm"
)

func TestLifecycleEventIsVersionedAndDeliveredOnce(t *testing.T) {
	db := openTestDatabase(t)
	user := model.User{Username: "event-user", PasswordHash: "unused", Locale: "en", Role: "user", Status: "active"}
	if err := db.Create(&user).Error; err != nil {
		t.Fatal(err)
	}
	secret := "webhook-secret"
	delivered := make(chan struct{}, 1)
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode payload: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		encoded, _ := json.Marshal(payload)
		if r.Header.Get("X-Xem-Signature-SHA256") != security.HMACToken([]byte(secret), string(encoded)) {
			t.Error("invalid webhook signature")
		}
		w.WriteHeader(http.StatusNoContent)
		delivered <- struct{}{}
	}))
	defer webhook.Close()
	application := &Server{DB: db, Cfg: config.Config{LifecycleWebhookURL: webhook.URL, LifecycleWebhookSecret: secret, OutboxPollInterval: 10 * time.Millisecond, OutboxMaxAttempts: 3}}
	if err := db.Transaction(func(tx *gorm.DB) error {
		return application.recordLifecycleEvent(tx, user.ID, "account.deactivated", nil)
	}); err != nil {
		t.Fatal(err)
	}
	application.startLifecycleDispatcher()
	defer application.Close()
	select {
	case <-delivered:
	case <-time.After(2 * time.Second):
		t.Fatal("lifecycle event was not delivered")
	}
	var events []model.LifecycleEvent
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		events = nil
		if err := db.Find(&events).Error; err == nil && len(events) == 1 && events[0].DeliveredAt != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := db.Find(&events).Error; err != nil || len(events) != 1 || events[0].DeliveredAt == nil || events[0].Attempts != 1 {
		t.Fatalf("unexpected outbox state: events=%#v err=%v", events, err)
	}
	var updated model.User
	if err := db.First(&updated, user.ID).Error; err != nil || updated.IdentityVersion <= user.IdentityVersion {
		t.Fatalf("identity version was not incremented: user=%#v err=%v", updated, err)
	}
}
