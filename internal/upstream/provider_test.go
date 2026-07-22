package upstream

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type testProvider struct{ kind string }

func (p testProvider) Kind() string { return p.kind }
func (p testProvider) AuthorizationURL(context.Context, AuthorizationRequest) (string, error) {
	return "https://example.test/authorize", nil
}
func (p testProvider) Exchange(context.Context, CallbackRequest) (Identity, error) {
	return Identity{Subject: "subject"}, nil
}

func TestRegistryAllowsCustomProvider(t *testing.T) {
	registry := NewRegistry()
	registry.Register("custom", func(config Config) (Provider, error) {
		return testProvider{kind: config.Kind}, nil
	})
	provider, err := registry.Build(Config{Kind: "CUSTOM"})
	if err != nil {
		t.Fatalf("build custom provider: %v", err)
	}
	if provider.Kind() != "custom" {
		t.Fatalf("provider kind = %q", provider.Kind())
	}
}

func TestGitHubUsesOnlyVerifiedEmail(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access", "token_type": "Bearer"})
		case "/user":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": 42, "login": "octocat", "email": "unverified@example.com", "avatar_url": "https://avatars.example/octocat.png"})
		case "/emails":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"email": "unverified@example.com", "primary": true, "verified": false},
				{"email": "verified@example.com", "primary": false, "verified": true},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	provider, err := newOAuth2Provider(Config{
		Kind: "github", ClientID: "client", ClientSecret: "secret", AuthorizationURL: server.URL + "/authorize",
		TokenURL: server.URL + "/token", UserInfoURL: server.URL + "/user", EmailInfoURL: server.URL + "/emails",
		HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}
	identity, err := provider.Exchange(context.Background(), CallbackRequest{RedirectURL: "http://localhost/callback", Code: "code", CodeVerifier: "verifier"})
	if err != nil {
		t.Fatalf("exchange identity: %v", err)
	}
	if identity.Email != "verified@example.com" || !identity.EmailVerified {
		t.Fatalf("unexpected GitHub email: %#v", identity)
	}
}

func TestOIDCRejectsIssuerMismatchAndInsecureEndpoints(t *testing.T) {
	var document map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(document)
	}))
	defer server.Close()

	document = map[string]any{
		"issuer": "https://different.example", "authorization_endpoint": server.URL + "/authorize",
		"token_endpoint": server.URL + "/token", "userinfo_endpoint": server.URL + "/userinfo",
	}
	provider, err := newOIDCProvider(Config{Kind: "oidc", ClientID: "client", ClientSecret: "secret", IssuerURL: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatalf("create OIDC provider: %v", err)
	}
	if _, err := provider.AuthorizationURL(context.Background(), AuthorizationRequest{}); err == nil {
		t.Fatal("expected issuer mismatch to be rejected")
	}

	document = map[string]any{
		"issuer": server.URL, "authorization_endpoint": "http://example.com/authorize",
		"token_endpoint": server.URL + "/token", "userinfo_endpoint": server.URL + "/userinfo",
	}
	if _, err := provider.AuthorizationURL(context.Background(), AuthorizationRequest{}); err == nil {
		t.Fatal("expected non-local HTTP endpoint to be rejected")
	}
}

func TestTelegramRejectsFutureAuthenticationDate(t *testing.T) {
	_, err := VerifyTelegram("bot-token", TelegramPayload{ID: 1, AuthDate: time.Now().Add(time.Minute).Unix(), Hash: "00"}, time.Now())
	if err == nil {
		t.Fatal("expected future auth_date to be rejected")
	}
}
