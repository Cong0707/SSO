package upstream

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

type oauth2Provider struct {
	config Config
}

func newOAuth2Provider(config Config) (Provider, error) {
	if config.ClientID == "" || config.ClientSecret == "" || config.AuthorizationURL == "" || config.TokenURL == "" || config.UserInfoURL == "" {
		return nil, errors.New("incomplete OAuth2 provider configuration")
	}
	return &oauth2Provider{config: config}, nil
}

func (p *oauth2Provider) Kind() string { return p.config.Kind }

func (p *oauth2Provider) AuthorizationURL(_ context.Context, request AuthorizationRequest) (string, error) {
	configuration := p.oauthConfig(request.RedirectURL)
	options := []oauth2.AuthCodeOption{oauth2.SetAuthURLParam("code_challenge", request.CodeChallenge), oauth2.SetAuthURLParam("code_challenge_method", request.CodeChallengeMethod)}
	return configuration.AuthCodeURL(request.State, options...), nil
}

func (p *oauth2Provider) Exchange(ctx context.Context, request CallbackRequest) (Identity, error) {
	client := p.httpClient()
	ctx = context.WithValue(ctx, oauth2.HTTPClient, client)
	configuration := p.oauthConfig(request.RedirectURL)
	token, err := configuration.Exchange(ctx, request.Code, oauth2.SetAuthURLParam("code_verifier", request.CodeVerifier))
	if err != nil {
		return Identity{}, fmt.Errorf("exchange OAuth2 code: %w", err)
	}
	identity, err := fetchJSONIdentity(ctx, client, p.config, token.AccessToken)
	if err != nil {
		return Identity{}, err
	}
	if p.config.Kind == "github" {
		email, verified, emailErr := fetchGitHubEmail(ctx, client, p.config.EmailInfoURL, token.AccessToken)
		if emailErr != nil {
			return Identity{}, emailErr
		}
		identity.Email = email
		identity.EmailVerified = verified
	}
	return identity, nil
}

func (p *oauth2Provider) oauthConfig(redirectURL string) oauth2.Config {
	return oauth2.Config{ClientID: p.config.ClientID, ClientSecret: p.config.ClientSecret, RedirectURL: redirectURL, Scopes: p.config.Scopes, Endpoint: oauth2.Endpoint{AuthURL: p.config.AuthorizationURL, TokenURL: p.config.TokenURL}}
}

func (p *oauth2Provider) httpClient() *http.Client {
	if p.config.HTTPClient != nil {
		return p.config.HTTPClient
	}
	return &http.Client{Timeout: 15 * time.Second}
}

func fetchJSONIdentity(ctx context.Context, client *http.Client, config Config, accessToken string) (Identity, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, config.UserInfoURL, nil)
	if err != nil {
		return Identity{}, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Identity-Center/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return Identity{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Identity{}, fmt.Errorf("userinfo status %d", resp.StatusCode)
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 1<<20))
	decoder.UseNumber()
	var raw map[string]any
	if err := decoder.Decode(&raw); err != nil {
		return Identity{}, err
	}
	identity := Identity{
		Subject:   firstString(raw, "sub", "id", "user_id"),
		Username:  firstString(raw, "preferred_username", "username", "login"),
		Name:      firstString(raw, "name", "global_name", "nickname"),
		Email:     firstString(raw, "email"),
		AvatarURL: firstString(raw, "picture", "avatar_url", "avatar"),
	}
	if identity.Name == "" {
		identity.Name = identity.Username
	}
	identity.EmailVerified, _ = raw["email_verified"].(bool)
	if !identity.EmailVerified {
		identity.EmailVerified, _ = raw["verified"].(bool)
	}
	if identity.Subject == "" {
		return Identity{}, errors.New("missing upstream subject")
	}
	return identity, nil
}

func fetchGitHubEmail(ctx context.Context, client *http.Client, endpoint, accessToken string) (string, bool, error) {
	if endpoint == "" {
		endpoint = "https://api.github.com/user/emails"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", false, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "Identity-Center/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", false, fmt.Errorf("GitHub email status %d", resp.StatusCode)
	}
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&emails); err != nil {
		return "", false, err
	}
	for _, email := range emails {
		if email.Primary && email.Verified && strings.TrimSpace(email.Email) != "" {
			return strings.ToLower(strings.TrimSpace(email.Email)), true, nil
		}
	}
	for _, email := range emails {
		if email.Verified && strings.TrimSpace(email.Email) != "" {
			return strings.ToLower(strings.TrimSpace(email.Email)), true, nil
		}
	}
	return "", false, nil
}

func firstString(values map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := values[key]; ok {
			switch typed := value.(type) {
			case string:
				if typed != "" {
					return typed
				}
			case json.Number:
				return typed.String()
			case float64:
				return fmt.Sprintf("%.0f", typed)
			}
		}
	}
	return ""
}
