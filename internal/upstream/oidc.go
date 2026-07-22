package upstream

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type oidcProvider struct {
	config Config
}

func newOIDCProvider(config Config) (Provider, error) {
	if config.ClientID == "" || config.ClientSecret == "" || config.IssuerURL == "" {
		return nil, errors.New("incomplete OIDC provider configuration")
	}
	if !validHTTPSOrLocal(config.IssuerURL) {
		return nil, errors.New("OIDC issuer must use HTTPS or localhost HTTP")
	}
	return &oidcProvider{config: config}, nil
}

func (p *oidcProvider) Kind() string { return p.config.Kind }

func (p *oidcProvider) AuthorizationURL(ctx context.Context, request AuthorizationRequest) (string, error) {
	configuration, err := p.discover(ctx)
	if err != nil {
		return "", err
	}
	provider, err := newOAuth2Provider(configuration)
	if err != nil {
		return "", err
	}
	return provider.AuthorizationURL(ctx, request)
}

func (p *oidcProvider) Exchange(ctx context.Context, request CallbackRequest) (Identity, error) {
	configuration, err := p.discover(ctx)
	if err != nil {
		return Identity{}, err
	}
	provider, err := newOAuth2Provider(configuration)
	if err != nil {
		return Identity{}, err
	}
	return provider.Exchange(ctx, request)
}

func (p *oidcProvider) discover(ctx context.Context) (Config, error) {
	issuer := strings.TrimRight(p.config.IssuerURL, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, issuer+"/.well-known/openid-configuration", nil)
	if err != nil {
		return Config{}, err
	}
	client := p.config.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return Config{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Config{}, fmt.Errorf("OIDC discovery status %d", resp.StatusCode)
	}
	var doc struct {
		Issuer                string `json:"issuer"`
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
		UserInfoEndpoint      string `json:"userinfo_endpoint"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
		return Config{}, err
	}
	if strings.TrimRight(doc.Issuer, "/") != issuer {
		return Config{}, errors.New("OIDC discovery issuer mismatch")
	}
	if !validHTTPSOrLocal(doc.AuthorizationEndpoint) || !validHTTPSOrLocal(doc.TokenEndpoint) || !validHTTPSOrLocal(doc.UserInfoEndpoint) {
		return Config{}, errors.New("invalid OIDC endpoints")
	}
	configuration := p.config
	configuration.AuthorizationURL = doc.AuthorizationEndpoint
	configuration.TokenURL = doc.TokenEndpoint
	configuration.UserInfoURL = doc.UserInfoEndpoint
	configuration.HTTPClient = client
	return configuration, nil
}

func validHTTPSOrLocal(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	return u.Scheme == "https" || (u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost"))
}
