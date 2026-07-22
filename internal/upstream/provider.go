package upstream

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

type Config struct {
	Kind             string
	DisplayName      string
	ClientID         string
	ClientSecret     string
	IssuerURL        string
	AuthorizationURL string
	TokenURL         string
	UserInfoURL      string
	EmailInfoURL     string
	Scopes           []string
	HTTPClient       *http.Client
}

type Identity struct {
	Subject       string
	Username      string
	Name          string
	Email         string
	AvatarURL     string
	EmailVerified bool
}

type AuthorizationRequest struct {
	RedirectURL         string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
}

type CallbackRequest struct {
	RedirectURL  string
	Code         string
	CodeVerifier string
}

type Provider interface {
	Kind() string
	AuthorizationURL(context.Context, AuthorizationRequest) (string, error)
	Exchange(context.Context, CallbackRequest) (Identity, error)
}

type Factory func(Config) (Provider, error)

type Registry struct {
	factories map[string]Factory
}

func NewRegistry() *Registry {
	registry := &Registry{factories: make(map[string]Factory)}
	registry.Register("github", newOAuth2Provider)
	registry.Register("discord", newOAuth2Provider)
	registry.Register("linuxdo", newOAuth2Provider)
	registry.Register("oidc", newOIDCProvider)
	registry.Register("wechat", newWeChatProvider)
	return registry
}

func (r *Registry) Register(kind string, factory Factory) {
	if r == nil || factory == nil {
		return
	}
	if r.factories == nil {
		r.factories = make(map[string]Factory)
	}
	r.factories[strings.ToLower(strings.TrimSpace(kind))] = factory
}

func (r *Registry) Build(config Config) (Provider, error) {
	if r == nil {
		return nil, errors.New("upstream provider registry is nil")
	}
	kind := strings.ToLower(strings.TrimSpace(config.Kind))
	factory, ok := r.factories[kind]
	if !ok {
		return nil, errors.New("unsupported upstream provider: " + kind)
	}
	config.Kind = kind
	return factory(config)
}
