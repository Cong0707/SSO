package config

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Addr                string
	Issuer              string
	DatabaseDriver      string
	DatabaseDSN         string
	OAuthTokenDB        string
	WebDir              string
	CookieSecure        bool
	SessionTTL          time.Duration
	RegistrationEnabled bool
	InviteRequired      bool
	MasterKey           []byte
}

func Load() (Config, error) {
	cfg := Config{
		Addr:                env("SSO_ADDR", ":8080"),
		Issuer:              strings.TrimRight(env("SSO_ISSUER", "http://127.0.0.1:8080"), "/"),
		DatabaseDriver:      strings.ToLower(env("SSO_DATABASE_DRIVER", "sqlite")),
		DatabaseDSN:         env("SSO_DATABASE_DSN", filepath.FromSlash("data/sso.db")),
		OAuthTokenDB:        env("SSO_OAUTH_TOKEN_DB", filepath.FromSlash("data/oauth-tokens.db")),
		WebDir:              env("SSO_WEB_DIR", filepath.FromSlash("web/dist")),
		CookieSecure:        envBool("SSO_COOKIE_SECURE", false),
		RegistrationEnabled: envBool("SSO_REGISTRATION_ENABLED", true),
		InviteRequired:      envBool("SSO_INVITE_REQUIRED", false),
	}

	issuer, err := url.Parse(cfg.Issuer)
	if err != nil || issuer.Scheme == "" || issuer.Host == "" {
		return Config{}, fmt.Errorf("SSO_ISSUER must be an absolute URL")
	}

	cfg.SessionTTL, err = time.ParseDuration(env("SSO_SESSION_TTL", "720h"))
	if err != nil || cfg.SessionTTL < time.Hour {
		return Config{}, fmt.Errorf("SSO_SESSION_TTL must be at least 1h")
	}

	if cfg.DatabaseDriver == "sqlite" {
		if err := os.MkdirAll(filepath.Dir(cfg.DatabaseDSN), 0o700); err != nil {
			return Config{}, fmt.Errorf("create database directory: %w", err)
		}
	}
	if err := os.MkdirAll(filepath.Dir(cfg.OAuthTokenDB), 0o700); err != nil {
		return Config{}, fmt.Errorf("create OAuth token directory: %w", err)
	}

	cfg.MasterKey, err = loadOrCreateMasterKey(filepath.Join(filepath.Dir(cfg.DatabaseDSN), "master.key"))
	if err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func env(name, fallback string) string {
	if value, ok := os.LookupEnv(name); ok {
		return value
	}
	return fallback
}

func envBool(name string, fallback bool) bool {
	value, ok := os.LookupEnv(name)
	if !ok {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func loadOrCreateMasterKey(path string) ([]byte, error) {
	if encoded, err := os.ReadFile(path); err == nil {
		key, decodeErr := base64.RawStdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
		if decodeErr != nil || len(key) != 32 {
			return nil, errors.New("invalid data/master.key")
		}
		return key, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read master key: %w", err)
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate master key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create key directory: %w", err)
	}
	if err := os.WriteFile(path, []byte(base64.RawStdEncoding.EncodeToString(key)), 0o600); err != nil {
		return nil, fmt.Errorf("write master key: %w", err)
	}
	return key, nil
}
