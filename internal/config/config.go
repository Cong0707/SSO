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
	Addr           string
	Issuer         string
	DatabaseDriver string
	DatabaseDSN    string
	// OAuthTokenDB is retained for source compatibility with older test and
	// deployment code. OAuth tokens are now stored in the primary database.
	OAuthTokenDB        string
	WebDir              string
	DataDir             string
	MasterKeyFile       string
	OIDCSigningKeyFile  string
	CookieSecure        bool
	SessionTTL          time.Duration
	RegistrationEnabled bool
	AllowKeyGeneration  bool
	TrustedProxies      []string
	MasterKey           []byte
}

func Load() (Config, error) {
	databaseDriver := strings.ToLower(env("SSO_DATABASE_DRIVER", "postgres"))
	dataDir := env("SSO_DATA_DIR", filepath.FromSlash("data"))
	cfg := Config{
		Addr:                env("SSO_ADDR", ":8080"),
		Issuer:              strings.TrimRight(env("SSO_ISSUER", "http://127.0.0.1:8080"), "/"),
		DatabaseDriver:      databaseDriver,
		DatabaseDSN:         env("SSO_DATABASE_DSN", "host=127.0.0.1 user=sso password=change-me dbname=sso port=5432 sslmode=disable TimeZone=UTC"),
		WebDir:              env("SSO_WEB_DIR", filepath.FromSlash("web/dist")),
		DataDir:             dataDir,
		MasterKeyFile:       env("SSO_MASTER_KEY_FILE", filepath.Join(dataDir, "master.key")),
		OIDCSigningKeyFile:  env("SSO_OIDC_SIGNING_KEY_FILE", filepath.Join(dataDir, "oidc-signing.pem")),
		CookieSecure:        envBool("SSO_COOKIE_SECURE", false),
		RegistrationEnabled: envBool("SSO_REGISTRATION_ENABLED", true),
		AllowKeyGeneration:  envBool("SSO_ALLOW_KEY_GENERATION", databaseDriver == "sqlite" || databaseDriver == "sqlite3"),
		TrustedProxies:      envList("SSO_TRUSTED_PROXIES"),
	}

	issuer, err := url.Parse(cfg.Issuer)
	if err != nil || issuer.Scheme == "" || issuer.Host == "" {
		return Config{}, fmt.Errorf("SSO_ISSUER must be an absolute URL")
	}

	cfg.SessionTTL, err = time.ParseDuration(env("SSO_SESSION_TTL", "720h"))
	if err != nil || cfg.SessionTTL < time.Hour {
		return Config{}, fmt.Errorf("SSO_SESSION_TTL must be at least 1h")
	}

	if cfg.DatabaseDriver == "sqlite" || cfg.DatabaseDriver == "sqlite3" {
		if err := os.MkdirAll(filepath.Dir(cfg.DatabaseDSN), 0o700); err != nil {
			return Config{}, fmt.Errorf("create database directory: %w", err)
		}
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return Config{}, fmt.Errorf("create data directory: %w", err)
	}

	cfg.MasterKey, err = loadOrCreateMasterKey(cfg.MasterKeyFile, cfg.AllowKeyGeneration)
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

func envList(name string) []string {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		if value := strings.TrimSpace(part); value != "" {
			values = append(values, value)
		}
	}
	return values
}

func loadOrCreateMasterKey(path string, allowGenerate bool) ([]byte, error) {
	if encoded, err := os.ReadFile(path); err == nil {
		key, decodeErr := base64.RawStdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
		if decodeErr != nil || len(key) != 32 {
			return nil, errors.New("invalid data/master.key")
		}
		return key, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read master key: %w", err)
	}
	if !allowGenerate {
		return nil, fmt.Errorf("master key file %q does not exist; mount a shared 32-byte key or set SSO_ALLOW_KEY_GENERATION=true for development", path)
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
