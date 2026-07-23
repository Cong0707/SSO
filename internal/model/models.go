package model

import (
	"time"

	"gorm.io/gorm"
)

type User struct {
	ID                   uint64     `gorm:"primaryKey" json:"id"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
	Username             string     `gorm:"size:64;uniqueIndex;not null" json:"username"`
	Email                string     `gorm:"size:254;index" json:"email"`
	PasswordHash         string     `gorm:"size:512;not null" json:"-"`
	PasswordConfigured   bool       `gorm:"not null;default:true" json:"password_configured"`
	DisplayName          string     `gorm:"size:100" json:"display_name"`
	AvatarURL            string     `gorm:"size:1024" json:"avatar_url"`
	Locale               string     `gorm:"size:12;not null" json:"locale"`
	EmailVerifiedAt      *time.Time `json:"email_verified_at"`
	MFAEnabled           bool       `gorm:"not null" json:"mfa_enabled"`
	MFASecretEncrypted   string     `gorm:"type:text" json:"-"`
	MFABackupCodeHashes  string     `gorm:"type:text" json:"-"`
	SecurityEmailEnabled bool       `gorm:"not null" json:"security_email_enabled"`
	Role                 string     `gorm:"size:32;not null;index" json:"role"`
	Status               string     `gorm:"size:32;not null;index" json:"status"`
	DeactivatedAt        *time.Time `gorm:"index" json:"deactivated_at"`
	MergedIntoUserID     *uint64    `gorm:"index" json:"merged_into_user_id"`
	LastLoginAt          *time.Time `json:"last_login_at"`
}

type UserEmail struct {
	ID              uint64     `gorm:"primaryKey" json:"id"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
	UserID          uint64     `gorm:"not null;index" json:"user_id"`
	OriginalUserID  uint64     `gorm:"not null;index" json:"original_user_id"`
	Email           string     `gorm:"size:254;not null" json:"email"`
	NormalizedEmail string     `gorm:"size:254;uniqueIndex;not null" json:"-"`
	Primary         bool       `gorm:"not null;index" json:"primary"`
	VerifiedAt      *time.Time `gorm:"index" json:"verified_at"`
	DisabledAt      *time.Time `gorm:"index" json:"disabled_at"`
}

type Session struct {
	ID         uint64     `gorm:"primaryKey" json:"id"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"-"`
	UserID     uint64     `gorm:"not null;index" json:"-"`
	TokenHash  string     `gorm:"size:64;uniqueIndex;not null" json:"-"`
	CSRFToken  string     `gorm:"size:128;not null" json:"-"`
	DeviceName string     `gorm:"size:120" json:"device_name"`
	IP         string     `gorm:"size:64" json:"ip"`
	UserAgent  string     `gorm:"size:1024" json:"user_agent"`
	LastSeenAt time.Time  `gorm:"not null;index" json:"last_seen_at"`
	ExpiresAt  time.Time  `gorm:"not null;index" json:"expires_at"`
	RevokedAt  *time.Time `gorm:"index" json:"revoked_at"`
}

type OAuthApplication struct {
	ID               uint64     `gorm:"primaryKey" json:"id"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
	OwnerID          uint64     `gorm:"not null;index" json:"owner_id"`
	Name             string     `gorm:"size:120;uniqueIndex;not null" json:"name"`
	Homepage         string     `gorm:"size:1024" json:"homepage"`
	Description      string     `gorm:"size:1000" json:"description"`
	RedirectURI      string     `gorm:"size:2048;not null" json:"redirect_uri"`
	LogoURL          string     `gorm:"size:2048" json:"logo_url"`
	ClientID         string     `gorm:"size:64;uniqueIndex;not null" json:"client_id"`
	ClientSecretHash string     `gorm:"size:64;not null" json:"-"`
	Public           bool       `gorm:"not null" json:"public"`
	AllowedScopes    string     `gorm:"type:text;not null" json:"allowed_scopes"`
	DisabledAt       *time.Time `gorm:"index" json:"disabled_at"`
}

type Grant struct {
	ID        uint64           `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time        `json:"created_at"`
	UpdatedAt time.Time        `json:"updated_at"`
	UserID    uint64           `gorm:"not null;uniqueIndex:idx_user_app" json:"user_id"`
	AppID     uint64           `gorm:"not null;uniqueIndex:idx_user_app" json:"app_id"`
	Scopes    string           `gorm:"type:text;not null" json:"scopes"`
	RevokedAt *time.Time       `gorm:"index" json:"revoked_at"`
	App       OAuthApplication `gorm:"foreignKey:AppID" json:"app"`
}

type AuthorizationLog struct {
	ID        uint64           `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time        `gorm:"index" json:"created_at"`
	AppID     uint64           `gorm:"not null;index" json:"app_id"`
	UserID    uint64           `gorm:"not null;index" json:"user_id"`
	Action    string           `gorm:"size:64;not null;index" json:"action"`
	Scopes    string           `gorm:"type:text" json:"scopes"`
	IP        string           `gorm:"size:64" json:"ip"`
	Status    string           `gorm:"size:32;not null;index" json:"status"`
	App       OAuthApplication `gorm:"foreignKey:AppID" json:"app"`
}

type PersonalAccessToken struct {
	ID         uint64     `gorm:"primaryKey" json:"id"`
	CreatedAt  time.Time  `json:"created_at"`
	UserID     uint64     `gorm:"not null;index" json:"-"`
	Name       string     `gorm:"size:100;not null" json:"name"`
	Prefix     string     `gorm:"size:24;not null;index" json:"prefix"`
	TokenHash  string     `gorm:"size:64;uniqueIndex;not null" json:"-"`
	Scopes     string     `gorm:"type:text;not null" json:"scopes"`
	LastUsedAt *time.Time `json:"last_used_at"`
	ExpiresAt  *time.Time `gorm:"index" json:"expires_at"`
	RevokedAt  *time.Time `gorm:"index" json:"revoked_at"`
}

type AuditEvent struct {
	ID        uint64    `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time `gorm:"index" json:"created_at"`
	UserID    uint64    `gorm:"not null;index" json:"-"`
	Action    string    `gorm:"size:100;not null;index" json:"action"`
	IP        string    `gorm:"size:64" json:"ip"`
	UserAgent string    `gorm:"size:1024" json:"-"`
	Metadata  string    `gorm:"type:text" json:"metadata,omitempty"`
}

type AuthFlow struct {
	ID                   uint64     `gorm:"primaryKey" json:"-"`
	CreatedAt            time.Time  `json:"-"`
	UpdatedAt            time.Time  `json:"-"`
	TokenHash            string     `gorm:"size:64;uniqueIndex;not null" json:"-"`
	Purpose              string     `gorm:"size:32;not null;index" json:"-"`
	Identifier           string     `gorm:"size:254" json:"-"`
	Username             string     `gorm:"size:64" json:"-"`
	Email                string     `gorm:"size:254" json:"-"`
	PasswordHash         string     `gorm:"size:512" json:"-"`
	VerificationCodeHash string     `gorm:"size:64" json:"-"`
	UserID               *uint64    `gorm:"index" json:"-"`
	SourceUserID         *uint64    `gorm:"index" json:"-"`
	SessionID            *uint64    `gorm:"index" json:"-"`
	Attempts             int        `gorm:"not null" json:"-"`
	LastSentAt           *time.Time `json:"-"`
	ExpiresAt            time.Time  `gorm:"not null;index" json:"-"`
	UsedAt               *time.Time `gorm:"index" json:"-"`
}

type SystemSetting struct {
	ID        uint64    `gorm:"primaryKey" json:"-"`
	CreatedAt time.Time `json:"-"`
	UpdatedAt time.Time `json:"updated_at"`
	Key       string    `gorm:"size:100;uniqueIndex;not null" json:"key"`
	Value     string    `gorm:"type:text" json:"value"`
	Secret    bool      `gorm:"not null" json:"-"`
}

type UpstreamProvider struct {
	ID                    uint64     `gorm:"primaryKey" json:"id"`
	CreatedAt             time.Time  `json:"created_at"`
	UpdatedAt             time.Time  `json:"updated_at"`
	Kind                  string     `gorm:"size:32;uniqueIndex;not null" json:"kind"`
	DisplayName           string     `gorm:"size:64;not null" json:"display_name"`
	ClientID              string     `gorm:"size:512" json:"client_id"`
	ClientSecretEncrypted string     `gorm:"type:text" json:"-"`
	IssuerURL             string     `gorm:"size:2048" json:"issuer_url"`
	AuthorizationURL      string     `gorm:"size:2048" json:"authorization_url"`
	TokenURL              string     `gorm:"size:2048" json:"token_url"`
	UserInfoURL           string     `gorm:"size:2048" json:"user_info_url"`
	EmailInfoURL          string     `gorm:"size:2048" json:"email_info_url"`
	Scopes                string     `gorm:"size:512" json:"scopes"`
	Enabled               bool       `gorm:"not null" json:"enabled"`
	DisabledAt            *time.Time `json:"disabled_at"`
}

type UpstreamIdentity struct {
	ID             uint64           `gorm:"primaryKey" json:"id"`
	CreatedAt      time.Time        `json:"created_at"`
	UpdatedAt      time.Time        `json:"updated_at"`
	UserID         uint64           `gorm:"not null;index" json:"user_id"`
	OriginalUserID uint64           `gorm:"not null;index" json:"original_user_id"`
	ProviderID     uint64           `gorm:"not null;uniqueIndex:idx_provider_external" json:"provider_id"`
	ExternalID     string           `gorm:"size:255;not null;uniqueIndex:idx_provider_external" json:"external_id"`
	ExternalName   string           `gorm:"size:255" json:"external_name"`
	ExternalEmail  string           `gorm:"size:254" json:"external_email"`
	Metadata       string           `gorm:"type:text" json:"metadata,omitempty"`
	VerifiedAt     *time.Time       `gorm:"index" json:"verified_at"`
	DisabledAt     *time.Time       `gorm:"index" json:"disabled_at"`
	LastLoginAt    time.Time        `json:"last_login_at"`
	Provider       UpstreamProvider `gorm:"foreignKey:ProviderID" json:"provider"`
}

type UpstreamOAuthState struct {
	ID                    uint64     `gorm:"primaryKey" json:"id"`
	CreatedAt             time.Time  `json:"created_at"`
	ProviderID            uint64     `gorm:"not null;index" json:"-"`
	SessionID             *uint64    `gorm:"index" json:"-"`
	MergeFlowID           *uint64    `gorm:"index" json:"-"`
	TokenHash             string     `gorm:"size:64;uniqueIndex;not null" json:"-"`
	CodeVerifierEncrypted string     `gorm:"type:text;not null" json:"-"`
	ReturnTo              string     `gorm:"size:2048" json:"-"`
	ExpiresAt             time.Time  `gorm:"not null;index" json:"-"`
	UsedAt                *time.Time `gorm:"index" json:"-"`
}

// OAuthTokenRecord stores OAuth2 authorization codes and tokens in the primary
// database so every application replica observes the same state. Raw token
// values are never persisted; PayloadEncrypted contains the encrypted oauth2
// token model and the lookup columns contain SHA-256 digests.
type OAuthTokenRecord struct {
	ID               uint64    `gorm:"primaryKey" json:"-"`
	CreatedAt        time.Time `json:"-"`
	CodeHash         string    `gorm:"size:64;index" json:"-"`
	AccessHash       string    `gorm:"size:64;index" json:"-"`
	RefreshHash      string    `gorm:"size:64;index" json:"-"`
	PayloadEncrypted string    `gorm:"type:text;not null" json:"-"`
	ExpiresAt        time.Time `gorm:"not null;index" json:"-"`
}

func Migrate(db *gorm.DB) error {
	return db.AutoMigrate(
		&User{},
		&UserEmail{},
		&Session{},
		&OAuthApplication{},
		&Grant{},
		&AuthorizationLog{},
		&PersonalAccessToken{},
		&AuditEvent{},
		&AuthFlow{},
		&SystemSetting{},
		&UpstreamProvider{},
		&UpstreamIdentity{},
		&UpstreamOAuthState{},
		&OAuthTokenRecord{},
	)
}
