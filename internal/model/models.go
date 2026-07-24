package model

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const CurrentSchemaVersion uint64 = 4

const (
	LocaleSourceUnknown  = "unknown"
	LocaleSourceImported = "imported"
	LocaleSourceBrowser  = "browser"
	LocaleSourceUser     = "user"
)

type User struct {
	ID                 uint64    `gorm:"primaryKey" json:"id"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
	Username           string    `gorm:"size:64;uniqueIndex;not null" json:"username"`
	PasswordHash       string    `gorm:"size:512;not null" json:"-"`
	PasswordConfigured bool      `gorm:"not null;default:true" json:"password_configured"`
	DisplayName        string    `gorm:"size:100" json:"display_name"`
	AvatarURL          string    `gorm:"size:1024" json:"avatar_url"`
	Locale             string    `gorm:"size:12;not null" json:"locale"`
	// LocaleSource distinguishes a deliberate preference from the temporary
	// fallback retained for legacy users whose language was never known.
	LocaleSource         string     `gorm:"size:16;not null;default:unknown" json:"-"`
	MFAEnabled           bool       `gorm:"not null" json:"mfa_enabled"`
	MFASecretEncrypted   string     `gorm:"type:text" json:"-"`
	MFABackupCodeHashes  string     `gorm:"type:text" json:"-"`
	SecurityEmailEnabled bool       `gorm:"not null" json:"security_email_enabled"`
	Role                 string     `gorm:"size:32;not null;index" json:"role"`
	Status               string     `gorm:"size:32;not null;index" json:"status"`
	DeactivatedAt        *time.Time `gorm:"index" json:"deactivated_at"`
	MergedIntoUserID     *uint64    `gorm:"index" json:"merged_into_user_id"`
	IdentityVersion      uint64     `gorm:"not null;default:1" json:"identity_version"`
	LastLoginAt          *time.Time `json:"last_login_at"`
}

type UserEmail struct {
	ID              uint64     `gorm:"primaryKey" json:"id"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
	UserID          uint64     `gorm:"not null;index" json:"user_id"`
	Email           string     `gorm:"size:254;not null" json:"email"`
	NormalizedEmail string     `gorm:"size:254;uniqueIndex;not null" json:"-"`
	VerifiedAt      *time.Time `gorm:"not null;index" json:"verified_at"`
	User            User       `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;" json:"-"`
}

// LegacyLoginIdentifier preserves identifiers imported from systems whose
// uniqueness rules are weaker than SSO's verified-email rules. In particular,
// several legacy accounts may share the same unverified email. These records
// remain non-authoritative and can be used for password login only when they
// resolve to exactly one active account.
type LegacyLoginIdentifier struct {
	ID                   uint64    `gorm:"primaryKey" json:"id"`
	CreatedAt            time.Time `json:"created_at"`
	UserID               uint64    `gorm:"not null;index" json:"user_id"`
	Kind                 string    `gorm:"size:32;not null;index:idx_legacy_identifier_lookup,priority:1;uniqueIndex:idx_legacy_source_identifier,priority:3" json:"kind"`
	Identifier           string    `gorm:"size:254;not null" json:"identifier"`
	NormalizedIdentifier string    `gorm:"size:254;not null;index:idx_legacy_identifier_lookup,priority:2" json:"-"`
	SourceSystem         string    `gorm:"size:64;not null;uniqueIndex:idx_legacy_source_identifier,priority:1" json:"source_system"`
	SourceUserID         int64     `gorm:"not null;uniqueIndex:idx_legacy_source_identifier,priority:2" json:"source_user_id"`
	User                 User      `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;" json:"-"`
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
	User       User       `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;" json:"-"`
}

type MFABackupCode struct {
	ID        uint64     `gorm:"primaryKey" json:"-"`
	CreatedAt time.Time  `json:"-"`
	UserID    uint64     `gorm:"not null;index;uniqueIndex:idx_mfa_backup_user_code" json:"-"`
	CodeHash  string     `gorm:"size:64;not null;index;uniqueIndex:idx_mfa_backup_user_code" json:"-"`
	UsedAt    *time.Time `gorm:"index" json:"-"`
	User      User       `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;" json:"-"`
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
	Owner            User       `gorm:"foreignKey:OwnerID;constraint:OnUpdate:CASCADE,OnDelete:RESTRICT;" json:"-"`
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
	User      User             `gorm:"foreignKey:UserID;constraint:OnUpdate:CASCADE,OnDelete:RESTRICT;" json:"-"`
}

type OAuthApproval struct {
	ID          uint64           `gorm:"primaryKey" json:"-"`
	CreatedAt   time.Time        `json:"-"`
	TokenHash   string           `gorm:"size:64;uniqueIndex;not null" json:"-"`
	UserID      uint64           `gorm:"not null;index" json:"-"`
	AppID       uint64           `gorm:"not null;index" json:"-"`
	Scopes      string           `gorm:"type:text;not null" json:"-"`
	RequestHash string           `gorm:"size:64;not null;index" json:"-"`
	StateHash   string           `gorm:"size:64;not null" json:"-"`
	ExpiresAt   time.Time        `gorm:"not null;index" json:"-"`
	UsedAt      *time.Time       `gorm:"index" json:"-"`
	User        User             `gorm:"foreignKey:UserID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;" json:"-"`
	App         OAuthApplication `gorm:"foreignKey:AppID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;" json:"-"`
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
	User       User       `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;" json:"-"`
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
	Locale               string     `gorm:"size:16" json:"-"`
	PasswordHash         string     `gorm:"size:512" json:"-"`
	VerificationCodeHash string     `gorm:"size:64" json:"-"`
	UserID               *uint64    `gorm:"index" json:"-"`
	SourceUserID         *uint64    `gorm:"index" json:"-"`
	SessionID            *uint64    `gorm:"index" json:"-"`
	Attempts             int        `gorm:"not null" json:"-"`
	LastSentAt           *time.Time `json:"-"`
	ExpiresAt            time.Time  `gorm:"not null;index" json:"-"`
	UsedAt               *time.Time `gorm:"index" json:"-"`
	User                 *User      `gorm:"foreignKey:UserID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;" json:"-"`
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
	ID            uint64           `gorm:"primaryKey" json:"id"`
	CreatedAt     time.Time        `json:"created_at"`
	UpdatedAt     time.Time        `json:"updated_at"`
	UserID        uint64           `gorm:"not null;index" json:"user_id"`
	ProviderID    uint64           `gorm:"not null;uniqueIndex:idx_provider_external" json:"provider_id"`
	ExternalID    string           `gorm:"size:255;not null;uniqueIndex:idx_provider_external" json:"external_id"`
	ExternalName  string           `gorm:"size:255" json:"external_name"`
	ExternalEmail string           `gorm:"size:254" json:"external_email"`
	Metadata      string           `gorm:"type:text" json:"metadata,omitempty"`
	VerifiedAt    *time.Time       `gorm:"not null;index" json:"verified_at"`
	LastLoginAt   time.Time        `json:"last_login_at"`
	Provider      UpstreamProvider `gorm:"foreignKey:ProviderID" json:"provider"`
	User          User             `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;" json:"-"`
}

type UpstreamOAuthState struct {
	ID                    uint64     `gorm:"primaryKey" json:"id"`
	CreatedAt             time.Time  `json:"created_at"`
	ProviderID            uint64     `gorm:"not null;index" json:"-"`
	SessionID             *uint64    `gorm:"index" json:"-"`
	MergeFlowID           *uint64    `gorm:"index" json:"-"`
	Locale                string     `gorm:"size:16" json:"-"`
	TokenHash             string     `gorm:"size:64;uniqueIndex;not null" json:"-"`
	BrowserNonceHash      string     `gorm:"size:64;not null" json:"-"`
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
	ID                uint64     `gorm:"primaryKey" json:"-"`
	CreatedAt         time.Time  `json:"-"`
	UserID            uint64     `gorm:"not null;index" json:"-"`
	AppID             *uint64    `gorm:"index" json:"-"`
	GrantID           *uint64    `gorm:"index" json:"-"`
	ClientID          string     `gorm:"size:64;not null;index" json:"-"`
	TokenFamilyID     string     `gorm:"size:64;not null;index" json:"-"`
	CodeHash          string     `gorm:"size:64;index" json:"-"`
	AccessHash        string     `gorm:"size:64;index" json:"-"`
	RefreshHash       string     `gorm:"size:64;index" json:"-"`
	RefreshConsumedAt *time.Time `gorm:"index" json:"-"`
	PayloadEncrypted  string     `gorm:"type:text;not null" json:"-"`
	ExpiresAt         time.Time  `gorm:"not null;index" json:"-"`
	RevokedAt         *time.Time `gorm:"index" json:"-"`
	User              User       `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;" json:"-"`
}

// SchemaMigration records the versioned migrations applied by the deployment
// migration Job. Application Pods only verify this state and never mutate it.
type SchemaMigration struct {
	Version   uint64    `gorm:"primaryKey"`
	AppliedAt time.Time `gorm:"not null"`
}

// AccountAlias makes a merged subject resolvable without rewriting any
// downstream service's immutable business user identifier.
type AccountAlias struct {
	SourceUserID    uint64    `gorm:"primaryKey" json:"source_user_id"`
	CanonicalUserID uint64    `gorm:"not null;index" json:"canonical_user_id"`
	CreatedAt       time.Time `gorm:"not null" json:"created_at"`
}

// LifecycleEvent is a transactional outbox record. It is created in the same
// transaction as an identity state transition and delivered asynchronously.
type LifecycleEvent struct {
	ID              string     `gorm:"primaryKey;size:36" json:"id"`
	CreatedAt       time.Time  `gorm:"not null;index" json:"created_at"`
	UserID          uint64     `gorm:"not null;index" json:"user_id"`
	IdentityVersion uint64     `gorm:"not null" json:"identity_version"`
	Type            string     `gorm:"size:64;not null;index" json:"type"`
	Payload         string     `gorm:"type:text;not null" json:"payload"`
	Attempts        int        `gorm:"not null;default:0" json:"attempts"`
	NextAttemptAt   time.Time  `gorm:"not null;index" json:"next_attempt_at"`
	LockedAt        *time.Time `gorm:"index" json:"-"`
	DeliveredAt     *time.Time `gorm:"index" json:"delivered_at"`
	DeadLetteredAt  *time.Time `gorm:"index" json:"dead_lettered_at"`
	LastError       string     `gorm:"type:text" json:"-"`
}

type IdentityMigrationBatch struct {
	ID           string     `gorm:"primaryKey;size:36" json:"id"`
	CreatedAt    time.Time  `gorm:"not null" json:"created_at"`
	CompletedAt  *time.Time `json:"completed_at"`
	SourceSystem string     `gorm:"size:64;not null;index" json:"source_system"`
	SourceMaxID  int64      `gorm:"not null" json:"source_max_id"`
	Status       string     `gorm:"size:32;not null;index" json:"status"`
}

type IdentityMigrationMapping struct {
	ID           uint64    `gorm:"primaryKey" json:"id"`
	CreatedAt    time.Time `gorm:"not null" json:"created_at"`
	BatchID      string    `gorm:"size:36;not null;index" json:"batch_id"`
	SourceSystem string    `gorm:"size:64;not null;uniqueIndex:idx_identity_source_user" json:"source_system"`
	SourceUserID int64     `gorm:"not null;uniqueIndex:idx_identity_source_user" json:"source_user_id"`
	SSOUserID    uint64    `gorm:"not null;uniqueIndex" json:"sso_user_id"`
	SourceRole   int       `gorm:"not null" json:"source_role"`
	SourceStatus int       `gorm:"not null" json:"source_status"`
}

type IdentityMigrationConflict struct {
	ID           uint64    `gorm:"primaryKey" json:"id"`
	CreatedAt    time.Time `gorm:"not null" json:"created_at"`
	BatchID      string    `gorm:"size:36;not null;index" json:"batch_id"`
	SourceUserID int64     `gorm:"not null;index" json:"source_user_id"`
	Severity     string    `gorm:"size:16;not null;index" json:"severity"`
	Kind         string    `gorm:"size:64;not null;index" json:"kind"`
	Detail       string    `gorm:"type:text;not null" json:"detail"`
}

func Migrate(db *gorm.DB) error {
	if err := migrateVerifiedBindings(db); err != nil {
		return err
	}
	if err := db.AutoMigrate(
		&User{},
		&UserEmail{},
		&LegacyLoginIdentifier{},
		&Session{},
		&MFABackupCode{},
		&OAuthApplication{},
		&Grant{},
		&OAuthApproval{},
		&AuthorizationLog{},
		&PersonalAccessToken{},
		&AuditEvent{},
		&AuthFlow{},
		&SystemSetting{},
		&UpstreamProvider{},
		&UpstreamIdentity{},
		&UpstreamOAuthState{},
		&OAuthTokenRecord{},
		&SchemaMigration{},
		&AccountAlias{},
		&LifecycleEvent{},
		&IdentityMigrationBatch{},
		&IdentityMigrationMapping{},
		&IdentityMigrationConflict{},
	); err != nil {
		return err
	}
	if err := enforceVerifiedBindingConstraints(db); err != nil {
		return err
	}
	if err := migrateLegacyBackupCodes(db); err != nil {
		return err
	}
	if err := migrateLocaleSources(db); err != nil {
		return err
	}
	return db.Transaction(func(tx *gorm.DB) error {
		var migration SchemaMigration
		err := tx.Where("version = ?", CurrentSchemaVersion).First(&migration).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return tx.Create(&SchemaMigration{Version: CurrentSchemaVersion, AppliedAt: time.Now().UTC()}).Error
		}
		return err
	})
}

// migrateLocaleSources keeps the historical locale value available as a
// fallback but explicitly marks migrated accounts with no trustworthy locale
// as unknown. A locale lifecycle event after the migration is treated as an explicit
// user choice; it is never inferred from the deployment's default language.
func migrateLocaleSources(db *gorm.DB) error {
	if !db.Migrator().HasColumn(&User{}, "locale_source") {
		return errors.New("locale_source column is missing")
	}
	return db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&User{}).
			Where("locale_source IS NULL OR locale_source NOT IN ?", []string{LocaleSourceUnknown, LocaleSourceImported, LocaleSourceBrowser, LocaleSourceUser}).
			Update("locale_source", LocaleSourceUnknown).Error; err != nil {
			return err
		}
		hasLifecycleEvents := tx.Migrator().HasTable(&LifecycleEvent{})
		hasAuditEvents := tx.Migrator().HasTable(&AuditEvent{})
		if hasLifecycleEvents && hasAuditEvents {
			// A previous v4 run could see the lifecycle event emitted by browser
			// initialization and incorrectly promote that account to "user".
			// The browser initialization audit is written after its lifecycle event;
			// only restore the source when no later locale lifecycle event exists.
			if err := tx.Exec(`
				UPDATE users
				SET locale_source = ?
				WHERE locale_source = ?
				  AND EXISTS (
					SELECT 1
					FROM audit_events AS ai
					WHERE ai.user_id = users.id
					  AND ai.action = ?
					  AND ai.metadata = ?
					  AND NOT EXISTS (
						SELECT 1
						FROM lifecycle_events AS later
						WHERE later.user_id = users.id
						  AND later.type = ?
						  AND later.created_at > ai.created_at
					  )
				  )
			`, LocaleSourceBrowser, LocaleSourceUser, "profile.locale_initialized", "source=browser", "profile.updated").Error; err != nil {
				return err
			}
		}
		if !tx.Migrator().HasTable(&IdentityMigrationMapping{}) || !hasLifecycleEvents {
			return nil
		}

		// Only a locale lifecycle event carrying an explicit user source can
		// establish that a migrated account actively chose a language. Browser
		// initialization also emits profile.updated for downstream synchronization,
		// so an event without source evidence is intentionally not inferred.
		var explicitUserIDs []uint64
		if err := tx.Table("lifecycle_events AS e").
			Select("DISTINCT e.user_id").
			Joins("JOIN identity_migration_mappings AS m ON m.sso_user_id = e.user_id AND m.source_system = ?", "new-api").
			Where("e.type = ? AND e.created_at >= m.created_at AND e.payload LIKE ?", "profile.updated", `%"locale_source":"user"%`).
			Pluck("e.user_id", &explicitUserIDs).Error; err != nil {
			return err
		}
		if len(explicitUserIDs) > 0 {
			if err := tx.Model(&User{}).
				Where("id IN ? AND locale_source = ?", explicitUserIDs, LocaleSourceUnknown).
				Update("locale_source", LocaleSourceUser).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

func migrateVerifiedBindings(db *gorm.DB) error {
	hasEmails := db.Migrator().HasTable(&UserEmail{})
	hasIdentities := db.Migrator().HasTable(&UpstreamIdentity{})
	if !hasEmails && !hasIdentities {
		return nil
	}
	if hasEmails && !db.Migrator().HasTable(&LegacyLoginIdentifier{}) {
		if err := db.AutoMigrate(&LegacyLoginIdentifier{}); err != nil {
			return fmt.Errorf("create legacy login identifier table: %w", err)
		}
	}
	return db.Transaction(func(tx *gorm.DB) error {
		if hasEmails {
			var emails []UserEmail
			if err := tx.Where("verified_at IS NULL").Order("id ASC").Find(&emails).Error; err != nil {
				return fmt.Errorf("find unverified email bindings: %w", err)
			}
			legacyIdentifiers := make([]LegacyLoginIdentifier, 0, len(emails))
			for _, email := range emails {
				if email.ID > uint64(1<<63-1) {
					return fmt.Errorf("email binding id %d cannot be converted to a legacy source id", email.ID)
				}
				createdAt := email.CreatedAt
				if createdAt.IsZero() {
					createdAt = time.Now().UTC()
				}
				legacyIdentifiers = append(legacyIdentifiers, LegacyLoginIdentifier{
					CreatedAt: createdAt, UserID: email.UserID, Kind: "email", Identifier: email.Email,
					NormalizedIdentifier: email.NormalizedEmail, SourceSystem: "sso-unverified-email-v2", SourceUserID: int64(email.ID),
				})
			}
			if len(legacyIdentifiers) > 0 {
				if err := tx.Clauses(clause.OnConflict{DoNothing: true}).CreateInBatches(&legacyIdentifiers, 500).Error; err != nil {
					return fmt.Errorf("preserve unverified email bindings: %w", err)
				}
				if err := tx.Where("verified_at IS NULL").Delete(&UserEmail{}).Error; err != nil {
					return fmt.Errorf("remove unverified email bindings: %w", err)
				}
			}
		}
		if hasIdentities {
			if err := tx.Model(&UpstreamIdentity{}).Where("verified_at IS NULL").UpdateColumn("verified_at", time.Now().UTC()).Error; err != nil {
				return fmt.Errorf("verify upstream identities: %w", err)
			}
		}
		return nil
	})
}

func enforceVerifiedBindingConstraints(db *gorm.DB) error {
	for _, item := range []struct {
		model  any
		field  string
		column string
	}{
		{model: &UserEmail{}, field: "VerifiedAt", column: "verified_at"},
		{model: &UpstreamIdentity{}, field: "VerifiedAt", column: "verified_at"},
	} {
		nullable, known, err := columnNullable(db, item.model, item.column)
		if err != nil {
			return err
		}
		if known && !nullable {
			continue
		}
		if err := db.Migrator().AlterColumn(item.model, item.field); err != nil {
			return fmt.Errorf("make %T.%s non-null: %w", item.model, item.field, err)
		}
		nullable, known, err = columnNullable(db, item.model, item.column)
		if err != nil {
			return err
		}
		if known && nullable {
			return fmt.Errorf("column %s remains nullable after migration", item.column)
		}
	}
	return nil
}

func columnNullable(db *gorm.DB, value any, column string) (bool, bool, error) {
	columns, err := db.Migrator().ColumnTypes(value)
	if err != nil {
		return false, false, fmt.Errorf("read column metadata for %T: %w", value, err)
	}
	for _, item := range columns {
		if item.Name() != column {
			continue
		}
		nullable, known := item.Nullable()
		return nullable, known, nil
	}
	return false, false, fmt.Errorf("column %s is missing from %T", column, value)
}

// SchemaReady only performs reads and is safe to call from readiness probes.
func SchemaReady(db *gorm.DB) error {
	if !db.Migrator().HasTable(&SchemaMigration{}) {
		return errors.New("schema migrations table is missing")
	}
	var migration SchemaMigration
	if err := db.Where("version = ?", CurrentSchemaVersion).First(&migration).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return errors.New("database schema is not migrated")
		}
		return err
	}
	return nil
}

func migrateLegacyBackupCodes(db *gorm.DB) error {
	var users []User
	if err := db.Where("mfa_backup_code_hashes <> '' AND mfa_backup_code_hashes <> '[]'").Find(&users).Error; err != nil {
		return err
	}
	for _, user := range users {
		var hashes []string
		if json.Unmarshal([]byte(user.MFABackupCodeHashes), &hashes) != nil {
			continue
		}
		if err := db.Transaction(func(tx *gorm.DB) error {
			for _, hash := range hashes {
				if hash == "" {
					continue
				}
				record := MFABackupCode{UserID: user.ID, CodeHash: hash}
				if err := tx.Where("user_id = ? AND code_hash = ?", user.ID, hash).FirstOrCreate(&record).Error; err != nil {
					return err
				}
			}
			return tx.Model(&user).Update("mfa_backup_code_hashes", "[]").Error
		}); err != nil {
			return err
		}
	}
	return nil
}
