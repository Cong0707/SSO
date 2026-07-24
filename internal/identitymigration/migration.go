// Package identitymigration imports the identity-owned portion of a new-api
// database without changing the source database or its business user IDs.
package identitymigration

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Cong0707/sso/internal/config"
	"github.com/Cong0707/sso/internal/model"
	"github.com/Cong0707/sso/internal/security"
	"github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const SourceSystemNewAPI = "new-api"

type Options struct {
	SourceDriver      string
	SourceDSN         string
	SourceSystem      string
	BatchID           string
	AfterID           int64
	Limit             int
	OIDCIssuer        string
	TrustSourceEmails bool
}

type Issue struct {
	SourceUserID int64  `json:"source_user_id"`
	Severity     string `json:"severity"`
	Kind         string `json:"kind"`
	Detail       string `json:"detail"`
}

type Result struct {
	BatchID     string  `json:"batch_id,omitempty"`
	SourceUsers int     `json:"source_users"`
	Imported    int     `json:"imported"`
	Reconciled  int     `json:"reconciled"`
	Skipped     int     `json:"skipped"`
	RolledBack  int     `json:"rolled_back"`
	Verified    int     `json:"verified"`
	Issues      []Issue `json:"issues,omitempty"`
}

type Runner struct {
	Target *gorm.DB
	Source *gorm.DB
	Cfg    config.Config
	Opts   Options
}

// SourceUser intentionally contains only the source columns that SSO owns.
// Business quotas, groups, subscriptions and access tokens are never read.
type SourceUser struct {
	ID          int64          `gorm:"column:id"`
	Username    string         `gorm:"column:username"`
	Password    string         `gorm:"column:password"`
	DisplayName string         `gorm:"column:display_name"`
	SSOLocale   string         `gorm:"column:sso_locale"`
	Role        int            `gorm:"column:role"`
	Status      int            `gorm:"column:status"`
	Email       string         `gorm:"column:email"`
	GitHubID    string         `gorm:"column:github_id"`
	DiscordID   string         `gorm:"column:discord_id"`
	OIDCID      string         `gorm:"column:oidc_id"`
	WeChatID    string         `gorm:"column:wechat_id"`
	TelegramID  string         `gorm:"column:telegram_id"`
	LinuxDOID   string         `gorm:"column:linux_do_id"`
	CreatedAt   int64          `gorm:"column:created_at"`
	LastLoginAt int64          `gorm:"column:last_login_at"`
	DeletedAt   gorm.DeletedAt `gorm:"column:deleted_at"`
}

func OpenSource(driver, dsn string) (*gorm.DB, error) {
	var dialector gorm.Dialector
	switch strings.ToLower(strings.TrimSpace(driver)) {
	case "sqlite", "sqlite3":
		dialector = sqlite.Open(dsn)
	case "postgres", "postgresql":
		dialector = postgres.Open(dsn)
	case "mysql":
		dialector = mysql.Open(dsn)
	default:
		return nil, fmt.Errorf("unsupported source driver %q", driver)
	}
	return gorm.Open(dialector, &gorm.Config{Logger: logger.Default.LogMode(logger.Error)})
}

func New(target *gorm.DB, cfg config.Config, opts Options) (*Runner, error) {
	if target == nil {
		return nil, errors.New("target database is required")
	}
	if opts.SourceSystem == "" {
		opts.SourceSystem = SourceSystemNewAPI
	}
	if opts.Limit <= 0 || opts.Limit > 100000 {
		opts.Limit = 20000
	}
	runner := &Runner{Target: target, Cfg: cfg, Opts: opts}
	if strings.TrimSpace(opts.SourceDSN) == "" {
		return runner, nil
	}
	source, err := OpenSource(opts.SourceDriver, opts.SourceDSN)
	if err != nil {
		return nil, err
	}
	if !source.Migrator().HasTable("users") {
		return nil, errors.New("source users table does not exist")
	}
	runner.Source = source
	return runner, nil
}

func (r *Runner) sourceUsers() ([]SourceUser, error) {
	if r.Source == nil {
		return nil, errors.New("source database is required")
	}
	var users []SourceUser
	err := r.Source.Unscoped().Table("users").Where("id > ?", r.Opts.AfterID).Order("id ASC").Limit(r.Opts.Limit).Find(&users).Error
	return users, err
}

func (r *Runner) DryRun() (Result, error) {
	users, err := r.sourceUsers()
	if err != nil {
		return Result{}, err
	}
	issues, err := r.validate(users)
	if err != nil {
		return Result{}, err
	}
	return Result{SourceUsers: len(users), Issues: issues}, nil
}

func (r *Runner) Import() (Result, error) {
	users, err := r.sourceUsers()
	if err != nil {
		return Result{}, err
	}
	batchID := r.Opts.BatchID
	if batchID == "" {
		batchID = uuid.NewString()
	}
	var existing model.IdentityMigrationBatch
	if err := r.Target.Where("id = ?", batchID).First(&existing).Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return Result{}, err
	} else if errors.Is(err, gorm.ErrRecordNotFound) {
		maxID := r.Opts.AfterID
		for _, user := range users {
			if user.ID > maxID {
				maxID = user.ID
			}
		}
		if err := r.Target.Create(&model.IdentityMigrationBatch{ID: batchID, CreatedAt: time.Now().UTC(), SourceSystem: r.Opts.SourceSystem, SourceMaxID: maxID, Status: "running"}).Error; err != nil {
			return Result{}, err
		}
	}

	result := Result{BatchID: batchID, SourceUsers: len(users)}
	issues, err := r.validate(users)
	if err != nil {
		return result, err
	}
	result.Issues = issues
	if err := r.persistIssues(batchID, issues); err != nil {
		return result, err
	}
	blocked := make(map[int64]bool)
	for _, issue := range issues {
		if issue.Severity == "error" {
			blocked[issue.SourceUserID] = true
		}
	}
	mapped, err := r.mappedSourceUsers()
	if err != nil {
		return result, err
	}
	duplicateEmails, err := r.sourceDuplicateEmails()
	if err != nil {
		return result, err
	}
	for _, sourceUser := range users {
		if mapped[sourceUser.ID] {
			result.Skipped++
			continue
		}
		if blocked[sourceUser.ID] {
			result.Skipped++
			continue
		}
		if err := r.importUser(batchID, sourceUser, duplicateEmails[normalizeEmail(sourceUser.Email)]); err != nil {
			issue := Issue{SourceUserID: sourceUser.ID, Severity: "error", Kind: "import_failed", Detail: err.Error()}
			result.Issues = append(result.Issues, issue)
			_ = r.persistIssues(batchID, []Issue{issue})
			result.Skipped++
			continue
		}
		result.Imported++
	}
	now := time.Now().UTC()
	status := "completed"
	if result.Skipped > 0 {
		status = "completed_with_issues"
	}
	if err := r.Target.Model(&model.IdentityMigrationBatch{}).Where("id = ?", batchID).Updates(map[string]any{"status": status, "completed_at": &now}).Error; err != nil {
		return result, err
	}
	return result, nil
}

func (r *Runner) Verify(batchID string) (Result, error) {
	if batchID == "" {
		return Result{}, errors.New("batch ID is required")
	}
	var mappings []model.IdentityMigrationMapping
	if err := r.Target.Where("batch_id = ?", batchID).Order("source_user_id ASC").Find(&mappings).Error; err != nil {
		return Result{}, err
	}
	var sourceUsers []SourceUser
	if err := r.Source.Unscoped().Table("users").Find(&sourceUsers).Error; err != nil {
		return Result{}, err
	}
	sourceByID := make(map[int64]SourceUser, len(sourceUsers))
	for _, sourceUser := range sourceUsers {
		sourceByID[sourceUser.ID] = sourceUser
	}
	var targetUsers []model.User
	if err := r.Target.Find(&targetUsers).Error; err != nil {
		return Result{}, err
	}
	targetByID := make(map[uint64]model.User, len(targetUsers))
	for _, targetUser := range targetUsers {
		targetByID[targetUser.ID] = targetUser
	}
	var emailBindings []model.UserEmail
	if err := r.Target.Find(&emailBindings).Error; err != nil {
		return Result{}, err
	}
	emailsByUser := make(map[uint64]map[string]bool)
	for _, binding := range emailBindings {
		if emailsByUser[binding.UserID] == nil {
			emailsByUser[binding.UserID] = make(map[string]bool)
		}
		emailsByUser[binding.UserID][binding.NormalizedEmail] = true
	}
	var legacyIdentifiers []model.LegacyLoginIdentifier
	if err := r.Target.Where("source_system = ?", r.Opts.SourceSystem).Find(&legacyIdentifiers).Error; err != nil {
		return Result{}, err
	}
	legacyBySource := make(map[string]model.LegacyLoginIdentifier, len(legacyIdentifiers))
	for _, identifier := range legacyIdentifiers {
		key := fmt.Sprintf("%d\x00%s", identifier.SourceUserID, identifier.Kind)
		legacyBySource[key] = identifier
	}
	var providers []model.UpstreamProvider
	if err := r.Target.Find(&providers).Error; err != nil {
		return Result{}, err
	}
	providerKindByID := make(map[uint64]string, len(providers))
	for _, provider := range providers {
		providerKindByID[provider.ID] = provider.Kind
	}
	var upstreamIdentities []model.UpstreamIdentity
	if err := r.Target.Find(&upstreamIdentities).Error; err != nil {
		return Result{}, err
	}
	identitySet := make(map[string]bool, len(upstreamIdentities))
	for _, identity := range upstreamIdentities {
		kind := providerKindByID[identity.ProviderID]
		identitySet[fmt.Sprintf("%d\x00%s\x00%s", identity.UserID, kind, identity.ExternalID)] = true
	}
	duplicateEmails, err := r.sourceDuplicateEmails()
	if err != nil {
		return Result{}, err
	}
	result := Result{BatchID: batchID}
	for _, mapping := range mappings {
		sourceUser, ok := sourceByID[mapping.SourceUserID]
		if !ok {
			result.Issues = append(result.Issues, Issue{SourceUserID: mapping.SourceUserID, Severity: "error", Kind: "source_missing", Detail: "source user no longer exists"})
			continue
		}
		targetUser, ok := targetByID[mapping.SSOUserID]
		if !ok {
			result.Issues = append(result.Issues, Issue{SourceUserID: mapping.SourceUserID, Severity: "error", Kind: "target_missing", Detail: "mapped SSO user no longer exists"})
			continue
		}
		expectedDisplayName := strings.TrimSpace(sourceUser.DisplayName)
		if expectedDisplayName == "" {
			expectedDisplayName = strings.TrimSpace(sourceUser.Username)
		}
		expectedUsername, _ := migratedUsername(sourceUser)
		passwordMismatch := !passwordStateMatches(sourceUser, targetUser, mapping.CreatedAt)
		expectedRole := "user"
		if r.Opts.TrustSourceEmails && bootstrapAdmin(r.Cfg, normalizeEmail(sourceUser.Email)) {
			expectedRole = "admin"
		}
		if targetUser.Username != expectedUsername || targetUser.DisplayName != expectedDisplayName || passwordMismatch || targetUser.Status != sourceStatus(sourceUser) || targetUser.Role != expectedRole {
			result.Issues = append(result.Issues, Issue{SourceUserID: mapping.SourceUserID, Severity: "error", Kind: "profile_checksum_mismatch", Detail: "username, display name, password hash, role, or status differs"})
			continue
		}
		email := normalizeEmail(sourceUser.Email)
		if email != "" {
			if validEmail(email) && !duplicateEmails[email] && r.Opts.TrustSourceEmails {
				if !emailsByUser[targetUser.ID][email] {
					result.Issues = append(result.Issues, Issue{SourceUserID: mapping.SourceUserID, Severity: "error", Kind: "email_mapping_missing", Detail: email})
					continue
				}
			} else {
				legacy, ok := legacyBySource[fmt.Sprintf("%d\x00email", sourceUser.ID)]
				if !ok || legacy.UserID != targetUser.ID || legacy.NormalizedIdentifier != email {
					result.Issues = append(result.Issues, Issue{SourceUserID: mapping.SourceUserID, Severity: "error", Kind: "legacy_email_mapping_missing", Detail: email})
					continue
				}
			}
		}
		identityMissing := false
		for _, identity := range r.identities(sourceUser) {
			key := fmt.Sprintf("%d\x00%s\x00%s", targetUser.ID, identity.Kind, identity.Subject)
			if !identitySet[key] {
				result.Issues = append(result.Issues, Issue{SourceUserID: mapping.SourceUserID, Severity: "error", Kind: "provider_mapping_missing", Detail: identity.Kind + ":" + identity.Subject})
				identityMissing = true
			}
		}
		if identityMissing {
			continue
		}
		result.Verified++
	}
	return result, nil
}

// RepairPasswordState corrects rows imported by older migration builds where
// GORM applied the database default and persisted password_configured=true for
// passwordless users. A row changed after its migration mapping was created is
// left untouched so a real password configured by the user is never removed.
func (r *Runner) RepairPasswordState(batchID string) (Result, error) {
	if batchID == "" {
		return Result{}, errors.New("batch ID is required")
	}
	var mappings []model.IdentityMigrationMapping
	if err := r.Target.Where("batch_id = ?", batchID).Order("source_user_id ASC").Find(&mappings).Error; err != nil {
		return Result{}, err
	}
	var sourceUsers []SourceUser
	if err := r.Source.Unscoped().Table("users").Find(&sourceUsers).Error; err != nil {
		return Result{}, err
	}
	sourceByID := make(map[int64]SourceUser, len(sourceUsers))
	for _, sourceUser := range sourceUsers {
		sourceByID[sourceUser.ID] = sourceUser
	}
	result := Result{BatchID: batchID}
	for _, mapping := range mappings {
		sourceUser, ok := sourceByID[mapping.SourceUserID]
		if !ok {
			result.Skipped++
			result.Issues = append(result.Issues, Issue{SourceUserID: mapping.SourceUserID, Severity: "error", Kind: "source_missing", Detail: "source user no longer exists"})
			continue
		}
		if sourceUser.Password != "" {
			continue
		}
		var targetUser model.User
		if err := r.Target.First(&targetUser, mapping.SSOUserID).Error; err != nil {
			result.Skipped++
			result.Issues = append(result.Issues, Issue{SourceUserID: mapping.SourceUserID, Severity: "error", Kind: "target_missing", Detail: "mapped SSO user no longer exists"})
			continue
		}
		if !targetUser.PasswordConfigured {
			result.Verified++
			continue
		}
		updated := r.Target.Model(&model.User{}).
			Where("id = ? AND password_configured = ? AND updated_at <= ?", targetUser.ID, true, mapping.CreatedAt).
			UpdateColumn("password_configured", false)
		if updated.Error != nil {
			return result, updated.Error
		}
		if updated.RowsAffected == 0 {
			result.Skipped++
			result.Issues = append(result.Issues, Issue{SourceUserID: mapping.SourceUserID, Severity: "error", Kind: "password_state_changed_after_import", Detail: "password state changed after migration; manual review required"})
			continue
		}
		result.Reconciled++
	}
	return result, nil
}

func passwordStateMatches(sourceUser SourceUser, targetUser model.User, migratedAt time.Time) bool {
	if sourceUser.Password == "" {
		return !targetUser.PasswordConfigured
	}
	if !targetUser.PasswordConfigured {
		return false
	}
	if targetUser.PasswordHash == sourceUser.Password {
		return true
	}
	return targetUser.UpdatedAt.After(migratedAt) && security.ValidPasswordHashEncoding(targetUser.PasswordHash)
}

// Rollback is intentionally limited to a batch before it is enabled for real
// users. It deletes only rows created by that batch and never touches source.
func (r *Runner) Rollback(batchID string) (Result, error) {
	if batchID == "" {
		return Result{}, errors.New("batch ID is required")
	}
	result := Result{BatchID: batchID}
	err := r.Target.Transaction(func(tx *gorm.DB) error {
		var mappings []model.IdentityMigrationMapping
		if err := tx.Where("batch_id = ?", batchID).Find(&mappings).Error; err != nil {
			return err
		}
		for _, mapping := range mappings {
			active, err := migrationUserHasActivity(tx, mapping.SSOUserID)
			if err != nil {
				return err
			}
			if active {
				return fmt.Errorf("refuse rollback: SSO user %d has post-import activity", mapping.SSOUserID)
			}
			if err := tx.Delete(&model.User{}, mapping.SSOUserID).Error; err != nil {
				return err
			}
			result.RolledBack++
		}
		if err := tx.Where("batch_id = ?", batchID).Delete(&model.IdentityMigrationMapping{}).Error; err != nil {
			return err
		}
		if err := tx.Where("batch_id = ?", batchID).Delete(&model.IdentityMigrationConflict{}).Error; err != nil {
			return err
		}
		return tx.Delete(&model.IdentityMigrationBatch{}, "id = ?", batchID).Error
	})
	return result, err
}

func migrationUserHasActivity(tx *gorm.DB, userID uint64) (bool, error) {
	checks := []any{
		&model.Session{}, &model.PersonalAccessToken{}, &model.OAuthApplication{}, &model.Grant{},
		&model.AuthorizationLog{}, &model.AuditEvent{}, &model.AuthFlow{}, &model.LifecycleEvent{},
	}
	for _, record := range checks {
		column := "user_id"
		if _, ok := record.(*model.OAuthApplication); ok {
			column = "owner_id"
		}
		var count int64
		if err := tx.Model(record).Where(column+" = ?", userID).Count(&count).Error; err != nil {
			return false, err
		}
		if count > 0 {
			return true, nil
		}
	}
	return false, nil
}

type validationState struct {
	mapped           map[int64]bool
	targetUsernames  map[string]bool
	targetEmails     map[string]bool
	providers        map[string]model.UpstreamProvider
	targetIdentities map[string]bool
	passkeyUsers     map[int64]bool
	totpUsers        map[int64]bool
	duplicateEmails  map[string]bool
}

func (r *Runner) validate(users []SourceUser) ([]Issue, error) {
	state, err := r.loadValidationState()
	if err != nil {
		return nil, err
	}
	issues := make([]Issue, 0)
	seenUsernames := make(map[string]int64)
	seenFoldedUsernames := make(map[string]int64)
	seenIdentities := make(map[string]int64)
	for _, user := range users {
		username, rewritten := migratedUsername(user)
		if rewritten {
			issues = append(issues, Issue{user.ID, "warning", "username_rewritten", "empty, oversized, or invalid legacy username was replaced with a stable alias"})
		}
		if prior, ok := seenUsernames[username]; ok {
			issues = append(issues, Issue{user.ID, "error", "duplicate_username_in_source", fmt.Sprintf("duplicates source user %d", prior)})
			issues = append(issues, Issue{prior, "error", "duplicate_username_in_source", fmt.Sprintf("duplicates source user %d", user.ID)})
		} else {
			seenUsernames[username] = user.ID
		}
		foldedUsername := strings.ToLower(strings.TrimSpace(username))
		if prior, ok := seenFoldedUsernames[foldedUsername]; ok && prior != user.ID {
			issues = append(issues, Issue{user.ID, "warning", "case_insensitive_username_collision", fmt.Sprintf("requires exact username casing; conflicts with source user %d", prior)})
			issues = append(issues, Issue{prior, "warning", "case_insensitive_username_collision", fmt.Sprintf("requires exact username casing; conflicts with source user %d", user.ID)})
		} else {
			seenFoldedUsernames[foldedUsername] = user.ID
		}
		if state.targetUsernames[username] && !state.mapped[user.ID] {
			issues = append(issues, Issue{user.ID, "error", "username_already_exists", username})
		}

		email := normalizeEmail(user.Email)
		if email != "" {
			switch {
			case !validEmail(email):
				issues = append(issues, Issue{user.ID, "warning", "invalid_email_preserved", "legacy email is retained as non-authoritative metadata"})
			case state.duplicateEmails[email]:
				issues = append(issues, Issue{user.ID, "warning", "duplicate_email_preserved", "shared legacy email requires username login until it is uniquely claimed"})
			case state.targetEmails[email] && !state.mapped[user.ID]:
				issues = append(issues, Issue{user.ID, "error", "email_already_exists", email})
			}
		}

		identities := r.identities(user)
		if len(identities) == 0 && strings.TrimSpace(user.Password) == "" {
			severity := "error"
			if sourceStatus(user) != "active" {
				severity = "warning"
			}
			issues = append(issues, Issue{user.ID, severity, "no_login_identity", "source user has neither a password nor a supported third-party identity"})
		}
		if user.Password != "" {
			if _, err := bcrypt.Cost([]byte(user.Password)); err != nil {
				issues = append(issues, Issue{user.ID, "error", "invalid_password_hash", "source password is not a supported bcrypt hash"})
			}
		}
		for _, identity := range identities {
			key := identity.Kind + "\x00" + identity.Subject
			if prior, ok := seenIdentities[key]; ok {
				issues = append(issues, Issue{user.ID, "error", "duplicate_provider_subject_in_source", fmt.Sprintf("%s duplicates source user %d", identity.Kind, prior)})
				issues = append(issues, Issue{prior, "error", "duplicate_provider_subject_in_source", fmt.Sprintf("%s duplicates source user %d", identity.Kind, user.ID)})
			} else {
				seenIdentities[key] = user.ID
			}
			if identity.Kind == "oidc" && strings.TrimSpace(r.Opts.OIDCIssuer) == "" {
				issues = append(issues, Issue{user.ID, "error", "oidc_issuer_required", "provide --oidc-issuer before importing OIDC identities"})
			}
			if provider, ok := state.providers[identity.Kind]; ok {
				if identity.Kind == "oidc" && provider.IssuerURL != "" && strings.TrimRight(provider.IssuerURL, "/") != strings.TrimRight(strings.TrimSpace(r.Opts.OIDCIssuer), "/") {
					issues = append(issues, Issue{user.ID, "error", "oidc_issuer_mismatch", "configured SSO OIDC issuer differs from the migration issuer"})
				}
				if state.targetIdentities[key] && !state.mapped[user.ID] {
					issues = append(issues, Issue{user.ID, "error", "provider_subject_already_exists", identity.Kind + ":" + identity.Subject})
				}
			}
		}
		if state.passkeyUsers[user.ID] {
			issues = append(issues, Issue{user.ID, "warning", "passkey_requires_reregistration", "Passkeys cannot be transferred; user must register again in SSO"})
		}
		if state.totpUsers[user.ID] {
			issues = append(issues, Issue{user.ID, "warning", "totp_requires_reenrollment", "TOTP and backup codes use a different protected format; user must enroll again in SSO"})
		}
	}
	return deduplicateIssues(issues), nil
}

func (r *Runner) loadValidationState() (validationState, error) {
	state := validationState{
		mapped: make(map[int64]bool), targetUsernames: make(map[string]bool), targetEmails: make(map[string]bool),
		providers: make(map[string]model.UpstreamProvider), targetIdentities: make(map[string]bool),
		passkeyUsers: make(map[int64]bool), totpUsers: make(map[int64]bool), duplicateEmails: make(map[string]bool),
	}
	var err error
	if state.mapped, err = r.mappedSourceUsers(); err != nil {
		return state, err
	}
	var users []model.User
	if err := r.Target.Select("username").Find(&users).Error; err != nil {
		return state, err
	}
	for _, user := range users {
		state.targetUsernames[user.Username] = true
	}
	var emails []string
	if err := r.Target.Model(&model.UserEmail{}).Pluck("normalized_email", &emails).Error; err != nil {
		return state, err
	}
	for _, email := range emails {
		state.targetEmails[email] = true
	}
	var providers []model.UpstreamProvider
	if err := r.Target.Find(&providers).Error; err != nil {
		return state, err
	}
	providerKinds := make(map[uint64]string, len(providers))
	for _, provider := range providers {
		state.providers[provider.Kind] = provider
		providerKinds[provider.ID] = provider.Kind
	}
	var identities []model.UpstreamIdentity
	if err := r.Target.Select("provider_id", "external_id").Find(&identities).Error; err != nil {
		return state, err
	}
	for _, identity := range identities {
		if kind := providerKinds[identity.ProviderID]; kind != "" {
			state.targetIdentities[kind+"\x00"+identity.ExternalID] = true
		}
	}
	if state.passkeyUsers, err = r.sourceCredentialUsers("passkey_credentials", ""); err != nil {
		return state, err
	}
	if state.totpUsers, err = r.sourceCredentialUsers("two_fas", "is_enabled = true"); err != nil {
		return state, err
	}
	if state.duplicateEmails, err = r.sourceDuplicateEmails(); err != nil {
		return state, err
	}
	return state, nil
}

func (r *Runner) importUser(batchID string, sourceUser SourceUser, duplicateEmail bool) error {
	return r.Target.Transaction(func(tx *gorm.DB) error {
		if r.hasMappingWithDB(tx, sourceUser.ID) {
			return nil
		}
		email := normalizeEmail(sourceUser.Email)
		createdAt := time.Unix(sourceUser.CreatedAt, 0).UTC()
		if sourceUser.CreatedAt <= 0 {
			createdAt = time.Now().UTC()
		}
		username, _ := migratedUsername(sourceUser)
		user := model.User{
			CreatedAt: createdAt, UpdatedAt: createdAt, Username: username, PasswordHash: sourceUser.Password,
			PasswordConfigured: sourceUser.Password != "", DisplayName: strings.TrimSpace(sourceUser.DisplayName), Locale: migratedLocale(sourceUser.SSOLocale),
			SecurityEmailEnabled: true, Role: "user", Status: sourceStatus(sourceUser),
		}
		if user.DisplayName == "" {
			user.DisplayName = user.Username
		}
		if email != "" && r.Opts.TrustSourceEmails && bootstrapAdmin(r.Cfg, email) {
			user.Role = "admin"
		}
		if sourceUser.LastLoginAt > 0 {
			lastLogin := time.Unix(sourceUser.LastLoginAt, 0).UTC()
			user.LastLoginAt = &lastLogin
		}
		if user.Status == "deactivated" {
			deactivated := time.Now().UTC()
			user.DeactivatedAt = &deactivated
		}
		if user.PasswordHash == "" {
			random, err := security.RandomToken(32)
			if err != nil {
				return err
			}
			hash, err := security.HashPassword(random + "A1")
			if err != nil {
				return err
			}
			user.PasswordHash, user.PasswordConfigured = hash, false
		}
		if err := tx.Create(&user).Error; err != nil {
			return err
		}
		if sourceUser.Password == "" {
			if err := tx.Model(&user).UpdateColumn("password_configured", false).Error; err != nil {
				return err
			}
			user.PasswordConfigured = false
		}
		if email != "" && validEmail(email) && !duplicateEmail && r.Opts.TrustSourceEmails {
			verifiedAt := createdAt
			if err := tx.Create(&model.UserEmail{UserID: user.ID, Email: email, NormalizedEmail: email, VerifiedAt: &verifiedAt}).Error; err != nil {
				return err
			}
		} else if email != "" {
			if err := tx.Create(&model.LegacyLoginIdentifier{
				UserID: user.ID, Kind: "email", Identifier: strings.TrimSpace(sourceUser.Email), NormalizedIdentifier: email,
				SourceSystem: r.Opts.SourceSystem, SourceUserID: sourceUser.ID,
			}).Error; err != nil {
				return err
			}
		}
		for _, identity := range r.identities(sourceUser) {
			provider, err := r.ensureProvider(tx, identity.Kind)
			if err != nil {
				return err
			}
			verifiedAt := createdAt
			if err := tx.Create(&model.UpstreamIdentity{UserID: user.ID, ProviderID: provider.ID, ExternalID: identity.Subject, ExternalName: sourceUser.Username, ExternalEmail: email, VerifiedAt: &verifiedAt, LastLoginAt: createdAt}).Error; err != nil {
				return err
			}
		}
		return tx.Create(&model.IdentityMigrationMapping{BatchID: batchID, SourceSystem: r.Opts.SourceSystem, SourceUserID: sourceUser.ID, SSOUserID: user.ID, SourceRole: sourceUser.Role, SourceStatus: sourceUser.Status}).Error
	})
}

type sourceIdentity struct{ Kind, Subject string }

func (r *Runner) identities(user SourceUser) []sourceIdentity {
	values := []sourceIdentity{{"github", user.GitHubID}, {"discord", user.DiscordID}, {"oidc", user.OIDCID}, {"linuxdo", user.LinuxDOID}, {"telegram", user.TelegramID}, {"wechat", user.WeChatID}}
	result := make([]sourceIdentity, 0, len(values))
	for _, value := range values {
		if subject := strings.TrimSpace(value.Subject); subject != "" {
			value.Subject = subject
			result = append(result, value)
		}
	}
	return result
}

func (r *Runner) ensureProvider(tx *gorm.DB, kind string) (model.UpstreamProvider, error) {
	var provider model.UpstreamProvider
	if err := tx.Where("kind = ?", kind).First(&provider).Error; err == nil {
		return provider, nil
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return provider, err
	}
	provider = model.UpstreamProvider{Kind: kind, DisplayName: providerDisplayName(kind), Enabled: false}
	if kind == "oidc" {
		provider.IssuerURL = strings.TrimSpace(r.Opts.OIDCIssuer)
	}
	return provider, tx.Create(&provider).Error
}

func (r *Runner) hasMappingWithDB(db *gorm.DB, sourceID int64) bool {
	var count int64
	return db.Model(&model.IdentityMigrationMapping{}).Where("source_system = ? AND source_user_id = ?", r.Opts.SourceSystem, sourceID).Count(&count).Error == nil && count > 0
}

func (r *Runner) mappedSourceUsers() (map[int64]bool, error) {
	var sourceIDs []int64
	if err := r.Target.Model(&model.IdentityMigrationMapping{}).
		Where("source_system = ?", r.Opts.SourceSystem).
		Pluck("source_user_id", &sourceIDs).Error; err != nil {
		return nil, err
	}
	result := make(map[int64]bool, len(sourceIDs))
	for _, sourceID := range sourceIDs {
		result[sourceID] = true
	}
	return result, nil
}

func (r *Runner) sourceCredentialUsers(table, condition string) (map[int64]bool, error) {
	result := make(map[int64]bool)
	if !r.Source.Migrator().HasTable(table) {
		return result, nil
	}
	query := r.Source.Table(table)
	if condition != "" {
		query = query.Where(condition)
	}
	var sourceIDs []int64
	if err := query.Distinct("user_id").Pluck("user_id", &sourceIDs).Error; err != nil {
		return nil, err
	}
	for _, sourceID := range sourceIDs {
		result[sourceID] = true
	}
	return result, nil
}

func (r *Runner) sourceDuplicateEmails() (map[string]bool, error) {
	type duplicateEmail struct {
		Normalized string `gorm:"column:normalized"`
	}
	var rows []duplicateEmail
	expression := "LOWER(TRIM(email))"
	err := r.Source.Unscoped().Table("users").
		Select(expression + " AS normalized").
		Where("email IS NOT NULL AND TRIM(email) <> ''").
		Group(expression).
		Having("COUNT(*) > 1").
		Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	result := make(map[string]bool, len(rows))
	for _, row := range rows {
		result[row.Normalized] = true
	}
	return result, nil
}

func migratedUsername(user SourceUser) (string, bool) {
	value := user.Username
	if strings.TrimSpace(value) == "" || !utf8.ValidString(value) || utf8.RuneCountInString(value) > 64 || strings.ContainsRune(value, '\x00') {
		return fmt.Sprintf("xem_legacy_user_%d", user.ID), true
	}
	return value, false
}

func (r *Runner) persistIssues(batchID string, issues []Issue) error {
	if len(issues) == 0 {
		return nil
	}
	rows := make([]model.IdentityMigrationConflict, 0, len(issues))
	for _, issue := range issues {
		rows = append(rows, model.IdentityMigrationConflict{BatchID: batchID, SourceUserID: issue.SourceUserID, Severity: issue.Severity, Kind: issue.Kind, Detail: issue.Detail})
	}
	return r.Target.CreateInBatches(&rows, 500).Error
}

func sourceStatus(user SourceUser) string {
	if user.Status != 1 || user.DeletedAt.Valid {
		return "deactivated"
	}
	return "active"
}

func migratedLocale(value string) string {
	normalized := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), "_", "-"))
	base := strings.Split(normalized, "-")[0]
	switch {
	case normalized == "zh-tw", normalized == "zh-hk", normalized == "zh-mo", normalized == "zhtw", strings.HasPrefix(normalized, "zh-hant"):
		return "zhTW"
	case normalized == "zh-cn", normalized == "zh-sg", normalized == "zhcn", normalized == "zh", strings.HasPrefix(normalized, "zh-hans"):
		return "zhCN"
	case base == "en", base == "fr", base == "ru", base == "ja", base == "vi":
		return base
	default:
		return "zhCN"
	}
}

func normalizeEmail(value string) string { return strings.ToLower(strings.TrimSpace(value)) }

func validEmail(value string) bool {
	at := strings.LastIndex(value, "@")
	return at > 0 && at < len(value)-1 && len(value) <= 254 && !strings.ContainsAny(value, " \t\r\n")
}

func bootstrapAdmin(cfg config.Config, email string) bool {
	for _, allowed := range cfg.BootstrapAdminEmails {
		if normalizeEmail(allowed) == normalizeEmail(email) {
			return true
		}
	}
	return false
}

func providerDisplayName(kind string) string {
	values := map[string]string{"github": "GitHub", "discord": "Discord", "oidc": "OIDC", "linuxdo": "LinuxDO", "telegram": "Telegram", "wechat": "微信"}
	return values[kind]
}

func deduplicateIssues(issues []Issue) []Issue {
	seen := make(map[string]struct{}, len(issues))
	result := make([]Issue, 0, len(issues))
	for _, issue := range issues {
		key := fmt.Sprintf("%d\x00%s\x00%s", issue.SourceUserID, issue.Kind, issue.Detail)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, issue)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].SourceUserID != result[j].SourceUserID {
			return result[i].SourceUserID < result[j].SourceUserID
		}
		return result[i].Kind < result[j].Kind
	})
	return result
}
