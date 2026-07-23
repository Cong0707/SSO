// Package identitymigration imports the identity-owned portion of a new-api
// database without changing the source database or its business user IDs.
package identitymigration

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

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

var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{3,64}$`)

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
	if opts.Limit <= 0 || opts.Limit > 5000 {
		opts.Limit = 5000
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
	issues := r.validate(users)
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
	issues := r.validate(users)
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
	for _, sourceUser := range users {
		if r.hasMapping(sourceUser.ID) {
			result.Skipped++
			continue
		}
		if blocked[sourceUser.ID] {
			result.Skipped++
			continue
		}
		if err := r.importUser(batchID, sourceUser); err != nil {
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
	result := Result{BatchID: batchID}
	for _, mapping := range mappings {
		var sourceUser SourceUser
		if err := r.Source.Unscoped().Table("users").Where("id = ?", mapping.SourceUserID).First(&sourceUser).Error; err != nil {
			result.Issues = append(result.Issues, Issue{SourceUserID: mapping.SourceUserID, Severity: "error", Kind: "source_missing", Detail: "source user no longer exists"})
			continue
		}
		var targetUser model.User
		if err := r.Target.First(&targetUser, mapping.SSOUserID).Error; err != nil {
			result.Issues = append(result.Issues, Issue{SourceUserID: mapping.SourceUserID, Severity: "error", Kind: "target_missing", Detail: "mapped SSO user no longer exists"})
			continue
		}
		expectedDisplayName := strings.TrimSpace(sourceUser.DisplayName)
		if expectedDisplayName == "" {
			expectedDisplayName = strings.TrimSpace(sourceUser.Username)
		}
		passwordMismatch := sourceUser.Password != "" && targetUser.PasswordHash != sourceUser.Password
		passwordMismatch = passwordMismatch || sourceUser.Password == "" && targetUser.PasswordConfigured
		if targetUser.Username != strings.TrimSpace(sourceUser.Username) || targetUser.DisplayName != expectedDisplayName || passwordMismatch {
			result.Issues = append(result.Issues, Issue{SourceUserID: mapping.SourceUserID, Severity: "error", Kind: "profile_checksum_mismatch", Detail: "username, display name, or password hash differs"})
			continue
		}
		email := normalizeEmail(sourceUser.Email)
		if email != "" {
			var binding model.UserEmail
			if err := r.Target.Where("user_id = ? AND normalized_email = ?", targetUser.ID, email).First(&binding).Error; err != nil {
				result.Issues = append(result.Issues, Issue{SourceUserID: mapping.SourceUserID, Severity: "error", Kind: "email_mapping_missing", Detail: email})
				continue
			}
		}
		result.Verified++
	}
	return result, nil
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

func (r *Runner) validate(users []SourceUser) []Issue {
	issues := make([]Issue, 0)
	seenUsernames := make(map[string]int64)
	seenEmails := make(map[string]int64)
	seenIdentities := make(map[string]int64)
	for _, user := range users {
		username := strings.TrimSpace(user.Username)
		if !usernamePattern.MatchString(username) {
			issues = append(issues, Issue{user.ID, "error", "invalid_username", "username must contain 3-64 ASCII letters, digits, _ or -"})
		}
		lowerUsername := strings.ToLower(username)
		if prior, ok := seenUsernames[lowerUsername]; ok {
			issues = append(issues, Issue{user.ID, "error", "duplicate_username_in_source", fmt.Sprintf("duplicates source user %d", prior)})
			issues = append(issues, Issue{prior, "error", "duplicate_username_in_source", fmt.Sprintf("duplicates source user %d", user.ID)})
		} else {
			seenUsernames[lowerUsername] = user.ID
		}
		var targetCount int64
		_ = r.Target.Model(&model.User{}).Where("LOWER(username) = ?", lowerUsername).Count(&targetCount).Error
		if targetCount > 0 && !r.hasMapping(user.ID) {
			issues = append(issues, Issue{user.ID, "error", "username_already_exists", username})
		}
		email := normalizeEmail(user.Email)
		if email != "" {
			if !validEmail(email) {
				issues = append(issues, Issue{user.ID, "error", "invalid_email", email})
			} else if prior, ok := seenEmails[email]; ok {
				issues = append(issues, Issue{user.ID, "error", "duplicate_email_in_source", fmt.Sprintf("duplicates source user %d", prior)})
				issues = append(issues, Issue{prior, "error", "duplicate_email_in_source", fmt.Sprintf("duplicates source user %d", user.ID)})
			} else {
				seenEmails[email] = user.ID
			}
			_ = r.Target.Model(&model.UserEmail{}).Where("normalized_email = ?", email).Count(&targetCount).Error
			if targetCount > 0 && !r.hasMapping(user.ID) {
				issues = append(issues, Issue{user.ID, "error", "email_already_exists", email})
			}
		}
		identities := r.identities(user)
		if len(identities) == 0 && (email == "" || strings.TrimSpace(user.Password) == "") {
			issues = append(issues, Issue{user.ID, "error", "no_login_identity", "source user needs both email and password, or at least one supported third-party identity"})
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
			var provider model.UpstreamProvider
			if err := r.Target.Where("kind = ?", identity.Kind).First(&provider).Error; err == nil {
				if identity.Kind == "oidc" && provider.IssuerURL != "" && strings.TrimRight(provider.IssuerURL, "/") != strings.TrimRight(strings.TrimSpace(r.Opts.OIDCIssuer), "/") {
					issues = append(issues, Issue{user.ID, "error", "oidc_issuer_mismatch", "configured SSO OIDC issuer differs from the migration issuer"})
				}
				var identityCount int64
				_ = r.Target.Model(&model.UpstreamIdentity{}).Where("provider_id = ? AND external_id = ?", provider.ID, identity.Subject).Count(&identityCount).Error
				if identityCount > 0 && !r.hasMapping(user.ID) {
					issues = append(issues, Issue{user.ID, "error", "provider_subject_already_exists", identity.Kind + ":" + identity.Subject})
				}
			}
		}
		issues = append(issues, r.legacyCredentialIssues(user.ID)...)
	}
	return deduplicateIssues(issues)
}

func (r *Runner) importUser(batchID string, sourceUser SourceUser) error {
	return r.Target.Transaction(func(tx *gorm.DB) error {
		if r.hasMappingWithDB(tx, sourceUser.ID) {
			return nil
		}
		email := normalizeEmail(sourceUser.Email)
		createdAt := time.Unix(sourceUser.CreatedAt, 0).UTC()
		if sourceUser.CreatedAt <= 0 {
			createdAt = time.Now().UTC()
		}
		user := model.User{
			CreatedAt: createdAt, UpdatedAt: createdAt, Username: strings.TrimSpace(sourceUser.Username), PasswordHash: sourceUser.Password,
			PasswordConfigured: sourceUser.Password != "", DisplayName: strings.TrimSpace(sourceUser.DisplayName), Locale: "en",
			SecurityEmailEnabled: true, Role: "user", Status: sourceStatus(sourceUser),
		}
		if user.DisplayName == "" {
			user.DisplayName = user.Username
		}
		if email != "" && bootstrapAdmin(r.Cfg, email) {
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
		if email != "" {
			var verifiedAt *time.Time
			if r.Opts.TrustSourceEmails {
				verified := createdAt
				verifiedAt = &verified
			}
			if err := tx.Create(&model.UserEmail{UserID: user.ID, Email: email, NormalizedEmail: email, VerifiedAt: verifiedAt}).Error; err != nil {
				return err
			}
		}
		for _, identity := range r.identities(sourceUser) {
			provider, err := r.ensureProvider(tx, identity.Kind)
			if err != nil {
				return err
			}
			if err := tx.Create(&model.UpstreamIdentity{UserID: user.ID, ProviderID: provider.ID, ExternalID: identity.Subject, ExternalName: sourceUser.Username, ExternalEmail: email, LastLoginAt: createdAt}).Error; err != nil {
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

func (r *Runner) hasMapping(sourceID int64) bool { return r.hasMappingWithDB(r.Target, sourceID) }

func (r *Runner) hasMappingWithDB(db *gorm.DB, sourceID int64) bool {
	var count int64
	return db.Model(&model.IdentityMigrationMapping{}).Where("source_system = ? AND source_user_id = ?", r.Opts.SourceSystem, sourceID).Count(&count).Error == nil && count > 0
}

func (r *Runner) persistIssues(batchID string, issues []Issue) error {
	if len(issues) == 0 {
		return nil
	}
	rows := make([]model.IdentityMigrationConflict, 0, len(issues))
	for _, issue := range issues {
		rows = append(rows, model.IdentityMigrationConflict{BatchID: batchID, SourceUserID: issue.SourceUserID, Severity: issue.Severity, Kind: issue.Kind, Detail: issue.Detail})
	}
	return r.Target.Create(&rows).Error
}

func (r *Runner) legacyCredentialIssues(userID int64) []Issue {
	issues := make([]Issue, 0, 2)
	for _, state := range []struct{ table, kind, detail string }{
		{"passkey_credentials", "passkey_requires_reregistration", "Passkeys cannot be transferred; user must register again in SSO"},
		{"two_fas", "totp_requires_reenrollment", "TOTP and backup codes use a different protected format; user must enroll again in SSO"},
	} {
		if !r.Source.Migrator().HasTable(state.table) {
			continue
		}
		var count int64
		query := r.Source.Table(state.table).Where("user_id = ?", userID)
		if state.table == "two_fas" {
			query = query.Where("is_enabled = ?", true)
		}
		if query.Count(&count).Error == nil && count > 0 {
			issues = append(issues, Issue{userID, "warning", state.kind, state.detail})
		}
	}
	return issues
}

func sourceStatus(user SourceUser) string {
	if user.Status != 1 || user.DeletedAt.Valid {
		return "deactivated"
	}
	return "active"
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
