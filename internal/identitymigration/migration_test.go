package identitymigration

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/Cong0707/sso/internal/config"
	"github.com/Cong0707/sso/internal/model"
	"github.com/Cong0707/sso/internal/security"
	"github.com/glebarez/sqlite"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func TestMigratedLocalePreservesKnownPreferenceAndMarksUnknown(t *testing.T) {
	tests := map[string]struct {
		locale string
		source string
	}{
		"":        {"en", model.LocaleSourceUnknown},
		"unknown": {"en", model.LocaleSourceUnknown},
		"zh-CN":   {"zhCN", model.LocaleSourceImported},
		"zh_Hant": {"zhTW", model.LocaleSourceImported},
		"en-US":   {"en", model.LocaleSourceImported},
		"fr":      {"fr", model.LocaleSourceImported},
	}
	for input, expected := range tests {
		locale, source := migratedLocale(input)
		if locale != expected.locale || source != expected.source {
			t.Fatalf("migratedLocale(%q) = (%q, %q), want (%q, %q)", input, locale, source, expected.locale, expected.source)
		}
	}
}

func TestMigrationImportVerifyAndRollback(t *testing.T) {
	temp := t.TempDir()
	sourcePath := filepath.Join(temp, "source.db")
	source, err := gorm.Open(sqlite.Open(sourcePath), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	sourceSQL, _ := source.DB()
	t.Cleanup(func() { _ = sourceSQL.Close() })
	if err := source.Table("users").AutoMigrate(&SourceUser{}); err != nil {
		t.Fatal(err)
	}
	password, _ := bcrypt.GenerateFromPassword([]byte("Password123"), bcrypt.DefaultCost)
	users := []SourceUser{
		{ID: 10, Username: "alice", Password: string(password), DisplayName: "Alice", Role: 100, Status: 1, Email: "Alice@example.com", GitHubID: "github-10", CreatedAt: time.Now().Unix()},
		{ID: 11, Username: "bob", Password: string(password), DisplayName: "Bob", Role: 1, Status: 1, Email: "bob@example.com", CreatedAt: time.Now().Unix()},
	}
	if err := source.Table("users").Create(&users).Error; err != nil {
		t.Fatal(err)
	}
	targetCfg := config.Config{DatabaseDriver: "sqlite", DatabaseDSN: filepath.Join(temp, "target.db"), BootstrapAdminEmails: []string{"alice@example.com"}}
	target, err := model.Open(targetCfg)
	if err != nil {
		t.Fatal(err)
	}
	targetSQL, _ := target.DB()
	t.Cleanup(func() { _ = targetSQL.Close() })
	runner, err := New(target, targetCfg, Options{SourceDriver: "sqlite", SourceDSN: sourcePath, Limit: 100, TrustSourceEmails: true})
	if err != nil {
		t.Fatal(err)
	}
	runnerSourceSQL, _ := runner.Source.DB()
	t.Cleanup(func() { _ = runnerSourceSQL.Close() })
	dryRun, err := runner.DryRun()
	if err != nil || len(dryRun.Issues) != 0 {
		t.Fatalf("dry run: result=%#v err=%v", dryRun, err)
	}
	imported, err := runner.Import()
	if err != nil || imported.Imported != 2 || imported.BatchID == "" {
		t.Fatalf("import: result=%#v err=%v", imported, err)
	}
	var alice model.User
	if err := target.Where("username = ?", "alice").First(&alice).Error; err != nil || alice.Role != "admin" {
		t.Fatalf("explicit bootstrap admin was not imported: user=%#v err=%v", alice, err)
	}
	var bob model.User
	if err := target.Where("username = ?", "bob").First(&bob).Error; err != nil || bob.Role != "user" {
		t.Fatalf("source business role leaked into SSO: user=%#v err=%v", bob, err)
	}
	verified, err := runner.Verify(imported.BatchID)
	if err != nil || verified.Verified != 2 || len(verified.Issues) != 0 {
		t.Fatalf("verify: result=%#v err=%v", verified, err)
	}
	activity := model.AuditEvent{UserID: alice.ID, Action: "test.activity"}
	if err := target.Create(&activity).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Rollback(imported.BatchID); err == nil {
		t.Fatal("rollback removed a migration batch after post-import activity")
	}
	if err := target.Delete(&activity).Error; err != nil {
		t.Fatal(err)
	}
	rolledBack, err := runner.Rollback(imported.BatchID)
	if err != nil || rolledBack.RolledBack != 2 {
		t.Fatalf("rollback: result=%#v err=%v", rolledBack, err)
	}
	var count int64
	if err := target.Model(&model.User{}).Count(&count).Error; err != nil || count != 0 {
		t.Fatalf("rollback left imported users: count=%d err=%v", count, err)
	}
}

func TestDuplicateLegacyEmailIsPreservedWithoutBlockingImport(t *testing.T) {
	temp := t.TempDir()
	sourcePath := filepath.Join(temp, "source.db")
	source, err := gorm.Open(sqlite.Open(sourcePath), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	sourceSQL, _ := source.DB()
	t.Cleanup(func() { _ = sourceSQL.Close() })
	if err := source.Table("users").AutoMigrate(&SourceUser{}); err != nil {
		t.Fatal(err)
	}
	password, _ := bcrypt.GenerateFromPassword([]byte("Password123"), bcrypt.DefaultCost)
	users := []SourceUser{
		{ID: 1, Username: "first", Password: string(password), Status: 1, Email: "duplicate@example.com"},
		{ID: 2, Username: "second", Password: string(password), Status: 1, Email: "DUPLICATE@example.com"},
	}
	if err := source.Table("users").Create(&users).Error; err != nil {
		t.Fatal(err)
	}
	targetCfg := config.Config{DatabaseDriver: "sqlite", DatabaseDSN: filepath.Join(temp, "target.db")}
	target, _ := model.Open(targetCfg)
	targetSQL, _ := target.DB()
	t.Cleanup(func() { _ = targetSQL.Close() })
	runner, _ := New(target, targetCfg, Options{SourceDriver: "sqlite", SourceDSN: sourcePath, Limit: 100})
	runnerSourceSQL, _ := runner.Source.DB()
	t.Cleanup(func() { _ = runnerSourceSQL.Close() })
	result, err := runner.DryRun()
	if err != nil {
		t.Fatal(err)
	}
	warned := map[int64]bool{}
	for _, issue := range result.Issues {
		if issue.Kind == "duplicate_email_preserved" && issue.Severity == "warning" {
			warned[issue.SourceUserID] = true
		}
	}
	if !warned[1] || !warned[2] {
		t.Fatalf("duplicate email was not reported for both source users: %#v", result.Issues)
	}
	imported, err := runner.Import()
	if err != nil || imported.Imported != 2 || imported.Skipped != 0 {
		t.Fatalf("duplicate email import failed: result=%#v err=%v", imported, err)
	}
	var legacyCount, emailCount int64
	if err := target.Model(&model.LegacyLoginIdentifier{}).Count(&legacyCount).Error; err != nil || legacyCount != 2 {
		t.Fatalf("legacy email rows=%d err=%v", legacyCount, err)
	}
	if err := target.Model(&model.UserEmail{}).Count(&emailCount).Error; err != nil || emailCount != 0 {
		t.Fatalf("duplicate email unexpectedly became authoritative: rows=%d err=%v", emailCount, err)
	}
	verified, err := runner.Verify(imported.BatchID)
	if err != nil || verified.Verified != 2 || len(verified.Issues) != 0 {
		t.Fatalf("duplicate email verify failed: result=%#v err=%v", verified, err)
	}
}

func TestUntrustedSourceEmailIsNotImportedAsBinding(t *testing.T) {
	temp := t.TempDir()
	sourcePath := filepath.Join(temp, "source.db")
	source, err := gorm.Open(sqlite.Open(sourcePath), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	sourceSQL, _ := source.DB()
	t.Cleanup(func() { _ = sourceSQL.Close() })
	if err := source.Table("users").AutoMigrate(&SourceUser{}); err != nil {
		t.Fatal(err)
	}
	password, _ := bcrypt.GenerateFromPassword([]byte("Password123"), bcrypt.DefaultCost)
	legacy := SourceUser{ID: 3, Username: "legacy-email", Password: string(password), Status: 1, Email: "legacy@example.com"}
	if err := source.Table("users").Create(&legacy).Error; err != nil {
		t.Fatal(err)
	}
	targetCfg := config.Config{DatabaseDriver: "sqlite", DatabaseDSN: filepath.Join(temp, "target.db"), BootstrapAdminEmails: []string{"legacy@example.com"}}
	target, err := model.Open(targetCfg)
	if err != nil {
		t.Fatal(err)
	}
	targetSQL, _ := target.DB()
	t.Cleanup(func() { _ = targetSQL.Close() })
	runner, err := New(target, targetCfg, Options{SourceDriver: "sqlite", SourceDSN: sourcePath, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	runnerSourceSQL, _ := runner.Source.DB()
	t.Cleanup(func() { _ = runnerSourceSQL.Close() })
	imported, err := runner.Import()
	if err != nil || imported.Imported != 1 {
		t.Fatalf("import untrusted source email: result=%#v err=%v", imported, err)
	}
	var user model.User
	if err := target.Where("username = ?", legacy.Username).First(&user).Error; err != nil {
		t.Fatal(err)
	}
	if user.Role != "user" {
		t.Fatalf("untrusted source email granted administrator access: %#v", user)
	}
	var emailCount, legacyCount int64
	if err := target.Model(&model.UserEmail{}).Where("user_id = ?", user.ID).Count(&emailCount).Error; err != nil || emailCount != 0 {
		t.Fatalf("untrusted email became a formal binding: count=%d err=%v", emailCount, err)
	}
	if err := target.Model(&model.LegacyLoginIdentifier{}).Where("user_id = ? AND normalized_identifier = ?", user.ID, "legacy@example.com").Count(&legacyCount).Error; err != nil || legacyCount != 1 {
		t.Fatalf("untrusted email was not preserved as a legacy login identifier: count=%d err=%v", legacyCount, err)
	}
	verified, err := runner.Verify(imported.BatchID)
	if err != nil || verified.Verified != 1 || len(verified.Issues) != 0 {
		t.Fatalf("verify untrusted source email import: result=%#v err=%v", verified, err)
	}
}

func TestLegacyUnicodeUsernameAndPasswordOnlyAccountRemainUsable(t *testing.T) {
	temp := t.TempDir()
	sourcePath := filepath.Join(temp, "source.db")
	source, err := gorm.Open(sqlite.Open(sourcePath), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	sourceSQL, _ := source.DB()
	t.Cleanup(func() { _ = sourceSQL.Close() })
	if err := source.Table("users").AutoMigrate(&SourceUser{}); err != nil {
		t.Fatal(err)
	}
	password, _ := bcrypt.GenerateFromPassword([]byte("Password123"), bcrypt.DefaultCost)
	legacy := SourceUser{ID: 7, Username: "鱼", Password: string(password), Status: 1}
	if err := source.Table("users").Create(&legacy).Error; err != nil {
		t.Fatal(err)
	}
	targetCfg := config.Config{DatabaseDriver: "sqlite", DatabaseDSN: filepath.Join(temp, "target.db")}
	target, err := model.Open(targetCfg)
	if err != nil {
		t.Fatal(err)
	}
	targetSQL, _ := target.DB()
	t.Cleanup(func() { _ = targetSQL.Close() })
	runner, err := New(target, targetCfg, Options{SourceDriver: "sqlite", SourceDSN: sourcePath, Limit: 20000})
	if err != nil {
		t.Fatal(err)
	}
	runnerSourceSQL, _ := runner.Source.DB()
	t.Cleanup(func() { _ = runnerSourceSQL.Close() })
	result, err := runner.DryRun()
	if err != nil {
		t.Fatal(err)
	}
	for _, issue := range result.Issues {
		if issue.Severity == "error" {
			t.Fatalf("legacy username was blocked: %#v", result.Issues)
		}
	}
	imported, err := runner.Import()
	if err != nil || imported.Imported != 1 {
		t.Fatalf("legacy username import failed: result=%#v err=%v", imported, err)
	}
	var user model.User
	if err := target.Where("username = ?", "鱼").First(&user).Error; err != nil || !user.PasswordConfigured {
		t.Fatalf("legacy username was not preserved: user=%#v err=%v", user, err)
	}
}

func TestPasswordlessProviderAccountRemainsPasswordless(t *testing.T) {
	temp := t.TempDir()
	sourcePath := filepath.Join(temp, "source.db")
	source, err := gorm.Open(sqlite.Open(sourcePath), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	sourceSQL, _ := source.DB()
	t.Cleanup(func() { _ = sourceSQL.Close() })
	if err := source.Table("users").AutoMigrate(&SourceUser{}); err != nil {
		t.Fatal(err)
	}
	legacy := SourceUser{ID: 8, Username: "provider-only", GitHubID: "github-8", Status: 1}
	if err := source.Table("users").Create(&legacy).Error; err != nil {
		t.Fatal(err)
	}
	targetCfg := config.Config{DatabaseDriver: "sqlite", DatabaseDSN: filepath.Join(temp, "target.db")}
	target, err := model.Open(targetCfg)
	if err != nil {
		t.Fatal(err)
	}
	targetSQL, _ := target.DB()
	t.Cleanup(func() { _ = targetSQL.Close() })
	runner, err := New(target, targetCfg, Options{SourceDriver: "sqlite", SourceDSN: sourcePath, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	runnerSourceSQL, _ := runner.Source.DB()
	t.Cleanup(func() { _ = runnerSourceSQL.Close() })
	imported, err := runner.Import()
	if err != nil || imported.Imported != 1 {
		t.Fatalf("provider-only import failed: result=%#v err=%v", imported, err)
	}
	var user model.User
	if err := target.Where("username = ?", legacy.Username).First(&user).Error; err != nil {
		t.Fatal(err)
	}
	if user.PasswordConfigured || user.PasswordHash == "" {
		t.Fatalf("passwordless account state is invalid: configured=%v hash_empty=%v", user.PasswordConfigured, user.PasswordHash == "")
	}
	verified, err := runner.Verify(imported.BatchID)
	if err != nil || verified.Verified != 1 || len(verified.Issues) != 0 {
		t.Fatalf("provider-only verify failed: result=%#v err=%v", verified, err)
	}
	var mapping model.IdentityMigrationMapping
	if err := target.Where("batch_id = ?", imported.BatchID).First(&mapping).Error; err != nil {
		t.Fatal(err)
	}
	legacyUpdatedAt := mapping.CreatedAt.Add(-time.Minute)
	if err := target.Model(&model.User{}).Where("id = ?", user.ID).Updates(map[string]any{
		"password_configured": true,
		"updated_at":          legacyUpdatedAt,
	}).Error; err != nil {
		t.Fatal(err)
	}
	repaired, err := runner.RepairPasswordState(imported.BatchID)
	if err != nil || repaired.Reconciled != 1 || repaired.Skipped != 0 {
		t.Fatalf("password state repair failed: result=%#v err=%v", repaired, err)
	}
	if err := target.First(&user, user.ID).Error; err != nil || user.PasswordConfigured {
		t.Fatalf("password state repair was not persisted: user=%#v err=%v", user, err)
	}
}

func TestVerifyAllowsPostMigrationPasswordUpgrade(t *testing.T) {
	temp := t.TempDir()
	sourcePath := filepath.Join(temp, "source.db")
	source, err := gorm.Open(sqlite.Open(sourcePath), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	sourceSQL, _ := source.DB()
	t.Cleanup(func() { _ = sourceSQL.Close() })
	if err := source.Table("users").AutoMigrate(&SourceUser{}); err != nil {
		t.Fatal(err)
	}
	password, _ := bcrypt.GenerateFromPassword([]byte("Password123"), bcrypt.DefaultCost)
	legacy := SourceUser{ID: 9, Username: "rehash-user", Password: string(password), Status: 1}
	if err := source.Table("users").Create(&legacy).Error; err != nil {
		t.Fatal(err)
	}
	targetCfg := config.Config{DatabaseDriver: "sqlite", DatabaseDSN: filepath.Join(temp, "target.db")}
	target, err := model.Open(targetCfg)
	if err != nil {
		t.Fatal(err)
	}
	targetSQL, _ := target.DB()
	t.Cleanup(func() { _ = targetSQL.Close() })
	runner, err := New(target, targetCfg, Options{SourceDriver: "sqlite", SourceDSN: sourcePath, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	runnerSourceSQL, _ := runner.Source.DB()
	t.Cleanup(func() { _ = runnerSourceSQL.Close() })
	imported, err := runner.Import()
	if err != nil || imported.Imported != 1 {
		t.Fatalf("rehash import failed: result=%#v err=%v", imported, err)
	}
	var mapping model.IdentityMigrationMapping
	if err := target.Where("batch_id = ?", imported.BatchID).First(&mapping).Error; err != nil {
		t.Fatal(err)
	}
	var user model.User
	if err := target.First(&user, mapping.SSOUserID).Error; err != nil {
		t.Fatal(err)
	}
	upgraded, err := security.HashPassword("Password123")
	if err != nil {
		t.Fatal(err)
	}
	if err := target.Model(&user).Updates(map[string]any{
		"password_hash": upgraded,
		"updated_at":    mapping.CreatedAt.Add(time.Second),
	}).Error; err != nil {
		t.Fatal(err)
	}
	verified, err := runner.Verify(imported.BatchID)
	if err != nil || verified.Verified != 1 || len(verified.Issues) != 0 {
		t.Fatalf("post-migration password upgrade was rejected: result=%#v err=%v", verified, err)
	}
}

func TestDryRunRejectsPasswordlessEmailOnlyUser(t *testing.T) {
	temp := t.TempDir()
	sourcePath := filepath.Join(temp, "source.db")
	source, err := gorm.Open(sqlite.Open(sourcePath), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	sourceSQL, _ := source.DB()
	t.Cleanup(func() { _ = sourceSQL.Close() })
	if err := source.Table("users").AutoMigrate(&SourceUser{}); err != nil {
		t.Fatal(err)
	}
	if err := source.Table("users").Create(&SourceUser{ID: 1, Username: "locked-user", Email: "locked@example.com", Status: 1}).Error; err != nil {
		t.Fatal(err)
	}
	targetCfg := config.Config{DatabaseDriver: "sqlite", DatabaseDSN: filepath.Join(temp, "target.db")}
	target, err := model.Open(targetCfg)
	if err != nil {
		t.Fatal(err)
	}
	targetSQL, _ := target.DB()
	t.Cleanup(func() { _ = targetSQL.Close() })
	runner, err := New(target, targetCfg, Options{SourceDriver: "sqlite", SourceDSN: sourcePath, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	runnerSourceSQL, _ := runner.Source.DB()
	t.Cleanup(func() { _ = runnerSourceSQL.Close() })
	result, err := runner.DryRun()
	if err != nil {
		t.Fatal(err)
	}
	for _, issue := range result.Issues {
		if issue.SourceUserID == 1 && issue.Kind == "no_login_identity" && issue.Severity == "error" {
			return
		}
	}
	t.Fatalf("passwordless email-only user was not blocked: %#v", result.Issues)
}
