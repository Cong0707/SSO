package identitymigration

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/Cong0707/sso/internal/config"
	"github.com/Cong0707/sso/internal/model"
	"github.com/glebarez/sqlite"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

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
	runner, err := New(target, targetCfg, Options{SourceDriver: "sqlite", SourceDSN: sourcePath, Limit: 100})
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
