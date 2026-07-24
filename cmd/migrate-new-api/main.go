package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/Cong0707/sso/internal/config"
	"github.com/Cong0707/sso/internal/identitymigration"
	"github.com/Cong0707/sso/internal/model"
)

func main() {
	mode := flag.String("mode", "dry-run", "dry-run, import, verify, or rollback")
	sourceDriver := flag.String("source-driver", os.Getenv("NEW_API_DATABASE_DRIVER"), "source database driver: postgres, mysql, sqlite")
	sourceDSN := flag.String("source-dsn", os.Getenv("NEW_API_DATABASE_DSN"), "source database DSN")
	batchID := flag.String("batch", "", "migration batch ID; import generates one when omitted")
	afterID := flag.Int64("after-id", 0, "only scan source users with ID greater than this checkpoint")
	limit := flag.Int("limit", 20000, "maximum source users to process")
	oidcIssuer := flag.String("oidc-issuer", "", "issuer for imported OIDC subjects")
	trustSourceEmails := flag.Bool("trust-source-emails", false, "mark source emails verified only when source ownership has been independently confirmed")
	report := flag.String("report", "", "optional JSON report file")
	flag.Parse()
	if *mode != "rollback" && (*sourceDriver == "" || *sourceDSN == "") {
		log.Fatal("-source-driver and -source-dsn are required unless -mode rollback")
	}
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("load target configuration: %v", err)
	}
	cfg.AutoMigrate = false
	target, err := model.Open(cfg)
	if err != nil {
		log.Fatalf("open target database: %v", err)
	}
	if err := model.SchemaReady(target); err != nil {
		log.Fatalf("target schema is not ready; run sso-migrate first: %v", err)
	}
	runner, err := identitymigration.New(target, cfg, identitymigration.Options{SourceDriver: *sourceDriver, SourceDSN: *sourceDSN, BatchID: *batchID, AfterID: *afterID, Limit: *limit, OIDCIssuer: *oidcIssuer, TrustSourceEmails: *trustSourceEmails})
	if err != nil {
		log.Fatalf("initialize migration: %v", err)
	}
	var result identitymigration.Result
	switch *mode {
	case "dry-run":
		result, err = runner.DryRun()
	case "import":
		result, err = runner.Import()
	case "verify":
		result, err = runner.Verify(*batchID)
	case "rollback":
		result, err = runner.Rollback(*batchID)
	default:
		log.Fatalf("unsupported mode %q", *mode)
	}
	if err != nil {
		log.Fatalf("migration %s failed: %v", *mode, err)
	}
	encoded, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(encoded))
	if *report != "" {
		if err := os.WriteFile(*report, append(encoded, '\n'), 0o600); err != nil {
			log.Fatalf("write report: %v", err)
		}
	}
}
