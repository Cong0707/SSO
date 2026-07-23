package main

import (
	"log"

	"github.com/Cong0707/sso/internal/config"
	"github.com/Cong0707/sso/internal/model"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("load configuration: %v", err)
	}
	cfg.AutoMigrate = false
	db, err := model.Open(cfg)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	if err := model.Migrate(db); err != nil {
		log.Fatalf("apply database migrations: %v", err)
	}
	log.Printf("database schema is at version %d", model.CurrentSchemaVersion)
}
