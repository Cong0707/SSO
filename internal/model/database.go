package model

import (
	"fmt"
	"strings"
	"time"

	"github.com/Cong0707/sso/internal/config"
	"github.com/glebarez/sqlite"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func Open(cfg config.Config) (*gorm.DB, error) {
	var dialector gorm.Dialector
	switch strings.ToLower(cfg.DatabaseDriver) {
	case "sqlite", "sqlite3":
		dialector = sqlite.Open(cfg.DatabaseDSN)
	case "postgres", "postgresql":
		dialector = postgres.Open(cfg.DatabaseDSN)
	case "mysql":
		dialector = mysql.Open(cfg.DatabaseDSN)
	default:
		return nil, fmt.Errorf("unsupported database driver %q", cfg.DatabaseDriver)
	}

	db, err := gorm.Open(dialector, &gorm.Config{Logger: logger.Default.LogMode(logger.Error)})
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("get database connection: %w", err)
	}
	sqlDB.SetConnMaxLifetime(30 * time.Minute)
	sqlDB.SetMaxIdleConns(5)
	sqlDB.SetMaxOpenConns(20)
	if strings.EqualFold(cfg.DatabaseDriver, "sqlite") || strings.EqualFold(cfg.DatabaseDriver, "sqlite3") {
		sqlDB.SetMaxOpenConns(1)
	}
	if err := Migrate(db); err != nil {
		return nil, fmt.Errorf("migrate database: %w", err)
	}
	return db, nil
}
