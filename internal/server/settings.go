package server

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/Cong0707/sso/internal/config"
	"github.com/Cong0707/sso/internal/model"
	"github.com/Cong0707/sso/internal/security"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	settingRegistrationEnabled = "registration_enabled"
	settingSMTPHost            = "smtp_host"
	settingSMTPPort            = "smtp_port"
	settingSMTPUsername        = "smtp_username"
	settingSMTPPassword        = "smtp_password"
	settingSMTPFrom            = "smtp_from"
	settingCaptchaMode         = "captcha_mode"
	settingTurnstileSiteKey    = "turnstile_site_key"
	settingTurnstileSecretKey  = "turnstile_secret_key"
	settingCAPSiteKey          = "cap_site_key"
	settingCAPSecretKey        = "cap_secret_key"
	settingCAPServerURL        = "cap_server_url"
)

var secretSettingKeys = map[string]bool{
	settingSMTPPassword:       true,
	settingTurnstileSecretKey: true,
	settingCAPSecretKey:       true,
}

func seedSettings(db *gorm.DB, cfg config.Config) error {
	defaults := map[string]string{
		settingRegistrationEnabled: strconv.FormatBool(cfg.RegistrationEnabled),
		settingSMTPHost:            os.Getenv("SSO_SMTP_HOST"),
		settingSMTPPort:            envOr("SSO_SMTP_PORT", "587"),
		settingSMTPUsername:        os.Getenv("SSO_SMTP_USERNAME"),
		settingSMTPPassword:        os.Getenv("SSO_SMTP_PASSWORD"),
		settingSMTPFrom:            os.Getenv("SSO_SMTP_FROM"),
		settingCaptchaMode:         strings.ToLower(envOr("SSO_CAPTCHA_MODE", "none")),
		settingTurnstileSiteKey:    os.Getenv("SSO_TURNSTILE_SITE_KEY"),
		settingTurnstileSecretKey:  os.Getenv("SSO_TURNSTILE_SECRET_KEY"),
		settingCAPSiteKey:          os.Getenv("SSO_CAP_SITE_KEY"),
		settingCAPSecretKey:        os.Getenv("SSO_CAP_SECRET_KEY"),
		settingCAPServerURL:        envOr("SSO_CAP_SERVER_URL", "http://cap:3000"),
	}
	for key, value := range defaults {
		if secretSettingKeys[key] && value != "" {
			encrypted, err := security.Encrypt(cfg.MasterKey, value)
			if err != nil {
				return err
			}
			value = encrypted
		}
		setting := model.SystemSetting{Key: key, Value: value, Secret: secretSettingKeys[key]}
		if err := db.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "key"}}, DoNothing: true}).Create(&setting).Error; err != nil {
			return fmt.Errorf("seed setting %s: %w", key, err)
		}
	}
	return nil
}

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func (s *Server) setting(key, fallback string) string {
	var record model.SystemSetting
	if err := s.DB.Where("key = ?", key).First(&record).Error; err != nil {
		return fallback
	}
	if !record.Secret || record.Value == "" {
		return record.Value
	}
	value, err := security.Decrypt(s.Cfg.MasterKey, record.Value)
	if err != nil {
		return fallback
	}
	return value
}

func (s *Server) settingBool(key string, fallback bool) bool {
	value, err := strconv.ParseBool(s.setting(key, strconv.FormatBool(fallback)))
	if err != nil {
		return fallback
	}
	return value
}

func (s *Server) saveSetting(tx *gorm.DB, key, value string) error {
	secret := secretSettingKeys[key]
	if secret {
		if value == "" {
			return nil
		}
		encrypted, err := security.Encrypt(s.Cfg.MasterKey, value)
		if err != nil {
			return err
		}
		value = encrypted
	}
	return tx.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "key"}},
		DoUpdates: clause.AssignmentColumns([]string{"value", "secret", "updated_at"}),
	}).Create(&model.SystemSetting{Key: key, Value: value, Secret: secret}).Error
}

func (s *Server) settingConfigured(key string) bool {
	var record model.SystemSetting
	return s.DB.Select("id").Where("key = ? AND value <> ''", key).First(&record).Error == nil
}

func validateCaptchaSettings(mode string, values map[string]string, current func(string, string) string) error {
	switch mode {
	case "none":
		return nil
	case "turnstile":
		if strings.TrimSpace(valueOrCurrent(values, settingTurnstileSiteKey, current)) == "" || strings.TrimSpace(valueOrCurrent(values, settingTurnstileSecretKey, current)) == "" {
			return errors.New("启用 Turnstile 前必须填写 Site Key 和 Secret Key")
		}
	case "cap":
		if strings.TrimSpace(valueOrCurrent(values, settingCAPSiteKey, current)) == "" || strings.TrimSpace(valueOrCurrent(values, settingCAPSecretKey, current)) == "" || !validateURL(valueOrCurrent(values, settingCAPServerURL, current), false) {
			return errors.New("启用 Cap 前必须填写有效的服务地址、Site Key 和 Secret Key")
		}
	default:
		return errors.New("人机验证模式仅支持 none、turnstile 或 cap")
	}
	return nil
}

func valueOrCurrent(values map[string]string, key string, current func(string, string) string) string {
	if value, ok := values[key]; ok && value != "" {
		return value
	}
	return current(key, "")
}
