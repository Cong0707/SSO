package server

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Cong0707/sso/internal/model"
	"gorm.io/gorm"
)

func (s *Server) findUserByIdentifier(identifier string) (model.User, error) {
	var user model.User
	identifier = strings.ToLower(strings.TrimSpace(identifier))
	err := s.DB.Where(
		"LOWER(username) = ? OR EXISTS (SELECT 1 FROM user_emails WHERE user_emails.user_id = users.id AND user_emails.normalized_email = ? AND user_emails.disabled_at IS NULL)",
		identifier, identifier,
	).First(&user).Error
	return user, err
}

func (s *Server) userEmails(userID uint64, includeDisabled bool) ([]model.UserEmail, error) {
	query := s.DB.Where("user_id = ?", userID)
	if !includeDisabled {
		query = query.Where("disabled_at IS NULL")
	}
	var emails []model.UserEmail
	err := query.Order("primary DESC, id ASC").Find(&emails).Error
	return emails, err
}

func (s *Server) mergeAccounts(firstID, secondID uint64) (model.User, bool, error) {
	if firstID == secondID {
		var unchanged model.User
		err := s.DB.First(&unchanged, firstID).Error
		return unchanged, false, err
	}
	targetID, sourceID := firstID, secondID
	if sourceID < targetID {
		targetID, sourceID = sourceID, targetID
	}
	var target model.User
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		var source model.User
		if err := tx.First(&target, targetID).Error; err != nil {
			return err
		}
		if err := tx.First(&source, sourceID).Error; err != nil {
			return err
		}
		if target.Status != "active" || source.Status != "active" {
			return errors.New("只有正常状态的账号可以合并")
		}
		updates := map[string]any{}
		if strings.TrimSpace(target.DisplayName) == "" && strings.TrimSpace(source.DisplayName) != "" {
			updates["display_name"] = source.DisplayName
		}
		if strings.TrimSpace(target.AvatarURL) == "" && strings.TrimSpace(source.AvatarURL) != "" {
			updates["avatar_url"] = source.AvatarURL
		}
		if !target.PasswordConfigured && source.PasswordConfigured {
			updates["password_hash"] = source.PasswordHash
			updates["password_configured"] = true
		}
		if !target.MFAEnabled && source.MFAEnabled {
			updates["mfa_enabled"] = true
			updates["mfa_secret_encrypted"] = source.MFASecretEncrypted
			updates["mfa_backup_code_hashes"] = source.MFABackupCodeHashes
		}
		if source.Role == "admin" {
			updates["role"] = "admin"
		}
		if len(updates) > 0 {
			if err := tx.Model(&target).Updates(updates).Error; err != nil {
				return err
			}
		}
		if err := tx.Model(&model.UserEmail{}).Where("user_id = ?", sourceID).Update("user_id", targetID).Error; err != nil {
			return fmt.Errorf("合并邮箱失败: %w", err)
		}
		if err := tx.Model(&model.UpstreamIdentity{}).Where("user_id = ?", sourceID).Update("user_id", targetID).Error; err != nil {
			return fmt.Errorf("合并第三方身份失败: %w", err)
		}
		now := time.Now()
		if err := tx.Model(&source).Updates(map[string]any{"status": "merged", "merged_into_user_id": targetID, "deactivated_at": &now}).Error; err != nil {
			return err
		}
		if err := tx.Model(&model.Session{}).Where("user_id IN ? AND revoked_at IS NULL", []uint64{targetID, sourceID}).Update("revoked_at", &now).Error; err != nil {
			return err
		}
		if err := tx.Model(&model.PersonalAccessToken{}).Where("user_id IN ? AND revoked_at IS NULL", []uint64{targetID, sourceID}).Update("revoked_at", &now).Error; err != nil {
			return err
		}
		if err := tx.Model(&model.Grant{}).Where("user_id = ? AND revoked_at IS NULL", sourceID).Update("revoked_at", &now).Error; err != nil {
			return err
		}
		if err := tx.Create(&model.AuditEvent{UserID: targetID, Action: "account.merged", Metadata: fmt.Sprintf("source_user_id=%d", sourceID)}).Error; err != nil {
			return err
		}
		return tx.First(&target, targetID).Error
	})
	return target, err == nil, err
}

func (s *Server) ensurePrimaryEmailSnapshot(tx *gorm.DB, userID uint64) error {
	var email model.UserEmail
	if err := tx.Where("user_id = ? AND disabled_at IS NULL", userID).Order("primary DESC, id ASC").First(&email).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		}
		return err
	}
	var user model.User
	if err := tx.First(&user, userID).Error; err != nil {
		return err
	}
	updates := map[string]any{"email": email.Email, "email_verified_at": email.VerifiedAt}
	return tx.Model(&user).Updates(updates).Error
}
