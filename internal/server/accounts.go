package server

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Cong0707/sso/internal/model"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func (s *Server) findUserByEmail(email string) (model.User, error) {
	var user model.User
	email = strings.ToLower(strings.TrimSpace(email))
	err := s.DB.Where(
		"EXISTS (SELECT 1 FROM user_emails WHERE user_emails.user_id = users.id AND user_emails.normalized_email = ?)",
		email,
	).First(&user).Error
	return user, err
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
		adoptSourceMFA := !target.MFAEnabled && source.MFAEnabled
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
		if adoptSourceMFA {
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
		if adoptSourceMFA {
			if err := tx.Where("user_id = ?", targetID).Delete(&model.MFABackupCode{}).Error; err != nil {
				return err
			}
			if err := tx.Model(&model.MFABackupCode{}).Where("user_id = ?", sourceID).Update("user_id", targetID).Error; err != nil {
				return err
			}
		} else if err := tx.Where("user_id = ?", sourceID).Delete(&model.MFABackupCode{}).Error; err != nil {
			return err
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
		if err := tx.Model(&model.AccountAlias{}).Where("canonical_user_id = ?", sourceID).Update("canonical_user_id", targetID).Error; err != nil {
			return err
		}
		if err := tx.Create(&model.AccountAlias{SourceUserID: sourceID, CanonicalUserID: targetID, CreatedAt: now}).Error; err != nil {
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
		if err := revokeOAuthTokens(tx, "user_id IN ?", []uint64{targetID, sourceID}); err != nil {
			return err
		}
		if err := s.recordLifecycleEvent(tx, sourceID, "account.merged", map[string]any{"canonical_sub": fmt.Sprintf("%d", targetID)}); err != nil {
			return err
		}
		if err := s.recordLifecycleEvent(tx, targetID, "account.identities_merged", map[string]any{"source_sub": fmt.Sprintf("%d", sourceID)}); err != nil {
			return err
		}
		if err := tx.Create(&model.AuditEvent{UserID: targetID, Action: "account.merged", Metadata: fmt.Sprintf("source_user_id=%d", sourceID)}).Error; err != nil {
			return err
		}
		return tx.First(&target, targetID).Error
	})
	return target, err == nil, err
}

func (s *Server) bindingRemovalAllowed(tx *gorm.DB, userID uint64, removingEmail bool) error {
	var user model.User
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Select("id").First(&user, userID).Error; err != nil {
		return err
	}
	var emailCount, identityCount int64
	if err := tx.Model(&model.UserEmail{}).Where("user_id = ?", userID).Count(&emailCount).Error; err != nil {
		return err
	}
	if err := tx.Model(&model.UpstreamIdentity{}).Where("user_id = ?", userID).Count(&identityCount).Error; err != nil {
		return err
	}
	if removingEmail {
		emailCount--
	} else {
		identityCount--
	}
	if emailCount+identityCount < 1 {
		return errors.New("账号必须保留至少一个绑定")
	}
	return nil
}

func (s *Server) deleteEmailBinding(tx *gorm.DB, userID, bindingID uint64, allowLast bool) error {
	var record model.UserEmail
	if err := tx.Where("id = ? AND user_id = ?", bindingID, userID).First(&record).Error; err != nil {
		return err
	}
	if !allowLast {
		if err := s.bindingRemovalAllowed(tx, userID, true); err != nil {
			return err
		}
	}
	return tx.Delete(&record).Error
}

func (s *Server) deleteUpstreamBinding(tx *gorm.DB, userID, bindingID uint64, allowLast bool) error {
	var record model.UpstreamIdentity
	if err := tx.Where("id = ? AND user_id = ?", bindingID, userID).First(&record).Error; err != nil {
		return err
	}
	if !allowLast {
		if err := s.bindingRemovalAllowed(tx, userID, false); err != nil {
			return err
		}
	}
	return tx.Delete(&record).Error
}
