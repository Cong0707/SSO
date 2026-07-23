package server

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/Cong0707/sso/internal/model"
	"github.com/Cong0707/sso/internal/security"
	"github.com/go-oauth2/oauth2/v4"
	oauthModels "github.com/go-oauth2/oauth2/v4/models"
	"gorm.io/gorm"
)

type databaseTokenStore struct {
	db        *gorm.DB
	masterKey []byte
}

type refreshClaimContextKey struct{}

func newDatabaseTokenStore(db *gorm.DB, masterKey []byte) oauth2.TokenStore {
	return &databaseTokenStore{db: db, masterKey: masterKey}
}

func (s *databaseTokenStore) Create(ctx context.Context, info oauth2.TokenInfo) error {
	userID, err := strconv.ParseUint(info.GetUserID(), 10, 64)
	if err != nil || userID == 0 {
		return errors.New("oauth token has invalid user")
	}
	familyID := ""
	if extended, ok := info.(oauth2.ExtendableTokenInfo); ok {
		familyID = extended.GetExtension().Get("token_family_id")
		if familyID == "" {
			familyID, err = security.RandomToken(24)
			if err != nil {
				return err
			}
			extended.GetExtension().Set("token_family_id", familyID)
		}
	}
	if familyID == "" {
		familyID, err = security.RandomToken(24)
		if err != nil {
			return err
		}
	}
	payload, err := json.Marshal(info)
	if err != nil {
		return err
	}
	encrypted, err := security.Encrypt(s.masterKey, string(payload))
	if err != nil {
		return err
	}
	record := model.OAuthTokenRecord{
		UserID:           userID,
		ClientID:         info.GetClientID(),
		TokenFamilyID:    familyID,
		CodeHash:         tokenDigest(info.GetCode()),
		AccessHash:       tokenDigest(info.GetAccess()),
		RefreshHash:      tokenDigest(info.GetRefresh()),
		PayloadEncrypted: encrypted,
		ExpiresAt:        tokenRecordExpiry(info),
	}
	var app model.OAuthApplication
	if err := s.db.WithContext(ctx).Where("client_id = ?", info.GetClientID()).First(&app).Error; err == nil {
		record.AppID = &app.ID
		var grant model.Grant
		if err := s.db.WithContext(ctx).Where("user_id = ? AND app_id = ? AND revoked_at IS NULL", userID, app.ID).First(&grant).Error; err == nil {
			record.GrantID = &grant.ID
		}
	}
	return s.db.WithContext(ctx).Create(&record).Error
}

func (s *databaseTokenStore) RemoveByCode(ctx context.Context, code string) error {
	if code == "" {
		return nil
	}
	return s.db.WithContext(ctx).Where("code_hash = ?", tokenDigest(code)).Delete(&model.OAuthTokenRecord{}).Error
}

func (s *databaseTokenStore) RemoveByAccess(ctx context.Context, access string) error {
	return s.remove(ctx, "access_hash", access)
}

func (s *databaseTokenStore) RemoveByRefresh(ctx context.Context, refresh string) error {
	return s.remove(ctx, "refresh_hash", refresh)
}

func (s *databaseTokenStore) GetByCode(ctx context.Context, code string) (oauth2.TokenInfo, error) {
	return s.get(ctx, "code_hash", code)
}

func (s *databaseTokenStore) GetByAccess(ctx context.Context, access string) (oauth2.TokenInfo, error) {
	return s.get(ctx, "access_hash", access)
}

func (s *databaseTokenStore) GetByRefresh(ctx context.Context, refresh string) (oauth2.TokenInfo, error) {
	return s.get(ctx, "refresh_hash", refresh)
}

func (s *databaseTokenStore) remove(ctx context.Context, column, raw string) error {
	if raw == "" {
		return nil
	}
	now := time.Now()
	return s.db.WithContext(ctx).Model(&model.OAuthTokenRecord{}).
		Where(column+" = ? AND revoked_at IS NULL", tokenDigest(raw)).Update("revoked_at", &now).Error
}

func (s *databaseTokenStore) get(ctx context.Context, column, raw string) (oauth2.TokenInfo, error) {
	if raw == "" {
		return nil, nil
	}
	var record model.OAuthTokenRecord
	err := s.db.WithContext(ctx).Where(column+" = ? AND expires_at > ?", tokenDigest(raw), time.Now()).Order("id DESC").First(&record).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if record.RevokedAt != nil {
		if column == "refresh_hash" && record.TokenFamilyID != "" {
			now := time.Now()
			_ = s.db.WithContext(ctx).Model(&model.OAuthTokenRecord{}).
				Where("token_family_id = ? AND revoked_at IS NULL", record.TokenFamilyID).Update("revoked_at", &now).Error
		}
		return nil, nil
	}
	if column == "refresh_hash" && record.RefreshConsumedAt != nil {
		claimedHash, _ := ctx.Value(refreshClaimContextKey{}).(string)
		if claimedHash == "" || claimedHash != record.RefreshHash {
			return nil, nil
		}
	}
	if !s.recordActive(ctx, &record) {
		return nil, nil
	}
	payload, err := security.Decrypt(s.masterKey, record.PayloadEncrypted)
	if err != nil {
		return nil, err
	}
	var token oauthModels.Token
	if err := json.Unmarshal([]byte(payload), &token); err != nil {
		return nil, err
	}
	return &token, nil
}

func (s *databaseTokenStore) claimRefresh(ctx context.Context, raw, clientID string) (context.Context, bool, error) {
	if raw == "" {
		return ctx, false, nil
	}
	hash := tokenDigest(raw)
	var record model.OAuthTokenRecord
	err := s.db.WithContext(ctx).Where("refresh_hash = ? AND expires_at > ?", hash, time.Now()).Order("id DESC").First(&record).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ctx, false, nil
	}
	if err != nil {
		return ctx, false, err
	}
	if record.ClientID != clientID || record.RevokedAt != nil || record.RefreshConsumedAt != nil {
		if record.TokenFamilyID != "" && (record.RevokedAt != nil || record.RefreshConsumedAt != nil) {
			now := time.Now()
			if err := s.db.WithContext(ctx).Model(&model.OAuthTokenRecord{}).
				Where("token_family_id = ? AND revoked_at IS NULL", record.TokenFamilyID).Update("revoked_at", &now).Error; err != nil {
				return ctx, false, err
			}
		}
		return ctx, false, nil
	}
	if !s.recordActive(ctx, &record) {
		return ctx, false, nil
	}
	now := time.Now()
	result := s.db.WithContext(ctx).Model(&model.OAuthTokenRecord{}).
		Where("id = ? AND revoked_at IS NULL AND refresh_consumed_at IS NULL", record.ID).
		Update("refresh_consumed_at", &now)
	if result.Error != nil {
		return ctx, false, result.Error
	}
	if result.RowsAffected != 1 {
		now := time.Now()
		if err := s.db.WithContext(ctx).Model(&model.OAuthTokenRecord{}).
			Where("token_family_id = ? AND revoked_at IS NULL", record.TokenFamilyID).Update("revoked_at", &now).Error; err != nil {
			return ctx, false, err
		}
		return ctx, false, nil
	}
	return context.WithValue(ctx, refreshClaimContextKey{}, hash), true, nil
}

func (s *databaseTokenStore) recordActive(ctx context.Context, record *model.OAuthTokenRecord) bool {
	var user model.User
	if s.db.WithContext(ctx).Select("id", "status").First(&user, record.UserID).Error != nil || user.Status != "active" {
		return false
	}
	if record.AppID == nil || record.GrantID == nil {
		return false
	}
	var app model.OAuthApplication
	if s.db.WithContext(ctx).Select("id", "client_id", "disabled_at").First(&app, *record.AppID).Error != nil || app.DisabledAt != nil || app.ClientID != record.ClientID {
		return false
	}
	var grant model.Grant
	if s.db.WithContext(ctx).Select("id", "user_id", "app_id", "scopes", "revoked_at").First(&grant, *record.GrantID).Error != nil || grant.RevokedAt != nil || grant.UserID != record.UserID || grant.AppID != app.ID {
		return false
	}
	payload, err := security.Decrypt(s.masterKey, record.PayloadEncrypted)
	if err != nil {
		return false
	}
	var token oauthModels.Token
	if json.Unmarshal([]byte(payload), &token) != nil || !scopeSubset(token.Scope, splitScopes(grant.Scopes)) {
		return false
	}
	return true
}

func tokenDigest(raw string) string {
	if raw == "" {
		return ""
	}
	return security.HashToken(raw)
}

func tokenRecordExpiry(info oauth2.TokenInfo) time.Time {
	if refresh := info.GetRefresh(); refresh != "" && info.GetRefreshExpiresIn() > 0 {
		return info.GetRefreshCreateAt().Add(info.GetRefreshExpiresIn())
	}
	if access := info.GetAccess(); access != "" && info.GetAccessExpiresIn() > 0 {
		return info.GetAccessCreateAt().Add(info.GetAccessExpiresIn())
	}
	if code := info.GetCode(); code != "" && info.GetCodeExpiresIn() > 0 {
		return info.GetCodeCreateAt().Add(info.GetCodeExpiresIn())
	}
	return time.Now().Add(24 * time.Hour)
}

func revokeOAuthTokens(tx *gorm.DB, query string, args ...any) error {
	now := time.Now()
	return tx.Model(&model.OAuthTokenRecord{}).
		Where(query+" AND revoked_at IS NULL", args...).Update("revoked_at", &now).Error
}
