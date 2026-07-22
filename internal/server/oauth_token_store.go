package server

import (
	"context"
	"encoding/json"
	"errors"
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

func newDatabaseTokenStore(db *gorm.DB, masterKey []byte) oauth2.TokenStore {
	return &databaseTokenStore{db: db, masterKey: masterKey}
}

func (s *databaseTokenStore) Create(ctx context.Context, info oauth2.TokenInfo) error {
	payload, err := json.Marshal(info)
	if err != nil {
		return err
	}
	encrypted, err := security.Encrypt(s.masterKey, string(payload))
	if err != nil {
		return err
	}
	record := model.OAuthTokenRecord{
		CodeHash:         tokenDigest(info.GetCode()),
		AccessHash:       tokenDigest(info.GetAccess()),
		RefreshHash:      tokenDigest(info.GetRefresh()),
		PayloadEncrypted: encrypted,
		ExpiresAt:        tokenRecordExpiry(info),
	}
	return s.db.WithContext(ctx).Create(&record).Error
}

func (s *databaseTokenStore) RemoveByCode(ctx context.Context, code string) error {
	return s.remove(ctx, "code_hash", code)
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
	return s.db.WithContext(ctx).Where(column+" = ?", tokenDigest(raw)).Delete(&model.OAuthTokenRecord{}).Error
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
