package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"

	"github.com/Cong0707/sso/internal/model"
	"github.com/go-oauth2/oauth2/v4"
	"gorm.io/gorm"
)

type clientInfo struct {
	id      string
	secret  string
	domain  string
	public  bool
	ownerID string
}

func (c clientInfo) GetID() string     { return c.id }
func (c clientInfo) GetSecret() string { return "" }
func (c clientInfo) GetDomain() string { return c.domain }
func (c clientInfo) IsPublic() bool    { return c.public }
func (c clientInfo) GetUserID() string { return c.ownerID }
func (c clientInfo) VerifyPassword(value string) bool {
	if c.public {
		return value == ""
	}
	sum := sha256.Sum256([]byte(value))
	got := hex.EncodeToString(sum[:])
	return subtleEqual(got, c.secret)
}

func subtleEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte
	for i := range a {
		result |= a[i] ^ b[i]
	}
	return result == 0
}

type clientStore struct{ db *gorm.DB }

func (s *clientStore) GetByID(ctx context.Context, id string) (oauth2.ClientInfo, error) {
	var app model.OAuthApplication
	if err := s.db.WithContext(ctx).Where("client_id = ? AND disabled_at IS NULL", id).First(&app).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("client not found")
		}
		return nil, err
	}
	return clientInfo{id: app.ClientID, secret: app.ClientSecretHash, domain: app.RedirectURI, public: app.Public, ownerID: strconv.FormatUint(app.OwnerID, 10)}, nil
}
