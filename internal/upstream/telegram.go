package upstream

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"
)

type TelegramPayload struct {
	ID        int64
	FirstName string
	LastName  string
	Username  string
	PhotoURL  string
	AuthDate  int64
	Hash      string
}

func VerifyTelegram(botToken string, payload TelegramPayload, now time.Time) (Identity, error) {
	age := now.Sub(time.Unix(payload.AuthDate, 0))
	if botToken == "" || payload.ID == 0 || payload.Hash == "" || age < 0 || age > 24*time.Hour {
		return Identity{}, errors.New("invalid Telegram login payload")
	}
	values := map[string]string{"auth_date": strconv.FormatInt(payload.AuthDate, 10), "id": strconv.FormatInt(payload.ID, 10), "first_name": payload.FirstName, "last_name": payload.LastName, "photo_url": payload.PhotoURL, "username": payload.Username}
	parts := make([]string, 0, len(values))
	for key, value := range values {
		if value != "" {
			parts = append(parts, key+"="+value)
		}
	}
	sort.Strings(parts)
	secretKey := sha256.Sum256([]byte(botToken))
	mac := hmac.New(sha256.New, secretKey[:])
	_, _ = mac.Write([]byte(strings.Join(parts, "\n")))
	expected, err := hex.DecodeString(strings.ToLower(payload.Hash))
	if err != nil || !hmac.Equal(expected, mac.Sum(nil)) {
		return Identity{}, errors.New("invalid Telegram signature")
	}
	name := strings.TrimSpace(payload.FirstName + " " + payload.LastName)
	if name == "" {
		name = payload.Username
	}
	return Identity{Subject: strconv.FormatInt(payload.ID, 10), Username: payload.Username, Name: name, AvatarURL: payload.PhotoURL}, nil
}
