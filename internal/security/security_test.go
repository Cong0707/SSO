package security

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestPasswordRoundTrip(t *testing.T) {
	hash, err := HashPassword("CorrectHorse123")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !VerifyPassword(hash, "CorrectHorse123") {
		t.Fatal("expected the password to verify")
	}
	if VerifyPassword(hash, "WrongPassword123") {
		t.Fatal("unexpected verification for the wrong password")
	}
}

func TestEncryptRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for index := range key {
		key[index] = byte(index + 1)
	}
	encrypted, err := Encrypt(key, "sensitive value")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	decrypted, err := Decrypt(key, encrypted)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if decrypted != "sensitive value" {
		t.Fatalf("unexpected plaintext %q", decrypted)
	}
}

func TestLegacyBcryptPasswordVerifies(t *testing.T) {
	legacy, err := bcrypt.GenerateFromPassword([]byte("LegacyPass123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("GenerateFromPassword: %v", err)
	}
	if !VerifyPassword(string(legacy), "LegacyPass123") {
		t.Fatal("expected bcrypt password to verify")
	}
}
