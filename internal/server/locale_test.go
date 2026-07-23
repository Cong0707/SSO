package server

import (
	"strings"
	"testing"
)

func TestRequestLocale(t *testing.T) {
	tests := []struct {
		name           string
		requested      string
		acceptLanguage string
		want           string
	}{
		{name: "explicit selection wins", requested: "ja", acceptLanguage: "fr-FR", want: "ja"},
		{name: "traditional Chinese browser", acceptLanguage: "zh-Hant-TW,zh;q=0.9", want: "zhTW"},
		{name: "regional language variant", acceptLanguage: "fr-CA,fr;q=0.8,en;q=0.5", want: "fr"},
		{name: "first supported preference", acceptLanguage: "de-DE,vi-VN;q=0.8,en;q=0.5", want: "vi"},
		{name: "unsupported browser fallback", acceptLanguage: "de-DE", want: "en"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := requestLocale(test.requested, test.acceptLanguage); got != test.want {
				t.Fatalf("requestLocale(%q, %q) = %q, want %q", test.requested, test.acceptLanguage, got, test.want)
			}
		})
	}
}

func TestVerificationEmailUsesAccountLocale(t *testing.T) {
	for _, locale := range []string{"zhCN", "en", "fr", "ru", "ja", "vi", "zhTW"} {
		subject, body := verificationEmail(locale, "123456")
		if subject == "" || !strings.Contains(body, "123456") {
			t.Fatalf("locale %q produced an incomplete verification email", locale)
		}
	}
}
