package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Cong0707/sso/internal/model"
	"github.com/gin-gonic/gin"
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
		{name: "quality weight wins", acceptLanguage: "en;q=0.5,ja;q=0.9", want: "ja"},
		{name: "disabled language is ignored", acceptLanguage: "zh-CN;q=0.00,en;q=0.8", want: "en"},
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

func TestDetectLocaleDoesNotInventPreference(t *testing.T) {
	for _, input := range []string{"", "de-DE", "*", "ja;q=0"} {
		if locale, ok := detectLocale("", input); ok || locale != "" {
			t.Fatalf("detectLocale accepted unsupported header %q as %q", input, locale)
		}
	}
}

func TestStoredBrowserLocaleSeparatesFallbackFromEvidence(t *testing.T) {
	tests := map[string]struct {
		locale string
		source string
	}{
		"en-US": {"en", model.LocaleSourceBrowser},
		"zh-CN": {"zhCN", model.LocaleSourceBrowser},
		"ja-JP": {"ja", model.LocaleSourceBrowser},
		"de-DE": {"en", model.LocaleSourceUnknown},
		"":      {"en", model.LocaleSourceUnknown},
	}
	for input, expected := range tests {
		locale, source := storedBrowserLocale(input)
		if locale != expected.locale || source != expected.source {
			t.Fatalf("storedBrowserLocale(%q) = (%q, %q), want (%q, %q)", input, locale, source, expected.locale, expected.source)
		}
	}
}

func TestUnknownLocaleInitializesFromBrowserOnlyOnce(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := openTestDatabase(t)
	application := &Server{DB: db}
	user := model.User{
		Username: "unknown-locale", PasswordHash: "unused", PasswordConfigured: true,
		Locale: "en", LocaleSource: model.LocaleSourceUnknown, Role: "user", Status: "active",
	}
	if err := db.Create(&user).Error; err != nil {
		t.Fatal(err)
	}

	contextWithLanguage := func(language string) *gin.Context {
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		ctx.Request = httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
		ctx.Request.Header.Set("Accept-Language", language)
		return ctx
	}

	initialized, err := application.initializeUnknownLocale(contextWithLanguage("ja-JP,ja;q=0.9"), &user, "")
	if err != nil || !initialized || user.Locale != "ja" || user.LocaleSource != model.LocaleSourceBrowser {
		t.Fatalf("browser locale was not initialized: initialized=%v user=%#v err=%v", initialized, user, err)
	}
	initialized, err = application.initializeUnknownLocale(contextWithLanguage("zh-CN"), &user, "")
	if err != nil || initialized || user.Locale != "ja" || user.LocaleSource != model.LocaleSourceBrowser {
		t.Fatalf("known locale was overwritten: initialized=%v user=%#v err=%v", initialized, user, err)
	}
	var events int64
	if err := db.Model(&model.LifecycleEvent{}).Where("user_id = ? AND type = ?", user.ID, "profile.updated").Count(&events).Error; err != nil || events != 1 {
		t.Fatalf("expected exactly one locale lifecycle event: count=%d err=%v", events, err)
	}
}

func TestUnsupportedBrowserLeavesLocaleUnknown(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := openTestDatabase(t)
	application := &Server{DB: db}
	user := model.User{
		Username: "unsupported-locale", PasswordHash: "unused", PasswordConfigured: true,
		Locale: "en", LocaleSource: model.LocaleSourceUnknown, Role: "user", Status: "active",
	}
	if err := db.Create(&user).Error; err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	ctx.Request.Header.Set("Accept-Language", "de-DE,de;q=0.9")
	initialized, err := application.initializeUnknownLocale(ctx, &user, "")
	if err != nil || initialized || user.LocaleSource != model.LocaleSourceUnknown {
		t.Fatalf("unsupported browser changed locale: initialized=%v user=%#v err=%v", initialized, user, err)
	}
	if locale := publicUser(&user)["locale"]; locale != "" {
		t.Fatalf("unknown internal fallback leaked to client: locale=%#v", locale)
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
