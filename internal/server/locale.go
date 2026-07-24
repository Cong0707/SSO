package server

import (
	"sort"
	"strconv"
	"strings"

	"github.com/Cong0707/sso/internal/model"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// requestLocale is for transient UI and email rendering where an English
// fallback is required. Persistent account preferences use browserLocale and
// storedBrowserLocale so an absent language remains unknown.
func requestLocale(requested, acceptLanguage string) string {
	if locale, ok := detectLocale(requested, acceptLanguage); ok {
		return locale
	}
	return "en"
}

// browserLocale returns a value suitable for persisting as browser evidence.
// Unlike requestLocale, it never invents a fallback language.
func browserLocale(acceptLanguage string) string {
	locale, _ := detectLocale("", acceptLanguage)
	return locale
}

func storedBrowserLocale(value string) (string, string) {
	if locale, ok := supportedLocale(value); ok {
		return locale, model.LocaleSourceBrowser
	}
	// Locale remains non-null for compatibility, but LocaleSource prevents this
	// internal fallback from being projected as a user preference.
	return "en", model.LocaleSourceUnknown
}

// detectLocale returns only a language actually advertised by the browser or
// explicitly selected by the user. Unsupported and absent languages remain
// unknown instead of being persisted as English or Chinese.
func detectLocale(requested, acceptLanguage string) (string, bool) {
	if locale, ok := supportedLocale(requested); ok {
		return locale, true
	}
	type preference struct {
		locale string
		weight float64
		order  int
	}
	preferences := make([]preference, 0, 4)
	for index, part := range strings.Split(acceptLanguage, ",") {
		segments := strings.Split(part, ";")
		candidate := strings.TrimSpace(segments[0])
		weight := 1.0
		for _, segment := range segments[1:] {
			key, raw, found := strings.Cut(strings.TrimSpace(segment), "=")
			if !found || !strings.EqualFold(strings.TrimSpace(key), "q") {
				continue
			}
			parsed, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
			if err != nil {
				weight = 0
			} else {
				weight = parsed
			}
		}
		if weight <= 0 {
			continue
		}
		if locale, ok := supportedLocale(candidate); ok {
			preferences = append(preferences, preference{locale: locale, weight: weight, order: index})
		}
	}
	sort.SliceStable(preferences, func(i, j int) bool {
		if preferences[i].weight == preferences[j].weight {
			return preferences[i].order < preferences[j].order
		}
		return preferences[i].weight > preferences[j].weight
	})
	if len(preferences) > 0 {
		return preferences[0].locale, true
	}
	return "", false
}

func supportedLocale(value string) (string, bool) {
	normalized := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), "_", "-"))
	if normalized == "zhtw" || normalized == "zh-tw" || normalized == "zh-hk" || normalized == "zh-mo" || strings.HasPrefix(normalized, "zh-hant") {
		return "zhTW", true
	}
	if normalized == "zhcn" || strings.HasPrefix(normalized, "zh") {
		return "zhCN", true
	}
	base := strings.SplitN(normalized, "-", 2)[0]
	switch base {
	case "en":
		return "en", true
	case "fr":
		return "fr", true
	case "ru":
		return "ru", true
	case "ja":
		return "ja", true
	case "vi":
		return "vi", true
	default:
		return "", false
	}
}

// initializeUnknownLocale persists the browser's supported language once for
// a legacy account. A later explicit profile choice changes LocaleSource to
// "user" and can never be overwritten by this path.
func (s *Server) initializeUnknownLocale(c *gin.Context, user *model.User, browserFallback string) (bool, error) {
	if user == nil || (user.LocaleSource != "" && user.LocaleSource != model.LocaleSourceUnknown) {
		return false, nil
	}
	locale, ok := detectLocale("", c.GetHeader("Accept-Language"))
	if !ok {
		locale, ok = supportedLocale(browserFallback)
	}
	if !ok {
		return false, nil
	}
	initialized := false
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		result := tx.Model(&model.User{}).
			Where("id = ? AND (locale_source = ? OR locale_source = '')", user.ID, model.LocaleSourceUnknown).
			Updates(map[string]any{"locale": locale, "locale_source": model.LocaleSourceBrowser})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			return tx.Select("locale", "locale_source").First(user, user.ID).Error
		}
		user.Locale = locale
		user.LocaleSource = model.LocaleSourceBrowser
		initialized = true
		return s.recordLifecycleEvent(tx, user.ID, "profile.updated", map[string]any{"locale": locale})
	})
	if err != nil {
		return false, err
	}
	if initialized {
		s.audit(c, "profile.locale_initialized", user.ID, "source=browser")
	}
	return initialized, nil
}

func projectedLocale(user *model.User) string {
	if user == nil || user.LocaleSource == "" || user.LocaleSource == model.LocaleSourceUnknown {
		return ""
	}
	locale, ok := supportedLocale(user.Locale)
	if !ok {
		return ""
	}
	return locale
}
