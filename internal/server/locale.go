package server

import "strings"

// requestLocale prefers an explicit choice and otherwise uses the browser's
// language header when a new account is created.
func requestLocale(requested, acceptLanguage string) string {
	if locale, ok := supportedLocale(requested); ok {
		return locale
	}
	for _, part := range strings.Split(acceptLanguage, ",") {
		candidate := strings.TrimSpace(strings.SplitN(part, ";", 2)[0])
		if locale, ok := supportedLocale(candidate); ok {
			return locale
		}
	}
	return "en"
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
