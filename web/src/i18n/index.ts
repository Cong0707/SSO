import translations from "./translations.json";

export const LANGUAGE_OPTIONS = [
  { code: "zhCN", label: "简体中文" },
  { code: "en", label: "English" },
  { code: "fr", label: "Français" },
  { code: "ru", label: "Русский" },
  { code: "ja", label: "日本語" },
  { code: "vi", label: "Tiếng Việt" },
  { code: "zhTW", label: "繁體中文" },
] as const;

export type LocaleCode = (typeof LANGUAGE_OPTIONS)[number]["code"];
type Translation = Record<LocaleCode, string>;

const resources = translations as Record<string, Translation>;
const dynamicResources: Record<string, Translation> = {
  "重新发送（{{seconds}}s）": {
    zhCN: "重新发送（{{seconds}}s）",
    en: "Resend ({{seconds}}s)",
    fr: "Renvoyer ({{seconds}} s)",
    ru: "Отправить снова ({{seconds}} с)",
    ja: "再送信（{{seconds}}秒）",
    vi: "Gửi lại ({{seconds}} giây)",
    zhTW: "重新傳送（{{seconds}}秒）",
  },
  "确认解绑 {{provider}} {{identifier}}？": {
    zhCN: "确认解绑 {{provider}} {{identifier}}？",
    en: "Disconnect {{provider}} {{identifier}}?",
    fr: "Dissocier {{provider}} {{identifier}} ?",
    ru: "Отвязать {{provider}} {{identifier}}?",
    ja: "{{provider}} {{identifier}} の連携を解除しますか？",
    vi: "Ngắt kết nối {{provider}} {{identifier}}?",
    zhTW: "確認解除連結 {{provider}} {{identifier}}？",
  },
  "用户 {{username}} 已更新": {
    zhCN: "用户 {{username}} 已更新",
    en: "User {{username}} updated",
    fr: "Utilisateur {{username}} mis à jour",
    ru: "Пользователь {{username}} обновлён",
    ja: "ユーザー {{username}} を更新しました",
    vi: "Đã cập nhật người dùng {{username}}",
    zhTW: "使用者 {{username}} 已更新",
  },
  "确认重置 {{username}} 的 MFA？": {
    zhCN: "确认重置 {{username}} 的 MFA？",
    en: "Reset MFA for {{username}}?",
    fr: "Réinitialiser la MFA de {{username}} ?",
    ru: "Сбросить MFA для {{username}}?",
    ja: "{{username}} の MFA をリセットしますか？",
    vi: "Đặt lại MFA cho {{username}}?",
    zhTW: "確認重設 {{username}} 的 MFA？",
  },
  "选择 {{username}}": {
    zhCN: "选择 {{username}}",
    en: "Select {{username}}",
    fr: "Sélectionner {{username}}",
    ru: "Выбрать {{username}}",
    ja: "{{username}} を選択",
    vi: "Chọn {{username}}",
    zhTW: "選擇 {{username}}",
  },
  "已选择 {{count}} 个": {
    zhCN: "已选择 {{count}} 个",
    en: "{{count}} selected",
    fr: "{{count}} sélectionné(s)",
    ru: "Выбрано: {{count}}",
    ja: "{{count}} 件選択済み",
    vi: "Đã chọn {{count}}",
    zhTW: "已選擇 {{count}} 個",
  },
  "{{provider}} 已保存": {
    zhCN: "{{provider}} 已保存",
    en: "{{provider}} saved",
    fr: "{{provider}} enregistré",
    ru: "{{provider}} сохранён",
    ja: "{{provider}} を保存しました",
    vi: "Đã lưu {{provider}}",
    zhTW: "{{provider}} 已儲存",
  },
  "{{provider}} 配置可用": {
    zhCN: "{{provider}} 配置可用",
    en: "{{provider}} configuration is valid",
    fr: "La configuration de {{provider}} est valide",
    ru: "Конфигурация {{provider}} действительна",
    ja: "{{provider}} の設定は有効です",
    vi: "Cấu hình {{provider}} hợp lệ",
    zhTW: "{{provider}} 設定可用",
  },
};
const supported = new Set<string>(LANGUAGE_OPTIONS.map(({ code }) => code));

export function normalizeLocale(value?: string | null): LocaleCode {
  if (!value) return "en";
  const normalized = value.trim().replaceAll("_", "-").toLowerCase();
  if (
    normalized === "zh-tw" ||
    normalized === "zh-hk" ||
    normalized === "zh-mo" ||
    normalized === "zhtw" ||
    normalized.startsWith("zh-hant")
  ) {
    return "zhTW";
  }
  if (
    normalized === "zh-cn" ||
    normalized === "zhcn" ||
    normalized.startsWith("zh")
  ) {
    return "zhCN";
  }
  const base = normalized.split("-")[0];
  return supported.has(base) ? (base as LocaleCode) : "en";
}

export function toIntlLocale(locale: LocaleCode): string {
  if (locale === "zhCN") return "zh-CN";
  if (locale === "zhTW") return "zh-TW";
  return locale;
}

let activeLocale = normalizeLocale(
  localStorage.getItem("i18nextLng") || navigator.language,
);

export function currentLocale(): LocaleCode {
  return activeLocale;
}

export function setActiveLocale(locale: string): LocaleCode {
  activeLocale = normalizeLocale(locale);
  localStorage.setItem("i18nextLng", activeLocale);
  document.documentElement.lang = toIntlLocale(activeLocale);
  return activeLocale;
}

export function tr(source: string): string {
  if (activeLocale === "zhCN") return source;
  return (
    resources[source]?.[activeLocale] ||
    dynamicResources[source]?.[activeLocale] ||
    source
  );
}

export function trf(
  source: string,
  variables: Record<string, string | number>,
): string {
  return Object.entries(variables).reduce(
    (value, [key, replacement]) =>
      value.replaceAll(`{{${key}}}`, String(replacement)),
    tr(source),
  );
}

setActiveLocale(activeLocale);
