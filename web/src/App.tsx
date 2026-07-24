import * as React from "react";
import { FormEvent, ReactNode, useCallback, useEffect, useState } from "react";
import { QRCodeSVG } from "qrcode.react";
import {
  Link,
  Navigate,
  useLocation,
  useNavigate,
  useSearchParams,
} from "react-router-dom";
import {
  Activity,
  AppWindow,
  ArrowLeft,
  ArrowRight,
  BadgeCheck,
  Check,
  ChevronDown,
  Clipboard,
  Copy,
  Github,
  Globe2,
  KeyRound,
  Languages,
  LayoutDashboard,
  Link2,
  LogOut,
  MessageCircle,
  Mail,
  Moon,
  Pencil,
  Plus,
  RefreshCw,
  RotateCcw,
  Search,
  Send,
  Settings2,
  Shield,
  ShieldCheck,
  Smartphone,
  Trash2,
  UserCircle2,
  Users,
  X,
} from "lucide-react";
import { api, apiForm, setCsrf } from "./lib/api";
import { BotProtectionChallenge, CaptchaConfig } from "./BotProtection";
import {
  currentLocale,
  LANGUAGE_OPTIONS,
  LocaleCode,
  normalizeLocale,
  setActiveLocale,
  toIntlLocale,
  tr,
  trf,
} from "./i18n";
type User = {
  id: number;
  username: string;
  display_name: string;
  avatar_url: string;
  locale: string;
  mfa_enabled: boolean;
  password_configured: boolean;
  security_email_enabled: boolean;
  created_at: string;
  last_login_at?: string;
  role: "user" | "admin";
  status: "active" | "deactivated" | "merged";
  bindings?: UserBinding[];
};
type UserBinding = {
  kind: string;
  display_name: string;
  identifier: string;
  account_name?: string;
  email?: string;
  binding_type: "email" | "upstream";
  binding_id: number;
  verified: boolean;
  created_at: string;
  last_login_at?: string;
};
type AppRecord = {
  id: number;
  name: string;
  description: string;
  homepage: string;
  redirect_uri: string;
  logo_url: string;
  client_id: string;
  public: boolean;
  created_at: string;
};
type Provider = {
  id: number;
  kind: string;
  display_name: string;
  enabled: boolean;
  configured: boolean;
  bound: boolean;
  bot_username?: string;
};
type Toast = {
  message: string;
  tone?: "error" | "success";
};
const copy = {
  zh: {
    dashboard: "仪表盘",
    apps: "我的应用",
    authorizations: "授权日志",
    grants: "已授权应用",
    profile: "个人资料",
    signIn: "登录",
    signUp: "注册",
    logout: "退出登录",
    welcome: "欢迎回来",
    noData: "暂无数据",
    create: "创建应用",
    save: "保存资料",
    cancel: "取消",
    confirm: "确认",
    loading: "加载中…",
    recent: "最近授权",
    appAccess: "应用接入",
    security: "安全状态总览",
    mfa: "二次验证（MFA）",
    sessions: "登录设备",
    pats: "个人访问令牌（PAT）",
    audit: "安全活动",
    danger: "危险操作",
    providers: "上游接入商",
    devices: "活跃设备",
    authorized: "授权",
    revoke: "撤销",
    delete: "删除",
    password: "密码",
    currentPassword: "当前密码",
    newPassword: "新密码",
    email: "邮箱",
    username: "用户名",
    description: "应用描述",
    homepage: "应用主页",
    callback: "回调地址",
    logo: "应用图标",
    appName: "应用名",
    copySecret: "复制密钥",
    copied: "已复制",
    createToken: "创建 token",
    noTokens: "还没有创建任何 token",
    enableMFA: "启用二次验证",
    disableMFA: "停用二次验证",
    sendVerify: "重新发送验证邮件",
    dangerDelete: "注销账户",
    changePassword: "修改密码",
    allDevices: "退出其它设备",
    recentDevices: "设备",
    open: "打开",
    connect: "连接",
    connected: "已连接",
  },
} as const;
function useLocale() {
  const [locale, setLocale] = useState<LocaleCode>(currentLocale);
  const changeLocale = useCallback((value: string) => {
    const normalized = setActiveLocale(value);
    setLocale(normalized);
    return normalized;
  }, []);
  const t = (key: keyof typeof copy.zh) => tr(copy.zh[key]);
  return { locale, changeLocale, t };
}
export function App() {
  const location = useLocation();
  const navigate = useNavigate();
  const i18n = useLocale();
  const [user, setUser] = useState<User | null>(null);
  const [checking, setChecking] = useState(true);
  const [toast, setToast] = useState<Toast | null>(null);
  const [dark, setDark] = useState(
    () => localStorage.getItem("sso_theme") === "dark",
  );
  useEffect(() => {
    document.documentElement.dataset.theme = dark ? "dark" : "light";
    localStorage.setItem("sso_theme", dark ? "dark" : "light");
  }, [dark]);
  useEffect(() => {
    if (
      location.pathname === "/login" ||
      location.pathname === "/register" ||
      location.pathname === "/forgot-password"
    ) {
      setUser(null);
      setChecking(false);
      return;
    }
    api<{
      user: User;
      csrf_token: string;
    }>("/api/auth/me")
      .then((data) => {
        setUser(data.user);
        setCsrf(data.csrf_token);
        i18n.changeLocale(data.user.locale);
      })
      .catch(() => setUser(null))
      .finally(() => setChecking(false));
  }, [i18n.changeLocale, location.pathname]);
  const acceptUser = async (nextUser: User) => {
    setUser(nextUser);
    i18n.changeLocale(nextUser.locale);
  };
  const changeLocale = async (value: string): Promise<LocaleCode> => {
    const previousLocale = i18n.locale;
    const previousUser = user;
    const locale = i18n.changeLocale(value);
    if (!user) return locale;
    setUser({ ...user, locale });
    try {
      const saved = await api<User>("/api/profile", {
        method: "PATCH",
        body: JSON.stringify({ locale }),
      });
      setUser(saved);
      return normalizeLocale(saved.locale);
    } catch (error) {
      i18n.changeLocale(previousLocale);
      if (previousUser) setUser(previousUser);
      show(error instanceof Error ? error.message : tr("保存失败"), "error");
      throw error;
    }
  };
  const show = (message: string, tone?: Toast["tone"]) => {
    setToast({ message, tone });
    window.setTimeout(() => setToast(null), 3200);
  };
  if (
    checking &&
    !["/login", "/register", "/forgot-password"].includes(location.pathname)
  )
    return (
      <div className="loading-screen">
        <strong className="loading-brand">xem SSO</strong>
        <span>{i18n.t("loading")}</span>
      </div>
    );
  if (location.pathname === "/login")
    return (
      <>
        <AuthPage
          mode="login"
          locale={i18n.locale}
          onLocaleChange={changeLocale}
          onUser={acceptUser}
          t={i18n.t}
          show={show}
        />
        <ToastView toast={toast} />
      </>
    );
  if (location.pathname === "/register")
    return (
      <>
        <AuthPage
          mode="register"
          locale={i18n.locale}
          onLocaleChange={changeLocale}
          onUser={acceptUser}
          t={i18n.t}
          show={show}
        />
        <ToastView toast={toast} />
      </>
    );
  if (location.pathname === "/forgot-password")
    return (
      <>
        <ForgotPasswordPage
          locale={i18n.locale}
          onLocaleChange={changeLocale}
          show={show}
        />
        <ToastView toast={toast} />
      </>
    );
  if (location.pathname === "/consent")
    return user ? (
      <>
        <ConsentPage t={i18n.t} show={show} />
        <ToastView toast={toast} />
      </>
    ) : (
      <Navigate
        to={`/login?redirect=${encodeURIComponent(location.pathname + location.search)}`}
        replace
      />
    );
  if (!user)
    return (
      <Navigate
        to={`/login?redirect=${encodeURIComponent(location.pathname + location.search)}`}
        replace
      />
    );
  return (
    <>
      <Shell
        user={user}
        setUser={setUser}
        t={i18n.t}
        dark={dark}
        setDark={setDark}
        show={show}
      >
        <PageRouter
          user={user}
          setUser={setUser}
          t={i18n.t}
          show={show}
          onLocaleChange={changeLocale}
        />
      </Shell>
      <ToastView toast={toast} />
    </>
  );
}
type T = (key: keyof typeof copy.zh) => string;
function Shell(props: {
  user: User;
  setUser: (user: User | null) => void;
  t: T;
  dark: boolean;
  setDark: (value: boolean) => void;
  show: (message: string, tone?: Toast["tone"]) => void;
  children: ReactNode;
}) {
  const navigate = useNavigate();
  const location = useLocation();
  const [menu, setMenu] = useState(false);
  const items = [
    { path: "/dashboard", label: props.t("dashboard"), icon: LayoutDashboard },
    { path: "/apps", label: props.t("apps"), icon: AppWindow },
    {
      path: "/authorizations",
      label: props.t("authorizations"),
      icon: Activity,
    },
    { path: "/grants", label: props.t("grants"), icon: ShieldCheck },
    { path: "/profile", label: props.t("profile"), icon: UserCircle2 },
  ];
  const adminItems =
    props.user.role === "admin"
      ? [
          {
            path: "/admin/users",
            label: tr("用户管理"),
            icon: Users,
          },
          {
            path: "/admin/settings",
            label: tr("系统设置"),
            icon: Settings2,
          },
        ]
      : [];
  const allItems = [...items, ...adminItems];
  async function logout() {
    try {
      await api("/api/auth/logout", { method: "POST" });
      props.setUser(null);
      navigate("/login");
    } catch (error) {
      props.show(
        error instanceof Error ? error.message : tr("退出失败"),
        "error",
      );
    }
  }
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="sidebar-brand">
          <span>xem SSO</span>
        </div>
        <div className="workspace-label">{tr("账号中心")}</div>
        <nav>
          {items.map((item) => {
            const Icon = item.icon;
            return (
              <Link
                key={item.path}
                to={item.path}
                className={`nav-item ${location.pathname.startsWith(item.path) ? "active" : ""}`}
              >
                <Icon size={17} />
                {item.label}
              </Link>
            );
          })}
        </nav>
        {adminItems.length > 0 && (
          <>
            <div className="workspace-label admin-label">{tr("管理")}</div>
            <nav>
              {adminItems.map((item) => {
                const Icon = item.icon;
                return (
                  <Link
                    key={item.path}
                    to={item.path}
                    className={`nav-item ${location.pathname.startsWith(item.path) ? "active" : ""}`}
                  >
                    <Icon size={17} />
                    {item.label}
                  </Link>
                );
              })}
            </nav>
          </>
        )}
      </aside>
      <div className="main-area">
        <header className="topbar">
          <strong className="mobile-brand">xem SSO</strong>
          <div className="top-actions">
            <div className="profile-menu">
              <button
                className="profile-trigger"
                onClick={() => setMenu(!menu)}
              >
                <Avatar user={props.user} small />
                <span>{props.user.display_name || props.user.username}</span>
                <ChevronDown size={14} />
              </button>
              {menu && (
                <div className="popover">
                  <Link to="/profile" onClick={() => setMenu(false)}>
                    <Settings2 size={15} />
                    {props.t("profile")}
                  </Link>
                  <button onClick={() => props.setDark(!props.dark)}>
                    <Moon size={15} />
                    {props.dark ? tr("浅色模式") : tr("深色模式")}
                  </button>
                  <Link to="/profile" onClick={() => setMenu(false)}>
                    <Languages size={15} />
                    {tr("语言")}
                  </Link>
                  <button onClick={logout}>
                    <LogOut size={15} />
                    {props.t("logout")}
                  </button>
                </div>
              )}
            </div>
          </div>
        </header>
        <main className="page-content">{props.children}</main>
      </div>
      <nav className="mobile-bottom-nav" aria-label={tr("主导航")}>
        {allItems.map((item) => {
          const Icon = item.icon;
          return (
            <Link
              key={item.path}
              to={item.path}
              className={
                location.pathname.startsWith(item.path) ? "active" : ""
              }
            >
              <Icon size={17} />
              <span>{item.label}</span>
            </Link>
          );
        })}
      </nav>
    </div>
  );
}
function PageRouter(props: {
  user: User;
  setUser: (user: User) => void;
  t: T;
  show: (message: string, tone?: Toast["tone"]) => void;
  onLocaleChange: (value: string) => Promise<LocaleCode>;
}) {
  const path = window.location.pathname;
  if (path.startsWith("/admin/users"))
    return <AdminUsersPage show={props.show} />;
  if (path.startsWith("/admin/settings"))
    return <AdminSettingsPage show={props.show} />;
  if (path === "/apps") return <AppsPage t={props.t} show={props.show} />;
  if (path === "/apps/new")
    return <AppFormPage t={props.t} show={props.show} />;
  if (path.startsWith("/apps/"))
    return (
      <AppFormPage t={props.t} show={props.show} id={path.split("/")[2]} />
    );
  if (path.startsWith("/authorizations"))
    return <AuthorizationsPage t={props.t} />;
  if (path.startsWith("/grants"))
    return <GrantsPage t={props.t} show={props.show} />;
  if (path.startsWith("/profile"))
    return (
      <ProfilePage
        user={props.user}
        setUser={props.setUser}
        t={props.t}
        show={props.show}
        onLocaleChange={props.onLocaleChange}
      />
    );
  return <DashboardPage user={props.user} t={props.t} show={props.show} />;
}
function Avatar({
  user,
  small = false,
}: {
  user: Pick<User, "display_name" | "username" | "avatar_url">;
  small?: boolean;
}) {
  return user.avatar_url ? (
    <img
      className={`avatar ${small ? "small" : ""}`}
      src={user.avatar_url}
      alt=""
    />
  ) : (
    <span className={`avatar avatar-fallback ${small ? "small" : ""}`}>
      {(user.display_name || user.username || "U").slice(0, 1).toUpperCase()}
    </span>
  );
}
function PageHeader(props: {
  title: string;
  description?: string;
  action?: ReactNode;
}) {
  return (
    <div className="page-header">
      <div>
        <h1>{props.title}</h1>
        {props.description && <p>{props.description}</p>}
      </div>
      {props.action}
    </div>
  );
}
function Panel(props: {
  title?: string;
  description?: string;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`panel ${props.className || ""}`}>
      <div className="panel-header">
        {props.title && (
          <div>
            <h2>{props.title}</h2>
            {props.description && <p>{props.description}</p>}
          </div>
        )}
        {props.action}
      </div>
      {props.children}
    </section>
  );
}
function Modal(props: {
  open: boolean;
  title: string;
  description?: string;
  children: ReactNode;
  footer?: ReactNode;
  onClose: () => void;
  wide?: boolean;
}) {
  if (!props.open) return null;
  return (
    <div
      className="modal-backdrop"
      role="presentation"
      onMouseDown={props.onClose}
    >
      <section
        className={`modal ${props.wide ? "wide" : ""}`}
        role="dialog"
        aria-modal="true"
        aria-label={props.title}
        onMouseDown={(event) => event.stopPropagation()}
      >
        <header className="modal-header">
          <div>
            <h2>{props.title}</h2>
            {props.description && <p>{props.description}</p>}
          </div>
          <button
            className="icon-button"
            onClick={props.onClose}
            aria-label={tr("关闭")}
          >
            <X size={18} />
          </button>
        </header>
        <div className="modal-body">{props.children}</div>
        {props.footer && (
          <footer className="modal-footer">{props.footer}</footer>
        )}
      </section>
    </div>
  );
}
function Button(props: {
  children: ReactNode;
  onClick?: () => void;
  type?: "button" | "submit";
  variant?: "primary" | "secondary" | "danger" | "ghost";
  disabled?: boolean;
  icon?: ReactNode;
  form?: string;
}) {
  return (
    <button
      type={props.type || "button"}
      onClick={props.onClick}
      disabled={props.disabled}
      form={props.form}
      className={`button ${props.variant || "primary"}`}
    >
      {props.icon}
      {props.children}
    </button>
  );
}
function Input(
  props: React.InputHTMLAttributes<HTMLInputElement> & {
    label?: string;
    hint?: string;
  },
) {
  const { label, hint, ...inputProps } = props;
  return (
    <label className="field">
      {label && <span>{label}</span>}
      <input
        {...inputProps}
        autoComplete={
          inputProps.autoComplete ||
          (inputProps.type === "password" ? "off" : undefined)
        }
      />
      {hint && <small>{hint}</small>}
    </label>
  );
}
function Select(
  props: React.SelectHTMLAttributes<HTMLSelectElement> & {
    label?: string;
  },
) {
  const { label, children, ...selectProps } = props;
  return (
    <label className="field">
      {label && <span>{label}</span>}
      <select {...selectProps}>{children}</select>
    </label>
  );
}
function Empty({ text }: { text: string }) {
  return (
    <div className="empty">
      <div className="empty-icon">
        <Search size={18} />
      </div>
      <span>{text}</span>
    </div>
  );
}
function formatDate(value?: string) {
  if (!value) return "—";
  return new Intl.DateTimeFormat(toIntlLocale(currentLocale()), {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}

function safeLocalReturnTo(value: string) {
  const fallback = "/dashboard";
  const candidate = value.trim();
  if (
    !candidate.startsWith("/") ||
    candidate.startsWith("//") ||
    candidate.includes("\\")
  ) {
    return fallback;
  }
  try {
    const parsed = new URL(candidate, window.location.origin);
    if (parsed.origin !== window.location.origin) return fallback;
    return `${parsed.pathname}${parsed.search}${parsed.hash}`;
  } catch {
    return fallback;
  }
}

function AuthPage(props: {
  mode: "login" | "register";
  locale: LocaleCode;
  onLocaleChange: (value: string) => void;
  onUser: (user: User) => Promise<void>;
  t: T;
  show: (message: string, tone?: Toast["tone"]) => void;
}) {
  const [params] = useSearchParams();
  const [step, setStep] = useState<1 | 2 | 3>(1);
  const [flowMode, setFlowMode] = useState<"login" | "register" | null>(null);
  const [flowToken, setFlowToken] = useState("");
  const [email, setEmail] = useState("");
  const [registrationUsername, setRegistrationUsername] = useState("");
  const [captchaToken, setCaptchaToken] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [code, setCode] = useState("");
  const [debugCode, setDebugCode] = useState("");
  const [countdown, setCountdown] = useState(0);
  const [busy, setBusy] = useState(false);
  const [providers, setProviders] = useState<Provider[]>([]);
  const [authConfig, setAuthConfig] = useState<{
    registration_enabled: boolean;
    captcha: CaptchaConfig;
  }>({ registration_enabled: true, captcha: { mode: "none" } });
  useEffect(() => {
    Promise.all([
      fetch("/api/providers", { credentials: "include" }).then((response) =>
        response.json(),
      ),
      fetch("/api/auth/config", { credentials: "include" }).then((response) =>
        response.json(),
      ),
    ])
      .then(([providerData, configData]) => {
        setProviders(providerData.data || []);
        if (configData.data) setAuthConfig(configData.data);
      })
      .catch(() => undefined);
  }, []);
  useEffect(() => {
    if (countdown <= 0) return;
    const timer = window.setInterval(
      () => setCountdown((value) => Math.max(0, value - 1)),
      1000,
    );
    return () => window.clearInterval(timer);
  }, [countdown]);
  const requestedReturnTo = params.get("redirect") || "/dashboard";
  const mergeToken = params.get("merge_token") || "";
  const visibleProviders = providers.filter(
    (provider) => provider.enabled && provider.configured,
  );
  async function identifyAccount(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    try {
      const data = await api<{
        flow_token: string;
        mode: "login" | "register";
      }>("/api/auth/identify", {
        method: "POST",
        body: JSON.stringify({
          identifier: email,
          captcha_token: captchaToken,
          merge_token: mergeToken,
          locale: props.locale,
        }),
      });
      setFlowToken(data.flow_token);
      setFlowMode(data.mode);
      setStep(2);
    } catch (error) {
      props.show(
        error instanceof Error ? error.message : tr("请求失败"),
        "error",
      );
    } finally {
      setBusy(false);
    }
  }
  async function submitCredentials(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    try {
      if (flowMode === "register") {
        const data = await api<{
          debug_code?: string;
          resend_after: number;
        }>("/api/auth/register/prepare", {
          method: "POST",
          body: JSON.stringify({
            flow_token: flowToken,
            password,
            confirm_password: confirmPassword,
            username: registrationUsername,
          }),
        });
        setDebugCode(data.debug_code || "");
        setCountdown(data.resend_after || 60);
        setStep(3);
      } else {
        const data = await api<{
          mfa_required?: boolean;
          user?: User;
          csrf_token?: string;
        }>("/api/auth/login/password", {
          method: "POST",
          body: JSON.stringify({ flow_token: flowToken, password }),
        });
        if (data.mfa_required) {
          setStep(3);
        } else if (data.user && data.csrf_token) {
          await finish(data.user, data.csrf_token);
        }
      }
    } catch (error) {
      props.show(
        error instanceof Error ? error.message : tr("请求失败"),
        "error",
      );
    } finally {
      setBusy(false);
    }
  }
  async function submitVerification(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    try {
      const data = await api<{
        user: User;
        csrf_token: string;
      }>(
        flowMode === "register"
          ? "/api/auth/register/complete"
          : "/api/auth/login/mfa",
        {
          method: "POST",
          body: JSON.stringify({ flow_token: flowToken, code }),
        },
      );
      await finish(data.user, data.csrf_token);
    } catch (error) {
      props.show(
        error instanceof Error ? error.message : tr("验证失败"),
        "error",
      );
    } finally {
      setBusy(false);
    }
  }
  async function finish(user: User, csrf: string) {
    setCsrf(csrf);
    await props.onUser(user);
    window.location.assign(
      mergeToken ? "/profile?merged=1" : safeLocalReturnTo(requestedReturnTo),
    );
  }
  async function resend() {
    if (countdown > 0 || busy) return;
    setBusy(true);
    try {
      const data = await api<{
        debug_code?: string;
        resend_after: number;
      }>("/api/auth/email/resend", {
        method: "POST",
        body: JSON.stringify({ flow_token: flowToken }),
      });
      setDebugCode(data.debug_code || "");
      setCountdown(data.resend_after || 60);
      props.show(tr("验证码已重新发送"), "success");
    } catch (error) {
      props.show(
        error instanceof Error ? error.message : tr("发送失败"),
        "error",
      );
    } finally {
      setBusy(false);
    }
  }
  function back() {
    if (step === 3 && flowMode === "register") {
      setCode("");
      setStep(2);
      return;
    }
    setStep(1);
    setFlowMode(null);
    setFlowToken("");
    setRegistrationUsername("");
    setPassword("");
    setConfirmPassword("");
    setCode("");
    setCaptchaToken("");
  }
  const title = mergeToken
    ? tr("登录要合并的账号")
    : step === 1
      ? tr("登录或注册")
      : flowMode === "register"
        ? step === 2
          ? tr("创建账号")
          : tr("验证邮箱")
        : step === 2
          ? tr("输入密码")
          : tr("二次验证");
  return (
    <div className="auth-layout">
      <div className="auth-brand">
        <span>xem SSO</span>
      </div>
      <label className="auth-language">
        <Languages size={16} />
        <select
          aria-label={tr("语言")}
          value={props.locale}
          onChange={(event) => props.onLocaleChange(event.target.value)}
        >
          {LANGUAGE_OPTIONS.map((language) => (
            <option key={language.code} value={language.code}>
              {language.label}
            </option>
          ))}
        </select>
      </label>
      <div className="auth-card">
        <div className="eyebrow">xem SSO</div>
        <div className="auth-steps" aria-label={tr("认证进度")}>
          {[1, 2, 3].map((value) => (
            <span key={value} className={step >= value ? "active" : ""} />
          ))}
        </div>
        <h1>{title}</h1>
        <p className="auth-lead">
          {mergeToken
            ? tr("请使用另一个账号完成验证。")
            : tr("使用一个账号访问你的应用、授权和安全设置。")}
        </p>
        {step === 1 && (
          <form onSubmit={identifyAccount} className="form-stack">
            <Input
              label={tr("邮箱或用户名")}
              type="text"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              autoComplete="username"
              required
            />
            <BotProtectionChallenge
              config={authConfig.captcha}
              locale={toIntlLocale(props.locale)}
              onVerify={setCaptchaToken}
              onExpire={() => setCaptchaToken("")}
            />
            <Button
              type="submit"
              disabled={
                busy || (authConfig.captcha.mode !== "none" && !captchaToken)
              }
              icon={
                busy ? (
                  <RefreshCw size={16} className="spin" />
                ) : (
                  <ArrowRight size={16} />
                )
              }
            >
              {tr("下一步")}
            </Button>
          </form>
        )}
        {step === 2 && (
          <form onSubmit={submitCredentials} className="form-stack">
            <input
              className="visually-hidden"
              value={email}
              autoComplete="username"
              readOnly
              tabIndex={-1}
              aria-hidden="true"
            />
            {flowMode === "register" && (
              <Input
                label={tr("用户名")}
                value={registrationUsername}
                onChange={(event) =>
                  setRegistrationUsername(event.target.value)
                }
                autoComplete="username"
                hint={tr("3-32 位字母、数字、下划线或连字符")}
                required
              />
            )}
            <Input
              label={tr("密码")}
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              autoComplete={
                flowMode === "login" ? "current-password" : "new-password"
              }
              required
              hint={
                flowMode === "register"
                  ? tr("至少 8 位，同时包含字母和数字")
                  : undefined
              }
            />
            {flowMode === "login" && !mergeToken && (
              <Link
                className="auth-inline-link"
                to={`/forgot-password?email=${encodeURIComponent(email)}`}
              >
                {tr("忘记密码")}
              </Link>
            )}
            {flowMode === "register" && (
              <Input
                label={tr("确认密码")}
                type="password"
                value={confirmPassword}
                onChange={(event) => setConfirmPassword(event.target.value)}
                autoComplete="new-password"
                required
              />
            )}
            <div className="auth-actions">
              <Button
                variant="ghost"
                onClick={back}
                icon={<ArrowLeft size={16} />}
              >
                {tr("返回")}
              </Button>
              <Button
                type="submit"
                disabled={busy}
                icon={<ArrowRight size={16} />}
              >
                {tr("下一步")}
              </Button>
            </div>
          </form>
        )}
        {step === 3 && (
          <form onSubmit={submitVerification} className="form-stack">
            <Input
              label={
                flowMode === "register" ? tr("邮箱验证码") : tr("2FA 验证码")
              }
              value={code}
              onChange={(event) => setCode(event.target.value)}
              inputMode="numeric"
              autoComplete="one-time-code"
              required
            />
            {debugCode && (
              <div className="debug-code">
                {tr("本地调试验证码：")}
                <code>{debugCode}</code>
              </div>
            )}
            <div className="auth-actions">
              <Button
                variant="ghost"
                onClick={back}
                icon={<ArrowLeft size={16} />}
              >
                {tr("返回")}
              </Button>
              {flowMode === "register" && (
                <Button
                  variant="secondary"
                  onClick={resend}
                  disabled={countdown > 0 || busy}
                >
                  {countdown > 0
                    ? trf("重新发送（{{seconds}}s）", { seconds: countdown })
                    : tr("重新发送")}
                </Button>
              )}
              <Button
                type="submit"
                disabled={busy}
                icon={<ArrowRight size={16} />}
              >
                {tr("完成")}
              </Button>
            </div>
          </form>
        )}
        {step === 1 && visibleProviders.length > 0 && (
          <div className="auth-providers">
            <div className="divider">
              <span>{tr("第三方登录 / 注册")}</span>
            </div>
            <div className="provider-grid">
              {visibleProviders.map((provider) =>
                provider.kind === "telegram" && provider.bot_username ? (
                  <TelegramLoginButton
                    key={provider.kind}
                    provider={provider}
                    mergeToken={mergeToken}
                    locale={props.locale}
                    onSuccess={finish}
                    onError={(message) => props.show(message, "error")}
                  />
                ) : (
                  <a
                    className="provider-button"
                    key={provider.kind}
                    href={`/oauth/upstream/${provider.kind}/start?return_to=${encodeURIComponent(requestedReturnTo)}&locale=${encodeURIComponent(props.locale)}${mergeToken ? `&merge_token=${encodeURIComponent(mergeToken)}` : ""}`}
                  >
                    <ProviderIcon kind={provider.kind} />
                    <span>{provider.display_name}</span>
                    <small>{tr("登录 / 注册")}</small>
                  </a>
                ),
              )}
            </div>
          </div>
        )}
        {!authConfig.registration_enabled && step === 1 && (
          <div className="auth-switch">{tr("当前仅允许已有账号登录")}</div>
        )}
      </div>
      <div className="auth-footer">xem SSO · OAuth 2.0 / OpenID Connect</div>
    </div>
  );
}
function ForgotPasswordPage(props: {
  locale: LocaleCode;
  onLocaleChange: (value: string) => void;
  show: (message: string, tone?: Toast["tone"]) => void;
}) {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const [step, setStep] = useState<1 | 2>(1);
  const [email, setEmail] = useState(params.get("email") || "");
  const [flowToken, setFlowToken] = useState("");
  const [code, setCode] = useState("");
  const [debugCode, setDebugCode] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [captchaToken, setCaptchaToken] = useState("");
  const [busy, setBusy] = useState(false);
  const [authConfig, setAuthConfig] = useState<{
    captcha: CaptchaConfig;
  }>({ captcha: { mode: "none" } });

  useEffect(() => {
    fetch("/api/auth/config", { credentials: "include" })
      .then((response) => response.json())
      .then((payload) => {
        if (payload.data) setAuthConfig(payload.data);
      })
      .catch(() => undefined);
  }, []);

  async function prepare(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    try {
      const data = await api<{
        flow_token: string;
        debug_code?: string;
      }>("/api/auth/password-reset/prepare", {
        method: "POST",
        body: JSON.stringify({
          email,
          captcha_token: captchaToken,
          locale: props.locale,
        }),
      });
      setFlowToken(data.flow_token);
      setDebugCode(data.debug_code || "");
      setStep(2);
      props.show(
        tr("验证码已发送。如果该邮箱对应可用账号，请检查收件箱。"),
        "success",
      );
    } catch (error) {
      props.show(
        error instanceof Error ? error.message : tr("发送失败"),
        "error",
      );
    } finally {
      setBusy(false);
    }
  }

  async function complete(event: FormEvent) {
    event.preventDefault();
    if (newPassword !== confirmPassword) {
      props.show(tr("两次输入的密码不一致"), "error");
      return;
    }
    setBusy(true);
    try {
      await api("/api/auth/password-reset/complete", {
        method: "POST",
        body: JSON.stringify({
          flow_token: flowToken,
          code,
          new_password: newPassword,
          confirm_password: confirmPassword,
        }),
      });
      props.show(tr("密码已重置，请重新登录。"), "success");
      navigate(`/login?email=${encodeURIComponent(email)}`);
    } catch (error) {
      props.show(
        error instanceof Error ? error.message : tr("重置密码失败"),
        "error",
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="auth-layout">
      <div className="auth-brand">
        <span>xem SSO</span>
      </div>
      <label className="auth-language">
        <Languages size={16} />
        <select
          aria-label={tr("语言")}
          value={props.locale}
          onChange={(event) => props.onLocaleChange(event.target.value)}
        >
          {LANGUAGE_OPTIONS.map((language) => (
            <option key={language.code} value={language.code}>
              {language.label}
            </option>
          ))}
        </select>
      </label>
      <div className="auth-card">
        <div className="eyebrow">xem SSO</div>
        <div className="auth-steps" aria-label={tr("认证进度")}>
          {[1, 2].map((value) => (
            <span key={value} className={step >= value ? "active" : ""} />
          ))}
        </div>
        <h1>{tr("重置密码")}</h1>
        <p className="auth-lead">
          {tr("输入绑定邮箱，我们会发送一次性验证码。")}
        </p>
        {step === 1 ? (
          <form onSubmit={prepare} className="form-stack">
            <Input
              label={tr("邮箱")}
              type="email"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              autoComplete="email"
              required
            />
            <BotProtectionChallenge
              config={authConfig.captcha}
              locale={toIntlLocale(props.locale)}
              onVerify={setCaptchaToken}
              onExpire={() => setCaptchaToken("")}
            />
            <div className="auth-actions">
              <Button
                variant="ghost"
                onClick={() => navigate("/login")}
                icon={<ArrowLeft size={16} />}
              >
                {tr("返回登录")}
              </Button>
              <Button
                type="submit"
                disabled={
                  busy || (authConfig.captcha.mode !== "none" && !captchaToken)
                }
                icon={<Mail size={16} />}
              >
                {tr("发送重置验证码")}
              </Button>
            </div>
          </form>
        ) : (
          <form onSubmit={complete} className="form-stack">
            <Input
              label={tr("密码重置验证码")}
              value={code}
              onChange={(event) => setCode(event.target.value)}
              inputMode="numeric"
              autoComplete="one-time-code"
              required
            />
            {debugCode && (
              <div className="debug-code">
                {tr("本地调试验证码：")}
                <code>{debugCode}</code>
              </div>
            )}
            <Input
              label={tr("新密码")}
              type="password"
              value={newPassword}
              onChange={(event) => setNewPassword(event.target.value)}
              autoComplete="new-password"
              hint={tr("至少 8 位，同时包含字母和数字")}
              required
            />
            <Input
              label={tr("确认新密码")}
              type="password"
              value={confirmPassword}
              onChange={(event) => setConfirmPassword(event.target.value)}
              autoComplete="new-password"
              required
            />
            <div className="auth-actions">
              <Button
                variant="ghost"
                onClick={() => {
                  setStep(1);
                  setCode("");
                  setDebugCode("");
                }}
                icon={<ArrowLeft size={16} />}
              >
                {tr("返回")}
              </Button>
              <Button
                type="submit"
                disabled={busy}
                icon={<KeyRound size={16} />}
              >
                {tr("设置新密码")}
              </Button>
            </div>
          </form>
        )}
      </div>
      <div className="auth-footer">xem SSO · OAuth 2.0 / OpenID Connect</div>
    </div>
  );
}
declare global {
  interface Window {
    XemSSOTelegramAuth?: (user: Record<string, unknown>) => void;
  }
}
function TelegramLoginButton(props: {
  provider: Provider;
  mergeToken: string;
  locale: LocaleCode;
  onSuccess: (user: User, csrf: string) => void;
  onError: (message: string) => void;
}) {
  const host = React.useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    const container = host.current;
    if (!container || !props.provider.bot_username) return;
    window.XemSSOTelegramAuth = async (telegramUser) => {
      try {
        const data = await api<{
          user: User;
          csrf_token: string;
        }>("/api/auth/telegram", {
          method: "POST",
          body: JSON.stringify({
            ...telegramUser,
            merge_token: props.mergeToken,
            locale: props.locale,
          }),
        });
        props.onSuccess(data.user, data.csrf_token);
      } catch (error) {
        props.onError(
          error instanceof Error ? error.message : tr("Telegram 登录失败"),
        );
      }
    };
    container.replaceChildren();
    const script = document.createElement("script");
    script.src = "https://telegram.org/js/telegram-widget.js?22";
    script.async = true;
    script.setAttribute("data-telegram-login", props.provider.bot_username);
    script.setAttribute("data-size", "large");
    script.setAttribute("data-radius", "6");
    script.setAttribute("data-request-access", "write");
    script.setAttribute("data-onauth", "XemSSOTelegramAuth(user)");
    container.appendChild(script);
    return () => {
      script.remove();
      delete window.XemSSOTelegramAuth;
    };
  }, [props.locale, props.mergeToken, props.provider.bot_username]);
  return (
    <div className="provider-button telegram-provider" ref={host}>
      <ProviderIcon kind="telegram" />
      <span>{props.provider.display_name}</span>
    </div>
  );
}
function ProviderIcon({ kind }: { kind: string }) {
  if (kind === "email") return <Mail size={17} />;
  if (kind === "github") return <Github size={17} />;
  if (kind === "discord") return <Users size={17} />;
  if (kind === "linuxdo") return <Globe2 size={17} />;
  if (kind === "telegram") return <Send size={17} />;
  if (kind === "wechat") return <MessageCircle size={17} />;
  return <Shield size={17} />;
}
function DashboardPage({
  user,
  t,
  show,
}: {
  user: User;
  t: T;
  show: (message: string, tone?: Toast["tone"]) => void;
}) {
  const [data, setData] = useState<{
    apps: number;
    authorizations: number;
    devices: number;
    providers: number;
    recent_authorizations: Array<{
      id: number;
      app: AppRecord;
      scopes: string;
      created_at: string;
      status: string;
    }>;
  } | null>(null);
  useEffect(() => {
    api<typeof data>("/api/dashboard")
      .then(setData)
      .catch((error) => show(error.message, "error"));
  }, []);
  return (
    <>
      <PageHeader
        title={t("dashboard")}
        description={tr("管理应用接入与账号安全。")}
        action={
          <Link className="button primary" to="/apps/new">
            <Plus size={16} />
            {t("create")}
          </Link>
        }
      />
      <div className="stat-grid">
        <Stat icon={<AppWindow />} label={t("apps")} value={data?.apps ?? 0} />
        <Stat
          icon={<Activity />}
          label={tr("总授权次数")}
          value={data?.authorizations ?? 0}
        />
        <Stat
          icon={<KeyRound />}
          label={t("devices")}
          value={data?.devices ?? 0}
        />
        <Stat
          icon={<Globe2 />}
          label={t("providers")}
          value={data?.providers ?? 0}
        />
      </div>
      <div className="content-grid">
        <Panel
          title={t("recent")}
          description={tr("最近发生的 OAuth 授权活动")}
          className="wide-panel"
        >
          <Table
            headers={[tr("应用"), tr("用户"), "Scope", tr("时间"), tr("状态")]}
            rows={
              data?.recent_authorizations?.map((item) => [
                <strong key="app">{item.app?.name || tr("应用")}</strong>,
                <strong key="user">{user.username}</strong>,
                <code key="scope">{item.scopes || "openid"}</code>,
                formatDate(item.created_at),
                <Badge
                  key="status"
                  tone={item.status === "approved" ? "success" : "muted"}
                >
                  {item.status === "approved" ? tr("已允许") : item.status}
                </Badge>,
              ]) || []
            }
            empty={t("noData")}
          />
        </Panel>
        <Panel
          title={t("appAccess")}
          description={tr("管理 OAuth2 / OIDC 应用")}
        >
          <div className="quick-access">
            <Link to="/apps/new">
              <Plus size={17} />
              <span>{tr("申请接入")}</span>
              <ArrowRight size={16} />
            </Link>
            <Link to="/profile">
              <ShieldCheck size={17} />
              <span>{tr("检查账号安全")}</span>
              <ArrowRight size={16} />
            </Link>
          </div>
        </Panel>
      </div>
    </>
  );
}
function Stat({
  icon,
  label,
  value,
}: {
  icon: ReactNode;
  label: string;
  value: number;
}) {
  return (
    <div className="stat">
      <div className="stat-icon">{icon}</div>
      <div>
        <span>{label}</span>
        <strong>{value}</strong>
      </div>
    </div>
  );
}
function Badge({
  children,
  tone = "muted",
}: {
  children: ReactNode;
  tone?: "success" | "warning" | "muted";
}) {
  return <span className={`badge ${tone}`}>{children}</span>;
}
function Table({
  headers,
  rows,
  empty,
}: {
  headers: string[];
  rows: ReactNode[][];
  empty: string;
}) {
  if (rows.length === 0) return <Empty text={empty} />;
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            {headers.map((header) => (
              <th key={header}>{header}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, index) => (
            <tr key={index}>
              {row.map((cell, cellIndex) => (
                <td key={cellIndex}>{cell}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
function AppsPage({
  t,
  show,
}: {
  t: T;
  show: (message: string, tone?: Toast["tone"]) => void;
}) {
  const navigate = useNavigate();
  const [apps, setApps] = useState<AppRecord[]>([]);
  const load = () =>
    api<AppRecord[]>("/api/apps")
      .then(setApps)
      .catch((error) => show(error.message, "error"));
  useEffect(() => {
    void load();
  }, []);
  async function remove(id: number) {
    if (!window.confirm(tr("确认删除这个应用？"))) return;
    try {
      await api(`/api/apps/${id}`, { method: "DELETE" });
      show(tr("应用已删除"), "success");
      void load();
    } catch (error) {
      show(error instanceof Error ? error.message : tr("删除失败"), "error");
    }
  }
  return (
    <>
      <PageHeader
        title={t("apps")}
        description={tr("管理 OAuth2 / OIDC 应用")}
        action={
          <Button
            onClick={() => navigate("/apps/new")}
            icon={<Plus size={16} />}
          >
            {t("create")}
          </Button>
        }
      />
      <Panel>
        <Table
          headers={[
            t("appName"),
            t("description"),
            "Client ID",
            t("callback"),
            tr("创建时间"),
            tr("操作"),
          ]}
          rows={apps.map((app) => [
            <div className="app-cell" key="name">
              {app.logo_url ? (
                <img src={app.logo_url} alt="" />
              ) : (
                <span className="app-dot" />
              )}
              <strong>{app.name}</strong>
            </div>,
            app.description || "—",
            <code key="client">{app.client_id}</code>,
            <code key="redirect">{app.redirect_uri}</code>,
            formatDate(app.created_at),
            <span key="actions" className="row-actions">
              <Button
                variant="ghost"
                onClick={() => navigate(`/apps/${app.id}`)}
                icon={<Settings2 size={15} />}
              >
                {tr("编辑")}
              </Button>
              <Button
                variant="ghost"
                onClick={() => remove(app.id)}
                icon={<Trash2 size={15} />}
              >
                {t("delete")}
              </Button>
            </span>,
          ])}
          empty={t("noData")}
        />
      </Panel>
    </>
  );
}
function AppFormPage({
  t,
  show,
  id,
}: {
  t: T;
  show: (message: string, tone?: Toast["tone"]) => void;
  id?: string;
}) {
  const navigate = useNavigate();
  const [form, setForm] = useState({
    name: "",
    homepage: "",
    description: "",
    redirect_uri: "",
    logo_url: "",
    public: false,
  });
  const [secret, setSecret] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (id)
      api<AppRecord>(`/api/apps/${id}`)
        .then((data) =>
          setForm({
            name: data.name,
            homepage: data.homepage,
            description: data.description,
            redirect_uri: data.redirect_uri,
            logo_url: data.logo_url,
            public: data.public,
          }),
        )
        .catch((error) => show(error.message, "error"));
  }, [id]);
  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    try {
      const data = await api<{
        app: AppRecord;
        client_secret?: string;
      }>(id ? `/api/apps/${id}` : "/api/apps", {
        method: id ? "PATCH" : "POST",
        body: JSON.stringify(form),
      });
      if (data.client_secret) setSecret(data.client_secret);
      else {
        show(tr("应用已更新"), "success");
        navigate("/apps");
      }
    } catch (error) {
      show(error instanceof Error ? error.message : tr("保存失败"), "error");
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <PageHeader
        title={id ? tr("编辑应用") : tr("创建应用")}
        description={tr("创建一个新的 OAuth2 / OIDC 应用")}
        action={
          <Link className="button secondary" to="/apps">
            <ArrowLeft size={16} />
            {tr("返回应用列表")}
          </Link>
        }
      />
      <Panel className="form-panel">
        <form onSubmit={submit} className="form-stack">
          <Input
            label={t("appName")}
            placeholder="My Application"
            value={form.name}
            onChange={(event) => setForm({ ...form, name: event.target.value })}
            required
          />
          <Input
            label={t("homepage")}
            placeholder="https://example.com"
            value={form.homepage}
            onChange={(event) =>
              setForm({ ...form, homepage: event.target.value })
            }
          />
          <Input
            label={t("description")}
            placeholder={tr("描述你的应用…")}
            value={form.description}
            onChange={(event) =>
              setForm({ ...form, description: event.target.value })
            }
          />
          <Input
            label={t("callback")}
            placeholder="https://example.com/callback"
            value={form.redirect_uri}
            onChange={(event) =>
              setForm({ ...form, redirect_uri: event.target.value })
            }
            required
            hint={tr("OAuth 授权结束后跳转回的地址，务必填写正确")}
          />
          <Input
            label={t("logo")}
            placeholder="https://example.com/logo.png"
            value={form.logo_url}
            onChange={(event) =>
              setForm({ ...form, logo_url: event.target.value })
            }
          />
          <label className="toggle-row">
            <input
              type="checkbox"
              checked={form.public}
              onChange={(event) =>
                setForm({ ...form, public: event.target.checked })
              }
            />
            <span>{tr("公共客户端（必须使用 PKCE）")}</span>
          </label>
          <Button
            type="submit"
            disabled={busy}
            icon={
              busy ? (
                <RefreshCw size={16} className="spin" />
              ) : (
                <Check size={16} />
              )
            }
          >
            {id ? t("save") : t("create")}
          </Button>
        </form>
      </Panel>
      {secret && (
        <Panel
          title={tr("客户端密钥已生成")}
          description={tr("此密钥只会显示一次，请立即复制并妥善保存。")}
          className="secret-panel"
        >
          <div className="secret-value">
            <code>{secret}</code>
            <button
              className="icon-button"
              onClick={() => {
                navigator.clipboard.writeText(secret);
                show(t("copied"), "success");
              }}
              title={t("copySecret")}
            >
              <Copy size={17} />
            </button>
          </div>
          <Link className="button secondary" to="/apps">
            {tr("完成")}
          </Link>
        </Panel>
      )}
    </>
  );
}
function AuthorizationsPage({ t }: { t: T }) {
  const [logs, setLogs] = useState<
    Array<{
      id: number;
      app: AppRecord;
      action: string;
      scopes: string;
      ip: string;
      created_at: string;
      status: string;
    }>
  >([]);
  useEffect(() => {
    api<typeof logs>("/api/authorizations")
      .then(setLogs)
      .catch(() => undefined);
  }, []);
  return (
    <>
      <PageHeader
        title={t("authorizations")}
        description={tr("查看应用授权记录")}
      />
      <Panel>
        <Table
          headers={[tr("应用"), tr("操作"), tr("授权范围"), "IP", tr("时间")]}
          rows={logs.map((item) => [
            <strong key="name">{item.app?.name || "—"}</strong>,
            item.action,
            <code key="scope">{item.scopes || "—"}</code>,
            item.ip || "—",
            formatDate(item.created_at),
          ])}
          empty={t("noData")}
        />
      </Panel>
    </>
  );
}
function GrantsPage({
  t,
  show,
}: {
  t: T;
  show: (message: string, tone?: Toast["tone"]) => void;
}) {
  const [grants, setGrants] = useState<
    Array<{
      id: number;
      app: AppRecord;
      scopes: string;
      created_at: string;
    }>
  >([]);
  const load = () =>
    api<typeof grants>("/api/grants")
      .then(setGrants)
      .catch(() => undefined);
  useEffect(() => {
    void load();
  }, []);
  async function revoke(id: number) {
    try {
      await api(`/api/grants/${id}`, { method: "DELETE" });
      show(tr("授权已撤销"), "success");
      void load();
    } catch (error) {
      show(error instanceof Error ? error.message : tr("撤销失败"), "error");
    }
  }
  return (
    <>
      <PageHeader
        title={t("grants")}
        description={tr("管理你已允许哪些应用调用你的资源 API")}
      />
      <Panel>
        <Table
          headers={[tr("应用"), tr("能力"), tr("授权时间"), tr("操作")]}
          rows={grants.map((item) => [
            <div className="app-cell" key="app">
              {item.app?.logo_url ? (
                <img src={item.app.logo_url} alt="" />
              ) : (
                <span className="app-dot" />
              )}
              {item.app?.name}
            </div>,
            <code key="scope">{item.scopes}</code>,
            formatDate(item.created_at),
            <Button
              key="action"
              variant="ghost"
              onClick={() => revoke(item.id)}
              icon={<Trash2 size={15} />}
            >
              {t("revoke")}
            </Button>,
          ])}
          empty={t("noData")}
        />
      </Panel>
    </>
  );
}
function ConsentPage({
  t,
  show,
}: {
  t: T;
  show: (message: string, tone?: Toast["tone"]) => void;
}) {
  const [params] = useSearchParams();
  const request = params.get("request") || "";
  const [data, setData] = useState<{
    app: {
      name: string;
      description: string;
      logo_url: string;
      homepage: string;
    };
    scopes: string[];
  } | null>(null);
  const navigate = useNavigate();
  useEffect(() => {
    api<typeof data>(
      `/api/oauth/consent?request=${encodeURIComponent(request)}`,
    )
      .then(setData)
      .catch((error) => show(error.message, "error"));
  }, [request]);
  async function decide(approved: boolean) {
    try {
      const result = await api<{
        redirect_url: string;
      }>("/api/oauth/consent", {
        method: "POST",
        body: JSON.stringify({ request, approved }),
      });
      window.location.assign(result.redirect_url);
    } catch (error) {
      show(error instanceof Error ? error.message : tr("操作失败"), "error");
    }
  }
  return (
    <div className="consent-layout">
      <div className="consent-card">
        {data ? (
          <>
            <div className="consent-app">
              <div className="app-logo">
                {data.app.logo_url ? (
                  <img src={data.app.logo_url} alt="" />
                ) : (
                  <Shield size={25} />
                )}
              </div>
              <div>
                <div className="eyebrow">{tr("授权请求")}</div>
                <h1>{data.app.name}</h1>
                <p>
                  {data.app.description ||
                    tr("此应用请求访问你的 xem SSO 账号。")}
                </p>
              </div>
            </div>
            <div className="consent-line">
              <span>{tr("应用主页")}</span>
              <a href={data.app.homepage} target="_blank" rel="noreferrer">
                {data.app.homepage || "—"}
              </a>
            </div>
            <div className="scope-list">
              <h2>{tr("此应用将获得")}</h2>
              {data.scopes.map((scope) => (
                <div className="scope-item" key={scope}>
                  <Check size={16} />
                  <div>
                    <strong>{scope}</strong>
                    <span>
                      {scope === "openid"
                        ? tr("使用你的身份标识登录")
                        : scope === "email"
                          ? tr("读取邮箱和验证状态")
                          : tr("读取基础个人资料")}
                    </span>
                  </div>
                </div>
              ))}
            </div>
            <div className="consent-actions">
              <Button
                variant="secondary"
                onClick={() => decide(false)}
                icon={<X size={16} />}
              >
                {t("cancel")}
              </Button>
              <Button onClick={() => decide(true)} icon={<Check size={16} />}>
                {t("confirm")}
              </Button>
            </div>
          </>
        ) : (
          <div className="skeleton-block">{t("loading")}</div>
        )}
      </div>
      <button className="text-button" onClick={() => navigate("/dashboard")}>
        <ArrowLeft size={14} />
        {tr("返回仪表盘")}
      </button>
    </div>
  );
}
function ProfilePage({
  user,
  setUser,
  t,
  show,
  onLocaleChange,
}: {
  user: User;
  setUser: (user: User) => void;
  t: T;
  show: (message: string, tone?: Toast["tone"]) => void;
  onLocaleChange: (value: string) => Promise<LocaleCode>;
}) {
  const [section, setSection] = useState<
    | "account"
    | "security"
    | "sessions"
    | "tokens"
    | "bindings"
    | "activity"
    | "danger"
  >("account");
  const [modal, setModal] = useState<
    | null
    | "password"
    | "email"
    | "mfa"
    | "mfa-disable"
    | "token"
    | "merge"
    | "delete"
  >(null);
  const [profile, setProfile] = useState(user);
  const [sessions, setSessions] = useState<
    Array<{
      id: number;
      device_name: string;
      ip: string;
      user_agent: string;
      last_seen_at: string;
      created_at: string;
      current: boolean;
    }>
  >([]);
  const [tokens, setTokens] = useState<
    Array<{
      id: number;
      name: string;
      prefix: string;
      scopes: string;
      created_at: string;
    }>
  >([]);
  const [audit, setAudit] = useState<
    Array<{
      id: number;
      action: string;
      ip: string;
      created_at: string;
    }>
  >([]);
  const [providers, setProviders] = useState<Provider[]>([]);
  const [password, setPassword] = useState({
    current_password: "",
    new_password: "",
    confirm_password: "",
  });
  const [mfaSecret, setMfaSecret] = useState<{
    secret: string;
    otpauth_url: string;
  } | null>(null);
  const [backupCodes, setBackupCodes] = useState<string[]>([]);
  const [patName, setPatName] = useState("");
  const [plainPAT, setPlainPAT] = useState("");
  const [newEmail, setNewEmail] = useState("");
  const [emailFlow, setEmailFlow] = useState<{
    token: string;
    debugCode?: string;
  } | null>(null);
  const [emailCode, setEmailCode] = useState("");
  const [mfaDisable, setMfaDisable] = useState({ password: "", code: "" });
  const [deletePassword, setDeletePassword] = useState("");
  const [mergePassword, setMergePassword] = useState("");
  const load = () => {
    api<User>("/api/profile")
      .then((data) => {
        setProfile(data);
        setUser(data);
      })
      .catch(() => undefined);
    api<typeof sessions>("/api/profile/sessions")
      .then(setSessions)
      .catch(() => undefined);
    api<typeof tokens>("/api/profile/tokens")
      .then(setTokens)
      .catch(() => undefined);
    api<typeof audit>("/api/profile/audit")
      .then(setAudit)
      .catch(() => undefined);
    api<Provider[]>("/api/providers")
      .then(setProviders)
      .catch(() => undefined);
  };
  useEffect(() => {
    load();
  }, []);
  async function saveProfile(event: FormEvent) {
    event.preventDefault();
    try {
      const data = await api<User>("/api/profile", {
        method: "PATCH",
        body: JSON.stringify({
          display_name: profile.display_name,
          security_email_enabled: profile.security_email_enabled,
        }),
      });
      setProfile({ ...profile, ...data });
      setUser({ ...profile, ...data });
      show(tr("资料已保存"), "success");
    } catch (error) {
      show(error instanceof Error ? error.message : tr("保存失败"), "error");
    }
  }
  async function changeProfileLocale(value: string) {
    const previousLocale = profile.locale;
    const locale = normalizeLocale(value);
    setProfile((current) => ({ ...current, locale }));
    try {
      await onLocaleChange(locale);
      show(tr("资料已保存"), "success");
    } catch {
      setProfile((current) => ({ ...current, locale: previousLocale }));
    }
  }
  async function prepareEmailBinding(event: FormEvent) {
    event.preventDefault();
    try {
      const verification = await api<{
        flow_token: string;
        debug_code?: string;
      }>("/api/profile/emails/prepare", {
        method: "POST",
        body: JSON.stringify({
          email: newEmail,
        }),
      });
      setEmailFlow({
        token: verification.flow_token,
        debugCode: verification.debug_code,
      });
      show(tr("验证码已发送"), "success");
    } catch (error) {
      show(error instanceof Error ? error.message : tr("发送失败"), "error");
    }
  }
  async function completeEmailChange() {
    if (!emailFlow) return;
    try {
      await api("/api/profile/emails/complete", {
        method: "POST",
        body: JSON.stringify({
          flow_token: emailFlow.token,
          code: emailCode,
        }),
      });
      setEmailFlow(null);
      setEmailCode("");
      setNewEmail("");
      setModal(null);
      show(tr("邮箱已绑定"), "success");
      load();
    } catch (error) {
      show(
        error instanceof Error ? error.message : tr("邮箱验证失败"),
        "error",
      );
    }
  }
  async function changePassword(event: FormEvent) {
    event.preventDefault();
    if (password.new_password !== password.confirm_password) {
      show(tr("两次输入的新密码不一致"), "error");
      return;
    }
    try {
      await api("/api/profile/password", {
        method: "POST",
        body: JSON.stringify(password),
      });
      setPassword({
        current_password: "",
        new_password: "",
        confirm_password: "",
      });
      const updatedProfile = { ...profile, password_configured: true };
      setProfile(updatedProfile);
      setUser(updatedProfile);
      show(tr("密码已修改，其他设备已退出"), "success");
      setModal(null);
      load();
    } catch (error) {
      show(error instanceof Error ? error.message : tr("修改失败"), "error");
    }
  }
  async function setupMFA() {
    try {
      const data = await api<typeof mfaSecret>("/api/profile/mfa/setup", {
        method: "POST",
        body: "{}",
      });
      setMfaSecret(data);
      setBackupCodes([]);
      setModal("mfa");
    } catch (error) {
      show(
        error instanceof Error ? error.message : tr("MFA 设置失败"),
        "error",
      );
    }
  }
  async function enableMFA(event: FormEvent) {
    event.preventDefault();
    const code = new FormData(event.currentTarget as HTMLFormElement).get(
      "code",
    );
    try {
      const data = await api<{
        backup_codes: string[];
      }>("/api/profile/mfa/enable", {
        method: "POST",
        body: JSON.stringify({ code }),
      });
      setBackupCodes(data.backup_codes);
      setMfaSecret(null);
      setProfile({ ...profile, mfa_enabled: true });
      setUser({ ...profile, mfa_enabled: true });
      show(tr("MFA 已启用"), "success");
    } catch (error) {
      show(
        error instanceof Error ? error.message : tr("MFA 验证失败"),
        "error",
      );
    }
  }
  async function disableMFA(event: FormEvent) {
    event.preventDefault();
    try {
      await api("/api/profile/mfa/disable", {
        method: "POST",
        body: JSON.stringify(mfaDisable),
      });
      setMfaDisable({ password: "", code: "" });
      setProfile({ ...profile, mfa_enabled: false });
      setUser({ ...profile, mfa_enabled: false });
      show(tr("MFA 已停用"), "success");
      setModal(null);
    } catch (error) {
      show(error instanceof Error ? error.message : tr("停用失败"), "error");
    }
  }
  async function createPAT(event: FormEvent) {
    event.preventDefault();
    try {
      const data = await api<{
        plain_token: string;
      }>("/api/profile/tokens", {
        method: "POST",
        body: JSON.stringify({ name: patName }),
      });
      setPlainPAT(data.plain_token);
      setPatName("");
      load();
      show(tr("令牌已创建"), "success");
    } catch (error) {
      show(error instanceof Error ? error.message : tr("创建失败"), "error");
    }
  }
  async function revokeSession(id: number) {
    try {
      await api(`/api/profile/sessions/${id}`, { method: "DELETE" });
      load();
    } catch (error) {
      show(error instanceof Error ? error.message : tr("操作失败"), "error");
    }
  }
  async function logoutAll() {
    try {
      await api("/api/auth/logout-all", { method: "POST" });
      show(tr("已退出其它设备"), "success");
      load();
    } catch (error) {
      show(error instanceof Error ? error.message : tr("操作失败"), "error");
    }
  }
  async function uploadAvatar(event: React.ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;
    const form = new FormData();
    form.append("avatar", file);
    try {
      const data = await apiForm<{
        avatar_url: string;
      }>("/api/profile/avatar", form);
      const next = { ...profile, avatar_url: data.avatar_url };
      setProfile(next);
      setUser(next);
      show(tr("头像已更新"), "success");
    } catch (error) {
      show(error instanceof Error ? error.message : tr("上传失败"), "error");
    } finally {
      event.target.value = "";
    }
  }
  async function unlinkBinding(binding: UserBinding) {
    if (
      !window.confirm(
        trf("确认解绑 {{provider}} {{identifier}}？", {
          provider: binding.display_name,
          identifier: binding.identifier,
        }),
      )
    )
      return;
    try {
      await api(
        `/api/profile/bindings/${binding.binding_type}/${binding.binding_id}`,
        { method: "DELETE" },
      );
      show(tr("账号已解绑"), "success");
      load();
    } catch (error) {
      show(error instanceof Error ? error.message : tr("解绑失败"), "error");
    }
  }
  async function deleteAccount(event: FormEvent) {
    event.preventDefault();
    if (!window.confirm(tr("确认注销账户？注销后将无法继续登录。"))) return;
    try {
      await api("/api/profile", {
        method: "DELETE",
        body: JSON.stringify({ password: deletePassword }),
      });
      window.location.assign("/login");
    } catch (error) {
      show(error instanceof Error ? error.message : tr("注销失败"), "error");
    }
  }
  async function startMerge(event: FormEvent) {
    event.preventDefault();
    if (!window.confirm(tr("账号合并完成后不可撤销，是否继续？"))) return;
    try {
      const data = await api<{
        login_url: string;
      }>("/api/profile/merge/start", {
        method: "POST",
        body: JSON.stringify({ password: mergePassword }),
      });
      window.location.assign(data.login_url);
    } catch (error) {
      show(
        error instanceof Error ? error.message : tr("发起合并失败"),
        "error",
      );
    }
  }
  const profileNavigation = [
    { id: "account", label: tr("个人资料"), icon: UserCircle2 },
    {
      id: "security",
      label: tr("账号安全"),
      icon: ShieldCheck,
    },
    { id: "sessions", label: tr("登录设备"), icon: Smartphone },
    { id: "tokens", label: tr("访问令牌"), icon: KeyRound },
    { id: "bindings", label: tr("账号绑定"), icon: Link2 },
    { id: "activity", label: tr("安全活动"), icon: Activity },
    { id: "danger", label: tr("危险操作"), icon: Trash2 },
  ] as const;
  return (
    <>
      <PageHeader
        title={t("profile")}
        description={tr("管理个人资料、登录方式与账号安全")}
      />
      <div className="profile-settings-layout">
        <aside className="profile-settings-nav" aria-label={tr("个人设置")}>
          <div className="profile-nav-account">
            <Avatar user={profile} small />
            <div>
              <strong>{profile.display_name || profile.username}</strong>
              <span>@{profile.username}</span>
            </div>
          </div>
          {profileNavigation.map((item) => {
            const Icon = item.icon;
            return (
              <button
                key={item.id}
                className={section === item.id ? "active" : ""}
                onClick={() => setSection(item.id)}
              >
                <Icon size={16} />
                {item.label}
                <ArrowRight size={14} />
              </button>
            );
          })}
        </aside>
        <section className="profile-settings-content">
          {section === "account" && (
            <>
              <div className="section-heading">
                <div>
                  <h2>{tr("个人资料")}</h2>
                  <p>{tr("更新公开展示信息和界面偏好。")}</p>
                </div>
              </div>
              <form onSubmit={saveProfile} className="settings-form-body">
                <div className="profile-avatar-row">
                  <Avatar user={profile} />
                  <div>
                    <strong>{profile.username}</strong>
                    <span>{tr("JPG、PNG 或 WebP，最大 2MB")}</span>
                    <label className="upload-button">
                      <Clipboard size={14} />
                      {tr("上传头像")}
                      <input
                        type="file"
                        accept="image/jpeg,image/png,image/webp"
                        onChange={uploadAvatar}
                      />
                    </label>
                  </div>
                </div>
                <Input
                  label={tr("用户名")}
                  value={profile.username}
                  disabled
                  hint={tr("用户名由管理员维护")}
                />
                <Input
                  label={tr("显示名称")}
                  value={profile.display_name}
                  onChange={(event) =>
                    setProfile({
                      ...profile,
                      display_name: event.target.value,
                    })
                  }
                />
                <Select
                  label={tr("语言")}
                  value={profile.locale}
                  onChange={(event) =>
                    void changeProfileLocale(event.target.value)
                  }
                >
                  {LANGUAGE_OPTIONS.map((language) => (
                    <option key={language.code} value={language.code}>
                      {language.label}
                    </option>
                  ))}
                </Select>
                <label className="setting-toggle">
                  <div>
                    <strong>{tr("接收安全邮件")}</strong>
                    <span>
                      {tr("密码、MFA、邮箱和异常登录发生变更时发送提醒。")}
                    </span>
                  </div>
                  <input
                    type="checkbox"
                    checked={profile.security_email_enabled}
                    onChange={(event) =>
                      setProfile({
                        ...profile,
                        security_email_enabled: event.target.checked,
                      })
                    }
                  />
                </label>
                <div className="settings-action-bar">
                  <Button type="submit" icon={<Check size={16} />}>
                    {t("save")}
                  </Button>
                </div>
              </form>
            </>
          )}
          {section === "security" && (
            <>
              <div className="section-heading">
                <div>
                  <h2>{tr("账号安全")}</h2>
                  <p>{tr("密码和二次验证分别在独立流程中完成。")}</p>
                </div>
              </div>
              <div className="settings-list">
                <div className="setting-action-row">
                  <div>
                    <strong>{tr("登录密码")}</strong>
                    <span>
                      {profile.password_configured
                        ? tr("已设置，可随时更新")
                        : tr("尚未设置密码")}
                    </span>
                  </div>
                  <Button
                    variant="secondary"
                    onClick={() => setModal("password")}
                    icon={<KeyRound size={15} />}
                  >
                    {profile.password_configured
                      ? tr("修改密码")
                      : tr("设置密码")}
                  </Button>
                </div>
                <div className="setting-action-row">
                  <div>
                    <strong>{tr("二次验证（MFA）")}</strong>
                    <span>
                      {profile.mfa_enabled
                        ? tr("已启用 Authenticator 验证")
                        : tr("未启用，建议配置")}
                    </span>
                  </div>
                  {profile.mfa_enabled ? (
                    <Button
                      variant="danger"
                      onClick={() => setModal("mfa-disable")}
                    >
                      {tr("停用")}
                    </Button>
                  ) : (
                    <Button onClick={setupMFA} icon={<Shield size={15} />}>
                      {tr("启用")}
                    </Button>
                  )}
                </div>
              </div>
            </>
          )}
          {section === "sessions" && (
            <>
              <div className="section-heading">
                <div>
                  <h2>{tr("登录设备")}</h2>
                  <p>{tr("查看当前有效会话并撤销不再使用的设备。")}</p>
                </div>
                <Button
                  variant="secondary"
                  onClick={logoutAll}
                  icon={<LogOut size={15} />}
                >
                  {tr("退出其它设备")}
                </Button>
              </div>
              <Table
                headers={[
                  tr("设备"),
                  "IP",
                  tr("浏览器 / 系统"),
                  tr("最近活跃"),
                  tr("操作"),
                ]}
                rows={sessions.map((session) => [
                  <div key="device">
                    <strong>{session.device_name}</strong>
                    {session.current && (
                      <Badge tone="success">{tr("当前")}</Badge>
                    )}
                  </div>,
                  session.ip,
                  <span className="ua">{session.user_agent}</span>,
                  formatDate(session.last_seen_at),
                  session.current ? (
                    "—"
                  ) : (
                    <Button
                      key="revoke"
                      variant="ghost"
                      onClick={() => revokeSession(session.id)}
                      icon={<X size={14} />}
                    >
                      {tr("撤销")}
                    </Button>
                  ),
                ])}
                empty={tr("暂无有效会话")}
              />
            </>
          )}
          {section === "tokens" && (
            <>
              <div className="section-heading">
                <div>
                  <h2>{tr("个人访问令牌")}</h2>
                  <p>{tr("用于服务端脚本、CI 和自动化的长期 API 凭证。")}</p>
                </div>
                <Button
                  onClick={() => {
                    setPlainPAT("");
                    setModal("token");
                  }}
                  icon={<Plus size={15} />}
                >
                  {tr("创建 token")}
                </Button>
              </div>
              <div className="settings-list">
                {tokens.length ? (
                  tokens.map((token) => (
                    <div className="setting-action-row" key={token.id}>
                      <div>
                        <strong>{token.name}</strong>
                        <span>
                          <code>{token.prefix}</code> · {token.scopes} ·{" "}
                          {formatDate(token.created_at)}
                        </span>
                      </div>
                      <Button
                        variant="danger"
                        onClick={() =>
                          api(`/api/profile/tokens/${token.id}`, {
                            method: "DELETE",
                          }).then(load)
                        }
                        icon={<Trash2 size={14} />}
                      >
                        {tr("撤销")}
                      </Button>
                    </div>
                  ))
                ) : (
                  <Empty text={tr("还没有创建任何 token")} />
                )}
              </div>
            </>
          )}
          {section === "bindings" && (
            <>
              <div className="section-heading">
                <div>
                  <h2>{tr("账号绑定")}</h2>
                </div>
                <Button
                  variant="secondary"
                  onClick={() => setModal("email")}
                  icon={<Mail size={15} />}
                >
                  {tr("绑定邮箱")}
                </Button>
              </div>
              <div className="binding-list unified">
                {profile.bindings?.map((binding) => (
                  <div
                    className="binding-record"
                    key={`${binding.binding_type}-${binding.binding_id}`}
                  >
                    <ProviderIcon kind={binding.kind} />
                    <div>
                      <strong>
                        {binding.display_name} <code>{binding.identifier}</code>
                      </strong>
                      {(binding.account_name || binding.email) && (
                        <span>{binding.account_name || binding.email}</span>
                      )}
                    </div>
                    <div className="binding-badges">
                      <Badge tone="success">{tr("已验证")}</Badge>
                      <button
                        type="button"
                        className="icon-button danger-icon"
                        onClick={() => unlinkBinding(binding)}
                        title={tr("解绑")}
                      >
                        <Trash2 size={14} />
                      </button>
                    </div>
                  </div>
                ))}
                {!profile.bindings?.length && (
                  <Empty text={tr("暂无账号绑定")} />
                )}
              </div>
              <div className="section-heading binding-connect-heading">
                <div>
                  <h2>{tr("添加第三方账号")}</h2>
                </div>
              </div>
              <div className="settings-list">
                {providers.map((provider) => (
                  <div className="setting-action-row" key={provider.kind}>
                    <div className="provider-title">
                      <ProviderIcon kind={provider.kind} />
                      <div>
                        <strong>{provider.display_name}</strong>
                        <span>
                          {provider.bound
                            ? tr("已有绑定，可继续绑定另一个账号")
                            : tr("尚未绑定")}
                        </span>
                      </div>
                    </div>
                    <a
                      className="button secondary"
                      href={`/oauth/upstream/${provider.kind}/start?return_to=/profile`}
                    >
                      {provider.bound ? tr("继续绑定") : tr("连接")}
                    </a>
                  </div>
                ))}
              </div>
            </>
          )}
          {section === "activity" && (
            <>
              <div className="section-heading">
                <div>
                  <h2>{tr("安全活动")}</h2>
                  <p>{tr("最近 100 条账号安全事件。")}</p>
                </div>
              </div>
              <Table
                headers={[tr("时间"), tr("动作"), "IP"]}
                rows={audit.map((event) => [
                  formatDate(event.created_at),
                  event.action,
                  event.ip || "—",
                ])}
                empty={tr("暂无安全活动")}
              />
            </>
          )}
          {section === "danger" && (
            <>
              <div className="section-heading">
                <div>
                  <h2>{tr("危险操作")}</h2>
                  <p>{tr("这些操作会改变账号归属或登录状态。")}</p>
                </div>
              </div>
              <div className="settings-list danger-settings">
                <div className="setting-action-row">
                  <div>
                    <strong>{tr("导出我的数据")}</strong>
                    <span>{tr("下载平台保存的全部账号数据（JSON）。")}</span>
                  </div>
                  <a className="button secondary" href="/api/profile/export">
                    <Clipboard size={15} />
                    {tr("导出")}
                  </a>
                </div>
                <div className="setting-action-row">
                  <div>
                    <strong>{tr("合并账号")}</strong>
                    <span>{tr("将另一个账号与当前账号合并。")}</span>
                  </div>
                  <Button
                    variant="secondary"
                    onClick={() => setModal("merge")}
                    icon={<Link2 size={15} />}
                  >
                    {tr("合并账号")}
                  </Button>
                </div>
                <div className="setting-action-row">
                  <div>
                    <strong>{tr("注销账户")}</strong>
                    <span>{tr("注销后将无法继续登录。")}</span>
                  </div>
                  <Button
                    variant="danger"
                    onClick={() => setModal("delete")}
                    icon={<Trash2 size={15} />}
                  >
                    {tr("注销账户")}
                  </Button>
                </div>
              </div>
            </>
          )}
        </section>
      </div>

      <Modal
        open={modal === "password"}
        title={profile.password_configured ? tr("修改密码") : tr("设置密码")}
        description={tr("修改后其它设备上的会话将被撤销。")}
        onClose={() => setModal(null)}
      >
        <form onSubmit={changePassword} className="form-stack">
          {profile.password_configured && (
            <Input
              label={tr("当前密码")}
              type="password"
              value={password.current_password}
              onChange={(event) =>
                setPassword({
                  ...password,
                  current_password: event.target.value,
                })
              }
              autoComplete="current-password"
              required
            />
          )}
          <Input
            label={tr("新密码")}
            type="password"
            value={password.new_password}
            onChange={(event) =>
              setPassword({ ...password, new_password: event.target.value })
            }
            hint={tr("至少 8 位，且同时包含字母和数字")}
            autoComplete="new-password"
            required
          />
          <Input
            label={tr("确认新密码")}
            type="password"
            value={password.confirm_password}
            onChange={(event) =>
              setPassword({
                ...password,
                confirm_password: event.target.value,
              })
            }
            autoComplete="new-password"
            required
          />
          <div className="modal-form-actions">
            <Button variant="secondary" onClick={() => setModal(null)}>
              {tr("取消")}
            </Button>
            <Button type="submit">{tr("确认修改")}</Button>
          </div>
        </form>
      </Modal>
      <Modal
        open={modal === "email"}
        title={tr("绑定邮箱")}
        description={tr("验证码将发送到新邮箱。")}
        onClose={() => {
          setModal(null);
          setNewEmail("");
          setEmailCode("");
          setEmailFlow(null);
        }}
      >
        {!emailFlow ? (
          <form onSubmit={prepareEmailBinding} className="form-stack">
            <Input
              label={tr("邮箱")}
              type="email"
              value={newEmail}
              onChange={(event) => setNewEmail(event.target.value)}
              autoComplete="email"
              required
            />
            <div className="modal-form-actions">
              <Button variant="secondary" onClick={() => setModal(null)}>
                {tr("取消")}
              </Button>
              <Button type="submit">{tr("发送验证码")}</Button>
            </div>
          </form>
        ) : (
          <div className="form-stack">
            <Input
              label={tr("邮箱验证码")}
              value={emailCode}
              onChange={(event) => setEmailCode(event.target.value)}
              inputMode="numeric"
              autoComplete="one-time-code"
              required
            />
            {emailFlow.debugCode && (
              <div className="debug-code">
                {tr("本地调试验证码：")}
                <code>{emailFlow.debugCode}</code>
              </div>
            )}
            <div className="modal-form-actions">
              <Button variant="secondary" onClick={() => setEmailFlow(null)}>
                {tr("返回")}
              </Button>
              <Button onClick={completeEmailChange}>{tr("验证并绑定")}</Button>
            </div>
          </div>
        )}
      </Modal>
      <Modal
        open={modal === "mfa"}
        title={tr("启用二次验证")}
        description={
          backupCodes.length
            ? tr("请立即保存备用码。")
            : tr("使用 Authenticator App 扫描二维码并验证。")
        }
        onClose={() => {
          setModal(null);
          setMfaSecret(null);
          setBackupCodes([]);
        }}
      >
        {mfaSecret && (
          <form onSubmit={enableMFA} className="form-stack">
            <div className="mfa-qr">
              <QRCodeSVG value={mfaSecret.otpauth_url} size={208} />
            </div>
            <div className="manual-secret">
              <span>{tr("无法扫码？手动输入密钥")}</span>
              <code>{mfaSecret.secret}</code>
              <button
                type="button"
                className="icon-button"
                onClick={() => navigator.clipboard.writeText(mfaSecret.secret)}
                title={tr("复制密钥")}
              >
                <Copy size={15} />
              </button>
            </div>
            <Input
              name="code"
              label={tr("Authenticator 验证码")}
              inputMode="numeric"
              autoComplete="one-time-code"
              maxLength={6}
              required
            />
            <div className="modal-form-actions">
              <Button variant="secondary" onClick={() => setModal(null)}>
                {tr("取消")}
              </Button>
              <Button type="submit">{tr("验证并启用")}</Button>
            </div>
          </form>
        )}
        {backupCodes.length > 0 && (
          <div className="form-stack">
            <div className="backup-code-grid">
              {backupCodes.map((code) => (
                <code key={code}>{code}</code>
              ))}
            </div>
            <div className="notice warning">
              {tr("每个备用码只能使用一次，请存放在安全位置。")}
            </div>
            <div className="modal-form-actions">
              <Button
                variant="secondary"
                onClick={() =>
                  navigator.clipboard.writeText(backupCodes.join("\n"))
                }
                icon={<Copy size={15} />}
              >
                {tr("复制全部")}
              </Button>
              <Button
                onClick={() => {
                  setModal(null);
                  setBackupCodes([]);
                }}
              >
                {tr("完成")}
              </Button>
            </div>
          </div>
        )}
      </Modal>
      <Modal
        open={modal === "mfa-disable"}
        title={tr("停用二次验证")}
        description={tr("确认后将删除当前 MFA 密钥和所有备用码。")}
        onClose={() => setModal(null)}
      >
        <form onSubmit={disableMFA} className="form-stack">
          {profile.password_configured && (
            <Input
              label={tr("当前密码")}
              type="password"
              value={mfaDisable.password}
              onChange={(event) =>
                setMfaDisable({ ...mfaDisable, password: event.target.value })
              }
              required
            />
          )}
          <Input
            label={tr("MFA 验证码或备用码")}
            value={mfaDisable.code}
            onChange={(event) =>
              setMfaDisable({ ...mfaDisable, code: event.target.value })
            }
            required
          />
          <div className="modal-form-actions">
            <Button variant="secondary" onClick={() => setModal(null)}>
              {tr("取消")}
            </Button>
            <Button type="submit" variant="danger">
              {tr("确认停用")}
            </Button>
          </div>
        </form>
      </Modal>
      <Modal
        open={modal === "token"}
        title={tr("创建个人访问令牌")}
        description={tr("令牌只会完整显示一次。")}
        onClose={() => {
          setModal(null);
          setPlainPAT("");
        }}
      >
        <form onSubmit={createPAT} className="form-stack">
          <Input
            label={tr("令牌名称")}
            value={patName}
            onChange={(event) => setPatName(event.target.value)}
            placeholder={tr("例如：CI deployment")}
            required
          />
          {plainPAT && (
            <div className="secret-value">
              <code>{plainPAT}</code>
              <button
                type="button"
                className="icon-button"
                onClick={() => navigator.clipboard.writeText(plainPAT)}
              >
                <Copy size={16} />
              </button>
            </div>
          )}
          <div className="modal-form-actions">
            <Button variant="secondary" onClick={() => setModal(null)}>
              {tr("关闭")}
            </Button>
            {!plainPAT && <Button type="submit">{tr("创建 token")}</Button>}
          </div>
        </form>
      </Modal>
      <Modal
        open={modal === "merge"}
        title={tr("合并账号")}
        description={tr("账号合并完成后不可撤销。")}
        onClose={() => setModal(null)}
      >
        <form onSubmit={startMerge} className="form-stack">
          {profile.password_configured && (
            <Input
              label={tr("当前密码")}
              type="password"
              value={mergePassword}
              onChange={(event) => setMergePassword(event.target.value)}
              required
            />
          )}
          <div className="modal-form-actions">
            <Button variant="secondary" onClick={() => setModal(null)}>
              {tr("取消")}
            </Button>
            <Button type="submit">{tr("继续验证另一个账号")}</Button>
          </div>
        </form>
      </Modal>
      <Modal
        open={modal === "delete"}
        title={tr("注销账户")}
        description={tr("注销后将无法继续登录。")}
        onClose={() => setModal(null)}
      >
        <form onSubmit={deleteAccount} className="form-stack">
          {profile.password_configured && (
            <Input
              label={tr("当前密码")}
              type="password"
              value={deletePassword}
              onChange={(event) => setDeletePassword(event.target.value)}
              required
            />
          )}
          <div className="modal-form-actions">
            <Button variant="secondary" onClick={() => setModal(null)}>
              {tr("取消")}
            </Button>
            <Button type="submit" variant="danger">
              {tr("确认注销")}
            </Button>
          </div>
        </form>
      </Modal>
    </>
  );
}
type AdminUser = User & {
  email_count: number;
  identity_count: number;
  binding_count: number;
  deactivated_at?: string;
  merged_into_user_id?: number;
  password?: string;
};
function AdminUsersPage({
  show,
}: {
  show: (message: string, tone?: Toast["tone"]) => void;
}) {
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState("all");
  const [role, setRole] = useState("all");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [sort, setSort] = useState("id");
  const [order, setOrder] = useState<"asc" | "desc">("asc");
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [total, setTotal] = useState(0);
  const [selected, setSelected] = useState<AdminUser | null>(null);
  const [checked, setChecked] = useState<number[]>([]);
  const [loading, setLoading] = useState(false);
  const loadUsers = async (nextPage = page) => {
    setLoading(true);
    try {
      const data = await api<{
        items: AdminUser[];
        total: number;
      }>(
        `/api/admin/users?q=${encodeURIComponent(query)}&status=${status}&role=${role}&page=${nextPage}&page_size=${pageSize}&sort=${sort}&order=${order}`,
      );
      setUsers(data.items);
      setTotal(data.total);
      setChecked([]);
    } catch (error) {
      show(
        error instanceof Error ? error.message : tr("读取用户失败"),
        "error",
      );
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => {
    loadUsers();
  }, [page, pageSize, sort, order, status, role]);
  function changeSort(column: string) {
    if (sort === column) setOrder(order === "asc" ? "desc" : "asc");
    else {
      setSort(column);
      setOrder("asc");
    }
    setPage(1);
  }
  async function openUser(id: number) {
    try {
      const data = await api<AdminUser>(`/api/admin/users/${id}`);
      setSelected({
        ...data,
        bindings: data.bindings || [],
        password: "",
      });
    } catch (error) {
      show(
        error instanceof Error ? error.message : tr("读取用户失败"),
        "error",
      );
    }
  }
  async function saveUser(event: FormEvent) {
    event.preventDefault();
    if (!selected) return;
    try {
      await api(`/api/admin/users/${selected.id}`, {
        method: "PATCH",
        body: JSON.stringify({
          username: selected.username,
          display_name: selected.display_name,
          password: selected.password || "",
          role: selected.role,
          status: selected.status,
        }),
      });
      show(
        trf("用户 {{username}} 已更新", { username: selected.username }),
        "success",
      );
      await loadUsers();
      await openUser(selected.id);
    } catch (error) {
      show(error instanceof Error ? error.message : tr("保存失败"), "error");
    }
  }
  async function deleteBinding(binding: UserBinding) {
    if (
      !window.confirm(
        trf("确认解绑 {{provider}} {{identifier}}？", {
          provider: binding.display_name,
          identifier: binding.identifier,
        }),
      )
    )
      return;
    try {
      await api(
        `/api/admin/bindings/${binding.binding_type}/${binding.binding_id}`,
        { method: "DELETE" },
      );
      show(tr("绑定已删除"), "success");
      if (selected) await openUser(selected.id);
      await loadUsers();
    } catch (error) {
      show(error instanceof Error ? error.message : tr("删除失败"), "error");
    }
  }
  async function resetMFA() {
    if (
      !selected ||
      !window.confirm(
        trf("确认重置 {{username}} 的 MFA？", {
          username: selected.username,
        }),
      )
    )
      return;
    try {
      await api(`/api/admin/users/${selected.id}/mfa`, { method: "DELETE" });
      show(tr("MFA 已重置"), "success");
      await openUser(selected.id);
    } catch (error) {
      show(error instanceof Error ? error.message : tr("重置失败"), "error");
    }
  }
  const pageCount = Math.max(1, Math.ceil(total / pageSize));
  const toggleAll = () =>
    setChecked(
      checked.length === users.length ? [] : users.map((item) => item.id),
    );
  const toggleOne = (id: number) =>
    setChecked((items) =>
      items.includes(id) ? items.filter((item) => item !== id) : [...items, id],
    );
  const statusLabel = (value: User["status"]) =>
    value === "active"
      ? tr("已启用")
      : value === "merged"
        ? tr("已合并")
        : tr("已注销");
  const SortHeader = ({
    column,
    children,
  }: {
    column: string;
    children: ReactNode;
  }) => (
    <button className="sort-header" onClick={() => changeSort(column)}>
      {children}
      <ChevronDown size={13} className={sort === column ? order : ""} />
    </button>
  );
  return (
    <>
      <PageHeader
        title={tr("用户管理")}
        description={tr("管理账号状态、权限和全部登录身份绑定。")}
      />
      <div className="data-table-shell">
        <div className="data-table-toolbar">
          <div className="table-search">
            <Search size={15} />
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter") {
                  setPage(1);
                  loadUsers(1);
                }
              }}
              placeholder={tr("按用户名、显示名称或邮箱筛选...")}
            />
          </div>
          <Select
            value={status}
            onChange={(event) => {
              setPage(1);
              setStatus(event.target.value);
            }}
            aria-label={tr("状态")}
          >
            <option value="all">{tr("全部状态")}</option>
            <option value="active">{tr("已启用")}</option>
            <option value="deactivated">{tr("已注销")}</option>
            <option value="merged">{tr("已合并")}</option>
          </Select>
          <Select
            value={role}
            onChange={(event) => {
              setPage(1);
              setRole(event.target.value);
            }}
            aria-label={tr("角色")}
          >
            <option value="all">{tr("全部角色")}</option>
            <option value="user">{tr("用户")}</option>
            <option value="admin">{tr("管理员")}</option>
          </Select>
          <Button
            variant="secondary"
            onClick={() => {
              setPage(1);
              loadUsers(1);
            }}
            icon={<Search size={15} />}
          >
            {tr("查询")}
          </Button>
        </div>
        <div className="table-wrap admin-table-wrap">
          <table className="admin-users-table">
            <thead>
              <tr>
                <th>
                  <input
                    type="checkbox"
                    checked={
                      users.length > 0 && checked.length === users.length
                    }
                    onChange={toggleAll}
                    aria-label={tr("选择本页全部用户")}
                  />
                </th>
                <th>
                  <SortHeader column="id">ID</SortHeader>
                </th>
                <th>
                  <SortHeader column="username">{tr("用户名")}</SortHeader>
                </th>
                <th>
                  <SortHeader column="status">{tr("状态")}</SortHeader>
                </th>
                <th>{tr("绑定")}</th>
                <th>
                  <SortHeader column="role">{tr("角色")}</SortHeader>
                </th>
                <th>
                  <SortHeader column="created_at">{tr("创建时间")}</SortHeader>
                </th>
                <th>
                  <SortHeader column="last_login_at">
                    {tr("最后登录")}
                  </SortHeader>
                </th>
                <th>{tr("操作")}</th>
              </tr>
            </thead>
            <tbody>
              {users.map((item) => (
                <tr
                  key={item.id}
                  className={item.status !== "active" ? "disabled-row" : ""}
                >
                  <td>
                    <input
                      type="checkbox"
                      checked={checked.includes(item.id)}
                      onChange={() => toggleOne(item.id)}
                      aria-label={trf("选择 {{username}}", {
                        username: item.username,
                      })}
                    />
                  </td>
                  <td>
                    <code>{item.id}</code>
                  </td>
                  <td>
                    <div className="admin-user-cell">
                      <Avatar user={item} small />
                      <div>
                        <strong>{item.username}</strong>
                        {item.display_name &&
                          item.display_name !== item.username && (
                            <span>{item.display_name}</span>
                          )}
                      </div>
                    </div>
                  </td>
                  <td>
                    <Badge
                      tone={item.status === "active" ? "success" : "muted"}
                    >
                      {statusLabel(item.status)}
                    </Badge>
                  </td>
                  <td>
                    <div className="binding-count">
                      <strong>{item.binding_count}</strong>
                      <span>
                        {item.email_count}
                        {" " + (tr("邮箱 ·") + " ")}
                        {item.identity_count}
                        {tr("第三方")}
                      </span>
                    </div>
                  </td>
                  <td>
                    {item.role === "admin" ? (
                      <>
                        <Shield size={14} />
                        {tr("管理员")}
                      </>
                    ) : (
                      <>
                        <UserCircle2 size={14} />
                        {tr("用户")}
                      </>
                    )}
                  </td>
                  <td>{formatDate(item.created_at)}</td>
                  <td>{formatDate(item.last_login_at)}</td>
                  <td>
                    <div className="row-actions">
                      <button
                        className="icon-button"
                        onClick={() => openUser(item.id)}
                        title={tr("编辑用户")}
                      >
                        <Pencil size={15} />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {!users.length && (
            <Empty
              text={loading ? tr("正在加载用户...") : tr("没有匹配的用户")}
            />
          )}
        </div>
        <div className="data-table-footer">
          <span>
            {tr("共")}
            {total}
            {tr("个用户")}
            {checked.length
              ? ` · ${trf("已选择 {{count}} 个", { count: checked.length })}`
              : ""}
          </span>
          <div>
            <Select
              value={pageSize}
              onChange={(event) => {
                setPage(1);
                setPageSize(Number(event.target.value));
              }}
              aria-label={tr("每页数量")}
            >
              <option value={10}>{tr("10 / 页")}</option>
              <option value={20}>{tr("20 / 页")}</option>
              <option value={50}>{tr("50 / 页")}</option>
            </Select>
            <Button
              variant="secondary"
              disabled={page <= 1}
              onClick={() => setPage(page - 1)}
              icon={<ArrowLeft size={14} />}
            >
              {tr("上一页")}
            </Button>
            <span>
              {page} / {pageCount}
            </span>
            <Button
              variant="secondary"
              disabled={page >= pageCount}
              onClick={() => setPage(page + 1)}
              icon={<ArrowRight size={14} />}
            >
              {tr("下一页")}
            </Button>
          </div>
        </div>
      </div>

      {selected && (
        <div className="drawer-backdrop" onMouseDown={() => setSelected(null)}>
          <aside
            className="side-drawer"
            role="dialog"
            aria-modal="true"
            aria-label={tr("更新用户")}
            onMouseDown={(event) => event.stopPropagation()}
          >
            <header className="side-drawer-header">
              <div>
                <h2>{tr("更新用户")}</h2>
                <p>{tr("通过必要信息更新用户。")}</p>
              </div>
              <button
                className="icon-button"
                onClick={() => setSelected(null)}
                aria-label={tr("关闭")}
              >
                <X size={18} />
              </button>
            </header>
            <form
              id="admin-user-form"
              onSubmit={saveUser}
              className="side-drawer-form"
            >
              <section className="drawer-section">
                <h3>{tr("基本信息")}</h3>
                <Input
                  label={tr("用户名")}
                  value={selected.username}
                  autoComplete="username"
                  onChange={(event) =>
                    setSelected({ ...selected, username: event.target.value })
                  }
                />
                <Input
                  label={tr("显示名称")}
                  value={selected.display_name || ""}
                  onChange={(event) =>
                    setSelected({
                      ...selected,
                      display_name: event.target.value,
                    })
                  }
                  hint={tr("留空以使用用户名")}
                />
                <Input
                  label={tr("密码")}
                  type="password"
                  value={selected.password || ""}
                  onChange={(event) =>
                    setSelected({ ...selected, password: event.target.value })
                  }
                  placeholder={tr("留空以保持不变")}
                  hint={tr("设置后会撤销该用户的全部现有会话")}
                  autoComplete="new-password"
                />
              </section>
              <section className="drawer-section">
                <h3>{tr("权限与状态")}</h3>
                <div className="form-grid-2">
                  <Select
                    label={tr("角色")}
                    value={selected.role}
                    onChange={(event) =>
                      setSelected({
                        ...selected,
                        role: event.target.value as User["role"],
                      })
                    }
                  >
                    <option value="user">{tr("用户")}</option>
                    <option value="admin">{tr("管理员")}</option>
                  </Select>
                  <Select
                    label={tr("状态")}
                    value={selected.status}
                    disabled={selected.status === "merged"}
                    onChange={(event) =>
                      setSelected({
                        ...selected,
                        status: event.target.value as User["status"],
                      })
                    }
                  >
                    <option value="active">{tr("已启用")}</option>
                    <option value="deactivated">{tr("已注销")}</option>
                    <option value="merged">{tr("已合并")}</option>
                  </Select>
                </div>
                <div className="setting-action-row compact">
                  <div>
                    <strong>{tr("二次验证")}</strong>
                    <span>
                      {selected.mfa_enabled ? tr("已启用") : tr("未启用")}
                    </span>
                  </div>
                  {selected.mfa_enabled && (
                    <Button variant="danger" onClick={resetMFA}>
                      {tr("重置 MFA")}
                    </Button>
                  )}
                </div>
              </section>
              <section className="drawer-section">
                <h3>{tr("账号绑定")}</h3>
                <div className="binding-list unified">
                  {selected.bindings?.map((binding) => (
                    <div
                      className="binding-record"
                      key={`${binding.binding_type}-${binding.binding_id}`}
                    >
                      <ProviderIcon kind={binding.kind} />
                      <div>
                        <strong>
                          {binding.display_name}{" "}
                          <code>{binding.identifier}</code>
                        </strong>
                        <span>
                          {[binding.account_name, binding.email]
                            .filter(Boolean)
                            .join(" · ") || "—"}
                        </span>
                      </div>
                      <div className="binding-badges">
                        <Badge tone="success">{tr("已验证")}</Badge>
                        <button
                          type="button"
                          className="icon-button danger-icon"
                          onClick={() => deleteBinding(binding)}
                          title={tr("解绑")}
                        >
                          <Trash2 size={14} />
                        </button>
                      </div>
                    </div>
                  ))}
                  {!selected.bindings?.length && (
                    <Empty text={tr("该用户没有绑定记录")} />
                  )}
                </div>
              </section>
            </form>
            <footer className="side-drawer-footer">
              <Button variant="secondary" onClick={() => setSelected(null)}>
                {tr("关闭")}
              </Button>
              <Button type="submit" form="admin-user-form">
                {tr("保存更改")}
              </Button>
            </footer>
          </aside>
        </div>
      )}
    </>
  );
}
type AdminSettings = {
  registration_enabled: boolean;
  smtp_host: string;
  smtp_port: string;
  smtp_username: string;
  smtp_from: string;
  captcha_mode: "none" | "turnstile" | "cap";
  turnstile_site_key: string;
  cap_site_key: string;
  cap_server_url: string;
  smtp_password_configured: boolean;
  turnstile_secret_configured: boolean;
  cap_secret_configured: boolean;
  email_debug: boolean;
};
type AdminProvider = {
  id: number;
  kind: string;
  display_name: string;
  client_id: string;
  client_secret?: string;
  issuer_url: string;
  authorization_url: string;
  token_url: string;
  user_info_url: string;
  email_info_url: string;
  scopes: string;
  enabled: boolean;
  secret_configured: boolean;
  callback_url: string;
};
function AdminSettingsPage({
  show,
}: {
  show: (message: string, tone?: Toast["tone"]) => void;
}) {
  const [active, setActive] = useState<"basic" | "email" | "oauth" | "bot">(
    "basic",
  );
  const [settings, setSettings] = useState<AdminSettings | null>(null);
  const [secrets, setSecrets] = useState({
    smtp_password: "",
    turnstile_secret_key: "",
    cap_secret_key: "",
  });
  const [testEmail, setTestEmail] = useState("");
  const [providers, setProviders] = useState<AdminProvider[]>([]);
  const [providerIndex, setProviderIndex] = useState(0);
  const load = () => {
    api<AdminSettings>("/api/admin/settings")
      .then(setSettings)
      .catch((error) => show(error.message, "error"));
    api<AdminProvider[]>("/api/admin/providers")
      .then(setProviders)
      .catch((error) => show(error.message, "error"));
  };
  useEffect(load, []);
  async function saveSettings(event: FormEvent) {
    event.preventDefault();
    if (!settings) return;
    const payload: Record<string, string | boolean> = {
      registration_enabled: settings.registration_enabled,
      smtp_host: settings.smtp_host,
      smtp_port: settings.smtp_port,
      smtp_username: settings.smtp_username,
      smtp_from: settings.smtp_from,
      captcha_mode: settings.captcha_mode,
      turnstile_site_key: settings.turnstile_site_key,
      cap_site_key: settings.cap_site_key,
      cap_server_url: settings.cap_server_url,
    };
    Object.entries(secrets).forEach(([key, value]) => {
      if (value) payload[key] = value;
    });
    try {
      await api("/api/admin/settings", {
        method: "PATCH",
        body: JSON.stringify(payload),
      });
      setSecrets({
        smtp_password: "",
        turnstile_secret_key: "",
        cap_secret_key: "",
      });
      show(tr("系统设置已保存"), "success");
      load();
    } catch (error) {
      show(error instanceof Error ? error.message : tr("保存失败"), "error");
    }
  }
  async function sendTestEmail() {
    try {
      await api("/api/admin/settings/email/test", {
        method: "POST",
        body: JSON.stringify({ email: testEmail }),
      });
      show(tr("测试邮件已发送"), "success");
    } catch (error) {
      show(error instanceof Error ? error.message : tr("发送失败"), "error");
    }
  }
  function updateProvider(field: keyof AdminProvider, value: string | boolean) {
    setProviders((items) =>
      items.map((item, index) =>
        index === providerIndex ? { ...item, [field]: value } : item,
      ),
    );
  }
  async function saveProvider(event: FormEvent) {
    event.preventDefault();
    const provider = providers[providerIndex];
    if (!provider) return;
    try {
      await api(`/api/admin/providers/${provider.id}`, {
        method: "PATCH",
        body: JSON.stringify(provider),
      });
      show(
        trf("{{provider}} 已保存", { provider: provider.display_name }),
        "success",
      );
      load();
    } catch (error) {
      show(error instanceof Error ? error.message : tr("保存失败"), "error");
    }
  }
  async function testProvider() {
    const provider = providers[providerIndex];
    if (!provider) return;
    try {
      await api(`/api/admin/providers/${provider.id}/test`, {
        method: "POST",
        body: "{}",
      });
      show(
        trf("{{provider}} 配置可用", { provider: provider.display_name }),
        "success",
      );
    } catch (error) {
      show(error instanceof Error ? error.message : tr("测试失败"), "error");
    }
  }
  if (!settings)
    return (
      <div className="loading-screen">
        <span>{tr("加载设置...")}</span>
      </div>
    );
  const provider = providers[providerIndex];
  const navGroups = [
    {
      label: tr("身份验证"),
      items: [
        {
          id: "basic",
          label: tr("基本身份验证"),
          icon: KeyRound,
        },
        {
          id: "bot",
          label: tr("机器人保护"),
          icon: ShieldCheck,
        },
      ],
    },
    {
      label: tr("第三方服务"),
      items: [
        { id: "email", label: tr("邮件服务"), icon: Send },
        { id: "oauth", label: tr("OAuth 集成"), icon: Link2 },
      ],
    },
  ] as const;
  return (
    <>
      <PageHeader
        title={tr("系统设置")}
        description={tr("配置身份验证与第三方服务。")}
      />
      {settings.email_debug && (
        <div className="notice warning settings-debug-notice">
          {tr("当前启用了邮件调试模式，生产环境必须设置")}{" "}
          <code>SSO_EMAIL_DEBUG=false</code>。
        </div>
      )}
      <div className="system-settings-layout">
        <aside className="system-settings-nav">
          {navGroups.map((group) => (
            <div className="settings-nav-group" key={group.label}>
              <span>{group.label}</span>
              {group.items.map((item) => {
                const Icon = item.icon;
                return (
                  <button
                    key={item.id}
                    className={active === item.id ? "active" : ""}
                    onClick={() => setActive(item.id)}
                  >
                    <Icon size={16} />
                    {item.label}
                    <ArrowRight size={14} />
                  </button>
                );
              })}
            </div>
          ))}
        </aside>
        <section className="system-settings-content">
          {active === "basic" && (
            <form onSubmit={saveSettings}>
              <div className="section-heading">
                <div>
                  <h2>{tr("基本身份验证")}</h2>
                  <p>{tr("控制邮箱、密码和注册流程。")}</p>
                </div>
              </div>
              <div className="settings-form-body">
                <label className="setting-toggle">
                  <div>
                    <strong>{tr("允许新用户注册")}</strong>
                    <span>
                      {tr(
                        "关闭后仍允许已有账号登录以及管理员配置的第三方身份登录。",
                      )}
                    </span>
                  </div>
                  <input
                    type="checkbox"
                    checked={settings.registration_enabled}
                    onChange={(event) =>
                      setSettings({
                        ...settings,
                        registration_enabled: event.target.checked,
                      })
                    }
                  />
                </label>
                <div className="setting-action-row">
                  <div>
                    <strong>{tr("注册邮箱验证")}</strong>
                    <span>
                      {tr("注册流程必须完成邮箱验证码，当前不可关闭。")}
                    </span>
                  </div>
                  <Badge tone="success">{tr("强制启用")}</Badge>
                </div>
                <div className="setting-action-row">
                  <div>
                    <strong>{tr("账号识别")}</strong>
                    <span>
                      {tr(
                        "第一页可使用邮箱或用户名识别账号；新用户使用邮箱注册。",
                      )}
                    </span>
                  </div>
                  <Badge tone="success">{tr("已启用")}</Badge>
                </div>
                <div className="settings-action-bar">
                  <Button type="submit" icon={<Check size={15} />}>
                    {tr("保存更改")}
                  </Button>
                </div>
              </div>
            </form>
          )}
          {active === "email" && (
            <form onSubmit={saveSettings}>
              <div className="section-heading">
                <div>
                  <h2>{tr("邮件服务")}</h2>
                  <p>{tr("用于注册、绑定邮箱和安全提醒。")}</p>
                </div>
              </div>
              <div className="settings-form-body">
                <div className="form-grid-2">
                  <Input
                    label={tr("SMTP 主机")}
                    value={settings.smtp_host}
                    onChange={(event) =>
                      setSettings({
                        ...settings,
                        smtp_host: event.target.value,
                      })
                    }
                  />
                  <Input
                    label={tr("SMTP 端口")}
                    value={settings.smtp_port}
                    onChange={(event) =>
                      setSettings({
                        ...settings,
                        smtp_port: event.target.value,
                      })
                    }
                  />
                  <Input
                    label={tr("SMTP 用户名")}
                    value={settings.smtp_username}
                    onChange={(event) =>
                      setSettings({
                        ...settings,
                        smtp_username: event.target.value,
                      })
                    }
                  />
                  <Input
                    label={tr("SMTP 密码")}
                    type="password"
                    value={secrets.smtp_password}
                    placeholder={
                      settings.smtp_password_configured
                        ? tr("已配置，留空不修改")
                        : tr("请输入密码")
                    }
                    onChange={(event) =>
                      setSecrets({
                        ...secrets,
                        smtp_password: event.target.value,
                      })
                    }
                    autoComplete="new-password"
                  />
                  <Input
                    label={tr("发件人")}
                    value={settings.smtp_from}
                    onChange={(event) =>
                      setSettings({
                        ...settings,
                        smtp_from: event.target.value,
                      })
                    }
                  />
                </div>
                <div className="setting-action-row">
                  <div>
                    <strong>{tr("发送测试邮件")}</strong>
                    <span>{tr("使用当前已保存配置发送测试邮件。")}</span>
                  </div>
                  <div className="inline-control">
                    <input
                      type="email"
                      value={testEmail}
                      onChange={(event) => setTestEmail(event.target.value)}
                      placeholder="admin@example.com"
                    />
                    <Button variant="secondary" onClick={sendTestEmail}>
                      {tr("发送测试")}
                    </Button>
                  </div>
                </div>
                <div className="settings-action-bar">
                  <Button type="submit" icon={<Check size={15} />}>
                    {tr("保存邮件设置")}
                  </Button>
                </div>
              </div>
            </form>
          )}
          {active === "bot" && (
            <form onSubmit={saveSettings}>
              <div className="section-heading">
                <div>
                  <h2>{tr("机器人保护")}</h2>
                  <p>{tr("在登录注册流程第一页验证客户端。")}</p>
                </div>
              </div>
              <div className="settings-form-body">
                <Select
                  label={tr("验证模式")}
                  value={settings.captcha_mode}
                  onChange={(event) =>
                    setSettings({
                      ...settings,
                      captcha_mode: event.target
                        .value as AdminSettings["captcha_mode"],
                    })
                  }
                >
                  <option value="none">{tr("无")}</option>
                  <option value="turnstile">Cloudflare Turnstile</option>
                  <option value="cap">PoW</option>
                </Select>
                {settings.captcha_mode === "turnstile" && (
                  <div className="form-grid-2">
                    <Input
                      label="Site Key"
                      value={settings.turnstile_site_key}
                      onChange={(event) =>
                        setSettings({
                          ...settings,
                          turnstile_site_key: event.target.value,
                        })
                      }
                    />
                    <Input
                      label="Secret Key"
                      type="password"
                      value={secrets.turnstile_secret_key}
                      placeholder={
                        settings.turnstile_secret_configured
                          ? tr("已配置，留空不修改")
                          : tr("请输入 Secret Key")
                      }
                      onChange={(event) =>
                        setSecrets({
                          ...secrets,
                          turnstile_secret_key: event.target.value,
                        })
                      }
                      autoComplete="new-password"
                    />
                  </div>
                )}
                {settings.captcha_mode === "cap" && (
                  <div className="form-grid-2">
                    <Input
                      label={tr("PoW 服务地址")}
                      value={settings.cap_server_url}
                      onChange={(event) =>
                        setSettings({
                          ...settings,
                          cap_server_url: event.target.value,
                        })
                      }
                    />
                    <Input
                      label="Site Key"
                      value={settings.cap_site_key}
                      onChange={(event) =>
                        setSettings({
                          ...settings,
                          cap_site_key: event.target.value,
                        })
                      }
                    />
                    <Input
                      label="Secret Key"
                      type="password"
                      value={secrets.cap_secret_key}
                      placeholder={
                        settings.cap_secret_configured
                          ? tr("已配置，留空不修改")
                          : tr("请输入 Secret Key")
                      }
                      onChange={(event) =>
                        setSecrets({
                          ...secrets,
                          cap_secret_key: event.target.value,
                        })
                      }
                      autoComplete="new-password"
                    />
                  </div>
                )}
                <div className="settings-action-bar">
                  <Button type="submit" icon={<Check size={15} />}>
                    {tr("保存机器人保护设置")}
                  </Button>
                </div>
              </div>
            </form>
          )}
          {active === "oauth" && (
            <>
              <div className="section-heading">
                <div>
                  <h2>{tr("OAuth 集成")}</h2>
                  <p>{tr("配置可用于客户登录和绑定的上游身份提供商。")}</p>
                </div>
              </div>
              {provider ? (
                <div className="oauth-settings-grid">
                  <div className="oauth-provider-list">
                    {providers.map((item, index) => (
                      <button
                        key={item.id}
                        className={providerIndex === index ? "active" : ""}
                        onClick={() => setProviderIndex(index)}
                      >
                        <ProviderIcon kind={item.kind} />
                        <div>
                          <strong>{item.display_name}</strong>
                          <span>
                            {item.enabled
                              ? tr("已启用")
                              : item.secret_configured
                                ? tr("已配置")
                                : tr("未配置")}
                          </span>
                        </div>
                        <Badge tone={item.enabled ? "success" : "muted"}>
                          {item.enabled ? tr("启用") : tr("停用")}
                        </Badge>
                      </button>
                    ))}
                  </div>
                  <form className="oauth-provider-form" onSubmit={saveProvider}>
                    <div className="provider-form-heading">
                      <div>
                        <ProviderIcon kind={provider.kind} />
                        <div>
                          <h3>{provider.display_name}</h3>
                          <span>{provider.kind}</span>
                        </div>
                      </div>
                      <label className="toggle-row compact">
                        <input
                          type="checkbox"
                          checked={provider.enabled}
                          onChange={(event) =>
                            updateProvider("enabled", event.target.checked)
                          }
                        />
                        <span>{tr("启用")}</span>
                      </label>
                    </div>
                    <Input
                      label={tr("显示名称")}
                      value={provider.display_name}
                      onChange={(event) =>
                        updateProvider("display_name", event.target.value)
                      }
                    />
                    <div className="form-grid-2">
                      <Input
                        label="Client ID / App ID"
                        value={provider.client_id}
                        onChange={(event) =>
                          updateProvider("client_id", event.target.value)
                        }
                      />
                      <Input
                        label="Client Secret / Bot Token"
                        type="password"
                        value={provider.client_secret || ""}
                        placeholder={
                          provider.secret_configured
                            ? tr("已配置，留空不修改")
                            : tr("请输入密钥")
                        }
                        onChange={(event) =>
                          updateProvider("client_secret", event.target.value)
                        }
                        autoComplete="new-password"
                      />
                    </div>
                    <Input
                      label="Scopes"
                      value={provider.scopes || ""}
                      onChange={(event) =>
                        updateProvider("scopes", event.target.value)
                      }
                    />
                    <Input
                      label="Issuer URL"
                      value={provider.issuer_url || ""}
                      onChange={(event) =>
                        updateProvider("issuer_url", event.target.value)
                      }
                    />
                    <Input
                      label="Authorization URL"
                      value={provider.authorization_url || ""}
                      onChange={(event) =>
                        updateProvider("authorization_url", event.target.value)
                      }
                    />
                    <Input
                      label="Token URL"
                      value={provider.token_url || ""}
                      onChange={(event) =>
                        updateProvider("token_url", event.target.value)
                      }
                    />
                    <Input
                      label="UserInfo URL"
                      value={provider.user_info_url || ""}
                      onChange={(event) =>
                        updateProvider("user_info_url", event.target.value)
                      }
                    />
                    <Input
                      label="Email API URL"
                      value={provider.email_info_url || ""}
                      onChange={(event) =>
                        updateProvider("email_info_url", event.target.value)
                      }
                    />
                    <Input
                      label={tr("回调地址")}
                      value={provider.callback_url}
                      readOnly
                    />
                    <div className="settings-action-bar">
                      <Button
                        variant="secondary"
                        onClick={testProvider}
                        icon={<Activity size={15} />}
                      >
                        {tr("连接测试")}
                      </Button>
                      <Button type="submit" icon={<Check size={15} />}>
                        {tr("保存 Provider")}
                      </Button>
                    </div>
                  </form>
                </div>
              ) : (
                <Empty text={tr("暂无可配置的 OAuth Provider")} />
              )}
            </>
          )}
        </section>
      </div>
    </>
  );
}
function SecurityItem({
  label,
  status,
  good,
  action,
}: {
  label: string;
  status: string;
  good: boolean;
  action?: ReactNode;
}) {
  return (
    <div className="security-item">
      <div className={`security-dot ${good ? "good" : "warn"}`} />
      <div>
        <strong>{label}</strong>
        <span>{status}</span>
      </div>
      {action}
    </div>
  );
}
function ToastView({ toast }: { toast: Toast | null }) {
  return toast ? (
    <div className={`toast ${toast.tone || ""}`}>
      {toast.tone === "success" ? (
        <Check size={15} />
      ) : toast.tone === "error" ? (
        <X size={15} />
      ) : null}
      {toast.message}
    </div>
  ) : null;
}
