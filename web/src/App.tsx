import * as React from "react";
import { FormEvent, ReactNode, useEffect, useState } from "react";
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
  Bell,
  Check,
  ChevronDown,
  CircleHelp,
  Clipboard,
  Copy,
  Github,
  Globe2,
  KeyRound,
  Languages,
  LayoutDashboard,
  Link2,
  LogOut,
  Menu,
  MessageCircle,
  Moon,
  MoreHorizontal,
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
import {
  BotProtectionChallenge,
  CaptchaConfig,
} from "./BotProtection";

type User = {
  id: number;
  username: string;
  email: string;
  display_name: string;
  avatar_url: string;
  locale: string;
  email_verified: boolean;
  mfa_enabled: boolean;
  password_configured: boolean;
  security_email_enabled: boolean;
  created_at: string;
  last_login_at?: string;
  role: "user" | "admin";
  status: "active" | "deactivated" | "merged";
  emails?: UserEmail[];
  identities?: IdentityBinding[];
};
type UserEmail = {
  id: number;
  email: string;
  primary: boolean;
  verified_at?: string;
  disabled_at?: string;
  original_user_id: number;
};
type IdentityBinding = {
  id: number;
  external_id: string;
  external_name: string;
  external_email: string;
  original_user_id: number;
  disabled_at?: string;
  provider: Provider;
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
type Toast = { message: string; tone?: "error" | "success" };

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
    language: "界面语言",
    chinese: "中文",
    english: "English",
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
    username: "用户名 / 邮箱",
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
  en: {
    dashboard: "Dashboard",
    apps: "My apps",
    authorizations: "Authorization logs",
    grants: "Granted apps",
    profile: "Profile",
    signIn: "Sign in",
    signUp: "Sign up",
    logout: "Sign out",
    welcome: "Welcome back",
    noData: "No data",
    create: "Create app",
    save: "Save profile",
    cancel: "Cancel",
    confirm: "Confirm",
    loading: "Loading…",
    recent: "Recent authorization",
    appAccess: "App access",
    security: "Security overview",
    language: "Language",
    chinese: "中文",
    english: "English",
    mfa: "Two-factor authentication",
    sessions: "Login devices",
    pats: "Personal access tokens",
    audit: "Security activity",
    danger: "Danger zone",
    providers: "Upstream providers",
    devices: "Active devices",
    authorized: "Authorized",
    revoke: "Revoke",
    delete: "Delete",
    password: "Password",
    currentPassword: "Current password",
    newPassword: "New password",
    email: "Email",
    username: "Username / email",
    description: "Description",
    homepage: "Homepage",
    callback: "Callback URL",
    logo: "App icon",
    appName: "Application name",
    copySecret: "Copy secret",
    copied: "Copied",
    createToken: "Create token",
    noTokens: "No tokens yet",
    enableMFA: "Enable MFA",
    disableMFA: "Disable MFA",
    sendVerify: "Resend verification",
    dangerDelete: "Delete account",
    changePassword: "Change password",
    allDevices: "Sign out other devices",
    recentDevices: "Devices",
    open: "Open",
    connect: "Connect",
    connected: "Connected",
  },
} as const;

type Locale = keyof typeof copy;
function useLocale() {
  const [locale, setLocale] = useState<Locale>(
    () => (localStorage.getItem("sso_locale") as Locale) || "zh",
  );
  const t = (key: keyof typeof copy.zh) => copy[locale][key];
  const change = (next: Locale) => {
    localStorage.setItem("sso_locale", next);
    setLocale(next);
  };
  return { locale, t, change };
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
    if (location.pathname === "/login" || location.pathname === "/register") {
      setUser(null);
      setChecking(false);
      return;
    }
    api<{ user: User; csrf_token: string }>("/api/auth/me")
      .then((data) => {
        setUser(data.user);
        setCsrf(data.csrf_token);
      })
      .catch(() => setUser(null))
      .finally(() => setChecking(false));
  }, [location.pathname]);
  const show = (message: string, tone?: Toast["tone"]) => {
    setToast({ message, tone });
    window.setTimeout(() => setToast(null), 3200);
  };
  if (checking && !["/login", "/register"].includes(location.pathname))
    return (
      <div className="loading-screen">
        <div className="brand-mark">ID</div>
        <span>{i18n.t("loading")}</span>
      </div>
    );
  if (location.pathname === "/login")
    return (
      <>
        <AuthPage
          mode="login"
          onUser={setUser}
          t={i18n.t}
          changeLocale={i18n.change}
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
          onUser={setUser}
          t={i18n.t}
          changeLocale={i18n.change}
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
        locale={i18n.locale}
        changeLocale={i18n.change}
        dark={dark}
        setDark={setDark}
        show={show}
      >
        <PageRouter user={user} setUser={setUser} t={i18n.t} show={show} />
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
  locale: Locale;
  changeLocale: (locale: Locale) => void;
  dark: boolean;
  setDark: (value: boolean) => void;
  show: (message: string, tone?: Toast["tone"]) => void;
  children: ReactNode;
}) {
  const navigate = useNavigate();
  const location = useLocation();
  const [mobile, setMobile] = useState(false);
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
          { path: "/admin/users", label: "用户管理", icon: Users },
          { path: "/admin/settings", label: "系统设置", icon: Settings2 },
        ]
      : [];
  const allItems = [...items, ...adminItems];
  async function logout() {
    try {
      await api("/api/auth/logout", { method: "POST" });
      props.setUser(null);
      navigate("/login");
    } catch (error) {
      props.show(error instanceof Error ? error.message : "退出失败", "error");
    }
  }
  return (
    <div className="app-shell">
      <aside className={`sidebar ${mobile ? "mobile-open" : ""}`}>
        <div className="sidebar-brand">
          <span className="brand-mark">ID</span>
          <span>Identity Center</span>
          <button
            className="icon-button mobile-close"
            onClick={() => setMobile(false)}
            aria-label="Close"
          >
            <X size={17} />
          </button>
        </div>
        <div className="workspace-label">ACCOUNT CENTER</div>
        <nav>
          {items.map((item) => {
            const Icon = item.icon;
            return (
              <Link
                key={item.path}
                to={item.path}
                className={`nav-item ${location.pathname.startsWith(item.path) ? "active" : ""}`}
                onClick={() => setMobile(false)}
              >
                <Icon size={17} />
                {item.label}
              </Link>
            );
          })}
        </nav>
        {adminItems.length > 0 && (
          <>
            <div className="workspace-label admin-label">管理</div>
            <nav>
              {adminItems.map((item) => {
                const Icon = item.icon;
                return (
                  <Link
                    key={item.path}
                    to={item.path}
                    className={`nav-item ${location.pathname.startsWith(item.path) ? "active" : ""}`}
                    onClick={() => setMobile(false)}
                  >
                    <Icon size={17} />
                    {item.label}
                  </Link>
                );
              })}
            </nav>
          </>
        )}
        <div className="sidebar-bottom">
          <button
            className="nav-item"
            onClick={() => props.setDark(!props.dark)}
          >
            <Moon size={17} />
            {props.dark ? "Light mode" : "Dark mode"}
          </button>
          <button
            className="nav-item"
            onClick={() =>
              props.changeLocale(props.locale === "zh" ? "en" : "zh")
            }
          >
            <Languages size={17} />
            {props.locale === "zh" ? "English" : "中文"}
          </button>
        </div>
      </aside>
      <div className={`main-area ${mobile ? "drawer-visible" : ""}`}>
        <header className="topbar">
          <button
            className="icon-button mobile-menu"
            onClick={() => setMobile(true)}
            aria-label="Menu"
          >
            <Menu size={20} />
          </button>
          <div className="breadcrumbs">
            <span>Identity Center</span>
            <ArrowRight size={14} />
            <strong>
              {allItems.find((item) => location.pathname.startsWith(item.path))
                ?.label || props.t("dashboard")}
            </strong>
          </div>
          <div className="top-actions">
            <button className="icon-button" title="Help">
              <CircleHelp size={18} />
            </button>
            <button className="icon-button" title="Notifications">
              <Bell size={18} />
            </button>
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
    </div>
  );
}

function PageRouter(props: {
  user: User;
  setUser: (user: User) => void;
  t: T;
  show: (message: string, tone?: Toast["tone"]) => void;
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
      />
    );
  return <DashboardPage t={props.t} show={props.show} />;
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
  eyebrow?: string;
  title: string;
  description?: string;
  action?: ReactNode;
}) {
  return (
    <div className="page-header">
      <div>
        <div className="eyebrow">{props.eyebrow || "IDENTITY CENTER"}</div>
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
function Button(props: {
  children: ReactNode;
  onClick?: () => void;
  type?: "button" | "submit";
  variant?: "primary" | "secondary" | "danger" | "ghost";
  disabled?: boolean;
  icon?: ReactNode;
}) {
  return (
    <button
      type={props.type || "button"}
      onClick={props.onClick}
      disabled={props.disabled}
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
  return (
    <label className="field">
      {props.label && <span>{props.label}</span>}
      <input {...props} />
      {props.hint && <small>{props.hint}</small>}
    </label>
  );
}
function Select(
  props: React.SelectHTMLAttributes<HTMLSelectElement> & { label?: string },
) {
  return (
    <label className="field">
      {props.label && <span>{props.label}</span>}
      <select {...props}>{props.children}</select>
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
  return new Intl.DateTimeFormat("zh-CN", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}

function AuthPage(props: {
  mode: "login" | "register";
  onUser: (user: User) => void;
  t: T;
  changeLocale: (locale: Locale) => void;
  show: (message: string, tone?: Toast["tone"]) => void;
}) {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const [step, setStep] = useState<1 | 2 | 3>(1);
  const [flowMode, setFlowMode] = useState<"login" | "register" | null>(null);
  const [flowToken, setFlowToken] = useState("");
  const [identifier, setIdentifier] = useState("");
  const [captchaToken, setCaptchaToken] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [email, setEmail] = useState("");
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
    (provider) =>
      provider.enabled && provider.configured && provider.kind !== "telegram",
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
          identifier,
          captcha_token: captchaToken,
          merge_token: mergeToken,
        }),
      });
      setFlowToken(data.flow_token);
      setFlowMode(data.mode);
      setStep(2);
    } catch (error) {
      props.show(error instanceof Error ? error.message : "请求失败", "error");
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
            email,
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
          finish(data.user, data.csrf_token);
        }
      }
    } catch (error) {
      props.show(error instanceof Error ? error.message : "请求失败", "error");
    } finally {
      setBusy(false);
    }
  }
  async function submitVerification(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    try {
      const data = await api<{ user: User; csrf_token: string }>(
        flowMode === "register"
          ? "/api/auth/register/complete"
          : "/api/auth/login/mfa",
        {
          method: "POST",
          body: JSON.stringify({ flow_token: flowToken, code }),
        },
      );
      finish(data.user, data.csrf_token);
    } catch (error) {
      props.show(error instanceof Error ? error.message : "验证失败", "error");
    } finally {
      setBusy(false);
    }
  }
  function finish(user: User, csrf: string) {
    setCsrf(csrf);
    props.onUser(user);
    navigate(mergeToken ? "/profile?merged=1" : requestedReturnTo);
  }
  async function resend() {
    if (countdown > 0 || busy) return;
    setBusy(true);
    try {
      const data = await api<{ debug_code?: string; resend_after: number }>(
        "/api/auth/email/resend",
        { method: "POST", body: JSON.stringify({ flow_token: flowToken }) },
      );
      setDebugCode(data.debug_code || "");
      setCountdown(data.resend_after || 60);
      props.show("验证码已重新发送", "success");
    } catch (error) {
      props.show(error instanceof Error ? error.message : "发送失败", "error");
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
    setPassword("");
    setConfirmPassword("");
    setCode("");
    setCaptchaToken("");
  }
  const title = mergeToken
    ? "登录要合并的账号"
    : step === 1
      ? "登录或注册"
      : flowMode === "register"
        ? step === 2
          ? "创建账号"
          : "验证邮箱"
        : step === 2
          ? "输入密码"
          : "二次验证";
  return (
    <div className="auth-layout">
      <div className="auth-brand">
        <span className="brand-mark">ID</span>
        <span>Identity Center</span>
      </div>
      <div className="auth-locale">
        <button onClick={() => props.changeLocale("zh")}>中文</button>
        <span>/</span>
        <button onClick={() => props.changeLocale("en")}>English</button>
      </div>
      <div className="auth-card">
        <div className="eyebrow">IDENTITY CENTER</div>
        <div className="auth-steps" aria-label="认证进度">
          {[1, 2, 3].map((value) => (
            <span key={value} className={step >= value ? "active" : ""} />
          ))}
        </div>
        <h1>{title}</h1>
        <p className="auth-lead">
          {mergeToken
            ? "验证另一个账号后，资料和登录渠道会合并到编号较小的账号。"
            : "使用一个账号访问你的应用、授权和安全设置。"}
        </p>
        {step === 1 && (
          <form onSubmit={identifyAccount} className="form-stack">
            <Input
              label="用户名或邮箱"
              value={identifier}
              onChange={(event) => setIdentifier(event.target.value)}
              autoComplete="username"
              required
            />
            <BotProtectionChallenge
              config={authConfig.captcha}
              onVerify={setCaptchaToken}
              onExpire={() => setCaptchaToken("")}
            />
            <Button
              type="submit"
              disabled={
                busy ||
                (authConfig.captcha.mode !== "none" && !captchaToken)
              }
              icon={busy ? <RefreshCw size={16} className="spin" /> : <ArrowRight size={16} />}
            >
              下一步
            </Button>
          </form>
        )}
        {step === 2 && (
          <form onSubmit={submitCredentials} className="form-stack">
            {flowMode === "register" && (
              <Input
                label="邮箱"
                type="email"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                autoComplete="email"
                required
              />
            )}
            <Input
              label="密码"
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              autoComplete={flowMode === "login" ? "current-password" : "new-password"}
              required
              hint={flowMode === "register" ? "至少 8 位，同时包含字母和数字" : undefined}
            />
            {flowMode === "register" && (
              <Input
                label="确认密码"
                type="password"
                value={confirmPassword}
                onChange={(event) => setConfirmPassword(event.target.value)}
                autoComplete="new-password"
                required
              />
            )}
            <div className="auth-actions">
              <Button variant="ghost" onClick={back} icon={<ArrowLeft size={16} />}>
                返回
              </Button>
              <Button type="submit" disabled={busy} icon={<ArrowRight size={16} />}>
                下一步
              </Button>
            </div>
          </form>
        )}
        {step === 3 && (
          <form onSubmit={submitVerification} className="form-stack">
            <Input
              label={flowMode === "register" ? "邮箱验证码" : "2FA 验证码"}
              value={code}
              onChange={(event) => setCode(event.target.value)}
              inputMode="numeric"
              autoComplete="one-time-code"
              required
            />
            {debugCode && (
              <div className="debug-code">
                本地调试验证码：<code>{debugCode}</code>
              </div>
            )}
            <div className="auth-actions">
              <Button variant="ghost" onClick={back} icon={<ArrowLeft size={16} />}>
                返回
              </Button>
              {flowMode === "register" && (
                <Button variant="secondary" onClick={resend} disabled={countdown > 0 || busy}>
                  {countdown > 0 ? `重新发送（${countdown}s）` : "重新发送"}
                </Button>
              )}
              <Button type="submit" disabled={busy} icon={<ArrowRight size={16} />}>
                完成
              </Button>
            </div>
          </form>
        )}
        {step === 1 && visibleProviders.length > 0 && (
          <div className="auth-providers">
            <div className="divider">
              <span>第三方登录 / 注册</span>
            </div>
            <div className="provider-grid">
              {visibleProviders.map((provider) => (
                provider.kind === "telegram" && provider.bot_username ? (
                  <TelegramLoginButton
                    key={provider.kind}
                    provider={provider}
                    mergeToken={mergeToken}
                    onSuccess={finish}
                    onError={(message) => props.show(message, "error")}
                  />
                ) : (
                  <a
                    className="provider-button"
                    key={provider.kind}
                    href={`/oauth/upstream/${provider.kind}/start?return_to=${encodeURIComponent(requestedReturnTo)}${mergeToken ? `&merge_token=${encodeURIComponent(mergeToken)}` : ""}`}
                  >
                    <ProviderIcon kind={provider.kind} />
                    <span>{provider.display_name}</span>
                    <small>登录 / 注册</small>
                  </a>
                )
              ))}
            </div>
            <p className="provider-hint">
              首次使用会自动创建账号并导入用户名、已验证邮箱和头像，之后可在个人资料中修改。
            </p>
          </div>
        )}
        {!authConfig.registration_enabled && step === 1 && (
          <div className="auth-switch">当前仅允许已有账号登录</div>
        )}
      </div>
      <div className="auth-footer">
        Identity Center · OAuth 2.0 / OpenID Connect
      </div>
    </div>
  );
}

declare global {
  interface Window {
    IdentityCenterTelegramAuth?: (user: Record<string, unknown>) => void;
  }
}

function TelegramLoginButton(props: {
  provider: Provider;
  mergeToken: string;
  onSuccess: (user: User, csrf: string) => void;
  onError: (message: string) => void;
}) {
  const host = React.useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    const container = host.current;
    if (!container || !props.provider.bot_username) return;
    window.IdentityCenterTelegramAuth = async (telegramUser) => {
      try {
        const data = await api<{ user: User; csrf_token: string }>(
          "/api/auth/telegram",
          {
            method: "POST",
            body: JSON.stringify({
              ...telegramUser,
              merge_token: props.mergeToken,
            }),
          },
        );
        props.onSuccess(data.user, data.csrf_token);
      } catch (error) {
        props.onError(error instanceof Error ? error.message : "Telegram 登录失败");
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
    script.setAttribute("data-onauth", "IdentityCenterTelegramAuth(user)");
    container.appendChild(script);
    return () => {
      script.remove();
      delete window.IdentityCenterTelegramAuth;
    };
  }, [props.mergeToken, props.provider.bot_username]);
  return (
    <div className="provider-button telegram-provider" ref={host}>
      <ProviderIcon kind="telegram" />
      <span>{props.provider.display_name}</span>
    </div>
  );
}

function ProviderIcon({ kind }: { kind: string }) {
  if (kind === "github") return <Github size={17} />;
  if (kind === "discord") return <Users size={17} />;
  if (kind === "linuxdo") return <Globe2 size={17} />;
  if (kind === "telegram") return <Send size={17} />;
  if (kind === "wechat") return <MessageCircle size={17} />;
  return <Shield size={17} />;
}

function DashboardPage({
  t,
  show,
}: {
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
        description="统一身份中心，掌握应用接入与账号安全。"
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
          label="总授权次数"
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
          description="最近发生的 OAuth 授权活动"
          className="wide-panel"
        >
          <Table
            headers={["应用", "用户", "Scope", "时间", "状态"]}
            rows={
              data?.recent_authorizations?.map((item) => [
                <strong key="app">{item.app?.name || "应用"}</strong>,
                "你",
                <code key="scope">{item.scopes || "openid"}</code>,
                formatDate(item.created_at),
                <Badge
                  key="status"
                  tone={item.status === "approved" ? "success" : "muted"}
                >
                  {item.status === "approved" ? "已允许" : item.status}
                </Badge>,
              ]) || []
            }
            empty={t("noData")}
          />
        </Panel>
        <Panel title={t("appAccess")} description="管理 OAuth2 / OIDC 应用">
          <div className="quick-access">
            <Link to="/apps/new">
              <Plus size={17} />
              <span>申请接入</span>
              <ArrowRight size={16} />
            </Link>
            <Link to="/profile">
              <ShieldCheck size={17} />
              <span>检查账号安全</span>
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
    if (!window.confirm("确认删除这个应用？")) return;
    try {
      await api(`/api/apps/${id}`, { method: "DELETE" });
      show("应用已删除", "success");
      void load();
    } catch (error) {
      show(error instanceof Error ? error.message : "删除失败", "error");
    }
  }
  return (
    <>
      <PageHeader
        title={t("apps")}
        description="管理 OAuth2 / OIDC 应用"
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
            "创建时间",
            "操作",
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
                编辑
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
      const data = await api<{ app: AppRecord; client_secret?: string }>(
        id ? `/api/apps/${id}` : "/api/apps",
        { method: id ? "PATCH" : "POST", body: JSON.stringify(form) },
      );
      if (data.client_secret) setSecret(data.client_secret);
      else {
        show("应用已更新", "success");
        navigate("/apps");
      }
    } catch (error) {
      show(error instanceof Error ? error.message : "保存失败", "error");
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <PageHeader
        title={id ? "编辑应用" : "创建应用"}
        description="创建一个新的 OAuth2 / OIDC 应用"
        action={
          <Link className="button secondary" to="/apps">
            <ArrowLeft size={16} />
            返回应用列表
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
            placeholder="描述你的应用…"
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
            hint="OAuth 授权结束后跳转回的地址，务必填写正确"
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
            <span>公共客户端（必须使用 PKCE）</span>
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
          title="客户端密钥已生成"
          description="此密钥只会显示一次，请立即复制并妥善保存。"
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
            完成
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
      <PageHeader title={t("authorizations")} description="查看应用授权记录" />
      <Panel>
        <Table
          headers={["应用", "操作", "授权范围", "IP", "时间"]}
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
    Array<{ id: number; app: AppRecord; scopes: string; created_at: string }>
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
      show("授权已撤销", "success");
      void load();
    } catch (error) {
      show(error instanceof Error ? error.message : "撤销失败", "error");
    }
  }
  return (
    <>
      <PageHeader
        title={t("grants")}
        description="管理你已允许哪些应用调用你的资源 API"
      />
      <Panel>
        <Table
          headers={["应用", "能力", "授权时间", "操作"]}
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
      const result = await api<{ redirect_url: string }>("/api/oauth/consent", {
        method: "POST",
        body: JSON.stringify({ request, approved }),
      });
      window.location.assign(result.redirect_url);
    } catch (error) {
      show(error instanceof Error ? error.message : "操作失败", "error");
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
                <div className="eyebrow">授权请求</div>
                <h1>{data.app.name}</h1>
                <p>
                  {data.app.description ||
                    "此应用请求访问你的统一身份中心账号。"}
                </p>
              </div>
            </div>
            <div className="consent-line">
              <span>应用主页</span>
              <a href={data.app.homepage} target="_blank" rel="noreferrer">
                {data.app.homepage || "—"}
              </a>
            </div>
            <div className="scope-list">
              <h2>此应用将获得</h2>
              {data.scopes.map((scope) => (
                <div className="scope-item" key={scope}>
                  <Check size={16} />
                  <div>
                    <strong>{scope}</strong>
                    <span>
                      {scope === "openid"
                        ? "使用你的身份标识登录"
                        : scope === "email"
                          ? "读取邮箱和验证状态"
                          : "读取基础个人资料"}
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
        返回仪表盘
      </button>
    </div>
  );
}

function ProfilePage({
  user,
  setUser,
  t,
  show,
}: {
  user: User;
  setUser: (user: User) => void;
  t: T;
  show: (message: string, tone?: Toast["tone"]) => void;
}) {
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
    Array<{ id: number; action: string; ip: string; created_at: string }>
  >([]);
  const [providers, setProviders] = useState<Provider[]>([]);
  const [password, setPassword] = useState({
    current_password: "",
    new_password: "",
  });
  const [mfaSecret, setMfaSecret] = useState<{
    secret: string;
    otpauth_url: string;
  } | null>(null);
  const [backupCodes, setBackupCodes] = useState<string[]>([]);
  const [patName, setPatName] = useState("");
  const [plainPAT, setPlainPAT] = useState("");
  const [savedEmail, setSavedEmail] = useState(user.email);
  const [emailPassword, setEmailPassword] = useState("");
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
        setSavedEmail(data.email);
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
        body: JSON.stringify({ ...profile, email: savedEmail }),
      });
      if (profile.email !== savedEmail) {
        const verification = await api<{
          flow_token: string;
          debug_code?: string;
        }>("/api/profile/emails/prepare", {
          method: "POST",
          body: JSON.stringify({
            email: profile.email,
            password: emailPassword,
          }),
        });
        setEmailFlow({
          token: verification.flow_token,
          debugCode: verification.debug_code,
        });
        show("验证码已发送到新邮箱", "success");
      } else {
        setProfile({ ...profile, ...data });
        setUser({ ...profile, ...data });
        show("资料已保存", "success");
      }
    } catch (error) {
      show(error instanceof Error ? error.message : "保存失败", "error");
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
      setEmailPassword("");
      show("新邮箱已验证并设为主邮箱", "success");
      load();
    } catch (error) {
      show(error instanceof Error ? error.message : "邮箱验证失败", "error");
    }
  }
  async function changePassword(event: FormEvent) {
    event.preventDefault();
    try {
      await api("/api/profile/password", {
        method: "POST",
        body: JSON.stringify(password),
      });
      setPassword({ current_password: "", new_password: "" });
      const updatedProfile = { ...profile, password_configured: true };
      setProfile(updatedProfile);
      setUser(updatedProfile);
      show("密码已修改，其他设备已退出", "success");
      load();
    } catch (error) {
      show(error instanceof Error ? error.message : "修改失败", "error");
    }
  }
  async function setupMFA() {
    try {
      const data = await api<typeof mfaSecret>("/api/profile/mfa/setup", {
        method: "POST",
        body: "{}",
      });
      setMfaSecret(data);
    } catch (error) {
      show(error instanceof Error ? error.message : "MFA 设置失败", "error");
    }
  }
  async function enableMFA(event: FormEvent) {
    event.preventDefault();
    const code = new FormData(event.currentTarget as HTMLFormElement).get(
      "code",
    );
    try {
      const data = await api<{ backup_codes: string[] }>(
        "/api/profile/mfa/enable",
        { method: "POST", body: JSON.stringify({ code }) },
      );
      setBackupCodes(data.backup_codes);
      setMfaSecret(null);
      setProfile({ ...profile, mfa_enabled: true });
      show("MFA 已启用", "success");
    } catch (error) {
      show(error instanceof Error ? error.message : "MFA 验证失败", "error");
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
      show("MFA 已停用", "success");
    } catch (error) {
      show(error instanceof Error ? error.message : "停用失败", "error");
    }
  }
  async function createPAT(event: FormEvent) {
    event.preventDefault();
    try {
      const data = await api<{ plain_token: string }>("/api/profile/tokens", {
        method: "POST",
        body: JSON.stringify({ name: patName }),
      });
      setPlainPAT(data.plain_token);
      setPatName("");
      load();
      show("令牌已创建", "success");
    } catch (error) {
      show(error instanceof Error ? error.message : "创建失败", "error");
    }
  }
  async function revokeSession(id: number) {
    try {
      await api(`/api/profile/sessions/${id}`, { method: "DELETE" });
      load();
    } catch (error) {
      show(error instanceof Error ? error.message : "操作失败", "error");
    }
  }
  async function logoutAll() {
    try {
      await api("/api/auth/logout-all", { method: "POST" });
      show("已退出其它设备", "success");
      load();
    } catch (error) {
      show(error instanceof Error ? error.message : "操作失败", "error");
    }
  }
  async function uploadAvatar(event: React.ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;
    const form = new FormData();
    form.append("avatar", file);
    try {
      const data = await apiForm<{ avatar_url: string }>(
        "/api/profile/avatar",
        form,
      );
      const next = { ...profile, avatar_url: data.avatar_url };
      setProfile(next);
      setUser(next);
      show("头像已更新", "success");
    } catch (error) {
      show(error instanceof Error ? error.message : "上传失败", "error");
    } finally {
      event.target.value = "";
    }
  }
  async function deleteAccount(event: FormEvent) {
    event.preventDefault();
    if (!window.confirm("确认注销账户？账号记录会永久保留，但将无法登录。")) return;
    try {
      await api("/api/profile", {
        method: "DELETE",
        body: JSON.stringify({ password: deletePassword }),
      });
      window.location.assign("/login");
    } catch (error) {
      show(error instanceof Error ? error.message : "注销失败", "error");
    }
  }
  async function startMerge(event: FormEvent) {
    event.preventDefault();
    if (!window.confirm("继续后需要登录另一个账号。合并完成后不能自动拆分。"))
      return;
    try {
      const data = await api<{ login_url: string }>("/api/profile/merge/start", {
        method: "POST",
        body: JSON.stringify({ password: mergePassword }),
      });
      window.location.assign(data.login_url);
    } catch (error) {
      show(error instanceof Error ? error.message : "发起合并失败", "error");
    }
  }
  return (
    <>
      <PageHeader title={t("profile")} description="更新你的账号信息" />
      <div className="profile-grid">
        <Panel title="个人资料">
          <form onSubmit={saveProfile} className="form-stack">
            <div className="profile-heading">
              <Avatar user={profile} />
              <div>
                <strong>{profile.username}</strong>
                <span>{profile.email}</span>
                <label className="upload-button">
                  <Clipboard size={14} />
                  上传头像
                  <input
                    type="file"
                    accept="image/jpeg,image/png,image/webp"
                    onChange={uploadAvatar}
                  />
                </label>
              </div>
            </div>
            <Input
              label="显示名称"
              value={profile.display_name}
              onChange={(event) =>
                setProfile({ ...profile, display_name: event.target.value })
              }
            />
            <Input
              label={t("email")}
              type="email"
              value={profile.email}
              onChange={(event) =>
                setProfile({ ...profile, email: event.target.value })
              }
              hint={profile.email_verified ? "已验证" : "邮箱还没有验证"}
            />
            {profile.email !== savedEmail && profile.password_configured && (
              <Input
                label="当前密码"
                type="password"
                value={emailPassword}
                onChange={(event) => setEmailPassword(event.target.value)}
                hint="更换邮箱前需要确认当前密码"
                required
              />
            )}
            {emailFlow && (
              <div className="email-verification-box">
                <Input
                  label="新邮箱验证码"
                  value={emailCode}
                  onChange={(event) => setEmailCode(event.target.value)}
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  required
                />
                {emailFlow.debugCode && (
                  <span className="form-hint">
                    本地调试验证码：<code>{emailFlow.debugCode}</code>
                  </span>
                )}
                <Button onClick={completeEmailChange} icon={<BadgeCheck size={16} />}>
                  验证新邮箱
                </Button>
              </div>
            )}
            <Input
              label="头像 URL"
              value={profile.avatar_url}
              onChange={(event) =>
                setProfile({ ...profile, avatar_url: event.target.value })
              }
            />
            <Select
              label={t("language")}
              value={profile.locale}
              onChange={(event) =>
                setProfile({ ...profile, locale: event.target.value })
              }
            >
              <option value="zh-CN">{t("chinese")}</option>
              <option value="en">{t("english")}</option>
            </Select>
            <label className="toggle-row">
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
              <span>接收安全邮件</span>
            </label>
            <Button type="submit" icon={<Check size={16} />}>
              {t("save")}
            </Button>
          </form>
        </Panel>
        <Panel title={t("security")}>
          <div className="security-overview">
            <SecurityItem
              label={t("mfa")}
              status={profile.mfa_enabled ? "已启用" : "建议启用 MFA"}
              good={profile.mfa_enabled}
              action={
                !profile.mfa_enabled ? (
                  <Button
                    variant="ghost"
                    onClick={setupMFA}
                    icon={<Shield size={15} />}
                  >
                    {t("enableMFA")}
                  </Button>
                ) : undefined
              }
            />
            <SecurityItem
              label="邮箱验证"
              status={profile.email_verified ? "良好" : "请先验证邮箱"}
              good={profile.email_verified}
            />
            <SecurityItem
              label="活跃登录设备"
              status={`${sessions.length} 台`}
              good={sessions.length < 8}
            />
            <SecurityItem
              label={t("pats")}
              status={`${tokens.length} 个`}
              good={tokens.length > 0}
            />
          </div>
        </Panel>
        <Panel
          title={t("sessions")}
          action={
            <Button
              variant="ghost"
              onClick={logoutAll}
              icon={<LogOut size={15} />}
            >
              {t("allDevices")}
            </Button>
          }
          className="wide-panel"
        >
          <Table
            headers={["设备标签", "IP", "设备", "最近活跃", "操作"]}
            rows={sessions.map((session) => [
              <div key="device">
                <strong>{session.device_name}</strong>
                {session.current && <Badge tone="success">当前</Badge>}
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
                  {t("revoke")}
                </Button>
              ),
            ])}
            empty="—"
          />
        </Panel>
        <Panel title={t("changePassword")}>
          <form onSubmit={changePassword} className="form-stack">
            {profile.password_configured ? (
              <Input
                label={t("currentPassword")}
                type="password"
                value={password.current_password}
                onChange={(event) =>
                  setPassword({
                    ...password,
                    current_password: event.target.value,
                  })
                }
                required
              />
            ) : (
              <p className="form-hint">
                这是第三方登录账号，首次设置密码无需输入旧密码。
              </p>
            )}
            <Input
              label={t("newPassword")}
              type="password"
              value={password.new_password}
              onChange={(event) =>
                setPassword({ ...password, new_password: event.target.value })
              }
              required
            />
            <Button type="submit" icon={<KeyRound size={16} />}>
              {t("changePassword")}
            </Button>
          </form>
        </Panel>
        <Panel
          title={t("mfa")}
          description={profile.mfa_enabled ? "已启用" : "未启用"}
        >
          {mfaSecret && (
            <form onSubmit={enableMFA} className="mfa-setup">
              <code>{mfaSecret.secret}</code>
              <p>在 Authenticator App 中添加此密钥，然后输入 6 位验证码。</p>
              <Input name="code" label="验证码" inputMode="numeric" required />
              <Button type="submit" icon={<ShieldCheck size={16} />}>
                {t("confirm")}
              </Button>
            </form>
          )}
          {backupCodes.length > 0 && (
            <div className="backup-codes">
              <strong>备用码，请立即保存</strong>
              <code>{backupCodes.join("  ")}</code>
            </div>
          )}
          {profile.mfa_enabled && (
            <form className="form-stack" onSubmit={disableMFA}>
              {profile.password_configured && (
                <Input
                  label={t("currentPassword")}
                  type="password"
                  value={mfaDisable.password}
                  onChange={(event) =>
                    setMfaDisable({
                      ...mfaDisable,
                      password: event.target.value,
                    })
                  }
                  required
                />
              )}
              <Input
                label="MFA 验证码或备用码"
                value={mfaDisable.code}
                onChange={(event) =>
                  setMfaDisable({ ...mfaDisable, code: event.target.value })
                }
                required
              />
              <Button
                type="submit"
                variant="danger"
                icon={<Shield size={15} />}
              >
                {t("disableMFA")}
              </Button>
            </form>
          )}
        </Panel>
        <Panel
          title={t("pats")}
          description="长期有效的 API 凭证，用于服务端脚本、CI 和自动化。"
        >
          <form className="inline-form" onSubmit={createPAT}>
            <Input
              placeholder="令牌名称"
              value={patName}
              onChange={(event) => setPatName(event.target.value)}
              required
            />
            <Button type="submit" icon={<Plus size={16} />}>
              {t("createToken")}
            </Button>
          </form>
          {plainPAT && (
            <div className="secret-value">
              <code>{plainPAT}</code>
              <button
                className="icon-button"
                onClick={() => navigator.clipboard.writeText(plainPAT)}
                title="Copy"
              >
                <Copy size={16} />
              </button>
            </div>
          )}
          <div className="token-list">
            {tokens.length ? (
              tokens.map((token) => (
                <div className="token-row" key={token.id}>
                  <div>
                    <strong>{token.name}</strong>
                    <span>
                      {token.prefix} · {token.scopes}
                    </span>
                  </div>
                  <Button
                    variant="ghost"
                    onClick={() =>
                      api(`/api/profile/tokens/${token.id}`, {
                        method: "DELETE",
                      }).then(load)
                    }
                    icon={<Trash2 size={15} />}
                  >
                    {t("revoke")}
                  </Button>
                </div>
              ))
            ) : (
              <Empty text={t("noTokens")} />
            )}
          </div>
        </Panel>
        <Panel title={t("providers")} description="连接用于登录的第三方身份。">
          {(profile.emails?.length || 0) > 0 && (
            <div className="binding-summary">
              <strong>已绑定邮箱</strong>
              {profile.emails?.map((email) => (
                <span key={email.id}>
                  {email.email}
                  {email.primary ? " · 主邮箱" : ""}
                </span>
              ))}
            </div>
          )}
          {(profile.identities?.length || 0) > 0 && (
            <div className="binding-summary">
              <strong>已绑定第三方账号</strong>
              {profile.identities?.map((identity) => (
                <span key={identity.id}>
                  {identity.provider.display_name} · {identity.external_name || identity.external_id}
                </span>
              ))}
            </div>
          )}
          <div className="provider-list">
            {providers.map((provider) => (
              <div className="provider-row" key={provider.kind}>
                <ProviderIcon kind={provider.kind} />
                <div>
                  <strong>{provider.display_name}</strong>
                  <span>{provider.bound ? t("connected") : "可连接"}</span>
                </div>
                <a
                  className="button ghost"
                  href={`/oauth/upstream/${provider.kind}/start?return_to=/profile`}
                >
                  {provider.bound ? "重新连接" : t("connect")}
                </a>
              </div>
            ))}
          </div>
        </Panel>
        <Panel title={t("audit")} className="wide-panel">
          <Table
            headers={["时间", "动作", "IP"]}
            rows={audit.map((event) => [
              formatDate(event.created_at),
              event.action,
              event.ip || "—",
            ])}
            empty={t("noData")}
          />
        </Panel>
        <Panel title={t("danger")} className="wide-panel danger-panel">
          <div className="danger-row export-row">
            <div>
              <strong>导出我的数据</strong>
              <span>下载平台保存的、与你账号相关的全部数据（JSON 格式）。</span>
            </div>
            <a className="button secondary" href="/api/profile/export">
              <Clipboard size={16} />
              导出我的数据
            </a>
          </div>
          <form className="danger-row merge-row" onSubmit={startMerge}>
            <div>
              <strong>合并账号</strong>
              <span>登录另一个账号，将邮箱和第三方登录渠道合并到编号较小的账号。</span>
            </div>
            <div className="danger-actions">
              {profile.password_configured && (
                <Input
                  type="password"
                  placeholder={t("currentPassword")}
                  value={mergePassword}
                  onChange={(event) => setMergePassword(event.target.value)}
                  required
                />
              )}
              <Button type="submit" variant="secondary" icon={<Link2 size={16} />}>
                合并账号
              </Button>
            </div>
          </form>
          <form className="danger-row" onSubmit={deleteAccount}>
            <div>
              <strong>{t("dangerDelete")}</strong>
              <span>账号和审计数据会永久保留并标记为已注销，但此账号将无法继续登录。</span>
            </div>
            <div className="danger-actions">
              {profile.password_configured && (
                <Input
                  type="password"
                  placeholder={t("currentPassword")}
                  value={deletePassword}
                  onChange={(event) => setDeletePassword(event.target.value)}
                  required
                />
              )}
              <Button
                type="submit"
                variant="danger"
                icon={<Trash2 size={16} />}
              >
                {t("delete")}
              </Button>
            </div>
          </form>
        </Panel>
      </div>
    </>
  );
}
type AdminUser = User & {
  email_count: number;
  identity_count: number;
  deactivated_at?: string;
  merged_into_user_id?: number;
  merge_sources?: AdminUser[];
};

function AdminUsersPage({
  show,
}: {
  show: (message: string, tone?: Toast["tone"]) => void;
}) {
  const [tab, setTab] = useState<"users" | "channels">("users");
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState("all");
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [total, setTotal] = useState(0);
  const [selected, setSelected] = useState<AdminUser | null>(null);
  const [channels, setChannels] = useState<
    Array<{
      kind: string;
      display_name: string;
      bindings: number;
      active_bindings: number;
      enabled?: boolean;
    }>
  >([]);
  const [channelKind, setChannelKind] = useState("");
  const [bindings, setBindings] = useState<Array<Record<string, any>>>([]);
  const loadUsers = () =>
    api<{ items: AdminUser[]; total: number }>(
      `/api/admin/users?q=${encodeURIComponent(query)}&status=${status}`,
    )
      .then((data) => {
        setUsers(data.items);
        setTotal(data.total);
      })
      .catch((error) => show(error.message, "error"));
  const loadChannels = () =>
    api<typeof channels>("/api/admin/channels")
      .then(setChannels)
      .catch((error) => show(error.message, "error"));
  useEffect(() => {
    loadUsers();
    loadChannels();
  }, []);
  async function openUser(id: number) {
    try {
      const data = await api<AdminUser>(`/api/admin/users/${id}`);
      setSelected({
        ...data,
        emails: data.emails || [],
        identities: data.identities || [],
        merge_sources: data.merge_sources || [],
      });
    } catch (error) {
      show(error instanceof Error ? error.message : "读取失败", "error");
    }
  }
  async function saveUser() {
    if (!selected) return;
    try {
      await api(`/api/admin/users/${selected.id}`, {
        method: "PATCH",
        body: JSON.stringify({ role: selected.role, status: selected.status }),
      });
      show("用户状态已更新", "success");
      loadUsers();
      openUser(selected.id);
    } catch (error) {
      show(error instanceof Error ? error.message : "保存失败", "error");
    }
  }
  async function openChannel(kind: string) {
    setChannelKind(kind);
    try {
      const data = await api<{ items: Array<Record<string, any>> }>(
        `/api/admin/channels/${kind}/bindings?page_size=100`,
      );
      setBindings(data.items);
    } catch (error) {
      show(error instanceof Error ? error.message : "读取失败", "error");
    }
  }
  async function disableBinding(id: number) {
    if (!window.confirm("确认禁用这条登录绑定？记录仍会保留用于审计。")) return;
    try {
      await api(
        `/api/admin/bindings/${channelKind === "email" ? "email" : "upstream"}/${id}`,
        { method: "DELETE" },
      );
      show("绑定已禁用", "success");
      openChannel(channelKind);
      loadChannels();
    } catch (error) {
      show(error instanceof Error ? error.message : "操作失败", "error");
    }
  }
  return (
    <>
      <PageHeader title="用户管理" description="查看用户、账号状态、合并来源和全部登录渠道绑定。" />
      <div className="segmented-tabs">
        <button className={tab === "users" ? "active" : ""} onClick={() => setTab("users")}>用户</button>
        <button className={tab === "channels" ? "active" : ""} onClick={() => setTab("channels")}>登录渠道</button>
      </div>
      {tab === "users" ? (
        <div className="admin-grid">
          <Panel
            title={`全部用户 · ${total}`}
            className="admin-list-panel"
            action={
              <div className="table-filters">
                <Input placeholder="搜索用户名、邮箱或昵称" value={query} onChange={(event) => setQuery(event.target.value)} />
                <Select value={status} onChange={(event) => setStatus(event.target.value)}>
                  <option value="all">全部状态</option>
                  <option value="active">正常</option>
                  <option value="deactivated">已注销</option>
                  <option value="merged">已合并</option>
                </Select>
                <Button variant="secondary" onClick={loadUsers} icon={<Search size={15} />}>查询</Button>
              </div>
            }
          >
            <Table
              headers={["ID", "用户", "状态", "角色", "绑定", "最近登录", "操作"]}
              rows={users.map((item) => [
                `#${item.id}`,
                <div key="user"><strong>{item.username}</strong><span className="table-subtitle">{item.email || "无主邮箱"}</span></div>,
                <Badge key="status" tone={item.status === "active" ? "success" : "muted"}>{item.status === "active" ? "正常" : item.status === "merged" ? "已合并" : "已注销"}</Badge>,
                item.role,
                `${item.email_count} 邮箱 / ${item.identity_count} 第三方`,
                formatDate(item.last_login_at),
                <Button key="open" variant="ghost" onClick={() => openUser(item.id)}>查看</Button>,
              ])}
              empty="没有匹配的用户"
            />
          </Panel>
          {selected && (
            <Panel title={`用户 #${selected.id}`} className="admin-detail-panel">
              <div className="form-stack">
                <Input label="用户名" value={selected.username} disabled />
                <Input label="主邮箱" value={selected.email || ""} disabled />
                <Select label="角色" value={selected.role} onChange={(event) => setSelected({ ...selected, role: event.target.value as User["role"] })}>
                  <option value="user">user</option>
                  <option value="admin">admin</option>
                </Select>
                <Select label="状态" value={selected.status} disabled={selected.status === "merged"} onChange={(event) => setSelected({ ...selected, status: event.target.value as User["status"] })}>
                  <option value="active">正常</option>
                  <option value="deactivated">已注销</option>
                  <option value="merged">已合并</option>
                </Select>
                {selected.merged_into_user_id && <div className="notice">已合并到用户 #{selected.merged_into_user_id}</div>}
                <Button onClick={saveUser} icon={<Check size={15} />}>保存用户</Button>
                <div className="binding-summary">
                  <strong>邮箱绑定</strong>
                  {selected.emails?.map((email) => <span key={email.id}>{email.email} · {email.disabled_at ? "已禁用" : email.primary ? "主邮箱" : "有效"} · 来源 #{email.original_user_id}</span>)}
                </div>
                <div className="binding-summary">
                  <strong>第三方绑定</strong>
                  {selected.identities?.map((identity) => <span key={identity.id}>{identity.provider.display_name} · {identity.external_name || identity.external_id} · 来源 #{identity.original_user_id}</span>)}
                </div>
                {(selected.merge_sources?.length || 0) > 0 && <div className="binding-summary"><strong>已并入的原账号</strong>{selected.merge_sources?.map((source) => <span key={source.id}>#{source.id} · {source.username}</span>)}</div>}
              </div>
            </Panel>
          )}
        </div>
      ) : (
        <div className="admin-grid">
          <Panel title="全部登录渠道" className="admin-list-panel">
            <div className="channel-cards">
              {channels.map((channel) => (
                <button key={channel.kind} className={`channel-card ${channelKind === channel.kind ? "active" : ""}`} onClick={() => openChannel(channel.kind)}>
                  <ProviderIcon kind={channel.kind} />
                  <strong>{channel.display_name}</strong>
                  <span>{channel.active_bindings} 有效 / {channel.bindings} 总计</span>
                </button>
              ))}
            </div>
          </Panel>
          {channelKind && (
            <Panel title={`${channels.find((item) => item.kind === channelKind)?.display_name || channelKind} 绑定`} className="admin-detail-panel">
              <div className="binding-admin-list">
                {bindings.map((binding) => (
                  <div className="binding-admin-row" key={binding.id}>
                    <div><strong>#{binding.id} · {binding.user?.username}</strong><span>{channelKind === "email" ? binding.email : `${binding.external_name || binding.external_id} · ${binding.external_email || "无邮箱"}`}</span><small>当前账号 #{binding.user?.id} · 原始账号 #{binding.original_user_id}</small></div>
                    {binding.disabled_at ? <Badge tone="muted">已禁用</Badge> : <Button variant="danger" onClick={() => disableBinding(binding.id)}>禁用</Button>}
                  </div>
                ))}
                {!bindings.length && <Empty text="暂无绑定" />}
              </div>
            </Panel>
          )}
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

function AdminSettingsPage({ show }: { show: (message: string, tone?: Toast["tone"]) => void }) {
  const [settings, setSettings] = useState<AdminSettings | null>(null);
  const [secrets, setSecrets] = useState({ smtp_password: "", turnstile_secret_key: "", cap_secret_key: "" });
  const [testEmail, setTestEmail] = useState("");
  const [providers, setProviders] = useState<AdminProvider[]>([]);
  const load = () => {
    api<AdminSettings>("/api/admin/settings").then(setSettings).catch((error) => show(error.message, "error"));
    api<AdminProvider[]>("/api/admin/providers").then(setProviders).catch((error) => show(error.message, "error"));
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
    Object.entries(secrets).forEach(([key, value]) => { if (value) payload[key] = value; });
    try {
      await api("/api/admin/settings", { method: "PATCH", body: JSON.stringify(payload) });
      setSecrets({ smtp_password: "", turnstile_secret_key: "", cap_secret_key: "" });
      show("系统设置已保存", "success");
      load();
    } catch (error) {
      show(error instanceof Error ? error.message : "保存失败", "error");
    }
  }
  async function sendTestEmail() {
    try {
      await api("/api/admin/settings/email/test", { method: "POST", body: JSON.stringify({ email: testEmail }) });
      show("测试邮件已发送", "success");
    } catch (error) {
      show(error instanceof Error ? error.message : "发送失败", "error");
    }
  }
  function updateProvider(index: number, field: keyof AdminProvider, value: string | boolean) {
    setProviders((items) => items.map((item, itemIndex) => itemIndex === index ? { ...item, [field]: value } : item));
  }
  async function saveProvider(index: number) {
    const provider = providers[index];
    try {
      await api(`/api/admin/providers/${provider.id}`, { method: "PATCH", body: JSON.stringify(provider) });
      show(`${provider.display_name} 已保存`, "success");
      load();
    } catch (error) {
      show(error instanceof Error ? error.message : "保存失败", "error");
    }
  }
  async function testProvider(provider: AdminProvider) {
    try {
      await api(`/api/admin/providers/${provider.id}/test`, { method: "POST", body: "{}" });
      show(`${provider.display_name} 配置可用`, "success");
    } catch (error) {
      show(error instanceof Error ? error.message : "测试失败", "error");
    }
  }
  if (!settings) return <div className="loading-screen"><span>加载设置…</span></div>;
  return (
    <>
      <PageHeader title="系统设置" description="集中配置注册、邮件、人机验证和第三方登录 Provider。未启用的登录方式不会出现在客户页面。" />
      {settings.email_debug && <div className="notice warning">当前启用了邮件调试模式，验证码会显示在浏览器响应中。生产环境必须设置 SSO_EMAIL_DEBUG=false。</div>}
      <form className="settings-grid" onSubmit={saveSettings}>
        <Panel title="注册与邮件" description="注册必须完成邮箱验证码校验。">
          <label className="toggle-row"><input type="checkbox" checked={settings.registration_enabled} onChange={(event) => setSettings({ ...settings, registration_enabled: event.target.checked })} /><span>允许新用户注册</span></label>
          <div className="form-grid-2">
            <Input label="SMTP 主机" value={settings.smtp_host} onChange={(event) => setSettings({ ...settings, smtp_host: event.target.value })} />
            <Input label="SMTP 端口" value={settings.smtp_port} onChange={(event) => setSettings({ ...settings, smtp_port: event.target.value })} />
            <Input label="SMTP 用户名" value={settings.smtp_username} onChange={(event) => setSettings({ ...settings, smtp_username: event.target.value })} />
            <Input label="SMTP 密码" type="password" value={secrets.smtp_password} placeholder={settings.smtp_password_configured ? "已配置，留空不修改" : "请输入密码"} onChange={(event) => setSecrets({ ...secrets, smtp_password: event.target.value })} />
            <Input label="发件人" value={settings.smtp_from} onChange={(event) => setSettings({ ...settings, smtp_from: event.target.value })} />
            <div className="field"><span>发送测试邮件</span><div className="inline-form"><input type="email" value={testEmail} onChange={(event) => setTestEmail(event.target.value)} placeholder="admin@example.com" /><Button variant="secondary" onClick={sendTestEmail}>测试</Button></div></div>
          </div>
        </Panel>
        <Panel title="人机验证" description="接口按模式抽象，后续可继续增加新的实现。">
          <Select label="验证模式" value={settings.captcha_mode} onChange={(event) => setSettings({ ...settings, captcha_mode: event.target.value as AdminSettings["captcha_mode"] })}>
            <option value="none">无</option><option value="turnstile">Cloudflare Turnstile</option><option value="cap">Cap Proof of Work</option>
          </Select>
          {settings.captcha_mode === "turnstile" && <div className="form-grid-2"><Input label="Site Key" value={settings.turnstile_site_key} onChange={(event) => setSettings({ ...settings, turnstile_site_key: event.target.value })} /><Input label="Secret Key" type="password" value={secrets.turnstile_secret_key} placeholder={settings.turnstile_secret_configured ? "已配置，留空不修改" : "请输入 Secret Key"} onChange={(event) => setSecrets({ ...secrets, turnstile_secret_key: event.target.value })} /></div>}
          {settings.captcha_mode === "cap" && <div className="form-grid-2"><Input label="Cap 服务地址" value={settings.cap_server_url} onChange={(event) => setSettings({ ...settings, cap_server_url: event.target.value })} /><Input label="Site Key" value={settings.cap_site_key} onChange={(event) => setSettings({ ...settings, cap_site_key: event.target.value })} /><Input label="Secret Key" type="password" value={secrets.cap_secret_key} placeholder={settings.cap_secret_configured ? "已配置，留空不修改" : "请输入 Secret Key"} onChange={(event) => setSecrets({ ...secrets, cap_secret_key: event.target.value })} /></div>}
          <div className="panel-footer"><Button type="submit" icon={<Check size={16} />}>保存系统设置</Button></div>
        </Panel>
      </form>
      <div className="provider-settings-list">
        {providers.map((provider, index) => (
          <Panel key={provider.id} title={provider.display_name} description={`${provider.kind} · 回调地址 ${provider.callback_url}`} action={<label className="toggle-row compact"><input type="checkbox" checked={provider.enabled} onChange={(event) => updateProvider(index, "enabled", event.target.checked)} /><span>启用</span></label>}>
            <div className="form-grid-2">
              <Input label="显示名称" value={provider.display_name} onChange={(event) => updateProvider(index, "display_name", event.target.value)} />
              <Input label="Client ID / App ID" value={provider.client_id} onChange={(event) => updateProvider(index, "client_id", event.target.value)} />
              <Input label="Client Secret / Bot Token" type="password" value={provider.client_secret || ""} placeholder={provider.secret_configured ? "已配置，留空不修改" : "请输入密钥"} onChange={(event) => updateProvider(index, "client_secret", event.target.value)} />
              <Input label="Scopes" value={provider.scopes || ""} onChange={(event) => updateProvider(index, "scopes", event.target.value)} />
              <Input label="Issuer URL" value={provider.issuer_url || ""} onChange={(event) => updateProvider(index, "issuer_url", event.target.value)} />
              <Input label="Authorization URL" value={provider.authorization_url || ""} onChange={(event) => updateProvider(index, "authorization_url", event.target.value)} />
              <Input label="Token URL" value={provider.token_url || ""} onChange={(event) => updateProvider(index, "token_url", event.target.value)} />
              <Input label="UserInfo URL" value={provider.user_info_url || ""} onChange={(event) => updateProvider(index, "user_info_url", event.target.value)} />
              <Input label="Email API URL" value={provider.email_info_url || ""} onChange={(event) => updateProvider(index, "email_info_url", event.target.value)} />
              <Input label="回调地址" value={provider.callback_url} readOnly />
            </div>
            <div className="panel-footer"><Button variant="secondary" onClick={() => testProvider(provider)} icon={<Activity size={15} />}>连接测试</Button><Button onClick={() => saveProvider(index)} icon={<Check size={15} />}>保存 Provider</Button></div>
          </Panel>
        ))}
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
