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

type User = {
  id: number;
  username: string;
  email: string;
  display_name: string;
  avatar_url: string;
  locale: string;
  email_verified: boolean;
  mfa_enabled: boolean;
  security_email_enabled: boolean;
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
    invite: "邀请码",
    providers: "上游接入商",
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
    invite: "Invite codes",
    providers: "Upstream providers",
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
        <div className="brand-mark">FZ</div>
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
          <span className="brand-mark">FZ</span>
          <span>Identity</span>
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
            <span>FZ Identity</span>
            <ArrowRight size={14} />
            <strong>
              {items.find((item) => location.pathname.startsWith(item.path))
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
        <div className="eyebrow">{props.eyebrow || "FZ IDENTITY"}</div>
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
  const [form, setForm] = useState({
    identifier: "",
    username: "",
    email: "",
    password: "",
    invite_code: "",
    code: "",
  });
  const [busy, setBusy] = useState(false);
  const [providers, setProviders] = useState<Provider[]>([]);
  useEffect(() => {
    fetch("/api/providers", { credentials: "include" })
      .then((response) => response.json())
      .then((data) => setProviders(data.data || []))
      .catch(() => undefined);
  }, []);
  const login = props.mode === "login";
  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    try {
      const data = await api<{ user: User; csrf_token: string }>(
        login ? "/api/auth/login" : "/api/auth/register",
        {
          method: "POST",
          body: JSON.stringify(
            login
              ? {
                  identifier: form.identifier,
                  password: form.password,
                  code: form.code,
                }
              : {
                  username: form.username,
                  email: form.email,
                  password: form.password,
                  invite_code: form.invite_code,
                },
          ),
        },
      );
      setCsrf(data.csrf_token);
      props.onUser(data.user);
      navigate(params.get("redirect") || "/dashboard");
    } catch (error) {
      props.show(error instanceof Error ? error.message : "请求失败", "error");
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="auth-layout">
      <div className="auth-brand">
        <span className="brand-mark">FZ</span>
        <span>Identity</span>
      </div>
      <div className="auth-locale">
        <button onClick={() => props.changeLocale("zh")}>中文</button>
        <span>/</span>
        <button onClick={() => props.changeLocale("en")}>English</button>
      </div>
      <div className="auth-card">
        <div className="eyebrow">FZ IDENTITY</div>
        <h1>{login ? props.t("signIn") : props.t("signUp")}</h1>
        <p className="auth-lead">
          {login
            ? "统一访问你的应用、授权和安全设置。"
            : "创建一个统一身份账号，连接你的所有服务。"}
        </p>
        <form onSubmit={submit} className="form-stack">
          {login ? (
            <Input
              label={props.t("username")}
              value={form.identifier}
              onChange={(event) =>
                setForm({ ...form, identifier: event.target.value })
              }
              autoComplete="username"
              required
            />
          ) : (
            <>
              <Input
                label="用户名"
                value={form.username}
                onChange={(event) =>
                  setForm({ ...form, username: event.target.value })
                }
                required
              />
              <Input
                label={props.t("email")}
                type="email"
                value={form.email}
                onChange={(event) =>
                  setForm({ ...form, email: event.target.value })
                }
                required
              />
            </>
          )}
          <Input
            label={props.t("password")}
            type="password"
            value={form.password}
            onChange={(event) =>
              setForm({ ...form, password: event.target.value })
            }
            autoComplete={login ? "current-password" : "new-password"}
            required
            hint="至少 8 位，同时包含字母和数字"
          />
          {login && (
            <Input
              label="MFA 验证码（如已启用）"
              inputMode="numeric"
              value={form.code}
              onChange={(event) =>
                setForm({ ...form, code: event.target.value })
              }
            />
          )}
          {!login && (
            <Input
              label="邀请码（可选）"
              value={form.invite_code}
              onChange={(event) =>
                setForm({ ...form, invite_code: event.target.value })
              }
            />
          )}
          <Button
            type="submit"
            disabled={busy}
            icon={
              busy ? (
                <RefreshCw size={16} className="spin" />
              ) : (
                <ArrowRight size={16} />
              )
            }
          >
            {login ? props.t("signIn") : props.t("signUp")}
          </Button>
        </form>
        {login &&
          providers.filter((provider) => provider.enabled).length > 0 && (
            <div className="auth-providers">
              <div className="divider">
                <span>或使用接入商</span>
              </div>
              {providers
                .filter(
                  (provider) =>
                    provider.enabled &&
                    provider.kind !== "telegram" &&
                    provider.kind !== "wechat",
                )
                .map((provider) => (
                  <a
                    className="provider-button"
                    key={provider.kind}
                    href={`/oauth/upstream/${provider.kind}/start?return_to=/dashboard`}
                  >
                    <ProviderIcon kind={provider.kind} />
                    {provider.display_name}
                  </a>
                ))}
            </div>
          )}
        <div className="auth-switch">
          {login ? (
            <>
              还没有账号？<Link to="/register">注册账号</Link>
            </>
          ) : (
            <>
              已有账号？<Link to="/login">返回登录</Link>
            </>
          )}
        </div>
      </div>
      <div className="auth-footer">
        FZ Identity · OAuth 2.0 / OpenID Connect
      </div>
    </div>
  );
}

function ProviderIcon({ kind }: { kind: string }) {
  if (kind === "github") return <Github size={17} />;
  if (kind === "discord") return <Users size={17} />;
  if (kind === "linuxdo") return <Globe2 size={17} />;
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
    invites: number;
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
          label={t("invite")}
          value={data?.invites ?? 0}
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
                    "此应用请求访问你的 FZ Identity 账号。"}
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
  const [mfaDisable, setMfaDisable] = useState({ password: "", code: "" });
  const [deletePassword, setDeletePassword] = useState("");
  const load = () => {
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
        body: JSON.stringify({ ...profile, current_password: emailPassword }),
      });
      setProfile(data);
      setUser(data);
      setSavedEmail(data.email);
      setEmailPassword("");
      show("资料已保存", "success");
    } catch (error) {
      show(error instanceof Error ? error.message : "保存失败", "error");
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
  async function verifyEmail() {
    try {
      const data = await api<{ verification_url: string }>(
        "/api/profile/email-verification",
        { method: "POST", body: "{}" },
      );
      window.open(data.verification_url, "_blank");
    } catch (error) {
      show(error instanceof Error ? error.message : "发送失败", "error");
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
    if (!window.confirm("确认永久注销账户？此操作无法撤销。")) return;
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
            {profile.email !== savedEmail && (
              <Input
                label="当前密码"
                type="password"
                value={emailPassword}
                onChange={(event) => setEmailPassword(event.target.value)}
                hint="更换邮箱前需要确认当前密码"
                required
              />
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
          {!profile.email_verified && (
            <Button
              variant="ghost"
              onClick={verifyEmail}
              icon={<Bell size={15} />}
            >
              {t("sendVerify")}
            </Button>
          )}
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
              <Input
                label={t("currentPassword")}
                type="password"
                value={mfaDisable.password}
                onChange={(event) =>
                  setMfaDisable({ ...mfaDisable, password: event.target.value })
                }
                required
              />
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
          <div className="provider-list">
            {providers.map((provider) => (
              <div className="provider-row" key={provider.kind}>
                <ProviderIcon kind={provider.kind} />
                <div>
                  <strong>{provider.display_name}</strong>
                  <span>
                    {provider.configured
                      ? provider.bound
                        ? t("connected")
                        : "已配置"
                      : "未配置"}
                  </span>
                </div>
                {provider.enabled && (
                  <a
                    className="button ghost"
                    href={`/oauth/upstream/${provider.kind}/start?return_to=/profile`}
                  >
                    {provider.bound ? "重新连接" : t("connect")}
                  </a>
                )}
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
          <form className="danger-row" onSubmit={deleteAccount}>
            <div>
              <strong>{t("dangerDelete")}</strong>
              <span>此操作不可撤销，账户和所有数据都会被永久删除。</span>
            </div>
            <div className="danger-actions">
              <Input
                type="password"
                placeholder={t("currentPassword")}
                value={deletePassword}
                onChange={(event) => setDeletePassword(event.target.value)}
                required
              />
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
