# xem SSO

xem SSO 是面向自有服务的用户管理与 OAuth 2.0 / OpenID Connect 服务。

## 已实现能力

- 三页式注册/登录：首屏使用邮箱识别和人机验证；新用户在第二页设置用户名与密码，已有用户输入密码；第三页完成注册邮箱验证码或按需出现的 MFA 验证。
- 注册邮箱必须验证成功后才创建账号；本地 SQLite 可显式启用 `SSO_EMAIL_DEBUG` 展示调试验证码，生产环境禁止启用。
- 用户资料、多邮箱与多第三方身份平等绑定、密码修改、TOTP MFA、一次性备用码、头像上传、设备管理、PAT、JSON 数据导出和安全审计。普通用户可删除任意绑定，但必须至少保留一条；管理员可删除最后一条绑定。
- 账号注销采用永久保留模型：账号状态改为 `deactivated`，会话和凭证撤销，数据库记录不物理删除。
- 账号合并需要先确认当前密码，再登录另一个账号；邮箱和第三方身份合并到 ID 较小的账号，原账号标记为 `merged` 并永久保留供审计。
- OAuth 应用创建、编辑、删除、客户端密钥轮换和应用图标。
- OAuth 授权码、强制 PKCE、刷新令牌、撤销、授权同意页、授权日志和已授权应用管理。
- OIDC Discovery、JWKS、`id_token`、`userinfo` 和标准 Bearer PAT API 认证。
- GitHub、Discord、LinuxDO、通用 OIDC、微信的统一上游 Provider 接口；Telegram Login Widget 使用独立签名校验接口。
- 第三方首次登录自动注册并导入用户名、显示名、已验证邮箱和头像；不会仅凭相同邮箱静默合并账号。一个账号允许绑定多个邮箱和同一 Provider 的多个外部身份。
- 管理员侧栏包含“用户管理”和“系统设置”：可查看正常、注销和已合并账号，管理所有渠道绑定，配置 SMTP、`none / turnstile / cap` 人机验证，以及全部上游 Provider。
- PostgreSQL 是默认数据库，OAuth 授权码、访问令牌和刷新令牌也持久化在 GORM 数据库中；SQLite 仅用于本地演示和测试。
- 邀请码/邀请系统已移除，注册不再依赖邀请码。

## 本地运行

使用 PostgreSQL：

```powershell
$env:SSO_DATABASE_DRIVER = "postgres"
$env:SSO_DATABASE_DSN = "host=127.0.0.1 user=sso password=change-me dbname=sso port=5432 sslmode=disable TimeZone=UTC"
$env:SSO_REDIS_ADDR = "127.0.0.1:6379"
$env:SSO_REDIS_PASSWORD = "replace-me"
$env:SSO_ALLOW_KEY_GENERATION = "true" # 仅本地演示
$env:SSO_SMTP_HOST = "smtp.example.com"
$env:SSO_SMTP_PORT = "587"
$env:SSO_SMTP_USERNAME = "mailer@example.com"
$env:SSO_SMTP_PASSWORD = "replace-me"
$env:SSO_SMTP_FROM = "mailer@example.com"
go run ./cmd/sso
```

没有 PostgreSQL 时可显式使用 SQLite 演示：

```powershell
$env:SSO_DATABASE_DRIVER = "sqlite"
$env:SSO_DATABASE_DSN = "data/sso.db"
$env:SSO_ALLOW_KEY_GENERATION = "true"
$env:SSO_EMAIL_DEBUG = "true" # 仅本机调试，页面会显示验证码
go run ./cmd/sso
```

前端开发服务器需要另开终端：

```powershell
cd web
npm install
npm run dev
```

默认后端/前端开发端口是 `8080` / `5174`。如果端口被占用，设置 `SSO_ADDR`、`SSO_ISSUER` 并同步修改 `web/vite.config.ts` 代理端口。

完成邮箱验证的第一个账号自动成为管理员。管理员登录后从侧栏进入 `管理 -> 系统设置` 配置邮件、Captcha 和第三方登录；未启用或未完整配置的登录方式不会显示在公开认证页。

生产构建：

```powershell
cd web
npm run build
cd ..
go build -o sso.exe ./cmd/sso
```

## Docker Compose

```powershell
docker compose up -d --build
```

Compose 会启动 PostgreSQL、Redis 和 SSO。Redis 保存跨实例共享的短期限流计数；SSO 启用限流后如果 Redis 不可用，会拒绝认证和敏感操作。Compose 为本地开发默认允许自动生成密钥；生产环境应改为挂载固定的 `SSO_MASTER_KEY_FILE` 和 `SSO_OIDC_SIGNING_KEY_FILE`，并关闭 `SSO_ALLOW_KEY_GENERATION`。

## Kubernetes 部署

清单位于 [`deploy/k8s`](deploy/k8s)，默认包含单副本 PostgreSQL、PVC、探针、非 root 容器、只读根文件系统、NetworkPolicy 和 Service。先创建实际 Secret，不要把真实 Secret 提交到 Git：

```powershell
kubectl create namespace sso
kubectl -n sso create secret generic sso-secrets `
  --from-literal=POSTGRES_PASSWORD='替换为随机长密码' `
  --from-literal=SSO_REDIS_PASSWORD='替换为另一随机长密码' `
  --from-literal=SSO_DATABASE_DSN='host=postgres user=sso password=替换为随机长密码 dbname=sso port=5432 sslmode=disable TimeZone=UTC' `
  --from-file=master.key=data/master.key `
  --from-file=oidc-signing.pem=data/oidc-signing.pem
kubectl apply -k deploy/k8s
```

`master.key` 必须是 32 字节密钥的无填充 Base64 文本，`oidc-signing.pem` 必须是 RSA 私钥。生产域名、TLS Secret 和镜像地址请修改 `sso-configmap.yaml`、`sso-ingress.example.yaml` 与 `sso-deployment.yaml`。Kubernetes 示例部署 Redis 供所有 SSO Pod 共享限流状态；正式环境可替换为高可用 Redis 服务。当前头像仍保存于应用 PVC，多副本部署应换成 Ceph、对象存储或 RWX 卷。

## OAuth/OIDC 端点

```text
GET  /.well-known/openid-configuration
GET  /oauth/authorize
POST /oauth/token
POST /oauth/revoke
GET  /oauth/userinfo
GET  /oauth/jwks.json
```

新应用默认允许 `openid profile email`，授权码有效期 5 分钟，访问令牌 15 分钟，刷新令牌 30 天。所有应用必须使用精确匹配的回调地址，授权请求必须带 `code_challenge`。

## 数据与密钥

`SSO_MASTER_KEY_FILE` 用于加密 MFA、上游客户端密钥和 OAuth 令牌载荷；`SSO_OIDC_SIGNING_KEY_FILE` 用于签发 OIDC ID Token。两者必须和数据库一起备份，权限应限制为服务用户。OAuth 令牌只在数据库中保存 SHA-256 索引和 AES-GCM 加密载荷，不再使用单机 BuntDB 文件。

注册和邮箱绑定验证码使用 master key 计算 HMAC-SHA256，10 分钟过期，限制尝试次数并带 60 秒重发间隔。生产环境必须通过环境变量引导 SMTP，或在首个管理员创建前由部署流程写入系统设置；`SSO_EMAIL_DEBUG` 必须保持为 `false`。

## 新增登录方式

核心流程只依赖 `internal/upstream.Provider`：

```go
type Provider interface {
    Kind() string
    AuthorizationURL(context.Context, AuthorizationRequest) (string, error)
    Exchange(context.Context, CallbackRequest) (Identity, error)
}
```

在 `internal/upstream` 注册新的 factory 后，服务端无需修改登录、绑定、资料同步和会话创建流程。Provider 返回统一的 `Identity`，包含 `Subject`、`Username`、`Name`、`Email`、`AvatarURL` 和 `EmailVerified`。

## new-api 迁移

字段映射、密码兼容策略、第三方身份绑定和迁移顺序见 [`docs/new-api-migration.md`](docs/new-api-migration.md)。当前登录器兼容 new-api 使用的 bcrypt 哈希，用户首次登录成功后会自动升级为 Argon2id。
