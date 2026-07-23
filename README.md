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
- 注册开启时，第三方首次登录可自动注册并导入用户名、显示名、已验证邮箱和头像；注册关闭时，未知第三方身份不能创建新账号。系统不会仅凭相同邮箱静默合并账号，一个账号允许绑定多个邮箱和同一 Provider 的多个外部身份。
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
$env:SSO_AUTO_MIGRATE = "false"
$env:SSO_BOOTSTRAP_ADMIN_EMAILS = "admin@example.com"
$env:SSO_SMTP_HOST = "smtp.example.com"
$env:SSO_SMTP_PORT = "587"
$env:SSO_SMTP_USERNAME = "mailer@example.com"
$env:SSO_SMTP_PASSWORD = "replace-me"
$env:SSO_SMTP_FROM = "mailer@example.com"
go run ./cmd/migrate
go run ./cmd/sso
```

没有 PostgreSQL 时可显式使用 SQLite 演示：

```powershell
$env:SSO_DATABASE_DRIVER = "sqlite"
$env:SSO_DATABASE_DSN = "data/sso.db"
$env:SSO_DATA_DIR = "data"
$env:SSO_ALLOW_KEY_GENERATION = "true"
$env:SSO_BOOTSTRAP_ADMIN_EMAILS = "admin@example.com"
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

系统不会把首个注册用户自动提升为管理员。只有 `SSO_BOOTSTRAP_ADMIN_EMAILS` 中明确列出的邮箱在完成验证后获得管理员权限。管理员登录后从侧栏进入 `管理 -> 系统设置` 配置邮件、Captcha 和第三方登录；未启用或未完整配置的登录方式不会显示在公开认证页。

生产构建：

```powershell
cd web
npm run build
cd ..
go build -o sso.exe ./cmd/sso
go build -o sso-migrate.exe ./cmd/migrate
go build -o sso-migrate-new-api.exe ./cmd/migrate-new-api
```

## Docker Compose

```powershell
docker compose up -d --build
```

Compose 会启动本地开发用 PostgreSQL、Redis，先执行一次 schema migration，再启动 SSO。Redis 保存跨实例共享的短期限流计数；SSO 启用限流后如果 Redis 不可用，会拒绝认证和敏感操作。Compose 只用于开发，生产环境应挂载固定密钥并使用外部高可用 PostgreSQL/Redis。

## Kubernetes 部署

清单位于 [`deploy/k8s`](deploy/k8s)，默认部署 2 个 SSO Pod、RollingUpdate、PDB、跨节点分布、CephFS RWX 卷、探针、非 root 容器、只读根文件系统和 NetworkPolicy。数据库和 Redis 必须由现有 PostgreSQL Operator 与 HA Redis 提供，默认清单不会创建单实例依赖。

先把 `sso-deployment.yaml` 和 `sso-migration-job.example.yaml` 中的镜像 digest 占位值替换为 CI 实际产物，并在首次启动前配置 SMTP、Captcha 与管理员邮箱。需要开放注册时，应在第一次启动应用 Pod 前把 `SSO_REGISTRATION_ENABLED` 改为 `true`；该值首次启动后由数据库设置页管理。

```powershell
kubectl create namespace sso
kubectl -n sso create secret generic sso-secrets `
  --from-literal=SSO_REDIS_PASSWORD='替换为另一随机长密码' `
  --from-literal=SSO_BOOTSTRAP_ADMIN_EMAILS='admin@example.com' `
  --from-literal=SSO_DATABASE_DSN='host=postgres-rw.database.svc.cluster.local user=sso password=替换为随机长密码 dbname=sso port=5432 sslmode=verify-full TimeZone=UTC' `
  --from-file=master.key=data/master.key `
  --from-file=oidc-signing.pem=data/oidc-signing.pem
kubectl -n sso apply -f deploy/k8s/sso-configmap.yaml
kubectl -n sso apply -f deploy/k8s/sso-pvc.yaml
kubectl -n sso delete job sso-schema-migrate --ignore-not-found
kubectl apply -f deploy/k8s/sso-migration-job.example.yaml
kubectl -n sso wait --for=condition=complete job/sso-schema-migrate --timeout=300s
kubectl apply -k deploy/k8s
```

`master.key` 必须是 32 字节密钥的无填充 Base64 文本，`oidc-signing.pem` 必须是 RSA 私钥。生产域名、TLS Secret、外部 Redis 地址、Ceph StorageClass 和实际 Ingress 可信代理 CIDR 必须在集群 overlay 中设置。应用 Pod 不执行 schema 变更；每次升级先运行迁移 Job，成功后再滚动 Deployment。

## OAuth/OIDC 端点

```text
GET  /.well-known/openid-configuration
GET  /oauth/authorize
POST /oauth/token
POST /oauth/revoke
POST /oauth/introspect
GET  /oauth/userinfo
GET  /oauth/jwks.json
```

新应用默认允许 `openid profile email`，授权码有效期 5 分钟，访问令牌 15 分钟，刷新令牌 30 天。所有应用必须使用精确匹配的回调地址和 S256 `code_challenge`。撤销与 introspection 都要求客户端认证。

## 数据与密钥

`SSO_MASTER_KEY_FILE` 用于加密 MFA、上游客户端密钥和 OAuth 令牌载荷；`SSO_OIDC_SIGNING_KEY_FILE` 用于签发 OIDC ID Token。两者必须和数据库一起备份，权限应限制为服务用户。OAuth 令牌只在数据库中保存 SHA-256 索引和 AES-GCM 加密载荷，不再使用单机 BuntDB 文件。

注册和邮箱绑定验证码使用 master key 计算 HMAC-SHA256，10 分钟过期，限制尝试次数并带 60 秒重发间隔。生产环境必须先通过环境变量引导 SMTP、Captcha 和管理员邮箱，完成配置后再开启注册；`SSO_EMAIL_DEBUG` 必须保持为 `false`。

账号注销、合并、重新启用和角色变化会写入事务 outbox。设置 `SSO_LIFECYCLE_WEBHOOK_URL` 与 `SSO_LIFECYCLE_WEBHOOK_SECRET` 后，多 Pod 会安全抢占待发送事件，使用 `X-Xem-Signature-SHA256` 验签，并记录成功回执、重试与死信。

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

迁移边界是身份接管，不是业务用户表替换。new-api 仍保留本地用户 ID、角色、分组、额度、钱包、订阅、支付、API Token、日志和业务 Session；SSO 接管密码、邮箱、第三方绑定、头像、MFA、账号合并和全局身份状态。new-api 应通过 OIDC `sub` 建立本地业务用户映射，并把个人信息管理入口跳转到 SSO。
