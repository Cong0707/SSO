# FZ SSO

FZ SSO 是面向自有服务的统一用户管理与 OAuth 2.0 / OpenID Connect 身份中心。界面参考 `Cong0707/new-api` 默认前端的中性主题、紧凑侧栏和账号安全设置，但业务模型独立于 AI 网关。

## 已实现能力

- 用户注册、登录、Cookie 会话、设备管理、退出其它设备和安全审计。
- 用户资料、邮箱验证回放链接、密码修改、TOTP MFA、一次性备用码、头像上传、JSON 数据导出和账户注销。
- OAuth 应用创建、编辑、删除、客户端密钥轮换和应用图标。
- OAuth 授权码、强制 PKCE、刷新令牌、撤销、授权同意页、授权日志和已授权应用管理。
- OIDC Discovery、JWKS、`id_token`、`userinfo` 和标准 Bearer PAT API 认证。
- GitHub、Discord、LinuxDO、通用 OIDC、微信的统一上游 Provider 接口；Telegram Login Widget 使用独立签名校验接口。
- 第三方首次登录自动注册并导入用户名、显示名、已验证邮箱和头像；用户可在个人资料中修改。第三方账号首次设置本地密码时不要求旧密码。
- PostgreSQL 是默认数据库，OAuth 授权码、访问令牌和刷新令牌也持久化在 GORM 数据库中；SQLite 仅用于本地演示和测试。
- 邀请码/邀请系统已移除，注册不再依赖邀请码。

## 本地运行

使用 PostgreSQL：

```powershell
$env:SSO_DATABASE_DRIVER = "postgres"
$env:SSO_DATABASE_DSN = "host=127.0.0.1 user=sso password=change-me dbname=sso port=5432 sslmode=disable TimeZone=UTC"
$env:SSO_ALLOW_KEY_GENERATION = "true" # 仅本地演示
go run ./cmd/sso
```

没有 PostgreSQL 时可显式使用 SQLite 演示：

```powershell
$env:SSO_DATABASE_DRIVER = "sqlite"
$env:SSO_DATABASE_DSN = "data/sso.db"
$env:SSO_ALLOW_KEY_GENERATION = "true"
go run ./cmd/sso
```

前端开发服务器需要另开终端：

```powershell
cd web
npm install
npm run dev
```

默认后端/前端开发端口是 `8080` / `5174`。如果端口被占用，设置 `SSO_ADDR`、`SSO_ISSUER` 并同步修改 `web/vite.config.ts` 代理端口。本轮验证使用 `8082` / `5174`。

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

Compose 会启动 PostgreSQL 和 SSO。Compose 为本地开发默认允许自动生成密钥；生产环境应改为挂载固定的 `SSO_MASTER_KEY_FILE` 和 `SSO_OIDC_SIGNING_KEY_FILE`，并关闭 `SSO_ALLOW_KEY_GENERATION`。

## Kubernetes 部署

清单位于 [`deploy/k8s`](deploy/k8s)，默认包含单副本 PostgreSQL、PVC、探针、非 root 容器、只读根文件系统、NetworkPolicy 和 Service。先创建实际 Secret，不要把真实 Secret 提交到 Git：

```powershell
kubectl create namespace sso
kubectl -n sso create secret generic sso-secrets `
  --from-literal=POSTGRES_PASSWORD='替换为随机长密码' `
  --from-literal=SSO_DATABASE_DSN='host=postgres user=sso password=替换为随机长密码 dbname=sso port=5432 sslmode=disable TimeZone=UTC' `
  --from-file=master.key=data/master.key `
  --from-file=oidc-signing.pem=data/oidc-signing.pem
kubectl apply -k deploy/k8s
```

`master.key` 必须是 32 字节密钥的无填充 Base64 文本，`oidc-signing.pem` 必须是 RSA 私钥。生产域名、TLS Secret 和镜像地址请修改 `sso-configmap.yaml`、`sso-ingress.example.yaml` 与 `sso-deployment.yaml`。当前头像仍保存于应用 PVC，多副本部署应换成对象存储或 RWX 卷。

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

没有配置 SMTP 时，邮箱验证接口返回开发环境回放链接，不应在公网生产环境直接展示该响应；接入邮件服务时只需替换发送实现，不改变验证 token 数据结构。

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
