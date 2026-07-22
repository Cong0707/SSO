# FZ SSO

FZ SSO 是面向自有服务的统一用户管理与 OAuth 2.0 / OpenID Connect 身份中心。界面参考 `Cong0707/new-api` 默认前端的中性主题、紧凑侧栏和账号安全设置，但业务模型独立于 AI 网关。

## 已实现能力

- 用户注册、登录、Cookie 会话、设备管理、退出其它设备和安全审计。
- 用户资料、邮箱验证回放链接、密码修改、TOTP MFA、一次性备用码、头像上传、JSON 数据导出和账户注销。
- OAuth 应用创建、编辑、删除、客户端密钥轮换和应用图标。
- OAuth 授权码、强制 PKCE、刷新令牌、撤销、授权同意页、授权日志和已授权应用管理。
- OIDC Discovery、JWKS、`id_token`、`userinfo` 和标准 Bearer PAT API 认证。
- GitHub、Discord、LinuxDO、通用 OIDC 的上游登录框架；Telegram/微信配置模型已保留，专用协议接入待补。
- SQLite 本地运行，保留 GORM PostgreSQL/MySQL 驱动；生产建议 PostgreSQL。

## 本地运行

```powershell
Copy-Item .env.example .env
go run ./cmd/sso
```

前端开发服务器需要另开终端：

```powershell
cd web
npm install
npm run dev
```

默认端口是 `8080` / `5173`。如果端口被占用，设置 `SSO_ADDR`、`SSO_ISSUER` 并同步修改 `web/vite.config.ts` 代理端口。本轮验证使用 `8082` / `5174`，地址为 <http://localhost:5174/login>。

生产构建：

```powershell
cd web
npm run build
cd ..
go build -o sso.exe ./cmd/sso
```

或直接使用 Docker Compose：

```powershell
docker compose up -d --build
```

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

`data/master.key` 用于加密 MFA 与上游客户端密钥，`data/oidc-signing.pem` 用于签发 OIDC ID Token；两者必须和数据库一起备份，权限应限制为服务用户。OAuth 临时令牌存储在 `SSO_OAUTH_TOKEN_DB` 指向的 BuntDB 文件中。

没有配置 SMTP 时，邮箱验证接口返回开发环境回放链接，不应在公网生产环境直接展示该响应；接入邮件服务时只需替换发送实现，不改变验证 token 数据结构。

## new-api 迁移

字段映射、密码兼容策略、第三方身份绑定和迁移顺序见 [`docs/new-api-migration.md`](docs/new-api-migration.md)。当前登录器兼容 new-api 使用的 bcrypt 哈希，用户首次登录成功后会自动升级为 Argon2id。
