# SSO 安全审计

审计范围：当前 `D:\Develop\Server\SSO` 代码、OAuth/OIDC 运行流程、账户资料接口、Docker/Kubernetes 清单和本地集成测试。审计依据优先采用实际代码路径和测试结果。

## 已修复或已落实

- 移除邀请码数据模型、注册参数、API 和前端入口，注册不再受邀请系统影响。
- 用户密码使用 Argon2id；兼容 new-api 的 bcrypt 哈希，并在成功登录后升级。
- Session、PAT、上游 OAuth state、客户端密钥和 OAuth token 索引均不保存明文；OAuth token 载荷使用 AES-GCM 加密，查找使用 SHA-256 摘要。
- Cookie 设置 `HttpOnly`、`SameSite=Lax`，状态变更接口要求 CSRF；PAT 请求不依赖浏览器 CSRF。
- OAuth 应用回调地址使用精确匹配；授权码流程强制 PKCE，state 单次使用且有过期时间；上游回调也采用一次性 state 和 PKCE。
- GitHub 邮箱只接受 `/user/emails` 返回的 `verified=true` 邮箱，优先 `primary=true`，不再把 `/user` 的普通邮箱当成已验证。
- OIDC discovery 严格校验 issuer；issuer、authorization、token 和 userinfo endpoint 仅允许 HTTPS 或本机 HTTP。
- Telegram 校验 HMAC-SHA256、字段排序、bot token 派生密钥，并拒绝未来时间和超过 24 小时的 `auth_date`。
- 上游登录方式通过 `internal/upstream.Provider` 抽象，核心绑定、资料同步、会话创建流程不依赖具体供应商。
- 第三方新用户保存 subject、用户名、显示名、邮箱和头像；已验证邮箱可替换 `@users.invalid` 占位邮箱；用户自行修改过的资料不会被后续上游登录覆盖。
- 生产配置缺少共享 master key 或 OIDC 签名 key 时启动失败；Kubernetes 通过 Secret 挂载共享密钥。
- `X-Forwarded-For` 不再无条件信任，使用 `SSO_TRUSTED_PROXIES` 配置 Gin 可信代理；响应增加 CSP、HSTS（Secure Cookie 开启时）、Permissions-Policy 等安全头。
- Kubernetes 清单包含非 root、禁止提权、只读根文件系统、资源限制、健康探针、PVC 和 PostgreSQL NetworkPolicy。

## 仍需在生产环境补齐

### 中风险：登录限流与账号锁定

当前没有基于 IP、账号标识或设备的登录失败限流。生产部署应接入网关/WAF 或共享 Redis 限流，并对 MFA 失败单独计数；不能只依赖单 Pod 内存状态。

### 中风险：邮件投递仍是开发回放

邮箱验证接口在未接入 SMTP 时会直接返回验证 URL。公网部署前必须替换为邮件队列/SMTP 发送，接口只返回通用成功消息，避免泄露验证 token。

### 中风险：头像存储是本地 PVC

当前头像写入 `/app/data/media/avatars`。Kubernetes 清单默认单副本加 `ReadWriteOnce` PVC；需要多副本时应改为对象存储或 RWX 卷，并增加内容扫描和旧头像清理。

### 中风险：上游自动按已验证邮箱关联

首次上游登录若提供已验证邮箱，会尝试关联已有本地账号。只应信任经过明确配置、issuer 固定且可信的上游；高安全租户可以关闭自动邮箱关联，改为登录本地账号后再绑定。

### 低风险：密钥轮换和 Secret 生命周期

master key 轮换需要先支持多版本解密再重新加密；OIDC signing key 轮换需要同时发布旧公钥和新公钥一段时间。当前清单中的 `sso-secrets.example.yaml` 仅是模板，不能直接用于生产。

### 低风险：反向代理边界

`SSO_TRUSTED_PROXIES` 必须填写实际 ingress/controller 网段，不能照抄示例的宽网段。HTTPS 终止点、Secure Cookie、HSTS 和 `SSO_ISSUER` 必须保持一致。

## 验证记录

- `go test ./... -count=1`
- `go vet ./...`
- `npm run typecheck`
- `npm run build`
- 上游 provider 单元测试覆盖 GitHub verified email、OIDC issuer/endpoint 校验、Telegram future `auth_date` 和自定义 Provider 注册。
- OAuth 集成测试覆盖注册、应用创建、授权同意、PKCE token 交换、userinfo、PAT 和账户注销。

本机未安装 Docker、kubectl 或 kustomize，因此容器启动和集群 apply 需要在具备对应工具的 CI/集群环境中继续验证。
