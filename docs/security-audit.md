# 统一身份中心安全审计

审计日期：2026-07-23

审计范围：Go API、React 认证与管理页面、OAuth/OIDC、上游身份 Provider、账号合并/注销、邮箱验证码、Captcha、Docker Compose 和 Kubernetes 清单。结论以本轮实际代码路径、自动化测试和浏览器验收为准。

## 本轮已修复

- 注册账号只有在邮箱验证码通过后才创建；验证码使用 master key 计算 HMAC-SHA256，10 分钟过期，最多尝试 8 次，重发间隔 60 秒，数据库单独泄露时不能离线枚举六位验证码。
- `SSO_EMAIL_DEBUG` 默认仅在 SQLite 开发模式启用；Compose 和 Kubernetes 显式关闭。生产响应不会包含验证码。
- 合并令牌绑定到发起账号的浏览器 Session、账号 ID 和 10 分钟有效期，泄露的 URL 不能在另一浏览器中完成合并。
- 登录同一个账号会取消合并，不创建额外会话；合并成功后撤销两个账号的 Session、PAT 和被合并账号的 Grant。
- 注销和合并均不物理删除用户；状态分别为 `deactivated`、`merged`，保留 `deactivated_at` 和 `merged_into_user_id` 供管理员审计。
- 邮箱和第三方身份使用平等的绑定记录，不存在主邮箱或主绑定；同一个账号允许多个邮箱及同一 Provider 的多条绑定，同一个 `provider_id + external_id` 只能归属一个账号。
- 用户解绑会物理删除绑定记录，并在事务内锁定用户行；普通用户不能删除最后一条绑定，管理员可以删除最后一条绑定。
- 第三方新账号不会仅凭“相同邮箱”静默并入现有账号，必须由用户明确发起账号合并。
- Provider 和 SMTP Secret 只允许覆盖写入，管理员 API 只返回 `*_configured` 状态，不返回明文。
- 系统设置和用户管理均要求浏览器 Session、管理员角色；状态变更继续要求 CSRF。
- 管理员编辑用户名、显示名称、角色、状态和重置密码均经过服务端白名单校验；密码使用统一强哈希函数，密码更新与目标用户全部会话撤销处于同一数据库事务。
- 管理员重置 MFA 和删除邮箱/OAuth 绑定均要求管理员 Session 与 CSRF；MFA 重置与目标会话撤销处于同一事务，操作写入审计事件。
- 管理员用户详情的统一绑定接口只返回渠道和外部标识等展示字段，不返回 OAuth token、Provider Secret、MFA Secret、密码摘要或原始身份 Metadata。
- 最后一个有效管理员不能被降级；管理员不能在当前会话中注销自己；已合并原账号不能重新启用。
- Turnstile 使用 Cloudflare `siteverify`；Cap 使用独立 `siteverify`。Cap 代理只允许 GET/POST 且路径必须位于当前 Site Key 下，避免形成通用反向代理。
- 未配置或未启用的 Provider 不进入公开接口；Cap 前端代码仅在模式启用后动态加载。
- Session、PAT、上游 OAuth state、客户端密钥和 OAuth token 均不保存明文；OAuth token 载荷使用 AES-GCM 加密。
- OAuth 回调地址精确匹配，授权码流程强制 PKCE，上游 OAuth state 单次使用且带过期时间。
- 认证、验证码、OAuth Token 和已登录敏感操作使用 Redis 共享限流；键名使用 master key 做 HMAC，不暴露邮箱、IP、用户编号或 Client ID。Redis 不可用时相关请求失败关闭并返回 `503`。
- Cookie 使用 `HttpOnly`、`SameSite=Lax`；生产启用 Secure Cookie 时发送 HSTS。响应包含 CSP、Permissions-Policy、X-Frame-Options 等安全头。
- Kubernetes 清单包含 PostgreSQL、Redis、非 root 运行、禁止提权、只读根文件系统、资源限制、健康探针和 NetworkPolicy。

## 剩余风险

### 高风险：下游账号生命周期同步

账号注销或合并后，本系统会立即撤销本地 Session、PAT 和相关授权，但下游业务默认不知道账号已注销或用户 ID 已合并。正式接入前需要提供并强制下游消费注销、合并事件，或提供实时账号状态查询；在此之前，下游保存的账号状态和业务数据可能继续指向已注销或被合并的用户 ID。

### 部署约束

当前 SMTP 实现使用 Go 标准库并依赖实际邮件服务能力；头像目录需要在多 Pod 环境挂载 Ceph、对象存储或其它跨节点存储。这两项按既定部署架构处理，不列为当前代码阻断项。

### 低风险：密钥轮换

master key 尚未支持多版本解密和在线重新加密；OIDC signing key 尚未支持新旧 JWKS 并行发布。生产轮换前应实现 key version 和过渡窗口。

### 低风险：可信代理配置

`SSO_TRUSTED_PROXIES` 必须限制为实际 Ingress 网段。示例的 `10.0.0.0/8` 不能不经评估直接用于公网集群。

## 验证

- `go test ./...`
- `go vet ./...`
- `npm run typecheck`
- `npm run build`
- `npm audit --omit=dev`：0 vulnerabilities
- 使用 PyYAML 解析 `docker-compose.yml` 和全部 Kubernetes YAML：通过
- 浏览器：完成三页式首个管理员注册，验证码页、管理员菜单、系统设置、用户详情和移动端 390x844 布局均通过。
- 浏览器：验证密集用户表、用户编辑抽屉、统一绑定列表、设置左侧分栏、密码弹窗和 MFA 二维码弹窗；MFA 验收后已重置临时密钥。
- 浏览器：公开认证页在 `captcha_mode=none` 且 Provider 未配置时不显示未完成的登录项，Cap chunk 未加载。

当前机器未安装 Docker 和 kubectl，因此未执行镜像构建、Compose 启动和 `kubectl apply --dry-run`。这些步骤需在 CI 或具备相应工具的部署机继续验证。
