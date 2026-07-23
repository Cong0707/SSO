# 统一身份中心安全审计

审计日期：2026-07-23

审计范围：Go API、React 认证与管理页面、OAuth/OIDC、上游身份 Provider、账号合并/注销、邮箱验证码、Captcha、Docker Compose 和 Kubernetes 清单。结论以本轮实际代码路径、自动化测试和浏览器验收为准。

## 本轮已修复

- 注册账号只有在邮箱验证码通过后才创建；验证码使用 master key 计算 HMAC-SHA256，10 分钟过期，最多尝试 8 次，重发间隔 60 秒，数据库单独泄露时不能离线枚举六位验证码。
- `SSO_EMAIL_DEBUG` 默认仅在 SQLite 开发模式启用；Compose 和 Kubernetes 显式关闭。生产响应不会包含验证码。
- 合并令牌绑定到发起账号的浏览器 Session、账号 ID 和 10 分钟有效期，泄露的 URL 不能在另一浏览器中完成合并。
- 登录同一个账号会取消合并，不创建额外会话；合并成功后撤销两个原账号的 Session、PAT 和来源账号 Grant。
- 注销和合并均不物理删除用户；状态分别为 `deactivated`、`merged`，保留 `deactivated_at` 和 `merged_into_user_id` 供管理员审计。
- 邮箱和第三方身份记录保存 `original_user_id`；合并只改变当前归属，不丢失来源。
- 同一个账号允许多个邮箱及同一 Provider 的多条绑定；同一个 `provider_id + external_id` 仍只能归属一个账号。
- 管理员禁用的第三方身份不能通过后续登录自动恢复；禁用绑定保留记录。
- 第三方新账号不会仅凭“相同邮箱”静默并入现有账号，必须由用户明确发起账号合并。
- Provider 和 SMTP Secret 只允许覆盖写入，管理员 API 只返回 `*_configured` 状态，不返回明文。
- 系统设置和用户管理均要求浏览器 Session、管理员角色；状态变更继续要求 CSRF。
- 管理员编辑用户名、显示名称、角色、状态和重置密码均经过服务端白名单校验；密码使用统一强哈希函数，密码更新与目标用户全部会话撤销处于同一数据库事务。
- 管理员重置 MFA 和禁用邮箱/OAuth 绑定均要求管理员 Session 与 CSRF；MFA 重置与目标会话撤销处于同一事务，操作写入审计事件，身份记录只禁用不删除。
- 管理员用户详情的统一绑定接口只返回渠道、外部标识、来源账号和状态，不返回 OAuth token、Provider Secret、MFA Secret 或密码摘要。
- 最后一个有效管理员不能被降级；管理员不能在当前会话中注销自己；已合并原账号不能重新启用。
- Turnstile 使用 Cloudflare `siteverify`；Cap 使用独立 `siteverify`。Cap 代理只允许 GET/POST 且路径必须位于当前 Site Key 下，避免形成通用反向代理。
- 未配置或未启用的 Provider 不进入公开接口；Cap 前端代码仅在模式启用后动态加载。
- Session、PAT、上游 OAuth state、客户端密钥和 OAuth token 均不保存明文；OAuth token 载荷使用 AES-GCM 加密。
- OAuth 回调地址精确匹配，授权码流程强制 PKCE，上游 OAuth state 单次使用且带过期时间。
- Cookie 使用 `HttpOnly`、`SameSite=Lax`；生产启用 Secure Cookie 时发送 HSTS。响应包含 CSP、Permissions-Policy、X-Frame-Options 等安全头。
- Kubernetes 清单使用非 root、禁止提权、只读根文件系统、资源限制、健康探针和 NetworkPolicy。

## 剩余风险

### 中风险：分布式限流

单个认证流程限制密码/MFA/邮箱验证码失败次数，但尚未实现跨 Pod 的 IP、账号和设备级全局限流。生产环境应在 Ingress/API Gateway 或 Redis 中实现共享限流，并对 `identify`、密码、MFA、验证码重发和 Provider 回调分别设置策略。

### 中风险：SMTP 传输能力

当前使用 Go 标准库 `smtp.SendMail`，适合 STARTTLS SMTP 服务，但不支持 SMTPS 465、OAuth2 SMTP、队列和重试。正式部署建议替换为邮件服务 API 或持久化任务队列；在投递确认前不要消耗验证码流程。

### 中风险：头像存储

头像仍写入本地 PVC。多副本部署应迁移到对象存储或 RWX 卷，并增加恶意内容扫描、配额与孤儿对象清理。

### 中风险：合并冲突策略

合并会保留 ID 较小账号的显示名和头像，仅在字段为空时从另一账号补充；MFA、密码和管理员角色按安全优先规则叠加。涉及同一业务应用的重复 Grant、应用所有权和下游业务数据时，需要业务方定义更细的冲突策略。

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
- 浏览器：验证 new-api 风格密集用户表、用户编辑抽屉、统一绑定列表、设置左侧分栏、密码弹窗和 MFA 二维码弹窗；MFA 验收后已重置临时密钥。
- 浏览器：公开认证页在 `captcha_mode=none` 且 Provider 未配置时不显示未完成的登录项，Cap chunk 未加载。

当前机器未安装 Docker 和 kubectl，因此未执行镜像构建、Compose 启动和 `kubectl apply --dry-run`。这些步骤需在 CI 或具备相应工具的部署机继续验证。
