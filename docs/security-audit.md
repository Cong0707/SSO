# xem SSO 安全审计修复记录

基于 2026-07-23 与 2026-07-24 审计。本文件记录工程当前状态，不是生产合规证明；上线前仍需在目标 Kubernetes、PostgreSQL、Redis、Ceph、Ingress/WAF 和真实 OIDC 消费方上验收。

## 当前边界

SSO 的目标是接管身份，不替换 new-api 的业务账号系统：

- SSO 权威管理密码、邮箱、第三方绑定、头像、显示名、语言、MFA、账号合并、全局注销和全局身份状态。
- new-api 保留本地用户 ID、角色、分组、额度、钱包、订阅、支付、API Token、日志、工单、使用记录和业务 Session。
- new-api 通过 OIDC `sub` 建立 `users.sso_subject` 一类的稳定映射；页面上的个人信息管理入口跳转到 SSO。
- SSO 生命周期事件里的 `role` 是 SSO 自身角色，不能直接写入 new-api 的 `1/10/100` 业务角色。

## 已修复

- OAuth 同意不再信任客户端 `consent` 参数；批准记录一次性、短期、绑定用户、应用、精确 scope、请求摘要和 state，并与 Grant 在同一事务创建。
- OAuth 仅接受 S256 PKCE；Discovery 只公布 S256。
- Access/Refresh Token 绑定用户、应用、Grant 和 Token family，检查账号、应用和 Grant 状态；刷新令牌使用数据库条件原子消费、旋转并检测并发重放。
- `/oauth/token` 和 `/oauth/revoke` 在 HTTP Basic 客户端认证场景下也会先解析表单，Refresh Token 原子消费和撤销逻辑不会被跳过。
- `/oauth/introspect` 不再把已过期 Access Token 因 Refresh Token 有效而标记为 active。
- 上游 OAuth state 绑定独立 HttpOnly、SameSite=Lax 浏览器 nonce，并在 callback 原子消费；上游登录 start 增加按 IP 限流。
- 注册关闭后，未知第三方身份不能自动创建新用户。
- CAP 代理重新构造上游请求，仅允许 `Accept`、`Content-Type`，不转发 Cookie、Authorization、代理头或 Set-Cookie/Location；请求、查询和响应有硬上限。
- PAT scope 使用固定枚举并在服务端逐路由执行；浏览器专属操作要求 Session。
- MFA 备用码使用独立表和 `used_at IS NULL` 原子消费；已启用 MFA 时，普通长期 Session 不能直接调用 setup 覆盖现有 MFA。
- 管理员重置 MFA 时同步删除备用码；账号合并采用来源 MFA 时迁移备用码，不采用时清理来源备用码。
- UserEmail、Session、PAT、MFA 备用码、上游身份和其它身份关系具备数据库级约束；SQLite 显式开启外键。
- Go 依赖升级到 Go 1.26.5、pgx 5.9.2、quic-go 0.59.1，`govulncheck` 当前无 reachable vulnerabilities。
- 默认不再由首个注册/上游用户自动成为管理员；必须使用 `SSO_BOOTSTRAP_ADMIN_EMAILS` 明确引导已验证邮箱。
- 应用 Pod 不执行并发 AutoMigrate。`cmd/migrate` 使用版本表执行 schema migration，Pod readiness 会拒绝未迁移 schema。
- 注销、合并、重新启用和角色变化在同一事务写入版本化生命周期 outbox；Webhook 具备签名、重试、死信、管理员重试接口。合并建立 `old_sub -> canonical_sub` 映射。
- 多个已验证邮箱时，OIDC 标准 claim 稳定输出最早绑定的已验证邮箱为 `email`，并保留完整 `emails` 数组。
- Gin 访问日志跳过 query string，避免 OAuth `code/state/approval` 泄露到应用访问日志。
- new-api 迁移 dry-run 会阻止“无密码、只有邮箱、没有第三方身份”的不可登录用户。
- 已补齐找回密码：只接受 active 账号的已验证邮箱，Captcha 与邮箱/IP 双重限流，未知邮箱返回统一结构；验证码 10 分钟有效且最多尝试 8 次。重置成功后撤销全部 Session、PAT 和 OAuth Token，并记录 `password.reset` 审计事件。

## 部署修复

- SSO 默认 2 副本、RollingUpdate、`maxUnavailable=0`、PDB 和跨节点拓扑分布。
- PostgreSQL、Redis 不再由默认 kustomization 创建单实例；使用外部 PostgreSQL Operator/HA Redis，并在 Secret 中配置其地址和 TLS。
- 头像 PVC 示例使用 CephFS `ReadWriteMany`；也可以替换为对象存储适配器。
- `/livez` 只检查进程，`/readyz`/`/healthz` 检查数据库、schema 版本、Redis、签名密钥。
- 镜像示例固定 tag+digest；发布时必须替换占位 digest。生产 registration 默认关闭，完成 SMTP/CAP/管理员配置后再打开。

## 当前迁移结论

按当前“双轨登录、先接入再逐步简化”的迁移策略，SSO 原先唯一阻止开始改造 new-api 的功能缺口是找回密码；该能力现已补齐，可以进入 new-api 身份边界盘点和 OIDC 双轨接入阶段。以下项目仍需排期，但不再阻止本轮开始 new-api 改造：

- 没有 Passkey/WebAuthn。现有 Passkey 用户无法迁移，只能在 SSO 重新绑定；切换前需要用户通知和回退入口。
- 缺少统一的近期认证/step-up。Session 默认 30 天，密码未配置用户仅凭长期 Session 即可设置首个密码、绑定邮箱、启动账号合并或注销。
- `AccountAlias` 目前只有表和生命周期事件，没有给下游在重建状态或补偿任务中查询 canonical subject 的接口；首阶段可以依赖 OIDC `sub` 映射和生命周期事件，补偿接口后续补齐。
- 生命周期事件字段 `role` 表示 SSO 角色，必须在事件 schema 或消费文档中避免被 new-api 当成业务角色写入。
- Telegram Login Widget 签名数据在 24 小时窗口内可重放；应增加 nonce、一次性消费或更短有效期。
- 用户名唯一性只有应用层 `LOWER(username)` 检查，数据库唯一索引仍区分大小写；并发注册可能产生大小写变体账号。
- 第三方首次登录的用户创建与身份绑定不是一个完整事务；并发首次登录可能产生孤儿用户或短期无绑定 Session。
- OAuth 应用回调地址当前允许任意远程 HTTP；生产应只允许 HTTPS，或仅允许 loopback HTTP 给本地开发客户端。
- `security_email_enabled` 只有字段和 UI，没有真正发送安全提醒邮件。
- SMTP 使用 `smtp.SendMail`，不强制 STARTTLS/TLS，也没有证书校验策略配置。
- Session、AuthFlow、OAuthApproval、OAuthState、Token、已投递 outbox、审计日志和旧头像缺少保留/清理策略。
- 头像重复上传会留下孤儿文件，2 GiB PVC 有被耗尽风险。
- 当前迁移仍是 `CurrentSchemaVersion = 1` 加 `AutoMigrate` 标记，不是严格的逐版本不可变 migration 序列。

## 上线配置项

- 替换所有全零镜像 digest、示例域名、Issuer、PostgreSQL、Redis、Ceph、TLS Secret 和 SMTP/CAP 配置。
- `SSO_TRUSTED_PROXIES` 必须填真实 Ingress/WAF CIDR；否则限流和审计只能看到代理 IP。
- `deploy/k8s/network-policy.yaml` 第二条 egress 只有 ports 没有 `to`，在生产 overlay 中必须限制到实际 PostgreSQL、Redis、SMTP、CAP、OIDC/GitHub 等目标。
- 检查上游 Nginx/Ingress/WAF 访问日志格式，不能记录完整 `$request_uri` 中的 OAuth `code/state`。
- 生产 master key、OIDC signing key 和 Provider Secret 必须有备份、轮换和恢复流程；轮换前不得覆盖唯一生产密钥。

## 仍需目标环境验证

- `go test ./...`、`go vet ./...`、前端 typecheck/build、`govulncheck` 和审计复现测试需在 CI 每次发布执行。
- 需要在真实 PostgreSQL 隔离级别下执行并发 MFA、Token rotation、迁移幂等、上游首次登录和 outbox 抢占测试。
- 需要在目标集群演练 Pod 滚动更新、PostgreSQL/Redis 故障、Ceph 故障、事件重试/死信和回滚。
- 需要用 new-api 测试环境验证 OIDC 登录、`sub -> users.id` 映射、旧 Session 处理、账号停用、账号合并和回滚开关。
