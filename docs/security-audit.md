# xem SSO 安全审计修复记录

基于 2026-07-23 审计报告的修复状态。此文档是工程记录，不是生产合规证明；上线前仍需在目标 Kubernetes、PostgreSQL、Redis 和 Ingress 环境执行验收。

## 已修复

- OAuth 同意不再信任客户端 `consent` 参数；批准记录一次性、短期、绑定用户、应用、精确 scope、请求摘要和 state，并与 Grant 在同一事务创建。
- OAuth 仅接受 S256 PKCE；Discovery 只公布 S256。Access/Refresh Token 绑定用户、应用、Grant 和 Token family，检查账号/应用/Grant 状态，刷新令牌使用数据库条件原子消费、旋转并检测并发重放；新增受客户端认证保护的 RFC 7662 风格 introspection 和撤销边界。
- 上游 OAuth state 绑定独立 HttpOnly、SameSite=Lax 浏览器 nonce，并在 callback 原子消费。
- CAP 代理重新构造上游请求，仅允许 `Accept`、`Content-Type`，不转发 Cookie、Authorization、代理头或 Set-Cookie/Location；请求、查询和响应有硬上限。
- PAT scope 使用固定枚举并在服务端逐路由执行；浏览器专属操作要求 Session。
- MFA 备用码使用独立表和 `used_at IS NULL` 原子消费；密码流程在摘要验证前原子检查失败次数。
- UserEmail、Session、PAT、MFA 备用码、上游身份和其它身份关系具备数据库级约束；SQLite 显式开启外键。
- Go 依赖升级到 Go 1.26.5、pgx 5.9.2、quic-go 0.59.1。
- 默认不再由首个注册/上游用户自动成为管理员；必须使用 `SSO_BOOTSTRAP_ADMIN_EMAILS` 明确引导已验证邮箱。
- 应用 Pod 不执行并发 AutoMigrate。`cmd/migrate` 使用版本表执行 schema migration，Pod readiness 会拒绝未迁移 schema。
- 注销、合并、重新启用和角色变化在同一事务写入版本化生命周期 outbox；Webhook 具备签名、重试、死信、管理员重试接口。合并建立 `old_sub -> canonical_sub` 映射。
- 头像目录固定使用 `SSO_DATA_DIR/media/avatars`，不再从数据库 DSN 推导。

## 部署修复

- SSO 默认 2 副本、RollingUpdate、`maxUnavailable=0`、PDB 和跨节点拓扑分布。
- PostgreSQL、Redis 不再由默认 kustomization 创建单实例；使用外部 PostgreSQL Operator/HA Redis，并在 Secret 中配置其地址和 TLS。
- 头像 PVC 示例使用 CephFS `ReadWriteMany`；也可以替换为对象存储适配器。
- `/livez` 只检查进程，`/readyz`/`/healthz` 检查数据库、schema 版本、Redis、签名密钥。
- 镜像示例固定 tag+digest；发布时必须替换占位 digest。生产 registration 默认关闭，完成 SMTP/CAP/管理员配置后再打开。

## 尚需目标环境验证

- `go test ./...`、`go vet ./...`、前端 typecheck/build、`govulncheck` 和审计复现测试需在 CI 每次发布执行。
- 需要在真实 PostgreSQL 隔离级别下执行并发 MFA、Token rotation、迁移幂等和 outbox 抢占测试。
- 需要在目标集群演练 Pod 滚动更新、PostgreSQL/Redis 故障、Ceph 故障、事件重试/死信和回滚。
- master key/OIDC signing key 目前仍需规划多版本轮换窗口；轮换前不得覆盖唯一生产密钥。
- trusted proxy 必须填实际 Ingress/WAF CIDR，不能使用宽泛共享网段。
