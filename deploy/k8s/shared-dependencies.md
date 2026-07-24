# SSO 共享基础设施

SSO 使用独立的 `sso` namespace 和独立的应用、Secret、Service、NetworkPolicy，
但不再创建第二套 PostgreSQL、Redis、Sentinel 或 HAProxy。

## 共享资源

- PostgreSQL：`postgres-pgbouncer.database.svc.cluster.local:5432`
- PostgreSQL 数据库和角色：`sso`，由 `database/postgres` 这个 PGO `PostgresCluster` 创建
- Redis：`redis-primary.new-api.svc.cluster.local:6379`
- Redis 隔离：使用独立键前缀 `xem-sso`；当前 Redis 认证密码与 new-api 共用，不在应用代码中复用 new-api Secret
- HTTP 入口：沿用每个节点上的 Nginx；Nginx 将 `user.xem8k5.top` 转发到 `sso.sso.svc.cluster.local:80`
- DNS：沿用现有 SuperDNS/PowerDNS 调度，不为 SSO 增加独立负载均衡器

## Secret 同步边界

`sso` namespace 不能直接引用其他 namespace 的 Secret。部署时必须把以下值写入
`sso/sso-secrets`，但不能提交到 Git：

- PGO 生成的 `postgres-pguser-sso` 连接信息，组装为 `SSO_DATABASE_DSN`
- `new-api/new-api-internal` 中的 Redis 密码，写入 `SSO_REDIS_PASSWORD`

实际 Secret 由部署操作记录保存“来源和校验方式”，不保存明文值。

## 不再使用的资源

以下清单不属于生产方案，不能重新加入 Kustomize：

- `sso-postgres.yaml`
- `sso-redis.yaml`
- SSO 专用 HAProxy

