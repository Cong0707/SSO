# new-api 身份迁移运行手册

这份文档描述上线前的身份迁移。new-api 只保留业务用户投影和本地会话承载层；new-api 的业务用户表、原始 `id`、角色、额度、分组、支付、订阅、工单、日志和业务 Token 不迁入 SSO，也不会被删除或改写。SSO 接管登录身份、密码、邮箱、第三方绑定、资料、MFA 和全局账号状态。new-api 不保留密码登录、注册、找回密码、邮箱验证、第三方登录、绑定、Passkey 或 2FA 的兼容入口。

## 权威边界

| 数据 | 权威系统 |
| --- | --- |
| 密码与已确认邮箱 | SSO `users`、`user_emails` |
| 尚未独立确认的源邮箱 | SSO `legacy_login_identifiers`，仅用于迁移兼容登录，不作为账号绑定 |
| GitHub/Discord/OIDC/LinuxDO/Telegram/微信绑定 | SSO `upstream_identities` |
| 显示名、头像、语言、MFA、账号注销/合并 | SSO |
| new-api 用户主键、角色 1/10/100、分组、额度、钱包、订阅、支付、业务 Token | new-api |

new-api 应增加 `sso_subject` 唯一映射，但不能用 SSO ID 替换现有业务 `users.id`。合并账号通过 SSO 生命周期事件中的 `sub` 与 `canonical_sub` 处理，不能重写历史业务外键。

new-api 接入 SSO 后仍负责建立自己的业务 Session、权限判断、额度扣费和业务审计。邮箱、头像、显示名等资料可以从 OIDC claims 或 UserInfo 获取并做短期缓存，但权威修改入口应跳转到 SSO 的个人信息管理页。

## 字段处理

- `users.id`：写入 SSO 迁移映射表，不复用为 SSO 主键。
- `username`：保留源值；源模型限制为 20 字符，SSO 接受 ASCII 3-64 字符。重复或非法值进入冲突报告，不自动改名。
- `password`：仅接受 bcrypt 摘要，原摘要导入；首次成功登录后由 SSO 升级 Argon2id。空密码账号要求通过已绑定的第三方身份登录后设置密码。
- `email`：统一 `lower(trim())`。只有使用 `-trust-source-emails` 明确确认所有权后才写入 `user_emails`；否则写入 `legacy_login_identifiers`，不显示为账号绑定，也不进入 OIDC 邮箱 claims。重复邮箱同样只保留为迁移兼容登录标识。
- `github_id`、`discord_id`、`oidc_id`、`linux_do_id`、`telegram_id`、`wechat_id`：写入平等的 `upstream_identities`。OIDC 必须显式提供 issuer，不能只凭数字 subject 判断全局唯一。
- `status`、软删除：启用映射为 `active`，其它状态或 `deleted_at` 非空映射为 `deactivated`。注销数据保留，不能重新登录。
- `role`：new-api 的 1/10/100 仍由 new-api 保存。SSO 只有在 `SSO_BOOTSTRAP_ADMIN_EMAILS` 明确列出已验证邮箱时才授予 `admin`，不会把 100 自动提升成 SSO 管理员。
- `AccessToken`：不导入 SSO PAT。它继续属于 new-api 业务 Token，迁移工具不会读取该列。
- Passkey、TOTP、备用码：格式和密钥保护不同，工具只生成需重新注册的警告，不复制密钥或备用码。

## 迁移工具

先执行单独的数据库 schema Job：

```powershell
$env:SSO_DATABASE_DRIVER = "postgres"
$env:SSO_DATABASE_DSN = "host=127.0.0.1 user=sso password=... dbname=sso port=5432 sslmode=verify-full"
$env:SSO_MASTER_KEY_FILE = "data/master.key"
$env:SSO_OIDC_SIGNING_KEY_FILE = "data/oidc-signing.pem"
$env:SSO_ALLOW_KEY_GENERATION = "false"
go run ./cmd/migrate
```

只读预检，不写目标库：

```powershell
go run ./cmd/migrate-new-api `
  -mode dry-run `
  -source-driver mysql `
  -source-dsn 'user:password@tcp(host:3306)/new_api?parseTime=true' `
  -oidc-issuer 'https://oidc.example.com' `
  -report migration-dry-run.json
```

按源用户 ID 导入，命令可重复执行；同一源用户已有映射时跳过。`-after-id` 用于停写期间的追加批次，不能代替带更新时间或变更日志的增量同步。真实切换前必须冻结 new-api 写入并再次执行 dry-run。

```powershell
go run ./cmd/migrate-new-api `
  -mode import `
  -source-driver mysql `
  -source-dsn 'user:password@tcp(host:3306)/new_api?parseTime=true' `
  -oidc-issuer 'https://oidc.example.com' `
  -report migration-import.json
```

源系统确实强制验证过所有存量邮箱且已完成抽样核验时，可以在导入命令增加 `-trust-source-emails`；否则不得启用。

校验映射：

```powershell
go run ./cmd/migrate-new-api -mode verify -batch <批次ID> `
  -source-driver mysql `
  -source-dsn 'user:password@tcp(host:3306)/new_api?parseTime=true'
```

仅在上线前的测试批次、确认没有用户活动时回滚；回滚只删除该批次在 SSO 新建的数据，不触碰源库：

```powershell
go run ./cmd/migrate-new-api -mode rollback -batch <批次ID>
```

## 冲突门槛

以下任一项都必须人工处理后再切换：重复用户名、规范化邮箱、第三方 subject、无效 bcrypt、缺失 OIDC issuer、没有任何可登录身份。Passkey/TOTP 警告不阻止导入，但必须在通知中要求重新注册。

## 切换与回滚

1. 备份 new-api 和 SSO，记录快照水位与迁移批次 ID。
2. 执行最终 dry-run、import、verify，确认没有错误冲突。
3. new-api 后端使用 OIDC Authorization Code + S256 PKCE；以稳定 `sub` 查找原有业务用户并建立本地 Session。
4. SSO 的停用、合并和角色变化通过 outbox webhook 消费；消费方按 `event_id` 幂等，失败进入重试/死信。
5. 停止旧版本后启动硬切换版本。启动检查会拒绝任何仍缺少 `sso_subject` 的活动业务用户；映射完成后删除 new-api 的旧密码/第三方 ID 列和旧绑定、OAuth、Passkey、2FA 表。
6. 确认 `/api/sso/start`、`/api/sso/callback` 和本地业务 Session 正常后开放流量。

### 硬切换边界

- new-api 不提供 old auth 回退开关，也不保留旧认证路由或旧认证页面。
- 迁移完成后不支持通过恢复旧列、旧表或旧前端来回滚认证；需要回退时只能修复 SSO 配置、映射或事件投递，不得重新启用已删除的认证实现。
- new-api 的管理员仍可管理业务角色、分组、额度和业务 Token，但不能在 new-api 修改 SSO 资料、密码、邮箱、绑定或 MFA。
