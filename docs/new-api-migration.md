# new-api 用户迁移映射

参考仓库：`git@github.com:cong0707/new-api.git`，当前基线 `6227b87b6c140edc70eeaf95f8125133c02aa346`。

## 字段映射

| new-api `model.User` | FZ SSO | 处理 |
| --- | --- | --- |
| `Id` | 不直接复用，写入迁移表映射 | SSO 使用自己的 `uint64` 主键，业务引用通过迁移映射表保存 |
| `Username` | `users.username` | 需要限制到 32 字符；重复值先人工解决 |
| `Email` | `users.email` | 统一 `lower(trim(email))`；SSO 要求唯一，重复邮箱必须先确认归属 |
| `Password` | `users.password_hash` | bcrypt 原值可直接导入；首次成功登录自动升级 Argon2id |
| `DisplayName` | `users.display_name` | 空值回退到 `Username` |
| `Role` | `users.role` | `RoleAdminUser` 映射 `admin`，其它映射 `user` |
| `Status` | `users.status` | enabled 映射 `active`，其它映射 `disabled` |
| `CreatedAt` | `users.created_at` | new-api Unix 秒转 `time.Time` |
| `LastLoginAt` | `users.last_login_at` | 0 转为空 |
| `GitHubId` | `upstream_identities(kind=github)` | `external_id` 原值，不复制 client secret |
| `DiscordId` | `upstream_identities(kind=discord)` | 同上 |
| `OidcId` | `upstream_identities(kind=oidc)` | 必须同时确认 OIDC issuer |
| `LinuxDOId` | `upstream_identities(kind=linuxdo)` | 同上 |
| `TelegramId` | `upstream_identities(kind=telegram)` | 专用 Telegram 校验完成后再写入 |
| `WeChatId` | `upstream_identities(kind=wechat)` | 专用微信校验完成后再写入 |
| `AccessToken` | `personal_access_tokens` | 只允许一次性导入并立即哈希，不在日志输出原 token |

`Quota`、`UsedQuota`、`RequestCount`、`Group`、Stripe、邀请额度等网关计费字段不属于 SSO 身份边界，应留在 new-api 或单独的业务库。

## 推荐迁移顺序

1. 以只读账号导出 new-api `users`，保留原始 CSV/JSON，不覆盖原库。
2. 建立 `new_api_user_id -> sso_user_id` 映射，先迁移用户名、邮箱、bcrypt 密码和账号状态。
3. 创建 GitHub、Discord、OIDC、LinuxDO、Telegram、微信 provider 记录，再迁移第三方 subject；发生冲突时停止该条记录，不自动合并账号。
4. 抽样用原密码登录，确认 Argon2id 自动升级、邮箱状态和管理员角色。
5. 最后导入 PAT/AccessToken，迁移期间禁止把明文 token 写入 SQL 日志、终端或 Git。
6. 冻结 new-api 写入，执行增量差异检查后再切换业务服务的 OAuth `issuer`。

## 需要人工确认的风险

- new-api 没有与 SSO 等价的邮箱验证时间字段，迁移账号默认保持“邮箱未验证”。
- 同一邮箱可能对应多个历史账号；SSO 的唯一邮箱约束不能静默合并。
- `OidcId` 只有在 issuer 固定后才有全局意义，不能把不同 OIDC 发行方的同值 subject 合并。
- new-api 的 `AccessToken` 是管理/业务 token，不应自动赋予 SSO 全部 scope；导入时应按用途分成最小 scope。
