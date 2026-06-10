# Invitation Reconciliation Runbook

阶段：5 invitation native 前置对账

## 目的

邀请系统切到 identity-service 前，必须先确认旧 Redis 邀请数据和旧 MySQL
邀请注册记录是否一致。本 runbook 只读，不改变用户行为。

## 旧 Redis 数据源

旧主后端使用 Redis hash 保存邀请码：

```text
key: invite:<code>
```

字段：

| 字段 | 含义 |
|---|---|
| `quota` | 邀请码总名额 |
| `remaining` | 当前剩余名额 |
| `expiresAt` | Unix 秒级过期时间 |
| `creatorId` | 创建者旧用户 id |
| `creatorName` | 创建者显示名 |
| `note` | 邀请备注 |
| `createdAt` | Unix 秒级创建时间 |

旧注册验证码使用：

```text
register:code:<email>
register:rate:<email>
```

这两个 key 在 invitation native 注册实现前仍由 legacy/proxy 处理。

## 旧 MySQL 记录

旧主后端 `invitation_record` 结构：

| 字段 | 含义 |
|---|---|
| `id` | 主键 |
| `invite_code` | 邀请码 |
| `inviter_id` | 邀请人旧用户 id |
| `invitee_id` | 被邀请人旧用户 id |
| `created_at` | Unix 秒级注册时间 |

## 启用只读诊断

```bash
IDENTITY_ACCOUNT_INVITATION_DIAGNOSTICS_ENABLED=true
IDENTITY_INTERNAL_API_TOKEN=<internal-service-token>
IDENTITY_INVITATION_REDIS_URL=redis://10.206.16.15:6379/0
LEGACY_DB_HOST=10.206.0.14
LEGACY_DB_PORT=3306
LEGACY_DB_NAME=bujiaban_development
LEGACY_DB_USER=identity_readonly
LEGACY_DB_PASSWORD=...
```

内部端点：

```bash
curl -H "X-Identity-Internal-Token: <internal-service-token>" \
  http://127.0.0.1:8086/internal/account-lifecycle/invitations/diagnostics
```

按邀请码过滤：

```bash
curl -H "X-Identity-Internal-Token: <internal-service-token>" \
  "http://127.0.0.1:8086/internal/account-lifecycle/invitations/diagnostics?code=<invite-code>"
```

## 结果解读

| 字段 | 含义 |
|---|---|
| `sources.legacyRedisConfigured` | 是否已配置旧 Redis |
| `sources.legacyDatabaseConfigured` | 是否已配置旧 MySQL |
| `redis.invitations` | 旧 Redis 里的邀请码快照 |
| `records.byCode` | 旧 MySQL 注册记录按邀请码统计 |
| `consistency.checked` | 两个数据源是否都可对账 |
| `consistency.issues` | 迁移前必须审查的风险项 |

常见 warning：

| 类型 | 处理 |
|---|---|
| `record_count_exceeds_used_quota` | 注册记录数大于 Redis 已使用名额，切 native 前需要人工核对。 |
| `record_without_redis_invite` | MySQL 有历史注册记录但 Redis 邀请已删除/过期，通常可保留为历史记录。 |
| `missing_quota` / `missing_remaining` | Redis 邀请字段不完整，不能导入为 native 邀请。 |
| `legacy_redis_not_configured` | 只配置了数据库，无法执行 Redis 对账。 |
| `legacy_database_not_configured` | 只配置了 Redis，无法核对注册记录。 |

## 导入到 identity DB

导入前必须先跑只读诊断，确认严重 error 已处理。导入脚本默认 dry-run：

```bash
npm run invitation:import -- --dry-run
```

按单个邀请码预览：

```bash
npm run invitation:import -- --code=<invite-code>
```

dry-run 输出：

| 字段 | 含义 |
|---|---|
| `summary.create` | Redis 有、identity DB 没有，执行 `--apply` 会新增 |
| `summary.update` | 两边都有但字段不同，执行 `--apply` 会更新 identity DB |
| `summary.unchanged` | 两边一致 |
| `summary.skip` | 字段缺失或配置缺失，不会写入 |
| `actions[].differences` | 需要更新的字段 |

确认 dry-run 后，才允许执行：

```bash
npm run invitation:import -- --apply
```

安全边界：

- `--apply` 只写 identity DB `identity_invitations`。
- 不写旧 Redis。
- 不扣减邀请码名额。
- 不发送注册验证码。
- 不创建用户。
- 不写旧 MySQL `invitation_record`。

导入后的公开邀请接口仍然保持 legacy/proxy，直到双写管理接口和
`check-invitation` native 通过独立 spec 验收。

## 回滚

只读诊断不改变数据。出现问题时关闭：

```bash
IDENTITY_ACCOUNT_INVITATION_DIAGNOSTICS_ENABLED=false
```

导入到 identity DB 后如需回滚，仅删除或修正 `identity_invitations` 中
`source='legacy-redis'` 的导入数据。旧 Redis 和旧 MySQL 未被脚本修改。

公开邀请接口仍保持 legacy/proxy 或 legacy 原逻辑。
