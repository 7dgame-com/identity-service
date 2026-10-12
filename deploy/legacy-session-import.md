# 旧 Yii Redis 登录态导入

导入器只读取离线 JSON 和身份私库，不连接 Redis，不签发 token，不改变原过期时间。账号快照必须已经导入，所有 `user_id` 必须是已存在的安全整数。默认 dry-run；只有 `NODE_ENV=staging` 且显式 `--apply` 才提交整个批次。任何账号缺失、身份冲突或客户端范围冲突都会回滚整批。

导出应在旧账号/会话写入口 drain 后生成最终一致快照，并在 Identity 接收会话写入前导入。旧 Redis 消费刷新凭据会删除记录，通常没有删除墓碑，因此不能把本工具当作“旧、新两个会话主源并行写入”的增量同步器。预演使用 dry-run；正式导入使用最终快照。若预导入过期的 staging 快照，先用隔离恢复流程重建 staging 数据，不允许本工具覆盖运行中的身份会话。

离线 manifest 的形状如下（示例值均为占位符）：

```json
{
  "version": 1,
  "sessions": [
    {
      "keyEncoding": "plain",
      "key": "example-offline-refresh-token",
      "user_id": 24,
      "session_id": "legacy-family-24",
      "username": "example",
      "created_at": 1700000000,
      "expires_at": 1700604800,
      "revoked_at": null,
      "ip_hash": null,
      "user_agent_hash": null,
      "client": null
    }
  ]
}
```

`key` 是 Redis record 的 `key` 属性值，不能包含 Redis 存储键前缀。每条必须显式声明 `keyEncoding`：`plain` 表示原 refresh token；`sha256-hex` 表示已计算好的 64 位十六进制 SHA-256。即使原明文恰好是 64 位十六进制，也必须按 `plain` 处理，工具不猜测。保留原 `session_id`、`created_at`、`expires_at`、`revoked_at`；时间可用 Unix 秒（支持毫秒精度小数）或带 `Z` 的 ISO UTC 时间。未撤销必须明确写 `null`，导出器应把旧记录中表示未撤销的空值/0 归一化为 `null`。不补默认寿命，不使用导入时间代替原签发时间。

已脱敏的 `ip_hash` / `user_agent_hash` 原样导入。若只能导出旧 `ip` / `user_agent`，工具会计算 SHA-256，且每种信息只能选原文或 hash 之一；报告不会输出这些值。存在 `replaced_by_hash` 时可以明确携带，不会恢复为未轮换状态。

有客户端约束的记录必须携带 `client: { "client_id": "unity", "scopes": ["openid", "profile"], "legacy_subject": "24" }`，并已经应用 `identity-wechat-oauth-schema.sql`。没有约束的 Yii 平台记录显式使用 `client: null`。绑定写入 `identity_oauth_session_bindings`；同一会话既有的客户端与 scope 范围不能被扩大。UUID 主体、base64url hash 的 auth-service 会话由其专用导入器处理，不接受伪装为 `sha256-hex` 的输入。

```bash
# 先 build；数据库变量明确指向身份私库。
NODE_ENV=staging IDENTITY_DATA_SOURCE=identity \
  node dist/scripts/legacy-session-import.js --file=/secure/offline/yii-sessions.json --dry-run

# 比对报告后，使用同一最终快照显式提交。
NODE_ENV=staging IDENTITY_DATA_SOURCE=identity \
  node dist/scripts/legacy-session-import.js --file=/secure/offline/yii-sessions.json --apply
```

还需提供 `IDENTITY_DB_HOST/PORT/NAME/USER/PASSWORD`。报告只包含条数；不包含 refresh、token hash、用户信息或密钥。输入上限为 64 MiB/100000 条。重复运行不修改已存在的 hash；即使旧快照写着未撤销，也不会覆盖 Identity 中已轮换/撤销的记录。已被撤销的会话族、账号级撤销时间覆盖的旧凭据也不会重新插入。过期或已撤销的源记录可以保留审计状态，但不能通过正常 refresh 验证。

旧 access token 的有限兼容使用 `IDENTITY_LEGACY_JWT_CONFIG_FILE`，参考 `legacy-jwt-trust.example.json`。示例时间故意已过期；部署时应替换为真实切换的 UTC 截止时间、公钥路径、原始 issuer 与 audience。旧 Yii 使用 `request.hostInfo` 作为 issuer，audience 来自 `JWT_AUDIENCE` 或原 API 域名；多个历史域名需要分别列明确切配置，不能以通配符扩大信任。只挂载旧公钥，不复制旧签名私钥。

旧 Lcobucci JWT 的 `aud` 可能是数组，`iat/nbf/exp` 可能是含微秒小数的数值。兼容验签需接受有限数值时间及单 audience 的 string/array 形状，同时严格核对配置的 audience 列表、ES256、issuer、原 exp/nbf、`issuedBefore` 与 `acceptUntil`；不能因为形状不同而跳过验证。过了兼容窗口后移除旧信任配置。对已经通过旧 access 验签的账号，仍须检查身份私库的当前状态、权限与撤销记录。
