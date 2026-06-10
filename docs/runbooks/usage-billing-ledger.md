# Usage Billing Ledger Runbook

阶段 5.5 将登录审计事件转换为影子使用量账本。该能力默认关闭，只服务未来计费对账，不实际扣费，不限制登录，不改变内容访问。

## 配置

```text
IDENTITY_USAGE_BILLING_SHADOW_ENABLED=false
IDENTITY_USAGE_BILLING_DRY_RUN=true
IDENTITY_USAGE_BILLING_LOGIN_RULE=successful-login-v1
IDENTITY_USAGE_BILLING_FREE_LOGIN_QUOTA=0
IDENTITY_USAGE_BILLING_SUBJECT_STRATEGY=user
IDENTITY_USAGE_BILLING_REPLAY_BATCH_SIZE=500
IDENTITY_USAGE_BILLING_INTERNAL_API_TOKEN=<internal token>
```

`IDENTITY_USAGE_BILLING_INTERNAL_API_TOKEN` 可省略并复用 `IDENTITY_INTERNAL_API_TOKEN`。

## 安全原则

- disabled 时不写账本。
- dry-run 不写账本和影子余额。
- apply 只写 Identity_DB。
- 登录、refresh、注册、密码、邮箱、邀请和内容业务不依赖影子账本。
- 报表必须标记为 shadow/non-billing。

## Dry-run

```bash
curl -X POST https://identity.example.com/internal/usage-billing/replay \
  -H 'X-Identity-Internal-Token: <token>' \
  -H 'Content-Type: application/json' \
  -d '{"dryRun":true,"afterId":0,"limit":100}'
```

## Apply shadow ledger

仅在 develop 验证通过后开启：

```text
IDENTITY_USAGE_BILLING_SHADOW_ENABLED=true
IDENTITY_USAGE_BILLING_DRY_RUN=false
```

然后执行：

```bash
curl -X POST https://identity.example.com/internal/usage-billing/replay \
  -H 'X-Identity-Internal-Token: <token>' \
  -H 'Content-Type: application/json' \
  -d '{"dryRun":false,"afterId":0,"limit":100,"rebuildBalance":true}'
```

## 验证

- `summary.createdLedgerRecords` 只随新事件增加。
- 重复执行同一批次时 `duplicateLedgerRecords` 递增，`createdLedgerRecords` 不重复增加。
- `GET /internal/usage-billing/subjects/user/legacy:<id>/balance` 可以查询影子余额。
- `GET /internal/usage-billing/ledger` 可以查看最近账本明细。

## 回滚

```text
IDENTITY_USAGE_BILLING_SHADOW_ENABLED=false
IDENTITY_USAGE_BILLING_DRY_RUN=true
```

停止 replay 调用即可。保留 `usage_billing_ledger`、`account_usage_balance_shadow` 和 `usage_billing_replay_runs`，不要删除阶段 3.5 登录审计事件。

## 补救

| 问题 | 补救 |
|---|---|
| 账本重复 | 依赖 `ledger_key` 唯一键去重，重建 shadow balance。 |
| 计费口径错误 | 停止 apply，发布新 rule version 后重新 replay。 |
| 影子余额不准 | 清空并从 `usage_billing_ledger` 重建。 |
| 报表与人工抽样不一致 | 标记 run failed，暂停进入下一阶段。 |
| 外部系统误读 shadow 数据 | 立即下线外部读取，确认所有结果只作为 shadow/non-billing。 |
