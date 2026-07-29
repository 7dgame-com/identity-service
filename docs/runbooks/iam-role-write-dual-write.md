# IAM 角色写入：Develop 双写运行手册

## 目标与边界

本手册只覆盖角色/权限迁移工作包的 develop 阶段。当前 legacy API 和 legacy RBAC
仍是唯一事实源。Identity 只保存可恢复的 candidate assignment，不可作为授权决策来源。

支持的旧写入契约：

- `PUT /v1/people/auth`，请求体 `{ "id": number, "auth": string }`
- `POST /v1/plugin-user/change-role`，请求体 `{ "id": number, "role": string }`

不得在本手册的窗口中更改 profile、organization、plugin-user create/update/delete、billing 或
IAM read mode。不得以本手册授权 `identity-primary`。

## 全局角色范围边界

Phase 3 与 Phase 4 只支持全局系统角色的兼容契约：`people/auth` 和
`plugin-user/change-role`。它们不实现 organization、campus 或其他业务 scope 的成员关系语义。

即使请求发起者命中 dual-write canary，只要请求体携带以下任一非空字段，identity-service 都必须
直接维持 legacy-only：`organization_id`、`organizationId`、`organization_ids`、
`organizationIds`、`campus_id`、`campusId`、`scope`、`scope_id`、`scopeId`、`scope_type`、
`scopeType`。该请求不会写入 Identity candidate assignment，也不会创建 role-write operation
ledger。日志决策原因应为 `unsupported_scope_legacy_only`，且不得记录原始请求体。

这是一项防串写措施，不代表 organization/campus scope 已迁移。此类语义必须在独立的
organization native-write 工作包中定义模型、授权计算、回滚与回归后，才能申请新的窗口。

## 默认安全姿态

以下值必须保持默认，除非单独批准某个 develop 窗口：

```yaml
IDENTITY_IAM_ROLE_WRITE_MODE: "disabled"
IDENTITY_IAM_ROLE_WRITE_DUAL_WRITE_EXECUTION_ENABLED: "false"
IDENTITY_IAM_ROLE_WRITE_IDENTITY_NATIVE_EXECUTION_ENABLED: "false"
IDENTITY_IAM_ROLE_WRITE_IDENTITY_NATIVE_TARGET_MODE: "single-target"
IDENTITY_IAM_ROLE_WRITE_IDENTITY_NATIVE_TARGET_LEGACY_USER_ID: "0"
IDENTITY_IAM_ROLE_WRITE_IDENTITY_NATIVE_TARGET_ALLOWLIST: ""
IDENTITY_IAM_ROLE_WRITE_ROLLOUT_MODE: "off"
IDENTITY_IAM_ROLE_WRITE_ROLLOUT_ALLOWLIST: ""
IDENTITY_IAM_ROLE_WRITE_ROLLOUT_PERCENTAGE: "0"
IDENTITY_IAM_ROLE_WRITE_CANDIDATE_RESTORE_ENABLED: "false"
IDENTITY_IAM_ROLE_WRITE_CANDIDATE_RESTORE_TARGET_LEGACY_USER_ID: "0"
IDENTITY_IAM_ROLE_WRITE_RECOVERY_DRILL_ENABLED: "false"
IDENTITY_IAM_ROLE_WRITE_RECOVERY_DRILL_TARGET_LEGACY_USER_ID: "0"
```

`IDENTITY_IAM_ROLE_WRITE_LEGACY_API_BASE_URL` 可省略；服务会依次回退到
`IDENTITY_IAM_PLUGIN_USER_WRITE_LEGACY_API_BASE_URL` 和
`IDENTITY_ACCOUNT_LIFECYCLE_LEGACY_API_BASE_URL`。显式配置仍优先，避免将来重构时改变上游。

`IDENTITY_IAM_ROLE_WRITE_POLICY_CHECKSUM` 必须是已经导入 Identity DB 的 64 位 candidate
policy checksum。checksum 缺失、candidate 不存在、ledger 不可用、Identity DB 不可用、legacy
reader 不可用或 rollout 未选中时，dual-write 一律不可执行或回退 legacy-proxy。

## Phase 3：legacy-proxy 窗口

仅得到单独批准后，在 develop 临时设置：

```yaml
IDENTITY_IAM_ROLE_WRITE_MODE: "legacy-proxy"
IDENTITY_IAM_ROLE_WRITE_LEGACY_API_BASE_URL: "http://api-d:80"
```

执行专用测试账号的 grant、refresh、revoke、relogin 与普通用户负向回归。服务保持旧 HTTP
方法、请求体、状态码和响应体；legacy API 继续做授权、目标账号与 root 校验。完成后恢复
`IDENTITY_IAM_ROLE_WRITE_MODE: "disabled"`。

## Phase 4：dual-write 窗口

仅在 Phase 3 closeout、develop CI 和专用账号基线都通过后，单独批准以下小窗口：

```yaml
IDENTITY_IAM_ROLE_WRITE_MODE: "dual-write"
IDENTITY_IAM_ROLE_WRITE_DUAL_WRITE_EXECUTION_ENABLED: "true"
IDENTITY_IAM_ROLE_WRITE_ROLLOUT_MODE: "canary"
IDENTITY_IAM_ROLE_WRITE_ROLLOUT_ALLOWLIST: "username:<dedicated-test-operator>"
IDENTITY_IAM_ROLE_WRITE_ROLLOUT_PERCENTAGE: "0"
IDENTITY_IAM_ROLE_WRITE_POLICY_CHECKSUM: "<approved-64-char-checksum>"
```

双写顺序固定为：legacy 成功后读取 legacy 当前 assignment，再写入 Identity candidate。任何
Identity 写入失败都会保留 legacy 结果，记录 `legacy_completed`、`compensation=required`，不重放
旧写入请求。通过内部恢复接口以旧库当前 assignment 重建 candidate：

```text
POST /internal/iam/role-write/operations/:operationKey/retry-identity-shadow
```

该接口需要 `X-Identity-Internal-Token`。操作记录和日志不得携带 Authorization、Cookie、密码、
完整 token 或原始 payload。

### 等价补偿演练

不要为了制造 Identity 写失败而关闭数据库、破坏 candidate policy 或修改真实用户。代码提供一个
默认关闭的内部等价补偿演练入口，它只准备 `legacy_completed + compensation=required` 的可恢复
ledger 状态，**不调用 Legacy 写接口**：

```text
POST /internal/iam/role-write/recovery-drill/prepare
```

该入口必须取得独立 Develop-only 批准，并同时满足：

- `IDENTITY_IAM_ROLE_WRITE_RECOVERY_DRILL_ENABLED=true`；
- `IDENTITY_IAM_ROLE_WRITE_RECOVERY_DRILL_TARGET_LEGACY_USER_ID` 只指向专用测试账号；
- role-write 已处于获批的 dual-write/canary/0% 窗口，readiness gate 为 executable；
- 目标在 Legacy 中恰好为 `user`，且不存在 root assignment；
- 内部 token 有效。

准备接口使用“目标 + 已审 policy checksum”的确定性 operation key；重复调用只返回原 operation，
不会产生多条待恢复账本。随后使用返回的 operation key 调用既有
`retry-identity-shadow`，确认它从当前 Legacy assignment 重建 Identity candidate，且 Legacy 写接口
调用次数保持 0。报告只保留 operation key 摘要和目标摘要，不保留原始内部 token。

演练结束必须把上述两个演练变量恢复为 `false/0`，并同时恢复 role-write 的
`disabled/false/off/空/0%`。本演练只能证明补偿执行器和真实存储链路，不替代正常
`user -> manager -> user` dual-write 窗口。

### 单账号 Identity candidate restore

如果一次已完成的窗口留下“Legacy 已恢复、Identity candidate 仍多出旧角色”，不得重放历史
grant/revoke，也不得重新导入整份 candidate policy。使用默认关闭的单账号恢复入口：

```text
POST /internal/iam/role-write/subjects/:legacyUserId/restore-candidate
body: { "policyChecksum": "<approved-64-char-checksum>" }
```

该入口只在取得独立 Develop-only 批准后临时配置：

```yaml
IDENTITY_IAM_ROLE_WRITE_CANDIDATE_RESTORE_ENABLED: "true"
IDENTITY_IAM_ROLE_WRITE_CANDIDATE_RESTORE_TARGET_LEGACY_USER_ID: "<exact-dedicated-test-user-id>"
```

恢复必须同时满足以下条件，否则 fail-closed 且不写入：

- IAM 为 `readonly`，AuthZ 为 `legacy/off/空/0%` 且 fallback 保持开启；
- role-write 为 `disabled/false/off/空/0%`，运行配置中不得设置 role policy checksum；
- recovery drill 保持关闭；
- 请求目标与配置的唯一目标完全一致，并携带内部 token 和已审 64 位 checksum；
- before alignment 的唯一 blocker 是 `candidate-assignment-mismatch`；
- Legacy/candidate 均无 policy 外 assignment、无 root、无 unresolved role-write operation。

写入来源只能是调用时读取到的 **当前 Legacy assignment**，写入范围只能是该账号的 Identity
candidate assignment。不得写 Legacy、不得创建或改写 operation ledger、不得执行 permission union、
不得重放历史 mutation。响应只返回账号/checksum 摘要、before/after 计数和安全标记；完整 checksum
只存在于内部请求，不写入报告或日志。

恢复后必须再次执行只读 alignment，要求 assignment 集合完全相等、unresolved=0、无 root、
`passed=true`。随后立即把恢复变量还原为 `false/0`；若 postcheck 未通过，role-write 仍保持关闭，
不得申请运行时窗口。

## Root 保护与回滚

legacy API 继续负责 root 保护。Identity candidate 路径永远不会 materialize `root`：请求目标角色
为 `root`、目标用户含 `root` 或 legacy assignment 含 `root` 时，Identity 写入被跳过并留下可审计
恢复项。不得为测试修改真实 root 或在用账号的角色。

回滚仅改配置，不改数据库：

```yaml
IDENTITY_IAM_ROLE_WRITE_MODE: "disabled"
IDENTITY_IAM_ROLE_WRITE_DUAL_WRITE_EXECUTION_ENABLED: "false"
IDENTITY_IAM_ROLE_WRITE_IDENTITY_NATIVE_EXECUTION_ENABLED: "false"
IDENTITY_IAM_ROLE_WRITE_IDENTITY_NATIVE_TARGET_MODE: "single-target"
IDENTITY_IAM_ROLE_WRITE_IDENTITY_NATIVE_TARGET_LEGACY_USER_ID: "0"
IDENTITY_IAM_ROLE_WRITE_IDENTITY_NATIVE_TARGET_ALLOWLIST: ""
IDENTITY_IAM_ROLE_WRITE_ROLLOUT_MODE: "off"
IDENTITY_IAM_ROLE_WRITE_ROLLOUT_ALLOWLIST: ""
IDENTITY_IAM_ROLE_WRITE_ROLLOUT_PERCENTAGE: "0"
IDENTITY_IAM_ROLE_WRITE_CANDIDATE_RESTORE_ENABLED: "false"
IDENTITY_IAM_ROLE_WRITE_CANDIDATE_RESTORE_TARGET_LEGACY_USER_ID: "0"
IDENTITY_IAM_ROLE_WRITE_RECOVERY_DRILL_ENABLED: "false"
IDENTITY_IAM_ROLE_WRITE_RECOVERY_DRILL_TARGET_LEGACY_USER_ID: "0"
```

窗口 closeout 至少保留：before/after readiness、测试账号命中证明、旧响应兼容、legacy 与
Identity assignment 对比、operation ledger、一次恢复或等价失败演练、普通用户拒绝、root 保护
和恢复默认关闭的证据。
