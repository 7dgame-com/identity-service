# IAM 角色写入：Identity-native 运行手册

## 范围

Develop 可用本手册验证专用测试账号。生产必须依照独立 production promotion spec 逐级执行，不能
把 Develop PASS 或发布默认关闭镜像解释为生产 owner 已切换。组织/校园成员关系、对象级权限和
root break-glass 均不属于全局 role-write owner。

## 默认关闭

窗口外必须是：

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
IDENTITY_IAM_ROLE_WRITE_POLICY_CHECKSUM: ""
```

readiness 必须同时证明 execution flag、目标范围、operation ledger、Identity repository、Legacy
只读模型、candidate checksum 与操作者 selector 可用。任何一项缺失均不可执行。

目标范围模式互斥：

- `single-target`：配置唯一 `TARGET_LEGACY_USER_ID`，allowlist 为空；
- `allowlist`：单目标 ID 为 0，`TARGET_ALLOWLIST` 是非空正整数 CSV；
- `full`：单目标 ID 为 0、allowlist 为空，且操作者 rollout 必须同时为 `full`。

目标进入 owner 范围前必须已有非空 candidate assignment。candidate 缺失时写入返回
`IAM_ROLE_WRITE_IDENTITY_NATIVE_CANDIDATE_MISSING`，不得自动创建、不得回落 Legacy 写入。

## Develop 单账号窗口

只在记录脱敏 before 且专用账号 Legacy/Identity assignment 对齐后临时设置：

```yaml
IDENTITY_IAM_ROLE_WRITE_MODE: "identity-native"
IDENTITY_IAM_ROLE_WRITE_IDENTITY_NATIVE_EXECUTION_ENABLED: "true"
IDENTITY_IAM_ROLE_WRITE_IDENTITY_NATIVE_TARGET_MODE: "single-target"
IDENTITY_IAM_ROLE_WRITE_IDENTITY_NATIVE_TARGET_LEGACY_USER_ID: "<dedicated-legacy-user-id>"
IDENTITY_IAM_ROLE_WRITE_IDENTITY_NATIVE_TARGET_ALLOWLIST: ""
IDENTITY_IAM_ROLE_WRITE_ROLLOUT_MODE: "canary"
IDENTITY_IAM_ROLE_WRITE_ROLLOUT_ALLOWLIST: "username:<dedicated-root-operator>"
IDENTITY_IAM_ROLE_WRITE_ROLLOUT_PERCENTAGE: "0"
IDENTITY_IAM_ROLE_WRITE_POLICY_CHECKSUM: "<approved-candidate-checksum>"
```

执行顺序固定为：

1. readiness `identityNativeGate.executable=true`；
2. 使用真实登录态调用
   `/v1/plugin-user/role-write-decision?targetLegacyUserId=<id>`，要求
   `writePerformed=false`、`targetOwned=true`、`effectiveSelected=true`、
   `effectiveWriteOwner=identity`；
3. 专用目标 `user -> manager`，请求携带唯一 idempotency key；
4. 重放同一请求，确认 ledger replay 且 assignment 不重复；
5. 验证 Legacy assignment 与 Legacy 写接口调用次数均不变化；
6. 专用目标 `manager -> user`，使用新的 idempotency key；
7. 刷新、退出重登与 user-management 读回；
8. 对齐检查、ledger unresolved=0；
9. 立即恢复默认关闭。

## Production 扩大顺序

只能按 `single-target -> allowlist -> full non-root` 扩大。allowlist 中每个目标必须分别通过
materialization、alignment 和目标级 preview。`full` 前必须完成全范围 reconciliation，要求
P0/P1/P2/mismatch=0、next cursor=null、unresolved=0、root candidate=0；随后才可将目标和操作者
rollout 同时设为 full。未覆盖 organization/campus/scope 写入仍由 Legacy 持有。

## 强制停止

以下任一情况立即停止并恢复默认关闭：目标归属不明确、scope 字段、root、操作者层级不足、checksum
缺失、candidate 缺失、ledger/repository/Legacy read-model 不可用、重复请求产生第二次写、Legacy 发生
任何写入、响应契约变化、unexpected 5xx 或恢复后 assignment 不等于 before。

报告只记录 ID/hash 摘要、计数、状态与 operation key 摘要，不记录密码、token、完整 JWT、完整
checksum、cookie 或原始 permission 集合。
