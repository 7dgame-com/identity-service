# IAM 角色写入：Develop Identity-native 运行手册

## 范围

本手册仅用于 xrteeth Develop 的专用测试账号。生产环境、教学账号、tmrpp Portainer、组织/校园
成员关系和对象级权限均不在授权范围内。生产必须保持 Legacy authoritative 与全部开关关闭。

## 默认关闭

窗口外必须是：

```yaml
IDENTITY_IAM_ROLE_WRITE_MODE: "disabled"
IDENTITY_IAM_ROLE_WRITE_DUAL_WRITE_EXECUTION_ENABLED: "false"
IDENTITY_IAM_ROLE_WRITE_IDENTITY_NATIVE_EXECUTION_ENABLED: "false"
IDENTITY_IAM_ROLE_WRITE_IDENTITY_NATIVE_TARGET_LEGACY_USER_ID: "0"
IDENTITY_IAM_ROLE_WRITE_ROLLOUT_MODE: "off"
IDENTITY_IAM_ROLE_WRITE_ROLLOUT_ALLOWLIST: ""
IDENTITY_IAM_ROLE_WRITE_ROLLOUT_PERCENTAGE: "0"
IDENTITY_IAM_ROLE_WRITE_POLICY_CHECKSUM: ""
```

readiness 必须同时证明 execution flag、唯一目标、operation ledger、Identity repository、Legacy
只读模型、candidate checksum 与单操作员 selector 可用。任何一项缺失均不可执行。

## Develop 单账号窗口

只在记录脱敏 before 且专用账号 Legacy/Identity assignment 对齐后临时设置：

```yaml
IDENTITY_IAM_ROLE_WRITE_MODE: "identity-native"
IDENTITY_IAM_ROLE_WRITE_IDENTITY_NATIVE_EXECUTION_ENABLED: "true"
IDENTITY_IAM_ROLE_WRITE_IDENTITY_NATIVE_TARGET_LEGACY_USER_ID: "<dedicated-legacy-user-id>"
IDENTITY_IAM_ROLE_WRITE_ROLLOUT_MODE: "canary"
IDENTITY_IAM_ROLE_WRITE_ROLLOUT_ALLOWLIST: "username:<dedicated-root-operator>"
IDENTITY_IAM_ROLE_WRITE_ROLLOUT_PERCENTAGE: "0"
IDENTITY_IAM_ROLE_WRITE_POLICY_CHECKSUM: "<approved-candidate-checksum>"
```

执行顺序固定为：

1. readiness `identityNativeGate.executable=true`；
2. 专用目标 `user -> manager`，请求携带唯一 idempotency key；
3. 重放同一请求，确认 ledger replay 且 assignment 不重复；
4. 验证 Legacy assignment 与 Legacy 写接口调用次数均不变化；
5. 专用目标 `manager -> user`，使用新的 idempotency key；
6. 刷新、退出重登与 user-management 读回；
7. 对齐检查、ledger unresolved=0；
8. 立即恢复默认关闭。

## 强制停止

以下任一情况立即停止并恢复默认关闭：目标不匹配、scope 字段、root、操作者层级不足、checksum
缺失、candidate 缺失、ledger/repository/Legacy read-model 不可用、重复请求产生第二次写、Legacy 发生
任何写入、响应契约变化、unexpected 5xx 或恢复后 assignment 不等于 before。

报告只记录 ID/hash 摘要、计数、状态与 operation key 摘要，不记录密码、token、完整 JWT、完整
checksum、cookie 或原始 permission 集合。
