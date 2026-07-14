# IAM 角色写入：Develop 双写运行手册

## 目标与边界

本手册只覆盖角色/权限迁移工作包的 develop 阶段。当前 legacy API 和 legacy RBAC
仍是唯一事实源。Identity 只保存可恢复的 candidate assignment，不可作为授权决策来源。

支持的旧写入契约：

- `PUT /v1/people/auth`，请求体 `{ "id": number, "auth": string }`
- `POST /v1/plugin-user/change-role`，请求体 `{ "id": number, "role": string }`

不得在本手册的窗口中更改 profile、organization、plugin-user create/update/delete、billing 或
IAM read mode。不得以本手册授权 `identity-primary`。

## 默认安全姿态

以下值必须保持默认，除非单独批准某个 develop 窗口：

```yaml
IDENTITY_IAM_ROLE_WRITE_MODE: "disabled"
IDENTITY_IAM_ROLE_WRITE_DUAL_WRITE_EXECUTION_ENABLED: "false"
IDENTITY_IAM_ROLE_WRITE_ROLLOUT_MODE: "off"
IDENTITY_IAM_ROLE_WRITE_ROLLOUT_ALLOWLIST: ""
IDENTITY_IAM_ROLE_WRITE_ROLLOUT_PERCENTAGE: "0"
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

## Root 保护与回滚

legacy API 继续负责 root 保护。Identity candidate 路径永远不会 materialize `root`：请求目标角色
为 `root`、目标用户含 `root` 或 legacy assignment 含 `root` 时，Identity 写入被跳过并留下可审计
恢复项。不得为测试修改真实 root 或在用账号的角色。

回滚仅改配置，不改数据库：

```yaml
IDENTITY_IAM_ROLE_WRITE_MODE: "disabled"
IDENTITY_IAM_ROLE_WRITE_DUAL_WRITE_EXECUTION_ENABLED: "false"
IDENTITY_IAM_ROLE_WRITE_ROLLOUT_MODE: "off"
IDENTITY_IAM_ROLE_WRITE_ROLLOUT_ALLOWLIST: ""
IDENTITY_IAM_ROLE_WRITE_ROLLOUT_PERCENTAGE: "0"
```

窗口 closeout 至少保留：before/after readiness、测试账号命中证明、旧响应兼容、legacy 与
Identity assignment 对比、operation ledger、一次恢复或等价失败演练、普通用户拒绝、root 保护
和恢复默认关闭的证据。
