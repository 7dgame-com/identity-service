# IAM 组织与成员关系写入运行手册

## 目标与边界

本能力只覆盖 `POST /v1/plugin-user/update-user` 请求中显式出现的 `organization_ids`，语义为
全量替换成员关系。字段缺省表示保持不变，`[]` 表示清空，数组元素必须是正整数；Identity
内部会去重并排序。组织创建、更新、删除、独立 bind/unbind、组织 scoped role、campus 与插件绑定
均不在此工作包。

Legacy 始终是本阶段唯一事实源。Legacy organization ID 是对外稳定键；Identity candidate ID
使用 `legacy:<id>` 显式映射。`name` 是小写不可变 slug，`title` 是可变展示名。不得把 candidate
用于 AuthZ，也不得以本手册授权 Legacy 清理、identity-primary 或组织 native write。

## 默认安全姿态

发布和部署必须保持：

```yaml
IDENTITY_IAM_ORG_WRITE_MODE: "disabled"
IDENTITY_IAM_ORG_WRITE_ROUTE_INTEGRATION_ENABLED: "false"
IDENTITY_IAM_ORG_WRITE_DUAL_WRITE_EXECUTION_ENABLED: "false"
IDENTITY_IAM_ORG_WRITE_ROLLOUT_MODE: "off"
IDENTITY_IAM_ORG_WRITE_ROLLOUT_ALLOWLIST: ""
IDENTITY_IAM_ORG_WRITE_ROLLOUT_PERCENTAGE: "0"
```

代码与镜像发布不等于运行窗口获批。只要 route integration 为 false，现有 plugin-user update
路径完全不经过组织兼容层。生产还必须维持 role-write `disabled/off/0%`、AuthZ
`legacy/off/0%`、fallback=true。

## 只读检查

以下内部接口都要求 `X-Identity-Internal-Token`：

```text
GET /internal/iam/organization-write/readiness
GET /internal/iam/organization-write/operations/summary?sinceMinutes=60
GET /internal/iam/organization-write/operations/recent?sinceMinutes=60&limit=50
GET /internal/iam/organization-write/subjects/:legacyUserId/alignment
```

对账等级：P0 为 Legacy 用户不存在，P1 为成员组织 ID 集合不一致，P2 为相同 ID 的 name/title
不一致。候选态不一致不得推进窗口。

## Phase 3：单次 Develop legacy-proxy 窗口

只有在刷新 incidents、调用方、字段/数据 owner 与专用测试资产，并取得单独批准后，才可临时设置：

```yaml
IDENTITY_IAM_ORG_WRITE_MODE: "legacy-proxy"
IDENTITY_IAM_ORG_WRITE_ROUTE_INTEGRATION_ENABLED: "true"
IDENTITY_IAM_ORG_WRITE_DUAL_WRITE_EXECUTION_ENABLED: "false"
IDENTITY_IAM_ORG_WRITE_ROLLOUT_MODE: "off"
IDENTITY_IAM_ORG_WRITE_ROLLOUT_ALLOWLIST: ""
IDENTITY_IAM_ORG_WRITE_ROLLOUT_PERCENTAGE: "0"
```

该窗口仍只调用既有 plugin-user Legacy owner 一次，并原样返回状态码和响应体，不写 Identity
candidate。完成专用账号 replace/empty/preserve、未知组织 422 与普通用户负向回归后，立即恢复默认。

## Phase 4：小范围 dual-write 窗口

只有 Phase 3 closeout 和专用账号基线通过后，另行批准：

```yaml
IDENTITY_IAM_ORG_WRITE_MODE: "dual-write"
IDENTITY_IAM_ORG_WRITE_ROUTE_INTEGRATION_ENABLED: "true"
IDENTITY_IAM_ORG_WRITE_DUAL_WRITE_EXECUTION_ENABLED: "true"
IDENTITY_IAM_ORG_WRITE_ROLLOUT_MODE: "allowlist"
IDENTITY_IAM_ORG_WRITE_ROLLOUT_ALLOWLIST: "legacy:<dedicated-test-user-id>"
IDENTITY_IAM_ORG_WRITE_ROLLOUT_PERCENTAGE: "0"
```

命中的请求必须携带客户端 `Idempotency-Key`。执行顺序固定为：既有 plugin-user owner 写 Legacy
成功 → 重新读取 Legacy 当前组织与成员关系 → 校验请求 ID 集合 → 事务性替换 Identity candidate。
禁止从旧请求 payload 做补偿。未命中 allowlist 的请求仍走 Legacy，不写 candidate。

若 Identity 写入失败，客户端仍得到 Legacy 原响应，但响应头会标记
`X-Identity-IAM-Organization-Write-Identity-Status: candidate-failed`，账本记录
`legacy_completed + compensation=required`。恢复只允许：

```text
POST /internal/iam/organization-write/operations/:operationKey/retry-identity-candidate
```

恢复接口会读取调用时的当前 Legacy 状态并重建 candidate，不重放历史 mutation。恢复后必须再次
执行 alignment，要求 `P0=0、P1=0、P2=0、mismatch=0`。

## 证据与回滚

日志、响应头和账本只保留 correlation ID、operation/idempotency 摘要、目标/操作者摘要、命中类型、
组织数量和状态，不保存 Authorization、Cookie、密码、完整 token 或原始请求/响应 payload。

任何异常立即恢复全部默认值。回滚只关闭配置，不删除 Legacy 数据、不清理 candidate、不切换
AuthZ owner。tmrpp 不通过 Portainer 操作，由用户按既定弹性服务器镜像同步流程处理。
