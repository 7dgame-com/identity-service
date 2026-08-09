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
IDENTITY_IAM_ORG_WRITE_CANDIDATE_MATERIALIZATION_ENABLED: "false"
IDENTITY_IAM_ORG_WRITE_CANDIDATE_MATERIALIZATION_TARGET_LEGACY_USER_ID: "0"
```

代码与镜像发布不等于运行窗口获批。只要 route integration 为 false，现有 plugin-user update
路径完全不经过组织兼容层。生产还必须维持 role-write `disabled/off/0%`、AuthZ
`legacy/off/0%`、fallback=true。

## 只读检查

公开 `/health` 会返回脱敏的 `capabilities.organizationWrite`，包括 mode、route integration、
dual-write execution、rollout mode、allowlist 数量、percentage、事实源和 native 支持状态；不会暴露
allowlist 主体。双域默认关闭门禁可直接执行：

```sh
npm run iam:organization-write:public-gate -- \
  --urls=https://identity.d.xrteeth.com/health,https://identity.d.tmrpp.com/health \
  --expected-revision=<full-develop-git-sha>
```

命令默认要求两个域名均为 `disabled / false / false / off / 0%`、Legacy 事实源且 native 不支持。
窗口期间必须显式传入期望值；不得以配置截图代替此 request-level 公共证据。

以下内部接口都要求 `X-Identity-Internal-Token`：

```text
GET /internal/iam/organization-write/readiness
GET /internal/iam/organization-write/subjects/:legacyUserId/decision
GET /internal/iam/organization-write/operations/summary?sinceMinutes=60
GET /internal/iam/organization-write/operations/recent?sinceMinutes=60&limit=50
GET /internal/iam/organization-write/subjects/:legacyUserId/alignment
```

`subjects/:legacyUserId/decision` 只计算当前 target 是否命中 allowlist 以及 mode gate 是否 executable，
返回脱敏 target fingerprint，不读取 Legacy、不写 Legacy/Identity。它只能用于写前 preflight；真正的
request-level route hit 仍必须由获批 mutation 的响应 header/日志/ledger 证明。

容器或受控内网入口中可用只读窗口门禁一次核验 health revision、内部 readiness、目标 decision、
近期 ledger 风险以及（dual-write 时）alignment。token 只允许通过环境变量传入，脚本不接受
`--token`，且只发送 GET：

```sh
IDENTITY_IAM_INTERNAL_API_TOKEN='<runtime-secret>' \
npm run iam:organization-write:window-gate -- \
  --adapter-url=http://127.0.0.1:8086 \
  --legacy-user-id=<approved-dedicated-user-id> \
  --expected-mode=legacy-proxy \
  --expected-revision=<full-develop-git-sha> \
  --expected-allowlist-count=1 \
  --since-minutes=60
```

dual-write 窗口另加 `--expected-mode=dual-write --require-alignment`。门禁遇到 pending/failed
operation、required/failed compensation、未命中 allowlist、不可执行 mode gate 或 alignment
任一 P0/P1/P2/mismatch 非零都会失败。输出不得保存 token，也不替代 Dedicated Test Assets 的
人工批准或真实 mutation 证据。

对账等级：P0 为 Legacy 用户不存在，P1 为成员组织 ID 集合不一致，P2 为相同 ID 的 name/title
不一致。候选态不一致不得推进窗口。

## 6.9：单目标 candidate materialization 契约

本能力只用于修复一个已批准专用账号的 `identity-candidate-snapshot-missing`。它是
**Identity candidate-only 写**：Legacy 只读且继续是唯一事实源，不改变 AuthZ 输入，不授权
dual-write、organization native write 或 owner 切换。当前本地实现和本节文档均不等于部署或运行
批准；6.9 的 P1 在取得独立的 Identity candidate-only 写批准并形成真实运行证据前仍未关闭。

默认必须保持：

```yaml
IDENTITY_IAM_ORG_WRITE_CANDIDATE_MATERIALIZATION_ENABLED: "false"
IDENTITY_IAM_ORG_WRITE_CANDIDATE_MATERIALIZATION_TARGET_LEGACY_USER_ID: "0"
```

`TARGET_LEGACY_USER_ID` 只能临时设为一个已批准 Dedicated Test Subject 的正整数 Legacy user ID；
不接受 allowlist、多目标、百分比或全量范围。`root`、非活跃账号、Legacy 不存在账号、已有 candidate
快照或存在 unresolved organization operation 的账号均 fail closed。精确目标之外的 preview/apply
都必须拒绝。

内部契约均要求 `X-Identity-Internal-Token`：

```text
GET  /internal/iam/organization-write/subjects/:legacyUserId/materialization-preview
POST /internal/iam/organization-write/subjects/:legacyUserId/materialize-candidate
```

建议先只配置精确 target、保持 `...MATERIALIZATION_ENABLED=false` 调用 preview。此时 preview
必须返回 `mutation=false`、`identityCandidateWritePerformed=false`，并以
`candidate-materialization-disabled` 保持 `executable=false`；可供审核的字段仅包括 target
fingerprint、当前 Legacy snapshot 的 `expectedSnapshotFingerprint`、组织数量、P0/P1/P2/mismatch、
unresolved operation 数量与 blockers。不得从 preview 响应推导已获 apply 权限。

获批 apply 窗口才可临时把 `...MATERIALIZATION_ENABLED=true`。POST body 必须精确为 preview
审核过的 64 位十六进制 fingerprint：

```json
{"expectedSnapshotFingerprint":"<reviewed-64-hex-legacy-snapshot-fingerprint>"}
```

同时必须携带 1–180 字符的 `Idempotency-Key`（或值相同的 `X-Idempotency-Key`，两者冲突时拒绝）。
apply 会重新读取当前 Legacy；fingerprint 已变化时拒绝，不得使用历史请求 payload。相同
idempotency key 只允许对应相同 snapshot：已完成且对齐时返回 `idempotentReplay=true`，不同
snapshot 复用必须冲突。写范围仅限 Identity 的 organization candidate、ID map、membership
snapshot/membership candidate 与 operation ledger；不得写 Legacy 表。

Apply 由 MySQL subject-scoped advisory lock 串行同一 Legacy subject 的所有 idempotency key；
锁不可用立即返回冲突，且不得读取 Legacy 或写 candidate。pending operation 使用五分钟 lease，
claim digest 只保存在现有 ledger metadata 内；过期的同 fingerprint operation 可由同 key reclaim，
terminal transition 必须同时满足 mode、pending、claim digest 与未过期 lease 的 CAS。Candidate 事务
写入前还会 `FOR UPDATE` 校验同一 claim；旧 worker、未知 mode/status/compensation 或非法状态组合
一律 fail closed。锁释放异常会销毁持锁连接，不得把未知锁状态的连接放回连接池。

成功后的同步 postcheck 必须是 `P0=0、P1=0、P2=0、mismatch=0`，且响应 safety 必须证明
`legacyWritePerformed=false`、`historicalMutationReplayed=false`、
`legacyRemainsAuthoritative=true`、`authzInputChanged=false`、
`writeScope=identity-candidate-only`。operation evidence 至少保留：批准引用、镜像完整 revision、
窗口前/中/后的 flags、preview target/snapshot fingerprint、组织数量、POST 状态、
`operationKeyDigest`、idempotency digest、`candidate-materialization` mode、before/after 对账计数、
ledger status、Identity status、compensation status 与 error code。证据不得保存内部 token、原始
idempotency key、Authorization/Cookie、原始请求/响应 payload 或未脱敏主体资料。

Candidate 事务提交后会重新读取 fresh Legacy，再次确认 subject 仍存在、active、非 root，且
fingerprint 与本次审核值一致；随后才允许以 `P0/P1/P2/mismatch=0` 完成 ledger。失败时不得调用 dual-write 专用的
`POST /internal/iam/organization-write/operations/:operationKey/retry-identity-candidate`。materialization
只能通过同一精确 target 的受控 POST 恢复。Identity 写前失败（`failed+none`）只能以同一 key 和
原 fingerprint 重试；仍在有效 lease 内的 pending 无论 fingerprint 是否相同都拒绝并发接管。Pending
lease 过期后，若 Legacy 已变化，必须先重新 preview 并审核当前 fingerprint，才可用同一 key 以
expected-old fingerprint + stale cutoff 的 CAS reclaim；ledger 保留 previous/current fingerprint
digest，旧 claim 随即失效。Candidate 已提交但 fresh postcheck 失败时 ledger 必须标记
`compensation=required`；若 Legacy 此后变化，同样必须先审核当前 fingerprint 才可从当前 Legacy
修复。所有恢复都重新读取当前 Legacy，不重放历史 mutation。Operation 无法安全续接、或 retry 后
仍不为全零时立即停止并保留账本，不得换 key 绕过 unresolved operation。

无论成功或失败，窗口结束立即回收：

```yaml
IDENTITY_IAM_ORG_WRITE_CANDIDATE_MATERIALIZATION_ENABLED: "false"
IDENTITY_IAM_ORG_WRITE_CANDIDATE_MATERIALIZATION_TARGET_LEGACY_USER_ID: "0"
IDENTITY_IAM_ORG_WRITE_MODE: "disabled"
IDENTITY_IAM_ORG_WRITE_ROUTE_INTEGRATION_ENABLED: "false"
IDENTITY_IAM_ORG_WRITE_DUAL_WRITE_EXECUTION_ENABLED: "false"
IDENTITY_IAM_ORG_WRITE_ROLLOUT_MODE: "off"
IDENTITY_IAM_ORG_WRITE_ROLLOUT_ALLOWLIST: ""
IDENTITY_IAM_ORG_WRITE_ROLLOUT_PERCENTAGE: "0"
```

### Candidate schema / DDL 批准边界

preview、readiness、alignment、ledger 和 materialization apply 均不再 lazy ensure schema。
Preview/readiness 只查询 `information_schema.tables`，确认 organization candidate、Legacy ID map、
membership candidate、membership snapshot 与 operation ledger 五张 Identity 表已存在；缺表或探测
失败只返回 `schema-not-ready` / `schema-readiness-unavailable` blocker。Apply 在任何 Legacy 读取或
Identity 写入前复核同一门禁并返回 503，不执行 `CREATE`、`ALTER` 或其他 DDL。

现有 dual-write 的首次写路径仍保留历史 lazy create 行为，但 materialization 的 default-off
preview/apply 不会调用该路径。若目标环境缺少上述五表或需要 schema 修订，立即停止并另行申请
精确 Identity candidate DDL 批准；不得借 preview、启动、内部 ensure 或 apply 顺带建表，更不得对
Legacy schema 执行 DDL。

## 7.2：离线全范围 organization reconciliation validator

本地 CLI 只校验调用方事先提供的 JSON 快照，不访问网络、数据库或 stdin，不接受 URL/token
参数，也不会采集数据或 materialize candidate：

```sh
npm run iam:organization-reconciliation:validate -- \
  --input=<explicit-local-json-file>
```

输入上限 16 MiB，CLI 在读取前先验证路径为普通本地文件并检查大小，读取后再次校验 byte count。
根输入必须包含 collector contract/hash、每次运行随机的高熵 `evidenceNonce`、logical snapshot/window、
两侧共同 source revision 与各自 snapshot ID。必须完整包含以下八个 surface；每个 surface 必须同时
提供 `legacy` 与 `identity` 两侧，每侧必须包含 `records`、与根 envelope 一致的非空
`sourceVersion`/snapshot ID，以及显式终止的 `nextCursor: null`。空字符串、空白字符串和非空 cursor
均不是终止证据：

| 输入字段 | 必要记录键/决策面 |
|---|---|
| `organizationDirectory` | `legacyOrganizationId`、name/title、active |
| `organizationMappings` | Legacy organization ID 到 Identity candidate ID 的一对一映射 |
| `memberships` | subject + Legacy organization ID + active |
| `organizationScopedRoles` | subject + Legacy organization ID + role + active |
| `pluginBindings` | plugin + binding + organization scope + active |
| `pluginVisibility` | subject + plugin + organization context 的 allow/deny |
| `campusContexts` | subject + campus + organization context 的 allow/deny |
| `effectiveDecisions` | subject + organization context + resource + capability 的最终 allow/deny |

surface、任一侧、collector envelope、共同 source revision、snapshot ID 或 pagination state 缺失，
`nextCursor` 非 null，或同一侧出现重复业务键，均为 coverage blocker。每侧 collection 必须从
`requestCursor=null` 开始，连续证明 page number、request/next cursor、record offset/count、page
count、总 record count、逐页及聚合 HMAC，并以 `nextCursor=null` 结束；任一断链、截断、hash
不符或 count 不符均 fail closed。Organization mapping 还必须双向一一，所有跨 surface 的 active
organization/subject/plugin/campus/decision 引用必须可解析，禁止把孤立记录当作完整覆盖。

validator 的比较策略固定为 `pairwise-no-union`：Legacy 与 Identity 独立形成同键记录/决策后逐项
比较，绝不把两边 organization、role、plugin 或 allow 集合求并集作为有效结果。枚举两侧 key 只为
发现缺失/多余记录，不是授权 union。主要分级为：

- P0：Identity-only 记录/决策、organization ID map 或 plugin scope 冲突、authorization context
  冲突，以及 `Legacy deny / Identity allow`；
- P1：Identity 缺记录/决策、directory/member/scoped-role 语义冲突，以及
  `Legacy allow / Identity deny`；
- P2：仅限显式 allowlist 的 organization directory `title` 展示差异；任意通用 metadata 已从输入
  契约移除，source revision 不一致属于 coverage blocker，不得降级成 P2/info。

输出固定声明 `dryRun=true`、`writeSideEffects=none`、`evidencePolicy=hash-only`、
`assuranceScope=collector-envelope-self-consistency`、`externalProvenanceRequired=true`。实体、两侧值和
source version 只使用本次 nonce 的 HMAC/hash，不回显 raw subject、organization ID/name、binding
或 decision 上下文；nonce 缺失/非法时直接短路敏感比较，不以可预测 key 生成实体 hash。原始输入
本身仍可能含这些值，必须保留在获批的本地临时边界内，不得提交仓库或复制到报告。参数/文件/
JSON/schema 错误退出 2。`staticChecksPassed=true` 只表示 envelope 内部一致且没有静态 P0/P1；当前
实现没有可信 collector attestation verifier，因此固定返回
`externalProvenanceVerified=false`、`safetyGate.passed=false`、`blocksDualWrite=true`，并以
`external-provenance-required` 退出 1。输入中不存在可伪造的 provenance 布尔开关；只有未来实现并
验证外部可信 attestation 后，CLI 才可能退出 0。
CLI 的通用 safety gate 允许“已分类 P2”存在，但工作包 4 的 Phase 4 准入更严格：仍要求
`P0=0、P1=0、P2=0、mismatch=0`，所以 P2 非零即使 CLI 退出 0 也不能推进。

本地 validator 通过只证明所给文件的 collector envelope 内部一致且 pairwise 差异满足上述静态
规则；nonce/HMAC 不认证 collector，也不能单独证明外部 API/数据库确实返回了这些页。可信采集器、
首游标与逐页原始响应/签名或等价 provenance、双节点/环境证据仍须另行批准和独立核验。CLI PASS
（未来具备 verifier 后）也不授权采集、部署、数据库访问或任何运行时写入；当前固定的 fail-closed
结果更不单独完成 Task 7.2。

## Phase 3：单次 Develop legacy-proxy 窗口

只有在刷新 incidents、调用方、字段/数据 owner 与专用测试资产，并取得单独批准后，才可临时设置：

```yaml
IDENTITY_IAM_ORG_WRITE_MODE: "legacy-proxy"
IDENTITY_IAM_ORG_WRITE_ROUTE_INTEGRATION_ENABLED: "true"
IDENTITY_IAM_ORG_WRITE_DUAL_WRITE_EXECUTION_ENABLED: "false"
IDENTITY_IAM_ORG_WRITE_ROLLOUT_MODE: "allowlist"
IDENTITY_IAM_ORG_WRITE_ROLLOUT_ALLOWLIST: "legacy:<approved-dedicated-user-id>"
IDENTITY_IAM_ORG_WRITE_ROLLOUT_PERCENTAGE: "0"
```

该窗口仍只调用既有 plugin-user Legacy owner 一次，并原样返回状态码和响应体，不写 Identity
candidate。未命中 allowlist 的请求完全旁路 organization compatibility layer，继续既有 plugin-user
Legacy 路径且不产生 organization route-hit header/readback。`rollout=off` 会 fail closed，不得作为
legacy-proxy 窗口配置。完成专用账号 replace/empty/preserve、未知组织 422 与普通用户负向回归后，
立即恢复默认。

## Phase 4：小范围 dual-write 窗口

当前 Phase 4 明确为 **NO-GO**。只有 6.9 candidate materialization、7.2 全范围对账、Phase 3
closeout 和专用账号基线均以真实获批证据通过后，才可再次请求独立批准；本手册不提供该批准：

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
AuthZ owner。工作包 4 的未授权部署、运行、API、数据库、Docker 或 Portainer 操作一律不得进入
tmrpp；tmrpp 仅由用户按既定弹性服务器镜像同步流程处理，本手册不授权代理操作。
