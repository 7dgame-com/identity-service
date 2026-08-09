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
npm run iam:organization-write:public-gate:dist -- \
  --urls=https://identity.d.xrteeth.com/health \
  --expected-revision=<full-xrteeth-develop-git-sha>

npm run iam:organization-write:public-gate:dist -- \
  --urls=https://identity.d.tmrpp.com/health \
  --expected-revision=<full-tmrpp-develop-git-sha>
```

两个域名必须分开执行，因为镜像同步时点、完整 revision 和 candidate window 期望可能不同。命令默认
要求当前单个域名为 `disabled / false / false / off / 0%`、candidate disabled/target unconfigured、
Legacy 事实源且 native 不支持。窗口期间必须显式传入该域名的期望值；不得以配置截图代替此
request-level 公共证据。tmrpp 只执行公开 health 请求，不进入 tmrpp Portainer；镜像同步继续由用户
按既定弹性服务器流程完成。

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
npm run iam:organization-write:window-gate:dist -- \
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

### Candidate 受控命令单

以下命令只适用于已经发布且另外获批的 xrteeth Develop 单目标窗口；它们不构成部署、配置变更或
materialization 授权。生产镜像只包含编译产物，因此一律使用 `:dist` 脚本。内部 adapter URL 必须是
`http://127.0.0.1:<port>`、`http://localhost:<port>` 或 `http://[::1]:<port>`，不得带 credentials、path、
query 或 fragment。`--expected-revision` 必须是本次已审核镜像的完整 40 位小写 Git SHA，不能使用短
SHA、tag 或浮动分支名。

1. **Preview（只读）**：仅配置一个精确 target，保持 candidate materialization disabled。token 只从
   环境变量读取；命令只发送 health/readiness/preview/alignment/ledger GET，不发送 POST：

   ```sh
   IDENTITY_IAM_INTERNAL_API_TOKEN='<runtime-secret>' \
   npm run iam:organization-write:materialization-gate:dist -- \
     --adapter-url=http://127.0.0.1:8086 \
     --legacy-user-id=<approved-positive-legacy-user-id> \
     --expected-revision=<full-40-character-develop-git-sha> \
     --since-minutes=60
   ```

   只有 `passed=true`，且输出中的 target fingerprint、组织数量、missing-candidate alignment、schema
   readiness 与零 unresolved ledger 均符合审核预期时，才可把输出中的完整 64 位
   `target.snapshotFingerprint` 登记为 reviewed fingerprint。不得把 token 或主体原始资料写入证据。

2. **Apply（唯一写命令）**：取得独立写批准后，临时将 candidate materialization enabled，并保持同一
   精确 target。fingerprint 必须逐字使用刚审核的 64 位小写十六进制值；1–180 字符 idempotency key
   只从专用环境变量读取，不得作为 CLI 参数：

   ```sh
   IDENTITY_IAM_INTERNAL_API_TOKEN='<runtime-secret>' \
   IDENTITY_IAM_ORG_CANDIDATE_MATERIALIZATION_IDEMPOTENCY_KEY='<approved-window-key>' \
   npm run iam:organization-write:materialization-gate:dist -- \
     --apply \
     --adapter-url=http://127.0.0.1:8086 \
     --legacy-user-id=<approved-positive-legacy-user-id> \
     --expected-revision=<full-40-character-develop-git-sha> \
     --expected-snapshot-fingerprint=<reviewed-64-hex-fingerprint> \
     --since-minutes=60
   ```

   CLI 会先完成全部只读 preflight，随后至多发送一次 POST，并以
   `X-Identity-Expected-Revision` 在服务端写入口再次锁定同一 revision。它禁止跨域 redirect，不自动
   重试，也不得由 operator 换 key 再发。

3. **同步 postcheck**：上一步的同一次 CLI 运行会在 201 后重新 GET health、目标 alignment、ledger
   summary/recent，并要求 fresh revision 不变、`P0/P1/P2/mismatch=0`、精确一条同 target/同
   idempotency digest 的 terminal ledger 记录及 Legacy read-only safety。只有
   `passed=true`、`applyAttempted=true`、`outcomeUnknown=false`、`postcheckIncomplete=false` 才是完整
   成功证据；不存在需要补发的“postcheck POST”。窗口中 xrteeth 的公开 posture 另行只读核验：

   ```sh
   npm run iam:organization-write:public-gate:dist -- \
     --urls=https://identity.d.xrteeth.com/health \
     --expected-revision=<full-40-character-develop-git-sha> \
     --expected-candidate-materialization-enabled=true \
     --expected-candidate-materialization-target-configured=true
   ```

   同期 tmrpp 必须作为另一条公开请求独立核验，使用它自己的已部署完整 revision，并保持默认的
   candidate disabled/target unconfigured；不得进入 tmrpp Portainer：

   ```sh
   npm run iam:organization-write:public-gate:dist -- \
     --urls=https://identity.d.tmrpp.com/health \
     --expected-revision=<full-tmrpp-develop-git-sha>
   ```

4. **不确定或不完整结果**：`outcomeUnknown=true` 表示 POST 传输/redirect/响应结果不可证明；
   `postcheckIncomplete=true` 表示 POST 已返回 201，但 fresh GET 证据不完整。两种情况都要先立即恢复
   candidate disabled、target `0` 及其余全部 default-off 配置；不得再次运行 `--apply`、自动重试或生成
   新 key。随后封存并复用原 key 运行纯 GET outcome verifier：

   ```sh
   IDENTITY_IAM_INTERNAL_API_TOKEN='<runtime-secret>' \
   IDENTITY_IAM_ORG_CANDIDATE_MATERIALIZATION_IDEMPOTENCY_KEY='<the-exact-original-window-key>' \
   npm run iam:organization-write:materialization-gate:dist -- \
     --verify-outcome \
     --adapter-url=http://127.0.0.1:8086 \
     --legacy-user-id=<approved-positive-legacy-user-id> \
     --expected-revision=<full-40-character-develop-git-sha> \
     --expected-snapshot-fingerprint=<reviewed-64-hex-fingerprint> \
     --since-minutes=60
   ```

   Verifier 要求已恢复的 health/readiness，只发送 health、readiness、目标 alignment、ledger
   summary/recent GET；原 key 仅在进程内转换为 SHA-256 digest，不作为 GET 参数或 header 发送，也不
   回显。只有精确一条同 subject/key digest 的 completed terminal 记录、完整
   `requestFingerprintDigest=SHA-256(reviewed fingerprint)`、匹配的 snapshot/target digest、合法
   Identity/compensation 配对、Legacy read-only safety、全局零 unresolved ledger 和
   `P0/P1/P2/mismatch=0` 才能 `passed=true` 且 `outcomeUnknown=false`。missing、pending、failed、
   required/failed compensation、malformed ledger 或不完整 GET 均返回 `outcomeUnknown=true`；GET
   不完整时还会返回 `postcheckIncomplete=true`。此时必须停止并另行申请恢复处置，禁止普通
   `--apply` 绕过，也不得把“可能成功”记为成功。

5. **Restore-check（纯 GET）**：无论成功或失败，先把 candidate enabled 恢复为 false、target 恢复为
   `0`，并恢复本手册的全部默认姿态，再运行：

   ```sh
   IDENTITY_IAM_INTERNAL_API_TOKEN='<runtime-secret>' \
   npm run iam:organization-write:materialization-gate:dist -- \
     --expect-restored \
     --adapter-url=http://127.0.0.1:8086 \
     --expected-revision=<full-40-character-develop-git-sha> \
     --since-minutes=60
   ```

   `--expect-restored` 与 subject 无关，不接受 `--legacy-user-id`、`--apply` 或 snapshot fingerprint；它只
   发送 health/readiness/ledger GET。它要求 candidate disabled/target unconfigured、
   `canPreview=false`、`canApply=false`、`target-not-configured` 与
   `candidate-materialization-disabled` blocker、schema ready、全局 ledger 格式有效且 unresolved=0。
   最后再分别运行本手册开头的 xrteeth 与 tmrpp 默认关闭 public gate；任一失败都不得关闭窗口证据。

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
npm run iam:organization-reconciliation:validate:dist -- \
  --input=<explicit-local-json-file>
```

输入上限 16 MiB，CLI 在读取前先验证路径为普通本地文件并检查大小，读取后再次校验 byte count。
根输入必须包含 v3 collector contract/hash、每次运行随机的高熵 `evidenceNonce`、logical snapshot/window、
两侧各自非空的 source revision 与各自 snapshot ID；异构 source revision 不要求字面相同。必须完整包含以下八个 surface；每个 surface 必须同时
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

surface、任一侧、collector envelope、本侧 source revision、snapshot ID 或 pagination state 缺失，
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
  契约移除；page source revision 与本侧 envelope 不一致属于 coverage blocker，不得降级成 P2/info。

当前构建还固定声明 `realSourceAdaptersReady=false` 并输出 coverage blocker；该值来自受审源码，不能由
输入 JSON、argv、环境变量、source adapter 或签名覆盖。在全部真实 adapter 注册并经源码审核前，即使
静态 envelope 与签名均有效也不得把 Task 7.2 判为 PASS。输出同时固定声明 `dryRun=true`、
`writeSideEffects=none`、`evidencePolicy=hash-only`、`externalProvenanceRequired=true`；snapshot-only
时 `assuranceScope=collector-envelope-self-consistency`，仅完整可信签名通过时才升级为 external attestation。实体、两侧值和
source version 只使用本次 nonce 的 HMAC/hash，不回显 raw subject、organization ID/name、binding
或 decision 上下文；nonce 缺失/非法时直接短路敏感比较，不以可预测 key 生成实体 hash。原始输入
本身仍可能含这些值，必须保留在获批的本地临时边界内，不得提交仓库或复制到报告。参数/文件/
JSON/schema 错误退出 2。当前因真实 adapter blocker，`staticChecksPassed=false`；未来只有经审核注册全部
真实 adapter 且 envelope 内部一致、没有静态 P0/P1 时才可能为 true。snapshot-only 调用没有外部信任根，固定返回 `externalProvenanceVerified=false`、
`safetyGate.passed=false`、`blocksDualWrite=true`，并以 `external-provenance-required` 退出 1。输入中
不存在可伪造的 provenance 布尔开关或公钥字段。

根输入还必须携带一个 v2 composite component manifest。该清单固定列出 `legacy-main`、`identity`、
`plugin` 三个独立 immutable snapshot，明确 `crossDatabaseAtomic=false`，并记录各自 source/version/
snapshot、schema/catalog/build digest、subject-universe scope、实际打开/关闭时间以及有界复合窗口。
manifest 的 domain-separated operation-evidence digest 必须绑定“移除 manifest 后的完整 v3 输入”，
manifest 自身再由 canonical digest 固定；外部 provenance 则签署包含 manifest 在内的最终输入。因此
缺 manifest、manifest digest 不符、清单 A 配数据 B、清单窗口未覆盖 envelope 窗口、Legacy/Identity
sourceVersion/snapshotId、subject count 或 subject-universe digest 不一致都属于 coverage blocker。由于物理快照的关闭时间晚于
记录组装，manifest 的实际外层窗口可以包含 envelope 的读取窗口；可信 policy 校验的是这个更宽的
物理复合窗口。manifest 中的 source/schema/catalog/build 值在 compiled owner-approved pin 完成前仍
只是受绑定声明，不能单独视为权威。

可信模式必须同时提供独立本地 attestation 文件、change-controlled trust-policy 文件和已编译的
trust profile 标识。生产 CLI 只从源码中的 immutable registry 解析 profile；不从 argv、环境变量、
snapshot、attestation 或 policy 接受 policy pin。当前 registry 故意为空，不包含任何生产 key/pin；
每个发布产物最多只能 provision 一个 profile，参数必须精确匹配；零个或多个 compiled profile 都
fail closed，避免调用方挑选较弱环境。新增 profile 必须经代码审查、CI 和正式 release，不能在运行
窗口临时注入：

```bash
npm run iam:organization-reconciliation:validate:dist -- \
  --input=<approved-local-snapshot.json> \
  --attestation=<approved-local-attestation.json> \
  --trust-policy=<approved-local-trust-policy.json> \
  --trust-profile=<reviewed-compiled-profile-id>
```

Compiled profile 固定 policy SHA-256、预期 environment，以及 required collector/node/key/fingerprint/build revision
集合；policy、签名 payload 与 report hash 同时绑定 profile/environment，避免把合法 Develop profile
误用为 Production 证据。Policy 只接受 canonical SPKI Ed25519 public key，并逐 key 校验 SPKI SHA-256
fingerprint；必须要求 2–8 个 collector，collector ID、node ID、key ID 和真实 key fingerprint 均唯一，
缺任一签名、额外/重复 signer、key/fingerprint 不符均 fail closed。
每个 domain-separated 签名绑定 canonical 完整 snapshot digest、collector contract hash、受审 collector
完整 40 位 build revision、logical
snapshot/window digest、environment、collector/node/key、policy digest、collection window 和签发/
过期时间。Policy 同时限制 collection window、证据年龄、attestation TTL、key/policy 有效期和 clock
skew。只有全部 required collector 签名有效且静态门禁通过，才会设置
`assuranceScope=collector-envelope-with-trusted-external-attestation`、
`externalProvenanceVerified=true`；report 仍只输出 hash、状态码与签名计数，不回显 key、签名、node、
environment 或原始业务值。Trusted artifact schema/文件/profile 参数错误或 profile 尚未编译 provision
时退出 2；compiled policy mismatch、签名失败、证据篡改、过期或窗口不合规返回安全报告并退出 1。
CLI 的 safety gate 与工作包 4 的 Phase 4 准入口径一致：只有
`P0=0、P1=0、P2=0、mismatch=0` 才可能通过；任一 P2 非零都会阻断并以非零状态退出。

collector、decision-universe、provenance、trust-policy、report hash 与签名 domain 均为 v3；v2
evidence/policy/signature 不兼容且必须拒绝。Composite manifest 与 operation-evidence 子协议为 v2；
其 v1 manifest/evidence 不兼容且必须拒绝。
Collector build revision 只能由受审 artifact 注入的 build-revision provider 产生并随 evidence 携带；
source adapter、调用参数与 evidence 均不能把自身字段作为权威来源，也不能覆盖 compiled trust
profile/policy 对该完整 40 位 revision 的外部 pin。

Legacy 与 Identity 使用不同版本命名空间时，二者的 source-owned opaque `sourceVersion` 允许不同；
每侧 page 必须与本侧 envelope 的 version/snapshot 精确一致，跨源同窗由 `logicalSnapshotId`、有界
collection window 和 trusted attestation 证明，不能伪造相同版本字符串。Envelope 还要求两侧相同的
完整 subject universe count/HMAC，以及 plugin visibility、campus context、effective decision 各自的
版本化 canonical key universe count/HMAC。每个 decision universe 还必须携带 v3 derivation contract、
与 collector artifact 相同的 build revision，以及严格的权威维度 count/HMAC：plugin visibility 为
subject/plugin/organization，campus context 为 subject/campus/organization，effective decision 为
subject/organization/resource/capability/reviewed rule-pair。逐页记录必须精确覆盖 key 与所有非空维度；非空 surface 必须
覆盖完整 subject universe。只有至少一个非 subject 权威维度被 adapter 证明为零时，keyCount=0 才合法；
不得用空 memberships 推导 subject universe、由调用方自报“真实空”，或静默省略零成员主体。

本地代码另提供严格 source-adapter collector primitive：只接受 immutable snapshot、snapshot-bound opaque
cursor、精确 count/offset/order/unique key，并在成功、读取失败、解码失败或顺序失败后 exactly-once
释放私有 snapshot/事务；close 失败同样拒绝证据，私有 source token 不进入 public evidence。它继续提供
三源 deterministic coordinator（按 `legacy-main → identity → plugin` 打开、反向关闭、明确非分布式
原子快照并把 exact operation body 绑定到 composite manifest）、只读 MySQL repeatable-read consistent-
snapshot session，以及无 I/O 的 cursor-chain assembler（只接受从 `requestCursor=null` 到
`nextCursor=null` 的完整有序链）和
可交给 HSM/KMS 的 canonical attestation payload/signature 组装接口；verifier 本身不读取或持有 private key。
该 MySQL session 不接受运行时 SQL，只接受源码内 immutable statement ID/catalog，固定 keyset
cursor 参数契约、Legacy RBAC `auth_item.type=1` 以及 Identity shadow 的
`source=legacy-shadow/status=shadow`；policy/参数/查询失败都会 poison 当前 session，只能 rollback。
这些 coordinator/session 仍是生命周期与内容绑定 primitive：通用 operation 尚未被限制为从已打开
snapshot 的 `readSnapshotPage` 构造八个 surface；campus/rule-pair/plugin catalog 也尚未与 compiled
owner-approved pins 绑定。仓库仍没有连接 Legacy/Identity/plugin runtime 的完整 source-specific
collector adapter，也没有已批准的公钥 policy、compiled trust profile、签名服务、逐页原始
响应保管或双节点运行证据。因此本地测试 PASS 只证明 verifier/collector primitives 正确，不证明外部
API/数据库实际返回这些页，也不单独完成 Task 7.2。任何采集、部署、数据库访问或运行时写入仍需
另行批准。
协调器产物只能通过 `assembleCoordinatedOrganizationReconciliationInput` 进入 validator/CLI；该 assembler
会重验 manifest/body digest、拒绝调用方嵌套 manifest，并冻结最终输入。这只关闭产物形状与 A/B
拼接空档，不能替代上述页级来源门禁。

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
