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
IDENTITY_IAM_ORG_WRITE_IDENTITY_NATIVE_EXECUTION_ENABLED: "false"
IDENTITY_IAM_ORG_WRITE_ROLLOUT_MODE: "off"
IDENTITY_IAM_ORG_WRITE_ROLLOUT_ALLOWLIST: ""
IDENTITY_IAM_ORG_WRITE_ROLLOUT_PERCENTAGE: "0"
IDENTITY_IAM_ORG_WRITE_CANDIDATE_MATERIALIZATION_ENABLED: "false"
IDENTITY_IAM_ORG_WRITE_CANDIDATE_MATERIALIZATION_TARGET_LEGACY_USER_ID: "0"
IDENTITY_IAM_ORG_WRITE_RECOVERY_DRILL_ENABLED: "false"
IDENTITY_IAM_ORG_WRITE_RECOVERY_DRILL_TARGET_LEGACY_USER_ID: "0"
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

### Develop 全主体 candidate batch（仅本地实现，尚不可运行）

为 7.2 的全主体对账准备 Identity candidate 基线，当前源码另提供一个严格限定在
`xrteeth-develop` 的批量 primitive。它读取同一 Legacy `REPEATABLE READ`、`READ ONLY` 快照中的完整
user/全局 role/organization membership，先做纯只读 preview，再只为 active ordinary subjects 补齐
缺失的 Identity candidate。具有 `root` 等受保护角色的主体只计数和报告，永不进入写循环；Legacy
始终只读，AuthZ owner 仍为 Legacy。该 primitive 不授权 dual-write、Identity-native、publish、tmrpp 或
Production，也不关闭 6.9/7.2。

默认和窗口恢复值必须固定为：

```yaml
IDENTITY_IAM_ORG_WRITE_CANDIDATE_BATCH_MATERIALIZATION_ENABLED: "false"
IDENTITY_IAM_ORG_WRITE_CANDIDATE_BATCH_MATERIALIZATION_ENVIRONMENT: "disabled"
IDENTITY_IAM_ORG_WRITE_CANDIDATE_BATCH_MATERIALIZATION_PLAN_HMAC_KEY: ""
IDENTITY_IAM_ORG_WRITE_CANDIDATE_BATCH_EXPECTED_LEGACY_SUBJECT_COUNT: "0"
IDENTITY_IAM_ORG_WRITE_CANDIDATE_BATCH_EXPECTED_PROTECTED_SUBJECT_COUNT: "0"
```

受控 preview/apply 要求 Identity DB 精确为 `xrugc_identity_dev`、Legacy DB 精确为
`bujiaban_development`，并要求
现有单主体 materialization 已恢复为 disabled/target `0`。preview 只返回聚合计数和 HMAC plan token，
不返回 Legacy user ID、用户名、角色或组织；plan token 绑定完整 Legacy source snapshot、状态、受保护分类
和组织 fingerprint。Preview 阶段必须保持 batch `ENABLED=false`；审核 token/计数并取得独立写批准后，
才可临时设为 `true` 进入 Apply。Apply 在跨节点 MySQL batch advisory lock 内重新读取并核对相同 source snapshot，
随后逐主体复用现有 subject lock、ledger、candidate transaction 和 fresh Legacy postcheck。中途失败可用
同一 plan/idempotency key 续跑，已对齐主体只跳过、不重写；普通主体出现 inactive、unresolved operation、
count drift、fingerprint drift 或任何 P0/P2 时，写循环开始前整体 fail closed。

内部实现入口为：

```text
GET  /internal/iam/organization-write/candidate-batch-materialization/preview
POST /internal/iam/organization-write/candidate-batch-materialization/apply
```

两者均要求 `X-Identity-Internal-Token` 和精确 40 位 `X-Identity-Expected-Revision`；POST 另要求
`Idempotency-Key` 和刚审核的 64 位 plan token。不得用临时 curl、Portainer console 或手工拼接请求；
只能在这组代码已发布到 xrteeth Develop、CI 通过且另行批准写窗后使用编译后的 operator gate。

Preview 阶段 batch `ENABLED=false`，但 environment/key/精确 expected counts 已配置：

```sh
IDENTITY_IAM_INTERNAL_API_TOKEN='<runtime-secret>' \
npm run iam:organization-write:batch-materialization-gate:dist -- \
  --adapter-url=http://127.0.0.1:8086 \
  --expected-revision=<full-40-character-develop-git-sha> \
  --expected-legacy-subject-count=<reviewed-full-count> \
  --expected-protected-subject-count=<reviewed-protected-count>
```

只有 `passed=true`、`ordinaryBlocked=0`、`inactiveOrdinary=0`、preview count 与审核值完全一致，才可把
输出中的完整 plan token 转入窗口专用 secret。取得独立写批准并临时将 batch `ENABLED=true` 后，Apply
只从环境变量读取 plan token、idempotency key 和 internal token，先重跑全量 preflight，至多 POST 一次，
随后再次要求全量 ordinary missing=0：

```sh
IDENTITY_IAM_INTERNAL_API_TOKEN='<runtime-secret>' \
IDENTITY_IAM_ORG_CANDIDATE_BATCH_PLAN_TOKEN='<reviewed-64-hex-plan>' \
IDENTITY_IAM_ORG_CANDIDATE_BATCH_IDEMPOTENCY_KEY='<approved-window-key>' \
npm run iam:organization-write:batch-materialization-gate:dist -- \
  --apply \
  --adapter-url=http://127.0.0.1:8086 \
  --expected-revision=<full-40-character-develop-git-sha> \
  --expected-legacy-subject-count=<reviewed-full-count> \
  --expected-protected-subject-count=<reviewed-protected-count>
```

每个阶段还要从 xrteeth Develop 公网入口独立核对正在运行的同一 revision；Preview 期预期 batch
disabled/develop，Apply 期只把 enabled 改为 true，窗口恢复后回到 public gate 的默认 false/disabled：

```sh
npm run iam:organization-write:public-gate:dist -- \
  --urls=https://identity.d.xrteeth.com/health \
  --expected-revision=<full-40-character-develop-git-sha> \
  --expected-candidate-batch-materialization-enabled=false \
  --expected-candidate-batch-materialization-environment=xrteeth-develop

npm run iam:organization-write:public-gate:dist -- \
  --urls=https://identity.d.xrteeth.com/health \
  --expected-revision=<full-40-character-develop-git-sha> \
  --expected-candidate-batch-materialization-enabled=true \
  --expected-candidate-batch-materialization-environment=xrteeth-develop
```

若输出 `outcomeUnknown=true` 或 `postcheckIncomplete=true`，立即把 batch `ENABLED=false`，不得重发 POST。
在 environment/key/count 尚保留的短暂核验状态，用原 plan/key 执行纯 GET outcome verifier；它只接受
full preview 中 ordinary missing=0，不会发送 POST：

```sh
IDENTITY_IAM_INTERNAL_API_TOKEN='<runtime-secret>' \
IDENTITY_IAM_ORG_CANDIDATE_BATCH_PLAN_TOKEN='<same-reviewed-plan>' \
IDENTITY_IAM_ORG_CANDIDATE_BATCH_IDEMPOTENCY_KEY='<same-window-key>' \
npm run iam:organization-write:batch-materialization-gate:dist -- \
  --verify-outcome \
  --adapter-url=http://127.0.0.1:8086 \
  --expected-revision=<full-40-character-develop-git-sha> \
  --expected-legacy-subject-count=<reviewed-full-count> \
  --expected-protected-subject-count=<reviewed-protected-count>
```

成功、失败或不确定结果处理完毕后，都必须清空五个 batch 配置并验证恢复；恢复门禁不读取 plan/key，
也不访问 Legacy：

```sh
IDENTITY_IAM_INTERNAL_API_TOKEN='<runtime-secret>' \
npm run iam:organization-write:batch-materialization-gate:dist -- \
  --expect-restored \
  --adapter-url=http://127.0.0.1:8086 \
  --expected-revision=<full-40-character-develop-git-sha>
```

operator 输出只在 Preview 成功时显示完整 plan token；Apply/outcome/restored 只显示 digest 和聚合计数，
不得保存 token、idempotency 原文或主体资料。在本切片推送、Develop CI、部署与独立写窗批准完成前，
这些命令仍只属于 default-off 的本地实现，禁止实际执行。

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

根输入还必须携带一个 v3 composite component manifest。该清单固定列出 `legacy-main`、`identity`、
`plugin` 三个独立 immutable snapshot，明确 `crossDatabaseAtomic=false`，并记录各自 source/version/
snapshot、schema/catalog/build digest、subject-universe scope、实际打开/关闭时间以及有界复合窗口。
每个 component 还必须绑定 v2 dataset inventory；inventory 使用
`hmac-sha256-run-secret/v1`，以每次 component/run 新生成且不进入公共产物的 32-byte 私有 secret，分别绑定
cursor、page records、dataset records 与 canonical lineage。这里的 commitment 是同一次 run 内的防篡改
承诺，不是可跨运行关联原始记录的稳定 digest。manifest 的 v2 domain-separated operation-evidence digest
必须绑定“移除 manifest 后的完整 v3 输入”，
manifest 自身再由 canonical digest 固定；外部 provenance 则签署包含 manifest 在内的最终输入。因此
缺 manifest、manifest digest 不符、清单 A 配数据 B、清单窗口未覆盖 envelope 窗口、Legacy/Identity
sourceVersion/snapshotId、subject count 或 subject-universe digest 不一致都属于 coverage blocker。由于物理快照的关闭时间晚于
记录组装，manifest 的实际外层窗口可以包含 envelope 的读取窗口；可信 policy 校验的是这个更宽的
物理复合窗口。transaction adapter 生成的 `sourceVersion`/`snapshotId` 是从本次 run 的 dataset inventory
派生的内容绑定；它们既不是数据库物理 revision，也不证明 adapter 确实连接了声明的物理 source。
manifest 中的 source/schema/catalog/build 值在 compiled owner-approved pin 完成前也仍只是受绑定声明，
不能单独视为权威或 physical-source attestation。

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
evidence/policy/signature 不兼容且必须拒绝。Composite manifest 子协议为 v3，operation-evidence 与
dataset inventory 子协议为 v2；旧 manifest/evidence/inventory 版本不兼容且必须拒绝。
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
snapshot session、dataset-lineage collector，以及可交给 HSM/KMS 的 canonical attestation
payload/signature 组装接口；外部 provenance verifier 本身不读取或持有 private key。

当前 Develop source-shape bridge 已实现 proposal 中固定的 21 个 raw dataset：Legacy 7 个、Identity 13 个、
plugin 1 个。Legacy 在既有目录、主体、成员关系、role assignment 与 `legacy-rbac-edge` 基础上加入完整
rule-free RBAC item/edge/direct role-or-permission assignment；任一 `rule_name IS NOT NULL` 都会 fail closed。
Identity 加入 candidate membership explicit snapshot、精确 pinned Develop IAM policy version、role、permission、
relation、subject assignment，以及由同一 read-only transaction 对完整 Identity subject universe 做 LEFT JOIN
聚合得到的 explicit zero-assignment snapshot；没有为预检创建新表或执行 DDL。当前 Develop IAM checksum 只是
源码固定的测试候选，不是 Production trust root。所有 text keyset 使用 MySQL explicit binary order 与 Node
UTF-8 byte order；这仍不证明运行时 schema、collation、物理 source 或 owner semantic registry。每个 component 在各自
独立的 repeatable-read transaction 内，按固定 dataset ID 集合与 caller-structured untrusted catalog 扫描。
adapter 不再缓存完整 raw page 集合：每页通过 canonical transport 写入同一受限本地 spool，并增量计算
page/dataset/component inventory；seal 后每次只从 spool 读取一个有界页回放。成功初始化后 spool 文件已
unlink，仅保留进程内 fd；但 create→unlink 仍有不可消除的命名 artifact 崩溃窗口，受控失败只做
best-effort cleanup，且当前没有证明 at-rest encryption、强擦除或跨进程磁盘 quota。

Legacy/Identity subject reference 只在 transaction-adapter hardened factory 闭包内由同一 raw subject page
逐页派生，不开放 mapper 或 spool 给调用方；sidecar 绑定该页的 dataset/count/offset/order，并以有界
k-way merge 复用现有 evidence-HMAC 字节协议。这个绑定仍只证明 factory 内结构化派生关系，不认证物理
数据库、owner catalog 或 source 真实性，也尚未 production-register。dataset-lineage 私下保留 spool
返回的 exact records 数组身份给 replay verifier，公开 artifact 继续只含 canonical 深拷贝，因此
clone、跨页/跨组件 A/B 与 accessor/proxy 替换会 fail closed。

对每个 component，只有固定 dataset 集合全部回放并通过 spool verifier，close gate 才可能接受
completed；spool cleanup 成功后才允许 raw transaction COMMIT，任何 spool 失败仍必须尝试 raw
ROLLBACK。三个事务仍然独立，不能据此声称跨数据库原子提交。私有 secret 不进入 snapshot、manifest、
lineage artifact 或 CLI 输入，销毁仅是 JavaScript 进程内的 best-effort overwrite，不构成强内存擦除保证。

上述 bridge 已具备默认关闭的 bounded transaction spool 接线，但仍没有 production runtime registration。
64 MiB/component、192 MiB process-global、最多 3 个 active spool，加上 page/record 上限与进程内
reservation，构成本地资源门禁；它们不是 production
streaming projector、JavaScript heap 上界、磁盘机密性或内存安全证明。尤其 dataset-lineage collector
仍会为最终 artifact 累积完整 canonical `records`，所以既有
`bounded-streaming-projector-not-implemented` blocker 必须保留，不能把本切片称为完成 Task 7.2。
generic dataset-lineage 的 WeakMap brand 只证明 artifact 来自同一进程内同一次结构化 collection run；
它不认证物理 source、owner catalog 或外部 attestation。

该 MySQL session 不接受运行时 SQL，只接受源码内 immutable statement ID/catalog，固定 keyset
cursor 参数契约、Legacy rule-free RBAC 与 Develop exact IAM checksum/source/status selectors；policy、参数、
decoder、顺序或查询失败都会 poison 当前 session，只能 rollback。仓库另提供
`iam:organization-reconciliation:develop-preflight:dist`：它只接受 `--environment=xrteeth-develop`，要求
Legacy database 为 `bujiaban_development`、Identity database 为 `xrugc_identity_dev`，在三源固定 read-only snapshot 中读取 schema metadata、aggregate
counts 与每个 dataset 的单行 strict-decoder probe，并只输出计数、检查 ID 与 SHA-256 摘要。v3 preflight
还在每个已连接 session 上执行 `SHOW GRANTS FOR CURRENT_USER()`：只接受精确 Develop schema 或固定表的
`SELECT`（可附带 `SHOW VIEW`）及全局 `USAGE`，拒绝全局 SELECT、角色间接授权、写/DDL 权限、未知 scope
和 `WITH GRANT OPTION`；公开报告只保留 grant-set digest 与通过布尔值，不回显账号或 grant 文本。它同时
要求 `DATABASE()` 精确为 `bujiaban_development`、`xrugc_identity_dev`、`bujiaban_development_plugin`，并要求 MySQL
`CURRENT_USER()` 解析出的账号精确等于对应专用配置用户名，防止凭据被接到同形异库或被数据库映射为另一授权身份。
preflight
会在进程内比较完整 Legacy subject ID 集合与选中的 Identity legacy-shadow 集合，但公开报告只输出
Legacy/Identity 总数、缺失数与额外数，不输出主体 ID；通过条件是每个 Legacy 主体均已在 Identity 中出现，
Identity-only 主体只作为额外集合单列，不能静默并入 Legacy 决策宇宙。Legacy RBAC 的 named-rule 门禁只检查
源码固定的 11 个 Develop reconciliation capability 及其授权祖先闭包；全库其它 Verse/Meta/resource 规则不再
误伤这个 source preflight，但 capability owner 决策、完整 evaluator 与 production registry 仍未批准。
membership snapshot 完整性同样以 Legacy 主体集合为边界：每个 Legacy 主体必须恰有一条 candidate snapshot
（包含显式 `organization_count=0`），Identity-only 主体不得被用来扩大或补足迁移集合。

三源均必须使用 reconciliation 专用只读身份：Legacy 使用
`IDENTITY_IAM_ORG_RECONCILIATION_LEGACY_DB_USER/PASSWORD`，Identity 使用
`IDENTITY_IAM_ORG_RECONCILIATION_IDENTITY_DB_USER/PASSWORD`，plugin 使用显式
`PLUGIN_DB_HOST/PORT/NAME/USER/PASSWORD`，其中 `PLUGIN_DB_NAME` 固定为 `bujiaban_development_plugin`。三个用户名必须
互不相同，并且不得等于 Legacy/Identity 服务运行账号；不得以 system-admin 运行账号作为替代。
用户名不同只完成配置门禁；只有实际 Develop v3 preflight 的
`databaseBindingPassed=true`（数据库名与 session 授权账号均精确）、`readOnlyGrantPassed=true` 和 grant digest
才构成当前 session 的只读证据。
实际 plugin access scope
枚举为 `auth-only`、`manager-only`、`admin-only`、`root-only`；这与 subject role/projector 的
`root/admin/manager/user` 是两层不同契约，禁止直接混用。

在 Portainer 更新 `identity_service_develop` 前，数据库 owner 必须先在相应 MySQL 实例中创建三个
不同的专用账号。每个账号只允许 `USAGE ON *.*` 与其精确来源 schema 的 `SELECT`（可选
`SHOW VIEW`）；不得授予全局 `SELECT`、任何写入/DDL、`WITH GRANT OPTION` 或间接 role。账号名和密码只
通过 Portainer secret/environment 注入，不写入 Git、报告、命令输出或 closeout。Legacy 精确来源必须是
`bujiaban_development`，Identity 必须是 `xrugc_identity_dev`。2026-08-11 从当前
`backend_develop-system-admin-d-1` 只读核验到 `DATABASE()` 为 `bujiaban_development_plugin`；因此
Develop preflight 固定使用该隔离库名，并明确拒绝旧的 `bujiaban_plugin`、相似库名或 Production 插件库。
这一运行事实不替代专用只读账号、物理 schema 指纹和数据库 owner 权限证明。

Portainer 只需向 identity adapter 增加以下键；值均由数据库 owner 提供，禁止从现有 service 账号复制：

```text
IDENTITY_IAM_ORG_RECONCILIATION_LEGACY_DB_USER
IDENTITY_IAM_ORG_RECONCILIATION_LEGACY_DB_PASSWORD
IDENTITY_IAM_ORG_RECONCILIATION_IDENTITY_DB_USER
IDENTITY_IAM_ORG_RECONCILIATION_IDENTITY_DB_PASSWORD
PLUGIN_DB_HOST
PLUGIN_DB_PORT
PLUGIN_DB_NAME
PLUGIN_DB_USER
PLUGIN_DB_PASSWORD
```

如果上述编译期配置门禁未满足，CLI 以
`iam-organization-reconciliation-xrteeth-develop-preflight-launch-diagnostic/v1` 输出一个固定 failure ID；
该诊断不回显任何环境变量值。只有 launch 成功后的 v3 sanitized report 才能作为 schema、grant、dataset
与完整性证据，launch failure 不能被记作 dataset mismatch。

仓库另保留一个默认关闭的双节点结构一致性工具，供未来 Production promotion 独立评审使用；它不是 Task 7.2
的通过条件。该工具只接受两份均已通过的 v3 sanitized report，要求两个调用方
标签不同、时间窗口有界，并逐项核对 build revision、source/statement catalog、IAM policy checksum、三组件
database identity/grant/schema digest、21 个 dataset probe、aggregate counts、subject universe、membership snapshot
与 Legacy RBAC scope。任一 A/B 拼接或集合缺失都会 fail closed；输出只保留 canonical SHA-256 和固定摘要。
该门禁的 node ID 与 expected build revision 仍是调用方提供的结构字段，hash 不是签名；当前没有 collector
公钥、compiled trust profile 或外部 attestation，所以它只能证明“双份脱敏报告结构一致”，不能证明节点身份、
物理来源真实性或完整八表面对账，也不能改变 Task 7.2 的 Develop-only 单签结论。

两台节点分别把单节点命令 stdout 原样保存为本地 JSON 后，结构门禁的离线调用为：

```bash
npm run iam:organization-reconciliation:develop-dual-node-preflight:dist -- \
  --environment=xrteeth-develop \
  --expected-build-revision=<40位小写Develop提交SHA> \
  --node-a-id=<节点A审计标签> --node-a-report=<节点A本地JSON> \
  --node-b-id=<节点B审计标签> --node-b-report=<节点B本地JSON>
```

输入必须是单节点 CLI 输出的 2-space canonical JSON（含结尾换行），每份不超过 1 MiB；URL、stdin、最终路径
组件为 symlink、hard link、非普通文件、重复 JSON key、改写格式或读取期间发生变化都会拒绝。节点标签不是身份
认证，不能用复制同一报告并更换标签的方式替代未来 Production promotion 的物理独立性评审。

该命令不做 DDL、不写数据、不翻 readiness，也不允许 main、publish、Production 或 tmrpp 目标。
当前 semantic registry 的 compiled production table 故意为空，且不接受 argv、环境变量、JSON 或 evidence
注入。Identity shadow/candidate owner selectors、organization role scopes、plugin overlay、campus public
context 与 capability catalog 五项 owner decision 均未批准；Legacy/Identity 两侧独立 semantic projector、
projector artifact provenance 和 compiled pipeline registration 也均未注册。

因此 bounded transaction spool 与 transaction-adapter factory capability 的 implementation fact 为
`true`，但两者的 production readiness 仍分别为 `false`；raw-source capability、transaction adapter、
dataset lineage、surface projector、operation-evidence projector、compiled pipeline 和 semantic registry
readiness 也全部保持 `false`。`assembleCoordinatedOrganizationReconciliationInput` 不是可用入口：它在 dedicated branded
operation-evidence projector readiness 为 false 时无条件硬拒，不能进入 validator/CLI；不存在调用参数、
环境变量或普通 adapter 可以打开这条路径。仓库也没有已批准的公钥 policy、compiled trust profile、签名
服务或逐页原始响应保管。因此本地测试 PASS 只证明这些默认关闭 primitive 的契约，
不证明外部 API/数据库实际返回完整页，也不单独完成 Task 7.2。

Task 7.2 当前结论明确为 **NO-GO**。任何真实采集、runtime wiring、语义 owner 决策、pipeline 注册、部署、
数据库访问或运行时写入都必须另行批准；Legacy 继续是唯一事实源，全部组织写入配置继续 default-off，
不得据此切换 identity-primary、开启组织 native write 或进入 tmrpp Portainer。

## Task 7.2：Develop-only Portainer 模板冻结

本节只冻结部署输入，不授权或执行部署。模板固定为
`deploy/iam-organization-reconciliation-develop/compose.signer.yml` 与
`deploy/iam-organization-reconciliation-develop/compose.full-range-runner.yml`。两者都只接受
`identity-develop-image-provenance-<40位Develop SHA>` CI artifact 中同一组 repository、`gitSha` 和
`sha256:` digest；`develop`、`sha-<commit>`、`latest` 等 tag 均不得作为镜像输入。当前 CI patch 只在
`develop` push 后保留 contract 为 `identity-service/develop-image-provenance/v1` 的 30 天 immutable image
artifact；它不部署容器，也不授权 main、publish、Production 或 tmrpp。

当前 Portainer 已核验只有一个 `local` standalone endpoint；这足以承载 Task 7.2 的一个 signer 与一个
one-shot runner。二者允许位于同一 endpoint、Docker engine 和物理 host，但必须是两个不同容器并由外部
Docker inspect 分别绑定。Task 7.2 证书必须固定输出 `physicalIndependenceVerified=false`、
`productionReady=false`、`productionPromotionAllowed=false`。若未来申请 Production promotion，物理独立
节点及其证据是届时的独立 blocker，不在本阶段新增 VM、费用或第二套 signer。

单 signer 模板只启动 HTTPS launcher，固定 uid/gid `1000:1000`、read-only rootfs、`cap_drop=ALL`、
`no-new-privileges`、16 MiB noexec tmpfs、private host bind、internal bridge 和 static container IPv4；没有
environment、数据库配置或 Docker socket。每个 endpoint 必须预先创建一个 `Driver=local`、`Scope=local` 的
external volume，并以只读方式挂到 `/run/identity-develop-signer`。其中所有普通文件必须由 uid 1000 拥有、
link count 为 1，volume 根目录必须由 uid/gid 1000 拥有且模式为 `0700`；除 TLS certificate 可使用
owner-readable 且 group/other 不可写的模式外，其余文件均为
`0600`：

- `launcher.json`：两空格 canonical JSON 且结尾换行；contract 固定为
  `iam-organization-reconciliation-xrteeth-develop-hash-signer-https-launcher/v1`，environment 固定为
  `xrteeth-develop`。`collectorId` 必须来自 compiled profile，`listen.host` 必须等于 Compose 的 static
  container IPv4，`listen.port` 固定为 `8443`。
- `trust-policy.json` 与 `deployment-evidence.json`：单 signer 使用的获批 public trust/deployment evidence；路径
  分别固定为 `/run/identity-develop-signer/trust-policy.json` 和
  `/run/identity-develop-signer/deployment-evidence.json`。
- `signer-ed25519-private.pem`、`tls-private-key.pem`、`tls-certificate.pem`、`bearer-token`：其绝对路径写入
  `launcher.json`。Ed25519 signing key 与 TLS key 必须不同；certificate DER fingerprint 必须等于 deployment
  evidence 对本节点的 pin；Bearer token 至少 32 个 printable ASCII 字节。

one-shot runner 模板使用完全相同的 repository@digest 与 compiled revision，固定 uid/gid `1000:1000`、
read-only rootfs、`cap_drop=ALL`、`no-new-privileges`、256 MiB noexec tmpfs、`restart: "no"`，不发布端口、
不挂载 Docker socket，也不挂载任何 Ed25519/TLS private key。runner 只接收三组彼此不同的专用只读数据库
账号：Legacy `bujiaban_development`、Identity `xrugc_identity_dev`、plugin
`bujiaban_development_plugin`；不得注入普通 service DB 账号。它还只读挂载 node-local external config volume
到 `/app/develop-config`，其中只有 `trust-policy.json`、`deployment-evidence.json`、
`signer-transport.json`、一个 signer Bearer token 和对应 private-CA certificate。所有这些文件均须
uid 1000、link count 1、`0600`，transport 中的绝对路径必须位于该挂载点。

runner 的 evidence external volume 读写挂载到 `/app/evidence`。在部署前，host/Portainer owner 必须独立核验
该 local volume 所在文件系统实际可用容量不小于 1 GiB，并把字节数作为
`DEVELOP_RUNNER_EVIDENCE_CAPACITY_BYTES` 输入；Compose label 和静态校验只记录/检查这个声明，不替代实际容量
证据。config volume 根目录与 evidence volume 根目录都必须由 uid/gid 1000 拥有且模式为 `0700`，否则
non-root runner 无权读取配置或创建输出。`IDENTITY_DEVELOP_EVIDENCE_FILE` 必须是尚不存在的安全 `.json`
basename；runner 使用 exclusive 0600
创建，重复文件会 fail closed。该 raw artifact 可能含敏感源记录，只能留在受控 evidence volume，不能提交
Git 或当作脱敏 closeout 传播。

部署前必须先运行以下只读校验；它只执行 `docker compose config --format json` 并在内存检查渲染结果，不会
create/start network、volume 或 container，也不会输出数据库密码：

```bash
node deploy/iam-organization-reconciliation-develop/validate-compose-templates.mjs --self-test
node deploy/iam-organization-reconciliation-develop/validate-compose-templates.mjs signer
node deploy/iam-organization-reconciliation-develop/validate-compose-templates.mjs runner
```

`signer` 与 `runner` 模式要求 Compose 文件中的每个 `${NAME:?…}` 均由 Portainer/受控 shell 提供，并额外
拒绝 mutable tag、placeholder、零 digest、非 40 位 revision、不安全 evidence filename、非 RFC1918 signer
bind/static IP、静态 IP 不属于 subnet、重复 DB 用户、config/evidence 共用 volume，以及声明容量小于 1 GiB。
渲染结果还必须只有获批的单一 service、network 与 volume source；额外 service/network/config/secret/device、
非固定 mount source、非 `8443` listener 或偏离只读 config prefix 的 token/private-CA 路径一律 fail closed。

两项角色的镜像一致性不得由应用容器自报。CI provenance、signer/runner 两份
`docker compose config --format json` 输出，以及同一已批准 Develop Docker daemon 外部采集的两个 container/image
`docker inspect` 脱敏 observation 必须写入彼此独立的普通 JSON 文件。observation 的 `source` 固定为
`docker-inspect`，同时记录 container 的 configured repository@digest、container image ID、image inspect ID、
RepoDigest 以及与 deployment evidence 相同的 container/endpoint/engine/physical-host 哈希。校验命令为：

```bash
npm run iam:organization-reconciliation:develop-validate-deployment-bundle -- \
  --ci-provenance=/absolute/identity-develop-image-provenance.json \
  --deployment-evidence=/absolute/deployment-evidence.json \
  --signer-compose=/absolute/signer-compose.json \
  --runner-compose=/absolute/runner-compose.json \
  --docker-inspect-observations=/absolute/docker-inspect-observations.json
```

该 gate 要求两份 Compose image 与两份 Docker inspect RepoDigest 都精确等于 CI artifact 的同一
`repository@sha256:digest`，container/image inspect ID 一致，deployment evidence 的 build revision 与
release image digest 同 CI provenance 一致，并要求 deployment evidence 的 `topologyObservationSha256`
精确等于整组外部 observation 的 domain hash。它不依赖 `sha-<commit>` tag，也不允许应用进程自省替代
Docker inspect 证据。compiled topology registry 仍必须唯一钉住 executor 与一个 signer 的
collector/node/key/public-key/TLS-certificate/endpoint/engine/physical-host；production registry 当前保持 0，
未另行审核 provision 前所有 runner、signer 与 certificate 路径均 fail closed。

校验 PASS 只证明模板渲染及静态隔离约束；它不证明 volume 容量、证书/密钥、数据库 grant、网络可达性、
运行证据或 Task 7.2 完成，也不证明 endpoint/host 物理独立。实际 `docker compose up` 或 Portainer stack
deploy 仍须保持在已批准 Develop 范围，禁止 main、publish、Production 或 tmrpp。

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
IDENTITY_IAM_ORG_WRITE_RECOVERY_DRILL_ENABLED: "false"
IDENTITY_IAM_ORG_WRITE_RECOVERY_DRILL_TARGET_LEGACY_USER_ID: "0"
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

### 等价补偿演练

不得为了制造 Identity 写失败而修改数据库 grant、执行 DDL、关闭共享数据库/网络或向未知用户发请求。
organization-write 提供一个默认关闭的 exact-target 内部演练入口；它只准备一条确定性的
`legacy_completed + compensation=required` ledger 状态，**不调用 Legacy 写接口**：

```text
POST /internal/iam/organization-write/recovery-drill/prepare
```

该入口仅在另行批准的 `xrteeth-develop` dual-write allowlist 窗口中临时启用：

```yaml
IDENTITY_IAM_ORG_WRITE_RECOVERY_DRILL_ENABLED: "true"
IDENTITY_IAM_ORG_WRITE_RECOVERY_DRILL_TARGET_LEGACY_USER_ID: "581"
```

它还要求 target 被 exact allowlist 选中、repository/readiness 可执行、Legacy target active、仅有 `user`
角色且 membership 精确为 `[1]`。准备操作使用确定性 operation key；重复调用不会创建第二条账本。
随后使用返回的 operation key 调用既有 `retry-identity-candidate`，从当前 Legacy `[1]` 重建 candidate，
并证明 Legacy 写调用为 0。该演练只证明真实 ledger/recovery/candidate 存储链，不能替代正常的
`[1] -> [] -> [1]` dual-write 窗口。

演练后必须把两个 recovery-drill 变量恢复为 `false/0`，再执行 alignment、ledger 与 public default-off gate。

## 证据与回滚

## Phase 5：Identity-native 独立窗口（Task 10.5）

Identity-native 绝不能由 dual-write 自动升级；必须在 dual-write 已恢复默认关闭后，以独立批准的
allowlist 或 percentage 窗口临时配置。代码和镜像仍默认关闭：

```yaml
IDENTITY_IAM_ORG_WRITE_MODE: "identity-native"
IDENTITY_IAM_ORG_WRITE_ROUTE_INTEGRATION_ENABLED: "true"
IDENTITY_IAM_ORG_WRITE_DUAL_WRITE_EXECUTION_ENABLED: "false"
IDENTITY_IAM_ORG_WRITE_IDENTITY_NATIVE_EXECUTION_ENABLED: "true"
IDENTITY_IAM_ORG_WRITE_ROLLOUT_MODE: "allowlist"
IDENTITY_IAM_ORG_WRITE_ROLLOUT_ALLOWLIST: "legacy:<approved-dedicated-user-id>"
IDENTITY_IAM_ORG_WRITE_ROLLOUT_PERCENTAGE: "0"
```

选择器现在表示 **Identity 拥有的目标用户**，不表示操作者；未选目标仍由既有 Legacy owner 处理。被选目标的
`organization_ids` 采用 Identity candidate exact replacement，Legacy 写调用必须为 0。被选请求必须：

- 只包含 `id` 与 `organization_ids`，混合 nickname/email/status 等资料更新明确失败，避免部分假成功；
- 携带有效 Identity bearer token 与显式 `Idempotency-Key`；
- 操作者同时满足 verified root 和 live Yii `user-management.update-user` permission；
- 目标在 `identity_users` 为 active legacy-shadow，且 Identity role shadow 不含 root；
- 目标已有 candidate snapshot，所有组织 ID 已在 Identity candidate catalog；
- 写后从 Identity candidate 读回精确 ID 集合；若提交确认丢失或 postcheck 失败，恢复写前 candidate snapshot，
  账本必须为 `legacyStatus=not-called` 且补偿终态明确。

运行前后使用只读 gate；Identity-native 会额外读取 candidate 摘要，不输出用户名或组织名：

```bash
npm run iam:organization-write:window-gate -- \
  --legacy-user-id=<approved-id> \
  --expected-mode=identity-native \
  --expected-allowlist-count=1
```

真正的单窗写不得手工拼接 curl。使用 native one-shot gate；它默认仅执行只读 window gate 与 desired-snapshot
preview，后者从当前 Identity organization candidate catalog 计算目标快照，只输出 count/SHA：

```bash
export IDENTITY_IAM_INTERNAL_API_TOKEN='<runtime secret; never argv/log>'
export IDENTITY_IAM_ORG_NATIVE_WINDOW_ORGANIZATION_IDS='2,7'
npm run iam:organization-write:native-window-gate -- \
  --legacy-user-id=<approved-id> \
  --expected-revision=<exact-40-char-deployed-revision> \
  --expected-before-fingerprint=<reviewed-current-candidate-sha256>
```

审批记录必须绑定预览输出中的 `revision`、target fingerprint、organization count/set digest、before fingerprint
与 desired fingerprint。获批后才临时注入管理员 token 与新的幂等键，并把已批准 desired SHA 原样作为 after：

```bash
export IDENTITY_IAM_ORG_NATIVE_WINDOW_OPERATOR_BEARER_TOKEN='<verified-root bearer; never argv/log>'
export IDENTITY_IAM_ORG_NATIVE_WINDOW_IDEMPOTENCY_KEY='<unique 16..200 char secret; never argv/log>'
npm run iam:organization-write:native-window-gate -- \
  --apply \
  --legacy-user-id=<approved-id> \
  --expected-revision=<exact-40-char-deployed-revision> \
  --expected-before-fingerprint=<reviewed-current-candidate-sha256> \
  --expected-after-fingerprint=<approved-desired-candidate-sha256>
```

operator 只允许 HTTP loopback adapter origin，拒绝 redirect、URL 凭据、path/query/fragment，所有敏感值和组织
ID 集只从环境读取。它最多发送一次业务 POST；POST outcome unknown 时固定停止且不得自动重试。业务 POST 自身携带并
强制校验 `X-Identity-Expected-Revision`，因此 preflight 后若发生部署切换会在读取/写入 candidate 前失败。写后 gate
重新读取 candidate 与 ledger，要求 exact after SHA/count、operation key/request fingerprint、`mode=identity-native`、
`legacyStatus=not-called`、`identityStatus=completed`、`compensationStatus=none`、`owner=identity`、
`legacyWritePerformed=false`，并精确核对 Identity response headers。

只有 `identityNativeGate.executable=true`、candidate digest 合法、账本无 pending/failed/required、管理员正向与
普通用户负向、重复键、未知 ID、缺字段、add/remove/replace/restore、插件/campus/登录态回归全部通过，才可
关闭该级窗口。关闭顺序固定为 execution=false、route=false、mode=disabled、rollout=off、allowlist 空、percentage=0。
关闭配置不会删除 candidate；如需业务 restore，必须在窗口内先用新 idempotency key 把原 candidate 集合写回并读回，
然后再关闭窗口。Production 每个比例仍需独立批准。

日志、响应头和账本只保留 correlation ID、operation/idempotency 摘要、目标/操作者摘要、命中类型、
组织数量和状态，不保存 Authorization、Cookie、密码、完整 token 或原始请求/响应 payload。

任何异常立即恢复全部默认值。回滚只关闭配置，不删除 Legacy 数据、不清理 candidate、不切换
AuthZ owner。工作包 4 的未授权部署、运行、API、数据库、Docker 或 Portainer 操作一律不得进入
tmrpp；tmrpp 仅由用户按既定弹性服务器镜像同步流程处理，本手册不授权代理操作。
