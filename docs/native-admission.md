# Native 请求准入适配器（默认关闭）

本适配器接 `driver/identity-dev-admission` 的私控协议，尚不能作为线上入口、全部 writer 已覆盖、真实排空或请求预算满足的证明。当前控制 URL 和子上游只允许同主机 `127.0.0.1` HTTP fixture；跨 host daemon、TLS/edge、双主备入口、完整实际 roster、进程观察与恢复仍须现场独立接通。没有云启动命令、凭据生成、public 激活 API 或自动 fallback。

`IDENTITY_ADMISSION_ENABLED` 默认 false。关闭时不读取 admission config/key 文件，现有认证、会话、SQL 和 bootstrap 规则保持。入口会删除 admission/continuation/instance/router/generation 伪标记；它们不参与用户授权。启用后以下两个现有受控文件必须由运行用户拥有、单硬链接、普通文件、无 symlink、group/other 不可访问：

- `IDENTITY_ADMISSION_CONFIG_FILE`：最多 32KiB，下面的严格 JSON。
- `IDENTITY_ADMISSION_KEY_FILE`：当前参与者已有的 boot 私控 key，canonical base64url、32..128 bytes、不带换行。不能从 JWT 派生、不自动生成；各参与者/operator 的 distinct key 由 coordinator 独立核验。

```json
{
  "version": 1,
  "controlUrl": "http://127.0.0.1:<reviewed-port>/",
  "identity": {
    "id": "<reviewed-instance-id>",
    "bootId": "<reviewed-current-boot-id>",
    "revision": "<exact-compiled-40hex-sha>",
    "routerHash": "<reviewed-router-64hex-sha>",
    "generation": "legacy"
  },
  "allowedChildren": [
    {"id":"<same-generation-child-id>","origin":"http://127.0.0.1:<child-port>","paths":["/internal/wechat-provider/qrcode","/internal/wechat-provider/profile"]}
  ],
  "childWaitMs": 1500
}
```

编译常量必须非空并精确匹配 revision；普通本地 build 不能启用。上述 JSON 是受控配置，不自动证明 router/roster 真实完整。实例 ID、boot、revision、router hash 和 generation 每次 RPC 都由 coordinator 核验。真实开发有 B0/B1 主备和共享私库，不能将此单进程配置当作完整现场拓扑。

## 入口与完成点

`IdentityAdmissionExpressAdapter` 在 Nest parser/auth/guard/session 之前装 middleware。`X-Identity-Admission-Lease` 只能有一个原始头、ASCII signed capability、最多 2048 bytes。私控 `enter` 成功才创建 writable scope；错实例、重复或重用 capability 不会降级成新 root，也不撤销另一真实 handler。没有 capability 的直接 HTTP 必须先 `begin` 再 `enter`；关闸后拒绝。公开 body/其它身份标记均不能选择 lease、consumer 或 scope。

只有不带 capability 的固定 `GET /health`、`GET /health/live` 走无写权限 probe。携带 gateway 已发 capability 时，即使 health 也必须真实 enter/complete，不能遗留 active lease；错误 capability 不因路径豁免。它们保留原 authority/DB/liveness 语义，不宣称 coordinator 全局已排空。任意其它 GET、错误路由、parser error 和普通 OPTIONS 都要真实 handler lease；CORS preflight 继续到经过包装的 OPTIONS fallback。health 路径上若尝试写方法，同样被拒绝。首位全局 AdmissionGuard 拒绝没有经过本入口 scope 的替代 Nest 启动；该检查先于原 explicit activation guard。

Nest `RouterProxy` 会 await 实际 route callback；本适配器包住这个 Promise 和 error/notfound callback 的 finally。`response.finish`、`response.end`、`response.close` 都不是完成证明。客户端异常断开只将本操作标为 unknown，随后事务即使提交也不能普通 complete 清除它。

写入通过显式 `@AdmissionWriter()` 方法登记到 AsyncLocalStorage scope，不改 mysql driver、不按 SQL 文本猜写入，也不替换 Pool/release。方法的 Promise 包含原 commit/rollback/release finally；无 lease 的直接 repository 写入会在进入方法前拒绝。已登记的未 await 方法仍在 pending 集合中，收尾 seal 后只允许这些尚未结束任务的重入子操作；没有登记的迟到 timer 不能启动新 writer。一旦 unknown，不能通过 scope.run/track 登记新工作，原已登记 Promise 的事务 commit/rollback/release finally 可实际收尾，但不能借其上下文新增 typed 写入。已知 SQL 连接异常或原 quiet rollback 失败会保留 unknown。未知/遗漏的原始 SQL、外部 cron、动态 provider、自定义异步 filter/streaming 不会因此被自动证明覆盖。

当前显式写边界包括账户注册/密码/邮箱/验证码、原生 session/OIDC/graph/旧凭据/ownerless signup、Native mutate/MDM transaction、Apple/WeChat OAuth、邀请、IAM shadow/materialization/operation ledger、audit/billing 和 Redis invitation command。正式 account/sync/session/provider/QR/challenge/graph/allocator/activation CLI 的写函数也前置 scope guard：启用环境里无专门已审 CLI scope 会直接拒绝。下面的固定迁移入口已有局部实现，**仍没有完整 CLI lease runner，不能称激活/最终同步已接入屏障。** 新 writer 必须独立审核并显式登记；此列表不是自动拓扑发现。

`admissionFetch` 在发行 continuation 之前登记整个异步任务，只允许配置中的固定 origin+exact path 和 coordinator `allowedChildren` 的同 generation 目标。保留原有内部认证/用户认证，删除旧伪标记，注入唯一新 child capability，拒绝重定向。Identity 当前 HTTP 外呼（provider、legacy proxy/revoke、邮件 webhook）都经过该 helper；未接真实 callee adapter 时必须拒绝或保留 unknown。SMTP 由本地 typed email method await 原 send/cancel/cleanup，不声称远端邮件系统已成为 roster participant。

父 scope 完成前验证原 operation/root/epoch、unknown=false、childrenActive=0；子 HTTP 响应不能替代子 complete。默认 child wait 总 1500ms、每次 25ms，只能配置 25..5000ms；本进程从最早 header 到达的单调时间计时，handler/control 时间消耗该预算，不能在 finish 续期。未发行 child 的长 handler 只允许一次 bounded validate 证明没有 child；有 child 则读取也受剩余预算限制。edge 原始排队预算仍是外部门槛，capability 当前没有携带跨服务 deadline，不能据此声称端到端预算已经验证。

continue 前和 ACK 后都核对原剩余预算，超时不开始远端 fetch；fetch signal 同样受剩余预算与原 caller signal 限制。已发行 child 后的失败须保留 parent/child unknown，不能把网络尚未调用当作取消证明。

complete 只发一次。仅按 action 对应的已审无副作用拒绝 code 和精确 409 形状处理为确定拒绝；5xx、未知/日志错误 409、畸形错误或成功 ACK 均永久锁住本实例并尝试既有 private lost。unknown 的拒绝或 ACK 失败同样走 lost，不能吞掉错误后重新 register、自动重试 mutation 或退回旧系统。暂存日志/实际 receipt/真实进程结果的恢复由 coordinator 的独立审核处理。

## 启动和现场门槛

main 在 create/init 前独立 register。旧 generation 的启动写入必须独立 begin+enter，包住整个 Nest create/init，完成后才 listen；不能借 HTTP lease 假包初始化。Native 启用 admission 时必须使用既有 explicit activation：在只读 probe scope create/init，任何 module init writer 都拒绝，仍保持原预热零账号/凭据/event 写入合同。默认 explicit activation schema/receipt/allocator proof 没有修改。启动先后及全部 participant 注册是外部协调条件，失败不自动重试启动写入。

本地测试使用 compiled AppModule/真实 Nest middleware/guard、随机私库、真实 event clock 行锁、事务提交及连接 KILL、断开客户端和本机 coordinator。它证明此候选进程的上述边界，不证明 B0/B1、F、PHP/A1/Y1、所有 ingress/worker 已切换。

```sh
IDENTITY_TEST_MYSQL=1 IDENTITY_TEST_MYSQL_HOST=127.0.0.1 \
IDENTITY_TEST_MYSQL_PORT=13316 IDENTITY_TEST_MYSQL_USER=root \
IDENTITY_TEST_MYSQL_PASSWORD='' node node_modules/vitest/vitest.mjs run \
  apps/identity-adapter/test/identity-admission.mysql.spec.ts
```

只允许本机专用 13316，或 GitHub CI 明确声明下的 loopback 3306，随机 `_test` 库 finally 清理。没有真实 stable key、云 DB/Redis/Portainer 操作。

## 独立仓库测试依赖

27 项真实 Nest/MySQL 准入测试始终加载 `apps/identity-adapter/test/support/admission-protocol/` 中冻结的五个正式 driver 模块；来源提交和每文件 SHA-256 记录在其 `manifest.json`。这使独立服务仓库的 CI 不再依赖超级项目目录。测试先核对所有冻结摘要；本地存在上游目录时再逐字核对，漂移即失败。上游缺席不会跳过测试，也不会换成 mock。更新流程见同目录 README；该快照只用于测试，不进入产品 runtime 接线。

## 专用迁移入口的局部合同

`identity-migration-entry.ts` 固定注册 `account-sync`、`allocator-highwater`、`identity-activate` 三个 compiled entry 身份，分别只接受明确的 typed invocation。没有 pathname、command、环境配置覆盖、动态 import 或外部 callback。它直接 await 现有业务 core；SQL、事务、fence 以及原 proof/deadline 校验保持原实现。普通 HTTP writable scope 不能执行这三个 core；迁移上下文也不能调用普通或装饰器 writer。allocator scope 仅额外允许固定的同步只读前置审核，不能 sync apply、直接账户导入、fresh allocator 或激活。

`NativeMigrationAdmission.environment()` 默认因缺少 `IDENTITY_MIGRATION_CONFIG_FILE`/`IDENTITY_MIGRATION_KEY_FILE` 拒绝，错误为 `MIGRATION_ENTER_NOT_WIRED`。它不创建 key、不提供 server、不注册普通 HTTP active、不调用 begin/complete。配置和 key 只读取已有的 owner 私有普通文件。严格配置为 `{version:1,controlUrl,executor:{id,bootId},compiledRevision,imageDigest,target}`；URL 仅同机 `http://127.0.0.1:<port>/`，target 固定为 `10.206.0.5:3306/xrugc_identity_dev/identity_dev/fenceId=1`，revision 必须匹配不可变编译值。

私控服务端接线仍缺失：未来 `migration-enter` 必须认证专用 executor/boot，核对已绑定 ledger 的当前唯一 active claim，并验证和消费不可伪造、单用的 claim capability；plain claim、HTTP lease 或自报字段都不能签发权限。本客户端要求完整 claim、请求 nonce/SHA 和严格 ACK 绑定，才创建内部 WeakMap 记录的单用 scope；claim 包含 run、claim、entry/mode、inputs、target、revision/image、plan/drain/epoch、deadline 与链摘要。请求应答丢失、畸形、超时或业务错误会永久锁存本地 unknown，仅尝试一次 best-effort unknown 通报，不能重试 enter/complete 或恢复为 verified。剩余截止时间不得超过原 3 秒窗口。

typed invocation 在首个 await 前拒绝非 plain/proxy/accessor、额外 symbol/非枚举字段，同步捕获固定连接和 journal 引用、复制所有输入 Buffer。随后检查字节摘要、实际 mysql2 endpoint/socket、`DATABASE()`/`CURRENT_USER()`、固定实例 UUID `1c6c32c4-00a9-11f1-9d18-0c42a14c701e` 和固定源库。object binding 使用 canonical JSON **不含 LF**，与 driver `migrationDigest` 一致；报告工件则按实际完整字节（包括 LF）计算摘要。冻结的真实 ledger claim 互操作 fixture 记录 root 来源提交及五个源文件摘要，避免客户端和测试用同一错误算法而互相通过。

source/target/fence 均先检查 autocommit，再用 `SET TRANSACTION ISOLATION LEVEL REPEATABLE READ` 拒绝已有事务；该语句在 MySQL 既有事务中报错，不隐式 commit/rollback，不建立外层事务或 fence。连接仍必须来自受信 owner，禁止其它调用方并发复用；本入口不能单靠一个 Connection 对象证明独占生命周期。业务 core 继续做自身独立校验。allocator/activation apply 必须提供 `MigrationResources` 已持有的 journal 对象；任意结构相同对象、改写方法或 callback 均拒绝。内部固定 callbacks await journal write/file fsync/parent fsync。品牌仅证明资源 owner，**不证明 artifact 的路径、所有者/祖先信任、工件来源或运行版本**；本地 helper 的 parent 检查也不能消除 ABA/同目录项替换等竞态。

返回值仅为真实 sync report、allocator plan+summary 或 activation result，不包含 `connectionsClosed`、`sideEffectsFinished` 或 ledger completed。调用方仍须持有真实连接/file owner、等待所有资源实际关闭、核对工件/镜像/运行身份，再向独立 ledger 完成步骤。source snapshot 当前仅绑定已审工件的字节摘要，**尚未证明实际数据库前后 fingerprint 与该快照一致**。可信 FD 输入桥、前后 source fingerprint 读器、不可变工件来源和完整 server/runner 都尚未接通，不能回退到重开 pathname，也不能把结果或文件存在当作全局完成证明。本地真实 MySQL 测试仅在临时 compiled fixture 树替换固定目标/实例 UUID/编译 revision；产品源码没有 fixture flag、可配置目标或测试 scope 签发器。
