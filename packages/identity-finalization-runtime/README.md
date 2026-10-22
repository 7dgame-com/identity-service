# 固定 Native 迁移运行包

此目录 vendor 自超级项目 `8f24384aee82d8bf03e6e799d57ed7d48d9d8a0a:driver/identity-dev-admission`。`upstream-manifest.json` 记录两份原始 `.mjs` 的 SHA；`scripts/verify-identity-finalization-runtime.mjs` 另有固定 commit／SHA 信任锚，不能通过同时改写文件和 manifest 绕过。这里只提供固定 artifact／journal 和纯 typed report 校验，不自行授予迁移权限。

专用镜像须显式构建 `--target migration-executor` 并提供完整 40 位 `BUILD_REVISION`。默认最后 stage 仍为原 `runtime`，HTTP 命令保持 `node dist/apps/identity-adapter/src/main.js`。CI 的 `publish_executor` 默认 false，仅 workflow_dispatch 可发布专用 target；先通过全部 mandatory test／MySQL gate，再使用同 registry 的单一 `executor-<SHA>-<run>-<attempt>` 标签。发布后按精确 digest 拉取，禁网／只读执行实际布局校验，单独保存 executor provenance（stage、source SHA、digest、compiled／OCI revision、运行文件 hash），不复用 HTTP artifact。本次没有构建、发布或部署线上镜像。

专用布局为 `/opt/xrugc/identity`：

- `GIT_COMMIT`：构建 revision 加一个 LF；须与实际生成的 compiled revision 一致。
- `dist/scripts/identity-owned-executor.js`：固定 ENTRYPOINT，无命令行参数。
- `dist/packages/identity-finalization-runtime/*.mjs`：在 TypeScript 编译后用两份审过的原始文件精确覆盖，再验证实际运行字节。manifest 的源 SHA 因此同时匹配专用 stage 的运行字节，未将 TypeScript emit 的近似文本当作相同 SHA。
- Native entry 和 resources 都静态导入这个相同 dist module URL；journal lease 的 WeakMap 品牌不跨模块副本，不接受结构相似的 FD 或 callback。

运行用户为 `node`（UID 1000）。构建仅建立空的 `/run/xrugc/identity-finalization/{config,inputs,reports}` 目录，叶目录 UID 1000／0700，可信父目录 root／0755；不生成 key、凭据或迁移输入。操作员受控挂载的配置与输入须 UID 1000、0600、单链接、无符号链接，并满足 adapter 的可信祖先检查。固定配置文件名为 `config/migration.json`、`config/migration.key`、`config/database.json`；专用入口拒绝非固定 config／key 环境路径。数据库连接的主机、库及 target 主体由 Native 固定，不能从控制帧提供。

私有 launcher 使用 libuv pipe／socket 包装继承的 **FD 3**，不把它当任意 regular file 打开；读取紧凑 NDJSON `{claim,claimCapability}`，按照 sync-apply、sync-zero、allocator、activation 四步执行 prepare → enterOwned → executeOwnedStep → completeOwned。单帧最多 16KiB，每帧另有绝对 2 秒控制等待预算（不随 chunk 续期，不延长原业务 3 秒硬窗）；拒绝额外字段、重复 JSON key、越界、缺帧、变更顺序与路径参数。stdout 只输出有界 `prepared`／`completed` 进度及公共 hash，逐帧等待 write callback；不会输出 capability、key 或数据库配置。stdout 不是 ledger 完成证明。

资源证明来自 Native 内部品牌 receipt：实际连接、socket、C artifact 与接管 journal 全部关闭之后才可提交私有 completion。入口结束还必须等待 FD 3 的实际 socket close，以及尚存 prepared 输入的关闭；先 destroy 取消待读取，再等待 iterator.return／close，不能以 timeout 或 iterator.return 冒充关闭。输入、stdout 或关闭失败会调用无参 poison 方法通报 unknown，保留原操作与关闭错误并以 exit 3 结束；没有自动重试。**parent 必须等待整个 `runOwnedExecutor` Promise 成功及私有 coordinator gate，才可确认开闸；不能只看 stdout、第四步 completion ACK 或 ledger 的四步计数。** 最终控制 FD 关闭失败仍会将已完成步骤的 run 封 unknown。

新增定向测试是 `identity-owned-executor-launcher.spec.ts`（真实私有 Unix socket FD／延迟关闭／关闭失败／peer 保持开放不写的预算）和 `identity-owned-executor-packaging.spec.ts`（实际 TypeScript 编译布局、精确运行字节、来源 hash、变造拒绝、无副作用导入及缺配置 CLI 拒绝）；workflow spec 实际执行公共 provenance 程序并核对原 HTTP job 未变。布局测试使用公共合成 revision，不冒充已构建镜像；不创建凭据、不连接数据库或云。实际镜像摘要、只属于开发环境的配置交接、同 host 私有控制进程、真实窗口预算和端到端迁移仍需单独验收。本机并行运行和串行运行均曾在 Hub 外置 APFS 卷触发真实 3 秒失败；分项测量显示 journal／typed-output 文件 fsync 是主要成本，不能只归因于 CPU。fixture 报告目录随后仅改为 OS tmpdir 中独占的 0700 临时目录，保留实际 fsync、回读、全部 FD 关闭及原窗口位置／预算；原失败和 I/O profile 保留。mandatory 独立 MySQL 组串行执行；本机 OS 临时文件系统通过不证明云端持久存储或线上窗口预算通过。
