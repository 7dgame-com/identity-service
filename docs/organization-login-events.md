# 组织登录流水

`GET /v1/plugin-user/login-events` 使用 Bearer JWT，需启用 `IDENTITY_LOGIN_AUDIT_ENABLED`。

当 `IDENTITY_DATA_SOURCE=identity` 时，账号、当前角色、组织成员和登录记录均来自 Identity 私库；每次请求验证当前会话与账号状态，不依赖 `IDENTITY_PLUGIN_USER_READONLY_ENABLED`、旧账号数据库或 staging shadow 表。缺少原生身份组件或私库时返回明确错误。

当 `IDENTITY_DATA_SOURCE=legacy` 时，仍需启用兼容入口 `IDENTITY_PLUGIN_USER_READONLY_ENABLED`，并配置 Legacy 与 Identity 数据库以执行迁移阶段的双边组织范围校验。

## 查询与返回

必填 `organization_id`（正整数）、`start_at`、`end_at`（带时区的 ISO 时间，起始包含、结束不包含）。可选 `search`（当前用户名或昵称，最多 255 字符）、`role`（`root/admin/manager/user/other`）、`page`（默认 1）、`pageSize`（默认 20，最多 100）。身份取当前最高角色；多角色优先级为 root > admin > manager > user。

返回 `{ code: 0, data: [...], pagination: { page, pageSize, total, totalPages } }`。每行包含 `eventKey`、`userId`、`username`、`nickname`、`primaryRole`、`occurredAt`（ISO）、`source`。仅查询已关联数字账号 ID（兼容字段名 `legacy_user_id`）的 `event_type='login' AND success=1` 事件，不返回原始 IP、Token、追踪标识或 metadata。

## 组织边界

仅允许 root、admin、manager；组织参数不可省略，即使 root 也不能请求全平台流水。非 root 还需属于目标组织。原生模式直接使用私库当前角色与完整组织关系；legacy 模式复用个人审计的 Legacy 与 Identity shadow 组织关系一致性校验。批量读取并确认目标成员后再搜索、筛选和计数。无法确认范围时返回 `ORGANIZATION_SCOPE_DENIED`，不会回退到宽范围数据。

组织按当前成员关系确定，不是登录时组织快照。加入组织后可查该账号历史事件；移出后不再可查。原生模式展示和筛选私库 `auth_assignment` 的当前角色，不以迁移候选分配覆盖其权限；legacy 模式保留既有的分阶段角色读取策略。无数据库、审计关闭、身份读取失败均返回明确错误，不当作空结果。

成员资料、角色、完整组织关系在账号数据库的只读事务内批量读取；仅 legacy 模式额外按批次读取 Identity shadow。事件计数和分页在同一只读快照内执行，排序为 `occurred_at DESC, id DESC`。沿用已有事件表及 `(legacy_user_id, occurred_at)` 索引，不需要组织流水数据回填。成员快照与事件快照分别读取，权限以本次请求读取的成员快照为准，后续请求重新校验。

个人登录审计仅向当前 root 返回完整 IP，其他已授权读取者收到脱敏 IP。组织账单使用当前成员账号，按 `IDENTITY_LOGIN_AUDIT_BILLING_TIMEZONE` 的自然日对成功登录去重；保留已有 `from`、`to` 两端包含的账单日期范围规则。

## 验证

```bash
npm test -- apps/identity-adapter/test/organization-login-events.spec.ts
npm test -- apps/identity-adapter/test/organization-login-events-native.spec.ts
npm run build
```

真实 SQL/HTTP 集成测试使用**一次性 MySQL 8 空实例**，不要指向业务数据库。测试以 root 连接 `127.0.0.1` 的指定端口，密码由 `LOGIN_EVENTS_MYSQL_TEST_PASSWORD` 提供（默认空），创建独立 `campus_login_test_<pid>` 库并在结束时删除；启动的容器需自行停止清理。CI 的 MySQL Integration 作业已包含此测试。

```bash
docker run --rm -d --name campus-login-test --tmpfs /var/lib/mysql \
  -e MYSQL_ALLOW_EMPTY_PASSWORD=yes -p 127.0.0.1:13317:3306 mysql:8.4
# 等待 MySQL 就绪后运行
LOGIN_EVENTS_MYSQL_TEST_PORT=13317 npm test -- apps/identity-adapter/test/organization-login-events.mysql.spec.ts
docker stop campus-login-test
```

集成测试覆盖真实密码登录、JWT、事件落库、失败登录/组织外账号排除、日期边界、超过 20 条的稳定分页、成员移出及 shadow 不一致。未指定测试端口时此套件默认跳过。

原生模式另有私库集成测试，使用同类一次性实例，创建随机测试库并在结束时删除；测试故意将旧账号数据库配置为不可达，并删除组织 shadow 表。运行时指定 `IDENTITY_TEST_MYSQL=1` 与测试实例连接参数：

```bash
TZ=Asia/Shanghai IDENTITY_TEST_MYSQL=1 \
  IDENTITY_DB_HOST=127.0.0.1 IDENTITY_DB_PORT=13317 \
  IDENTITY_DB_USER=root IDENTITY_DB_PASSWORD='' \
  npm test -- apps/identity-adapter/test/organization-login-events-native.mysql.spec.ts
```

此套件覆盖当前私库角色变更、成员移出、跨组织边界、撤销会话、UTC 日期绑定与稳定分页、IP 脱敏，以及按上海自然日计算账单。
