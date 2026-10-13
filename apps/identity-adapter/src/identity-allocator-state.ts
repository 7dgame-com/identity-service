import type {
  Connection,
  Pool,
  PoolConnection,
  RowDataPacket,
} from "mysql2/promise";
import {
  allocatorTables,
  allocatorDigest,
  allocatorFail,
  integer,
  normalizeAllocatorManifest,
  type AllocatorManifest,
  type AllocatorTable,
} from "./identity-allocator-manifest.js";
import { allocatorSchema } from "./identity-allocator-schema.js";
import { assertMigrationStaging } from "./migration-state.js";
export type AllocatorConnection = Connection | PoolConnection;
export const formalAllocatorTables = [
  "account_lifecycle_operations",
  "account_usage_balance_shadow",
  "auth_assignment",
  "auth_item",
  "auth_item_child",
  "auth_login_events",
  "auth_rule",
  "email_change_tokens",
  "email_verification_challenges",
  "iam_reconciliation_items",
  "iam_reconciliation_runs",
  "identity_account_import_runs",
  "identity_account_password_requests",
  "identity_account_registration_requests",
  "identity_apple_challenges",
  "identity_apple_identities",
  "identity_apple_import_runs",
  "identity_auth_subject_maps",
  "identity_event_clock",
  "identity_invitations",
  "identity_legacy_challenge_imports",
  "identity_legacy_challenge_limits",
  "identity_legacy_invitation_days",
  "identity_legacy_link_email_limits",
  "identity_legacy_profile_history",
  "identity_legacy_profile_rows",
  "identity_legacy_refresh_credentials",
  "identity_legacy_trial_claims",
  "identity_legacy_wechat_signup_credentials",
  "identity_login_codes",
  "identity_migration_control",
  "identity_migration_rows",
  "identity_native_operations",
  "identity_oauth_session_bindings",
  "identity_oidc_session_bindings",
  "identity_organization_memberships_shadow",
  "identity_organization_name_locks",
  "identity_password_reset_tokens",
  "identity_profile_avatars",
  "identity_refresh_replays",
  "identity_refresh_sessions",
  "identity_registration_email_limits",
  "identity_role_assignments_shadow",
  "identity_subject_events",
  "identity_subject_maps",
  "identity_user_revocations",
  "identity_users",
  "identity_wechat_identities",
  "identity_wechat_import_runs",
  "identity_wechat_oauth_codes",
  "identity_wechat_scenes",
  "invitation",
  "invitation_email_challenges",
  "invitation_quota_ledger",
  "invitation_record",
  "organization",
  "password_reset_challenges",
  "usage_billing_ledger",
  "usage_billing_replay_runs",
  "user",
  "user_info",
  "user_login_stats",
  "user_organization",
  "wechat",
] as const;
const allowedPrivateTables = new Set<string>([
  ...formalAllocatorTables,
  "identity_activation_receipt",
  "identity_legacy_refresh_graph_families",
  "identity_legacy_refresh_graph_credentials",
  "identity_legacy_refresh_graph_replays",
  "identity_iam_item_relations",
  "identity_iam_permissions",
  "identity_iam_policy_versions",
  "identity_iam_roles",
  "identity_iam_subject_assignments",
  "identity_organization_id_map",
  "identity_organization_membership_snapshots",
  "identity_organization_memberships_candidate",
  "identity_organization_write_operations",
  "identity_organizations_candidate",
  "plugin_user_write_operations",
  "profile_write_operations",
  "identity_migration_allocator_state",
  "oidc_authorization_codes",
]);
export const quoteIdentifier = (name: string) => {
  if (!/^[a-zA-Z0-9_]{1,64}$/.test(name))
    allocatorFail("ALLOCATOR_INVALID_IDENTIFIER");
  return "`" + name + "`";
};
export interface Column {
  table_name: string;
  column_name: string;
  column_type: string;
  extra: string;
}
export interface AllocatorInventory {
  database: string;
  columns: Column[];
  counters: Record<AllocatorTable, string>;
  capacities: Record<AllocatorTable, string>;
  reserved: Record<AllocatorTable, string>;
  schemaSha256: string;
}
export function columnCapacity(type: string): bigint {
  const match = type
    .toLowerCase()
    .match(
      /^(tinyint|smallint|mediumint|int|bigint)(?:\([0-9]+\))?( unsigned)?$/,
    );
  if (!match) allocatorFail("ALLOCATOR_UNSUPPORTED_ID_TYPE");
  const bits = (
    { tinyint: 8, smallint: 16, mediumint: 24, int: 32, bigint: 64 } as Record<
      string,
      number
    >
  )[match[1]];
  const max = (1n << BigInt(bits - (match[2] ? 0 : 1))) - 1n;
  return max < BigInt(Number.MAX_SAFE_INTEGER)
    ? max
    : BigInt(Number.MAX_SAFE_INTEGER);
}
export async function allocatorDatabase(
  c: AllocatorConnection,
): Promise<string> {
  const [r] = await c.query<RowDataPacket[]>("SELECT DATABASE() AS name");
  if (typeof r[0]?.name !== "string")
    allocatorFail("ALLOCATOR_DATABASE_REQUIRED");
  return r[0].name;
}
export async function columnsFor(c: AllocatorConnection): Promise<Column[]> {
  const [rows] = await c.query<RowDataPacket[]>(
    `SELECT TABLE_NAME AS table_name,COLUMN_NAME AS column_name,COLUMN_TYPE AS column_type,EXTRA AS extra FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() ORDER BY TABLE_NAME,ORDINAL_POSITION`,
  );
  if (rows.length > 4096) allocatorFail("ALLOCATOR_SCHEMA_BOUND");
  return rows as Column[];
}
async function assertPrivateSchema(c: AllocatorConnection, columns: Column[]) {
  const actual = new Set(columns.map((x) => x.table_name));
  for (const t of formalAllocatorTables)
    if (!actual.has(t)) allocatorFail("ALLOCATOR_REQUIRED_TABLE_MISSING");
  for (const t of actual)
    if (!allowedPrivateTables.has(t))
      allocatorFail("ALLOCATOR_UNREVIEWED_PRIVATE_TABLE");
  const [tables] = await c.query<RowDataPacket[]>(
    "SELECT TABLE_NAME AS name,ENGINE AS engine FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_TYPE='BASE TABLE'",
  );
  if (tables.some((t) => t.engine !== "InnoDB"))
    allocatorFail("ALLOCATOR_NONTRANSACTIONAL_TABLE");
}
export async function maximum(
  c: AllocatorConnection,
  table: string,
  column: string,
  condition = "",
): Promise<bigint> {
  const [r] = await c.query<RowDataPacket[]>(
    `SELECT CAST(MAX(${quoteIdentifier(column)}) AS CHAR) AS value FROM ${quoteIdentifier(table)}${condition}`,
  );
  return r[0]?.value == null ? 0n : integer(String(r[0].value));
}
export function referenceNamespace(col: Column): AllocatorTable | null {
  if (
    col.table_name === "identity_subject_maps" &&
    col.column_name === "subject_id"
  )
    return null;
  if (
    col.column_name === "identity_user_id" ||
    col.column_name === "auth_user_id" ||
    col.column_name === "identity_organization_id"
  )
    return null;
  if (
    col.column_name === "user_id" ||
    col.column_name.endsWith("_user_id") ||
    [
      "created_by",
      "inviter_id",
      "invitee_id",
      "sender_id",
      "recipient_id",
    ].includes(col.column_name)
  )
    return "user";
  if (
    col.column_name === "organization_id" ||
    col.column_name.endsWith("_organization_id")
  )
    return "organization";
  if (
    [
      "identity_legacy_profile_rows",
      "identity_legacy_profile_history",
    ].includes(col.table_name) &&
    ["id", "selected_profile_id"].includes(col.column_name)
  )
    return "user_info";
  if (
    col.table_name === "identity_legacy_wechat_signup_credentials" &&
    col.column_name === "source_record_id"
  )
    return "wechat";
  if (col.column_name === "invitation_id") return "invitation";
  return null;
}
/** Only the existing canonical writer's explicit legacy namespace is numeric. UUID/provider IDs stay opaque. */
function explicitLegacyReference(value: unknown): bigint | null {
  if (typeof value !== "string" || !value.toLowerCase().startsWith("legacy:"))
    return null;
  if (!/^legacy:[1-9][0-9]*$/.test(value))
    allocatorFail("ALLOCATOR_NONCANONICAL_SUBJECT_REFERENCE");
  return integer(value.slice(7));
}
/** All states count: deleted accounts, expired sessions and tombstones reserve IDs. */
export async function readPrivateAllocatorInventory(
  c: AllocatorConnection,
): Promise<AllocatorInventory> {
  const database = await allocatorDatabase(c),
    columns = await columnsFor(c);
  await assertPrivateSchema(c, columns);
  const reserved = Object.fromEntries(
    allocatorTables.map((t) => [t, 0n]),
  ) as Record<AllocatorTable, bigint>;
  const capacities = Object.fromEntries(
    allocatorTables.map((t) => [t, BigInt(Number.MAX_SAFE_INTEGER)]),
  ) as Record<AllocatorTable, bigint>;
  capacities.user = 2147483647n; // Existing business user/projection foreign keys are signed INT.
  for (const col of columns) {
    let ns = referenceNamespace(col);
    if (
      allocatorTables.includes(col.table_name as AllocatorTable) &&
      col.column_name === "id"
    )
      ns = col.table_name as AllocatorTable;
    if (!ns) continue;
    if (col.table_name === "auth_assignment" && col.column_name === "user_id") {
      const [invalid] = await c.query<RowDataPacket[]>(
        "SELECT 1 FROM auth_assignment WHERE user_id IS NOT NULL AND NOT REGEXP_LIKE(user_id,'^[1-9][0-9]*$','c') LIMIT 1",
      );
      if (invalid.length)
        allocatorFail("ALLOCATOR_NONCANONICAL_USER_REFERENCE");
      const [r] = await c.query<RowDataPacket[]>(
        "SELECT CAST(MAX(CAST(user_id AS DECIMAL(65,0))) AS CHAR) AS value FROM auth_assignment",
      );
      const n = r[0]?.value == null ? 0n : integer(String(r[0].value));
      if (n > reserved[ns]) reserved[ns] = n;
      continue;
    }
    const cap = columnCapacity(col.column_type);
    if (cap < capacities[ns]) capacities[ns] = cap;
    const n = await maximum(c, col.table_name, col.column_name);
    if (n > reserved[ns]) reserved[ns] = n;
  }
  for (const col of columns) {
    const ns =
      col.column_name === "identity_organization_id"
        ? "organization"
        : col.column_name === "identity_user_id" ||
            (col.table_name === "identity_users" && col.column_name === "id")
          ? "user"
          : null;
    if (!ns) continue;
    const field = quoteIdentifier(col.column_name);
    const [rows] = await c.query<RowDataPacket[]>(
      `SELECT ${field} AS value FROM ${quoteIdentifier(col.table_name)} WHERE ${field} IS NOT NULL AND LOWER(LEFT(${field},7))='legacy:' LIMIT 100001`,
    );
    if (rows.length > 100000) allocatorFail("ALLOCATOR_REFERENCE_BOUND");
    for (const row of rows) {
      const n = explicitLegacyReference(row.value);
      if (n !== null && n > reserved[ns]) reserved[ns] = n;
    }
  }
  const [maps] = await c.query<RowDataPacket[]>(
    "SELECT subject_id FROM identity_subject_maps WHERE subject_type='legacy_user' LIMIT 100001",
  );
  if (maps.length > 100000) allocatorFail("ALLOCATOR_REFERENCE_BOUND");
  for (const r of maps) {
    if (typeof r.subject_id !== "string" || !/^[1-9][0-9]*$/.test(r.subject_id))
      allocatorFail("ALLOCATOR_NONCANONICAL_USER_REFERENCE");
    const n = integer(r.subject_id);
    if (n > reserved.user) reserved.user = n;
  }
  for (const table of [
    "identity_subject_maps",
    "usage_billing_ledger",
    "account_usage_balance_shadow",
  ]) {
    const [rows] = await c.query<RowDataPacket[]>(
      `SELECT subject_type,subject_id FROM ${quoteIdentifier(table)} WHERE subject_type IN ('legacy_user','user','organization','legacy_organization') LIMIT 100001`,
    );
    if (rows.length > 100000) allocatorFail("ALLOCATOR_REFERENCE_BOUND");
    for (const row of rows) {
      const value = String(row.subject_id);
      let numeric: string | null = null;
      if (["legacy_user", "legacy_organization"].includes(row.subject_type))
        numeric = value;
      else if (/^[1-9][0-9]*$/.test(value)) numeric = value;
      else if (/^(?:legacy:|identity:legacy:)[1-9][0-9]*$/.test(value))
        numeric = value.slice(value.lastIndexOf(":") + 1);
      else if (
        row.subject_type === "user" &&
        /^(?:identity:|username:).+/.test(value)
      )
        continue;
      else allocatorFail("ALLOCATOR_NONCANONICAL_SUBJECT_REFERENCE");
      if (!numeric || !/^[1-9][0-9]*$/.test(numeric))
        allocatorFail("ALLOCATOR_NONCANONICAL_SUBJECT_REFERENCE");
      const n = integer(numeric);
      const ns = ["organization", "legacy_organization"].includes(
        row.subject_type,
      )
        ? "organization"
        : "user";
      if (n > reserved[ns]) reserved[ns] = n;
    }
  }
  const [plugins] = await c.query<RowDataPacket[]>(
    "SELECT subject_id FROM identity_subject_maps WHERE subject_type='plugin_user' LIMIT 100001",
  );
  if (plugins.length > 100000) allocatorFail("ALLOCATOR_REFERENCE_BOUND");
  for (const row of plugins) {
    if (!/^legacy:[1-9][0-9]*$/.test(String(row.subject_id)))
      allocatorFail("ALLOCATOR_NONCANONICAL_USER_REFERENCE");
    const n = integer(String(row.subject_id).slice(7));
    if (n > reserved.user) reserved.user = n;
  }
  for (const prefix of ["legacy", "identity"]) {
    const [rows] = await c.query<RowDataPacket[]>(
      `SELECT ${prefix}_subject_type AS type,${prefix}_subject_id AS value FROM iam_reconciliation_items WHERE ${prefix}_subject_type IN ('legacy_user','organization','legacy_organization') LIMIT 100001`,
    );
    if (rows.length > 100000) allocatorFail("ALLOCATOR_REFERENCE_BOUND");
    for (const row of rows) {
      if (!/^[1-9][0-9]*$/.test(String(row.value)))
        allocatorFail("ALLOCATOR_NONCANONICAL_SUBJECT_REFERENCE");
      const ns = row.type === "legacy_user" ? "user" : "organization",
        n = integer(String(row.value));
      if (n > reserved[ns]) reserved[ns] = n;
    }
  }
  const [identitySubjects] = await c.query<RowDataPacket[]>(
    "SELECT identity_subject_type AS type,identity_subject_id AS value FROM iam_reconciliation_items WHERE identity_subject_type IN ('identity_user','identity_organization') LIMIT 100001",
  );
  if (identitySubjects.length > 100000)
    allocatorFail("ALLOCATOR_REFERENCE_BOUND");
  for (const row of identitySubjects) {
    const n = explicitLegacyReference(row.value),
      ns = row.type === "identity_user" ? "user" : "organization";
    if (n !== null && n > reserved[ns]) reserved[ns] = n;
  }
  await c.query("SET SESSION information_schema_stats_expiry=0");
  const [meta] = await c.query<RowDataPacket[]>(
    "SELECT TABLE_NAME AS name,CAST(AUTO_INCREMENT AS CHAR) AS next_id FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() ORDER BY TABLE_NAME",
  );
  const counters = {} as Record<AllocatorTable, string>;
  for (const t of allocatorTables) {
    const col = columns.find(
      (x) => x.table_name === t && x.column_name === "id",
    );
    const row = meta.find((x) => x.name === t);
    if (!col?.extra.includes("auto_increment") || row?.next_id == null)
      allocatorFail("ALLOCATOR_COUNTER_MISSING");
    counters[t] = integer(row.next_id).toString();
  }
  return {
    database,
    columns,
    counters,
    capacities: Object.fromEntries(
      allocatorTables.map((t) => [t, capacities[t].toString()]),
    ) as Record<AllocatorTable, string>,
    reserved: Object.fromEntries(
      allocatorTables.map((t) => [t, reserved[t].toString()]),
    ) as Record<AllocatorTable, string>,
    schemaSha256: allocatorDigest(columns),
  };
}
/** No DDL in an import transaction. An absent checkpoint already forbids activation. */
export async function invalidateAllocatorReady(
  c: AllocatorConnection,
): Promise<void> {
  const [exists] = await c.query<RowDataPacket[]>(
    "SELECT 1 FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='identity_migration_allocator_state'",
  );
  if (exists.length)
    await c.execute(
      "UPDATE identity_migration_allocator_state SET state='pending',updated_at=UTC_TIMESTAMP(3) WHERE id=1",
    );
}
async function assertFreshEmpty(c: AllocatorConnection) {
  const columns = await columnsFor(c);
  await assertPrivateSchema(c, columns);
  for (const t of new Set(columns.map((x) => x.table_name))) {
    if (
      [
        "identity_migration_allocator_state",
        "identity_migration_control",
        "identity_event_clock",
      ].includes(t)
    )
      continue;
    if (t === "auth_item") {
      const [r] = await c.query<RowDataPacket[]>(
        "SELECT name,type,description,rule_name,data FROM auth_item ORDER BY name",
      );
      if (
        r.length !== 4 ||
        r.some(
          (x) =>
            !["root", "admin", "manager", "user"].includes(x.name) ||
            Number(x.type) !== 1 ||
            x.description !== x.name ||
            x.rule_name !== null ||
            x.data !== null,
        )
      )
        allocatorFail("ALLOCATOR_FRESH_NOT_EMPTY");
      continue;
    }
    const [r] = await c.query<RowDataPacket[]>(
      `SELECT 1 FROM ${quoteIdentifier(t)} LIMIT 1`,
    );
    if (r.length) allocatorFail("ALLOCATOR_FRESH_NOT_EMPTY");
  }
  await c.query("SET SESSION information_schema_stats_expiry=0");
  const [sequences] = await c.query<RowDataPacket[]>(
    "SELECT CAST(AUTO_INCREMENT AS CHAR) AS next_id FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND AUTO_INCREMENT IS NOT NULL",
  );
  if (sequences.some((x) => integer(String(x.next_id)) !== 1n))
    allocatorFail("ALLOCATOR_FRESH_SEQUENCE_HISTORY");
  const [control] = await c.query<RowDataPacket[]>(
    "SELECT id,authority,activated_at FROM identity_migration_control",
  );
  const [clock] = await c.query<RowDataPacket[]>(
    "SELECT id FROM identity_event_clock",
  );
  if (
    control.length !== 1 ||
    Number(control[0].id) !== 1 ||
    control[0].authority !== "staging" ||
    control[0].activated_at !== null ||
    clock.length !== 1 ||
    Number(clock[0].id) !== 1
  )
    allocatorFail("ALLOCATOR_INVALID_FRESH_SEEDS");
}
/** Explicit fresh installer only; never inferred from an empty user table or an ENV flag. */
export async function initializeFreshAllocator(
  c: AllocatorConnection,
): Promise<void> {
  await c.query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ");
  const [mode] = await c.query<RowDataPacket[]>(
    "SELECT @@autocommit AS enabled",
  );
  if (Number(mode[0]?.enabled) !== 1)
    allocatorFail("ALLOCATOR_IDLE_AUTOCOMMIT_REQUIRED");
  await c.query(allocatorSchema);
  await c.beginTransaction();
  try {
    await assertMigrationStaging(c);
    const [r] = await c.query<RowDataPacket[]>(
      "SELECT id FROM identity_migration_allocator_state FOR UPDATE",
    );
    if (r.length) allocatorFail("ALLOCATOR_ALREADY_INITIALIZED");
    await assertFreshEmpty(c);
    const inv = await readPrivateAllocatorInventory(c);
    const m: AllocatorManifest = {
      version: 1,
      kind: "fresh",
      targetDatabase: inv.database,
      capturedAt: new Date().toISOString(),
      source: null,
      drain: null,
      baseline: null,
      floors: Object.fromEntries(
        allocatorTables.map((t) => [
          t,
          {
            floor: inv.counters[t],
            capacity: inv.capacities[t],
            sourceNext: null,
            reservedMax: "0",
          },
        ]),
      ) as AllocatorManifest["floors"],
    };
    normalizeAllocatorManifest(m);
    await c.execute(
      "INSERT INTO identity_migration_allocator_state(id,state,manifest_json,manifest_sha256,finalized_at) VALUES(1,'ready',?,?,UTC_TIMESTAMP(3))",
      [JSON.stringify(m), allocatorDigest(m)],
    );
    await c.commit();
  } catch (e) {
    await c.rollback();
    throw e;
  }
}
/** Caller holds identity_migration_control FOR UPDATE through validation and activation. */
export async function assertAllocatorReady(
  c: AllocatorConnection,
): Promise<AllocatorManifest> {
  const [state] = await c.query<RowDataPacket[]>(
    "SELECT id,state,manifest_json,manifest_sha256 FROM identity_migration_allocator_state FOR UPDATE",
  );
  if (state.length !== 1 || Number(state[0].id) !== 1)
    allocatorFail("ALLOCATOR_NOT_READY");
  if (state[0]?.state !== "ready") allocatorFail("ALLOCATOR_NOT_READY");
  let raw: unknown;
  try {
    raw =
      typeof state[0].manifest_json === "string"
        ? JSON.parse(state[0].manifest_json)
        : state[0].manifest_json;
  } catch {
    allocatorFail("ALLOCATOR_INVALID_MANIFEST");
  }
  const m = normalizeAllocatorManifest(raw);
  if (allocatorDigest(m) !== state[0].manifest_sha256)
    allocatorFail("ALLOCATOR_PROOF_DIGEST_MISMATCH");
  const [fence] = await c.query<RowDataPacket[]>(
    "SELECT authority FROM identity_migration_control WHERE id=1",
  );
  if (!["staging", "identity"].includes(fence[0]?.authority))
    allocatorFail("ALLOCATOR_INVALID_AUTHORITY");
  if (m.kind === "fresh" && fence[0].authority === "staging")
    await assertFreshEmpty(c);
  const inv = await readPrivateAllocatorInventory(c);
  if (inv.database !== m.targetDatabase)
    allocatorFail("ALLOCATOR_TARGET_MISMATCH");
  if (m.kind === "migrated") {
    const [baseline] = await c.execute<RowDataPacket[]>(
      "SELECT source_database FROM identity_account_import_runs WHERE import_key=?",
      [m.baseline!.importKey],
    );
    if (baseline[0]?.source_database !== m.source!.database)
      allocatorFail("ALLOCATOR_BASELINE_MISMATCH");
  }
  for (const t of allocatorTables) {
    const n = integer(inv.counters[t]),
      f = m.floors[t];
    if (
      n < integer(f.floor) ||
      n <= integer(inv.reserved[t]) ||
      n > integer(f.capacity) ||
      integer(f.capacity) > integer(inv.capacities[t])
    )
      allocatorFail("ALLOCATOR_COUNTER_UNSAFE");
  }
  return m;
}

export async function allocatorMutation<T>(
  c: AllocatorConnection,
  write: () => Promise<T>,
): Promise<T> {
  await invalidateAllocatorReady(c);
  return write();
}

/** Legacy reconciliation/materialization must not silently change reserved IDs after a finalized proof. */
export async function withAllocatorImportFence<T>(
  pool: Pool,
  work: (c: Pool | PoolConnection) => Promise<T>,
): Promise<T> {
  const [exists] = await pool.query<RowDataPacket[]>(
    "SELECT 1 FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='identity_migration_allocator_state'",
  );
  if (!exists.length) return work(pool); // Existing legacy deployments need no allocator table/proof.
  const c = await pool.getConnection();
  try {
    await c.beginTransaction();
    await assertMigrationStaging(c);
    await invalidateAllocatorReady(c);
    const result = await work(c);
    await c.commit();
    return result;
  } catch (e) {
    await c.rollback();
    throw e;
  } finally {
    c.release();
  }
}

export async function fenceAllocatorImport(
  c: AllocatorConnection,
): Promise<void> {
  const [exists] = await c.query<RowDataPacket[]>(
    "SELECT 1 FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='identity_migration_allocator_state'",
  );
  if (exists.length) {
    await assertMigrationStaging(c);
    await invalidateAllocatorReady(c);
  }
}
