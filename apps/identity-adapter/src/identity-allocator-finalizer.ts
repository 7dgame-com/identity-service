import type { RowDataPacket } from "mysql2/promise";
import {
  allocatorDigest,
  allocatorFail,
  allocatorTables,
  integer,
  normalizeAllocatorManifest,
  type AllocatorManifest,
  type AllocatorTable,
} from "./identity-allocator-manifest.js";
import {
  allocatorDatabase,
  columnsFor,
  columnCapacity,
  maximum,
  quoteIdentifier,
  readPrivateAllocatorInventory,
  referenceNamespace,
  type AllocatorConnection,
  type Column,
} from "./identity-allocator-state.js";
import { assertMigrationStaging } from "./migration-state.js";
export interface AllocatorDrainReview {
  version: 1;
  sourceDatabase: string;
  targetDatabase: string;
  importKey: string;
  sourceServerUuid: string;
  writersDrainedAt: string;
  finalSyncSha256: string;
  referenceReviewSha256: string;
}
export interface AllocatorPlan {
  manifest: AllocatorManifest;
  manifestSha256: string;
  sourceMetadataSha256: string;
  targetSchemaSha256: string;
  sourceStateSha256: string;
}
export type AllocatorStep = {
  table: AllocatorTable;
  phase: "intent" | "success";
  floor: string;
};
const approvedBusinessTables = new Set(
  "ai_rodin apple_id audit_log auth_assignment auth_item auth_item_child auth_rule code device device_sn edu_class edu_class_group edu_school edu_student edu_teacher failed_login_attempt feedback feedback_describe feedback_state file group group_user group_verse info invitation invitation_record local manager menu message meta meta_code meta_resource migration multilanguage_verse organization password_history phototype property resource scene_publication_revision security_config snapshot source_message space tags token token_revocation user user_info user_organization verse verse_code verse_meta verse_property verse_script verse_space verse_tags version vp_guide vp_key_value vp_level vp_map vp_score vp_token webmcp_authoring_task webmcp_operation wechat wx identity_user_projection_state identity_projection_checkpoint".split(
    " ",
  ),
);
function strictReview(r: AllocatorDrainReview) {
  if (
    Object.keys(r).sort().join(",") !==
      [
        "version",
        "sourceDatabase",
        "targetDatabase",
        "importKey",
        "sourceServerUuid",
        "writersDrainedAt",
        "finalSyncSha256",
        "referenceReviewSha256",
      ]
        .sort()
        .join(",") ||
    r.version !== 1 ||
    typeof r.sourceServerUuid !== "string" ||
    !/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(
      r.sourceServerUuid,
    ) ||
    !/^[A-Za-z0-9_]{1,64}$/.test(r.sourceDatabase) ||
    !/^[A-Za-z0-9_]{1,64}$/.test(r.targetDatabase) ||
    !/^[A-Za-z0-9_.:-]{1,160}$/.test(r.importKey) ||
    !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(r.writersDrainedAt) ||
    !Number.isFinite(Date.parse(r.writersDrainedAt)) ||
    new Date(r.writersDrainedAt).toISOString() !== r.writersDrainedAt ||
    Date.parse(r.writersDrainedAt) > Date.now() ||
    !/^[a-f0-9]{64}$/.test(r.finalSyncSha256) ||
    !/^[a-f0-9]{64}$/.test(r.referenceReviewSha256)
  )
    allocatorFail("ALLOCATOR_INVALID_DRAIN_REVIEW");
  if (
    r.targetDatabase === "xrugc_identity_dev" &&
    r.sourceDatabase !== "bujiaban_development"
  )
    allocatorFail("ALLOCATOR_SOURCE_TARGET_MISMATCH");
}
export async function readSourceAllocatorInventory(c: AllocatorConnection) {
  const database = await allocatorDatabase(c),
    columns = await columnsFor(c);
  const [location] = await c.query<RowDataPacket[]>(
    "SELECT @@server_uuid AS server_uuid",
  );
  const [fk] = await c.query<RowDataPacket[]>(
    "SELECT TABLE_NAME AS table_name,COLUMN_NAME AS column_name,REFERENCED_TABLE_NAME AS parent_table,REFERENCED_COLUMN_NAME AS parent_column FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA=DATABASE() AND REFERENCED_TABLE_SCHEMA=DATABASE() ORDER BY TABLE_NAME,COLUMN_NAME",
  );
  const references: {
    table_name: string;
    column_name: string;
    namespace: AllocatorTable;
    column_type: string;
  }[] = [];
  for (const f of fk) {
    if (
      !allocatorTables.includes(f.parent_table as AllocatorTable) ||
      f.parent_column !== "id"
    )
      continue;
    if (!approvedBusinessTables.has(f.table_name))
      allocatorFail("ALLOCATOR_UNREVIEWED_BUSINESS_REFERENCE");
    const col = columns.find(
      (x) => x.table_name === f.table_name && x.column_name === f.column_name,
    );
    if (!col) allocatorFail("ALLOCATOR_REFERENCE_SCHEMA_MISMATCH");
    references.push({ ...col, namespace: f.parent_table as AllocatorTable });
  }
  // Retained semantic IDs without foreign keys still reserve IDs (notably device_sn.original_user_id).
  for (const col of columns) {
    const ns = referenceNamespace(col);
    if (!ns) continue;
    if (!approvedBusinessTables.has(col.table_name))
      allocatorFail("ALLOCATOR_UNREVIEWED_BUSINESS_REFERENCE");
    if (
      !references.some(
        (x) =>
          x.table_name === col.table_name && x.column_name === col.column_name,
      )
    )
      references.push({ ...col, namespace: ns });
  }
  references.sort((a, b) =>
    (a.table_name + "." + a.column_name).localeCompare(
      b.table_name + "." + b.column_name,
    ),
  );
  const reserved = Object.fromEntries(
    allocatorTables.map((t) => [t, 0n]),
  ) as Record<AllocatorTable, bigint>;
  const capacities = Object.fromEntries(
    allocatorTables.map((t) => [t, BigInt(Number.MAX_SAFE_INTEGER)]),
  ) as Record<AllocatorTable, bigint>;
  capacities.user = 2147483647n;
  for (const r of references) {
    let n: bigint;
    if (r.table_name === "auth_assignment" && r.column_name === "user_id") {
      const [bad] = await c.query<RowDataPacket[]>(
        "SELECT 1 FROM auth_assignment WHERE user_id IS NOT NULL AND NOT REGEXP_LIKE(user_id,'^[1-9][0-9]*$','c') LIMIT 1",
      );
      if (bad.length) allocatorFail("ALLOCATOR_NONCANONICAL_USER_REFERENCE");
      const [max] = await c.query<RowDataPacket[]>(
        "SELECT CAST(MAX(CAST(user_id AS DECIMAL(65,0))) AS CHAR) AS value FROM auth_assignment",
      );
      n = max[0]?.value == null ? 0n : integer(String(max[0].value));
    } else {
      const cap = columnCapacity(r.column_type);
      if (cap < capacities[r.namespace]) capacities[r.namespace] = cap;
      n = await maximum(c, r.table_name, r.column_name);
    }
    if (n > reserved[r.namespace]) reserved[r.namespace] = n;
  }
  const counters = {} as Record<AllocatorTable, string>;
  await c.query("SET SESSION information_schema_stats_expiry=0");
  const [meta] = await c.query<RowDataPacket[]>(
    "SELECT TABLE_NAME AS name,CAST(AUTO_INCREMENT AS CHAR) AS next_id FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() ORDER BY TABLE_NAME",
  );
  for (const table of allocatorTables) {
    const col = columns.find(
        (x) => x.table_name === table && x.column_name === "id",
      ),
      row = meta.find((x) => x.name === table);
    if (!col?.extra.includes("auto_increment") || row?.next_id == null)
      allocatorFail("ALLOCATOR_SOURCE_COUNTER_MISSING");
    const cap = columnCapacity(col.column_type);
    if (cap < capacities[table]) capacities[table] = cap;
    counters[table] = integer(row.next_id).toString();
    const n = await maximum(c, table, "id");
    if (n > reserved[table]) reserved[table] = n;
  }
  const serializedReserved = Object.fromEntries(
    allocatorTables.map((t) => [t, reserved[t].toString()]),
  );
  return {
    stateSha256: allocatorDigest({
      columns,
      fk,
      counters,
      reserved: serializedReserved,
    }),
    database,
    serverUuid: String(location[0]?.server_uuid),
    counters,
    capacities: Object.fromEntries(
      allocatorTables.map((t) => [t, capacities[t].toString()]),
    ) as Record<AllocatorTable, string>,
    reserved: Object.fromEntries(
      allocatorTables.map((t) => [t, reserved[t].toString()]),
    ) as Record<AllocatorTable, string>,
    referenceReviewSha256: allocatorDigest({ columns, references }),
    metadataSha256: allocatorDigest({ columns, fk, counters }),
  };
}
/** Source is READ ONLY. Distinct target/fence connections keep the authority lock across DDL implicit commits.
 * The library accepts arbitrary fixture databases; production CLI pins direct endpoints and both dev schemas.
 */
export async function finalizeAllocator(options: {
  source: AllocatorConnection;
  target: AllocatorConnection;
  fence: AllocatorConnection;
  review: AllocatorDrainReview;
  reviewSha256: string;
  apply?: boolean;
  onStep?: (step: AllocatorStep) => Promise<void>;
}): Promise<AllocatorPlan> {
  const { source, target, fence, review } = options;
  strictReview(review);
  if (
    source === target ||
    source === fence ||
    target === fence ||
    !/^[a-f0-9]{64}$/.test(options.reviewSha256)
  )
    allocatorFail("ALLOCATOR_DISTINCT_CONNECTIONS_REQUIRED");
  if (
    (await allocatorDatabase(source)) !== review.sourceDatabase ||
    (await allocatorDatabase(target)) !== review.targetDatabase ||
    (await allocatorDatabase(fence)) !== review.targetDatabase
  )
    allocatorFail("ALLOCATOR_SOURCE_TARGET_MISMATCH");
  // SET TRANSACTION fails if a caller already has an active transaction; never commit a caller's work.
  for (const c of [source, target, fence]) {
    await c.query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ");
    const [mode] = await c.query<RowDataPacket[]>(
      "SELECT @@autocommit AS enabled",
    );
    if (Number(mode[0]?.enabled) !== 1)
      allocatorFail("ALLOCATOR_IDLE_AUTOCOMMIT_REQUIRED");
  }
  await fence.beginTransaction();
  let sourceStarted = false;
  try {
    await assertMigrationStaging(fence);
    if (options.apply)
      await target.execute(
        "INSERT INTO identity_migration_allocator_state(id,state) VALUES(1,'pending') ON DUPLICATE KEY UPDATE state='pending',updated_at=UTC_TIMESTAMP(3)",
      );
    const [baseline] = await target.execute<RowDataPacket[]>(
      "SELECT source_database FROM identity_account_import_runs WHERE import_key=?",
      [review.importKey],
    );
    if (baseline[0]?.source_database !== review.sourceDatabase)
      allocatorFail("ALLOCATOR_BASELINE_MISMATCH");
    const before = await readSourceAllocatorInventory(source);
    if (before.serverUuid !== review.sourceServerUuid)
      allocatorFail("ALLOCATOR_SOURCE_UUID_MISMATCH");
    if (before.referenceReviewSha256 !== review.referenceReviewSha256)
      allocatorFail("ALLOCATOR_REFERENCE_REVIEW_MISMATCH");
    await source.query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ");
    await source.query("START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY");
    sourceStarted = true;
    const input = await readSourceAllocatorInventory(source),
      privateState = await readPrivateAllocatorInventory(target);
    if (before.stateSha256 !== input.stateSha256)
      allocatorFail("ALLOCATOR_SOURCE_METADATA_CHANGED");
    const floors = {} as AllocatorManifest["floors"];
    for (const t of allocatorTables) {
      const reserved = [
        integer(input.reserved[t]),
        integer(privateState.reserved[t]),
      ].reduce((a, b) => (a > b ? a : b));
      const floor = [
        integer(input.counters[t]),
        integer(privateState.counters[t]),
        reserved + 1n,
      ].reduce((a, b) => (a > b ? a : b));
      const capacity = [
        integer(input.capacities[t]),
        integer(privateState.capacities[t]),
      ].reduce((a, b) => (a < b ? a : b));
      floors[t] = {
        floor: floor.toString(),
        capacity: capacity.toString(),
        sourceNext: input.counters[t],
        reservedMax: reserved.toString(),
      };
    }
    const manifest = normalizeAllocatorManifest({
      version: 1,
      kind: "migrated",
      targetDatabase: review.targetDatabase,
      capturedAt: new Date().toISOString(),
      source: {
        database: review.sourceDatabase,
        host: "10.206.0.5",
        port: "3306",
        serverUuid: input.serverUuid,
      },
      drain: {
        reviewSha256: options.reviewSha256,
        writersDrainedAt: review.writersDrainedAt,
        finalSyncSha256: review.finalSyncSha256,
      },
      baseline: {
        importKey: review.importKey,
        referenceReviewSha256: review.referenceReviewSha256,
      },
      floors,
    });
    const plan = {
      manifest,
      manifestSha256: allocatorDigest(manifest),
      sourceMetadataSha256: input.metadataSha256,
      targetSchemaSha256: privateState.schemaSha256,
      sourceStateSha256: input.stateSha256,
    };
    // Leave RR before checking for drift: information_schema counters are live but MAX references
    // would otherwise remain hidden in the original row snapshot.
    await source.rollback();
    sourceStarted = false;
    const fresh = await readSourceAllocatorInventory(source);
    if (fresh.stateSha256 !== input.stateSha256)
      allocatorFail("ALLOCATOR_SOURCE_METADATA_CHANGED");
    if (!options.apply) return plan;
    // Commit pending before any DDL; old evidence is retained but can never activate.
    await target.execute(
      "INSERT INTO identity_migration_allocator_state(id,state) VALUES(1,'pending') ON DUPLICATE KEY UPDATE state='pending',updated_at=UTC_TIMESTAMP(3)",
    );
    for (const t of allocatorTables) {
      const check = await readSourceAllocatorInventory(source);
      if (check.stateSha256 !== input.stateSha256)
        allocatorFail("ALLOCATOR_SOURCE_METADATA_CHANGED");
      const current = await readPrivateAllocatorInventory(target);
      if (current.schemaSha256 !== privateState.schemaSha256)
        allocatorFail("ALLOCATOR_TARGET_SCHEMA_CHANGED");
      const desired = integer(floors[t].floor);
      if (integer(current.counters[t]) < desired) {
        await options.onStep?.({
          table: t,
          phase: "intent",
          floor: desired.toString(),
        });
        await target.query(
          `ALTER TABLE ${quoteIdentifier(t)} AUTO_INCREMENT = ${desired}`,
        );
        const after = await readPrivateAllocatorInventory(target);
        if (
          integer(after.counters[t]) < desired ||
          after.schemaSha256 !== privateState.schemaSha256
        )
          allocatorFail("ALLOCATOR_DDL_POSTCONDITION_FAILED");
        await options.onStep?.({
          table: t,
          phase: "success",
          floor: desired.toString(),
        });
      }
    }
    const afterSource = await readSourceAllocatorInventory(source),
      afterTarget = await readPrivateAllocatorInventory(target);
    if (afterSource.stateSha256 !== input.stateSha256)
      allocatorFail("ALLOCATOR_SOURCE_METADATA_CHANGED");
    if (afterTarget.schemaSha256 !== privateState.schemaSha256)
      allocatorFail("ALLOCATOR_TARGET_SCHEMA_CHANGED");
    for (const t of allocatorTables)
      if (
        integer(afterTarget.counters[t]) < integer(floors[t].floor) ||
        integer(afterTarget.counters[t]) <= integer(afterTarget.reserved[t])
      )
        allocatorFail("ALLOCATOR_DDL_POSTCONDITION_FAILED");
    await target.execute(
      "UPDATE identity_migration_allocator_state SET state='ready',manifest_json=?,manifest_sha256=?,finalized_at=UTC_TIMESTAMP(3) WHERE id=1",
      [JSON.stringify(manifest), plan.manifestSha256],
    );
    return plan;
  } finally {
    try {
      if (sourceStarted) await source.rollback();
    } finally {
      await fence.rollback();
    }
  }
}
