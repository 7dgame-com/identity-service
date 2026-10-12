import type { Connection, RowDataPacket } from "mysql2/promise";
import type { ExecuteValues } from "mysql2";
import { accountImportTables, appendLegacyProfileHistory, legacyProfileArchiveColumns } from "./identity-account-import.js";
import { projectLegacyProfiles, type ProfileSelectionManifest } from "./identity-profile-migration.js";
import { assertAccountImportUniqueConstraints } from "./identity-account-constraints.js";
import { assertProfileJsonValues, legacyProfileJsonTypeSelection } from "./identity-profile-source.js";
import {
  assertMigrationStaging,
  migrationPrimaryKeys,
  migrationRowHash,
  migrationRowKey,
  recordMigrationBaseline,
} from "./migration-state.js";

type Row = Record<string, unknown>;
interface Baseline {
  columns: string[];
  sourceHash: string | null;
  targetHash: string | null;
}
interface Dataset {
  table: string;
  columns: string[];
  source: Map<string, Row>;
  target: Map<string, Row>;
  baseline: Map<string, Baseline>;
}
interface Delta {
  dataset: Dataset;
  source: Row | null;
  target: Row | null;
}
export interface AccountSyncReport {
  applied: boolean;
  changes: number;
  inserts: number;
  updates: number;
  deletions: number;
  affectedSubjects: number;
  tableChanges: Record<string, number>;
}
const avatarColumns = ["user_id", "avatar_id"];
const tables: Readonly<Record<string, readonly string[]>> = {
  ...accountImportTables,
  identity_profile_avatars: avatarColumns,
  identity_legacy_profile_rows: legacyProfileArchiveColumns,
};
const quoted = (columns: readonly string[]) =>
  columns.map((c) => `\`${c}\``).join(",");
const json = (value: unknown): unknown =>
  typeof value === "string" ? JSON.parse(value) : value;
function bind(value: unknown): ExecuteValues {
  if (value == null) return null;
  if (
    ["string", "number", "bigint", "boolean"].includes(typeof value) ||
    Buffer.isBuffer(value) ||
    value instanceof Date
  )
    return value as ExecuteValues;
  if (typeof value === "object") return JSON.stringify(value);
  throw new Error("Unsupported account migration value.");
}

/** One-way source deltas, permitted only while the private database is still staging.
 * The same transaction advances the baseline and outbox; retrying a committed batch is a no-op.
 */
export async function syncIdentityAccounts(
  source: Connection,
  target: Connection,
  options: { apply?: boolean; maxChanges: number; maxRows?: number; profileSelection?: ProfileSelectionManifest },
): Promise<AccountSyncReport> {
  const maxRows = options.maxRows ?? 100_000;
  if (
    !Number.isSafeInteger(options.maxChanges) ||
    options.maxChanges < 1 ||
    options.maxChanges > 100_000
  )
    throw new Error(
      "maxChanges must be an explicit integer between 1 and 100000.",
    );
  if (!Number.isSafeInteger(maxRows) || maxRows < 1 || maxRows > 1_000_000)
    throw new Error("maxRows must be an integer between 1 and 1000000.");
  if (source === target)
    throw new Error("Source and target account databases must differ.");
  const [[sourceLocation], [targetLocation]] = await Promise.all([
    source.query<RowDataPacket[]>(
      "SELECT DATABASE() AS name, @@server_uuid AS server_id",
    ),
    target.query<RowDataPacket[]>(
      "SELECT DATABASE() AS name, @@server_uuid AS server_id",
    ),
  ]);
  if (
    !sourceLocation[0]?.name ||
    !targetLocation[0]?.name ||
    (sourceLocation[0].name === targetLocation[0].name &&
      sourceLocation[0].server_id === targetLocation[0].server_id)
  )
    throw new Error(
      "Distinct source and target account databases must be selected.",
    );

  // Acquire the target fence before taking the source snapshot. Competing syncs cannot apply older snapshots last.
  await target.beginTransaction();
  let sourceTransaction = false;
  try {
    await assertMigrationStaging(target);
    const [runs] = await target.execute<RowDataPacket[]>(
      "SELECT DISTINCT source_database FROM identity_account_import_runs",
    );
    if (runs.length !== 1 || runs[0].source_database !== sourceLocation[0].name)
      throw new Error(
        "Account sync requires a completed baseline from this source database.",
      );
    const [stored] = await target.query<RowDataPacket[]>(
      "SELECT table_name,key_hash,columns_json,source_hash,target_hash FROM identity_migration_rows",
    );
    const baselines = new Map<string, Map<string, Baseline>>();
    for (const row of stored) {
      const table = String(row.table_name),
        allowed = tables[table];
      const columns = json(row.columns_json);
      if (
        !allowed ||
        !Array.isArray(columns) ||
        !columns.length ||
        columns.some(
          (column) => typeof column !== "string" || !allowed.includes(column),
        ) ||
        !migrationPrimaryKeys[table].every((key) => columns.includes(key))
      )
        throw new Error("Invalid account migration baseline schema.");
      let baseline = baselines.get(table);
      if (!baseline) baselines.set(table, (baseline = new Map()));
      baseline.set(String(row.key_hash), {
        columns,
        sourceHash: row.source_hash,
        targetHash: row.target_hash,
      });
    }
    await source.query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ");
    await source.query("START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY");
    sourceTransaction = true;

    const datasets = new Map<string, Dataset>();
    let hasAvatarColumn = false;
    let profileProjection: ReturnType<typeof projectLegacyProfiles> | undefined;
    const [previousArchiveRows] = await target.query<RowDataPacket[]>(`SELECT ${quoted(legacyProfileArchiveColumns)}
      FROM identity_legacy_profile_rows LIMIT ${maxRows+1} FOR UPDATE`);
    if(previousArchiveRows.length>maxRows)throw new Error("Legacy profile archive exceeds the bounded table size");
    for (const [table, allowed] of Object.entries(tables)) {
      const baseline = baselines.get(table) ?? new Map<string, Baseline>();
      let columns: string[],
        rows: RowDataPacket[] = [];
      if (table === "identity_profile_avatars") {
        columns = avatarColumns;
        if (
          !hasAvatarColumn &&
          [...baseline.values()].some((row) => row.sourceHash !== null)
        )
          throw new Error(
            "Legacy avatar source schema changed since the baseline.",
          );
        rows = (profileProjection?.avatarRows ?? []) as RowDataPacket[];
      } else if (table === "identity_legacy_profile_rows") {
        columns = legacyProfileArchiveColumns;
        rows = (profileProjection?.archiveRows ?? []).map(row=>({...row,is_present:1})) as RowDataPacket[];
        const presentIds = new Set(rows.map(row=>String(row.id)));
        const selections = new Map(profileProjection?.report.selections.map(row=>[row.userId,row.profileId]));
        // A deleted historical record remains archived; no payload is discarded.
        for(const previous of previousArchiveRows)if(!presentIds.has(String(previous.id)))rows.push({...previous,
          selected_profile_id:selections.get(Number(previous.user_id))??previous.selected_profile_id,is_present:0} as RowDataPacket);
      } else {
        const [exists] = await source.query<RowDataPacket[]>(
          "SHOW TABLES LIKE ?",
          [table],
        );
        if (!exists.length) {
          if (
            ["user", "auth_item", "auth_assignment"].includes(table) ||
            [...baseline.values()].some((row) => row.sourceHash !== null)
          )
            throw new Error(`Legacy source table disappeared: ${table}`);
          columns = [...(baseline.values().next().value?.columns ?? allowed)];
        } else {
          const [schema] = await source.query<RowDataPacket[]>(
            `SHOW COLUMNS FROM \`${table}\``,
          );
          const present = new Set(schema.map((column) => String(column.Field)));
          if (table === "user_info") hasAvatarColumn = present.has("avatar_id");
          columns = allowed.filter((column) => present.has(column));
          if (
            !migrationPrimaryKeys[table].every((key) => columns.includes(key))
          )
            throw new Error(
              `Legacy source primary key is incomplete: ${table}`,
            );
          const readColumns=table==="user_info"&&hasAvatarColumn?[...columns,"avatar_id"]:columns;
          const profileType=table==="user_info"?legacyProfileJsonTypeSelection(schema):"";
          [rows] = await source.query<RowDataPacket[]>(
            `SELECT ${quoted(readColumns)}${profileType} FROM \`${table}\` LIMIT ${maxRows + 1}`,
          );
          if(table==="user_info"){
            if(rows.length>maxRows)throw new Error("Account sync exceeds the bounded raw profile size");
            assertProfileJsonValues(rows,true);
            profileProjection=projectLegacyProfiles(rows,{manifest:options.profileSelection,previousArchiveRows,hasAvatarColumn});
            rows=profileProjection.canonicalRows as RowDataPacket[];
          }
        }
      }
      if (
        [...baseline.values()].some(
          (row) => JSON.stringify(row.columns) !== JSON.stringify(columns),
        )
      )
        throw new Error(
          `Legacy source columns changed since the baseline: ${table}`,
        );
      const targetColumns =
        table === "user" ? [...columns, "deleted_at"] : columns;
      const [targetRows] = await target.query<RowDataPacket[]>(
        `SELECT ${quoted(targetColumns)} FROM \`${table}\` LIMIT ${maxRows + 1} FOR UPDATE`,
      );
      if(table==="user_info")assertProfileJsonValues(targetRows);
      if (rows.length > maxRows || targetRows.length > maxRows)
        throw new Error(
          `Account sync exceeds the bounded table size: ${table}`,
        );
      datasets.set(table, {
        table,
        columns,
        baseline,
        source: indexRows(table, rows),
        target: indexRows(table, targetRows),
      });
    }
    await assertAccountImportUniqueConstraints(source,target,new Map([...datasets].map(([table,dataset])=>
      [table,{columns:dataset.columns,rows:[...dataset.source.values()]}])));

    const deltas: Delta[] = [];
    for (const dataset of datasets.values()) {
      for (const key of new Set([
        ...dataset.source.keys(),
        ...dataset.target.keys(),
        ...dataset.baseline.keys(),
      ])) {
        const baseline = dataset.baseline.get(key),
          previous = dataset.target.get(key) ?? null;
        const incoming = dataset.source.get(key) ?? null;
        if (
          (!baseline && previous) ||
          (baseline &&
            (previous ? migrationRowHash(previous, dataset.columns) : null) !==
              baseline.targetHash)
        )
          throw new Error(
            `Private account data diverged from the migration baseline: ${dataset.table}`,
          );
        if (
          dataset.table === "user" &&
          previous?.deleted_at != null &&
          baseline?.sourceHash !== null
        )
          throw new Error(
            "Private account tombstone diverged from the migration baseline.",
          );
        const incomingHash = incoming
          ? migrationRowHash(incoming, dataset.columns)
          : null;
        if (incomingHash === (baseline?.sourceHash ?? null)) continue;
        if (
          dataset.table === "user" &&
          incoming &&
          previous?.deleted_at != null
        )
          throw new Error(
            "Legacy source cannot reuse a tombstoned integer account ID.",
          );
        if (
          dataset.table === "user" &&
          incoming &&
          previous &&
          baseline?.sourceHash === null
        )
          throw new Error(
            "Legacy source cannot reuse an integer account ID reserved by another imported authority.",
          );
        deltas.push({ dataset, source: incoming, target: previous });
      }
    }
    if (deltas.length > options.maxChanges)
      throw new Error(
        "Account sync exceeds maxChanges; cancel the cutover and reduce the final delta.",
      );
    const subjects = affectedSubjects(deltas, datasets);
    if (subjects.size > options.maxChanges)
      throw new Error(
        "Account sync outbox fanout exceeds maxChanges; cancel the cutover and reduce the final delta.",
      );
    const report: AccountSyncReport = {
      applied: false,
      changes: deltas.length,
      inserts: deltas.filter((row) => row.source && !row.target).length,
      updates: deltas.filter((row) => row.source && row.target).length,
      deletions: deltas.filter((row) => !row.source).length,
      affectedSubjects: subjects.size,
      tableChanges: {},
    };
    for (const delta of deltas)
      report.tableChanges[delta.dataset.table] =
        (report.tableChanges[delta.dataset.table] ?? 0) + 1;
    if (!options.apply) {
      await target.rollback();
      return report;
    }

    // Delete relations first and write account/role parents first. All table names and columns are static allowlists.
    for (const delta of [...deltas].reverse())
      if (!delta.source) await applyDelta(target, delta);
    for (const delta of deltas)
      if (delta.source) await applyDelta(target, delta);
    await appendLegacyProfileHistory(target,deltas.filter(delta=>delta.dataset.table==="identity_legacy_profile_rows"&&delta.source)
      .map(delta=>delta.source!),sourceLocation[0].name);
    for (const delta of deltas) {
      const { dataset, source: incoming, target: previous } = delta;
      const keyRow = (incoming ?? previous)!;
      const keys = migrationPrimaryKeys[dataset.table];
      const [current] = await target.execute<RowDataPacket[]>(
        `SELECT ${quoted(dataset.columns)} FROM \`${dataset.table}\` WHERE ${keys.map((key) => `\`${key}\`=?`).join(" AND ")}`,
        keys.map((key) => bind(keyRow[key])),
      );
      await recordMigrationBaseline(
        target,
        dataset.table,
        dataset.columns,
        incoming,
        current[0] ?? previous,
      );
      // Physical deletions must record target_hash=null rather than the pre-deletion row.
      if (!current[0])
        await target.execute(
          "UPDATE identity_migration_rows SET target_hash=NULL WHERE table_name=? AND key_hash=?",
          [dataset.table, migrationRowKey(dataset.table, keyRow).keyHash],
        );
      if (dataset.table === "user") {
        const id = integerId(keyRow.id);
        await syncSubjectMapping(
          target,
          id,
          current[0] ?? keyRow,
          incoming !== null,
        );
        if (
          !incoming ||
          Number(incoming.status) !== 10 ||
          (previous &&
            ["password_hash", "auth_key", "wx_openid"].some(
              (field) => incoming[field] !== previous[field],
            ))
        ) {
          await target.execute(
            "UPDATE identity_refresh_sessions SET revoked_at=COALESCE(revoked_at,UTC_TIMESTAMP(3)) WHERE legacy_user_id=?",
            [id],
          );
          await target.execute(
            "INSERT INTO identity_user_revocations (user_id,revoked_before) VALUES (?,UTC_TIMESTAMP(3)) ON DUPLICATE KEY UPDATE revoked_before=UTC_TIMESTAMP(3)",
            [id],
          );
        }
      }
    }
    if (subjects.size) {
      await target.execute(
        "SELECT id FROM identity_event_clock WHERE id=1 FOR UPDATE",
      );
      for (const id of [...subjects].sort((a, b) => a - b))
        await target.execute(
          "INSERT INTO identity_subject_events (user_id,version) VALUES (?,?)",
          [id, Date.now()],
        );
    }
    await target.commit();
    report.applied = true;
    return report;
  } catch (error) {
    await target.rollback();
    throw error;
  } finally {
    if (sourceTransaction) await source.rollback();
  }
}

function indexRows(table: string, rows: Row[]): Map<string, Row> {
  const indexed = new Map<string, Row>();
  for (const row of rows) {
    if (table === "user") integerId(row.id);
    for (const field of ["user_id", "inviter_id", "invitee_id"])
      if (row[field] != null) integerId(row[field]);
    const { keyHash } = migrationRowKey(table, row);
    if (indexed.has(keyHash))
      throw new Error(`Duplicate account migration key: ${table}`);
    indexed.set(keyHash, row);
  }
  return indexed;
}
function integerId(value: unknown): number {
  if (
    !/^\d+$/.test(String(value)) ||
    !Number.isSafeInteger(Number(value)) ||
    Number(value) < 1
  )
    throw new Error(
      "Account migration requires positive, safe integer user IDs.",
    );
  return Number(value);
}
async function applyDelta(connection: Connection, delta: Delta): Promise<void> {
  const { dataset, source, target } = delta;
  const keys = migrationPrimaryKeys[dataset.table];
  if (!source) {
    if (dataset.table === "user")
      await connection.execute(
        "UPDATE user SET status=0,deleted_at=UNIX_TIMESTAMP(),updated_at=UNIX_TIMESTAMP() WHERE id=?",
        [bind(target!.id)],
      );
    else
      await connection.execute(
        `DELETE FROM \`${dataset.table}\` WHERE ${keys.map((key) => `\`${key}\`=?`).join(" AND ")}`,
        keys.map((key) => bind(target![key])),
      );
  } else if (target) {
    const columns = dataset.columns.filter((column) => !keys.includes(column));
    if (columns.length)
      await connection.execute(
        `UPDATE \`${dataset.table}\` SET ${columns.map((column) => `\`${column}\`=?`).join(",")} WHERE ${keys.map((key) => `\`${key}\`=?`).join(" AND ")}`,
        [
          ...columns.map((column) => bind(source[column])),
          ...keys.map((key) => bind(source[key])),
        ],
      );
  } else
    await connection.execute(
      `INSERT INTO \`${dataset.table}\` (${quoted(dataset.columns)}) VALUES (${dataset.columns.map(() => "?").join(",")})`,
      dataset.columns.map((column) => bind(source[column])),
    );
}
async function syncSubjectMapping(
  connection: Connection,
  id: number,
  row: Row,
  present: boolean,
) {
  const [maps] = await connection.execute<RowDataPacket[]>(
    "SELECT id FROM identity_users WHERE legacy_user_id=?",
    [id],
  );
  const identityId = maps[0]?.id ?? `legacy:${id}`;
  await connection.execute(
    `INSERT INTO identity_users (id,legacy_user_id,username,email,status,source) VALUES (?,?,?,?,?,'identity-import')
     ON DUPLICATE KEY UPDATE username=VALUES(username),email=VALUES(email),status=VALUES(status)`,
    [
      identityId,
      id,
      bind(row.username),
      bind(row.email),
      present && Number(row.status) === 10 ? "active" : "disabled",
    ],
  );
  await connection.execute(
    `INSERT INTO identity_subject_maps (identity_user_id,subject_type,subject_id,source,status) VALUES (?,'legacy_user',?,'identity-import',?)
     ON DUPLICATE KEY UPDATE identity_user_id=VALUES(identity_user_id),status=VALUES(status)`,
    [identityId, String(id), present ? "active" : "disabled"],
  );
}
function affectedSubjects(
  deltas: Delta[],
  datasets: Map<string, Dataset>,
): Set<number> {
  const subjects = new Set<number>();
  const policyChanged = deltas.some((delta) =>
    ["auth_rule", "auth_item", "auth_item_child"].includes(delta.dataset.table),
  );
  if (policyChanged)
    for (const row of [
      ...datasets.get("user")!.source.values(),
      ...datasets.get("user")!.target.values(),
    ])
      subjects.add(integerId(row.id));
  for (const delta of deltas) {
    for (const row of [delta.source, delta.target].filter(
      (row): row is Row => row !== null,
    )) {
      if (delta.dataset.table === "user") subjects.add(integerId(row.id));
      for (const field of ["user_id", "inviter_id", "invitee_id"])
        if (row[field] != null) subjects.add(integerId(row[field]));
      if (delta.dataset.table === "organization")
        for (const membership of [
          ...datasets.get("user_organization")!.source.values(),
          ...datasets.get("user_organization")!.target.values(),
        ])
          if (String(membership.organization_id) === String(row.id))
            subjects.add(integerId(membership.user_id));
    }
  }
  return subjects;
}
