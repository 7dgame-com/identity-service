import { assertAdmissionWriter } from "./identity-admission.js";
import { type MigrationResources, withMigrationResources } from "./identity-migration-resources.js";
import { invalidateAllocatorReady } from "./identity-allocator-state.js";
import mysql, { type Connection, type RowDataPacket } from "mysql2/promise";
import type { ExecuteValues } from "mysql2";
import { loadConfig } from "./config.js";
import { assertMigrationStaging, migrationPrimaryKeys, migrationRowHash, recordMigrationBaseline } from "./migration-state.js";
import { projectLegacyProfiles, type ProfileSelectionManifest } from "./identity-profile-migration.js";
import { assertAccountImportUniqueConstraints } from "./identity-account-constraints.js";
import { assertProfileJsonValues, legacyProfileJsonTypeSelection } from "./identity-profile-source.js";

import { accountImportTables, legacyProfileArchiveColumns } from "./identity-account-import-tables.js";
export { accountImportTables, legacyProfileArchiveColumns } from "./identity-account-import-tables.js";
function importBind(value:unknown):ExecuteValues {
  if(value==null)return null;
  if(["string","number","bigint","boolean"].includes(typeof value)||Buffer.isBuffer(value)||value instanceof Date)return value as ExecuteValues;
  if(typeof value==="object")return JSON.stringify(value);
  throw new Error("Unsupported account import value");
}
export async function appendLegacyProfileHistory(connection: Connection, rows: readonly Record<string,unknown>[], sourceDatabase: string) {
  assertAdmissionWriter("sync-leaf");
  for (const row of rows) {
    const payload = typeof row.payload_json === "string" ? JSON.parse(row.payload_json) : row.payload_json;
    await connection.execute(`INSERT INTO identity_legacy_profile_history(id,payload_hash,payload_json,source_database)
      VALUES(?,?,?,?) ON DUPLICATE KEY UPDATE id=VALUES(id)`,
      [importBind(row.id),migrationRowHash({payload_json:payload},["payload_json"]),JSON.stringify(payload),sourceDatabase]);
  }
}



export interface AccountImportReport {
  applied: boolean;
  replay: boolean;
  importKey: string;
  rowCounts: Record<string, number>;
  absentOptionalTables: string[];
  profiles?: Pick<ReturnType<typeof projectLegacyProfiles>["report"],"sourceRows"|"owners"|"duplicateGroups"|"archivedRows">;
}

/** Source is read-only; target is a one-time, all-or-nothing account snapshot. */
export async function importIdentityAccounts(
  source: Connection,
  target: Connection,
  options: { apply?: boolean; importKey: string; maxRows?: number; profileSelection?: ProfileSelectionManifest }
): Promise<AccountImportReport> {
  assertAdmissionWriter();
  if (source === target) throw new Error("Source and target account connections must differ.");
  if (!/^[A-Za-z0-9_.:-]{1,160}$/.test(options.importKey)) throw new Error("Invalid account import key.");
  const [sourceName] = await source.query<RowDataPacket[]>("SELECT DATABASE() AS name, @@server_uuid AS server_uuid");
  const [targetName] = await target.query<RowDataPacket[]>("SELECT DATABASE() AS name, @@server_uuid AS server_uuid");
  // Also blocks accidentally importing onto the platform database on the same host.
  if (!sourceName[0]?.name || !targetName[0]?.name) throw new Error("Both account databases must be selected.");
  if(sourceName[0].name===targetName[0].name && sourceName[0].server_uuid===targetName[0].server_uuid)throw new Error("Source and target account databases must differ.");
  const [existing] = await target.execute<RowDataPacket[]>(
    "SELECT source_database, row_counts FROM identity_account_import_runs WHERE import_key = ?", [options.importKey]
  );
  if (existing[0]) {
    if (existing[0].source_database !== sourceName[0].name) throw new Error("Import key is bound to another source database.");
    const counts = typeof existing[0].row_counts === "string" ? JSON.parse(existing[0].row_counts) : existing[0].row_counts;
    return { applied: false, replay: true, importKey: options.importKey, rowCounts: counts, absentOptionalTables: [] };
  }
  const [targetUsers] = await target.query<RowDataPacket[]>("SELECT COUNT(*) AS count FROM user");
  if (Number(targetUsers[0].count) !== 0) throw new Error("Account snapshot import requires an empty target account table; active identity accounts cannot be overwritten.");
  const [archived] = await target.query<RowDataPacket[]>("SELECT COUNT(*) AS count FROM identity_legacy_profile_rows");
  if(Number(archived[0].count)!==0)throw new Error("Account snapshot import requires an empty unclaimed profile archive");
  await source.query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ");
  await source.query("START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY");
  const datasets = new Map<string, { columns: string[]; rows: Record<string,unknown>[] }>();
  let profileAvatars: Record<string,unknown>[] = [];
  const report: AccountImportReport = { applied: false, replay: false, importKey: options.importKey, rowCounts: {}, absentOptionalTables: [] };
  try {
    for (const [table, allowedColumns] of Object.entries(accountImportTables)) {
      const [tables] = await source.query<RowDataPacket[]>("SHOW TABLES LIKE ?", [table]);
      if (!tables.length) {
        if (["user", "auth_item", "auth_assignment"].includes(table)) throw new Error(`Required identity source table is missing: ${table}`);
        report.absentOptionalTables.push(table);
        continue;
      }
      const [sourceColumns] = await source.query<RowDataPacket[]>(`SHOW COLUMNS FROM \`${table}\``);
      const present = new Set(sourceColumns.map((column) => String(column.Field)));
      const columns = allowedColumns.filter((column) => present.has(column));
      const readColumns = table === "user_info" && present.has("avatar_id") ? [...columns,"avatar_id"] : columns;
      const profileType = table === "user_info" ? legacyProfileJsonTypeSelection(sourceColumns) : "";
      const [rows] = await source.query<RowDataPacket[]>(`SELECT ${readColumns.map((column) => `\`${column}\``).join(", ")}${profileType} FROM \`${table}\` LIMIT ${Math.max(1, options.maxRows ?? 100_000) + 1}`);
      if (rows.length > (options.maxRows ?? 100_000)) throw new Error(`Identity source table exceeds the bounded import size: ${table}`);
      if (table === "user_info") {
        assertProfileJsonValues(rows,true);
        const projection = projectLegacyProfiles(rows,{manifest:options.profileSelection,hasAvatarColumn:present.has("avatar_id")});
        const archive = projection.archiveRows.map(row=>({...row,is_present:1}));
        datasets.set(table,{columns,rows:projection.canonicalRows});
        datasets.set("identity_legacy_profile_rows",{columns:legacyProfileArchiveColumns,rows:archive});
        report.rowCounts.user_info=projection.canonicalRows.length;
        report.rowCounts.identity_legacy_profile_rows=archive.length;
        const {sourceRows,owners,duplicateGroups,archivedRows}=projection.report;
        report.profiles={sourceRows,owners,duplicateGroups,archivedRows};
        profileAvatars=projection.avatarRows;
        report.rowCounts.identity_profile_avatars=profileAvatars.length;
        continue;
      }
      report.rowCounts[table] = rows.length;
      datasets.set(table, { columns, rows });
    }
    await assertAccountImportUniqueConstraints(source,target,datasets,{checkExistingTarget:true});
    if (!options.apply) return report;
    await target.beginTransaction();
    try {
      await assertMigrationStaging(target);await invalidateAllocatorReady(target);
      const [lockedCount]=await target.query<RowDataPacket[]>("SELECT COUNT(*) AS count FROM user");
      if(Number(lockedCount[0].count)!==0)throw new Error("Account snapshot import requires an empty target account table");
      // The import marker serializes competing runs before either inserts users.
      await target.execute("INSERT INTO identity_account_import_runs (import_key, source_database, row_counts, completed_at) VALUES (?, ?, ?, ?)",
        [options.importKey, sourceName[0].name, JSON.stringify(report.rowCounts), new Date()]);
      for (const [table, { columns, rows }] of datasets) {
        for (const row of rows) {
          const values = columns.map((column) => {
            const value = row[column];
            return value !== null && typeof value === "object" && !Buffer.isBuffer(value) && !(value instanceof Date) ? JSON.stringify(value) : value;
          });
          // Seeded role rows may already exist; no other account conflicts are ignored.
          const suffix = table === "auth_item" ? ` ON DUPLICATE KEY UPDATE ${columns.filter((column) => column !== "name").map((column) => `\`${column}\` = VALUES(\`${column}\`)`).join(", ")}` : "";
          await target.execute(`INSERT INTO \`${table}\` (${columns.map((column) => `\`${column}\``).join(", ")}) VALUES (${columns.map(() => "?").join(", ")})${suffix}`, values.map(importBind));
          const keys=migrationPrimaryKeys[table];
          const [stored]=await target.execute<RowDataPacket[]>(`SELECT ${columns.map(column=>`\`${column}\``).join(",")} FROM \`${table}\` WHERE ${keys.map(key=>`\`${key}\`=?`).join(" AND ")}`,keys.map(key=>importBind(row[key])));
          await recordMigrationBaseline(target,table,columns,row,stored[0]);
        }
      }
      await appendLegacyProfileHistory(target,datasets.get("identity_legacy_profile_rows")?.rows??[],sourceName[0].name);
      for (const avatar of profileAvatars) {
        await target.execute("INSERT INTO identity_profile_avatars (user_id,avatar_id) VALUES (?,?)",[importBind(avatar.user_id),importBind(avatar.avatar_id)]);
        await recordMigrationBaseline(target,"identity_profile_avatars",["user_id","avatar_id"],avatar,avatar);
      }
      const itemColumns=datasets.get("auth_item")!.columns;
      const sourceItems=new Set(datasets.get("auth_item")!.rows.map(row=>String(row.name)));
      const [seededItems]=await target.query<RowDataPacket[]>(`SELECT ${itemColumns.map(column=>`\`${column}\``).join(",")} FROM auth_item`);
      for(const item of seededItems)if(!sourceItems.has(String(item.name)))await recordMigrationBaseline(target,"auth_item",itemColumns,null,item);
      // The clock remains locked until this import commits, preserving cursor commit order.
      await target.execute("SELECT id FROM identity_event_clock WHERE id = 1 FOR UPDATE");
      for (const row of datasets.get("user")!.rows) {
        const [maps] = await target.execute<RowDataPacket[]>("SELECT id FROM identity_users WHERE legacy_user_id = ?", [importBind(row.id)]);
        const identityUserId = maps[0]?.id ?? `legacy:${row.id}`;
        await target.execute(
          `INSERT INTO identity_users (id, legacy_user_id, username, email, status, source)
           VALUES (?, ?, ?, ?, ?, 'identity-import') ON DUPLICATE KEY UPDATE username = VALUES(username), email = VALUES(email), status = VALUES(status), source = 'identity-import'`,
          [identityUserId, row.id, row.username ?? null, row.email ?? null, Number(row.status) === 10 ? "active" : "disabled"].map(importBind)
        );
        await target.execute(
          `INSERT INTO identity_subject_maps (identity_user_id, subject_type, subject_id, source, status)
           VALUES (?, 'legacy_user', ?, 'identity-import', 'active') ON DUPLICATE KEY UPDATE identity_user_id = VALUES(identity_user_id)`,
          [identityUserId, String(row.id)]
        );
        await target.execute("INSERT INTO identity_subject_events (user_id, version) VALUES (?, ?)", [importBind(row.id), Date.now()]);
      }
      const [actual] = await target.query<RowDataPacket[]>("SELECT COUNT(*) AS count FROM user");
      if (Number(actual[0].count) !== report.rowCounts.user) throw new Error("Account import row-count verification failed.");
      await target.commit();
      report.applied = true;
    } catch (error) {
      await target.rollback();
      throw error;
    }
    return report;
  } finally {
    await source.rollback();
  }
}

export async function connectAccountImportDatabases(resources?: MigrationResources) {
  const config = loadConfig();
  if (!config.legacyDb.host || !config.legacyDb.user || !config.identityDb.host || !config.identityDb.user) {
    throw new Error("Explicit source and target account database connections are required.");
  }
  // Legacy import CLIs own the returned pair themselves. Do not retain observers
  // they cannot consume; only the explicit awaited owner receives ownership here.
  const acquired = <T extends Connection>(connection: T): T => resources ? resources.connection(connection) : connection;
  const source = acquired(await mysql.createConnection({ host: config.legacyDb.host, port: config.legacyDb.port, user: config.legacyDb.user, password: config.legacyDb.password, database: config.legacyDb.name, timezone:"Z" }));
  let target: Connection | undefined;
  try {
    target = acquired(await mysql.createConnection({ host: config.identityDb.host, port: config.identityDb.port, user: config.identityDb.user, password: config.identityDb.password, database: config.identityDb.name, timezone:"Z" }));
    const sourceEndpoint = [config.legacyDb.host, config.legacyDb.port, config.legacyDb.name].join(":");
    const targetEndpoint = [config.identityDb.host, config.identityDb.port, config.identityDb.name].join(":");
    if (sourceEndpoint === targetEndpoint) throw new Error("Source and target account databases must differ.");
    return { source, target };
  } catch (error) {
    if (!resources) return withMigrationResources(async cleanup => {
      cleanup.connection(source); if (target) cleanup.connection(target); throw error;
    });
    throw error;
  }
}
