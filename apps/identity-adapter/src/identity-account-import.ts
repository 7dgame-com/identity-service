import mysql, { type Connection, type RowDataPacket } from "mysql2/promise";
import { loadConfig } from "./config.js";
import { assertMigrationStaging, migrationPrimaryKeys, recordMigrationBaseline } from "./migration-state.js";

// Explicit identity-only columns. Business balances and file references never cross this boundary.
export const accountImportTables: Readonly<Record<string, readonly string[]>> = {
  user: ["id", "username", "auth_key", "password_hash", "password_reset_token", "verification_token", "email", "status", "nickname", "wx_openid", "email_verified_at", "created_at", "updated_at"],
  user_info: ["id", "user_id", "info"],
  auth_rule: ["name", "data", "created_at", "updated_at"],
  auth_item: ["name", "type", "description", "rule_name", "data", "created_at", "updated_at"],
  auth_item_child: ["parent", "child"],
  auth_assignment: ["item_name", "user_id", "created_at"],
  organization: ["id", "name", "title", "created_at", "updated_at"],
  user_organization: ["user_id", "organization_id"],
  wechat: ["id", "openid", "unionid", "user_id", "token", "created_at", "updated_at"],
  invitation_record: ["id", "invite_code", "inviter_id", "invitee_id", "created_at"],
  invitation: ["id", "code", "sender_id", "recipient_id", "used", "auth_item_name", "create_at"]
};

export interface AccountImportReport {
  applied: boolean;
  replay: boolean;
  importKey: string;
  rowCounts: Record<string, number>;
  absentOptionalTables: string[];
}

/** Source is read-only; target is a one-time, all-or-nothing account snapshot. */
export async function importIdentityAccounts(
  source: Connection,
  target: Connection,
  options: { apply?: boolean; importKey: string; maxRows?: number }
): Promise<AccountImportReport> {
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
  await source.query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ");
  await source.query("START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY");
  const datasets = new Map<string, { columns: string[]; rows: RowDataPacket[] }>();
  let profileAvatars: RowDataPacket[] = [];
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
      if (table === "user_info" && present.has("avatar_id")) {
        const [avatars] = await source.query<RowDataPacket[]>(`SELECT user_id,avatar_id FROM user_info WHERE avatar_id IS NOT NULL LIMIT ${Math.max(1, options.maxRows ?? 100_000) + 1}`);
        if (avatars.length > (options.maxRows ?? 100_000)) throw new Error("Avatar reference import exceeds the bounded import size.");
        profileAvatars = avatars;
        report.rowCounts.identity_profile_avatars = avatars.length;
      }
      const columns = allowedColumns.filter((column) => present.has(column));
      const [rows] = await source.query<RowDataPacket[]>(`SELECT ${columns.map((column) => `\`${column}\``).join(", ")} FROM \`${table}\` LIMIT ${Math.max(1, options.maxRows ?? 100_000) + 1}`);
      if (rows.length > (options.maxRows ?? 100_000)) throw new Error(`Identity source table exceeds the bounded import size: ${table}`);
      report.rowCounts[table] = rows.length;
      datasets.set(table, { columns, rows });
    }
    if (!options.apply) return report;
    await target.beginTransaction();
    try {
      await assertMigrationStaging(target);
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
          await target.execute(`INSERT INTO \`${table}\` (${columns.map((column) => `\`${column}\``).join(", ")}) VALUES (${columns.map(() => "?").join(", ")})${suffix}`, values);
          const keys=migrationPrimaryKeys[table];
          const [stored]=await target.execute<RowDataPacket[]>(`SELECT ${columns.map(column=>`\`${column}\``).join(",")} FROM \`${table}\` WHERE ${keys.map(key=>`\`${key}\`=?`).join(" AND ")}`,keys.map(key=>row[key]));
          await recordMigrationBaseline(target,table,columns,row,stored[0]);
        }
      }
      for (const avatar of profileAvatars) {
        await target.execute("INSERT INTO identity_profile_avatars (user_id,avatar_id) VALUES (?,?)",[avatar.user_id,avatar.avatar_id]);
        await recordMigrationBaseline(target,"identity_profile_avatars",["user_id","avatar_id"],avatar,avatar);
      }
      const itemColumns=datasets.get("auth_item")!.columns;
      const sourceItems=new Set(datasets.get("auth_item")!.rows.map(row=>String(row.name)));
      const [seededItems]=await target.query<RowDataPacket[]>(`SELECT ${itemColumns.map(column=>`\`${column}\``).join(",")} FROM auth_item`);
      for(const item of seededItems)if(!sourceItems.has(String(item.name)))await recordMigrationBaseline(target,"auth_item",itemColumns,null,item);
      // The clock remains locked until this import commits, preserving cursor commit order.
      await target.execute("SELECT id FROM identity_event_clock WHERE id = 1 FOR UPDATE");
      for (const row of datasets.get("user")!.rows) {
        const [maps] = await target.execute<RowDataPacket[]>("SELECT id FROM identity_users WHERE legacy_user_id = ?", [row.id]);
        const identityUserId = maps[0]?.id ?? `legacy:${row.id}`;
        await target.execute(
          `INSERT INTO identity_users (id, legacy_user_id, username, email, status, source)
           VALUES (?, ?, ?, ?, ?, 'identity-import') ON DUPLICATE KEY UPDATE username = VALUES(username), email = VALUES(email), status = VALUES(status), source = 'identity-import'`,
          [identityUserId, row.id, row.username ?? null, row.email ?? null, Number(row.status) === 10 ? "active" : "disabled"]
        );
        await target.execute(
          `INSERT INTO identity_subject_maps (identity_user_id, subject_type, subject_id, source, status)
           VALUES (?, 'legacy_user', ?, 'identity-import', 'active') ON DUPLICATE KEY UPDATE identity_user_id = VALUES(identity_user_id)`,
          [identityUserId, String(row.id)]
        );
        await target.execute("INSERT INTO identity_subject_events (user_id, version) VALUES (?, ?)", [row.id, Date.now()]);
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

export async function connectAccountImportDatabases() {
  const config = loadConfig();
  if (!config.legacyDb.host || !config.legacyDb.user || !config.identityDb.host || !config.identityDb.user) {
    throw new Error("Explicit source and target account database connections are required.");
  }
  const source = await mysql.createConnection({ host: config.legacyDb.host, port: config.legacyDb.port, user: config.legacyDb.user, password: config.legacyDb.password, database: config.legacyDb.name, timezone:"Z" });
  try {
    const target = await mysql.createConnection({ host: config.identityDb.host, port: config.identityDb.port, user: config.identityDb.user, password: config.identityDb.password, database: config.identityDb.name, timezone:"Z" });
    const sourceEndpoint = [config.legacyDb.host, config.legacyDb.port, config.legacyDb.name].join(":");
    const targetEndpoint = [config.identityDb.host, config.identityDb.port, config.identityDb.name].join(":");
    if (sourceEndpoint === targetEndpoint) { await target.end(); throw new Error("Source and target account databases must differ."); }
    return { source, target };
  } catch (error) {
    await source.end();
    throw error;
  }
}
