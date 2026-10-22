import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, readFile, writeFile, rm } from "node:fs/promises";
import { createHash, randomUUID } from "node:crypto";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import mysql, { type Connection, type RowDataPacket } from "mysql2/promise";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
const enabled = process.env.IDENTITY_TEST_MYSQL === "1", root = fileURLToPath(new URL("../../../", import.meta.url));
const options = { host: process.env.IDENTITY_TEST_MYSQL_HOST ?? "127.0.0.1", port: Number(process.env.IDENTITY_TEST_MYSQL_PORT ?? 13316), user: process.env.IDENTITY_TEST_MYSQL_USER ?? "root", password: process.env.IDENTITY_TEST_MYSQL_PASSWORD ?? "", timezone: "Z", multipleStatements: true };
const execute = promisify(execFile), sha = (b: Buffer) => createHash("sha256").update(b).digest("hex");
describe.skipIf(!enabled)("actual raw source fingerprint in the sync RR snapshot", () => {
  let admin: Connection, source: Connection, target: Connection, build: string, sourceName: string, targetName: string, fingerprint: any, sync: any, account: any, profile: any, manifest: any, profileBytes: Buffer, baselineTarget: string;
  beforeAll(async () => {
    if (options.host !== "127.0.0.1" || !(options.port === 13316 || (options.port === 3306 && (process.env.CI === "true" || process.env.GITHUB_ACTIONS === "true")))) throw new Error("Disposable local or CI MySQL required");
    admin = await mysql.createConnection(options); const [identity] = await admin.query<RowDataPacket[]>("SELECT @@server_uuid AS uuid");
    sourceName = `test_fingerprint_source_${randomUUID().replaceAll("-", "")}`; targetName = `test_fingerprint_target_${randomUUID().replaceAll("-", "")}`;
    build = await mkdtemp(join(root, ".identity-source-fingerprint-build-"));
    await execute(process.execPath, [join(root, "node_modules/typescript/bin/tsc"), "--outDir", build, "--noEmitOnError", "true"], { cwd: root, timeout: 90000, maxBuffer: 1024 * 1024 });
    const path = join(build, "apps/identity-adapter/src/identity-source-fingerprint.js");
    let code = await readFile(path, "utf8"); code = code.replaceAll(JSON.stringify("bujiaban_development"), JSON.stringify(sourceName)).replaceAll(JSON.stringify("1c6c32c4-00a9-11f1-9d18-0c42a14c701e"), JSON.stringify(identity[0].uuid)); await writeFile(path, code);
    const load = (n: string) => import(pathToFileURL(join(build, "apps/identity-adapter/src", `${n}.js`)).href);
    [fingerprint, sync, account, profile] = await Promise.all([load("identity-source-fingerprint"), load("identity-account-sync"), load("identity-account-import"), load("identity-profile-migration")]);
  }, 90000);
  beforeEach(async () => {
    vi.stubEnv("IDENTITY_ADMISSION_ENABLED", "false");
    for (const n of [sourceName, targetName]) await admin.query(`CREATE DATABASE \`${n}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`);
    source = await mysql.createConnection({ ...options, database: sourceName }); target = await mysql.createConnection({ ...options, database: targetName });
    const init = await readFile(join(root, "deploy/mysql/init.sql"), "utf8"); await target.query(init.slice(init.indexOf("CREATE TABLE IF NOT EXISTS `auth_login_events`")));
    for (const schema of ["identity-account-schema.sql", "identity-runtime-schema.sql", "identity-wechat-oauth-schema.sql", "identity-allocator-schema.sql"]) await target.query(await readFile(join(root, "deploy/mysql", schema), "utf8"));
    const sql = await readFile(join(root, "deploy/mysql/identity-account-schema.sql"), "utf8");
    for (const statement of sql.split(";")) { const table = statement.match(/CREATE TABLE IF NOT EXISTS `?([a-z_]+)`?\s*\(/)?.[1]; if (table && Object.hasOwn(account.accountImportTables, table)) await source.query(statement); }
    await source.query("ALTER TABLE user_info DROP INDEX account_profile_user,ADD COLUMN avatar_id BIGINT NULL;INSERT INTO auth_item(name,type) VALUES('user',1),('admin',1);INSERT INTO user(id,username,status,nickname,password_hash) VALUES(7101,'fingerprint',10,'Before','hash');INSERT INTO user_info(id,user_id,info,avatar_id) VALUES(1,7101,JSON_OBJECT('selected',true),11),(2,7101,JSON_OBJECT('retained',true),12);INSERT INTO auth_assignment(item_name,user_id) VALUES('user','7101');INSERT INTO organization(id,name,title) VALUES(41,'old','Before');INSERT INTO user_organization(user_id,organization_id) VALUES(7101,41);INSERT INTO wechat(id,openid,user_id) VALUES(7,'wx-fingerprint',7101)");
    const [rows] = await source.query<RowDataPacket[]>("SELECT id,user_id,info,avatar_id FROM user_info");
    manifest = { version: 1, selections: [{ userId: 7101, profileId: 1, sourceRowsSha256: profile.profileGroupSha256(rows, true) }] }; profileBytes = Buffer.from(`${JSON.stringify(manifest)}\n`);
    await account.importIdentityAccounts(source, target, { importKey: "fingerprint", apply: true, profileSelection: manifest });
    baselineTarget = await targetSnapshot();
  }, 30000);
  afterEach(async () => { vi.restoreAllMocks(); vi.unstubAllEnvs(); await Promise.allSettled([source?.end(), target?.end()]); for (const n of [sourceName, targetName]) await admin.query(`DROP DATABASE IF EXISTS \`${n}\``); });
  afterAll(async () => { await admin?.end(); if (build) await rm(build, { recursive: true, force: true }); });
  const observe = () => fingerprint.readActualSourceFingerprint(source, { profileSelectionSha256: sha(profileBytes), maxRows: 100 });
  const bind = (m: any) => fingerprint.prepareExpectedSourceFingerprint(Buffer.from(JSON.stringify(m)), profileBytes, 100);
  const apply = (token: any) => sync.syncIdentityAccounts(source, target, { apply: true, maxChanges: 100, maxRows: 100, profileSelection: manifest, expectedSourceFingerprint: token });
  async function targetSnapshot() {
    const result = [];
    for (const table of [...Object.keys(account.accountImportTables), "identity_subject_events", "identity_migration_rows", "identity_migration_allocator_state"]) { const [rows] = await target.query<RowDataPacket[]>(`SELECT * FROM \`${table}\``); result.push([table, rows.map(row => JSON.stringify(row)).sort()]); }
    return sha(Buffer.from(JSON.stringify(result)));
  }
  async function unchanged() { expect(await targetSnapshot()).toBe(baselineTarget); }
  it("keeps hashes identical to legacy SHOW metadata while bounding metadata round trips", async () => {
    const query = vi.spyOn(source, "query"), observed = await observe(), sql = query.mock.calls.map(args => String(args[0])); query.mockRestore();
    expect(sql.filter(v => v.includes("COLUMN_NAME AS Field"))).toHaveLength(1); expect(sql.filter(v => v.includes("t.TABLE_TYPE AS tableType"))).toHaveLength(1); expect(sql.filter(v => /^SHOW (TABLES|COLUMNS)/.test(v))).toHaveLength(0);
    const load = (n: string) => import(pathToFileURL(join(build, "apps/identity-adapter/src", `${n}.js`)).href);
    const [state, digestModule] = await Promise.all([load("migration-state"), load("identity-allocator-manifest")]); const tables = [];
    await source.query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ"); await source.query("START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY");
    try {
      for (const [table, allowed] of Object.entries(account.accountImportTables) as [string, string[]][]) {
        const [schema] = await source.query<RowDataPacket[]>(`SHOW COLUMNS FROM \`${table}\``), columns = allowed.filter(n => schema.some(c => c.Field === n));
        if (table === "user_info" && schema.some(c => c.Field === "avatar_id")) columns.push("avatar_id");
        const [rows] = await source.query<RowDataPacket[]>(`SELECT ${columns.map(n => `\`${n}\``).join(",")}${table === "user_info" ? ",JSON_TYPE(info) AS __identity_profile_info_type" : ""} FROM \`${table}\``);
        const [facts] = await source.query<RowDataPacket[]>("SELECT TABLE_TYPE AS tableType,ENGINE AS engine FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=?", [table]);
        tables.push({ table, present: true, facts: { tableType: facts[0].tableType, engine: facts[0].engine }, columns: columns.map(name => ({ name, type: schema.find(c => c.Field === name)!.Type })), rows: rows.map(row => ({ key: state.migrationRowKey(table, row).keyHash, hash: state.migrationRowHash(row, columns) })).sort((a, b) => a.key.localeCompare(b.key)) });
      }
      tables.sort((a, b) => a.table.localeCompare(b.table)); expect(observed.schemaSha256).toBe(digestModule.allocatorDigest(tables.map(({ table, present, facts, columns }) => ({ table, present, facts, columns })))); expect(observed.rowsSha256).toBe(digestModule.allocatorDigest(tables.map(({ table, rows }) => ({ table, rows }))));
    } finally { await source.rollback(); }
  });
  it("rejects a real allowlist column added between initial metadata and raw table read", async () => {
    await source.query("ALTER TABLE user DROP COLUMN email_verified_at"); const query = source.query.bind(source); let changed = false;
    vi.spyOn(source, "query").mockImplementation((async (...args: any[]) => {
      const result = await (query as any)(...args);
      if (!changed && String(args[0]).includes("COLUMN_NAME AS Field")) { changed = true; await admin.query(`ALTER TABLE \`${sourceName}\`.user ADD COLUMN email_verified_at BIGINT NULL`); }
      return result;
    }) as any);
    let failure: any; try { await observe(); } catch (error) { failure = error; }
    expect(["ER_TABLE_DEF_CHANGED", "SOURCE_FINGERPRINT_SCHEMA_CHANGED_DURING_READ"]).toContain(failure?.code); expect(changed).toBe(true); await unchanged();
  });
  it("preserves optional-table absence in both the batched reader and typed sync", async () => {
    await source.query("DROP TABLE auth_rule"); const token = bind(await observe()); await expect(apply(token)).resolves.toMatchObject({ applied: true, changes: 0 }); await unchanged();
  });
  it("observes stable raw rows/schema independently of observation time and applies only the matching source", async () => {
    await source.query("UPDATE user SET nickname='Reviewed' WHERE id=7101"); const first = await observe(), token = bind(first); await expect(apply(token)).resolves.toMatchObject({ applied: true, changes: 1 });
    const after = await observe(); expect(() => fingerprint.assertSameSourceFingerprint(first, after)).not.toThrow(); expect(first.rowsSha256).toBe(after.rowsSha256);
  });
  it.each([
    ["credential", "UPDATE user SET password_hash='unreviewed' WHERE id=7101"],
    ["role", "INSERT INTO auth_assignment(item_name,user_id) VALUES('admin','7101')"],
    ["organization", "UPDATE organization SET title='Unreviewed' WHERE id=41"],
    ["membership", "DELETE FROM user_organization WHERE user_id=7101"],
    ["binding", "UPDATE wechat SET unionid='unreviewed-binding' WHERE id=7"],
    ["selected column type", "ALTER TABLE user MODIFY nickname VARCHAR(254) NULL"],
  ])("rejects %s drift before any target mutation", async (_name, mutation) => {
    const first = await observe(), token = bind(first); await source.query(mutation); const after = await observe(); expect(() => fingerprint.assertSameSourceFingerprint(first, after)).toThrow("DRIFT"); await expect(apply(token)).rejects.toThrow("SOURCE_FINGERPRINT_DRIFT"); await unchanged();
  });
  it.each(["MyISAM", "view"])("rejects a non-snapshot %s source before target mutation", async kind => {
    const token = bind(await observe());
    if (kind === "MyISAM") await source.query("ALTER TABLE auth_rule ENGINE=MyISAM");
    else await source.query("RENAME TABLE auth_rule TO old_auth_rule;CREATE VIEW auth_rule AS SELECT * FROM old_auth_rule");
    await expect(observe()).rejects.toThrow("SOURCE_FINGERPRINT_TRANSACTIONAL_TABLE_REQUIRED");
    await expect(apply(token)).rejects.toThrow("SOURCE_FINGERPRINT_TRANSACTIONAL_TABLE_REQUIRED"); await unchanged();
  });
  it("fingerprints unselected raw profile data and rejects its later change before writing target", async () => {
    const first = await observe(), token = bind(first); await source.query("UPDATE user_info SET info=JSON_OBJECT('retained','changed'),avatar_id=99 WHERE id=2"); const after = await observe(); expect(first.rowsSha256).not.toBe(after.rowsSha256); await expect(apply(token)).rejects.toThrow(); await unchanged();
  });
  it("rejects changed source identity, profile binding and row bound without a target write", async () => {
    const first = await observe();
    for (const changed of [{ ...first, database: targetName }, { ...first, serverUuid: "ffffffff-ffff-ffff-ffff-ffffffffffff" }, { ...first, profileSelectionSha256: null }, { ...first, maxRows: 99 }]) expect(() => bind(changed)).toThrow(); await unchanged();
  });
  it("does not take over or roll back an existing caller transaction", async () => {
    await source.beginTransaction(); await source.query("UPDATE user SET nickname='Uncommitted' WHERE id=7101"); await expect(observe()).rejects.toMatchObject({ code: "ER_CANT_CHANGE_TX_CHARACTERISTICS" });
    const [own] = await source.query<RowDataPacket[]>("SELECT nickname FROM user WHERE id=7101"); expect(own[0].nickname).toBe("Uncommitted"); await source.rollback(); await unchanged();
  });
  it("uses the same actual RR rows as sync and detects a concurrent source change in post observation", async () => {
    await source.query("UPDATE user SET nickname='Reviewed' WHERE id=7101"); const before = await observe(), token = bind(before), query = source.query.bind(source); let changed = false;
    vi.spyOn(source, "query").mockImplementation((async (...args: any[]) => {
      const result = await (query as any)(...args);
      if (!changed && String(args[0]).startsWith("SELECT `id`,`username`")) { changed = true; await admin.query(`UPDATE \`${sourceName}\`.user SET nickname='After-snapshot' WHERE id=7101`); }
      return result;
    }) as any);
    await expect(apply(token)).resolves.toMatchObject({ applied: true }); vi.restoreAllMocks(); expect(changed).toBe(true);
    const [targetRows] = await target.query<RowDataPacket[]>("SELECT nickname FROM user WHERE id=7101"); expect(targetRows[0].nickname).toBe("Reviewed");
    const after = await observe(); expect(() => fingerprint.assertSameSourceFingerprint(before, after)).toThrow("DRIFT");
  });
});
