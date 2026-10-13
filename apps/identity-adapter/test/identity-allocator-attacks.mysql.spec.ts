import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import mysql, { type Connection, type RowDataPacket } from "mysql2/promise";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { initializeFreshAllocator, assertAllocatorReady, invalidateAllocatorReady, readPrivateAllocatorInventory } from "../src/identity-allocator-state.js";
import { AccountRegistrationRepository } from "../src/account-registration.repository.js";
import { IdentityWechatOAuthService } from "../src/identity-wechat-oauth.service.js";
import { IdentitySessionRepository } from "../src/identity-session.repository.js";
import { JwtIssuerService } from "../src/jwt-issuer.service.js";
import { LegacyIdentityReader } from "../src/legacy-identity.reader.js";
import { NativeIdentityService } from "../src/native-identity.service.js";
import { accountImportTables, importIdentityAccounts } from "../src/identity-account-import.js";
import { allocatorDigest } from "../src/identity-allocator-manifest.js";
import { finalizeAllocator, readSourceAllocatorInventory } from "../src/identity-allocator-finalizer.js";
import { importLegacySessions } from "../src/legacy-session-import.js";
import { activateIdentityAuthority, assertMigrationStaging } from "../src/migration-state.js";

const enabled = process.env.IDENTITY_TEST_MYSQL === "1";
const options = {
  host: process.env.IDENTITY_TEST_MYSQL_HOST ?? "127.0.0.1",
  port: Number(process.env.IDENTITY_TEST_MYSQL_PORT ?? 13316),
  user: process.env.IDENTITY_TEST_MYSQL_USER ?? "root",
  password: process.env.IDENTITY_TEST_MYSQL_PASSWORD ?? "",
  timezone: "Z", multipleStatements: true,
};
const schemas = ["identity-account-schema.sql", "identity-password-reset-token-schema.sql",
  "identity-legacy-challenge-schema.sql", "identity-runtime-schema.sql", "identity-wechat-oauth-schema.sql",
  "identity-qrcode-schema.sql", "identity-apple-schema.sql", "identity-allocator-schema.sql"];

describe.skipIf(!enabled)("allocator checkpoint attacks against disposable private MySQL", () => {
  let admin: Connection, db: Connection, database: string;
  const extraConnections: Connection[] = [];
  const sourceDatabases: string[] = [];
  async function connection() {
    const result = await mysql.createConnection({ ...options, database });
    extraConnections.push(result); return result;
  }
  async function migratedFixture() {
    const sourceDatabase = `test_allocator_source_${randomUUID().replaceAll("-", "")}`;
    sourceDatabases.push(sourceDatabase);
    await admin.query(`CREATE DATABASE \`${sourceDatabase}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`);
    const source = await mysql.createConnection({ ...options, database: sourceDatabase });
    extraConnections.push(source);
    const sql = await readFile(new URL("../../../deploy/mysql/identity-account-schema.sql", import.meta.url), "utf8");
    for (const statement of sql.split(";")) {
      const table = statement.match(/CREATE TABLE IF NOT EXISTS `?([a-z_]+)`?\s*\(/)?.[1];
      if (table && Object.hasOwn(accountImportTables, table)) await source.query(statement);
    }
    await source.query("INSERT INTO auth_item(name,type,description) VALUES ('root',1,'root'),('admin',1,'admin'),('manager',1,'manager'),('user',1,'user');INSERT INTO user(id,username,status) VALUES (10,'migrated-source',10);INSERT INTO user_info(id,user_id,info) VALUES (20,10,'{}');INSERT INTO auth_assignment(item_name,user_id) VALUES ('user','10');ALTER TABLE user AUTO_INCREMENT=100;CREATE TABLE device_sn(id BIGINT NOT NULL PRIMARY KEY,original_user_id INT UNSIGNED NULL) ENGINE=InnoDB;INSERT INTO device_sn VALUES (1,150)");
    const importKey = "real-account-import";
    await importIdentityAccounts(source, db, { importKey, apply: true });
    await db.query("INSERT INTO identity_users(id,legacy_user_id,status,source) VALUES ('retained-dangling-map',250,'disabled','legacy');INSERT INTO identity_legacy_profile_history(id,payload_hash,payload_json,source_database) VALUES (500,REPEAT('c',64),'{}','retained-source')");
    const fence = await connection();
    async function reviewed() {
      const inventory = await readSourceAllocatorInventory(source);
      const review = { version: 1 as const, sourceDatabase, targetDatabase: database, sourceServerUuid: inventory.serverUuid,
        importKey, writersDrainedAt: new Date().toISOString(), finalSyncSha256: allocatorDigest({ fixture: "account snapshot complete" }),
        referenceReviewSha256: inventory.referenceReviewSha256 };
      return { source, target: db, fence, review, reviewSha256: allocatorDigest(review) };
    }
    return { source, sourceDatabase, fence, reviewed };
  }
  async function authority() {
    return (await db.query<RowDataPacket[]>("SELECT authority FROM identity_migration_control WHERE id=1"))[0][0].authority;
  }
  async function retainedOrganizationMap() {
    // The optional legacy writer's real shape; its opaque ID is a separate namespace from its numeric legacy column.
    await db.query(`CREATE TABLE identity_organization_id_map (
      legacy_organization_id BIGINT NOT NULL,
      identity_organization_id VARCHAR(128) NOT NULL,
      source VARCHAR(32) NOT NULL,
      mapping_status VARCHAR(32) NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      PRIMARY KEY (legacy_organization_id),
      UNIQUE KEY idx_identity_org_map_identity_id (identity_organization_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`);
  }
  async function guardedActivation(conn = db) {
    await conn.beginTransaction();
    try {
      await assertMigrationStaging(conn);
      await assertAllocatorReady(conn);
      await activateIdentityAuthority(conn);
      await conn.commit();
    } catch (error) { await conn.rollback(); throw error; }
  }
  async function guardedRestart() {
    await db.beginTransaction();
    try {
      await db.query("SELECT authority FROM identity_migration_control WHERE id=1 FOR UPDATE");
      await assertAllocatorReady(db); await db.commit();
    } catch (error) { await db.rollback(); throw error; }
  }
  async function waitForFenceWaiter(id: number) {
    for (let attempt = 0; attempt < 200; attempt++) {
      const [rows] = await admin.query<RowDataPacket[]>("SHOW PROCESSLIST");
      if (rows.some(row => Number(row.Id) === id && row.db === database
        && String(row.Info).includes("identity_migration_control") && String(row.Info).includes("FOR UPDATE"))) return;
      await new Promise(resolve => setTimeout(resolve, 10));
    }
    throw new Error("Disposable allocator fixture did not reach the migration-fence wait");
  }

  beforeAll(async () => {
    const githubMysql = options.port === 3306 && (process.env.CI === "true" || process.env.GITHUB_ACTIONS === "true");
    if (options.host !== "127.0.0.1" || (options.port !== 13316 && !githubMysql)) throw new Error("Allocator attack fixtures require the dedicated local or CI MySQL instance");
    admin = await mysql.createConnection(options);
  });
  beforeEach(async () => {
    database = `test_allocator_attack_${randomUUID().replaceAll("-", "")}`;
    await admin.query(`CREATE DATABASE \`${database}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`);
    db = await mysql.createConnection({ ...options, database });
    const init = await readFile(new URL("../../../deploy/mysql/init.sql", import.meta.url), "utf8");
    await db.query(init.slice(init.indexOf("CREATE TABLE IF NOT EXISTS `auth_login_events`")));
    for (const schema of schemas) await db.query(await readFile(new URL(`../../../deploy/mysql/${schema}`, import.meta.url), "utf8"));
  }, 30_000);
  afterEach(async () => {
    await db?.rollback();
    for (const conn of extraConnections.splice(0)) { await conn.rollback(); await conn.end(); }
    await db?.end();
    for (const sourceDatabase of sourceDatabases.splice(0)) await admin.query(`DROP DATABASE IF EXISTS \`${sourceDatabase}\``);
    if (database) await admin.query(`DROP DATABASE IF EXISTS \`${database}\``);
    vi.unstubAllEnvs();
  }, 30_000);
  afterAll(async () => { await admin?.end(); });

  it("rejects missing checkpoint without activating an otherwise complete empty schema", async () => {
    await expect(guardedActivation()).rejects.toThrow();
    expect(await authority()).toBe("staging");
    const [rows] = await db.query<RowDataPacket[]>("SELECT COUNT(*) AS n FROM identity_migration_allocator_state");
    expect(Number(rows[0].n)).toBe(0);
  });

  const retainedReferences = [
    ["legacy identity map", "INSERT INTO identity_users(id,legacy_user_id,status,source) VALUES ('retained',900,'disabled','legacy')"],
    ["legacy subject map", "INSERT INTO identity_subject_maps(identity_user_id,subject_type,subject_id,source,status) VALUES ('retained','legacy_user','900','legacy','disabled')"],
    ["expired refresh", "INSERT INTO identity_refresh_sessions(refresh_token_hash,session_id,legacy_user_id,issued_at,expires_at,revoked_at) VALUES (REPEAT('a',64),'expired',900,'2025-01-01','2025-01-02','2025-01-02')"],
    ["revocation cutoff", "INSERT INTO identity_user_revocations(user_id,revoked_before) VALUES (900,UTC_TIMESTAMP(3))"],
    ["profile archive", "INSERT INTO identity_legacy_profile_rows(id,user_id,payload_json,selected_profile_id) VALUES (900,901,'{}',900)"],
    ["profile history", "INSERT INTO identity_legacy_profile_history(id,payload_hash,payload_json,source_database) VALUES (900,REPEAT('b',64),'{}','reviewed_source')"],
    ["empty-account import baseline", "INSERT INTO identity_account_import_runs(import_key,source_database,row_counts,completed_at) VALUES ('retained','reviewed_source','{\"user\":0}',UTC_TIMESTAMP(3))"],
    ["ownerless provider credential", "INSERT INTO wechat(openid,user_id,token) VALUES ('retained-ownerless',NULL,'old-signup-proof')"],
  ] as const;
  it.each(retainedReferences)("does not certify fresh while a %s remains", async (_label, sql) => {
    await db.query(sql);
    await expect(initializeFreshAllocator(db)).rejects.toThrow();
    expect(await authority()).toBe("staging");
    await expect(guardedActivation()).rejects.toThrow();
  });

  it("refuses fresh initialization in a caller transaction without committing its account write", async () => {
    await db.beginTransaction(); await db.query("INSERT INTO user(id,username,status) VALUES (99,'fresh-uncommitted-caller',10)");
    await expect(initializeFreshAllocator(db)).rejects.toThrow(); await db.rollback();
    const [rows] = await db.query<RowDataPacket[]>("SELECT id FROM user WHERE id=99");
    expect(rows).toHaveLength(0); expect(await authority()).toBe("staging");
  });

  it("rechecks strict fresh emptiness under the activation fence", async () => {
    await initializeFreshAllocator(db);
    await db.query("INSERT INTO user(id,username,status) VALUES (42,'late-staging-account',10)");
    await expect(guardedActivation()).rejects.toThrow();
    expect(await authority()).toBe("staging");
  });

  it("allows real native growth and restart without treating fresh as permanently empty", async () => {
    await initializeFreshAllocator(db); await guardedActivation();
    await db.query("INSERT INTO user(id,username,status) VALUES (42,'native-growth',10); INSERT INTO user_info(user_id) VALUES (42); INSERT INTO auth_assignment(item_name,user_id) VALUES ('user','42'); INSERT INTO organization(id,name,title) VALUES (70,'native-org','Native organization'); INSERT INTO user_organization(user_id,organization_id) VALUES (42,70)");
    await expect(guardedRestart()).resolves.toBeUndefined();
    expect(await authority()).toBe("identity");
  });

  it("rejects an empty but previously used allocator as a fresh installation", async () => {
    await db.query("ALTER TABLE user AUTO_INCREMENT=100");
    await expect(initializeFreshAllocator(db)).rejects.toThrow("ALLOCATOR_FRESH_SEQUENCE_HISTORY");
    expect(await authority()).toBe("staging");
  });

  it("rejects a lowered migrated counter even when its allocator table is empty", async () => {
    const fixture = await migratedFixture();
    await fixture.source.query("ALTER TABLE organization AUTO_INCREMENT=100");
    await finalizeAllocator({ ...await fixture.reviewed(), apply: true });
    await db.query("ALTER TABLE organization AUTO_INCREMENT=10");
    await expect(guardedActivation()).rejects.toThrow("ALLOCATOR_COUNTER_UNSAFE");
    expect(await authority()).toBe("staging");
  });

  it("checks current historical references beyond the original floor on restart", async () => {
    await initializeFreshAllocator(db); await guardedActivation();
    await db.query("INSERT INTO user(id,username,status) VALUES (42,'retained-after-activation',10); INSERT INTO identity_users(id,legacy_user_id,status,source) VALUES ('later-retained',900,'disabled','identity')");
    await expect(guardedRestart()).rejects.toThrow();
    expect(await authority()).toBe("identity");
  });

  it("does not accept a corrupted stored manifest under its previous hash", async () => {
    await initializeFreshAllocator(db);
    await db.query("UPDATE identity_migration_allocator_state SET manifest_json=JSON_SET(manifest_json,'$.targetDatabase','different_private_database') WHERE id=1");
    await expect(guardedActivation()).rejects.toThrow();
    expect(await authority()).toBe("staging");
  });

  it("invalidates a previously ready checkpoint before another staging mutation", async () => {
    await initializeFreshAllocator(db);
    await db.beginTransaction();
    try { await assertMigrationStaging(db); await invalidateAllocatorReady(db); await db.commit(); }
    catch (error) { await db.rollback(); throw error; }
    await expect(guardedActivation()).rejects.toThrow();
    expect(await authority()).toBe("staging");
  });

  it("serializes activation against a competing cooperative staging writer", async () => {
    await initializeFreshAllocator(db);
    await db.beginTransaction(); await assertMigrationStaging(db);
    const writer = await connection();
    const competing = (async () => {
      await writer.beginTransaction();
      try {
        await assertMigrationStaging(writer); await invalidateAllocatorReady(writer);
        await writer.query("INSERT INTO user(username,status) VALUES ('must-not-appear',10)");
        await writer.commit(); return "committed";
      } catch (error) { await writer.rollback(); return error; }
    })();
    await waitForFenceWaiter(writer.threadId);
    await assertAllocatorReady(db); await activateIdentityAuthority(db); await db.commit();
    expect(await competing).toBeInstanceOf(Error);
    expect(await authority()).toBe("identity");
    const [rows] = await db.query<RowDataPacket[]>("SELECT COUNT(*) AS n FROM user WHERE username='must-not-appear'");
    expect(Number(rows[0].n)).toBe(0);
  });

  it("raises migrated counters above source highwater, dangling account references and archived profile IDs", async () => {
    const fixture = await migratedFixture();
    const plan = await finalizeAllocator({ ...await fixture.reviewed(), apply: true });
    expect(plan.manifest.kind).toBe("migrated");
    expect(plan.manifest.floors.user).toMatchObject({ floor: "251", sourceNext: "100", reservedMax: "250" });
    expect(plan.manifest.floors.user_info).toMatchObject({ floor: "501", sourceNext: "21", reservedMax: "500" });
    await guardedActivation();
    const [result] = await db.query<mysql.ResultSetHeader>("INSERT INTO user(username,status) VALUES ('first-native-user',10)");
    expect(result.insertId).toBe(251);
    await expect(guardedRestart()).resolves.toBeUndefined();
  });

  it("reserves legacy-prefixed billing subjects while preserving opaque UUID and username namespaces", async () => {
    const fixture = await migratedFixture();
    await db.query("INSERT INTO account_usage_balance_shadow(subject_type,subject_id,usage_type) VALUES ('user','legacy:700','fixture'),('user','identity:legacy:800','fixture'),('user','identity:opaque-provider-uuid','fixture'),('user','username:9000000','fixture');INSERT INTO identity_subject_maps(identity_user_id,subject_type,subject_id,source,status) VALUES ('billing-retained','plugin_user','legacy:850','legacy','disabled');INSERT INTO iam_reconciliation_items(run_key,scope,severity,legacy_subject_type,legacy_subject_id,field_path) VALUES ('retained','fixture','warning','legacy_user','900','fixture')");
    const plan = await finalizeAllocator({ ...await fixture.reviewed(), apply: true });
    expect(plan.manifest.floors.user).toMatchObject({ floor: "901", reservedMax: "900" });
    await expect(guardedActivation()).resolves.toBeUndefined();
  });

  it("reserves explicit legacy IDs retained only in identity maps, shadows and reconciliation without guessing opaque namespaces", async () => {
    const fixture = await migratedFixture();
    await retainedOrganizationMap();
    await db.query("INSERT INTO identity_users(id,legacy_user_id,status,source) VALUES ('legacy:900',NULL,'disabled','legacy'),('9999999',NULL,'disabled','provider'),('08e47145-47cc-4b5d-b86b-a55cddc17813',NULL,'disabled','provider')");
    expect((await readPrivateAllocatorInventory(db)).reserved.user).toBe("900");
    await db.query("INSERT INTO identity_role_assignments_shadow(identity_user_id,legacy_user_id,role_name,observed_at) VALUES ('legacy:950',NULL,'user',UTC_TIMESTAMP(3)),('987654321',NULL,'user',UTC_TIMESTAMP(3));INSERT INTO identity_organization_id_map(legacy_organization_id,identity_organization_id,source,mapping_status) VALUES (1,'legacy:700','legacy','retained'),(2,'987654321','provider','retained')");
    const shadows = await readPrivateAllocatorInventory(db);
    expect(shadows.reserved).toMatchObject({ user: "950", organization: "700" });
    await db.query("INSERT INTO iam_reconciliation_items(run_key,scope,severity,identity_subject_type,identity_subject_id,field_path) VALUES ('retained-user','fixture','warning','identity_user','legacy:1100','fixture'),('retained-org','fixture','warning','identity_organization','legacy:1200','fixture'),('opaque-user','fixture','warning','identity_user','999999999','fixture'),('opaque-org','fixture','warning','identity_organization','08e47145-47cc-4b5d-b86b-a55cddc17813','fixture')");
    const plan = await finalizeAllocator({ ...await fixture.reviewed(), apply: true });
    expect(plan.manifest.floors.user).toMatchObject({ floor: "1101", reservedMax: "1100" });
    expect(plan.manifest.floors.organization).toMatchObject({ floor: "1201", reservedMax: "1200" });
    await expect(guardedActivation()).resolves.toBeUndefined();
  });

  it.each([
    ["map leading zero", "INSERT INTO identity_users(id,legacy_user_id,status,source) VALUES ('legacy:0900',NULL,'disabled','legacy')"],
    ["shadow prefix case", "INSERT INTO identity_role_assignments_shadow(identity_user_id,legacy_user_id,role_name,observed_at) VALUES ('Legacy:950',NULL,'user',UTC_TIMESTAMP(3))"],
    ["reconciliation negative", "INSERT INTO iam_reconciliation_items(run_key,scope,severity,identity_subject_type,identity_subject_id,field_path) VALUES ('retained','fixture','warning','identity_organization','legacy:-700','fixture')"],
  ])("rejects a noncanonical explicit legacy reference: %s", async (_label, sql) => {
    const fixture = await migratedFixture();
    await db.query(sql);
    await expect(finalizeAllocator({ ...await fixture.reviewed(), apply: true })).rejects.toThrow("ALLOCATOR_NONCANONICAL_SUBJECT_REFERENCE");
    expect(await authority()).toBe("staging");
    await expect(guardedActivation()).rejects.toThrow();
  });

  it("rejects exhausted business-ID capacity without lowering or widening any target allocator", async () => {
    const fixture = await migratedFixture();
    await fixture.source.query("ALTER TABLE user AUTO_INCREMENT=2147483648");
    await expect(finalizeAllocator({ ...await fixture.reviewed(), apply: true })).rejects.toThrow("ALLOCATOR_FLOOR_CAPACITY");
    await expect(guardedActivation()).rejects.toThrow("ALLOCATOR_NOT_READY");
    const [meta] = await db.query<RowDataPacket[]>("SELECT AUTO_INCREMENT AS n FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='user'");
    expect(Number(meta[0].n)).toBe(11);
    expect(await authority()).toBe("staging");
  });

  it("keeps the ready proof on identical session replay and read-only preview, invalidating only a new imported row", async () => {
    const fixture = await migratedFixture(), now = Math.floor(Date.now() / 1000);
    const input = { version: 1, sessions: [{ keyEncoding: "plain", key: "reviewed-allocator-session", user_id: 10,
      session_id: "allocator-retained-session", created_at: now - 10, expires_at: now + 600, revoked_at: null, client: null }] };
    await importLegacySessions(db, input, { apply: true, environment: "staging" });
    const plan = await finalizeAllocator({ ...await fixture.reviewed(), apply: true });
    expect(await importLegacySessions(db, input, { apply: true, environment: "staging" })).toMatchObject({ existing: 1, imported: 0 });
    const fresh = { ...input, sessions: [{ ...input.sessions[0], key: "another-reviewed-session", session_id: "allocator-new-session" }] };
    expect(await importLegacySessions(db, fresh)).toMatchObject({ imported: 0, wouldImport: 1 });
    const [ready] = await db.query<RowDataPacket[]>("SELECT state,manifest_sha256 FROM identity_migration_allocator_state WHERE id=1");
    expect(ready[0]).toMatchObject({ state: "ready", manifest_sha256: plan.manifestSha256 });
    await importLegacySessions(db, fresh, { apply: true, environment: "staging" });
    await expect(guardedActivation()).rejects.toThrow("ALLOCATOR_NOT_READY");
  });

  it("refuses a caller's active transaction without committing its uncommitted account", async () => {
    const fixture = await migratedFixture(), reviewed = await fixture.reviewed();
    await db.beginTransaction(); await db.query("INSERT INTO user(id,username,status) VALUES (99,'uncommitted-caller',10)");
    await expect(finalizeAllocator({ ...reviewed, apply: true })).rejects.toThrow();
    await db.rollback();
    const [rows] = await db.query<RowDataPacket[]>("SELECT id FROM user WHERE id=99");
    expect(rows).toHaveLength(0);
    expect(await authority()).toBe("staging");
  });

  it("allows the last business-safe user ID and rolls back ordinary and OAuth allocation beyond it while running", async () => {
    await initializeFreshAllocator(db); await guardedActivation();
    await db.query("ALTER TABLE user AUTO_INCREMENT=2147483647");
    for (const [key, value] of Object.entries({ IDENTITY_DATA_SOURCE: "identity", IDENTITY_DB_HOST: options.host,
      IDENTITY_DB_PORT: String(options.port), IDENTITY_DB_NAME: database, IDENTITY_DB_USER: options.user,
      IDENTITY_DB_PASSWORD: options.password, IDENTITY_INTERNAL_API_TOKEN: "allocator-test-internal-token-at-least-32-bytes",
      LEGACY_DB_HOST: "127.0.0.1", LEGACY_DB_PORT: "1", LEGACY_DB_USER: "unreachable",
      LEGACY_WRITE_DB_HOST: "127.0.0.1", LEGACY_WRITE_DB_PORT: "1", LEGACY_WRITE_DB_USER: "unreachable" })) vi.stubEnv(key, value);
    const registration = new AccountRegistrationRepository(), reader = new LegacyIdentityReader();
    const sessions = new IdentitySessionRepository(), jwt = new JwtIssuerService();
    const native = new NativeIdentityService(reader, jwt, sessions), oauth = new IdentityWechatOAuthService(reader, sessions, jwt, native);
    const counts = async () => {
      const result: Record<string, number> = {};
      for (const table of ["user", "user_info", "auth_assignment", "identity_subject_events", "identity_refresh_sessions",
        "identity_wechat_identities", "wechat", "identity_account_registration_requests"]) {
        const [rows] = await db.query<RowDataPacket[]>(`SELECT COUNT(*) AS n FROM \`${table}\``); result[table] = Number(rows[0].n);
      }
      return result;
    };
    try {
      const last = await registration.register({ username: "last-business-safe", password: "Last-safe-password!73" }, "last-business-safe-registration");
      expect(last.id).toBe(2147483647);
      const before = await counts(); expect(before.user).toBe(1); expect(before.identity_subject_events).toBe(1);
      await expect(registration.register({ username: "must-rollback-capacity", password: "Capacity-password!73" }, "capacity-exceeded-registration")).rejects.toThrow("ALLOCATOR_USER_CAPACITY_EXHAUSTED");
      expect(await counts()).toEqual(before);
      await expect(oauth.resolveWechat({ provider: "wechat_official_account", providerAppId: "wx-allocator-test",
        openId: "must-rollback-provider-placeholder", nickname: "Capacity fixture" }, true)).rejects.toThrow("ALLOCATOR_USER_CAPACITY_EXHAUSTED");
      expect(await counts()).toEqual(before);
      const [saved] = await db.query<RowDataPacket[]>("SELECT id FROM user ORDER BY id"); expect(saved.map(row => Number(row.id))).toEqual([2147483647]);
    } finally { await Promise.all([registration, reader, sessions, native, oauth].map(resource => resource.onModuleDestroy())); }
  });

  it("retains the old evidence as pending after a partially successful counter increase", async () => {
    const fixture = await migratedFixture();
    const first = await finalizeAllocator({ ...await fixture.reviewed(), apply: true });
    await fixture.source.query("ALTER TABLE user AUTO_INCREMENT=600;ALTER TABLE user_info AUTO_INCREMENT=800");
    await expect(finalizeAllocator({ ...await fixture.reviewed(), apply: true, onStep: async step => {
      if (step.table === "user" && step.phase === "success") throw new Error("injected operator journal failure");
    } })).rejects.toThrow("injected operator journal failure");
    const [checkpoint] = await db.query<RowDataPacket[]>("SELECT state,manifest_sha256 FROM identity_migration_allocator_state WHERE id=1");
    expect(checkpoint[0]).toMatchObject({ state: "pending", manifest_sha256: first.manifestSha256 });
    const [counter] = await db.query<RowDataPacket[]>("SELECT AUTO_INCREMENT AS n FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='user'");
    expect(Number(counter[0].n)).toBe(600);
    await expect(guardedActivation()).rejects.toThrow("ALLOCATOR_NOT_READY");
    expect(await authority()).toBe("staging");
  });

  it("detects a live source allocator advance across the consistent row snapshot", async () => {
    const fixture = await migratedFixture();
    const liveWriter = await mysql.createConnection({ ...options, database: fixture.sourceDatabase });
    extraConnections.push(liveWriter);
    await expect(finalizeAllocator({ ...await fixture.reviewed(), apply: true, onStep: async step => {
      if (step.table === "user" && step.phase === "intent") await liveWriter.query("INSERT INTO user(id,username,status) VALUES (900,'late-source-writer',10)");
    } })).rejects.toThrow("ALLOCATOR_SOURCE_METADATA_CHANGED");
    await expect(guardedActivation()).rejects.toThrow("ALLOCATOR_NOT_READY");
    expect(await authority()).toBe("staging");
  });

  it("detects changed semantic source references even when every source allocator counter is unchanged", async () => {
    const fixture = await migratedFixture();
    const liveWriter = await mysql.createConnection({ ...options, database: fixture.sourceDatabase });
    extraConnections.push(liveWriter);
    const before = await readSourceAllocatorInventory(liveWriter);
    await expect(finalizeAllocator({ ...await fixture.reviewed(), apply: true, onStep: async step => {
      if (step.table === "user" && step.phase === "intent") {
        await liveWriter.query("UPDATE device_sn SET original_user_id=900 WHERE id=1");
        expect((await readSourceAllocatorInventory(liveWriter)).counters).toEqual(before.counters);
      }
    } })).rejects.toThrow("ALLOCATOR_SOURCE_METADATA_CHANGED");
    await expect(guardedActivation()).rejects.toThrow("ALLOCATOR_NOT_READY");
    expect(await authority()).toBe("staging");
  });

  it("refuses target schema drift introduced by a separate connection between DDL steps", async () => {
    const fixture = await migratedFixture(), driftWriter = await connection();
    await expect(finalizeAllocator({ ...await fixture.reviewed(), apply: true, onStep: async step => {
      if (step.table === "user" && step.phase === "intent") await driftWriter.query("ALTER TABLE user_info ADD COLUMN unexpected_allocator_drift BIGINT NULL");
    } })).rejects.toThrow("ALLOCATOR_DDL_POSTCONDITION_FAILED");
    await expect(guardedActivation()).rejects.toThrow("ALLOCATOR_NOT_READY");
    expect(await authority()).toBe("staging");
  });

  it("does not allow a waiting bootstrap to use the old proof after partial finalization", async () => {
    const fixture = await migratedFixture();
    await finalizeAllocator({ ...await fixture.reviewed(), apply: true });
    await fixture.source.query("ALTER TABLE user AUTO_INCREMENT=600");
    const bootstrap = await connection();
    let attempt: Promise<void> | undefined;
    await expect(finalizeAllocator({ ...await fixture.reviewed(), apply: true, onStep: async step => {
      if (step.table === "user" && step.phase === "success") {
        attempt = guardedActivation(bootstrap);
        // Register rejection before finalization releases the fence to avoid an unhandled rejection.
        void attempt.catch(() => undefined);
        await waitForFenceWaiter(bootstrap.threadId);
        throw new Error("injected finalization interruption");
      }
    } })).rejects.toThrow("injected finalization interruption");
    expect(attempt).toBeDefined(); await expect(attempt!).rejects.toThrow("ALLOCATOR_NOT_READY");
    expect(await authority()).toBe("staging");
  });
});
