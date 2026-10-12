import { readFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import mysql, { type Connection, type RowDataPacket } from "mysql2/promise";
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
} from "vitest";
import {
  accountImportTables,
  importIdentityAccounts,
} from "../src/identity-account-import.js";
import { syncIdentityAccounts } from "../src/identity-account-sync.js";
import {
  activateIdentityAuthority,
  recordMigrationBaseline,
} from "../src/migration-state.js";
import { importLegacySessions } from "../src/legacy-session-import.js";

const enabled = process.env.IDENTITY_TEST_MYSQL === "1";
const options = {
  host: process.env.IDENTITY_DB_HOST ?? "127.0.0.1",
  port: Number(process.env.IDENTITY_DB_PORT ?? 3306),
  user: process.env.IDENTITY_DB_USER ?? "root",
  password: process.env.IDENTITY_DB_PASSWORD ?? "",
  multipleStatements: true,
  timezone: "Z",
};
let admin: Connection, source: Connection, target: Connection;
let sourceName: string, targetName: string;
const owned: string[] = [];
const apply = { apply: true, maxChanges: 100 };
async function database(): Promise<{ connection: Connection; name: string }> {
  const name = `test_account_sync_${randomUUID().replaceAll("-", "")}`;
  owned.push(name);
  await admin.query(
    `CREATE DATABASE \`${name}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`,
  );
  const connection = await mysql.createConnection({
    ...options,
    database: name,
  });
  const init = await readFile(
    new URL("../../../deploy/mysql/init.sql", import.meta.url),
    "utf8",
  );
  await connection.query(
    init.slice(init.indexOf("CREATE TABLE IF NOT EXISTS `auth_login_events`")),
  );
  for (const schema of [
    "identity-account-schema.sql",
    "identity-runtime-schema.sql",
    "identity-wechat-oauth-schema.sql",
  ])
    await connection.query(
      await readFile(
        new URL(`../../../deploy/mysql/${schema}`, import.meta.url),
        "utf8",
      ),
    );
  return { connection, name };
}
async function rows(sql: string) {
  const [result] = await target.query<RowDataPacket[]>(sql);
  return result;
}
async function eventCount() {
  return Number(
    (await rows("SELECT COUNT(*) AS count FROM identity_subject_events"))[0]
      .count,
  );
}

describe.skipIf(!enabled)("staging account delta MySQL sync", () => {
  beforeAll(async () => {
    if (!["127.0.0.1", "localhost", "::1"].includes(options.host))
      throw new Error(
        "Account sync integration requires a disposable local MySQL instance.",
      );
    admin = await mysql.createConnection(options);
  });
  beforeEach(async () => {
    const from = await database(),
      to = await database();
    source = from.connection;
    sourceName = from.name;
    target = to.connection;
    targetName = to.name;
    await source.query(
      "ALTER TABLE user_info ADD COLUMN avatar_id BIGINT NULL",
    );
    await source.query(`INSERT INTO user (id,username,email,status,nickname,password_hash,created_at,updated_at)
      VALUES (7001,'first','first@example.test',10,'First','existing-password-1',1700000000,1700000000),
             (7002,'second','second@example.test',10,'Second','existing-password-2',1700000000,1700000000)`);
    await source.query(
      'INSERT INTO user_info (id,user_id,info,avatar_id) VALUES (1,7001,\'{"nested":{"b":2,"a":1}}\',99)',
    );
    await source.query(
      "INSERT INTO auth_assignment (item_name,user_id,created_at) VALUES ('user','7001',1700000000),('user','7002',1700000000)",
    );
    await source.query(
      "INSERT INTO organization (id,name,title) VALUES (41,'team','Old team')",
    );
    await source.query(
      "INSERT INTO user_organization (user_id,organization_id) VALUES (7001,41),(7002,41)",
    );
    await importIdentityAccounts(source, target, {
      importKey: "baseline",
      apply: true,
    });
  }, 30_000);
  afterEach(async () => {
    await Promise.all([source?.end(), target?.end()]);
    for (const name of owned.splice(0))
      await admin.query(`DROP DATABASE IF EXISTS \`${name}\``);
  });
  afterAll(async () => {
    await admin?.end();
  });

  it("previews without writes, applies identity-only deltas and is idempotent after commit", async () => {
    await source.query("UPDATE user SET nickname='Changed' WHERE id=7001");
    await source.query("UPDATE user_info SET avatar_id=123 WHERE user_id=7001");
    await source.query(
      "INSERT INTO user (id,username,email,status) VALUES (7003,'third','third@example.test',10)",
    );
    await source.query(
      "INSERT INTO auth_assignment (item_name,user_id) VALUES ('manager','7003')",
    );
    await source.query(
      "INSERT INTO organization (id,name,title) VALUES (42,'new','New team')",
    );
    await source.query(
      "INSERT INTO user_organization (user_id,organization_id) VALUES (7003,42)",
    );
    const before = await eventCount();
    expect(
      await syncIdentityAccounts(source, target, { maxChanges: 10 }),
    ).toMatchObject({
      applied: false,
      changes: 7,
      inserts: 4,
      updates: 3,
      affectedSubjects: 2,
    });
    expect(
      (await rows("SELECT nickname FROM user WHERE id=7001"))[0].nickname,
    ).toBe("First");
    expect(await eventCount()).toBe(before);
    expect(
      await syncIdentityAccounts(source, target, { ...apply, maxChanges: 10 }),
    ).toMatchObject({ applied: true, changes: 7 });
    expect(
      (await rows("SELECT nickname,password_hash FROM user WHERE id=7001"))[0],
    ).toMatchObject({
      nickname: "Changed",
      password_hash: "existing-password-1",
    });
    expect(
      Number(
        (
          await rows(
            "SELECT avatar_id FROM identity_profile_avatars WHERE user_id=7001",
          )
        )[0].avatar_id,
      ),
    ).toBe(123);
    expect(
      (
        await rows(
          "SELECT legacy_user_id,status FROM identity_users WHERE legacy_user_id=7003",
        )
      )[0],
    ).toMatchObject({ legacy_user_id: 7003, status: "active" });
    expect(
      (await rows("SHOW COLUMNS FROM user_info")).map((row) => row.Field),
    ).toEqual(["id", "user_id", "info"]);
    expect(await eventCount()).toBe(before + 2);
    expect(await syncIdentityAccounts(source, target, apply)).toMatchObject({
      applied: true,
      changes: 0,
    });
    expect(await eventCount()).toBe(before + 2);
  });

  it("detects target independent writes even on rows that the source did not change", async () => {
    await source.query(
      "UPDATE user SET nickname='Source update' WHERE id=7001",
    );
    await target.query(
      "UPDATE user SET nickname='Native update' WHERE id=7002",
    );
    await expect(syncIdentityAccounts(source, target, apply)).rejects.toThrow(
      "diverged",
    );
    expect(
      (await rows("SELECT nickname FROM user ORDER BY id")).map(
        (row) => row.nickname,
      ),
    ).toEqual(["First", "Native update"]);
  });

  it("rejects unknown private rows instead of overwriting or silently adopting them", async () => {
    await target.query(
      "INSERT INTO user (id,username,status) VALUES (7999,'native-only',10)",
    );
    await source.query(
      "UPDATE user SET nickname='Source update' WHERE id=7001",
    );
    await expect(syncIdentityAccounts(source, target, apply)).rejects.toThrow(
      "diverged",
    );
    expect(
      (await rows("SELECT nickname FROM user WHERE id=7001"))[0].nickname,
    ).toBe("First");
  });
  it("preserves baselined accounts owned by a separate imported source and rejects integer ID collisions", async () => {
    await target.query(
      "INSERT INTO user (id,username,status) VALUES (7999,'oauth-only',10)",
    );
    const [oauth] = await target.query<RowDataPacket[]>(
      "SELECT * FROM user WHERE id=7999",
    );
    await recordMigrationBaseline(
      target,
      "user",
      accountImportTables.user,
      null,
      oauth[0],
    );
    expect(await syncIdentityAccounts(source, target, apply)).toMatchObject({
      changes: 0,
    });
    await source.query(
      "INSERT INTO user (id,username,status) VALUES (7999,'new-legacy-user',10)",
    );
    await expect(syncIdentityAccounts(source, target, apply)).rejects.toThrow(
      "reserved by another imported authority",
    );
    expect(
      (await rows("SELECT username FROM user WHERE id=7999"))[0].username,
    ).toBe("oauth-only");
  });

  it("aborts before writes when the row or outbox fanout exceeds the explicit change budget", async () => {
    const before = await eventCount();
    await source.query("UPDATE user SET nickname='Budget update'");
    await expect(
      syncIdentityAccounts(source, target, { apply: true, maxChanges: 1 }),
    ).rejects.toThrow("exceeds maxChanges");
    await source.query("UPDATE user SET nickname=IF(id=7001,'First','Second')");
    await source.query(
      "UPDATE auth_item SET description='New policy' WHERE name='user'",
    );
    await expect(
      syncIdentityAccounts(source, target, { apply: true, maxChanges: 1 }),
    ).rejects.toThrow("fanout exceeds maxChanges");
    expect(await eventCount()).toBe(before);
    expect(
      (await rows("SELECT description FROM auth_item WHERE name='user'"))[0]
        .description,
    ).toBe("user");
  });

  it("keeps integer-ID tombstones and revokes deleted account sessions without resurrecting on retry", async () => {
    await importLegacySessions(
      target,
      {
        version: 1,
        sessions: [
          {
            keyEncoding: "plain",
            key: "deleted-user-refresh",
            user_id: 7001,
            session_id: "deleted-family",
            created_at: 1700000000,
            expires_at: "2099-01-01T00:00:00Z",
            revoked_at: null,
            client: null,
          },
        ],
      },
      { apply: true, environment: "staging" },
    );
    await source.query("DELETE FROM user WHERE id=7001");
    await source.query("DELETE FROM user_info WHERE user_id=7001");
    await source.query("DELETE FROM auth_assignment WHERE user_id='7001'");
    await source.query("DELETE FROM user_organization WHERE user_id=7001");
    expect(await syncIdentityAccounts(source, target, apply)).toMatchObject({
      deletions: 5,
    });
    const tombstone = (
      await rows("SELECT id,status,deleted_at FROM user WHERE id=7001")
    )[0];
    expect(tombstone).toMatchObject({ id: 7001, status: 0 });
    expect(Number(tombstone.deleted_at)).toBeGreaterThan(0);
    expect(
      (
        await rows(
          "SELECT status FROM identity_users WHERE legacy_user_id=7001",
        )
      )[0].status,
    ).toBe("disabled");
    expect(
      (await rows("SELECT revoked_at FROM identity_refresh_sessions"))[0]
        .revoked_at,
    ).toBeInstanceOf(Date);
    expect(
      (
        await rows(
          "SELECT source_hash,target_hash FROM identity_migration_rows WHERE table_name='user_info'",
        )
      )[0],
    ).toMatchObject({ source_hash: null, target_hash: null });
    expect(await syncIdentityAccounts(source, target, apply)).toMatchObject({
      changes: 0,
    });
    await source.query(
      "INSERT INTO user (id,username,status) VALUES (7001,'reused',10)",
    );
    await expect(syncIdentityAccounts(source, target, apply)).rejects.toThrow(
      "cannot reuse a tombstoned",
    );
  });

  it("orders policy and organization invalidations for every affected user in the same commit", async () => {
    const before = Number(
      (await rows("SELECT MAX(id) AS id FROM identity_subject_events"))[0].id,
    );
    await source.query(
      "UPDATE auth_item SET description='Policy changed' WHERE name='user'",
    );
    await source.query(
      "UPDATE organization SET title='Renamed team' WHERE id=41",
    );
    expect(await syncIdentityAccounts(source, target, apply)).toMatchObject({
      changes: 2,
      affectedSubjects: 2,
    });
    expect(
      (
        await rows(
          `SELECT user_id FROM identity_subject_events WHERE id>${before} ORDER BY id`,
        )
      ).map((row) => Number(row.user_id)),
    ).toEqual([7001, 7002]);
  });

  it("serializes competing snapshots and emits each committed delta once", async () => {
    const otherSource = await mysql.createConnection({
      ...options,
      database: sourceName,
    });
    const otherTarget = await mysql.createConnection({
      ...options,
      database: targetName,
    });
    try {
      const before = await eventCount();
      await source.query("UPDATE user SET nickname='Parallel' WHERE id=7001");
      const result = await Promise.all([
        syncIdentityAccounts(source, target, apply),
        syncIdentityAccounts(otherSource, otherTarget, apply),
      ]);
      expect(result.map((report) => report.changes).sort()).toEqual([0, 1]);
      expect(await eventCount()).toBe(before + 1);
    } finally {
      await Promise.all([otherSource.end(), otherTarget.end()]);
    }
  });

  it("rolls back account writes, baseline and events together after a later SQL failure", async () => {
    const before = await eventCount();
    await source.query("UPDATE user SET nickname='Will rollback'");
    await target.query(
      "CREATE TRIGGER abort_second BEFORE UPDATE ON user FOR EACH ROW BEGIN IF NEW.id=7002 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='test rollback'; END IF; END",
    );
    await expect(syncIdentityAccounts(source, target, apply)).rejects.toThrow(
      "test rollback",
    );
    expect(
      (await rows("SELECT nickname FROM user ORDER BY id")).map(
        (row) => row.nickname,
      ),
    ).toEqual(["First", "Second"]);
    expect(await eventCount()).toBe(before);
    await target.query("DROP TRIGGER abort_second");
    expect(await syncIdentityAccounts(source, target, apply)).toMatchObject({
      changes: 2,
    });
  });

  it("refuses source schema drift and the same physical database before applying anything", async () => {
    await source.query("ALTER TABLE user DROP COLUMN nickname");
    await expect(syncIdentityAccounts(source, target, apply)).rejects.toThrow(
      "columns changed",
    );
    const same = await mysql.createConnection({
      ...options,
      database: sourceName,
    });
    try {
      await expect(syncIdentityAccounts(source, same, apply)).rejects.toThrow(
        "Distinct source and target",
      );
    } finally {
      await same.end();
    }
  });

  it("permanently fences both preview and apply after Identity becomes authoritative", async () => {
    await target.beginTransaction();
    await activateIdentityAuthority(target);
    await target.commit();
    await source.query("UPDATE user SET nickname='Old source' WHERE id=7001");
    await expect(syncIdentityAccounts(source, target, apply)).rejects.toThrow(
      "already authoritative",
    );
    await expect(
      syncIdentityAccounts(source, target, { maxChanges: 100 }),
    ).rejects.toThrow("already authoritative");
    expect(
      (await rows("SELECT nickname FROM user WHERE id=7001"))[0].nickname,
    ).toBe("First");
  });
});
