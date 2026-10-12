import "reflect-metadata";
import { randomUUID } from "node:crypto";
import mysql, { type Connection } from "mysql2/promise";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { LegacyIdentityReader } from "../src/legacy-identity.reader.js";

// Disposable local fixture only; never point this test at an application schema.
const enabled = process.env.IDENTITY_TEST_MYSQL === "1";
describe.skipIf(!enabled)("native SN uses independent business device source", () => {
  const suffix = randomUUID().replaceAll("-", "");
  const privateName = `test_sn_private_${suffix}`, businessName = `test_sn_business_${suffix}`;
  const opts = { host: "127.0.0.1", port: Number(process.env.IDENTITY_TEST_MYSQL_PORT ?? 13316),
    user: process.env.IDENTITY_TEST_MYSQL_USER ?? "identity_test", password: process.env.IDENTITY_TEST_MYSQL_PASSWORD ?? "",
    multipleStatements: true };
  let admin: Connection, accounts: Connection, devices: Connection, reader: LegacyIdentityReader;

  beforeAll(async () => {
    if (process.env.NODE_ENV === "production") throw new Error("Disposable database test cannot run in production.");
    admin = await mysql.createConnection(opts);
    await admin.query(`CREATE DATABASE ${privateName} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
      CREATE DATABASE ${businessName} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`);
    accounts = await mysql.createConnection({ ...opts, database: privateName });
    devices = await mysql.createConnection({ ...opts, database: businessName });
    await accounts.query(`CREATE TABLE user (id INT PRIMARY KEY, username VARCHAR(100), email VARCHAR(100), status INT,
      nickname VARCHAR(100), email_verified_at INT, created_at INT, updated_at INT, deleted_at INT NULL);
      CREATE TABLE user_info (user_id INT, info JSON);
      CREATE TABLE auth_item (name VARCHAR(100) PRIMARY KEY, type INT, description VARCHAR(100));
      CREATE TABLE auth_assignment (user_id VARCHAR(30), item_name VARCHAR(100));
      CREATE TABLE auth_item_child (parent VARCHAR(100), child VARCHAR(100));
      INSERT INTO user (id, username, status) VALUES (7,'canonical-device-user',10);
      INSERT INTO auth_item (name,type) VALUES ('user',1),('admin',1),('root',1),('manager',1),('team',1);
      INSERT INTO auth_assignment VALUES ('7','user')`);
    // No business user/RBAC tables exist, so any legacy account join fails the fixture.
    await devices.query(`CREATE TABLE device_sn (id INT PRIMARY KEY, user_id INT, device_uuid VARCHAR(255), enabled BOOL, activated_at DATETIME);
      INSERT INTO device_sn VALUES (42,7,'rokid-uuid-not-rfc-uuid',1,NOW())`);
    for (const [prefix, database] of [["IDENTITY_DB", privateName], ["DEVICE_SN_DB", businessName]]) {
      for (const [key, value] of Object.entries({ HOST: opts.host, PORT: String(opts.port), NAME: database, USER: opts.user, PASSWORD: opts.password })) {
        vi.stubEnv(`${prefix}_${key}`, value);
      }
    }
    vi.stubEnv("IDENTITY_DATA_SOURCE", "identity");
    vi.stubEnv("LEGACY_DB_HOST", "127.0.0.1"); vi.stubEnv("LEGACY_DB_PORT", "1"); vi.stubEnv("LEGACY_DB_USER", "unreachable");
    reader = new LegacyIdentityReader();
  }, 30000);
  beforeEach(async () => {
    await accounts.query("DELETE FROM user WHERE id<>7; UPDATE user SET status=10,deleted_at=NULL; DELETE FROM auth_assignment; INSERT INTO auth_assignment VALUES ('7','user'); DELETE FROM auth_item_child");
    await devices.query("UPDATE device_sn SET user_id=7,enabled=1,activated_at=NOW(),device_uuid='rokid-uuid-not-rfc-uuid'");
  });
  afterAll(async () => {
    await reader?.onModuleDestroy(); await accounts?.end(); await devices?.end();
    if (admin) { await admin.query(`DROP DATABASE IF EXISTS ${privateName}; DROP DATABASE IF EXISTS ${businessName}`); await admin.end(); }
    vi.unstubAllEnvs();
  });

  it("checks live private accounts with only device_sn present in the separate business database", async () => {
    expect(await reader.deviceSnReadiness()).toBe(true);
    await expect(reader.assertDeviceSnAuthorized(42, 7)).resolves.toBeUndefined();
    expect((await reader.getUserById(7))?.source).toBe("identity-db");
    const [tables] = await devices.query("SHOW TABLES"); expect(tables).toHaveLength(1);
  });
  it("refuses disabled device issue/refresh but preserves original access grace", async () => {
    await devices.query("UPDATE device_sn SET enabled=0");
    await expect(reader.assertDeviceSnAuthorized(42, 7)).rejects.toMatchObject({ status: 401 });
    await expect(reader.assertDeviceSnAuthorized(42, 7, false)).resolves.toBeUndefined();
  });
  it.each(["root", "admin", "manager"])("immediately denies current private %s role even in the access grace period", async (role) => {
    await accounts.execute("INSERT INTO auth_assignment VALUES ('7',?)", [role]);
    await expect(reader.assertDeviceSnAuthorized(42, 7, false)).rejects.toMatchObject({ status: 401, response: { code: "DEVICE_SN_ACCOUNT_INELIGIBLE" } });
  });
  it("denies inherited elevated role from the private graph", async () => {
    await accounts.query("INSERT INTO auth_item_child VALUES ('user','team'),('team','manager')");
    await expect(reader.assertDeviceSnAuthorized(42, 7, false)).rejects.toMatchObject({ status: 401 });
  });
  it("denies disabled and deleted private accounts", async () => {
    await accounts.query("UPDATE user SET status=0");
    await expect(reader.assertDeviceSnAuthorized(42, 7, false)).rejects.toMatchObject({ status: 401 });
    await accounts.query("UPDATE user SET status=10,deleted_at=1");
    await expect(reader.assertDeviceSnAuthorized(42, 7, false)).rejects.toMatchObject({ status: 401 });
  });
  it("requires current device ownership, activation and exact bound UUID", async () => {
    for (const mutation of ["user_id=8", "activated_at=NULL", "device_uuid='uuid/path'", "device_uuid=CONCAT('uuid',CHAR(10))"]) {
      await devices.query(`UPDATE device_sn SET ${mutation}`);
      await expect(reader.assertDeviceSnAuthorized(42, 7, false)).rejects.toMatchObject({ status: 401 });
      await devices.query("UPDATE device_sn SET user_id=7,activated_at=NOW(),device_uuid='rokid-uuid-not-rfc-uuid'");
    }
  });
  it("reports false when the device source loses its schema without reading the old user database", async () => {
    await devices.query("RENAME TABLE device_sn TO missing_device_sn");
    try {
      expect(await reader.deviceSnReadiness()).toBe(false);
      await expect(reader.assertDeviceSnAuthorized(42, 7)).rejects.toMatchObject({ status: 503, response: { code: "DEVICE_SN_VALIDATION_UNAVAILABLE" } });
    } finally { await devices.query("RENAME TABLE missing_device_sn TO device_sn"); }
  });
  it("lists only live private eligible accounts with inherited role exclusion, search and pagination", async () => {
    await accounts.query(`INSERT INTO user (id,username,status,deleted_at) VALUES
      (8,'disabled',0,NULL),(9,'deleted',10,1),(10,'privileged',10,NULL),(11,'inherited',10,NULL),(12,'needle',10,NULL);
      INSERT INTO auth_assignment VALUES ('10','admin'),('11','team'),('12','user');
      INSERT INTO auth_item_child VALUES ('team','manager')`);
    expect(await reader.listDeviceSnAccounts("", 1, 1)).toMatchObject({ total: 2, page: 1, page_size: 1, items: [{ id: 7 }] });
    expect(await reader.listDeviceSnAccounts("", 2, 1)).toMatchObject({ total: 2, items: [{ id: 12 }] });
    expect(await reader.listDeviceSnAccounts("needle", 1, 20)).toMatchObject({ total: 1, items: [{ id: 12, username: "needle" }] });
    await accounts.query("INSERT INTO auth_assignment VALUES ('12','root')");
    expect(await reader.listDeviceSnAccounts("needle", 1, 20)).toMatchObject({ total: 0, items: [] });
  });
});
