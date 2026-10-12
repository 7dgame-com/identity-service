import "reflect-metadata";
import { generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";
import mysql, { type Connection } from "mysql2/promise";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { IdentitySessionRepository } from "../src/identity-session.repository.js";
import { JwtIssuerService } from "../src/jwt-issuer.service.js";
import { LegacyIdentityReader } from "../src/legacy-identity.reader.js";
import { LoginAuditService } from "../src/login-audit.service.js";
import { TokenIssuanceService } from "../src/token-issuance.service.js";

// Only use a disposable MySQL server. This suite owns and removes its own schema.
const port = process.env.DEVICE_SN_MYSQL_TEST_PORT;
describe.skipIf(!port)("device SN sessions against MySQL", () => {
  const database = `device_sn_identity_test_${process.pid}`;
  let connection: Connection;
  let reader: LegacyIdentityReader;
  let sessions: IdentitySessionRepository;
  let jwt: JwtIssuerService;
  let tokens: TokenIssuanceService;

  beforeAll(async () => {
    connection = await mysql.createConnection({ host: "127.0.0.1", port: Number(port), user: "root",
      password: process.env.DEVICE_SN_MYSQL_TEST_PASSWORD ?? "", multipleStatements: true });
    await connection.query(`CREATE DATABASE ${database}`);
    await connection.query(`USE ${database}`);
    for (const prefix of ["LEGACY_DB", "IDENTITY_DB"]) {
      vi.stubEnv(`${prefix}_HOST`, "127.0.0.1"); vi.stubEnv(`${prefix}_PORT`, port!);
      vi.stubEnv(`${prefix}_NAME`, database); vi.stubEnv(`${prefix}_USER`, "root");
      vi.stubEnv(`${prefix}_PASSWORD`, process.env.DEVICE_SN_MYSQL_TEST_PASSWORD ?? "");
    }
    vi.stubEnv("IDENTITY_TOKEN_ISSUANCE_ENABLED", "true");
    vi.stubEnv("IDENTITY_JWT_PRIVATE_KEY_PEM", generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({ type: "pkcs8", format: "pem" }).toString());
    await connection.query(`CREATE TABLE user (id INT PRIMARY KEY, username VARCHAR(100), email VARCHAR(100), status INT,
      nickname VARCHAR(100), email_verified_at INT, created_at INT, updated_at INT);
      CREATE TABLE user_info (user_id INT, info JSON);
      CREATE TABLE auth_item (name VARCHAR(100) PRIMARY KEY, type INT);
      CREATE TABLE auth_assignment (user_id VARCHAR(30), item_name VARCHAR(100));
      CREATE TABLE device_sn (id INT PRIMARY KEY, user_id INT, device_uuid VARCHAR(255) NULL UNIQUE, enabled BOOL, activated_at DATETIME);
      INSERT INTO user (id,username,status) VALUES (7,'rokid-user',10);
      INSERT INTO auth_item VALUES ('user',1),('admin',1);
      INSERT INTO auth_assignment VALUES ('7','user');
      INSERT INTO device_sn VALUES (42,7,'rokid-uuid-not-rfc-uuid',1,NOW());`);
    // Model the table deployed before this feature, so the first issue proves an incremental upgrade.
    await connection.query(`CREATE TABLE identity_refresh_sessions (
      id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, refresh_token_hash CHAR(64) UNIQUE,
      session_id VARCHAR(128), legacy_user_id BIGINT, username VARCHAR(255), issued_at DATETIME(3),
      expires_at DATETIME(3), revoked_at DATETIME(3), replaced_by_hash CHAR(64), ip_hash CHAR(64), user_agent_hash CHAR(64))`);
    reader = new LegacyIdentityReader(); sessions = new IdentitySessionRepository(); jwt = new JwtIssuerService();
    tokens = new TokenIssuanceService(reader, sessions, jwt, {} as LoginAuditService);
  }, 30_000);

  afterAll(async () => {
    await reader?.onModuleDestroy(); await sessions?.onModuleDestroy();
    if (connection) { await connection.query(`DROP DATABASE IF EXISTS ${database}`); await connection.end(); }
    vi.unstubAllEnvs();
  });
  beforeEach(async () => {
    await connection.query("UPDATE device_sn SET enabled=1,activated_at=NOW(),user_id=7,device_uuid='rokid-uuid-not-rfc-uuid'; UPDATE user SET status=10; DELETE FROM auth_assignment WHERE item_name <> 'user'");
  });
  const issue = () => tokens.issueLegacyUserToken({ legacyUserId: 7, auth_method: "device_sn", device_sn_id: 42 });

  it("issues and refreshes without a legacy device table and upgrades existing session storage", async () => {
    const [legacyDeviceTables] = await connection.query("SHOW TABLES LIKE 'device'");
    expect(legacyDeviceTables).toEqual([]);
    expect(await sessions.deviceSnReadiness()).toBe(false);
    expect(await reader.deviceSnReadiness()).toBe(true);
    const initial = await issue();
    expect(await sessions.deviceSnReadiness()).toBe(true);
    const refreshed = await tokens.refresh({ refreshToken: initial.token.refreshToken });
    expect(jwt.verifyAccessToken(refreshed.token.accessToken)).toMatchObject({ uid: 7, authMethod: "device_sn", deviceSnId: 42 });
    expect(await sessions.findValidSession(refreshed.token.refreshToken)).toMatchObject({ authMethod: "device_sn", deviceSnId: 42 });
    const migration = readFileSync(new URL("../../../deploy/mysql/migrations/20260926_device_sn_sessions.sql", import.meta.url), "utf8");
    await connection.query(migration); await connection.query(migration);
    expect(await sessions.deviceSnReadiness()).toBe(true);
  });

  it("permits one concurrent refresh and rejects replay of the consumed refresh", async () => {
    const initial = await issue();
    const results = await Promise.allSettled([1, 2].map(() => tokens.refresh({ refreshToken: initial.token.refreshToken })));
    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(results.filter((result) => result.status === "rejected")).toHaveLength(1);
    await expect(tokens.refresh({ refreshToken: initial.token.refreshToken })).rejects.toThrow();
  });

  it("denies disabled SN issue/refresh while preserving the existing access grace period", async () => {
    const initial = await issue();
    await connection.query("UPDATE device_sn SET enabled=0 WHERE id=42");
    await expect(issue()).rejects.toMatchObject({ status: 401 });
    await expect(tokens.refresh({ refreshToken: initial.token.refreshToken })).rejects.toMatchObject({ status: 401 });
    await expect(reader.assertDeviceSnAuthorized(42, 7, false)).resolves.toBeUndefined();
  });

  it("rejects inactive accounts, privilege elevation and unactivated SN", async () => {
    const initial = await issue();
    for (const [mutation, restore] of [
      ["UPDATE user SET status=0", "UPDATE user SET status=10"],
      ["INSERT INTO auth_assignment VALUES ('7','admin')", "DELETE FROM auth_assignment WHERE item_name='admin'"],
      ["UPDATE device_sn SET activated_at=NULL", "UPDATE device_sn SET activated_at=NOW()"]
    ]) {
      await connection.query(mutation);
      await expect(reader.assertDeviceSnAuthorized(42, 7, false)).rejects.toMatchObject({ status: 401 });
      await expect(tokens.refresh({ refreshToken: initial.token.refreshToken })).rejects.toMatchObject({ status: 401 });
      await connection.query(restore);
    }
  });

  it.each([null, "", "   ", "UPPERCASE", "uuid/path", "_leading", "设备-uuid", "uuid\n"])("rejects an invalid stored UUID (%s) without issuing or refreshing", async (uuid) => {
    const initial = await issue();
    await connection.execute("UPDATE device_sn SET device_uuid=? WHERE id=42", [uuid]);
    await expect(issue()).rejects.toMatchObject({ status: 401 });
    await expect(tokens.refresh({ refreshToken: initial.token.refreshToken })).rejects.toMatchObject({ status: 401 });
    await expect(reader.assertDeviceSnAuthorized(42, 7, false)).rejects.toMatchObject({ status: 401 });
  });

  it("preserves historical ordinary rows and fails closed on partial stored provenance", async () => {
    const ordinary = await sessions.issue({ legacyUserId: 7, username: "rokid-user", sessionId: "ordinary", expiresAt: new Date(Date.now() + 60000) });
    const refreshed = await tokens.refresh({ refreshToken: ordinary.refreshToken });
    expect(jwt.verifyAccessToken(refreshed.token.accessToken)).not.toHaveProperty("authMethod");
    const initial = await issue();
    await connection.query("UPDATE identity_refresh_sessions SET device_sn_id=NULL WHERE auth_method='device_sn'");
    await expect(tokens.refresh({ refreshToken: initial.token.refreshToken })).rejects.toMatchObject({ status: 401 });
  });
});
