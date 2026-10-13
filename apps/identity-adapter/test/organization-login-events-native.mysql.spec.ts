import "reflect-metadata";
import { generateKeyPairSync, randomBytes, randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import bcrypt from "bcryptjs";
import mysql, { type Connection } from "mysql2/promise";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { LegacyIdentityReader } from "../src/legacy-identity.reader.js";
import { IdentitySessionRepository } from "../src/identity-session.repository.js";
import { JwtIssuerService } from "../src/jwt-issuer.service.js";
import { TokenIssuanceService } from "../src/token-issuance.service.js";
import { NativeIdentityService } from "../src/native-identity.service.js";
import { IamRepository } from "../src/iam.repository.js";
import { LoginAuditRepository } from "../src/login-audit.repository.js";
import { LoginAuditService } from "../src/login-audit.service.js";
import { PluginUserPrimaryReadService } from "../src/plugin-user-primary-read.service.js";
import { PluginUserReadonlyController } from "../src/plugin-user-readonly.controller.js";
import { initializeFreshAllocator } from "../src/identity-allocator-state.js";

const options = { host: process.env.IDENTITY_DB_HOST ?? "127.0.0.1", port: Number(process.env.IDENTITY_DB_PORT ?? 3306),
  user: process.env.IDENTITY_DB_USER ?? "root", password: process.env.IDENTITY_DB_PASSWORD ?? "", timezone: "Z", multipleStatements: true };
const database = `test_native_login_audit_${randomUUID().replaceAll("-", "")}`;
const query = { organization_id: "7", start_at: "2026-09-25T00:00:00+08:00", end_at: "2026-09-27T00:00:00+08:00" };

describe.skipIf(process.env.IDENTITY_TEST_MYSQL !== "1")("private organization audits with obsolete account sources unreachable", () => {
  let admin: Connection;
  let db: Connection;
  let reader: LegacyIdentityReader;
  let sessions: IdentitySessionRepository;
  let native: NativeIdentityService;
  let iam: IamRepository;
  let repository: LoginAuditRepository;
  let audit: LoginAuditService;
  let controller: PluginUserReadonlyController;
  let rootToken: string;
  let adminToken: string;
  let managerToken: string;
  let userToken: string;
  const resources: Array<{ onModuleDestroy(): Promise<void> }> = [];

  beforeAll(async () => {
    admin = await mysql.createConnection(options);
    await admin.query(`CREATE DATABASE ${database} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`);
    db = await mysql.createConnection({ ...options, database });
    const base = await readFile(new URL("../../../deploy/mysql/init.sql", import.meta.url), "utf8");
    await db.query(base.slice(base.indexOf("CREATE TABLE IF NOT EXISTS `auth_login_events`")));
    for (const filename of ["identity-account-schema.sql", "identity-runtime-schema.sql", "identity-password-reset-token-schema.sql", "identity-legacy-challenge-schema.sql", "identity-wechat-oauth-schema.sql", "identity-qrcode-schema.sql", "identity-apple-schema.sql", "identity-allocator-schema.sql"]) {
      await db.query(await readFile(new URL(`../../../deploy/mysql/${filename}`, import.meta.url), "utf8"));
    }
    await initializeFreshAllocator(db);
    const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const environment = { IDENTITY_DATA_SOURCE: "identity", IDENTITY_DB_HOST: options.host, IDENTITY_DB_PORT: String(options.port),
      IDENTITY_DB_USER: options.user, IDENTITY_DB_PASSWORD: options.password, IDENTITY_DB_NAME: database,
      IDENTITY_LOGIN_AUDIT_ENABLED: "true", IDENTITY_TOKEN_ISSUANCE_ENABLED: "true", IDENTITY_PLUGIN_USER_READONLY_ENABLED: "false",
      IDENTITY_LOGIN_AUDIT_BILLING_TIMEZONE: "Asia/Shanghai", IDENTITY_LOGIN_AUDIT_UNIT_PRICE_CENTS: "12500",
      IDENTITY_REFRESH_REPLAY_KEY: randomBytes(32).toString("base64url"), IDENTITY_INTERNAL_API_TOKEN: randomBytes(32).toString("hex"),
      IDENTITY_JWT_PRIVATE_KEY_PEM: privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
      LEGACY_DB_HOST: "127.0.0.1", LEGACY_DB_PORT: "1", LEGACY_DB_USER: "unreachable", LEGACY_DB_NAME: "unreachable",
      LEGACY_WRITE_DB_HOST: "127.0.0.1", LEGACY_WRITE_DB_PORT: "1", LEGACY_WRITE_DB_USER: "unreachable",
      IDENTITY_IAM_ROLE_WRITE_MODE: "identity-native", IDENTITY_IAM_ROLE_WRITE_IDENTITY_NATIVE_EXECUTION_ENABLED: "true",
      IDENTITY_IAM_ROLE_WRITE_POLICY_CHECKSUM: "a".repeat(64) };
    for (const [key, value] of Object.entries(environment)) vi.stubEnv(key, value);
    reader = new LegacyIdentityReader(); sessions = new IdentitySessionRepository(); iam = new IamRepository(); repository = new LoginAuditRepository();
    const jwt = new JwtIssuerService();
    audit = new LoginAuditService(repository);
    const tokens = new TokenIssuanceService(reader, sessions, jwt, audit);
    native = new NativeIdentityService(reader, jwt, sessions);
    resources.push(native, reader, sessions, iam, repository);
    await native.onApplicationBootstrap();
    await db.query("DROP TABLE IF EXISTS identity_organization_memberships_shadow");
    const hash = bcrypt.hashSync("Private-audit!123", 4);
    for (const [id, role] of [[1, "root"], [2, "admin"], [3, "user"], [4, "manager"], [5, "user"]] as const) {
      await db.execute("INSERT INTO user(id,username,nickname,status,password_hash,created_at,updated_at) VALUES (?,?,?,10,?,1,1)", [id, `audit-${id}`, `成员${id}`, hash]);
      await db.execute("INSERT INTO auth_assignment(item_name,user_id) VALUES (?,?)", [role, String(id)]);
    }
    await db.query("INSERT INTO organization(id,name,title) VALUES (7,'school','学校'),(8,'outside','其他组织')");
    await db.query("INSERT INTO user_organization(user_id,organization_id) VALUES (1,8),(2,7),(3,7),(4,7),(5,8)");
    rootToken = (await tokens.login({ username: "audit-1", password: "Private-audit!123" })).token.accessToken;
    adminToken = (await tokens.login({ username: "audit-2", password: "Private-audit!123" })).token.accessToken;
    managerToken = (await tokens.login({ username: "audit-4", password: "Private-audit!123" })).token.accessToken;
    userToken = (await tokens.login({ username: "audit-3", password: "Private-audit!123" })).token.accessToken;
    controller = new PluginUserReadonlyController(reader, jwt, new PluginUserPrimaryReadService(iam, reader), audit, iam, native);
  }, 30_000);
  beforeEach(async () => {
    await db.query("DELETE FROM auth_login_events; DELETE FROM user_login_stats");
    await db.query("DELETE FROM auth_assignment WHERE user_id IN ('3','4'); INSERT INTO auth_assignment(item_name,user_id) VALUES ('user','3'),('manager','4')");
    await db.query("DELETE FROM user_organization WHERE user_id IN (3,4); INSERT INTO user_organization(user_id,organization_id) VALUES (3,7),(4,7)");
  });
  afterAll(async () => {
    await Promise.all(resources.map((resource) => resource.onModuleDestroy()));
    await db?.end();
    if (admin) { await admin.query(`DROP DATABASE IF EXISTS ${database}`); await admin.end(); }
    vi.unstubAllEnvs();
  });
  const list = (filters: Record<string, unknown> = query, token = adminToken) => controller.organizationLoginEvents(`Bearer ${token}`, filters);
  const record = (eventKey: string, legacyUserId = 3, occurredAt = "2026-09-25T01:00:00Z", extra: Record<string, unknown> = {}) => audit.record({ eventKey, legacyUserId, occurredAt, ...extra });

  it("reads private members without a shadow table and enforces current roles and organization scope", async () => {
    await record("private-member-login"); await record("outside-member-login", 5);
    expect(await list()).toMatchObject({ data: [{ userId: 3, nickname: "成员3", primaryRole: "user" }], pagination: { total: 1 } });
    expect(await list(query, rootToken)).toMatchObject({ pagination: { total: 1 } });
    await expect(list(query, userToken)).rejects.toMatchObject({ status: 403 });
    await expect(list({ ...query, organization_id: "8" }, managerToken)).rejects.toMatchObject({ status: 403 });
    await db.query("UPDATE auth_assignment SET item_name='user' WHERE user_id='4'");
    await expect(list(query, managerToken)).rejects.toMatchObject({ status: 403 });
  });

  it("uses current private roles and membership removals when filtering historical events", async () => {
    await record("student-history");
    await db.query("UPDATE auth_assignment SET item_name='manager' WHERE user_id='3'");
    expect(await list({ ...query, role: "manager", search: "成员3" })).toMatchObject({ data: [{ userId: 3, primaryRole: "manager" }], pagination: { total: 1 } });
    await db.query("DELETE FROM user_organization WHERE user_id=3");
    expect(await list()).toMatchObject({ data: [], pagination: { total: 0 } });
  });

  it("binds date ranges in UTC, includes start and excludes end with stable tied pages", async () => {
    await record("date-start-boundary", 3, query.start_at);
    await record("date-end-boundary", 3, query.end_at);
    await record("failed-not-counted", 3, undefined, { success: false });
    await record("refresh-not-counted", 3, undefined, { eventType: "refresh" });
    for (let index = 0; index < 25; index++) await record(`tied-login-${index}`);
    await record("tied-login-24");
    const first = await list(); const second = await list({ ...query, page: "2" });
    expect(first.pagination.total).toBe(26); expect(first.data).toHaveLength(20);
    expect(second.data.map((event) => event.eventKey)).toEqual(["tied-login-4", "tied-login-3", "tied-login-2", "tied-login-1", "tied-login-0", "date-start-boundary"]);
    expect(new Set([...first.data, ...second.data].map((event) => event.eventKey)).size).toBe(26);
    expect(second.data.at(-1)?.occurredAt).toBe("2026-09-24T16:00:00.000Z");
  });

  it("shows full normalized IP only to current private root and masks other privileged readers", async () => {
    await record("ip-address-login", 3, undefined, { ipAddress: "::ffff:203.0.113.77" });
    const root = await controller.userLoginAudit(`Bearer ${rootToken}`, "3", {});
    const manager = await controller.userLoginAudit(`Bearer ${managerToken}`, "3", { organization_id: "7" });
    expect(root.data.recentEvents[0]?.ipAddress).toBe("203.0.113.77");
    expect(manager.data.recentEvents[0]?.ipAddress).toBe("203.0.113.*");
    await expect(controller.userLoginAudit(`Bearer ${managerToken}`, "3", {})).rejects.toMatchObject({ status: 403 });
  });

  it("charges successful private member logins once per configured calendar day and checks invoice scope", async () => {
    await record("invoice-first", 3, "2026-09-24T16:30:00Z");
    await record("invoice-same-day", 3, "2026-09-25T15:59:59Z");
    await record("invoice-next-day", 3, "2026-09-25T16:00:00Z");
    await record("invoice-outside", 5); await record("invoice-failed", 3, undefined, { success: false });
    const result = await controller.organizationLoginUsageInvoice(`Bearer ${managerToken}`, "7", { from: query.start_at, to: query.end_at });
    expect(result.data).toMatchObject({ organization: { id: 7 }, billingTimezone: "Asia/Shanghai", unitPriceCents: 12500,
      successfulLoginCount: 3, usageCount: 2, amountCents: 25000, accountCount: 3,
      accounts: [{ legacyUserId: 3, usageDays: ["2026-09-25", "2026-09-26"], amountCents: 25000 }] });
    await expect(controller.organizationLoginUsageInvoice(`Bearer ${managerToken}`, "8", {})).rejects.toMatchObject({ status: 403 });
  });

  it("rejects revoked sessions for organization and invoice reads", async () => {
    await sessions.revokeUserSessions(2);
    await expect(list()).rejects.toMatchObject({ status: 401 });
    await expect(controller.organizationLoginUsageInvoice(`Bearer ${adminToken}`, "7", {})).rejects.toMatchObject({ status: 401 });
  });
});
