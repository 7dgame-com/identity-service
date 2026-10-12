import "reflect-metadata";
import { generateKeyPairSync } from "node:crypto";
import type { INestApplication } from "@nestjs/common";
import { Test } from "@nestjs/testing";
import bcrypt from "bcryptjs";
import mysql, { type Connection } from "mysql2/promise";
import request from "supertest";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { AuthController } from "../src/auth.controller.js";
import { PluginUserReadonlyController } from "../src/plugin-user-readonly.controller.js";
import { LegacyIdentityReader } from "../src/legacy-identity.reader.js";
import { IamRepository } from "../src/iam.repository.js";
import { IdentitySessionRepository } from "../src/identity-session.repository.js";
import { LoginAuditRepository } from "../src/login-audit.repository.js";
import { LoginAuditService } from "../src/login-audit.service.js";
import { JwtIssuerService } from "../src/jwt-issuer.service.js";
import { PluginUserPrimaryReadService } from "../src/plugin-user-primary-read.service.js";
import { TokenIssuanceService } from "../src/token-issuance.service.js";

// Opt-in: point ONLY at a disposable MySQL 8 instance. This suite owns its separate test schema.
const port = process.env.LOGIN_EVENTS_MYSQL_TEST_PORT;
const password = process.env.LOGIN_EVENTS_MYSQL_TEST_PASSWORD ?? "";
describe.skipIf(!port)("organization login events with MySQL and real HTTP login", () => {
  let connection: Connection;
  let app: INestApplication;
  let reader: LegacyIdentityReader;
  let jwt: JwtIssuerService;
  let audit: LoginAuditService;
  let adminToken: string;
  let studentToken: string;
  const resources: Array<{ onModuleDestroy(): Promise<void> }> = [];
  const database = `campus_login_test_${process.pid}`;
  const baseQuery = { organization_id: "7", start_at: "2026-09-25T00:00:00+08:00", end_at: "2026-09-27T00:00:00+08:00" };

  beforeAll(async () => {
    connection = await mysql.createConnection({ host: "127.0.0.1", port: Number(port), user: "root", password });
    await connection.query(`CREATE DATABASE ${database}`);
    await connection.query(`USE ${database}`);
    for (const prefix of ["LEGACY_DB", "IDENTITY_DB"]) {
      vi.stubEnv(`${prefix}_HOST`, "127.0.0.1"); vi.stubEnv(`${prefix}_PORT`, port!);
      vi.stubEnv(`${prefix}_NAME`, database); vi.stubEnv(`${prefix}_USER`, "root"); vi.stubEnv(`${prefix}_PASSWORD`, password);
    }
    vi.stubEnv("IDENTITY_PLUGIN_USER_READONLY_ENABLED", "true");
    vi.stubEnv("IDENTITY_LOGIN_AUDIT_ENABLED", "true");
    vi.stubEnv("IDENTITY_TOKEN_ISSUANCE_ENABLED", "true");
    vi.stubEnv("IDENTITY_JWT_PRIVATE_KEY_PEM", generateKeyPairSync("ec", { namedCurve: "prime256v1" }).privateKey.export({ type: "pkcs8", format: "pem" }).toString());
    vi.stubEnv("IDENTITY_IAM_ROLE_WRITE_MODE", "legacy-proxy");
    await connection.query(`CREATE TABLE user (id BIGINT PRIMARY KEY, username VARCHAR(100), nickname VARCHAR(100),
      email VARCHAR(100), status INT DEFAULT 10, email_verified_at BIGINT, created_at BIGINT, updated_at BIGINT, password_hash VARCHAR(255))`);
    await connection.query("CREATE TABLE user_info (user_id BIGINT, info JSON)");
    await connection.query("CREATE TABLE auth_item (name VARCHAR(100) PRIMARY KEY, type INT)");
    await connection.query("CREATE TABLE auth_assignment (user_id VARCHAR(30), item_name VARCHAR(100))");
    await connection.query("CREATE TABLE organization (id BIGINT PRIMARY KEY, name VARCHAR(100), title VARCHAR(100), created_at BIGINT, updated_at BIGINT)");
    await connection.query("CREATE TABLE user_organization (user_id BIGINT, organization_id BIGINT)");
    await connection.query(`CREATE TABLE identity_organization_memberships_shadow (
      identity_user_id VARCHAR(100), legacy_user_id BIGINT, organization_id BIGINT, organization_role VARCHAR(100),
      source VARCHAR(100), status VARCHAR(30), observed_at DATETIME, metadata JSON)`);
    const passwordHash = bcrypt.hashSync("Test-pass-123!", 4);
    for (const [id, username, nickname] of [[1, "teacher", "老师"], [2, "student", "张同学"], [3, "outside", "组织外"]]) {
      await connection.execute("INSERT INTO user (id, username, nickname, password_hash) VALUES (?, ?, ?, ?)", [id, username, nickname, passwordHash]);
    }
    await connection.query("INSERT INTO auth_item VALUES ('admin', 1), ('user', 1)");
    await connection.query("INSERT INTO auth_assignment VALUES ('1','admin'),('2','user'),('3','user')");
    await connection.query("INSERT INTO organization (id,name,title) VALUES (7,'school','学校'),(8,'outside','另一组织')");
    await connection.query("INSERT INTO user_organization VALUES (1,7),(2,7),(3,8)");
    await connection.query(`INSERT INTO identity_organization_memberships_shadow (identity_user_id,legacy_user_id,organization_id,status)
      VALUES ('legacy:1',1,7,'shadow'),('legacy:2',2,7,'shadow'),('legacy:3',3,8,'shadow')`);

    reader = new LegacyIdentityReader();
    const iam = new IamRepository();
    const repository = new LoginAuditRepository();
    const sessions = new IdentitySessionRepository();
    resources.push(reader, iam, repository, sessions);
    jwt = new JwtIssuerService();
    expect((await reader.listOrganizationAuditMembers(7)).map((member) => member.id).sort()).toEqual([1, 2]);
    expect(await iam.listOrganizationMembershipsShadow(1)).toEqual([expect.objectContaining({ legacyUserId: 1, organizationId: 7 })]);
    expect(await iam.listOrganizationMembershipsShadowForUsers([1, 2])).toHaveLength(2);
    audit = new LoginAuditService(repository);
    const primary = new PluginUserPrimaryReadService(iam, reader);
    const tokens = new TokenIssuanceService(reader, sessions, jwt, audit);
    const module = await Test.createTestingModule({
      controllers: [AuthController, PluginUserReadonlyController],
      providers: [
        { provide: LegacyIdentityReader, useValue: reader }, { provide: IamRepository, useValue: iam },
        { provide: LoginAuditRepository, useValue: repository }, { provide: LoginAuditService, useValue: audit },
        { provide: JwtIssuerService, useValue: jwt }, { provide: IdentitySessionRepository, useValue: sessions },
        { provide: PluginUserPrimaryReadService, useValue: primary }, { provide: TokenIssuanceService, useValue: tokens },
      ],
    }).compile();
    app = module.createNestApplication();
    await app.init();
    adminToken = jwt.issue((await reader.getUserById(1))!, "test-admin").accessToken;
    studentToken = jwt.issue((await reader.getUserById(2))!, "test-student").accessToken;
    await repository.getUserAudit(2); // Initialize the existing audit schema.
  }, 30_000);

  afterAll(async () => {
    if (app) await app.close();
    else await Promise.all(resources.map((resource) => resource.onModuleDestroy()));
    if (connection) { await connection.query(`DROP DATABASE IF EXISTS ${database}`); await connection.end(); }
    vi.unstubAllEnvs();
  });
  beforeEach(async () => {
    await connection.query("DELETE FROM auth_login_events");
    await connection.query("DELETE FROM user_login_stats");
    await connection.query("UPDATE identity_organization_memberships_shadow SET status = 'shadow'");
    await connection.query("DELETE FROM user_organization WHERE user_id = 2");
    await connection.query("INSERT INTO user_organization VALUES (2,7)");
  });
  const list = (query = baseQuery, token = adminToken) => request(app.getHttpServer())
    .get("/v1/plugin-user/login-events").query(query).set("Authorization", `Bearer ${token}`);
  async function record(key: string, userId = 2, success = true, occurredAt = "2026-09-25T01:00:00Z", eventType = "login") {
    await audit.record({ eventKey: key, legacyUserId: userId, username: `user${userId}`, success, occurredAt, eventType });
  }

  it("queries a real successful login, while rejecting bad credentials and student readers", async () => {
    await request(app.getHttpServer()).post("/v1/auth/login").send({ username: "student", password: "wrong" }).expect(401);
    await request(app.getHttpServer()).post("/v1/auth/login").send({ username: "student", password: "Test-pass-123!" }).expect(201);
    const now = new Date();
    const query = { ...baseQuery, start_at: new Date(now.getTime() - 60_000).toISOString(), end_at: new Date(now.getTime() + 60_000).toISOString() };
    const response = await list(query).expect(200);
    expect(response.body.pagination.total).toBe(1);
    expect(response.body.data[0]).toMatchObject({ userId: 2, username: "student", nickname: "张同学", primaryRole: "user", source: "identity-adapter" });
    expect(Object.keys(response.body.data[0]).sort()).toEqual(["eventKey", "nickname", "occurredAt", "primaryRole", "source", "userId", "username"].sort());
    await list(query, studentToken).expect(403);
  });

  it("filters actual SQL by membership, success, event type and inclusive/exclusive dates", async () => {
    await record("boundary-start", 2, true, baseQuery.start_at);
    await record("boundary-end", 2, true, baseQuery.end_at);
    await record("outside-user", 3);
    await record("failed-login", 2, false);
    await record("token-refresh", 2, true, "2026-09-25T01:00:00Z", "refresh");
    const response = await list().expect(200);
    expect(response.body.pagination.total).toBe(1);
    expect(response.body.data.map((event: any) => event.eventKey)).toEqual(["boundary-start"]);
  });

  it("paginates beyond 20 events with stable ties, and deduplicates event keys", async () => {
    for (let index = 0; index < 25; index++) await record(`page-event-${index}`);
    await record("page-event-24");
    const first = await list().expect(200);
    const second = await list({ ...baseQuery, ...{ page: "2" } }).expect(200);
    expect(first.body.pagination.total).toBe(25);
    expect(first.body.data).toHaveLength(20);
    expect(second.body.data.map((event: any) => event.eventKey)).toEqual(["page-event-4", "page-event-3", "page-event-2", "page-event-1", "page-event-0"]);
    expect(new Set([...first.body.data, ...second.body.data].map((event: any) => event.eventKey)).size).toBe(25);
  });

  it("filters by current account and highest role before counting", async () => {
    await record("student-login"); await record("teacher-login", 1);
    const response = await list({ ...baseQuery, ...{ search: "张同学", role: "user" } }).expect(200);
    expect(response.body.pagination.total).toBe(1);
    expect(response.body.data[0].userId).toBe(2);
    const empty = await list({ ...baseQuery, ...{ role: "other" } }).expect(200);
    expect(empty.body).toMatchObject({ data: [], pagination: { total: 0 } });
  });

  it("removes history from the old organization after a membership removal", async () => {
    await record("removed-login");
    await connection.query("DELETE FROM user_organization WHERE user_id = 2");
    const response = await list().expect(200);
    expect(response.body).toMatchObject({ data: [], pagination: { total: 0 } });
  });

  it("fails closed on shadow mismatch and cross-organization requests", async () => {
    await record("private-login");
    await connection.query("UPDATE identity_organization_memberships_shadow SET status = 'inactive' WHERE legacy_user_id = 2");
    const response = await list().expect(403);
    expect(response.body.pagination).toBeUndefined();
    await list({ ...baseQuery, organization_id: "8" }).expect(403);
  });

  it("rejects array scope and invalid query parameters through the HTTP route", async () => {
    await list({ ...baseQuery, ...{ pageSize: "101" } }).expect(400);
    await request(app.getHttpServer()).get("/v1/plugin-user/login-events")
      .query({ ...baseQuery, organization_id: ["7", "8"] }).set("Authorization", `Bearer ${adminToken}`).expect(400);
  });
});
