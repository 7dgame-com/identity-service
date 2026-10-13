import "reflect-metadata";
import { createHash, generateKeyPairSync, randomBytes, randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import type { INestApplication } from "@nestjs/common";
import { Test } from "@nestjs/testing";
import mysql, { type Connection, type RowDataPacket } from "mysql2/promise";
import request from "supertest";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { LegacyIdentityReader } from "../src/legacy-identity.reader.js";
import { IdentitySessionRepository } from "../src/identity-session.repository.js";
import { JwtIssuerService } from "../src/jwt-issuer.service.js";
import { NativeIdentityService } from "../src/native-identity.service.js";
import { OidcAuthorizationCodeRepository } from "../src/oidc-authorization-code.repository.js";
import { OidcController } from "../src/oidc.controller.js";
import { OidcService } from "../src/oidc.service.js";
import { TokenIssuanceService } from "../src/token-issuance.service.js";
import { initializeFreshAllocator } from "../src/identity-allocator-state.js";
import type { LoginAuditService } from "../src/login-audit.service.js";

const options = { host: process.env.IDENTITY_DB_HOST ?? "127.0.0.1", port: Number(process.env.IDENTITY_DB_PORT ?? 3306),
  user: process.env.IDENTITY_DB_USER ?? "root", password: process.env.IDENTITY_DB_PASSWORD ?? "", timezone: "Z", multipleStatements: true };
const database = `test_oidc_native_session_${randomUUID().replaceAll("-", "")}`;
const clientId = "native-session-client";
const redirectUri = "https://client.example.test/callback";
const clients = [{ clientId, redirectUris: [redirectUri], scopes: ["openid", "profile", "roles", "offline_access"], requirePkce: true },
  { clientId: "another-client", redirectUris: [redirectUri], scopes: ["openid", "profile", "roles", "offline_access"], requirePkce: true },
  { clientId: "generic-api", redirectUris: [redirectUri], scopes: ["openid", "profile", "offline_access"], requirePkce: true }];

describe.skipIf(process.env.IDENTITY_TEST_MYSQL !== "1")("native OIDC sessions without offline access", () => {
  let admin: Connection;
  let db: Connection;
  let app: INestApplication;
  let reader: LegacyIdentityReader;
  let sessions: IdentitySessionRepository;
  let codes: OidcAuthorizationCodeRepository;
  let jwt: JwtIssuerService;
  let native: NativeIdentityService;
  let initialToken: string;
  let initialRefresh: string;
  let tokens: TokenIssuanceService;

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
      IDENTITY_DB_NAME: database, IDENTITY_DB_USER: options.user, IDENTITY_DB_PASSWORD: options.password,
      IDENTITY_TOKEN_ISSUANCE_ENABLED: "true", IDENTITY_REFRESH_REPLAY_KEY: randomBytes(32).toString("base64url"),
      IDENTITY_INTERNAL_API_TOKEN: randomBytes(32).toString("hex"),
      IDENTITY_JWT_PRIVATE_KEY_PEM: privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
      IDENTITY_JWT_AUDIENCE: "generic-api",
      IDENTITY_OIDC_ENABLED: "true", IDENTITY_OIDC_AUTHORIZATION_ENDPOINT_ENABLED: "true", IDENTITY_OIDC_TOKEN_ENDPOINT_ENABLED: "true",
      IDENTITY_OIDC_ISSUER_MODE: "fixed", IDENTITY_OIDC_ISSUER: "https://identity.example.test",
      IDENTITY_OIDC_CLIENTS_JSON: JSON.stringify(clients),
      LEGACY_DB_HOST: "127.0.0.1", LEGACY_DB_PORT: "1", LEGACY_DB_USER: "unreachable", LEGACY_DB_NAME: "unreachable" };
    for (const [key, value] of Object.entries(environment)) vi.stubEnv(key, value);
    reader = new LegacyIdentityReader(); sessions = new IdentitySessionRepository(); codes = new OidcAuthorizationCodeRepository();
    jwt = new JwtIssuerService(); native = new NativeIdentityService(reader, jwt, sessions);
    tokens = new TokenIssuanceService(reader, sessions, jwt, {} as LoginAuditService);
    const oidc = new OidcService(codes, reader, sessions, jwt, tokens, native);
    const module = await Test.createTestingModule({ controllers: [OidcController], providers: [
      { provide: OidcService, useValue: oidc }, { provide: JwtIssuerService, useValue: jwt },
      { provide: NativeIdentityService, useValue: native }
    ] }).compile();
    app = module.createNestApplication();
    await app.init();
    await db.execute("INSERT INTO user(id,username,status) VALUES (7,'native-oidc-user',10)");
    await db.execute("INSERT INTO auth_assignment(item_name,user_id) VALUES ('user','7')");
  }, 30_000);

  beforeEach(async () => {
    vi.stubEnv("IDENTITY_DATA_SOURCE", "identity");
    vi.stubEnv("IDENTITY_OIDC_CLIENTS_JSON", JSON.stringify(clients));
    const initial = await sessions.issue({ legacyUserId: 7, username: "native-oidc-user", sessionId: randomUUID(), expiresAt: new Date(Date.now() + 60_000) });
    initialToken = jwt.issue((await reader.getUserById(7))!, initial.sessionId).accessToken;
    initialRefresh = initial.refreshToken;
  });

  afterAll(async () => {
    await app?.close();
    await Promise.all([reader, sessions, codes].filter(Boolean).map((resource) => resource.onModuleDestroy()));
    await db?.end();
    if (admin) { await admin.query(`DROP DATABASE IF EXISTS ${database}`); await admin.end(); }
    vi.unstubAllEnvs();
  });

  it("exchanges a code for immediately usable, revocable native access without disclosing a refresh token, preserving legacy behavior", async () => {
    const verifier = randomBytes(48).toString("base64url");
    const authorizeQuery = { response_type: "code", response_mode: "json", client_id: clientId, redirect_uri: redirectUri,
      scope: "openid profile", code_challenge: createHash("sha256").update(verifier).digest("base64url"), code_challenge_method: "S256" };
    const authorization = await request(app.getHttpServer()).get("/authorize").set("Authorization", `Bearer ${initialToken}`).query(authorizeQuery).expect(200);
    const exchange = { grant_type: "authorization_code", client_id: clientId, redirect_uri: redirectUri, code_verifier: verifier };
    const response = await request(app.getHttpServer()).post("/token").send({ ...exchange, code: authorization.body.code }).expect(200);
    expect(response.body).toMatchObject({ token_type: "Bearer", scope: "openid profile" });
    expect(response.body).not.toHaveProperty("refresh_token");
    const claims = jwt.verifyAccessToken(response.body.access_token, { audience: clientId });
    expect(claims.sessionId).not.toBe(jwt.verifyAccessToken(initialToken).sessionId);
    const [stored] = await db.execute<RowDataPacket[]>("SELECT legacy_user_id, revoked_at FROM identity_refresh_sessions WHERE session_id=?", [claims.sessionId]);
    expect(stored).toHaveLength(1);
    expect(stored[0]).toMatchObject({ legacy_user_id: 7, revoked_at: null });
    expect(await native.verify(response.body.access_token, { audience: clientId })).toMatchObject({ id: 7, username: "native-oidc-user" });
    await expect(native.verify(response.body.access_token)).rejects.toMatchObject({ status: 401 });
    await request(app.getHttpServer()).get("/userinfo").set("Authorization", `Bearer ${response.body.access_token}`).expect(200)
      .expect(({ body }) => {
        expect(body).toMatchObject({ sub: "7", uid: 7, preferred_username: "native-oidc-user" });
        expect(body).not.toHaveProperty("roles");
      });

    // Legacy mode keeps its original untracked access-only exchange; it must not start issuing refresh credentials.
    vi.stubEnv("IDENTITY_DATA_SOURCE", "legacy");
    const legacy = new OidcService(codes, reader, sessions, jwt, {} as TokenIssuanceService);
    const authorized = await legacy.authorize(authorizeQuery, `Bearer ${initialToken}`);
    expect(authorized.responseMode).toBe("json");
    if (authorized.responseMode !== "json") throw new Error("Expected JSON authorization response");
    const legacyResponse = await legacy.token({ ...exchange, code: authorized.code }, undefined);
    expect(JSON.parse(JSON.stringify(legacyResponse))).not.toHaveProperty("refresh_token");
    const legacyClaims = jwt.verifyAccessToken(legacyResponse.access_token);
    const [legacySessions] = await db.execute<RowDataPacket[]>("SELECT id FROM identity_refresh_sessions WHERE session_id=?", [legacyClaims.sessionId]);
    expect(legacySessions).toHaveLength(0);

    await sessions.revokeUserSessions(7);
    await request(app.getHttpServer()).get("/userinfo").set("Authorization", `Bearer ${response.body.access_token}`).expect(401);
  });

  async function authorization(scope = "openid profile roles offline_access", authorizedClient = clientId) {
    const verifier = randomBytes(48).toString("base64url");
    const response = await request(app.getHttpServer()).get("/authorize").set("Authorization", `Bearer ${initialToken}`).query({
      response_type: "code", response_mode: "json", client_id: authorizedClient, redirect_uri: redirectUri, scope,
      code_challenge: createHash("sha256").update(verifier).digest("base64url"), code_challenge_method: "S256"
    }).expect(200);
    return { grant_type: "authorization_code", client_id: authorizedClient, redirect_uri: redirectUri, code_verifier: verifier, code: response.body.code };
  }

  it("restarts under the allocator guard after real OIDC authorization-code storage has been used", async () => {
    await authorization("openid profile");
    const [rows] = await db.query<RowDataPacket[]>("SELECT COUNT(*) AS n FROM oidc_authorization_codes");
    expect(Number(rows[0].n)).toBeGreaterThan(0);
    await expect(native.onApplicationBootstrap()).resolves.toBeUndefined();
  });

  it("rejects cross-client, ordinary and expanding refreshes before rotation, while preserving the owner's narrowed concurrent replay", async () => {
    const issued = await request(app.getHttpServer()).post("/token").send(await authorization()).expect(200);
    const refresh = { grant_type: "refresh_token", client_id: clientId, refresh_token: issued.body.refresh_token };
    await request(app.getHttpServer()).post("/token").send({ ...refresh, client_id: "another-client" }).expect(401);
    await request(app.getHttpServer()).post("/token").send({ ...refresh, scope: "openid permissions" }).expect(400);
    await request(app.getHttpServer()).post("/token").send({ ...refresh, refresh_token: initialRefresh }).expect(401);
    await expect(tokens.refresh({ refreshToken: issued.body.refresh_token })).rejects.toMatchObject({ status: 401 });
    await expect(sessions.findValidSession(issued.body.refresh_token)).resolves.toBeDefined();
    await expect(sessions.findValidSession(initialRefresh)).resolves.toBeDefined();
    const owner = await request(app.getHttpServer()).post("/token").send({ ...refresh, scope: "openid" }).expect(200);
    expect(owner.body.scope).toBe("openid");
    const ownerClaims = jwt.verifyAccessToken(owner.body.access_token, { audience: clientId });
    expect(ownerClaims.sessionId).toBe(jwt.verifyAccessToken(issued.body.access_token, { audience: clientId }).sessionId);
    expect(JSON.parse(Buffer.from(owner.body.access_token.split(".")[1], "base64url").toString()).scope).toBe("openid");
    await request(app.getHttpServer()).get("/userinfo").set("Authorization", `Bearer ${owner.body.access_token}`).expect(200)
      .expect(({ body }) => expect(body).toEqual({ sub: "7", uid: 7 }));
    const replay = await Promise.all(Array.from({ length: 2 }, () => request(app.getHttpServer()).post("/token")
      .send({ ...refresh, refresh_token: owner.body.refresh_token, scope: "openid" }).expect(200)));
    expect(replay[0].body.refresh_token).toBe(replay[1].body.refresh_token);
    for (const response of replay) expect(jwt.verifyAccessToken(response.body.access_token, { audience: clientId }).sessionId).toBe(ownerClaims.sessionId);
  });

  it("rechecks current client scopes after authorization and before issuing a session", async () => {
    const code = await authorization("openid roles");
    vi.stubEnv("IDENTITY_OIDC_CLIENTS_JSON", JSON.stringify([{ ...clients[0], scopes: ["openid", "profile"] }]));
    const restricted = new OidcService(codes, reader, sessions, jwt, tokens, native);
    const [before] = await db.query<RowDataPacket[]>("SELECT COUNT(*) AS count FROM identity_refresh_sessions");
    await expect(restricted.token(code, undefined)).rejects.toMatchObject({ status: 400, response: { code: "INVALID_SCOPE" } });
    const [after] = await db.query<RowDataPacket[]>("SELECT COUNT(*) AS count FROM identity_refresh_sessions");
    expect(after[0].count).toBe(before[0].count);
  });

  it("uses the persisted OIDC client and grant for userinfo rather than a signed token's chosen audience or expanded scopes", async () => {
    const response = await request(app.getHttpServer()).post("/token").send(await authorization("openid profile offline_access")).expect(200);
    const sessionId = jwt.verifyAccessToken(response.body.access_token, { audience: clientId }).sessionId!;
    const user = (await reader.getUserById(7))!;
    for (const options of [{ audience: "another-client", scopes: ["openid", "profile"] }, { audience: clientId, scopes: ["openid", "profile", "roles"] }]) {
      const token = jwt.issue(user, sessionId, options);
      await request(app.getHttpServer()).get("/userinfo").set("Authorization", `Bearer ${token.accessToken}`).expect(401);
    }
    // Same client ID in the other OAuth protocol must not match this binding table.
    const ordinary = await sessions.issue({ legacyUserId: 7, username: user.username, sessionId: randomUUID(), expiresAt: new Date(Date.now() + 60_000) });
    await db.execute("INSERT INTO identity_oauth_session_bindings(session_id,client_id,scopes_json) VALUES (?,?,?)", [ordinary.sessionId, clientId, JSON.stringify(["openid"])]);
    await request(app.getHttpServer()).post("/token").send({ grant_type: "refresh_token", client_id: clientId, refresh_token: ordinary.refreshToken }).expect(401);
    const otherProtocolToken = jwt.issue(user, ordinary.sessionId, { audience: clientId, scopes: ["openid"] });
    await request(app.getHttpServer()).get("/userinfo").set("Authorization", `Bearer ${otherProtocolToken.accessToken}`).expect(401);
    await expect(sessions.findValidSession(ordinary.refreshToken)).resolves.toBeDefined();
  });

  it("keeps binding creation atomic and rejects a client's revoked offline permission before consuming the owner's refresh", async () => {
    const response = await request(app.getHttpServer()).post("/token").send(await authorization()).expect(200);
    const sessionId = jwt.verifyAccessToken(response.body.access_token, { audience: clientId }).sessionId!;
    const [before] = await db.query<RowDataPacket[]>("SELECT COUNT(*) AS count FROM identity_refresh_sessions WHERE session_id=?", [sessionId]);
    await expect(sessions.issueOidcSession({ legacyUserId: 7, username: "native-oidc-user", sessionId, expiresAt: new Date(Date.now() + 60_000) },
      { clientId, scopes: ["openid"] })).rejects.toMatchObject({ code: "ER_DUP_ENTRY" });
    const [after] = await db.query<RowDataPacket[]>("SELECT COUNT(*) AS count FROM identity_refresh_sessions WHERE session_id=?", [sessionId]);
    expect(after[0].count).toBe(before[0].count);
    expect(await sessions.getOidcBinding(sessionId)).toEqual({ clientId, scopes: ["openid", "profile", "roles", "offline_access"] });
    vi.stubEnv("IDENTITY_OIDC_CLIENTS_JSON", JSON.stringify([{ ...clients[0], scopes: ["openid", "profile", "roles"] }]));
    const restricted = new OidcService(codes, reader, sessions, jwt, tokens, native);
    await expect(restricted.token({ grant_type: "refresh_token", client_id: clientId, refresh_token: response.body.refresh_token, scope: "openid" }, undefined))
      .rejects.toMatchObject({ status: 401 });
    await expect(sessions.findValidSession(response.body.refresh_token)).resolves.toBeDefined();
    await request(app.getHttpServer()).post("/token").send({ grant_type: "refresh_token", client_id: clientId, refresh_token: response.body.refresh_token }).expect(200);
  });

  it("keeps both OAuth protocols out of generic reads and writes even when the client ID equals the generic audience", async () => {
    const collisionClient = "generic-api";
    const response = await request(app.getHttpServer()).post("/token").send(await authorization("openid profile offline_access", collisionClient)).expect(200);
    // Cryptographic audience matching alone accepts this token; the persisted protocol binding is essential.
    expect(jwt.verifyAccessToken(response.body.access_token)).toMatchObject({ uid: 7 });
    await expect(native.verify(response.body.access_token)).rejects.toMatchObject({ status: 401 });
    expect(await native.verify(response.body.access_token, { audience: collisionClient })).toMatchObject({ id: 7 });
    await request(app.getHttpServer()).get("/userinfo").set("Authorization", `Bearer ${response.body.access_token}`).expect(200)
      .expect(({ body }) => expect(body).toMatchObject({ sub: "7", preferred_username: "native-oidc-user" }));
    const user = (await reader.getUserById(7))!;
    const wechat = await sessions.issue({ legacyUserId: 7, username: user.username, sessionId: randomUUID(), expiresAt: new Date(Date.now() + 60_000) });
    await db.execute("INSERT INTO identity_oauth_session_bindings(session_id,client_id,scopes_json) VALUES (?,?,?)", [wechat.sessionId, collisionClient, JSON.stringify(["openid"])]);
    const wechatToken = jwt.issue(user, wechat.sessionId, { audience: collisionClient, scopes: ["openid"] }).accessToken;
    await expect(native.verify(wechatToken)).rejects.toMatchObject({ status: 401 });
    expect(await native.verify(wechatToken, { audience: collisionClient })).toMatchObject({ id: 7 });
    await request(app.getHttpServer()).get("/userinfo").set("Authorization", `Bearer ${wechatToken}`).expect(401);
    const connection = await mysql.createConnection({ ...options, database });
    try {
      await connection.beginTransaction();
      for (const token of [response.body.access_token, wechatToken]) {
        await expect(native.assertAccessInTransaction(token, 7, connection as never)).rejects.toMatchObject({ status: 401 });
      }
    } finally { await connection.rollback(); await connection.end(); }
  });
});
