import "reflect-metadata";
import { generateKeyPairSync, sign } from "node:crypto";
import { ExecutionContext, INestApplication, UnauthorizedException } from "@nestjs/common";
import { APP_GUARD } from "@nestjs/core";
import { Test } from "@nestjs/testing";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { deviceSnClaims, deviceSnSource } from "../src/device-sn-source.js";
import { DeviceSnAccessGuard } from "../src/device-sn-access.guard.js";
import { IdentitySessionRepository, InvalidRefreshTokenError } from "../src/identity-session.repository.js";
import { JwtIssuerService } from "../src/jwt-issuer.service.js";
import { LegacyIdentityReader, type LegacyUserReadModel } from "../src/legacy-identity.reader.js";
import { LoginAuditService } from "../src/login-audit.service.js";
import { TokenIssuanceService } from "../src/token-issuance.service.js";
import { OidcService } from "../src/oidc.service.js";
import { OidcAuthorizationCodeRepository } from "../src/oidc-authorization-code.repository.js";
import { AuthController } from "../src/auth.controller.js";
import { InternalAuthController } from "../src/internal-auth.controller.js";
import { OidcController } from "../src/oidc.controller.js";
import { AccountLifecycleController } from "../src/account-lifecycle.controller.js";
import { AccountLifecycleService } from "../src/account-lifecycle.service.js";

const source = { authMethod: "device_sn" as const, deviceSnId: 42 };
const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
const user: LegacyUserReadModel = {
  id: 7, username: "rokid-user", email: null, status: 10, nickname: null, emailVerifiedAt: null,
  createdAt: null, updatedAt: null, userInfo: {}, roles: ["user"], organizations: [], source: "legacy"
};

beforeEach(() => {
  vi.stubEnv("IDENTITY_TOKEN_ISSUANCE_ENABLED", "true");
  vi.stubEnv("IDENTITY_ACCESS_TOKEN_TTL_SECONDS", "20000");
  vi.stubEnv("IDENTITY_JWT_PRIVATE_KEY_PEM", privateKey.export({ type: "pkcs8", format: "pem" }).toString());
  vi.stubEnv("IDENTITY_JWT_ISSUER", "device-sn-test");
  vi.stubEnv("IDENTITY_JWT_AUDIENCE", "api");
  vi.stubEnv("LEGACY_DB_HOST", "");
  vi.stubEnv("IDENTITY_DB_HOST", "");
});
afterEach(() => vi.unstubAllEnvs());

describe("device SN token provenance", () => {
  it("accepts historical ordinary sessions and rejects incomplete source fields", () => {
    expect(deviceSnSource(null, null)).toBeNull();
    expect(deviceSnClaims({ uid: 7 })).toBeNull();
    for (const claims of [{ auth_method: "device_sn" }, { device_sn_id: 42 }, { auth_method: null, device_sn_id: null },
      { auth_method: "password", device_sn_id: 42 }, { auth_method: "device_sn", device_sn_id: "42" }]) {
      expect(() => deviceSnClaims(claims)).toThrow();
    }
  });

  it("keeps token shape and applies the 3-hour cap only to device sessions", async () => {
    const fixture = tokenFixture();
    const result = await fixture.tokens.issueLegacyUserToken({ legacyUserId: 7, auth_method: "device_sn", device_sn_id: 42 });
    expect(Object.keys(result.token).sort()).toEqual(["accessToken", "expires", "refreshToken", "token", "tokenType"]);
    const payload = jwtPayload(result.token.accessToken);
    expect(payload).toMatchObject({ uid: 7, auth_method: "device_sn", device_sn_id: 42 });
    expect(Number(payload.exp) - Number(payload.iat)).toBe(10800);
    expect(fixture.sessions.issue).toHaveBeenCalledWith(expect.objectContaining(source));
    expect(fixture.reader.assertDeviceSnAuthorized).toHaveBeenCalledWith(42, 7);
    const ordinary = fixture.jwt.issue(user, "ordinary");
    expect(jwtPayload(ordinary.accessToken)).not.toHaveProperty("auth_method");
    expect(Number(jwtPayload(ordinary.accessToken).exp) - Number(jwtPayload(ordinary.accessToken).iat)).toBe(20000);
  });

  it("refreshes from stored source, ignoring a caller attempting to change it", async () => {
    const fixture = tokenFixture();
    const response = await fixture.tokens.refresh({ refreshToken: "old", auth_method: "password", device_sn_id: 999 });
    expect(fixture.sessions.rotate).toHaveBeenCalledWith("old", expect.objectContaining(source));
    expect(fixture.jwt.verifyAccessToken(response.token.accessToken)).toMatchObject(source);
    expect(fixture.reader.assertDeviceSnAuthorized).toHaveBeenCalledTimes(2);
  });

  it("refuses disabled or unavailable authorizations without rotation", async () => {
    for (const error of [new UnauthorizedException({ code: "DEVICE_SN_UNAVAILABLE" }), new Error("authoritative DB unavailable")]) {
      const fixture = tokenFixture();
      fixture.reader.assertDeviceSnAuthorized.mockRejectedValue(error);
      await expect(fixture.tokens.refresh({ refreshToken: "old" })).rejects.toThrow();
      expect(fixture.sessions.rotate).not.toHaveBeenCalled();
      await expect(fixture.tokens.issueLegacyUserToken({ legacyUserId: 7, auth_method: "device_sn", device_sn_id: 42 })).rejects.toThrow();
      expect(fixture.sessions.issue).not.toHaveBeenCalled();
    }
  });

  it("rechecks authorization after session persistence and does not return a token after a racing disable", async () => {
    const fixture = tokenFixture();
    fixture.reader.assertDeviceSnAuthorized.mockResolvedValueOnce(undefined).mockRejectedValueOnce(new UnauthorizedException());
    await expect(fixture.tokens.refresh({ refreshToken: "old" })).rejects.toThrow();
    expect(fixture.sessions.rotate).toHaveBeenCalledOnce();
  });

  it.each(["root", "admin", "manager"])("rejects an account elevated to %s before issue/refresh", async (role) => {
    const fixture = tokenFixture();
    fixture.reader.getUserById.mockResolvedValue({ ...user, roles: ["user", role] });
    await expect(fixture.tokens.refresh({ refreshToken: "old" })).rejects.toThrow();
    expect(fixture.sessions.rotate).not.toHaveBeenCalled();
  });

  it("rejects partial source in internal requests and stored sessions", async () => {
    const fixture = tokenFixture();
    await expect(fixture.tokens.issueLegacyUserToken({ legacyUserId: 7, auth_method: "device_sn" })).rejects.toThrow();
    fixture.sessions.findValidSession.mockResolvedValue({ legacyUserId: 7, authMethod: "device_sn" } as never);
    await expect(fixture.tokens.refresh({ refreshToken: "old" })).rejects.toThrow();
    expect(fixture.sessions.rotate).not.toHaveBeenCalled();
  });

  it("keeps SN-specific failure codes when the account disappears or the authority is unavailable", async () => {
    const fixture = tokenFixture();
    fixture.reader.getUserById.mockResolvedValue(null);
    await expect(fixture.tokens.refresh({ refreshToken: "old" })).rejects.toMatchObject({
      response: { code: "DEVICE_SN_UNAVAILABLE" }, status: 401
    });
    fixture.reader.getUserById.mockRejectedValue(new Error("database unavailable"));
    await expect(fixture.tokens.refresh({ refreshToken: "old" })).rejects.toMatchObject({
      response: { code: "DEVICE_SN_VALIDATION_UNAVAILABLE" }, status: 503
    });
  });

  it("rejects correctly signed incomplete source and overlong device JWTs", () => {
    const jwt = new JwtIssuerService();
    const base = jwtPayload(jwt.issue(user, "test", source).accessToken);
    const incomplete = { ...base }; delete incomplete.device_sn_id;
    for (const payload of [incomplete, { ...base, exp: Number(base.iat) + 10801 }]) {
      expect(() => jwt.verifyAccessToken(signPayload(payload))).toThrow();
    }
  });
});

describe("device SN HTTP boundary", () => {
  it("allows existing disabled-SN access until expiry but rechecks current account eligibility", async () => {
    const fixture = tokenFixture();
    const guard = new DeviceSnAccessGuard(fixture.jwt, fixture.reader as unknown as LegacyIdentityReader);
    const token = fixture.jwt.issue(user, "test", source).accessToken;
    await expect(guard.canActivate(httpContext("/userinfo", "GET", token))).resolves.toBe(true);
    expect(fixture.reader.assertDeviceSnAuthorized).toHaveBeenCalledWith(42, 7, false);
    fixture.reader.assertDeviceSnAuthorized.mockRejectedValue(new UnauthorizedException());
    await expect(guard.canActivate(httpContext("/userinfo", "GET", token))).rejects.toThrow();
    await expect(guard.canActivate(httpContext("/internal/iam/plugin/verify-token", "POST", undefined, { token }))).rejects.toThrow();
  });

  it.each(["/authorize", "/token", "/v1/password/change", "/v1/email/verify", "/v1/email/unbind", "/v1/auth/register", "/V1/EMAIL/VERIFY", "/Authorize/"])(
    "blocks credential derivation at %s before native/proxy handlers", async (path) => {
      const fixture = tokenFixture();
      const guard = new DeviceSnAccessGuard(fixture.jwt, fixture.reader as unknown as LegacyIdentityReader);
      await expect(guard.canActivate(httpContext(path, path === "/authorize" ? "GET" : "POST", fixture.jwt.issue(user, "sn", source).accessToken))).rejects.toMatchObject({ status: 403 });
      await expect(guard.canActivate(httpContext(path, "POST", fixture.jwt.issue(user, "ordinary").accessToken))).resolves.toBe(true);
    }
  );

  it("rejects SN refresh at OIDC even without an access header", async () => {
    const fixture = tokenFixture();
    const oidc = new OidcService({} as OidcAuthorizationCodeRepository, fixture.reader as unknown as LegacyIdentityReader,
      fixture.sessions as unknown as IdentitySessionRepository, fixture.jwt, fixture.tokens);
    const refresh = oidc as unknown as { refreshToken(input: { refreshToken: string }): Promise<unknown> };
    await expect(refresh.refreshToken({ refreshToken: "old" })).rejects.toMatchObject({ status: 403 });
    expect(fixture.sessions.rotate).not.toHaveBeenCalled();
  });

  it("keeps invalid ordinary OIDC refresh tokens as 401 rather than an unhandled server error", async () => {
    const fixture = tokenFixture();
    fixture.sessions.findValidSession.mockRejectedValue(new InvalidRefreshTokenError());
    const oidc = new OidcService({} as OidcAuthorizationCodeRepository, fixture.reader as unknown as LegacyIdentityReader,
      fixture.sessions as unknown as IdentitySessionRepository, fixture.jwt, fixture.tokens);
    const refresh = oidc as unknown as { refreshToken(input: { refreshToken: string }): Promise<unknown> };
    await expect(refresh.refreshToken({ refreshToken: "expired" })).rejects.toMatchObject({ status: 401, response: { code: "REFRESH_TOKEN_INVALID" } });
  });
});

describe("device SN HTTP integration", () => {
  let app: INestApplication;
  let fixture: ReturnType<typeof tokenFixture>;
  const proxy = vi.fn(async () => ({ status: 200, body: { success: true } }));
  beforeEach(async () => {
    vi.stubEnv("IDENTITY_INTERNAL_API_TOKEN", "sn-internal-test");
    fixture = tokenFixture();
    const module = await Test.createTestingModule({
      controllers: [AuthController, InternalAuthController, OidcController, AccountLifecycleController],
      providers: [
        { provide: TokenIssuanceService, useValue: fixture.tokens },
        { provide: JwtIssuerService, useValue: fixture.jwt },
        { provide: LegacyIdentityReader, useValue: { ...fixture.reader, deviceSnReadiness: async () => true } },
        { provide: IdentitySessionRepository, useValue: { ...fixture.sessions, deviceSnReadiness: async () => true } },
        { provide: AccountLifecycleService, useValue: { proxy } },
        { provide: OidcService, useValue: {} },
        { provide: APP_GUARD, useClass: DeviceSnAccessGuard }
      ]
    }).compile();
    app = module.createNestApplication(); await app.init(); proxy.mockClear();
  });
  afterEach(async () => { await app?.close(); });

  it("protects internal issuance/readiness and returns a standard device-token response", async () => {
    await request(app.getHttpServer()).post("/internal/auth/issue-user-token")
      .send({ legacyUserId: 7, auth_method: "device_sn", device_sn_id: 42 }).expect(401);
    const issued = await request(app.getHttpServer()).post("/internal/auth/issue-user-token")
      .set("X-Identity-Internal-Token", "sn-internal-test")
      .send({ legacyUserId: 7, auth_method: "device_sn", device_sn_id: 42 }).expect(201);
    expect(fixture.jwt.verifyAccessToken(issued.body.token.accessToken)).toMatchObject(source);
    await request(app.getHttpServer()).get("/internal/auth/device-sn/readiness").expect(401);
    const ready = await request(app.getHttpServer()).get("/internal/auth/device-sn/readiness")
      .set("X-Identity-Internal-Token", "sn-internal-test").expect(200);
    expect(ready.body).toEqual({ ready: true, legacySchema: true, sessionSchema: true });
  });

  it("runs the global source guard before a credential proxy and on every access use", async () => {
    const bearer = `Bearer ${fixture.jwt.issue(user, "http", source).accessToken}`;
    await request(app.getHttpServer()).get("/userinfo").set("Authorization", bearer).expect(200);
    await request(app.getHttpServer()).post("/v1/email/verify").set("Authorization", bearer).send({ code: "123456" }).expect(403);
    await request(app.getHttpServer()).post("/V1/EMAIL/VERIFY/").set("Authorization", bearer).send({ code: "123456" }).expect(403);
    expect(proxy).not.toHaveBeenCalled();
    fixture.reader.assertDeviceSnAuthorized.mockRejectedValue(new UnauthorizedException({ code: "DEVICE_SN_UNAVAILABLE" }));
    await request(app.getHttpServer()).get("/userinfo").set("Authorization", bearer).expect(401);
    await request(app.getHttpServer()).post("/v1/auth/refresh").send({ refreshToken: "old" }).expect(401);
    expect(fixture.sessions.rotate).not.toHaveBeenCalled();
  });
});

describe("identity refresh persistence", () => {
  it("incrementally upgrades an existing table, then preserves source under a row lock", async () => {
    const fixture = repositoryFixture();
    const issued = await fixture.repository.issue({ legacyUserId: 7, username: user.username, sessionId: "s1", expiresAt: new Date(Date.now() + 60000), ...source });
    expect(issued).toMatchObject(source);
    expect(fixture.columns).toEqual(new Set(["auth_method", "device_sn_id"]));
    const next = await fixture.repository.rotate("old", { legacyUserId: 99, username: user.username, sessionId: "s2", expiresAt: new Date(Date.now() + 60000) });
    expect(next).toMatchObject({ ...source, legacyUserId: 7 });
    expect(fixture.connection.execute.mock.calls.some(([sql]) => String(sql).includes("FOR UPDATE"))).toBe(true);
    expect(fixture.connection.commit).toHaveBeenCalledOnce();
    expect(fixture.connection.rollback).not.toHaveBeenCalled();
    expect(fixture.connection.release).toHaveBeenCalledOnce();
    const secondRepository = new IdentitySessionRepository();
    Object.assign(secondRepository, { pool: fixture.pool });
    await secondRepository.issue({ legacyUserId: 7, username: user.username, sessionId: "ordinary", expiresAt: new Date() });
    expect(fixture.pool.query.mock.calls.filter(([sql]) => String(sql).startsWith("ALTER TABLE"))).toHaveLength(2);
    expect(await secondRepository.deviceSnReadiness()).toBe(true);
  });

  it("rejects a partial stored source and rolls back before creating a replacement", async () => {
    const fixture = repositoryFixture();
    fixture.row.deviceSnId = null;
    await expect(fixture.repository.rotate("old", { legacyUserId: 7, username: null, sessionId: "next", expiresAt: new Date() })).rejects.toThrow();
    expect(fixture.connection.rollback).toHaveBeenCalledOnce();
    expect(fixture.connection.execute.mock.calls.some(([sql]) => String(sql).includes("INSERT INTO"))).toBe(false);
  });

  it("rejects when migration fails rather than silently dropping provenance", async () => {
    const fixture = repositoryFixture();
    fixture.pool.query.mockRejectedValue(new Error("migration denied"));
    await expect(fixture.repository.issue({ legacyUserId: 7, username: null, sessionId: "next", expiresAt: new Date(), ...source })).rejects.toThrow("migration denied");
    expect(fixture.pool.execute).not.toHaveBeenCalled();
  });
});

describe("authoritative legacy SN lookup", () => {
  it("validates the SN UUID, active account and disallowed roles without the legacy device table", async () => {
    const reader = new LegacyIdentityReader();
    const query = vi.fn().mockResolvedValue([[{ id: 42, deviceUuid: "rokid-uuid-not-rfc-uuid" }], []]);
    Object.assign(reader, { pool: { query } });
    await reader.assertDeviceSnAuthorized(42, 7);
    expect(query).toHaveBeenCalledWith(expect.stringContaining("sn.device_uuid IS NOT NULL"), [42, 7, 1]);
    expect(query.mock.calls[0][0]).toContain("CHAR_LENGTH(TRIM(sn.device_uuid)) > 0");
    expect(query.mock.calls[0][0]).not.toMatch(/JOIN\s+device\s/i);
    expect(query.mock.calls[0][0]).not.toContain("device_id");
    expect(query.mock.calls[0][0]).toContain("u.status = 10");
    expect(query.mock.calls[0][0]).toContain("'root', 'admin', 'manager'");
    query.mockResolvedValue([[], []]);
    await expect(reader.assertDeviceSnAuthorized(42, 7)).rejects.toMatchObject({ status: 401 });
  });

  it.each([null, "", "   ", "UPPERCASE", "uuid/path", "_leading", "设备-uuid", "uuid\n", "a".repeat(256)])(
    "rejects a corrupted stored device UUID (%s)", async (deviceUuid) => {
      const reader = new LegacyIdentityReader();
      Object.assign(reader, { pool: { query: vi.fn().mockResolvedValue([[{ id: 42, deviceUuid }], []]) } });
      await expect(reader.assertDeviceSnAuthorized(42, 7)).rejects.toMatchObject({ status: 401 });
    }
  );

  it("checks readiness using only the SN authorization and account tables", async () => {
    const reader = new LegacyIdentityReader();
    const query = vi.fn().mockResolvedValue([[], []]);
    Object.assign(reader, { pool: { query } });
    await expect(reader.deviceSnReadiness()).resolves.toBe(true);
    expect(query.mock.calls[0][0]).toContain("sn.device_uuid");
    expect(query.mock.calls[0][0]).not.toMatch(/JOIN\s+device\s/i);
    query.mockRejectedValue(new Error("Unknown column device_uuid"));
    await expect(reader.deviceSnReadiness()).resolves.toBe(false);
  });
});

function tokenFixture() {
  const reader = { getUserById: vi.fn().mockResolvedValue({ ...user }), assertDeviceSnAuthorized: vi.fn().mockResolvedValue(undefined) };
  const sessions = {
    isConfigured: () => true,
    issue: vi.fn().mockImplementation(async (input) => ({ ...input, refreshToken: "new-refresh" })),
    findValidSession: vi.fn().mockResolvedValue({ legacyUserId: 7, ...source }),
    rotate: vi.fn().mockImplementation(async (_old, input) => ({ ...input, refreshToken: "rotated-refresh" }))
  };
  const jwt = new JwtIssuerService();
  const tokens = new TokenIssuanceService(reader as unknown as LegacyIdentityReader, sessions as unknown as IdentitySessionRepository, jwt, {} as LoginAuditService);
  return { reader, sessions, jwt, tokens };
}
function jwtPayload(token: string): Record<string, unknown> { return JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString()); }
function signPayload(payload: Record<string, unknown>): string {
  const input = `${Buffer.from(JSON.stringify({ alg: "ES256" })).toString("base64url")}.${Buffer.from(JSON.stringify(payload)).toString("base64url")}`;
  return `${input}.${sign("sha256", Buffer.from(input), { key: privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url")}`;
}
function httpContext(path: string, method: string, token?: string, body?: Record<string, unknown>): ExecutionContext {
  return { switchToHttp: () => ({ getRequest: () => ({ path, method, headers: token ? { authorization: `Bearer ${token}` } : {}, body }) }) } as ExecutionContext;
}
function repositoryFixture() {
  const columns = new Set<string>();
  const row: Record<string, unknown> = { id: 1, refreshTokenHash: "hash", sessionId: "old", legacyUserId: 7, username: user.username,
    expiresAt: new Date(Date.now() + 60000), revokedAt: null, authMethod: "device_sn", deviceSnId: 42 };
  const execute = vi.fn(async (sql: string, _params?: unknown[]) => sql.includes("SELECT id") ? [[row], []] : [{ affectedRows: 1 }, []]);
  const connection = { execute, beginTransaction: vi.fn(), commit: vi.fn(), rollback: vi.fn(), release: vi.fn() };
  const pool = {
    execute: vi.fn(async (_sql: string, _params?: unknown[]) => [{ affectedRows: 1 }, []]),
    query: vi.fn(async (sql: string, params?: unknown[]): Promise<unknown[]> => {
      if (sql.includes("information_schema")) return [columns.has(String(params?.[0])) ? [{ COLUMN_NAME: params?.[0] }] : [], []];
      if (sql.startsWith("ALTER TABLE")) columns.add(sql.includes("auth_method") ? "auth_method" : "device_sn_id");
      return [[], []];
    }), getConnection: vi.fn(async () => connection)
  };
  const repository = new IdentitySessionRepository();
  Object.assign(repository, { pool });
  return { repository, pool, connection, row, columns };
}
