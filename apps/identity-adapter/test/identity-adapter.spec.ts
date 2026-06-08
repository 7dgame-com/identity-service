import "reflect-metadata";
import { generateKeyPairSync } from "node:crypto";
import { INestApplication } from "@nestjs/common";
import { Test } from "@nestjs/testing";
import bcrypt from "bcryptjs";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { AppModule } from "../src/app.module.js";
import { loadConfig } from "../src/config.js";
import { IdentitySessionRepository, InvalidRefreshTokenError } from "../src/identity-session.repository.js";
import { LegacyIdentityReader } from "../src/legacy-identity.reader.js";
import { LoginAuditRepository, PersistedLoginAuditEvent } from "../src/login-audit.repository.js";
import { sanitizeMetadata } from "../src/login-audit.service.js";
import { assertReadonlySql } from "../src/readonly-write.guard.js";
import { normalizeOtlpTraceEndpoint, startTelemetry } from "../src/telemetry.js";

class FakeLegacyIdentityReader {
  readonly passwordHash = bcrypt.hashSync("123456", 4);

  async health() {
    return "not_configured";
  }

  async diagnostics() {
    return {
      legacyDatabaseConfigured: false,
      tables: {
        user: false,
        user_info: false,
        auth_item: false,
        auth_assignment: false,
        organization: false,
        user_organization: false
      }
    };
  }

  async getUserById(id: number) {
    if (id !== 24) {
      return null;
    }

    return {
      id: 24,
      username: "guanfei",
      email: "ogre3d@163.com",
      status: 10,
      nickname: "babamama",
      emailVerifiedAt: 1772210253,
      createdAt: 1558664856,
      updatedAt: 1763711034,
      userInfo: { locale: "zh-CN" },
      roles: ["admin"],
      organizations: [{ id: 1, name: "test-university", title: "测试大学", createdAt: 1, updatedAt: 1 }],
      source: "legacy" as const
    };
  }

  async getUserCredentialByUsername(username: string) {
    if (username !== "guanfei") {
      return null;
    }

    return {
      id: 24,
      username: "guanfei",
      email: "ogre3d@163.com",
      status: 10,
      nickname: "babamama",
      passwordHash: this.passwordHash
    };
  }

  async listRoles() {
    return [{ name: "admin", description: "Administrator", createdAt: 1, updatedAt: 1 }];
  }

  async listOrganizations() {
    return [{ id: 1, name: "test-university", title: "测试大学", createdAt: 1, updatedAt: 1 }];
  }
}

class FakeIdentitySessionRepository {
  readonly sessions = new Map<
    string,
    {
      id: number;
      sessionId: string;
      legacyUserId: number;
      username: string | null;
      expiresAt: Date;
      revokedAt: Date | null;
    }
  >();
  nextId = 1;

  isConfigured() {
    return true;
  }

  async issue(input: { legacyUserId: number; username: string | null; sessionId: string; expiresAt: Date }) {
    const refreshToken = `refresh-${this.nextId}`;
    const session = {
      id: this.nextId,
      sessionId: input.sessionId,
      legacyUserId: input.legacyUserId,
      username: input.username,
      expiresAt: input.expiresAt,
      revokedAt: null
    };
    this.nextId += 1;
    this.sessions.set(refreshToken, session);

    return {
      refreshToken,
      refreshTokenHash: `hash-${refreshToken}`,
      sessionId: session.sessionId,
      legacyUserId: session.legacyUserId,
      username: session.username,
      expiresAt: session.expiresAt
    };
  }

  async findValidSession(refreshToken: string) {
    const session = this.sessions.get(refreshToken);
    if (!session || session.revokedAt || session.expiresAt.getTime() <= Date.now()) {
      throw new InvalidRefreshTokenError();
    }

    return {
      ...session,
      refreshTokenHash: `hash-${refreshToken}`
    };
  }

  async rotate(
    refreshToken: string,
    input: { legacyUserId: number; username: string | null; sessionId: string; expiresAt: Date }
  ) {
    const current = await this.findValidSession(refreshToken);
    const stored = this.sessions.get(refreshToken);
    if (stored) {
      stored.revokedAt = new Date();
    }

    expect(current.legacyUserId).toBe(input.legacyUserId);
    return this.issue(input);
  }

  async revoke(refreshToken: string | null | undefined) {
    if (!refreshToken) {
      return true;
    }

    const session = this.sessions.get(refreshToken);
    if (session) {
      session.revokedAt = session.revokedAt ?? new Date();
    }

    return true;
  }
}

class FakeLoginAuditRepository {
  readonly events = new Map<string, PersistedLoginAuditEvent>();
  readonly stats = new Map<number, { loginCount: number; failedLoginCount: number; lastLoginAt: string | null }>();

  isConfigured() {
    return true;
  }

  async recordEvent(event: PersistedLoginAuditEvent) {
    if (this.events.has(event.eventKey)) {
      return { duplicate: true };
    }

    this.events.set(event.eventKey, event);
    if (event.legacyUserId) {
      const current = this.stats.get(event.legacyUserId) ?? {
        loginCount: 0,
        failedLoginCount: 0,
        lastLoginAt: null
      };
      if (event.success) {
        current.loginCount += 1;
        current.lastLoginAt = event.occurredAt.toISOString();
      } else {
        current.failedLoginCount += 1;
      }
      this.stats.set(event.legacyUserId, current);
    }

    return { duplicate: false };
  }

  async getUserAudit(legacyUserId: number) {
    const stats = this.stats.get(legacyUserId);

    return {
      stats: stats
        ? {
            legacyUserId,
            identityUserId: null,
            username: "guanfei",
            loginCount: stats.loginCount,
            failedLoginCount: stats.failedLoginCount,
            lastLoginAt: stats.lastLoginAt,
            lastFailedLoginAt: null,
            updatedAt: stats.lastLoginAt
          }
        : null,
      recentEvents: [...this.events.values()]
        .filter((event) => event.legacyUserId === legacyUserId)
        .map((event) => ({
          eventKey: event.eventKey,
          eventType: event.eventType,
          success: event.success,
          occurredAt: event.occurredAt.toISOString(),
          source: event.source,
          traceId: event.traceId,
          metadata: event.metadata
        }))
    };
  }
}

describe("identity-adapter readonly API", () => {
  let app: INestApplication;

  beforeEach(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [AppModule]
    })
      .overrideProvider(LegacyIdentityReader)
      .useClass(FakeLegacyIdentityReader)
      .compile();

    app = moduleRef.createNestApplication();
    await app.init();
  });

  afterEach(async () => {
    await app.close();
  });

  it("returns health in readonly mode", async () => {
    const response = await request(app.getHttpServer()).get("/health").expect(200);

    expect(response.body).toMatchObject({
      status: "ok",
      service: "identity-adapter",
      mode: "readonly",
      dependencies: {
        legacyDatabase: "not_configured"
      }
    });
  });

  it("returns safe empty JWKS by default", async () => {
    const response = await request(app.getHttpServer()).get("/jwks.json").expect(200);

    expect(response.body).toEqual({ keys: [] });
  });

  it("returns readonly legacy user details", async () => {
    const response = await request(app.getHttpServer()).get("/admin/users/24").expect(200);

    expect(response.body.data).toMatchObject({
      id: 24,
      username: "guanfei",
      roles: ["admin"],
      organizations: [{ name: "test-university", title: "测试大学" }],
      source: "legacy"
    });
  });

  it("returns roles and organizations", async () => {
    const roles = await request(app.getHttpServer()).get("/admin/roles").expect(200);
    const organizations = await request(app.getHttpServer()).get("/admin/organizations").expect(200);

    expect(roles.body.data).toEqual([{ name: "admin", description: "Administrator", createdAt: 1, updatedAt: 1 }]);
    expect(organizations.body.data).toEqual([
      { id: 1, name: "test-university", title: "测试大学", createdAt: 1, updatedAt: 1 }
    ]);
  });

  it("does not implement token introspection in phase 3", async () => {
    await request(app.getHttpServer())
      .get("/userinfo")
      .set("Authorization", "Bearer legacy-token")
      .expect(501);
  });

  it("blocks write-like SQL statements", () => {
    expect(() => assertReadonlySql("SELECT * FROM user")).not.toThrow();
    expect(() => assertReadonlySql("UPDATE user SET status = 0")).toThrow(/blocked write-like SQL/);
  });

  it("loads optional OpenTelemetry settings safely", () => {
    const config = loadConfig({
      OTEL_SERVICE_NAME: "identity-adapter-test",
      OTEL_EXPORTER_OTLP_ENDPOINT: "http://collector:4318",
      OTEL_EXPORTER_OTLP_TRACES_HEADERS: "tenant=dev,token=a=b"
    });

    expect(config.otel).toEqual({
      serviceName: "identity-adapter-test",
      exporterOtlpEndpoint: "http://collector:4318",
      exporterOtlpHeaders: "tenant=dev,token=a=b"
    });
    expect(normalizeOtlpTraceEndpoint(config.otel.exporterOtlpEndpoint!)).toBe("http://collector:4318/v1/traces");
  });

  it("keeps telemetry disabled unless an OTLP endpoint is configured", () => {
    const config = loadConfig({});

    expect(startTelemetry(config, {})).toEqual({ enabled: false, reason: "not_configured" });
  });

  it("keeps login audit disabled by default", async () => {
    await request(app.getHttpServer())
      .post("/internal/login-events")
      .send({
        eventKey: "legacy-login:24:test-disabled",
        legacyUserId: 24,
        username: "guanfei"
      })
      .expect(404);
  });

  it("keeps token issuance disabled by default", async () => {
    await request(app.getHttpServer())
      .post("/v1/auth/login")
      .send({ username: "guanfei", password: "123456" })
      .expect(404);
  });
});

describe("identity-adapter token issuance API", () => {
  let app: INestApplication;
  let repository: FakeIdentitySessionRepository;
  const originalEnv = { ...process.env };
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();

  beforeEach(async () => {
    process.env.IDENTITY_TOKEN_ISSUANCE_ENABLED = "true";
    process.env.IDENTITY_JWT_PRIVATE_KEY_PEM = privateKeyPem;
    process.env.IDENTITY_JWT_KEY_ID = "test-key";
    process.env.IDENTITY_JWT_ISSUER = "identity-test";
    process.env.IDENTITY_JWT_AUDIENCE = "xrugc-api";
    process.env.IDENTITY_ACCESS_TOKEN_TTL_SECONDS = "3600";
    process.env.IDENTITY_REFRESH_TOKEN_TTL_SECONDS = "604800";

    repository = new FakeIdentitySessionRepository();

    const moduleRef = await Test.createTestingModule({
      imports: [AppModule]
    })
      .overrideProvider(LegacyIdentityReader)
      .useClass(FakeLegacyIdentityReader)
      .overrideProvider(IdentitySessionRepository)
      .useValue(repository)
      .compile();

    app = moduleRef.createNestApplication();
    await app.init();
  });

  afterEach(async () => {
    process.env = { ...originalEnv };
    await app.close();
  });

  it("logs in with legacy credentials and returns a backward-compatible token shape", async () => {
    const response = await request(app.getHttpServer())
      .post("/v1/auth/login")
      .send({ username: "guanfei", password: "123456" })
      .expect(201);

    expect(response.body).toMatchObject({
      success: true,
      message: "login",
      token: {
        tokenType: "Bearer",
        refreshToken: "refresh-1"
      }
    });
    expect(response.body.token.token).toBe(response.body.token.accessToken);

    const payload = decodeJwtPayload(response.body.token.accessToken);
    expect(payload).toMatchObject({
      iss: "identity-test",
      aud: "xrugc-api",
      sub: "24",
      uid: 24,
      username: "guanfei",
      roles: ["admin"]
    });
    expect(payload.session_id).toEqual(expect.any(String));
    expect(payload.jti).toEqual(expect.any(String));

    const jwks = await request(app.getHttpServer()).get("/jwks.json").expect(200);
    expect(jwks.body.keys[0]).toMatchObject({
      kid: "test-key",
      alg: "ES256",
      use: "sig"
    });
  });

  it("rejects wrong passwords without issuing a refresh session", async () => {
    await request(app.getHttpServer())
      .post("/v1/auth/login")
      .send({ username: "guanfei", password: "wrong" })
      .expect(401);

    expect(repository.sessions.size).toBe(0);
  });

  it("rotates refresh tokens and rejects replay of the old token", async () => {
    const login = await request(app.getHttpServer())
      .post("/v1/auth/login")
      .send({ username: "guanfei", password: "123456" })
      .expect(201);

    const refresh = await request(app.getHttpServer())
      .post("/v1/auth/refresh")
      .send({ refreshToken: login.body.token.refreshToken })
      .expect(201);

    expect(refresh.body.message).toBe("refresh");
    expect(refresh.body.token.refreshToken).toBe("refresh-2");

    await request(app.getHttpServer())
      .post("/v1/auth/refresh")
      .send({ refreshToken: login.body.token.refreshToken })
      .expect(401);
  });

  it("keeps logout idempotent and revokes the refresh token", async () => {
    const login = await request(app.getHttpServer())
      .post("/v1/auth/login")
      .send({ username: "guanfei", password: "123456" })
      .expect(201);

    await request(app.getHttpServer())
      .post("/v1/auth/logout")
      .send({ refreshToken: login.body.token.refreshToken })
      .expect(201);

    await request(app.getHttpServer())
      .post("/v1/auth/logout")
      .send({ refreshToken: login.body.token.refreshToken })
      .expect(201);

    await request(app.getHttpServer())
      .post("/v1/auth/refresh")
      .send({ refreshToken: login.body.token.refreshToken })
      .expect(401);
  });
});

describe("identity-adapter login audit API", () => {
  let app: INestApplication;
  let repository: FakeLoginAuditRepository;
  const originalEnv = { ...process.env };

  beforeEach(async () => {
    process.env.IDENTITY_LOGIN_AUDIT_ENABLED = "true";
    process.env.IDENTITY_INTERNAL_API_TOKEN = "test-internal-token";
    process.env.IDENTITY_LOGIN_AUDIT_HASH_SALT = "test-salt";
    process.env.IDENTITY_DB_HOST = "identity-mysql";
    process.env.IDENTITY_DB_USER = "identity";

    repository = new FakeLoginAuditRepository();

    const moduleRef = await Test.createTestingModule({
      imports: [AppModule]
    })
      .overrideProvider(LegacyIdentityReader)
      .useClass(FakeLegacyIdentityReader)
      .overrideProvider(LoginAuditRepository)
      .useValue(repository)
      .compile();

    app = moduleRef.createNestApplication();
    await app.init();
  });

  afterEach(async () => {
    process.env = { ...originalEnv };
    await app.close();
  });

  it("requires the internal service token", async () => {
    await request(app.getHttpServer())
      .post("/internal/login-events")
      .send({
        eventKey: "legacy-login:24:missing-token",
        legacyUserId: 24,
        username: "guanfei"
      })
      .expect(401);
  });

  it("records successful login events without leaking raw client data", async () => {
    const payload = {
      eventKey: "legacy-login:24:session-1",
      legacyUserId: 24,
      username: "guanfei",
      eventType: "login",
      success: true,
      occurredAt: "2026-06-06T14:30:00.000Z",
      ipAddress: "127.0.0.1",
      userAgent: "Mozilla/5.0",
      source: "legacy-backend",
      traceId: "session-1",
      metadata: {
        provider: "password",
        token: "should-not-persist",
        nested: { password: "secret", safe: "ok" }
      }
    };

    const first = await request(app.getHttpServer())
      .post("/internal/login-events")
      .set("X-Identity-Internal-Token", "test-internal-token")
      .send(payload)
      .expect(202);

    expect(first.body).toEqual({ accepted: true, duplicate: false });

    const event = repository.events.get(payload.eventKey);
    expect(event).toMatchObject({
      legacyUserId: 24,
      username: "guanfei",
      success: true,
      source: "legacy-backend"
    });
    expect(event?.ipAddressHash).toHaveLength(64);
    expect(event?.userAgentHash).toHaveLength(64);
    expect(event?.metadata).toEqual({
      provider: "password",
      token: "[filtered]",
      nested: { password: "[filtered]", safe: "ok" }
    });
  });

  it("keeps duplicate login events idempotent", async () => {
    const payload = {
      eventKey: "legacy-login:24:session-duplicate",
      legacyUserId: 24,
      username: "guanfei",
      occurredAt: "2026-06-06T14:30:00.000Z"
    };

    await request(app.getHttpServer())
      .post("/internal/login-events")
      .set("X-Identity-Internal-Token", "test-internal-token")
      .send(payload)
      .expect(202);

    const duplicate = await request(app.getHttpServer())
      .post("/internal/login-events")
      .set("X-Identity-Internal-Token", "test-internal-token")
      .send(payload)
      .expect(202);

    expect(duplicate.body).toEqual({ accepted: true, duplicate: true });

    const audit = await request(app.getHttpServer())
      .get("/internal/login-audit/users/24")
      .set("X-Identity-Internal-Token", "test-internal-token")
      .expect(200);

    expect(audit.body.data.stats).toMatchObject({
      legacyUserId: 24,
      loginCount: 1,
      failedLoginCount: 0
    });
    expect(audit.body.data.recentEvents).toHaveLength(1);
  });

  it("filters sensitive metadata recursively", () => {
    expect(
      sanitizeMetadata({
        token: "abc",
        nested: {
          authorization: "Bearer abc",
          safe: "value"
        }
      })
    ).toEqual({
      token: "[filtered]",
      nested: {
        authorization: "[filtered]",
        safe: "value"
      }
    });
  });
});

function decodeJwtPayload(token: string): Record<string, unknown> {
  const payload = token.split(".")[1];
  return JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
}
