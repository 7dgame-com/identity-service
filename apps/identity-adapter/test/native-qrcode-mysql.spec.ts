import "reflect-metadata";
import { generateKeyPairSync, randomUUID, createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import mysql, { Connection, RowDataPacket } from "mysql2/promise";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { AccountRegistrationRepository } from "../src/account-registration.repository.js";
import { AccountRegistrationService } from "../src/account-registration.service.js";
import { AccountLifecycleOperationRepository } from "../src/account-lifecycle-operation.repository.js";
import { IdentitySessionRepository } from "../src/identity-session.repository.js";
import { IdentityWechatOAuthService } from "../src/identity-wechat-oauth.service.js";
import { JwtIssuerService } from "../src/jwt-issuer.service.js";
import { LegacyIdentityReader } from "../src/legacy-identity.reader.js";
import { LoginAuditService } from "../src/login-audit.service.js";
import { NativeIdentityService } from "../src/native-identity.service.js";
import { NativeQrcodeRepository } from "../src/native-qrcode.repository.js";
import { NativeQrcodeService } from "../src/native-qrcode.service.js";
import { TokenIssuanceService } from "../src/token-issuance.service.js";

class LocalProviderQrcodeService extends NativeQrcodeService {
  clock = Math.floor(Date.now() / 1000);
  profile: Record<string, unknown> = {};
  protected now() { return this.clock; }
  protected async provider(action: "qrcode" | "profile", _payload: Record<string, unknown>) {
    return action === "qrcode" ? { ticket: "local-provider-ticket" } : this.profile;
  }
}

describe.skipIf(process.env.IDENTITY_TEST_MYSQL !== "1")("Independent QR MySQL transactions", () => {
  const database = `identity_qr_test_${randomUUID().replace(/-/g, "")}`;
  let db: Connection;
  let reader: LegacyIdentityReader;
  let sessions: IdentitySessionRepository;
  let native: NativeIdentityService;
  let repository: NativeQrcodeRepository;
  let oauth: IdentityWechatOAuthService;
  let registrationRepository: AccountRegistrationRepository;
  let service: LocalProviderQrcodeService;
  let authorization: string;

  beforeAll(async () => {
    const host = process.env.IDENTITY_TEST_MYSQL_HOST ?? "127.0.0.1";
    const port = Number(process.env.IDENTITY_TEST_MYSQL_PORT ?? 13316);
    const user = process.env.IDENTITY_TEST_MYSQL_USER ?? "identity_test";
    const password = process.env.IDENTITY_TEST_MYSQL_PASSWORD ?? "";
    db = await mysql.createConnection({ host, port, user, password, multipleStatements: true });
    await db.query(`CREATE DATABASE \`${database}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`);
    await db.query(`USE \`${database}\``);
    for (const schema of ["identity-account-schema.sql", "identity-runtime-schema.sql", "identity-wechat-oauth-schema.sql", "identity-qrcode-schema.sql"]) {
      await db.query(readFileSync(new URL(`../../../deploy/mysql/${schema}`, import.meta.url), "utf8"));
    }
    for (const [key, value] of Object.entries({ IDENTITY_DATA_SOURCE: "identity", IDENTITY_DB_HOST: host,
      IDENTITY_DB_PORT: String(port), IDENTITY_DB_USER: user, IDENTITY_DB_PASSWORD: password, IDENTITY_DB_NAME: database,
      IDENTITY_TOKEN_ISSUANCE_ENABLED: "true", IDENTITY_TOKEN_ISSUANCE_INTERNAL_API_TOKEN: "test-internal-token",
      IDENTITY_JWT_ISSUER: "https://identity.test", IDENTITY_JWT_AUDIENCE: "xrugc-test" })) vi.stubEnv(key, value);
    const keys = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    vi.stubEnv("IDENTITY_JWT_PRIVATE_KEY_PEM", keys.privateKey.export({ format: "pem", type: "pkcs8" }).toString());
    vi.stubEnv("IDENTITY_JWT_PUBLIC_KEY_PEM", keys.publicKey.export({ format: "pem", type: "spki" }).toString());
    await db.query("INSERT INTO user (id,username,status,created_at,updated_at) VALUES (42,'qr-owner',10,1,1)");
    await db.query("INSERT INTO user_info (user_id) VALUES (42)");
    await db.query("INSERT INTO auth_assignment (item_name,user_id) VALUES ('root','42')");
    reader = new LegacyIdentityReader(); sessions = new IdentitySessionRepository();
    const jwt = new JwtIssuerService(); native = new NativeIdentityService(reader, jwt, sessions);
    const tokens = new TokenIssuanceService(reader, sessions, jwt, { record: vi.fn() } as unknown as LoginAuditService);
    oauth = new IdentityWechatOAuthService(reader, sessions, jwt, native); repository = new NativeQrcodeRepository();
    registrationRepository = new AccountRegistrationRepository();
    const registration = new AccountRegistrationService(registrationRepository,
      { isConfigured: () => true } as unknown as AccountLifecycleOperationRepository, tokens);
    service = new LocalProviderQrcodeService(repository, native, tokens, oauth, registration);
    authorization = `Bearer ${(await tokens.issueLegacyUserToken({ legacyUserId: 42 })).token.accessToken}`;
  }, 30_000);

  beforeEach(async () => {
    await db.query("DELETE FROM identity_login_codes");
    await db.query("UPDATE user SET status=10 WHERE id=42");
  });

  afterAll(async () => {
    await Promise.all([reader?.onModuleDestroy(), sessions?.onModuleDestroy(), native?.onModuleDestroy(),
      oauth?.onModuleDestroy(), repository?.onModuleDestroy(), registrationRepository?.onModuleDestroy()]);
    if (db) { await db.query(`DROP DATABASE IF EXISTS \`${database}\``); await db.end(); }
    vi.unstubAllEnvs();
  });

  it("issues four independent sessions concurrently from one 60 second code", async () => {
    const code = await service.issueLoginCode({ headers: { authorization } });
    const responses = await Promise.all(Array.from({ length: 4 }, (_, index) => service.redeemLoginCode(`web_${code.key}`, { userAgent: `device-${index}` })));
    expect(new Set(responses.map((response) => response.token.refreshToken)).size).toBe(4);
    const [rows] = await db.query<RowDataPacket[]>("SELECT code_hash,user_id,expires_at,issued_at FROM identity_login_codes");
    expect(rows).toHaveLength(1); expect(Number(rows[0].user_id)).toBe(42);
    expect(Number(rows[0].expires_at) - Number(rows[0].issued_at)).toBe(60);
    expect(JSON.stringify(rows)).not.toContain(code.key);
    for (const response of responses) expect(JSON.stringify(rows)).not.toContain(response.token.refreshToken);
  });

  it("rejects expiry and disabled subjects without creating a session", async () => {
    const [before] = await db.query<RowDataPacket[]>("SELECT COUNT(*) AS total FROM identity_refresh_sessions");
    const code = await service.issueLoginCode({ headers: { authorization } });
    await db.query("UPDATE identity_login_codes SET expires_at=?", [service.clock]);
    await expect(service.redeemLoginCode(`web_${code.key}`)).rejects.toThrow("invalid or expired");
    await db.query("UPDATE identity_login_codes SET expires_at=?", [service.clock + 60]);
    await db.query("UPDATE user SET status=0 WHERE id=42");
    await expect(service.redeemLoginCode(`web_${code.key}`)).rejects.toThrow();
    const [after] = await db.query<RowDataPacket[]>("SELECT COUNT(*) AS total FROM identity_refresh_sessions");
    expect(Number(after[0].total)).toBe(Number(before[0].total));
  });

  it("serializes issuance to preserve the five per minute limit", async () => {
    const outcomes = await Promise.allSettled(Array.from({ length: 8 }, () => service.issueLoginCode({ headers: { authorization } })));
    expect(outcomes.filter((outcome) => outcome.status === "fulfilled")).toHaveLength(5);
    const [rows] = await db.query<RowDataPacket[]>("SELECT COUNT(*) AS total FROM identity_login_codes");
    expect(Number(rows[0].total)).toBe(5);
  });

  it("prevents concurrent callbacks from rebinding one scene to another openid", async () => {
    const code = await service.createWechatQr(); const hash = createHash("sha256").update(code.token).digest("hex");
    const outcomes = await Promise.allSettled(["first", "second"].map((openId) =>
      repository.confirmWechatScene(hash, "test-app", openId, null, null, { openId }, service.clock)));
    expect(outcomes.filter((outcome) => outcome.status === "fulfilled")).toHaveLength(1);
    expect(outcomes.filter((outcome) => outcome.status === "rejected")).toHaveLength(1);
    const scene = await repository.wechatScene(hash); expect(["first", "second"]).toContain(scene?.openId);
  });

  it("registers a confirmed WeChat identity once under competing username requests", async () => {
    const code = await service.createWechatQr();
    service.profile = { provider: "wechat_official_account", providerAppId: "test-app", openId: "new-wechat", unionId: "new-union", nickname: "New user" };
    await service.confirmWechatScan({ scene: code.token, providerAppId: "test-app", openId: "new-wechat" });
    const status = await service.wechatStatus(code.token); expect(status.message).toBe("signup");
    const payload = { token: status.token, password: "QrPassword-793!" };
    const outcomes = await Promise.allSettled(["wechat-one", "wechat-two"].map((username) => service.wechatRegister({ ...payload, username })));
    expect(outcomes.filter((outcome) => outcome.status === "fulfilled")).toHaveLength(1);
    const [rows] = await db.query<RowDataPacket[]>("SELECT user_id FROM wechat WHERE openid='new-wechat'");
    expect(Number(rows[0].user_id)).toBeGreaterThan(42);
    const [accounts] = await db.query<RowDataPacket[]>("SELECT id FROM user WHERE username IN ('wechat-one','wechat-two')");
    expect(accounts).toHaveLength(1);
    expect(await service.wechatStatus(code.token)).toEqual({ success: true, message: "signin", token: code.token });
  }, 20_000);
});
