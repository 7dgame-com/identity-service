import "reflect-metadata";
import { createHash, generateKeyPairSync, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import bcrypt from "bcryptjs";
import mysql, { Connection, RowDataPacket } from "mysql2/promise";
import {
  afterAll,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";
import { AccountLifecycleOperationRepository } from "../src/account-lifecycle-operation.repository.js";
import { AccountRegistrationRepository } from "../src/account-registration.repository.js";
import { AccountRegistrationService } from "../src/account-registration.service.js";
import { IdentitySessionRepository } from "../src/identity-session.repository.js";
import { IdentityWechatOAuthService } from "../src/identity-wechat-oauth.service.js";
import { JwtIssuerService } from "../src/jwt-issuer.service.js";
import { LegacyIdentityReader } from "../src/legacy-identity.reader.js";
import { LoginAuditService } from "../src/login-audit.service.js";
import { NativeIdentityService } from "../src/native-identity.service.js";
import { NativeQrcodeController } from "../src/native-qrcode.controller.js";
import { NativeQrcodeRepository } from "../src/native-qrcode.repository.js";
import { NativeQrcodeService } from "../src/native-qrcode.service.js";
import { TokenIssuanceService } from "../src/token-issuance.service.js";

const password = "ExistingPassword-739!";
const hash = (value: string) =>
  createHash("sha256").update(value).digest("hex");

describe.skipIf(process.env.IDENTITY_TEST_MYSQL !== "1")(
  "Native WeChat binding MySQL",
  () => {
    const database = `identity_binding_${randomUUID().replace(/-/g, "")}`;
    let db: Connection;
    let reader: LegacyIdentityReader;
    let sessions: IdentitySessionRepository;
    let jwt: JwtIssuerService;
    let native: NativeIdentityService;
    let oauth: IdentityWechatOAuthService;
    let repository: NativeQrcodeRepository;
    let registrationRepository: AccountRegistrationRepository;
    let tokens: TokenIssuanceService;
    let service: NativeQrcodeService;
    let passwordHash: string;

    beforeAll(async () => {
      const host = process.env.IDENTITY_TEST_MYSQL_HOST ?? "127.0.0.1";
      const port = Number(process.env.IDENTITY_TEST_MYSQL_PORT ?? 13316);
      const user = process.env.IDENTITY_TEST_MYSQL_USER ?? "identity_test";
      const dbPassword = process.env.IDENTITY_TEST_MYSQL_PASSWORD ?? "";
      db = await mysql.createConnection({
        host,
        port,
        user,
        password: dbPassword,
        multipleStatements: true,
      });
      await db.query(
        `CREATE DATABASE \`${database}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`,
      );
      await db.query(`USE \`${database}\``);
      for (const schema of [
        "identity-account-schema.sql",
        "identity-runtime-schema.sql",
        "identity-wechat-oauth-schema.sql",
        "identity-qrcode-schema.sql",
      ]) {
        await db.query(
          readFileSync(
            new URL(`../../../deploy/mysql/${schema}`, import.meta.url),
            "utf8",
          ),
        );
      }
      for (const [key, value] of Object.entries({
        IDENTITY_DATA_SOURCE: "identity",
        IDENTITY_DB_HOST: host,
        IDENTITY_DB_PORT: String(port),
        IDENTITY_DB_USER: user,
        IDENTITY_DB_PASSWORD: dbPassword,
        IDENTITY_DB_NAME: database,
        IDENTITY_TOKEN_ISSUANCE_ENABLED: "true",
        IDENTITY_TOKEN_ISSUANCE_INTERNAL_API_TOKEN:
          "binding-test-internal-token-at-least-32-characters",
        IDENTITY_JWT_ISSUER: "https://identity.test",
        IDENTITY_JWT_AUDIENCE: "xrugc-test",
      }))
        vi.stubEnv(key, value);
      const keys = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
      vi.stubEnv(
        "IDENTITY_JWT_PRIVATE_KEY_PEM",
        keys.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
      );
      vi.stubEnv(
        "IDENTITY_JWT_PUBLIC_KEY_PEM",
        keys.publicKey.export({ format: "pem", type: "spki" }).toString(),
      );
      passwordHash = (await bcrypt.hash(password, 4)).replace(
        /^\$2b\$/,
        "$2y$",
      );
      await db.query(
        "INSERT INTO user(id,username,password_hash,status,created_at,updated_at) VALUES (41,'existing-one',?,10,1,1),(42,'existing-two',?,10,1,1)",
        [passwordHash, passwordHash],
      );
      await db.query("INSERT INTO user_info(user_id) VALUES (41),(42)");
      reader = new LegacyIdentityReader();
      sessions = new IdentitySessionRepository();
      jwt = new JwtIssuerService();
      await sessions.ensureSchema();
      native = new NativeIdentityService(reader, jwt, sessions);
      tokens = new TokenIssuanceService(reader, sessions, jwt, {
        record: vi.fn(),
      } as unknown as LoginAuditService);
      oauth = new IdentityWechatOAuthService(reader, sessions, jwt, native);
      repository = new NativeQrcodeRepository();
      registrationRepository = new AccountRegistrationRepository();
      const registration = new AccountRegistrationService(
        registrationRepository,
        {
          isConfigured: () => true,
        } as unknown as AccountLifecycleOperationRepository,
        tokens,
      );
      service = new NativeQrcodeService(
        repository,
        native,
        tokens,
        oauth,
        registration,
      );
    }, 30_000);

    beforeEach(async () => {
      vi.restoreAllMocks();
      await db.query(
        "DELETE FROM identity_wechat_scenes; DELETE FROM identity_wechat_identities; DELETE FROM wechat; DELETE FROM identity_subject_events; DELETE FROM identity_refresh_sessions",
      );
      await db.query(
        "UPDATE user SET status=10,deleted_at=NULL,wx_openid=NULL,password_hash=? WHERE id IN (41,42)",
        [passwordHash],
      );
    });

    afterAll(async () => {
      await Promise.all([
        reader?.onModuleDestroy(),
        sessions?.onModuleDestroy(),
        native?.onModuleDestroy(),
        oauth?.onModuleDestroy(),
        repository?.onModuleDestroy(),
        registrationRepository?.onModuleDestroy(),
      ]);
      if (db) {
        await db.query(`DROP DATABASE IF EXISTS \`${database}\``);
        await db.end();
      }
      vi.unstubAllEnvs();
    });

    async function scene(
      token = "original-scene",
      options: {
        app?: string;
        openId?: string | null;
        signup?: string;
        expires?: number;
        userId?: number;
        profile?: Record<string, unknown>;
      } = {},
    ) {
      const app = options.app ?? "wx-app";
      const openId =
        options.openId === undefined ? "scanned-openid" : options.openId;
      const expires = options.expires ?? Math.floor(Date.now() / 1000) + 600;
      await db.execute(
        "INSERT INTO identity_wechat_scenes(scene_hash,expires_at,provider_app_id,open_id,user_id,signup_token_hash,profile_json) VALUES (?,?,?,?,?,?,?)",
        [
          hash(token),
          expires,
          app,
          openId,
          options.userId ?? null,
          options.signup ? hash(options.signup) : null,
          JSON.stringify(options.profile ?? { providerAppId: app, openId }),
        ],
      );
      return { token, expires };
    }
    const input = (token = "original-scene", username = "existing-one") => ({
      token,
      username,
      password,
    });
    async function counts() {
      const [rows] = await db.query<RowDataPacket[]>(
        "SELECT (SELECT COUNT(*) FROM identity_subject_events) events,(SELECT COUNT(*) FROM identity_refresh_sessions) sessions",
      );
      return {
        events: Number(rows[0].events),
        sessions: Number(rows[0].sessions),
      };
    }

    it("keeps the old public route/response and derives subject from the original confirmed scene", async () => {
      const issued = await scene();
      const controller = new NativeQrcodeController(service);
      expect(Reflect.getMetadata("path", controller.binding)).toBe(
        "v1/wechat/binding",
      );
      expect(Reflect.getMetadata("__httpCode__",controller.binding)).toBe(200);
      const response = await controller.binding({
        headers: { "user-agent": "old-browser" },
        body: { ...input(), openId: "attacker", providerAppId: "attacker-app" },
      });
      expect(response.code).toBe(20000);
      expect(jwt.verifyAccessToken(response.access_token).uid).toBe(41);
      const [bindings] = await db.query<RowDataPacket[]>(
        "SELECT user_id,provider_app_id,open_id FROM identity_wechat_identities",
      );
      expect(
        bindings.map((row) => [
          Number(row.user_id),
          row.provider_app_id,
          row.open_id,
        ]),
      ).toEqual([[41, "wx-app", "scanned-openid"]]);
      const [scenes] = await db.query<RowDataPacket[]>(
        "SELECT expires_at,user_id FROM identity_wechat_scenes",
      );
      expect(Number(scenes[0].expires_at)).toBe(issued.expires);
      expect(Number(scenes[0].user_id)).toBe(41);
      expect(await counts()).toEqual({ events: 1, sessions: 1 });
    });

    it("accepts an active signup challenge and retries the same account without another binding event", async () => {
      await scene("original-scene", { signup: "signup-challenge" });
      const first = await service.wechatBinding(input("signup-challenge"));
      const [beforePoll] = await db.query<RowDataPacket[]>(
        "SELECT expires_at FROM identity_wechat_scenes",
      );
      expect(await service.wechatStatus("original-scene")).toEqual({
        success: true,
        message: "signin",
        token: "original-scene",
      });
      const second = await service.wechatBinding(input("signup-challenge"));
      const [afterPoll] = await db.query<RowDataPacket[]>(
        "SELECT expires_at,signup_token_hash FROM identity_wechat_scenes",
      );
      expect(afterPoll[0].expires_at).toBe(beforePoll[0].expires_at);
      expect(afterPoll[0].signup_token_hash).toBe(hash("signup-challenge"));
      expect(jwt.verifyAccessToken(first.access_token).uid).toBe(41);
      expect(jwt.verifyAccessToken(second.access_token).uid).toBe(41);
      expect(await counts()).toEqual({ events: 1, sessions: 2 });
      await expect(
        service.wechatBinding(input("signup-challenge", "existing-two")),
      ).rejects.toThrow("其他绑定");
      expect(await counts()).toEqual({ events: 1, sessions: 2 });
    });

    it("serializes competing account bindings and commits only one owner", async () => {
      await scene();
      const outcomes = await Promise.allSettled(
        ["existing-one", "existing-two"].map((username) =>
          service.wechatBinding(input("original-scene", username)),
        ),
      );
      expect(
        outcomes.filter((outcome) => outcome.status === "fulfilled"),
      ).toHaveLength(1);
      expect(
        outcomes.filter((outcome) => outcome.status === "rejected"),
      ).toHaveLength(1);
      expect(await counts()).toEqual({ events: 1, sessions: 1 });
    });

    it.each(["wrong-password", "disabled", "deleted"])(
      "rejects %s before issuing or binding",
      async (variant) => {
        await scene();
        if (variant === "disabled")
          await db.query("UPDATE user SET status=0 WHERE id=41");
        if (variant === "deleted")
          await db.query("UPDATE user SET deleted_at=1 WHERE id=41");
        await expect(
          service.wechatBinding({
            ...input(),
            password: variant === "wrong-password" ? "wrong" : password,
          }),
        ).rejects.toThrow();
        expect(await counts()).toEqual({ events: 0, sessions: 0 });
        const [bindings] = await db.query<RowDataPacket[]>(
          "SELECT * FROM identity_wechat_identities",
        );
        expect(bindings).toHaveLength(0);
      },
    );

    it.each([
      "unknown",
      "expired",
      "unconfirmed",
      "cross-app",
      "profile-mismatch",
    ])("requires exact live provider proof: %s", async (variant) => {
      if (variant !== "unknown")
        await scene("original-scene", {
          expires:
            variant === "expired" ? Math.floor(Date.now() / 1000) : undefined,
          openId: variant === "unconfirmed" ? null : undefined,
          signup: variant === "cross-app" ? "shared-challenge" : undefined,
          profile:
            variant === "profile-mismatch" ? { openId: "another" } : undefined,
        });
      if (variant === "cross-app")
        await scene("other-scene", {
          app: "other-app",
          signup: "shared-challenge",
        });
      await expect(
        service.wechatBinding(
          input(
            variant === "cross-app" ? "shared-challenge" : "original-scene",
          ),
        ),
      ).rejects.toThrow();
      expect(await counts()).toEqual({ events: 0, sessions: 0 });
    });

    it("never overwrites a prior exact provider owner or another binding in the same app", async () => {
      await scene();
      await db.query(
        "INSERT INTO identity_wechat_identities(provider,provider_app_id,open_id,user_id) VALUES ('wechat_official_account','wx-app','scanned-openid',42)",
      );
      await expect(service.wechatBinding(input())).rejects.toThrow("其他绑定");
      await db.query("DELETE FROM identity_wechat_identities");
      await db.query(
        "INSERT INTO identity_wechat_identities(provider,provider_app_id,open_id,user_id) VALUES ('wechat_official_account','wx-app','another-existing-openid',41)",
      );
      await expect(service.wechatBinding(input())).rejects.toThrow("其他绑定");
      expect(await counts()).toEqual({ events: 0, sessions: 0 });
    });

    it("allows explicit binding to a second app while preserving the old scalar projection", async () => {
      await scene("second-app-scene", {
        app: "second-app",
        openId: "second-app-openid",
      });
      await db.query(
        "UPDATE user SET wx_openid='first-app-openid' WHERE id=41",
      );
      await db.query(
        "INSERT INTO identity_wechat_identities(provider,provider_app_id,open_id,user_id) VALUES ('wechat_official_account','first-app','first-app-openid',41)",
      );
      const response = await service.wechatBinding(input("second-app-scene"));
      expect(jwt.verifyAccessToken(response.access_token).uid).toBe(41);
      const [users] = await db.query<RowDataPacket[]>(
        "SELECT wx_openid FROM user WHERE id=41",
      );
      expect(users[0].wx_openid).toBe("first-app-openid");
      const [bindings] = await db.query<RowDataPacket[]>(
        "SELECT open_id FROM identity_wechat_identities WHERE user_id=41 ORDER BY provider_app_id",
      );
      expect(bindings.map((binding) => binding.open_id)).toEqual([
        "first-app-openid",
        "second-app-openid",
      ]);
    });

    it("serializes two different openids competing for the same account and app", async () => {
      await scene("first-scene", { openId: "first-openid" });
      await scene("second-scene", { openId: "second-openid" });
      const outcomes = await Promise.allSettled(
        ["first-scene", "second-scene"].map((token) =>
          service.wechatBinding(input(token)),
        ),
      );
      expect(
        outcomes.filter((outcome) => outcome.status === "fulfilled"),
      ).toHaveLength(1);
      expect(
        outcomes.filter((outcome) => outcome.status === "rejected"),
      ).toHaveLength(1);
      expect(await counts()).toEqual({ events: 1, sessions: 1 });
    });

    it("preflights signing before any binding mutation", async () => {
      await scene();
      vi.spyOn(jwt, "assertSigningReady").mockImplementation(() => {
        throw new Error("signing unavailable");
      });
      await expect(service.wechatBinding(input())).rejects.toThrow(
        "signing unavailable",
      );
      const [bindings] = await db.query<RowDataPacket[]>(
        "SELECT * FROM identity_wechat_identities",
      );
      expect(bindings).toHaveLength(0);
      expect(await counts()).toEqual({ events: 0, sessions: 0 });
    });

    it("rechecks the password hash under the binding transaction lock", async () => {
      await scene();
      const original = reader.getUserCredentialByUsername.bind(reader);
      vi.spyOn(reader, "getUserCredentialByUsername").mockImplementationOnce(
        async (username) => {
          const credential = await original(username);
          await db.query("UPDATE user SET password_hash='changed' WHERE id=41");
          return credential;
        },
      );
      await expect(service.wechatBinding(input())).rejects.toThrow();
      expect(await counts()).toEqual({ events: 0, sessions: 0 });
    });

    it.each(["expiry", "subject"])(
      "rechecks %s after password verification before binding commit",
      async (variant) => {
        await scene();
        const original = reader.getUserCredentialByUsername.bind(reader);
        vi.spyOn(reader, "getUserCredentialByUsername").mockImplementationOnce(
          async (username) => {
            const credential = await original(username);
            if (variant === "expiry")
              await db.query("UPDATE identity_wechat_scenes SET expires_at=?", [
                Math.floor(Date.now() / 1000),
              ]);
            else
              await db.query(
                "UPDATE identity_wechat_scenes SET open_id='changed-openid',profile_json=NULL",
              );
            return credential;
          },
        );
        await expect(service.wechatBinding(input())).rejects.toThrow();
        expect(await counts()).toEqual({ events: 0, sessions: 0 });
        const [bindings] = await db.query<RowDataPacket[]>(
          "SELECT * FROM identity_wechat_identities",
        );
        expect(bindings).toHaveLength(0);
      },
    );

    it.each(["password", "status"])(
      "session issuance CAS rejects changed %s after binding commit",
      async (variant) => {
        await scene();
        const original = tokens.issueRegisteredUser.bind(tokens);
        vi.spyOn(tokens, "issueRegisteredUser").mockImplementationOnce(
          async (...args) => {
            await db.query(
              variant === "password"
                ? "UPDATE user SET password_hash='changed' WHERE id=41"
                : "UPDATE user SET status=0 WHERE id=41",
            );
            return original(...args);
          },
        );
        await expect(service.wechatBinding(input())).rejects.toThrow();
        expect(await counts()).toEqual({ events: 1, sessions: 0 });
      },
    );

    it("refuses to inherit another app's unscoped openid without verified union proof", async () => {
      await db.query(
        "INSERT INTO identity_wechat_identities(provider,provider_app_id,open_id,user_id) VALUES ('wechat_official_account','first-app','collision-openid',41)",
      );
      await db.query(
        "INSERT INTO wechat(openid,user_id,token) VALUES ('collision-openid',41,'stable-token')",
      );
      await expect(
        oauth.resolveWechat({
          provider: "wechat_official_account",
          providerAppId: "second-app",
          openId: "collision-openid",
        }),
      ).rejects.toThrow("exact app binding");
      const [bindings] = await db.query<RowDataPacket[]>(
        "SELECT provider_app_id FROM identity_wechat_identities ORDER BY provider_app_id",
      );
      expect(bindings.map((binding) => binding.provider_app_id)).toEqual([
        "first-app",
      ]);
      expect(
        await oauth.resolveWechat({
          provider: "wechat_official_account",
          providerAppId: "first-app",
          openId: "collision-openid",
        }),
      ).toEqual({ userId: 41, signupToken: null });
    });

    it("allows explicit second-app ownership despite an unrelated global openid projection", async () => {
      await db.query(
        "INSERT INTO identity_wechat_identities(provider,provider_app_id,open_id,user_id) VALUES ('wechat_official_account','first-app','collision-openid',41)",
      );
      await db.query(
        "INSERT INTO wechat(openid,user_id,token) VALUES ('collision-openid',41,'stable-token')",
      );
      await scene("second-app-scene", {
        app: "second-app",
        openId: "collision-openid",
      });
      const response = await service.wechatBinding(
        input("second-app-scene", "existing-two"),
      );
      expect(jwt.verifyAccessToken(response.access_token).uid).toBe(42);
      expect(
        await oauth.resolveWechat({
          provider: "wechat_official_account",
          providerAppId: "second-app",
          openId: "collision-openid",
        }),
      ).toEqual({ userId: 42, signupToken: null });
      const login = await service.wechatLogin({ token: "second-app-scene" });
      expect(jwt.verifyAccessToken(login.token.accessToken).uid).toBe(42);
      const [legacy] = await db.query<RowDataPacket[]>(
        "SELECT user_id FROM wechat WHERE openid='collision-openid'",
      );
      expect(Number(legacy[0].user_id)).toBe(41);
      const [bindings] = await db.query<RowDataPacket[]>(
        "SELECT provider_app_id,user_id FROM identity_wechat_identities ORDER BY provider_app_id",
      );
      expect(
        bindings.map((binding) => [
          binding.provider_app_id,
          Number(binding.user_id),
        ]),
      ).toEqual([
        ["first-app", 41],
        ["second-app", 42],
      ]);
    });

    it("inherits only a provider-verified exact union ID across applications", async () => {
      await db.query(
        "INSERT INTO identity_wechat_identities(provider,provider_app_id,open_id,user_id,union_id) VALUES ('wechat_official_account','first-app','first-openid',41,'VerifiedUnion')",
      );
      await db.query(
        "INSERT INTO wechat(openid,user_id,token,unionid) VALUES ('first-openid',41,'stable-token','VerifiedUnion')",
      );
      expect(
        await oauth.resolveWechat({
          provider: "wechat_official_account",
          providerAppId: "second-app",
          openId: "second-openid",
          unionId: "VerifiedUnion",
        }),
      ).toEqual({ userId: 41, signupToken: null });
      expect(
        await oauth.resolveWechat({
          provider: "wechat_official_account",
          providerAppId: "third-app",
          openId: "third-openid",
          unionId: "verifiedunion",
        }),
      ).toMatchObject({ userId: null });
    });

    it("rejects ambiguous union ownership in a new app while honoring an existing exact binding", async () => {
      await db.query(
        "INSERT INTO identity_wechat_identities(provider,provider_app_id,open_id,user_id,union_id) VALUES ('wechat_official_account','first-app','first-openid',41,'shared-union'),('wechat_official_account','second-app','second-openid',42,'shared-union')",
      );
      await db.query(
        "INSERT INTO wechat(openid,user_id,token,unionid) VALUES ('first-openid',41,'first-token','shared-union'),('second-openid',42,'second-token',NULL)",
      );
      await expect(
        oauth.resolveWechat({
          provider: "wechat_official_account",
          providerAppId: "third-app",
          openId: "third-openid",
          unionId: "shared-union",
        }),
      ).rejects.toThrow("conflict");
      expect(
        await oauth.resolveWechat({
          provider: "wechat_official_account",
          providerAppId: "second-app",
          openId: "second-openid",
          unionId: "shared-union",
        }),
      ).toEqual({ userId: 42, signupToken: null });
    });

    it("keeps app IDs and openids case-sensitive in resolver and payment reads", async () => {
      await db.query(
        "INSERT INTO identity_wechat_identities(provider,provider_app_id,open_id,user_id) VALUES ('wechat_official_account','CaseApp','CaseOpenId',41)",
      );
      await db.query(
        "INSERT INTO wechat(openid,user_id,token) VALUES ('CaseOpenId',41,'stable-token')",
      );
      expect(await oauth.paymentIdentity(41, "CaseApp")).toEqual({
        providerAppId: "CaseApp",
        openId: "CaseOpenId",
        unionId: null,
      });
      expect(await oauth.paymentIdentity(41, "caseapp")).toBeNull();
      await expect(
        oauth.resolveWechat({
          provider: "wechat_official_account",
          providerAppId: "caseapp",
          openId: "CaseOpenId",
        }),
      ).rejects.toThrow("exact app binding");
      expect(
        await oauth.resolveWechat({
          provider: "wechat_official_account",
          providerAppId: "CaseApp",
          openId: "caseopenid",
        }),
      ).toMatchObject({ userId: null });
      const [bindings] = await db.query<RowDataPacket[]>(
        "SELECT open_id FROM identity_wechat_identities WHERE provider_app_id='CaseApp' ORDER BY BINARY open_id",
      );
      expect(bindings.map((binding) => binding.open_id)).toEqual([
        "CaseOpenId",
        "caseopenid",
      ]);
    });

    it("upgrades an existing private schema without changing account IDs or QR deadlines", async () => {
      const issued = await scene();
      await db.query(
        "ALTER TABLE identity_wechat_identities MODIFY provider_app_id VARCHAR(191) COLLATE utf8mb4_unicode_ci NOT NULL",
      );
      await db.query(
        readFileSync(
          new URL(
            "../../../deploy/mysql/identity-wechat-binary-migration.sql",
            import.meta.url,
          ),
          "utf8",
        ),
      );
      const [columns] = await db.query<RowDataPacket[]>(
        "SELECT TABLE_NAME,COLUMN_NAME,COLLATION_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=? AND ((TABLE_NAME='user' AND COLUMN_NAME='wx_openid') OR (TABLE_NAME='identity_wechat_identities' AND COLUMN_NAME IN ('provider','provider_app_id','open_id','union_id')) OR (TABLE_NAME='wechat' AND COLUMN_NAME IN ('openid','unionid','token')) OR (TABLE_NAME='identity_wechat_scenes' AND COLUMN_NAME IN ('provider_app_id','open_id')))",
        [database],
      );
      expect(columns).toHaveLength(10);
      expect(
        columns.every((column) => column.COLLATION_NAME === "utf8mb4_bin"),
      ).toBe(true);
      const [scenes] = await db.query<RowDataPacket[]>(
        "SELECT expires_at FROM identity_wechat_scenes",
      );
      expect(Number(scenes[0].expires_at)).toBe(issued.expires);
    });

    it("accepts the original scene on the unchanged legacy signup page", async () => {
      await scene("old-page-scene", { openId: "registration-openid" });
      const response = await service.wechatRegister({
        token: "old-page-scene",
        username: "new-from-old-page",
        password: "RegistrationPassword-739!",
      });
      expect(response).toMatchObject({ success: true, message: "register" });
      const [bindings] = await db.query<RowDataPacket[]>(
        "SELECT user_id FROM identity_wechat_identities WHERE open_id='registration-openid'",
      );
      expect(Number(bindings[0].user_id)).toBeGreaterThan(42);
      expect(await service.wechatStatus("old-page-scene")).toEqual({
        success: true,
        message: "signin",
        token: "old-page-scene",
      });
    }, 20_000);
  },
);
