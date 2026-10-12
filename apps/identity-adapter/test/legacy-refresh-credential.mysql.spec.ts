import "reflect-metadata";
import { execFile } from "node:child_process";
import { createHash, generateKeyPairSync, randomBytes, randomUUID } from "node:crypto";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";
import type { INestApplication } from "@nestjs/common";
import { NestFactory } from "@nestjs/core";
import mysql, { type Connection, type RowDataPacket } from "mysql2/promise";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { AccountPasswordRepository } from "../src/account-password.repository.js";
import { IdentitySessionRepository } from "../src/identity-session.repository.js";
import { JwtIssuerService } from "../src/jwt-issuer.service.js";
import { LegacyIdentityReader } from "../src/legacy-identity.reader.js";
import { LegacyEmailLinkService } from "../src/legacy-email-link.service.js";
import { LegacyRefreshCredentialRepository } from "../src/legacy-refresh-credential.repository.js";
import { importLegacyRefreshCredentials } from "../src/legacy-refresh-credential-import.js";
import { importLegacySessions } from "../src/legacy-session-import.js";
import { exportLegacyRefreshCredentials, legacyRefreshAccountFingerprint } from "../src/legacy-refresh-credential-manifest.js";
import { NativeIdentityService } from "../src/native-identity.service.js";
import { TokenIssuanceService } from "../src/token-issuance.service.js";
import { hashLegacyPassword } from "../src/legacy-password.js";
import type { LoginAuditService } from "../src/login-audit.service.js";

const opts = { host: process.env.IDENTITY_TEST_MYSQL_HOST ?? "127.0.0.1", port: Number(process.env.IDENTITY_TEST_MYSQL_PORT ?? 13316),
  user: process.env.IDENTITY_TEST_MYSQL_USER ?? "root", password: process.env.IDENTITY_TEST_MYSQL_PASSWORD ?? "", multipleStatements: true, timezone: "Z" };
const name = `test_legacy_refresh_${randomUUID().replaceAll("-", "")}`;
const projectRoot = fileURLToPath(new URL("../../../", import.meta.url));
const source = { storage: "yii2-redis-active-record-hash", redisDatabase: 1, keyPrefix: "refresh_token:a:",
  a1Revision: "f5bf6667a6fc5bfc65590f13bccd9d8ba0612a74", serverRevision: "1".repeat(40), namespaceReviewed: true,
  keyEncodingReviewed: true, accountSnapshotReviewed: true, writersDrained: true, a1LookupReviewed: true, serverLookupReviewed: true };
const password = "Legacy-migration!73", authKey = "k".repeat(32), internal = randomBytes(32).toString("hex");
const hash = (value: string) => createHash("sha256").update(value).digest("hex");
const apply = { apply: true, environment: "staging" };

describe.skipIf(process.env.IDENTITY_TEST_MYSQL !== "1")("reviewed Yii AR credential migration and private authority", () => {
  let admin: Connection, db: Connection, sessions: IdentitySessionRepository, reader: LegacyIdentityReader, jwt: JwtIssuerService,
    ledger: LegacyRefreshCredentialRepository, tokens: TokenIssuanceService, native: NativeIdentityService, passwords: AccountPasswordRepository,
    legacyEmail: LegacyEmailLinkService;
  let passwordHash: string, fingerprint: string, app: INestApplication | undefined, buildDirectory: string | undefined, baseUrl: string;
  const nativeCount = async () => Number((await db.query<RowDataPacket[]>("SELECT COUNT(*) AS n FROM identity_refresh_sessions"))[0][0].n);
  const ledgerRows = async () => (await db.query<RowDataPacket[]>("SELECT * FROM identity_legacy_refresh_credentials ORDER BY source_record_id"))[0];
  function manifest(raw = randomBytes(24).toString("base64url"), options: { expires?: number; revoked?: number; encoded?: boolean; a1?: boolean; server?: boolean; userId?: number; recordId?: number } = {}) {
    const userId = options.userId ?? 42, recordId = options.recordId ?? 7, expanded = options.expires !== undefined || options.encoded === true || options.revoked !== undefined;
    const fields: Record<string, string> = { id: String(recordId), user_id: String(userId), key: options.encoded ? hash(raw) : raw };
    if (expanded) Object.assign(fields, { session_id: "source-session", created_at: "1700000000", ...(options.expires === undefined ? {} : { expires_at: String(options.expires) }),
      ...(options.revoked === undefined ? {} : { revoked_at: String(options.revoked) }) });
    return { raw, data: exportLegacyRefreshCredentials({ version: 1, source, capturedAt: new Date(Date.now() - 10).toISOString(),
      accounts: [{ userId, accountFingerprint: fingerprint }], entries: [{ redisKey: `refresh_token:a:${recordId}`, type: "hash", pttl: -1,
        sourceKind: expanded ? "server" : "a1", keyEncoding: options.encoded ? "sha256-hex" : "plain", a1Compatible: options.a1 ?? !options.encoded, serverCompatible: options.server ?? true, fields }] }).manifest };
  }
  async function importOne(options: Parameters<typeof manifest>[1] = {}) { const input = manifest(undefined, options); await importLegacyRefreshCredentials(db, input.data, apply); return input; }
  async function reset() {
    await db.query("DELETE FROM identity_legacy_refresh_credentials;DELETE FROM identity_refresh_replays;DELETE FROM identity_refresh_sessions;DELETE FROM identity_user_revocations;DELETE FROM identity_login_codes;DELETE FROM identity_native_operations;DELETE FROM identity_account_password_requests;UPDATE identity_migration_control SET authority='staging',activated_at=NULL WHERE id=1");
    await db.execute("UPDATE user SET status=10,deleted_at=NULL,password_hash=?,auth_key=?,email=NULL,email_verified_at=NULL,password_reset_token=NULL WHERE id IN (1,42)", [passwordHash, authKey]);
    await db.query("DELETE FROM auth_assignment WHERE user_id='42';INSERT INTO auth_assignment(item_name,user_id) VALUES ('user','42')");
  }
  async function http(path: string, body?: unknown, headers: Record<string, string> = {}) {
    const response = await fetch(`${baseUrl}${path}`, { method: body === undefined ? "GET" : "POST", headers: { "content-type": "application/json", ...headers },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }), signal: AbortSignal.timeout(10_000) });
    return { status: response.status, body: await response.json() as any };
  }
  beforeAll(async () => {
    if (process.env.NODE_ENV === "production") throw new Error("Disposable fixture cannot run in production.");
    admin = await mysql.createConnection(opts); await admin.query(`CREATE DATABASE \`${name}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`);
    db = await mysql.createConnection({ ...opts, database: name });
    const init = await readFile(join(projectRoot, "deploy/mysql/init.sql"), "utf8"); await db.query(init.slice(init.indexOf("CREATE TABLE IF NOT EXISTS `auth_login_events`")));
    for (const schema of ["identity-account-schema.sql", "identity-runtime-schema.sql", "identity-password-reset-token-schema.sql", "identity-legacy-challenge-schema.sql", "identity-wechat-oauth-schema.sql", "identity-qrcode-schema.sql", "identity-apple-schema.sql"])
      await db.query(await readFile(join(projectRoot, "deploy/mysql", schema), "utf8"));
    const keys = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    for (const [key, value] of Object.entries({ IDENTITY_DATA_SOURCE: "identity", IDENTITY_DB_HOST: opts.host, IDENTITY_DB_PORT: String(opts.port),
      IDENTITY_DB_USER: opts.user, IDENTITY_DB_PASSWORD: opts.password, IDENTITY_DB_NAME: name, IDENTITY_TOKEN_ISSUANCE_ENABLED: "true",
      IDENTITY_TOKEN_ISSUANCE_INTERNAL_API_TOKEN: internal, IDENTITY_INTERNAL_API_TOKEN: internal, IDENTITY_IAM_INTERNAL_API_TOKEN: internal,
      IDENTITY_JWT_PRIVATE_KEY_PEM: keys.privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
      IDENTITY_JWT_PUBLIC_KEY_PEM: keys.publicKey.export({ type: "spki", format: "pem" }).toString(), IDENTITY_JWT_ISSUER: "https://legacy-refresh.test",
      IDENTITY_JWT_AUDIENCE: "private-api", IDENTITY_REFRESH_REPLAY_KEY: randomBytes(32).toString("base64url"), IDENTITY_LOGIN_AUDIT_ENABLED: "false",
      IDENTITY_IAM_ENABLED: "false", IDENTITY_OIDC_ENABLED: "false", LEGACY_DB_HOST: "127.0.0.1", LEGACY_DB_PORT: "1", LEGACY_DB_USER: "unreachable",
      LEGACY_WRITE_DB_HOST: "127.0.0.1", LEGACY_WRITE_DB_PORT: "1", LEGACY_WRITE_DB_USER: "unreachable" })) vi.stubEnv(key, value);
    passwordHash = await hashLegacyPassword(password); fingerprint = legacyRefreshAccountFingerprint(passwordHash, authKey);
    for (const [id, role] of [[1, "root"], [42, "user"]] as const) {
      await db.execute("INSERT INTO user(id,username,password_hash,auth_key,status,created_at,updated_at) VALUES (?,?,?,?,10,1,1)", [id, `legacy-user-${id}`, passwordHash, authKey]);
      await db.execute("INSERT INTO user_info(user_id) VALUES (?)", [id]); await db.execute("INSERT INTO auth_assignment(item_name,user_id) VALUES (?,?)", [role, String(id)]);
    }
    sessions = new IdentitySessionRepository(); jwt = new JwtIssuerService(); ledger = new LegacyRefreshCredentialRepository(sessions, jwt);
    reader = new LegacyIdentityReader(); native = new NativeIdentityService(reader, jwt, sessions);
    tokens = new TokenIssuanceService(reader, sessions, jwt, {} as LoginAuditService, ledger); passwords = new AccountPasswordRepository();
    legacyEmail = new LegacyEmailLinkService(tokens, sessions); await sessions.ensureSchema();
  }, 30_000);
  afterAll(async () => {
    await app?.close(); await Promise.all([sessions?.onModuleDestroy(), ledger?.onModuleDestroy(), reader?.onModuleDestroy(), native?.onModuleDestroy(), passwords?.onModuleDestroy(), legacyEmail?.onModuleDestroy()]);
    await db?.end(); if (admin) { await admin.query(`DROP DATABASE IF EXISTS \`${name}\``); await admin.end(); }
    if (buildDirectory) await rm(buildDirectory, { recursive: true, force: true }); vi.unstubAllEnvs();
  }, 30_000);

  describe("transactional importer and exchange", () => {
    beforeEach(reset);
    it("dry-runs without writes and imports hash-only permanent evidence idempotently", async () => {
      const input = manifest(); expect(await importLegacyRefreshCredentials(db, input.data)).toMatchObject({ applied: false, wouldImport: 1, imported: 0, permanent: 1 });
      expect(await ledgerRows()).toHaveLength(0); await importLegacyRefreshCredentials(db, input.data, apply);
      const rows = await ledgerRows(); expect(rows).toHaveLength(1); expect(rows[0].expires_at).toBeNull(); expect(rows[0].credential_hash).toBe(hash(input.raw));
      expect(JSON.stringify(rows)).not.toContain(input.raw); expect(JSON.stringify(rows)).not.toContain(passwordHash); expect(JSON.stringify(rows)).not.toContain(authKey);
      expect(await importLegacyRefreshCredentials(db, input.data, apply)).toMatchObject({ existing: 1, imported: 0 });
    });
    it("does not bind an old source credential to a changed target password or auth_key", async () => {
      for (const field of ["password_hash", "auth_key"]) {
        const input = manifest(); await db.query(`UPDATE user SET ${field}='changed' WHERE id=42`);
        await expect(importLegacyRefreshCredentials(db, input.data, apply)).rejects.toThrow("no longer match"); expect(await ledgerRows()).toHaveLength(0); await reset();
      }
    });
    it("fails both dry-run and apply when a cutoff has no trustworthy source issuance ordering", async () => {
      const input = manifest(); await db.query("INSERT INTO identity_user_revocations(user_id,revoked_before) VALUES (42,NOW(3))");
      await expect(importLegacyRefreshCredentials(db, input.data)).rejects.toThrow("review is required");
      await expect(importLegacyRefreshCredentials(db, input.data, apply)).rejects.toThrow("review is required"); expect(await ledgerRows()).toHaveLength(0);
    });
    it("rolls back all rows on missing accounts and honors the one-way authority fence", async () => {
      const first = manifest(), second = manifest(undefined, { userId: 43, recordId: 8 }); first.data.credentials.push(...second.data.credentials);
      await expect(importLegacyRefreshCredentials(db, first.data, apply)).rejects.toThrow("missing private account"); expect(await ledgerRows()).toHaveLength(0);
      await db.query("UPDATE identity_migration_control SET authority='identity' WHERE id=1");
      await expect(importLegacyRefreshCredentials(db, manifest().data, apply)).rejects.toThrow("already authoritative");
    });
    it("serializes eight competing first redemptions into one native family with an encrypted bounded replay", async () => {
      const input = await importOne(), results = await Promise.all(Array.from({ length: 8 }, () => tokens.refresh({ refreshToken: input.raw }, { idempotencyKey: "one-original-request" })));
      expect(new Set(results.map(result => result.token.refreshToken)).size).toBe(1); expect(await nativeCount()).toBe(1);
      expect(await native.verify(results[0].token.accessToken)).toMatchObject({ id: 42, roles: ["user"] });
      const rows = await ledgerRows(); expect(rows[0].session_id).toBe(jwt.verifyAccessToken(results[0].token.accessToken).sessionId);
      expect(rows[0].successor_hash).toBe(hash(results[0].token.refreshToken)); expect(rows[0].encrypted_response).toEqual(expect.any(String));
      expect(JSON.stringify(rows)).not.toContain(input.raw); expect(JSON.stringify(rows)).not.toContain(results[0].token.refreshToken);
      expect(JSON.stringify(rows)).not.toContain(results[0].token.accessToken);
    });
    it("checks original expiry for generic refresh while only reviewed plaintext can use the internal A1 exception", async () => {
      const expired = await importOne({ expires: Math.floor(Date.now() / 1000) - 10, a1: true });
      await expect(tokens.refresh({ refreshToken: expired.raw, consumer: "a1" })).rejects.toMatchObject({ status: 401 });
      const result = await tokens.refresh({ refreshToken: expired.raw }, {}, "a1"); expect(await native.verify(result.token.accessToken)).toMatchObject({ id: 42 });
      expect((await ledgerRows())[0].expires_at.getTime()).toBe(new Date(expired.data.credentials[0].expiresAt!).getTime());
      await expect(tokens.refresh({ refreshToken: expired.raw })).rejects.toMatchObject({ status: 401 });
      await reset(); const encoded = await importOne({ encoded: true, expires: Math.floor(Date.now() / 1000) + 100 });
      await expect(tokens.refresh({ refreshToken: encoded.raw }, {}, "a1")).rejects.toMatchObject({ status: 401 });
      expect((await tokens.refresh({ refreshToken: encoded.raw })).success).toBe(true);
    });
    it("keeps permanent A1-only evidence unavailable to the public/server consumer", async () => {
      const input = await importOne({ a1: true, server: false });
      expect((await ledgerRows())[0].expires_at).toBeNull();
      await expect(tokens.refresh({ refreshToken: input.raw, consumer: "a1" })).rejects.toMatchObject({ status: 401 });
      expect(await nativeCount()).toBe(0);
      expect((await tokens.refresh({ refreshToken: input.raw }, {}, "a1")).success).toBe(true);
      await expect(tokens.refresh({ refreshToken: input.raw })).rejects.toMatchObject({ status: 401 });
    });
    it.each(["revoked", "rotated", "oauth", "device_sn"])("rejects a native %s digest during dry-run and apply rather than downgrading its classification", async kind => {
      const sessionId = `existing-${kind}`, existing = await sessions.issue({ legacyUserId: 42, username: "legacy-user-42", sessionId,
        expiresAt: new Date(Date.now() + 600_000) });
      if (kind === "revoked" || kind === "rotated") await db.execute("UPDATE identity_refresh_sessions SET revoked_at=UTC_TIMESTAMP(3),replaced_by_hash=? WHERE refresh_token_hash=?",
        [kind === "rotated" ? "a".repeat(64) : null, existing.refreshTokenHash]);
      if (kind === "oauth") await db.execute("INSERT INTO identity_oauth_session_bindings(session_id,client_id,scopes_json) VALUES (?,?,?)", [sessionId, "isolated-client", '["openid"]']);
      if (kind === "device_sn") await db.execute("UPDATE identity_refresh_sessions SET auth_method='device_sn',device_sn_id=9 WHERE refresh_token_hash=?", [existing.refreshTokenHash]);
      const input = manifest(existing.refreshToken, { expires: Math.floor(Date.now() / 1000) + 600 });
      for (const options of [{}, apply]) await expect(importLegacyRefreshCredentials(db, input.data, options)).rejects.toThrow("existing native refresh classification");
      expect(await ledgerRows()).toHaveLength(0); expect(await nativeCount()).toBe(1);
    });
    it("rejects the reverse import order when a native session manifest reuses an imported AR digest", async () => {
      const input = await importOne(), now = Math.floor(Date.now() / 1000);
      const payload = { version: 1, sessions: [{ keyEncoding: "plain", key: input.raw, user_id: 42, session_id: "conflicting-native-family",
        created_at: now - 10, expires_at: now + 600, revoked_at: null, client: null }] };
      for (const options of [{}, apply]) await expect(importLegacySessions(db, payload, options)).rejects.toThrow("imported Yii AR credential classification");
      expect(await nativeCount()).toBe(0); expect(await ledgerRows()).toHaveLength(1);
    });
    it("rejects an already known native tombstone even if a conflicting legacy row was inserted out of band", async () => {
      const input = await importOne();
      await db.execute(`INSERT INTO identity_refresh_sessions(refresh_token_hash,session_id,legacy_user_id,username,issued_at,expires_at,revoked_at)
        VALUES (?,'known-native-tombstone',42,'legacy-user-42',DATE_SUB(UTC_TIMESTAMP(3),INTERVAL 10 SECOND),DATE_ADD(UTC_TIMESTAMP(3),INTERVAL 600 SECOND),UTC_TIMESTAMP(3))`, [hash(input.raw)]);
      expect(await tokens.hasRefreshCredential(input.raw)).toBe(true);
      await expect(tokens.refresh({ refreshToken: input.raw })).rejects.toMatchObject({ status: 401 });
      await expect(tokens.refresh({ refreshToken: input.raw }, {}, "a1")).rejects.toMatchObject({ status: 401 });
      await expect(ledger.redeem(input.raw, {}, "a1")).rejects.toMatchObject({ status: 401 });
      expect((await ledgerRows())[0].redeemed_at).toBeNull(); expect(await nativeCount()).toBe(1);
    });
    it("rejects source-revoked credentials under every consumer", async () => {
      const input = await importOne({ revoked: Math.floor(Date.now() / 1000) - 1, a1: true });
      for (const consumer of ["a1", "server"] as const) await expect(tokens.refresh({ refreshToken: input.raw }, {}, consumer)).rejects.toMatchObject({ status: 401 });
      expect(await ledger.hasCredential(input.raw)).toBe(true); expect(await nativeCount()).toBe(0);
    });
    it("never reconstructs a family after its original successor rotates or logs out", async () => {
      const input = await importOne(), first = await tokens.refresh({ refreshToken: input.raw });
      const next = await tokens.refresh({ refreshToken: first.token.refreshToken }); expect(await nativeCount()).toBe(2);
      await expect(tokens.refresh({ refreshToken: input.raw })).rejects.toMatchObject({ status: 401 });
      await tokens.logout({ refreshToken: next.token.refreshToken });
      expect((await ledgerRows())[0].revoked_at).not.toBeNull(); expect((await ledgerRows())[0].encrypted_response).toBeNull();
      await expect(tokens.refresh({ refreshToken: input.raw })).rejects.toMatchObject({ status: 401 });
      expect(await importLegacyRefreshCredentials(db, input.data, apply)).toMatchObject({ existing: 1, imported: 0 });
      expect((await ledgerRows())[0].revoked_at).not.toBeNull(); expect(await ledger.hasCredential(input.raw)).toBe(true);
    });
    it("records logout before first redemption as a permanent known tombstone", async () => {
      const input = await importOne(); expect(await tokens.logout({ refreshToken: input.raw })).toMatchObject({ revoked: true });
      await expect(tokens.refresh({ refreshToken: input.raw }, {}, "a1")).rejects.toMatchObject({ status: 401 });
      await importLegacyRefreshCredentials(db, input.data, apply); expect(await ledger.hasCredential(input.raw)).toBe(true); expect(await nativeCount()).toBe(0);
    });
    it("serializes logout against an in-flight first exchange and revokes its newly committed family", async () => {
      const input = await importOne(), original = sessions.issueInTransaction.bind(sessions);
      let entered!: () => void, release!: () => void;
      const started = new Promise<void>(resolve => { entered = resolve; }), gate = new Promise<void>(resolve => { release = resolve; });
      const paused = vi.spyOn(sessions, "issueInTransaction").mockImplementationOnce(async (connection, next) => {
        entered(); await gate; return original(connection, next);
      });
      try {
        const pending = tokens.refresh({ refreshToken: input.raw }); await started;
        const logout = tokens.logout({ refreshToken: input.raw }); release();
        const [issued, result] = await Promise.all([pending, logout]); expect(result.revoked).toBe(true);
        await expect(native.verify(issued.token.accessToken)).rejects.toMatchObject({ status: 401 });
        await expect(tokens.refresh({ refreshToken: input.raw })).rejects.toMatchObject({ status: 401 });
        await expect(tokens.refresh({ refreshToken: issued.token.refreshToken })).rejects.toMatchObject({ status: 401 });
        expect((await ledgerRows())[0].revoked_at).not.toBeNull(); expect(await nativeCount()).toBe(1);
      } finally { release(); paused.mockRestore(); }
    });
    it("limits anonymous retries to five seconds and matching idempotency retries to thirty seconds", async () => {
      const input = await importOne(), response = await tokens.refresh({ refreshToken: input.raw }, { idempotencyKey: "owner" });
      await db.query("UPDATE identity_legacy_refresh_credentials SET redeemed_at=DATE_SUB(UTC_TIMESTAMP(3),INTERVAL 6 SECOND)");
      await expect(tokens.refresh({ refreshToken: input.raw })).rejects.toMatchObject({ status: 401 });
      await expect(tokens.refresh({ refreshToken: input.raw }, { idempotencyKey: "other" })).rejects.toMatchObject({ status: 401 });
      expect(await tokens.refresh({ refreshToken: input.raw }, { idempotencyKey: "owner" })).toEqual(response);
      await db.query("UPDATE identity_legacy_refresh_credentials SET replay_expires_at=DATE_SUB(UTC_TIMESTAMP(3),INTERVAL 1 SECOND)");
      await expect(tokens.refresh({ refreshToken: input.raw }, { idempotencyKey: "owner" })).rejects.toMatchObject({ status: 401 }); expect(await nativeCount()).toBe(1);
    });
    it("replays with an existing standard-base64 native encryption key", async () => {
      const configured = process.env.IDENTITY_REFRESH_REPLAY_KEY!;
      vi.stubEnv("IDENTITY_REFRESH_REPLAY_KEY", Buffer.from(configured, "base64url").toString("base64"));
      try {
        const input = await importOne(), first = await tokens.refresh({ refreshToken: input.raw }, { idempotencyKey: "base64-key" });
        expect(await tokens.refresh({ refreshToken: input.raw }, { idempotencyKey: "base64-key" })).toEqual(first);
        expect(await nativeCount()).toBe(1);
      } finally { vi.stubEnv("IDENTITY_REFRESH_REPLAY_KEY", configured); }
    });
    it("does not allow replay without an encryption key or after credential/family tampering", async () => {
      const key = process.env.IDENTITY_REFRESH_REPLAY_KEY!; vi.stubEnv("IDENTITY_REFRESH_REPLAY_KEY", "");
      const input = await importOne(); await tokens.refresh({ refreshToken: input.raw });
      await expect(tokens.refresh({ refreshToken: input.raw })).rejects.toMatchObject({ status: 401 }); vi.stubEnv("IDENTITY_REFRESH_REPLAY_KEY", key);
      await reset(); const encrypted = await importOne(); await tokens.refresh({ refreshToken: encrypted.raw });
      await db.query("UPDATE identity_legacy_refresh_credentials SET session_id='tampered-family'");
      await expect(tokens.refresh({ refreshToken: encrypted.raw })).rejects.toMatchObject({ status: 401 });
    });
    it("cryptographically binds a replay response to its original credential and native family", async () => {
      const first = await importOne(), second = await importOne({ recordId: 8 });
      await tokens.refresh({ refreshToken: first.raw }, { idempotencyKey: "first" });
      const secondResponse = await tokens.refresh({ refreshToken: second.raw }, { idempotencyKey: "second" });
      const rows = await ledgerRows();
      await db.execute("UPDATE identity_legacy_refresh_credentials SET encrypted_response=? WHERE credential_hash=?", [rows[1].encrypted_response, hash(first.raw)]);
      await expect(tokens.refresh({ refreshToken: first.raw }, { idempotencyKey: "first" })).rejects.toMatchObject({ status: 401 });
      expect(await tokens.refresh({ refreshToken: second.raw }, { idempotencyKey: "second" })).toEqual(secondResponse);
      expect(await nativeCount()).toBe(2);
    });
    it("rolls back the credential exchange if native session creation fails", async () => {
      const input = await importOne(), failure = vi.spyOn(sessions, "issueInTransaction").mockRejectedValueOnce(new Error("fixture session failure"));
      try { await expect(tokens.refresh({ refreshToken: input.raw })).rejects.toThrow("fixture session failure"); }
      finally { failure.mockRestore(); }
      expect((await ledgerRows())[0].redeemed_at).toBeNull(); expect(await nativeCount()).toBe(0);
      expect((await tokens.refresh({ refreshToken: input.raw })).success).toBe(true);
    });
    it("checks current credentials, roles, status and cutoff rather than source metadata", async () => {
      const input = await importOne(); await db.query("UPDATE auth_assignment SET item_name='admin' WHERE user_id='42'");
      const response = await tokens.refresh({ refreshToken: input.raw }); expect(await native.verify(response.token.accessToken)).toMatchObject({ roles: ["admin"] });
      for (const sql of ["UPDATE user SET auth_key='changed' WHERE id=42", "UPDATE user SET password_hash='changed' WHERE id=42", "UPDATE user SET status=0 WHERE id=42", "UPDATE user SET deleted_at=1 WHERE id=42"]) {
        await db.execute("UPDATE user SET auth_key=?,password_hash=?,status=10,deleted_at=NULL WHERE id=42", [authKey, passwordHash]); await db.query(sql);
        await expect(tokens.refresh({ refreshToken: input.raw })).rejects.toMatchObject({ status: 401 });
      }
      await db.execute("UPDATE user SET auth_key=?,password_hash=?,status=10,deleted_at=NULL WHERE id=42", [authKey, passwordHash]);
      await sessions.revokeUserSessions(42); await expect(tokens.refresh({ refreshToken: input.raw })).rejects.toMatchObject({ status: 401 });
      expect((await ledgerRows())[0].revoked_at).not.toBeNull();
    });
    it("atomically invalidates unredeemed legacy credentials on real password changes", async () => {
      const input = await importOne(), credential = await passwords.getCredentialById(42); await passwords.changePassword(credential!, "Changed-password!94");
      expect((await ledgerRows())[0].revoked_at).not.toBeNull(); await expect(tokens.refresh({ refreshToken: input.raw }, {}, "a1")).rejects.toMatchObject({ status: 401 });
    });
    it("consumes a real native reset token and invalidates the legacy credential in the password transaction", async () => {
      const input = await importOne(), resetToken = randomBytes(32).toString("base64url"), email = "reset-legacy@example.test";
      await db.execute("UPDATE user SET email=?,email_verified_at=1 WHERE id=42", [email]);
      await db.execute(`INSERT INTO identity_password_reset_tokens(token_hash,legacy_user_id,email,issued_at,expires_at)
        VALUES (?,42,?,UTC_TIMESTAMP(3),DATE_ADD(UTC_TIMESTAMP(3),INTERVAL 60 SECOND))`, [hash(resetToken), email]);
      await passwords.changePassword((await passwords.getCredentialById(42))!, "Reset-password!94", { operationKey: "legacy-native-reset", resetTokenHash: hash(resetToken) });
      const [proof] = await db.execute<RowDataPacket[]>("SELECT consumed_at FROM identity_password_reset_tokens WHERE token_hash=?", [hash(resetToken)]);
      expect(proof[0].consumed_at).not.toBeNull(); expect((await ledgerRows())[0].revoked_at).not.toBeNull();
      await expect(tokens.refresh({ refreshToken: input.raw }, {}, "a1")).rejects.toMatchObject({ status: 401 });
    });
    it("consumes an existing Yii email reset link and permanently revokes the exchanged family", async () => {
      const input = await importOne(), issued = await tokens.refresh({ refreshToken: input.raw }), resetToken = `${randomBytes(24).toString("base64url")}_${Math.floor(Date.now() / 1000)}`;
      await db.execute("UPDATE user SET password_reset_token=? WHERE id=42", [resetToken]);
      expect(await legacyEmail.reset({ token: resetToken, password: "Email-reset!94" }, "legacy-email-reset")).toMatchObject({ userId: 42 });
      const [account] = await db.query<RowDataPacket[]>("SELECT password_reset_token FROM user WHERE id=42"); expect(account[0].password_reset_token).toBeNull();
      expect((await ledgerRows())[0].revoked_at).not.toBeNull(); expect((await ledgerRows())[0].encrypted_response).toBeNull();
      await expect(native.verify(issued.token.accessToken)).rejects.toMatchObject({ status: 401 });
      await expect(tokens.refresh({ refreshToken: input.raw })).rejects.toMatchObject({ status: 401 });
    });
    it("does not revive legacy credentials after native disable/reactivate", async () => {
      const input = await importOne(), root = await tokens.issueLegacyUserToken({ legacyUserId: 1 });
      for (const status of [0, 10]) await native.pluginWrite({ headers: { authorization: `Bearer ${root.token.accessToken}`,
        "idempotency-key": `legacy-disable-${status}` }, body: { id: 42, status } }, "update-user");
      expect((await ledgerRows())[0].revoked_at).not.toBeNull(); await expect(tokens.refresh({ refreshToken: input.raw }, {}, "a1")).rejects.toMatchObject({ status: 401 });
    });
  });

  describe("compiled AppModule HTTP consumers", () => {
    const fixtures = new Map<number, string>();
    let cliReport: Record<string, unknown>;
    beforeAll(async () => {
      await reset();
      for (const id of [42, 43, 44, 45, 46, 47]) {
        if (id !== 42) {
          await db.execute("INSERT INTO user(id,username,password_hash,auth_key,status,created_at,updated_at) VALUES (?,?,?,?,10,1,1)", [id, `legacy-user-${id}`, passwordHash, authKey]);
          await db.execute("INSERT INTO user_info(user_id) VALUES (?)", [id]); await db.execute("INSERT INTO auth_assignment(item_name,user_id) VALUES ('user',?)", [String(id)]);
        }
        const input = manifest(undefined, { userId: id, recordId: id, expires: Math.floor(Date.now() / 1000) - 10, a1: id !== 47 });
        fixtures.set(id, input.raw); await importLegacyRefreshCredentials(db, input.data, apply);
      }
      // Production emit is required to exercise Nest's real constructor metadata and provider graph.
      buildDirectory = await mkdtemp(join(projectRoot, ".identity-legacy-refresh-build-"));
      await promisify(execFile)(process.execPath, [join(projectRoot, "node_modules/typescript/bin/tsc"), "--outDir", buildDirectory, "--noEmitOnError", "true"],
        { cwd: projectRoot, timeout: 90_000, maxBuffer: 1024 * 1024 });
      const raw = randomBytes(24).toString("base64url"), snapshotFile = join(buildDirectory, "protected-snapshot.json"), manifestFile = join(buildDirectory, "protected-manifest.json");
      await writeFile(snapshotFile, JSON.stringify({ version: 1, source, capturedAt: new Date(Date.now() - 10).toISOString(), accounts: [{ userId: 42, accountFingerprint: fingerprint }],
        entries: [{ redisKey: "refresh_token:a:99", type: "hash", pttl: -1, sourceKind: "a1", keyEncoding: "plain", a1Compatible: true, serverCompatible: false, fields: { id: "99", user_id: "42", key: raw } }] }), { mode: 0o600 });
      const exported = await promisify(execFile)(process.execPath, [join(buildDirectory, "scripts/legacy-refresh-credential-export.js"), `--snapshot=${snapshotFile}`, `--out=${manifestFile}`]);
      expect(exported.stdout).not.toContain(raw); expect((await stat(manifestFile)).mode & 0o077).toBe(0);
      expect(await readFile(manifestFile, "utf8")).not.toContain(raw);
      const imported = await promisify(execFile)(process.execPath, [join(buildDirectory, "scripts/legacy-refresh-credential-import.js"), `--file=${manifestFile}`, "--apply"],
        { env: { ...process.env, NODE_ENV: "staging" } });
      cliReport = JSON.parse(imported.stdout); expect(imported.stdout).not.toContain(raw); expect(imported.stdout).not.toContain(fingerprint);
      const { AppModule } = await import(pathToFileURL(join(buildDirectory, "apps/identity-adapter/src/app.module.js")).href);
      app = await NestFactory.create(AppModule, { logger: false, abortOnError: false }); await app.listen(0, "127.0.0.1"); baseUrl = await app.getUrl();
    }, 120_000);
    it("runs the compiled standalone exporter and staging importer against the private fixture before activation", () => {
      expect(cliReport).toMatchObject({ applied: true, total: 1, imported: 1, permanent: 1, notFinal: true });
    });
    it("requires internal auth and never lets public consumer fields activate the A1 expiry exception", async () => {
      const raw = fixtures.get(42)!;
      expect((await http("/internal/yii3/refresh", { refreshToken: raw, allowLoginCode: false, consumer: "a1" })).status).toBe(401);
      expect((await http("/v1/auth/refresh", { refreshToken: raw, consumer: "a1" })).status).toBe(401);
      expect((await http("/v1/auth/refresh", { refreshToken: raw, consumer: "a1" }, { "x-identity-internal-token": internal })).status).toBe(401);
      const result = await http("/internal/yii3/refresh", { refreshToken: raw, allowLoginCode: false, consumer: "a1" }, { "x-identity-internal-token": internal });
      expect(result.status).toBe(201); expect(result.body.subject).toMatchObject({ id: 42, status: 10, roles: ["user"] });
      const info = await http("/v1/user/info", undefined, { authorization: `Bearer ${result.body.authTokens.accessToken}` }); expect(info.status).toBe(200);
    });
    it("keeps nonreviewed plaintext on source expiry and rejects unknown consumers or A1 login-code mode", async () => {
      const headers = { "x-identity-internal-token": internal }, raw = fixtures.get(47)!;
      expect((await http("/internal/yii3/refresh", { refreshToken: raw, allowLoginCode: false, consumer: "a1" }, headers)).status).toBe(401);
      expect((await http("/internal/yii3/refresh", { refreshToken: raw, allowLoginCode: false, consumer: "other" }, headers)).status).toBe(400);
      expect((await http("/internal/yii3/refresh", { refreshToken: raw, allowLoginCode: true, consumer: "a1" }, headers)).status).toBe(400);
    });
    it("does not fall back from raw or wrapped revoked legacy refresh to a matching live code", async () => {
      const raw = fixtures.get(43)!, now = Math.floor(Date.now() / 1000), headers = { "x-identity-internal-token": internal };
      await http("/v1/auth/logout", { refreshToken: raw });
      await db.execute("INSERT INTO identity_login_codes(code_hash,user_id,issued_at,expires_at,context_json) VALUES (?,43,?,?,?)", [hash(raw), now, now + 60, "{}"]);
      for (const wrapped of [raw, `web_${raw}`, `https://frontend.test/login?web_${raw}`]) {
        expect((await http("/internal/yii3/refresh", { refreshToken: wrapped, allowLoginCode: true }, headers)).status).toBe(401);
        expect((await http("/v1/auth/refresh", { refreshToken: wrapped })).status).toBe(401);
      }
      const [rows] = await db.query<RowDataPacket[]>("SELECT id FROM identity_refresh_sessions WHERE legacy_user_id=43"); expect(rows).toHaveLength(0);
    });
    it("revokes the bound native family and legacy tombstone through real logout HTTP", async () => {
      const raw = fixtures.get(44)!, headers = { "x-identity-internal-token": internal };
      const first = await http("/internal/yii3/refresh", { refreshToken: raw, allowLoginCode: false, consumer: "a1" }, headers); expect(first.status).toBe(201);
      expect((await http("/v1/auth/logout", { refreshToken: first.body.authTokens.refreshToken })).status).toBe(201);
      expect((await http("/internal/yii3/refresh", { refreshToken: raw, allowLoginCode: false, consumer: "a1" }, headers)).status).toBe(401);
      expect((await http("/v1/user/info", undefined, { authorization: `Bearer ${first.body.authTokens.accessToken}` })).status).toBe(401);
    });
    it("cannot import another source snapshot after the actual app activates private authority", async () => {
      await expect(importLegacyRefreshCredentials(db, manifest(undefined, { recordId: 99 }).data, apply)).rejects.toThrow("already authoritative");
    });
  });
});
