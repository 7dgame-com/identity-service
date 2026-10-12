import "reflect-metadata";
import { readFile } from "node:fs/promises";
import { randomUUID, createHash } from "node:crypto";
import mysql, { type Connection, type RowDataPacket } from "mysql2/promise";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { importLegacySessions } from "../src/legacy-session-import.js";
import { IdentitySessionRepository } from "../src/identity-session.repository.js";

const enabled = process.env.IDENTITY_TEST_MYSQL === "1";
const options = {
  host: process.env.IDENTITY_DB_HOST ?? "127.0.0.1",
  port: Number(process.env.IDENTITY_DB_PORT ?? 3306),
  user: process.env.IDENTITY_DB_USER ?? "root",
  password: process.env.IDENTITY_DB_PASSWORD ?? "",
  multipleStatements: true,
  timezone: "Z",
};
const name = `test_legacy_sessions_${randomUUID().replaceAll("-", "")}`;
let admin: Connection, db: Connection, sessions: IdentitySessionRepository;
const digest = (key: string) => createHash("sha256").update(key).digest("hex");
const row = (key: string, extra: Record<string, unknown> = {}) => ({
  keyEncoding: "plain",
  key,
  user_id: 24,
  session_id: `session-${key}`,
  created_at: 1700000000,
  expires_at: "2099-01-01T00:00:00.000Z",
  revoked_at: null,
  client: null,
  ...extra,
});
const payload = (...rows: unknown[]) => ({ version: 1, sessions: rows });
const apply = { apply: true, environment: "staging" };

describe.skipIf(!enabled)("legacy refresh session MySQL import", () => {
  beforeAll(async () => {
    if (!["127.0.0.1", "localhost", "::1"].includes(options.host))
      throw new Error(
        "Session import integration requires a disposable local MySQL instance.",
      );
    admin = await mysql.createConnection(options);
    await admin.query(`CREATE DATABASE \`${name}\` CHARACTER SET utf8mb4`);
    db = await mysql.createConnection({ ...options, database: name });
    const init = await readFile(
      new URL("../../../deploy/mysql/init.sql", import.meta.url),
      "utf8",
    );
    await db.query(
      init.slice(
        init.indexOf("CREATE TABLE IF NOT EXISTS `auth_login_events`"),
      ),
    );
    await db.query(
      await readFile(
        new URL(
          "../../../deploy/mysql/identity-account-schema.sql",
          import.meta.url,
        ),
        "utf8",
      ),
    );
    await db.query(
      await readFile(
        new URL(
          "../../../deploy/mysql/identity-runtime-schema.sql",
          import.meta.url,
        ),
        "utf8",
      ),
    );
    await db.query(
      await readFile(
        new URL(
          "../../../deploy/mysql/identity-wechat-oauth-schema.sql",
          import.meta.url,
        ),
        "utf8",
      ),
    );
    await db.query(
      "INSERT INTO user (id,username,status) VALUES (24,'old-user',10),(25,'other-user',10)",
    );
    vi.stubEnv("IDENTITY_DATA_SOURCE", "identity");
    vi.stubEnv("IDENTITY_DB_HOST", options.host);
    vi.stubEnv("IDENTITY_DB_PORT", String(options.port));
    vi.stubEnv("IDENTITY_DB_USER", options.user);
    vi.stubEnv("IDENTITY_DB_PASSWORD", options.password);
    vi.stubEnv("IDENTITY_DB_NAME", name);
    vi.stubEnv(
      "IDENTITY_REFRESH_REPLAY_KEY",
      Buffer.alloc(32, 7).toString("base64url"),
    );
    sessions = new IdentitySessionRepository();
  }, 30_000);
  afterAll(async () => {
    await sessions?.onModuleDestroy();
    await db?.end();
    if (admin) {
      await admin.query(`DROP DATABASE IF EXISTS \`${name}\``);
      await admin.end();
    }
    vi.unstubAllEnvs();
  });

  it("imports declared plaintext and hash keys as usable existing credentials with exact original metadata", async () => {
    const plain = "a".repeat(64),
      hashedToken = "pre-hashed-legacy-token";
    const report = await importLegacySessions(
      db,
      payload(
        row(plain, {
          session_id: "legacy-fixed-family",
          ip_hash: "b".repeat(64),
          user_agent: "unity-agent",
        }),
        row(digest(hashedToken), {
          keyEncoding: "sha256-hex",
          session_id: "hashed-family",
        }),
      ),
      apply,
    );
    expect(report).toMatchObject({
      imported: 2,
      wouldImport: 2,
      applied: true,
    });
    expect(await sessions.findValidSession(plain)).toMatchObject({
      legacyUserId: 24,
      sessionId: "legacy-fixed-family",
    });
    expect(await sessions.findValidSession(hashedToken)).toMatchObject({
      sessionId: "hashed-family",
    });
    const [stored] = await db.execute<RowDataPacket[]>(
      "SELECT * FROM identity_refresh_sessions WHERE refresh_token_hash=?",
      [digest(plain)],
    );
    expect(stored[0].issued_at.toISOString()).toBe("2023-11-14T22:13:20.000Z");
    expect(stored[0].expires_at.toISOString()).toBe("2099-01-01T00:00:00.000Z");
    expect(stored[0].ip_hash).toBe("b".repeat(64));
    expect(stored[0].user_agent_hash).toBe(digest("unity-agent"));
  });

  it("never overwrites a rotated predecessor or revives its successor family", async () => {
    const original = row("rotate-before-reimport");
    await importLegacySessions(db, payload(original), apply);
    const next = await sessions.rotate(original.key, {
      legacyUserId: 24,
      username: "old-user",
      sessionId: original.session_id,
      expiresAt: new Date("2099-01-02"),
    });
    const report = await importLegacySessions(
      db,
      payload(
        original,
        row("old-sibling", { session_id: original.session_id }),
      ),
      apply,
    );
    expect(report).toMatchObject({ existing: 1, protected: 1, imported: 0 });
    const [stored] = await db.execute<RowDataPacket[]>(
      "SELECT revoked_at,replaced_by_hash FROM identity_refresh_sessions WHERE refresh_token_hash=?",
      [digest(original.key)],
    );
    expect(stored[0].revoked_at).toBeInstanceOf(Date);
    expect(stored[0].replaced_by_hash).toBe(next.refreshTokenHash);
    await sessions.revoke(next.refreshToken);
    await importLegacySessions(db, payload(original), apply);
    await expect(
      sessions.findValidSession(next.refreshToken),
    ).rejects.toThrow();
  });

  it("retains expired/revoked records without extending them or making them usable", async () => {
    await importLegacySessions(
      db,
      payload(
        row("expired", { expires_at: 1700000200 }),
        row("revoked", { revoked_at: 1700000100 }),
      ),
      apply,
    );
    await expect(sessions.findValidSession("expired")).rejects.toThrow();
    await expect(sessions.findValidSession("revoked")).rejects.toThrow();
    const [stored] = await db.execute<RowDataPacket[]>(
      "SELECT expires_at,revoked_at FROM identity_refresh_sessions WHERE refresh_token_hash IN (?,?) ORDER BY refresh_token_hash",
      [digest("expired"), digest("revoked")],
    );
    expect(
      stored.some(
        (r) => r.expires_at.toISOString() === "2023-11-14T22:16:40.000Z",
      ),
    ).toBe(true);
    expect(
      stored.some(
        (r) => r.revoked_at?.toISOString() === "2023-11-14T22:15:00.000Z",
      ),
    ).toBe(true);
  });

  it("rolls back the complete batch if one account is missing", async () => {
    await expect(
      importLegacySessions(
        db,
        payload(
          row("rollback-first"),
          row("rollback-missing", { user_id: 999 }),
        ),
        apply,
      ),
    ).rejects.toThrow("missing identity account");
    const [stored] = await db.execute<RowDataPacket[]>(
      "SELECT id FROM identity_refresh_sessions WHERE refresh_token_hash=?",
      [digest("rollback-first")],
    );
    expect(stored).toHaveLength(0);
  });

  it("preserves exact client scope and rejects widening a preexisting session binding", async () => {
    const bound = row("scoped", {
      client: {
        client_id: "unity",
        scopes: ["openid", "profile"],
        legacy_subject: "old-subject",
      },
    });
    await importLegacySessions(db, payload(bound), apply);
    const [bindings] = await db.execute<RowDataPacket[]>(
      "SELECT client_id,scopes_json,legacy_subject FROM identity_oauth_session_bindings WHERE session_id=?",
      [bound.session_id],
    );
    expect(bindings[0]).toMatchObject({
      client_id: "unity",
      scopes_json: ["openid", "profile"],
      legacy_subject: "old-subject",
    });
    await expect(
      importLegacySessions(
        db,
        payload(
          row("scope-widening", {
            session_id: bound.session_id,
            client: {
              client_id: "unity",
              scopes: ["openid", "profile", "admin"],
              legacy_subject: "old-subject",
            },
          }),
        ),
        apply,
      ),
    ).rejects.toThrow("client scope conflict");
    await expect(
      importLegacySessions(
        db,
        payload(row("scope-removal", { session_id: bound.session_id })),
        apply,
      ),
    ).rejects.toThrow("client scope conflict");
  });

  it("serializes two import connections so the same credential is inserted once", async () => {
    const other = await mysql.createConnection({ ...options, database: name });
    try {
      const reports = await Promise.all([
        importLegacySessions(db, payload(row("parallel")), apply),
        importLegacySessions(other, payload(row("parallel")), apply),
      ]);
      expect(reports.reduce((sum, report) => sum + report.imported, 0)).toBe(1);
      expect(reports.reduce((sum, report) => sum + report.existing, 0)).toBe(1);
    } finally {
      await other.end();
    }
  });

  it("keeps dry-run write free and respects account-wide revocations", async () => {
    expect(
      await importLegacySessions(db, payload(row("dry-run"))),
    ).toMatchObject({ imported: 0, wouldImport: 1, applied: false });
    await db.execute(
      "INSERT INTO identity_user_revocations (user_id,revoked_before) VALUES (25,?)",
      [new Date("2024-01-01T00:00:00Z")],
    );
    expect(
      await importLegacySessions(
        db,
        payload(row("revoked-account", { user_id: 25 })),
        apply,
      ),
    ).toMatchObject({ imported: 0, protected: 1 });
    const [stored] = await db.execute<RowDataPacket[]>(
      "SELECT id FROM identity_refresh_sessions WHERE refresh_token_hash IN (?,?)",
      [digest("dry-run"), digest("revoked-account")],
    );
    expect(stored).toHaveLength(0);
  });
  it("permanently rejects apply after native authority activation regardless of staging environment", async () => {
    await db.execute(
      "UPDATE identity_migration_control SET authority='identity' WHERE id=1",
    );
    await expect(
      importLegacySessions(db, payload(row("too-late")), apply),
    ).rejects.toThrow("already authoritative");
    const [stored] = await db.execute<RowDataPacket[]>(
      "SELECT id FROM identity_refresh_sessions WHERE refresh_token_hash=?",
      [digest("too-late")],
    );
    expect(stored).toHaveLength(0);
  });
});
