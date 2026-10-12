import "reflect-metadata";
import { readFile } from "node:fs/promises";
import { randomUUID, createHash } from "node:crypto";
import mysql, { type Connection, type RowDataPacket } from "mysql2/promise";
import {
  beforeAll,
  beforeEach,
  afterAll,
  describe,
  expect,
  it,
  vi,
} from "vitest";
import {
  importLegacyChallenges,
  normalizeLegacyChallengeManifest,
} from "../src/legacy-challenge-import.js";
import { PasswordResetChallengeRepository } from "../src/password-reset-challenge.repository.js";
import { EmailVerificationChallengeRepository } from "../src/email-verification-challenge.repository.js";
import { EmailChangeTokenRepository } from "../src/email-change-token.repository.js";

const enabled = process.env.IDENTITY_TEST_MYSQL === "1";
const options = {
  host: process.env.IDENTITY_DB_HOST ?? "127.0.0.1",
  port: Number(process.env.IDENTITY_DB_PORT ?? 13316),
  user: process.env.IDENTITY_DB_USER ?? "identity_test",
  password: process.env.IDENTITY_DB_PASSWORD ?? "",
  multipleStatements: true,
  timezone: "Z",
};
const name = `test_legacy_challenges_${randomUUID().replaceAll("-", "")}`;
const salts = {
  passwordReset: "test-password-salt",
  emailVerification: "test-email-salt",
};
const apply = { apply: true, environment: "staging", salts };
const sha = (value: string) => createHash("sha256").update(value).digest("hex");
const address = "old@example.com";
const resetToken = "R".repeat(32),
  changeToken = "C".repeat(48);
const review = {
  email: address,
  user_id: 24,
  account_email: address,
  review_reference: "reviewed-final-account-and-request-24",
};
const record = (
  key: string,
  value: unknown,
  pttl = 300000,
  time = Date.now(),
) => ({
  key,
  value: typeof value === "string" ? value : JSON.stringify(value),
  redis_time_ms: time,
  pttl_ms: pttl,
  expires_at_ms: time + pttl,
});
const code = (
  kind: "password" | "email" = "password",
  time = Date.now(),
  pttl = 300000,
) =>
  record(
    kind === "password"
      ? `password:reset:code:${address}`
      : `email:verify:${address}`,
    kind === "password"
      ? {
          code: "123456",
          email: address,
          user_id: 24,
          created_at: Math.floor((time - 120000) / 1000),
        }
      : { code: "654321", created_at: Math.floor((time - 120000) / 1000) },
    pttl,
    time,
  );
const manifest = (records: unknown[], reviews: unknown[] = [review]) => ({
  version: 1,
  final_drained_snapshot: true,
  records,
  reviewed_email_associations: reviews,
});
let admin: Connection,
  db: Connection,
  password: PasswordResetChallengeRepository,
  email: EmailVerificationChallengeRepository,
  change: EmailChangeTokenRepository;

describe.skipIf(!enabled)("offline final legacy challenges MySQL", () => {
  beforeAll(async () => {
    if (!["127.0.0.1", "localhost", "::1"].includes(options.host))
      throw new Error("Disposable local MySQL required.");
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
    for (const file of [
      "identity-account-schema.sql",
      "identity-runtime-schema.sql",
      "identity-password-reset-token-schema.sql",
      "identity-legacy-challenge-schema.sql",
    ])
      await db.query(
        await readFile(
          new URL(`../../../deploy/mysql/${file}`, import.meta.url),
          "utf8",
        ),
      );
    await db.execute(
      "INSERT INTO user (id,username,email,status,email_verified_at) VALUES (24,'old-user',?,10,1700000000),(25,'other-user','other@example.com',10,1700000000)",
      [address],
    );
    vi.stubEnv("IDENTITY_DATA_SOURCE", "identity");
    vi.stubEnv("IDENTITY_DB_HOST", options.host);
    vi.stubEnv("IDENTITY_DB_PORT", String(options.port));
    vi.stubEnv("IDENTITY_DB_USER", options.user);
    vi.stubEnv("IDENTITY_DB_PASSWORD", options.password);
    vi.stubEnv("IDENTITY_DB_NAME", name);
    vi.stubEnv("IDENTITY_PASSWORD_RESET_CODE_HASH_SALT", salts.passwordReset);
    vi.stubEnv("IDENTITY_EMAIL_CODE_HASH_SALT", salts.emailVerification);
    password = new PasswordResetChallengeRepository();
    email = new EmailVerificationChallengeRepository();
    change = new EmailChangeTokenRepository();
  }, 30000);
  beforeEach(async () => {
    for (const table of [
      "password_reset_challenges",
      "email_verification_challenges",
      "email_change_tokens",
      "identity_password_reset_tokens",
      "identity_legacy_challenge_imports",
      "identity_legacy_challenge_limits",
    ])
      await db.query(`DELETE FROM ${table}`);
    await db.execute(
      "UPDATE identity_migration_control SET authority='staging' WHERE id=1",
    );
  });
  afterAll(async () => {
    await password?.onModuleDestroy();
    await email?.onModuleDestroy();
    await change?.onModuleDestroy();
    await db?.end();
    if (admin) {
      await admin.query(`DROP DATABASE IF EXISTS \`${name}\``);
      await admin.end();
    }
    vi.unstubAllEnvs();
  });

  it("preserves four existing credentials with native hashes and exact original deadlines", async () => {
    const now = Date.now(),
      issued = Math.floor((now - 120000) / 1000);
    const input = manifest([
      code("password", now),
      code("email", now),
      record(
        `password:reset:${resetToken}`,
        { email: address, user_id: 24, created_at: issued },
        600000,
        now,
      ),
      record("email:change:token:24", changeToken, 180000, now),
    ]);
    expect(await importLegacyChallenges(db, input, apply)).toMatchObject({
      applied: true,
      imported: 4,
    });
    expect(await password.verifyCode(address, "123456")).toMatchObject({
      legacyUserId: 24,
      codeHash: sha(`${salts.passwordReset}\x1f${address}\x1f123456`),
    });
    expect(await email.verifyCode(address, "654321")).toMatchObject({
      legacyUserId: 24,
    });
    expect(await password.findActiveByToken(resetToken)).toMatchObject({
      legacyUserId: 24,
      issuedAt: new Date(issued * 1000),
      expiresAt: new Date(now + 600000),
    });
    expect(await change.verifyToken(24, changeToken)).toMatchObject({
      legacyUserId: 24,
      expiresAt: new Date(now + 180000),
    });
    const [stored] = await db.query<RowDataPacket[]>(
      "SELECT * FROM identity_password_reset_tokens",
    );
    expect(stored[0].token_hash).toBe(sha(resetToken));
    expect(JSON.stringify(stored)).not.toContain(resetToken);
  });
  it("keeps dry-run write free and requires staging for apply", async () => {
    const input = manifest([code()]);
    expect(await importLegacyChallenges(db, input, { salts })).toMatchObject({
      applied: false,
      imported: 0,
      wouldImport: 1,
    });
    await expect(
      importLegacyChallenges(db, input, {
        apply: true,
        environment: "production",
        salts,
      }),
    ).rejects.toThrow("staging");
    const [rows] = await db.query<RowDataPacket[]>(
      "SELECT * FROM password_reset_challenges",
    );
    expect(rows).toHaveLength(0);
  });
  it("permanently rejects apply after private authority activation", async () => {
    await db.query(
      "UPDATE identity_migration_control SET authority='identity' WHERE id=1",
    );
    await expect(
      importLegacyChallenges(db, manifest([code()]), apply),
    ).rejects.toThrow("already authoritative");
  });
  it("refuses an email code without reviewed ownership instead of guessing from email", async () => {
    await expect(
      importLegacyChallenges(db, manifest([code("email")], []), apply),
    ).rejects.toThrow("unproven");
  });
  it("checks reviewed private account email and rolls back the whole batch", async () => {
    const bad = { ...review, account_email: "changed@example.com" };
    await expect(
      importLegacyChallenges(
        db,
        manifest([code(), code("email")], [bad]),
        apply,
      ),
    ).rejects.toThrow("association");
    const [rows] = await db.query<RowDataPacket[]>(
      "SELECT * FROM password_reset_challenges",
    );
    expect(rows).toHaveLength(0);
  });
  it("supports reviewed target email distinct from the current account email", async () => {
    const target = "new@example.com",
      row = code("email");
    row.key = `email:verify:${target}`;
    await importLegacyChallenges(
      db,
      manifest([row], [{ ...review, email: target }]),
      apply,
    );
    expect(await email.verifyCode(target, "654321")).toMatchObject({
      legacyUserId: 24,
      email: target,
    });
  });
  it("does not revive expired credentials or extend their lifetime", async () => {
    const row = code("password", Date.now() - 600000, 1000);
    await importLegacyChallenges(db, manifest([row]), apply);
    await expect(password.verifyCode(address, "123456")).rejects.toMatchObject({
      code: "INVALID_CODE",
    });
    const [rows] = await db.query<RowDataPacket[]>(
      "SELECT expires_at FROM password_reset_challenges",
    );
    expect(rows[0].expires_at.getTime()).toBe(row.redis_time_ms + row.pttl_ms);
  });
  it("retains consumed tokens and advanced attempts on idempotent replay", async () => {
    const row = code();
    const input = manifest([row]);
    await importLegacyChallenges(db, input, apply);
    const verified = await password.verifyCode(address, "123456");
    await password.consume(verified.challengeKey);
    await db.execute(
      "UPDATE password_reset_challenges SET attempts=7 WHERE challenge_key=?",
      [verified.challengeKey],
    );
    expect(await importLegacyChallenges(db, input, apply)).toMatchObject({
      existing: 1,
      imported: 0,
    });
    const [stored] = await db.query<RowDataPacket[]>(
      "SELECT attempts,consumed_at FROM password_reset_challenges",
    );
    expect(stored[0].attempts).toBe(7);
    expect(stored[0].consumed_at).toBeInstanceOf(Date);
    await expect(password.verifyCode(address, "123456")).rejects.toMatchObject({
      code: "INVALID_CODE",
    });
  });
  it("uses exact independent rate and lock deadlines when a code is reissued", async () => {
    const now = Date.now();
    await importLegacyChallenges(
      db,
      manifest([
        code("password", now),
        record(`password:reset:attempts:${address}`, "5", 80000, now),
        record(`email:ratelimit:request_reset:${address}`, "1", 45000, now),
      ]),
      apply,
    );
    await expect(
      password.createChallenge({ email: address, legacyUserId: 24 }),
    ).rejects.toMatchObject({ code: "RATE_LIMIT_EXCEEDED" });
    await db.execute(
      "UPDATE identity_legacy_challenge_limits SET rate_limit_until=UTC_TIMESTAMP(3)-INTERVAL 1 SECOND",
    );
    const next = await password.createChallenge({
      email: address,
      legacyUserId: 24,
    });
    await expect(password.verifyCode(address, next.code)).rejects.toMatchObject(
      { code: "ACCOUNT_LOCKED" },
    );
    const [limits] = await db.query<RowDataPacket[]>(
      "SELECT attempts,attempts_expires_at FROM identity_legacy_challenge_limits",
    );
    expect(limits[0].attempts).toBe(5);
    expect(limits[0].attempts_expires_at.getTime()).toBe(now + 80000);
  });
  it("increments the original attempt window atomically without extending it or resetting on send", async () => {
    const now = Date.now();
    await importLegacyChallenges(
      db,
      manifest([
        code("email", now),
        record(`email:verify:attempts:${address}`, "4", 80000, now),
      ]),
      apply,
    );
    const next = await email.createChallenge({
      email: address,
      legacyUserId: 24,
    });
    await expect(email.verifyCode(address, "wrong")).rejects.toMatchObject({
      code: "INVALID_CODE",
    });
    await expect(email.verifyCode(address, next.code)).rejects.toMatchObject({
      code: "ACCOUNT_LOCKED",
    });
    const [limits] = await db.query<RowDataPacket[]>(
      "SELECT attempts,attempts_expires_at FROM identity_legacy_challenge_limits",
    );
    expect(limits[0].attempts).toBe(5);
    expect(limits[0].attempts_expires_at.getTime()).toBe(now + 80000);
    const [newRows] = await db.query<RowDataPacket[]>(
      "SELECT attempts FROM email_verification_challenges WHERE challenge_key NOT LIKE 'legacy-challenge:%'",
    );
    expect(newRows[0].attempts).toBe(0);
  });
  it("does not enforce an already expired original attempt window on a new code", async () => {
    const now = Date.now() - 1000;
    await importLegacyChallenges(
      db,
      manifest([record(`email:verify:attempts:${address}`, "5", 0, now)]),
      apply,
    );
    const next = await email.createChallenge({
      email: address,
      legacyUserId: 24,
    });
    expect(await email.verifyCode(address, next.code)).toMatchObject({
      legacyUserId: 24,
    });
  });
  it("preserves rate-only keys without inventing a code or creation timestamp", async () => {
    await importLegacyChallenges(
      db,
      manifest([
        record(`email:ratelimit:send_verification:${address}`, "1", 50000),
      ]),
      apply,
    );
    expect(await email.getCooldown(address)).toMatchObject({ canSend: false });
    await expect(
      email.createChallenge({ email: address, legacyUserId: 24 }),
    ).rejects.toMatchObject({ code: "RATE_LIMIT_EXCEEDED" });
  });
  it("refuses changed final snapshots and cannot overwrite a newer native challenge", async () => {
    const row = code();
    await importLegacyChallenges(db, manifest([row]), apply);
    await expect(
      importLegacyChallenges(
        db,
        manifest([
          {
            ...row,
            pttl_ms: row.pttl_ms + 1,
            expires_at_ms: row.expires_at_ms + 1,
          },
        ]),
        apply,
      ),
    ).rejects.toThrow("Changed or stale");
    await db.query(
      "DELETE FROM identity_legacy_challenge_imports;DELETE FROM password_reset_challenges",
    );
    await password.createChallenge({ email: address, legacyUserId: 24 });
    await expect(
      importLegacyChallenges(db, manifest([row]), apply),
    ).rejects.toThrow("newer native");
  });
  it("serializes duplicate applies across connections", async () => {
    const input = manifest([code()]),
      other = await mysql.createConnection({ ...options, database: name });
    try {
      const reports = await Promise.all([
        importLegacyChallenges(db, input, apply),
        importLegacyChallenges(other, input, apply),
      ]);
      expect(reports.reduce((sum, r) => sum + r.imported, 0)).toBe(1);
      expect(reports.reduce((sum, r) => sum + r.existing, 0)).toBe(1);
    } finally {
      await other.end();
    }
  });
  it("rejects missing/negative TTL, excessive old TTL, arbitrary keys and weak reset-token shapes", () => {
    for (const row of [
      { ...code(), pttl_ms: -1 },
      record(`email:verify:attempts:${address}`, "5", 900001),
      record("arbitrary", "value"),
      record("password:reset:short", {
        email: address,
        user_id: 24,
        created_at: 1,
      }),
    ])
      expect(() =>
        normalizeLegacyChallengeManifest(manifest([row]), salts),
      ).toThrow();
    expect(() =>
      normalizeLegacyChallengeManifest(
        { ...manifest([code()]), final_drained_snapshot: false },
        salts,
      ),
    ).toThrow();
  });
  it("accepts baseline actor metadata only when code, issue and exact expiry agree", async () => {
    const row = code("email"),
      body = JSON.parse(row.value);
    const metadata = record(
      `identity:legacy_email_challenge:${sha(address)}`,
      {
        issuer: "yii-email-code-v1",
        user_id: 24,
        account_email: address,
        target_email: address,
        code_hash: sha(body.code),
        issued_at: body.created_at,
        expires_at_ms: row.expires_at_ms,
      },
      row.pttl_ms,
      row.redis_time_ms,
    );
    await importLegacyChallenges(db, manifest([row, metadata], []), apply);
    expect(await email.verifyCode(address, "654321")).toMatchObject({
      legacyUserId: 24,
    });
  });
  it("rejects forged/stale baseline code digests, deadlines and conflicting manual association", async () => {
    const row = code("email"),
      body = JSON.parse(row.value),
      base = {
        issuer: "yii-email-code-v1",
        user_id: 24,
        account_email: address,
        target_email: address,
        code_hash: sha(body.code),
        issued_at: body.created_at,
        expires_at_ms: row.expires_at_ms,
      };
    const metadata = (data: unknown) =>
      record(
        `identity:legacy_email_challenge:${sha(address)}`,
        data,
        row.pttl_ms,
        row.redis_time_ms,
      );
    for (const change of [
      { code_hash: sha("other-code") },
      { issued_at: body.created_at + 1 },
      { expires_at_ms: row.expires_at_ms + 1 },
    ])
      await expect(
        importLegacyChallenges(
          db,
          manifest([row, metadata({ ...base, ...change })], []),
          apply,
        ),
      ).rejects.toThrow();
    await expect(
      importLegacyChallenges(
        db,
        manifest([row, metadata(base)], [{ ...review, user_id: 25 }]),
        apply,
      ),
    ).rejects.toThrow();
  });
  it("allows proven initial email binding only while the private account still has no email", async () => {
    const target = "initial@example.com",
      row = code("email"),
      body = JSON.parse(row.value);
    row.key = `email:verify:${target}`;
    await db.execute(
      "INSERT INTO user (id,username,email,status) VALUES (26,'initial-user','',10) ON DUPLICATE KEY UPDATE email=''",
    );
    const metadata = record(
      `identity:legacy_email_challenge:${sha(target)}`,
      {
        issuer: "yii-email-code-v1",
        user_id: 26,
        account_email: null,
        target_email: target,
        code_hash: sha(body.code),
        issued_at: body.created_at,
        expires_at_ms: row.expires_at_ms,
      },
      row.pttl_ms,
      row.redis_time_ms,
    );
    await importLegacyChallenges(db, manifest([row, metadata], []), apply);
    expect(await email.verifyCode(target, "654321")).toMatchObject({
      legacyUserId: 26,
    });
  });
  it("applies independent attempt locks even when the original code key is absent", async () => {
    await importLegacyChallenges(
      db,
      manifest([record(`password:reset:attempts:${address}`, "5", 80000)]),
      apply,
    );
    await expect(password.verifyCode(address, "123456")).rejects.toMatchObject({
      code: "ACCOUNT_LOCKED",
    });
  });
  it("cannot revive consumed reset/change tokens by replaying their final manifest", async () => {
    const now = Date.now(),
      input = manifest([
        record(
          `password:reset:${resetToken}`,
          {
            email: address,
            user_id: 24,
            created_at: Math.floor((now - 1000) / 1000),
          },
          600000,
          now,
        ),
        record("email:change:token:24", changeToken, 300000, now),
      ]);
    await importLegacyChallenges(db, input, apply);
    await db.execute(
      "UPDATE identity_password_reset_tokens SET consumed_at=UTC_TIMESTAMP(3)",
    );
    const token = await change.verifyToken(24, changeToken);
    await change.consume(token.tokenKey);
    expect(await importLegacyChallenges(db, input, apply)).toMatchObject({
      existing: 2,
      imported: 0,
    });
    expect(await password.findActiveByToken(resetToken)).toBeNull();
    await expect(change.verifyToken(24, changeToken)).rejects.toMatchObject({
      code: "INVALID_CODE",
    });
  });
  it("rejects a reset token whose original account email no longer matches", async () => {
    const now = Date.now();
    await expect(
      importLegacyChallenges(
        db,
        manifest([
          record(
            `password:reset:${resetToken}`,
            {
              email: "other@example.com",
              user_id: 24,
              created_at: Math.floor(now / 1000),
            },
            600000,
            now,
          ),
        ]),
        apply,
      ),
    ).rejects.toThrow("association");
    const [rows] = await db.query<RowDataPacket[]>(
      "SELECT * FROM identity_password_reset_tokens",
    );
    expect(rows).toHaveLength(0);
  });
});
