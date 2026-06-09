import { createHash, randomInt, randomUUID } from "node:crypto";
import { Injectable, OnModuleDestroy } from "@nestjs/common";
import mysql, { Pool, ResultSetHeader, RowDataPacket } from "mysql2/promise";
import { loadConfig } from "./config.js";

export interface PasswordResetChallenge {
  id: number;
  challengeKey: string;
  legacyUserId: number;
  email: string;
  codeHash: string;
  attempts: number;
  expiresAt: Date;
  lockedUntil: Date | null;
  consumedAt: Date | null;
  createdAt: Date;
}

export class PasswordResetChallengeError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    readonly message: string,
    readonly retryAfter?: number
  ) {
    super(message);
    this.name = "PasswordResetChallengeError";
  }
}

@Injectable()
export class PasswordResetChallengeRepository implements OnModuleDestroy {
  private readonly config = loadConfig();
  private readonly pool: Pool | null;
  private schemaReady: Promise<void> | null = null;

  constructor() {
    this.pool = this.createPool();
  }

  async onModuleDestroy(): Promise<void> {
    await this.pool?.end();
  }

  isConfigured(): boolean {
    return this.pool !== null;
  }

  async createChallenge(input: { email: string; legacyUserId: number }): Promise<{ code: string; challenge: PasswordResetChallenge }> {
    const pool = this.requirePool();
    await this.ensureSchema();
    const email = normalizeEmail(input.email);
    const latest = await this.findLatestByEmail(email);
    if (latest) {
      const availableAt = latest.createdAt.getTime() + this.config.passwordReset.rateLimitSeconds * 1000;
      if (availableAt > Date.now()) {
        throw new PasswordResetChallengeError(
          429,
          "RATE_LIMIT_EXCEEDED",
          `请求过于频繁，请 ${Math.ceil((availableAt - Date.now()) / 1000)} 秒后再试`,
          Math.ceil((availableAt - Date.now()) / 1000)
        );
      }
    }

    const code = randomCode();
    const challengeKey = `password-reset:${randomUUID()}`;
    const expiresAt = new Date(Date.now() + this.config.passwordReset.codeTtlSeconds * 1000);
    await pool.execute<ResultSetHeader>(
      `INSERT INTO password_reset_challenges
        (challenge_key, legacy_user_id, email, code_hash, attempts, expires_at)
       VALUES (?, ?, ?, ?, 0, ?)`,
      [challengeKey, input.legacyUserId, email, this.hashCode(email, code), expiresAt]
    );

    const challenge = await this.findLatestByEmail(email);
    if (!challenge) {
      throw new Error("password reset challenge was not created");
    }

    return { code, challenge };
  }

  async verifyCode(email: string, code: string): Promise<PasswordResetChallenge> {
    const challenge = await this.requireActiveChallenge(email);
    if (challenge.lockedUntil && challenge.lockedUntil.getTime() > Date.now()) {
      throw new PasswordResetChallengeError(
        429,
        "ACCOUNT_LOCKED",
        `验证失败次数过多，账户已被锁定，请 ${Math.ceil((challenge.lockedUntil.getTime() - Date.now()) / 1000)} 秒后再试`,
        Math.ceil((challenge.lockedUntil.getTime() - Date.now()) / 1000)
      );
    }
    if (challenge.expiresAt.getTime() <= Date.now()) {
      throw new PasswordResetChallengeError(400, "INVALID_CODE", "验证码不存在或已过期");
    }
    if (challenge.codeHash !== this.hashCode(normalizeEmail(email), code)) {
      await this.incrementAttempts(challenge);
      throw new PasswordResetChallengeError(400, "INVALID_CODE", "验证码不正确");
    }

    return challenge;
  }

  async consume(challengeKey: string): Promise<void> {
    const pool = this.requirePool();
    await this.ensureSchema();
    await pool.execute(
      `UPDATE password_reset_challenges
          SET consumed_at = COALESCE(consumed_at, ?)
        WHERE challenge_key = ?`,
      [new Date(), challengeKey]
    );
  }

  private async requireActiveChallenge(email: string): Promise<PasswordResetChallenge> {
    const challenge = await this.findLatestByEmail(normalizeEmail(email));
    if (!challenge || challenge.consumedAt) {
      throw new PasswordResetChallengeError(400, "INVALID_CODE", "验证码不存在或已过期");
    }

    return challenge;
  }

  private async findLatestByEmail(email: string): Promise<PasswordResetChallenge | null> {
    const pool = this.requirePool();
    await this.ensureSchema();
    const [rows] = await pool.execute<RowDataPacket[]>(
      `SELECT id,
              challenge_key AS challengeKey,
              legacy_user_id AS legacyUserId,
              email,
              code_hash AS codeHash,
              attempts,
              expires_at AS expiresAt,
              locked_until AS lockedUntil,
              consumed_at AS consumedAt,
              created_at AS createdAt
         FROM password_reset_challenges
        WHERE email = ?
        ORDER BY created_at DESC, id DESC
        LIMIT 1`,
      [email]
    );

    return rows[0] ? normalizeChallenge(rows[0]) : null;
  }

  private async incrementAttempts(challenge: PasswordResetChallenge): Promise<void> {
    const pool = this.requirePool();
    const nextAttempts = challenge.attempts + 1;
    const lockedUntil = nextAttempts >= this.config.passwordReset.maxAttempts ? new Date(Date.now() + this.config.passwordReset.lockSeconds * 1000) : null;
    await pool.execute(
      `UPDATE password_reset_challenges
          SET attempts = ?, locked_until = COALESCE(?, locked_until)
        WHERE id = ?`,
      [nextAttempts, lockedUntil, challenge.id]
    );
  }

  private hashCode(email: string, code: string): string {
    return createHash("sha256").update(`${this.config.passwordReset.codeHashSalt}\u001f${email}\u001f${code}`).digest("hex");
  }

  private async ensureSchema(): Promise<void> {
    if (!this.schemaReady) {
      this.schemaReady = this.createSchema();
    }

    return this.schemaReady;
  }

  private async createSchema(): Promise<void> {
    const pool = this.requirePool();
    await pool.query(`
      CREATE TABLE IF NOT EXISTS password_reset_challenges (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        challenge_key VARCHAR(160) NOT NULL,
        legacy_user_id BIGINT NOT NULL,
        email VARCHAR(255) NOT NULL,
        code_hash CHAR(64) NOT NULL,
        attempts INT NOT NULL DEFAULT 0,
        expires_at DATETIME(3) NOT NULL,
        locked_until DATETIME(3) NULL,
        consumed_at DATETIME(3) NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY idx_password_reset_challenges_key (challenge_key),
        KEY idx_password_reset_challenges_email (email, created_at),
        KEY idx_password_reset_challenges_user (legacy_user_id, created_at)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);
  }

  private requirePool(): Pool {
    if (!this.pool) {
      throw new Error("identity database is not configured");
    }

    return this.pool;
  }

  private createPool(): Pool | null {
    const { identityDb } = this.config;
    if (!identityDb.host || !identityDb.user) {
      return null;
    }

    return mysql.createPool({
      host: identityDb.host,
      port: identityDb.port,
      database: identityDb.name,
      user: identityDb.user,
      password: identityDb.password,
      waitForConnections: true,
      connectionLimit: 5,
      namedPlaceholders: false
    });
  }
}

function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

function randomCode(): string {
  return String(randomInt(0, 1000000)).padStart(6, "0");
}

function normalizeChallenge(row: RowDataPacket): PasswordResetChallenge {
  return {
    id: Number(row.id),
    challengeKey: String(row.challengeKey),
    legacyUserId: Number(row.legacyUserId),
    email: String(row.email),
    codeHash: String(row.codeHash),
    attempts: Number(row.attempts),
    expiresAt: toDate(row.expiresAt),
    lockedUntil: row.lockedUntil ? toDate(row.lockedUntil) : null,
    consumedAt: row.consumedAt ? toDate(row.consumedAt) : null,
    createdAt: toDate(row.createdAt)
  };
}

function toDate(value: unknown): Date {
  return value instanceof Date ? value : new Date(String(value));
}
