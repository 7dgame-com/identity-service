import { createHash, randomBytes } from "node:crypto";
import { Injectable, OnModuleDestroy } from "@nestjs/common";
import mysql, { Pool, ResultSetHeader, RowDataPacket } from "mysql2/promise";
import { loadConfig } from "./config.js";

export interface EmailChangeToken {
  id: number;
  tokenKey: string;
  legacyUserId: number;
  tokenHash: string;
  expiresAt: Date;
  consumedAt: Date | null;
  createdAt: Date;
}

export class EmailChangeTokenError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    readonly message: string
  ) {
    super(message);
    this.name = "EmailChangeTokenError";
  }
}

@Injectable()
export class EmailChangeTokenRepository implements OnModuleDestroy {
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

  async createToken(legacyUserId: number): Promise<{ token: string; expiresIn: number; record: EmailChangeToken }> {
    const pool = this.requirePool();
    await this.ensureSchema();
    const token = randomBytes(32).toString("base64url");
    const tokenKey = `email-change:${randomBytes(16).toString("hex")}`;
    const expiresIn = this.config.emailChange.tokenTtlSeconds;
    const expiresAt = new Date(Date.now() + expiresIn * 1000);

    await pool.execute<ResultSetHeader>(
      `INSERT INTO email_change_tokens
        (token_key, legacy_user_id, token_hash, expires_at)
       VALUES (?, ?, ?, ?)`,
      [tokenKey, legacyUserId, this.hashToken(legacyUserId, token), expiresAt]
    );

    const record = await this.findLatestByUser(legacyUserId);
    if (!record) {
      throw new Error("email change token was not created");
    }

    return { token, expiresIn, record };
  }

  async verifyToken(legacyUserId: number, token: string | undefined): Promise<EmailChangeToken> {
    if (!token) {
      throw new EmailChangeTokenError(400, "INVALID_CODE", "改绑邮箱需先完成旧邮箱验证");
    }

    const record = await this.findLatestByUser(legacyUserId);
    if (!record || record.consumedAt || record.expiresAt.getTime() <= Date.now()) {
      throw new EmailChangeTokenError(400, "INVALID_CODE", "改绑确认已失效，请重新验证旧邮箱");
    }

    if (record.tokenHash !== this.hashToken(legacyUserId, token)) {
      throw new EmailChangeTokenError(400, "INVALID_CODE", "改绑确认已失效，请重新验证旧邮箱");
    }

    return record;
  }

  async consume(tokenKey: string): Promise<void> {
    const pool = this.requirePool();
    await this.ensureSchema();
    await pool.execute(
      `UPDATE email_change_tokens
          SET consumed_at = COALESCE(consumed_at, ?)
        WHERE token_key = ?`,
      [new Date(), tokenKey]
    );
  }

  private async findLatestByUser(legacyUserId: number): Promise<EmailChangeToken | null> {
    const pool = this.requirePool();
    await this.ensureSchema();
    const [rows] = await pool.execute<RowDataPacket[]>(
      `SELECT id,
              token_key AS tokenKey,
              legacy_user_id AS legacyUserId,
              token_hash AS tokenHash,
              expires_at AS expiresAt,
              consumed_at AS consumedAt,
              created_at AS createdAt
         FROM email_change_tokens
        WHERE legacy_user_id = ?
        ORDER BY created_at DESC, id DESC
        LIMIT 1`,
      [legacyUserId]
    );

    return rows[0] ? normalizeToken(rows[0]) : null;
  }

  private hashToken(legacyUserId: number, token: string): string {
    return createHash("sha256").update(`${this.config.emailVerification.codeHashSalt}\u001f${legacyUserId}\u001f${token}`).digest("hex");
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
      CREATE TABLE IF NOT EXISTS email_change_tokens (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        token_key VARCHAR(160) NOT NULL,
        legacy_user_id BIGINT NOT NULL,
        token_hash CHAR(64) NOT NULL,
        expires_at DATETIME(3) NOT NULL,
        consumed_at DATETIME(3) NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY idx_email_change_tokens_key (token_key),
        KEY idx_email_change_tokens_user (legacy_user_id, created_at)
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

function normalizeToken(row: RowDataPacket): EmailChangeToken {
  return {
    id: Number(row.id),
    tokenKey: String(row.tokenKey),
    legacyUserId: Number(row.legacyUserId),
    tokenHash: String(row.tokenHash),
    expiresAt: toDate(row.expiresAt),
    consumedAt: row.consumedAt ? toDate(row.consumedAt) : null,
    createdAt: toDate(row.createdAt)
  };
}

function toDate(value: unknown): Date {
  return value instanceof Date ? value : new Date(String(value));
}
