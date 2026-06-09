import { createHash, randomBytes } from "node:crypto";
import { Injectable, OnModuleDestroy } from "@nestjs/common";
import mysql, { Pool, ResultSetHeader, RowDataPacket } from "mysql2/promise";
import { loadConfig } from "./config.js";

export class InvalidRefreshTokenError extends Error {
  constructor(message = "refresh token is invalid") {
    super(message);
    this.name = "InvalidRefreshTokenError";
  }
}

export interface IdentitySessionInput {
  legacyUserId: number;
  username: string | null;
  sessionId: string;
  expiresAt: Date;
  ipAddressHash?: string | null;
  userAgentHash?: string | null;
}

export interface IssuedIdentitySession {
  refreshToken: string;
  refreshTokenHash: string;
  sessionId: string;
  legacyUserId: number;
  username: string | null;
  expiresAt: Date;
}

interface StoredIdentitySession {
  id: number;
  refreshTokenHash: string;
  sessionId: string;
  legacyUserId: number;
  username: string | null;
  expiresAt: Date;
  revokedAt: Date | null;
}

@Injectable()
export class IdentitySessionRepository implements OnModuleDestroy {
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

  async issue(input: IdentitySessionInput): Promise<IssuedIdentitySession> {
    const pool = this.requirePool();
    await this.ensureSchema();

    const refreshToken = randomBytes(48).toString("base64url");
    const refreshTokenHash = hashRefreshToken(refreshToken);

    await pool.execute<ResultSetHeader>(
      `INSERT INTO identity_refresh_sessions
        (refresh_token_hash, session_id, legacy_user_id, username, issued_at, expires_at,
         ip_hash, user_agent_hash)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        refreshTokenHash,
        input.sessionId,
        input.legacyUserId,
        input.username,
        new Date(),
        input.expiresAt,
        input.ipAddressHash ?? null,
        input.userAgentHash ?? null
      ]
    );

    return {
      refreshToken,
      refreshTokenHash,
      sessionId: input.sessionId,
      legacyUserId: input.legacyUserId,
      username: input.username,
      expiresAt: input.expiresAt
    };
  }

  async rotate(refreshToken: string, next: IdentitySessionInput): Promise<IssuedIdentitySession> {
    const pool = this.requirePool();
    await this.ensureSchema();

    const current = await this.findValidSession(refreshToken);
    const replacement = await this.issue(next);

    await pool.execute(
      `UPDATE identity_refresh_sessions
          SET revoked_at = ?, replaced_by_hash = ?
        WHERE id = ? AND revoked_at IS NULL`,
      [new Date(), replacement.refreshTokenHash, current.id]
    );

    return replacement;
  }

  async revoke(refreshToken: string | null | undefined): Promise<boolean> {
    if (!refreshToken) {
      return true;
    }

    const pool = this.requirePool();
    await this.ensureSchema();
    const refreshTokenHash = hashRefreshToken(refreshToken);

    await pool.execute(
      `UPDATE identity_refresh_sessions
          SET revoked_at = COALESCE(revoked_at, ?)
        WHERE refresh_token_hash = ?`,
      [new Date(), refreshTokenHash]
    );

    return true;
  }

  async findValidSession(refreshToken: string): Promise<StoredIdentitySession> {
    const pool = this.requirePool();
    await this.ensureSchema();
    const refreshTokenHash = hashRefreshToken(refreshToken);

    const [rows] = await pool.execute<RowDataPacket[]>(
      `SELECT id,
              refresh_token_hash AS refreshTokenHash,
              session_id AS sessionId,
              legacy_user_id AS legacyUserId,
              username,
              expires_at AS expiresAt,
              revoked_at AS revokedAt
         FROM identity_refresh_sessions
        WHERE refresh_token_hash = ?
        LIMIT 1`,
      [refreshTokenHash]
    );

    const session = rows[0] ? normalizeStoredSession(rows[0]) : null;
    if (!session || session.revokedAt || session.expiresAt.getTime() <= Date.now()) {
      throw new InvalidRefreshTokenError();
    }

    return session;
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
      CREATE TABLE IF NOT EXISTS identity_refresh_sessions (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        refresh_token_hash CHAR(64) NOT NULL,
        session_id VARCHAR(128) NOT NULL,
        legacy_user_id BIGINT NOT NULL,
        username VARCHAR(255) NULL,
        issued_at DATETIME(3) NOT NULL,
        expires_at DATETIME(3) NOT NULL,
        revoked_at DATETIME(3) NULL,
        replaced_by_hash CHAR(64) NULL,
        ip_hash CHAR(64) NULL,
        user_agent_hash CHAR(64) NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY idx_identity_refresh_sessions_token_hash (refresh_token_hash),
        KEY idx_identity_refresh_sessions_legacy_user (legacy_user_id, expires_at),
        KEY idx_identity_refresh_sessions_session (session_id)
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

export function hashRefreshToken(refreshToken: string): string {
  return createHash("sha256").update(refreshToken).digest("hex");
}

function normalizeStoredSession(row: RowDataPacket): StoredIdentitySession {
  return {
    id: Number(row.id),
    refreshTokenHash: String(row.refreshTokenHash),
    sessionId: String(row.sessionId),
    legacyUserId: Number(row.legacyUserId),
    username: row.username ?? null,
    expiresAt: normalizeDate(row.expiresAt),
    revokedAt: row.revokedAt ? normalizeDate(row.revokedAt) : null
  };
}

function normalizeDate(value: unknown): Date {
  if (value instanceof Date) {
    return value;
  }

  const parsed = new Date(String(value));
  return Number.isNaN(parsed.getTime()) ? new Date(0) : parsed;
}
