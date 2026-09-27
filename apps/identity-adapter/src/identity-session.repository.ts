import { createHash, randomBytes } from "node:crypto";
import { Injectable, OnModuleDestroy } from "@nestjs/common";
import mysql, { Pool, PoolConnection, ResultSetHeader, RowDataPacket } from "mysql2/promise";
import { loadConfig } from "./config.js";
import { deviceSnSource } from "./device-sn-source.js";

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
  authMethod?: "device_sn" | null;
  deviceSnId?: number | null;
}

export interface IssuedIdentitySession {
  refreshToken: string;
  refreshTokenHash: string;
  sessionId: string;
  legacyUserId: number;
  username: string | null;
  expiresAt: Date;
  authMethod?: "device_sn";
  deviceSnId?: number;
}

interface StoredIdentitySession {
  id: number;
  refreshTokenHash: string;
  sessionId: string;
  legacyUserId: number;
  username: string | null;
  expiresAt: Date;
  revokedAt: Date | null;
  authMethod?: "device_sn";
  deviceSnId?: number;
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
    return this.issueUsing(pool, input);
  }

  private async issueUsing(pool: Pool | PoolConnection, input: IdentitySessionInput): Promise<IssuedIdentitySession> {
    const source = deviceSnSource(input.authMethod, input.deviceSnId);

    const refreshToken = randomBytes(48).toString("base64url");
    const refreshTokenHash = hashRefreshToken(refreshToken);

    await pool.execute<ResultSetHeader>(
      `INSERT INTO identity_refresh_sessions
        (refresh_token_hash, session_id, legacy_user_id, username, issued_at, expires_at,
         ip_hash, user_agent_hash, auth_method, device_sn_id)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        refreshTokenHash,
        input.sessionId,
        input.legacyUserId,
        input.username,
        new Date(),
        input.expiresAt,
        input.ipAddressHash ?? null,
        input.userAgentHash ?? null,
        source?.authMethod ?? null,
        source?.deviceSnId ?? null
      ]
    );

    return {
      refreshToken,
      refreshTokenHash,
      sessionId: input.sessionId,
      legacyUserId: input.legacyUserId,
      username: input.username,
      expiresAt: input.expiresAt,
      ...(source ?? {})
    };
  }

  async rotate(refreshToken: string, next: IdentitySessionInput): Promise<IssuedIdentitySession> {
    const pool = this.requirePool();
    await this.ensureSchema();

    const connection = await pool.getConnection();
    try {
      await connection.beginTransaction();
      const current = await this.readValidSession(connection, refreshToken, true);
      // Provenance belongs to the stored session, never a caller-supplied replacement.
      const source = deviceSnSource(current.authMethod, current.deviceSnId);
      const replacement = await this.issueUsing(connection, {
        ...next, legacyUserId: current.legacyUserId,
        authMethod: source?.authMethod ?? null, deviceSnId: source?.deviceSnId ?? null
      });
      await connection.execute(
        `UPDATE identity_refresh_sessions SET revoked_at = ?, replaced_by_hash = ? WHERE id = ? AND revoked_at IS NULL`,
        [new Date(), replacement.refreshTokenHash, current.id]
      );
      await connection.commit();
      return replacement;
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally { connection.release(); }
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

  async revokeUserSessions(legacyUserId: number): Promise<number> {
    const pool = this.requirePool();
    await this.ensureSchema();
    const [result] = await pool.execute<ResultSetHeader>(
      `UPDATE identity_refresh_sessions
          SET revoked_at = COALESCE(revoked_at, ?)
        WHERE legacy_user_id = ? AND revoked_at IS NULL`,
      [new Date(), legacyUserId]
    );

    return result.affectedRows;
  }

  async findValidSession(refreshToken: string): Promise<StoredIdentitySession> {
    const pool = this.requirePool();
    await this.ensureSchema();
    return this.readValidSession(pool, refreshToken);
  }

  private async readValidSession(pool: Pool | PoolConnection, refreshToken: string, lock = false): Promise<StoredIdentitySession> {
    const refreshTokenHash = hashRefreshToken(refreshToken);

    const [rows] = await pool.execute<RowDataPacket[]>(
      `SELECT id,
              refresh_token_hash AS refreshTokenHash,
              session_id AS sessionId,
              legacy_user_id AS legacyUserId,
              username,
              expires_at AS expiresAt,
              revoked_at AS revokedAt,
              auth_method AS authMethod,
              device_sn_id AS deviceSnId
         FROM identity_refresh_sessions
        WHERE refresh_token_hash = ?
        LIMIT 1${lock ? " FOR UPDATE" : ""}`,
      [refreshTokenHash]
    );

    const session = rows[0] ? normalizeStoredSession(rows[0]) : null;
    if (!session || session.revokedAt || session.expiresAt.getTime() <= Date.now()) {
      throw new InvalidRefreshTokenError();
    }

    return session;
  }

  async deviceSnReadiness(): Promise<boolean> {
    if (!this.pool) return false;
    try {
      await this.pool.query("SELECT auth_method, device_sn_id FROM identity_refresh_sessions LIMIT 0");
      return true;
    } catch { return false; }
  }

  private async ensureSchema(): Promise<void> {
    if (!this.schemaReady) {
      this.schemaReady = this.createSchema().catch((error) => {
        this.schemaReady = null;
        throw error;
      });
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
        auth_method VARCHAR(32) NULL,
        device_sn_id INT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY idx_identity_refresh_sessions_token_hash (refresh_token_hash),
        KEY idx_identity_refresh_sessions_legacy_user (legacy_user_id, expires_at),
        KEY idx_identity_refresh_sessions_session (session_id)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);
    // CREATE TABLE IF NOT EXISTS does not upgrade installations created before device SN.
    for (const [name, definition] of [["auth_method", "VARCHAR(32) NULL"], ["device_sn_id", "INT NULL"]]) {
      const [columns] = await pool.query<RowDataPacket[]>(
        "SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'identity_refresh_sessions' AND COLUMN_NAME = ?", [name]
      );
      if (!columns.length) {
        try { await pool.query(`ALTER TABLE identity_refresh_sessions ADD COLUMN ${name} ${definition}`); }
        catch (error) { if ((error as { code?: string }).code !== "ER_DUP_FIELDNAME") throw error; }
      }
    }
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
  const source = deviceSnSource(row.authMethod, row.deviceSnId == null ? null : Number(row.deviceSnId));
  return {
    id: Number(row.id),
    refreshTokenHash: String(row.refreshTokenHash),
    sessionId: String(row.sessionId),
    legacyUserId: Number(row.legacyUserId),
    username: row.username ?? null,
    expiresAt: normalizeDate(row.expiresAt),
    revokedAt: row.revokedAt ? normalizeDate(row.revokedAt) : null,
    ...(source ?? {})
  };
}

function normalizeDate(value: unknown): Date {
  if (value instanceof Date) {
    return value;
  }

  const parsed = new Date(String(value));
  return Number.isNaN(parsed.getTime()) ? new Date(0) : parsed;
}
