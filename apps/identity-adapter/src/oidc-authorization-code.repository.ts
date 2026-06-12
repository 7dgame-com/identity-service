import { createHash, randomBytes } from "node:crypto";
import { Injectable, OnModuleDestroy } from "@nestjs/common";
import mysql, { Pool, ResultSetHeader, RowDataPacket } from "mysql2/promise";
import { loadConfig } from "./config.js";

export class InvalidAuthorizationCodeError extends Error {
  constructor(message = "authorization code is invalid") {
    super(message);
    this.name = "InvalidAuthorizationCodeError";
  }
}

export interface OidcAuthorizationCodeInput {
  clientId: string;
  redirectUri: string;
  legacyUserId: number;
  username: string | null;
  scope: string;
  codeChallenge: string;
  codeChallengeMethod: "S256";
  nonce: string | null;
  authTime: Date;
  expiresAt: Date;
}

export interface IssuedOidcAuthorizationCode extends OidcAuthorizationCodeInput {
  code: string;
  codeHash: string;
}

export interface ConsumedOidcAuthorizationCode extends OidcAuthorizationCodeInput {
  id: number;
  consumedAt: Date | null;
}

@Injectable()
export class OidcAuthorizationCodeRepository implements OnModuleDestroy {
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

  async issue(input: OidcAuthorizationCodeInput): Promise<IssuedOidcAuthorizationCode> {
    const pool = this.requirePool();
    await this.ensureSchema();

    const code = randomBytes(32).toString("base64url");
    const codeHash = hashAuthorizationCode(code);

    await pool.execute<ResultSetHeader>(
      `INSERT INTO oidc_authorization_codes
        (code_hash, client_id, redirect_uri, legacy_user_id, username, scope,
         code_challenge, code_challenge_method, nonce, auth_time, issued_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        codeHash,
        input.clientId,
        input.redirectUri,
        input.legacyUserId,
        input.username,
        input.scope,
        input.codeChallenge,
        input.codeChallengeMethod,
        input.nonce,
        input.authTime,
        new Date(),
        input.expiresAt
      ]
    );

    return {
      ...input,
      code,
      codeHash
    };
  }

  async consume(input: { code: string; clientId: string; redirectUri: string }): Promise<ConsumedOidcAuthorizationCode> {
    const pool = this.requirePool();
    await this.ensureSchema();

    const codeHash = hashAuthorizationCode(input.code);
    const [rows] = await pool.execute<RowDataPacket[]>(
      `SELECT id,
              client_id AS clientId,
              redirect_uri AS redirectUri,
              legacy_user_id AS legacyUserId,
              username,
              scope,
              code_challenge AS codeChallenge,
              code_challenge_method AS codeChallengeMethod,
              nonce,
              auth_time AS authTime,
              expires_at AS expiresAt,
              consumed_at AS consumedAt
         FROM oidc_authorization_codes
        WHERE code_hash = ?
          AND client_id = ?
          AND redirect_uri = ?
        LIMIT 1`,
      [codeHash, input.clientId, input.redirectUri]
    );

    const code = rows[0] ? normalizeCode(rows[0]) : null;
    if (!code || code.consumedAt || code.expiresAt.getTime() <= Date.now()) {
      throw new InvalidAuthorizationCodeError();
    }

    const [result] = await pool.execute<ResultSetHeader>(
      `UPDATE oidc_authorization_codes
          SET consumed_at = ?
        WHERE id = ? AND consumed_at IS NULL`,
      [new Date(), code.id]
    );
    if (result.affectedRows !== 1) {
      throw new InvalidAuthorizationCodeError();
    }

    return code;
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
      CREATE TABLE IF NOT EXISTS oidc_authorization_codes (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        code_hash CHAR(64) NOT NULL,
        client_id VARCHAR(128) NOT NULL,
        redirect_uri VARCHAR(2048) NOT NULL,
        legacy_user_id BIGINT NOT NULL,
        username VARCHAR(255) NULL,
        scope VARCHAR(512) NOT NULL,
        code_challenge VARCHAR(128) NOT NULL,
        code_challenge_method VARCHAR(16) NOT NULL,
        nonce VARCHAR(255) NULL,
        auth_time DATETIME(3) NOT NULL,
        issued_at DATETIME(3) NOT NULL,
        expires_at DATETIME(3) NOT NULL,
        consumed_at DATETIME(3) NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY idx_oidc_authorization_codes_hash (code_hash),
        KEY idx_oidc_authorization_codes_client_user (client_id, legacy_user_id, expires_at),
        KEY idx_oidc_authorization_codes_expires (expires_at)
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

export function hashAuthorizationCode(code: string): string {
  return createHash("sha256").update(code).digest("hex");
}

function normalizeCode(row: RowDataPacket): ConsumedOidcAuthorizationCode {
  return {
    id: Number(row.id),
    clientId: String(row.clientId),
    redirectUri: String(row.redirectUri),
    legacyUserId: Number(row.legacyUserId),
    username: row.username ?? null,
    scope: String(row.scope),
    codeChallenge: String(row.codeChallenge),
    codeChallengeMethod: "S256",
    nonce: row.nonce ?? null,
    authTime: normalizeDate(row.authTime),
    expiresAt: normalizeDate(row.expiresAt),
    consumedAt: row.consumedAt ? normalizeDate(row.consumedAt) : null
  };
}

function normalizeDate(value: unknown): Date {
  if (value instanceof Date) {
    return value;
  }

  const parsed = new Date(String(value));
  return Number.isNaN(parsed.getTime()) ? new Date(0) : parsed;
}
