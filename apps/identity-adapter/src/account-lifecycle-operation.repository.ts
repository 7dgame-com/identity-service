import { createHash } from "node:crypto";
import { Injectable, OnModuleDestroy } from "@nestjs/common";
import mysql, { Pool, ResultSetHeader, RowDataPacket } from "mysql2/promise";
import { loadConfig } from "./config.js";
import { LegacyUserReadModel } from "./legacy-identity.reader.js";

export interface AccountLifecycleOperationInput {
  operationKey: string;
  operationType: string;
  username: string | null;
  email: string | null;
  metadata?: Record<string, unknown> | null;
}

export interface AccountLifecycleOperationCompletion extends AccountLifecycleOperationInput {
  user: LegacyUserReadModel;
}

export class AccountLifecycleOperationInProgressError extends Error {
  constructor(readonly operationKey: string) {
    super(`account lifecycle operation ${operationKey} is already pending`);
    this.name = "AccountLifecycleOperationInProgressError";
  }
}

@Injectable()
export class AccountLifecycleOperationRepository implements OnModuleDestroy {
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

  async findCompleted(operationKey: string): Promise<LegacyUserReadModel | null> {
    const pool = this.requirePool();
    await this.ensureSchema();

    const [rows] = await pool.execute<RowDataPacket[]>(
      `SELECT legacy_user_id AS legacyUserId,
              username,
              email,
              metadata
         FROM account_lifecycle_operations
        WHERE operation_key = ? AND status = 'completed'
        LIMIT 1`,
      [operationKey]
    );
    const row = rows[0];
    if (!row?.legacyUserId) {
      return null;
    }

    const metadata = parseJsonMaybe(row.metadata);
    const roles = Array.isArray(metadata?.roles) ? metadata.roles.filter((role): role is string => typeof role === "string") : ["user"];

    return {
      id: Number(row.legacyUserId),
      username: row.username ?? null,
      email: row.email ?? null,
      status: 10,
      nickname: null,
      emailVerifiedAt: null,
      createdAt: null,
      updatedAt: null,
      userInfo: null,
      roles,
      organizations: [],
      source: "legacy"
    };
  }

  async begin(input: AccountLifecycleOperationInput): Promise<void> {
    const pool = this.requirePool();
    await this.ensureSchema();

    const now = new Date();
    const [result] = await pool.execute<ResultSetHeader>(
      `INSERT IGNORE INTO account_lifecycle_operations
        (operation_key, operation_type, username, email, status, requested_at, metadata)
       VALUES (?, ?, ?, ?, 'pending', ?, ?)`,
      [input.operationKey, input.operationType, input.username, input.email, now, stringifyJson(input.metadata)]
    );
    if (result.affectedRows > 0) {
      return;
    }

    const [rows] = await pool.execute<RowDataPacket[]>(
      `SELECT status
         FROM account_lifecycle_operations
        WHERE operation_key = ?
        LIMIT 1`,
      [input.operationKey]
    );
    const status = rows[0]?.status;
    if (status === "failed") {
      await pool.execute(
        `UPDATE account_lifecycle_operations
            SET status = 'pending',
                requested_at = ?,
                completed_at = NULL,
                failed_at = NULL,
                error_code = NULL,
                username = ?,
                email = ?,
                metadata = ?
          WHERE operation_key = ? AND status = 'failed'`,
        [now, input.username, input.email, stringifyJson(input.metadata), input.operationKey]
      );
      return;
    }

    throw new AccountLifecycleOperationInProgressError(input.operationKey);
  }

  async complete(input: AccountLifecycleOperationCompletion): Promise<void> {
    const pool = this.requirePool();
    await this.ensureSchema();

    await pool.execute(
      `UPDATE account_lifecycle_operations
          SET status = 'completed',
              legacy_user_id = ?,
              username = ?,
              email = ?,
              completed_at = ?,
              failed_at = NULL,
              error_code = NULL,
              metadata = ?
        WHERE operation_key = ?`,
      [
        input.user.id,
        input.user.username ?? input.username,
        input.user.email ?? input.email,
        new Date(),
        stringifyJson({
          ...(input.metadata ?? {}),
          roles: input.user.roles
        }),
        input.operationKey
      ]
    );
  }

  async fail(input: AccountLifecycleOperationInput & { errorCode: string }): Promise<void> {
    const pool = this.requirePool();
    await this.ensureSchema();

    await pool.execute(
      `UPDATE account_lifecycle_operations
          SET status = 'failed',
              failed_at = ?,
              error_code = ?,
              metadata = ?
        WHERE operation_key = ? AND status = 'pending'`,
      [new Date(), input.errorCode, stringifyJson(input.metadata), input.operationKey]
    );
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
      CREATE TABLE IF NOT EXISTS account_lifecycle_operations (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        operation_key VARCHAR(160) NOT NULL,
        operation_type VARCHAR(64) NOT NULL,
        legacy_user_id BIGINT NULL,
        identity_user_id VARCHAR(128) NULL,
        username VARCHAR(255) NULL,
        email VARCHAR(255) NULL,
        status VARCHAR(32) NOT NULL DEFAULT 'pending',
        requested_at DATETIME(3) NOT NULL,
        completed_at DATETIME(3) NULL,
        failed_at DATETIME(3) NULL,
        error_code VARCHAR(128) NULL,
        metadata JSON NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY idx_account_lifecycle_operations_key (operation_key),
        KEY idx_account_lifecycle_operations_legacy_user (legacy_user_id, requested_at),
        KEY idx_account_lifecycle_operations_type_status (operation_type, status, requested_at),
        KEY idx_account_lifecycle_operations_email (email, requested_at)
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

export function operationKeyForRegister(kind: "standard" | "wechat", parts: string[]): string {
  const digest = createHash("sha256").update(parts.map((part) => part.trim().toLowerCase()).join("\u001f")).digest("hex");
  return `register:${kind}:${digest.slice(0, 48)}`;
}

export function operationKeyForPasswordChange(userId: number, oldPassword: string, newPassword: string): string {
  const digest = createHash("sha256").update([String(userId), oldPassword, newPassword].join("\u001f")).digest("hex");
  return `password:change:${digest.slice(0, 48)}`;
}

export function operationKeyForPasswordReset(email: string, code: string, newPassword: string): string {
  const digest = createHash("sha256").update([email.trim().toLowerCase(), code, newPassword].join("\u001f")).digest("hex");
  return `password:reset:${digest.slice(0, 48)}`;
}

function stringifyJson(value: Record<string, unknown> | null | undefined): string {
  return JSON.stringify(value ?? {});
}

function parseJsonMaybe(value: unknown): Record<string, unknown> | null {
  if (!value) {
    return null;
  }
  if (typeof value === "object" && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  if (typeof value !== "string") {
    return null;
  }

  try {
    const parsed = JSON.parse(value);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}
