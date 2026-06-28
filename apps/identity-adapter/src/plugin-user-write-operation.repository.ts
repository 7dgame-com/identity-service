import { createHash } from "node:crypto";
import { Injectable, OnModuleDestroy } from "@nestjs/common";
import mysql, { Pool, ResultSetHeader } from "mysql2/promise";
import { loadConfig } from "./config.js";

export type PluginUserWriteRoute = "create-user" | "update-user" | "delete-user" | "change-role" | "batch-create-users";
export type PluginUserWriteMode = "legacy-proxy" | "dual-write" | "identity-native";
export type PluginUserWriteOperationStatus = "pending" | "legacy_completed" | "identity_completed" | "completed" | "failed";
export type PluginUserWriteCompensationStatus = "none" | "required" | "in_progress" | "completed" | "failed";

export interface PluginUserWriteOperationInput {
  operationKey: string;
  idempotencyKey: string;
  route: PluginUserWriteRoute;
  mode: PluginUserWriteMode;
  actorSubject: string | null;
  targetSubject: string | null;
  legacyUserId?: number | null;
  identityUserId?: string | null;
  metadata?: Record<string, unknown> | null;
}

export interface PluginUserWriteOperationUpdate {
  operationKey: string;
  status: PluginUserWriteOperationStatus;
  legacyStatus?: string | null;
  identityStatus?: string | null;
  compensationStatus?: PluginUserWriteCompensationStatus;
  errorCode?: string | null;
  metadata?: Record<string, unknown> | null;
}

@Injectable()
export class PluginUserWriteOperationRepository implements OnModuleDestroy {
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

  async begin(input: PluginUserWriteOperationInput): Promise<{ duplicate: boolean }> {
    const pool = this.requirePool();
    await this.ensureSchema();

    const [result] = await pool.execute<ResultSetHeader>(
      `INSERT IGNORE INTO plugin_user_write_operations
        (operation_key, idempotency_key, route, mode, actor_subject, target_subject,
         legacy_user_id, identity_user_id, status, compensation_status, requested_at, metadata)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', 'none', ?, ?)`,
      [
        input.operationKey,
        input.idempotencyKey,
        input.route,
        input.mode,
        input.actorSubject,
        input.targetSubject,
        input.legacyUserId ?? null,
        input.identityUserId ?? null,
        new Date(),
        stringifyJson(redactPluginUserWriteMetadata(input.metadata))
      ]
    );

    return { duplicate: result.affectedRows === 0 };
  }

  async update(input: PluginUserWriteOperationUpdate): Promise<void> {
    const pool = this.requirePool();
    await this.ensureSchema();

    await pool.execute(
      `UPDATE plugin_user_write_operations
          SET status = ?,
              legacy_status = COALESCE(?, legacy_status),
              identity_status = COALESCE(?, identity_status),
              compensation_status = COALESCE(?, compensation_status),
              error_code = ?,
              completed_at = CASE WHEN ? IN ('completed', 'failed') THEN ? ELSE completed_at END,
              metadata = ?
        WHERE operation_key = ?`,
      [
        input.status,
        input.legacyStatus ?? null,
        input.identityStatus ?? null,
        input.compensationStatus ?? null,
        input.errorCode ?? null,
        input.status,
        new Date(),
        stringifyJson(redactPluginUserWriteMetadata(input.metadata)),
        input.operationKey
      ]
    );
  }

  async ensureSchema(): Promise<void> {
    if (!this.schemaReady) {
      this.schemaReady = this.createSchema();
    }

    return this.schemaReady;
  }

  private async createSchema(): Promise<void> {
    const pool = this.requirePool();

    await pool.query(`
      CREATE TABLE IF NOT EXISTS plugin_user_write_operations (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        operation_key VARCHAR(160) NOT NULL,
        idempotency_key VARCHAR(160) NOT NULL,
        route VARCHAR(64) NOT NULL,
        mode VARCHAR(32) NOT NULL,
        actor_subject VARCHAR(255) NULL,
        target_subject VARCHAR(255) NULL,
        legacy_user_id BIGINT NULL,
        identity_user_id VARCHAR(128) NULL,
        status VARCHAR(32) NOT NULL DEFAULT 'pending',
        legacy_status VARCHAR(64) NULL,
        identity_status VARCHAR(64) NULL,
        compensation_status VARCHAR(32) NOT NULL DEFAULT 'none',
        error_code VARCHAR(128) NULL,
        requested_at DATETIME(3) NOT NULL,
        completed_at DATETIME(3) NULL,
        metadata JSON NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY idx_plugin_user_write_operations_key (operation_key),
        UNIQUE KEY idx_plugin_user_write_operations_idempotency (idempotency_key),
        KEY idx_plugin_user_write_operations_route_status (route, status, requested_at),
        KEY idx_plugin_user_write_operations_legacy_user (legacy_user_id, requested_at),
        KEY idx_plugin_user_write_operations_identity_user (identity_user_id, requested_at),
        KEY idx_plugin_user_write_operations_compensation (compensation_status, requested_at)
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

export function pluginUserWriteOperationKey(input: {
  route: PluginUserWriteRoute;
  actorSubject?: string | null;
  targetSubject?: string | null;
  requestFingerprint: string;
}): string {
  const digest = createHash("sha256")
    .update([input.route, input.actorSubject ?? "", input.targetSubject ?? "", input.requestFingerprint].join("\u001f"))
    .digest("hex");
  return `plugin-user-write:v1:${input.route}:${digest.slice(0, 48)}`;
}

export function pluginUserWriteRequestFingerprint(route: PluginUserWriteRoute, payload: unknown): string {
  const sanitized = redactPluginUserWriteMetadata(payload);
  return createHash("sha256").update(`${route}\u001f${stableStringify(sanitized)}`).digest("hex");
}

export function redactPluginUserWriteMetadata(value: unknown): Record<string, unknown> {
  const redacted = redactValue(value, 0);
  if (redacted && typeof redacted === "object" && !Array.isArray(redacted)) {
    return redacted as Record<string, unknown>;
  }

  return { value: redacted };
}

function redactValue(value: unknown, depth: number): unknown {
  if (depth > 8) {
    return "[truncated]";
  }

  if (Array.isArray(value)) {
    return value.map((item) => redactValue(item, depth + 1));
  }

  if (!value || typeof value !== "object") {
    return value;
  }

  const output: Record<string, unknown> = {};
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    if (isSecretKey(key)) {
      output[key] = "[redacted]";
      continue;
    }

    output[key] = redactValue(child, depth + 1);
  }

  return output;
}

function isSecretKey(key: string): boolean {
  return /password|passwd|pwd|token|secret|credential|authorization|cookie|code|key/i.test(key);
}

function stableStringify(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(",")}]`;
  }

  if (!value || typeof value !== "object") {
    return JSON.stringify(value);
  }

  const entries = Object.entries(value as Record<string, unknown>).sort(([left], [right]) => left.localeCompare(right));
  return `{${entries.map(([key, child]) => `${JSON.stringify(key)}:${stableStringify(child)}`).join(",")}}`;
}

function stringifyJson(value: Record<string, unknown> | null | undefined): string {
  return JSON.stringify(value ?? {});
}
