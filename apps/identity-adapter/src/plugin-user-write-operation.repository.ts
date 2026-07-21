import { createHash } from "node:crypto";
import { Injectable, OnModuleDestroy } from "@nestjs/common";
import mysql, { Pool, ResultSetHeader, RowDataPacket } from "mysql2/promise";
import { loadConfig } from "./config.js";

export type PluginUserWriteRoute =
  | "create-user"
  | "update-user"
  | "delete-user"
  | "change-role"
  | "batch-create-users"
  | "people-auth";
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

export interface PluginUserWriteOperationRecord {
  operationKey: string;
  idempotencyKey: string;
  route: PluginUserWriteRoute;
  mode: PluginUserWriteMode;
  actorSubject: string | null;
  targetSubject: string | null;
  legacyUserId: number | null;
  identityUserId: string | null;
  status: PluginUserWriteOperationStatus;
  legacyStatus: string | null;
  identityStatus: string | null;
  compensationStatus: PluginUserWriteCompensationStatus;
  errorCode: string | null;
  metadata: Record<string, unknown>;
}

export interface PluginUserWriteReplayResponse {
  status: number;
  body: unknown;
}

export interface PluginUserWriteOperationSummaryRow {
  route: PluginUserWriteRoute;
  mode: PluginUserWriteMode;
  status: PluginUserWriteOperationStatus;
  compensationStatus: PluginUserWriteCompensationStatus;
  total: number;
  firstRequestedAt: string | null;
  lastRequestedAt: string | null;
}

export interface PluginUserWriteOperationRecentRow {
  route: PluginUserWriteRoute;
  mode: PluginUserWriteMode;
  status: PluginUserWriteOperationStatus;
  compensationStatus: PluginUserWriteCompensationStatus;
  operationKeyDigest: string;
  idempotencyKeyDigest: string;
  legacyUserId: number | null;
  requestedAt: string | null;
  completedAt: string | null;
  correlationId?: string | null;
  rolloutDecision?: string | null;
  actorFingerprint?: string | null;
  matchedSelectorKind?: string | null;
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

  async findByOperationKey(operationKey: string): Promise<PluginUserWriteOperationRecord | null> {
    const pool = this.requirePool();
    await this.ensureSchema();

    const [rows] = await pool.execute<RowDataPacket[]>(
      `SELECT operation_key AS operationKey,
              idempotency_key AS idempotencyKey,
              route,
              mode,
              actor_subject AS actorSubject,
              target_subject AS targetSubject,
              legacy_user_id AS legacyUserId,
              identity_user_id AS identityUserId,
              status,
              legacy_status AS legacyStatus,
              identity_status AS identityStatus,
              compensation_status AS compensationStatus,
              error_code AS errorCode,
              metadata
         FROM plugin_user_write_operations
        WHERE operation_key = ?
        LIMIT 1`,
      [operationKey]
    );

    const row = rows[0];
    if (!row) {
      return null;
    }

    return {
      operationKey: String(row.operationKey),
      idempotencyKey: String(row.idempotencyKey),
      route: row.route as PluginUserWriteRoute,
      mode: row.mode as PluginUserWriteMode,
      actorSubject: nullableString(row.actorSubject),
      targetSubject: nullableString(row.targetSubject),
      legacyUserId: nullableNumber(row.legacyUserId),
      identityUserId: nullableString(row.identityUserId),
      status: row.status as PluginUserWriteOperationStatus,
      legacyStatus: nullableString(row.legacyStatus),
      identityStatus: nullableString(row.identityStatus),
      compensationStatus: row.compensationStatus as PluginUserWriteCompensationStatus,
      errorCode: nullableString(row.errorCode),
      metadata: parseMetadata(row.metadata)
    };
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

  async summarizeRecent(input: { sinceMinutes: number }): Promise<PluginUserWriteOperationSummaryRow[]> {
    const pool = this.requirePool();
    await this.ensureSchema();

    const since = new Date(Date.now() - Math.max(1, Math.min(1440, Math.trunc(input.sinceMinutes))) * 60_000);
    const [rows] = await pool.execute<RowDataPacket[]>(
      `SELECT route,
              mode,
              status,
              compensation_status AS compensationStatus,
              COUNT(*) AS total,
              MIN(requested_at) AS firstRequestedAt,
              MAX(requested_at) AS lastRequestedAt
         FROM plugin_user_write_operations
        WHERE requested_at >= ?
        GROUP BY route, mode, status, compensation_status
        ORDER BY route, mode, status, compensation_status`,
      [since]
    );

    return rows.map((row) => ({
      route: row.route as PluginUserWriteRoute,
      mode: row.mode as PluginUserWriteMode,
      status: row.status as PluginUserWriteOperationStatus,
      compensationStatus: row.compensationStatus as PluginUserWriteCompensationStatus,
      total: Number(row.total ?? 0),
      firstRequestedAt: dateString(row.firstRequestedAt),
      lastRequestedAt: dateString(row.lastRequestedAt)
    }));
  }

  async listRecentSafe(input: { sinceMinutes: number; limit: number }): Promise<PluginUserWriteOperationRecentRow[]> {
    const pool = this.requirePool();
    await this.ensureSchema();

    const since = new Date(Date.now() - Math.max(1, Math.min(1440, Math.trunc(input.sinceMinutes))) * 60_000);
    const limit = Math.max(1, Math.min(200, Math.trunc(input.limit)));
    const [rows] = await pool.query<RowDataPacket[]>(
      `SELECT operation_key AS operationKey,
              idempotency_key AS idempotencyKey,
              route,
              mode,
              status,
              compensation_status AS compensationStatus,
              legacy_user_id AS legacyUserId,
              requested_at AS requestedAt,
              completed_at AS completedAt,
              metadata
         FROM plugin_user_write_operations
        WHERE requested_at >= ?
        ORDER BY requested_at DESC, id DESC
        LIMIT ${limit}`,
      [since]
    );

    return rows.map((row) => {
      const metadata = parseMetadata(row.metadata);
      return {
        route: row.route as PluginUserWriteRoute,
        mode: row.mode as PluginUserWriteMode,
        status: row.status as PluginUserWriteOperationStatus,
        compensationStatus: row.compensationStatus as PluginUserWriteCompensationStatus,
        operationKeyDigest: shortDigest(row.operationKey),
        idempotencyKeyDigest: shortDigest(row.idempotencyKey),
        legacyUserId: nullableNumber(row.legacyUserId),
        requestedAt: dateString(row.requestedAt),
        completedAt: dateString(row.completedAt),
        correlationId: nullableString(metadata.correlationId),
        rolloutDecision: nullableString(metadata.rolloutDecision),
        actorFingerprint: nullableString(metadata.actorFingerprint),
        matchedSelectorKind: nullableString(metadata.matchedSelectorKind)
      };
    });
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
  const redacted = redactPluginUserWriteEvidence(value);
  if (redacted && typeof redacted === "object" && !Array.isArray(redacted)) {
    return redacted as Record<string, unknown>;
  }

  return { value: redacted };
}

export function redactPluginUserWriteEvidence(value: unknown): unknown {
  return redactValue(value, 0, {});
}

export function pluginUserWriteResponseReplayMetadata(input: { status: number; body: unknown }): Record<string, unknown> {
  return {
    responseReplay: {
      httpStatus: input.status,
      body: redactValue(input.body, 0, { preserveBusinessCode: true }),
      redacted: true
    }
  };
}

export function pluginUserWriteCompensationMetadata(input: {
  phase: "legacy" | "identity" | "replay";
  reason: string;
  errorCode?: string | null;
  legacyStatus?: string | number | null;
  identityStatus?: string | null;
  detail?: unknown;
}): Record<string, unknown> {
  return {
    compensation: {
      required: true,
      phase: input.phase,
      reason: input.reason,
      errorCode: input.errorCode ?? null,
      legacyStatus: input.legacyStatus ?? null,
      identityStatus: input.identityStatus ?? null,
      detail: redactPluginUserWriteEvidence(input.detail ?? {})
    }
  };
}

export function pluginUserWriteReplayResponseFromOperation(
  operation: Pick<PluginUserWriteOperationRecord, "status" | "metadata">
): PluginUserWriteReplayResponse | null {
  if (operation.status !== "completed") {
    return null;
  }

  const responseReplay = recordValue(operation.metadata.responseReplay);
  const httpStatus = Number(responseReplay?.httpStatus);
  if (!Number.isInteger(httpStatus) || httpStatus < 100 || httpStatus > 599 || !("body" in responseReplay)) {
    return null;
  }

  return {
    status: httpStatus,
    body: responseReplay.body
  };
}

function redactValue(value: unknown, depth: number, options: { preserveBusinessCode?: boolean }): unknown {
  if (depth > 8) {
    return "[truncated]";
  }

  if (Array.isArray(value)) {
    return value.map((item) => redactValue(item, depth + 1, options));
  }

  if (!value || typeof value !== "object") {
    return value;
  }

  const output: Record<string, unknown> = {};
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    if (isSecretKey(key, options)) {
      output[key] = "[redacted]";
      continue;
    }

    output[key] = redactValue(child, depth + 1, options);
  }

  return output;
}

function isSecretKey(key: string, options: { preserveBusinessCode?: boolean }): boolean {
  if (options.preserveBusinessCode && key.toLowerCase() === "code") {
    return false;
  }

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

function parseMetadata(value: unknown): Record<string, unknown> {
  if (!value) {
    return {};
  }

  if (typeof value === "object" && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }

  if (typeof value === "string") {
    try {
      const parsed = JSON.parse(value) as unknown;
      return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : {};
    } catch {
      return {};
    }
  }

  return {};
}

function dateString(value: unknown): string | null {
  if (value instanceof Date) {
    return value.toISOString();
  }

  return typeof value === "string" && value.trim() !== "" ? value : null;
}

function shortDigest(value: unknown): string {
  return createHash("sha256").update(String(value ?? "")).digest("hex").slice(0, 16);
}

function recordValue(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

function nullableString(value: unknown): string | null {
  return typeof value === "string" && value !== "" ? value : null;
}

function nullableNumber(value: unknown): number | null {
  if (value === null || value === undefined || value === "") {
    return null;
  }

  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric : null;
}
