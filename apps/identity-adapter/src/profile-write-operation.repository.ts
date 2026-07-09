import { createHash } from "node:crypto";
import { Injectable, OnModuleDestroy } from "@nestjs/common";
import mysql, { Pool, ResultSetHeader, RowDataPacket } from "mysql2/promise";
import { loadConfig } from "./config.js";

export type ProfileWriteRoute = "update-profile";
export type ProfileWriteMode = "legacy-proxy" | "dual-write" | "identity-native";
export type ProfileWriteOperationStatus = "pending" | "legacy_completed" | "identity_completed" | "completed" | "failed";
export type ProfileWriteCompensationStatus = "none" | "required" | "in_progress" | "completed" | "failed";

export interface ProfileWriteOperationInput {
  operationKey: string;
  idempotencyKey: string;
  route: ProfileWriteRoute;
  mode: ProfileWriteMode;
  subjectId: string | null;
  legacyUserId?: number | null;
  identityUserId?: string | null;
  metadata?: Record<string, unknown> | null;
}

export interface ProfileWriteOperationUpdate {
  operationKey: string;
  status: ProfileWriteOperationStatus;
  legacyStatus?: string | null;
  identityStatus?: string | null;
  compensationStatus?: ProfileWriteCompensationStatus;
  errorCode?: string | null;
  metadata?: Record<string, unknown> | null;
}

export interface ProfileWriteOperationRecord {
  operationKey: string;
  idempotencyKey: string;
  route: ProfileWriteRoute;
  mode: ProfileWriteMode;
  subjectId: string | null;
  legacyUserId: number | null;
  identityUserId: string | null;
  status: ProfileWriteOperationStatus;
  legacyStatus: string | null;
  identityStatus: string | null;
  compensationStatus: ProfileWriteCompensationStatus;
  errorCode: string | null;
  metadata: Record<string, unknown>;
}

export interface ProfileWriteReplayResponse {
  status: number;
  body: unknown;
}

export interface ProfileWriteOperationSummaryRow {
  route: ProfileWriteRoute;
  mode: ProfileWriteMode;
  status: ProfileWriteOperationStatus;
  compensationStatus: ProfileWriteCompensationStatus;
  total: number;
  firstRequestedAt: string | null;
  lastRequestedAt: string | null;
}

export interface ProfileWriteOperationRecentRow {
  route: ProfileWriteRoute;
  mode: ProfileWriteMode;
  status: ProfileWriteOperationStatus;
  legacyStatus: string | null;
  identityStatus: string | null;
  compensationStatus: ProfileWriteCompensationStatus;
  errorCode: string | null;
  operationKeyDigest: string;
  idempotencyKeyDigest: string;
  legacyUserId: number | null;
  requestedAt: string | null;
  completedAt: string | null;
}

@Injectable()
export class ProfileWriteOperationRepository implements OnModuleDestroy {
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

  async begin(input: ProfileWriteOperationInput): Promise<{ duplicate: boolean }> {
    const pool = this.requirePool();
    await this.ensureSchema();

    const [result] = await pool.execute<ResultSetHeader>(
      `INSERT IGNORE INTO profile_write_operations
        (operation_key, idempotency_key, route, mode, subject_id, legacy_user_id,
         identity_user_id, status, compensation_status, requested_at, metadata)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', 'none', ?, ?)`,
      [
        input.operationKey,
        input.idempotencyKey,
        input.route,
        input.mode,
        input.subjectId,
        input.legacyUserId ?? null,
        input.identityUserId ?? null,
        new Date(),
        stringifyJson(redactProfileWriteMetadata(input.metadata))
      ]
    );

    return { duplicate: result.affectedRows === 0 };
  }

  async findByOperationKey(operationKey: string): Promise<ProfileWriteOperationRecord | null> {
    const pool = this.requirePool();
    await this.ensureSchema();

    const [rows] = await pool.execute<RowDataPacket[]>(
      `SELECT operation_key AS operationKey,
              idempotency_key AS idempotencyKey,
              route,
              mode,
              subject_id AS subjectId,
              legacy_user_id AS legacyUserId,
              identity_user_id AS identityUserId,
              status,
              legacy_status AS legacyStatus,
              identity_status AS identityStatus,
              compensation_status AS compensationStatus,
              error_code AS errorCode,
              metadata
         FROM profile_write_operations
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
      route: row.route as ProfileWriteRoute,
      mode: row.mode as ProfileWriteMode,
      subjectId: nullableString(row.subjectId),
      legacyUserId: nullableNumber(row.legacyUserId),
      identityUserId: nullableString(row.identityUserId),
      status: row.status as ProfileWriteOperationStatus,
      legacyStatus: nullableString(row.legacyStatus),
      identityStatus: nullableString(row.identityStatus),
      compensationStatus: row.compensationStatus as ProfileWriteCompensationStatus,
      errorCode: nullableString(row.errorCode),
      metadata: parseMetadata(row.metadata)
    };
  }

  async update(input: ProfileWriteOperationUpdate): Promise<void> {
    const pool = this.requirePool();
    await this.ensureSchema();

    await pool.execute(
      `UPDATE profile_write_operations
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
        stringifyJson(redactProfileWriteMetadata(input.metadata)),
        input.operationKey
      ]
    );
  }

  async summarizeRecent(input: { sinceMinutes: number }): Promise<ProfileWriteOperationSummaryRow[]> {
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
         FROM profile_write_operations
        WHERE requested_at >= ?
        GROUP BY route, mode, status, compensation_status
        ORDER BY route, mode, status, compensation_status`,
      [since]
    );

    return rows.map((row) => ({
      route: row.route as ProfileWriteRoute,
      mode: row.mode as ProfileWriteMode,
      status: row.status as ProfileWriteOperationStatus,
      compensationStatus: row.compensationStatus as ProfileWriteCompensationStatus,
      total: Number(row.total ?? 0),
      firstRequestedAt: dateString(row.firstRequestedAt),
      lastRequestedAt: dateString(row.lastRequestedAt)
    }));
  }

  async listRecentSafe(input: { sinceMinutes: number; limit: number }): Promise<ProfileWriteOperationRecentRow[]> {
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
              legacy_status AS legacyStatus,
              identity_status AS identityStatus,
              compensation_status AS compensationStatus,
              error_code AS errorCode,
              legacy_user_id AS legacyUserId,
              requested_at AS requestedAt,
              completed_at AS completedAt
         FROM profile_write_operations
        WHERE requested_at >= ?
        ORDER BY requested_at DESC, id DESC
        LIMIT ${limit}`,
      [since]
    );

    return rows.map((row) => ({
      route: row.route as ProfileWriteRoute,
      mode: row.mode as ProfileWriteMode,
      status: row.status as ProfileWriteOperationStatus,
      legacyStatus: nullableString(row.legacyStatus),
      identityStatus: nullableString(row.identityStatus),
      compensationStatus: row.compensationStatus as ProfileWriteCompensationStatus,
      errorCode: nullableString(row.errorCode),
      operationKeyDigest: shortDigest(row.operationKey),
      idempotencyKeyDigest: shortDigest(row.idempotencyKey),
      legacyUserId: nullableNumber(row.legacyUserId),
      requestedAt: dateString(row.requestedAt),
      completedAt: dateString(row.completedAt)
    }));
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
      CREATE TABLE IF NOT EXISTS profile_write_operations (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        operation_key VARCHAR(180) NOT NULL,
        idempotency_key VARCHAR(180) NOT NULL,
        route VARCHAR(64) NOT NULL,
        mode VARCHAR(32) NOT NULL,
        subject_id VARCHAR(128) NULL,
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
        UNIQUE KEY idx_profile_write_operations_key (operation_key),
        UNIQUE KEY idx_profile_write_operations_idempotency (idempotency_key),
        KEY idx_profile_write_operations_route_status (route, status, requested_at),
        KEY idx_profile_write_operations_legacy_user (legacy_user_id, requested_at),
        KEY idx_profile_write_operations_identity_user (identity_user_id, requested_at),
        KEY idx_profile_write_operations_compensation (compensation_status, requested_at)
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

export function profileWriteOperationKey(input: {
  subjectId: string | null;
  route: ProfileWriteRoute;
  requestFingerprint: string;
}): string {
  const subject = input.subjectId ?? "anonymous";
  return `profile-write:v1:${subject}:v1/user/update:${input.requestFingerprint.slice(0, 48)}`;
}

export function profileWriteRequestFingerprint(payload: unknown): string {
  const sanitized = redactProfileWriteMetadata(payload);
  return createHash("sha256").update(`update-profile\u001f${stableStringify(sanitized)}`).digest("hex");
}

export function redactProfileWriteMetadata(value: unknown): Record<string, unknown> {
  const redacted = redactProfileWriteEvidence(value);
  if (redacted && typeof redacted === "object" && !Array.isArray(redacted)) {
    return redacted as Record<string, unknown>;
  }

  return { value: redacted };
}

export function redactProfileWriteEvidence(value: unknown): unknown {
  return redactValue(value, 0, {});
}

export function profileWriteResponseReplayMetadata(input: { status: number; body: unknown }): Record<string, unknown> {
  return {
    responseReplay: {
      httpStatus: input.status,
      body: redactValue(input.body, 0, { preserveBusinessCode: true }),
      redacted: true
    }
  };
}

export function profileWriteCompensationMetadata(input: {
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
      detail: redactProfileWriteEvidence(input.detail ?? {})
    }
  };
}

export function profileWriteReplayResponseFromOperation(
  operation: Pick<ProfileWriteOperationRecord, "status" | "metadata">
): ProfileWriteReplayResponse | null {
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
