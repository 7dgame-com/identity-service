import { Injectable, OnModuleDestroy } from "@nestjs/common";
import mysql, { Pool, ResultSetHeader, RowDataPacket } from "mysql2/promise";
import { loadConfig } from "./config.js";

export interface LoginAuditSourceEvent {
  id: number;
  eventKey: string;
  legacyUserId: number | null;
  identityUserId: string | null;
  username: string | null;
  eventType: string;
  success: boolean;
  occurredAt: Date;
  source: string;
}

export interface UsageLedgerRecord {
  ledgerKey: string;
  sourceEventId: number;
  subjectType: string;
  subjectId: string;
  usageType: string;
  quantity: number;
  unit: string;
  chargeMode: string;
  billingStatus: string;
  occurredAt: Date;
  metadata: Record<string, unknown>;
}

export interface UsageLedgerRow {
  ledgerKey: string;
  sourceEventId: number;
  subjectType: string;
  subjectId: string;
  usageType: string;
  quantity: number;
  unit: string;
  chargeMode: string;
  billingStatus: string;
  occurredAt: string;
  createdAt: string | null;
  metadata: unknown;
}

export interface UsageBalanceRow {
  subjectType: string;
  subjectId: string;
  usageType: string;
  includedQuota: number;
  usedQuantity: number;
  remainingQuantity: number;
  billingCycle: string;
  updatedAt: string | null;
}

export interface UsageReplayRunRow {
  runKey: string;
  mode: string;
  status: string;
  startedAt: string | null;
  finishedAt: string | null;
  processedCount: number;
  createdCount: number;
  skippedCount: number;
  metadata: unknown;
}

export interface LoginUsageReportRow {
  totalLedgerRecords: number;
  freeLoginRecords: number;
  billableLoginRecords: number;
  shadowRecords: number;
  usedQuantity: number;
}

@Injectable()
export class UsageBillingRepository implements OnModuleDestroy {
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

  async listSuccessfulLoginEvents(input: { afterId: number; limit: number }): Promise<LoginAuditSourceEvent[]> {
    const pool = this.requirePool();
    await this.ensureSchema();

    const safeLimit = Math.max(1, Math.min(input.limit, 5000));
    const [rows] = await pool.execute<RowDataPacket[]>(
      `SELECT id,
              event_key AS eventKey,
              legacy_user_id AS legacyUserId,
              identity_user_id AS identityUserId,
              username,
              event_type AS eventType,
              success,
              occurred_at AS occurredAt,
              source
         FROM auth_login_events
        WHERE id > ?
          AND success = 1
          AND event_type = 'login'
        ORDER BY id ASC
        LIMIT ${safeLimit}`,
      [input.afterId]
    );

    return rows.map(normalizeSourceEvent);
  }

  async insertLedger(record: UsageLedgerRecord): Promise<{ duplicate: boolean }> {
    const pool = this.requirePool();
    await this.ensureSchema();

    const [result] = await pool.execute<ResultSetHeader>(
      `INSERT IGNORE INTO usage_billing_ledger
        (ledger_key, source_event_id, subject_type, subject_id, usage_type, quantity, unit,
         charge_mode, billing_status, occurred_at, metadata)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        record.ledgerKey,
        record.sourceEventId,
        record.subjectType,
        record.subjectId,
        record.usageType,
        record.quantity,
        record.unit,
        record.chargeMode,
        record.billingStatus,
        record.occurredAt,
        JSON.stringify(record.metadata ?? {})
      ]
    );

    return { duplicate: result.affectedRows === 0 };
  }

  async createReplayRun(input: { runKey: string; mode: string; metadata: Record<string, unknown> }): Promise<void> {
    const pool = this.requirePool();
    await this.ensureSchema();

    await pool.execute(
      `INSERT INTO usage_billing_replay_runs
        (run_key, mode, status, started_at, metadata)
       VALUES (?, ?, 'running', ?, ?)
       ON DUPLICATE KEY UPDATE
         mode = VALUES(mode),
         status = 'running',
         started_at = VALUES(started_at),
         finished_at = NULL,
         processed_count = 0,
         created_count = 0,
         skipped_count = 0,
         metadata = VALUES(metadata)`,
      [input.runKey, input.mode, new Date(), JSON.stringify(input.metadata ?? {})]
    );
  }

  async finishReplayRun(input: {
    runKey: string;
    status: "succeeded" | "failed";
    processedCount: number;
    createdCount: number;
    skippedCount: number;
    metadata: Record<string, unknown>;
  }): Promise<void> {
    const pool = this.requirePool();
    await this.ensureSchema();

    await pool.execute(
      `UPDATE usage_billing_replay_runs
          SET status = ?,
              finished_at = ?,
              processed_count = ?,
              created_count = ?,
              skipped_count = ?,
              metadata = ?
        WHERE run_key = ?`,
      [
        input.status,
        new Date(),
        input.processedCount,
        input.createdCount,
        input.skippedCount,
        JSON.stringify(input.metadata ?? {}),
        input.runKey
      ]
    );
  }

  async rebuildShadowBalances(input: { includedQuota: number; billingCycle: string }): Promise<number> {
    const pool = this.requirePool();
    await this.ensureSchema();

    await pool.query("DELETE FROM account_usage_balance_shadow");
    const [result] = await pool.execute<ResultSetHeader>(
      `INSERT INTO account_usage_balance_shadow
        (subject_type, subject_id, usage_type, included_quota, used_quantity, remaining_quantity, billing_cycle)
       SELECT subject_type,
              subject_id,
              usage_type,
              ? AS included_quota,
              SUM(quantity) AS used_quantity,
              ? - SUM(quantity) AS remaining_quantity,
              ? AS billing_cycle
         FROM usage_billing_ledger
        WHERE billing_status = 'shadow'
        GROUP BY subject_type, subject_id, usage_type`,
      [input.includedQuota, input.includedQuota, input.billingCycle]
    );

    return result.affectedRows;
  }

  async getBalance(subjectType: string, subjectId: string, usageType = "login"): Promise<UsageBalanceRow | null> {
    const pool = this.requirePool();
    await this.ensureSchema();

    const [rows] = await pool.execute<RowDataPacket[]>(
      `SELECT subject_type AS subjectType,
              subject_id AS subjectId,
              usage_type AS usageType,
              included_quota AS includedQuota,
              used_quantity AS usedQuantity,
              remaining_quantity AS remainingQuantity,
              billing_cycle AS billingCycle,
              updated_at AS updatedAt
         FROM account_usage_balance_shadow
        WHERE subject_type = ?
          AND subject_id = ?
          AND usage_type = ?
        LIMIT 1`,
      [subjectType, subjectId, usageType]
    );

    return rows[0] ? normalizeBalance(rows[0]) : null;
  }

  async listLedger(limit = 50): Promise<UsageLedgerRow[]> {
    const pool = this.requirePool();
    await this.ensureSchema();

    const safeLimit = Math.max(1, Math.min(limit, 500));
    const [rows] = await pool.execute<RowDataPacket[]>(
      `SELECT ledger_key AS ledgerKey,
              source_event_id AS sourceEventId,
              subject_type AS subjectType,
              subject_id AS subjectId,
              usage_type AS usageType,
              quantity,
              unit,
              charge_mode AS chargeMode,
              billing_status AS billingStatus,
              occurred_at AS occurredAt,
              created_at AS createdAt,
              metadata
         FROM usage_billing_ledger
        ORDER BY id DESC
        LIMIT ${safeLimit}`
    );

    return rows.map(normalizeLedger);
  }

  async getReplayRun(runKey: string): Promise<UsageReplayRunRow | null> {
    const pool = this.requirePool();
    await this.ensureSchema();

    const [rows] = await pool.execute<RowDataPacket[]>(
      `SELECT run_key AS runKey,
              mode,
              status,
              started_at AS startedAt,
              finished_at AS finishedAt,
              processed_count AS processedCount,
              created_count AS createdCount,
              skipped_count AS skippedCount,
              metadata
         FROM usage_billing_replay_runs
        WHERE run_key = ?
        LIMIT 1`,
      [runKey]
    );

    return rows[0] ? normalizeRun(rows[0]) : null;
  }

  async getLoginUsageReport(input: { from?: Date; to?: Date }): Promise<LoginUsageReportRow> {
    const pool = this.requirePool();
    await this.ensureSchema();

    const conditions = ["usage_type = 'login'"];
    const params: Date[] = [];
    if (input.from) {
      conditions.push("occurred_at >= ?");
      params.push(input.from);
    }
    if (input.to) {
      conditions.push("occurred_at <= ?");
      params.push(input.to);
    }

    const [rows] = await pool.execute<RowDataPacket[]>(
      `SELECT COUNT(*) AS totalLedgerRecords,
              SUM(CASE WHEN charge_mode = 'free' THEN 1 ELSE 0 END) AS freeLoginRecords,
              SUM(CASE WHEN charge_mode = 'billable' THEN 1 ELSE 0 END) AS billableLoginRecords,
              SUM(CASE WHEN billing_status = 'shadow' THEN 1 ELSE 0 END) AS shadowRecords,
              COALESCE(SUM(quantity), 0) AS usedQuantity
         FROM usage_billing_ledger
        WHERE ${conditions.join(" AND ")}`,
      params
    );

    const row = rows[0] ?? {};
    return {
      totalLedgerRecords: Number(row.totalLedgerRecords ?? 0),
      freeLoginRecords: Number(row.freeLoginRecords ?? 0),
      billableLoginRecords: Number(row.billableLoginRecords ?? 0),
      shadowRecords: Number(row.shadowRecords ?? 0),
      usedQuantity: Number(row.usedQuantity ?? 0)
    };
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
      CREATE TABLE IF NOT EXISTS usage_billing_ledger (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        ledger_key VARCHAR(255) NOT NULL,
        source_event_id BIGINT UNSIGNED NOT NULL,
        subject_type VARCHAR(32) NOT NULL,
        subject_id VARCHAR(128) NOT NULL,
        usage_type VARCHAR(64) NOT NULL,
        quantity BIGINT NOT NULL DEFAULT 1,
        unit VARCHAR(32) NOT NULL DEFAULT 'times',
        charge_mode VARCHAR(64) NOT NULL DEFAULT 'shadow',
        billing_status VARCHAR(64) NOT NULL DEFAULT 'shadow',
        occurred_at DATETIME(3) NOT NULL,
        metadata JSON NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY idx_usage_billing_ledger_key (ledger_key),
        KEY idx_usage_billing_ledger_source (source_event_id),
        KEY idx_usage_billing_ledger_subject (subject_type, subject_id, usage_type, occurred_at),
        KEY idx_usage_billing_ledger_status (billing_status, occurred_at)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS account_usage_balance_shadow (
        subject_type VARCHAR(32) NOT NULL,
        subject_id VARCHAR(128) NOT NULL,
        usage_type VARCHAR(64) NOT NULL,
        included_quota BIGINT NOT NULL DEFAULT 0,
        used_quantity BIGINT NOT NULL DEFAULT 0,
        remaining_quantity BIGINT NOT NULL DEFAULT 0,
        billing_cycle VARCHAR(64) NOT NULL DEFAULT 'default',
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (subject_type, subject_id, usage_type, billing_cycle)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS usage_billing_replay_runs (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        run_key VARCHAR(160) NOT NULL,
        mode VARCHAR(32) NOT NULL,
        status VARCHAR(32) NOT NULL,
        started_at DATETIME(3) NOT NULL,
        finished_at DATETIME(3) NULL,
        processed_count BIGINT UNSIGNED NOT NULL DEFAULT 0,
        created_count BIGINT UNSIGNED NOT NULL DEFAULT 0,
        skipped_count BIGINT UNSIGNED NOT NULL DEFAULT 0,
        metadata JSON NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY idx_usage_billing_replay_runs_key (run_key),
        KEY idx_usage_billing_replay_runs_status (status, started_at)
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

function normalizeSourceEvent(row: RowDataPacket): LoginAuditSourceEvent {
  return {
    id: Number(row.id),
    eventKey: String(row.eventKey),
    legacyUserId: row.legacyUserId === null ? null : Number(row.legacyUserId),
    identityUserId: row.identityUserId ?? null,
    username: row.username ?? null,
    eventType: String(row.eventType),
    success: Boolean(row.success),
    occurredAt: row.occurredAt instanceof Date ? row.occurredAt : new Date(String(row.occurredAt)),
    source: String(row.source)
  };
}

function normalizeLedger(row: RowDataPacket): UsageLedgerRow {
  return {
    ledgerKey: String(row.ledgerKey),
    sourceEventId: Number(row.sourceEventId),
    subjectType: String(row.subjectType),
    subjectId: String(row.subjectId),
    usageType: String(row.usageType),
    quantity: Number(row.quantity),
    unit: String(row.unit),
    chargeMode: String(row.chargeMode),
    billingStatus: String(row.billingStatus),
    occurredAt: dateToIso(row.occurredAt) ?? new Date(0).toISOString(),
    createdAt: dateToIso(row.createdAt),
    metadata: parseJsonMaybe(row.metadata)
  };
}

function normalizeBalance(row: RowDataPacket): UsageBalanceRow {
  return {
    subjectType: String(row.subjectType),
    subjectId: String(row.subjectId),
    usageType: String(row.usageType),
    includedQuota: Number(row.includedQuota),
    usedQuantity: Number(row.usedQuantity),
    remainingQuantity: Number(row.remainingQuantity),
    billingCycle: String(row.billingCycle),
    updatedAt: dateToIso(row.updatedAt)
  };
}

function normalizeRun(row: RowDataPacket): UsageReplayRunRow {
  return {
    runKey: String(row.runKey),
    mode: String(row.mode),
    status: String(row.status),
    startedAt: dateToIso(row.startedAt),
    finishedAt: dateToIso(row.finishedAt),
    processedCount: Number(row.processedCount),
    createdCount: Number(row.createdCount),
    skippedCount: Number(row.skippedCount),
    metadata: parseJsonMaybe(row.metadata)
  };
}

function dateToIso(value: unknown): string | null {
  if (!value) {
    return null;
  }
  if (value instanceof Date) {
    return value.toISOString();
  }

  const parsed = new Date(String(value));
  return Number.isNaN(parsed.getTime()) ? null : parsed.toISOString();
}

function parseJsonMaybe(value: unknown): unknown {
  if (typeof value !== "string") {
    return value ?? null;
  }

  try {
    return JSON.parse(value);
  } catch {
    return value;
  }
}
