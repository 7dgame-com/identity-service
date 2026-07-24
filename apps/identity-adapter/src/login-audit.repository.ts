import { Injectable, OnModuleDestroy } from "@nestjs/common";
import mysql, { Pool, ResultSetHeader, RowDataPacket } from "mysql2/promise";
import { loadConfig } from "./config.js";

export interface PersistedLoginAuditEvent {
  eventKey: string;
  legacyUserId: number | null;
  identityUserId: string | null;
  username: string | null;
  eventType: string;
  success: boolean;
  occurredAt: Date;
  ipAddress: string | null;
  ipAddressHash: string | null;
  userAgentHash: string | null;
  source: string;
  traceId: string | null;
  metadata: Record<string, unknown> | null;
}

export interface LoginAuditStats {
  legacyUserId: number | null;
  identityUserId: string | null;
  username: string | null;
  loginCount: number;
  failedLoginCount: number;
  lastLoginAt: string | null;
  lastFailedLoginAt: string | null;
  updatedAt: string | null;
}

export interface LoginAuditRecentEvent {
  eventKey: string;
  eventType: string;
  success: boolean;
  occurredAt: string;
  source: string;
  traceId: string | null;
  ipAddress: string | null;
  metadata: unknown;
}

export interface LoginUsageSourceEvent {
  legacyUserId: number;
  occurredAt: Date;
}

export type LoginAuditIpExposure = "full" | "masked";

@Injectable()
export class LoginAuditRepository implements OnModuleDestroy {
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

  async recordEvent(event: PersistedLoginAuditEvent): Promise<{ duplicate: boolean }> {
    const pool = this.requirePool();
    await this.ensureSchema();

    const [result] = await pool.execute<ResultSetHeader>(
      `INSERT IGNORE INTO auth_login_events
        (event_key, legacy_user_id, identity_user_id, username, event_type, success, occurred_at,
         ip_address, ip_address_hash, user_agent_hash, source, trace_id, metadata)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        event.eventKey,
        event.legacyUserId,
        event.identityUserId,
        event.username,
        event.eventType,
        event.success ? 1 : 0,
        event.occurredAt,
        event.ipAddress,
        event.ipAddressHash,
        event.userAgentHash,
        event.source,
        event.traceId,
        JSON.stringify(event.metadata ?? {})
      ]
    );

    const duplicate = result.affectedRows === 0;
    if (!duplicate) {
      await this.upsertStats(event);
    }

    return { duplicate };
  }

  async getUserAudit(
    legacyUserId: number,
    limit = 20,
    ipExposure: LoginAuditIpExposure = "full"
  ): Promise<{ stats: LoginAuditStats | null; recentEvents: LoginAuditRecentEvent[] }> {
    const pool = this.requirePool();
    await this.ensureSchema();

    const statsKey = statsKeyFor({ legacyUserId, identityUserId: null, username: null });
    const [statsRows] = await pool.execute<RowDataPacket[]>(
      `SELECT legacy_user_id AS legacyUserId,
              identity_user_id AS identityUserId,
              username,
              login_count AS loginCount,
              failed_login_count AS failedLoginCount,
              last_login_at AS lastLoginAt,
              last_failed_login_at AS lastFailedLoginAt,
              updated_at AS updatedAt
         FROM user_login_stats
        WHERE stats_key = ?
        LIMIT 1`,
      [statsKey]
    );

    const safeLimit = Math.max(1, Math.min(limit, 100));
    const [eventRows] = await pool.execute<RowDataPacket[]>(
      `SELECT event_key AS eventKey,
              event_type AS eventType,
              success,
              occurred_at AS occurredAt,
              source,
              trace_id AS traceId,
              ip_address AS ipAddress,
              metadata
         FROM auth_login_events
        WHERE legacy_user_id = ?
        ORDER BY occurred_at DESC, id DESC
        LIMIT ${safeLimit}`,
      [legacyUserId]
    );

    return {
      stats: statsRows[0] ? normalizeStats(statsRows[0]) : null,
      recentEvents: eventRows.map((row) => normalizeRecentEvent(row, ipExposure))
    };
  }

  async listSuccessfulLoginEventsByLegacyUserIds(
    legacyUserIds: number[],
    input: { from?: Date; to?: Date }
  ): Promise<LoginUsageSourceEvent[]> {
    if (legacyUserIds.length === 0) return [];

    const pool = this.requirePool();
    await this.ensureSchema();
    const ids = [...new Set(legacyUserIds)].filter(Number.isSafeInteger).filter((id) => id > 0);
    if (ids.length === 0) return [];

    const where = [
      "success = 1",
      "event_type = 'login'",
      `legacy_user_id IN (${ids.map(() => "?").join(", ")})`
    ];
    const params: Array<number | Date> = [...ids];
    if (input.from) {
      where.push("occurred_at >= ?");
      params.push(input.from);
    }
    if (input.to) {
      where.push("occurred_at <= ?");
      params.push(input.to);
    }

    const [rows] = await pool.execute<RowDataPacket[]>(
      `SELECT legacy_user_id AS legacyUserId,
              occurred_at AS occurredAt
         FROM auth_login_events
        WHERE ${where.join(" AND ")}
        ORDER BY legacy_user_id ASC, occurred_at ASC, id ASC`,
      params
    );

    return rows.map((row) => ({
      legacyUserId: Number(row.legacyUserId),
      occurredAt: row.occurredAt instanceof Date ? row.occurredAt : new Date(String(row.occurredAt))
    }));
  }

  private async upsertStats(event: PersistedLoginAuditEvent): Promise<void> {
    const pool = this.requirePool();
    const statsKey = statsKeyFor(event);
    const loginIncrement = event.success ? 1 : 0;
    const failedIncrement = event.success ? 0 : 1;
    const lastLoginAt = event.success ? event.occurredAt : null;
    const lastFailedLoginAt = event.success ? null : event.occurredAt;

    await pool.execute(
      `INSERT INTO user_login_stats
        (stats_key, legacy_user_id, identity_user_id, username, login_count, failed_login_count,
         last_login_at, last_failed_login_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE
         legacy_user_id = VALUES(legacy_user_id),
         identity_user_id = COALESCE(VALUES(identity_user_id), identity_user_id),
         username = COALESCE(VALUES(username), username),
         login_count = login_count + VALUES(login_count),
         failed_login_count = failed_login_count + VALUES(failed_login_count),
         last_login_at = CASE
           WHEN VALUES(last_login_at) IS NULL THEN last_login_at
           WHEN last_login_at IS NULL OR VALUES(last_login_at) > last_login_at THEN VALUES(last_login_at)
           ELSE last_login_at
         END,
         last_failed_login_at = CASE
           WHEN VALUES(last_failed_login_at) IS NULL THEN last_failed_login_at
           WHEN last_failed_login_at IS NULL OR VALUES(last_failed_login_at) > last_failed_login_at THEN VALUES(last_failed_login_at)
           ELSE last_failed_login_at
         END`,
      [
        statsKey,
        event.legacyUserId,
        event.identityUserId,
        event.username,
        loginIncrement,
        failedIncrement,
        lastLoginAt,
        lastFailedLoginAt
      ]
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
      CREATE TABLE IF NOT EXISTS auth_login_events (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        event_key VARCHAR(128) NOT NULL,
        legacy_user_id BIGINT NULL,
        identity_user_id VARCHAR(128) NULL,
        username VARCHAR(255) NULL,
        event_type VARCHAR(64) NOT NULL DEFAULT 'login',
        success TINYINT(1) NOT NULL DEFAULT 1,
        occurred_at DATETIME(3) NOT NULL,
        ip_address VARCHAR(45) NULL,
        ip_address_hash CHAR(64) NULL,
        user_agent_hash CHAR(64) NULL,
        source VARCHAR(64) NOT NULL DEFAULT 'legacy-backend',
        trace_id VARCHAR(128) NULL,
        metadata JSON NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY idx_auth_login_events_event_key (event_key),
        KEY idx_auth_login_events_legacy_user (legacy_user_id, occurred_at),
        KEY idx_auth_login_events_username (username, occurred_at)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    await this.ensureColumn("auth_login_events", "ip_address", "VARCHAR(45) NULL AFTER occurred_at");

    await pool.query(`
      CREATE TABLE IF NOT EXISTS user_login_stats (
        stats_key VARCHAR(255) NOT NULL,
        legacy_user_id BIGINT NULL,
        identity_user_id VARCHAR(128) NULL,
        username VARCHAR(255) NULL,
        login_count BIGINT UNSIGNED NOT NULL DEFAULT 0,
        failed_login_count BIGINT UNSIGNED NOT NULL DEFAULT 0,
        last_login_at DATETIME(3) NULL,
        last_failed_login_at DATETIME(3) NULL,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (stats_key),
        KEY idx_user_login_stats_legacy_user (legacy_user_id),
        KEY idx_user_login_stats_username (username)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);
  }

  private async ensureColumn(tableName: string, columnName: string, definition: string): Promise<void> {
    const pool = this.requirePool();
    const [rows] = await pool.execute<RowDataPacket[]>(
      `SELECT 1
         FROM information_schema.columns
        WHERE table_schema = DATABASE()
          AND table_name = ?
          AND column_name = ?
        LIMIT 1`,
      [tableName, columnName]
    );
    if (rows.length === 0) {
      await pool.query(`ALTER TABLE ${tableName} ADD COLUMN ${columnName} ${definition}`);
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

function statsKeyFor(input: Pick<PersistedLoginAuditEvent, "legacyUserId" | "identityUserId" | "username">): string {
  if (input.legacyUserId) {
    return `legacy:${input.legacyUserId}`;
  }
  if (input.identityUserId) {
    return `identity:${input.identityUserId}`;
  }

  return `username:${(input.username ?? "unknown").toLowerCase()}`;
}

function normalizeStats(row: RowDataPacket): LoginAuditStats {
  return {
    legacyUserId: row.legacyUserId === null ? null : Number(row.legacyUserId),
    identityUserId: row.identityUserId ?? null,
    username: row.username ?? null,
    loginCount: Number(row.loginCount),
    failedLoginCount: Number(row.failedLoginCount),
    lastLoginAt: dateToIso(row.lastLoginAt),
    lastFailedLoginAt: dateToIso(row.lastFailedLoginAt),
    updatedAt: dateToIso(row.updatedAt)
  };
}

function normalizeRecentEvent(row: RowDataPacket, ipExposure: LoginAuditIpExposure): LoginAuditRecentEvent {
  return {
    eventKey: String(row.eventKey),
    eventType: String(row.eventType),
    success: Boolean(row.success),
    occurredAt: dateToIso(row.occurredAt) ?? new Date(0).toISOString(),
    source: String(row.source),
    traceId: row.traceId ?? null,
    ipAddress: exposeIpAddress(row.ipAddress, ipExposure),
    metadata: parseJsonMaybe(row.metadata)
  };
}

function exposeIpAddress(value: unknown, exposure: LoginAuditIpExposure): string | null {
  if (typeof value !== "string" || !value.trim()) return null;
  const ipAddress = value.trim();
  return exposure === "full" ? ipAddress : maskIpAddress(ipAddress);
}

function maskIpAddress(ipAddress: string): string {
  if (ipAddress.includes(".")) {
    const segments = ipAddress.split(".");
    if (segments.length === 4) return `${segments.slice(0, 3).join(".")}.*`;
  }

  const segments = ipAddress.split(":").filter(Boolean);
  if (segments.length > 0) return `${segments.slice(0, 3).join(":")}:*`;
  return "*";
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
