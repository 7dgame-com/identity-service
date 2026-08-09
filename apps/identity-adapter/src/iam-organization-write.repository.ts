import { createHash } from "node:crypto";
import { Injectable, OnModuleDestroy } from "@nestjs/common";
import mysql, { Pool, ResultSetHeader, RowDataPacket } from "mysql2/promise";
import { loadConfig } from "./config.js";
import type { LegacyOrganization } from "./legacy-identity.reader.js";

export type OrganizationWriteOperationStatus = "pending" | "legacy_completed" | "completed" | "failed";
export type OrganizationWriteCompensationStatus = "none" | "required" | "completed" | "failed";
export type OrganizationWriteOperationMode = "dual-write" | "candidate-materialization";

export const ORGANIZATION_CANDIDATE_MATERIALIZATION_PENDING_LEASE_MS = 5 * 60_000;

const ORGANIZATION_MATERIALIZATION_TABLES = [
  "identity_organizations_candidate",
  "identity_organization_id_map",
  "identity_organization_memberships_candidate",
  "identity_organization_membership_snapshots",
  "identity_organization_write_operations"
] as const;

export interface OrganizationMaterializationSchemaReadiness {
  ready: boolean;
  requiredTableCount: number;
  existingTableCount: number;
  missingTables: string[];
}

export interface OrganizationWriteOperationRecord {
  operationKey: string;
  idempotencyKeyDigest: string;
  requestFingerprint: string;
  legacyUserId: number;
  mode: OrganizationWriteOperationMode;
  status: OrganizationWriteOperationStatus;
  legacyStatus: string | null;
  identityStatus: string | null;
  compensationStatus: OrganizationWriteCompensationStatus;
  errorCode: string | null;
  requestedAt: string | null;
  completedAt: string | null;
  metadata: Record<string, unknown>;
}

export interface OrganizationCandidateSnapshot {
  legacyUserId: number;
  organizations: LegacyOrganization[];
}

@Injectable()
export class IamOrganizationWriteRepository implements OnModuleDestroy {
  private readonly config = loadConfig();
  private readonly pool: Pool | null;
  private schemaReady: Promise<void> | null = null;

  constructor() {
    const { identityDb } = this.config;
    this.pool = identityDb.host && identityDb.user
      ? mysql.createPool({
          host: identityDb.host,
          port: identityDb.port,
          database: identityDb.name,
          user: identityDb.user,
          password: identityDb.password,
          waitForConnections: true,
          connectionLimit: 5,
          namedPlaceholders: false
        })
      : null;
  }

  async onModuleDestroy(): Promise<void> {
    await this.pool?.end();
  }

  isConfigured(): boolean {
    return this.pool !== null;
  }

  async begin(input: {
    operationKey: string;
    idempotencyKeyDigest: string;
    requestFingerprint: string;
    legacyUserId: number;
    metadata: Record<string, unknown>;
  }): Promise<{ duplicate: boolean }> {
    const pool = this.requirePool();
    await this.ensureSchema();
    const [result] = await pool.execute<ResultSetHeader>(
      `INSERT IGNORE INTO identity_organization_write_operations
        (operation_key, idempotency_key_digest, request_fingerprint, legacy_user_id, mode,
         status, compensation_status, requested_at, metadata)
       VALUES (?, ?, ?, ?, 'dual-write', 'pending', 'none', ?, ?)`,
      [
        input.operationKey,
        input.idempotencyKeyDigest,
        input.requestFingerprint,
        input.legacyUserId,
        new Date(),
        JSON.stringify(redactOrganizationWriteMetadata(input.metadata))
      ]
    );
    return { duplicate: result.affectedRows === 0 };
  }

  async beginCandidateMaterialization(input: {
    operationKey: string;
    idempotencyKeyDigest: string;
    requestFingerprint: string;
    legacyUserId: number;
    claimToken: string;
    metadata: Record<string, unknown>;
  }): Promise<{ duplicate: boolean }> {
    const pool = this.requirePool();
    const [result] = await pool.execute<ResultSetHeader>(
      `INSERT IGNORE INTO identity_organization_write_operations
        (operation_key, idempotency_key_digest, request_fingerprint, legacy_user_id, mode,
         status, legacy_status, identity_status, compensation_status, requested_at, metadata)
       VALUES (?, ?, ?, ?, 'candidate-materialization', 'pending', 'read-only', 'pending', 'none', ?, ?)`,
      [
        input.operationKey,
        input.idempotencyKeyDigest,
        input.requestFingerprint,
        input.legacyUserId,
        new Date(),
        JSON.stringify(candidateClaimMetadata(input.metadata, input.claimToken))
      ]
    );
    return { duplicate: result.affectedRows === 0 };
  }

  async resumeCandidateMaterialization(
    operationKey: string,
    expectedRequestFingerprint: string,
    requestFingerprint: string,
    claimToken: string,
    metadata: Record<string, unknown>
  ): Promise<{ claimed: boolean }> {
    const pool = this.requirePool();
    const [result] = await pool.execute<ResultSetHeader>(
      `UPDATE identity_organization_write_operations
          SET status = 'pending',
              request_fingerprint = ?,
              legacy_status = 'read-only',
              identity_status = 'pending',
              compensation_status = 'none',
              error_code = NULL,
              requested_at = ?,
              completed_at = NULL,
              metadata = ?
        WHERE operation_key = ?
          AND mode = 'candidate-materialization'
          AND status = 'failed'
          AND compensation_status IN ('none', 'required', 'failed')
          AND request_fingerprint = ?`,
      [
        requestFingerprint,
        new Date(),
        JSON.stringify(candidateClaimMetadata(metadata, claimToken)),
        operationKey,
        expectedRequestFingerprint
      ]
    );
    return { claimed: result.affectedRows === 1 };
  }

  async reclaimStaleCandidateMaterialization(input: {
    operationKey: string;
    expectedRequestFingerprint: string;
    requestFingerprint: string;
    claimToken: string;
    staleBefore: Date;
    metadata: Record<string, unknown>;
  }): Promise<{ claimed: boolean }> {
    const pool = this.requirePool();
    const [result] = await pool.execute<ResultSetHeader>(
      `UPDATE identity_organization_write_operations
          SET request_fingerprint = ?,
              legacy_status = 'read-only',
              identity_status = 'pending',
              compensation_status = 'none',
              error_code = NULL,
              requested_at = ?,
              completed_at = NULL,
              metadata = ?
        WHERE operation_key = ?
          AND mode = 'candidate-materialization'
          AND status = 'pending'
          AND compensation_status = 'none'
          AND request_fingerprint = ?
          AND requested_at <= ?`,
      [
        input.requestFingerprint,
        new Date(),
        JSON.stringify(candidateClaimMetadata(input.metadata, input.claimToken)),
        input.operationKey,
        input.expectedRequestFingerprint,
        input.staleBefore
      ]
    );
    return { claimed: result.affectedRows === 1 };
  }

  async finalizeCandidateMaterialization(input: {
    operationKey: string;
    status: "completed" | "failed";
    legacyStatus: string;
    identityStatus: string;
    compensationStatus: OrganizationWriteCompensationStatus;
    claimToken: string;
    leaseValidAfter: Date;
    errorCode?: string | null;
    metadata: Record<string, unknown>;
  }): Promise<{ updated: boolean }> {
    const pool = this.requirePool();
    const [result] = await pool.execute<ResultSetHeader>(
      `UPDATE identity_organization_write_operations
          SET status = ?,
              legacy_status = ?,
              identity_status = ?,
              compensation_status = ?,
              error_code = ?,
              completed_at = ?,
              metadata = ?
        WHERE operation_key = ?
          AND mode = 'candidate-materialization'
          AND status = 'pending'
          AND compensation_status = 'none'
          AND JSON_UNQUOTE(JSON_EXTRACT(metadata, '$._claimDigest')) = SHA2(?, 256)
          AND requested_at > ?`,
      [
        input.status,
        input.legacyStatus,
        input.identityStatus,
        input.compensationStatus,
        input.errorCode ?? null,
        new Date(),
        JSON.stringify(redactOrganizationWriteMetadata(input.metadata)),
        input.operationKey,
        input.claimToken,
        input.leaseValidAfter
      ]
    );
    return { updated: result.affectedRows === 1 };
  }

  async find(operationKey: string): Promise<OrganizationWriteOperationRecord | null> {
    const pool = this.requirePool();
    const [rows] = await pool.execute<RowDataPacket[]>(
      `SELECT operation_key AS operationKey,
              idempotency_key_digest AS idempotencyKeyDigest,
              request_fingerprint AS requestFingerprint,
              legacy_user_id AS legacyUserId,
              mode, status,
              legacy_status AS legacyStatus,
              identity_status AS identityStatus,
              compensation_status AS compensationStatus,
              error_code AS errorCode,
              requested_at AS requestedAt,
              completed_at AS completedAt,
              metadata
         FROM identity_organization_write_operations
        WHERE operation_key = ? LIMIT 1`,
      [operationKey]
    );
    const row = rows[0];
    return row ? operationRecord(row) : null;
  }

  async update(input: {
    operationKey: string;
    status: OrganizationWriteOperationStatus;
    legacyStatus?: string | null;
    identityStatus?: string | null;
    compensationStatus?: OrganizationWriteCompensationStatus;
    errorCode?: string | null;
    metadata?: Record<string, unknown>;
  }): Promise<void> {
    const pool = this.requirePool();
    await pool.execute(
      `UPDATE identity_organization_write_operations
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
        JSON.stringify(redactOrganizationWriteMetadata(input.metadata ?? {})),
        input.operationKey
      ]
    );
  }

  async replaceCandidate(input: OrganizationCandidateSnapshot & {
    operationKey: string;
    materializationClaim?: { claimToken: string; leaseValidAfter: Date };
  }): Promise<void> {
    const pool = this.requirePool();
    const connection = await pool.getConnection();
    try {
      await connection.beginTransaction();
      if (input.materializationClaim) {
        const [claimRows] = await connection.execute<RowDataPacket[]>(
          `SELECT id
             FROM identity_organization_write_operations
            WHERE operation_key = ?
              AND mode = 'candidate-materialization'
              AND status = 'pending'
              AND compensation_status = 'none'
              AND JSON_UNQUOTE(JSON_EXTRACT(metadata, '$._claimDigest')) = SHA2(?, 256)
              AND requested_at > ?
            FOR UPDATE`,
          [input.operationKey, input.materializationClaim.claimToken, input.materializationClaim.leaseValidAfter]
        );
        if (!claimRows[0]) throw new Error("CandidateMaterializationLeaseLost");
      }
      for (const organization of input.organizations) {
        const identityOrganizationId = identityOrganizationIdForLegacy(organization.id);
        await connection.execute(
          `INSERT INTO identity_organizations_candidate
             (identity_organization_id, legacy_organization_id, name, title, source, candidate_status, metadata)
           VALUES (?, ?, ?, ?, 'legacy', 'candidate', ?)
           ON DUPLICATE KEY UPDATE name = VALUES(name), title = VALUES(title), metadata = VALUES(metadata)`,
          [
            identityOrganizationId,
            organization.id,
            organization.name,
            organization.title,
            JSON.stringify({ legacyCreatedAt: organization.createdAt, legacyUpdatedAt: organization.updatedAt })
          ]
        );
        await connection.execute(
          `INSERT INTO identity_organization_id_map
             (legacy_organization_id, identity_organization_id, source, mapping_status)
           VALUES (?, ?, 'legacy', 'active')
           ON DUPLICATE KEY UPDATE identity_organization_id = VALUES(identity_organization_id), mapping_status = 'active'`,
          [organization.id, identityOrganizationId]
        );
      }

      await connection.execute(
        `DELETE FROM identity_organization_memberships_candidate WHERE legacy_user_id = ?`,
        [input.legacyUserId]
      );
      for (const organization of input.organizations) {
        await connection.execute(
          `INSERT INTO identity_organization_memberships_candidate
             (identity_user_id, legacy_user_id, identity_organization_id, legacy_organization_id,
              organization_role, source, candidate_status, operation_key)
           VALUES (?, ?, ?, ?, 'member', 'legacy', 'candidate', ?)`,
          [
            `legacy:${input.legacyUserId}`,
            input.legacyUserId,
            identityOrganizationIdForLegacy(organization.id),
            organization.id,
            input.operationKey
          ]
        );
      }
      await connection.execute(
        `INSERT INTO identity_organization_membership_snapshots
           (identity_user_id, legacy_user_id, operation_key, organization_count, source, candidate_status)
         VALUES (?, ?, ?, ?, 'legacy', 'candidate')
         ON DUPLICATE KEY UPDATE operation_key = VALUES(operation_key),
                                 organization_count = VALUES(organization_count),
                                 candidate_status = 'candidate'`,
        [`legacy:${input.legacyUserId}`, input.legacyUserId, input.operationKey, input.organizations.length]
      );
      await connection.commit();
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  }

  async candidateForLegacyUser(legacyUserId: number): Promise<OrganizationCandidateSnapshot | null> {
    const pool = this.requirePool();
    const [snapshots] = await pool.execute<RowDataPacket[]>(
      `SELECT legacy_user_id AS legacyUserId
         FROM identity_organization_membership_snapshots
        WHERE legacy_user_id = ? LIMIT 1`,
      [legacyUserId]
    );
    if (!snapshots[0]) return null;
    const [rows] = await pool.execute<RowDataPacket[]>(
      `SELECT o.legacy_organization_id AS id, o.name, o.title,
              JSON_UNQUOTE(JSON_EXTRACT(o.metadata, '$.legacyCreatedAt')) AS createdAt,
              JSON_UNQUOTE(JSON_EXTRACT(o.metadata, '$.legacyUpdatedAt')) AS updatedAt
         FROM identity_organization_memberships_candidate m
         JOIN identity_organizations_candidate o
           ON o.identity_organization_id = m.identity_organization_id
        WHERE m.legacy_user_id = ?
        ORDER BY o.legacy_organization_id ASC`,
      [legacyUserId]
    );
    return {
      legacyUserId,
      organizations: rows.map((row) => ({
        id: Number(row.id),
        name: String(row.name),
        title: String(row.title),
        createdAt: nullableNumber(row.createdAt),
        updatedAt: nullableNumber(row.updatedAt)
      }))
    };
  }

  async countUnresolvedForLegacyUser(legacyUserId: number, excludeOperationKey?: string): Promise<number> {
    const pool = this.requirePool();
    const exclusion = excludeOperationKey ? " AND operation_key <> ?" : "";
    const params: Array<number | string> = excludeOperationKey
      ? [legacyUserId, excludeOperationKey]
      : [legacyUserId];
    const [rows] = await pool.execute<RowDataPacket[]>(
      `SELECT COUNT(*) AS total
         FROM identity_organization_write_operations
        WHERE legacy_user_id = ?
          AND NOT (
            mode IN ('dual-write', 'candidate-materialization')
            AND (
              (status = 'completed' AND compensation_status IN ('none', 'completed'))
              OR (status = 'failed' AND compensation_status = 'none')
            )
          )${exclusion}`,
      params
    );
    return Number(rows[0]?.total ?? 0);
  }

  async summarizeRecent(sinceMinutes: number): Promise<Record<string, unknown>[]> {
    const pool = this.requirePool();
    const since = new Date(Date.now() - clamp(sinceMinutes, 1, 1440) * 60_000);
    const [rows] = await pool.execute<RowDataPacket[]>(
      `SELECT mode, status, compensation_status AS compensationStatus, COUNT(*) AS total,
              MIN(requested_at) AS firstRequestedAt, MAX(requested_at) AS lastRequestedAt
         FROM identity_organization_write_operations
        WHERE requested_at >= ?
        GROUP BY mode, status, compensation_status
        ORDER BY mode, status, compensation_status`,
      [since]
    );
    return rows.map((row) => ({
      mode: String(row.mode),
      status: String(row.status),
      compensationStatus: String(row.compensationStatus),
      total: Number(row.total),
      firstRequestedAt: dateString(row.firstRequestedAt),
      lastRequestedAt: dateString(row.lastRequestedAt)
    }));
  }

  async listRecentSafe(sinceMinutes: number, limit: number): Promise<Record<string, unknown>[]> {
    const pool = this.requirePool();
    const since = new Date(Date.now() - clamp(sinceMinutes, 1, 1440) * 60_000);
    const safeLimit = clamp(limit, 1, 200);
    const [rows] = await pool.query<RowDataPacket[]>(
      `SELECT operation_key AS operationKey, idempotency_key_digest AS idempotencyKeyDigest,
              legacy_user_id AS legacyUserId, mode, status,
              compensation_status AS compensationStatus, requested_at AS requestedAt,
              completed_at AS completedAt, metadata
         FROM identity_organization_write_operations
        WHERE requested_at >= ? ORDER BY requested_at DESC, id DESC LIMIT ${safeLimit}`,
      [since]
    );
    return rows.map((row) => ({
      operationKeyDigest: digest(String(row.operationKey)),
      idempotencyKeyDigest: String(row.idempotencyKeyDigest),
      legacyUserId: Number(row.legacyUserId),
      mode: String(row.mode),
      status: String(row.status),
      compensationStatus: String(row.compensationStatus),
      requestedAt: dateString(row.requestedAt),
      completedAt: dateString(row.completedAt),
      metadata: publicOrganizationWriteMetadata(parseMetadata(row.metadata))
    }));
  }

  async materializationSchemaReadiness(): Promise<OrganizationMaterializationSchemaReadiness> {
    const pool = this.requirePool();
    const placeholders = ORGANIZATION_MATERIALIZATION_TABLES.map(() => "?").join(", ");
    const [rows] = await pool.query<RowDataPacket[]>(
      `SELECT table_name AS tableName
         FROM information_schema.tables
        WHERE table_schema = DATABASE()
          AND table_name IN (${placeholders})`,
      [...ORGANIZATION_MATERIALIZATION_TABLES]
    );
    const existing = new Set(rows.map((row) => String(row.tableName)));
    const missingTables: string[] = ORGANIZATION_MATERIALIZATION_TABLES.filter((table) => !existing.has(table));
    return {
      ready: missingTables.length === 0,
      requiredTableCount: ORGANIZATION_MATERIALIZATION_TABLES.length,
      existingTableCount: ORGANIZATION_MATERIALIZATION_TABLES.length - missingTables.length,
      missingTables
    };
  }

  async withCandidateMaterializationSubjectLock<T>(
    legacyUserId: number,
    callback: () => Promise<T>
  ): Promise<{ acquired: false } | { acquired: true; value: T }> {
    const pool = this.requirePool();
    const connection = await pool.getConnection();
    const lockName = organizationCandidateMaterializationSubjectLockName(legacyUserId);
    let acquired = false;
    let reusable = true;
    try {
      const [rows] = await connection.execute<RowDataPacket[]>("SELECT GET_LOCK(?, 0) AS acquired", [lockName]);
      acquired = Number(rows[0]?.acquired) === 1;
      if (!acquired) return { acquired: false };
      return { acquired: true, value: await callback() };
    } finally {
      if (acquired) {
        try {
          const [rows] = await connection.execute<RowDataPacket[]>("SELECT RELEASE_LOCK(?) AS released", [lockName]);
          if (Number(rows[0]?.released) !== 1) {
            reusable = false;
            connection.destroy();
          }
        } catch {
          reusable = false;
          connection.destroy();
        }
      }
      if (reusable) connection.release();
    }
  }

  private async ensureSchema(): Promise<void> {
    this.schemaReady ??= this.createSchema();
    await this.schemaReady;
  }

  private async createSchema(): Promise<void> {
    const pool = this.requirePool();
    await pool.query(`CREATE TABLE IF NOT EXISTS identity_organizations_candidate (
      identity_organization_id VARCHAR(128) NOT NULL,
      legacy_organization_id BIGINT NOT NULL,
      name VARCHAR(128) NOT NULL,
      title VARCHAR(255) NOT NULL,
      source VARCHAR(32) NOT NULL,
      candidate_status VARCHAR(32) NOT NULL,
      metadata JSON NULL,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      PRIMARY KEY (identity_organization_id),
      UNIQUE KEY idx_identity_org_candidate_legacy_id (legacy_organization_id),
      UNIQUE KEY idx_identity_org_candidate_name (name)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`);
    await pool.query(`CREATE TABLE IF NOT EXISTS identity_organization_id_map (
      legacy_organization_id BIGINT NOT NULL,
      identity_organization_id VARCHAR(128) NOT NULL,
      source VARCHAR(32) NOT NULL,
      mapping_status VARCHAR(32) NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      PRIMARY KEY (legacy_organization_id),
      UNIQUE KEY idx_identity_org_map_identity_id (identity_organization_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`);
    await pool.query(`CREATE TABLE IF NOT EXISTS identity_organization_memberships_candidate (
      identity_user_id VARCHAR(128) NOT NULL,
      legacy_user_id BIGINT NOT NULL,
      identity_organization_id VARCHAR(128) NOT NULL,
      legacy_organization_id BIGINT NOT NULL,
      organization_role VARCHAR(64) NOT NULL,
      source VARCHAR(32) NOT NULL,
      candidate_status VARCHAR(32) NOT NULL,
      operation_key VARCHAR(160) NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      PRIMARY KEY (identity_user_id, identity_organization_id),
      KEY idx_identity_org_membership_legacy_user (legacy_user_id),
      KEY idx_identity_org_membership_legacy_org (legacy_organization_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`);
    await pool.query(`CREATE TABLE IF NOT EXISTS identity_organization_membership_snapshots (
      identity_user_id VARCHAR(128) NOT NULL,
      legacy_user_id BIGINT NOT NULL,
      operation_key VARCHAR(160) NOT NULL,
      organization_count INT UNSIGNED NOT NULL,
      source VARCHAR(32) NOT NULL,
      candidate_status VARCHAR(32) NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      PRIMARY KEY (identity_user_id),
      UNIQUE KEY idx_identity_org_snapshot_legacy_user (legacy_user_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`);
    await pool.query(`CREATE TABLE IF NOT EXISTS identity_organization_write_operations (
      id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      operation_key VARCHAR(160) NOT NULL,
      idempotency_key_digest CHAR(64) NOT NULL,
      request_fingerprint CHAR(64) NOT NULL,
      legacy_user_id BIGINT NOT NULL,
      mode VARCHAR(32) NOT NULL,
      status VARCHAR(32) NOT NULL,
      legacy_status VARCHAR(64) NULL,
      identity_status VARCHAR(64) NULL,
      compensation_status VARCHAR(32) NOT NULL,
      error_code VARCHAR(128) NULL,
      requested_at DATETIME(3) NOT NULL,
      completed_at DATETIME(3) NULL,
      metadata JSON NULL,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      PRIMARY KEY (id),
      UNIQUE KEY idx_identity_org_write_operation_key (operation_key),
      KEY idx_identity_org_write_user_status (legacy_user_id, status, requested_at),
      KEY idx_identity_org_write_compensation (compensation_status, requested_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`);
  }

  private requirePool(): Pool {
    if (!this.pool) throw new Error("identity database is not configured");
    return this.pool;
  }
}

export function organizationWriteOperationKey(legacyUserId: number, idempotencyKey: string): string {
  return `iam-organization-write:v1:membership-replace:${digest(`${legacyUserId}\u001f${idempotencyKey}`).slice(0, 48)}`;
}

export function organizationWriteRequestFingerprint(legacyUserId: number, organizationIds: number[]): string {
  return digest(`${legacyUserId}\u001f${[...organizationIds].sort((a, b) => a - b).join(",")}`);
}

export function organizationCandidateMaterializationOperationKey(legacyUserId: number, idempotencyKey: string): string {
  return `iam-organization-write:v1:candidate-materialization:${digest(`${legacyUserId}\u001f${idempotencyKey}`).slice(0, 48)}`;
}

export function organizationCandidateMaterializationSubjectLockName(legacyUserId: number): string {
  return `iam-org-materialize:${digest(String(legacyUserId)).slice(0, 40)}`;
}

export function organizationCandidateSnapshotFingerprint(
  legacyUserId: number,
  organizations: LegacyOrganization[]
): string {
  const canonical = [...organizations]
    .sort((left, right) => left.id - right.id)
    .map(({ id, name, title }) => ({ id, name, title }));
  return digest(JSON.stringify({ legacyUserId, organizations: canonical }));
}

export function identityOrganizationIdForLegacy(legacyOrganizationId: number): string {
  return `legacy:${legacyOrganizationId}`;
}

function operationRecord(row: RowDataPacket): OrganizationWriteOperationRecord {
  return {
    operationKey: String(row.operationKey),
    idempotencyKeyDigest: String(row.idempotencyKeyDigest),
    requestFingerprint: String(row.requestFingerprint),
    legacyUserId: Number(row.legacyUserId),
    mode: organizationWriteOperationMode(row.mode),
    status: organizationWriteOperationStatus(row.status),
    legacyStatus: nullableString(row.legacyStatus),
    identityStatus: nullableString(row.identityStatus),
    compensationStatus: organizationWriteCompensationStatus(row.compensationStatus),
    errorCode: nullableString(row.errorCode),
    requestedAt: dateString(row.requestedAt),
    completedAt: dateString(row.completedAt),
    metadata: redactOrganizationWriteMetadata(parseMetadata(row.metadata))
  };
}

export function organizationWriteOperationMode(value: unknown): OrganizationWriteOperationMode {
  if (value === "dual-write" || value === "candidate-materialization") return value;
  throw new Error(`Unknown organization write operation mode: ${String(value)}`);
}

export function organizationWriteOperationStatus(value: unknown): OrganizationWriteOperationStatus {
  if (value === "pending" || value === "legacy_completed" || value === "completed" || value === "failed") return value;
  throw new Error(`Unknown organization write operation status: ${String(value)}`);
}

export function organizationWriteCompensationStatus(value: unknown): OrganizationWriteCompensationStatus {
  if (value === "none" || value === "required" || value === "completed" || value === "failed") return value;
  throw new Error(`Unknown organization write compensation status: ${String(value)}`);
}

export function redactOrganizationWriteMetadata(value: Record<string, unknown>): Record<string, unknown> {
  return redactValue(value, 0) as Record<string, unknown>;
}

function candidateClaimMetadata(metadata: Record<string, unknown>, claimToken: string): Record<string, unknown> {
  return { ...redactOrganizationWriteMetadata(metadata), _claimDigest: digest(claimToken) };
}

function publicOrganizationWriteMetadata(metadata: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(redactOrganizationWriteMetadata(metadata)).filter(([key]) => !key.startsWith("_"))
  );
}

function redactValue(value: unknown, depth: number): unknown {
  if (depth > 8) return "[truncated]";
  if (Array.isArray(value)) return value.map((item) => redactValue(item, depth + 1));
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [
    key,
    /authorization|cookie|token|password|secret|payload|body/i.test(key) ? "[redacted]" : redactValue(child, depth + 1)
  ]));
}

function parseMetadata(value: unknown): Record<string, unknown> {
  if (value && typeof value === "object" && !Array.isArray(value)) return value as Record<string, unknown>;
  if (typeof value === "string") {
    try {
      const parsed = JSON.parse(value) as unknown;
      return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed as Record<string, unknown> : {};
    } catch { return {}; }
  }
  return {};
}

function digest(value: string): string { return createHash("sha256").update(value).digest("hex"); }
function clamp(value: number, min: number, max: number): number { return Math.max(min, Math.min(max, Number.isFinite(value) ? Math.trunc(value) : min)); }
function nullableString(value: unknown): string | null { return typeof value === "string" && value !== "" ? value : null; }
function nullableNumber(value: unknown): number | null {
  if (value === null || value === undefined || value === "") return null;
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}
function dateString(value: unknown): string | null { return value instanceof Date ? value.toISOString() : typeof value === "string" ? value : null; }
