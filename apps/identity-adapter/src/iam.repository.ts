import { Injectable, OnModuleDestroy } from "@nestjs/common";
import mysql, { Pool, ResultSetHeader, RowDataPacket } from "mysql2/promise";
import { loadConfig } from "./config.js";
import { assertReadonlySql } from "./readonly-write.guard.js";

export interface IdentityUserRow {
  id: string;
  legacyUserId: number | null;
  keycloakSubject: string | null;
  username: string | null;
  email: string | null;
  status: string;
  source: string;
  metadata: unknown;
  createdAt: string | null;
  updatedAt: string | null;
}

export interface IdentitySubjectMapRow {
  identityUserId: string;
  subjectType: string;
  subjectId: string;
  source: string;
  status: string;
  metadata: unknown;
  createdAt: string | null;
  updatedAt: string | null;
}

export interface IdentityRoleShadowRow {
  identityUserId: string | null;
  legacyUserId: number | null;
  roleName: string;
  source: string;
  status: string;
  observedAt: string | null;
}

export interface IdentityOrganizationShadowRow {
  identityUserId: string | null;
  legacyUserId: number | null;
  organizationId: number;
  organizationRole: string | null;
  source: string;
  status: string;
  observedAt: string | null;
  metadata: unknown;
}

export interface IdentityManagedUserListInput {
  page: number;
  pageSize: number;
  search?: string;
  status?: number;
  sort?: string;
  order?: "asc" | "desc";
}

export interface IdentityManagedUserListResult {
  users: IdentityUserRow[];
  page: number;
  pageSize: number;
  total: number;
  totalPages: number;
}

export interface IamReconciliationRunInput {
  runKey: string;
  scope: string;
  mode: string;
  metadata: Record<string, unknown>;
}

export interface IamReconciliationRunFinishInput {
  runKey: string;
  status: "succeeded" | "failed";
  sampleCount: number;
  mismatchCount: number;
  p0Count: number;
  p1Count: number;
  metadata: Record<string, unknown>;
}

export interface IamReconciliationRunRow {
  runKey: string;
  scope: string;
  mode: string;
  status: string;
  startedAt: string | null;
  finishedAt: string | null;
  sampleCount: number;
  mismatchCount: number;
  p0Count: number;
  p1Count: number;
  metadata: unknown;
}

export interface IamReconciliationItemInput {
  runKey: string;
  scope: string;
  severity: string;
  legacySubjectType: string | null;
  legacySubjectId: string | null;
  identitySubjectType: string | null;
  identitySubjectId: string | null;
  fieldPath: string;
  legacyValueHash: string | null;
  identityValueHash: string | null;
  message: string;
  metadata: Record<string, unknown>;
}

export interface IamReconciliationItemRow extends IamReconciliationItemInput {
  createdAt: string | null;
}

export interface IamReconciliationSeveritySummary {
  p0: number;
  p1: number;
  p2: number;
  info: number;
}

export interface IdentityUserShadowInput {
  identityUserId: string;
  legacyUserId: number;
  username: string | null;
  email: string | null;
  status: string;
  metadata: Record<string, unknown>;
}

export interface RoleShadowInput {
  identityUserId: string;
  legacyUserId: number;
  roleName: string;
  source: string;
}

export interface OrganizationShadowInput {
  identityUserId: string;
  legacyUserId: number;
  organizationId: number;
  organizationRole: string | null;
  source: string;
  metadata?: Record<string, unknown>;
}

@Injectable()
export class IamRepository implements OnModuleDestroy {
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

  async health(): Promise<"configured" | "not_configured" | "unavailable"> {
    if (!this.pool) {
      return "not_configured";
    }

    try {
      await this.query("SELECT 1 AS ok");
      return "configured";
    } catch {
      return "unavailable";
    }
  }

  async diagnostics(): Promise<Record<string, unknown>> {
    const tables = await Promise.all(
      [
        "identity_users",
        "identity_subject_maps",
        "identity_role_assignments_shadow",
        "identity_organization_memberships_shadow",
        "iam_reconciliation_runs",
        "iam_reconciliation_items"
      ].map(async (table) => [table, this.pool ? await this.tableExists(table) : false] as const)
    );

    return {
      identityDatabaseConfigured: this.isConfigured(),
      tables: Object.fromEntries(tables)
    };
  }

  async getIdentityUserByLegacyId(legacyUserId: number): Promise<IdentityUserRow | null> {
    if (!(await this.tableExists("identity_users"))) {
      return null;
    }

    const rows = await this.query<RowDataPacket[]>(
      `SELECT id,
              legacy_user_id AS legacyUserId,
              keycloak_subject AS keycloakSubject,
              username,
              email,
              status,
              source,
              metadata,
              created_at AS createdAt,
              updated_at AS updatedAt
         FROM identity_users
        WHERE legacy_user_id = ?
        LIMIT 1`,
      [legacyUserId]
    );

    return rows.length > 0 ? normalizeIdentityUser(rows[0]) : null;
  }

  async listManagedUsers(input: IdentityManagedUserListInput): Promise<IdentityManagedUserListResult> {
    if (!(await this.tableExists("identity_users"))) {
      return {
        users: [],
        page: input.page,
        pageSize: input.pageSize,
        total: 0,
        totalPages: 0
      };
    }

    const page = Math.max(1, input.page);
    const pageSize = Math.max(1, Math.min(input.pageSize, 100));
    const offset = (page - 1) * pageSize;
    const where = ["legacy_user_id IS NOT NULL"];
    const params: unknown[] = [];

    if (input.search?.trim()) {
      where.push("(username LIKE ? OR email LIKE ?)");
      const pattern = `%${input.search.trim()}%`;
      params.push(pattern, pattern);
    }

    const status = identityStatusForLegacyStatus(input.status);
    if (status) {
      where.push("status = ?");
      params.push(status);
    }

    const whereSql = `WHERE ${where.join(" AND ")}`;
    const totalRows = await this.query<RowDataPacket[]>(
      `SELECT COUNT(*) AS total
         FROM identity_users
        ${whereSql}`,
      params
    );
    const total = Number(totalRows[0]?.total ?? 0);
    const sortOrder = input.order === "asc" ? "ASC" : "DESC";
    const sortColumn = identityUserSortColumn(input.sort);

    const rows = await this.query<RowDataPacket[]>(
      `SELECT id,
              legacy_user_id AS legacyUserId,
              keycloak_subject AS keycloakSubject,
              username,
              email,
              status,
              source,
              metadata,
              created_at AS createdAt,
              updated_at AS updatedAt
         FROM identity_users
        ${whereSql}
        ORDER BY ${sortColumn} ${sortOrder}
        LIMIT ${pageSize} OFFSET ${offset}`,
      params
    );

    return {
      users: rows.map(normalizeIdentityUser),
      page,
      pageSize,
      total,
      totalPages: Math.ceil(total / pageSize)
    };
  }

  async listSubjectMaps(identityUserId: string): Promise<IdentitySubjectMapRow[]> {
    if (!(await this.tableExists("identity_subject_maps"))) {
      return [];
    }

    const rows = await this.query<RowDataPacket[]>(
      `SELECT identity_user_id AS identityUserId,
              subject_type AS subjectType,
              subject_id AS subjectId,
              source,
              status,
              metadata,
              created_at AS createdAt,
              updated_at AS updatedAt
         FROM identity_subject_maps
        WHERE identity_user_id = ?
        ORDER BY subject_type ASC, subject_id ASC`,
      [identityUserId]
    );

    return rows.map(normalizeSubjectMap);
  }

  async listRoleAssignmentsShadow(legacyUserId: number): Promise<IdentityRoleShadowRow[]> {
    if (!(await this.tableExists("identity_role_assignments_shadow"))) {
      return [];
    }

    const rows = await this.query<RowDataPacket[]>(
      `SELECT identity_user_id AS identityUserId,
              legacy_user_id AS legacyUserId,
              role_name AS roleName,
              source,
              status,
              observed_at AS observedAt
         FROM identity_role_assignments_shadow
        WHERE legacy_user_id = ?
          AND status = 'shadow'
        ORDER BY role_name ASC`,
      [legacyUserId]
    );

    return rows.map(normalizeRoleShadow);
  }

  async listOrganizationMembershipsShadow(legacyUserId: number): Promise<IdentityOrganizationShadowRow[]> {
    if (!(await this.tableExists("identity_organization_memberships_shadow"))) {
      return [];
    }

    const rows = await this.query<RowDataPacket[]>(
      `SELECT identity_user_id AS identityUserId,
              legacy_user_id AS legacyUserId,
              organization_id AS organizationId,
              organization_role AS organizationRole,
              source,
              status,
              observed_at AS observedAt,
              metadata
         FROM identity_organization_memberships_shadow
        WHERE legacy_user_id = ?
          AND status = 'shadow'
        ORDER BY organization_id ASC`,
      [legacyUserId]
    );

    return rows.map(normalizeOrganizationShadow);
  }

  async upsertIdentityUserShadow(input: IdentityUserShadowInput): Promise<void> {
    const pool = this.requirePool();
    await this.ensureSchema();

    await pool.execute(
      `INSERT INTO identity_users
        (id, legacy_user_id, username, email, status, source, metadata)
       VALUES (?, ?, ?, ?, ?, 'legacy-shadow', ?)
       ON DUPLICATE KEY UPDATE
         legacy_user_id = VALUES(legacy_user_id),
         username = VALUES(username),
         email = VALUES(email),
         status = VALUES(status),
         source = VALUES(source),
         metadata = VALUES(metadata)`,
      [
        input.identityUserId,
        input.legacyUserId,
        input.username,
        input.email,
        input.status,
        JSON.stringify(input.metadata ?? {})
      ]
    );

    await pool.execute(
      `INSERT INTO identity_subject_maps
        (identity_user_id, subject_type, subject_id, source, status, metadata)
       VALUES (?, 'legacy_user', ?, 'legacy-shadow', 'active', ?)
       ON DUPLICATE KEY UPDATE
         status = 'active',
         source = VALUES(source),
         metadata = VALUES(metadata)`,
      [
        input.identityUserId,
        String(input.legacyUserId),
        JSON.stringify({
          legacyUserId: input.legacyUserId,
          source: "legacy-shadow-reconciliation"
        })
      ]
    );
  }

  async upsertPluginSubjectMap(input: { identityUserId: string; legacyUserId: number; metadata: Record<string, unknown> }): Promise<void> {
    const pool = this.requirePool();
    await this.ensureSchema();

    await pool.execute(
      `INSERT INTO identity_subject_maps
        (identity_user_id, subject_type, subject_id, source, status, metadata)
       VALUES (?, 'plugin_user', ?, 'legacy-shadow', 'active', ?)
       ON DUPLICATE KEY UPDATE
         status = 'active',
         source = VALUES(source),
         metadata = VALUES(metadata)`,
      [input.identityUserId, `legacy:${input.legacyUserId}`, JSON.stringify(input.metadata ?? {})]
    );
  }

  async replaceRoleAssignmentsShadow(legacyUserId: number, roles: RoleShadowInput[]): Promise<number> {
    const pool = this.requirePool();
    await this.ensureSchema();

    await pool.execute(
      `UPDATE identity_role_assignments_shadow
          SET status = 'inactive',
              observed_at = ?
        WHERE legacy_user_id = ?
          AND source = 'legacy-shadow'
          AND status = 'shadow'`,
      [new Date(), legacyUserId]
    );

    let affected = 0;
    for (const role of roles) {
      const [result] = await pool.execute<ResultSetHeader>(
        `INSERT INTO identity_role_assignments_shadow
          (identity_user_id, legacy_user_id, role_name, source, status, observed_at)
         VALUES (?, ?, ?, ?, 'shadow', ?)
         ON DUPLICATE KEY UPDATE
           identity_user_id = VALUES(identity_user_id),
           status = 'shadow',
           observed_at = VALUES(observed_at)`,
        [role.identityUserId, role.legacyUserId, role.roleName, role.source, new Date()]
      );
      affected += result.affectedRows > 0 ? 1 : 0;
    }

    return affected;
  }

  async replaceOrganizationMembershipsShadow(legacyUserId: number, organizations: OrganizationShadowInput[]): Promise<number> {
    const pool = this.requirePool();
    await this.ensureSchema();

    await pool.execute(
      `UPDATE identity_organization_memberships_shadow
          SET status = 'inactive',
              observed_at = ?
        WHERE legacy_user_id = ?
          AND source = 'legacy-shadow'
          AND status = 'shadow'`,
      [new Date(), legacyUserId]
    );

    let affected = 0;
    for (const organization of organizations) {
      const [result] = await pool.execute<ResultSetHeader>(
        `INSERT INTO identity_organization_memberships_shadow
          (identity_user_id, legacy_user_id, organization_id, organization_role, source, status, observed_at, metadata)
         VALUES (?, ?, ?, ?, ?, 'shadow', ?, ?)
         ON DUPLICATE KEY UPDATE
           identity_user_id = VALUES(identity_user_id),
           organization_role = VALUES(organization_role),
           status = 'shadow',
           observed_at = VALUES(observed_at),
           metadata = VALUES(metadata)`,
        [
          organization.identityUserId,
          organization.legacyUserId,
          organization.organizationId,
          organization.organizationRole,
          organization.source,
          new Date(),
          JSON.stringify(organization.metadata ?? {})
        ]
      );
      affected += result.affectedRows > 0 ? 1 : 0;
    }

    return affected;
  }

  async createReconciliationRun(input: IamReconciliationRunInput): Promise<void> {
    const pool = this.requirePool();
    await this.ensureSchema();

    await pool.execute(
      `INSERT INTO iam_reconciliation_runs
        (run_key, scope, mode, status, started_at, metadata)
       VALUES (?, ?, ?, 'running', ?, ?)
       ON DUPLICATE KEY UPDATE
         scope = VALUES(scope),
         mode = VALUES(mode),
         status = 'running',
         started_at = VALUES(started_at),
         finished_at = NULL,
         sample_count = 0,
         mismatch_count = 0,
         p0_count = 0,
         p1_count = 0,
         metadata = VALUES(metadata)`,
      [input.runKey, input.scope, input.mode, new Date(), JSON.stringify(input.metadata ?? {})]
    );

    await pool.execute("DELETE FROM iam_reconciliation_items WHERE run_key = ?", [input.runKey]);
  }

  async insertReconciliationItems(items: IamReconciliationItemInput[]): Promise<number> {
    if (items.length === 0) {
      return 0;
    }

    const pool = this.requirePool();
    await this.ensureSchema();

    let affected = 0;
    for (const item of items) {
      const [result] = await pool.execute<ResultSetHeader>(
        `INSERT INTO iam_reconciliation_items
          (run_key, scope, severity, legacy_subject_type, legacy_subject_id,
           identity_subject_type, identity_subject_id, field_path, legacy_value_hash,
           identity_value_hash, message, metadata)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          item.runKey,
          item.scope,
          item.severity,
          item.legacySubjectType,
          item.legacySubjectId,
          item.identitySubjectType,
          item.identitySubjectId,
          item.fieldPath,
          item.legacyValueHash,
          item.identityValueHash,
          item.message,
          JSON.stringify(item.metadata ?? {})
        ]
      );
      affected += result.affectedRows;
    }

    return affected;
  }

  async finishReconciliationRun(input: IamReconciliationRunFinishInput): Promise<void> {
    const pool = this.requirePool();
    await this.ensureSchema();

    await pool.execute(
      `UPDATE iam_reconciliation_runs
          SET status = ?,
              finished_at = ?,
              sample_count = ?,
              mismatch_count = ?,
              p0_count = ?,
              p1_count = ?,
              metadata = ?
        WHERE run_key = ?`,
      [
        input.status,
        new Date(),
        input.sampleCount,
        input.mismatchCount,
        input.p0Count,
        input.p1Count,
        JSON.stringify(input.metadata ?? {}),
        input.runKey
      ]
    );
  }

  async getReconciliationRun(runKey: string): Promise<IamReconciliationRunRow | null> {
    if (!(await this.tableExists("iam_reconciliation_runs"))) {
      return null;
    }

    const rows = await this.query<RowDataPacket[]>(
      `SELECT run_key AS runKey,
              scope,
              mode,
              status,
              started_at AS startedAt,
              finished_at AS finishedAt,
              sample_count AS sampleCount,
              mismatch_count AS mismatchCount,
              p0_count AS p0Count,
              p1_count AS p1Count,
              metadata
         FROM iam_reconciliation_runs
        WHERE run_key = ?
        LIMIT 1`,
      [runKey]
    );

    return rows[0] ? normalizeReconciliationRun(rows[0]) : null;
  }

  async listRecentReconciliationRuns(limit = 10): Promise<IamReconciliationRunRow[]> {
    if (!(await this.tableExists("iam_reconciliation_runs"))) {
      return [];
    }

    const safeLimit = Math.max(1, Math.min(limit, 50));
    const rows = await this.query<RowDataPacket[]>(
      `SELECT run_key AS runKey,
              scope,
              mode,
              status,
              started_at AS startedAt,
              finished_at AS finishedAt,
              sample_count AS sampleCount,
              mismatch_count AS mismatchCount,
              p0_count AS p0Count,
              p1_count AS p1Count,
              metadata
         FROM iam_reconciliation_runs
        ORDER BY started_at DESC, id DESC
        LIMIT ${safeLimit}`
    );

    return rows.map(normalizeReconciliationRun);
  }

  async listReconciliationItems(runKey: string, limit = 200): Promise<IamReconciliationItemRow[]> {
    if (!(await this.tableExists("iam_reconciliation_items"))) {
      return [];
    }

    const safeLimit = Math.max(1, Math.min(limit, 1000));
    const rows = await this.query<RowDataPacket[]>(
      `SELECT run_key AS runKey,
              scope,
              severity,
              legacy_subject_type AS legacySubjectType,
              legacy_subject_id AS legacySubjectId,
              identity_subject_type AS identitySubjectType,
              identity_subject_id AS identitySubjectId,
              field_path AS fieldPath,
              legacy_value_hash AS legacyValueHash,
              identity_value_hash AS identityValueHash,
              message,
              metadata,
              created_at AS createdAt
         FROM iam_reconciliation_items
        WHERE run_key = ?
        ORDER BY id ASC
        LIMIT ${safeLimit}`,
      [runKey]
    );

    return rows.map(normalizeReconciliationItem);
  }

  async summarizeReconciliationItems(runKey: string): Promise<IamReconciliationSeveritySummary> {
    if (!(await this.tableExists("iam_reconciliation_items"))) {
      return { p0: 0, p1: 0, p2: 0, info: 0 };
    }

    const rows = await this.query<RowDataPacket[]>(
      `SELECT severity, COUNT(*) AS count
         FROM iam_reconciliation_items
        WHERE run_key = ?
        GROUP BY severity`,
      [runKey]
    );
    const summary: IamReconciliationSeveritySummary = { p0: 0, p1: 0, p2: 0, info: 0 };
    for (const row of rows) {
      const severity = String(row.severity);
      if (severity === "p0" || severity === "p1" || severity === "p2" || severity === "info") {
        summary[severity] = Number(row.count ?? 0);
      }
    }

    return summary;
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
      CREATE TABLE IF NOT EXISTS identity_users (
        id VARCHAR(64) NOT NULL,
        legacy_user_id INT UNSIGNED NULL,
        keycloak_subject VARCHAR(255) NULL,
        username VARCHAR(255) NULL,
        email VARCHAR(255) NULL,
        status VARCHAR(32) NOT NULL DEFAULT 'active',
        source VARCHAR(64) NOT NULL DEFAULT 'legacy-shadow',
        metadata JSON NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY idx_identity_users_legacy_user_id (legacy_user_id),
        KEY idx_identity_users_keycloak_subject (keycloak_subject),
        KEY idx_identity_users_username (username),
        KEY idx_identity_users_email (email),
        KEY idx_identity_users_status (status)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS identity_subject_maps (
        identity_user_id VARCHAR(64) NOT NULL,
        subject_type VARCHAR(64) NOT NULL,
        subject_id VARCHAR(255) NOT NULL,
        source VARCHAR(64) NOT NULL DEFAULT 'legacy-shadow',
        status VARCHAR(32) NOT NULL DEFAULT 'active',
        metadata JSON NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (identity_user_id, subject_type, subject_id),
        KEY idx_identity_subject_maps_subject (subject_type, subject_id),
        KEY idx_identity_subject_maps_status (status)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS identity_role_assignments_shadow (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        identity_user_id VARCHAR(64) NULL,
        legacy_user_id INT UNSIGNED NULL,
        role_name VARCHAR(255) NOT NULL,
        source VARCHAR(64) NOT NULL DEFAULT 'legacy-shadow',
        status VARCHAR(32) NOT NULL DEFAULT 'shadow',
        observed_at DATETIME(3) NOT NULL,
        metadata JSON NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY idx_identity_role_shadow_legacy_role (legacy_user_id, role_name, source),
        KEY idx_identity_role_shadow_identity_user (identity_user_id, status),
        KEY idx_identity_role_shadow_role (role_name, status),
        KEY idx_identity_role_shadow_observed (observed_at)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS identity_organization_memberships_shadow (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        identity_user_id VARCHAR(64) NULL,
        legacy_user_id INT UNSIGNED NULL,
        organization_id INT UNSIGNED NOT NULL,
        organization_role VARCHAR(64) NULL,
        source VARCHAR(64) NOT NULL DEFAULT 'legacy-shadow',
        status VARCHAR(32) NOT NULL DEFAULT 'shadow',
        observed_at DATETIME(3) NOT NULL,
        metadata JSON NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY idx_identity_org_shadow_legacy_org (legacy_user_id, organization_id, source),
        KEY idx_identity_org_shadow_identity_user (identity_user_id, status),
        KEY idx_identity_org_shadow_org (organization_id, status),
        KEY idx_identity_org_shadow_observed (observed_at)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS iam_reconciliation_runs (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        run_key VARCHAR(160) NOT NULL,
        scope VARCHAR(64) NOT NULL,
        mode VARCHAR(32) NOT NULL DEFAULT 'shadow',
        status VARCHAR(32) NOT NULL,
        started_at DATETIME(3) NOT NULL,
        finished_at DATETIME(3) NULL,
        sample_count BIGINT UNSIGNED NOT NULL DEFAULT 0,
        mismatch_count BIGINT UNSIGNED NOT NULL DEFAULT 0,
        p0_count BIGINT UNSIGNED NOT NULL DEFAULT 0,
        p1_count BIGINT UNSIGNED NOT NULL DEFAULT 0,
        metadata JSON NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY idx_iam_reconciliation_runs_key (run_key),
        KEY idx_iam_reconciliation_runs_scope (scope, started_at),
        KEY idx_iam_reconciliation_runs_status (status, started_at)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS iam_reconciliation_items (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        run_key VARCHAR(160) NOT NULL,
        scope VARCHAR(64) NOT NULL,
        severity VARCHAR(16) NOT NULL,
        legacy_subject_type VARCHAR(64) NULL,
        legacy_subject_id VARCHAR(255) NULL,
        identity_subject_type VARCHAR(64) NULL,
        identity_subject_id VARCHAR(255) NULL,
        field_path VARCHAR(255) NOT NULL,
        legacy_value_hash CHAR(64) NULL,
        identity_value_hash CHAR(64) NULL,
        message VARCHAR(1024) NULL,
        metadata JSON NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        KEY idx_iam_reconciliation_items_run (run_key, severity),
        KEY idx_iam_reconciliation_items_legacy (legacy_subject_type, legacy_subject_id),
        KEY idx_iam_reconciliation_items_identity (identity_subject_type, identity_subject_id),
        KEY idx_iam_reconciliation_items_scope (scope, created_at)
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

  private async tableExists(tableName: string): Promise<boolean> {
    if (!this.pool) {
      return false;
    }

    const rows = await this.query<RowDataPacket[]>("SHOW TABLES LIKE ?", [tableName]);
    return rows.length > 0;
  }

  private async query<T extends RowDataPacket[]>(sql: string, params: unknown[] = []): Promise<T> {
    assertReadonlySql(sql);
    if (!this.pool) {
      return [] as unknown as T;
    }

    const [rows] = await this.pool.query<T>(sql, params);
    return rows;
  }
}

function normalizeIdentityUser(row: RowDataPacket): IdentityUserRow {
  return {
    id: String(row.id),
    legacyUserId: row.legacyUserId === null ? null : Number(row.legacyUserId),
    keycloakSubject: row.keycloakSubject ?? null,
    username: row.username ?? null,
    email: row.email ?? null,
    status: String(row.status),
    source: String(row.source),
    metadata: parseJsonMaybe(row.metadata),
    createdAt: dateToIso(row.createdAt),
    updatedAt: dateToIso(row.updatedAt)
  };
}

function normalizeSubjectMap(row: RowDataPacket): IdentitySubjectMapRow {
  return {
    identityUserId: String(row.identityUserId),
    subjectType: String(row.subjectType),
    subjectId: String(row.subjectId),
    source: String(row.source),
    status: String(row.status),
    metadata: parseJsonMaybe(row.metadata),
    createdAt: dateToIso(row.createdAt),
    updatedAt: dateToIso(row.updatedAt)
  };
}

function normalizeRoleShadow(row: RowDataPacket): IdentityRoleShadowRow {
  return {
    identityUserId: row.identityUserId ?? null,
    legacyUserId: row.legacyUserId === null ? null : Number(row.legacyUserId),
    roleName: String(row.roleName),
    source: String(row.source),
    status: String(row.status),
    observedAt: dateToIso(row.observedAt)
  };
}

function normalizeOrganizationShadow(row: RowDataPacket): IdentityOrganizationShadowRow {
  return {
    identityUserId: row.identityUserId ?? null,
    legacyUserId: row.legacyUserId === null ? null : Number(row.legacyUserId),
    organizationId: Number(row.organizationId),
    organizationRole: row.organizationRole ?? null,
    source: String(row.source),
    status: String(row.status),
    observedAt: dateToIso(row.observedAt),
    metadata: parseJsonMaybe(row.metadata)
  };
}

function identityStatusForLegacyStatus(status: number | undefined): string | null {
  if (status === undefined) {
    return null;
  }

  return status === 10 ? "active" : "inactive";
}

function identityUserSortColumn(sort: string | undefined): string {
  switch (sort) {
    case "username":
      return "username";
    case "nickname":
      return "username";
    case "email":
      return "email";
    case "created_at":
      return "created_at";
    case "id":
    case "roles":
    default:
      return "legacy_user_id";
  }
}

function normalizeReconciliationRun(row: RowDataPacket): IamReconciliationRunRow {
  return {
    runKey: String(row.runKey),
    scope: String(row.scope),
    mode: String(row.mode),
    status: String(row.status),
    startedAt: dateToIso(row.startedAt),
    finishedAt: dateToIso(row.finishedAt),
    sampleCount: Number(row.sampleCount ?? 0),
    mismatchCount: Number(row.mismatchCount ?? 0),
    p0Count: Number(row.p0Count ?? 0),
    p1Count: Number(row.p1Count ?? 0),
    metadata: parseJsonMaybe(row.metadata)
  };
}

function normalizeReconciliationItem(row: RowDataPacket): IamReconciliationItemRow {
  return {
    runKey: String(row.runKey),
    scope: String(row.scope),
    severity: String(row.severity),
    legacySubjectType: row.legacySubjectType ?? null,
    legacySubjectId: row.legacySubjectId ?? null,
    identitySubjectType: row.identitySubjectType ?? null,
    identitySubjectId: row.identitySubjectId ?? null,
    fieldPath: String(row.fieldPath),
    legacyValueHash: row.legacyValueHash ?? null,
    identityValueHash: row.identityValueHash ?? null,
    message: String(row.message ?? ""),
    metadata: parseJsonMaybe(row.metadata) as Record<string, unknown>,
    createdAt: dateToIso(row.createdAt)
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
