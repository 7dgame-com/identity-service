import { Injectable, OnModuleDestroy } from "@nestjs/common";
import mysql, { Pool, RowDataPacket } from "mysql2/promise";
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
}

@Injectable()
export class IamRepository implements OnModuleDestroy {
  private readonly config = loadConfig();
  private readonly pool: Pool | null;

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
              observed_at AS observedAt
         FROM identity_organization_memberships_shadow
        WHERE legacy_user_id = ?
        ORDER BY organization_id ASC`,
      [legacyUserId]
    );

    return rows.map(normalizeOrganizationShadow);
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
    observedAt: dateToIso(row.observedAt)
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
