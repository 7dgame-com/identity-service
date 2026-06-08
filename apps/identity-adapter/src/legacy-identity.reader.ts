import { Injectable, OnModuleDestroy } from "@nestjs/common";
import mysql, { Pool, RowDataPacket } from "mysql2/promise";
import { loadConfig } from "./config.js";
import { assertReadonlySql } from "./readonly-write.guard.js";

export interface LegacyRole {
  name: string;
  description: string | null;
  createdAt: number | null;
  updatedAt: number | null;
}

export interface LegacyOrganization {
  id: number;
  name: string;
  title: string;
  createdAt: number | null;
  updatedAt: number | null;
}

export interface LegacyUserReadModel {
  id: number;
  username: string | null;
  email: string | null;
  status: number;
  nickname: string | null;
  emailVerifiedAt: number | null;
  createdAt: number | null;
  updatedAt: number | null;
  userInfo: unknown;
  roles: string[];
  organizations: LegacyOrganization[];
  source: "legacy";
}

export interface LegacyUserCredential {
  id: number;
  username: string | null;
  email: string | null;
  status: number;
  nickname: string | null;
  passwordHash: string | null;
}

@Injectable()
export class LegacyIdentityReader implements OnModuleDestroy {
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

  async getUserById(id: number): Promise<LegacyUserReadModel | null> {
    if (!this.pool) {
      return null;
    }

    const users = await this.query<RowDataPacket[]>(
      `SELECT u.id, u.username, u.email, u.status, u.nickname,
              u.email_verified_at AS emailVerifiedAt,
              u.created_at AS createdAt,
              u.updated_at AS updatedAt,
              ui.info AS userInfo
         FROM user u
    LEFT JOIN user_info ui ON ui.user_id = u.id
        WHERE u.id = ?
        LIMIT 1`,
      [id]
    );

    if (users.length === 0) {
      return null;
    }

    const user = users[0];
    const [roles, organizations] = await Promise.all([
      this.getUserRoles(id),
      this.getUserOrganizations(id)
    ]);

    return {
      id: Number(user.id),
      username: user.username ?? null,
      email: user.email ?? null,
      status: Number(user.status),
      nickname: user.nickname ?? null,
      emailVerifiedAt: numberOrNull(user.emailVerifiedAt),
      createdAt: numberOrNull(user.createdAt),
      updatedAt: numberOrNull(user.updatedAt),
      userInfo: parseJsonMaybe(user.userInfo),
      roles,
      organizations,
      source: "legacy"
    };
  }

  async getUserCredentialByUsername(username: string): Promise<LegacyUserCredential | null> {
    if (!this.pool) {
      return null;
    }

    const users = await this.query<RowDataPacket[]>(
      `SELECT id, username, email, status, nickname, password_hash AS passwordHash
         FROM user
        WHERE username = ?
        LIMIT 1`,
      [username]
    );

    if (users.length === 0) {
      return null;
    }

    const user = users[0];
    return {
      id: Number(user.id),
      username: user.username ?? null,
      email: user.email ?? null,
      status: Number(user.status),
      nickname: user.nickname ?? null,
      passwordHash: user.passwordHash ?? null
    };
  }

  async listRoles(): Promise<LegacyRole[]> {
    if (!this.pool) {
      return [];
    }

    const rows = await this.query<RowDataPacket[]>(
      `SELECT name, description, created_at AS createdAt, updated_at AS updatedAt
         FROM auth_item
        WHERE type = 1
        ORDER BY name ASC`
    );

    return rows.map((row) => ({
      name: String(row.name),
      description: row.description ?? null,
      createdAt: numberOrNull(row.createdAt),
      updatedAt: numberOrNull(row.updatedAt)
    }));
  }

  async listOrganizations(): Promise<LegacyOrganization[]> {
    if (!this.pool || !(await this.tableExists("organization"))) {
      return [];
    }

    const rows = await this.query<RowDataPacket[]>(
      `SELECT id, name, title, created_at AS createdAt, updated_at AS updatedAt
         FROM organization
        ORDER BY title ASC, id ASC`
    );

    return rows.map(normalizeOrganization);
  }

  async diagnostics(): Promise<Record<string, unknown>> {
    const tables = await Promise.all(
      ["user", "user_info", "auth_item", "auth_assignment", "organization", "user_organization"].map(
        async (table) => [table, this.pool ? await this.tableExists(table) : false] as const
      )
    );

    return {
      legacyDatabaseConfigured: this.isConfigured(),
      tables: Object.fromEntries(tables)
    };
  }

  private createPool(): Pool | null {
    const { legacyDb } = this.config;
    if (!legacyDb.host || !legacyDb.user) {
      return null;
    }

    return mysql.createPool({
      host: legacyDb.host,
      port: legacyDb.port,
      database: legacyDb.name,
      user: legacyDb.user,
      password: legacyDb.password,
      waitForConnections: true,
      connectionLimit: 5,
      namedPlaceholders: false
    });
  }

  private async getUserRoles(userId: number): Promise<string[]> {
    const rows = await this.query<RowDataPacket[]>(
      `SELECT item_name AS role
         FROM auth_assignment
        WHERE user_id = ?
        ORDER BY item_name ASC`,
      [String(userId)]
    );

    return rows.map((row) => String(row.role));
  }

  private async getUserOrganizations(userId: number): Promise<LegacyOrganization[]> {
    if (!(await this.tableExists("organization")) || !(await this.tableExists("user_organization"))) {
      return [];
    }

    const rows = await this.query<RowDataPacket[]>(
      `SELECT o.id, o.name, o.title, o.created_at AS createdAt, o.updated_at AS updatedAt
         FROM organization o
   INNER JOIN user_organization uo ON uo.organization_id = o.id
        WHERE uo.user_id = ?
        ORDER BY o.title ASC, o.id ASC`,
      [userId]
    );

    return rows.map(normalizeOrganization);
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

function normalizeOrganization(row: RowDataPacket): LegacyOrganization {
  return {
    id: Number(row.id),
    name: String(row.name),
    title: String(row.title),
    createdAt: numberOrNull(row.createdAt),
    updatedAt: numberOrNull(row.updatedAt)
  };
}

function numberOrNull(value: unknown): number | null {
  if (value === null || value === undefined || value === "") {
    return null;
  }

  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
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
