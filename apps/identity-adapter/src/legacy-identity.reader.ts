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

export interface LegacyPermission {
  name: string;
  description: string | null;
  source: "direct" | "role-child";
}

export interface LegacyRbacPolicyItem {
  name: string;
  type: "role" | "permission";
  description: string | null;
}

export interface LegacyRbacPolicyRelation {
  parent: string;
  child: string;
}

export interface LegacyRbacPolicySnapshot {
  items: LegacyRbacPolicyItem[];
  relations: LegacyRbacPolicyRelation[];
}

export interface LegacyRbacAssignment {
  name: string;
  type: "role" | "permission";
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

export interface LegacyUserListInput {
  afterId: number;
  limit: number;
}

export interface LegacyManagedUserListInput {
  page: number;
  pageSize: number;
  search?: string;
  status?: number;
  sort?: string;
  order?: "asc" | "desc";
}

export interface LegacyManagedUserListResult {
  users: LegacyUserReadModel[];
  page: number;
  pageSize: number;
  total: number;
  totalPages: number;
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

  async listUsers(input: LegacyUserListInput): Promise<LegacyUserReadModel[]> {
    if (!this.pool) {
      return [];
    }

    const safeLimit = Math.max(1, Math.min(input.limit, 5000));
    const rows = await this.query<RowDataPacket[]>(
      `SELECT id
         FROM user
        WHERE id > ?
        ORDER BY id ASC
        LIMIT ${safeLimit}`,
      [input.afterId]
    );

    const users = await Promise.all(rows.map((row) => this.getUserById(Number(row.id))));
    return users.filter((user): user is LegacyUserReadModel => user !== null);
  }

  async listUsersByOrganization(organizationId: number): Promise<LegacyUserReadModel[]> {
    if (!this.pool || !(await this.tableExists("user_organization"))) {
      return [];
    }

    const rows = await this.query<RowDataPacket[]>(
      `SELECT user_id AS userId
         FROM user_organization
        WHERE organization_id = ?
        ORDER BY user_id ASC`,
      [organizationId]
    );
    const users = await Promise.all(rows.map((row) => this.getUserById(Number(row.userId))));
    return users.filter((user): user is LegacyUserReadModel => user !== null);
  }

  async listManagedUsers(input: LegacyManagedUserListInput): Promise<LegacyManagedUserListResult> {
    if (!this.pool) {
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
    const where: string[] = [];
    const params: unknown[] = [];

    if (input.search?.trim()) {
      where.push("(u.username LIKE ? OR u.email LIKE ?)");
      const pattern = `%${input.search.trim()}%`;
      params.push(pattern, pattern);
    }
    if (input.status !== undefined) {
      where.push("u.status = ?");
      params.push(input.status);
    }

    const whereSql = where.length > 0 ? `WHERE ${where.join(" AND ")}` : "";
    const totalRows = await this.query<RowDataPacket[]>(
      `SELECT COUNT(*) AS total
         FROM user u
        ${whereSql}`,
      params
    );
    const total = Number(totalRows[0]?.total ?? 0);
    const sortOrder = input.order === "asc" ? "ASC" : "DESC";
    const requestedSort = input.sort ?? "";
    const sortField = ["id", "username", "nickname", "email", "created_at", "roles"].includes(requestedSort)
      ? requestedSort
      : "id";

    let rows: RowDataPacket[];
    if (sortField === "roles") {
      rows = await this.query<RowDataPacket[]>(
        `SELECT u.id
           FROM user u
      LEFT JOIN auth_assignment aa ON aa.user_id = u.id
          ${whereSql}
       GROUP BY u.id
       ORDER BY MAX(CASE aa.item_name
         WHEN 'root' THEN 4 WHEN 'admin' THEN 3 WHEN 'manager' THEN 2 WHEN 'user' THEN 1 ELSE 0 END) ${sortOrder},
                u.id ${sortOrder}
          LIMIT ${pageSize} OFFSET ${offset}`,
        params
      );
    } else {
      rows = await this.query<RowDataPacket[]>(
        `SELECT u.id
           FROM user u
          ${whereSql}
       ORDER BY u.${sortField} ${sortOrder}
          LIMIT ${pageSize} OFFSET ${offset}`,
        params
      );
    }

    const users = await Promise.all(rows.map((row) => this.getUserById(Number(row.id))));
    return {
      users: users.filter((user): user is LegacyUserReadModel => user !== null),
      page,
      pageSize,
      total,
      totalPages: Math.ceil(total / pageSize)
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

  async listUserPermissions(userId: number): Promise<LegacyPermission[]> {
    if (!this.pool) {
      return [];
    }

    const assignments = await this.query<RowDataPacket[]>(
      `SELECT item_name AS itemName
         FROM auth_assignment
        WHERE user_id = ?`,
      [String(userId)]
    );

    if (assignments.length === 0) {
      return [];
    }

    const items = await this.query<RowDataPacket[]>(
      `SELECT name, description, type
         FROM auth_item`
    );
    const children = await this.query<RowDataPacket[]>(
      `SELECT parent, child
         FROM auth_item_child`
    );

    const itemByName = new Map(items.map((row) => [String(row.name), row]));
    const childrenByParent = new Map<string, string[]>();
    for (const row of children) {
      const parent = String(row.parent);
      const list = childrenByParent.get(parent) ?? [];
      list.push(String(row.child));
      childrenByParent.set(parent, list);
    }

    const assignedNames = assignments.map((row) => String(row.itemName));
    const queue = [...assignedNames];
    const visited = new Set<string>();
    const directAssignments = new Set(assignedNames);
    const permissions = new Map<string, LegacyPermission>();

    while (queue.length > 0) {
      const name = queue.shift()!;
      if (visited.has(name)) {
        continue;
      }
      visited.add(name);

      const item = itemByName.get(name);
      if (item && Number(item.type) === 2) {
        permissions.set(name, {
          name,
          description: item.description ?? null,
          source: directAssignments.has(name) ? "direct" : "role-child"
        });
      }

      for (const child of childrenByParent.get(name) ?? []) {
        if (!visited.has(child)) {
          queue.push(child);
        }
      }
    }

    return [...permissions.values()].sort((a, b) => a.name.localeCompare(b.name));
  }

  async readRbacPolicySnapshot(): Promise<LegacyRbacPolicySnapshot> {
    if (!this.pool) {
      return { items: [], relations: [] };
    }

    const [items, relations] = await Promise.all([
      this.query<RowDataPacket[]>(
        `SELECT name, description, type
           FROM auth_item
          WHERE type IN (1, 2)
          ORDER BY name ASC`
      ),
      this.query<RowDataPacket[]>(
        `SELECT parent, child
           FROM auth_item_child
          ORDER BY parent ASC, child ASC`
      )
    ]);

    return {
      items: items.map((row) => ({
        name: String(row.name),
        type: Number(row.type) === 1 ? "role" : "permission",
        description: row.description ?? null
      })),
      relations: relations.map((row) => ({
        parent: String(row.parent),
        child: String(row.child)
      }))
    };
  }

  async listUserRbacAssignments(userId: number): Promise<LegacyRbacAssignment[]> {
    if (!this.pool) {
      return [];
    }

    const rows = await this.query<RowDataPacket[]>(
      `SELECT aa.item_name AS name, ai.type
         FROM auth_assignment aa
         JOIN auth_item ai ON ai.name = aa.item_name
        WHERE aa.user_id = ?
          AND ai.type IN (1, 2)
        ORDER BY aa.item_name ASC`,
      [String(userId)]
    );

    return rows.map((row) => ({
      name: String(row.name),
      type: Number(row.type) === 1 ? "role" : "permission"
    }));
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
