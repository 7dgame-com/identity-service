import { Injectable, OnModuleDestroy } from "@nestjs/common";
import mysql, { Pool, PoolConnection, RowDataPacket } from "mysql2/promise";
import { loadConfig } from "./config.js";

export interface PluginUserTemporaryAuthorizationGrantInput {
  legacyUserId: number;
  routes: string[];
  role: "admin" | "manager" | null;
  runKey: string;
  grantedAt: string;
  expiresAt: string;
}

export interface PluginUserTemporaryRouteGrantState {
  route: string;
  itemExisted: boolean;
  assignmentExisted: boolean;
}

export interface PluginUserTemporaryRoleGrantState {
  role: "admin" | "manager";
  assignmentExisted: boolean;
}

export interface PluginUserTemporaryAuthorizationGrantState {
  legacyUserId: number;
  runKey: string;
  grantedAt: string;
  expiresAt: string;
  routes: PluginUserTemporaryRouteGrantState[];
  role: PluginUserTemporaryRoleGrantState | null;
}

export interface PluginUserTemporaryAuthorizationRevokeResult {
  removedRouteAssignments: number;
  removedRouteItems: number;
  removedRoleAssignments: number;
}

const TEMP_DESCRIPTION_PREFIX = "identity-service temporary plugin-user authorization";

@Injectable()
export class PluginUserTemporaryAuthorizationRepository implements OnModuleDestroy {
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

  async grant(input: PluginUserTemporaryAuthorizationGrantInput): Promise<PluginUserTemporaryAuthorizationGrantState> {
    const connection = await this.requireConnection();
    try {
      await connection.beginTransaction();
      await this.assertDeletePrivilege(connection);

      const state: PluginUserTemporaryAuthorizationGrantState = {
        legacyUserId: input.legacyUserId,
        runKey: input.runKey,
        grantedAt: input.grantedAt,
        expiresAt: input.expiresAt,
        routes: [],
        role: null
      };

      for (const route of input.routes) {
        state.routes.push(await this.grantRoute(connection, input.legacyUserId, route, input.runKey));
      }

      if (input.role) {
        state.role = await this.grantRole(connection, input.legacyUserId, input.role);
      }

      await connection.commit();
      return state;
    } catch (error) {
      await rollbackQuietly(connection);
      throw error;
    } finally {
      connection.release();
    }
  }

  async revoke(state: PluginUserTemporaryAuthorizationGrantState): Promise<PluginUserTemporaryAuthorizationRevokeResult> {
    const connection = await this.requireConnection();
    try {
      await connection.beginTransaction();
      await this.assertDeletePrivilege(connection);

      let removedRouteAssignments = 0;
      let removedRouteItems = 0;
      let removedRoleAssignments = 0;

      if (state.role && !state.role.assignmentExisted) {
        removedRoleAssignments += await this.deleteAssignment(connection, state.role.role, state.legacyUserId);
      }

      for (const route of state.routes) {
        if (!route.assignmentExisted) {
          removedRouteAssignments += await this.deleteAssignment(connection, route.route, state.legacyUserId);
        }
        if (!route.itemExisted) {
          removedRouteItems += await this.deleteTemporaryRouteItemIfUnused(connection, route.route);
        }
      }

      await connection.commit();
      return {
        removedRouteAssignments,
        removedRouteItems,
        removedRoleAssignments
      };
    } catch (error) {
      await rollbackQuietly(connection);
      throw error;
    } finally {
      connection.release();
    }
  }

  private async grantRoute(
    connection: PoolConnection,
    legacyUserId: number,
    route: string,
    runKey: string
  ): Promise<PluginUserTemporaryRouteGrantState> {
    const itemExisted = await this.authItemExists(connection, route);
    const assignmentExisted = await this.assignmentExists(connection, route, legacyUserId);
    const now = unixNow();

    if (!itemExisted) {
      await connection.execute(
        `INSERT INTO auth_item (name, type, description, created_at, updated_at)
         VALUES (?, 2, ?, ?, ?)`,
        [route, `${TEMP_DESCRIPTION_PREFIX}; run=${runKey}`, now, now]
      );
    }

    if (!assignmentExisted) {
      await connection.execute(
        `INSERT INTO auth_assignment (item_name, user_id, created_at)
         VALUES (?, ?, ?)`,
        [route, String(legacyUserId), now]
      );
    }

    return {
      route,
      itemExisted,
      assignmentExisted
    };
  }

  private async grantRole(
    connection: PoolConnection,
    legacyUserId: number,
    role: "admin" | "manager"
  ): Promise<PluginUserTemporaryRoleGrantState> {
    const roleExists = await this.authItemExists(connection, role, 1);
    if (!roleExists) {
      throw new Error(`legacy role ${role} does not exist`);
    }

    const assignmentExisted = await this.assignmentExists(connection, role, legacyUserId);
    if (!assignmentExisted) {
      await connection.execute(
        `INSERT INTO auth_assignment (item_name, user_id, created_at)
         VALUES (?, ?, ?)`,
        [role, String(legacyUserId), unixNow()]
      );
    }

    return {
      role,
      assignmentExisted
    };
  }

  private async authItemExists(connection: PoolConnection, name: string, type?: number): Promise<boolean> {
    const [rows] = await connection.execute<RowDataPacket[]>(
      `SELECT name
         FROM auth_item
        WHERE name = ?
          AND (? IS NULL OR type = ?)
        LIMIT 1`,
      [name, type ?? null, type ?? null]
    );
    return rows.length > 0;
  }

  private async assignmentExists(connection: PoolConnection, itemName: string, legacyUserId: number): Promise<boolean> {
    const [rows] = await connection.execute<RowDataPacket[]>(
      `SELECT item_name
         FROM auth_assignment
        WHERE item_name = ?
          AND user_id = ?
        LIMIT 1`,
      [itemName, String(legacyUserId)]
    );
    return rows.length > 0;
  }

  private async deleteAssignment(connection: PoolConnection, itemName: string, legacyUserId: number): Promise<number> {
    const [result] = await connection.execute<mysql.ResultSetHeader>(
      `DELETE FROM auth_assignment
        WHERE item_name = ?
          AND user_id = ?`,
      [itemName, String(legacyUserId)]
    );
    return result.affectedRows;
  }

  private async deleteTemporaryRouteItemIfUnused(connection: PoolConnection, route: string): Promise<number> {
    const [assignmentRows] = await connection.execute<RowDataPacket[]>(
      `SELECT COUNT(*) AS total
         FROM auth_assignment
        WHERE item_name = ?`,
      [route]
    );
    if (Number(assignmentRows[0]?.total ?? 0) > 0) {
      return 0;
    }

    const [itemRows] = await connection.execute<RowDataPacket[]>(
      `SELECT description
         FROM auth_item
        WHERE name = ?
        LIMIT 1`,
      [route]
    );
    const description = itemRows[0]?.description;
    if (typeof description !== "string" || !description.startsWith(TEMP_DESCRIPTION_PREFIX)) {
      return 0;
    }

    const [result] = await connection.execute<mysql.ResultSetHeader>(
      `DELETE FROM auth_item
        WHERE name = ?`,
      [route]
    );
    return result.affectedRows;
  }

  private async assertDeletePrivilege(connection: PoolConnection): Promise<void> {
    const probe = `__identity_temp_auth_preflight_${Date.now().toString(36)}`;
    await connection.execute(`DELETE FROM auth_assignment WHERE item_name = ? AND user_id = ?`, [probe, probe]);
    await connection.execute(`DELETE FROM auth_item WHERE name = ?`, [probe]);
  }

  private async requireConnection(): Promise<PoolConnection> {
    if (!this.pool) {
      throw new Error("legacy write database is not configured");
    }

    return this.pool.getConnection();
  }

  private createPool(): Pool | null {
    const { legacyWriteDb } = this.config;
    if (!legacyWriteDb.host || !legacyWriteDb.user) {
      return null;
    }

    return mysql.createPool({
      host: legacyWriteDb.host,
      port: legacyWriteDb.port,
      database: legacyWriteDb.name,
      user: legacyWriteDb.user,
      password: legacyWriteDb.password,
      waitForConnections: true,
      connectionLimit: 3,
      namedPlaceholders: false
    });
  }
}

function unixNow(): number {
  return Math.floor(Date.now() / 1000);
}

async function rollbackQuietly(connection: PoolConnection): Promise<void> {
  try {
    await connection.rollback();
  } catch {
    // Keep the original error.
  }
}
