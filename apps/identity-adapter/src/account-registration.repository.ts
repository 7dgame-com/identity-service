import { randomBytes } from "node:crypto";
import { Injectable, OnModuleDestroy } from "@nestjs/common";
import mysql, { Pool, PoolConnection, ResultSetHeader, RowDataPacket } from "mysql2/promise";
import { loadConfig } from "./config.js";
import { hashLegacyPassword } from "./legacy-password.js";
import { LegacyUserReadModel } from "./legacy-identity.reader.js";

export interface NativeRegisterInput {
  username: string;
  password: string;
  email?: string | null;
}

export interface NativeWechatRegisterInput extends NativeRegisterInput {
  wechatToken: string;
}

export class NativeRegistrationError extends Error {
  constructor(
    readonly status: number,
    readonly body: string | Record<string, unknown>
  ) {
    super(typeof body === "string" ? body : JSON.stringify(body));
    this.name = "NativeRegistrationError";
  }
}

@Injectable()
export class AccountRegistrationRepository implements OnModuleDestroy {
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

  async register(input: NativeRegisterInput): Promise<LegacyUserReadModel> {
    const connection = await this.requireConnection();
    try {
      await connection.beginTransaction();
      const user = await this.insertUser(connection, input);
      await connection.commit();

      return user;
    } catch (error) {
      await rollbackQuietly(connection);
      throw normalizeWriteError(error);
    } finally {
      connection.release();
    }
  }

  async registerWechat(input: NativeWechatRegisterInput): Promise<LegacyUserReadModel> {
    const connection = await this.requireConnection();
    try {
      await connection.beginTransaction();
      const wechat = await this.findWechatForUpdate(connection, input.wechatToken);
      if (!wechat) {
        throw new NativeRegistrationError(400, "no wechat");
      }
      if (wechat.userId !== null) {
        throw new NativeRegistrationError(400, `already registered,${wechat.userId}`);
      }

      const user = await this.insertUser(connection, input);
      await connection.execute(
        `UPDATE wechat
            SET user_id = ?, updated_at = NOW()
          WHERE id = ?`,
        [user.id, wechat.id]
      );
      await connection.commit();

      return user;
    } catch (error) {
      await rollbackQuietly(connection);
      throw normalizeWriteError(error);
    } finally {
      connection.release();
    }
  }

  private async insertUser(connection: PoolConnection, input: NativeRegisterInput): Promise<LegacyUserReadModel> {
    const username = input.username.trim();
    const email = input.email?.trim().toLowerCase() || null;
    const now = unixNow();
    const existing = await this.findUserByUsername(connection, username);
    if (existing) {
      throw new NativeRegistrationError(400, {
        username: [`Username "${username}" has already been taken.`],
        message: "username already exists"
      });
    }

    const passwordHash = await hashLegacyPassword(input.password);
    const authKey = randomBytes(24).toString("base64url").slice(0, 32);
    const [result] = await connection.execute<ResultSetHeader>(
      `INSERT INTO user
        (username, auth_key, password_hash, email, status, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [username, authKey, passwordHash, email, 10, now, now]
    );
    const userId = Number(result.insertId);

    await connection.execute(`INSERT INTO user_info (user_id) VALUES (?)`, [userId]);
    await connection.execute(
      `INSERT IGNORE INTO auth_assignment (item_name, user_id, created_at)
       VALUES (?, ?, ?)`,
      ["user", String(userId), now]
    );

    return {
      id: userId,
      username,
      email,
      status: 10,
      nickname: null,
      emailVerifiedAt: null,
      createdAt: now,
      updatedAt: now,
      userInfo: null,
      roles: ["user"],
      organizations: [],
      source: "legacy"
    };
  }

  private async findUserByUsername(connection: PoolConnection, username: string): Promise<number | null> {
    const [rows] = await connection.execute<RowDataPacket[]>(
      `SELECT id
         FROM user
        WHERE username = ?
        LIMIT 1`,
      [username]
    );

    return rows[0] ? Number(rows[0].id) : null;
  }

  private async findWechatForUpdate(
    connection: PoolConnection,
    token: string
  ): Promise<{ id: number; userId: number | null } | null> {
    const [rows] = await connection.execute<RowDataPacket[]>(
      `SELECT id, user_id AS userId
         FROM wechat
        WHERE token = ?
        LIMIT 1
        FOR UPDATE`,
      [token]
    );
    const row = rows[0];
    if (!row) {
      return null;
    }

    return {
      id: Number(row.id),
      userId: row.userId === null || row.userId === undefined ? null : Number(row.userId)
    };
  }

  private async requireConnection(): Promise<PoolConnection> {
    if (!this.pool) {
      throw new NativeRegistrationError(503, {
        code: "LEGACY_WRITE_DB_NOT_CONFIGURED",
        message: "Legacy write database is not configured."
      });
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
      connectionLimit: 5,
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
    // Nothing useful to recover here; the original error is more important.
  }
}

function normalizeWriteError(error: unknown): Error {
  if (error instanceof NativeRegistrationError) {
    return error;
  }

  if (isDuplicateKeyError(error)) {
    return new NativeRegistrationError(400, {
      username: ["Username has already been taken."],
      message: "username already exists"
    });
  }

  return error instanceof Error ? error : new Error(String(error));
}

function isDuplicateKeyError(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && (error as { code?: string }).code === "ER_DUP_ENTRY";
}
