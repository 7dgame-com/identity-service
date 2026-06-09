import { Injectable, OnModuleDestroy } from "@nestjs/common";
import mysql, { Pool, ResultSetHeader, RowDataPacket } from "mysql2/promise";
import { loadConfig } from "./config.js";

export interface EmailUserProfile {
  id: number;
  username: string | null;
  email: string | null;
  status: number;
  emailVerifiedAt: number | null;
}

export class NativeEmailError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    readonly message: string
  ) {
    super(message);
    this.name = "NativeEmailError";
  }
}

@Injectable()
export class AccountEmailRepository implements OnModuleDestroy {
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

  async getUserById(userId: number): Promise<EmailUserProfile | null> {
    const pool = this.requirePool();
    const [rows] = await pool.execute<RowDataPacket[]>(
      `SELECT id,
              username,
              email,
              status,
              email_verified_at AS emailVerifiedAt
         FROM user
        WHERE id = ?
        LIMIT 1`,
      [userId]
    );

    return rows[0] ? normalizeUser(rows[0]) : null;
  }

  async isEmailBoundByOther(email: string, legacyUserId: number): Promise<boolean> {
    const pool = this.requirePool();
    const [rows] = await pool.execute<RowDataPacket[]>(
      `SELECT id
         FROM user
        WHERE email = ?
          AND id <> ?
        LIMIT 1`,
      [normalizeEmail(email), legacyUserId]
    );

    return Boolean(rows[0]);
  }

  async bindVerifiedEmail(legacyUserId: number, email: string, verifiedAt: number): Promise<EmailUserProfile> {
    const pool = this.requirePool();
    try {
      const [result] = await pool.execute<ResultSetHeader>(
        `UPDATE user
            SET email = ?, email_verified_at = ?, updated_at = ?
          WHERE id = ?`,
        [normalizeEmail(email), verifiedAt, verifiedAt, legacyUserId]
      );
      if (result.affectedRows !== 1) {
        throw new NativeEmailError(500, "BIND_FAILED", "邮箱绑定失败，请稍后重试");
      }
    } catch (error) {
      if (isDuplicateEntry(error)) {
        throw new NativeEmailError(400, "INVALID_CODE", "该邮箱已被其他账号绑定");
      }
      throw error;
    }

    const user = await this.getUserById(legacyUserId);
    if (!user) {
      throw new NativeEmailError(500, "BIND_FAILED", "邮箱绑定失败，请稍后重试");
    }

    return user;
  }

  async unbindEmail(legacyUserId: number, updatedAt: number): Promise<EmailUserProfile> {
    const pool = this.requirePool();
    const [result] = await pool.execute<ResultSetHeader>(
      `UPDATE user
          SET email = NULL, email_verified_at = NULL, updated_at = ?
        WHERE id = ?`,
      [updatedAt, legacyUserId]
    );
    if (result.affectedRows !== 1) {
      throw new NativeEmailError(500, "UNBIND_FAILED", "邮箱解绑失败，请稍后重试");
    }

    const user = await this.getUserById(legacyUserId);
    if (!user) {
      throw new NativeEmailError(500, "UNBIND_FAILED", "邮箱解绑失败，请稍后重试");
    }

    return user;
  }

  private requirePool(): Pool {
    if (!this.pool) {
      throw new NativeEmailError(503, "LEGACY_WRITE_DB_NOT_CONFIGURED", "Legacy write database is not configured.");
    }

    return this.pool;
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

export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

function normalizeUser(row: RowDataPacket): EmailUserProfile {
  return {
    id: Number(row.id),
    username: row.username ?? null,
    email: row.email ?? null,
    status: Number(row.status),
    emailVerifiedAt: row.emailVerifiedAt === null || row.emailVerifiedAt === undefined ? null : Number(row.emailVerifiedAt)
  };
}

function isDuplicateEntry(error: unknown): boolean {
  return Boolean(error && typeof error === "object" && "code" in error && (error as { code?: unknown }).code === "ER_DUP_ENTRY");
}
