import { Injectable, OnModuleDestroy } from "@nestjs/common";
import mysql, { Pool, ResultSetHeader, RowDataPacket } from "mysql2/promise";
import { loadConfig } from "./config.js";
import { hashLegacyPassword, verifyLegacyPassword } from "./legacy-password.js";
import { LegacyUserReadModel } from "./legacy-identity.reader.js";

export interface PasswordUserCredential {
  id: number;
  username: string | null;
  email: string | null;
  status: number;
  passwordHash: string | null;
  emailVerifiedAt: number | null;
}

export class NativePasswordError extends Error {
  constructor(
    readonly status: number,
    readonly body: Record<string, unknown>
  ) {
    super(JSON.stringify(body));
    this.name = "NativePasswordError";
  }
}

@Injectable()
export class AccountPasswordRepository implements OnModuleDestroy {
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

  async getCredentialById(userId: number): Promise<PasswordUserCredential | null> {
    const pool = this.requirePool();
    const [rows] = await pool.execute<RowDataPacket[]>(
      `SELECT id,
              username,
              email,
              status,
              password_hash AS passwordHash,
              email_verified_at AS emailVerifiedAt
         FROM user
        WHERE id = ?
        LIMIT 1`,
      [userId]
    );
    const row = rows[0];
    if (!row) {
      return null;
    }

    return {
      id: Number(row.id),
      username: row.username ?? null,
      email: row.email ?? null,
      status: Number(row.status),
      passwordHash: row.passwordHash ?? null,
      emailVerifiedAt: row.emailVerifiedAt === null || row.emailVerifiedAt === undefined ? null : Number(row.emailVerifiedAt)
    };
  }

  async getCredentialByEmail(email: string): Promise<PasswordUserCredential | null> {
    const pool = this.requirePool();
    const [rows] = await pool.execute<RowDataPacket[]>(
      `SELECT id,
              username,
              email,
              status,
              password_hash AS passwordHash,
              email_verified_at AS emailVerifiedAt
         FROM user
        WHERE email = ?
        LIMIT 1`,
      [email]
    );
    const row = rows[0];
    if (!row) {
      return null;
    }

    return {
      id: Number(row.id),
      username: row.username ?? null,
      email: row.email ?? null,
      status: Number(row.status),
      passwordHash: row.passwordHash ?? null,
      emailVerifiedAt: row.emailVerifiedAt === null || row.emailVerifiedAt === undefined ? null : Number(row.emailVerifiedAt)
    };
  }

  async changePassword(user: PasswordUserCredential, newPassword: string): Promise<LegacyUserReadModel> {
    const pool = this.requirePool();
    const passwordHash = await hashLegacyPassword(newPassword);
    const [result] = await pool.execute<ResultSetHeader>(
      `UPDATE user
          SET password_hash = ?, updated_at = ?
        WHERE id = ?`,
      [passwordHash, Math.floor(Date.now() / 1000), user.id]
    );
    if (result.affectedRows !== 1) {
      throw new NativePasswordError(500, {
        success: false,
        error: {
          code: "CHANGE_FAILED",
          message: "修改密码失败，请稍后重试"
        }
      });
    }

    return {
      id: user.id,
      username: user.username,
      email: user.email,
      status: user.status,
      nickname: null,
      emailVerifiedAt: user.emailVerifiedAt,
      createdAt: null,
      updatedAt: Math.floor(Date.now() / 1000),
      userInfo: null,
      roles: ["user"],
      organizations: [],
      source: "legacy"
    };
  }

  async verifyPassword(password: string, passwordHash: string | null): Promise<boolean> {
    if (!passwordHash) {
      return false;
    }

    return verifyLegacyPassword(password, passwordHash);
  }

  private requirePool(): Pool {
    if (!this.pool) {
      throw new NativePasswordError(503, {
        code: "LEGACY_WRITE_DB_NOT_CONFIGURED",
        message: "Legacy write database is not configured."
      });
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
