import { AdmissionWriter } from "./identity-admission.js";
import { Injectable, OnModuleDestroy } from "@nestjs/common";
import mysql, { Pool, PoolConnection, ResultSetHeader, RowDataPacket } from "mysql2/promise";
import { identityAccountWriteDb, loadConfig } from "./config.js";
import { enqueueSubjectEvent } from "./subject-events.js";

export interface EmailWriteProof { challengeKey?:string|null;changeTokenKey?:string|null;expectedEmail?:string|null;authorize?:(connection:PoolConnection)=>Promise<void>; }

export interface EmailUserProfile {
  id: number;
  username: string | null;
  email: string | null;
  status: number;
  emailVerifiedAt: number | null;
  authorizeWrite?:(connection:PoolConnection)=>Promise<void>;
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

  @AdmissionWriter()
  async bindVerifiedEmail(legacyUserId: number, email: string, verifiedAt: number, proof?:EmailWriteProof): Promise<EmailUserProfile> {
    try {
      const result = await this.writeUser(
        `UPDATE user
            SET email = ?, email_verified_at = ?, updated_at = ?
          WHERE id = ?`,
        [normalizeEmail(email), verifiedAt, verifiedAt, legacyUserId], legacyUserId,proof
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

  @AdmissionWriter()
  async unbindEmail(legacyUserId: number, updatedAt: number, proof?:EmailWriteProof): Promise<EmailUserProfile> {
    const result = await this.writeUser(
      `UPDATE user
          SET email = NULL, email_verified_at = NULL, updated_at = ?
        WHERE id = ?`,
      [updatedAt, legacyUserId], legacyUserId,proof
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

  private async writeUser(sql: string, params: Array<string | number | null>, userId: number,proof?:EmailWriteProof): Promise<ResultSetHeader> {
    const pool = this.requirePool();
    if (this.config.dataSource === "legacy") return (await pool.execute<ResultSetHeader>(sql, params))[0];
    const connection = await pool.getConnection();
    try {
      await connection.beginTransaction();
      const [users]=await connection.execute<RowDataPacket[]>("SELECT status,email FROM user WHERE id=? FOR UPDATE",[userId]);
      if(Number(users[0]?.status)!==10 || (proof && "expectedEmail" in proof && (users[0]?.email??null)!==proof.expectedEmail)) {
        throw new NativeEmailError(409,"ACCOUNT_CHANGED","账号或邮箱已变更，请重新验证");
      }
      await proof?.authorize?.(connection);
      if(proof?.challengeKey) {
        const [consumed]=await connection.execute<ResultSetHeader>(`UPDATE email_verification_challenges SET consumed_at=UTC_TIMESTAMP(3)
          WHERE challenge_key=? AND legacy_user_id=? AND consumed_at IS NULL AND expires_at>UTC_TIMESTAMP(3)`,[proof.challengeKey,userId]);
        if(consumed.affectedRows!==1)throw new NativeEmailError(400,"INVALID_CODE","验证码不存在或已过期");
      }
      if(proof?.changeTokenKey) {
        const [consumed]=await connection.execute<ResultSetHeader>(`UPDATE email_change_tokens SET consumed_at=UTC_TIMESTAMP(3)
          WHERE token_key=? AND legacy_user_id=? AND consumed_at IS NULL AND expires_at>UTC_TIMESTAMP(3)`,[proof.changeTokenKey,userId]);
        if(consumed.affectedRows!==1)throw new NativeEmailError(400,"INVALID_CODE","改绑邮箱需重新完成旧邮箱验证");
      }
      const [result] = await connection.execute<ResultSetHeader>(sql, params);
      if (result.affectedRows === 1) await enqueueSubjectEvent(connection,userId);
      await connection.commit();
      return result;
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  }

  private requirePool(): Pool {
    if (!this.pool) {
      throw new NativeEmailError(503, "LEGACY_WRITE_DB_NOT_CONFIGURED", "Legacy write database is not configured.");
    }

    return this.pool;
  }

  private createPool(): Pool | null {
    const legacyWriteDb = identityAccountWriteDb(this.config);
    if (!legacyWriteDb.host || !legacyWriteDb.user) {
      return null;
    }

    return mysql.createPool({
      host: legacyWriteDb.host,
      port: legacyWriteDb.port,
      database: legacyWriteDb.name,
      user: legacyWriteDb.user,
      password: legacyWriteDb.password,
      ...(this.config.dataSource === "identity" ? { timezone: "Z" } : {}),
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
