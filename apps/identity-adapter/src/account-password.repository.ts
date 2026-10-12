import { Injectable, OnModuleDestroy } from "@nestjs/common";
import mysql, { Pool, PoolConnection, ResultSetHeader, RowDataPacket } from "mysql2/promise";
import { identityAccountWriteDb, loadConfig } from "./config.js";
import { hashLegacyPassword, verifyLegacyPassword } from "./legacy-password.js";
import { LegacyUserReadModel } from "./legacy-identity.reader.js";
import { enqueueSubjectEvent } from "./subject-events.js";

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

  async findCompletedPasswordOperation(operationKey: string, userId?: number): Promise<LegacyUserReadModel | null> {
    if (this.config.dataSource !== "identity") return null;
    const [rows] = await this.requirePool().execute<RowDataPacket[]>(
      "SELECT user_id FROM identity_account_password_requests WHERE operation_key = ?", [operationKey]
    );
    if (!rows[0] || (userId !== undefined && Number(rows[0].user_id) !== userId)) return null;
    const user = await this.getCredentialById(Number(rows[0].user_id));
    return user ? this.readModel(user) : null;
  }

  async changePassword(user: PasswordUserCredential, newPassword: string, operation?: { operationKey: string; resetChallengeKey?: string; resetTokenHash?: string; authorize?:(connection:PoolConnection)=>Promise<void> }): Promise<LegacyUserReadModel> {
    const pool = this.requirePool();
    const passwordHash = await hashLegacyPassword(newPassword);
    const connection = this.config.dataSource === "identity" ? await pool.getConnection() : null;
    let result: ResultSetHeader;
    try {
      if (connection) {
        await connection.beginTransaction();
        const [current]=await connection.execute<RowDataPacket[]>("SELECT status,email,email_verified_at,deleted_at FROM user WHERE id=? FOR UPDATE",[user.id]);
        if(Number(current[0]?.status)!==10)throw new NativePasswordError(401,{code:"UNAUTHORIZED",message:"Account is not active."});
        if(operation?.resetTokenHash&&(current[0].deleted_at!==null||current[0].email_verified_at===null||String(current[0].email).toLowerCase()!==user.email?.toLowerCase())){
          throw invalidResetToken();
        }
        await operation?.authorize?.(connection);
      }
      [result] = await (connection ?? pool).execute<ResultSetHeader>(
        `UPDATE user SET password_hash = ?, updated_at = ? WHERE id = ? AND password_hash = ?`,
        [passwordHash, Math.floor(Date.now() / 1000), user.id, user.passwordHash]
      );
      if (result.affectedRows !== 1) throw new NativePasswordError(409, { code: "PASSWORD_CHANGED_CONCURRENTLY", message: "Account password changed; retry the operation." });
      if (connection && result.affectedRows === 1) {
        if (operation?.resetTokenHash) {
          const [consumed] = await connection.execute<ResultSetHeader>(
            `UPDATE identity_password_reset_tokens SET consumed_at=UTC_TIMESTAMP(3)
              WHERE token_hash=? AND legacy_user_id=? AND email=? AND consumed_at IS NULL
                AND issued_at<=UTC_TIMESTAMP(3) AND expires_at>UTC_TIMESTAMP(3)`,
            [operation.resetTokenHash,user.id,user.email!.toLowerCase()]
          );
          if(consumed.affectedRows!==1)throw invalidResetToken();
        }
        if (operation?.resetChallengeKey) {
          const [consumed] = await connection.execute<ResultSetHeader>(
            "UPDATE password_reset_challenges SET consumed_at = ? WHERE challenge_key = ? AND consumed_at IS NULL AND expires_at > ?",
            [new Date(), operation.resetChallengeKey, new Date()]
          );
          if (consumed.affectedRows !== 1) throw new NativePasswordError(400, { code: "INVALID_CODE", message: "Password reset code is expired or already used." });
        }
        if (operation) await connection.execute("INSERT INTO identity_account_password_requests (operation_key, user_id) VALUES (?, ?)", [operation.operationKey, user.id]);
        await connection.execute(
          `INSERT INTO identity_user_revocations (user_id, revoked_before) VALUES (?, UTC_TIMESTAMP(3))
           ON DUPLICATE KEY UPDATE revoked_before = GREATEST(revoked_before, VALUES(revoked_before))`, [user.id]
        );
        await connection.execute(
          "UPDATE identity_refresh_sessions SET revoked_at = COALESCE(revoked_at, UTC_TIMESTAMP(3)) WHERE legacy_user_id = ?", [user.id]
        );
        await enqueueSubjectEvent(connection,user.id);
      }
      if (connection) await connection.commit();
    } catch (error) {
      if (connection) await connection.rollback();
      throw error;
    } finally {
      connection?.release();
    }
    if (result.affectedRows !== 1) {
      throw new NativePasswordError(500, {
        success: false,
        error: {
          code: "CHANGE_FAILED",
          message: "修改密码失败，请稍后重试"
        }
      });
    }

    return this.readModel(user);
  }

  private readModel(user: PasswordUserCredential): LegacyUserReadModel {
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
      source: this.config.dataSource === "identity" ? "identity-db" : "legacy"
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

function invalidResetToken(){return new NativePasswordError(400,{success:false,error:{code:"INVALID_TOKEN",message:"重置令牌无效或已过期"}});}
