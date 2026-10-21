import { AdmissionWriter, markAdmissionUnknown } from "./identity-admission.js";
import { assertNativeUserAllocation } from "./identity-allocator-manifest.js";
import { createHash, randomBytes, randomInt, randomUUID } from "node:crypto";
import { Injectable, OnModuleDestroy } from "@nestjs/common";
import mysql, { Pool, PoolConnection, ResultSetHeader, RowDataPacket } from "mysql2/promise";
import { identityAccountWriteDb, loadConfig } from "./config.js";
import { hashLegacyPassword, verifyLegacyPassword } from "./legacy-password.js";
import { LegacyUserReadModel } from "./legacy-identity.reader.js";
import { enqueueSubjectEvent } from "./subject-events.js";
import { credentialOperationDigest } from "./account-lifecycle-operation.repository.js";

export interface NativeRegisteredUser extends LegacyUserReadModel { expectedPasswordHash?:string; }

export interface NativeRegisterInput {
  username: string;
  password: string;
  email?: string | null;
}

export interface NativeWechatRegisterInput extends NativeRegisterInput {
  wechatToken: string;
}

export interface NativeInvitationRegisterInput extends NativeRegisterInput {
  email: string;
  inviteCode: string;
  verificationCode: string;
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

  @AdmissionWriter()
  async register(input: NativeRegisterInput, operationKey?: string): Promise<NativeRegisteredUser> {
    const connection = await this.requireConnection();
    try {
      await connection.beginTransaction();
      const replay = await this.claimRegistration(connection, operationKey,input);
      if (replay) {
        await connection.commit();
        return replay;
      }
      const user = await this.insertUser(connection, input);
      await this.completeRegistration(connection, operationKey, user);
      await connection.commit();

      return user;
    } catch (error) {
      await rollbackQuietly(connection);
      throw normalizeWriteError(error);
    } finally {
      connection.release();
    }
  }

  @AdmissionWriter()
  async registerWechat(input: NativeWechatRegisterInput, operationKey?: string): Promise<NativeRegisteredUser> {
    const connection = await this.requireConnection();
    try {
      await connection.beginTransaction();
      const replay = await this.claimRegistration(connection, operationKey,input);
      if (replay) {
        await connection.commit();
        return replay;
      }
      const signupHash=createHash("sha256").update(input.wechatToken).digest("hex");
      if(this.config.dataSource==="identity") {
        const [bindings]=await connection.execute<RowDataPacket[]>("SELECT user_id FROM identity_wechat_identities WHERE signup_token_hash=? FOR UPDATE",[signupHash]);
        if(bindings.length>1 || bindings.some((binding)=>binding.user_id!=null))throw new NativeRegistrationError(409,"Provider registration bindings conflict");
      }
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
      if(this.config.dataSource==="identity")await connection.execute("UPDATE identity_wechat_identities SET user_id=?,signup_token_hash=NULL WHERE signup_token_hash=?",[user.id,signupHash]);
      await this.completeRegistration(connection, operationKey, user);
      await connection.commit();

      return user;
    } catch (error) {
      await rollbackQuietly(connection);
      throw normalizeWriteError(error);
    } finally {
      connection.release();
    }
  }

  @AdmissionWriter()
  async createInvitationEmailChallenge(inviteCode: string, rawEmail: string): Promise<string> {
    this.assertIndependent();
    const email = rawEmail.trim().toLowerCase();
    const connection = await this.requireConnection();
    try {
      await connection.beginTransaction();
      await this.requireInvitation(connection, inviteCode);
      const [users] = await connection.execute<RowDataPacket[]>("SELECT id FROM user WHERE email = ? LIMIT 1", [email]);
      if (users.length) throw new NativeRegistrationError(409, { code: 4002, message: "该邮箱已注册" });
      await connection.execute("INSERT IGNORE INTO identity_registration_email_limits (email) VALUES (?)", [email]);
      const [limits] = await connection.execute<RowDataPacket[]>(
        "SELECT last_sent_at FROM identity_registration_email_limits WHERE email = ? FOR UPDATE", [email]
      );
      const now = unixNow();
      const retryAfter = this.config.emailVerification.rateLimitSeconds - (now - Number(limits[0]?.last_sent_at ?? 0));
      if (retryAfter > 0) throw new NativeRegistrationError(429, { code: 4003, message: `发送过于频繁，请 ${retryAfter} 秒后再试` });
      const code = String(randomInt(0, 1_000_000)).padStart(6, "0");
      await connection.execute(
        `INSERT INTO invitation_email_challenges (challenge_key, invite_code, email, code_hash, expires_at)
         VALUES (?, ?, ?, ?, ?)`,
        [`invitation-email:${randomUUID()}`, inviteCode, email, this.invitationCodeHash(inviteCode, email, code),
          new Date(Date.now() + this.config.emailVerification.codeTtlSeconds * 1000)]
      );
      await connection.execute("UPDATE identity_registration_email_limits SET last_sent_at = ? WHERE email = ?", [now, email]);
      await connection.commit();
      return code;
    } catch (error) {
      await rollbackQuietly(connection);
      throw normalizeWriteError(error);
    } finally {
      connection.release();
    }
  }

  @AdmissionWriter()
  async registerInvitation(input: NativeInvitationRegisterInput, operationKey: string): Promise<LegacyUserReadModel> {
    this.assertIndependent();
    const connection = await this.requireConnection();
    const email = input.email.trim().toLowerCase();
    try {
      await connection.beginTransaction();
      const replay = await this.claimRegistration(connection, operationKey,input);
      if (replay) { await connection.commit(); return replay; }
      const invitation = await this.requireInvitation(connection, input.inviteCode);
      const [challenges] = await connection.execute<RowDataPacket[]>(
        `SELECT id, code_hash, attempts, expires_at, locked_until, consumed_at FROM invitation_email_challenges
         WHERE invite_code = ? AND email = ? ORDER BY id DESC LIMIT 1 FOR UPDATE`, [input.inviteCode, email]
      );
      const challenge = challenges[0];
      if (!challenge || challenge.consumed_at || new Date(challenge.expires_at).getTime() <= Date.now()) {
        throw new NativeRegistrationError(400, { code: 4001, message: "验证码已过期或未发送，请重新获取" });
      }
      if (Number(challenge.attempts) >= this.config.emailVerification.maxAttempts ||
          (challenge.locked_until && new Date(challenge.locked_until).getTime() > Date.now())) {
        throw new NativeRegistrationError(429, { code: 4003, message: "验证失败次数过多，请重新获取验证码" });
      }
      if (challenge.code_hash !== this.invitationCodeHash(input.inviteCode, email, input.verificationCode)) {
        await connection.execute("UPDATE invitation_email_challenges SET attempts = attempts + 1 WHERE id = ?", [challenge.id]);
        // Failed attempts must survive the rejected registration transaction.
        await connection.commit();
        throw new NativeRegistrationError(400, { code: 4001, message: "邮箱验证码不正确" });
      }
      const user = await this.insertUser(connection, input);
      const verifiedAt = unixNow();
      await connection.execute("UPDATE user SET email_verified_at = ? WHERE id = ?", [verifiedAt, user.id]);
      user.emailVerifiedAt = verifiedAt;
      await connection.execute(
        "UPDATE identity_invitations SET remaining = remaining - 1 WHERE invite_code = ? AND remaining > 0", [input.inviteCode]
      );
      await connection.execute(
        "INSERT INTO invitation_record (invite_code, inviter_id, invitee_id, created_at) VALUES (?, ?, ?, ?)",
        [input.inviteCode, Number(invitation.creator_legacy_user_id ?? 0), user.id, verifiedAt]
      );
      await connection.execute("UPDATE invitation_email_challenges SET consumed_at = ? WHERE id = ?", [new Date(), challenge.id]);
      await this.completeRegistration(connection, operationKey, user);
      await connection.commit();
      return user;
    } catch (error) {
      await rollbackQuietly(connection);
      throw normalizeWriteError(error);
    } finally {
      connection.release();
    }
  }

  private assertIndependent(): void {
    if (this.config.dataSource !== "identity") throw new NativeRegistrationError(404, "Independent invitation registration is disabled.");
  }

  private async requireInvitation(connection: PoolConnection, inviteCode: string): Promise<RowDataPacket> {
    const [rows] = await connection.execute<RowDataPacket[]>(
      "SELECT * FROM identity_invitations WHERE invite_code = ? FOR UPDATE", [inviteCode]
    );
    const invitation = rows[0];
    if (!invitation || invitation.deleted_at || invitation.status === "deleted" || Number(invitation.expires_at) <= unixNow()) {
      throw new NativeRegistrationError(400, { code: 4001, message: "邀请码不存在或已过期" });
    }
    if (Number(invitation.remaining) < 1) throw new NativeRegistrationError(400, { code: 4001, message: "邀请名额已用完" });
    return invitation;
  }

  private invitationCodeHash(inviteCode: string, email: string, code: string): string {
    return createHash("sha256").update([this.config.emailVerification.codeHashSalt, inviteCode, email, code].join("\u001f")).digest("hex");
  }

  private async claimRegistration(connection: PoolConnection, operationKey:string|undefined,input:NativeRegisterInput): Promise<NativeRegisteredUser | null> {
    if (this.config.dataSource !== "identity" || !operationKey) return null;
    await connection.execute(
      `INSERT INTO identity_account_registration_requests (operation_key,request_hash) VALUES (?,?)
       ON DUPLICATE KEY UPDATE operation_key = VALUES(operation_key)`, [operationKey,registrationFingerprint(input)]
    );
    const [rows] = await connection.execute<RowDataPacket[]>(
      "SELECT user_id,request_hash FROM identity_account_registration_requests WHERE operation_key = ? FOR UPDATE", [operationKey]
    );
    if(rows[0]?.request_hash!==registrationFingerprint(input))throw new NativeRegistrationError(409,"Registration request key was used with different input.");
    if (!rows[0]?.user_id) return null;
    const [users] = await connection.execute<RowDataPacket[]>(
      `SELECT id, username, email, status, nickname, password_hash, email_verified_at, created_at, updated_at
       FROM user WHERE id = ? FOR UPDATE`, [rows[0].user_id]
    );
    const user = users[0];
    if (!user || Number(user.status) !== 10) throw new NativeRegistrationError(409, "Registered account is no longer active.");
    if(typeof user.password_hash!=="string" || !(await verifyLegacyPassword(input.password,user.password_hash)))throw new NativeRegistrationError(409,"Registration credential has changed; sign in with the current password.");
    const [roles] = await connection.execute<RowDataPacket[]>(
      `SELECT aa.item_name FROM auth_assignment aa JOIN auth_item ai ON ai.name = aa.item_name
       WHERE aa.user_id = ? AND ai.type = 1`, [String(user.id)]
    );
    return {
      id: Number(user.id), username: user.username, email: user.email, status: Number(user.status),
      nickname: user.nickname, emailVerifiedAt: user.email_verified_at === null ? null : Number(user.email_verified_at),
      createdAt: Number(user.created_at), updatedAt: Number(user.updated_at), userInfo: null,
      roles: roles.map((role) => String(role.item_name)), organizations: [], source: "identity-db",expectedPasswordHash:user.password_hash
    };
  }

  private async completeRegistration(connection: PoolConnection, operationKey: string | undefined, user: LegacyUserReadModel): Promise<void> {
    if (this.config.dataSource !== "identity" || !operationKey) return;
    await connection.execute(
      "UPDATE identity_account_registration_requests SET user_id = ? WHERE operation_key = ?", [user.id, operationKey]
    );
  }

  /** Reuse the native account/role/profile policy inside an atomic provider-proof transaction. */
  @AdmissionWriter()
  async createUserInTransaction(connection:PoolConnection,input:NativeRegisterInput):Promise<NativeRegisteredUser>{
    this.assertIndependent();
    try{return await this.insertUser(connection,input);}catch(error){throw normalizeWriteError(error);}
  }

  private async insertUser(connection: PoolConnection, input: NativeRegisterInput): Promise<NativeRegisteredUser> {
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
    const userId = this.config.dataSource === "identity" ? assertNativeUserAllocation(result.insertId) : Number(result.insertId);

    await connection.execute(`INSERT INTO user_info (user_id) VALUES (?)`, [userId]);
    await connection.execute(
      `INSERT IGNORE INTO auth_assignment (item_name, user_id, created_at)
       VALUES (?, ?, ?)`,
      ["user", String(userId), now]
    );
    if (this.config.dataSource === "identity") {
      await enqueueSubjectEvent(connection,userId);
    }

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
      source: this.config.dataSource === "identity" ? "identity-db" : "legacy"
      ,...(this.config.dataSource==="identity"?{expectedPasswordHash:passwordHash}:{})
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

function registrationFingerprint(input:NativeRegisterInput):string {
  const value={...input,username:input.username.trim().toLowerCase(),email:input.email?.trim().toLowerCase()||null};
  return credentialOperationDigest(Object.keys(value).sort().map((key)=>JSON.stringify([key,(value as Record<string,unknown>)[key]])));
}

function unixNow(): number {
  return Math.floor(Date.now() / 1000);
}

async function rollbackQuietly(connection: PoolConnection): Promise<void> {
  try {
    await connection.rollback();
  } catch {
    await markAdmissionUnknown();
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
