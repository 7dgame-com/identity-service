import { createHash, randomBytes, createCipheriv, createDecipheriv, timingSafeEqual } from "node:crypto";
import { Injectable, OnModuleDestroy } from "@nestjs/common";
import mysql, { Pool, PoolConnection, ResultSetHeader, RowDataPacket } from "mysql2/promise";
import { loadConfig } from "./config.js";
import { assertDeviceSnAccount, deviceSnSource } from "./device-sn-source.js";
import { legacyRefreshCredentialSchema } from "./legacy-refresh-credential-schema.js";
import { legacyWechatSignupSchema } from "./legacy-wechat-signup-schema.js";
import { revokeLegacyRefreshCredentialsInTransaction, revokeLegacyRefreshFamilyInTransaction } from "./legacy-refresh-credential-revocation.js";

export class InvalidRefreshTokenError extends Error {
  constructor(message = "refresh token is invalid") {
    super(message);
    this.name = "InvalidRefreshTokenError";
  }
}

export interface IdentitySessionInput {
  legacyUserId: number;
  username: string | null;
  sessionId: string;
  expiresAt: Date;
  ipAddressHash?: string | null;
  userAgentHash?: string | null;
  expectedPasswordHash?: string;
  expectedLegacyAuthKey?: string;
  authMethod?: "device_sn" | null;
  deviceSnId?: number | null;
}

export interface IssuedIdentitySession {
  refreshToken: string;
  refreshTokenHash: string;
  sessionId: string;
  legacyUserId: number;
  username: string | null;
  expiresAt: Date;
  authMethod?: "device_sn";
  deviceSnId?: number;
}

export interface StoredIdentitySession {
  id: number;
  refreshTokenHash: string;
  sessionId: string;
  legacyUserId: number;
  username: string | null;
  expiresAt: Date;
  revokedAt: Date | null;
  authMethod?: "device_sn";
  deviceSnId?: number;
}

export interface OidcSessionBinding {
  clientId: string;
  scopes: string[];
}

@Injectable()
export class IdentitySessionRepository implements OnModuleDestroy {
  private readonly config = loadConfig();
  private readonly pool: Pool | null;
  private schemaReady: Promise<void> | null = null;

  constructor() {
    this.pool = this.createPool();
  }

  async onModuleDestroy(): Promise<void> {
    await this.pool?.end();
  }

  isConfigured(): boolean {
    return this.pool !== null;
  }

  async issue(input: IdentitySessionInput): Promise<IssuedIdentitySession> {
    const pool = this.requirePool();
    await this.ensureSchema();

    const connection = await pool.getConnection();
    try {
      await connection.beginTransaction();
      await this.lockActiveUser(connection, input);
      const session = await this.insertSession(connection, input);
      await connection.commit();
      return session;
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally { connection.release(); }
  }

  /** OIDC grants and their session family must become visible in the same commit. */
  async issueOidcSession(input: IdentitySessionInput, binding: OidcSessionBinding): Promise<IssuedIdentitySession> {
    await this.ensureSchema();
    const connection = await this.requirePool().getConnection();
    try {
      await connection.beginTransaction();
      await this.lockActiveUser(connection, input);
      const session = await this.insertSession(connection, input);
      await connection.execute("INSERT INTO identity_oidc_session_bindings(session_id,client_id,scopes_json) VALUES (?,?,?)",
        [session.sessionId, binding.clientId, JSON.stringify(binding.scopes)]);
      await connection.commit();
      return session;
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally { connection.release(); }
  }

  async getOidcBinding(sessionId: string): Promise<OidcSessionBinding | null> {
    await this.ensureSchema();
    const [rows] = await this.requirePool().execute<RowDataPacket[]>(
      "SELECT client_id,scopes_json FROM identity_oidc_session_bindings WHERE session_id=? LIMIT 1", [sessionId]);
    if (!rows[0]) return null;
    const scopes: unknown = typeof rows[0].scopes_json === "string" ? JSON.parse(rows[0].scopes_json) : rows[0].scopes_json;
    if (!Array.isArray(scopes) || !scopes.every((scope) => typeof scope === "string")) throw new InvalidRefreshTokenError("OIDC binding is invalid");
    return { clientId: String(rows[0].client_id), scopes };
  }

  /** Caller owns the transaction; readiness must be checked before taking account locks. */
  async issueInTransaction(connection:PoolConnection,input:IdentitySessionInput):Promise<IssuedIdentitySession>{
    await this.lockActiveUser(connection,input);
    return this.insertSession(connection,input);
  }

  /** A verification retry can replay only its original still-live refresh credential. */
  async canReplayInTransaction(connection:PoolConnection,userId:number,sessionId:string,refreshTokenHash:string):Promise<boolean>{
    const [rows]=await connection.execute<RowDataPacket[]>(`SELECT issued_at,expires_at,revoked_at FROM identity_refresh_sessions
      WHERE legacy_user_id=? AND session_id=? AND refresh_token_hash=? FOR SHARE`,[userId,sessionId,refreshTokenHash]);
    if(!rows[0]||rows[0].revoked_at||normalizeDate(rows[0].expires_at).getTime()<=Date.now())return false;
    const [cutoffs]=await connection.execute<RowDataPacket[]>("SELECT revoked_before FROM identity_user_revocations WHERE user_id=? FOR SHARE",[userId]);
    return !cutoffs[0]||normalizeDate(rows[0].issued_at).getTime()>normalizeDate(cutoffs[0].revoked_before).getTime();
  }

  /** Consume and replace under the same row lock. Never issue two successors. */
  async rotate(refreshToken: string, next: IdentitySessionInput, idempotencyKey?: string): Promise<IssuedIdentitySession> {
    const pool = this.requirePool();
    await this.ensureSchema();
    const connection = await pool.getConnection();
    const tokenHash = hashRefreshToken(refreshToken);
    const replayKey = replayEncryptionKey();
    try {
      await connection.beginTransaction();
      await this.lockActiveUser(connection, next);
      const [rows] = await connection.execute<RowDataPacket[]>(
        `SELECT id, session_id, revoked_at, expires_at, legacy_user_id, auth_method, device_sn_id FROM identity_refresh_sessions
          WHERE refresh_token_hash = ? LIMIT 1 FOR UPDATE`, [tokenHash]);
      const current = rows[0];
      if (!current || normalizeDate(current.expires_at).getTime() <= Date.now()
          || Number(current.legacy_user_id) !== next.legacyUserId) throw new InvalidRefreshTokenError();
      const source = deviceSnSource(current.auth_method, current.device_sn_id == null ? null : Number(current.device_sn_id));
      const replacementInput = { ...next, sessionId: String(current.session_id), authMethod: source?.authMethod ?? null, deviceSnId: source?.deviceSnId ?? null };
      await this.lockActiveUser(connection, replacementInput);
      if (current.revoked_at) {
        const replay = replayKey ? await this.readReplay(connection, tokenHash, idempotencyKey, replayKey) : null;
        if (!replay) throw new InvalidRefreshTokenError();
        await connection.commit();
        return replay;
      }
      // Session provenance is immutable, including for callers that omit or forge it.
      const replacement = await this.insertSession(connection, replacementInput);
      const [changed] = await connection.execute<ResultSetHeader>(
        `UPDATE identity_refresh_sessions SET revoked_at = UTC_TIMESTAMP(3), replaced_by_hash = ?
          WHERE id = ? AND revoked_at IS NULL`, [replacement.refreshTokenHash, current.id]);
      if (changed.affectedRows !== 1) throw new InvalidRefreshTokenError();
      if (replayKey) {
        await connection.execute(
          `INSERT INTO identity_refresh_replays (predecessor_hash, successor_hash, request_hash, encrypted_response, created_at, expires_at)
           VALUES (?, ?, ?, ?, UTC_TIMESTAMP(3), DATE_ADD(UTC_TIMESTAMP(3), INTERVAL 30 SECOND))`,
          [tokenHash, replacement.refreshTokenHash, hashMaybe(idempotencyKey), encryptReplay(replacement, replayKey)]);
      }
      await connection.commit();
      return replacement;
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally { connection.release(); }
  }

  private async insertSession(connection: PoolConnection, input: IdentitySessionInput): Promise<IssuedIdentitySession> {
    const source = deviceSnSource(input.authMethod, input.deviceSnId);
    const refreshToken = randomBytes(48).toString("base64url");
    const refreshTokenHash = hashRefreshToken(refreshToken);
    await connection.execute(
      `INSERT INTO identity_refresh_sessions (refresh_token_hash, session_id, legacy_user_id, username, issued_at, expires_at, ip_hash, user_agent_hash, auth_method, device_sn_id)
       VALUES (?, ?, ?, ?, GREATEST(UTC_TIMESTAMP(3), COALESCE((SELECT DATE_ADD(revoked_before, INTERVAL 1000 MICROSECOND) FROM identity_user_revocations WHERE user_id = ?), UTC_TIMESTAMP(3))), ?, ?, ?, ?, ?)`,
      [refreshTokenHash, input.sessionId, input.legacyUserId, input.username, input.legacyUserId, input.expiresAt,
       input.ipAddressHash ?? null, input.userAgentHash ?? null, source?.authMethod ?? null, source?.deviceSnId ?? null]);
    return { refreshToken, refreshTokenHash, sessionId: input.sessionId, legacyUserId: input.legacyUserId,
      username: input.username, expiresAt: input.expiresAt, ...(source ?? {}) };
  }

  private async readReplay(connection: PoolConnection, hash: string, requestKey: string | undefined, key: Buffer): Promise<IssuedIdentitySession | null> {
    const [rows] = await connection.execute<RowDataPacket[]>(
      `SELECT r.encrypted_response, r.request_hash, r.created_at FROM identity_refresh_replays r
       JOIN identity_refresh_sessions s ON s.refresh_token_hash = r.successor_hash
       WHERE r.predecessor_hash = ? AND r.expires_at > UTC_TIMESTAMP(3)
         AND s.revoked_at IS NULL AND s.expires_at > UTC_TIMESTAMP(3) LIMIT 1`, [hash]);
    const row = rows[0];
    if (!row) return null;
    const sameRequest = !!requestKey && row.request_hash === hashMaybe(requestKey);
    if (!sameRequest && Date.now() - normalizeDate(row.created_at).getTime() > 5000) return null;
    const result = decryptReplay(String(row.encrypted_response), key);
    return { ...result, expiresAt: new Date(result.expiresAt) };
  }

  /** Peek also permits a bounded replay; rotation remains the sole consumer. */
  async findRefreshCandidate(refreshToken: string): Promise<StoredIdentitySession> {
    try { return await this.findValidSession(refreshToken); }
    catch (error) {
      if (!(error instanceof InvalidRefreshTokenError) || !replayEncryptionKey()) throw error;
      const [rows] = await this.requirePool().execute<RowDataPacket[]>(
        `SELECT s.id, s.refresh_token_hash AS refreshTokenHash, s.session_id AS sessionId,
          s.legacy_user_id AS legacyUserId, s.username, s.expires_at AS expiresAt, s.revoked_at AS revokedAt,
          s.auth_method AS authMethod, s.device_sn_id AS deviceSnId
         FROM identity_refresh_sessions s JOIN identity_refresh_replays r ON r.predecessor_hash = s.refresh_token_hash
         WHERE s.refresh_token_hash = ? AND r.expires_at > UTC_TIMESTAMP(3) LIMIT 1`, [hashRefreshToken(refreshToken)]);
      if (!rows[0]) throw error;
      return normalizeStoredSession(rows[0]);
    }
  }

  async isAccessRevoked(userId: number, issuedAt: number, sessionId: string | null, allowUntrackedLegacy = false, connection?: PoolConnection): Promise<boolean> {
    if (this.config.dataSource !== "identity") return false;
    await this.ensureSchema();
    const pool = connection ?? this.requirePool();
    const lock = connection ? " FOR SHARE" : "";
    const [rows] = await pool.execute<RowDataPacket[]>(
      `SELECT revoked_before FROM identity_user_revocations WHERE user_id = ?${lock}`, [userId]);
    const cutoff = rows[0] ? normalizeDate(rows[0].revoked_before).getTime() : null;
    if (!sessionId) return cutoff !== null && issuedAt * 1000 <= cutoff;
    const [sessions] = await pool.execute<RowDataPacket[]>(
      `SELECT issued_at, revoked_at, replaced_by_hash FROM identity_refresh_sessions WHERE session_id = ? AND legacy_user_id = ? ORDER BY id DESC LIMIT 1${lock}`,
      [sessionId, userId]);
    const session = sessions[0];
    if (!session) return !allowUntrackedLegacy || (cutoff !== null && issuedAt * 1000 <= cutoff);
    if (cutoff !== null && normalizeDate(session.issued_at).getTime() <= cutoff) return true;
    // Stable session IDs survive rotation. Explicit logout revokes the whole family.
    return !!session.revoked_at && !session.replaced_by_hash;
  }

  async revoke(refreshToken: string | null | undefined): Promise<boolean> {
    if (!refreshToken) return true;
    await this.ensureSchema();
    const connection = await this.requirePool().getConnection();
    try {
      await connection.beginTransaction();
      if (this.config.dataSource === "identity") {
        const [owners] = await connection.execute<RowDataPacket[]>("SELECT legacy_user_id FROM identity_refresh_sessions WHERE refresh_token_hash=?", [hashRefreshToken(refreshToken)]);
        if (owners[0]) await connection.execute("SELECT id FROM user WHERE id=? FOR UPDATE", [owners[0].legacy_user_id]);
      }
      let hash: string | null = hashRefreshToken(refreshToken);
      const visited = new Set<string>();
      // Lock the same predecessor as rotate before following its committed successors.
      while (hash && !visited.has(hash)) {
        visited.add(hash);
        const [rows]: [RowDataPacket[], unknown] = await connection.execute<RowDataPacket[]>(
          "SELECT session_id, replaced_by_hash FROM identity_refresh_sessions WHERE refresh_token_hash = ? FOR UPDATE", [hash]);
        if (!rows[0]) break;
        const next: string | null = rows[0].replaced_by_hash ? String(rows[0].replaced_by_hash) : null;
        await connection.execute(`UPDATE identity_refresh_sessions
          SET revoked_at = COALESCE(revoked_at, UTC_TIMESTAMP(3)), replaced_by_hash = NULL
          WHERE session_id = ?`, [rows[0].session_id]);
        if (this.config.dataSource === "identity") await revokeLegacyRefreshFamilyInTransaction(connection, String(rows[0].session_id));
        hash = next;
      }
      await connection.commit();
      return true;
    } catch (error) { await connection.rollback(); throw error; }
    finally { connection.release(); }
  }

  async revokeUserSessions(legacyUserId: number): Promise<number> {
    await this.ensureSchema();
    const connection = await this.requirePool().getConnection();
    try {
      await connection.beginTransaction();
      if (this.config.dataSource === "identity") {
        await connection.execute("SELECT id FROM user WHERE id = ? FOR UPDATE", [legacyUserId]);
        await connection.execute(`INSERT INTO identity_user_revocations (user_id, revoked_before) VALUES (?, UTC_TIMESTAMP(3))
          ON DUPLICATE KEY UPDATE revoked_before = UTC_TIMESTAMP(3)`, [legacyUserId]);
      }
      const [result] = await connection.execute<ResultSetHeader>(`UPDATE identity_refresh_sessions
        SET revoked_at = COALESCE(revoked_at, UTC_TIMESTAMP(3)), replaced_by_hash = NULL
        WHERE legacy_user_id = ? AND revoked_at IS NULL`, [legacyUserId]);
      if (this.config.dataSource === "identity") await revokeLegacyRefreshCredentialsInTransaction(connection, legacyUserId);
      await connection.commit();
      return result.affectedRows;
    } catch (error) { await connection.rollback(); throw error; }
    finally { connection.release(); }
  }

  private async lockActiveUser(connection: PoolConnection, input: IdentitySessionInput) {
    if (this.config.dataSource !== "identity") return;
    const [users] = await connection.execute<RowDataPacket[]>(
      "SELECT status,password_hash,auth_key FROM user WHERE id = ? FOR UPDATE", [input.legacyUserId]);
    if (Number(users[0]?.status) !== 10 || (input.expectedPasswordHash !== undefined && users[0]?.password_hash !== input.expectedPasswordHash)) {
      throw new InvalidRefreshTokenError("account changed while authenticating");
    }
    if (deviceSnSource(input.authMethod, input.deviceSnId)) {
      const [roles] = await connection.execute<RowDataPacket[]>(`SELECT aa.item_name FROM auth_assignment aa
        JOIN auth_item ai ON ai.name=aa.item_name WHERE aa.user_id=? AND ai.type=1`, [String(input.legacyUserId)]);
      assertDeviceSnAccount({ status: Number(users[0].status), roles: roles.map(row=>String(row.item_name)) });
    }
    if(input.expectedLegacyAuthKey!==undefined){
      const actual=Buffer.from(String(users[0]?.auth_key??"")),expected=Buffer.from(input.expectedLegacyAuthKey);
      const deadline=Date.parse(process.env.IDENTITY_LEGACY_PHP_SESSION_ACCEPT_UNTIL??"");
      const [revocations]=await connection.execute<RowDataPacket[]>("SELECT user_id FROM identity_user_revocations WHERE user_id=? FOR SHARE",[input.legacyUserId]);
      if(!Number.isFinite(deadline)||Date.now()>=deadline||expected.length<16||actual.length!==expected.length||!timingSafeEqual(actual,expected)||revocations.length)throw new InvalidRefreshTokenError("legacy browser session is no longer accepted");
    }
  }

  async findValidSession(refreshToken: string): Promise<StoredIdentitySession> {
    const pool = this.requirePool();
    await this.ensureSchema();
    const refreshTokenHash = hashRefreshToken(refreshToken);

    const [rows] = await pool.execute<RowDataPacket[]>(
      `SELECT id,
              refresh_token_hash AS refreshTokenHash,
              session_id AS sessionId,
              legacy_user_id AS legacyUserId,
              username,
              expires_at AS expiresAt,
              revoked_at AS revokedAt,
              auth_method AS authMethod,
              device_sn_id AS deviceSnId
         FROM identity_refresh_sessions
        WHERE refresh_token_hash = ?
        LIMIT 1`,
      [refreshTokenHash]
    );

    const session = rows[0] ? normalizeStoredSession(rows[0]) : null;
    if (!session || session.revokedAt || session.expiresAt.getTime() <= Date.now()) {
      throw new InvalidRefreshTokenError();
    }

    return session;
  }

  /** Credential classification includes expired/revoked rows; they must never become login codes. */
  async hasRefreshToken(refreshToken:string):Promise<boolean> {
    await this.ensureSchema();
    const [rows]=await this.requirePool().execute<RowDataPacket[]>(
      "SELECT id FROM identity_refresh_sessions WHERE refresh_token_hash=? LIMIT 1",[hashRefreshToken(refreshToken)]);
    return rows.length>0;
  }
  async isOAuthBound(sessionId:string,connection?:PoolConnection):Promise<boolean> {
    await this.ensureSchema();
    const [rows]=await (connection??this.requirePool()).execute<RowDataPacket[]>(`SELECT session_id FROM identity_oauth_session_bindings WHERE session_id=?
      UNION ALL SELECT session_id FROM identity_oidc_session_bindings WHERE session_id=? LIMIT 1`,[sessionId,sessionId]);
    return rows.length>0;
  }

  async deviceSnReadiness(): Promise<boolean> {
    if (!this.pool) return false;
    try { await this.pool.query("SELECT auth_method, device_sn_id FROM identity_refresh_sessions LIMIT 0"); return true; }
    catch { return false; }
  }

  async ensureSchema(): Promise<void> {
    if (!this.schemaReady) {
      this.schemaReady = (this.config.activationMode === "explicit" ? this.validateExistingSchema() : this.createSchema())
        .catch((error) => { this.schemaReady = null; throw error; });
    }

    return this.schemaReady;
  }

  /** Explicit standby performs no automatic DDL, including CREATE IF NOT EXISTS. */
  async useExistingSchema(): Promise<void> {
    if (!this.schemaReady) this.schemaReady = this.validateExistingSchema()
      .catch((error) => { this.schemaReady = null; throw error; });
    return this.schemaReady;
  }

  private async validateExistingSchema(): Promise<void> {
    // Keep the complete contracts in step with createSchema and its two imported ledgers.
    // LIMIT 0 checks even nullable/replay fields without reading credential contents.
    const columns: Record<string, string> = {
      identity_refresh_sessions: "id,refresh_token_hash,session_id,legacy_user_id,username,issued_at,expires_at,revoked_at,replaced_by_hash,ip_hash,user_agent_hash,auth_method,device_sn_id,created_at,updated_at",
      identity_refresh_replays: "predecessor_hash,successor_hash,request_hash,encrypted_response,created_at,expires_at",
      identity_user_revocations: "user_id,revoked_before",
      identity_legacy_refresh_credentials: "credential_hash,source_record_id,legacy_user_id,source_kind,source_revision,source_fields_json,key_encoding,a1_compatible,server_compatible,snapshot_at,account_fingerprint,expires_at,source_revoked_at,revoked_at,redeemed_at,redeemed_consumer,session_id,successor_hash,request_hash,encrypted_response,replay_expires_at",
      identity_legacy_wechat_signup_credentials: "credential_hash,source_database,source_record_id,source_revision,manifest_hash,evidence_json,provider,provider_app_id,open_id,expires_at,source_revoked_at,revoked_at,consumed_at,consumed_user_id,consumed_action,account_fingerprint,session_id,successor_hash,request_hash,encrypted_response,replay_expires_at",
      identity_oauth_session_bindings: "session_id,client_id,scopes_json,legacy_subject",
      identity_oidc_session_bindings: "session_id,client_id,scopes_json",
    };
    type RequiredIndex = { columns: string[]; primary?: true; unique?: true };
    const indexes: Record<string, RequiredIndex[]> = {
      identity_refresh_sessions: [
        { columns: ["id"], primary: true }, { columns: ["refresh_token_hash"], unique: true },
        { columns: ["legacy_user_id", "expires_at"] }, { columns: ["session_id"] },
      ],
      identity_refresh_replays: [{ columns: ["predecessor_hash"], primary: true }, { columns: ["expires_at"] }],
      identity_user_revocations: [{ columns: ["user_id"], primary: true }],
      identity_legacy_refresh_credentials: [
        { columns: ["credential_hash"], primary: true }, { columns: ["source_record_id"], unique: true },
        { columns: ["legacy_user_id"] }, { columns: ["session_id"] },
      ],
      identity_legacy_wechat_signup_credentials: [
        { columns: ["credential_hash"], primary: true }, { columns: ["source_database", "source_record_id"], unique: true },
        { columns: ["provider", "provider_app_id", "open_id"], unique: true },
        { columns: ["consumed_user_id"] }, { columns: ["session_id"] },
      ],
      identity_oauth_session_bindings: [{ columns: ["session_id"], primary: true }, { columns: ["client_id"] }],
      identity_oidc_session_bindings: [{ columns: ["session_id"], primary: true }, { columns: ["client_id"] }],
    };
    const pool = this.requirePool();
    for (const [table, fields] of Object.entries(columns)) await pool.query(`SELECT ${fields} FROM ${table} LIMIT 0`);
    const tables = Object.keys(columns);
    const [rows] = await pool.query<RowDataPacket[]>(`SELECT TABLE_NAME,INDEX_NAME,NON_UNIQUE,SEQ_IN_INDEX,COLUMN_NAME,SUB_PART,INDEX_TYPE,IS_VISIBLE
      FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN (${tables.map(() => "?").join(",")})
      ORDER BY TABLE_NAME,INDEX_NAME,SEQ_IN_INDEX`, tables);
    for (const [table, required] of Object.entries(indexes)) {
      const actual = new Map<string, RowDataPacket[]>();
      for (const row of rows.filter((row) => row.TABLE_NAME === table)) {
        const parts = actual.get(String(row.INDEX_NAME)) ?? [];
        parts.push(row); actual.set(String(row.INDEX_NAME), parts);
      }
      for (const index of required) {
        // Names may differ in a historical schema. Column order, complete keys and
        // uniqueness must match; a prefix/fulltext/invisible lookup index is insufficient.
        const present = [...actual.entries()].some(([name, parts]) =>
          (!index.primary || name === "PRIMARY") &&
          (!index.primary && !index.unique || parts.every((part) => Number(part.NON_UNIQUE) === 0)) &&
          (index.primary || index.unique || parts.every((part) => part.IS_VISIBLE === "YES")) &&
          parts.length === index.columns.length && parts.every((part, position) =>
            Number(part.SEQ_IN_INDEX) === position + 1 && part.COLUMN_NAME === index.columns[position] &&
            part.SUB_PART == null && part.INDEX_TYPE === "BTREE"));
        if (!present) throw new Error(`IDENTITY_SESSION_SCHEMA_INDEX_REQUIRED:${table}`);
      }
    }
  }

  private async createSchema(): Promise<void> {
    const pool = this.requirePool();

    await pool.query(`
      CREATE TABLE IF NOT EXISTS identity_refresh_sessions (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        refresh_token_hash CHAR(64) NOT NULL,
        session_id VARCHAR(128) NOT NULL,
        legacy_user_id BIGINT NOT NULL,
        username VARCHAR(255) NULL,
        issued_at DATETIME(3) NOT NULL,
        expires_at DATETIME(3) NOT NULL,
        revoked_at DATETIME(3) NULL,
        replaced_by_hash CHAR(64) NULL,
        ip_hash CHAR(64) NULL,
        user_agent_hash CHAR(64) NULL,
        auth_method VARCHAR(32) NULL,
        device_sn_id INT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY idx_identity_refresh_sessions_token_hash (refresh_token_hash),
        KEY idx_identity_refresh_sessions_legacy_user (legacy_user_id, expires_at),
        KEY idx_identity_refresh_sessions_session (session_id)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);
    for (const [name, definition] of [["auth_method", "VARCHAR(32) NULL"], ["device_sn_id", "INT NULL"]]) {
      const [columns] = await pool.query<RowDataPacket[]>(
        "SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'identity_refresh_sessions' AND COLUMN_NAME = ?", [name]);
      if (!columns.length) {
        try { await pool.query(`ALTER TABLE identity_refresh_sessions ADD COLUMN ${name} ${definition}`); }
        catch (error) { if ((error as { code?: string }).code !== "ER_DUP_FIELDNAME") throw error; }
      }
    }
    await pool.query(`CREATE TABLE IF NOT EXISTS identity_refresh_replays (
      predecessor_hash CHAR(64) PRIMARY KEY, successor_hash CHAR(64) NOT NULL,
      request_hash CHAR(64) NULL, encrypted_response TEXT NOT NULL,
      created_at DATETIME(3) NOT NULL, expires_at DATETIME(3) NOT NULL,
      KEY idx_identity_refresh_replay_expiry (expires_at)
    ) ENGINE=InnoDB`);
    await pool.query(`CREATE TABLE IF NOT EXISTS identity_user_revocations (
      user_id BIGINT PRIMARY KEY, revoked_before DATETIME(3) NOT NULL
    ) ENGINE=InnoDB`);
    await pool.query(legacyRefreshCredentialSchema);
    await pool.query(legacyWechatSignupSchema);
    await pool.query(`CREATE TABLE IF NOT EXISTS identity_oauth_session_bindings (
      session_id VARCHAR(128) PRIMARY KEY, client_id VARCHAR(128) NOT NULL, scopes_json JSON NOT NULL,
      legacy_subject VARCHAR(128) NULL, KEY oauth_client (client_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`);
    await pool.query(`CREATE TABLE IF NOT EXISTS identity_oidc_session_bindings (
      session_id VARCHAR(128) PRIMARY KEY, client_id VARCHAR(128) NOT NULL, scopes_json JSON NOT NULL,
      KEY oidc_client (client_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin`);
  }

  private requirePool(): Pool {
    if (!this.pool) {
      throw new Error("identity database is not configured");
    }

    return this.pool;
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
      namedPlaceholders: false,
      timezone: "Z"
    });
  }
}

export function hashRefreshToken(refreshToken: string): string {
  return createHash("sha256").update(refreshToken).digest("hex");
}

function normalizeStoredSession(row: RowDataPacket): StoredIdentitySession {
  const source = deviceSnSource(row.authMethod, row.deviceSnId == null ? null : Number(row.deviceSnId));
  return {
    id: Number(row.id),
    refreshTokenHash: String(row.refreshTokenHash),
    sessionId: String(row.sessionId),
    legacyUserId: Number(row.legacyUserId),
    username: row.username ?? null,
    expiresAt: normalizeDate(row.expiresAt),
    revokedAt: row.revokedAt ? normalizeDate(row.revokedAt) : null,
    ...(source ?? {})
  };
}

function normalizeDate(value: unknown): Date {
  if (value instanceof Date) {
    return value;
  }

  const parsed = new Date(String(value));
  return Number.isNaN(parsed.getTime()) ? new Date(0) : parsed;
}

function hashMaybe(value?: string): string | null { return value ? createHash("sha256").update(value).digest("hex") : null; }
function replayEncryptionKey(): Buffer | null {
  const raw = process.env.IDENTITY_REFRESH_REPLAY_KEY;
  if (!raw) return null;
  const key = Buffer.from(raw, "base64url");
  if (key.length !== 32) throw new Error("IDENTITY_REFRESH_REPLAY_KEY must encode 32 random bytes");
  return key;
}
function encryptReplay(value: IssuedIdentitySession, key: Buffer): string {
  const iv = randomBytes(12); const cipher = createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(JSON.stringify(value), "utf8"), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), encrypted]).toString("base64url");
}
function decryptReplay(value: string, key: Buffer): IssuedIdentitySession {
  const bytes = Buffer.from(value, "base64url");
  const decipher = createDecipheriv("aes-256-gcm", key, bytes.subarray(0, 12));
  decipher.setAuthTag(bytes.subarray(12, 28));
  return JSON.parse(Buffer.concat([decipher.update(bytes.subarray(28)), decipher.final()]).toString("utf8"));
}
