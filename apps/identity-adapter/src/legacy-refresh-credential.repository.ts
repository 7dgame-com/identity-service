import { createHash, createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { Injectable, type OnModuleDestroy, ServiceUnavailableException, UnauthorizedException } from "@nestjs/common";
import mysql, { type Pool, type RowDataPacket } from "mysql2/promise";
import { loadConfig } from "./config.js";
import { IdentitySessionRepository, hashRefreshToken } from "./identity-session.repository.js";
import { JwtIssuerService } from "./jwt-issuer.service.js";
import type { LegacyUserReadModel } from "./legacy-identity.reader.js";
import type { AuthTokenResponse, RequestContext } from "./token-issuance.service.js";
import { legacyRefreshAccountFingerprint } from "./legacy-refresh-credential-manifest.js";

/** Known credentials retain their type after expiry, exchange or revocation. */
@Injectable()
export class LegacyRefreshCredentialRepository implements OnModuleDestroy {
  private readonly config = loadConfig();
  private readonly pool: Pool | null;
  constructor(private readonly sessions: IdentitySessionRepository, private readonly jwt: JwtIssuerService) {
    const db = this.config.identityDb;
    this.pool = this.config.dataSource === "identity" && db.host && db.user ? mysql.createPool({ host: db.host, port: db.port,
      database: db.name, user: db.user, password: db.password, connectionLimit: 5, timezone: "Z" }) : null;
  }
  async onModuleDestroy(): Promise<void> { await this.pool?.end(); }
  async hasCredential(raw: string): Promise<boolean> {
    if (this.config.dataSource !== "identity") return false;
    await this.sessions.ensureSchema();
    const [rows] = await this.db().execute<RowDataPacket[]>("SELECT credential_hash FROM identity_legacy_refresh_credentials WHERE credential_hash=? LIMIT 1", [credentialHash(raw)]);
    return rows.length > 0;
  }

  async redeem(raw: string, context: RequestContext = {}, consumer: "server" | "a1" = "server"): Promise<AuthTokenResponse> {
    const hash = credentialHash(raw), key = replayKey();
    this.jwt.assertSigningReady();
    await this.sessions.ensureSchema();
    const [owners] = await this.db().execute<RowDataPacket[]>("SELECT legacy_user_id FROM identity_legacy_refresh_credentials WHERE credential_hash=?", [hash]);
    if (!owners[0]) throw invalid();
    const userId = Number(owners[0].legacy_user_id), connection = await this.db().getConnection();
    try {
      await connection.beginTransaction();
      const [users] = await connection.execute<RowDataPacket[]>("SELECT * FROM user WHERE id=? FOR UPDATE", [userId]);
      const [rows] = await connection.execute<RowDataPacket[]>("SELECT * FROM identity_legacy_refresh_credentials WHERE credential_hash=? FOR UPDATE", [hash]);
      const user = users[0], row = rows[0];
      const [native] = await connection.execute<RowDataPacket[]>("SELECT id FROM identity_refresh_sessions WHERE refresh_token_hash=? FOR SHARE", [hash]);
      if (native.length) throw invalid();
      if (!row || !user || Number(row.legacy_user_id) !== userId || Number(user.status) !== 10 || user.deleted_at != null ||
          row.revoked_at || row.source_revoked_at || (consumer === "a1" ? Number(row.a1_compatible) !== 1 :
            (Number(row.server_compatible) !== 1 || (row.expires_at && new Date(row.expires_at).getTime() <= Date.now()))) ||
          row.account_fingerprint !== legacyRefreshAccountFingerprint(user.password_hash ?? null, user.auth_key ?? null)) throw invalid();
      const [cutoffs] = await connection.execute<RowDataPacket[]>("SELECT revoked_before FROM identity_user_revocations WHERE user_id=? FOR SHARE", [userId]);
      if (cutoffs.length) throw invalid();
      if (!row.redeemed_at && (row.session_id || row.successor_hash || row.encrypted_response || row.replay_expires_at || row.redeemed_consumer)) throw invalid();
      if (row.redeemed_at) {
        const sameRequest = !!context.idempotencyKey && row.request_hash === hashMaybe(context.idempotencyKey);
        if (row.redeemed_consumer !== consumer || !key || !row.encrypted_response || !row.replay_expires_at || new Date(row.replay_expires_at).getTime() <= Date.now() ||
            (!sameRequest && Date.now() - new Date(row.redeemed_at).getTime() > 5000) ||
            !row.session_id || !row.successor_hash || !await this.sessions.canReplayInTransaction(connection, userId, row.session_id, row.successor_hash)) throw invalid();
        const response = decrypt(row.encrypted_response, key, associatedData(hash, userId, consumer, row.session_id, row.successor_hash));
        if (hashRefreshToken(response.token.refreshToken) !== row.successor_hash) throw invalid();
        await connection.commit();
        return response;
      }
      // Roles and account state come from the private database while the account row is locked.
      const [roles] = await connection.execute<RowDataPacket[]>(`SELECT aa.item_name AS name FROM auth_assignment aa
        JOIN auth_item ai ON ai.name=aa.item_name WHERE aa.user_id=? AND ai.type=1 ORDER BY aa.item_name`, [String(userId)]);
      const model: LegacyUserReadModel = { id: userId, username: user.username ?? null, email: user.email ?? null, status: 10,
        nickname: user.nickname ?? null, emailVerifiedAt: user.email_verified_at == null ? null : Number(user.email_verified_at),
        createdAt: user.created_at == null ? null : Number(user.created_at), updatedAt: user.updated_at == null ? null : Number(user.updated_at),
        roles: roles.map(role => String(role.name)), organizations: [], userInfo: null, source: "identity-db" };
      const sessionId = randomBytes(24).toString("base64url"), access = this.jwt.issue(model, sessionId);
      const session = await this.sessions.issueInTransaction(connection, { legacyUserId: userId, username: model.username, sessionId,
        expiresAt: new Date(Date.now() + this.config.tokenIssuance.refreshTokenTtlSeconds * 1000),
        expectedPasswordHash: user.password_hash ?? undefined, ipAddressHash: hashMaybe(context.ip), userAgentHash: hashMaybe(context.userAgent) });
      const response: AuthTokenResponse = { success: true, message: "refresh", token: { token: access.accessToken, accessToken: access.accessToken,
        refreshToken: session.refreshToken, expires: access.expiresAt.toISOString(), tokenType: "Bearer" } };
      await connection.execute(`UPDATE identity_legacy_refresh_credentials SET redeemed_at=UTC_TIMESTAMP(3),redeemed_consumer=?,session_id=?,successor_hash=?,request_hash=?,
        encrypted_response=?,replay_expires_at=${key ? "DATE_ADD(UTC_TIMESTAMP(3),INTERVAL 30 SECOND)" : "NULL"} WHERE credential_hash=? AND redeemed_at IS NULL`,
        [consumer, sessionId, session.refreshTokenHash, hashMaybe(context.idempotencyKey), key ? encrypt(response, key, associatedData(hash, userId, consumer, sessionId, session.refreshTokenHash)) : null, hash]);
      await connection.commit();
      return response;
    } catch (error) { await connection.rollback(); throw error; } finally { connection.release(); }
  }

  async revoke(raw: string): Promise<boolean> {
    const hash = credentialHash(raw);
    const [owners] = await this.db().execute<RowDataPacket[]>("SELECT legacy_user_id FROM identity_legacy_refresh_credentials WHERE credential_hash=?", [hash]);
    if (!owners[0]) return false;
    const connection = await this.db().getConnection();
    try {
      await connection.beginTransaction();
      await connection.execute("SELECT id FROM user WHERE id=? FOR UPDATE", [owners[0].legacy_user_id]);
      const [rows] = await connection.execute<RowDataPacket[]>("SELECT session_id FROM identity_legacy_refresh_credentials WHERE credential_hash=? FOR UPDATE", [hash]);
      await connection.execute("UPDATE identity_legacy_refresh_credentials SET revoked_at=COALESCE(revoked_at,UTC_TIMESTAMP(3)),encrypted_response=NULL,replay_expires_at=NULL WHERE credential_hash=?", [hash]);
      if (rows[0]?.session_id) await connection.execute("UPDATE identity_refresh_sessions SET revoked_at=COALESCE(revoked_at,UTC_TIMESTAMP(3)),replaced_by_hash=NULL WHERE session_id=?", [rows[0].session_id]);
      await connection.commit(); return true;
    } catch (error) { await connection.rollback(); throw error; } finally { connection.release(); }
  }
  private db(): Pool {
    if (!this.pool) throw new ServiceUnavailableException("Private legacy credential storage is unavailable.");
    return this.pool;
  }
}

function credentialHash(raw: string): string {
  if (typeof raw !== "string" || raw.length < 1 || raw.length > 4096) throw invalid();
  return hashRefreshToken(raw);
}
function invalid(): UnauthorizedException { return new UnauthorizedException("Refresh token is invalid."); }
function hashMaybe(value?: string | null): string | null { return value ? createHash("sha256").update(value).digest("hex") : null; }
function replayKey(): Buffer | null {
  const raw = process.env.IDENTITY_REFRESH_REPLAY_KEY;
  if (!raw) return null;
  const key = Buffer.from(raw, "base64url");
  if (key.length !== 32 || (key.toString("base64url") !== raw && key.toString("base64") !== raw)) throw new Error("IDENTITY_REFRESH_REPLAY_KEY must canonically encode 32 random bytes.");
  return key;
}
function associatedData(hash: string, userId: number, consumer: string, session: string, successor: string): Buffer {
  return Buffer.from(JSON.stringify(["legacy-ar-refresh-v1", hash, userId, consumer, session, successor]));
}
function encrypt(response: AuthTokenResponse, key: Buffer, aad: Buffer): string {
  const iv = randomBytes(12), cipher = createCipheriv("aes-256-gcm", key, iv); cipher.setAAD(aad);
  const encrypted = Buffer.concat([cipher.update(JSON.stringify(response), "utf8"), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), encrypted]).toString("base64url");
}
function decrypt(value: string, key: Buffer, aad: Buffer): AuthTokenResponse {
  try {
    const raw = Buffer.from(value, "base64url");
    if (raw.length < 29 || raw.toString("base64url") !== value) throw invalid();
    const decipher = createDecipheriv("aes-256-gcm", key, raw.subarray(0, 12)); decipher.setAAD(aad); decipher.setAuthTag(raw.subarray(12, 28));
    const response = JSON.parse(Buffer.concat([decipher.update(raw.subarray(28)), decipher.final()]).toString("utf8")) as AuthTokenResponse;
    if (response?.success !== true || response.message !== "refresh" || typeof response.token?.refreshToken !== "string") throw invalid();
    return response;
  } catch { throw invalid(); }
}
