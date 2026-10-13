import { revokeRefreshGraphUser,revokeRefreshGraphSession } from "./legacy-refresh-graph-revocation.js";
import type { PoolConnection } from "mysql2/promise";

/** Caller holds the private user row lock. Includes unredeemed credentials. */
export async function revokeLegacyRefreshCredentialsInTransaction(connection: PoolConnection, userId: number): Promise<void> {
  await revokeRefreshGraphUser(connection,userId);
  await connection.execute(`UPDATE identity_legacy_refresh_credentials SET revoked_at=COALESCE(revoked_at,UTC_TIMESTAMP(3)),
    encrypted_response=NULL,replay_expires_at=NULL WHERE legacy_user_id=?`, [userId]);
  await connection.execute(`UPDATE identity_legacy_wechat_signup_credentials SET revoked_at=COALESCE(revoked_at,UTC_TIMESTAMP(3)),
    encrypted_response=NULL,replay_expires_at=NULL WHERE consumed_user_id=?`,[userId]);
}
export async function revokeLegacyRefreshFamilyInTransaction(connection: PoolConnection, sessionId: string): Promise<void> {
  await revokeRefreshGraphSession(connection,sessionId);
  await connection.execute(`UPDATE identity_legacy_refresh_credentials SET revoked_at=COALESCE(revoked_at,UTC_TIMESTAMP(3)),
    encrypted_response=NULL,replay_expires_at=NULL WHERE session_id=?`, [sessionId]);
  await connection.execute(`UPDATE identity_legacy_wechat_signup_credentials SET revoked_at=COALESCE(revoked_at,UTC_TIMESTAMP(3)),
    encrypted_response=NULL,replay_expires_at=NULL WHERE session_id=?`,[sessionId]);
}
