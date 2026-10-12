import type { PoolConnection } from "mysql2/promise";

/** Caller holds the private user row lock. Includes unredeemed credentials. */
export async function revokeLegacyRefreshCredentialsInTransaction(connection: PoolConnection, userId: number): Promise<void> {
  await connection.execute(`UPDATE identity_legacy_refresh_credentials SET revoked_at=COALESCE(revoked_at,UTC_TIMESTAMP(3)),
    encrypted_response=NULL,replay_expires_at=NULL WHERE legacy_user_id=?`, [userId]);
}
export async function revokeLegacyRefreshFamilyInTransaction(connection: PoolConnection, sessionId: string): Promise<void> {
  await connection.execute(`UPDATE identity_legacy_refresh_credentials SET revoked_at=COALESCE(revoked_at,UTC_TIMESTAMP(3)),
    encrypted_response=NULL,replay_expires_at=NULL WHERE session_id=?`, [sessionId]);
}
