import type { Pool, RowDataPacket } from "mysql2/promise";

export type LegacyChallengeKind = "password_reset" | "email_verification";
export const importedChallengePrefix = "legacy-challenge:";

export async function readLegacyChallengeLimits(
  pool: Pool,
  kind: LegacyChallengeKind,
  email: string,
) {
  const [rows] = await pool.execute<RowDataPacket[]>(
    `SELECT attempts, attempts_expires_at, rate_limit_until FROM identity_legacy_challenge_limits
      WHERE kind=? AND BINARY email=BINARY ?`,
    [kind, email],
  );
  const row = rows[0];
  return {
    attempts: row ? Number(row.attempts) : 0,
    attemptsExpiresAt: row?.attempts_expires_at
      ? new Date(row.attempts_expires_at)
      : null,
    rateLimitUntil: row?.rate_limit_until
      ? new Date(row.rate_limit_until)
      : null,
  };
}

/** Serialize failures in the original independent window without extending it. */
export async function incrementLegacyChallengeAttempts(
  pool: Pool,
  kind: LegacyChallengeKind,
  email: string,
): Promise<boolean> {
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    const [rows] = await connection.execute<RowDataPacket[]>(
      `SELECT attempts FROM identity_legacy_challenge_limits WHERE kind=? AND BINARY email=BINARY ?
        AND attempts_expires_at>UTC_TIMESTAMP(3) FOR UPDATE`,
      [kind, email],
    );
    if (rows.length)
      await connection.execute(
        "UPDATE identity_legacy_challenge_limits SET attempts=attempts+1 WHERE kind=? AND BINARY email=BINARY ?",
        [kind, email],
      );
    await connection.commit();
    return rows.length > 0;
  } catch (error) {
    await connection.rollback();
    throw error;
  } finally {
    connection.release();
  }
}
