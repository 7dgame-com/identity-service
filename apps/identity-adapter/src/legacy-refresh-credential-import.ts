import { assertAdmissionWriter } from "./identity-admission.js";
import { allocatorMutation } from "./identity-allocator-state.js";
import type { Connection, RowDataPacket } from "mysql2/promise";
import { assertMigrationStaging } from "./migration-state.js";
import { legacyRefreshAccountFingerprint, normalizeLegacyRefreshCredentialManifest } from "./legacy-refresh-credential-manifest.js";

/** Offline import under the same one-way fence as account/session migration. Never performs DDL. */
export async function importLegacyRefreshCredentials(target: Connection, payload: unknown, options: {
  apply?: boolean; environment?: string; now?: Date;
} = {}) {
  assertAdmissionWriter();
  if (options.apply && (options.environment ?? process.env.NODE_ENV) !== "staging") throw new Error("Legacy credentials may only be applied in staging.");
  const manifest = normalizeLegacyRefreshCredentialManifest(payload), now = options.now ?? new Date();
  const capturedAt = new Date(manifest.capturedAt);
  if (!Number.isFinite(now.getTime()) || capturedAt > now) throw new Error("Invalid legacy credential capture time.");
  const report = { total: manifest.credentials.length, imported: 0, wouldImport: 0, existing: 0, expired: 0, sourceRevoked: 0,
    permanent: 0, applied: false, notFinal: true as const };
  await target.beginTransaction();
  try {
    if(options.apply){await assertMigrationStaging(target);}
    const lock = options.apply ? " FOR UPDATE" : "";
    for (const row of [...manifest.credentials].sort((a, b) => a.userId - b.userId || a.recordId - b.recordId)) {
      const [users] = await target.execute<RowDataPacket[]>(`SELECT status,deleted_at,password_hash,auth_key FROM user WHERE id=?${lock}`, [row.userId]);
      if (!users[0]) throw new Error("Legacy credential references a missing private account.");
      const [existing] = await target.execute<RowDataPacket[]>(`SELECT * FROM identity_legacy_refresh_credentials WHERE credential_hash=? OR source_record_id=?${lock}`,
        [row.credentialHash, row.recordId]);
      if (existing.length) {
        const saved = existing[0];
        if (existing.length !== 1 || saved.credential_hash !== row.credentialHash || Number(saved.source_record_id) !== row.recordId ||
            Number(saved.legacy_user_id) !== row.userId || saved.account_fingerprint !== row.accountFingerprint ||
            saved.key_encoding !== row.keyEncoding || saved.source_kind !== row.sourceKind ||
            Boolean(saved.a1_compatible) !== row.a1Compatible ||
            Boolean(saved.server_compatible) !== row.serverCompatible ||
            asTime(saved.expires_at) !== asTime(row.expiresAt) || asTime(saved.source_revoked_at) !== asTime(row.sourceRevokedAt)) {
          throw new Error("Legacy credential evidence conflicts with an existing tombstone.");
        }
        // This row may have been consumed, revoked or password-invalidated. It is immutable on reimport.
        report.existing++;
        continue;
      }
      if (legacyRefreshAccountFingerprint(users[0].password_hash ?? null, users[0].auth_key ?? null) !== row.accountFingerprint) {
        throw new Error("Reviewed source account credentials no longer match the private account.");
      }
      const [signup]=await target.execute<RowDataPacket[]>(`SELECT credential_hash FROM identity_legacy_wechat_signup_credentials WHERE credential_hash=?${lock}`,[row.credentialHash]);
      if(signup.length)throw new Error("Legacy refresh conflicts with a known signup classification.");
      const [native] = await target.execute<RowDataPacket[]>(`SELECT id FROM identity_refresh_sessions WHERE refresh_token_hash=?${lock}`, [row.credentialHash]);
      if (native.length) throw new Error("Legacy credential conflicts with an existing native refresh classification.");
      const [cutoffs] = await target.execute<RowDataPacket[]>(`SELECT revoked_before FROM identity_user_revocations WHERE user_id=?${lock}`, [row.userId]);
      // There is no trustworthy issuance time for A1 AR credentials. Never guess their relation to a cutoff.
      if (cutoffs.length) throw new Error("Legacy credential has no issuance evidence relative to an account revocation; review is required.");
      if (Number(users[0].status) !== 10 || users[0].deleted_at != null) throw new Error("Legacy credential references an inactive private account.");
      if (row.expiresAt === null) report.permanent++; else if (new Date(row.expiresAt) <= now) report.expired++;
      if (row.sourceRevokedAt) report.sourceRevoked++;
      report.wouldImport++;
      if (!options.apply) continue;
      const revision = row.sourceKind === "a1" ? manifest.source.a1Revision : manifest.source.serverRevision!;
      await allocatorMutation(target,()=>target.execute(`INSERT INTO identity_legacy_refresh_credentials
        (credential_hash,source_record_id,legacy_user_id,source_kind,source_revision,source_fields_json,key_encoding,a1_compatible,server_compatible,snapshot_at,
         account_fingerprint,expires_at,source_revoked_at,revoked_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
        [row.credentialHash, row.recordId, row.userId, row.sourceKind, revision, JSON.stringify(row.sourceFields), row.keyEncoding, row.a1Compatible, row.serverCompatible, capturedAt,
          row.accountFingerprint, row.expiresAt ? new Date(row.expiresAt) : null, row.sourceRevokedAt ? new Date(row.sourceRevokedAt) : null,
          row.sourceRevokedAt ? new Date(row.sourceRevokedAt) : null]));
      report.imported++;
    }
    if (options.apply) { await target.commit(); report.applied = true; } else await target.rollback();
    return report;
  } catch (error) { await target.rollback(); throw error; }
}
function asTime(value: unknown): number | null { return value == null ? null : new Date(value as string | Date).getTime(); }
