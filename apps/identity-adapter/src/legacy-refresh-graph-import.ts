import type { Connection, PoolConnection, RowDataPacket } from "mysql2/promise";
import { allocatorMutation } from "./identity-allocator-state.js";
import { assertMigrationStaging } from "./migration-state.js";
import { legacyRefreshAccountFingerprint } from "./legacy-refresh-credential-manifest.js";
import { decryptSourceGraphResponse, encryptGraphBody, graphBodyAad, graphEncryptionKey, verifyGraphResponse } from "./legacy-refresh-graph-crypto.js";
import { graphAccountsSchema, graphCanonical, graphFamilyKey, graphHash, graphReplayKey, graphTokens, normalizeRefreshGraph } from "./legacy-refresh-graph-manifest.js";

export const graphTables = ["identity_legacy_refresh_graph_families", "identity_legacy_refresh_graph_credentials", "identity_legacy_refresh_graph_replays"] as const;
export async function assertGraphSchema(connection: Connection | PoolConnection): Promise<void> {
  const columns:Record<string,string>={
    identity_legacy_refresh_graph_families:"family_key,protocol,source_family_id,legacy_user_id,native_session_id,source_json,source_sha256,account_snapshot_json,account_snapshot_sha256,target_cutoff_ms,current_hash,revoked_at",
    identity_legacy_refresh_graph_credentials:"credential_hash,family_key,legacy_user_id,origin,source_json,source_sha256,state,successor_hash,consumed_consumer,revoked_at",
    identity_legacy_refresh_graph_replays:"replay_key,predecessor_hash,successor_hash,family_key,legacy_user_id,source_json,origin,response_sha256,access_token_hash,encrypted_response"
  };
  for (const table of graphTables) await connection.query(`SELECT ${columns[table]} FROM ${table} LIMIT 0`);
  const [indexes]=await connection.query<RowDataPacket[]>("SELECT TABLE_NAME,INDEX_NAME,NON_UNIQUE,GROUP_CONCAT(COLUMN_NAME ORDER BY SEQ_IN_INDEX) AS cols FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN (?,?,?) GROUP BY TABLE_NAME,INDEX_NAME,NON_UNIQUE",[...graphTables]);
  for(const [table,cols] of [[graphTables[0],"family_key"],[graphTables[0],"native_session_id"],[graphTables[1],"credential_hash"],[graphTables[2],"replay_key"]])
    if(!indexes.some(i=>i.TABLE_NAME===table&&Number(i.NON_UNIQUE)===0&&i.cols===cols))throw new Error("Legacy graph schema requires its unique identity indexes.");
}
const json = (value: unknown) => JSON.stringify(value);
const object = (value: unknown): unknown => typeof value === "string" ? JSON.parse(value) : value;
const timeMs = (value: unknown): number | null => value == null ? null : new Date(value as Date | string).getTime();

/** Offline-only. Never creates schema, signs access, connects to Redis or changes authority. */
export async function importRefreshGraph(target: Connection, manifestBytes: Buffer, accountsBytes: Buffer, options: {
  apply?: boolean; environment?: string; reviewedSha256?: string; now?: number;
  assertDeviceSnAuthorized?: (deviceSnId: number, userId: number) => Promise<void>;
  sourceResponseKeys?: Partial<Record<"a1" | "server", Buffer>>;
  /** Explicit library-only common-key compatibility; the CLI never infers it. */
  sourceResponseKey?:Buffer;
} = {}) {
  if (manifestBytes.length > 64 * 1024 * 1024 || accountsBytes.length > 32 * 1024 * 1024) throw new Error("Legacy graph input exceeds its bound.");
  const manifestSha256 = graphHash(manifestBytes), accountsSha256 = graphHash(accountsBytes), now = options.now ?? Date.now();
  if (options.apply && ((options.environment ?? process.env.NODE_ENV) !== "staging" || options.reviewedSha256 !== manifestSha256)) {
    throw new Error("Applying a legacy graph requires staging and its exact reviewed file SHA256.");
  }
  const accounts = graphAccountsSchema.parse(JSON.parse(accountsBytes.toString("utf8")));
  const graph = normalizeRefreshGraph(JSON.parse(manifestBytes.toString("utf8")), accounts, accountsSha256);
  if (graph.capturedAtMs > now || now - graph.capturedAtMs > 24 * 3600 * 1000) throw new Error("Legacy graph capture time requires review.");
  const accountMap = new Map(accounts.accounts.map(a => [a.userId, a])), credentialMap = new Map(graph.credentials.map(c => [c.credentialHash, c]));
  const key = graphEncryptionKey();
  const report = { applied: false, manifestSha256, protocol: graph.protocol, families: graph.families.length,
    credentials: graph.credentials.length, replays: graph.replays.length, imported: 0, existing: 0, expiredReplays: 0,
    nativeSessionsIssued: 0, sourceWrites: 0, notFinal: true as const };
  await assertGraphSchema(target);
  // Without SESSION this must fail inside an existing caller transaction;
  // unlike SET autocommit it cannot silently commit outstanding caller writes.
  await target.query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED");
  const [tx]=await target.query<RowDataPacket[]>("SELECT @@autocommit AS enabled");if(Number(tx[0]?.enabled)!==1)throw new Error("An idle autocommit connection is required.");
  await target.beginTransaction();
  try {
    if (options.apply) await assertMigrationStaging(target);
    const lock = options.apply ? " FOR UPDATE" : " FOR SHARE";
    // All owners first, in numeric order, matching every live refresh/revoke path.
    const cutoffs = new Map<number, number | null>();
    for (const id of [...new Set(graph.credentials.map(c => c.userId))].sort((a, b) => a - b)) {
      const [users] = await target.execute<RowDataPacket[]>(`SELECT id,status,deleted_at,password_hash,auth_key FROM user WHERE id=?${lock}`, [id]);
      if (!users[0]) throw new Error("Legacy graph references a missing private account.");
      const a = accountMap.get(id)!;
      if (a.status === 10 && (Number(users[0].status) !== 10 || users[0].deleted_at != null
        || legacyRefreshAccountFingerprint(users[0].password_hash ?? null, users[0].auth_key ?? null) !== a.accountFingerprint)) {
        throw new Error("Current source security snapshot does not match the private account.");
      }
      const [savedCutoffs] = await target.execute<RowDataPacket[]>(`SELECT revoked_before FROM identity_user_revocations WHERE user_id=?${lock}`, [id]);
      let cutoff = timeMs(savedCutoffs[0]?.revoked_before);
      const sourceTimes = [graph.revocations.find(r => r.userId === id)?.revokedAtMs ?? null, a.securityChangedAtMs]
        .filter((value): value is number => value !== null);
      const sourceRevocation = sourceTimes.length ? Math.max(...sourceTimes) : null;
      if (sourceRevocation !== null && (cutoff === null || sourceRevocation > cutoff)) {
        if (options.apply) await allocatorMutation(target, () => target.execute(`INSERT INTO identity_user_revocations(user_id,revoked_before) VALUES (?,?)
          ON DUPLICATE KEY UPDATE revoked_before=GREATEST(revoked_before,VALUES(revoked_before))`, [id, new Date(sourceRevocation)]));
        cutoff = sourceRevocation;
      }
      cutoffs.set(id, cutoff);
    }
    for (const c of graph.credentials) {
      if (c.state === "active" && c.sourceRecordPresent && (c.expiresAtMs === null || c.expiresAtMs > now) && "auth_method" in c.authContext) {
        if (!options.assertDeviceSnAuthorized) throw new Error("Active graph device credentials require current independent authorization.");
        await options.assertDeviceSnAuthorized(c.authContext.device_sn_id, c.userId);
      }
      const [signup] = await target.execute<RowDataPacket[]>(`SELECT credential_hash FROM identity_legacy_wechat_signup_credentials WHERE credential_hash=?${lock}`, [c.credentialHash]);
      if (signup.length) throw new Error("Legacy graph conflicts with a signup credential classification.");
      const [native] = await target.execute<RowDataPacket[]>(`SELECT legacy_user_id,auth_method,device_sn_id,expires_at,revoked_at,replaced_by_hash FROM identity_refresh_sessions WHERE refresh_token_hash=?${lock}`, [c.credentialHash]);
      if (native.length && (native[0].revoked_at || native[0].replaced_by_hash || Number(native[0].legacy_user_id) !== c.userId || (native[0].auth_method ?? null) !== ("auth_method" in c.authContext ? c.authContext.auth_method : null)
        || (native[0].device_sn_id == null ? null : Number(native[0].device_sn_id)) !== ("device_sn_id" in c.authContext ? c.authContext.device_sn_id : null)
        || c.expiresAtMs !== timeMs(native[0].expires_at))) throw new Error("Legacy graph conflicts with a native session classification.");
      const [old]=await target.execute<RowDataPacket[]>(`SELECT legacy_user_id,account_fingerprint,revoked_at,source_revoked_at,redeemed_at FROM identity_legacy_refresh_credentials WHERE credential_hash=?${lock}`,[c.credentialHash]);
      if(old[0]&&(Number(old[0].legacy_user_id)!==c.userId||old[0].account_fingerprint!==c.accountFingerprint||old[0].revoked_at||old[0].source_revoked_at||old[0].redeemed_at))throw new Error("Legacy graph conflicts with a retained ordinary credential.");
    }
    for (const family of graph.families) {
      const familyKey = graphFamilyKey(graph.protocol, family.familyId), sourceSha256 = graphHash(json(family)), a = accountMap.get(family.userId)!;
      const [existing] = await target.execute<RowDataPacket[]>(`SELECT source_sha256,account_snapshot_sha256 FROM identity_legacy_refresh_graph_families WHERE family_key=?${lock}`, [familyKey]);
      if (existing.length) {
        if (existing[0].source_sha256 !== sourceSha256 || existing[0].account_snapshot_sha256 !== accountsSha256) throw new Error("Legacy graph family evidence conflicts with its immutable import.");
        report.existing++; continue;
      }
      const current = graph.revocations.find(r => r.userId === family.userId)!;
      const cutoff = cutoffs.get(family.userId) ?? null;
      const revoked = !family.available || family.revokedAtMs !== null || a.status !== 10 || a.accountEpoch !== family.accountEpoch
        || a.accountFingerprint !== family.accountFingerprint || current.userEpoch !== family.userEpoch
        // A private revocation after the source security observation cannot
        // become a newly imported family's permissive baseline.
        || (cutoff !== null && cutoff >= accounts.capturedAtMs);
      report.imported++;
      if (options.apply) await allocatorMutation(target, () => target.execute(`INSERT INTO identity_legacy_refresh_graph_families
        (family_key,protocol,source_family_id,legacy_user_id,native_session_id,source_json,source_sha256,account_snapshot_json,account_snapshot_sha256,target_cutoff_ms,current_hash,revoked_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`, [familyKey, graph.protocol, family.familyId, family.userId, `legacy-graph:${graph.protocol}:${family.familyId}`,
          json(family), sourceSha256, json(a), accountsSha256, cutoffs.get(family.userId) ?? null, family.currentHash, revoked ? new Date(now) : null]));
    }
    for (const c of graph.credentials) {
      const sourceSha256 = graphHash(json(c)), familyKey = graphFamilyKey(graph.protocol, c.familyId);
      const [existing] = await target.execute<RowDataPacket[]>(`SELECT origin,source_sha256 FROM identity_legacy_refresh_graph_credentials WHERE credential_hash=?${lock}`, [c.credentialHash]);
      if (existing.length) {
        if (existing[0].origin !== "source" || existing[0].source_sha256 !== sourceSha256) throw new Error("Legacy graph credential evidence conflicts with a retained tombstone.");
        report.existing++; continue;
      }
      report.imported++;
      if (options.apply) await allocatorMutation(target, () => target.execute(`INSERT INTO identity_legacy_refresh_graph_credentials
        (credential_hash,family_key,legacy_user_id,origin,source_json,source_sha256,state,successor_hash,consumed_consumer,revoked_at)
        VALUES (?,?,?,'source',?,?,?,?,?,?)`, [c.credentialHash, familyKey, c.userId, json(c), sourceSha256, c.state, c.successorHash,
          c.state === "consumed" ? "server" : c.state === "rotated" ? "yii3" : null, c.revokedAtMs ? new Date(c.revokedAtMs) : null]));
    }
    for (const replay of graph.replays) {
      const predecessor = credentialMap.get(replay.predecessorHash)!, successor = credentialMap.get(replay.successorHash)!;
      // Verification at the captured Redis instant also covers a response that
      // expires while the operator reviews/imports. Its cutoff is never renewed.
      const sourceKey=graph.protocol==="ar"&&options.sourceResponseKeys!==undefined
        ? options.sourceResponseKeys[replay.consumer as "a1" | "server"] : options.sourceResponseKey;
      if(!sourceKey||!replay.sourceEncryptedResponse)throw new Error("Source full-response authentication key is required.");
      const authenticated=decryptSourceGraphResponse(graph.protocol,replay,replay.sourceEncryptedResponse,sourceKey);
      if(graphCanonical(authenticated)!==graphCanonical(replay.response))throw new Error("Source full response does not match its authenticated body.");
      const claims = verifyGraphResponse(replay, undefined, graph.capturedAtMs);
      // Reviewed signer trust must cover the complete original retry window.
      // The imported deadline itself is still never extended.
      verifyGraphResponse(replay, undefined, replay.expiresAtMs - 1);
      const auth = successor.authContext;
      if ((claims.auth_method ?? null) !== ("auth_method" in auth ? auth.auth_method : null)
        || (claims.device_sn_id ?? null) !== ("device_sn_id" in auth ? auth.device_sn_id : null)) throw new Error("Legacy graph response lost its device provenance.");
      if (replay.createdAtMs > graph.capturedAtMs || replay.createdAtMs < (predecessor.issuedAtMs ?? 0)) throw new Error("Legacy replay timing is inconsistent.");
      if (replay.expiresAtMs <= now) report.expiredReplays++;
      const replayKey = graphReplayKey(graph.protocol, replay), bodySha256 = graphHash(json(replay.response)), { response, ...metadata } = replay;
      const [existing] = await target.execute<RowDataPacket[]>(`SELECT source_json,response_sha256 FROM identity_legacy_refresh_graph_replays WHERE replay_key=?${lock}`, [replayKey]);
      if (existing.length) {
        if (graphCanonical(object(existing[0].source_json)) !== graphCanonical(metadata) || existing[0].response_sha256 !== bodySha256) throw new Error("Legacy graph original response conflicts with immutable replay evidence.");
        report.existing++; continue;
      }
      report.imported++;
      if (options.apply) await allocatorMutation(target, () => target.execute(`INSERT INTO identity_legacy_refresh_graph_replays
        (replay_key,predecessor_hash,successor_hash,family_key,legacy_user_id,source_json,origin,response_sha256,access_token_hash,encrypted_response)
        VALUES (?,?,?,?,?,? ,'source',?,?,?)`, [replayKey, replay.predecessorHash, replay.successorHash, graphFamilyKey(graph.protocol, replay.familyId), replay.userId,
          json(metadata), bodySha256, graphHash(graphTokens(response).accessToken), encryptGraphBody(response, key, graphBodyAad(graph.protocol, metadata))]));
    }
    if (options.apply) { await target.commit(); report.applied = true; } else await target.rollback();
    return report;
  } catch (error) { await target.rollback(); throw error; }
}
