import { createHash } from "node:crypto";
import mysql, { type Connection, type RowDataPacket } from "mysql2/promise";
import { assertMigrationStaging } from "./migration-state.js";
import { z } from "zod";
import { loadConfig } from "./config.js";

const hash = (value: string) =>
  createHash("sha256").update(value).digest("hex");
const digest = z.string().regex(/^[a-fA-F0-9]{64}$/);
const timestamp = z.union([
  z.number().finite().nonnegative(),
  z.string().regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/),
]);
const clientSchema = z
  .object({
    client_id: z.string().min(1).max(128),
    scopes: z.array(z.string().min(1).max(128).regex(/^\S+$/)).max(100),
    legacy_subject: z.string().min(1).max(128).nullable().optional(),
  })
  .strict();
const entrySchema = z
  .object({
    keyEncoding: z.enum(["plain", "sha256-hex"]),
    key: z.string().min(1).max(4096),
    user_id: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
    session_id: z.string().regex(/^[A-Za-z0-9_.:-]{1,128}$/),
    username: z.string().max(255).nullable().optional(),
    created_at: timestamp,
    expires_at: timestamp,
    revoked_at: timestamp.nullable(),
    replaced_by_hash: digest.nullable().optional(),
    ip_hash: digest.nullable().optional(),
    user_agent_hash: digest.nullable().optional(),
    ip: z.string().max(128).nullable().optional(),
    user_agent: z.string().max(4096).nullable().optional(),
    client: clientSchema.nullable(),
  })
  .strict();

export interface ImportedLegacySession {
  refreshHash: string;
  userId: number;
  sessionId: string;
  username: string | null;
  issuedAt: Date;
  expiresAt: Date;
  revokedAt: Date | null;
  replacedByHash: string | null;
  ipHash: string | null;
  userAgentHash: string | null;
  client: z.infer<typeof clientSchema> | null;
}
export interface LegacySessionImportReport {
  applied: boolean;
  total: number;
  unique: number;
  duplicates: number;
  imported: number;
  wouldImport: number;
  existing: number;
  protected: number;
  expired: number;
  revoked: number;
  clientBindings: number;
}

/** No heuristic key detection: a 64-character hex plaintext token is still plaintext. */
export function normalizeLegacySessionManifest(
  payload: unknown,
  maxRows = 100_000,
): ImportedLegacySession[] {
  if (!Number.isSafeInteger(maxRows) || maxRows < 1 || maxRows > 100_000)
    throw new Error("Invalid legacy session import limit.");
  const manifest = z
    .object({
      version: z.literal(1),
      sessions: z.array(z.unknown()).max(maxRows),
    })
    .strict()
    .safeParse(payload);
  if (!manifest.success)
    throw new Error("Invalid legacy session manifest envelope.");
  return manifest.data.sessions.map((value, index) => {
    const parsed = entrySchema.safeParse(value);
    const invalid = () =>
      new Error(`Invalid legacy session manifest entry ${index + 1}.`);
    if (!parsed.success) throw invalid();
    const row = parsed.data;
    if (row.keyEncoding === "sha256-hex" && !digest.safeParse(row.key).success)
      throw invalid();
    if (
      (row.ip != null && row.ip_hash != null) ||
      (row.user_agent != null && row.user_agent_hash != null)
    )
      throw invalid();
    if (
      row.client &&
      new Set(row.client.scopes).size !== row.client.scopes.length
    )
      throw invalid();
    const date = (value: z.infer<typeof timestamp>): Date => {
      const result = new Date(typeof value === "number" ? value * 1000 : value);
      if (
        !Number.isFinite(result.getTime()) ||
        result.getUTCFullYear() < 1970 ||
        result.getUTCFullYear() > 9999
      )
        throw invalid();
      return result;
    };
    const issuedAt = date(row.created_at),
      expiresAt = date(row.expires_at);
    const revokedAt = row.revoked_at === null ? null : date(row.revoked_at);
    if (expiresAt <= issuedAt || (revokedAt && revokedAt < issuedAt))
      throw invalid();
    return {
      refreshHash:
        row.keyEncoding === "plain" ? hash(row.key) : row.key.toLowerCase(),
      userId: row.user_id,
      sessionId: row.session_id,
      username: row.username ?? null,
      issuedAt,
      expiresAt,
      revokedAt,
      replacedByHash: row.replaced_by_hash?.toLowerCase() ?? null,
      ipHash: row.ip_hash?.toLowerCase() ?? (row.ip ? hash(row.ip) : null),
      userAgentHash:
        row.user_agent_hash?.toLowerCase() ??
        (row.user_agent ? hash(row.user_agent) : null),
      client: row.client,
    };
  });
}

/** Apply only the final drained snapshot, before Identity accepts session writes. */
export async function importLegacySessions(
  target: Connection,
  payload: unknown,
  options: {
    apply?: boolean;
    environment?: string;
    maxRows?: number;
    now?: Date;
  } = {},
): Promise<LegacySessionImportReport> {
  if (
    options.apply &&
    (options.environment ?? process.env.NODE_ENV) !== "staging"
  ) {
    throw new Error("Legacy sessions may only be applied in staging.");
  }
  const sessions = normalizeLegacySessionManifest(payload, options.maxRows);
  const unique = new Map<string, ImportedLegacySession>();
  for (const session of sessions) {
    const existing = unique.get(session.refreshHash);
    if (existing && JSON.stringify(existing) !== JSON.stringify(session))
      throw new Error("Conflicting duplicate legacy sessions.");
    unique.set(session.refreshHash, session);
  }
  const now = options.now ?? new Date();
  const report: LegacySessionImportReport = {
    applied: false,
    total: sessions.length,
    unique: unique.size,
    duplicates: sessions.length - unique.size,
    imported: 0,
    wouldImport: 0,
    existing: 0,
    protected: 0,
    expired: sessions.filter((s) => s.expiresAt <= now).length,
    revoked: sessions.filter((s) => s.revokedAt !== null).length,
    clientBindings: 0,
  };
  await target.beginTransaction();
  try {
    if (options.apply) await assertMigrationStaging(target);
    // Use the same account-first lock order as rotation, password changes and logout.
    const rows = [...unique.values()].sort(
      (a, b) =>
        a.userId - b.userId || a.refreshHash.localeCompare(b.refreshHash),
    );
    const lock = options.apply ? " FOR UPDATE" : "";
    for (const row of rows) {
      const [users] = await target.execute<RowDataPacket[]>(
        `SELECT id FROM user WHERE id = ?${lock}`,
        [row.userId],
      );
      if (!users[0])
        throw new Error(
          "Legacy session import references a missing identity account.",
        );
      const [existing] = await target.execute<RowDataPacket[]>(
        `SELECT legacy_user_id, session_id FROM identity_refresh_sessions WHERE refresh_token_hash = ?${lock}`,
        [row.refreshHash],
      );
      if (existing[0]) {
        if (
          Number(existing[0].legacy_user_id) !== row.userId ||
          existing[0].session_id !== row.sessionId
        )
          throw new Error("Legacy session identity conflict.");
        // Never replace any stored lifetime, revocation, successor or binding.
        report.existing++;
        continue;
      }
      const [family] = await target.execute<RowDataPacket[]>(
        `SELECT id FROM identity_refresh_sessions WHERE session_id = ? AND (revoked_at IS NOT NULL OR replaced_by_hash IS NOT NULL) LIMIT 1${lock}`,
        [row.sessionId],
      );
      const [revocations] = await target.execute<RowDataPacket[]>(
        `SELECT revoked_before FROM identity_user_revocations WHERE user_id = ?${lock}`,
        [row.userId],
      );
      if (
        family.length ||
        (revocations[0] &&
          new Date(revocations[0].revoked_before) >= row.issuedAt)
      ) {
        report.protected++;
        continue;
      }
      const [bindings] = await target.execute<RowDataPacket[]>(
        `SELECT client_id, scopes_json, legacy_subject FROM identity_oauth_session_bindings WHERE session_id = ?${lock}`,
        [row.sessionId],
      );
      const binding = bindings[0];
      if (binding && !row.client)
        throw new Error("Legacy session client scope conflict.");
      if (row.client) {
        const scopes = binding
          ? typeof binding.scopes_json === "string"
            ? JSON.parse(binding.scopes_json)
            : binding.scopes_json
          : null;
        if (
          binding &&
          (binding.client_id !== row.client.client_id ||
            !sameScopes(scopes, row.client.scopes) ||
            (binding.legacy_subject ?? null) !==
              (row.client.legacy_subject ?? null))
        )
          throw new Error("Legacy session client scope conflict.");
        if (!binding && options.apply)
          await target.execute(
            "INSERT INTO identity_oauth_session_bindings (session_id,client_id,scopes_json,legacy_subject) VALUES (?,?,?,?)",
            [
              row.sessionId,
              row.client.client_id,
              JSON.stringify(row.client.scopes),
              row.client.legacy_subject ?? null,
            ],
          );
        if (!binding) report.clientBindings++;
      }
      report.wouldImport++;
      if (options.apply) {
        await target.execute(
          `INSERT INTO identity_refresh_sessions
          (refresh_token_hash,session_id,legacy_user_id,username,issued_at,expires_at,revoked_at,replaced_by_hash,ip_hash,user_agent_hash)
          VALUES (?,?,?,?,?,?,?,?,?,?)`,
          [
            row.refreshHash,
            row.sessionId,
            row.userId,
            row.username,
            row.issuedAt,
            row.expiresAt,
            row.revokedAt,
            row.replacedByHash,
            row.ipHash,
            row.userAgentHash,
          ],
        );
        report.imported++;
      }
    }
    if (options.apply) {
      await target.commit();
      report.applied = true;
    } else await target.rollback();
    return report;
  } catch (error) {
    await target.rollback();
    throw error;
  }
}

function sameScopes(actual: unknown, expected: string[]): boolean {
  return (
    Array.isArray(actual) &&
    actual.length === expected.length &&
    [...actual]
      .sort()
      .every((scope, index) => scope === [...expected].sort()[index])
  );
}

export async function connectLegacySessionImportTarget(): Promise<Connection> {
  const config = loadConfig();
  if (
    config.dataSource !== "identity" ||
    !config.identityDb.host ||
    !config.identityDb.user
  ) {
    throw new Error(
      "An explicit independent identity database target is required.",
    );
  }
  const db = config.identityDb;
  return mysql.createConnection({
    host: db.host,
    port: db.port,
    database: db.name,
    user: db.user,
    password: db.password,
    timezone: "Z",
  });
}
