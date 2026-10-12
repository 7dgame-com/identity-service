import { createHash } from "node:crypto";
import { z } from "zod";

const positive = z.number().int().positive().max(Number.MAX_SAFE_INTEGER);
const digest = z.string().length(64).regex(/^[a-f0-9]{64}$/);
const revision = z.string().length(40).regex(/^[a-f0-9]{40}$/);
const date = z.string().refine(value => {
  const parsed = new Date(value);
  return Number.isFinite(parsed.getTime()) && parsed.toISOString() === value;
});

/** The source account snapshot must be taken after all old credential writers drain. */
export const legacyRefreshSourceSchema = z.object({
  storage: z.literal("yii2-redis-active-record-hash"),
  redisDatabase: z.literal(1),
  keyPrefix: z.literal("refresh_token:a:"),
  a1Revision: revision,
  serverRevision: revision.optional(),
  namespaceReviewed: z.literal(true),
  keyEncodingReviewed: z.literal(true),
  accountSnapshotReviewed: z.literal(true),
  writersDrained: z.literal(true),
  a1LookupReviewed: z.boolean(),
  serverLookupReviewed: z.boolean(),
}).strict();
export const legacyRefreshManifestSchema = z.object({
  version: z.literal(1), source: legacyRefreshSourceSchema, capturedAt: date,
  credentials: z.array(z.object({
    recordId: positive,
    credentialHash: digest,
    userId: positive,
    accountFingerprint: digest,
    sourceKind: z.enum(["a1", "server"]),
    sourceFields: z.array(z.string()).min(3).max(12),
    keyEncoding: z.enum(["plain", "sha256-hex"]),
    a1Compatible: z.boolean(),
    serverCompatible: z.boolean(),
    expiresAt: date.nullable(),
    sourceRevokedAt: date.nullable(),
  }).strict()).max(100_000),
}).strict();
export type LegacyRefreshManifest = z.infer<typeof legacyRefreshManifestSchema>;
export type LegacyRefreshCredentialEntry = LegacyRefreshManifest["credentials"][number];

/** Shared with the reviewed source snapshot producer; neither value is stored in the ledger. */
export function legacyRefreshAccountFingerprint(passwordHash: string | null, authKey: string | null): string {
  return createHash("sha256").update(JSON.stringify(["yii-ar-account-v1", passwordHash, authKey])).digest("hex");
}

const snapshotSchema = z.object({
  version: z.literal(1), source: legacyRefreshSourceSchema, capturedAt: date,
  accounts: z.array(z.object({ userId: positive, accountFingerprint: digest }).strict()).max(100_000),
  entries: z.array(z.object({
    redisKey: z.string().min(1).max(128), type: z.literal("hash"), pttl: z.literal(-1),
    sourceKind: z.enum(["a1", "server"]), keyEncoding: z.enum(["plain", "sha256-hex"]),
    a1Compatible: z.boolean(),
    serverCompatible: z.boolean(),
    fields: z.record(z.string().max(4096)),
  }).strict()).max(100_000),
}).strict();
const a1Fields = ["id", "key", "user_id"];
const serverFields = new Set([...a1Fields, "session_id", "user_agent", "ip", "created_at", "expires_at", "revoked_at"]);

/** Offline conversion only. It proves neither an actual snapshot nor a completed cutover. */
export function exportLegacyRefreshCredentials(input: unknown): { manifest: LegacyRefreshManifest; report: {
  total: number; permanent: number; expiring: number; sourceRevoked: number; notFinal: true; sourceWrites: 0; targetWrites: 0;
} } {
  const parsed = snapshotSchema.safeParse(input);
  if (!parsed.success) throw new Error("Invalid reviewed Yii AR refresh snapshot.");
  const snapshot = parsed.data, accounts = new Map<number, string>();
  for (const account of snapshot.accounts) {
    if (accounts.has(account.userId)) throw new Error("Duplicate source account evidence.");
    accounts.set(account.userId, account.accountFingerprint);
  }
  const credentials: LegacyRefreshCredentialEntry[] = [];
  for (const entry of snapshot.entries) {
    const recordId = canonicalId(entry.fields.id), userId = canonicalId(entry.fields.user_id);
    if (entry.redisKey !== `refresh_token:a:${recordId}`) throw new Error("Invalid Yii AR record key.");
    const fields = Object.keys(entry.fields).sort();
    if (entry.sourceKind === "a1") {
      if (JSON.stringify(fields) !== JSON.stringify(a1Fields) || entry.keyEncoding !== "plain" ||
          entry.fields.key?.length !== 32 || !/^[A-Za-z0-9_-]{32}$/.test(entry.fields.key)) throw new Error("Unsupported A1 credential shape.");
    } else {
      // Even an empty provenance field is outside this ordinary-credential contract.
      if ("auth_method" in entry.fields || "device_sn_id" in entry.fields) throw new Error("Device credentials require a provenance-aware migration.");
      if (!snapshot.source.serverRevision || a1Fields.some(field => !(field in entry.fields)) || fields.some(field => !serverFields.has(field))) {
        throw new Error("Unsupported server credential shape.");
      }
      if (entry.fields.created_at) epochSeconds(entry.fields.created_at);
    }
    const key = entry.fields.key;
    if (entry.keyEncoding === "sha256-hex" ? !digest.safeParse(key).success :
      !([32, 64].includes(key?.length) && /^[A-Za-z0-9_-]{32}(?:[A-Za-z0-9_-]{32})?$/.test(key))) throw new Error("Invalid explicitly encoded credential.");
    const accountFingerprint = accounts.get(userId);
    if (!accountFingerprint) throw new Error("Missing reviewed source account evidence.");
    credentials.push({ recordId, userId, accountFingerprint, sourceKind: entry.sourceKind, sourceFields: fields,
      keyEncoding: entry.keyEncoding, a1Compatible: entry.a1Compatible, serverCompatible: entry.serverCompatible, credentialHash: entry.keyEncoding === "plain" ? hash(key) : key,
      expiresAt: entry.fields.expires_at === undefined ? null : epochSeconds(entry.fields.expires_at),
      sourceRevokedAt: entry.fields.revoked_at === undefined || entry.fields.revoked_at === "0" || entry.fields.revoked_at === ""
        ? null : epochSeconds(entry.fields.revoked_at) });
  }
  const manifest = normalizeLegacyRefreshCredentialManifest({ version: 1, source: snapshot.source, capturedAt: snapshot.capturedAt, credentials });
  return { manifest, report: { total: credentials.length, permanent: credentials.filter(row => row.expiresAt === null).length,
    expiring: credentials.filter(row => row.expiresAt !== null).length, sourceRevoked: credentials.filter(row => row.sourceRevokedAt !== null).length,
    notFinal: true, sourceWrites: 0, targetWrites: 0 } };
}

export function normalizeLegacyRefreshCredentialManifest(input: unknown): LegacyRefreshManifest {
  const parsed = legacyRefreshManifestSchema.safeParse(input);
  if (!parsed.success) throw new Error("Invalid hash-only Yii AR refresh manifest.");
  const manifest = parsed.data, hashes = new Set<string>(), records = new Set<number>();
  for (const row of manifest.credentials) {
    if (hashes.has(row.credentialHash) || records.has(row.recordId)) throw new Error("Duplicate Yii AR credential evidence.");
    hashes.add(row.credentialHash); records.add(row.recordId);
    const fields = [...row.sourceFields].sort();
    if (new Set(fields).size !== fields.length || a1Fields.some(field => !fields.includes(field)) || fields.some(field => !serverFields.has(field))) {
      throw new Error("Invalid source field evidence.");
    }
    if (row.sourceKind === "a1" && (JSON.stringify(fields) !== JSON.stringify(a1Fields) || row.keyEncoding !== "plain" || row.expiresAt !== null || row.sourceRevokedAt !== null)) {
      throw new Error("A1 lifetime must remain unknown.");
    }
    if (row.sourceKind === "server" && (!manifest.source.serverRevision || fields.includes("expires_at") !== (row.expiresAt !== null) ||
      (!fields.includes("revoked_at") && row.sourceRevokedAt !== null))) throw new Error("Server lifetime evidence is inconsistent.");
    if (row.a1Compatible && (row.keyEncoding !== "plain" || !manifest.source.a1LookupReviewed)) throw new Error("A1 compatibility requires explicit reviewed plaintext lookup evidence.");
    if (row.serverCompatible && (!manifest.source.serverLookupReviewed || !manifest.source.serverRevision)) throw new Error("Server compatibility requires explicit reviewed consumer evidence.");
  }
  return manifest;
}

function canonicalId(value: string | undefined): number {
  const number = Number(value);
  if (!value || !Number.isSafeInteger(number) || number < 1 || String(number) !== value) throw new Error("Invalid canonical Yii AR identifier.");
  return number;
}
function epochSeconds(value: string): string {
  const seconds = canonicalId(value), result = new Date(seconds * 1000);
  if (!Number.isFinite(result.getTime()) || result.getUTCFullYear() > 9999) throw new Error("Invalid source expiry.");
  return result.toISOString();
}
function hash(value: string): string { return createHash("sha256").update(value).digest("hex"); }
