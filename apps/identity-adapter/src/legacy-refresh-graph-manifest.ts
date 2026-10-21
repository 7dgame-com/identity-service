import { createHash } from "node:crypto";
import { z } from "zod";

const digest = z.string().regex(/^[a-f0-9]{64}$/);
const id = z.number().int().positive().safe();
const time = id.max(253402300799999);
const uint64 = z.string().regex(/^[1-9][0-9]{0,19}$/).refine(v => v.length < 20 || v <= "18446744073709551615");
const epoch = z.string().regex(/^(0|[1-9][0-9]{0,15})$/).refine(v => BigInt(v) <= 9007199254740991n);
export const graphContextSchema = z.union([z.object({}).strict(), z.object({ auth_method: z.literal("device_sn"), device_sn_id: id }).strict()]);
export const graphProtocolSchema = z.enum(["yii3", "ar"]);
export type GraphProtocol = z.infer<typeof graphProtocolSchema>;
export type GraphConsumer = "yii3" | "a1" | "server";
const accountSchema = z.object({ userId: id, status: z.number().int(), accountFingerprint: digest, accountEpoch: uint64,
  securityChangedAtMs: time.nullable() }).strict();
/** This is a separately captured SQL ledger snapshot, never metadata's old epoch. */
export const graphAccountsSchema = z.object({ version: z.literal("legacy-refresh-accounts-v1"),
  sourceDatabase: z.literal("bujiaban_development"), sourceServerUuid: z.string().regex(/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/),
  capturedAtMs: time, accounts: z.array(accountSchema).max(100_000) }).strict();
export type GraphAccounts = z.infer<typeof graphAccountsSchema>;
const familySchema = z.object({ familyId: z.string().regex(/^[a-f0-9]{32}$/), userId: id,
  accountFingerprint: digest, accountEpoch: uint64, userEpoch: epoch, available: z.boolean(),
  currentHash: digest.nullable(), expiresAtMs: time.nullable(), revokedAtMs: time.nullable() }).strict();
export const graphCredentialSchema = z.object({ credentialHash: digest, userId: id, familyId: z.string().regex(/^[a-f0-9]{32}$/),
  accountFingerprint: digest, accountEpoch: uint64, userEpoch: epoch, authContext: graphContextSchema,
  issuedAtMs: time.nullable(), expiresAtMs: time.nullable(), state: z.enum(["active", "rotated", "revoked", "consumed"]),
  successorHash: digest.nullable(), rotatedAtMs: time.nullable(), revokedAtMs: time.nullable(),
  keyEncoding: z.enum(["plain", "sha256"]), a1Compatible: z.boolean(), serverCompatible: z.boolean(),
  sourceRecordId: id.nullable(), sourceRecordSha256: digest, sourceRecordPresent: z.boolean() }).strict();
const tokenSchema = z.object({ accessToken: z.string().min(1).max(16_384), expires: z.string().min(1).max(64),
  refreshToken: z.string().min(1).max(4096) }).strict();
export const graphBodySchema = z.union([
  z.object({ token: tokenSchema, nickname: z.string().max(4096), user: z.object({ id, username: z.string().refine(v => [...v].length <= 255 && Buffer.from(v, "utf8").toString("utf8") === v),
    nickname: z.string().max(4096), fixture: z.literal(false) }).strict() }).strict(),
  z.object({ success: z.literal(true), message: z.literal("refresh"), nickname: z.string().max(4096).nullable(), token: tokenSchema }).strict(),
  z.object({ success: z.literal(true), message: z.literal("refresh"), token: tokenSchema }).strict(),
  z.object({ success: z.literal(true), message: z.literal("report success"), user: z.object({ nickname: z.string().max(4096).nullable(),
    token: tokenSchema }).strict(), data: z.object({ watermark: z.literal(false) }).strict() }).strict(),
]);
export type GraphBody = z.infer<typeof graphBodySchema>;
const replaySchema = z.object({ predecessorHash: digest, successorHash: digest, userId: id,
  familyId: z.string().regex(/^[a-f0-9]{32}$/), accountFingerprint: digest, accountEpoch: uint64, userEpoch: epoch,
  consumer: z.enum(["yii3", "a1", "server"]), endpoint: z.enum(["y1-refresh-pair", "/v1/auth/refresh", "/v1/common/report"]),
  issuer: z.string().max(2048).nullable(), requestHash: digest.nullable(), createdAtMs: time, expiresAtMs: time,
  sourceEncryptedResponse:z.string().min(1).max(400000).nullable(), response: graphBodySchema }).strict();
export const graphManifestSchema = z.object({ version: z.literal("legacy-refresh-graph-v1"), protocol: graphProtocolSchema,
  capturedAtMs: time, source: z.object({ revisions: z.array(z.string().regex(/^[a-f0-9]{40}$/)).min(1).max(4),
    redisDatabase: z.literal(1), keyPrefix: z.enum(["refresh_token:", "refresh_token:a:"]),
    metadataPrefix: z.enum(["y1:refresh-replay:v1:", "identity:legacy-refresh:ar:v1:"]),
    namespaceReviewSha256: digest, drainReviewSha256: digest, sourceSnapshotSha256: digest, accountSnapshotSha256: digest,
    sourceDatabase: z.literal("bujiaban_development"), sourceServerUuid: z.string().regex(/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/) }).strict(),
  families: z.array(familySchema).max(100_000), credentials: z.array(graphCredentialSchema).max(100_000),
  revocations: z.array(z.object({ userId: id, userEpoch: epoch, revokedAtMs: time.nullable() }).strict()).max(100_000),
  replays: z.array(replaySchema).max(100_000) }).strict();
export type RefreshGraphManifest = z.infer<typeof graphManifestSchema>;
export type GraphCredential = RefreshGraphManifest["credentials"][number];
export type GraphReplay = RefreshGraphManifest["replays"][number];
export function graphCanonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(graphCanonical).join(",")}]`;
  if (value !== null && typeof value === "object") return `{${Object.entries(value as Record<string,unknown>).sort(([a],[b])=>a<b?-1:a>b?1:0).map(([k,v])=>`${JSON.stringify(k)}:${graphCanonical(v)}`).join(",")}}`;
  return JSON.stringify(value);
}
export const graphHash = (value: string | Buffer) => createHash("sha256").update(value).digest("hex");
export const graphFamilyKey = (protocol: GraphProtocol, familyId: string) => graphHash(JSON.stringify([protocol, familyId]));
export const graphReplayKey = (protocol: GraphProtocol, r: Pick<GraphReplay, "predecessorHash" | "consumer" | "endpoint" | "requestHash">) =>
  graphHash(JSON.stringify([protocol, r.predecessorHash, r.consumer, r.endpoint, r.requestHash]));
export function graphTokens(body: GraphBody): z.infer<typeof tokenSchema> { return "token" in body ? body.token : body.user.token; }
function reject(): never { throw new Error("Invalid reviewed legacy refresh graph."); }
function unique<T>(rows: T[], key: (row: T) => string | number): Map<string | number, T> {
  const map = new Map<string | number, T>(); for (const row of rows) { const k = key(row); if (map.has(k)) reject(); map.set(k, row); } return map;
}
/** Structural, graph and consumer checks precede any private SQL mutation. */
export function normalizeRefreshGraph(payload: unknown, accountsPayload: unknown, accountsFileSha256: string): RefreshGraphManifest {
  const parsed = graphManifestSchema.safeParse(payload), captured = graphAccountsSchema.safeParse(accountsPayload);
  if (!parsed.success || !captured.success) reject();
  const graph = parsed.data, accounts = captured.data;
  if (graph.source.accountSnapshotSha256 !== accountsFileSha256 || !digest.safeParse(accountsFileSha256).success
    || accounts.sourceDatabase !== graph.source.sourceDatabase || accounts.sourceServerUuid !== graph.source.sourceServerUuid
    || accounts.capturedAtMs > graph.capturedAtMs || graph.capturedAtMs - accounts.capturedAtMs > 60_000) reject();
  for (const account of accounts.accounts) if ((account.accountEpoch === "1") !== (account.securityChangedAtMs === null)
    || (account.securityChangedAtMs !== null && account.securityChangedAtMs > accounts.capturedAtMs)) reject();
  if (graph.protocol === "yii3" ? graph.source.keyPrefix !== "refresh_token:" || graph.source.metadataPrefix !== "y1:refresh-replay:v1:"
    : graph.source.keyPrefix !== "refresh_token:a:" || graph.source.metadataPrefix !== "identity:legacy-refresh:ar:v1:") reject();
  if (new Set(graph.source.revisions).size!==graph.source.revisions.length) reject();
  const currentAccounts = unique(accounts.accounts, r => r.userId), families = unique(graph.families, r => r.familyId),
    credentials = unique(graph.credentials, r => r.credentialHash), revocations = unique(graph.revocations, r => r.userId);
  unique(graph.replays, r => graphReplayKey(graph.protocol, r));
  for (const r of graph.revocations) if (!currentAccounts.has(r.userId) || (r.userEpoch === "0" && r.revokedAtMs !== null)
    || (graph.protocol === "yii3" && (r.userEpoch === "0") !== (r.revokedAtMs === null))
    || (r.revokedAtMs !== null && r.revokedAtMs > graph.capturedAtMs)) reject();
  if (graph.protocol === "ar") unique(graph.credentials, c => c.sourceRecordId!);
  for (const f of graph.families) {
    if (!currentAccounts.has(f.userId) || !revocations.has(f.userId) || (!f.available && (f.currentHash !== null || f.expiresAtMs !== null))) reject();
    if (f.available && graph.protocol === "yii3" && (!f.currentHash || !f.expiresAtMs)) reject();
  }
  const complete = new Set<string>();
  const familyContexts = new Map<string, string>();
  for (const c of graph.credentials) {
    const f = families.get(c.familyId), a = currentAccounts.get(c.userId), revoke = revocations.get(c.userId);
    if (!f || !a || !revoke || c.userId !== f.userId || c.accountFingerprint !== f.accountFingerprint || c.accountEpoch !== f.accountEpoch
      || c.userEpoch !== f.userEpoch || BigInt(c.userEpoch) > BigInt(revoke.userEpoch)) reject();
    const context = graphCanonical(c.authContext), previousContext = familyContexts.get(c.familyId);
    if (previousContext !== undefined && previousContext !== context) reject();
    familyContexts.set(c.familyId, context);
    if (c.expiresAtMs !== null && c.issuedAtMs !== null && c.expiresAtMs <= c.issuedAtMs) reject();
    if (c.state === "active" && (c.successorHash !== null || c.rotatedAtMs !== null || c.revokedAtMs !== null)) reject();
    if ((c.state === "rotated" || c.state === "consumed") && (!c.successorHash || !c.rotatedAtMs || c.revokedAtMs !== null)) reject();
    if (c.state === "revoked" && !c.revokedAtMs) reject();
    if (graph.protocol === "yii3") {
      if (c.issuedAtMs === null || c.expiresAtMs === null || c.expiresAtMs - c.issuedAtMs !== 2592000000
        || c.sourceRecordId !== null || c.a1Compatible || c.serverCompatible || c.keyEncoding !== "plain" || c.state === "consumed") reject();
      if (c.state === "active" && c.sourceRecordPresent && f.currentHash !== c.credentialHash) reject();
    } else {
      if (c.sourceRecordId === null || c.issuedAtMs !== null || (c.a1Compatible && c.keyEncoding !== "plain") || c.state === "rotated") reject();
      if (c.state === "consumed" && c.sourceRecordPresent) reject();
    }
    if (c.successorHash) {
      const next = credentials.get(c.successorHash); if (!next || next.familyId !== c.familyId || next.userId !== c.userId || next.credentialHash === c.credentialHash) reject();
    }
    const seen = new Set<string>(); let link: GraphCredential | undefined = c;
    while (link?.successorHash && !complete.has(link.credentialHash)) { if (seen.has(link.credentialHash)) reject(); seen.add(link.credentialHash); link = credentials.get(link.successorHash); }
    for (const hash of seen) complete.add(hash);
  }
  for (const f of graph.families) if (f.currentHash) {
    const c=credentials.get(f.currentHash);if(!c||c.familyId!==f.familyId||c.userId!==f.userId)reject();
    if(graph.protocol==="yii3"&&f.available&&f.expiresAtMs!==c.expiresAtMs)reject();
  }
  for (const r of graph.replays) {
    const p = credentials.get(r.predecessorHash), s = credentials.get(r.successorHash);
    if (!r.sourceEncryptedResponse || !p || !s || p.familyId !== r.familyId || s.familyId !== r.familyId || p.userId !== r.userId || s.userId !== r.userId
      || r.accountFingerprint !== p.accountFingerprint || r.accountEpoch !== p.accountEpoch || r.userEpoch !== p.userEpoch
      || r.expiresAtMs <= r.createdAtMs || r.expiresAtMs > r.createdAtMs + (r.requestHash === null && graph.protocol === "ar" ? 5000 : 30000)
      || (p.expiresAtMs !== null && r.expiresAtMs > p.expiresAtMs) || (s.expiresAtMs !== null && r.expiresAtMs > s.expiresAtMs)
      || graphHash(graphTokens(r.response).refreshToken) !== r.successorHash) reject();
    if (graph.protocol === "yii3") {
      if (r.consumer !== "yii3" || r.endpoint !== "y1-refresh-pair" || r.issuer !== null || p.successorHash !== s.credentialHash
        || !("nickname" in r.response) || !("user" in r.response) || !("id" in r.response.user) || r.response.user.id !== r.userId) reject();
    } else if ((r.consumer === "server" && (!("token" in r.response) || "nickname" in r.response || !("message" in r.response) || r.response.message !== "refresh"))
      || (r.consumer === "a1" && (r.endpoint === "/v1/auth/refresh" ? !("token" in r.response) || !("nickname" in r.response) || !("message" in r.response) || r.response.message !== "refresh"
        : !("message" in r.response) || r.response.message !== "report success")) || r.consumer === "yii3" || !r.issuer || (r.consumer === "server" && (r.endpoint !== "/v1/auth/refresh" || p.successorHash !== s.credentialHash))
      || (r.consumer === "a1" && (!p.a1Compatible || !["/v1/auth/refresh", "/v1/common/report"].includes(r.endpoint)))) reject();
  }
  return graph;
}
