import { AsyncLocalStorage } from "node:async_hooks";
import { createHash, randomBytes } from "node:crypto";
import { constants, closeSync, fstatSync, openSync, readFileSync } from "node:fs";
import { isProxy } from "node:util/types";
import type { Connection, RowDataPacket } from "mysql2/promise";
import { z } from "zod";
import { syncIdentityAccounts, type AccountSyncReport } from "./identity-account-sync.js";
import { finalizeAllocator, type AllocatorPlan, type AllocatorDrainReview } from "./identity-allocator-finalizer.js";
import { activateExplicitIdentity, activationRequestSha256, immutableIdentityRevision, type ExplicitActivationResult } from "./identity-activation.js";
import { assertZeroAccountSyncReport } from "./identity-allocator-manifest.js";
import { assertOwnedMigrationReport, writeMigrationReport, type MigrationReportFile } from "./identity-migration-resources.js";

/** These are identities, never caller supplied executable paths. */
export const nativeMigrationEntries = Object.freeze({
  "account-sync": "dist/scripts/account-sync.js",
  "allocator-highwater": "dist/scripts/allocator-highwater.js",
  "identity-activate": "dist/scripts/identity-activate.js",
});
const reviewedTarget = Object.freeze({ host: "10.206.0.5", port: 3306, database: "xrugc_identity_dev", principal: "identity_dev", fenceId: 1 });
const reviewedSource = "bujiaban_development";
const reviewedServerUuid = "1c6c32c4-00a9-11f1-9d18-0c42a14c701e";
const hex = z.string().regex(/^[a-f0-9]{64}$/);
const revision = z.string().regex(/^[a-f0-9]{40}$/);
const utc = z.string().regex(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/).refine(v => Number.isFinite(Date.parse(v)) && new Date(v).toISOString() === v);
const executorSchema = z.object({ id: z.string().regex(/^[a-z][a-z0-9_-]{0,63}$/), bootId: z.string().regex(/^[A-Za-z0-9_-]{8,80}$/) }).strict();
const targetSchema = z.object({ host: z.literal(reviewedTarget.host), port: z.literal(reviewedTarget.port), database: z.literal(reviewedTarget.database), principal: z.literal(reviewedTarget.principal), fenceId: z.literal(1) }).strict();
const limitsSchema = z.object({ maxChanges: z.number().int().min(1).max(100000), maxRows: z.number().int().min(1).max(1000000) }).strict();
const syncInputs = z.object({ sourceSnapshotSha256: hex, profileSelectionSha256: hex.nullable(), limits: limitsSchema, apply: z.boolean() }).strict();
const allocatorInputs = z.object({ reviewSha256: hex, finalSyncReportSha256: hex, sourceSnapshotSha256: hex }).strict();
const activationInputs = z.object({ expectedProofSha256: hex, expectedRevision: revision, deadline: utc, requestSha256: hex }).strict();
const commonClaim = {
  version: z.literal(1), runId: z.string().uuid(), planSha256: hex, epoch: z.number().int().positive().safe(), drainSha256: hex,
  compiledRevision: revision, imageDigest: z.string().regex(/^sha256:[a-f0-9]{64}$/), executor: executorSchema, target: targetSchema,
  deadline: utc, claimId: z.string().uuid(), entrySha256: hex, inputSha256: hex, previousChainSha256: hex,
};
const claimSchema = z.discriminatedUnion("stepId", [
  z.object({ ...commonClaim, stepId: z.literal("sync-apply"), entry: z.literal("account-sync"), entrypoint: z.literal(nativeMigrationEntries["account-sync"]), mode: z.literal("apply"), inputs: syncInputs.extend({ apply: z.literal(true) }) }).strict(),
  z.object({ ...commonClaim, stepId: z.literal("sync-zero"), entry: z.literal("account-sync"), entrypoint: z.literal(nativeMigrationEntries["account-sync"]), mode: z.literal("dry-run"), inputs: syncInputs.extend({ apply: z.literal(false) }) }).strict(),
  z.object({ ...commonClaim, stepId: z.literal("allocator"), entry: z.literal("allocator-highwater"), entrypoint: z.literal(nativeMigrationEntries["allocator-highwater"]), mode: z.literal("apply"), inputs: allocatorInputs }).strict(),
  z.object({ ...commonClaim, stepId: z.literal("activation"), entry: z.literal("identity-activate"), entrypoint: z.literal(nativeMigrationEntries["identity-activate"]), mode: z.literal("apply"), inputs: activationInputs }).strict(),
]);
export type NativeMigrationClaim = z.infer<typeof claimSchema>;
type Permission = "sync-apply" | "sync-read" | "allocator-apply" | "allocator-read" | "activation-apply" | "activation-read" | "sync-leaf";
export type NativeMigrationPermission = Permission;
const canonical = (value: unknown): string => {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonical((value as Record<string, unknown>)[k])}`).join(",")}}`;
};
/** Same object binding as driver migrationDigest: canonical JSON, WITHOUT LF.
 * Artifact/report byte hashes are deliberately separate and retain their LF.
 */
export const migrationBindingSha256 = (value: unknown) => createHash("sha256").update(canonical(value)).digest("hex");
const digest = (bytes: Buffer) => createHash("sha256").update(bytes).digest("hex");
export class NativeMigrationEntryError extends Error {
  readonly automaticRetry = false;
  constructor(readonly code: string, readonly outcome: "refused" | "unknown" = "refused", cause?: unknown) { super(code, { cause }); this.name = "NativeMigrationEntryError"; }
}
function fail(code: string): never { throw new NativeMigrationEntryError(code); }
function claim(value: unknown): NativeMigrationClaim {
  assertJsonData(value);
  const parsed = claimSchema.safeParse(value);
  if (!parsed.success) fail("MIGRATION_INVALID_CLAIM");
  const c = parsed.data;
  if (migrationBindingSha256(c.inputs) !== c.inputSha256 || c.compiledRevision !== immutableIdentityRevision()) fail("MIGRATION_CLAIM_BINDING_MISMATCH");
  if (c.stepId === "activation" && (c.inputs.expectedRevision !== c.compiledRevision || c.inputs.deadline !== c.deadline || c.inputs.requestSha256 !== activationRequestSha256(reviewedTarget.database, c.inputs.expectedProofSha256, c.compiledRevision, c.deadline))) fail("MIGRATION_CLAIM_BINDING_MISMATCH");
  return c;
}
function assertDeadline(c: NativeMigrationClaim) {
  const remaining = Date.parse(c.deadline) - Date.now();
  if (remaining <= 0 || remaining > 3000) fail("MIGRATION_DEADLINE_INVALID");
}
declare const opaqueScope: unique symbol;
export type NativeMigrationScope = { readonly [opaqueScope]: true };
type ScopeState = { claim: NativeMigrationClaim; capability: string; state: "ready" | "running" | "consumed" | "unknown"; client: NativeMigrationAdmission; nonce: string };
const scopes = new WeakMap<NativeMigrationScope, ScopeState>();
const context = new AsyncLocalStorage<ScopeState>();

/** Called only by existing writer guards. No exported context setter or callback runner exists. */
export function assertNativeMigrationWriter(permission?: NativeMigrationPermission): boolean {
  const current = context.getStore();
  if (!current) return false;
  current.client.assertKnown();
  if (current.state !== "running") fail("MIGRATION_SCOPE_NOT_RUNNING");
  assertDeadline(current.claim);
  const step = current.claim.stepId;
  const allowed = step === "sync-apply" ? ["sync-apply", "sync-leaf"] : step === "sync-zero" ? ["sync-read"] : step === "allocator" ? ["allocator-apply", "sync-read"] : ["activation-apply"];
  if (!permission || !allowed.includes(permission)) fail("MIGRATION_SCOPE_PURPOSE_MISMATCH");
  return true;
}

const configurationSchema = z.object({ version: z.literal(1), controlUrl: z.string(), executor: executorSchema, compiledRevision: revision, imageDigest: z.string().regex(/^sha256:[a-f0-9]{64}$/), target: targetSchema }).strict();
type Configuration = z.infer<typeof configurationSchema>;
const capabilitySchema = z.string().regex(/^[A-Za-z0-9_-]{32,2048}\.[A-Za-z0-9_-]{32,2048}$/);
const configuredRuntime = Symbol("protected migration runtime");
function protectedText(filename: string | undefined, max: number): string {
  if (!filename) fail("MIGRATION_ENTER_NOT_WIRED");
  const fd = openSync(filename!, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.nlink !== 1 || (stat.mode & 0o077) !== 0 || stat.uid !== process.getuid?.() || stat.size < 2 || stat.size > max) fail("MIGRATION_PROTECTED_CONFIGURATION_REQUIRED");
    const body = readFileSync(fd);
    if (body.length !== stat.size || !Buffer.from(body.toString("utf8")).equals(body)) fail("MIGRATION_PROTECTED_CONFIGURATION_REQUIRED");
    return body.toString("utf8");
  } finally { closeSync(fd); }
}
/** The future private coordinator must authenticate the executor, validate its currently
 * unique ledger claim and consume its opaque single-use capability. Plain claims and
 * ordinary HTTP admission leases cannot authorize migration-enter. There is deliberately
 * no server, default endpoint, default key, register/begin or complete action here.
 */
export class NativeMigrationAdmission {
  #unknown = false;
  readonly #attempted = new Set<string>();
  readonly #config: Configuration;
  readonly #key: string;
  private constructor(config: Configuration, key: string, authorization: symbol) {
    if (authorization !== configuredRuntime) fail("MIGRATION_PROTECTED_CONFIGURATION_REQUIRED");
    this.#config = config; this.#key = key;
  }
  static environment(): NativeMigrationAdmission {
    const parsed = configurationSchema.safeParse(JSON.parse(protectedText(process.env.IDENTITY_MIGRATION_CONFIG_FILE, 16384)));
    if (!parsed.success) fail("MIGRATION_INVALID_CONFIGURATION");
    const config = parsed.data, url = new URL(config.controlUrl);
    if (url.protocol !== "http:" || url.hostname !== "127.0.0.1" || url.pathname !== "/" || url.username || url.password || url.search || url.hash) fail("MIGRATION_PRIVATE_CONTROL_REQUIRED");
    if (config.compiledRevision !== immutableIdentityRevision()) fail("MIGRATION_COMPILED_REVISION_MISMATCH");
    const key = protectedText(process.env.IDENTITY_MIGRATION_KEY_FILE, 256).trim();
    if (!/^[A-Za-z0-9_-]{43,171}$/.test(key) || Buffer.from(key, "base64url").toString("base64url") !== key) fail("MIGRATION_PROTECTED_KEY_REQUIRED");
    return new NativeMigrationAdmission(Object.freeze(config), key, configuredRuntime);
  }
  private async post(action: "migration-enter" | "migration-unknown", body: unknown, deadline: string): Promise<unknown> {
    const response = await fetch(new URL(action, this.#config.controlUrl), { method: "POST", headers: { authorization: `Bearer ${this.#key}`, "content-type": "application/json", "x-identity-migration-executor": this.#config.executor.id, "x-identity-migration-boot": this.#config.executor.bootId }, body: JSON.stringify(body), redirect: "error", signal: AbortSignal.timeout(Math.max(1, Math.min(2000, Date.parse(deadline) - Date.now()))) });
    if (!response.ok || !response.body) fail("MIGRATION_ENTER_ACK_REQUIRED");
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = []; let size = 0;
    try { for (;;) { const { done, value } = await reader.read(); if (done) break; size += value.length; if (size > 16384) fail("MIGRATION_ENTER_ACK_REQUIRED"); chunks.push(value); } }
    finally { await reader.cancel(); }
    const bytes = Buffer.concat(chunks);
    if (!Buffer.from(bytes.toString("utf8")).equals(bytes)) fail("MIGRATION_ENTER_ACK_REQUIRED");
    return JSON.parse(bytes.toString("utf8"));
  }
  async enter(value: unknown, claimCapability: string): Promise<NativeMigrationScope> {
    this.assertKnown();
    const c = claim(value); assertDeadline(c);
    if (!capabilitySchema.safeParse(claimCapability).success || canonical(c.executor) !== canonical(this.#config.executor) || c.imageDigest !== this.#config.imageDigest || c.compiledRevision !== this.#config.compiledRevision) fail("MIGRATION_EXECUTOR_BINDING_MISMATCH");
    if (this.#attempted.has(c.claimId)) fail("MIGRATION_CLAIM_ALREADY_ATTEMPTED");
    this.#attempted.add(c.claimId);
    const nonce = randomBytes(32).toString("base64url"), request = { version: 1, nonce, claim: c, claimCapability }, requestSha256 = migrationBindingSha256(request);
    try {
      const ack = z.object({ version: z.literal(1), nonce: z.literal(nonce), requestSha256: z.literal(requestSha256), claim: claimSchema, scopeCapability: capabilitySchema }).strict().parse(await this.post("migration-enter", { ...request, requestSha256 }, c.deadline));
      if (canonical(ack.claim) !== canonical(c)) fail("MIGRATION_ENTER_ACK_BINDING_MISMATCH");
      this.assertKnown();
      assertDeadline(c);
      const scope = Object.freeze(Object.create(null)) as NativeMigrationScope;
      scopes.set(scope, { claim: c, capability: ack.scopeCapability, state: "ready", client: this, nonce });
      return scope;
    } catch (cause) {
      this.#unknown = true;
      // The enter may have consumed its capability even though no ACK arrived.
      // Report that uncertainty without retrying enter or inventing a scope.
      try { await this.post("migration-unknown", { ...request, requestSha256 }, c.deadline); } catch { /* Local unknown is permanent. */ }
      throw new NativeMigrationEntryError("MIGRATION_ENTER_UNKNOWN", "unknown", cause);
    }
  }
  /** Best effort only; no response can clear the local permanent unknown latch. */
  async noteUnknown(state: ScopeState): Promise<void> {
    state.state = "unknown"; this.#unknown = true;
    try { await this.post("migration-unknown", { version: 1, nonce: state.nonce, claim: state.claim, scopeCapability: state.capability }, state.claim.deadline); } catch { /* Permanent local unknown remains authoritative. */ }
  }
  assertKnown(): void { if (this.#unknown) fail("MIGRATION_CONTROL_UNKNOWN"); }
}

type SyncInvocation = { entry: "account-sync"; source: Connection; target: Connection; sourceSnapshot: Buffer; profileSelection: Buffer | null };
type AllocatorInvocation = { entry: "allocator-highwater"; source: Connection; target: Connection; fence: Connection; sourceSnapshot: Buffer; review: Buffer; finalSyncReport: Buffer; journal: MigrationReportFile };
type ActivationInvocation = { entry: "identity-activate"; target: Connection; journal: MigrationReportFile };
export type NativeMigrationInvocation = SyncInvocation | AllocatorInvocation | ActivationInvocation;
export type NativeAllocatorResult = { plan: AllocatorPlan; summary: { success: true; applied: true; ready: true; manifestSha256: string; tables: 6; authorityActivated: false; sourceWritten: false } };
function dataDescriptors(value: unknown): Record<string, PropertyDescriptor> {
  if (!value || typeof value !== "object" || isProxy(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail("MIGRATION_TYPED_INPUT_REQUIRED");
  const keys = Reflect.ownKeys(value), descriptors = Object.getOwnPropertyDescriptors(value);
  if (keys.some(k => typeof k !== "string" || !descriptors[k].enumerable || !("value" in descriptors[k]))) fail("MIGRATION_TYPED_INPUT_REQUIRED");
  return descriptors;
}
function assertJsonData(value: unknown, ancestors = new Set<object>()): void {
  if (value === null || ["string", "number", "boolean"].includes(typeof value)) return;
  const descriptors = dataDescriptors(value);
  if (ancestors.has(value as object)) fail("MIGRATION_TYPED_INPUT_REQUIRED");
  ancestors.add(value as object);
  for (const d of Object.values(descriptors)) assertJsonData(d.value, ancestors);
  ancestors.delete(value as object);
}
/** Capture all caller-owned fields synchronously, before the first await. Never
 * validate one connection then re-read another from a mutable invocation object.
 */
function captureInvocation(value: NativeMigrationInvocation): NativeMigrationInvocation {
  const d = dataDescriptors(value), entry = d.entry?.value;
  const keys = entry === "account-sync" ? ["entry", "source", "target", "sourceSnapshot", "profileSelection"] : entry === "allocator-highwater" ? ["entry", "source", "target", "fence", "sourceSnapshot", "review", "finalSyncReport", "journal"] : entry === "identity-activate" ? ["entry", "target", "journal"] : fail("MIGRATION_TYPED_INPUT_REQUIRED");
  if (Object.keys(d).sort().join(",") !== keys.sort().join(",")) fail("MIGRATION_TYPED_INPUT_REQUIRED");
  const captured: Record<string, unknown> = Object.create(null);
  for (const k of keys) {
    const field = d[k].value;
    if (["sourceSnapshot", "profileSelection", "review", "finalSyncReport"].includes(k)) {
      if (k === "profileSelection" && field === null) captured[k] = null;
      else { if (!Buffer.isBuffer(field) || isProxy(field) || field.length > 1048576) fail("MIGRATION_TYPED_INPUT_REQUIRED"); captured[k] = Buffer.from(field); }
    } else captured[k] = field;
  }
  if (entry !== "account-sync") assertOwnedMigrationReport(captured.journal as MigrationReportFile);
  return Object.freeze(captured) as unknown as NativeMigrationInvocation;
}
function exactKeys(value: object, keys: string[]) {
  if (Object.keys(value).sort().join(",") !== keys.sort().join(",")) fail("MIGRATION_TYPED_INPUT_REQUIRED");
}
function jsonBytes(bytes: Buffer, expected: string): unknown {
  if (!Buffer.isBuffer(bytes) || bytes.length < 2 || bytes.length > 1048576 || digest(bytes) !== expected || !Buffer.from(bytes.toString("utf8")).equals(bytes)) fail("MIGRATION_INPUT_BINDING_MISMATCH");
  return JSON.parse(bytes.toString("utf8"));
}
async function location(c: Connection, target: boolean) {
  // Check the actual mysql2 endpoint as well as server-selected schema/principal.
  // These checks add no transaction or fence; the original cores own those.
  const base = (c as Connection & { connection?: { config?: { host?: string; port?: number; user?: string }; stream?: { remoteAddress?: string; remotePort?: number } } }).connection;
  if (!base || base.config?.host !== reviewedTarget.host || base.config.port !== reviewedTarget.port || base.stream?.remoteAddress?.replace(/^::ffff:/, "") !== reviewedTarget.host || base.stream.remotePort !== reviewedTarget.port || (target && base.config.user !== reviewedTarget.principal)) fail("MIGRATION_CONNECTION_TARGET_MISMATCH");
  const [rows] = await c.query<RowDataPacket[]>("SELECT DATABASE() AS name,CURRENT_USER() AS principal,@@server_uuid AS server_id");
  const row = rows[0];
  if (rows.length !== 1 || row?.name !== (target ? reviewedTarget.database : reviewedSource) || row.server_id !== reviewedServerUuid || (target && String(row.principal).split("@")[0] !== reviewedTarget.principal)) fail("MIGRATION_DATABASE_TARGET_MISMATCH");
  const [mode] = await c.query<RowDataPacket[]>("SELECT @@autocommit AS enabled");
  if (Number(mode[0]?.enabled) !== 1) fail("MIGRATION_IDLE_AUTOCOMMIT_REQUIRED");
  // Unlike START/BEGIN this statement never commits an existing transaction:
  // MySQL rejects it with ER_CANT_CHANGE_TX_CHARACTERISTICS. Never roll back a
  // caller's work here. Original cores still own every transaction and fence.
  await c.query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ");
  return row;
}
/** Closed dispatch only: no callback, command, environment, dynamic import or pathname.
 * Results are business results, NOT ledger completion or durable-cleanup evidence.
 * Resource ownership and the trusted FD/artifact bridge remain the caller's obligation.
 */
export async function invokeNativeMigration(scope: NativeMigrationScope, value: NativeMigrationInvocation): Promise<AccountSyncReport | NativeAllocatorResult | ExplicitActivationResult> {
  const state = scopes.get(scope);
  if (!state || state.state !== "ready") fail("MIGRATION_VERIFIED_SINGLE_USE_SCOPE_REQUIRED");
  state.state = "running";
  try {
    state.client.assertKnown();
    const input = captureInvocation(value);
    const c = state.claim; assertDeadline(c);
    if (!input || input.entry !== c.entry) fail("MIGRATION_SCOPE_PURPOSE_MISMATCH");
    const result = await context.run(state, async () => {
      if (input.entry === "account-sync" && (c.stepId === "sync-apply" || c.stepId === "sync-zero")) {
        exactKeys(input, ["entry", "source", "target", "sourceSnapshot", "profileSelection"]);
        jsonBytes(input.sourceSnapshot, c.inputs.sourceSnapshotSha256);
        const profileSchema = z.object({ version: z.literal(1), selections: z.array(z.object({ userId: z.number().int().positive().safe(), profileId: z.number().int().positive().safe(), sourceRowsSha256: hex }).strict()).max(100000) }).strict();
        const profile = c.inputs.profileSelectionSha256 === null ? undefined : profileSchema.parse(jsonBytes(input.profileSelection!, c.inputs.profileSelectionSha256));
        if (c.inputs.profileSelectionSha256 === null && input.profileSelection !== null) fail("MIGRATION_INPUT_BINDING_MISMATCH");
        await location(input.source, false); await location(input.target, true);
        return syncIdentityAccounts(input.source, input.target, { ...c.inputs.limits, apply: c.inputs.apply, profileSelection: profile });
      }
      if (input.entry === "allocator-highwater" && c.stepId === "allocator") {
        exactKeys(input, ["entry", "source", "target", "fence", "sourceSnapshot", "review", "finalSyncReport", "journal"]);
        assertOwnedMigrationReport(input.journal);
        jsonBytes(input.sourceSnapshot, c.inputs.sourceSnapshotSha256);
        const review = jsonBytes(input.review, c.inputs.reviewSha256) as AllocatorDrainReview;
        const finalSync = jsonBytes(input.finalSyncReport, c.inputs.finalSyncReportSha256);
        assertZeroAccountSyncReport(finalSync);
        if (review.finalSyncSha256 !== c.inputs.finalSyncReportSha256 || review.sourceDatabase !== reviewedSource || review.targetDatabase !== reviewedTarget.database) fail("MIGRATION_INPUT_BINDING_MISMATCH");
        await location(input.source, false); await location(input.target, true); await location(input.fence, true);
        assertZeroAccountSyncReport(await syncIdentityAccounts(input.source, input.target, { apply: false, maxChanges: 100000 }));
        const plan = await finalizeAllocator({ source: input.source, target: input.target, fence: input.fence, review, reviewSha256: c.inputs.reviewSha256, apply: true,
          onStep: async step => { await writeMigrationReport(input.journal, { ...step, at: new Date().toISOString() }); } });
        return { plan, summary: { success: true, applied: true, ready: true, manifestSha256: plan.manifestSha256, tables: 6, authorityActivated: false, sourceWritten: false } } as NativeAllocatorResult;
      }
      if (input.entry === "identity-activate" && c.stepId === "activation") {
        exactKeys(input, ["entry", "target", "journal"]); assertOwnedMigrationReport(input.journal);
        await location(input.target, true);
        const result = await activateExplicitIdentity({ connection: input.target, expectedProofSha256: c.inputs.expectedProofSha256, expectedRevision: c.inputs.expectedRevision, deadline: c.inputs.deadline, apply: true,
          onCommitIntent: async receipt => { if (receipt.requestSha256 !== c.inputs.requestSha256) fail("MIGRATION_ACTIVATION_REQUEST_MISMATCH"); await writeMigrationReport(input.journal, { phase: "commit_intent", receipt }); } });
        if (result.outcome === "unknown" || result.acknowledgementAfterDeadline) throw new NativeMigrationEntryError("MIGRATION_ACTIVATION_UNKNOWN", "unknown");
        const receipt = z.object({ allocatorManifestSha256: z.literal(c.inputs.expectedProofSha256), compiledRevision: z.literal(c.compiledRevision), requestSha256: z.literal(c.inputs.requestSha256), decisionAt: utc, deadline: z.literal(c.deadline) }).strict().parse(result.receipt);
        if (!["activated", "already_active"].includes(result.outcome) || result.authority !== "identity" || receipt.decisionAt >= receipt.deadline) fail("MIGRATION_ACTIVATION_RESULT_MISMATCH");
        return result;
      }
      return fail("MIGRATION_TYPED_INPUT_REQUIRED");
    });
    state.client.assertKnown(); assertDeadline(c);
    return result;
  } catch (cause) {
    await state.client.noteUnknown(state);
    throw new NativeMigrationEntryError("MIGRATION_INVOCATION_UNKNOWN", "unknown", cause);
  } finally { if (state.state === "running") state.state = "consumed"; }
}
