import { AsyncLocalStorage } from "node:async_hooks";
import { createHash, randomBytes } from "node:crypto";
import { constants, closeSync, fstatSync, openSync, readFileSync } from "node:fs";
import { isProxy } from "node:util/types";
import mysql from "mysql2";
import type { Connection, RowDataPacket } from "mysql2/promise";
import { openMigrationArtifacts, validateMigrationTypedReport, type MigrationArtifactSession } from "../../../packages/identity-finalization-runtime/migration-artifacts.mjs";
import { prepareExpectedSourceFingerprint, expectedSourceManifest, readActualSourceFingerprint, assertSameSourceFingerprint, type ExpectedSourceFingerprint } from "./identity-source-fingerprint.js";
import type { ProfileSelectionManifest } from "./identity-profile-migration.js";
import { z } from "zod";
import { syncIdentityAccounts, type AccountSyncReport } from "./identity-account-sync.js";
import { finalizeAllocator, type AllocatorPlan, type AllocatorDrainReview } from "./identity-allocator-finalizer.js";
import { activateExplicitIdentity, activationRequestSha256, immutableIdentityRevision, type ExplicitActivationResult } from "./identity-activation.js";
import { assertZeroAccountSyncReport } from "./identity-allocator-manifest.js";
import { assertOwnedMigrationReport, writeMigrationReport, withMigrationResources, type MigrationResources, type MigrationReportFile } from "./identity-migration-resources.js";

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

const configurationSchema = z.object({ version: z.literal(1), controlUrl: z.string(), executor: executorSchema, compiledRevision: revision, imageDigest: z.string().regex(/^sha256:[a-f0-9]{64}$/), target: targetSchema, planSha256: hex.optional() }).strict();
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
/** The private coordinator must authenticate the executor, validate its currently
 * unique ledger claim and consume its opaque single-use capability. Plain claims and
 * ordinary HTTP admission leases cannot authorize migration-enter. There is deliberately
 * no server, default endpoint/key, participant register/begin, or generic
 * caller-supplied completion envelope here.
 */
export class NativeMigrationAdmission {
  #unknown = false;
  readonly #attempted = new Set<string>();
  readonly #config: Configuration;
  readonly #key: string;
  #prepared: OwnedPreparation | undefined;
  #preparing = false;
  #preparationFinished: Promise<void> = Promise.resolve();
  #finishPreparation: (() => void) | undefined;
  #lastOwned: ScopeState | undefined;
  private constructor(config: Configuration, key: string, authorization: symbol) {
    if (authorization !== configuredRuntime) fail("MIGRATION_PROTECTED_CONFIGURATION_REQUIRED");
    this.#config = config; this.#key = key;
    Object.preventExtensions(this);
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
  async #post(action: "migration-enter" | "migration-unknown" | "migration-complete", body: unknown, deadline: string): Promise<unknown> {
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
  /** Claim-free, read-only preflight. It is neither drain evidence nor authority. */
  async prepareOwnedPlan(): Promise<void> {
    this.assertKnown();
    if (this.#prepared || this.#preparing || !this.#config.planSha256) fail("MIGRATION_OWNED_PLAN_NOT_WIRED");
    this.#preparing = true;
    this.#preparationFinished = new Promise<void>(resolve => { this.#finishPreparation = resolve; });
    let artifacts: MigrationArtifactSession | undefined;
    try {
      artifacts = await openMigrationArtifacts({ planSha256: this.#config.planSha256, compiledRevision: this.#config.compiledRevision, imageDigest: this.#config.imageDigest });
      const p = artifacts.plan;
      if (canonical(p.executor) !== canonical(this.#config.executor) || canonical(p.target) !== canonical(this.#config.target)) fail("MIGRATION_OWNED_PLAN_BINDING");
      const bytes = await artifacts.readPreparedInputs();
      const review = ownedReviewSchema.parse(JSON.parse(bytes.review.toString("utf8")));
      if (Date.parse(review.writersDrainedAt) > Date.now()) fail("MIGRATION_OWNED_REVIEW_BINDING");
      const expected = prepareExpectedSourceFingerprint(bytes.source, bytes.profile ?? null, p.limits.maxRows);
      const credentials = databaseCredentialsSchema.parse(JSON.parse(protectedText(ownedDatabaseConfiguration, 16384)));
      await withMigrationResources(async resources => {
        const source = await freshConnection(resources, credentials, false);
        await location(source, false);
        assertSameSourceFingerprint(expectedSourceManifest(expected), await readActualSourceFingerprint(source, { profileSelectionSha256: p.inputs.profileSelectionSha256, maxRows: p.limits.maxRows }));
      });
      this.assertKnown();
      this.#prepared = { artifacts, expected, credentials, profile: bytes.profile ? profileSelectionSchema.parse(JSON.parse(bytes.profile.toString("utf8"))) : undefined };
    } catch (cause) {
      this.#unknown = true;
      if (artifacts) { try { await artifacts.close(); } catch (closeError) { throw new NativeMigrationEntryError("MIGRATION_PREFLIGHT_UNKNOWN", "unknown", new AggregateError([cause, closeError])); } }
      throw new NativeMigrationEntryError("MIGRATION_PREFLIGHT_UNKNOWN", "unknown", cause);
    } finally { this.#preparing = false; this.#finishPreparation?.(); this.#finishPreparation = undefined; }
  }
  async noteOwnedControlUnknown(): Promise<void> {
    this.#unknown = true;
    if (this.#lastOwned) await this.noteUnknown(this.#lastOwned);
  }
  async closePreparedPlan(): Promise<void> {
    if (this.#preparing) {
      this.#unknown = true;
      await this.#preparationFinished;
      throw new NativeMigrationEntryError("MIGRATION_PREFLIGHT_CLOSED_DURING_PREPARATION", "unknown");
    }
    const prepared = this.#prepared; this.#prepared = undefined;
    if (!prepared) return;
    this.#unknown = true;
    await prepared.artifacts.close();
  }
  async enterOwned(value: unknown, claimCapability: string): Promise<NativeMigrationScope> {
    this.assertKnown();
    const prepared = this.#prepared; this.#prepared = undefined;
    if (!prepared) fail("MIGRATION_OWNED_PREFLIGHT_REQUIRED");
    try {
      const c = claim(value);
      if (c.planSha256 !== prepared.artifacts.planSha256) fail("MIGRATION_OWNED_PLAN_BINDING");
      const scope = await this.enter(c, claimCapability);
      ownedScopes.set(scope, prepared);
      this.#lastOwned = scopes.get(scope)!;
      return scope;
    } catch (cause) {
      this.#unknown = true;
      try { await prepared.artifacts.close(); } catch (closeError) { throw new NativeMigrationEntryError("MIGRATION_OWNED_ENTER_UNKNOWN", "unknown", new AggregateError([cause, closeError])); }
      throw cause;
    }
  }
  /** Only the private brand minted AFTER actual resource cleanup can complete. */
  async completeOwned(receipt: ClosedStepReceipt): Promise<Readonly<{ reportSha256: string; outputSha256: string; chainSha256: string }>> {
    const closed = closedReceipts.get(receipt);
    if (!closed || closed.state.client !== this) fail("MIGRATION_CLOSED_RECEIPT_REQUIRED");
    if (closed.consumed) { await this.noteUnknown(closed.state); throw new NativeMigrationEntryError("MIGRATION_COMPLETION_REPLAY_UNKNOWN", "unknown"); }
    closed.consumed = true;
    const state = closed.state, c = state.claim;
    try {
      this.assertKnown(); assertDeadline(c);
      const nonce = randomBytes(32).toString("base64url");
      const request = { version: 1, nonce, enterNonce: state.nonce, claim: c, scopeCapability: state.capability, typedReportBase64: closed.bytes.toString("base64"), typedReportSha256: digest(closed.bytes) };
      const requestSha256 = migrationBindingSha256(request);
      const expected = completionHashes(c, closed.output);
      const ack = z.object({ version: z.literal(1), nonce: z.literal(nonce), requestSha256: z.literal(requestSha256), claim: claimSchema, reportSha256: z.literal(expected.reportSha256), outputSha256: z.literal(expected.outputSha256), chainSha256: z.literal(expected.chainSha256) }).strict().parse(await this.#post("migration-complete", { ...request, requestSha256 }, c.deadline));
      if (canonical(ack.claim) !== canonical(c)) fail("MIGRATION_COMPLETE_ACK_BINDING");
      this.assertKnown(); assertDeadline(c);
      if (c.stepId === "sync-zero") completedZero.set(this, { runId: c.runId, planSha256: c.planSha256, bytes: canonicalBytes(closed.output), outputSha256: expected.outputSha256 });
      return Object.freeze(expected);
    } catch (cause) {
      await this.noteUnknown(state);
      throw new NativeMigrationEntryError("MIGRATION_COMPLETION_UNKNOWN", "unknown", cause);
    }
  }
  async enter(value: unknown, claimCapability: string): Promise<NativeMigrationScope> {
    this.assertKnown();
    const c = claim(value); assertDeadline(c);
    if (!capabilitySchema.safeParse(claimCapability).success || canonical(c.executor) !== canonical(this.#config.executor) || c.imageDigest !== this.#config.imageDigest || c.compiledRevision !== this.#config.compiledRevision) fail("MIGRATION_EXECUTOR_BINDING_MISMATCH");
    if (this.#attempted.has(c.claimId)) fail("MIGRATION_CLAIM_ALREADY_ATTEMPTED");
    this.#attempted.add(c.claimId);
    const nonce = randomBytes(32).toString("base64url"), request = { version: 1, nonce, claim: c, claimCapability }, requestSha256 = migrationBindingSha256(request);
    try {
      const ack = z.object({ version: z.literal(1), nonce: z.literal(nonce), requestSha256: z.literal(requestSha256), claim: claimSchema, scopeCapability: capabilitySchema }).strict().parse(await this.#post("migration-enter", { ...request, requestSha256 }, c.deadline));
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
      try { await this.#post("migration-unknown", { ...request, requestSha256 }, c.deadline); } catch { /* Local unknown is permanent. */ }
      throw new NativeMigrationEntryError("MIGRATION_ENTER_UNKNOWN", "unknown", cause);
    }
  }
  /** Best effort only; no response can clear the local permanent unknown latch. */
  async noteUnknown(state: ScopeState): Promise<void> {
    state.state = "unknown"; this.#unknown = true;
    try { await this.#post("migration-unknown", { version: 1, nonce: state.nonce, claim: state.claim, scopeCapability: state.capability }, state.claim.deadline); } catch { /* Permanent local unknown remains authoritative. */ }
  }
  assertKnown(): void { if (this.#unknown) fail("MIGRATION_CONTROL_UNKNOWN"); }
}

type SyncInvocation = { entry: "account-sync"; source: Connection; target: Connection; sourceSnapshot: Buffer; profileSelection: Buffer | null };
type AllocatorInvocation = { entry: "allocator-highwater"; source: Connection; target: Connection; fence: Connection; sourceSnapshot: Buffer; review: Buffer; finalSyncReport: Buffer; journal: MigrationReportFile };
type ActivationInvocation = { entry: "identity-activate"; target: Connection; journal: MigrationReportFile };
export type NativeMigrationInvocation = SyncInvocation | AllocatorInvocation | ActivationInvocation;
export const nativeMigrationInputBounds = Object.freeze({ sourceSnapshot: 16 * 1024 * 1024, profileSelection: 2 * 1024 * 1024, review: 65536, finalSyncReport: 65536 });
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
      else { if (!Buffer.isBuffer(field) || isProxy(field) || field.length > nativeMigrationInputBounds[k as keyof typeof nativeMigrationInputBounds]) fail("MIGRATION_TYPED_INPUT_REQUIRED"); captured[k] = Buffer.from(field); }
    } else captured[k] = field;
  }
  if (entry !== "account-sync") assertOwnedMigrationReport(captured.journal as MigrationReportFile);
  return Object.freeze(captured) as unknown as NativeMigrationInvocation;
}
function exactKeys(value: object, keys: string[]) {
  if (Object.keys(value).sort().join(",") !== keys.sort().join(",")) fail("MIGRATION_TYPED_INPUT_REQUIRED");
}
function jsonBytes(bytes: Buffer, expected: string, bound = 65536): unknown {
  if (!Buffer.isBuffer(bytes) || bytes.length < 2 || bytes.length > bound || digest(bytes) !== expected || !Buffer.from(bytes.toString("utf8")).equals(bytes)) fail("MIGRATION_INPUT_BINDING_MISMATCH");
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
  if (ownedScopes.has(scope) || invocationOwned.has(scope)) fail("MIGRATION_OWNED_SCOPE_ONLY");
  return invokeNativeMigrationInternal(scope, value);
}
async function invokeNativeMigrationInternal(scope: NativeMigrationScope, value: NativeMigrationInvocation): Promise<AccountSyncReport | NativeAllocatorResult | ExplicitActivationResult> {
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
        jsonBytes(input.sourceSnapshot, c.inputs.sourceSnapshotSha256, nativeMigrationInputBounds.sourceSnapshot);
        const profile = c.inputs.profileSelectionSha256 === null ? undefined : profileSelectionSchema.parse(jsonBytes(input.profileSelection!, c.inputs.profileSelectionSha256, nativeMigrationInputBounds.profileSelection));
        if (c.inputs.profileSelectionSha256 === null && input.profileSelection !== null) fail("MIGRATION_INPUT_BINDING_MISMATCH");
        await location(input.source, false); await location(input.target, true);
        return syncIdentityAccounts(input.source, input.target, { ...c.inputs.limits, apply: c.inputs.apply, profileSelection: profile, ...(invocationOwned.has(scope) ? { expectedSourceFingerprint: invocationOwned.get(scope)!.expected } : {}) });
      }
      if (input.entry === "allocator-highwater" && c.stepId === "allocator") {
        exactKeys(input, ["entry", "source", "target", "fence", "sourceSnapshot", "review", "finalSyncReport", "journal"]);
        assertOwnedMigrationReport(input.journal);
        jsonBytes(input.sourceSnapshot, c.inputs.sourceSnapshotSha256, nativeMigrationInputBounds.sourceSnapshot);
        const review = jsonBytes(input.review, c.inputs.reviewSha256) as AllocatorDrainReview;
        const finalSync = jsonBytes(input.finalSyncReport, c.inputs.finalSyncReportSha256);
        assertZeroAccountSyncReport(finalSync);
        if (review.finalSyncSha256 !== c.inputs.finalSyncReportSha256 || review.sourceDatabase !== reviewedSource || review.targetDatabase !== reviewedTarget.database) fail("MIGRATION_INPUT_BINDING_MISMATCH");
        await location(input.source, false); await location(input.target, true); await location(input.fence, true);
        const owned = invocationOwned.get(scope);
        assertZeroAccountSyncReport(await syncIdentityAccounts(input.source, input.target, owned ? { apply: false, ...owned.artifacts.plan.limits, expectedSourceFingerprint: owned.expected, profileSelection: owned.profile } : { apply: false, maxChanges: 100000 }));
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

const profileSelectionSchema = z.object({ version: z.literal(1), selections: z.array(z.object({ userId: z.number().int().positive().safe(), profileId: z.number().int().positive().safe(), sourceRowsSha256: hex }).strict()).max(100000) }).strict();
const ownedReviewSchema = z.object({ version: z.literal(1), sourceDatabase: z.literal(reviewedSource), targetDatabase: z.literal(reviewedTarget.database), importKey: z.string().regex(/^[A-Za-z0-9_.:-]{1,160}$/), sourceServerUuid: z.literal(reviewedServerUuid), writersDrainedAt: utc, finalSyncSha256: hex, referenceReviewSha256: hex }).strict();
const ownedDatabaseConfiguration = "/run/xrugc/identity-finalization/config/database.json";
const credential = z.object({ user: z.string().regex(/^[a-zA-Z0-9_]{1,32}$/), password: z.string().min(1).max(4096) }).strict();
const databaseCredentialsSchema = z.object({ version: z.literal(1), source: credential, target: credential.extend({ user: z.literal(reviewedTarget.principal) }) }).strict();
type DatabaseCredentials = z.infer<typeof databaseCredentialsSchema>;
type OwnedPreparation = { artifacts: MigrationArtifactSession; expected: ExpectedSourceFingerprint; credentials: DatabaseCredentials; profile?: ProfileSelectionManifest };
const ownedScopes = new WeakMap<NativeMigrationScope, OwnedPreparation>();
const completedZero = new WeakMap<NativeMigrationAdmission, { runId: string; planSha256: string; bytes: Buffer; outputSha256: string }>();
declare const closedReceiptBrand: unique symbol;
export type ClosedStepReceipt = { readonly [closedReceiptBrand]: true };
const closedReceipts = new WeakMap<ClosedStepReceipt, { state: ScopeState; bytes: Buffer; output: unknown; consumed: boolean }>();
const canonicalBytes = (value: unknown) => Buffer.from(`${canonical(value)}\n`);
async function freshConnection(resources: MigrationResources, credentials: DatabaseCredentials, target: boolean): Promise<Connection> {
  const auth = target ? credentials.target : credentials.source;
  // Register immediately after acquisition, including during later acquisitions.
  const raw = mysql.createConnection({ host: reviewedTarget.host, port: reviewedTarget.port, database: target ? reviewedTarget.database : reviewedSource, user: auth.user, password: auth.password, timezone: "Z", supportBigNumbers: true, bigNumberStrings: false, multipleStatements: false, connectTimeout: 2000 });
  // The raw socket exists before handshake success. Own it now, so a rejected
  // handshake also waits for actual physical close rather than losing its FD.
  const connection = resources.connection(raw.promise());
  try { await new Promise<void>((resolve, reject) => raw.connect(error => error ? reject(error) : resolve())); }
  catch (error) { raw.destroy(); throw error; }
  return connection;
}
function completionHashes(c: NativeMigrationClaim, output: unknown) {
  // These fields are private conclusions of the resource owner, never wire input.
  const envelope = { version: 1, runId: c.runId, claimId: c.claimId, stepId: c.stepId, planSha256: c.planSha256, inputSha256: c.inputSha256, previousChainSha256: c.previousChainSha256, compiledRevision: c.compiledRevision, epoch: c.epoch, target: c.target, deadline: c.deadline, outcome: "completed", sideEffectsFinished: true, connectionsClosed: true, output };
  const reportSha256 = digest(canonicalBytes(envelope)), outputSha256 = digest(canonicalBytes(output));
  return { reportSha256, outputSha256, chainSha256: migrationBindingSha256({ previousChainSha256: c.previousChainSha256, claimSha256: migrationBindingSha256(c), reportSha256, outputSha256 }) };
}
/** Closed production owner. Only a prepared, genuinely entered scope is accepted.
 * All inputs come from held pinned-adapter FDs; all DBs are fresh and exclusive.
 * No caller connection, pathname, callback, file descriptor or cleanup flag exists.
 */
export async function executeOwnedStep(scope: NativeMigrationScope): Promise<ClosedStepReceipt> {
  const arity = arguments.length;
  const state = scopes.get(scope), prepared = ownedScopes.get(scope);
  if (!state || !prepared) fail("MIGRATION_OWNED_SCOPE_REQUIRED");
  // Consume preparation before the first await; a failed invocation never revives it.
  ownedScopes.delete(scope);
  // The closed dispatcher may read this internal binding, but it is never caller data.
  invocationOwned.set(scope, prepared);
  try {
    const c = state.claim;
    const typed = await withMigrationResources(async resources => {
      resources.file(prepared.artifacts);
      state.client.assertKnown(); assertDeadline(c);
      if (arity !== 1 || state.state !== "ready") fail("MIGRATION_OWNED_SCOPE_REQUIRED");
      const inputs = await prepared.artifacts.readStep(c);
      const source = await freshConnection(resources, prepared.credentials, false);
      await location(source, false);
      const expected = expectedSourceManifest(prepared.expected);
      const observe = () => readActualSourceFingerprint(source, { profileSelectionSha256: expected.profileSelectionSha256, maxRows: expected.maxRows });
      assertSameSourceFingerprint(expected, await observe());
      state.client.assertKnown(); assertDeadline(c);
      const target = await freshConnection(resources, prepared.credentials, true);
      let invocation: NativeMigrationInvocation;
      if (c.entry === "account-sync") invocation = { entry: c.entry, source, target, sourceSnapshot: inputs.source, profileSelection: inputs.profile ?? null };
      else {
        const journal = await resources.adoptMigrationJournal(await prepared.artifacts.reserveJournal(c), c);
        if (c.entry === "allocator-highwater") {
          const zero = completedZero.get(state.client);
          if (!zero || zero.runId !== c.runId || zero.planSha256 !== c.planSha256 || c.stepId !== "allocator" || zero.outputSha256 !== c.inputs.finalSyncReportSha256) fail("MIGRATION_OWNED_ZERO_RESULT_REQUIRED");
          const fence = await freshConnection(resources, prepared.credentials, true);
          invocation = { entry: c.entry, source, target, fence, sourceSnapshot: inputs.source, review: inputs.review, finalSyncReport: Buffer.from(zero.bytes), journal };
        } else invocation = { entry: c.entry, target, journal };
      }
      const result = await invokeNativeMigrationInternal(scope, invocation);
      // A changed source after any step (including activation) makes the run unknown.
      assertSameSourceFingerprint(expected, await observe());
      state.client.assertKnown(); assertDeadline(c);
      const allocator = c.stepId === "allocator" ? result as NativeAllocatorResult : null;
      const written = await prepared.artifacts.writeTypedOutput(c, canonicalBytes(allocator ? allocator.plan : result), allocator ? canonicalBytes(allocator.summary) : null);
      const bytes = canonicalBytes(written.report);
      const checked = validateMigrationTypedReport(c, bytes);
      if (checked.reportSha256 !== written.reportSha256 || checked.outputSha256 !== written.outputSha256) fail("MIGRATION_OWNED_OUTPUT_BINDING");
      return { bytes, output: checked.report.output };
    });
    // withMigrationResources has awaited every actual transport/file/parent close.
    state.client.assertKnown(); assertDeadline(state.claim);
    const receipt = Object.freeze(Object.create(null)) as ClosedStepReceipt;
    closedReceipts.set(receipt, { state, bytes: Buffer.from(typed.bytes), output: typed.output, consumed: false });
    return receipt;
  } catch (cause) {
    await state.client.noteUnknown(state);
    throw new NativeMigrationEntryError("MIGRATION_OWNED_EXECUTION_UNKNOWN", "unknown", cause);
  } finally { invocationOwned.delete(scope); }
}
const invocationOwned = new WeakMap<NativeMigrationScope, OwnedPreparation>();

// No instance or prototype shadowing can replace internal public compatibility
// methods (enter/assertKnown/noteUnknown) used by the closed trusted bridge.
Object.freeze(NativeMigrationAdmission.prototype);
