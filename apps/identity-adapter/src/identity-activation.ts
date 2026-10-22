import { assertAdmissionWriter } from "./identity-admission.js";
import type { Connection, PoolConnection, RowDataPacket } from "mysql2/promise";
import { allocatorDigest } from "./identity-allocator-manifest.js";
import { assertAllocatorReady, allocatorDatabase } from "./identity-allocator-state.js";
import { ORGANIZATION_RECONCILIATION_COMPILED_BUILD_REVISION } from "./generated/iam-organization-reconciliation-compiled-revision.js";

type Transaction = Connection | PoolConnection;
export class IdentityActivationError extends Error {
  constructor(readonly code: string) { super(code); this.name = "IdentityActivationError"; }
}
function fail(code: string): never { throw new IdentityActivationError(code); }
const sha256 = /^[a-f0-9]{64}$/;
const revision = /^[a-f0-9]{40}$/;
const utc = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/;
export function immutableIdentityRevision(): string {
  const value = ORGANIZATION_RECONCILIATION_COMPILED_BUILD_REVISION;
  if (typeof value !== "string" || !revision.test(value)) fail("ACTIVATION_COMPILED_REVISION_REQUIRED");
  return value!;
}
function iso(value: unknown): string {
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) fail("ACTIVATION_INVALID_RECEIPT");
  return (value as Date).toISOString();
}
export interface ActivationReceipt {
  allocatorManifestSha256: string;
  compiledRevision: string;
  requestSha256: string;
  decisionAt: string;
  deadline: string;
}
export interface ExplicitActivationStatus {
  authority: "staging" | "identity";
  state: "sealed" | "active";
  receipt: ActivationReceipt | null;
  allocatorManifestSha256: string | null;
}
export function activationRequestSha256(database: string, proof: string, compiledRevision: string, deadline: string) {
  return allocatorDigest({ version: 1, database, allocatorManifestSha256: proof, compiledRevision, deadline });
}
async function receipt(c: Transaction): Promise<ActivationReceipt | null> {
  let rows: RowDataPacket[];
  try {
    [rows] = await c.query<RowDataPacket[]>("SELECT id,allocator_manifest_sha256,compiled_revision,request_sha256,decision_at,deadline FROM identity_activation_receipt FOR SHARE");
  } catch (error) {
    if ((error as { code?: string }).code === "ER_NO_SUCH_TABLE") fail("ACTIVATION_SCHEMA_REQUIRED");
    throw error;
  }
  if (!rows.length) return null;
  if (rows.length !== 1 || Number(rows[0].id) !== 1) fail("ACTIVATION_INVALID_RECEIPT");
  const r = rows[0];
  if (!sha256.test(r.allocator_manifest_sha256) || !sha256.test(r.request_sha256) || !revision.test(r.compiled_revision)) fail("ACTIVATION_INVALID_RECEIPT");
  const result = { allocatorManifestSha256: r.allocator_manifest_sha256 as string, compiledRevision: r.compiled_revision as string,
    requestSha256: r.request_sha256 as string, decisionAt: iso(r.decision_at), deadline: iso(r.deadline) };
  if (result.decisionAt >= result.deadline || activationRequestSha256(await allocatorDatabase(c), result.allocatorManifestSha256,
    result.compiledRevision, result.deadline) !== result.requestSha256) fail("ACTIVATION_INVALID_RECEIPT");
  return result;
}
/** Caller owns the migration-control row lock; neither this nor inspection creates schema. */
export async function inspectExplicitActivationLocked(c: Transaction): Promise<ExplicitActivationStatus> {
  const [control] = await c.query<RowDataPacket[]>("SELECT id,authority,activated_at FROM identity_migration_control FOR UPDATE");
  if (control.length !== 1 || Number(control[0].id) !== 1 || !["staging", "identity"].includes(control[0].authority)) fail("ACTIVATION_INVALID_AUTHORITY");
  const r = await receipt(c);
  if (control[0].authority === "staging") {
    if (r !== null || control[0].activated_at !== null) fail("ACTIVATION_INCONSISTENT_RECEIPT");
    const [proof] = await c.query<RowDataPacket[]>("SELECT state,manifest_sha256 FROM identity_migration_allocator_state WHERE id=1");
    return { authority: "staging", state: "sealed", receipt: null,
      allocatorManifestSha256: proof[0]?.state === "ready" && sha256.test(proof[0].manifest_sha256) ? proof[0].manifest_sha256 : null };
  }
  if (!r || control[0].activated_at === null) fail("ACTIVATION_RECEIPT_REQUIRED");
  if (iso(control[0].activated_at) !== r.decisionAt) fail("ACTIVATION_INCONSISTENT_RECEIPT");
  const manifest = await assertAllocatorReady(c), proof = allocatorDigest(manifest);
  if (r.allocatorManifestSha256 !== proof) fail("ACTIVATION_PROOF_MISMATCH");
  // The receipt records the first activation's artifact. It does not prohibit later reviewed upgrades.
  return { authority: "identity", state: "active", receipt: r, allocatorManifestSha256: proof };
}
async function idle(c: Transaction) {
  // SET TRANSACTION rejects an already active transaction, before any implicit commit or mutation.
  await c.query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED");
  const [mode] = await c.query<RowDataPacket[]>("SELECT @@autocommit AS enabled");
  if (Number(mode[0]?.enabled) !== 1) fail("ACTIVATION_IDLE_CONNECTION_REQUIRED");
}
export async function inspectExplicitActivation(c: Transaction): Promise<ExplicitActivationStatus> {
  await idle(c); await c.beginTransaction();
  try { return await inspectExplicitActivationLocked(c); }
  finally { await c.rollback(); }
}
export interface ExplicitActivationOptions {
  connection: Connection;
  expectedProofSha256: string;
  expectedRevision: string;
  deadline: string;
  apply: boolean;
  /** Durable local intent must be synced before COMMIT is sent. A failure here remains cancellable. */
  onCommitIntent?: (intent: ActivationReceipt) => Promise<void>;
}
export interface ExplicitActivationResult {
  outcome: "dry_run" | "activated" | "already_active" | "unknown";
  authority: "staging" | "identity" | "unknown";
  receipt: ActivationReceipt;
  /** Host wall-clock observation of acknowledgement only; not the database commit time. */
  acknowledgementAfterDeadline?: boolean;
  errorCode?: "ACTIVATION_COMMIT_RESULT_UNKNOWN";
}
/** Private-only operation. No source DB, automatic retry, schema creation or downgrade path. */
export async function activateExplicitIdentity(options: ExplicitActivationOptions): Promise<ExplicitActivationResult> {
  assertAdmissionWriter(options.apply ? "activation-apply" : "activation-read");
  const { connection: c } = options;
  const compiledRevision = immutableIdentityRevision();
  if (!revision.test(options.expectedRevision) || options.expectedRevision !== compiledRevision) fail("ACTIVATION_REVISION_MISMATCH");
  if (!sha256.test(options.expectedProofSha256)) fail("ACTIVATION_INVALID_PROOF");
  const deadline = new Date(options.deadline);
  if (!utc.test(options.deadline) || !Number.isFinite(deadline.getTime()) || deadline.toISOString() !== options.deadline) fail("ACTIVATION_INVALID_DEADLINE");
  await idle(c); await c.beginTransaction();
  let commitSent = false, committed = false;
  let intent: ActivationReceipt | undefined;
  try {
    const state = await inspectExplicitActivationLocked(c);
    const manifest = await assertAllocatorReady(c), proof = allocatorDigest(manifest);
    if (proof !== options.expectedProofSha256) fail("ACTIVATION_PROOF_MISMATCH");
    const requestSha256 = activationRequestSha256(await allocatorDatabase(c), proof, compiledRevision, options.deadline);
    if (state.authority === "identity") {
      if (state.receipt!.requestSha256 !== requestSha256) fail("ACTIVATION_ALREADY_ACTIVE_DIFFERENT_REQUEST");
      return { outcome: "already_active", authority: "identity", receipt: state.receipt! };
    }
    const [clock] = await c.query<RowDataPacket[]>("SELECT UTC_TIMESTAMP(3) AS now");
    const now = clock[0]?.now;
    if (!(now instanceof Date) || now >= deadline) fail("ACTIVATION_DEADLINE_EXPIRED");
    if (deadline.getTime() - now.getTime() > 300_000) fail("ACTIVATION_DEADLINE_TOO_DISTANT");
    intent = { allocatorManifestSha256: proof, compiledRevision, deadline: options.deadline, decisionAt: now.toISOString(),
      requestSha256 };
    if (!options.apply) return { outcome: "dry_run", authority: "staging", receipt: intent };
    await c.execute("INSERT INTO identity_activation_receipt(id,allocator_manifest_sha256,compiled_revision,request_sha256,decision_at,deadline) VALUES(1,?,?,?,?,?)",
      [proof, compiledRevision, intent.requestSha256, now, deadline]);
    const [updated] = await c.execute<import("mysql2/promise").ResultSetHeader>(
      "UPDATE identity_migration_control SET authority='identity',activated_at=? WHERE id=1 AND authority='staging' AND UTC_TIMESTAMP(3) < ?", [now, deadline]);
    if (updated.affectedRows !== 1) fail("ACTIVATION_DEADLINE_EXPIRED");
    await options.onCommitIntent?.(intent);
    const [beforeCommit] = await c.query<RowDataPacket[]>("SELECT UTC_TIMESTAMP(3) AS now");
    if (!(beforeCommit[0]?.now instanceof Date) || beforeCommit[0].now >= deadline) fail("ACTIVATION_DEADLINE_EXPIRED");
    commitSent = true;
    try { await c.commit(); committed = true; }
    catch {
      // COMMIT may already be durable. Closing the connection is not proof of cancellation.
      c.destroy();
      return { outcome: "unknown", authority: "unknown", receipt: intent, errorCode: "ACTIVATION_COMMIT_RESULT_UNKNOWN" };
    }
    return { outcome: "activated", authority: "identity", receipt: intent, acknowledgementAfterDeadline: Date.now() >= deadline.getTime() };
  } finally {
    if (!commitSent && !committed) await c.rollback();
  }
}
