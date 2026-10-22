import fs from "node:fs/promises";
import { constants } from "node:fs";
import { dirname, join } from "node:path";
import { isProxy } from "node:util/types";
import {
  canonicalMigrationJson as canonical,
  exactMigrationObject as exact,
  freezeMigration as freeze,
  migrationBytesDigest as bytesDigest,
  migrationDigest as digest,
  migrationEntries,
  migrationFailure as fail,
  migrationHash as hash,
  migrationInteger as integer,
  migrationTarget,
  migrationTime as time,
  parseMigrationPlan,
} from "./migration-plan.mjs";

/** Fixed future Linux launcher layout. No caller-selected path, command or environment. */
export const migrationArtifactLayout = freeze({
  code: "/opt/xrugc/identity",
  inputs: "/run/xrugc/identity-finalization/inputs",
  reports: "/run/xrugc/identity-finalization/reports",
  revision: "GIT_COMMIT",
  plan: "migration-plan.json",
  source: "source-snapshot.json",
  profile: "profile-selection.json",
  review: "allocator-review.json",
});
export const migrationArtifactBounds = freeze({
  plan: 16384,
  revision: 41,
  entry: 1024 * 1024,
  source: 16 * 1024 * 1024,
  profile: 2 * 1024 * 1024,
  review: 65536,
  report: 65536,
});
export const migrationJournalBounds = freeze({
  recordBytes: 4096,
  bytes: 256 * 1024,
  records: 64,
  pending: 16,
});
const uid = () => {
  const value = process.getuid?.();
  if (!Number.isSafeInteger(value)) fail("MIGRATION_POSIX_UID_REQUIRED");
  return value;
};
const identity = (s) => `${s.dev}:${s.ino}`;
const metadata = (s) =>
  [s.dev, s.ino, s.size, s.mode, s.uid, s.nlink, s.mtimeMs, s.ctimeMs].join(":");
const sameIdentity = (a, b) => identity(a) === identity(b);
const trustedOwner = (s) => s.uid === 0 || s.uid === uid();
function directory(s) {
  if (!s.isDirectory() || !trustedOwner(s) || (s.mode & 0o022) !== 0)
    fail("MIGRATION_UNTRUSTED_ANCESTOR");
}
function regular(s, protectedInput, max) {
  if (
    !s.isFile() || s.nlink !== 1 ||
    (protectedInput ? s.uid !== uid() || (s.mode & 0o7777) !== 0o600
      : !trustedOwner(s) || (s.mode & 0o7022) !== 0) ||
    !Number.isSafeInteger(s.size) || s.size < 1 || s.size > max
  ) fail("MIGRATION_UNTRUSTED_FILE");
}
const flags = constants.O_RDONLY | constants.O_NOFOLLOW;

// Brands are deliberately local to this packaged module instance. The Native
// owner must import this actual module, not copy its implementation or accept a
// structural FileHandle supplied by its caller.
const journalReservations = new WeakMap();
const journalOwners = new WeakMap();
function journalFailure(record, cause) {
  record.failure ??= Object.assign(new Error("MIGRATION_JOURNAL_IO_UNKNOWN", { cause }), {
    safeCode: "MIGRATION_JOURNAL_IO_UNKNOWN",
    outcome: "unknown",
    automaticRetry: false,
  });
  if (record.session) record.session.unknown = true;
  return record.failure;
}
function safeDataCopy(value, seen = new Set(), depth = 0) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (depth > 32 || !value || typeof value !== "object" || isProxy(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value)) || seen.has(value))
    fail("MIGRATION_ARTIFACT_DATA_REQUIRED");
  const descriptors = Object.getOwnPropertyDescriptors(value), result = Object.create(null);
  seen.add(value);
  for (const key of Reflect.ownKeys(descriptors)) {
    const descriptor = descriptors[key];
    if (typeof key !== "string" || !descriptor.enumerable || !("value" in descriptor))
      fail("MIGRATION_ARTIFACT_DATA_REQUIRED");
    result[key] = safeDataCopy(descriptor.value, seen, depth + 1);
  }
  seen.delete(value);
  return result;
}
function journalRegular(s) {
  if (!s.isFile() || s.nlink !== 1 || s.uid !== uid() || (s.mode & 0o7777) !== 0o600 ||
      !Number.isSafeInteger(s.size) || s.size < 0 || s.size > migrationJournalBounds.bytes)
    fail("MIGRATION_UNTRUSTED_JOURNAL");
}
async function checkJournal(record) {
  for (const ancestor of record.ancestors) {
    const [named, held] = await Promise.all([fs.lstat(ancestor.path), ancestor.handle.stat()]);
    directory(named); directory(held);
    if (!sameIdentity(named, ancestor.stat) || !sameIdentity(held, ancestor.stat))
      fail("MIGRATION_JOURNAL_REPLACED");
  }
  const [named, held] = await Promise.all([fs.lstat(record.path), record.file.stat()]);
  journalRegular(named); journalRegular(held);
  if (metadata(named) !== metadata(record.stat) || metadata(held) !== metadata(record.stat) || held.size !== record.expected.length)
    fail("MIGRATION_JOURNAL_REPLACED");
}
async function journalReadback(record) {
  const bytes = Buffer.alloc(record.expected.length + 1);
  let offset = 0;
  while (offset < bytes.length) {
    const { bytesRead } = await record.file.read(bytes, offset, bytes.length - offset, offset);
    if (bytesRead === 0) break;
    offset += bytesRead;
  }
  if (offset !== record.expected.length || !bytes.subarray(0, offset).equals(record.expected))
    fail("MIGRATION_JOURNAL_BYTES_UNKNOWN");
}
async function flushJournal(record) {
  await checkJournal(record);
  await journalReadback(record);
  await record.file.sync();
  await record.ancestors.at(-1).handle.sync();
  await checkJournal(record);
  await journalReadback(record);
  return freeze({ bytes: record.expected.length, records: record.records, sha256: bytesDigest(record.expected) });
}
function ownedJournal(token) {
  const record = journalOwners.get(token);
  if (!record) fail("MIGRATION_OWNED_JOURNAL_REQUIRED");
  return record;
}
function queueJournal(record, work) {
  if (record.closing || record.state !== "owned") fail("MIGRATION_JOURNAL_CLOSED");
  if (record.failure) throw record.failure;
  if (record.pending >= migrationJournalBounds.pending)
    throw journalFailure(record, new Error("MIGRATION_JOURNAL_BACKLOG_BOUND"));
  record.pending++;
  const operation = record.tail.then(async () => {
    if (record.failure) throw record.failure;
    try {
      const result = await work();
      if (record.failure) throw record.failure;
      return result;
    }
    catch (cause) { throw journalFailure(record, cause); }
  }).finally(() => record.pending--);
  record.tail = operation.catch(() => {});
  return operation;
}
function journalEvent(record, bytes) {
  const event = nativeJson(bytes), claim = record.claim;
  if (claim.stepId === "allocator") {
    exact(event, ["table", "phase", "floor", "at"]);
    const index = allocatorTables.indexOf(event.table);
    if (index < 0 || !["intent", "success"].includes(event.phase) || allocatorInteger(event.floor) < 1n ||
        time(event.at) < time(record.startedAt) || time(event.at) >= time(claim.deadline))
      fail("MIGRATION_JOURNAL_EVENT_BINDING");
    if (event.phase === "intent") {
      if (record.intent !== null || index <= record.tableIndex) fail("MIGRATION_JOURNAL_EVENT_ORDER");
    } else if (record.intent?.table !== event.table || record.intent.floor !== event.floor)
      fail("MIGRATION_JOURNAL_EVENT_ORDER");
  } else {
    exact(event, ["phase", "receipt"]);
    if (event.phase !== "commit_intent" || record.records !== 0) fail("MIGRATION_JOURNAL_EVENT_ORDER");
    const receipt = activationOutput({ outcome: "already_active", authority: "identity", receipt: event.receipt }, claim);
    if (time(receipt.decisionAt) < time(record.startedAt)) fail("MIGRATION_JOURNAL_EVENT_BINDING");
  }
  return event;
}

/** Single-use ownership transfer; no path, fd integer, callback or cleanup flag. */
export function consumeMigrationJournalLease(lease, suppliedClaim) {
  const record = journalReservations.get(lease);
  if (!record) fail("MIGRATION_JOURNAL_LEASE_REQUIRED");
  if (record.state !== "reserved" || record.closing) fail("MIGRATION_JOURNAL_LEASE_ALREADY_CONSUMED_OR_CLOSED");
  if (record.session.closed || record.session.unknown) fail("MIGRATION_ARTIFACT_SESSION_CLOSED");
  const claim = safeDataCopy(suppliedClaim);
  if (canonical(claim) !== canonical(record.claim)) fail("MIGRATION_JOURNAL_CLAIM_MISMATCH");
  const owner = Object.freeze(Object.create(null));
  record.state = "owned";
  journalOwners.set(owner, record);
  return owner;
}

/** Appends exactly one typed Native event. Durability is completed by sync. */
export function appendMigrationJournal(owner, suppliedBytes) {
  const record = ownedJournal(owner);
  if (record.closing || record.state !== "owned") fail("MIGRATION_JOURNAL_CLOSED");
  if (record.failure) throw record.failure;
  if (!Buffer.isBuffer(suppliedBytes) || isProxy(suppliedBytes) || suppliedBytes.length < 2 || suppliedBytes.length > migrationJournalBounds.recordBytes)
    throw journalFailure(record, new Error("MIGRATION_JOURNAL_RECORD_BOUND"));
  const bytes = Buffer.from(suppliedBytes);
  return queueJournal(record, async () => {
    await checkJournal(record);
    const event = journalEvent(record, bytes);
    const encoded = Buffer.from(canonical({ version: 1, runId: record.claim.runId, claimId: record.claim.claimId,
      stepId: record.claim.stepId, planSha256: record.claim.planSha256, inputSha256: record.claim.inputSha256,
      sequence: record.records + 1, event }) + "\n");
    if (encoded.length > migrationJournalBounds.recordBytes || record.records >= migrationJournalBounds.records ||
        record.expected.length + encoded.length > migrationJournalBounds.bytes)
      fail("MIGRATION_JOURNAL_RECORD_BOUND");
    let offset = 0;
    while (offset < encoded.length) {
      const { bytesWritten } = await record.file.write(encoded, offset, encoded.length - offset, record.expected.length + offset);
      if (bytesWritten < 1) fail("MIGRATION_JOURNAL_WRITE_UNKNOWN");
      offset += bytesWritten;
    }
    record.expected = Buffer.concat([record.expected, encoded]);
    record.stat = await record.file.stat();
    await checkJournal(record);
    await journalReadback(record);
    record.records++;
    if (record.claim.stepId === "allocator") {
      record.tableIndex = allocatorTables.indexOf(event.table);
      record.intent = event.phase === "intent" ? { table: event.table, floor: event.floor } : null;
    }
  });
}
export function syncMigrationJournal(owner) {
  const record = ownedJournal(owner);
  return queueJournal(record, () => flushJournal(record));
}
function closeJournalRecord(record) {
  if (record.closePromise) return record.closePromise;
  record.closing = true;
  record.closePromise = (async () => {
    await record.tail;
    let summary;
    try {
      if (!record.failure) summary = await flushJournal(record);
      if (!record.failure && record.intent !== null)
        journalFailure(record, new Error("MIGRATION_JOURNAL_INCOMPLETE_INTENT"));
    } catch (cause) { journalFailure(record, cause); }
    const results = await Promise.allSettled([record.file, ...record.ancestors.map((a) => a.handle)].map((handle) => handle.close()));
    if (results.some((r) => r.status === "rejected"))
      journalFailure(record, new AggregateError(results.filter((r) => r.status === "rejected").map((r) => r.reason), "MIGRATION_JOURNAL_CLOSE_UNKNOWN"));
    record.state = "closed";
    if (record.failure) throw record.failure;
    return summary;
  })();
  return record.closePromise;
}
/** Always attempts all actual closes, including after a partial write/failed sync. */
export function closeMigrationJournal(owner) { return closeJournalRecord(ownedJournal(owner)); }

async function reserveFixedJournal(claim, plan, session) {
  const path = join(migrationArtifactLayout.reports, claim.stepId + ".journal.jsonl");
  const ancestors = await holdAncestors(path);
  let file;
  try {
    file = await fs.open(path, constants.O_RDWR | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    const stat = await file.stat(); journalRegular(stat);
    if (stat.size !== 0) fail("MIGRATION_UNTRUSTED_JOURNAL");
    const record = { path, ancestors, file, stat, claim, session, startedAt: plan.window.startedAt,
      state: "reserved", closing: false, failure: null, closePromise: null, tail: Promise.resolve(), pending: 0,
      expected: Buffer.alloc(0), records: 0, intent: null, tableIndex: -1 };
    await flushJournal(record);
    return record;
  } catch (cause) {
    try { await closeAll([...(file ? [file] : []), ...ancestors.map((a) => a.handle)]); }
    catch (closeError) { throw journalFailure({ failure: null, session }, new AggregateError([cause, closeError], "MIGRATION_JOURNAL_RESERVE_UNKNOWN")); }
    if (file) throw journalFailure({ failure: null, session }, cause);
    throw cause;
  }
}
async function closeAll(handles) {
  const results = await Promise.allSettled(handles.map((h) => h.close()));
  if (results.some((r) => r.status === "rejected"))
    fail("MIGRATION_ARTIFACT_CLOSE_UNKNOWN");
}

/**
 * Holds directory and leaf FDs, reads those FDs, and detects persistent pathname
 * replacement and same-inode modification. Node provides no openat(2) walk: these
 * checks do NOT defeat an actively malicious trusted owner doing rename/ABA.
 * A real launcher must pin a read-only OCI code mount (including dependencies),
 * isolate private input/report mounts and owners, and supply an openat2/dirfd
 * boundary before claiming resistance to that adversary. This module executes
 * nothing and never hands a validated pathname to a Native CLI to reopen.
 */
class HeldFile {
  constructor(path, handle, before, ancestors, max, protectedInput, expected) {
    Object.assign(this, { path, handle, before, ancestors, max, protectedInput, expected });
  }
  async check() {
    for (const a of this.ancestors) {
      const [named, held] = await Promise.all([fs.lstat(a.path), a.handle.stat()]);
      directory(named); directory(held);
      if (!sameIdentity(named, a.stat) || !sameIdentity(held, a.stat))
        fail("MIGRATION_ARTIFACT_REPLACED");
    }
    const [named, held] = await Promise.all([fs.lstat(this.path), this.handle.stat()]);
    regular(named, this.protectedInput, this.max);
    regular(held, this.protectedInput, this.max);
    if (metadata(named) !== metadata(this.before) || metadata(held) !== metadata(this.before))
      fail("MIGRATION_ARTIFACT_REPLACED");
  }
  async read() {
    await this.check();
    // Never readFile(path) or re-open the name. Bound allocation even if a writer
    // grows the inode while read is in flight; the trailing byte detects growth.
    const result = Buffer.alloc(this.before.size + 1);
    let offset = 0;
    while (offset < result.length) {
      const { bytesRead } = await this.handle.read(result, offset, result.length - offset, offset);
      if (bytesRead === 0) break;
      offset += bytesRead;
    }
    await this.check();
    if (offset !== this.before.size) fail("MIGRATION_ARTIFACT_LENGTH_CHANGED");
    const bytes = result.subarray(0, offset);
    if (this.expected !== undefined && bytesDigest(bytes) !== this.expected)
      fail("MIGRATION_ARTIFACT_HASH_MISMATCH");
    return Buffer.from(bytes);
  }
  async close() { await closeAll([this.handle, ...this.ancestors.map((a) => a.handle)]); }
}
async function holdAncestors(path) {
  const names = [];
  for (let p = dirname(path); ; p = dirname(p)) {
    names.unshift(p);
    if (p === "/") break;
  }
  const held = [];
  try {
    for (const path of names) {
      const before = await fs.lstat(path);
      directory(before);
      const handle = await fs.open(path, flags | constants.O_DIRECTORY);
      held.push({ path, handle, stat: before });
      const after = await handle.stat(); directory(after);
      if (!sameIdentity(before, after)) fail("MIGRATION_ARTIFACT_REPLACED");
    }
    return held;
  } catch (error) {
    try { await closeAll(held.map((a) => a.handle)); }
    catch (closeError) { throw new AggregateError([error, closeError], "MIGRATION_ARTIFACT_OPEN_UNKNOWN"); }
    throw error;
  }
}
async function holdFile(path, max, protectedInput, expected) {
  const ancestors = await holdAncestors(path);
  let handle;
  try {
    const before = await fs.lstat(path);
    regular(before, protectedInput, max);
    handle = await fs.open(path, flags);
    const file = new HeldFile(path, handle, before, ancestors, max, protectedInput, expected);
    await file.read();
    return file;
  } catch (error) {
    try { await closeAll([...(handle ? [handle] : []), ...ancestors.map((a) => a.handle)]); }
    catch (closeError) { throw new AggregateError([error, closeError], "MIGRATION_ARTIFACT_OPEN_UNKNOWN"); }
    throw error;
  }
}
function nativeJson(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 2 || bytes.length > migrationArtifactBounds.report ||
      !Buffer.from(bytes.toString("utf8")).equals(bytes)) fail("MIGRATION_NATIVE_REPORT_BOUND");
  const text = bytes.toString("utf8");
  let depth = 0, quoted = false, escaped = false;
  for (const character of text) {
    if (quoted) {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === '"') quoted = false;
    } else if (character === '"') quoted = true;
    else if (character === "{" || character === "[") {
      if (++depth > 64) fail("MIGRATION_NATIVE_REPORT_DEPTH");
    } else if (character === "}" || character === "]") depth--;
  }
  let value;
  try { value = JSON.parse(text); }
  catch { fail("MIGRATION_NATIVE_REPORT_INVALID"); }
  // Actual Native writer uses compact JSON or indentation 2, each with one LF.
  // Re-encoding also rejects duplicate keys, trailing records and exotic values.
  if (![JSON.stringify(value) + "\n", JSON.stringify(value, null, 2) + "\n", canonical(value) + "\n"].includes(text))
    fail("MIGRATION_NATIVE_REPORT_ENCODING");
  return value;
}
const syncKeys = ["applied", "changes", "inserts", "updates", "deletions", "affectedSubjects", "tableChanges"];
const tables = new Set("user user_info auth_rule auth_item auth_item_child auth_assignment organization user_organization wechat invitation_record invitation identity_profile_avatars identity_legacy_profile_rows".split(" "));
function syncOutput(value, claim) {
  exact(value, syncKeys);
  if (value.applied !== (claim.stepId === "sync-apply")) fail("MIGRATION_SYNC_MODE_MISMATCH");
  const { maxChanges, maxRows } = claim.inputs.limits;
  for (const key of syncKeys.slice(1, 5)) integer(value[key], 0, maxChanges);
  integer(value.affectedSubjects, 0, 2 * maxRows);
  if (value.changes !== value.inserts + value.updates + value.deletions ||
      !value.tableChanges || typeof value.tableChanges !== "object" || Array.isArray(value.tableChanges))
    fail("MIGRATION_SYNC_COUNTS");
  let count = 0;
  for (const [table, n] of Object.entries(value.tableChanges)) {
    if (!tables.has(table)) fail("MIGRATION_SYNC_COUNTS");
    integer(n, 1, maxChanges); count += n;
  }
  if (count !== value.changes || (claim.stepId === "sync-zero" &&
      (value.changes !== 0 || value.affectedSubjects !== 0 || Object.keys(value.tableChanges).length)))
    fail("MIGRATION_ZERO_SYNC_REQUIRED");
  return value;
}
const allocatorTables = ["user", "user_info", "organization", "wechat", "invitation_record", "invitation"];
function allocatorInteger(value) {
  if (typeof value !== "string" || !/^(?:0|[1-9][0-9]{0,15})$/.test(value) || BigInt(value) > BigInt(Number.MAX_SAFE_INTEGER))
    fail("MIGRATION_ALLOCATOR_FLOOR");
  return BigInt(value);
}
function allocatorOutput(plan, summary, claim) {
  exact(plan, ["manifest", "manifestSha256", "sourceMetadataSha256", "targetSchemaSha256", "sourceStateSha256"]);
  for (const key of ["manifestSha256", "sourceMetadataSha256", "targetSchemaSha256", "sourceStateSha256"]) hash(plan[key]);
  const m = plan.manifest;
  exact(m, ["version", "kind", "targetDatabase", "capturedAt", "source", "drain", "baseline", "floors"]);
  if (m.version !== 1 || m.kind !== "migrated" || m.targetDatabase !== migrationTarget.database || digest(m) !== plan.manifestSha256)
    fail("MIGRATION_ALLOCATOR_MANIFEST");
  time(m.capturedAt);
  exact(m.source, ["database", "host", "port", "serverUuid"]);
  if (m.source.database !== "bujiaban_development" || m.source.host !== migrationTarget.host || m.source.port !== "3306" ||
      typeof m.source.serverUuid !== "string" || !/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(m.source.serverUuid))
    fail("MIGRATION_ALLOCATOR_SOURCE");
  exact(m.drain, ["reviewSha256", "writersDrainedAt", "finalSyncSha256"]);
  if (m.drain.reviewSha256 !== claim.inputs.reviewSha256 || m.drain.finalSyncSha256 !== claim.inputs.finalSyncReportSha256 ||
      time(m.drain.writersDrainedAt) > time(m.capturedAt)) fail("MIGRATION_ALLOCATOR_RESULT_BINDING");
  exact(m.baseline, ["importKey", "referenceReviewSha256"]);
  if (typeof m.baseline.importKey !== "string" || !/^[A-Za-z0-9_.:-]{1,160}$/.test(m.baseline.importKey))
    fail("MIGRATION_ALLOCATOR_BASELINE");
  hash(m.baseline.referenceReviewSha256);
  exact(m.floors, allocatorTables);
  for (const table of allocatorTables) {
    const f = m.floors[table]; exact(f, ["floor", "capacity", "sourceNext", "reservedMax"]);
    const floor = allocatorInteger(f.floor), cap = allocatorInteger(f.capacity), reserved = allocatorInteger(f.reservedMax), next = allocatorInteger(f.sourceNext);
    if (floor < 1n || floor <= reserved || floor > cap || next < 1n || next > floor || (table === "user" && cap > 2147483647n))
      fail("MIGRATION_ALLOCATOR_FLOOR");
  }
  exact(summary, ["success", "applied", "ready", "manifestSha256", "tables", "authorityActivated", "sourceWritten"]);
  if (summary.success !== true || summary.applied !== true || summary.ready !== true || summary.tables !== 6 ||
      summary.authorityActivated !== false || summary.sourceWritten !== false || summary.manifestSha256 !== plan.manifestSha256)
    fail("MIGRATION_ALLOCATOR_SUMMARY");
  return {
    allocatorManifestSha256: plan.manifestSha256,
    sourceSnapshotSha256: claim.inputs.sourceSnapshotSha256,
    finalSyncReportSha256: m.drain.finalSyncSha256,
    reviewSha256: m.drain.reviewSha256,
    authority: "staging",
    state: "ready",
  };
}
function activationOutput(result, claim) {
  const keys = ["outcome", "authority", "receipt"];
  if (result?.outcome === "activated") keys.push("acknowledgementAfterDeadline");
  exact(result, keys);
  if (!["activated", "already_active"].includes(result.outcome) || result.authority !== "identity" ||
      (result.outcome === "activated" && result.acknowledgementAfterDeadline !== false))
    fail("MIGRATION_ACTUAL_RECEIPT_REQUIRED");
  const r = result.receipt;
  exact(r, ["allocatorManifestSha256", "compiledRevision", "requestSha256", "decisionAt", "deadline"]);
  if (r.allocatorManifestSha256 !== claim.inputs.expectedProofSha256 || r.compiledRevision !== claim.compiledRevision ||
      r.compiledRevision !== claim.inputs.expectedRevision || r.requestSha256 !== claim.inputs.requestSha256 ||
      r.deadline !== claim.deadline || r.deadline !== claim.inputs.deadline || time(r.decisionAt) >= time(r.deadline) ||
      digest({ version: 1, database: migrationTarget.database, allocatorManifestSha256: r.allocatorManifestSha256,
        compiledRevision: r.compiledRevision, deadline: r.deadline }) !== r.requestSha256)
    fail("MIGRATION_ACTUAL_RECEIPT_BINDING");
  return r;
}
const claimKeys = ["version", "runId", "planSha256", "epoch", "drainSha256", "compiledRevision", "imageDigest", "executor", "target", "deadline", "stepId", "claimId", "entry", "entrypoint", "entrySha256", "mode", "inputs", "inputSha256", "previousChainSha256"];

/** Pure completion-wire validation, using an already authenticated ledger claim.
 * This grants no scope and proves neither execution nor resource cleanup. Only
 * the fixed Native owned executor's closed-receipt API may submit these bytes.
 */
export function validateMigrationTypedReport(suppliedClaim, suppliedBytes) {
  const claim = safeDataCopy(suppliedClaim);
  exact(claim, claimKeys);
  if (claim.version !== 1 || !["sync-apply", "sync-zero", "allocator", "activation"].includes(claim.stepId) ||
      canonical(claim.target) !== canonical(migrationTarget) || digest(claim.inputs) !== claim.inputSha256)
    fail("MIGRATION_TYPED_REPORT_CLAIM_REQUIRED");
  if (!Buffer.isBuffer(suppliedBytes) || isProxy(suppliedBytes) || suppliedBytes.length < 2 ||
      suppliedBytes.length > migrationArtifactBounds.report) fail("MIGRATION_NATIVE_REPORT_BOUND");
  const bytes = Buffer.from(suppliedBytes), report = nativeJson(bytes);
  if (!Buffer.from(canonical(report) + "\n").equals(bytes)) fail("MIGRATION_TYPED_REPORT_CANONICAL_REQUIRED");
  exact(report, ["version", "kind", "runId", "claimId", "stepId", "planSha256", "inputSha256",
    "nativeReportSha256", "nativeSummarySha256", "nativeReport", "nativeSummary", "output"]);
  if (report.version !== 1 || report.kind !== "identity-native-typed-output" ||
      ["runId", "claimId", "stepId", "planSha256", "inputSha256"].some(k => report[k] !== claim[k]))
    fail("MIGRATION_TYPED_REPORT_BINDING");
  // The dedicated owned executor uses one canonical encoding for original
  // Native results. Other legacy CLI encodings are not completion-wire inputs.
  if (report.nativeReportSha256 !== bytesDigest(Buffer.from(canonical(report.nativeReport) + "\n")))
    fail("MIGRATION_TYPED_REPORT_NATIVE_HASH");
  let output;
  if (claim.stepId === "allocator") {
    if (report.nativeSummary === null || report.nativeSummarySha256 !== bytesDigest(Buffer.from(canonical(report.nativeSummary) + "\n")))
      fail("MIGRATION_TYPED_REPORT_NATIVE_HASH");
    output = allocatorOutput(report.nativeReport, report.nativeSummary, claim);
  } else {
    if (report.nativeSummary !== null || report.nativeSummarySha256 !== null)
      fail("MIGRATION_TYPED_REPORT_SUMMARY_FORBIDDEN");
    output = claim.stepId === "activation" ? activationOutput(report.nativeReport, claim) : syncOutput(report.nativeReport, claim);
  }
  if (canonical(output) !== canonical(report.output)) fail("MIGRATION_TYPED_REPORT_OUTPUT_MISMATCH");
  return freeze({ report, reportSha256: bytesDigest(bytes), outputSha256: bytesDigest(Buffer.from(canonical(output) + "\n")) });
}

function validateClaim(claim, plan, planSha) {
  exact(claim, claimKeys);
  const step = plan.steps.find((s) => s.id === claim.stepId);
  if (!step || claim.version !== 1 || claim.planSha256 !== planSha || claim.epoch !== plan.epoch ||
      claim.drainSha256 !== plan.drainSha256 || claim.compiledRevision !== plan.compiledRevision || claim.imageDigest !== plan.imageDigest ||
      canonical(claim.executor) !== canonical(plan.executor) || canonical(claim.target) !== canonical(plan.target) ||
      claim.deadline !== plan.window.deadline || claim.entry !== step.entry || claim.entrypoint !== migrationEntries[step.entry] ||
      claim.entrySha256 !== step.entrySha256 || claim.mode !== step.mode || claim.inputSha256 !== digest(claim.inputs) ||
      ![claim.runId, claim.claimId].every((v) => typeof v === "string" && /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(v)))
    fail("MIGRATION_ARTIFACT_CLAIM_BINDING");
  hash(claim.previousChainSha256);
  if (["sync-apply", "sync-zero"].includes(claim.stepId)) {
    exact(claim.inputs, ["sourceSnapshotSha256", "profileSelectionSha256", "limits", "apply"]);
    if (claim.inputs.sourceSnapshotSha256 !== plan.inputs.sourceSnapshotSha256 || claim.inputs.profileSelectionSha256 !== plan.inputs.profileSelectionSha256 ||
        canonical(claim.inputs.limits) !== canonical(plan.limits) || claim.inputs.apply !== (claim.mode === "apply"))
      fail("MIGRATION_ARTIFACT_CLAIM_BINDING");
  } else if (claim.stepId === "allocator") {
    exact(claim.inputs, ["reviewSha256", "finalSyncReportSha256", "sourceSnapshotSha256"]);
    if (claim.inputs.reviewSha256 !== plan.inputs.allocatorReviewSha256 || claim.inputs.sourceSnapshotSha256 !== plan.inputs.sourceSnapshotSha256)
      fail("MIGRATION_ARTIFACT_CLAIM_BINDING");
    hash(claim.inputs.finalSyncReportSha256);
  } else {
    exact(claim.inputs, ["expectedProofSha256", "expectedRevision", "deadline", "requestSha256"]);
    hash(claim.inputs.expectedProofSha256); hash(claim.inputs.requestSha256);
    if (claim.inputs.expectedRevision !== plan.compiledRevision || claim.inputs.deadline !== plan.window.deadline)
      fail("MIGRATION_ARTIFACT_CLAIM_BINDING");
  }
  return step;
}

/**
 * Loads bytes from fixed anchored FDs. This is NOT a migration executor or an
 * admission capability. No stdout, exit code or caller digest is completion.
 * The report produced below deliberately lacks sideEffectsFinished/connectionsClosed:
 * only a future authenticated in-process bridge that awaited Native resource
 * cleanup may construct the ledger's completed envelope from this typed output.
 */
export async function openMigrationArtifacts(binding) {
  exact(binding, ["planSha256", "compiledRevision", "imageDigest"]);
  binding = freeze(JSON.parse(canonical(binding)));
  hash(binding.planSha256);
  if (typeof binding.compiledRevision !== "string" || !/^[a-f0-9]{40}$/.test(binding.compiledRevision) ||
      typeof binding.imageDigest !== "string" || !/^sha256:[a-f0-9]{64}$/.test(binding.imageDigest))
    fail("MIGRATION_BUILD_BINDING");
  const held = new Map();
  const session = { closed: false, unknown: false }, journals = new Set(), reservations = new Set();
  let closePromise;
  const assertOpen = () => {
    if (session.closed || session.unknown) fail("MIGRATION_ARTIFACT_SESSION_CLOSED");
  };
  const load = async (key, root, name, max, protectedInput, expected) => {
    const file = await holdFile(join(root, name), max, protectedInput, expected);
    held.set(key, file); return file;
  };
  try {
    const planFile = await load("plan", migrationArtifactLayout.inputs, migrationArtifactLayout.plan, migrationArtifactBounds.plan, true, binding.planSha256);
    const { plan, planSha256 } = parseMigrationPlan(await planFile.read());
    if (plan.compiledRevision !== binding.compiledRevision || plan.imageDigest !== binding.imageDigest) fail("MIGRATION_BUILD_BINDING");
    const rev = await load("revision", migrationArtifactLayout.code, migrationArtifactLayout.revision, migrationArtifactBounds.revision, false,
      bytesDigest(Buffer.from(binding.compiledRevision + "\n")));
    if ((await rev.read()).toString("utf8") !== binding.compiledRevision + "\n") fail("MIGRATION_BUILD_BINDING");
    for (const entry of Object.keys(migrationEntries))
      await load(entry, migrationArtifactLayout.code, migrationEntries[entry], migrationArtifactBounds.entry, false, plan.steps.find((s) => s.entry === entry).entrySha256);
    await load("source", migrationArtifactLayout.inputs, migrationArtifactLayout.source, migrationArtifactBounds.source, true, plan.inputs.sourceSnapshotSha256);
    await load("review", migrationArtifactLayout.inputs, migrationArtifactLayout.review, migrationArtifactBounds.review, true, plan.inputs.allocatorReviewSha256);
    if (plan.inputs.profileSelectionSha256 !== null)
      await load("profile", migrationArtifactLayout.inputs, migrationArtifactLayout.profile, migrationArtifactBounds.profile, true, plan.inputs.profileSelectionSha256);
    return Object.freeze({
      plan,
      planSha256,
      async readPreparedInputs(...args) {
        assertOpen();
        if (args.length !== 0) fail("MIGRATION_PREPARED_INPUTS_NO_ARGUMENTS");
        const inputs = {};
        try {
          // Pre-claim observation must verify the whole pinned bundle, without
          // inventing a claim or allowing a caller to choose files to skip.
          for (const [name, file] of held) {
            const bytes = await file.read();
            assertOpen();
            if (["source", "review", "profile"].includes(name)) inputs[name] = bytes;
          }
        } catch (error) { session.unknown = true; throw error; }
        return Object.freeze(inputs);
      },
      async readStep(claim) {
        assertOpen(); const step = validateClaim(claim, plan, planSha256);
        const names = ["plan", "revision", step.entry, "source", "review", ...(held.has("profile") ? ["profile"] : [])];
        const bytes = {};
        try { for (const name of names) bytes[name] = await held.get(name).read(); }
        catch (error) { session.unknown = true; throw error; }
        return Object.freeze(bytes); // Copies from held FDs; no path is returned.
      },
      async reserveJournal(suppliedClaim) {
        assertOpen();
        const claim = freeze(JSON.parse(canonical(safeDataCopy(suppliedClaim))));
        validateClaim(claim, plan, planSha256);
        if (!["allocator", "activation"].includes(claim.stepId)) fail("MIGRATION_JOURNAL_STEP_REQUIRED");
        const reservation = (async () => {
          try {
            const record = await reserveFixedJournal(claim, plan, session);
            journals.add(record);
            assertOpen();
            const lease = Object.freeze(Object.create(null));
            journalReservations.set(lease, record);
            return lease;
          } catch (error) { session.unknown = true; throw error; }
        })();
        reservations.add(reservation);
        void reservation.then(() => reservations.delete(reservation), () => reservations.delete(reservation));
        return reservation;
      },
      async writeTypedOutput(claim, nativeBytes, nativeSummaryBytes = null) {
        assertOpen(); validateClaim(claim, plan, planSha256);
        claim = freeze(JSON.parse(canonical(claim)));
        const copyNative = (bytes) => {
          if (!Buffer.isBuffer(bytes) || bytes.length < 2 || bytes.length > migrationArtifactBounds.report)
            fail("MIGRATION_NATIVE_REPORT_BOUND");
          return Buffer.from(bytes);
        };
        nativeBytes = copyNative(nativeBytes);
        if (nativeSummaryBytes !== null) nativeSummaryBytes = copyNative(nativeSummaryBytes);
        // Validate actual held input bytes again, including source and review.
        try { for (const file of held.values()) await file.read(); }
        catch (error) { session.unknown = true; throw error; }
        const native = nativeJson(nativeBytes);
        let output, nativeSummary = null;
        if (claim.stepId.startsWith("sync-")) {
          if (nativeSummaryBytes !== null) fail("MIGRATION_NATIVE_REPORT_INVALID");
          output = syncOutput(native, claim);
        } else if (claim.stepId === "allocator") {
          nativeSummary = nativeJson(nativeSummaryBytes);
          output = allocatorOutput(native, nativeSummary, claim);
          // The real review is not replaced by fields copied from a caller's claim.
          const review = nativeJson(await held.get("review").read());
          exact(review, ["version", "sourceDatabase", "targetDatabase", "importKey", "sourceServerUuid", "writersDrainedAt", "finalSyncSha256", "referenceReviewSha256"]);
          if (review.version !== 1 || review.sourceDatabase !== "bujiaban_development" || review.targetDatabase !== migrationTarget.database ||
              review.importKey !== native.manifest.baseline.importKey || review.sourceServerUuid !== native.manifest.source.serverUuid ||
              review.writersDrainedAt !== native.manifest.drain.writersDrainedAt || review.finalSyncSha256 !== native.manifest.drain.finalSyncSha256 ||
              review.referenceReviewSha256 !== native.manifest.baseline.referenceReviewSha256)
            fail("MIGRATION_ALLOCATOR_REVIEW_BINDING");
        } else {
          if (nativeSummaryBytes !== null) fail("MIGRATION_NATIVE_REPORT_INVALID");
          output = activationOutput(native, claim);
        }
        const report = {
          version: 1, kind: "identity-native-typed-output", runId: claim.runId, claimId: claim.claimId,
          stepId: claim.stepId, planSha256, inputSha256: claim.inputSha256,
          nativeReportSha256: bytesDigest(nativeBytes),
          nativeSummarySha256: nativeSummaryBytes === null ? null : bytesDigest(nativeSummaryBytes),
          nativeReport: native, nativeSummary,
          output,
        };
        const bytes = Buffer.from(canonical(report) + "\n");
        if (bytes.length > migrationArtifactBounds.report) fail("MIGRATION_NATIVE_REPORT_BOUND");
        const path = join(migrationArtifactLayout.reports, claim.stepId + ".typed-output.json");
        const ancestors = await holdAncestors(path);
        let handle;
        try {
          handle = await fs.open(path, constants.O_RDWR | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
          const before = await handle.stat();
          if (!before.isFile() || before.nlink !== 1 || before.uid !== uid() || (before.mode & 0o7777) !== 0o600 || before.size !== 0)
            fail("MIGRATION_UNTRUSTED_REPORT");
          let offset = 0;
          while (offset < bytes.length) {
            const { bytesWritten } = await handle.write(bytes, offset, bytes.length - offset, offset);
            if (bytesWritten < 1) fail("MIGRATION_REPORT_WRITE_UNKNOWN");
            offset += bytesWritten;
          }
          await handle.sync();
          await ancestors.at(-1).handle.sync();
          const postWrite = await handle.stat();
          const persisted = Buffer.alloc(bytes.length + 1);
          let readOffset = 0;
          while (readOffset < persisted.length) {
            const { bytesRead } = await handle.read(persisted, readOffset, persisted.length - readOffset, readOffset);
            if (bytesRead === 0) break;
            readOffset += bytesRead;
          }
          if (readOffset !== bytes.length || !persisted.subarray(0, readOffset).equals(bytes))
            fail("MIGRATION_REPORT_BYTES_UNKNOWN");
          for (const a of ancestors) {
            const [named, opened] = await Promise.all([fs.lstat(a.path), a.handle.stat()]);
            directory(named); directory(opened);
            if (!sameIdentity(a.stat, named) || !sameIdentity(a.stat, opened)) fail("MIGRATION_ARTIFACT_REPLACED");
          }
          const [named, opened] = await Promise.all([fs.lstat(path), handle.stat()]);
          regular(named, true, migrationArtifactBounds.report); regular(opened, true, migrationArtifactBounds.report);
          if (!sameIdentity(before, named) || !sameIdentity(before, opened) ||
              metadata(named) !== metadata(postWrite) || metadata(opened) !== metadata(postWrite) || opened.size !== bytes.length)
            fail("MIGRATION_ARTIFACT_REPLACED");
          await closeAll([handle, ...ancestors.map((a) => a.handle)]); handle = null; ancestors.length = 0;
          return freeze({ report, reportSha256: bytesDigest(bytes), outputSha256: bytesDigest(Buffer.from(canonical(output) + "\n")) });
        } catch (error) {
          // A partial or non-durable artifact is retained, never truncated/reused.
          session.unknown = true;
          try { await closeAll([...(handle ? [handle] : []), ...ancestors.map((a) => a.handle)]); }
          catch (closeError) { throw new AggregateError([error, closeError], "MIGRATION_REPORT_UNKNOWN"); }
          throw error;
        }
      },
      close() {
        if (closePromise) return closePromise;
        session.closed = true;
        closePromise = (async () => {
          const opening = await Promise.allSettled([...reservations]);
          // Transferred journals belong exclusively to Native. Never double-close
          // their FD/ancestors or infer Native cleanup from closing this session.
          const results = await Promise.allSettled([
            ...[...held.values()].map((f) => f.close()),
            ...[...journals].filter((j) => j.state === "reserved").map(closeJournalRecord),
          ]);
          if ([...opening, ...results].some((r) => r.status === "rejected"))
            fail("MIGRATION_ARTIFACT_CLOSE_UNKNOWN");
        })();
        return closePromise;
      },
    });
  } catch (error) {
    try { await closeAll([...held.values()].flatMap((f) => [f.handle, ...f.ancestors.map((a) => a.handle)])); }
    catch (closeError) { throw new AggregateError([error, closeError], "MIGRATION_ARTIFACT_OPEN_UNKNOWN"); }
    throw error;
  }
}
