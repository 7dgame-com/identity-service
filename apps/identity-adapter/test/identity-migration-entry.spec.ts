import { createHash, randomBytes, randomUUID } from "node:crypto";
import { createServer } from "node:http";
import { once } from "node:events";
import { mkdtemp, rm, writeFile, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Connection } from "mysql2/promise";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
const mocks = vi.hoisted(() => ({ sync: vi.fn(), allocator: vi.fn(), activation: vi.fn() }));
vi.mock("../src/generated/iam-organization-reconciliation-compiled-revision.js", () => ({ ORGANIZATION_RECONCILIATION_COMPILED_BUILD_REVISION: "a".repeat(40) }));
vi.mock("../src/identity-account-sync.js", () => ({ syncIdentityAccounts: mocks.sync }));
vi.mock("../src/identity-allocator-finalizer.js", () => ({ finalizeAllocator: mocks.allocator }));
vi.mock("../src/identity-activation.js", () => ({ immutableIdentityRevision: () => "a".repeat(40), activateExplicitIdentity: mocks.activation, activationRequestSha256: (database: string, proof: string, compiledRevision: string, deadline: string) => migrationBindingSha256({ version: 1, database, allocatorManifestSha256: proof, compiledRevision, deadline }) }));
import { NativeMigrationAdmission, nativeMigrationEntries, migrationBindingSha256, invokeNativeMigration, type NativeMigrationClaim, type NativeMigrationInvocation } from "../src/identity-migration-entry.js";
import { assertAdmissionWriter, AdmissionWriter, AdmissionScope } from "../src/identity-admission.js";
import { withMigrationResources } from "../src/identity-migration-resources.js";

const sha = (b: Buffer) => createHash("sha256").update(b).digest("hex"), hex = "b".repeat(64);
const zero = { applied: false, changes: 0, inserts: 0, updates: 0, deletions: 0, affectedSubjects: 0, tableChanges: {} };
const sourceSnapshot = Buffer.from('{"version":1}\n'), finalSyncReport = Buffer.from(`${JSON.stringify(zero)}\n`);
const target = { host: "10.206.0.5", port: 3306, database: "xrugc_identity_dev", principal: "identity_dev", fenceId: 1 } as const;
const executor = { id: "migration-executor", bootId: "boot_fixture_20261022" };
const capability = `${"x".repeat(43)}.${"y".repeat(43)}`;
function makeClaim(stepId: NativeMigrationClaim["stepId"] = "sync-apply"): NativeMigrationClaim {
  const deadline = new Date(Date.now() + 2900).toISOString();
  const review = reviewBytes();
  const inputs = stepId === "activation" ? { expectedProofSha256: hex, expectedRevision: "a".repeat(40), deadline, requestSha256: migrationBindingSha256({ version: 1, database: target.database, allocatorManifestSha256: hex, compiledRevision: "a".repeat(40), deadline }) } : stepId === "allocator" ? { reviewSha256: sha(review), finalSyncReportSha256: sha(finalSyncReport), sourceSnapshotSha256: sha(sourceSnapshot) } : { sourceSnapshotSha256: sha(sourceSnapshot), profileSelectionSha256: null, limits: { maxChanges: 10, maxRows: 100 }, apply: stepId === "sync-apply" };
  const entry = stepId.startsWith("sync-") ? "account-sync" : stepId === "allocator" ? "allocator-highwater" : "identity-activate";
  return { version: 1, runId: randomUUID(), claimId: randomUUID(), planSha256: hex, epoch: 7, drainSha256: hex, compiledRevision: "a".repeat(40), imageDigest: `sha256:${hex}`, executor, target, deadline, stepId, entry, entrypoint: nativeMigrationEntries[entry], entrySha256: hex, mode: stepId === "sync-zero" ? "dry-run" : "apply", inputs, inputSha256: migrationBindingSha256(inputs), previousChainSha256: hex } as NativeMigrationClaim;
}
function reviewBytes() { return Buffer.from(JSON.stringify({ version: 1, sourceDatabase: "bujiaban_development", targetDatabase: target.database, importKey: "fixture", sourceServerUuid: "11111111-1111-1111-1111-111111111111", writersDrainedAt: "2026-10-01T00:00:00.000Z", finalSyncSha256: sha(finalSyncReport), referenceReviewSha256: hex })); }
function connection(source = false): Connection {
  return { connection: { config: { host: target.host, port: target.port, user: target.principal }, stream: { remoteAddress: target.host, remotePort: target.port } }, query: vi.fn(async (sql: string) => sql.includes("@@autocommit") ? [[{ enabled: 1 }], []] : sql.startsWith("SET TRANSACTION") ? [[], []] : [[{ name: source ? "bujiaban_development" : target.database, principal: "identity_dev@%", server_id: "1c6c32c4-00a9-11f1-9d18-0c42a14c701e" }], []]) } as unknown as Connection;
}
const syncInput = () => ({ entry: "account-sync" as const, source: connection(true), target: connection(), sourceSnapshot, profileSelection: null });

describe("dedicated Native migration enter and closed dispatch", () => {
  let directory: string, server: ReturnType<typeof createServer>, key: string;
  let fault: "nonce" | "binding" | "drop" | null, calls: string[], seenBody: any;
  let heldClaim: string | null, held: Promise<void>, release: () => void, sawHeld: () => void;
  beforeEach(async () => {
    vi.clearAllMocks(); vi.stubEnv("IDENTITY_ADMISSION_ENABLED", "true");
    directory = await mkdtemp(join(tmpdir(), "native-migration-entry-")); key = randomBytes(32).toString("base64url"); calls = []; fault = null; heldClaim = null;
    server = createServer(async (req, res) => {
      calls.push(req.url!); expect(req.headers.authorization).toBe(`Bearer ${key}`);
      const chunks: Buffer[] = []; for await (const b of req) chunks.push(Buffer.from(b)); const body = JSON.parse(Buffer.concat(chunks).toString()); seenBody = body;
      if (req.url === "/migration-unknown") { res.end("{}"); return; }
      const selectedFault = fault;
      expect(req.url).toBe("/migration-enter"); expect(body.claimCapability).toBe(capability);
      expect(body.requestSha256).toBe(migrationBindingSha256({ version: 1, nonce: body.nonce, claim: body.claim, claimCapability: capability }));
      if (heldClaim === body.claim.claimId) { sawHeld(); await held; }
      if (selectedFault === "drop") { req.socket.destroy(); return; }
      const ack = { version: 1, nonce: selectedFault === "nonce" ? "wrong" : body.nonce, requestSha256: body.requestSha256, claim: structuredClone(body.claim), scopeCapability: capability };
      if (selectedFault === "binding") ack.claim.entrySha256 = "c".repeat(64);
      res.setHeader("content-type", "application/json"); res.end(JSON.stringify(ack));
    }).listen(0, "127.0.0.1"); await once(server, "listening");
    const config = join(directory, "config.json"), keyPath = join(directory, "key");
    await writeFile(config, JSON.stringify({ version: 1, controlUrl: `http://127.0.0.1:${(server.address() as any).port}/`, executor, compiledRevision: "a".repeat(40), imageDigest: `sha256:${hex}`, target }), { mode: 0o600 });
    await writeFile(keyPath, key, { mode: 0o600 }); vi.stubEnv("IDENTITY_MIGRATION_CONFIG_FILE", config); vi.stubEnv("IDENTITY_MIGRATION_KEY_FILE", keyPath);
    mocks.sync.mockImplementation(async (_s, _t, options) => { assertAdmissionWriter(options.apply ? "sync-apply" : "sync-read"); return { ...zero, applied: !!options.apply }; });
    mocks.allocator.mockImplementation(async options => { assertAdmissionWriter("allocator-apply"); await options.onStep({ table: "user", phase: "intent", floor: "1" }); return { manifest: {}, manifestSha256: hex, sourceMetadataSha256: hex, targetSchemaSha256: hex, sourceStateSha256: hex }; });
    mocks.activation.mockImplementation(async options => { assertAdmissionWriter("activation-apply"); const receipt = { allocatorManifestSha256: hex, compiledRevision: "a".repeat(40), requestSha256: migrationBindingSha256({ version: 1, database: target.database, allocatorManifestSha256: hex, compiledRevision: "a".repeat(40), deadline: options.deadline }), decisionAt: new Date().toISOString(), deadline: options.deadline }; await options.onCommitIntent(receipt); return { outcome: "activated", authority: "identity", receipt, acknowledgementAfterDeadline: false }; });
  });
  afterEach(async () => { server.closeAllConnections(); await new Promise<void>(r => server.close(() => r())); await rm(directory, { recursive: true, force: true }); vi.unstubAllEnvs(); });
  it("is unwired by default and cannot create a scope from a plain claim", async () => {
    vi.stubEnv("IDENTITY_MIGRATION_CONFIG_FILE", ""); expect(() => NativeMigrationAdmission.environment()).toThrow("MIGRATION_ENTER_NOT_WIRED");
    await expect(invokeNativeMigration({} as any, syncInput())).rejects.toThrow("VERIFIED_SINGLE_USE"); expect(mocks.sync).not.toHaveBeenCalled();
  });
  it("accepts the frozen claim actually emitted by the independent driver ledger (canonical object hash without LF)", async () => {
    const bytes = await readFile(new URL("./support/migration-ledger-claim.json", import.meta.url));
    expect(sha(bytes)).toBe("8adabd88852163a1a962c6ba3982a5f0d7a9ca285385029968ceaefd27f9915e");
    const fixture = JSON.parse(bytes.toString()); expect(fixture.sources).toHaveLength(5);
    expect(fixture.claim.inputSha256).toBe("97cfec2e534738176820b127d68dd921e6ed7260b69c3914d2c79857f42e35e4");
    const now = vi.spyOn(Date, "now").mockReturnValue(Date.parse(fixture.claim.deadline) - 2000);
    try { await expect(NativeMigrationAdmission.environment().enter(fixture.claim, capability)).resolves.toBeDefined(); } finally { now.mockRestore(); }
  });
  it("runs only the fixed sync apply from a verified single-use enter, without HTTP begin or complete", async () => {
    const runtime = NativeMigrationAdmission.environment(), c = makeClaim(), scope = await runtime.enter(c, capability);
    await expect(invokeNativeMigration(scope, syncInput())).resolves.toEqual({ ...zero, applied: true });
    await expect(invokeNativeMigration(scope, syncInput())).rejects.toThrow("VERIFIED_SINGLE_USE");
    await expect(runtime.enter(c, capability)).rejects.toThrow("ALREADY_ATTEMPTED"); expect(calls).toEqual(["/migration-enter"]);
    expect(mocks.sync.mock.calls[0][2]).toEqual({ maxChanges: 10, maxRows: 100, apply: true, profileSelection: undefined });
  });
  it.each(["nonce", "binding", "drop"] as const)("permanently latches a %s enter ACK fault, with no retry", async f => {
    fault = f; const runtime = NativeMigrationAdmission.environment(); await expect(runtime.enter(makeClaim(), capability)).rejects.toMatchObject({ code: "MIGRATION_ENTER_UNKNOWN", outcome: "unknown", automaticRetry: false });
    fault = null; await expect(runtime.enter(makeClaim(), capability)).rejects.toThrow("CONTROL_UNKNOWN"); expect(calls).toEqual(["/migration-enter", "/migration-unknown"]);
  });
  it("invalidates an older ready scope when a later enter makes its client unknown", async () => {
    const runtime = NativeMigrationAdmission.environment(), scope = await runtime.enter(makeClaim(), capability);
    fault = "nonce"; await expect(runtime.enter(makeClaim(), capability)).rejects.toThrow("ENTER_UNKNOWN");
    const input = syncInput(); await expect(invokeNativeMigration(scope, input)).rejects.toMatchObject({ outcome: "unknown" }); expect(input.source.query).not.toHaveBeenCalled(); expect(mocks.sync).not.toHaveBeenCalled();
  });
  it("cannot issue a late verified scope after a concurrent enter has become unknown", async () => {
    const runtime = NativeMigrationAdmission.environment(), first = makeClaim(); heldClaim = first.claimId;
    held = new Promise<void>(r => { release = r; }); const seen = new Promise<void>(r => { sawHeld = r; });
    const pending = runtime.enter(first, capability); const settled = pending.then(() => "accepted", () => "rejected"); await seen;
    fault = "nonce"; await expect(runtime.enter(makeClaim(), capability)).rejects.toThrow("ENTER_UNKNOWN"); release(); expect(await settled).toBe("rejected"); expect(mocks.sync).not.toHaveBeenCalled();
  });
  it("does not return a successful SQL result after the same client becomes unknown mid-operation", async () => {
    const runtime = NativeMigrationAdmission.environment(), scope = await runtime.enter(makeClaim(), capability);
    let releaseSql!: () => void, sawSql!: () => void; const sqlGate = new Promise<void>(r => { releaseSql = r; }), seen = new Promise<void>(r => { sawSql = r; });
    mocks.sync.mockImplementation(async () => { assertAdmissionWriter("sync-apply"); sawSql(); await sqlGate; expect(() => assertAdmissionWriter("sync-apply")).toThrow("CONTROL_UNKNOWN"); return { ...zero, applied: true }; });
    const pending = invokeNativeMigration(scope, syncInput()), settled = pending.then(() => "accepted", () => "rejected"); await seen;
    fault = "nonce"; await expect(runtime.enter(makeClaim(), capability)).rejects.toThrow("ENTER_UNKNOWN"); releaseSql(); expect(await settled).toBe("rejected");
  });
  it.each(["entry", "mode", "target", "revision", "inputs", "deadline"])("rejects a mismatched %s before requesting permission", async field => {
    const c: any = makeClaim(); if (field === "entry") c.entrypoint = "dist/scripts/arbitrary.js";
    if (field === "mode") c.mode = "dry-run"; if (field === "target") c.target = { ...target, database: "other" };
    if (field === "revision") c.compiledRevision = "c".repeat(40); if (field === "inputs") c.inputs.limits.maxChanges = 11;
    if (field === "deadline") c.deadline = new Date(Date.now() - 1).toISOString();
    await expect(NativeMigrationAdmission.environment().enter(c, capability)).rejects.toThrow(); expect(calls).toEqual([]);
  });
  it("binds dry-run to read only and rejects untagged and decorated ordinary writers", async () => {
    const runtime = NativeMigrationAdmission.environment(); const scope = await runtime.enter(makeClaim("sync-zero"), capability);
    mocks.sync.mockImplementation(async () => {
      assertAdmissionWriter("sync-read"); expect(() => assertAdmissionWriter("sync-apply")).toThrow("PURPOSE_MISMATCH"); expect(() => assertAdmissionWriter()).toThrow("PURPOSE_MISMATCH");
      const descriptor = { value: vi.fn(async () => undefined) }; AdmissionWriter()({}, "write", descriptor); expect(() => descriptor.value()).toThrow("PURPOSE_MISMATCH"); return zero;
    });
    await expect(invokeNativeMigration(scope, syncInput())).resolves.toEqual(zero);
  });
  it("does not let an ordinary HTTP scope authorize any migration entry", async () => {
    const scope = new AdmissionScope({} as any, null, false);
    for (const p of ["sync-apply", "sync-read", "allocator-apply", "activation-apply"] as const) expect(() => scope.run(() => assertAdmissionWriter(p))).toThrow();
  });
  it("rejects changing the input entry or adding a command/path before SQL", async () => {
    const runtime = NativeMigrationAdmission.environment(), scope = await runtime.enter(makeClaim(), capability), input = syncInput() as any;
    input.command = "anything"; await expect(invokeNativeMigration(scope, input)).rejects.toMatchObject({ outcome: "unknown" }); expect(input.target.query).not.toHaveBeenCalled(); expect(mocks.sync).not.toHaveBeenCalled(); expect(calls).toEqual(["/migration-enter", "/migration-unknown"]);
  });
  it("rejects a physical endpoint mismatch without starting business SQL", async () => {
    const runtime = NativeMigrationAdmission.environment(), scope = await runtime.enter(makeClaim(), capability), input = syncInput() as any;
    input.source.connection.stream.remoteAddress = "127.0.0.1"; await expect(invokeNativeMigration(scope, input)).rejects.toMatchObject({ outcome: "unknown" }); expect(input.source.query).not.toHaveBeenCalled(); expect(mocks.sync).not.toHaveBeenCalled();
  });
  it("rejects the actual selected database/principal, even when connection config looks reviewed", async () => {
    const runtime = NativeMigrationAdmission.environment(), scope = await runtime.enter(makeClaim(), capability), input = syncInput() as any;
    input.target.query.mockResolvedValue([[{ name: target.database, principal: "root@%", server_id: "fixture" }], []]);
    await expect(invokeNativeMigration(scope, input)).rejects.toMatchObject({ outcome: "unknown" }); expect(mocks.sync).not.toHaveBeenCalled();
  });
  it("rejects a different actual server UUID at the reviewed address", async () => {
    const scope = await NativeMigrationAdmission.environment().enter(makeClaim(), capability), input = syncInput();
    vi.mocked(input.target.query).mockResolvedValue([[{ name: target.database, principal: "identity_dev@%", server_id: "ffffffff-ffff-ffff-ffff-ffffffffffff" }], []] as any);
    await expect(invokeNativeMigration(scope, input)).rejects.toMatchObject({ outcome: "unknown" }); expect(mocks.sync).not.toHaveBeenCalled();
  });
  it("allocator permits only its fixed read-only sync audit and never activation or sync apply", async () => {
    const runtime = NativeMigrationAdmission.environment(), c = makeClaim("allocator"), scope = await runtime.enter(c, capability);
    mocks.allocator.mockImplementation(async options => { assertAdmissionWriter("allocator-apply"); for (const p of ["sync-apply", "activation-apply", "allocator-read"] as const) expect(() => assertAdmissionWriter(p)).toThrow("PURPOSE_MISMATCH"); await options.onStep({ table: "user", phase: "intent", floor: "1" }); return { manifest: {}, manifestSha256: hex, sourceMetadataSha256: hex, targetSchemaSha256: hex, sourceStateSha256: hex }; });
    await withMigrationResources(async resources => {
      const journal = await resources.openReport(join(directory, "allocator.jsonl"));
      const result = await invokeNativeMigration(scope, { entry: "allocator-highwater", source: connection(true), target: connection(), fence: connection(), sourceSnapshot, review: reviewBytes(), finalSyncReport, journal });
      expect(result).toMatchObject({ summary: { ready: true, authorityActivated: false, sourceWritten: false } }); expect(result).not.toHaveProperty("connectionsClosed");
    });
    expect(mocks.sync.mock.calls[0][2]).toEqual({ apply: false, maxChanges: 100000 }); expect(mocks.activation).not.toHaveBeenCalled();
  });
  it("captures connection/journal references and Buffer bytes before an awaited location check", async () => {
    const c = makeClaim("allocator"), scope = await NativeMigrationAdmission.environment().enter(c, capability);
    await withMigrationResources(async resources => {
      const journal = await resources.openReport(join(directory, "captured-journal.jsonl")), source = connection(true), targetConnection = connection(), fence = connection();
      const input: any = { entry: "allocator-highwater", source, target: targetConnection, fence, journal, sourceSnapshot: Buffer.from(sourceSnapshot), review: reviewBytes(), finalSyncReport: Buffer.from(finalSyncReport) };
      let releaseQuery!: () => void, sawQuery!: () => void; const gate = new Promise<void>(r => { releaseQuery = r; }), seen = new Promise<void>(r => { sawQuery = r; });
      const query = vi.mocked(source.query).getMockImplementation()!;
      vi.mocked(source.query).mockImplementationOnce((async (...args: any[]) => { sawQuery(); await gate; return (query as any)(...args); }) as any);
      const pending = invokeNativeMigration(scope, input); await seen;
      const replacement = connection(); input.source = replacement; input.target = replacement; input.fence = replacement; input.journal = { writeFile: vi.fn(), sync: vi.fn() }; input.sourceSnapshot.fill(0); input.review.fill(0); input.finalSyncReport.fill(0); releaseQuery();
      await expect(pending).resolves.toHaveProperty("plan"); expect(replacement.query).not.toHaveBeenCalled(); expect(mocks.sync.mock.calls[0].slice(0, 2)).toEqual([source, targetConnection]);
      expect(mocks.allocator.mock.calls[0][0]).toMatchObject({ source, target: targetConnection, fence });
    });
  });
  it.each(["getter", "symbol", "hidden", "prototype", "proxy"])("rejects a %s invocation shape before invoking caller code or SQL", async kind => {
    const scope = await NativeMigrationAdmission.environment().enter(makeClaim(), capability), original = syncInput(), getter = vi.fn(); let input: any = original;
    if (kind === "getter") Object.defineProperty(input, "target", { get: getter });
    if (kind === "symbol") input[Symbol("hidden")] = 1;
    if (kind === "hidden") Object.defineProperty(input, "extra", { value: 1, enumerable: false });
    if (kind === "prototype") Object.setPrototypeOf(input, { anything: true });
    if (kind === "proxy") input = new Proxy(input, { ownKeys: getter });
    await expect(invokeNativeMigration(scope, input)).rejects.toMatchObject({ outcome: "unknown" }); expect(getter).not.toHaveBeenCalled(); expect(original.source.query).not.toHaveBeenCalled();
  });
  it("requires an owned journal rather than an arbitrary callback or structural fake", async () => {
    const scope = await NativeMigrationAdmission.environment().enter(makeClaim("activation"), capability);
    await expect(invokeNativeMigration(scope, { entry: "identity-activate", target: connection(), journal: { writeFile: vi.fn(), sync: vi.fn() } } as any)).rejects.toMatchObject({ outcome: "unknown" }); expect(mocks.activation).not.toHaveBeenCalled();
  });
  it("rejects changed owned journal methods without executing their getters or callbacks", async () => {
    const scope = await NativeMigrationAdmission.environment().enter(makeClaim("activation"), capability), getter = vi.fn();
    await withMigrationResources(async resources => {
      const journal = await resources.openReport(join(directory, "changed-journal.jsonl"));
      Object.defineProperty(journal, "sync", { get: getter });
      await expect(invokeNativeMigration(scope, { entry: "identity-activate", target: connection(), journal })).rejects.toMatchObject({ outcome: "unknown" }); expect(getter).not.toHaveBeenCalled();
    });
  });
  it("does not let a late async task reuse the completed invocation context", async () => {
    let late!: Promise<void>;
    mocks.sync.mockImplementation(async () => { assertAdmissionWriter("sync-apply"); late = new Promise(resolve => setTimeout(() => { expect(() => assertAdmissionWriter("sync-apply")).toThrow("NOT_RUNNING"); resolve(); }, 5)); return { ...zero, applied: true }; });
    const scope = await NativeMigrationAdmission.environment().enter(makeClaim(), capability);
    await invokeNativeMigration(scope, syncInput()); await late;
  });
  it("checks the original deadline again after enter, before starting business SQL", async () => {
    const runtime = NativeMigrationAdmission.environment(), c = makeClaim(), scope = await runtime.enter(c, capability), input = syncInput();
    const now = vi.spyOn(Date, "now").mockReturnValue(Date.parse(c.deadline) + 1);
    try { await expect(invokeNativeMigration(scope, input)).rejects.toMatchObject({ outcome: "unknown" }); expect(input.source.query).not.toHaveBeenCalled(); expect(mocks.sync).not.toHaveBeenCalled(); }
    finally { now.mockRestore(); }
  });
  it("awaits its fixed activation intent fsync and returns only the actual business result", async () => {
    const scope = await NativeMigrationAdmission.environment().enter(makeClaim("activation"), capability);
    await withMigrationResources(async resources => {
      const journal = await resources.openReport(join(directory, "activation.jsonl"));
      const result = await invokeNativeMigration(scope, { entry: "identity-activate", target: connection(), journal });
      expect(result).toMatchObject({ outcome: "activated", authority: "identity" }); expect(result).not.toHaveProperty("sideEffectsFinished"); expect(calls).toEqual(["/migration-enter"]);
    });
  });
  it("checks an already-active receipt binding even when the core did not invoke the intent callback", async () => {
    const scope = await NativeMigrationAdmission.environment().enter(makeClaim("activation"), capability);
    mocks.activation.mockImplementation(async options => { assertAdmissionWriter("activation-apply"); return { outcome: "already_active", authority: "identity", receipt: { allocatorManifestSha256: hex, compiledRevision: "a".repeat(40), requestSha256: hex, deadline: options.deadline, decisionAt: new Date().toISOString() } }; });
    await withMigrationResources(async resources => {
      const journal = await resources.openReport(join(directory, "already-active.jsonl"));
      await expect(invokeNativeMigration(scope, { entry: "identity-activate", target: connection(), journal })).rejects.toMatchObject({ outcome: "unknown" });
    });
  });
  it("refuses a self-consistent activation claim whose request hash does not match the actual activation tuple", async () => {
    const c: any = makeClaim("activation"); c.inputs.requestSha256 = hex; c.inputSha256 = migrationBindingSha256(c.inputs);
    await expect(NativeMigrationAdmission.environment().enter(c, capability)).rejects.toThrow("CLAIM_BINDING_MISMATCH"); expect(calls).toEqual([]);
  });
});
