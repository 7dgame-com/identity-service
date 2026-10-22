import "reflect-metadata";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import fs from "node:fs/promises";
import { createServer } from "node:http";
import { once } from "node:events";
import { randomUUID, randomBytes, createHash } from "node:crypto";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath, pathToFileURL } from "node:url";
import mysql, { type Connection, type RowDataPacket } from "mysql2/promise";
import mysqlRaw from "mysql2";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
const enabled = process.env.IDENTITY_TEST_MYSQL === "1", root = fileURLToPath(new URL("../../../", import.meta.url));
const options = { host: process.env.IDENTITY_TEST_MYSQL_HOST ?? "127.0.0.1", port: Number(process.env.IDENTITY_TEST_MYSQL_PORT ?? 13316), user: process.env.IDENTITY_TEST_MYSQL_USER ?? "root", password: process.env.IDENTITY_TEST_MYSQL_PASSWORD ?? "", timezone: "Z", multipleStatements: true };
const run = promisify(execFile), revision = "a".repeat(40), h = "b".repeat(64), capability = `${"x".repeat(43)}.${"y".repeat(43)}`;
const real = Object.fromEntries(["open", "lstat", "mkdir", "readFile", "writeFile", "chmod", "rm", "mkdtemp"].map(k => [k, (fs as any)[k].bind(fs)])) as typeof fs;
const sha = (b: Buffer) => createHash("sha256").update(b).digest("hex");
const canonical = (v: any): string => v === null || typeof v !== "object" ? JSON.stringify(v) : Array.isArray(v) ? `[${v.map(canonical).join(",")}]` : `{${Object.keys(v).sort().map(k => `${JSON.stringify(k)}:${canonical(v[k])}`).join(",")}}`;
const bytes = (v: any) => Buffer.from(canonical(v) + "\n"), digest = (v: any) => sha(Buffer.from(canonical(v)));
const zero = { applied: false, changes: 0, inserts: 0, updates: 0, deletions: 0, affectedSubjects: 0, tableChanges: {} };
describe.skipIf(!enabled)("closed owned executor with real held files and exclusive MySQL", () => {
  let build: string, physicalRoot: string, admin: Connection, source: Connection, target: Connection, sourceName: string, targetName: string, api: any, account: any, fingerprint: any, allocator: any, planApi: any, artifactApi: any;
  let server: ReturnType<typeof createServer>, configPath: string, keyPath: string, credentialsPath: string, targetBinding: any, plan: any, claims: any[], calls: string[], entered: any, connections: Connection[], handles: any[], fault: string | null, client: any;
  const physicalRoots = new Set<string>();
  let spySetupMs = 0;
  const executor = { id: "owned-fixture", bootId: "owned_fixture_20261022" }, user = `owned_${randomUUID().replaceAll("-", "").slice(0, 15)}`, password = "disposable-fixture-only";
  const physical = (p: string) => p === "/" ? physicalRoot : join(physicalRoot, p);
  beforeAll(async () => {
    if (options.host !== "127.0.0.1" || !(options.port === 13316 || (options.port === 3306 && process.env.CI === "true"))) throw new Error("Disposable MySQL only");
    admin = await mysql.createConnection(options); const [id] = await admin.query<RowDataPacket[]>("SELECT @@server_uuid AS uuid");
    sourceName = `test_owned_source_${randomUUID().replaceAll("-", "")}`; targetName = `test_owned_target_${randomUUID().replaceAll("-", "")}`;
    await admin.query("CREATE USER ?@'%' IDENTIFIED BY ?", [user, password]); await admin.query(`GRANT ALL ON \`${sourceName}\`.* TO ?@'%'`, [user]); await admin.query(`GRANT ALL ON \`${targetName}\`.* TO ?@'%'`, [user]);
    build = await real.mkdtemp(join(root, ".identity-owned-build-")); credentialsPath = join(build, "database.json"); configPath = join(build, "config.json"); keyPath = join(build, "key");
    await run(process.execPath, [join(root, "node_modules/typescript/bin/tsc"), "--outDir", build, "--noEmitOnError", "true"], { cwd: root, timeout: 90000, maxBuffer: 1024 * 1024 });
    const src = join(build, "apps/identity-adapter/src"); await real.writeFile(join(src, "generated/iam-organization-reconciliation-compiled-revision.js"), `export const ORGANIZATION_RECONCILIATION_COMPILED_BUILD_REVISION=${JSON.stringify(revision)};\n`);
    for (const file of ["identity-migration-entry.js", "identity-source-fingerprint.js", "identity-allocator-finalizer.js", "identity-allocator-manifest.js", "../../../packages/identity-finalization-runtime/migration-plan.mjs", "../../../packages/identity-finalization-runtime/migration-artifacts.mjs"]) {
      const p = join(src, file); let code = await real.readFile(p, "utf8");
      for (const [a, b] of [["10.206.0.5", "127.0.0.1"], ["xrugc_identity_dev", targetName], ["bujiaban_development", sourceName], ["identity_dev", user], ["3306", String(options.port)], ["1c6c32c4-00a9-11f1-9d18-0c42a14c701e", id[0].uuid], ["/run/xrugc/identity-finalization/config/database.json", credentialsPath]]) code = code.replaceAll(JSON.stringify(a), JSON.stringify(b));
      code = code.replaceAll("port: 3306", `port: ${options.port}`); await real.writeFile(p, code);
    }
    const load = (n: string) => import(pathToFileURL(join(src, `${n}.js`)).href);
    [api, account, fingerprint, allocator] = await Promise.all([load("identity-migration-entry"), load("identity-account-import"), load("identity-source-fingerprint"), load("identity-allocator-finalizer")]);
    planApi = await import(pathToFileURL(join(build, "packages/identity-finalization-runtime/migration-plan.mjs")).href); artifactApi = await import(pathToFileURL(join(build, "packages/identity-finalization-runtime/migration-artifacts.mjs")).href);
    await real.writeFile(credentialsPath, JSON.stringify({ version: 1, source: { user, password }, target: { user, password } }), { mode: 0o600 });
  }, 90000);
  beforeEach(async () => {
    fault = null; calls = []; claims = []; connections = []; handles = []; entered = null; spySetupMs = 0;
    vi.stubEnv("IDENTITY_ADMISSION_ENABLED", "false");
    for (const n of [sourceName, targetName]) await admin.query(`CREATE DATABASE \`${n}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`);
    source = await mysql.createConnection({ ...options, database: sourceName }); target = await mysql.createConnection({ ...options, database: targetName });
    const init = await real.readFile(join(root, "deploy/mysql/init.sql"), "utf8"); await target.query(init.slice(init.indexOf("CREATE TABLE IF NOT EXISTS `auth_login_events`")));
    for (const n of ["account", "password-reset-token", "legacy-challenge", "runtime", "wechat-oauth", "qrcode", "apple", "allocator", "activation"]) await target.query(await real.readFile(join(root, `deploy/mysql/identity-${n}-schema.sql`), "utf8"));
    const sql = await real.readFile(join(root, "deploy/mysql/identity-account-schema.sql"), "utf8");
    for (const statement of sql.split(";")) { const table = statement.match(/CREATE TABLE IF NOT EXISTS `?([a-z_]+)`?\s*\(/)?.[1]; if (table && Object.hasOwn(account.accountImportTables, table)) await source.query(statement); }
    await source.query("CREATE TABLE device_sn(id INT PRIMARY KEY,original_user_id INT) ENGINE=InnoDB;INSERT INTO device_sn VALUES(1,99000);INSERT INTO user(id,username,status,nickname,password_hash) VALUES(7301,'owned',10,'Before','hash')"); await account.importIdentityAccounts(source, target, { importKey: "owned", apply: true }); await source.query("UPDATE user SET nickname='Reviewed' WHERE id=7301");
    const manifest = await fingerprint.readActualSourceFingerprint(source, { profileSelectionSha256: null, maxRows: 100 }); const sourceBytes = bytes(manifest), inv = await allocator.readSourceAllocatorInventory(source);
    // Real OS temporary filesystem; platform/storage type is external evidence.
    // The compiled module stays in the repository for dependency resolution.
    physicalRoot = await real.mkdtemp(join(tmpdir(), "xrugc-owned-files-")); physicalRoots.add(physicalRoot); await real.chmod(physicalRoot, 0o700);
    const put = async (p: string, value: Buffer | string, mode = 0o600) => { await real.mkdir(dirname(physical(p)), { recursive: true, mode: 0o700 }); await real.writeFile(physical(p), value, { mode }); };
    const layout = artifactApi.migrationArtifactLayout;
    for (const d of [layout.code, layout.inputs, layout.reports]) await real.mkdir(physical(d), { recursive: true, mode: 0o700 });
    targetBinding = { host: "127.0.0.1", port: options.port, database: targetName, principal: user, fenceId: 1 };
    const review = { version: 1, sourceDatabase: sourceName, targetDatabase: targetName, importKey: "owned", sourceServerUuid: manifest.serverUuid, writersDrainedAt: new Date().toISOString(), finalSyncSha256: sha(bytes(zero)), referenceReviewSha256: inv.referenceReviewSha256 }, reviewBytes = bytes(review);
    const entries: any = {}; for (const [name, entry] of Object.entries(api.nativeMigrationEntries)) { const value = await real.readFile(join(build, (entry as string).replace(/^dist\//, ""))); entries[name] = sha(value); await put(join(layout.code, entry as string), value, 0o644); }
    const start = Date.now(); plan = { version: 1, kind: "identity-development-finalization-plan", epoch: 1, drainSha256: h, rosterSha256: h, compiledRevision: revision, imageDigest: `sha256:${h}`, executor, target: targetBinding, window: { startedAt: new Date(start).toISOString(), deadline: new Date(start + 2900).toISOString() }, inputs: { sourceSnapshotSha256: sha(sourceBytes), profileSelectionSha256: null, allocatorReviewSha256: sha(reviewBytes) }, limits: { maxChanges: 100, maxRows: 100 }, steps: [ { id: "sync-apply", entry: "account-sync", mode: "apply", entrySha256: entries["account-sync"] }, { id: "sync-zero", entry: "account-sync", mode: "dry-run", entrySha256: entries["account-sync"] }, { id: "allocator", entry: "allocator-highwater", mode: "apply", entrySha256: entries["allocator-highwater"] }, { id: "activation", entry: "identity-activate", mode: "apply", entrySha256: entries["identity-activate"] } ] };
    const planBytes = planApi.migrationPlanBytes(plan); await put(join(layout.inputs, layout.plan), planBytes); await put(join(layout.inputs, layout.source), sourceBytes); await put(join(layout.inputs, layout.review), reviewBytes); await put(join(layout.code, layout.revision), revision + "\n", 0o644);
    // Real files/FDs in a private test tree. Only the logical Linux prefix is remapped;
    // production code has no filesystem or target override.
    const spyStart = performance.now();
    vi.spyOn(fs, "lstat").mockImplementation(((p: string, ...args: any[]) => (real.lstat as any)(p.startsWith("/opt/") || p.startsWith("/run/") || ["/", "/opt", "/run"].includes(p) ? physical(p) : p, ...args)) as any);
    vi.spyOn(fs, "open").mockImplementation((async (p: string, ...args: any[]) => { const handle = await (real.open as any)(p.startsWith("/opt/") || p.startsWith("/run/") || ["/", "/opt", "/run"].includes(p) ? physical(p) : p, ...args); handles.push(handle); return handle; }) as any);
    const create = mysqlRaw.createConnection.bind(mysqlRaw); vi.spyOn(mysqlRaw, "createConnection").mockImplementation(((...args: any[]) => {
      const raw = (create as any)(...args), connection = raw.promise(); vi.spyOn(raw, "promise").mockReturnValue(connection); connections.push(connection);
      if (fault === "post-source-drift") { const commit = connection.commit.bind(connection); vi.spyOn(connection, "commit").mockImplementation(async () => { await commit(); await source.query("UPDATE user SET nickname='After-commit' WHERE id=7301"); }); }
      return raw;
    }) as any);
    spySetupMs = performance.now() - spyStart;
    const key = randomBytes(32).toString("base64url"); await real.writeFile(keyPath, key, { mode: 0o600 });
    server = createServer(async (req, res) => {
      calls.push(req.url!); const chunks: Buffer[] = []; for await (const b of req) chunks.push(Buffer.from(b)); const body = JSON.parse(Buffer.concat(chunks).toString());
      expect(req.headers.authorization).toBe(`Bearer ${key}`);
      if (req.url === "/migration-unknown") { res.end("{}"); return; }
      if (req.url === "/migration-enter") { entered = body; res.end(JSON.stringify({ version: 1, nonce: body.nonce, requestSha256: body.requestSha256, claim: body.claim, scopeCapability: capability })); return; }
      expect(req.url).toBe("/migration-complete"); const { requestSha256, ...request } = body; expect(requestSha256).toBe(digest(request)); expect(body.enterNonce).toBe(entered.nonce);
      expect(connections.every(c => (c as any).connection.stream.closed)).toBe(true); expect(handles.every(handle => handle.fd === -1)).toBe(true);
      const report = artifactApi.validateMigrationTypedReport(body.claim, Buffer.from(body.typedReportBase64, "base64")); expect(body.typedReportSha256).toBe(report.reportSha256);
      const c = body.claim, output = report.report.output, envelope = { version: 1, runId: c.runId, claimId: c.claimId, stepId: c.stepId, planSha256: c.planSha256, inputSha256: c.inputSha256, previousChainSha256: c.previousChainSha256, compiledRevision: c.compiledRevision, epoch: c.epoch, target: c.target, deadline: c.deadline, outcome: "completed", sideEffectsFinished: true, connectionsClosed: true, output }, reportSha256 = sha(bytes(envelope)), outputSha256 = sha(bytes(output));
      if (fault === "drop") { req.socket.destroy(); return; }
      res.end(JSON.stringify({ version: 1, nonce: body.nonce, requestSha256, claim: c, reportSha256: fault === "hash" ? h : reportSha256, outputSha256, chainSha256: digest({ previousChainSha256: c.previousChainSha256, claimSha256: digest(c), reportSha256, outputSha256 }) }));
    }).listen(0, "127.0.0.1"); await once(server, "listening");
    await real.writeFile(configPath, JSON.stringify({ version: 1, controlUrl: `http://127.0.0.1:${(server.address() as any).port}/`, executor, compiledRevision: revision, imageDigest: `sha256:${h}`, target: targetBinding, planSha256: sha(planBytes) }), { mode: 0o600 });
    vi.stubEnv("IDENTITY_ADMISSION_ENABLED", "true"); vi.stubEnv("IDENTITY_MIGRATION_CONFIG_FILE", configPath); vi.stubEnv("IDENTITY_MIGRATION_KEY_FILE", keyPath); client = api.NativeMigrationAdmission.environment();
  }, 30000);
  afterEach(async () => {
    const errors: unknown[] = [], attempt = async (work: () => Promise<unknown>) => { try { await work(); } catch (error) { errors.push(error); } };
    try {
      await attempt(() => client?.closePreparedPlan()); vi.restoreAllMocks(); vi.unstubAllEnvs();
      server?.closeAllConnections(); if (server) await attempt(() => new Promise<void>(r => server.close(() => r())));
      const closed = await Promise.allSettled([source?.end(), target?.end(), ...handles.map(h => h.close())]);
      for (const r of closed) if (r.status === "rejected") errors.push(r.reason);
      for (const n of [sourceName, targetName]) await attempt(() => admin.query(`DROP DATABASE IF EXISTS \`${n}\``));
    } finally {
      if (physicalRoot && physicalRoots.has(physicalRoot)) await attempt(async () => { await real.rm(physicalRoot, { recursive: true, force: true }); physicalRoots.delete(physicalRoot); });
    }
    if (errors.length) throw new AggregateError(errors, "OWNED_FIXTURE_CLEANUP_FAILED");
  });
  afterAll(async () => {
    const results = await Promise.allSettled([
      (async () => { try { await admin?.query("DROP USER IF EXISTS ?@'%'", [user]); } finally { await admin?.end(); } })(),
      ...[...physicalRoots].map(path => real.rm(path, { recursive: true, force: true })),
      ...(build ? [real.rm(build, { recursive: true, force: true })] : []),
    ]);
    const errors = results.filter(r => r.status === "rejected").map(r => (r as PromiseRejectedResult).reason);
    if (errors.length) throw new AggregateError(errors, "OWNED_FIXTURE_FINAL_CLEANUP_FAILED");
  });
  function makeClaim(stepId = "sync-apply", proof = h) {
    const step = plan.steps.find((s: any) => s.id === stepId), deadline = plan.window.deadline;
    const inputs = stepId.startsWith("sync-") ? { sourceSnapshotSha256: plan.inputs.sourceSnapshotSha256, profileSelectionSha256: null, limits: plan.limits, apply: step.mode === "apply" } : stepId === "allocator" ? { reviewSha256: plan.inputs.allocatorReviewSha256, finalSyncReportSha256: sha(bytes(zero)), sourceSnapshotSha256: plan.inputs.sourceSnapshotSha256 } : { expectedProofSha256: proof, expectedRevision: revision, deadline, requestSha256: digest({ version: 1, database: targetName, allocatorManifestSha256: proof, compiledRevision: revision, deadline }) };
    const previous = claims.at(-1); const c = { version: 1, runId: previous?.runId ?? randomUUID(), claimId: randomUUID(), planSha256: digest(plan) /* canonical plan has LF: overwritten below */, epoch: 1, drainSha256: h, compiledRevision: revision, imageDigest: plan.imageDigest, executor, target: targetBinding, deadline, stepId, entry: step.entry, entrypoint: api.nativeMigrationEntries[step.entry], entrySha256: step.entrySha256, mode: step.mode, inputs, inputSha256: digest(inputs), previousChainSha256: h }; c.planSha256 = sha(planApi.migrationPlanBytes(plan)); claims.push(c); return c;
  }
  async function ready(step = "sync-apply") { try { await client.prepareOwnedPlan(); } catch (e: any) { throw e.cause ?? e; } return client.enterOwned(makeClaim(step), capability); }
  it("closes actual exclusive sockets and all held FDs before completion, then forbids receipt replay", async () => {
    const scope = await ready(); const closed = await api.executeOwnedStep(scope); expect(Object.keys(closed)).toEqual([]); expect((client as any).post).toBeUndefined();
    await expect(client.completeOwned(closed)).resolves.toHaveProperty("chainSha256");
    await expect(client.completeOwned(closed)).rejects.toMatchObject({ outcome: "unknown" }); expect(calls.filter(p => p === "/migration-complete")).toHaveLength(1); expect(() => client.assertKnown()).toThrow("UNKNOWN");
    const [rows] = await target.query<RowDataPacket[]>("SELECT nickname FROM user WHERE id=7301"); expect(rows[0].nickname).toBe("Reviewed");
  });
  it("executes all four fixed entries with real journal transfer and actual authority activation", async () => {
    const fixtureWindowSetupMs = Date.now() - Date.parse(plan.window.startedAt); let proof = h; const costs: { step: string; phase: string; milliseconds: number }[] = [];
    const timed = async <T>(step: string, phase: string, work: () => Promise<T>) => { const start = performance.now(); try { return await work(); } finally { costs.push({ step, phase, milliseconds: performance.now() - start }); } };
    try { for (const step of ["sync-apply", "sync-zero", "allocator", "activation"]) {
      await timed(step, "prepare", () => client.prepareOwnedPlan()); const scope = await timed(step, "enter", () => client.enterOwned(makeClaim(step, proof), capability));
      let closed; try { closed = await timed(step, "execute-and-close", () => api.executeOwnedStep(scope)); } catch (e: any) { while (e.cause) e = e.cause; throw e; } await timed(step, "complete", () => client.completeOwned(closed));
      if (step === "allocator") { const [rows] = await target.query<RowDataPacket[]>("SELECT manifest_sha256 FROM identity_migration_allocator_state WHERE id=1"); proof = rows[0].manifest_sha256; }
    } } finally {
      process.stderr.write(JSON.stringify({ diagnostic: "owned-four-step-costs", storage: "os-tmpdir-real-filesystem", fixtureWindowSetupMs, spySetupMs, costs }) + "\n");
    }
    const [rows] = await target.query<RowDataPacket[]>("SELECT authority FROM identity_migration_control WHERE id=1"); expect(rows[0].authority).toBe("identity");
    for (const step of ["allocator", "activation"]) {
      const path = physical(`/run/xrugc/identity-finalization/reports/${step}.journal.jsonl`), journal = await real.readFile(path, "utf8"); expect(journal.endsWith("\n")).toBe(true); expect(journal).toContain('"claimId"'); expect((await real.lstat(path)).mode & 0o777).toBe(0o600);
    }
    expect(calls.filter(p => p === "/migration-complete")).toHaveLength(4);
  });
  it("locks unknown after a real descriptor close failure, still waits every other close and never completes", async () => {
    const scope = await ready(), handle = handles[0], close = handle.close.bind(handle), inputCount = handles.length; let others = 0;
    vi.spyOn(handle, "close").mockImplementation(async () => { await close(); throw new Error("fixture actual close failure"); });
    for (const other of handles.slice(1)) { const finish = other.close.bind(other); vi.spyOn(other, "close").mockImplementation(async () => { await new Promise(r => setTimeout(r, 15)); await finish(); others++; }); }
    await expect(api.executeOwnedStep(scope)).rejects.toMatchObject({ outcome: "unknown" }); expect(others).toBe(inputCount - 1); expect(handles.every(h => h.fd === -1)).toBe(true); expect(calls).not.toContain("/migration-complete"); expect(() => client.assertKnown()).toThrow("UNKNOWN");
  });
  it("waits a delayed actual descriptor close before minting the private receipt", async () => {
    const scope = await ready(), handle = handles[0], close = handle.close.bind(handle); let release!: () => void, seen!: () => void, finished = false;
    const gate = new Promise<void>(r => { release = r; }), observed = new Promise<void>(r => { seen = r; });
    vi.spyOn(handle, "close").mockImplementation(async () => { seen(); await gate; await close(); });
    const pending = api.executeOwnedStep(scope).then((v: any) => { finished = true; return v; }); await observed; expect(finished).toBe(false); expect(handle.fd).not.toBe(-1); release(); const receipt = await pending; await expect(client.completeOwned(receipt)).resolves.toHaveProperty("chainSha256");
  });
  it("closes held descriptors when its owning client becomes unknown before execution", async () => {
    const scope = await ready(); await client.noteOwnedControlUnknown(); await expect(api.executeOwnedStep(scope)).rejects.toMatchObject({ outcome: "unknown" }); expect(handles.every(h => h.fd === -1)).toBe(true); expect(calls).not.toContain("/migration-complete");
  });
  it("preserves a committed target write as unknown if the actual post-source snapshot drifts", async () => {
    const scope = await ready(); fault = "post-source-drift"; await expect(api.executeOwnedStep(scope)).rejects.toMatchObject({ outcome: "unknown" }); const [rows] = await target.query<RowDataPacket[]>("SELECT nickname FROM user WHERE id=7301"); expect(rows[0].nickname).toBe("Reviewed"); expect(calls).not.toContain("/migration-complete"); expect(connections.every(c => (c as any).connection.stream.closed)).toBe(true);
  });
  it("marks an actual typed-output fsync failure unknown after the business commit and closes all resources", async () => {
    const scope = await ready(), open = vi.mocked(fs.open).getMockImplementation()!;
    vi.mocked(fs.open).mockImplementation((async (p: string, ...args: any[]) => { const h = await (open as any)(p, ...args); if (p.endsWith(".typed-output.json")) vi.spyOn(h, "sync").mockRejectedValue(new Error("fixture fsync failed")); return h; }) as any);
    await expect(api.executeOwnedStep(scope)).rejects.toMatchObject({ outcome: "unknown" }); expect(handles.every(h => h.fd === -1)).toBe(true); expect(calls).not.toContain("/migration-complete"); const [rows] = await target.query<RowDataPacket[]>("SELECT nickname FROM user WHERE id=7301"); expect(rows[0].nickname).toBe("Reviewed");
  });
  it("closes a genuine held scope even when extra execution arguments are refused", async () => {
    const scope = await ready(); await expect(api.executeOwnedStep(scope, "forbidden")).rejects.toMatchObject({ outcome: "unknown" }); expect(handles.every(h => h.fd === -1)).toBe(true); expect(calls).not.toContain("/migration-complete");
  });
  it("cannot revive a preparation after concurrent close has returned", async () => {
    const open = vi.mocked(fs.open).getMockImplementation()!; let release!: () => void, seen!: () => void, first = true, closed = false;
    const gate = new Promise<void>(r => { release = r; }), observed = new Promise<void>(r => { seen = r; });
    vi.mocked(fs.open).mockImplementation((async (...args: any[]) => { if (first) { first = false; seen(); await gate; } return (open as any)(...args); }) as any);
    const pending = client.prepareOwnedPlan(); const failed = expect(pending).rejects.toMatchObject({ outcome: "unknown" }); await observed;
    const closing = client.closePreparedPlan().finally(() => { closed = true; }); const rejected = expect(closing).rejects.toMatchObject({ outcome: "unknown" }); expect(closed).toBe(false); release(); await Promise.all([failed, rejected]); expect(handles.every(h => h.fd === -1)).toBe(true); await expect(client.enterOwned(makeClaim(), capability)).rejects.toThrow("UNKNOWN");
  });
  it("owns a failed MySQL handshake socket and waits its physical close", async () => {
    await real.writeFile(credentialsPath, JSON.stringify({ version: 1, source: { user, password: "wrong-fixture-password" }, target: { user, password } }), { mode: 0o600 });
    await expect(client.prepareOwnedPlan()).rejects.toMatchObject({ outcome: "unknown" }); expect(connections.length).toBe(1); expect((connections[0] as any).connection.stream.closed).toBe(true); expect(handles.every(h => h.fd === -1)).toBe(true);
    await real.writeFile(credentialsPath, JSON.stringify({ version: 1, source: { user, password }, target: { user, password } }), { mode: 0o600 });
  });
  it("forbids caller resources through an owned scope and cannot mint from a fake receipt", async () => {
    const scope = await ready(); await expect(api.invokeNativeMigration(scope, {})).rejects.toThrow("OWNED_SCOPE_ONLY"); await expect(client.completeOwned({})).rejects.toThrow("CLOSED_RECEIPT_REQUIRED"); await expect(api.executeOwnedStep(scope)).resolves.toBeDefined();
  });
  it.each(["drop", "hash"])("permanently locks unknown after a %s completion ACK without retrying a committed write", async f => {
    const closed = await api.executeOwnedStep(await ready()); fault = f; await expect(client.completeOwned(closed)).rejects.toMatchObject({ outcome: "unknown" }); expect(calls.filter(p => p === "/migration-complete")).toHaveLength(1); await expect(client.prepareOwnedPlan()).rejects.toThrow("UNKNOWN");
  });
  it("closes held input descriptors when scope expires before execution", async () => {
    const scope = await ready(), now = vi.spyOn(Date, "now").mockReturnValue(Date.parse(plan.window.deadline) + 1); await expect(api.executeOwnedStep(scope)).rejects.toMatchObject({ outcome: "unknown" }); now.mockRestore(); expect(handles.every(h => h.fd === -1)).toBe(true); expect(calls).not.toContain("/migration-complete");
  });
  it("rejects source drift after enter before writing target and closes every acquired resource", async () => {
    const scope = await ready(); await source.query("UPDATE user SET nickname='Unreviewed' WHERE id=7301"); await expect(api.executeOwnedStep(scope)).rejects.toMatchObject({ outcome: "unknown" }); expect(handles.every(h => h.fd === -1)).toBe(true); expect(connections.every(c => (c as any).connection.stream.closed)).toBe(true); const [rows] = await target.query<RowDataPacket[]>("SELECT nickname FROM user WHERE id=7301"); expect(rows[0].nickname).toBe("Before");
  });
});
