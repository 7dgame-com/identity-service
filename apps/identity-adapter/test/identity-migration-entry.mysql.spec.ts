import "reflect-metadata";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, readFile, writeFile, rm } from "node:fs/promises";
import { createServer } from "node:http";
import { once } from "node:events";
import { randomUUID, randomBytes, createHash } from "node:crypto";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import mysql, { type Connection, type RowDataPacket } from "mysql2/promise";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
const enabled = process.env.IDENTITY_TEST_MYSQL === "1", root = fileURLToPath(new URL("../../../", import.meta.url));
const options = { host: process.env.IDENTITY_TEST_MYSQL_HOST ?? "127.0.0.1", port: Number(process.env.IDENTITY_TEST_MYSQL_PORT ?? 13316), user: process.env.IDENTITY_TEST_MYSQL_USER ?? "root", password: process.env.IDENTITY_TEST_MYSQL_PASSWORD ?? "", timezone: "Z", multipleStatements: true };
const execute = promisify(execFile), revision = "a".repeat(40), hex = "b".repeat(64), capability = `${"x".repeat(43)}.${"y".repeat(43)}`;
const sourceSnapshot = Buffer.from('{"version":1}\n'), sha = (b: Buffer) => createHash("sha256").update(b).digest("hex");
const executor = { id: "migration-fixture", bootId: "fixture_boot_20261022" };

describe.skipIf(!enabled)("compiled dedicated migration scopes with real MySQL", () => {
  let build: string, configPath: string, keyPath: string, admin: Connection, source: Connection, target: Connection, fence: Connection;
  let sourceName: string, targetName: string, api: any, admission: any, account: any, sync: any, activation: any, allocator: any, resourcesModule: any, resources: any;
  let server: ReturnType<typeof createServer>, targetBinding: any, claimTemplate: any, calls: string[];
  beforeAll(async () => {
    if (!["127.0.0.1", "localhost", "::1"].includes(options.host)) throw new Error("Only disposable local MySQL is allowed for this fixture");
    admin = await mysql.createConnection(options);
    const [serverRows] = await admin.query<RowDataPacket[]>("SELECT @@server_uuid AS uuid");
    const suffix = randomUUID().replaceAll("-", ""); sourceName = `test_migration_source_${suffix}`; targetName = `test_migration_target_${suffix}`;
    build = await mkdtemp(join(root, ".identity-migration-entry-build-"));
    await execute(process.execPath, [join(root, "node_modules/typescript/bin/tsc"), "--outDir", build, "--noEmitOnError", "true"], { cwd: root, timeout: 90000, maxBuffer: 1024 * 1024 });
    const src = join(build, "apps/identity-adapter/src");
    await writeFile(join(src, "generated/iam-organization-reconciliation-compiled-revision.js"), `export const ORGANIZATION_RECONCILIATION_COMPILED_BUILD_REVISION=${JSON.stringify(revision)};\n`);
    // Only this disposable compiled fixture substitutes the immutable target. The
    // production module has no test flag, configurable target or scope factory.
    const entryPath = join(src, "identity-migration-entry.js");
    let code = await readFile(entryPath, "utf8");
    for (const [from, to] of [["10.206.0.5", "127.0.0.1"], ["xrugc_identity_dev", targetName], ["bujiaban_development", sourceName], ["identity_dev", options.user], ["1c6c32c4-00a9-11f1-9d18-0c42a14c701e", String(serverRows[0].uuid)]]) code = code.replaceAll(JSON.stringify(from), JSON.stringify(to));
    code = code.replace("port: 3306", `port: ${options.port}`); await writeFile(entryPath, code);
    const load = (n: string) => import(pathToFileURL(join(src, `${n}.js`)).href);
    [api, admission, account, sync, activation, allocator, resourcesModule] = await Promise.all([load("identity-migration-entry"), load("identity-admission"), load("identity-account-import"), load("identity-account-sync"), load("identity-activation"), load("identity-allocator-finalizer"), load("identity-migration-resources")]);
    const key = randomBytes(32).toString("base64url");
    server = createServer(async (req, res) => {
      calls.push(req.url!); if (req.headers.authorization !== `Bearer ${key}`) { res.writeHead(401).end(); return; }
      const chunks: Buffer[] = []; for await (const b of req) chunks.push(Buffer.from(b)); const body = JSON.parse(Buffer.concat(chunks).toString());
      if (req.url === "/migration-unknown") { res.end("{}"); return; }
      res.end(JSON.stringify({ version: 1, nonce: body.nonce, requestSha256: body.requestSha256, claim: body.claim, scopeCapability: capability }));
    }).listen(0, "127.0.0.1"); await once(server, "listening");
    targetBinding = { host: "127.0.0.1", port: options.port, database: targetName, principal: options.user, fenceId: 1 };
    configPath = join(build, "private-config.json"); keyPath = join(build, "private-key");
    await writeFile(configPath, JSON.stringify({ version: 1, controlUrl: `http://127.0.0.1:${(server.address() as any).port}/`, executor, compiledRevision: revision, imageDigest: `sha256:${hex}`, target: targetBinding }), { mode: 0o600 }); await writeFile(keyPath, key, { mode: 0o600 });
  }, 90000);
  beforeEach(async () => {
    vi.stubEnv("IDENTITY_ADMISSION_ENABLED", "false"); calls = [];
    for (const name of [sourceName, targetName]) await admin.query(`CREATE DATABASE \`${name}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`);
    resources = new resourcesModule.MigrationResources();
    source = resources.connection(await mysql.createConnection({ ...options, database: sourceName })); target = resources.connection(await mysql.createConnection({ ...options, database: targetName })); fence = resources.connection(await mysql.createConnection({ ...options, database: targetName }));
    const init = await readFile(join(root, "deploy/mysql/init.sql"), "utf8");
    await target.query(init.slice(init.indexOf("CREATE TABLE IF NOT EXISTS `auth_login_events`")));
    for (const schema of ["identity-account-schema.sql", "identity-password-reset-token-schema.sql", "identity-legacy-challenge-schema.sql", "identity-runtime-schema.sql", "identity-wechat-oauth-schema.sql", "identity-qrcode-schema.sql", "identity-apple-schema.sql", "identity-allocator-schema.sql", "identity-activation-schema.sql"]) await target.query(await readFile(join(root, "deploy/mysql", schema), "utf8"));
    const accountSql = await readFile(join(root, "deploy/mysql/identity-account-schema.sql"), "utf8");
    for (const statement of accountSql.split(";")) { const table = statement.match(/CREATE TABLE IF NOT EXISTS `?([a-z_]+)`?\s*\(/)?.[1]; if (table && Object.hasOwn(account.accountImportTables, table)) await source.query(statement); }
    await source.query("INSERT INTO user(id,username,status,nickname,password_hash) VALUES(7001,'before',10,'Before','hash')");
    await account.importIdentityAccounts(source, target, { importKey: "fixture", apply: true });
    vi.stubEnv("IDENTITY_ADMISSION_ENABLED", "true"); vi.stubEnv("IDENTITY_MIGRATION_CONFIG_FILE", configPath); vi.stubEnv("IDENTITY_MIGRATION_KEY_FILE", keyPath);
    const inputs = { sourceSnapshotSha256: sha(sourceSnapshot), profileSelectionSha256: null, limits: { maxChanges: 10, maxRows: 100 }, apply: true };
    claimTemplate = { version: 1, runId: randomUUID(), claimId: randomUUID(), planSha256: hex, epoch: 1, drainSha256: hex, compiledRevision: revision, imageDigest: `sha256:${hex}`, executor, target: targetBinding, stepId: "sync-apply", entry: "account-sync", entrypoint: "dist/scripts/account-sync.js", entrySha256: hex, mode: "apply", inputs, inputSha256: api.migrationBindingSha256(inputs), previousChainSha256: hex };
  }, 30000);
  afterEach(async () => {
    vi.unstubAllEnvs(); await resources?.close(false, undefined);
    for (const name of [sourceName, targetName]) await admin.query(`DROP DATABASE IF EXISTS \`${name}\``);
  });
  afterAll(async () => { server?.closeAllConnections(); if (server) await new Promise<void>(r => server.close(() => r())); await admin?.end(); if (build) await rm(build, { recursive: true, force: true }); });
  const input = () => ({ entry: "account-sync", source, target, sourceSnapshot, profileSelection: null });
  async function enter(c = claimTemplate) { return api.NativeMigrationAdmission.environment().enter({ ...c, deadline: c.stepId === "activation" ? c.inputs.deadline : new Date(Date.now() + 2900).toISOString() }, capability); }
  async function nickname() { const [rows] = await target.query<RowDataPacket[]>("SELECT nickname FROM user WHERE id=7001"); return rows[0].nickname; }
  async function allocatorInvocation() {
    const zeroClaim = { ...claimTemplate, stepId: "sync-zero", mode: "dry-run", inputs: { ...claimTemplate.inputs, apply: false } }; zeroClaim.inputSha256 = api.migrationBindingSha256(zeroClaim.inputs);
    const zeroReport = await api.invokeNativeMigration(await enter(zeroClaim), input()), finalSyncReport = Buffer.from(`${JSON.stringify(zeroReport)}\n`);
    const inventory = await allocator.readSourceAllocatorInventory(source);
    const review = Buffer.from(JSON.stringify({ version: 1, sourceDatabase: sourceName, targetDatabase: targetName, importKey: "fixture", sourceServerUuid: inventory.serverUuid, writersDrainedAt: new Date().toISOString(), finalSyncSha256: sha(finalSyncReport), referenceReviewSha256: inventory.referenceReviewSha256 }));
    const inputs = { reviewSha256: sha(review), finalSyncReportSha256: sha(finalSyncReport), sourceSnapshotSha256: sha(sourceSnapshot) };
    const c = { ...claimTemplate, claimId: randomUUID(), stepId: "allocator", entry: "allocator-highwater", entrypoint: "dist/scripts/allocator-highwater.js", inputs, inputSha256: api.migrationBindingSha256(inputs) };
    const journal = await resources.openReport(join(build, `allocator-${randomUUID()}.jsonl`));
    return { c, invocation: { entry: "allocator-highwater", source, target, fence, sourceSnapshot: Buffer.from(sourceSnapshot), review, finalSyncReport, journal } };
  }
  async function finalizeViaRegistry() { const { c, invocation } = await allocatorInvocation(); return api.invokeNativeMigration(await enter(c), invocation); }
  it("allows a verified sync apply on actual selected source/target and consumes scope once", async () => {
    await source.query("UPDATE user SET nickname='After' WHERE id=7001"); const scope = await enter();
    await expect(api.invokeNativeMigration(scope, input())).resolves.toMatchObject({ applied: true, changes: 1 }); expect(await nickname()).toBe("After");
    await expect(api.invokeNativeMigration(scope, input())).rejects.toThrow("VERIFIED_SINGLE_USE"); expect(calls).toEqual(["/migration-enter"]);
  });
  it("runs the real sync zero audit without applying a source change", async () => {
    await source.query("UPDATE user SET nickname='Unapplied' WHERE id=7001");
    const c = { ...claimTemplate, stepId: "sync-zero", mode: "dry-run", inputs: { ...claimTemplate.inputs, apply: false } }; c.inputSha256 = api.migrationBindingSha256(c.inputs);
    await expect(api.invokeNativeMigration(await enter(c), input())).resolves.toMatchObject({ applied: false, changes: 1 }); expect(await nickname()).toBe("Before");
  });
  it("refuses all three real cores before their first SQL when ordinary admission is enabled", async () => {
    const query = vi.spyOn(target, "query");
    const refusal = { response: { code: "ADMISSION_WRITER_SCOPE_REQUIRED" } };
    await expect(sync.syncIdentityAccounts(source, target, { apply: true, maxChanges: 10 })).rejects.toMatchObject(refusal);
    await expect(allocator.finalizeAllocator({ source, target, fence, apply: true })).rejects.toMatchObject(refusal);
    await expect(activation.activateExplicitIdentity({ connection: target, apply: true })).rejects.toMatchObject(refusal);
    expect(query).not.toHaveBeenCalled(); query.mockRestore(); expect(await nickname()).toBe("Before");
  });
  it("refuses a reviewed-looking connection that actually selected the source as target", async () => {
    await source.query("UPDATE user SET nickname='MustNotApply' WHERE id=7001");
    await expect(api.invokeNativeMigration(await enter(), { ...input(), target: source })).rejects.toMatchObject({ outcome: "unknown" }); expect(await nickname()).toBe("Before"); expect(calls).toEqual(["/migration-enter", "/migration-unknown"]);
  });
  it("cannot borrow a sync scope for activation, including an owned intent journal", async () => {
    const journal = await resources.openReport(join(build, `journal-${randomUUID()}.jsonl`));
    await expect(api.invokeNativeMigration(await enter(), { entry: "identity-activate", target, journal })).rejects.toMatchObject({ outcome: "unknown" });
    const [rows] = await target.query<RowDataPacket[]>("SELECT authority FROM identity_migration_control WHERE id=1"); expect(rows[0].authority).toBe("staging");
  });
  it("refuses an existing caller transaction without committing or rolling back its marker", async () => {
    await target.beginTransaction(); await target.query("INSERT INTO user(id,username,status) VALUES(7777,'uncommitted-caller',10)");
    const visible = async () => (await admin.query<RowDataPacket[]>(`SELECT COUNT(*) AS n FROM \`${targetName}\`.user WHERE id=7777`))[0][0].n;
    expect(Number(await visible())).toBe(0);
    await expect(api.invokeNativeMigration(await enter(), input())).rejects.toMatchObject({ outcome: "unknown" });
    expect(Number(await visible())).toBe(0); const [own] = await target.query<RowDataPacket[]>("SELECT id FROM user WHERE id=7777"); expect(own).toHaveLength(1);
    await expect(target.query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")).rejects.toMatchObject({ code: "ER_CANT_CHANGE_TX_CHARACTERISTICS" }); await target.rollback();
  });
  it("refuses autocommit zero without changing the caller's mode", async () => {
    await target.query("SET SESSION autocommit=0");
    await expect(api.invokeNativeMigration(await enter(), input())).rejects.toMatchObject({ outcome: "unknown" });
    const [mode] = await target.query<RowDataPacket[]>("SELECT @@autocommit AS enabled"); expect(Number(mode[0].enabled)).toBe(0); await target.rollback(); await target.query("SET SESSION autocommit=1");
  });
  it("cannot borrow an allocator scope for real sync apply or activation", async () => {
    const inputs = { reviewSha256: hex, finalSyncReportSha256: hex, sourceSnapshotSha256: sha(sourceSnapshot) }, c = { ...claimTemplate, stepId: "allocator", entry: "allocator-highwater", entrypoint: "dist/scripts/allocator-highwater.js", inputs, inputSha256: api.migrationBindingSha256(inputs) };
    await expect(api.invokeNativeMigration(await enter(c), input())).rejects.toMatchObject({ outcome: "unknown" }); expect(await nickname()).toBe("Before");
  });
  it("awaits real allocator DDL and durable intent while leaving authority staging", async () => {
    const result = await finalizeViaRegistry(); expect(result).toMatchObject({ summary: { ready: true, authorityActivated: false, sourceWritten: false } });
    const [rows] = await target.query<RowDataPacket[]>("SELECT state,manifest_sha256 FROM identity_migration_allocator_state WHERE id=1"); expect(rows[0].state).toBe("ready"); expect(rows[0].manifest_sha256).toBe(result.plan.manifestSha256);
    const [authority] = await target.query<RowDataPacket[]>("SELECT authority FROM identity_migration_control WHERE id=1"); expect(authority[0].authority).toBe("staging");
  });
  it("keeps captured real connections, journal and bytes despite caller mutation during a delayed location query", async () => {
    const { c, invocation } = await allocatorInvocation(), scope = await enter(c);
    let release!: () => void, sawQuery!: () => void; const gate = new Promise<void>(r => { release = r; }), seen = new Promise<void>(r => { sawQuery = r; });
    const query = source.query.bind(source), spy = vi.spyOn(source, "query").mockImplementationOnce((async (...args: any[]) => { const rows = await (query as any)(...args); sawQuery(); await gate; return rows; }) as any);
    const pending = api.invokeNativeMigration(scope, invocation); await seen;
    const changed: any = invocation; changed.source = target; changed.target = source; changed.fence = source; changed.journal = { writeFile: vi.fn(), sync: vi.fn() }; changed.sourceSnapshot.fill(0); changed.review.fill(0); changed.finalSyncReport.fill(0); release();
    await expect(pending).resolves.toMatchObject({ summary: { ready: true, authorityActivated: false } }); spy.mockRestore();
    const [rows] = await target.query<RowDataPacket[]>("SELECT state FROM identity_migration_allocator_state WHERE id=1"); expect(rows[0].state).toBe("ready");
  });
  it("activates only with its own verified scope, actual allocator proof and synced commit intent", async () => {
    const finalized = await finalizeViaRegistry(), deadline = new Date(Date.now() + 2900).toISOString();
    const inputs = { expectedProofSha256: finalized.plan.manifestSha256, expectedRevision: revision, deadline, requestSha256: activation.activationRequestSha256(targetName, finalized.plan.manifestSha256, revision, deadline) };
    const c = { ...claimTemplate, claimId: randomUUID(), stepId: "activation", entry: "identity-activate", entrypoint: "dist/scripts/identity-activate.js", deadline, inputs, inputSha256: api.migrationBindingSha256(inputs) };
    const journal = await resources.openReport(join(build, `activation-${randomUUID()}.jsonl`));
    await expect(api.invokeNativeMigration(await enter(c), { entry: "identity-activate", target, journal })).resolves.toMatchObject({ outcome: "activated", authority: "identity", receipt: { requestSha256: inputs.requestSha256 } });
    const again = { ...c, claimId: randomUUID() }, againJournal = await resources.openReport(join(build, `activation-again-${randomUUID()}.jsonl`));
    await expect(api.invokeNativeMigration(await enter(again), { entry: "identity-activate", target, journal: againJournal })).resolves.toMatchObject({ outcome: "already_active", receipt: { requestSha256: inputs.requestSha256 } });
    const wrong = { ...c, claimId: randomUUID(), inputs: { ...inputs, requestSha256: hex } }; wrong.inputSha256 = api.migrationBindingSha256(wrong.inputs);
    const before = calls.length; await expect(enter(wrong)).rejects.toThrow("CLAIM_BINDING_MISMATCH"); expect(calls.length).toBe(before);
    const [rows] = await target.query<RowDataPacket[]>("SELECT authority FROM identity_migration_control WHERE id=1"); expect(rows[0].authority).toBe("identity"); expect(calls.every(p => p === "/migration-enter")).toBe(true);
  });
});
