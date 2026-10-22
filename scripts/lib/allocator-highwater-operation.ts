import { constants } from "node:fs";
import { open } from "node:fs/promises";
import { createHash } from "node:crypto";
import mysql from "mysql2/promise";
import {
  withMigrationResources,
  writeMigrationReport,
} from "../../apps/identity-adapter/src/identity-migration-resources.js";
import { loadConfig } from "../../apps/identity-adapter/src/config.js";
import { syncIdentityAccounts } from "../../apps/identity-adapter/src/identity-account-sync.js";
import { assertZeroAccountSyncReport } from "../../apps/identity-adapter/src/identity-allocator-manifest.js";
import {
  initializeFreshAllocator,
  readPrivateAllocatorInventory,
} from "../../apps/identity-adapter/src/identity-allocator-state.js";
import {
  finalizeAllocator,
  readSourceAllocatorInventory,
  type AllocatorDrainReview,
} from "../../apps/identity-adapter/src/identity-allocator-finalizer.js";
const sha = (s: Buffer | string) =>
  createHash("sha256").update(s).digest("hex");
async function protectedFile(path: string) {
  return withMigrationResources(async (resources) => {
    const f = resources.file(
      await open(path, constants.O_RDONLY | constants.O_NOFOLLOW),
    );
    const st = await f.stat();
    if (
      !st.isFile() ||
      (st.mode & 0o777) !== 0o600 ||
      st.uid !== process.getuid?.() ||
      st.size > 65536 ||
      st.size < 2
    )
      throw new Error("Invalid protected input");
    return { body: await f.readFile(), modified: st.mtimeMs };
  });
}
export async function runAllocatorHighwaterOperation(args: readonly string[]) {
  const usage =
    "allocator-highwater --inventory | --fresh --apply | --review=<0600.json> --review-sha256=<SHA256> --final-sync-report=<0600.json> --report=<new0600.json> [--apply --journal=<new0600.jsonl>]. Default: read-only.";
  if (args.includes("--help")) {
    return { help: usage };
  }
  if (
    args.some(
      (x) =>
        !["--inventory", "--fresh", "--apply", "--dry-run"].includes(x) &&
        ![
          "--review=",
          "--review-sha256=",
          "--final-sync-report=",
          "--report=",
          "--journal=",
        ].some((p) => x.startsWith(p)),
    ) ||
    new Set(args.map((a) => a.split("=")[0])).size !== args.length ||
    (args.includes("--apply") && args.includes("--dry-run"))
  )
    throw new Error(usage);
  const value = (p: string) =>
      args.find((x) => x.startsWith(p))?.slice(p.length),
    config = loadConfig();
  const targetCfg = config.identityDb,
    sourceCfg = config.legacyDb;
  if (
    targetCfg.host !== "10.206.0.5" ||
    targetCfg.port !== 3306 ||
    targetCfg.name !== "xrugc_identity_dev" ||
    targetCfg.user !== "identity_dev"
  )
    throw new Error(
      "Only the reviewed direct development private target is allowed",
    );
  return withMigrationResources(async (resources) => {
    const connect = async (db: typeof targetCfg) => {
      const c = resources.connection(
        await mysql.createConnection({
          host: db.host,
          port: db.port,
          database: db.name,
          user: db.user,
          password: db.password,
          timezone: "Z",
          supportBigNumbers: true,
          bigNumberStrings: true,
          connectTimeout: 10000,
        }),
      );
      await c.query("SET SESSION max_execution_time=10000");
      return c;
    };
    const target = await connect(targetCfg);
    if (args.includes("--fresh")) {
      if (args.length !== 2 || !args.includes("--apply"))
        throw new Error(usage);
      await initializeFreshAllocator(target);
      return {
        success: true,
        kind: "fresh",
        ready: true,
        authorityActivated: false,
      };
    }
    if (
      sourceCfg.host !== "10.206.0.5" ||
      sourceCfg.port !== 3306 ||
      sourceCfg.name !== "bujiaban_development" ||
      !sourceCfg.user
    )
      throw new Error(
        "Only the reviewed direct development read-only source is allowed",
      );
    const source = await connect(sourceCfg);
    if (args.length === 0 || (args.length === 1 && args[0] === "--inventory")) {
      await source.query(
        "START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY",
      );
      try {
        const src = await readSourceAllocatorInventory(source),
          dst = await readPrivateAllocatorInventory(target);
        return {
          success: true,
          applied: false,
          sourceDatabase: src.database,
          sourceServerUuid: src.serverUuid,
          referenceReviewSha256: src.referenceReviewSha256,
          sourceMetadataSha256: src.metadataSha256,
          targetSchemaSha256: dst.schemaSha256,
          tables: 6,
          authorityActivated: false,
        };
      } finally {
        await source.rollback();
      }
    }
    const path = value("--review="),
      expected = value("--review-sha256="),
      syncPath = value("--final-sync-report="),
      reportPath = value("--report="),
      journalPath = value("--journal=");
    if (
      !path ||
      !expected ||
      !syncPath ||
      !reportPath ||
      (args.includes("--apply") && !journalPath) ||
      (!args.includes("--apply") && journalPath)
    )
      throw new Error(usage);
    const input = await protectedFile(path);
    if (!/^[a-f0-9]{64}$/.test(expected) || sha(input.body) !== expected)
      throw new Error("Reviewed file digest mismatch");
    const review = JSON.parse(input.body.toString()) as AllocatorDrainReview;
    if (
      review.sourceDatabase !== "bujiaban_development" ||
      review.targetDatabase !== "xrugc_identity_dev"
    )
      throw new Error("Review is for another schema");
    const sync = await protectedFile(syncPath),
      syncReport = JSON.parse(sync.body.toString());
    assertZeroAccountSyncReport(syncReport);
    if (
      sha(sync.body) !== review.finalSyncSha256 ||
      syncReport.applied !== false ||
      syncReport.changes !== 0 ||
      sync.modified < Date.parse(review.writersDrainedAt) ||
      input.modified < Date.parse(review.writersDrainedAt)
    )
      throw new Error("Final drained zero-change sync proof is required");
    // Re-run the existing read-only delta audit on these exact connections; a hand-authored
    // two-field JSON or stale zero report cannot substitute for the current source/target audit.
    assertZeroAccountSyncReport(
      await syncIdentityAccounts(source, target, {
        apply: false,
        maxChanges: 100000,
      }),
    );
    const report = await resources.openReport(reportPath);
    const journal = journalPath
      ? await resources.openReport(journalPath)
      : undefined;
    const fence = await connect(targetCfg);
    const plan = await finalizeAllocator({
      source,
      target,
      fence,
      review,
      reviewSha256: expected,
      apply: args.includes("--apply"),
      onStep: journal
        ? async (step) => {
            await writeMigrationReport(journal, {
              ...step,
              at: new Date().toISOString(),
            });
          }
        : undefined,
    });
    await writeMigrationReport(report, plan, 2);
    return {
      success: true,
      applied: args.includes("--apply"),
      ready: args.includes("--apply"),
      manifestSha256: plan.manifestSha256,
      tables: 6,
      authorityActivated: false,
      sourceWritten: false,
    };
  });
}
