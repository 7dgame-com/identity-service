import { constants } from "node:fs";
import { open, type FileHandle } from "node:fs/promises";
import { createHash } from "node:crypto";
import mysql, { type Connection } from "mysql2/promise";
import { loadConfig } from "../apps/identity-adapter/src/config.js";
import { syncIdentityAccounts } from "../apps/identity-adapter/src/identity-account-sync.js";
import {
  AllocatorError,
  assertZeroAccountSyncReport,
} from "../apps/identity-adapter/src/identity-allocator-manifest.js";
import {
  initializeFreshAllocator,
  readPrivateAllocatorInventory,
} from "../apps/identity-adapter/src/identity-allocator-state.js";
import {
  finalizeAllocator,
  readSourceAllocatorInventory,
  type AllocatorDrainReview,
} from "../apps/identity-adapter/src/identity-allocator-finalizer.js";
const sha = (s: Buffer | string) =>
  createHash("sha256").update(s).digest("hex");
async function protectedFile(path: string) {
  const f = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
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
  } finally {
    await f.close();
  }
}
async function main() {
  const args = process.argv.slice(2),
    usage =
      "allocator-highwater --inventory | --fresh --apply | --review=<0600.json> --review-sha256=<SHA256> --final-sync-report=<0600.json> --report=<new0600.json> [--apply --journal=<new0600.jsonl>]. Default: read-only.";
  if (args.includes("--help")) {
    console.log(usage);
    return;
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
  const connections: Connection[] = [],
    files: FileHandle[] = [];
  const connect = async (db: typeof targetCfg) => {
    const c = await mysql.createConnection({
      host: db.host,
      port: db.port,
      database: db.name,
      user: db.user,
      password: db.password,
      timezone: "Z",
      supportBigNumbers: true,
      bigNumberStrings: true,
      connectTimeout: 10000,
    });
    connections.push(c);
    await c.query("SET SESSION max_execution_time=10000");
    return c;
  };
  try {
    const target = await connect(targetCfg);
    if (args.includes("--fresh")) {
      if (args.length !== 2 || !args.includes("--apply"))
        throw new Error(usage);
      await initializeFreshAllocator(target);
      console.log(
        JSON.stringify({
          success: true,
          kind: "fresh",
          ready: true,
          authorityActivated: false,
        }),
      );
      return;
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
        console.log(
          JSON.stringify({
            success: true,
            applied: false,
            sourceDatabase: src.database,
            sourceServerUuid: src.serverUuid,
            referenceReviewSha256: src.referenceReviewSha256,
            sourceMetadataSha256: src.metadataSha256,
            targetSchemaSha256: dst.schemaSha256,
            tables: 6,
            authorityActivated: false,
          }),
        );
      } finally {
        await source.rollback();
      }
      return;
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
    const report = await open(
      reportPath,
      constants.O_WRONLY |
        constants.O_CREAT |
        constants.O_EXCL |
        constants.O_NOFOLLOW,
      0o600,
    );
    files.push(report);
    const journal = journalPath
      ? await open(
          journalPath,
          constants.O_WRONLY |
            constants.O_CREAT |
            constants.O_EXCL |
            constants.O_NOFOLLOW,
          0o600,
        )
      : undefined;
    if (journal) files.push(journal);
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
            await journal.write(
              JSON.stringify({ ...step, at: new Date().toISOString() }) + "\n",
            );
            await journal.sync();
          }
        : undefined,
    });
    await report.writeFile(JSON.stringify(plan, null, 2) + "\n");
    await report.sync();
    console.log(
      JSON.stringify({
        success: true,
        applied: args.includes("--apply"),
        ready: args.includes("--apply"),
        manifestSha256: plan.manifestSha256,
        tables: 6,
        authorityActivated: false,
        sourceWritten: false,
      }),
    );
  } finally {
    try {
      for (const f of files) await f.close();
    } finally {
      await Promise.allSettled(connections.map((c) => c.end()));
    }
  }
}
main().catch((error) => {
  console.error(
    JSON.stringify({
      success: false,
      code:
        error instanceof AllocatorError
          ? error.code
          : "ALLOCATOR_OPERATION_FAILED",
      automaticRetry: false,
      authorityActivated: false,
    }),
  );
  process.exitCode = 1;
});
