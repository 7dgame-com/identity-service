import {
  mkdir,
  mkdtemp,
  readFile,
  rename,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { EventEmitter } from "node:events";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  MigrationResourceCloseError,
  MigrationResources,
} from "../src/identity-migration-resources.js";

const mocks = vi.hoisted(() => ({
  config: vi.fn(),
  connect: vi.fn(),
  sync: vi.fn(),
  fresh: vi.fn(),
  activate: vi.fn(),
  inspect: vi.fn(),
  finalize: vi.fn(),
}));
vi.mock("../src/config.js", () => ({ loadConfig: mocks.config }));
vi.mock("mysql2/promise", () => ({
  default: { createConnection: mocks.connect },
}));
vi.mock("../src/identity-account-sync.js", () => ({
  syncIdentityAccounts: mocks.sync,
}));
vi.mock("../src/identity-allocator-state.js", async (original) => ({
  ...(await original<object>()),
  initializeFreshAllocator: mocks.fresh,
}));
vi.mock("../src/identity-activation.js", async (original) => ({
  ...(await original<object>()),
  activateExplicitIdentity: mocks.activate,
  inspectExplicitActivation: mocks.inspect,
  immutableIdentityRevision: () => "a".repeat(40),
}));
vi.mock("../src/identity-allocator-finalizer.js", async (original) => ({
  ...(await original<object>()),
  finalizeAllocator: mocks.finalize,
}));

import { runAccountSyncOperation } from "../../../scripts/lib/account-sync-operation.js";
import { runAllocatorHighwaterOperation } from "../../../scripts/lib/allocator-highwater-operation.js";
import {
  runIdentityActivateOperation,
  IdentityActivationOperationError,
} from "../../../scripts/lib/identity-activate-operation.js";
import { connectAccountImportDatabases } from "../src/identity-account-import.js";

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}
const zeroReport = {
  applied: false,
  changes: 0,
  inserts: 0,
  updates: 0,
  deletions: 0,
  affectedSubjects: 0,
  tableChanges: {},
};
const connection = () => {
  const stream = Object.assign(new EventEmitter(), { closed: false });
  const end = vi.fn(async () => {});
  // The test double's transport closes even when the mocked end callback fails.
  // Dedicated transport tests separately control an early end/late physical close.
  const physicalEnd = new Proxy(end, {
    apply: (target, receiver, args) => {
      let operation: Promise<unknown>;
      try {
        operation = Promise.resolve(Reflect.apply(target, receiver, args));
      } catch (error) {
        operation = Promise.reject(error);
      }
      return operation.finally(() => {
        stream.closed = true;
        stream.emit("close", false);
      });
    },
  });
  return {
    query: vi.fn(async () => [[{ principal: "identity_dev" }]]),
    connection: { stream },
    end: physicalEnd,
  };
};

const activationArgs = (path: string) => [
  `--expected-proof-sha256=${"b".repeat(64)}`,
  `--expected-revision=${"a".repeat(40)}`,
  "--deadline=2030-01-01T00:00:00.000Z",
  `--report=${path}`,
  "--apply",
];
let directory: string;
beforeEach(async () => {
  for (const mock of Object.values(mocks)) mock.mockReset();
  mocks.config.mockReturnValue({
    dataSource: "identity",
    activationMode: "explicit",
    identityDb: {
      host: "10.206.0.5",
      port: 3306,
      name: "xrugc_identity_dev",
      user: "identity_dev",
      password: "",
    },
    legacyDb: {
      host: "10.206.0.5",
      port: 3306,
      name: "bujiaban_development",
      user: "fixture_source",
      password: "",
    },
  });
  directory = await mkdtemp(join(tmpdir(), "identity-awaited-cli-"));
});
afterEach(async () => {
  vi.restoreAllMocks();
  await rm(directory, { recursive: true, force: true });
});

describe("import-safe awaited compatibility CLI operations", () => {
  it("imports all three executable wrappers without opening connections, loading config or running business", async () => {
    const log = vi.spyOn(console, "log"),
      error = vi.spyOn(console, "error"),
      exitCode = process.exitCode;
    await import("../../../scripts/account-sync.js");
    await import("../../../scripts/allocator-highwater.js");
    await import("../../../scripts/identity-activate.js");
    expect(mocks.config).not.toHaveBeenCalled();
    expect(mocks.connect).not.toHaveBeenCalled();
    expect(mocks.sync).not.toHaveBeenCalled();
    expect(mocks.fresh).not.toHaveBeenCalled();
    expect(mocks.activate).not.toHaveBeenCalled();
    expect(log).not.toHaveBeenCalled();
    expect(error).not.toHaveBeenCalled();
    expect(process.exitCode).toBe(exitCode);
  });
  it("supports help without reading environment or opening connections", async () => {
    for (const run of [
      runAccountSyncOperation,
      runAllocatorHighwaterOperation,
      runIdentityActivateOperation,
    ])
      expect(await run(["--help"])).toHaveProperty("help");
    expect(mocks.config).not.toHaveBeenCalled();
    expect(mocks.connect).not.toHaveBeenCalled();
  });
  it("account sync waits for its real result, report fsync and both late closes", async () => {
    const source = connection(),
      target = connection(),
      business = deferred(),
      late = deferred(),
      closing = deferred();
    mocks.connect.mockResolvedValueOnce(source).mockResolvedValueOnce(target);
    mocks.sync.mockImplementation(async () => {
      await business.promise;
      return zeroReport;
    });
    target.end.mockImplementation(async () => {
      closing.resolve();
      await late.promise;
    });
    const path = join(directory, "sync.json");
    let settled = false;
    const operation = runAccountSyncOperation([
      "--max-changes=100",
      `--report=${path}`,
    ]).finally(() => {
      settled = true;
    });
    await vi.waitFor(() => expect(mocks.sync).toHaveBeenCalledOnce());
    expect(source.end).not.toHaveBeenCalled();
    business.resolve();
    await closing.promise;
    expect(JSON.parse(await readFile(path, "utf8"))).toEqual(zeroReport);
    expect((await stat(path)).mode & 0o777).toBe(0o600);
    expect(source.end).toHaveBeenCalledOnce();
    expect(settled).toBe(false);
    late.resolve();
    expect(await operation).toEqual(zeroReport);
  });
  it("account sync waits for the other connection after a close rejects", async () => {
    const source = connection(),
      target = connection(),
      late = deferred(),
      closing = deferred();
    source.end.mockRejectedValue(new Error("source end"));
    target.end.mockImplementation(async () => {
      closing.resolve();
      await late.promise;
    });
    mocks.connect.mockResolvedValueOnce(source).mockResolvedValueOnce(target);
    mocks.sync.mockResolvedValue(zeroReport);
    let settled = false;
    const operation = runAccountSyncOperation(["--max-changes=100"]);
    const observed = operation.catch((error) => {
      settled = true;
      return error;
    });
    await closing.promise;
    expect(settled).toBe(false);
    late.resolve();
    expect(await observed).toBeInstanceOf(MigrationResourceCloseError);
  });
  it("account sync never overwrites or follows an existing report", async () => {
    const original = join(directory, "retained.json"),
      link = join(directory, "report-link.json");
    await writeFile(original, "retained fixture report\n", { mode: 0o600 });
    await symlink(original, link);
    for (const path of [original, link]) {
      const source = connection(),
        target = connection();
      mocks.connect.mockResolvedValueOnce(source).mockResolvedValueOnce(target);
      await expect(
        runAccountSyncOperation(["--max-changes=100", `--report=${path}`]),
      ).rejects.toMatchObject({ code: "EEXIST" });
      expect(source.end).toHaveBeenCalledOnce();
      expect(target.end).toHaveBeenCalledOnce();
      expect(await readFile(original, "utf8")).toBe(
        "retained fixture report\n",
      );
    }
    expect(mocks.sync).not.toHaveBeenCalled();
  });
  it("account sync explicitly fails unknown when report durability fails after business commits", async () => {
    const source = connection(),
      target = connection();
    mocks.connect.mockResolvedValueOnce(source).mockResolvedValueOnce(target);
    mocks.sync.mockResolvedValue({ ...zeroReport, applied: true });
    const original = MigrationResources.prototype.openReport;
    vi.spyOn(MigrationResources.prototype, "openReport").mockImplementation(
      async function (this: MigrationResources, name: string) {
        const report = await original.call(this, name);
        report.sync = async () => {
          throw new Error("report durability");
        };
        return report;
      },
    );
    await expect(
      runAccountSyncOperation([
        "--apply",
        "--max-changes=100",
        `--report=${join(directory, "failed-report.json")}`,
      ]),
    ).rejects.toMatchObject({
      code: "MIGRATION_REPORT_WRITE_UNKNOWN",
      outcome: "unknown",
      automaticRetry: false,
    });
    expect(mocks.sync).toHaveBeenCalledOnce();
    expect(source.end).toHaveBeenCalledOnce();
    expect(target.end).toHaveBeenCalledOnce();
  });
  it("partial connection acquisition waits for source cleanup and preserves acquisition failure", async () => {
    const source = connection(),
      late = deferred(),
      closing = deferred(),
      failure = new Error("target unavailable");
    source.end.mockImplementation(async () => {
      closing.resolve();
      await late.promise;
    });
    mocks.connect.mockResolvedValueOnce(source).mockRejectedValueOnce(failure);
    let settled = false;
    const observed = connectAccountImportDatabases().catch((error) => {
      settled = true;
      return error;
    });
    await closing.promise;
    expect(settled).toBe(false);
    late.resolve();
    expect(await observed).toBe(failure);
  });
  it("observes source failure while target connection acquisition is still pending", async () => {
    const source = connection(),
      target = connection(),
      waiting = deferred(),
      transportError = new Error("source died while acquiring target");
    let supplyTarget!: (value: ReturnType<typeof connection>) => void;
    mocks.connect.mockResolvedValueOnce(source).mockImplementationOnce(() => {
      waiting.resolve();
      return new Promise((resolve) => {
        supplyTarget = resolve;
      });
    });
    mocks.sync.mockResolvedValue(zeroReport);
    const operation = runAccountSyncOperation(["--max-changes=100"]),
      observed = operation.catch((error) => error);
    await waiting.promise;
    expect(() =>
      source.connection.stream.emit("error", transportError),
    ).not.toThrow();
    source.connection.stream.closed = true;
    source.connection.stream.emit("close", true);
    supplyTarget(target);
    expect(await observed).toMatchObject({
      code: "MIGRATION_RESOURCE_CLOSE_UNKNOWN",
      errors: [transportError],
      automaticRetry: false,
    });
    expect(source.end).toHaveBeenCalledOnce();
    expect(target.end).toHaveBeenCalledOnce();
  });
  it("hands a successful legacy no-owner pair back without installing or retaining observers", async () => {
    const source = Object.assign(new EventEmitter(), connection()),
      target = Object.assign(new EventEmitter(), connection());
    mocks.connect.mockResolvedValueOnce(source).mockResolvedValueOnce(target);
    const pair = await connectAccountImportDatabases();
    expect(pair).toEqual({ source, target });
    for (const c of [source, target]) {
      expect(c.listenerCount("error")).toBe(0);
      expect(c.connection.stream.listenerCount("error")).toBe(0);
      expect(c.connection.stream.listenerCount("close")).toBe(0);
    }
    const failure = new Error("owned by legacy caller, not swallowed");
    expect(() => source.emit("error", failure)).toThrow(failure);
    await Promise.all([source.end(), target.end()]);
    for (const c of [source, target]) expect(c.listenerCount("error")).toBe(0);
  });
  it("explicit awaited ownership removes its observers after a successful pair completes", async () => {
    const source = Object.assign(new EventEmitter(), connection()),
      target = Object.assign(new EventEmitter(), connection());
    mocks.connect.mockResolvedValueOnce(source).mockResolvedValueOnce(target);
    mocks.sync.mockImplementation(async () => {
      for (const c of [source, target])
        expect(c.listenerCount("error")).toBe(1);
      return zeroReport;
    });
    expect(await runAccountSyncOperation(["--max-changes=100"])).toEqual(
      zeroReport,
    );
    for (const c of [source, target]) {
      expect(c.listenerCount("error")).toBe(0);
      expect(c.connection.stream.listenerCount("error")).toBe(0);
      expect(c.connection.stream.listenerCount("close")).toBe(0);
    }
  });
  it("detects a real parent directory replacement before writing a post-commit report", async () => {
    const source = connection(),
      target = connection(),
      reports = join(directory, "reports"),
      retained = join(directory, "retained-reports");
    await mkdir(reports);
    mocks.connect.mockResolvedValueOnce(source).mockResolvedValueOnce(target);
    mocks.sync.mockImplementation(async () => {
      await rename(reports, retained);
      await mkdir(reports);
      return { ...zeroReport, applied: true };
    });
    await expect(
      runAccountSyncOperation([
        "--apply",
        "--max-changes=100",
        `--report=${join(reports, "sync.json")}`,
      ]),
    ).rejects.toMatchObject({
      code: "MIGRATION_REPORT_WRITE_UNKNOWN",
      outcome: "unknown",
      automaticRetry: false,
      cause: { message: "MIGRATION_REPORT_PARENT_CHANGED" },
    });
    expect(await readFile(join(retained, "sync.json"), "utf8")).toBe("");
    await expect(stat(join(reports, "sync.json"))).rejects.toMatchObject({
      code: "ENOENT",
    });
    expect(source.end).toHaveBeenCalledOnce();
    expect(target.end).toHaveBeenCalledOnce();
  });
  it("same-endpoint rejection still awaits every connection and fails unknown when any close fails", async () => {
    const config = mocks.config();
    config.legacyDb = { ...config.identityDb };
    const source = connection(),
      target = connection(),
      late = deferred(),
      closing = deferred();
    target.end.mockRejectedValue(new Error("end"));
    source.end.mockImplementation(async () => {
      closing.resolve();
      await late.promise;
    });
    mocks.connect.mockResolvedValueOnce(source).mockResolvedValueOnce(target);
    let settled = false;
    const observed = connectAccountImportDatabases().catch((error) => {
      settled = true;
      return error;
    });
    await closing.promise;
    expect(settled).toBe(false);
    late.resolve();
    const failure = await observed;
    expect(failure).toBeInstanceOf(MigrationResourceCloseError);
    expect(failure.errors).toHaveLength(2);
  });
  it("allocator fresh waits for initialization and late close", async () => {
    const target = connection(),
      init = deferred(),
      late = deferred(),
      closing = deferred();
    mocks.connect.mockResolvedValue(target);
    mocks.fresh.mockImplementation(async () => {
      await init.promise;
    });
    target.end.mockImplementation(async () => {
      closing.resolve();
      await late.promise;
    });
    let settled = false;
    const operation = runAllocatorHighwaterOperation([
      "--fresh",
      "--apply",
    ]).finally(() => {
      settled = true;
    });
    await vi.waitFor(() => expect(mocks.fresh).toHaveBeenCalledOnce());
    expect(target.end).not.toHaveBeenCalled();
    init.resolve();
    await closing.promise;
    expect(settled).toBe(false);
    late.resolve();
    expect(await operation).toMatchObject({ success: true, ready: true });
  });
  it("allocator rejects a failed close even after successful initialization", async () => {
    const target = connection();
    target.end.mockRejectedValue(new Error("close"));
    mocks.connect.mockResolvedValue(target);
    mocks.fresh.mockResolvedValue(undefined);
    await expect(
      runAllocatorHighwaterOperation(["--fresh", "--apply"]),
    ).rejects.toMatchObject({
      code: "MIGRATION_RESOURCE_CLOSE_UNKNOWN",
      outcome: "unknown",
    });
  });
  it("allocator retains a failed journal fsync even when core cleanup replaces its exception", async () => {
    const target = connection(),
      source = connection(),
      fence = connection();
    mocks.connect
      .mockResolvedValueOnce(target)
      .mockResolvedValueOnce(source)
      .mockResolvedValueOnce(fence);
    mocks.sync.mockResolvedValue(zeroReport);
    const digest = (text: string) =>
        createHash("sha256").update(text).digest("hex"),
      syncBody = `${JSON.stringify(zeroReport)}\n`;
    const reviewBody = JSON.stringify({
      version: 1,
      sourceDatabase: "bujiaban_development",
      targetDatabase: "xrugc_identity_dev",
      writersDrainedAt: new Date(Date.now() - 1000).toISOString(),
      finalSyncSha256: digest(syncBody),
    });
    const review = join(directory, "review.json"),
      sync = join(directory, "sync.json"),
      journal = join(directory, "journal.jsonl");
    await writeFile(review, reviewBody, { mode: 0o600 });
    await writeFile(sync, syncBody, { mode: 0o600 });
    const original = MigrationResources.prototype.openReport;
    vi.spyOn(MigrationResources.prototype, "openReport").mockImplementation(
      async function (this: MigrationResources, name: string) {
        const report = await original.call(this, name);
        if (name === journal)
          report.sync = async () => {
            throw new Error("journal fsync");
          };
        return report;
      },
    );
    mocks.finalize.mockImplementation(async ({ onStep }) => {
      try {
        await onStep({ phase: "intent", table: "user", floor: "1" });
      } finally {
        throw new Error("fence rollback");
      }
    });
    await expect(
      runAllocatorHighwaterOperation([
        `--review=${review}`,
        `--review-sha256=${digest(reviewBody)}`,
        `--final-sync-report=${sync}`,
        `--report=${join(directory, "plan.json")}`,
        `--journal=${journal}`,
        "--apply",
      ]),
    ).rejects.toMatchObject({
      code: "MIGRATION_REPORT_WRITE_UNKNOWN",
      outcome: "unknown",
      automaticRetry: false,
    });
    expect(target.end).toHaveBeenCalledOnce();
    expect(source.end).toHaveBeenCalledOnce();
    expect(fence.end).toHaveBeenCalledOnce();
  });
  it("activation fsyncs commit intent before business continuation, then waits for close", async () => {
    const db = connection(),
      late = deferred(),
      closing = deferred(),
      path = join(directory, "activation.jsonl"),
      receipt = { requestSha256: "f".repeat(64) };
    mocks.connect.mockResolvedValue(db);
    db.end.mockImplementation(async () => {
      closing.resolve();
      await late.promise;
    });
    mocks.activate.mockImplementation(async ({ onCommitIntent }) => {
      await onCommitIntent(receipt);
      expect(
        (await readFile(path, "utf8"))
          .trim()
          .split("\n")
          .map((line) => JSON.parse(line).phase),
      ).toEqual(["prepared", "commit_intent"]);
      return { outcome: "activated", authority: "identity", receipt };
    });
    let settled = false;
    const operation = runIdentityActivateOperation(
      activationArgs(path),
    ).finally(() => {
      settled = true;
    });
    await closing.promise;
    expect(settled).toBe(false);
    expect(
      (await readFile(path, "utf8"))
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line).phase),
    ).toEqual(["prepared", "commit_intent", "result"]);
    late.resolve();
    expect(await operation).toMatchObject({ outcome: "activated" });
  });
  it("activation does not classify acknowledged commit plus failed close as successful completion", async () => {
    const db = connection();
    mocks.connect.mockResolvedValue(db);
    db.end.mockRejectedValue(new Error("close"));
    mocks.activate.mockResolvedValue({
      outcome: "activated",
      authority: "identity",
      receipt: {},
    });
    await expect(
      runIdentityActivateOperation(
        activationArgs(join(directory, "activation.jsonl")),
      ),
    ).rejects.toMatchObject({
      exitCode: 3,
      failure: {
        errorCode: "MIGRATION_RESOURCE_CLOSE_UNKNOWN",
        authority: "identity",
        statusRequired: true,
      },
    });
  });
  it("unknown COMMIT with an already-destroyed connection remains unknown", async () => {
    const db = connection();
    mocks.connect.mockResolvedValue(db);
    db.end.mockRejectedValue(new Error("destroyed"));
    mocks.activate.mockResolvedValue({
      outcome: "unknown",
      authority: "unknown",
      receipt: {},
    });
    await expect(
      runIdentityActivateOperation(
        activationArgs(join(directory, "activation.jsonl")),
      ),
    ).rejects.toMatchObject({
      exitCode: 3,
      failure: {
        errorCode: "MIGRATION_RESOURCE_CLOSE_UNKNOWN",
        authority: "unconfirmed",
        statusRequired: true,
      },
    });
  });
  it("report fsync failure after acknowledged COMMIT preserves durable intent and requires status", async () => {
    const db = connection(),
      path = join(directory, "activation.jsonl");
    mocks.connect.mockResolvedValue(db);
    const original = MigrationResources.prototype.openReport;
    vi.spyOn(MigrationResources.prototype, "openReport").mockImplementation(
      async function (this: MigrationResources, name: string) {
        const file = await original.call(this, name),
          sync = file.sync.bind(file);
        let calls = 0;
        file.sync = async () => {
          if (++calls >= 3) throw new Error("fsync");
          await sync();
        };
        return file;
      },
    );
    mocks.activate.mockImplementation(async ({ onCommitIntent }) => {
      await onCommitIntent({});
      return { outcome: "activated", authority: "identity", receipt: {} };
    });
    let failure: unknown;
    try {
      await runIdentityActivateOperation(activationArgs(path));
    } catch (error) {
      failure = error;
    }
    expect(failure).toBeInstanceOf(IdentityActivationOperationError);
    expect(failure).toMatchObject({
      exitCode: 3,
      failure: {
        errorCode: "ACTIVATION_COMMITTED_REPORT_FAILED",
        authority: "identity",
        statusRequired: true,
      },
    });
    expect(db.end).toHaveBeenCalledOnce();
    expect(await readFile(path, "utf8")).toContain('"phase":"commit_intent"');
  });
  for (const failAt of [1, 2]) {
    it(`activation keeps ${failAt === 1 ? "prepared" : "commit_intent"} report fsync failure unknown even when the failure record also fails`, async () => {
      const db = connection();
      mocks.connect.mockResolvedValue(db);
      const original = MigrationResources.prototype.openReport;
      vi.spyOn(MigrationResources.prototype, "openReport").mockImplementation(
        async function (this: MigrationResources, name: string) {
          const report = await original.call(this, name),
            sync = report.sync.bind(report);
          let calls = 0;
          report.sync = async () => {
            if (++calls >= failAt) throw new Error("report-fsync");
            await sync();
          };
          return report;
        },
      );
      mocks.activate.mockImplementation(async ({ onCommitIntent }) => {
        try {
          await onCommitIntent({});
        } finally {
          throw new Error("rollback overwrites report failure");
        }
      });
      await expect(
        runIdentityActivateOperation(
          activationArgs(join(directory, "failed-intent.jsonl")),
        ),
      ).rejects.toMatchObject({
        exitCode: 3,
        outcome: "unknown",
        automaticRetry: false,
        failure: {
          errorCode: "MIGRATION_REPORT_WRITE_UNKNOWN",
          authority: "unconfirmed",
          statusRequired: true,
        },
      });
      if (failAt === 1) {
        expect(mocks.connect).not.toHaveBeenCalled();
        expect(mocks.activate).not.toHaveBeenCalled();
      } else {
        expect(mocks.activate).toHaveBeenCalledOnce();
        expect(db.end).toHaveBeenCalledOnce();
      }
    });
  }
  it("does not weaken the fixed development target before opening connections", async () => {
    mocks.config().identityDb.host = "unreviewed.invalid";
    await expect(
      runAllocatorHighwaterOperation(["--fresh", "--apply"]),
    ).rejects.toThrow("reviewed direct development");
    await expect(runIdentityActivateOperation(["--status"])).rejects.toThrow(
      "ACTIVATION_FIXED_DEVELOPMENT_TARGET_REQUIRED",
    );
    expect(mocks.connect).not.toHaveBeenCalled();
  });
});
