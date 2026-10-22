import { fstatSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { once } from "node:events";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
const mocked = vi.hoisted(() => ({ environment: vi.fn(), execute: vi.fn(), reader: vi.fn() }));
vi.mock("node:net", async importOriginal => ({ ...await importOriginal<typeof import("node:net")>(), Socket: mocked.reader }));
vi.mock("../src/identity-migration-entry.js", () => ({
  NativeMigrationAdmission: { environment: mocked.environment }, executeOwnedStep: mocked.execute,
  NativeMigrationEntryError: class extends Error { constructor(readonly code: string) { super(code); } },
}));
import { runOwnedExecutor } from "../../../scripts/identity-owned-executor.js";

const steps = ["sync-apply", "sync-zero", "allocator", "activation"];
const frames = () => steps.map(stepId => JSON.stringify({ claim: { stepId }, claimCapability: "fixture-capability" }) + "\n").join("");
const deferred = () => { let resolve!: () => void; const promise = new Promise<void>(done => { resolve = done; }); return { promise, resolve }; };
function causes(error: unknown): unknown[] {
  return [error, ...(error instanceof AggregateError ? error.errors.flatMap(causes) : [])];
}
describe("fixed owned-executor launcher and its real input descriptor", () => {
  let directory: string, input: string, endAfterInput: boolean, originalArgv: string[], fd: number | undefined;
  let stream: import("node:net").Socket, peer: import("node:net").Socket, server: import("node:net").Server;
  let releaseClose: ReturnType<typeof deferred> | undefined, closeStarted: ReturnType<typeof deferred>, closeFailure: Error | undefined;
  let client: { prepareOwnedPlan: ReturnType<typeof vi.fn>; enterOwned: ReturnType<typeof vi.fn>; completeOwned: ReturnType<typeof vi.fn>; closePreparedPlan: ReturnType<typeof vi.fn>; noteOwnedControlUnknown: ReturnType<typeof vi.fn> };
  let output: unknown[];
  beforeEach(async () => {
    vi.clearAllMocks();
    originalArgv = process.argv; process.argv = [process.execPath, "fixture-owned-executor"];
    vi.stubEnv("IDENTITY_MIGRATION_CONFIG_FILE", ""); vi.stubEnv("IDENTITY_MIGRATION_KEY_FILE", "");
    directory = await mkdtemp(join(tmpdir(), "owned-launcher-")); input = frames();
    fd = undefined; releaseClose = undefined; closeFailure = undefined; closeStarted = deferred(); output = []; endAfterInput = false;
    const actual = await vi.importActual<typeof import("node:net")>("node:net");
    server = actual.createServer(); server.listen(join(directory, "private-control.sock")); await once(server, "listening");
    const accepted = once(server, "connection"); stream = actual.createConnection(join(directory, "private-control.sock")); await once(stream, "connect"); [peer] = await accepted;
    mocked.reader.mockImplementation(function (_options) {
      fd = (stream as unknown as { _handle: { fd: number } })._handle.fd;
      const destroy = stream._destroy.bind(stream);
      stream._destroy = (error, callback) => {
        closeStarted.resolve();
        const close = () => destroy(closeFailure ?? error, callback);
        if (releaseClose) void releaseClose.promise.then(close); else close();
      };
      if (input) queueMicrotask(() => { peer.write(input); if (endAfterInput) peer.end(); });
      return stream;
    });
    client = { prepareOwnedPlan: vi.fn(async () => {}), enterOwned: vi.fn(async () => ({})), completeOwned: vi.fn(async () => ({ reportSha256: "a".repeat(64), outputSha256: "b".repeat(64), chainSha256: "c".repeat(64) })),
      closePreparedPlan: vi.fn(async () => {}), noteOwnedControlUnknown: vi.fn(async () => {}) };
    mocked.environment.mockReturnValue(client); mocked.execute.mockResolvedValue(Object.freeze({}));
    vi.spyOn(process.stdout, "write").mockImplementation(((value: string, callback: (error?: Error | null) => void) => {
      output.push(JSON.parse(value)); queueMicrotask(() => callback()); return true;
    }) as typeof process.stdout.write);
  });
  afterEach(async () => {
    releaseClose?.resolve();
    if (stream && !stream.closed) { const closed = new Promise<void>(resolve => stream.once("close", resolve)); stream.destroy(); await closed; }
    peer?.destroy(); if (server?.listening) await new Promise<void>(resolve => server.close(() => resolve()));
    process.argv = originalArgv; vi.restoreAllMocks(); vi.unstubAllEnvs(); await rm(directory, { recursive: true, force: true });
  });
  it("importing the launcher does not start a client or open FD3", () => {
    expect(mocked.environment).not.toHaveBeenCalled(); expect(mocked.reader).not.toHaveBeenCalled();
  });
  it("rejects arguments and caller-selected configuration paths before touching a client or FD3", async () => {
    process.argv.push("--plan=/tmp/caller.json"); await expect(runOwnedExecutor()).rejects.toThrow("ARGUMENTS_FORBIDDEN"); process.argv.pop();
    vi.stubEnv("IDENTITY_MIGRATION_CONFIG_FILE", "/tmp/caller.json"); await expect(runOwnedExecutor()).rejects.toThrow("CONFIG_LAYOUT_REQUIRED");
    expect(mocked.environment).not.toHaveBeenCalled(); expect(mocked.reader).not.toHaveBeenCalled();
  });
  it("missing protected configuration never mistakenly opens FD3", async () => {
    mocked.environment.mockImplementation(() => { throw new Error("MIGRATION_ENTER_NOT_WIRED"); });
    await expect(runOwnedExecutor()).rejects.toThrow("NOT_WIRED"); expect(mocked.reader).not.toHaveBeenCalled();
  });
  it("executes four fixed frames and closes the actual descriptor before resolving", async () => {
    await runOwnedExecutor();
    expect(output.map((v: any) => [v.event, v.stepId])).toEqual(steps.flatMap(step => [["prepared", step], ["completed", step]]));
    expect(client.enterOwned.mock.calls.map(([claim]) => claim.stepId)).toEqual(steps);
    expect(() => fstatSync(fd!)).toThrow(); expect(stream!.closed).toBe(true);
    expect(client.noteOwnedControlUnknown).not.toHaveBeenCalled();
    expect(mocked.reader.mock.calls[0][0]).toEqual({ fd: 3, readable: true, writable: false, highWaterMark: 16385 });
  });
  it("awaits actual delayed Unix socket close rather than iterator return", async () => {
    releaseClose = deferred(); let settled = false;
    const running = runOwnedExecutor().finally(() => { settled = true; });
    await closeStarted.promise; await new Promise(resolve => setImmediate(resolve));
    expect(settled).toBe(false); expect(fstatSync(fd!).isSocket()).toBe(true);
    releaseClose.resolve(); await running;
    expect(() => fstatSync(fd!)).toThrow(); expect(stream!.closed).toBe(true);
  });
  it("retains the original operation error and a real-close error, then reports unknown", async () => {
    const original = new Error("fixture preparation failure"); closeFailure = new Error("fixture close callback failure"); client.prepareOwnedPlan.mockRejectedValue(original);
    let failure: unknown; try { await runOwnedExecutor(); } catch (error) { failure = error; }
    expect(causes(failure)).toContain(original); expect(causes(failure)).toContain(closeFailure);
    expect(client.noteOwnedControlUnknown).toHaveBeenCalledTimes(1); expect(() => fstatSync(fd!)).toThrow();
  });
  it("also waits for and retains prepared-input cleanup failure", async () => {
    const failure = new Error("fixture prepared close failure"); client.closePreparedPlan.mockRejectedValue(failure);
    await expect(runOwnedExecutor()).rejects.toSatisfy(error => causes(error).includes(failure));
    expect(client.noteOwnedControlUnknown).toHaveBeenCalledTimes(1); expect(() => fstatSync(fd!)).toThrow();
  });
  it.each(["duplicate", "wrong-step", "large", "unterminated"])("rejects %s control metadata and actually closes the input", async mode => {
    const first = JSON.stringify({ claim: { stepId: mode === "wrong-step" ? "activation" : "sync-apply" }, claimCapability: "fixture" });
    input = mode === "duplicate" ? first.replace("{", '{"claim":{},') + "\n" : mode === "large" ? "x".repeat(16386) : mode === "unterminated" ? first : first + "\n";
    endAfterInput = mode === "unterminated";
    await expect(runOwnedExecutor()).rejects.toThrow(); expect(client.noteOwnedControlUnknown).toHaveBeenCalledTimes(1);
    expect(() => fstatSync(fd!)).toThrow(); expect(client.completeOwned).not.toHaveBeenCalled();
  });
  it("awaits stdout callback failures and closes all input state before reporting unknown", async () => {
    const failure = new Error("fixture stdout EPIPE"); vi.mocked(process.stdout.write).mockImplementation(((_value: string, callback: (error?: Error) => void) => {
      queueMicrotask(() => callback(failure)); return false;
    }) as typeof process.stdout.write);
    await expect(runOwnedExecutor()).rejects.toBe(failure);
    expect(client.noteOwnedControlUnknown).toHaveBeenCalledTimes(1); expect(() => fstatSync(fd!)).toThrow();
  });
  it("bounds one frame by two absolute seconds when the private Unix-socket peer stays open without writing", async () => {
    input = ""; const start = Date.now();
    await expect(runOwnedExecutor()).rejects.toThrow();
    expect(Date.now() - start).toBeGreaterThanOrEqual(1800); expect(Date.now() - start).toBeLessThan(2700);
    expect(stream.closed).toBe(true); expect(() => fstatSync(fd!)).toThrow();
    expect(client.noteOwnedControlUnknown).toHaveBeenCalledTimes(1); expect(client.enterOwned).not.toHaveBeenCalled();
  });
});
