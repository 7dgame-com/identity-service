import { Socket } from "node:net";
import { NativeMigrationAdmission, executeOwnedStep, NativeMigrationEntryError } from "../apps/identity-adapter/src/identity-migration-entry.js";
import { isDirectCli } from "./lib/direct-cli.js";

/** Private launcher pipe, FD 3. No path/command/connection/cleanup arguments. */
export async function runOwnedExecutor(): Promise<void> {
  if (process.argv.length !== 2) throw new NativeMigrationEntryError("MIGRATION_EXECUTOR_ARGUMENTS_FORBIDDEN");
  for (const [name, fixed] of [["IDENTITY_MIGRATION_CONFIG_FILE", "/run/xrugc/identity-finalization/config/migration.json"],
    ["IDENTITY_MIGRATION_KEY_FILE", "/run/xrugc/identity-finalization/config/migration.key"]]) {
    if (process.env[name] && process.env[name] !== fixed) throw new NativeMigrationEntryError("MIGRATION_EXECUTOR_CONFIG_LAYOUT_REQUIRED");
  }
  const client = NativeMigrationAdmission.environment();
  // FD3 is a private launcher pipe/socket, not a caller-selected regular file.
  // libuv can cancel its pending read; blocking fs.read cannot provide that bound.
  const pipeOptions = { fd: 3, readable: true, writable: false, highWaterMark: 16385 };
  const reader = new Socket(pipeOptions);
  let readerFailure: unknown;
  reader.on("error", error => { readerFailure ??= error; });
  const physicallyClosed = new Promise<void>(resolve => reader.once("close", resolve));
  let buffered = Buffer.alloc(0);
  // Iterator return alone does not await fs.close and normally manufactures an
  // AbortError on early return. Own explicit destroy + actual close separately.
  const iterator = reader.iterator({ destroyOnReturn: false });
  const emit = (value: unknown) => new Promise<void>((resolve, reject) => {
    process.stdout.write(JSON.stringify(value) + "\n", error => error ? reject(error) : resolve());
  });
  const frame = async () => {
    const deadline = setTimeout(() => reader.destroy(new NativeMigrationEntryError("MIGRATION_CONTROL_FRAME_BUDGET_EXPIRED", "unknown")), 2000);
    deadline.unref();
    try { for (;;) {
      const newline = buffered.indexOf(10);
      if (newline >= 0) {
        const bytes = buffered.subarray(0, newline); buffered = buffered.subarray(newline + 1);
        if (bytes.length > 16384 || !Buffer.from(bytes.toString("utf8")).equals(bytes)) throw new NativeMigrationEntryError("MIGRATION_CONTROL_FRAME_INVALID");
        const value = JSON.parse(bytes.toString("utf8"));
        if (!value || Object.keys(value).sort().join(",") !== "claim,claimCapability" || JSON.stringify(value) !== bytes.toString("utf8")) throw new NativeMigrationEntryError("MIGRATION_CONTROL_FRAME_INVALID");
        return value;
      }
      const item = await iterator.next();
      if (item.done) throw new NativeMigrationEntryError("MIGRATION_CONTROL_FRAME_REQUIRED");
      buffered = Buffer.concat([buffered, item.value]);
      if (buffered.length > 16385) throw new NativeMigrationEntryError("MIGRATION_CONTROL_FRAME_INVALID");
    } } finally { clearTimeout(deadline); }
  };
  let failed = false, operationError: unknown;
  try {
    for (const stepId of ["sync-apply", "sync-zero", "allocator", "activation"]) {
      await client.prepareOwnedPlan();
      await emit({ version: 1, event: "prepared", stepId });
      const next = await frame();
      if (next.claim?.stepId !== stepId) throw new NativeMigrationEntryError("MIGRATION_FIXED_STEP_ORDER");
      const scope = await client.enterOwned(next.claim, next.claimCapability);
      const closed = await executeOwnedStep(scope);
      const completed = await client.completeOwned(closed);
      await emit({ version: 1, event: "completed", stepId, ...completed });
    }
  } catch (error) { failed = true; operationError = error; }
  const closeReader = async () => {
    reader.destroy();
    const returning = iterator.return?.() ?? Promise.resolve();
    const results = await Promise.allSettled([returning, physicallyClosed]);
    const errors = results.filter(r => r.status === "rejected").map(r => (r as PromiseRejectedResult).reason);
    if (readerFailure) errors.push(readerFailure);
    if (errors.length) throw new AggregateError(errors, "MIGRATION_CONTROL_FD_CLOSE_UNKNOWN");
  };
  const results = await Promise.allSettled([client.closePreparedPlan(), closeReader()]);
  const failures = results.filter(r => r.status === "rejected").map(r => (r as PromiseRejectedResult).reason);
  if (failed || failures.length) {
    // Only a poison operation exists here; no caller state or cleanup assertion
    // is accepted, and a lost final control FD cannot leave the runtime known.
    try { await client.noteOwnedControlUnknown(); } catch (error) { failures.push(error); }
    if (failures.length) throw new AggregateError([...(failed ? [operationError] : []), ...failures], "MIGRATION_EXECUTOR_CLOSE_UNKNOWN");
    throw operationError;
  }
}
if (isDirectCli(import.meta.url)) {
  try { await runOwnedExecutor(); }
  catch (error) {
    console.error(JSON.stringify({ code: error instanceof NativeMigrationEntryError ? error.code : "MIGRATION_EXECUTOR_UNKNOWN", outcome: "unknown", automaticRetry: false }));
    process.exitCode = 3;
  }
}
