import { constants } from "node:fs";
import { lstat, open, type FileHandle } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import type { Socket } from "node:net";
import type { EventEmitter } from "node:events";

type Resource = {
  kind: "connection" | "file" | "directory";
  close: () => Promise<unknown>;
};
export type MigrationReportFile = Pick<FileHandle, "writeFile" | "sync">;
const reportOwners = new WeakMap<MigrationReportFile, MigrationResources>();

/** mysql2 resolves end() before writing QUIT and can fulfill with an Error.
 * Capture transport state when ownership begins, before business work can destroy
 * the connection. The observation never rejects before cleanup consumes it.
 */
function observeMigrationConnection(connection: {
  end(): Promise<unknown>;
}): () => Promise<void> {
  const stream = (connection as { connection?: { stream?: Socket } }).connection
    ?.stream;
  let transportFailure: unknown;
  const emitter = connection as Partial<
    Pick<EventEmitter, "on" | "removeListener">
  >;
  // mysql2's existing stream listener can synchronously forward error to the
  // PromiseConnection before our stream listener runs. Own that channel too.
  const onConnectionError = (error: unknown) => {
    transportFailure = error;
  };
  emitter.on?.("error", onConnectionError);
  let transport: Promise<void>;
  if (
    !stream ||
    typeof stream.once !== "function" ||
    typeof stream.removeListener !== "function" ||
    typeof stream.closed !== "boolean"
  ) {
    transportFailure = new Error(
      "MIGRATION_CONNECTION_CLOSE_OBSERVATION_REQUIRED",
    );
    transport = Promise.resolve();
  } else if (stream.closed) {
    transportFailure = new Error(
      "MIGRATION_CONNECTION_CLOSED_BEFORE_REGISTRATION",
      { cause: stream.errored },
    );
    transport = Promise.resolve();
  } else {
    transportFailure = stream.errored;
    transport = new Promise<void>((resolve) => {
      const onError = (error: unknown) => {
        transportFailure = error;
      };
      stream.once("error", onError);
      stream.once("close", (hadError: boolean) => {
        stream.removeListener("error", onError);
        if (hadError && !transportFailure)
          transportFailure = new Error(
            "MIGRATION_CONNECTION_TRANSPORT_CLOSE_UNKNOWN",
          );
        resolve();
      });
    });
  }
  return async () => {
    const results = await Promise.allSettled([
      Promise.resolve().then(() => connection.end()),
      transport,
    ]);
    emitter.removeListener?.("error", onConnectionError);
    const failures: unknown[] = [];
    for (const [index, result] of results.entries()) {
      if (result.status === "rejected") failures.push(result.reason);
      else if (index === 0 && result.value !== undefined)
        failures.push(
          new Error("MIGRATION_CONNECTION_END_RESULT_UNKNOWN", {
            cause: result.value,
          }),
        );
    }
    if (transportFailure) failures.push(transportFailure);
    if (failures.length === 1) throw failures[0];
    if (failures.length)
      throw new AggregateError(failures, "MIGRATION_CONNECTION_CLOSE_UNKNOWN");
  };
}

export class MigrationReportWriteError extends Error {
  readonly code = "MIGRATION_REPORT_WRITE_UNKNOWN";
  readonly outcome = "unknown";
  readonly automaticRetry = false;
  constructor(cause: unknown) {
    super("MIGRATION_REPORT_WRITE_UNKNOWN", { cause });
    this.name = "MigrationReportWriteError";
  }
}

/** Closing a connection is part of completion, even if its COMMIT was acknowledged.
 * Never turn a failed close into permission to retry a migration.
 */
export class MigrationResourceCloseError extends AggregateError {
  readonly code = "MIGRATION_RESOURCE_CLOSE_UNKNOWN";
  readonly outcome = "unknown";
  readonly automaticRetry = false;
  constructor(
    readonly failedResources: readonly {
      kind: Resource["kind"];
      index: number;
    }[],
    causes: unknown[],
  ) {
    super(causes, "MIGRATION_RESOURCE_CLOSE_UNKNOWN");
    this.name = "MigrationResourceCloseError";
  }
}

export class MigrationResources {
  private readonly resources: Resource[] = [];
  private reportFailure: MigrationReportWriteError | undefined;
  connection<T extends { end(): Promise<unknown> }>(connection: T): T {
    this.resources.push({
      kind: "connection",
      close: observeMigrationConnection(connection),
    });
    return connection;
  }
  file<T extends { close(): Promise<unknown> }>(file: T): T {
    this.resources.push({ kind: "file", close: () => file.close() });
    return file;
  }
  async openReport(path: string): Promise<MigrationReportFile> {
    const reportPath = resolve(path),
      parentPath = dirname(reportPath);
    const directory = await open(
      parentPath,
      constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
    );
    this.resources.push({ kind: "directory", close: () => directory.close() });
    const identity = await directory.stat({ bigint: true });
    const assertParent = async () => {
      const current = await lstat(parentPath, { bigint: true });
      if (
        !identity.isDirectory() ||
        !current.isDirectory() ||
        identity.dev !== current.dev ||
        identity.ino !== current.ino
      )
        throw new Error("MIGRATION_REPORT_PARENT_CHANGED");
    };
    // This detects a changed parent at these checkpoints; it is not openat and
    // cannot establish trusted ancestry or eliminate an adversarial ABA race.
    await assertParent();
    const file = this.file(
      await open(
        reportPath,
        constants.O_WRONLY |
          constants.O_CREAT |
          constants.O_EXCL |
          constants.O_NOFOLLOW,
        0o600,
      ),
    );
    await assertParent();
    const stat = await file.stat();
    if (
      !stat.isFile() ||
      stat.nlink !== 1 ||
      (stat.mode & 0o777) !== 0o600 ||
      stat.uid !== process.getuid?.()
    )
      throw new Error("MIGRATION_PROTECTED_REPORT_REQUIRED");
    const report = {
      writeFile: (async (...args: Parameters<FileHandle["writeFile"]>) => {
        await assertParent();
        await file.writeFile(...args);
        await assertParent();
      }) as FileHandle["writeFile"],
      sync: async () => {
        await assertParent();
        await file.sync();
        await directory.sync();
        await assertParent();
      },
    };
    reportOwners.set(report, this);
    return report;
  }
  noteReportFailure(failure: MigrationReportWriteError) {
    this.reportFailure ??= failure;
  }
  retainedReportFailure(
    operationFailed: boolean,
    operationError: unknown,
  ): MigrationReportWriteError | undefined {
    if (!this.reportFailure) return undefined;
    if (!operationFailed || operationError === this.reportFailure)
      return this.reportFailure;
    return new MigrationReportWriteError(
      new AggregateError(
        [this.reportFailure, operationError],
        "MIGRATION_REPORT_FAILURE_PRESERVED",
      ),
    );
  }
  /** Start every close before observing errors, then wait for every result. */
  async close(
    operationFailed: boolean,
    operationError: unknown,
  ): Promise<void> {
    const results = await Promise.allSettled(
      this.resources.map((resource) =>
        Promise.resolve().then(() => resource.close()),
      ),
    );
    const failures: { kind: Resource["kind"]; index: number }[] = [];
    const causes: unknown[] = operationFailed ? [operationError] : [];
    for (const [index, result] of results.entries()) {
      if (result.status === "rejected") {
        failures.push({ kind: this.resources[index].kind, index });
        causes.push(result.reason);
      }
    }
    if (failures.length)
      throw new MigrationResourceCloseError(failures, causes);
  }
}

/** The returned Promise owns the business work and every resource it acquired.
 * This is deliberately not an admission scope, migration lease or coordinator gate.
 */
export async function withMigrationResources<T>(
  work: (resources: MigrationResources) => Promise<T>,
): Promise<T> {
  const resources = new MigrationResources();
  let result: T | undefined,
    operationFailed = false,
    operationError: unknown;
  try {
    result = await work(resources);
  } catch (error) {
    operationFailed = true;
    operationError = error;
  }
  const reportFailure = resources.retainedReportFailure(
    operationFailed,
    operationError,
  );
  if (reportFailure) {
    operationFailed = true;
    operationError = reportFailure;
  }
  await resources.close(operationFailed, operationError);
  if (operationFailed) throw operationError;
  return result as T;
}

export async function writeMigrationReport(
  file: MigrationReportFile,
  value: unknown,
  indent?: number,
): Promise<void> {
  try {
    await file.writeFile(`${JSON.stringify(value, null, indent)}\n`);
    await file.sync();
  } catch (error) {
    const failure = new MigrationReportWriteError(error);
    reportOwners.get(file)?.noteReportFailure(failure);
    throw failure;
  }
}
