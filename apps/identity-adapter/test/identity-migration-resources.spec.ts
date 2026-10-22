import { constants } from "node:fs";
import { EventEmitter } from "node:events";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  MigrationResourceCloseError,
  withMigrationResources,
  writeMigrationReport,
} from "../src/identity-migration-resources.js";
const filesystem = vi.hoisted(() => ({ open: vi.fn(), lstat: vi.fn() }));
vi.mock("node:fs/promises", () => ({
  open: filesystem.open,
  lstat: filesystem.lstat,
}));
const directoryIdentity = () => ({ isDirectory: () => true, dev: 1n, ino: 2n });
beforeEach(() => {
  filesystem.open.mockReset();
  filesystem.lstat.mockReset().mockResolvedValue(directoryIdentity());
});

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

function physicalFixture<T extends { end(): Promise<unknown> }>(value: T) {
  const stream = Object.assign(new EventEmitter(), { closed: false });
  return {
    ...value,
    connection: { stream },
    end: async () => {
      try {
        return await value.end();
      } finally {
        stream.closed = true;
        stream.emit("close", false);
      }
    },
  };
}

describe("awaited migration resource completion", () => {
  it("does not equate fulfilled end() with an actually closed transport", async () => {
    const stream = Object.assign(new EventEmitter(), { closed: false }),
      end = vi.fn(async () => {});
    let settled = false;
    const operation = withMigrationResources(async (resources) => {
      resources.connection({ connection: { stream }, end });
      return "closed";
    }).finally(() => {
      settled = true;
    });
    await vi.waitFor(() => expect(end).toHaveBeenCalledOnce());
    expect(settled).toBe(false);
    stream.closed = true;
    stream.emit("close", false);
    expect(await operation).toBe("closed");
  });
  it("retains an error and close observed during business work until cleanup consumes it", async () => {
    const stream = Object.assign(new EventEmitter(), { closed: false }),
      business = deferred(),
      failure = new Error("transport");
    const operation = withMigrationResources(async (resources) => {
      resources.connection({ connection: { stream }, end: async () => {} });
      await business.promise;
    });
    stream.emit("error", failure);
    stream.closed = true;
    stream.emit("close", true);
    business.resolve();
    await expect(operation).rejects.toMatchObject({
      code: "MIGRATION_RESOURCE_CLOSE_UNKNOWN",
      errors: [failure],
    });
  });
  it("treats mysql2's fulfilled Error end result as unknown instead of success", async () => {
    const stream = Object.assign(new EventEmitter(), { closed: false }),
      failure = new Error("closed-state callback");
    await expect(
      withMigrationResources(async (resources) => {
        resources.connection({
          connection: { stream },
          end: async () => {
            stream.closed = true;
            stream.emit("close", false);
            return failure;
          },
        });
      }),
    ).rejects.toMatchObject({
      code: "MIGRATION_RESOURCE_CLOSE_UNKNOWN",
      errors: [
        { message: "MIGRATION_CONNECTION_END_RESULT_UNKNOWN", cause: failure },
      ],
    });
  });
  it("owns mysql2's connection error forwarded by its older stream listener before ours can run", async () => {
    const stream = Object.assign(new EventEmitter(), { closed: false }),
      business = deferred(),
      failure = new Error("forwarded mysql2 error");
    const connection = Object.assign(new EventEmitter(), {
      connection: { stream },
      end: async () => {},
    });
    stream.on("error", (error) => {
      connection.emit("error", error);
    });
    const operation = withMigrationResources(async (resources) => {
      resources.connection(connection);
      await business.promise;
    });
    expect(() => stream.emit("error", failure)).not.toThrow();
    stream.closed = true;
    stream.emit("close", true);
    business.resolve();
    await expect(operation).rejects.toMatchObject({
      code: "MIGRATION_RESOURCE_CLOSE_UNKNOWN",
      errors: [failure],
    });
    expect(connection.listenerCount("error")).toBe(0);
  });
  it("attempts end but refuses completion when physical close cannot be observed", async () => {
    const end = vi.fn(async () => {});
    await expect(
      withMigrationResources(async (resources) => {
        resources.connection({ end });
      }),
    ).rejects.toMatchObject({
      code: "MIGRATION_RESOURCE_CLOSE_UNKNOWN",
      errors: [{ message: "MIGRATION_CONNECTION_CLOSE_OBSERVATION_REQUIRED" }],
    });
    expect(end).toHaveBeenCalledOnce();
  });
  it("waits for the actual business Promise before closing, then waits for late close", async () => {
    const business = deferred(),
      close = deferred(),
      started = deferred();
    const end = vi.fn(async () => {
      started.resolve();
      await close.promise;
    });
    let settled = false;
    const operation = withMigrationResources(async (resources) => {
      resources.connection(physicalFixture({ end }));
      await business.promise;
      return "result";
    }).finally(() => {
      settled = true;
    });
    expect(end).not.toHaveBeenCalled();
    expect(settled).toBe(false);
    business.resolve();
    await started.promise;
    expect(end).toHaveBeenCalledOnce();
    expect(settled).toBe(false);
    close.resolve();
    expect(await operation).toBe("result");
    expect(settled).toBe(true);
  });
  it("does not reject early when one close rejects and a sibling is still closing", async () => {
    const late = deferred(),
      started = deferred(),
      connectionError = new Error("connection-close"),
      fileError = new Error("file-close");
    let settled = false;
    const operation = withMigrationResources(async (resources) => {
      resources.connection(
        physicalFixture({
          end: async () => {
            throw connectionError;
          },
        }),
      );
      resources.connection(
        physicalFixture({
          end: async () => {
            started.resolve();
            await late.promise;
          },
        }),
      );
      resources.file({
        close: async () => {
          throw fileError;
        },
      });
      return "must-not-succeed";
    });
    const observed = operation.then(
      () => {
        settled = true;
        return null;
      },
      (error) => {
        settled = true;
        return error;
      },
    );
    await started.promise;
    expect(settled).toBe(false);
    late.resolve();
    const failure = await observed;
    expect(failure).toBeInstanceOf(MigrationResourceCloseError);
    expect(failure).toMatchObject({
      outcome: "unknown",
      automaticRetry: false,
      failedResources: [
        { kind: "connection", index: 0 },
        { kind: "file", index: 2 },
      ],
    });
    expect(failure.errors).toEqual([connectionError, fileError]);
  });
  it("preserves the business error when cleanup succeeds", async () => {
    const failure = new Error("business"),
      end = vi.fn(async () => {});
    await expect(
      withMigrationResources(async (resources) => {
        resources.connection(physicalFixture({ end }));
        throw failure;
      }),
    ).rejects.toBe(failure);
    expect(end).toHaveBeenCalledOnce();
  });
  it("preserves both business and synchronous close errors in an unknown failure", async () => {
    const business = new Error("business"),
      close = new Error("close"),
      otherEnd = vi.fn(async () => {});
    let failure: unknown;
    try {
      await withMigrationResources(async (resources) => {
        resources.connection(
          physicalFixture({
            end: () => {
              throw close;
            },
          }),
        );
        resources.connection(physicalFixture({ end: otherEnd }));
        throw business;
      });
    } catch (error) {
      failure = error;
    }
    expect(otherEnd).toHaveBeenCalledOnce();
    expect(failure).toBeInstanceOf(MigrationResourceCloseError);
    expect((failure as MigrationResourceCloseError).errors).toEqual([
      business,
      close,
    ]);
  });
  it("waits for report write and fsync before any resource can close", async () => {
    const write = deferred(),
      sync = deferred(),
      syncStarted = deferred(),
      events: string[] = [];
    const report = {
      writeFile: vi.fn(async () => {
        events.push("write");
        await write.promise;
      }),
      sync: vi.fn(async () => {
        events.push("fsync");
        syncStarted.resolve();
        await sync.promise;
      }),
      close: vi.fn(async () => {
        events.push("close");
      }),
    };
    const operation = withMigrationResources(async (resources) => {
      resources.file(report);
      await writeMigrationReport(report as never, { applied: true });
      return "durable";
    });
    expect(events).toEqual(["write"]);
    expect(report.sync).not.toHaveBeenCalled();
    write.resolve();
    await syncStarted.promise;
    expect(events).toEqual(["write", "fsync"]);
    expect(report.close).not.toHaveBeenCalled();
    sync.resolve();
    expect(await operation).toBe("durable");
    expect(events).toEqual(["write", "fsync", "close"]);
    expect(report.writeFile).toHaveBeenCalledWith('{"applied":true}\n');
  });
  it("fails a fsync error, closes every resource, and never treats it as completion", async () => {
    const failure = new Error("fsync"),
      end = vi.fn(async () => {}),
      close = vi.fn(async () => {});
    await expect(
      withMigrationResources(async (resources) => {
        resources.connection(physicalFixture({ end }));
        resources.file({ close });
        await writeMigrationReport(
          {
            writeFile: async () => {},
            sync: async () => {
              throw failure;
            },
          } as never,
          {},
        );
      }),
    ).rejects.toMatchObject({
      code: "MIGRATION_REPORT_WRITE_UNKNOWN",
      outcome: "unknown",
      automaticRetry: false,
      cause: failure,
    });
    expect(end).toHaveBeenCalledOnce();
    expect(close).toHaveBeenCalledOnce();
  });
  it("fsyncs the report and parent directory before closing either descriptor or completing", async () => {
    const parentSync = deferred(),
      parentStarted = deferred(),
      events: string[] = [];
    const directory = {
      stat: async () => directoryIdentity(),
      sync: vi.fn(async () => {
        events.push("parent-fsync");
        parentStarted.resolve();
        await parentSync.promise;
      }),
      close: vi.fn(async () => {
        events.push("parent-close");
      }),
    };
    const file = {
      writeFile: vi.fn(async () => {
        events.push("write");
      }),
      sync: vi.fn(async () => {
        events.push("file-fsync");
      }),
      stat: async () => ({
        isFile: () => true,
        nlink: 1,
        mode: 0o600,
        uid: process.getuid?.(),
      }),
      close: vi.fn(async () => {
        events.push("file-close");
      }),
    };
    filesystem.open
      .mockResolvedValueOnce(directory)
      .mockResolvedValueOnce(file);
    let settled = false;
    const operation = withMigrationResources(async (resources) => {
      const report = await resources.openReport("/protected/report.json");
      await writeMigrationReport(report, {});
      return "durable";
    }).finally(() => {
      settled = true;
    });
    await parentStarted.promise;
    expect(events).toEqual(["write", "file-fsync", "parent-fsync"]);
    expect(settled).toBe(false);
    expect(filesystem.open).toHaveBeenCalledWith(
      "/protected",
      constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
    );
    expect(filesystem.open).toHaveBeenCalledWith(
      "/protected/report.json",
      constants.O_WRONLY |
        constants.O_CREAT |
        constants.O_EXCL |
        constants.O_NOFOLLOW,
      0o600,
    );
    parentSync.resolve();
    expect(await operation).toBe("durable");
    expect(directory.close).toHaveBeenCalledOnce();
    expect(file.close).toHaveBeenCalledOnce();
  });
  it("does not complete when parent directory fsync fails, while still closing both descriptors", async () => {
    const failure = new Error("parent-fsync"),
      directory = {
        stat: async () => directoryIdentity(),
        sync: async () => {
          throw failure;
        },
        close: vi.fn(async () => {}),
      };
    const file = {
      writeFile: vi.fn(async () => {}),
      sync: vi.fn(async () => {}),
      stat: async () => ({
        isFile: () => true,
        nlink: 1,
        mode: 0o600,
        uid: process.getuid?.(),
      }),
      close: vi.fn(async () => {}),
    };
    filesystem.open
      .mockResolvedValueOnce(directory)
      .mockResolvedValueOnce(file);
    await expect(
      withMigrationResources(async (resources) => {
        await writeMigrationReport(
          await resources.openReport("/protected/report.json"),
          {},
        );
      }),
    ).rejects.toMatchObject({
      code: "MIGRATION_REPORT_WRITE_UNKNOWN",
      cause: failure,
      automaticRetry: false,
    });
    expect(file.sync).toHaveBeenCalledOnce();
    expect(directory.close).toHaveBeenCalledOnce();
    expect(file.close).toHaveBeenCalledOnce();
  });
  it("latches report failure even when business finally replaces it with a rollback error", async () => {
    const fsyncError = new Error("fsync"),
      rollbackError = new Error("rollback");
    const directory = {
      stat: async () => directoryIdentity(),
      sync: async () => {},
      close: vi.fn(async () => {}),
    };
    const file = {
      writeFile: async () => {},
      sync: async () => {
        throw fsyncError;
      },
      stat: async () => ({
        isFile: () => true,
        nlink: 1,
        mode: 0o600,
        uid: process.getuid?.(),
      }),
      close: vi.fn(async () => {}),
    };
    filesystem.open
      .mockResolvedValueOnce(directory)
      .mockResolvedValueOnce(file);
    let failure: any;
    try {
      await withMigrationResources(async (resources) => {
        const report = await resources.openReport("/protected/report.json");
        try {
          await writeMigrationReport(report, {});
        } finally {
          throw rollbackError;
        }
      });
    } catch (error) {
      failure = error;
    }
    expect(failure).toMatchObject({
      code: "MIGRATION_REPORT_WRITE_UNKNOWN",
      outcome: "unknown",
      automaticRetry: false,
    });
    expect(failure.cause.errors[0]).toMatchObject({
      code: "MIGRATION_REPORT_WRITE_UNKNOWN",
      cause: fsyncError,
    });
    expect(failure.cause.errors[1]).toBe(rollbackError);
    expect(directory.close).toHaveBeenCalledOnce();
    expect(file.close).toHaveBeenCalledOnce();
  });
  it("rejects a changed parent identity before creating a report and closes the directory descriptor", async () => {
    const directory = {
      stat: async () => directoryIdentity(),
      close: vi.fn(async () => {}),
    };
    filesystem.open.mockResolvedValueOnce(directory);
    filesystem.lstat.mockResolvedValue({ ...directoryIdentity(), ino: 3n });
    await expect(
      withMigrationResources(async (resources) => {
        await resources.openReport("/protected/report.json");
      }),
    ).rejects.toThrow("MIGRATION_REPORT_PARENT_CHANGED");
    expect(filesystem.open).toHaveBeenCalledOnce();
    expect(directory.close).toHaveBeenCalledOnce();
  });
  it("rejects a parent changed during report creation and still closes both acquired descriptors", async () => {
    const directory = {
        stat: async () => directoryIdentity(),
        close: vi.fn(async () => {}),
      },
      file = { close: vi.fn(async () => {}) };
    filesystem.open
      .mockResolvedValueOnce(directory)
      .mockResolvedValueOnce(file);
    filesystem.lstat
      .mockResolvedValueOnce(directoryIdentity())
      .mockResolvedValueOnce({ ...directoryIdentity(), ino: 3n });
    await expect(
      withMigrationResources(async (resources) => {
        await resources.openReport("/protected/report.json");
      }),
    ).rejects.toThrow("MIGRATION_REPORT_PARENT_CHANGED");
    expect(directory.close).toHaveBeenCalledOnce();
    expect(file.close).toHaveBeenCalledOnce();
  });
});
