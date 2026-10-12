import type { Connection } from "mysql2/promise";
import { describe, expect, it, vi } from "vitest";
import { readAccountBaseline } from "../src/identity-account-baseline.js";
import { accountImportTables } from "../src/identity-account-import.js";

describe("offline account baseline", () => {
  it("reads all metadata through parameterized text queries without server prepared state", async () => {
    const execute = vi.fn(() => { throw Object.assign(new Error("No prepared statement handle"), { code: "ER_UNKNOWN_STMT_HANDLER" }); });
    const rollback = vi.fn(async () => undefined);
    const query = vi.fn(async (sql: string, values?: unknown[]) => {
      if (sql.includes("information_schema.TABLES")) return [[{ TABLE_NAME: values?.[0] }], []];
      if (sql.includes("information_schema.COLUMNS")) return [[{ COLUMN_NAME: "id", DATA_TYPE: "bigint" }], []];
      if (sql.includes("information_schema.STATISTICS")) return [[{ INDEX_NAME: "PRIMARY", COLUMN_NAME: "id" }], []];
      if (sql.includes("SELECT COUNT(*)")) return [[{ total: 2 }], []];
      if (sql.includes("SELECT id,status")) return [[
        { id: 3, status: 10, algorithm: "bcrypt-2y" },
        { id: 624, status: 0, algorithm: "bcrypt-2b" },
      ], []];
      return [[], []];
    });
    const report = await readAccountBaseline({ query, execute, rollback } as unknown as Connection, 1000);
    expect(report.users).toMatchObject({ count: 2, minId: 3, maxId: 624, statuses: { "0": 1, "10": 1 } });
    expect(report.missingTables).toEqual([]);
    expect(Object.keys(report.tables)).toEqual(Object.keys(accountImportTables));
    const tableQueries = query.mock.calls.filter(([sql]) => sql.includes("information_schema.TABLES"));
    expect(tableQueries.map(([, values]) => values)).toEqual(Object.keys(accountImportTables).map((table) => [table]));
    expect(tableQueries.every(([sql]) => sql.includes("TABLE_NAME=?"))).toBe(true);
    expect(execute).not.toHaveBeenCalled();
    expect(rollback).toHaveBeenCalledOnce();
    expect(query.mock.calls[1][0]).toBe("START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY");
  });

  it("rolls back a failed read-only snapshot without retrying", async () => {
    const failure = Object.assign(new Error("Read failed"), { code: "ER_TABLEACCESS_DENIED_ERROR" });
    const rollback = vi.fn(async () => undefined);
    const query = vi.fn(async (sql: string) => {
      if (sql.includes("information_schema.TABLES")) throw failure;
      return [[], []];
    });
    await expect(readAccountBaseline({ query, rollback } as unknown as Connection)).rejects.toBe(failure);
    expect(query.mock.calls.filter(([sql]) => sql.includes("information_schema.TABLES"))).toHaveLength(1);
    expect(rollback).toHaveBeenCalledOnce();
  });
});
