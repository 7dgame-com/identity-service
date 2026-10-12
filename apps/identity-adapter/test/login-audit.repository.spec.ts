import "reflect-metadata";
import mysql from "mysql2/promise";
import { afterEach, expect, it, vi } from "vitest";
import { LoginAuditRepository } from "../src/login-audit.repository.js";
import { IamRepository } from "../src/iam.repository.js";

afterEach(() => { vi.restoreAllMocks(); vi.unstubAllEnvs(); });

it("does not return empty audit results or candidate roles when the private database is unconfigured", async () => {
  vi.stubEnv("IDENTITY_DB_HOST", "");
  vi.stubEnv("IDENTITY_DB_USER", "");
  const audit = new LoginAuditRepository();
  const iam = new IamRepository();
  try {
    await expect(audit.listSuccessfulLoginEventsByLegacyUserIds([], {})).rejects.toThrow(/identity database is not configured/i);
    await expect(audit.listOrganizationEvents({ userIds: [], startAt: new Date("2026-09-25T00:00:00Z"), endAt: new Date("2026-09-26T00:00:00Z"), page: 1, pageSize: 20 }))
      .rejects.toThrow(/identity database is not configured/i);
    await expect(iam.listAuditNativeRoles([], "a".repeat(64))).rejects.toThrow(/identity database is not configured/i);
  } finally {
    await audit.onModuleDestroy();
    await iam.onModuleDestroy();
  }
});

it("reads a consistent count and page when the database proxy rejects prepared JSON_TABLE statements", async () => {
  vi.stubEnv("IDENTITY_DB_HOST", "test-proxy");
  vi.stubEnv("IDENTITY_DB_USER", "test-user");
  const occurredAt = new Date("2026-09-25T01:00:00Z");
  const connection = {
    // Reproduces the deployed CynosDB error without requiring its private endpoint in CI.
    execute: vi.fn(async () => { throw Object.assign(new Error("Unknown prepared statement id: 1."), { code: "ER_UNKNOWN_STMT_HANDLER" }); }),
    query: vi.fn(async (sql: string) => {
      if (sql.startsWith("SELECT COUNT")) return [[{ total: 21 }]];
      if (sql.startsWith("SELECT e.event_key")) return [[{ eventKey: "login-21", userId: 2, occurredAt, source: "identity-adapter" }]];
      return [[]];
    }),
    commit: vi.fn(), rollback: vi.fn(), release: vi.fn()
  };
  vi.spyOn(mysql, "createPool").mockReturnValue({
    query: vi.fn(async () => [[]]), execute: vi.fn(async () => [[{ exists: 1 }]]),
    getConnection: vi.fn(async () => connection), end: vi.fn()
  } as unknown as ReturnType<typeof mysql.createPool>);
  const repository = new LoginAuditRepository();
  const startAt = new Date("2026-09-25T00:00:00Z");
  const endAt = new Date("2026-09-26T00:00:00Z");
  try {
    await expect(repository.listOrganizationEvents({ userIds: [2, 2], startAt, endAt, page: 2, pageSize: 20 }))
      .resolves.toEqual({ total: 21, events: [{ eventKey: "login-21", userId: 2, occurredAt: occurredAt.toISOString(), source: "identity-adapter" }] });
    expect(connection.query).toHaveBeenCalledWith(expect.stringContaining("SELECT COUNT"), ["[2]", startAt, endAt]);
    expect(connection.query).toHaveBeenCalledWith(expect.stringContaining("LIMIT ? OFFSET ?"), ["[2]", startAt, endAt, 20, 20]);
    expect(connection.commit).toHaveBeenCalledOnce();
    expect(connection.rollback).not.toHaveBeenCalled();
    expect(connection.release).toHaveBeenCalledOnce();
  } finally { await repository.onModuleDestroy(); }
});
