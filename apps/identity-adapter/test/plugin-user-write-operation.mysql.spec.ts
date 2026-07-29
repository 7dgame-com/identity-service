import { randomUUID } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import mysql, { ResultSetHeader } from "mysql2/promise";
import {
  PluginUserWriteOperationRepository,
  pluginUserWriteOperationKey
} from "../src/plugin-user-write-operation.repository.js";

const mysqlIntegrationEnabled = process.env.IDENTITY_TEST_MYSQL === "1";
const repositories: PluginUserWriteOperationRepository[] = [];

afterEach(async () => {
  await Promise.all(repositories.splice(0).map((repository) => repository.onModuleDestroy()));
});

describe.skipIf(!mysqlIntegrationEnabled)("plugin-user operation MySQL concurrency", () => {
  it("coordinates two independent connection pools through the shared unique index", async () => {
    const database = safeMysqlTestTarget();
    const firstRepository = new PluginUserWriteOperationRepository();
    const secondRepository = new PluginUserWriteOperationRepository();
    repositories.push(firstRepository, secondRepository);

    expect(firstRepository.isConfigured()).toBe(true);
    expect(secondRepository.isConfigured()).toBe(true);

    const actorSubject = "integration-test-actor";
    const targetSubject = "integration-test-target";
    const operationKey = pluginUserWriteOperationKey({
      route: "update-user",
      actorSubject,
      targetSubject,
      requestFingerprint: `integration-test:${randomUUID()}`
    });
    const input = {
      operationKey,
      idempotencyKey: operationKey,
      route: "update-user" as const,
      mode: "dual-write" as const,
      actorSubject,
      targetSubject,
      legacyUserId: null,
      metadata: {
        route: "update-user",
        method: "POST",
        idempotencySource: "client-header",
        requestFingerprint: "f".repeat(64),
        redactedBody: { target: "integration-test", password: "[redacted]" }
      }
    };

    let assertionsCompleted = false;
    try {
      const results = await Promise.all([
        firstRepository.begin(input),
        secondRepository.begin(input)
      ]);

      expect(results.map((result) => result.duplicate).sort()).toEqual([false, true]);
      await expect(firstRepository.findByOperationKey(operationKey)).resolves.toMatchObject({
        operationKey,
        status: "pending",
        actorSubject,
        targetSubject
      });
      await expect(secondRepository.findByOperationKey(operationKey)).resolves.toMatchObject({
        operationKey,
        status: "pending"
      });
      assertionsCompleted = true;
    } finally {
      const deletedRows = await deleteTestOperation(database, operationKey);
      if (assertionsCompleted) {
        expect(deletedRows).toBe(1);
      }
    }
  }, 30_000);
});

interface MysqlTestTarget {
  host: string;
  port: number;
  database: string;
  user: string;
  password: string;
}

function safeMysqlTestTarget(): MysqlTestTarget {
  if (process.env.IDENTITY_TEST_MYSQL !== "1" || process.env.NODE_ENV === "production") {
    throw new Error("MySQL integration requires the explicit test switch outside production.");
  }

  const host = process.env.IDENTITY_DB_HOST?.trim().toLowerCase() ?? "";
  const database = process.env.IDENTITY_DB_NAME?.trim() ?? "";
  const user = process.env.IDENTITY_DB_USER?.trim() ?? "";
  const password = process.env.IDENTITY_DB_PASSWORD ?? "";
  const port = Number(process.env.IDENTITY_DB_PORT ?? 3306);

  if (!["127.0.0.1", "localhost", "::1"].includes(host)) {
    throw new Error("MySQL integration is restricted to a local disposable database.");
  }
  if (!database.toLowerCase().endsWith("_test")) {
    throw new Error("MySQL integration database name must end with _test.");
  }
  if (!user || !password || !Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new Error("MySQL integration test configuration is incomplete.");
  }

  return { host, port, database, user, password };
}

async function deleteTestOperation(target: MysqlTestTarget, operationKey: string): Promise<number> {
  const connection = await mysql.createConnection(target);
  try {
    const [result] = await connection.execute<ResultSetHeader>(
      "DELETE FROM plugin_user_write_operations WHERE operation_key = ?",
      [operationKey]
    );
    return result.affectedRows;
  } finally {
    await connection.end();
  }
}
