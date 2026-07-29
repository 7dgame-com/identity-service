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

  it("atomically reopens only one exact failed legacy 401 retry across connection pools", async () => {
    const database = safeMysqlTestTarget();
    const firstRepository = new PluginUserWriteOperationRepository();
    const secondRepository = new PluginUserWriteOperationRepository();
    repositories.push(firstRepository, secondRepository);

    const requestFingerprint = "f".repeat(64);
    const operationKey = pluginUserWriteOperationKey({
      route: "update-user",
      actorSubject: "integration-test-actor",
      targetSubject: "legacy-user:42",
      requestFingerprint: `integration-test-reopen:${randomUUID()}`
    });
    const operationMetadata = {
      route: "update-user",
      method: "POST",
      targetSubject: "legacy-user:42",
      idempotencySource: "client-header" as const,
      requestFingerprint,
      redactedBody: { id: 42, password: "[redacted]" }
    };

    let assertionsCompleted = false;
    try {
      await firstRepository.begin({
        operationKey,
        idempotencyKey: operationKey,
        route: "update-user",
        mode: "dual-write",
        actorSubject: "integration-test-actor",
        targetSubject: "legacy-user:42",
        legacyUserId: 42,
        metadata: operationMetadata
      });
      await firstRepository.update({
        operationKey,
        status: "failed",
        legacyStatus: "401",
        identityStatus: "skipped",
        compensationStatus: "none",
        errorCode: "LegacyRejected",
        metadata: {
          ...operationMetadata,
          responseReplay: {
            httpStatus: 401,
            body: { code: 4010, password: "must-not-persist", token: "must-not-persist" }
          }
        }
      });

      await expect(firstRepository.reopenFailedLegacyUnauthorized({
        operationKey,
        requestFingerprint: "0".repeat(64),
        metadata: operationMetadata
      })).resolves.toBe(false);

      const results = await Promise.all([
        firstRepository.reopenFailedLegacyUnauthorized({
          operationKey,
          requestFingerprint,
          metadata: {
            ...operationMetadata,
            authorization: "must-not-persist"
          }
        }),
        secondRepository.reopenFailedLegacyUnauthorized({
          operationKey,
          requestFingerprint,
          metadata: {
            ...operationMetadata,
            authorization: "must-not-persist"
          }
        })
      ]);

      expect(results.sort()).toEqual([false, true]);
      const reopened = await firstRepository.findByOperationKey(operationKey);
      expect(reopened).toMatchObject({
        status: "pending",
        legacyStatus: null,
        identityStatus: null,
        compensationStatus: "none",
        errorCode: null,
        metadata: {
          idempotencySource: "client-header",
          requestFingerprint,
          authorization: "[redacted]"
        }
      });
      expect(JSON.stringify(reopened)).not.toContain("must-not-persist");

      await firstRepository.update({
        operationKey,
        status: "failed",
        legacyStatus: "403",
        identityStatus: "skipped",
        compensationStatus: "none",
        errorCode: "LegacyRejected",
        metadata: operationMetadata
      });
      await expect(Promise.all([
        firstRepository.reopenFailedLegacyUnauthorized({ operationKey, requestFingerprint, metadata: operationMetadata }),
        secondRepository.reopenFailedLegacyUnauthorized({ operationKey, requestFingerprint, metadata: operationMetadata })
      ])).resolves.toEqual([false, false]);
      await expect(firstRepository.findByOperationKey(operationKey)).resolves.toMatchObject({
        status: "failed",
        legacyStatus: "403"
      });

      const ineligibleStates = [
        {
          status: "legacy_completed" as const,
          legacyStatus: "401",
          identityStatus: "skipped",
          compensationStatus: "none" as const,
          errorCode: "LegacyRejected",
          metadata: operationMetadata
        },
        {
          status: "failed" as const,
          legacyStatus: "401",
          identityStatus: "failed",
          compensationStatus: "none" as const,
          errorCode: "LegacyRejected",
          metadata: operationMetadata
        },
        {
          status: "failed" as const,
          legacyStatus: "401",
          identityStatus: "skipped",
          compensationStatus: "required" as const,
          errorCode: "LegacyRejected",
          metadata: operationMetadata
        },
        {
          status: "failed" as const,
          legacyStatus: "401",
          identityStatus: "skipped",
          compensationStatus: "none" as const,
          errorCode: "DifferentFailure",
          metadata: operationMetadata
        },
        {
          status: "failed" as const,
          legacyStatus: "401",
          identityStatus: "skipped",
          compensationStatus: "none" as const,
          errorCode: "LegacyRejected",
          metadata: { ...operationMetadata, idempotencySource: "per-request" as const }
        }
      ];
      for (const state of ineligibleStates) {
        await firstRepository.update({ operationKey, ...state });
        await expect(firstRepository.reopenFailedLegacyUnauthorized({
          operationKey,
          requestFingerprint,
          metadata: operationMetadata
        })).resolves.toBe(false);
      }
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
