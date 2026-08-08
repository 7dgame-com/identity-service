import { randomBytes, randomUUID } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import mysql from "mysql2/promise";
import {
  IamOrganizationWriteRepository,
  organizationWriteOperationKey,
  organizationWriteRequestFingerprint
} from "../src/iam-organization-write.repository.js";

const enabled = process.env.IDENTITY_TEST_MYSQL === "1";
const repositories: IamOrganizationWriteRepository[] = [];

afterEach(async () => {
  await Promise.all(repositories.splice(0).map((repository) => repository.onModuleDestroy()));
});

describe.skipIf(!enabled)("IAM organization write MySQL integration", () => {
  it("coordinates operation idempotency and transactionally replaces candidate memberships", async () => {
    const target = safeMysqlTestTarget();
    const first = new IamOrganizationWriteRepository();
    const second = new IamOrganizationWriteRepository();
    repositories.push(first, second);
    const legacyUserId = 1_000_000 + randomBytes(3).readUIntBE(0, 3);
    const legacyOrganizationId = 1_000_000 + randomBytes(3).readUIntBE(0, 3);
    const idempotencyKey = `mysql-org-${randomUUID()}`;
    const operationKey = organizationWriteOperationKey(legacyUserId, idempotencyKey);
    const requestFingerprint = organizationWriteRequestFingerprint(legacyUserId, [legacyOrganizationId]);
    const input = {
      operationKey,
      idempotencyKeyDigest: "a".repeat(64),
      requestFingerprint,
      legacyUserId,
      metadata: { correlationId: randomUUID(), organizationCount: 1, authorization: "must-redact" }
    };

    try {
      const begins = await Promise.all([first.begin(input), second.begin(input)]);
      expect(begins.map((item) => item.duplicate).sort()).toEqual([false, true]);
      await first.replaceCandidate({
        operationKey,
        legacyUserId,
        organizations: [{
          id: legacyOrganizationId,
          name: `mysql-org-${legacyOrganizationId}`,
          title: "MySQL integration organization",
          createdAt: 1,
          updatedAt: 2
        }]
      });
      await first.update({
        operationKey,
        status: "completed",
        legacyStatus: "200",
        identityStatus: "candidate-completed",
        compensationStatus: "none",
        metadata: { organizationCount: 1 }
      });

      await expect(second.find(operationKey)).resolves.toMatchObject({
        operationKey,
        legacyUserId,
        status: "completed",
        identityStatus: "candidate-completed",
        metadata: { organizationCount: 1 }
      });
      await expect(second.candidateForLegacyUser(legacyUserId)).resolves.toMatchObject({
        legacyUserId,
        organizations: [{ id: legacyOrganizationId, name: `mysql-org-${legacyOrganizationId}` }]
      });
    } finally {
      await cleanup(target, { operationKey, legacyUserId, legacyOrganizationId });
    }
  }, 30_000);
});

interface MysqlTestTarget { host: string; port: number; database: string; user: string; password: string; }

function safeMysqlTestTarget(): MysqlTestTarget {
  if (process.env.IDENTITY_TEST_MYSQL !== "1" || process.env.NODE_ENV === "production") {
    throw new Error("MySQL integration requires the explicit test switch outside production.");
  }
  const target = {
    host: process.env.IDENTITY_DB_HOST?.trim().toLowerCase() ?? "",
    port: Number(process.env.IDENTITY_DB_PORT ?? 3306),
    database: process.env.IDENTITY_DB_NAME?.trim() ?? "",
    user: process.env.IDENTITY_DB_USER?.trim() ?? "",
    password: process.env.IDENTITY_DB_PASSWORD ?? ""
  };
  if (!["127.0.0.1", "localhost", "::1"].includes(target.host) || !target.database.toLowerCase().endsWith("_test")) {
    throw new Error("MySQL integration is restricted to a local disposable *_test database.");
  }
  if (!target.user || !target.password || !Number.isInteger(target.port) || target.port < 1 || target.port > 65_535) {
    throw new Error("MySQL integration test configuration is incomplete.");
  }
  return target;
}

async function cleanup(target: MysqlTestTarget, ids: { operationKey: string; legacyUserId: number; legacyOrganizationId: number }) {
  const connection = await mysql.createConnection(target);
  try {
    await connection.execute("DELETE FROM identity_organization_memberships_candidate WHERE legacy_user_id = ?", [ids.legacyUserId]);
    await connection.execute("DELETE FROM identity_organization_membership_snapshots WHERE legacy_user_id = ?", [ids.legacyUserId]);
    await connection.execute("DELETE FROM identity_organization_id_map WHERE legacy_organization_id = ?", [ids.legacyOrganizationId]);
    await connection.execute("DELETE FROM identity_organizations_candidate WHERE legacy_organization_id = ?", [ids.legacyOrganizationId]);
    await connection.execute("DELETE FROM identity_organization_write_operations WHERE operation_key = ?", [ids.operationKey]);
  } finally {
    await connection.end();
  }
}
