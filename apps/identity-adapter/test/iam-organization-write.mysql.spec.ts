import { randomBytes, randomUUID } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import mysql from "mysql2/promise";
import {
  IamOrganizationWriteRepository,
  organizationCandidateMaterializationOperationKey,
  organizationCandidateSnapshotFingerprint,
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
    const identityNativeApplyOperationKey = organizationWriteOperationKey(
      legacyUserId,
      `mysql-org-identity-native-apply-${randomUUID()}`
    );
    const identityNativeRestoreOperationKey = organizationWriteOperationKey(
      legacyUserId,
      `mysql-org-identity-native-restore-${randomUUID()}`
    );
    const materializationIdempotencyKey = `mysql-org-materialization-${randomUUID()}`;
    const materializationOperationKey = organizationCandidateMaterializationOperationKey(
      legacyUserId,
      materializationIdempotencyKey
    );
    const staleOperationKey = organizationCandidateMaterializationOperationKey(legacyUserId, `stale-${randomUUID()}`);
    const failedNoneOperationKey = organizationCandidateMaterializationOperationKey(legacyUserId + 1, `failed-none-${randomUUID()}`);
    const failedCompletedOperationKey = organizationCandidateMaterializationOperationKey(legacyUserId + 1, `failed-completed-${randomUUID()}`);
    const failedRequiredOperationKey = organizationCandidateMaterializationOperationKey(legacyUserId + 1, `failed-required-${randomUUID()}`);
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
      await expect(first.materializationSchemaReadiness()).resolves.toMatchObject({ ready: true, existingTableCount: 5 });
      const materializationFingerprint = organizationCandidateSnapshotFingerprint(legacyUserId, [{
        id: legacyOrganizationId,
        name: `mysql-org-${legacyOrganizationId}`,
        title: "MySQL integration organization",
        createdAt: 1,
        updatedAt: 2
      }]);
      const materializationBegins = await Promise.all([
        first.beginCandidateMaterialization({
          operationKey: materializationOperationKey,
          idempotencyKeyDigest: "b".repeat(64),
          requestFingerprint: materializationFingerprint,
          legacyUserId,
          claimToken: "c".repeat(64),
          metadata: { source: "mysql-integration", organizationCount: 1 }
        }),
        second.beginCandidateMaterialization({
          operationKey: materializationOperationKey,
          idempotencyKeyDigest: "b".repeat(64),
          requestFingerprint: materializationFingerprint,
          legacyUserId,
          claimToken: "d".repeat(64),
          metadata: { source: "mysql-integration", organizationCount: 1 }
        })
      ]);
      expect(materializationBegins.map((item) => item.duplicate).sort()).toEqual([false, true]);
      await expect(first.find(materializationOperationKey)).resolves.toMatchObject({
        mode: "candidate-materialization",
        status: "pending",
        requestFingerprint: materializationFingerprint
      });
      await first.update({
        operationKey: materializationOperationKey,
        status: "failed",
        legacyStatus: "read-only",
        identityStatus: "candidate-materialization-failed",
        compensationStatus: "none",
        metadata: { source: "mysql-integration" }
      });
      await ageOperation(target, materializationOperationKey);
      const requestedAtBeforeResume = (await first.find(materializationOperationKey))?.requestedAt;
      const resumeTokens = ["e".repeat(64), "f".repeat(64)];
      const resumeClaims = await Promise.all([
        first.resumeCandidateMaterialization(
          materializationOperationKey,
          materializationFingerprint,
          materializationFingerprint,
          resumeTokens[0]!,
          { source: "mysql-integration-retry" }
        ),
        second.resumeCandidateMaterialization(
          materializationOperationKey,
          materializationFingerprint,
          materializationFingerprint,
          resumeTokens[1]!,
          { source: "mysql-integration-retry" }
        )
      ]);
      expect(resumeClaims.map((item) => item.claimed).sort()).toEqual([false, true]);
      const resumedOperation = await first.find(materializationOperationKey);
      expect(resumedOperation).toMatchObject({
        mode: "candidate-materialization",
        status: "pending",
        compensationStatus: "none",
        errorCode: null,
        completedAt: null
      });
      expect(Date.parse(resumedOperation!.requestedAt!)).toBeGreaterThan(Date.parse(requestedAtBeforeResume!));
      const resumeWinnerToken = resumeTokens[resumeClaims.findIndex((item) => item.claimed)]!;
      await expect(first.finalizeCandidateMaterialization({
        operationKey: materializationOperationKey,
        status: "completed",
        legacyStatus: "read-only",
        identityStatus: "candidate-materialized",
        compensationStatus: "none",
        claimToken: "0".repeat(64),
        leaseValidAfter: new Date(Date.now() - 5 * 60_000),
        metadata: { source: "mysql-integration-retry" }
      })).resolves.toEqual({ updated: false });
      await expect(first.finalizeCandidateMaterialization({
        operationKey: materializationOperationKey,
        status: "completed",
        legacyStatus: "read-only",
        identityStatus: "candidate-materialized",
        compensationStatus: "none",
        claimToken: resumeWinnerToken,
        leaseValidAfter: new Date(Date.now() - 5 * 60_000),
        metadata: { source: "mysql-integration-retry" }
      })).resolves.toEqual({ updated: true });
      await expect(first.finalizeCandidateMaterialization({
        operationKey: materializationOperationKey,
        status: "completed",
        legacyStatus: "read-only",
        identityStatus: "candidate-materialized",
        compensationStatus: "none",
        claimToken: resumeWinnerToken,
        leaseValidAfter: new Date(Date.now() - 5 * 60_000),
        metadata: { source: "mysql-integration-retry" }
      })).resolves.toEqual({ updated: false });
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
      await first.replaceCandidate({
        operationKey: materializationOperationKey,
        legacyUserId,
        organizations: []
      });
      await expect(second.candidateForLegacyUser(legacyUserId)).resolves.toEqual({
        legacyUserId,
        organizations: []
      });

      const identityNativeOrganization = {
        id: legacyOrganizationId,
        name: `mysql-org-${legacyOrganizationId}`,
        title: "MySQL integration organization",
        createdAt: 1,
        updatedAt: 2
      };
      const identityNativeApplyFingerprint = organizationWriteRequestFingerprint(
        legacyUserId,
        [legacyOrganizationId]
      );
      await expect(first.begin({
        operationKey: identityNativeApplyOperationKey,
        idempotencyKeyDigest: "c".repeat(64),
        requestFingerprint: identityNativeApplyFingerprint,
        legacyUserId,
        mode: "identity-native",
        metadata: { source: "mysql-identity-native-apply", legacyWritePerformed: false }
      })).resolves.toEqual({ duplicate: false });
      await first.replaceCandidate({
        operationKey: identityNativeApplyOperationKey,
        legacyUserId,
        organizations: [identityNativeOrganization]
      });
      await first.update({
        operationKey: identityNativeApplyOperationKey,
        status: "completed",
        legacyStatus: "not-called",
        identityStatus: "completed",
        compensationStatus: "none",
        metadata: { source: "mysql-identity-native-apply", legacyWritePerformed: false }
      });
      await expect(second.find(identityNativeApplyOperationKey)).resolves.toMatchObject({
        mode: "identity-native",
        status: "completed",
        legacyStatus: "not-called",
        identityStatus: "completed",
        compensationStatus: "none",
        metadata: { source: "mysql-identity-native-apply", legacyWritePerformed: false }
      });
      await expect(second.candidateForLegacyUser(legacyUserId)).resolves.toMatchObject({
        legacyUserId,
        organizations: [{ id: legacyOrganizationId }]
      });

      const identityNativeRestoreFingerprint = organizationWriteRequestFingerprint(legacyUserId, []);
      await expect(second.begin({
        operationKey: identityNativeRestoreOperationKey,
        idempotencyKeyDigest: "d".repeat(64),
        requestFingerprint: identityNativeRestoreFingerprint,
        legacyUserId,
        mode: "identity-native",
        metadata: { source: "mysql-identity-native-restore", legacyWritePerformed: false }
      })).resolves.toEqual({ duplicate: false });
      await second.replaceCandidate({
        operationKey: identityNativeRestoreOperationKey,
        legacyUserId,
        organizations: []
      });
      await second.update({
        operationKey: identityNativeRestoreOperationKey,
        status: "completed",
        legacyStatus: "not-called",
        identityStatus: "completed",
        compensationStatus: "none",
        metadata: { source: "mysql-identity-native-restore", legacyWritePerformed: false }
      });
      await expect(first.find(identityNativeRestoreOperationKey)).resolves.toMatchObject({
        mode: "identity-native",
        status: "completed",
        legacyStatus: "not-called",
        identityStatus: "completed",
        compensationStatus: "none",
        metadata: { source: "mysql-identity-native-restore", legacyWritePerformed: false }
      });
      await expect(first.candidateForLegacyUser(legacyUserId)).resolves.toEqual({
        legacyUserId,
        organizations: []
      });

      const staleInitialToken = "1".repeat(64);
      const changedMaterializationFingerprint = organizationCandidateSnapshotFingerprint(legacyUserId, [{
        id: legacyOrganizationId,
        name: `mysql-org-${legacyOrganizationId}-reviewed-current`,
        title: "MySQL integration organization (reviewed current)",
        createdAt: 3,
        updatedAt: 4
      }]);
      await first.beginCandidateMaterialization({
        operationKey: staleOperationKey,
        idempotencyKeyDigest: "2".repeat(64),
        requestFingerprint: materializationFingerprint,
        legacyUserId,
        claimToken: staleInitialToken,
        metadata: { source: "mysql-stale-lease" }
      });
      await ageOperation(target, staleOperationKey);
      const reclaimTokens = ["3".repeat(64), "4".repeat(64)];
      const reclaimClaims = await Promise.all(reclaimTokens.map((claimToken, index) =>
        (index === 0 ? first : second).reclaimStaleCandidateMaterialization({
          operationKey: staleOperationKey,
          expectedRequestFingerprint: materializationFingerprint,
          requestFingerprint: changedMaterializationFingerprint,
          claimToken,
          staleBefore: new Date(Date.now() - 5 * 60_000),
          metadata: { source: "mysql-stale-reclaim" }
        })
      ));
      expect(reclaimClaims.map((item) => item.claimed).sort()).toEqual([false, true]);
      const reclaimWinnerToken = reclaimTokens[reclaimClaims.findIndex((item) => item.claimed)]!;
      await expect(first.find(staleOperationKey)).resolves.toMatchObject({
        status: "pending",
        requestFingerprint: changedMaterializationFingerprint
      });
      await expect(first.replaceCandidate({
        operationKey: staleOperationKey,
        legacyUserId,
        organizations: [],
        materializationClaim: {
          claimToken: staleInitialToken,
          leaseValidAfter: new Date(Date.now() - 5 * 60_000)
        }
      })).rejects.toThrow("CandidateMaterializationLeaseLost");
      await expect(first.finalizeCandidateMaterialization({
        operationKey: staleOperationKey,
        status: "completed",
        legacyStatus: "read-only",
        identityStatus: "candidate-materialized",
        compensationStatus: "none",
        claimToken: staleInitialToken,
        leaseValidAfter: new Date(Date.now() - 5 * 60_000),
        metadata: { source: "mysql-stale-reclaim" }
      })).resolves.toEqual({ updated: false });
      await expect(first.finalizeCandidateMaterialization({
        operationKey: staleOperationKey,
        status: "completed",
        legacyStatus: "read-only",
        identityStatus: "candidate-materialized",
        compensationStatus: "none",
        claimToken: reclaimWinnerToken,
        leaseValidAfter: new Date(Date.now() - 5 * 60_000),
        metadata: { source: "mysql-stale-reclaim" }
      })).resolves.toEqual({ updated: true });

      const unresolvedUserId = legacyUserId + 1;
      const unresolvedFingerprint = organizationCandidateSnapshotFingerprint(unresolvedUserId, []);
      await first.beginCandidateMaterialization({
        operationKey: failedNoneOperationKey,
        idempotencyKeyDigest: "5".repeat(64),
        requestFingerprint: unresolvedFingerprint,
        legacyUserId: unresolvedUserId,
        claimToken: "6".repeat(64),
        metadata: { source: "mysql-failed-none" }
      });
      await first.update({
        operationKey: failedNoneOperationKey,
        status: "failed",
        legacyStatus: "read-only",
        identityStatus: "candidate-materialization-failed",
        compensationStatus: "none",
        metadata: { source: "mysql-failed-none" }
      });
      await expect(first.countUnresolvedForLegacyUser(unresolvedUserId)).resolves.toBe(0);

      await first.beginCandidateMaterialization({
        operationKey: failedCompletedOperationKey,
        idempotencyKeyDigest: "7".repeat(64),
        requestFingerprint: unresolvedFingerprint,
        legacyUserId: unresolvedUserId,
        claimToken: "8".repeat(64),
        metadata: { source: "mysql-failed-completed" }
      });
      await first.update({
        operationKey: failedCompletedOperationKey,
        status: "failed",
        legacyStatus: "read-only",
        identityStatus: "inconsistent-terminal-state",
        compensationStatus: "completed",
        metadata: { source: "mysql-failed-completed" }
      });
      await expect(first.countUnresolvedForLegacyUser(unresolvedUserId)).resolves.toBe(1);

      await first.beginCandidateMaterialization({
        operationKey: failedRequiredOperationKey,
        idempotencyKeyDigest: "9".repeat(64),
        requestFingerprint: unresolvedFingerprint,
        legacyUserId: unresolvedUserId,
        claimToken: "a".repeat(64),
        metadata: { source: "mysql-failed-required" }
      });
      await first.update({
        operationKey: failedRequiredOperationKey,
        status: "failed",
        legacyStatus: "read-only",
        identityStatus: "candidate-write-outcome-unknown",
        compensationStatus: "required",
        errorCode: "InjectedCandidateFailure",
        metadata: { source: "mysql-failed-required" }
      });
      const recent = await first.listRecentSafe(60, 200);
      expect(recent.find((operation) => operation.idempotencyKeyDigest === "b".repeat(64))).toMatchObject({
        legacyUserId,
        mode: "candidate-materialization",
        status: "completed",
        legacyStatus: "read-only",
        identityStatus: "candidate-materialized",
        compensationStatus: "none",
        errorCode: null
      });
      expect(recent.find((operation) => operation.idempotencyKeyDigest === "9".repeat(64))).toMatchObject({
        legacyUserId: unresolvedUserId,
        mode: "candidate-materialization",
        status: "failed",
        legacyStatus: "read-only",
        identityStatus: "candidate-write-outcome-unknown",
        compensationStatus: "required",
        errorCode: "InjectedCandidateFailure"
      });
      await expect(first.countUnresolvedForLegacyUser(unresolvedUserId)).resolves.toBe(2);
      await setOperationMode(target, failedCompletedOperationKey, "future-mode");
      await expect(first.find(failedCompletedOperationKey)).rejects.toThrow("Unknown organization write operation mode");
      await expect(first.countUnresolvedForLegacyUser(unresolvedUserId)).resolves.toBe(2);
    } finally {
      await cleanup(target, {
        operationKeys: [
          operationKey,
          identityNativeApplyOperationKey,
          identityNativeRestoreOperationKey,
          materializationOperationKey,
          staleOperationKey,
          failedNoneOperationKey,
          failedCompletedOperationKey,
          failedRequiredOperationKey
        ],
        legacyUserId,
        legacyOrganizationId
      });
    }
  }, 30_000);

  it("holds a subject advisory lock on one MySQL session and releases it on success or error", async () => {
    safeMysqlTestTarget();
    const first = new IamOrganizationWriteRepository();
    const second = new IamOrganizationWriteRepository();
    repositories.push(first, second);
    const legacyUserId = 2_000_000 + randomBytes(3).readUIntBE(0, 3);
    let entered!: () => void;
    let release!: () => void;
    const enteredPromise = new Promise<void>((resolve) => { entered = resolve; });
    const releasePromise = new Promise<void>((resolve) => { release = resolve; });

    const held = first.withCandidateMaterializationSubjectLock(legacyUserId, async () => {
      entered();
      await releasePromise;
      return "held";
    });
    await enteredPromise;
    await expect(second.withCandidateMaterializationSubjectLock(legacyUserId, async () => "unexpected"))
      .resolves.toEqual({ acquired: false });
    release();
    await expect(held).resolves.toEqual({ acquired: true, value: "held" });
    await expect(second.withCandidateMaterializationSubjectLock(legacyUserId, async () => "released"))
      .resolves.toEqual({ acquired: true, value: "released" });

    await expect(first.withCandidateMaterializationSubjectLock(legacyUserId, async () => {
      throw new Error("lock callback failed");
    })).rejects.toThrow("lock callback failed");
    await expect(second.withCandidateMaterializationSubjectLock(legacyUserId, async () => "released-after-error"))
      .resolves.toEqual({ acquired: true, value: "released-after-error" });
  }, 30_000);

  it("holds the cross-node candidate batch lock on one MySQL session and releases it exactly after the callback", async () => {
    safeMysqlTestTarget();
    const first = new IamOrganizationWriteRepository();
    const second = new IamOrganizationWriteRepository();
    repositories.push(first, second);
    let entered!: () => void;
    let release!: () => void;
    const enteredPromise = new Promise<void>((resolve) => { entered = resolve; });
    const releasePromise = new Promise<void>((resolve) => { release = resolve; });

    const held = first.withCandidateMaterializationBatchLock(async () => {
      entered();
      await releasePromise;
      return "held";
    });
    await enteredPromise;
    await expect(second.withCandidateMaterializationBatchLock(async () => "unexpected"))
      .resolves.toEqual({ acquired: false });
    release();
    await expect(held).resolves.toEqual({ acquired: true, value: "held" });
    await expect(second.withCandidateMaterializationBatchLock(async () => "released"))
      .resolves.toEqual({ acquired: true, value: "released" });

    await expect(first.withCandidateMaterializationBatchLock(async () => {
      throw new Error("batch callback failed");
    })).rejects.toThrow("batch callback failed");
    await expect(second.withCandidateMaterializationBatchLock(async () => "released-after-error"))
      .resolves.toEqual({ acquired: true, value: "released-after-error" });
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

async function ageOperation(target: MysqlTestTarget, operationKey: string): Promise<void> {
  const connection = await mysql.createConnection(target);
  try {
    await connection.execute(
      "UPDATE identity_organization_write_operations SET requested_at = DATE_SUB(UTC_TIMESTAMP(3), INTERVAL 10 MINUTE) WHERE operation_key = ?",
      [operationKey]
    );
  } finally {
    await connection.end();
  }
}

async function setOperationMode(target: MysqlTestTarget, operationKey: string, mode: string): Promise<void> {
  const connection = await mysql.createConnection(target);
  try {
    await connection.execute("UPDATE identity_organization_write_operations SET mode = ? WHERE operation_key = ?", [mode, operationKey]);
  } finally {
    await connection.end();
  }
}

async function cleanup(target: MysqlTestTarget, ids: { operationKeys: string[]; legacyUserId: number; legacyOrganizationId: number }) {
  const connection = await mysql.createConnection(target);
  try {
    await connection.execute("DELETE FROM identity_organization_memberships_candidate WHERE legacy_user_id = ?", [ids.legacyUserId]);
    await connection.execute("DELETE FROM identity_organization_membership_snapshots WHERE legacy_user_id = ?", [ids.legacyUserId]);
    await connection.execute("DELETE FROM identity_organization_id_map WHERE legacy_organization_id = ?", [ids.legacyOrganizationId]);
    await connection.execute("DELETE FROM identity_organizations_candidate WHERE legacy_organization_id = ?", [ids.legacyOrganizationId]);
    for (const operationKey of ids.operationKeys) {
      await connection.execute("DELETE FROM identity_organization_write_operations WHERE operation_key = ?", [operationKey]);
    }
  } finally {
    await connection.end();
  }
}
