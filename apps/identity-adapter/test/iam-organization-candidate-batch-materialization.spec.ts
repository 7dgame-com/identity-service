import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { IamOrganizationWriteService } from "../src/iam-organization-write.service.js";
import type { LegacyOrganization, LegacyUserReadModel } from "../src/legacy-identity.reader.js";

const originalEnv = { ...process.env };
const PLAN_KEY = "ab".repeat(32);

describe("xrteeth Develop organization candidate batch materialization", () => {
  beforeEach(() => {
    process.env = { ...originalEnv };
    enableBatchMaterialization();
  });

  afterEach(() => {
    process.env = { ...originalEnv };
  });

  it("previews only counts and an opaque plan while keeping protected subjects out of the write set", async () => {
    const fixture = batchFixture();

    const preview = await fixture.service.previewCandidateBatchMaterialization();

    expect(preview).toMatchObject({
      mutation: false,
      executable: true,
      applyEnabled: true,
      legacySubjectCount: 3,
      ordinarySubjectCount: 2,
      protectedSubjectCount: 1,
      ordinaryAlignedCount: 1,
      ordinaryMissingCount: 1,
      ordinaryBlockedCount: 0,
      protectedAlignedCount: 0,
      protectedMissingCount: 1,
      protectedSubjectWritePerformed: false,
      blockedReasons: []
    });
    expect(preview.planToken).toMatch(/^[a-f0-9]{64}$/);
    const serialized = JSON.stringify(preview);
    expect(serialized).not.toContain("ordinary-missing");
    expect(serialized).not.toContain("root");
    expect(serialized).not.toContain('"legacyUserId"');
  });

  it("materializes only missing ordinary subjects, skips aligned subjects and never writes protected root", async () => {
    const fixture = batchFixture();
    const preview = await fixture.service.previewCandidateBatchMaterialization();

    const result = await fixture.service.materializeCandidateBatch({
      planToken: preview.planToken,
      idempotencyKey: "reviewed-develop-batch-1"
    });

    expect(result).toMatchObject({
      completed: true,
      mutation: true,
      legacySubjectCount: 3,
      ordinarySubjectCount: 2,
      protectedSkippedCount: 1,
      appliedCount: 1,
      replayedCount: 0,
      skippedAlignedCount: 1,
      legacyWritePerformed: false,
      protectedSubjectWritePerformed: false,
      writeScope: "identity-candidate-only"
    });
    expect(fixture.repository.replaceCandidate).toHaveBeenCalledTimes(1);
    expect(fixture.repository.replaceCandidate).toHaveBeenCalledWith(expect.objectContaining({ legacyUserId: 2 }));
    expect(fixture.repository.replaceCandidate).not.toHaveBeenCalledWith(expect.objectContaining({ legacyUserId: 3 }));

    const retry = await fixture.service.materializeCandidateBatch({
      planToken: preview.planToken,
      idempotencyKey: "reviewed-develop-batch-1"
    });
    expect(retry).toMatchObject({ completed: true, mutation: false, appliedCount: 0, skippedAlignedCount: 2 });
    expect(fixture.repository.replaceCandidate).toHaveBeenCalledTimes(1);
  });

  it("rejects a forged or stale plan before any candidate write", async () => {
    const fixture = batchFixture();
    const preview = await fixture.service.previewCandidateBatchMaterialization();

    await expect(fixture.service.materializeCandidateBatch({
      planToken: "00".repeat(32),
      idempotencyKey: "reviewed-develop-batch-2"
    })).rejects.toMatchObject({ response: { code: "IAM_ORGANIZATION_CANDIDATE_BATCH_PLAN_CHANGED" } });
    expect(fixture.repository.replaceCandidate).not.toHaveBeenCalled();

    fixture.sources[1] = sourceUser(2, "ordinary-missing", [], 10, [organization(2)]);
    await expect(fixture.service.materializeCandidateBatch({
      planToken: preview.planToken,
      idempotencyKey: "reviewed-develop-batch-2"
    })).rejects.toMatchObject({ response: { code: "IAM_ORGANIZATION_CANDIDATE_BATCH_PLAN_CHANGED" } });
    expect(fixture.repository.replaceCandidate).not.toHaveBeenCalled();
  });

  it("fails the whole preflight before writes when an ordinary subject is inactive", async () => {
    const fixture = batchFixture({ secondStatus: 0 });
    const preview = await fixture.service.previewCandidateBatchMaterialization();

    expect(preview).toMatchObject({ executable: false, inactiveOrdinaryCount: 1, ordinaryBlockedCount: 1 });
    expect(preview.blockedReasons).toContain("ordinary-subject-not-materializable");
    await expect(fixture.service.materializeCandidateBatch({
      planToken: preview.planToken,
      idempotencyKey: "reviewed-develop-batch-3"
    })).rejects.toMatchObject({ response: { code: "IAM_ORGANIZATION_CANDIDATE_BATCH_PLAN_BLOCKED" } });
    expect(fixture.repository.replaceCandidate).not.toHaveBeenCalled();
  });

  it("fails closed when the cross-node batch lock is unavailable", async () => {
    const fixture = batchFixture({ batchLockAcquired: false });
    const preview = await fixture.service.previewCandidateBatchMaterialization();

    await expect(fixture.service.materializeCandidateBatch({
      planToken: preview.planToken,
      idempotencyKey: "reviewed-develop-batch-4"
    })).rejects.toMatchObject({ response: { code: "IAM_ORGANIZATION_CANDIDATE_BATCH_BUSY" } });
    expect(fixture.repository.replaceCandidate).not.toHaveBeenCalled();
  });

  it("resumes after a partial failure without rewriting an already aligned subject", async () => {
    const fixture = batchFixture({ includeSecondMissing: true, busySubjectId: 3 });
    const preview = await fixture.service.previewCandidateBatchMaterialization();

    await expect(fixture.service.materializeCandidateBatch({
      planToken: preview.planToken,
      idempotencyKey: "reviewed-develop-batch-partial"
    })).rejects.toMatchObject({
      response: { code: "IAM_ORGANIZATION_CANDIDATE_MATERIALIZATION_SUBJECT_BUSY" }
    });
    expect(fixture.repository.replaceCandidate).toHaveBeenCalledTimes(1);
    expect(fixture.repository.replaceCandidate).toHaveBeenLastCalledWith(
      expect.objectContaining({ legacyUserId: 2 })
    );

    fixture.releaseBusySubject();
    const retry = await fixture.service.materializeCandidateBatch({
      planToken: preview.planToken,
      idempotencyKey: "reviewed-develop-batch-partial"
    });
    expect(retry).toMatchObject({
      completed: true,
      appliedCount: 1,
      skippedAlignedCount: 2,
      protectedSkippedCount: 1
    });
    expect(fixture.repository.replaceCandidate).toHaveBeenCalledTimes(2);
    expect(fixture.repository.replaceCandidate).toHaveBeenLastCalledWith(
      expect.objectContaining({ legacyUserId: 3 })
    );
  });

  it("blocks a reviewed plan when the exact subject-count expectation drifts", async () => {
    const fixture = batchFixture({ expectedLegacySubjectCount: 4 });
    const preview = await fixture.service.previewCandidateBatchMaterialization();

    expect(preview).toMatchObject({ executable: false, legacySubjectCount: 3 });
    expect(preview.blockedReasons).toContain("legacy-subject-count-mismatch");
    await expect(fixture.service.materializeCandidateBatch({
      planToken: preview.planToken,
      idempotencyKey: "reviewed-develop-batch-count-drift"
    })).rejects.toMatchObject({ response: { code: "IAM_ORGANIZATION_CANDIDATE_BATCH_PLAN_BLOCKED" } });
    expect(fixture.repository.replaceCandidate).not.toHaveBeenCalled();
  });

  it("does not report success when the full Legacy source drifts during the batch", async () => {
    const fixture = batchFixture({ driftLegacySourceDuringFinalPostcheck: true });
    const preview = await fixture.service.previewCandidateBatchMaterialization();

    await expect(fixture.service.materializeCandidateBatch({
      planToken: preview.planToken,
      idempotencyKey: "reviewed-develop-batch-final-drift"
    })).rejects.toMatchObject({
      response: { code: "IAM_ORGANIZATION_CANDIDATE_BATCH_POSTCHECK_FAILED" }
    });
    expect(fixture.repository.replaceCandidate).toHaveBeenCalledTimes(1);
  });

  it("blocks the whole batch when any subject has an unresolved materialization operation", async () => {
    const fixture = batchFixture({ unresolvedSubjectId: 1 });
    const preview = await fixture.service.previewCandidateBatchMaterialization();

    expect(preview).toMatchObject({ executable: false, ordinaryBlockedCount: 1 });
    expect(preview.blockedReasons).toContain("unresolved-candidate-materialization-operation");
    await expect(fixture.service.materializeCandidateBatch({
      planToken: preview.planToken,
      idempotencyKey: "reviewed-develop-batch-unresolved"
    })).rejects.toMatchObject({ response: { code: "IAM_ORGANIZATION_CANDIDATE_BATCH_PLAN_BLOCKED" } });
    expect(fixture.repository.replaceCandidate).not.toHaveBeenCalled();
  });

  it("keeps the new batch gate disabled and unconfigured by default", async () => {
    process.env = { ...originalEnv };
    const fixture = batchFixture({ batchEnabled: false });

    await expect(fixture.service.readiness()).resolves.toMatchObject({
      candidateBatchMaterialization: {
        enabled: false,
        environment: "disabled",
        planHmacKeyConfigured: false,
        canPreview: false,
        canApply: false,
        protectedSubjectsWritten: false
      }
    });
    await expect(fixture.service.materializeCandidateBatch({
      planToken: "00".repeat(32),
      idempotencyKey: "disabled"
    })).rejects.toMatchObject({ response: { code: "IAM_ORGANIZATION_CANDIDATE_BATCH_MATERIALIZATION_DISABLED" } });
  });

  it("permits a configured read-only preview while the apply switch remains disabled", async () => {
    const fixture = batchFixture({ batchEnabled: false });

    await expect(fixture.service.previewCandidateBatchMaterialization()).resolves.toMatchObject({
      executable: true,
      applyEnabled: false,
      ordinaryMissingCount: 1,
      blockedReasons: []
    });
    await expect(fixture.service.materializeCandidateBatch({
      planToken: "00".repeat(32),
      idempotencyKey: "preview-only"
    })).rejects.toMatchObject({ response: { code: "IAM_ORGANIZATION_CANDIDATE_BATCH_MATERIALIZATION_DISABLED" } });
    expect(fixture.repository.replaceCandidate).not.toHaveBeenCalled();
  });
});

function batchFixture(input: {
  secondStatus?: number;
  batchLockAcquired?: boolean;
  includeSecondMissing?: boolean;
  busySubjectId?: number;
  expectedLegacySubjectCount?: number;
  driftLegacySourceDuringFinalPostcheck?: boolean;
  batchEnabled?: boolean;
  unresolvedSubjectId?: number;
} = {}) {
  let busySubjectId = input.busySubjectId ?? null;
  const sources = [
    sourceUser(1, "ordinary-aligned", [], 10, [organization(1)]),
    sourceUser(2, "ordinary-missing", [], input.secondStatus ?? 10, []),
    ...(input.includeSecondMissing ? [sourceUser(3, "ordinary-missing-two", [], 10, [])] : []),
    sourceUser(input.includeSecondMissing ? 4 : 3, "root", ["root"], 10, [])
  ];
  process.env.IDENTITY_IAM_ORG_WRITE_CANDIDATE_BATCH_EXPECTED_LEGACY_SUBJECT_COUNT = String(
    input.expectedLegacySubjectCount ?? sources.length
  );
  process.env.IDENTITY_IAM_ORG_WRITE_CANDIDATE_BATCH_MATERIALIZATION_ENABLED = String(
    input.batchEnabled ?? true
  );
  const candidates = new Map<number, { legacyUserId: number; organizations: LegacyOrganization[] } | null>([
    [1, { legacyUserId: 1, organizations: [organization(1)] }],
    [2, null],
    [3, null],
    [4, null]
  ]);
  const operations = new Map<string, Record<string, any>>();
  const repository = {
    isConfigured: vi.fn(() => true),
    materializationSchemaReadiness: vi.fn(async () => ({
      ready: true, requiredTableCount: 5, existingTableCount: 5, missingTables: []
    })),
    withCandidateMaterializationBatchLock: vi.fn(async (callback: () => Promise<unknown>) =>
      input.batchLockAcquired === false
        ? { acquired: false as const }
        : { acquired: true as const, value: await callback() }
    ),
    withCandidateMaterializationSubjectLock: vi.fn(async (id: number, callback: () => Promise<unknown>) =>
      id === busySubjectId
        ? { acquired: false as const }
        : { acquired: true as const, value: await callback() }
    ),
    candidateForLegacyUser: vi.fn(async (legacyUserId: number) => candidates.get(legacyUserId) ?? null),
    countUnresolvedForLegacyUser: vi.fn(async (legacyUserId: number) =>
      legacyUserId === input.unresolvedSubjectId ? 1 : 0
    ),
    find: vi.fn(async (operationKey: string) => operations.get(operationKey) ?? null),
    beginCandidateMaterialization: vi.fn(async (operation: Record<string, any>) => {
      if (operations.has(operation.operationKey)) return { duplicate: true };
      operations.set(operation.operationKey, {
        ...operation,
        mode: "candidate-materialization",
        status: "pending",
        compensationStatus: "none",
        requestedAt: new Date().toISOString()
      });
      return { duplicate: false };
    }),
    resumeCandidateMaterialization: vi.fn(async () => ({ claimed: false })),
    reclaimStaleCandidateMaterialization: vi.fn(async () => ({ claimed: false })),
    replaceCandidate: vi.fn(async (snapshot: {
      legacyUserId: number;
      organizations: LegacyOrganization[];
    }) => {
      candidates.set(snapshot.legacyUserId, {
        legacyUserId: snapshot.legacyUserId,
        organizations: snapshot.organizations.map((item) => ({ ...item }))
      });
    }),
    finalizeCandidateMaterialization: vi.fn(async (operation: Record<string, any>) => {
      const existing = operations.get(operation.operationKey);
      if (!existing || existing.status !== "pending") return { updated: false };
      operations.set(operation.operationKey, { ...existing, ...operation });
      return { updated: true };
    }),
    summarizeRecent: vi.fn(async () => []),
    listRecentSafe: vi.fn(async () => [])
  };
  let snapshotReadCount = 0;
  const legacy = {
    readOrganizationCandidateSourceSnapshot: vi.fn(async () => {
      snapshotReadCount += 1;
      const snapshotSources = sources.map((source) => ({
        ...source,
        roles: [...source.roles],
        organizations: source.organizations.map((item) => ({ ...item }))
      }));
      if (input.driftLegacySourceDuringFinalPostcheck && snapshotReadCount >= 3) {
        snapshotSources[0] = {
          ...snapshotSources[0]!,
          organizations: [organization(99)]
        };
      }
      return {
        contract: "legacy-organization-candidate-source-snapshot/v1",
        users: snapshotSources
      };
    }),
    getUserById: vi.fn(async (legacyUserId: number) => {
      const source = sources.find((candidate) => candidate.id === legacyUserId);
      return source ? fullLegacyUser(source) : null;
    })
  };
  const plugin = { readiness: vi.fn(() => ({ mode: "legacy-proxy", legacyProxyConfigured: true })) };
  const jwt = { verifyAccessToken: vi.fn(() => { throw new Error("not used"); }) };
  const service = new IamOrganizationWriteService(plugin as never, repository as never, legacy as never, jwt as never);
  return {
    service,
    repository,
    legacy,
    sources,
    releaseBusySubject: () => { busySubjectId = null; }
  };
}

function sourceUser(
  id: number,
  username: string,
  roles: string[],
  status: number,
  organizations: LegacyOrganization[]
) {
  return { id, username, status, roles, organizations };
}

function fullLegacyUser(source: ReturnType<typeof sourceUser>): LegacyUserReadModel {
  return {
    id: source.id,
    username: source.username,
    email: null,
    status: source.status,
    nickname: null,
    emailVerifiedAt: null,
    createdAt: null,
    updatedAt: null,
    userInfo: {},
    roles: [...source.roles],
    organizations: source.organizations.map((item) => ({ ...item })),
    source: "legacy"
  };
}

function organization(id: number): LegacyOrganization {
  return { id, name: `organization-${id}`, title: `Organization ${id}`, createdAt: 1, updatedAt: 2 };
}

function enableBatchMaterialization(): void {
  process.env.IDENTITY_DB_NAME = "xrugc_identity_dev";
  process.env.LEGACY_DB_NAME = "bujiaban";
  process.env.IDENTITY_IAM_ENABLED = "true";
  process.env.IDENTITY_IAM_MODE = "readonly";
  process.env.IDENTITY_IAM_FALLBACK_ENABLED = "true";
  process.env.IDENTITY_IAM_RECONCILIATION_ENABLED = "false";
  process.env.IDENTITY_IAM_ROLE_PERMISSION_MATERIALIZATION_ENABLED = "false";
  process.env.IDENTITY_IAM_PERMISSION_MODEL_IMPORT_ENABLED = "false";
  process.env.IDENTITY_IAM_ORG_WRITE_MODE = "disabled";
  process.env.IDENTITY_IAM_ORG_WRITE_ROUTE_INTEGRATION_ENABLED = "false";
  process.env.IDENTITY_IAM_ORG_WRITE_DUAL_WRITE_EXECUTION_ENABLED = "false";
  process.env.IDENTITY_IAM_ORG_WRITE_ROLLOUT_MODE = "off";
  process.env.IDENTITY_IAM_ORG_WRITE_ROLLOUT_ALLOWLIST = "";
  process.env.IDENTITY_IAM_ORG_WRITE_ROLLOUT_PERCENTAGE = "0";
  process.env.IDENTITY_IAM_ORG_WRITE_CANDIDATE_MATERIALIZATION_ENABLED = "false";
  process.env.IDENTITY_IAM_ORG_WRITE_CANDIDATE_MATERIALIZATION_TARGET_LEGACY_USER_ID = "0";
  process.env.IDENTITY_IAM_ORG_WRITE_CANDIDATE_BATCH_MATERIALIZATION_ENABLED = "true";
  process.env.IDENTITY_IAM_ORG_WRITE_CANDIDATE_BATCH_MATERIALIZATION_ENVIRONMENT = "xrteeth-develop";
  process.env.IDENTITY_IAM_ORG_WRITE_CANDIDATE_BATCH_MATERIALIZATION_PLAN_HMAC_KEY = PLAN_KEY;
  process.env.IDENTITY_IAM_ORG_WRITE_CANDIDATE_BATCH_EXPECTED_LEGACY_SUBJECT_COUNT = "3";
  process.env.IDENTITY_IAM_ORG_WRITE_CANDIDATE_BATCH_EXPECTED_PROTECTED_SUBJECT_COUNT = "1";
  process.env.IDENTITY_IAM_AUTHZ_READ_MODE = "legacy";
  process.env.IDENTITY_IAM_AUTHZ_FALLBACK_ENABLED = "true";
  process.env.IDENTITY_IAM_AUTHZ_ROLLOUT_MODE = "off";
  process.env.IDENTITY_IAM_ROLE_WRITE_MODE = "disabled";
}
