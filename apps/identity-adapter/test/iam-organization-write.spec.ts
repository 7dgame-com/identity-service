import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createHash } from "node:crypto";
import { loadConfig } from "../src/config.js";
import { IamOrganizationWriteController } from "../src/iam-organization-write.controller.js";
import { IamOrganizationWriteService } from "../src/iam-organization-write.service.js";
import {
  IamOrganizationWriteRepository,
  ORGANIZATION_CANDIDATE_MATERIALIZATION_PENDING_LEASE_MS,
  organizationCandidateMaterializationOperationKey,
  organizationCandidateSnapshotFingerprint,
  organizationWriteCompensationStatus,
  organizationWriteOperationMode,
  organizationWriteOperationStatus,
  redactOrganizationWriteMetadata
} from "../src/iam-organization-write.repository.js";
import type { LegacyOrganization, LegacyUserReadModel } from "../src/legacy-identity.reader.js";

const originalEnv = { ...process.env };

describe("IAM organization membership write compatibility layer", () => {
  beforeEach(() => {
    process.env = { ...originalEnv };
    delete process.env.IDENTITY_IAM_ORG_WRITE_MODE;
    delete process.env.IDENTITY_IAM_ORG_WRITE_ROUTE_INTEGRATION_ENABLED;
    delete process.env.IDENTITY_IAM_ORG_WRITE_DUAL_WRITE_EXECUTION_ENABLED;
    delete process.env.IDENTITY_IAM_ORG_WRITE_ROLLOUT_MODE;
    delete process.env.IDENTITY_IAM_ORG_WRITE_ROLLOUT_ALLOWLIST;
    delete process.env.IDENTITY_IAM_ORG_WRITE_ROLLOUT_PERCENTAGE;
    delete process.env.IDENTITY_IAM_ORG_WRITE_CANDIDATE_MATERIALIZATION_ENABLED;
    delete process.env.IDENTITY_IAM_ORG_WRITE_CANDIDATE_MATERIALIZATION_TARGET_LEGACY_USER_ID;
  });

  afterEach(() => {
    process.env = { ...originalEnv };
  });

  it("is disabled and route-disconnected by default", async () => {
    const fixture = createFixture();

    await expect(fixture.service.readiness()).resolves.toMatchObject({
      enabled: false,
      mode: "disabled",
      routeIntegrationEnabled: false,
      sourceOfTruth: "legacy",
      candidateMaterialization: {
        enabled: false,
        targetConfigured: false,
        requiresExpectedSnapshotFingerprint: true,
        requiresIdempotencyKey: true,
        mutatesLegacy: false,
        writeScope: "identity-candidate-only"
      },
      identityNativeSupported: false
    });
    await expect(fixture.service.proxyMembershipUpdate(updateRequest([1]))).resolves.toBeNull();
    expect(fixture.plugin.proxy).not.toHaveBeenCalled();
  });

  it("pins all organization write configuration defaults closed", () => {
    expect(loadConfig({}).iam).toMatchObject({
      organizationWriteMode: "disabled",
      organizationWriteRouteIntegrationEnabled: false,
      organizationWriteDualWriteExecutionEnabled: false,
      organizationWriteRolloutMode: "off",
      organizationWriteRolloutAllowlist: "",
      organizationWriteRolloutPercentage: 0,
      organizationWriteCandidateMaterializationEnabled: false,
      organizationWriteCandidateMaterializationTargetLegacyUserId: 0
    });
  });

  it("maps the internal preview/apply controller contract without accepting conflicting idempotency headers", async () => {
    process.env.IDENTITY_IAM_INTERNAL_API_TOKEN = "organization-internal-test";
    process.env.IDENTITY_BUILD_REVISION = "a".repeat(40);
    const organizationWrite = {
      previewCandidateMaterialization: vi.fn(async () => ({ mutation: false, expectedSnapshotFingerprint: "a".repeat(64) })),
      materializeCandidate: vi.fn(async () => ({ materialized: true }))
    };
    const controller = new IamOrganizationWriteController(organizationWrite as never);

    await expect(controller.previewCandidateMaterialization("organization-internal-test", "24")).resolves.toMatchObject({
      capability: "iam-organization-candidate-materialization-preview",
      data: { mutation: false, expectedSnapshotFingerprint: "a".repeat(64) }
    });
    await expect(controller.materializeCandidate(
      "organization-internal-test",
      "a".repeat(40),
      "materialize-24",
      undefined,
      "24",
      { expectedSnapshotFingerprint: "a".repeat(64) }
    )).resolves.toMatchObject({
      capability: "iam-organization-candidate-materialization",
      data: { materialized: true }
    });
    expect(organizationWrite.materializeCandidate).toHaveBeenCalledWith({
      legacyUserId: 24,
      expectedSnapshotFingerprint: "a".repeat(64),
      idempotencyKey: "materialize-24"
    });
    await expect(controller.materializeCandidate(
      "organization-internal-test",
      "a".repeat(40),
      "one",
      "two",
      "24",
      { expectedSnapshotFingerprint: "a".repeat(64) }
    )).rejects.toMatchObject({ response: { code: "IDEMPOTENCY_KEY_CONFLICT" } });
  });

  it.each([
    [undefined, "IDENTITY_EXPECTED_BUILD_REVISION_INVALID"],
    ["invalid", "IDENTITY_EXPECTED_BUILD_REVISION_INVALID"],
    ["b".repeat(40), "IDENTITY_BUILD_REVISION_MISMATCH"]
  ])("rejects materialization revision %s before any service call", async (expectedRevision, code) => {
    process.env.IDENTITY_IAM_INTERNAL_API_TOKEN = "organization-internal-test";
    process.env.IDENTITY_BUILD_REVISION = "a".repeat(40);
    const organizationWrite = { materializeCandidate: vi.fn() };
    const controller = new IamOrganizationWriteController(organizationWrite as never);

    await expect(controller.materializeCandidate(
      "organization-internal-test",
      expectedRevision,
      "materialize-24",
      undefined,
      "24",
      { expectedSnapshotFingerprint: "a".repeat(64) }
    )).rejects.toMatchObject({ response: { code } });
    expect(organizationWrite.materializeCandidate).not.toHaveBeenCalled();
  });

  it("rejects duplicate expected revision headers before any service call", async () => {
    process.env.IDENTITY_IAM_INTERNAL_API_TOKEN = "organization-internal-test";
    process.env.IDENTITY_BUILD_REVISION = "a".repeat(40);
    const organizationWrite = { materializeCandidate: vi.fn() };
    const controller = new IamOrganizationWriteController(organizationWrite as never);

    await expect(controller.materializeCandidate(
      "organization-internal-test",
      ["a".repeat(40), "a".repeat(40)],
      "materialize-24",
      undefined,
      "24",
      { expectedSnapshotFingerprint: "a".repeat(64) }
    )).rejects.toMatchObject({ response: { code: "IDENTITY_EXPECTED_BUILD_REVISION_INVALID" } });
    expect(organizationWrite.materializeCandidate).not.toHaveBeenCalled();
  });

  it.each([undefined, "invalid", "A".repeat(40)])(
    "rejects unavailable or invalid running revision %s before any service call",
    async (actualRevision) => {
      process.env.IDENTITY_IAM_INTERNAL_API_TOKEN = "organization-internal-test";
      if (actualRevision === undefined) delete process.env.IDENTITY_BUILD_REVISION;
      else process.env.IDENTITY_BUILD_REVISION = actualRevision;
      const organizationWrite = { materializeCandidate: vi.fn() };
      const controller = new IamOrganizationWriteController(organizationWrite as never);

      await expect(controller.materializeCandidate(
        "organization-internal-test",
        "a".repeat(40),
        "materialize-24",
        undefined,
        "24",
        { expectedSnapshotFingerprint: "a".repeat(64) }
      )).rejects.toMatchObject({ response: { code: "IDENTITY_BUILD_REVISION_UNAVAILABLE" } });
      expect(organizationWrite.materializeCandidate).not.toHaveBeenCalled();
    }
  );

  it("preserves safe completed and failed materialization ledger states through the service and controller", async () => {
    process.env.IDENTITY_IAM_INTERNAL_API_TOKEN = "organization-internal-test";
    const operations = [
      {
        operationKeyDigest: "a".repeat(64),
        idempotencyKeyDigest: "b".repeat(64),
        legacyUserId: 581,
        mode: "candidate-materialization",
        status: "completed",
        legacyStatus: "read-only",
        identityStatus: "candidate-materialized",
        compensationStatus: "none",
        errorCode: null
      },
      {
        operationKeyDigest: "c".repeat(64),
        idempotencyKeyDigest: "d".repeat(64),
        legacyUserId: 581,
        mode: "candidate-materialization",
        status: "failed",
        legacyStatus: "read-only",
        identityStatus: "candidate-write-outcome-unknown",
        compensationStatus: "required",
        errorCode: "ServiceUnavailableException"
      }
    ];
    const fixture = createFixture({ recentOperations: operations });

    await expect(fixture.service.operationLedgerRecent({ sinceMinutes: 60, limit: 50 })).resolves.toMatchObject({
      configured: true,
      schemaReady: true,
      sinceMinutes: 60,
      limit: 50,
      operations
    });
    expect(fixture.repository.listRecentSafe).toHaveBeenCalledWith(60, 50);

    const controller = new IamOrganizationWriteController(fixture.service);
    await expect(controller.operationLedgerRecent("organization-internal-test", "60", "50")).resolves.toMatchObject({
      status: "ok",
      capability: "iam-organization-write-operation-ledger",
      data: { configured: true, schemaReady: true, operations }
    });
  });

  it("does not intercept updates when organization_ids is absent", async () => {
    enableLegacyProxy();
    const fixture = createFixture();

    await expect(fixture.service.proxyMembershipUpdate(updateRequest(undefined))).resolves.toBeNull();
    expect(fixture.plugin.proxy).not.toHaveBeenCalled();
  });

  it("preserves the exact Legacy response in the separately enabled legacy-proxy window", async () => {
    enableLegacyProxy();
    const fixture = createFixture();
    const response = await fixture.service.proxyMembershipUpdate(updateRequest([]));

    expect(response).toMatchObject({
      status: 200,
      body: { code: 0, data: { id: 24, organizations: [] } },
      mode: "legacy-proxy",
      evidence: { decision: "selected:allowlist", matchedSelectorKind: "legacy", identityStatus: "legacy-readback-aligned" }
    });
    expect(fixture.plugin.proxy).toHaveBeenCalledTimes(1);
    expect(fixture.repository.begin).not.toHaveBeenCalled();
  });

  it("does not leak the underlying plugin-user dual-write mode into a legacy-proxy organization response", async () => {
    enableLegacyProxy();
    const fixture = createFixture({ pluginMode: "dual-write" });
    const response = await fixture.service.proxyMembershipUpdate(updateRequest([999]));

    expect(response).toMatchObject({
      status: 200,
      mode: "legacy-proxy",
      evidence: { decision: "selected:allowlist", matchedSelectorKind: "legacy" }
    });
    await expect(fixture.plugin.proxy.mock.results[0]?.value).resolves.toMatchObject({ mode: "dual-write" });
  });

  it("fails closed when legacy-proxy has no scoped rollout selector", async () => {
    process.env.IDENTITY_IAM_ORG_WRITE_MODE = "legacy-proxy";
    process.env.IDENTITY_IAM_ORG_WRITE_ROUTE_INTEGRATION_ENABLED = "true";
    const fixture = createFixture();

    await expect(fixture.service.readiness()).resolves.toMatchObject({
      legacyProxyGate: { executable: false, missingCapabilities: ["scoped-rollout-selector"] },
      blockedReasons: ["scoped-rollout-selector"]
    });
    await expect(fixture.service.proxyMembershipUpdate(updateRequest([1]))).resolves.toBeNull();
    expect(fixture.plugin.proxy).not.toHaveBeenCalled();
    expect(fixture.legacy.getUserById).not.toHaveBeenCalled();
  });

  it("does not intercept a legacy-proxy membership update outside the approved allowlist", async () => {
    enableLegacyProxy();
    const fixture = createFixture();

    await expect(fixture.service.proxyMembershipUpdate({
      method: "POST",
      headers: {},
      body: { id: 25, organization_ids: [1] }
    })).resolves.toBeNull();
    expect(fixture.plugin.proxy).not.toHaveBeenCalled();
    expect(fixture.legacy.getUserById).not.toHaveBeenCalled();
  });

  it("previews selected and unselected legacy-proxy targets without reading or writing", async () => {
    enableLegacyProxy();
    const fixture = createFixture();

    await expect(fixture.service.previewMembershipRollout(24)).resolves.toMatchObject({
      mutation: false,
      mode: "legacy-proxy",
      route: "/v1/plugin-user/update-user",
      scope: "membership-replace",
      selected: true,
      executable: true,
      decision: "selected:allowlist",
      matchedSelectorKind: "legacy",
      sourceOfTruth: "legacy",
      identityNativeSupported: false,
      blockedReasons: []
    });
    await expect(fixture.service.previewMembershipRollout(25)).resolves.toMatchObject({
      mutation: false,
      selected: false,
      executable: false,
      decision: "not-selected:allowlist",
      blockedReasons: ["target-not-selected"]
    });
    expect(fixture.plugin.proxy).not.toHaveBeenCalled();
    expect(fixture.repository.begin).not.toHaveBeenCalled();
    expect(fixture.legacy.getUserById).not.toHaveBeenCalled();
  });

  it("leaves malformed organization_ids to the existing Legacy contract path", async () => {
    enableLegacyProxy();
    const fixture = createFixture();
    await expect(fixture.service.proxyMembershipUpdate({
      method: "POST",
      headers: {},
      body: { id: 24, organization_ids: ["not-an-id"] }
    })).resolves.toBeNull();
    expect(fixture.plugin.proxy).not.toHaveBeenCalled();
    expect(fixture.repository.begin).not.toHaveBeenCalled();
  });

  it("requires an explicit idempotency key for a selected dual-write", async () => {
    enableDualWrite();
    const fixture = createFixture();

    await expect(fixture.service.proxyMembershipUpdate(updateRequest([1]))).rejects.toMatchObject({
      response: { code: "IAM_ORGANIZATION_WRITE_IDEMPOTENCY_KEY_REQUIRED" }
    });
    expect(fixture.plugin.proxy).not.toHaveBeenCalled();
  });

  it("preserves Legacy authorization and validation failures without writing candidate state", async () => {
    enableDualWrite();
    const fixture = createFixture({ pluginResponse: { status: 403, body: { code: 403, message: "Forbidden" } } });
    const response = await fixture.service.proxyMembershipUpdate(updateRequest([999], "org-forbidden-1"));

    expect(response).toMatchObject({ status: 403, body: { code: 403, message: "Forbidden" }, evidence: { identityStatus: "skipped" } });
    expect(fixture.repository.replaceCandidate).not.toHaveBeenCalled();
    expect(fixture.repository.update).toHaveBeenLastCalledWith(expect.objectContaining({
      status: "failed",
      errorCode: "LegacyRejected",
      compensationStatus: "none"
    }));
  });

  it("fails closed for a protected root subject before invoking the Legacy mutation", async () => {
    enableDualWrite();
    const fixture = createFixture({ username: "root", roles: ["root"] });

    await expect(fixture.service.proxyMembershipUpdate(updateRequest([1], "org-root-1"))).rejects.toMatchObject({
      response: { code: "IAM_ORGANIZATION_WRITE_PROTECTED_SUBJECT" }
    });
    expect(fixture.plugin.proxy).not.toHaveBeenCalled();
    expect(fixture.repository.begin).not.toHaveBeenCalled();
  });

  it("writes candidate membership only after successful Legacy readback alignment", async () => {
    enableDualWrite();
    const fixture = createFixture({ organizations: [organization(1, "campus-one", "Campus One")] });
    const response = await fixture.service.proxyMembershipUpdate(updateRequest([1], "org-success-1"));

    expect(response).toMatchObject({
      status: 200,
      body: { code: 0, data: { id: 24 } },
      mode: "dual-write",
      evidence: { identityStatus: "candidate-completed" }
    });
    expect(fixture.plugin.proxy).toHaveBeenCalledTimes(1);
    expect(fixture.repository.replaceCandidate).toHaveBeenCalledWith(expect.objectContaining({
      legacyUserId: 24,
      organizations: [expect.objectContaining({ id: 1, name: "campus-one" })]
    }));
    expect(fixture.repository.update).toHaveBeenLastCalledWith(expect.objectContaining({
      status: "completed",
      identityStatus: "candidate-completed",
      compensationStatus: "none"
    }));
  });

  it("returns Legacy success but records required recovery when readback mismatches", async () => {
    enableDualWrite();
    const fixture = createFixture({ organizations: [organization(2, "campus-two", "Campus Two")] });
    const response = await fixture.service.proxyMembershipUpdate(updateRequest([1], "org-mismatch-1"));

    expect(response).toMatchObject({
      status: 200,
      body: { code: 0, data: { id: 24 } },
      evidence: { identityStatus: "candidate-failed" }
    });
    expect(fixture.repository.replaceCandidate).not.toHaveBeenCalled();
    expect(fixture.repository.update).toHaveBeenLastCalledWith(expect.objectContaining({
      status: "legacy_completed",
      identityStatus: "candidate-failed",
      compensationStatus: "required",
      errorCode: "Error"
    }));
  });

  it("rejects reuse of an idempotency key with a different membership set before Legacy", async () => {
    enableDualWrite();
    const fixture = createFixture({ duplicate: true, existingFingerprint: "different" });

    await expect(fixture.service.proxyMembershipUpdate(updateRequest([1], "org-conflict-1"))).rejects.toMatchObject({
      response: { code: "IDEMPOTENCY_KEY_REUSED_WITH_DIFFERENT_REQUEST" }
    });
    expect(fixture.plugin.proxy).not.toHaveBeenCalled();
  });

  it("reports P1 membership and P2 organization metadata mismatches independently", async () => {
    enableDualWrite();
    const fixture = createFixture({
      organizations: [organization(1, "campus-one", "Campus One"), organization(2, "campus-two", "Campus Two")],
      candidateOrganizations: [organization(1, "campus-one", "Renamed")]
    });

    await expect(fixture.service.subjectAlignment(24)).resolves.toMatchObject({
      aligned: false,
      mismatch: 2,
      P0: 0,
      P1: 1,
      P2: 1,
      membershipMismatch: [2],
      metadataMismatch: [1]
    });
  });

  it("does not treat two empty sets as aligned when the Identity candidate snapshot is missing", async () => {
    enableDualWrite();
    const fixture = createFixture({ candidateMissing: true });

    await expect(fixture.service.subjectAlignment(24)).resolves.toMatchObject({
      aligned: false,
      mismatch: 1,
      P0: 0,
      P1: 1,
      P2: 0,
      reason: "identity-candidate-snapshot-missing"
    });
  });

  it("previews one exact candidate materialization without exposing raw subject or organization ids", async () => {
    enableCandidateMaterialization();
    const organizations = [organization(7, "MixedCase-Campus", "Mixed Case Campus")];
    const fixture = createFixture({ organizations, candidateMissing: true });

    const preview = await fixture.service.previewCandidateMaterialization(24);

    expect(preview).toMatchObject({
      mutation: false,
      executable: true,
      organizationCount: 1,
      alignment: { aligned: false, P0: 0, P1: 1, P2: 0, reason: "identity-candidate-snapshot-missing" },
      unresolvedOperationCount: 0,
      sourceOfTruth: "legacy",
      blockedReasons: []
    });
    expect(preview.expectedSnapshotFingerprint).toBe(organizationCandidateSnapshotFingerprint(24, organizations));
    expect(JSON.stringify(preview)).not.toContain("MixedCase-Campus");
    expect(JSON.stringify(preview)).not.toContain('"legacyUserId":24');
    expect(fixture.repository.replaceCandidate).not.toHaveBeenCalled();
  });

  it("reports schema-aware materialization readiness without exposing the configured target", async () => {
    enableCandidateMaterialization();
    const ready = createFixture();
    await expect(ready.service.readiness()).resolves.toMatchObject({
      candidateMaterialization: {
        enabled: true,
        targetConfigured: true,
        schemaReady: true,
        canPreview: true,
        canApply: true,
        blockers: []
      }
    });
    expect(JSON.stringify(await ready.service.readiness())).not.toContain('"legacyUserId":24');

    const missing = createFixture({ schemaReady: false });
    await expect(missing.service.readiness()).resolves.toMatchObject({
      candidateMaterialization: {
        schemaReady: false,
        canPreview: false,
        canApply: false,
        blockers: expect.arrayContaining(["schema-not-ready"])
      }
    });
    const unavailable = createFixture({ schemaReadinessThrows: true });
    await expect(unavailable.service.readiness()).resolves.toMatchObject({
      candidateMaterialization: {
        canPreview: false,
        canApply: false,
        blockers: expect.arrayContaining(["schema-readiness-unavailable"])
      }
    });
  });

  it("keeps preview read-only and blocks apply before Legacy reads when the five-table schema is missing", async () => {
    enableCandidateMaterialization();
    const fixture = createFixture({ schemaReady: false, candidateMissing: true });

    await expect(fixture.service.previewCandidateMaterialization(24)).resolves.toMatchObject({
      mutation: false,
      executable: false,
      schemaReady: false,
      expectedSnapshotFingerprint: null,
      blockedReasons: ["schema-not-ready"]
    });
    expect(fixture.legacy.getUserById).not.toHaveBeenCalled();
    expect(fixture.repository.candidateForLegacyUser).not.toHaveBeenCalled();
    expect(fixture.repository.countUnresolvedForLegacyUser).not.toHaveBeenCalled();

    await expect(fixture.service.materializeCandidate({
      legacyUserId: 24,
      expectedSnapshotFingerprint: "a".repeat(64),
      idempotencyKey: "schema-missing"
    })).rejects.toMatchObject({
      response: { code: "IAM_ORGANIZATION_CANDIDATE_MATERIALIZATION_SCHEMA_NOT_READY" }
    });
    expect(fixture.legacy.getUserById).not.toHaveBeenCalled();
    expect(fixture.repository.beginCandidateMaterialization).not.toHaveBeenCalled();
  });

  it("serializes different idempotency keys for the same subject with a nowait advisory lock", async () => {
    enableCandidateMaterialization();
    const organizations = [organization(1, "test", "Test")];
    let releaseCandidateWrite!: () => void;
    const candidateWriteGate = new Promise<void>((resolve) => { releaseCandidateWrite = resolve; });
    const fixture = createFixture({ organizations, candidateMissing: true, replaceCandidateGate: candidateWriteGate });
    const expectedSnapshotFingerprint = organizationCandidateSnapshotFingerprint(24, organizations);
    const first = fixture.service.materializeCandidate({
      legacyUserId: 24,
      expectedSnapshotFingerprint,
      idempotencyKey: "subject-lock-first"
    });
    await vi.waitFor(() => expect(fixture.repository.replaceCandidate).toHaveBeenCalledTimes(1));

    await expect(fixture.service.materializeCandidate({
      legacyUserId: 24,
      expectedSnapshotFingerprint,
      idempotencyKey: "subject-lock-second"
    })).rejects.toMatchObject({
      response: { code: "IAM_ORGANIZATION_CANDIDATE_MATERIALIZATION_SUBJECT_BUSY" }
    });
    expect(fixture.repository.beginCandidateMaterialization).toHaveBeenCalledTimes(1);
    releaseCandidateWrite();
    await expect(first).resolves.toMatchObject({ materialized: true });
  });

  it("does not probe schema or Legacy when the subject advisory lock is unavailable", async () => {
    enableCandidateMaterialization();
    const fixture = createFixture({ candidateMissing: true, lockAcquired: false });

    await expect(fixture.service.materializeCandidate({
      legacyUserId: 24,
      expectedSnapshotFingerprint: organizationCandidateSnapshotFingerprint(24, []),
      idempotencyKey: "subject-lock-unavailable"
    })).rejects.toMatchObject({
      response: { code: "IAM_ORGANIZATION_CANDIDATE_MATERIALIZATION_SUBJECT_BUSY" }
    });
    expect(fixture.repository.materializationSchemaReadiness).not.toHaveBeenCalled();
    expect(fixture.legacy.getUserById).not.toHaveBeenCalled();
    expect(fixture.repository.beginCandidateMaterialization).not.toHaveBeenCalled();
  });

  it("materializes only the reviewed current Legacy snapshot and preserves the original organization name", async () => {
    enableCandidateMaterialization();
    const organizations = [organization(7, "MixedCase-Campus", "Mixed Case Campus")];
    const fixture = createFixture({ organizations, candidateMissing: true });
    const expectedSnapshotFingerprint = organizationCandidateSnapshotFingerprint(24, organizations);

    const result = await fixture.service.materializeCandidate({
      legacyUserId: 24,
      expectedSnapshotFingerprint,
      idempotencyKey: "candidate-materialize-24-v1"
    });

    expect(result).toMatchObject({
      materialized: true,
      idempotentReplay: false,
      operationKeyDigest: operationDigest(24, "candidate-materialize-24-v1"),
      organizationCount: 1,
      before: { aligned: false, P0: 0, P1: 1, P2: 0 },
      after: { aligned: true, mismatch: 0, P0: 0, P1: 0, P2: 0 },
      safety: {
        legacyWritePerformed: false,
        identityCandidateWritePerformed: true,
        historicalMutationReplayed: false,
        legacyRemainsAuthoritative: true,
        authzInputChanged: false,
        writeScope: "identity-candidate-only"
      }
    });
    expect(fixture.repository.replaceCandidate).toHaveBeenCalledWith(expect.objectContaining({
      legacyUserId: 24,
      organizations: [expect.objectContaining({ id: 7, name: "MixedCase-Campus" })]
    }));
    expect(fixture.repository.beginCandidateMaterialization).toHaveBeenCalledWith(expect.objectContaining({
      legacyUserId: 24,
      requestFingerprint: expectedSnapshotFingerprint
    }));
    expect(fixture.repository.finalizeCandidateMaterialization).toHaveBeenLastCalledWith(expect.objectContaining({
      status: "completed",
      legacyStatus: "read-only",
      identityStatus: "candidate-materialized",
      compensationStatus: "none"
    }));
    expect(fixture.plugin.proxy).not.toHaveBeenCalled();
  });

  it("persists an explicit empty candidate snapshot and replays the same idempotency key without rewriting", async () => {
    enableCandidateMaterialization();
    const fixture = createFixture({ organizations: [], candidateMissing: true });
    const input = {
      legacyUserId: 24,
      expectedSnapshotFingerprint: organizationCandidateSnapshotFingerprint(24, []),
      idempotencyKey: "candidate-materialize-empty-24"
    };

    await expect(fixture.service.materializeCandidate(input)).resolves.toMatchObject({
      materialized: true,
      operationKeyDigest: operationDigest(24, input.idempotencyKey),
      organizationCount: 0,
      after: { aligned: true, P1: 0 }
    });
    await expect(fixture.service.materializeCandidate(input)).resolves.toMatchObject({
      materialized: false,
      idempotentReplay: true,
      operationKeyDigest: operationDigest(24, input.idempotencyKey),
      organizationCount: 0
    });
    expect(fixture.repository.replaceCandidate).toHaveBeenCalledTimes(1);
    expect(fixture.repository.beginCandidateMaterialization).toHaveBeenCalledTimes(1);
  });

  it("conservatively requires recovery after a candidate-write failure and keeps the guarded recovery path", async () => {
    enableCandidateMaterialization();
    const organizations = [organization(1, "test", "Test")];
    const fixture = createFixture({ organizations, candidateMissing: true, replaceCandidateFailures: 1 });
    const input = {
      legacyUserId: 24,
      expectedSnapshotFingerprint: organizationCandidateSnapshotFingerprint(24, organizations),
      idempotencyKey: "candidate-materialize-retry-24"
    };

    await expect(fixture.service.materializeCandidate(input)).rejects.toThrow("candidate write failed");
    expect(fixture.repository.finalizeCandidateMaterialization).toHaveBeenLastCalledWith(expect.objectContaining({
      status: "failed",
      identityStatus: "candidate-write-outcome-unknown",
      compensationStatus: "required"
    }));

    await expect(fixture.service.materializeCandidate(input)).resolves.toMatchObject({
      materialized: true,
      operationKeyDigest: operationDigest(24, input.idempotencyKey),
      after: { aligned: true, P1: 0 }
    });
    expect(fixture.repository.resumeCandidateMaterialization).toHaveBeenCalledTimes(1);
    expect(fixture.repository.replaceCandidate).toHaveBeenCalledTimes(2);
  });

  it("recovers from current reviewed Legacy when a committed candidate write loses its acknowledgement", async () => {
    enableCandidateMaterialization();
    const original = [organization(1, "original", "Original")];
    const current = [organization(2, "current", "Current")];
    const originalFingerprint = organizationCandidateSnapshotFingerprint(24, original);
    const currentFingerprint = organizationCandidateSnapshotFingerprint(24, current);
    const idempotencyKey = "candidate-materialize-commit-ack-lost-24";
    const fixture = createFixture({
      organizations: original,
      candidateMissing: true,
      replaceCandidateCommitsThenFailures: 1,
      postcheckUser: { organizations: current }
    });

    await expect(fixture.service.materializeCandidate({
      legacyUserId: 24,
      expectedSnapshotFingerprint: originalFingerprint,
      idempotencyKey
    })).rejects.toThrow("candidate write acknowledgement lost");
    expect(fixture.repository.finalizeCandidateMaterialization).toHaveBeenLastCalledWith(expect.objectContaining({
      status: "failed",
      identityStatus: "candidate-write-outcome-unknown",
      compensationStatus: "required"
    }));

    await expect(fixture.service.materializeCandidate({
      legacyUserId: 24,
      expectedSnapshotFingerprint: currentFingerprint,
      idempotencyKey
    })).resolves.toMatchObject({
      materialized: true,
      after: { aligned: true, mismatch: 0 }
    });
    expect(fixture.repository.resumeCandidateMaterialization).toHaveBeenCalledWith(
      expect.any(String),
      originalFingerprint,
      currentFingerprint,
      expect.any(String),
      expect.objectContaining({
        recovery: "current-reviewed-legacy-snapshot",
        source: "current-legacy-read"
      })
    );
    expect(fixture.repository.replaceCandidate).toHaveBeenLastCalledWith(expect.objectContaining({
      organizations: current
    }));
  });

  it("records a postcheck failure as recovery-required and repairs it only through the same guarded endpoint", async () => {
    enableCandidateMaterialization();
    const organizations = [organization(1, "test", "Test")];
    const fixture = createFixture({ organizations, candidateMissing: true, postcheckMismatchOnce: true });
    const idempotencyKey = "candidate-materialize-postcheck-24";
    const input = {
      legacyUserId: 24,
      expectedSnapshotFingerprint: organizationCandidateSnapshotFingerprint(24, organizations),
      idempotencyKey
    };

    await expect(fixture.service.materializeCandidate(input)).rejects.toMatchObject({
      response: { code: "IAM_ORGANIZATION_CANDIDATE_MATERIALIZATION_POSTCHECK_FAILED" }
    });
    expect(fixture.repository.finalizeCandidateMaterialization).toHaveBeenLastCalledWith(expect.objectContaining({
      status: "failed",
      identityStatus: "candidate-postcheck-failed",
      compensationStatus: "required"
    }));

    await expect(fixture.service.retryIdentityCandidate(
      organizationCandidateMaterializationOperationKey(24, idempotencyKey)
    )).rejects.toMatchObject({ response: { code: "IAM_ORGANIZATION_WRITE_RECOVERY_NOT_APPLICABLE" } });
    await expect(fixture.service.materializeCandidate(input)).resolves.toMatchObject({
      materialized: true,
      operationKeyDigest: operationDigest(24, input.idempotencyKey),
      after: { aligned: true, P0: 0, P1: 0, P2: 0 }
    });
    expect(fixture.repository.resumeCandidateMaterialization).toHaveBeenCalledTimes(1);
  });

  it("rejects a different reviewed snapshot under the same idempotency key", async () => {
    enableCandidateMaterialization();
    const organizations = [organization(1, "test", "Test")];
    const fixture = createFixture({ organizations, candidateMissing: true });
    const idempotencyKey = "candidate-materialize-conflict-24";
    await fixture.service.materializeCandidate({
      legacyUserId: 24,
      expectedSnapshotFingerprint: organizationCandidateSnapshotFingerprint(24, organizations),
      idempotencyKey
    });

    const changed = [organization(2, "test-two", "Test Two")];
    fixture.legacyUser.organizations = changed;
    await expect(fixture.service.materializeCandidate({
      legacyUserId: 24,
      expectedSnapshotFingerprint: organizationCandidateSnapshotFingerprint(24, changed),
      idempotencyKey
    })).rejects.toMatchObject({ response: { code: "IDEMPOTENCY_KEY_REUSED_WITH_DIFFERENT_REQUEST" } });
    expect(fixture.repository.replaceCandidate).toHaveBeenCalledTimes(1);
  });

  it("fails closed when another worker wins the initial reservation or failed-operation retry claim", async () => {
    enableCandidateMaterialization();
    const organizations = [organization(1, "test", "Test")];
    const expectedSnapshotFingerprint = organizationCandidateSnapshotFingerprint(24, organizations);

    await expect(createFixture({
      organizations,
      candidateMissing: true,
      materializationBeginRace: true
    }).service.materializeCandidate({
      legacyUserId: 24,
      expectedSnapshotFingerprint,
      idempotencyKey: "candidate-materialize-race-24"
    })).rejects.toMatchObject({
      response: { code: "IAM_ORGANIZATION_CANDIDATE_MATERIALIZATION_OPERATION_IN_PROGRESS" }
    });

    const retryFixture = createFixture({ organizations, candidateMissing: true, replaceCandidateFailures: 1, resumeClaimed: false });
    const retryInput = {
      legacyUserId: 24,
      expectedSnapshotFingerprint,
      idempotencyKey: "candidate-materialize-claim-24"
    };
    await expect(retryFixture.service.materializeCandidate(retryInput)).rejects.toThrow("candidate write failed");
    await expect(retryFixture.service.materializeCandidate(retryInput)).rejects.toMatchObject({
      response: { code: "IAM_ORGANIZATION_CANDIDATE_MATERIALIZATION_OPERATION_IN_PROGRESS" }
    });
    expect(retryFixture.repository.replaceCandidate).toHaveBeenCalledTimes(1);
  });

  it("returns only the operation digest when a completed reservation race is replayed", async () => {
    enableCandidateMaterialization();
    const organizations = [organization(1, "test", "Test")];
    const idempotencyKey = "candidate-materialize-completed-race-24";
    const fixture = createFixture({
      organizations,
      candidateMissing: true,
      materializationBeginRaceCompleted: true
    });

    await expect(fixture.service.materializeCandidate({
      legacyUserId: 24,
      expectedSnapshotFingerprint: organizationCandidateSnapshotFingerprint(24, organizations),
      idempotencyKey
    })).resolves.toMatchObject({
      materialized: false,
      idempotentReplay: true,
      operationKeyDigest: operationDigest(24, idempotencyKey),
      after: { aligned: true, mismatch: 0 }
    });
    expect(fixture.repository.replaceCandidate).not.toHaveBeenCalled();
  });

  it("reclaims only a stale same-key pending lease and refreshes ownership before writing", async () => {
    enableCandidateMaterialization();
    const organizations = [organization(1, "test", "Test")];
    const idempotencyKey = "candidate-materialize-stale-lease-24";
    const requestFingerprint = organizationCandidateSnapshotFingerprint(24, organizations);
    const operationKey = organizationCandidateMaterializationOperationKey(24, idempotencyKey);
    const stale = createFixture({
      organizations,
      candidateMissing: true,
      initialMaterializationOperation: {
        operationKey,
        mode: "candidate-materialization",
        status: "pending",
        compensationStatus: "none",
        legacyUserId: 24,
        requestFingerprint,
        requestedAt: new Date(Date.now() - ORGANIZATION_CANDIDATE_MATERIALIZATION_PENDING_LEASE_MS - 1_000).toISOString()
      }
    });

    await expect(stale.service.materializeCandidate({
      legacyUserId: 24,
      expectedSnapshotFingerprint: requestFingerprint,
      idempotencyKey
    })).resolves.toMatchObject({ materialized: true, after: { aligned: true } });
    expect(stale.repository.reclaimStaleCandidateMaterialization).toHaveBeenCalledWith(expect.objectContaining({
      operationKey,
      expectedRequestFingerprint: requestFingerprint,
      requestFingerprint
    }));
    expect(stale.repository.beginCandidateMaterialization).not.toHaveBeenCalled();

    const fresh = createFixture({
      organizations,
      candidateMissing: true,
      initialMaterializationOperation: {
        operationKey,
        mode: "candidate-materialization",
        status: "pending",
        compensationStatus: "none",
        legacyUserId: 24,
        requestFingerprint,
        requestedAt: new Date().toISOString()
      }
    });
    await expect(fresh.service.materializeCandidate({
      legacyUserId: 24,
      expectedSnapshotFingerprint: requestFingerprint,
      idempotencyKey
    })).rejects.toMatchObject({
      response: { code: "IAM_ORGANIZATION_CANDIDATE_MATERIALIZATION_OPERATION_IN_PROGRESS" }
    });
    expect(fresh.repository.reclaimStaleCandidateMaterialization).toHaveBeenCalledTimes(1);
    expect(fresh.repository.replaceCandidate).not.toHaveBeenCalled();
  });

  it("reclaims a stale same-key pending lease from a newly reviewed current Legacy snapshot", async () => {
    enableCandidateMaterialization();
    const previousOrganizations = [organization(1, "previous", "Previous")];
    const currentOrganizations = [organization(2, "current", "Current")];
    const idempotencyKey = "candidate-materialize-stale-changed-24";
    const previousFingerprint = organizationCandidateSnapshotFingerprint(24, previousOrganizations);
    const currentFingerprint = organizationCandidateSnapshotFingerprint(24, currentOrganizations);
    const operationKey = organizationCandidateMaterializationOperationKey(24, idempotencyKey);
    const stale = createFixture({
      organizations: currentOrganizations,
      candidateMissing: true,
      initialMaterializationOperation: {
        operationKey,
        mode: "candidate-materialization",
        status: "pending",
        compensationStatus: "none",
        legacyUserId: 24,
        requestFingerprint: previousFingerprint,
        requestedAt: new Date(Date.now() - ORGANIZATION_CANDIDATE_MATERIALIZATION_PENDING_LEASE_MS - 1_000).toISOString()
      }
    });

    await expect(stale.service.materializeCandidate({
      legacyUserId: 24,
      expectedSnapshotFingerprint: currentFingerprint,
      idempotencyKey
    })).resolves.toMatchObject({ materialized: true, after: { aligned: true, mismatch: 0 } });
    expect(stale.repository.reclaimStaleCandidateMaterialization).toHaveBeenCalledWith(expect.objectContaining({
      operationKey,
      expectedRequestFingerprint: previousFingerprint,
      requestFingerprint: currentFingerprint,
      metadata: expect.objectContaining({
        recovery: "stale-pending-current-reviewed-legacy-snapshot",
        recoveryPreviousSnapshotFingerprintDigest: shortHash(previousFingerprint),
        recoverySnapshotFingerprintDigest: shortHash(currentFingerprint),
        source: "current-legacy-read"
      })
    }));
    expect(stale.repository.replaceCandidate).toHaveBeenCalledWith(expect.objectContaining({
      operationKey,
      organizations: currentOrganizations,
      materializationClaim: expect.objectContaining({ claimToken: expect.any(String) })
    }));

    const active = createFixture({
      organizations: currentOrganizations,
      candidateMissing: true,
      initialMaterializationOperation: {
        operationKey,
        mode: "candidate-materialization",
        status: "pending",
        compensationStatus: "none",
        legacyUserId: 24,
        requestFingerprint: previousFingerprint,
        requestedAt: new Date().toISOString()
      }
    });
    await expect(active.service.materializeCandidate({
      legacyUserId: 24,
      expectedSnapshotFingerprint: currentFingerprint,
      idempotencyKey
    })).rejects.toMatchObject({
      response: { code: "IAM_ORGANIZATION_CANDIDATE_MATERIALIZATION_OPERATION_IN_PROGRESS" }
    });
    expect(active.repository.reclaimStaleCandidateMaterialization).not.toHaveBeenCalled();
    expect(active.repository.replaceCandidate).not.toHaveBeenCalled();
  });

  it.each([
    ["legacy_completed", "none"],
    ["completed", "required"],
    ["completed", "failed"],
    ["pending", "required"],
    ["failed", "completed"]
  ])("fails closed for materialization ledger state %s/%s", async (status, compensationStatus) => {
    enableCandidateMaterialization();
    const organizations = [organization(1, "test", "Test")];
    const idempotencyKey = `invalid-ledger-${status}-${compensationStatus}`;
    const requestFingerprint = organizationCandidateSnapshotFingerprint(24, organizations);
    const fixture = createFixture({
      organizations,
      candidateMissing: true,
      initialMaterializationOperation: {
        operationKey: organizationCandidateMaterializationOperationKey(24, idempotencyKey),
        mode: "candidate-materialization",
        status,
        compensationStatus,
        legacyUserId: 24,
        requestFingerprint,
        requestedAt: new Date().toISOString()
      }
    });

    await expect(fixture.service.materializeCandidate({
      legacyUserId: 24,
      expectedSnapshotFingerprint: requestFingerprint,
      idempotencyKey
    })).rejects.toMatchObject({
      response: { code: "IAM_ORGANIZATION_CANDIDATE_MATERIALIZATION_LEDGER_STATE_INVALID" }
    });
    expect(fixture.repository.replaceCandidate).not.toHaveBeenCalled();
  });

  it("fails closed when the pending owner token loses the terminal ledger CAS", async () => {
    enableCandidateMaterialization();
    const organizations = [organization(1, "test", "Test")];
    const fixture = createFixture({ organizations, candidateMissing: true, terminalCasUpdated: false });

    await expect(fixture.service.materializeCandidate({
      legacyUserId: 24,
      expectedSnapshotFingerprint: organizationCandidateSnapshotFingerprint(24, organizations),
      idempotencyKey: "candidate-terminal-cas-lost"
    })).rejects.toMatchObject({
      response: { code: "IAM_ORGANIZATION_CANDIDATE_MATERIALIZATION_LEDGER_CAS_FAILED" }
    });
    expect(fixture.repository.finalizeCandidateMaterialization).toHaveBeenCalledTimes(2);
  });

  it.each([
    ["inactive", { status: 0 }, "IAM_ORGANIZATION_CANDIDATE_MATERIALIZATION_POSTCHECK_INACTIVE_SUBJECT"],
    ["protected", { roles: ["root"] }, "IAM_ORGANIZATION_CANDIDATE_MATERIALIZATION_POSTCHECK_PROTECTED_SUBJECT"],
    ["changed", { organizations: [organization(2, "changed", "Changed")] }, "IAM_ORGANIZATION_CANDIDATE_MATERIALIZATION_POSTCHECK_SNAPSHOT_CHANGED"],
    ["missing", null, "IAM_ORGANIZATION_CANDIDATE_MATERIALIZATION_POSTCHECK_LEGACY_USER_MISSING"]
  ])("records failed/required when fresh Legacy becomes %s after candidate write", async (_case, postcheckUser, code) => {
    enableCandidateMaterialization();
    const organizations = [organization(1, "test", "Test")];
    const fixture = createFixture({ organizations, candidateMissing: true, postcheckUser });

    await expect(fixture.service.materializeCandidate({
      legacyUserId: 24,
      expectedSnapshotFingerprint: organizationCandidateSnapshotFingerprint(24, organizations),
      idempotencyKey: `candidate-postcheck-${String(_case)}`
    })).rejects.toMatchObject({ response: { code } });
    expect(fixture.repository.finalizeCandidateMaterialization).toHaveBeenLastCalledWith(expect.objectContaining({
      status: "failed",
      identityStatus: "candidate-postcheck-failed",
      compensationStatus: "required"
    }));
  });

  it("recovers failed/required with the same key from a newly reviewed current Legacy snapshot", async () => {
    enableCandidateMaterialization();
    const original = [organization(1, "original", "Original")];
    const current = [organization(2, "current", "Current")];
    const idempotencyKey = "candidate-reviewed-recovery-24";
    const fixture = createFixture({
      organizations: original,
      candidateMissing: true,
      postcheckUser: { organizations: current }
    });

    await expect(fixture.service.materializeCandidate({
      legacyUserId: 24,
      expectedSnapshotFingerprint: organizationCandidateSnapshotFingerprint(24, original),
      idempotencyKey
    })).rejects.toMatchObject({
      response: { code: "IAM_ORGANIZATION_CANDIDATE_MATERIALIZATION_POSTCHECK_SNAPSHOT_CHANGED" }
    });
    await expect(fixture.service.materializeCandidate({
      legacyUserId: 24,
      expectedSnapshotFingerprint: organizationCandidateSnapshotFingerprint(24, current),
      idempotencyKey
    })).resolves.toMatchObject({
      materialized: true,
      after: { aligned: true, mismatch: 0 }
    });
    expect(fixture.repository.resumeCandidateMaterialization).toHaveBeenCalledWith(
      expect.any(String),
      organizationCandidateSnapshotFingerprint(24, original),
      organizationCandidateSnapshotFingerprint(24, current),
      expect.any(String),
      expect.objectContaining({
        recovery: "current-reviewed-legacy-snapshot",
        recoveryPreviousSnapshotFingerprintDigest: expect.any(String),
        recoverySnapshotFingerprintDigest: expect.any(String)
      })
    );
    expect(fixture.repository.replaceCandidate).toHaveBeenLastCalledWith(expect.objectContaining({
      organizations: [expect.objectContaining({ id: 2, name: "current" })]
    }));
  });

  it("does not read arbitrary subjects during preview and rejects disabled, mismatched, or inactive apply targets", async () => {
    enableCandidateMaterialization();
    const selected = createFixture({ candidateMissing: true });
    await expect(selected.service.previewCandidateMaterialization(25)).rejects.toMatchObject({
      response: { code: "IAM_ORGANIZATION_CANDIDATE_MATERIALIZATION_TARGET_MISMATCH" }
    });
    expect(selected.legacy.getUserById).not.toHaveBeenCalled();
    expect(selected.repository.candidateForLegacyUser).not.toHaveBeenCalled();

    const expectedSnapshotFingerprint = organizationCandidateSnapshotFingerprint(24, []);
    const inactive = createFixture({ candidateMissing: true, status: 0 });
    await expect(inactive.service.materializeCandidate({
      legacyUserId: 24,
      expectedSnapshotFingerprint,
      idempotencyKey: "candidate-inactive"
    })).rejects.toMatchObject({ response: { code: "IAM_ORGANIZATION_CANDIDATE_MATERIALIZATION_INACTIVE_SUBJECT" } });

    process.env.IDENTITY_IAM_ORG_WRITE_CANDIDATE_MATERIALIZATION_ENABLED = "false";
    const disabled = createFixture({ candidateMissing: true });
    await expect(disabled.service.materializeCandidate({
      legacyUserId: 24,
      expectedSnapshotFingerprint,
      idempotencyKey: "candidate-disabled"
    })).rejects.toMatchObject({ response: { code: "IAM_ORGANIZATION_CANDIDATE_MATERIALIZATION_DISABLED" } });
    expect(disabled.repository.candidateForLegacyUser).not.toHaveBeenCalled();
  });

  it("fails closed for unreviewed snapshots, unsafe posture, protected subjects, and unresolved operations", async () => {
    enableCandidateMaterialization();
    const organizations = [organization(1, "test", "Test")];
    const expectedSnapshotFingerprint = organizationCandidateSnapshotFingerprint(24, organizations);

    await expect(createFixture({ organizations, candidateMissing: true }).service.materializeCandidate({
      legacyUserId: 24,
      expectedSnapshotFingerprint: "a".repeat(64),
      idempotencyKey: "candidate-snapshot-changed"
    })).rejects.toMatchObject({ response: { code: "IAM_ORGANIZATION_CANDIDATE_MATERIALIZATION_SNAPSHOT_CHANGED" } });

    process.env.IDENTITY_IAM_ORG_WRITE_ROUTE_INTEGRATION_ENABLED = "true";
    await expect(createFixture({ organizations, candidateMissing: true }).service.materializeCandidate({
      legacyUserId: 24,
      expectedSnapshotFingerprint,
      idempotencyKey: "candidate-unsafe-posture"
    })).rejects.toMatchObject({ response: { code: "IAM_ORGANIZATION_CANDIDATE_MATERIALIZATION_UNSAFE_POSTURE" } });
    process.env.IDENTITY_IAM_ORG_WRITE_ROUTE_INTEGRATION_ENABLED = "false";

    process.env.IDENTITY_IAM_ROLE_WRITE_RECOVERY_DRILL_ENABLED = "true";
    await expect(createFixture({ organizations, candidateMissing: true }).service.materializeCandidate({
      legacyUserId: 24,
      expectedSnapshotFingerprint,
      idempotencyKey: "candidate-role-recovery-active"
    })).rejects.toMatchObject({
      response: {
        code: "IAM_ORGANIZATION_CANDIDATE_MATERIALIZATION_UNSAFE_POSTURE",
        blockedReasons: expect.arrayContaining(["role-recovery-drill-must-be-disabled"])
      }
    });
    process.env.IDENTITY_IAM_ROLE_WRITE_RECOVERY_DRILL_ENABLED = "false";

    await expect(createFixture({ organizations, candidateMissing: true, roles: ["root"] }).service.materializeCandidate({
      legacyUserId: 24,
      expectedSnapshotFingerprint,
      idempotencyKey: "candidate-root"
    })).rejects.toMatchObject({ response: { code: "IAM_ORGANIZATION_CANDIDATE_MATERIALIZATION_PROTECTED_SUBJECT" } });

    await expect(createFixture({ organizations, candidateMissing: true, unresolvedCount: 1 }).service.materializeCandidate({
      legacyUserId: 24,
      expectedSnapshotFingerprint,
      idempotencyKey: "candidate-unresolved"
    })).rejects.toMatchObject({ response: { code: "IAM_ORGANIZATION_CANDIDATE_MATERIALIZATION_UNRESOLVED_OPERATION" } });
  });

  it("recovers candidate state from a fresh Legacy read instead of replaying an old payload", async () => {
    enableDualWrite();
    const fixture = createFixture({
      organizations: [organization(3, "current-campus", "Current Campus")],
      existingCompensationStatus: "required"
    });

    await expect(fixture.service.retryIdentityCandidate("operation-1")).resolves.toMatchObject({
      recovered: true,
      source: "current-legacy-read"
    });
    expect(fixture.repository.replaceCandidate).toHaveBeenCalledWith(expect.objectContaining({
      operationKey: "operation-1",
      organizations: [expect.objectContaining({ id: 3 })]
    }));
    expect(fixture.repository.update).toHaveBeenLastCalledWith(expect.objectContaining({
      compensationStatus: "completed",
      identityStatus: "candidate-recovered-from-current-legacy"
    }));
  });

  it("redacts nested secrets at the organization operation repository boundary", () => {
    expect(redactOrganizationWriteMetadata({
      safe: "kept",
      nested: { authorization: "Bearer secret", requestBody: { password: "secret" }, count: 2 },
      cookie: "session=secret"
    })).toEqual({
      safe: "kept",
      nested: { authorization: "[redacted]", requestBody: "[redacted]", count: 2 },
      cookie: "[redacted]"
    });
  });

  it("returns strict string-or-null operation statuses from the safe recent ledger view", async () => {
    const completedOperationKey = "candidate-materialization-completed";
    const failedOperationKey = "candidate-materialization-failed";
    const query = vi.fn(async (_sql: string, _params?: unknown[]) => [[
      {
        operationKey: completedOperationKey,
        idempotencyKeyDigest: "a".repeat(64),
        requestFingerprint: "c".repeat(64),
        legacyUserId: 581,
        mode: "candidate-materialization",
        status: "completed",
        legacyStatus: "read-only",
        identityStatus: "candidate-materialized",
        compensationStatus: "none",
        errorCode: null,
        requestedAt: "2026-08-09T01:00:00.000Z",
        completedAt: "2026-08-09T01:00:01.000Z",
        metadata: JSON.stringify({ source: "test", token: "must-redact" })
      },
      {
        operationKey: failedOperationKey,
        idempotencyKeyDigest: "b".repeat(64),
        requestFingerprint: "d".repeat(64),
        legacyUserId: 581,
        mode: "candidate-materialization",
        status: "failed",
        legacyStatus: "read-only",
        identityStatus: "candidate-write-outcome-unknown",
        compensationStatus: "required",
        errorCode: "ServiceUnavailableException",
        requestedAt: "2026-08-09T01:01:00.000Z",
        completedAt: "2026-08-09T01:01:01.000Z",
        metadata: { source: "test" }
      }
    ]]);
    const repository = repositoryWithQuery(query);

    await expect(repository.listRecentSafe(60, 50)).resolves.toEqual([
      {
        operationKeyDigest: createHash("sha256").update(completedOperationKey).digest("hex"),
        idempotencyKeyDigest: "a".repeat(64),
        requestFingerprintDigest: createHash("sha256").update("c".repeat(64)).digest("hex"),
        legacyUserId: 581,
        mode: "candidate-materialization",
        status: "completed",
        legacyStatus: "read-only",
        identityStatus: "candidate-materialized",
        compensationStatus: "none",
        errorCode: null,
        requestedAt: "2026-08-09T01:00:00.000Z",
        completedAt: "2026-08-09T01:00:01.000Z",
        metadata: { source: "test", token: "[redacted]" }
      },
      {
        operationKeyDigest: createHash("sha256").update(failedOperationKey).digest("hex"),
        idempotencyKeyDigest: "b".repeat(64),
        requestFingerprintDigest: createHash("sha256").update("d".repeat(64)).digest("hex"),
        legacyUserId: 581,
        mode: "candidate-materialization",
        status: "failed",
        legacyStatus: "read-only",
        identityStatus: "candidate-write-outcome-unknown",
        compensationStatus: "required",
        errorCode: "ServiceUnavailableException",
        requestedAt: "2026-08-09T01:01:00.000Z",
        completedAt: "2026-08-09T01:01:01.000Z",
        metadata: { source: "test" }
      }
    ]);
    expect(query.mock.calls[0]?.[0]).toContain("legacy_status AS legacyStatus");
    expect(query.mock.calls[0]?.[0]).toContain("request_fingerprint AS requestFingerprint");
    expect(query.mock.calls[0]?.[0]).toContain("identity_status AS identityStatus");
    expect(query.mock.calls[0]?.[0]).toContain("error_code AS errorCode");
  });

  it.each([
    ["legacyStatus", 200],
    ["identityStatus", { unsafe: true }],
    ["errorCode", undefined]
  ])("fails closed when safe recent ledger %s is neither a string nor null", async (field, invalidValue) => {
    const row: Record<string, unknown> = {
      operationKey: "candidate-materialization-invalid-status",
      idempotencyKeyDigest: "a".repeat(64),
      requestFingerprint: "b".repeat(64),
      legacyUserId: 581,
      mode: "candidate-materialization",
      status: "failed",
      legacyStatus: "read-only",
      identityStatus: "candidate-write-outcome-unknown",
      compensationStatus: "required",
      errorCode: "ServiceUnavailableException",
      requestedAt: "2026-08-09T01:01:00.000Z",
      completedAt: "2026-08-09T01:01:01.000Z",
      metadata: {}
    };
    row[field] = invalidValue;

    await expect(repositoryWithQuery(vi.fn(async () => [[row]])).listRecentSafe(60, 50))
      .rejects.toThrow(`Invalid organization write operation ${field}: expected string or null`);
  });

  it("fails closed for unknown ledger mode, status, or compensation values", () => {
    expect(() => organizationWriteOperationMode("future-mode")).toThrow("Unknown organization write operation mode");
    expect(() => organizationWriteOperationStatus("future-status")).toThrow("Unknown organization write operation status");
    expect(() => organizationWriteCompensationStatus(null)).toThrow("Unknown organization write compensation status");
  });
});

function createFixture(input: {
  organizations?: LegacyOrganization[];
  candidateOrganizations?: LegacyOrganization[];
  duplicate?: boolean;
  existingFingerprint?: string;
  existingCompensationStatus?: "none" | "required" | "completed" | "failed";
  candidateMissing?: boolean;
  replaceCandidateFailures?: number;
  replaceCandidateCommitsThenFailures?: number;
  postcheckMismatchOnce?: boolean;
  materializationBeginRace?: boolean;
  materializationBeginRaceCompleted?: boolean;
  resumeClaimed?: boolean;
  reclaimClaimed?: boolean;
  schemaReady?: boolean;
  schemaReadinessThrows?: boolean;
  lockAcquired?: boolean;
  terminalCasUpdated?: boolean;
  initialMaterializationOperation?: Record<string, any>;
  postcheckUser?: Partial<LegacyUserReadModel> | null;
  replaceCandidateGate?: Promise<void>;
  recentOperations?: Record<string, unknown>[];
  unresolvedCount?: number;
  pluginResponse?: { status: number; body: unknown };
  pluginMode?: "legacy-proxy" | "dual-write";
  username?: string;
  roles?: string[];
  status?: number;
} = {}) {
  const organizations = input.organizations ?? [];
  const pluginMode = input.pluginMode ?? "legacy-proxy";
  const plugin = {
    readiness: vi.fn(() => ({
      enabled: true,
      mode: pluginMode,
      legacyProxyConfigured: true,
      dualWriteSupported: pluginMode === "dual-write"
    })),
    proxy: vi.fn(async () => ({
      status: input.pluginResponse?.status ?? 200,
      body: input.pluginResponse?.body ?? { code: 0, data: { id: 24, organizations } },
      mode: pluginMode
    }))
  };
  let candidateState = input.candidateMissing
    ? null
    : { legacyUserId: 24, organizations: input.candidateOrganizations ?? organizations };
  let materializationOperation: Record<string, any> | null = input.initialMaterializationOperation
    ? { ...input.initialMaterializationOperation }
    : null;
  let remainingCandidateFailures = input.replaceCandidateFailures ?? 0;
  let remainingCandidateCommitAckFailures = input.replaceCandidateCommitsThenFailures ?? 0;
  let postcheckMismatchRemaining = input.postcheckMismatchOnce ?? false;
  let subjectLocked = false;
  const repository = {
    isConfigured: vi.fn(() => true),
    materializationSchemaReadiness: vi.fn(async () => {
      if (input.schemaReadinessThrows) throw new Error("schema probe unavailable");
      const ready = input.schemaReady ?? true;
      return {
        ready,
        requiredTableCount: 5,
        existingTableCount: ready ? 5 : 4,
        missingTables: ready ? [] : ["identity_organization_write_operations"]
      };
    }),
    withCandidateMaterializationSubjectLock: vi.fn(async (_legacyUserId: number, callback: () => Promise<unknown>) => {
      if (input.lockAcquired === false || subjectLocked) return { acquired: false as const };
      subjectLocked = true;
      try {
        return { acquired: true as const, value: await callback() };
      } finally {
        subjectLocked = false;
      }
    }),
    begin: vi.fn(async () => ({ duplicate: input.duplicate ?? false })),
    beginCandidateMaterialization: vi.fn(async (operation: Record<string, any>) => {
      if (materializationOperation) return { duplicate: true };
      materializationOperation = {
        ...operation,
        mode: "candidate-materialization",
        status: "pending",
        compensationStatus: "none",
        requestedAt: new Date().toISOString()
      };
      if (input.materializationBeginRaceCompleted) {
        materializationOperation.status = "completed";
        candidateState = { legacyUserId: 24, organizations };
      }
      return { duplicate: input.materializationBeginRaceCompleted || (input.materializationBeginRace ?? false) };
    }),
    resumeCandidateMaterialization: vi.fn(async (
      _operationKey: string,
      _expectedRequestFingerprint: string,
      requestFingerprint: string,
      _claimToken: string,
      metadata: Record<string, unknown>
    ) => {
      if (input.resumeClaimed === false || materializationOperation?.status !== "failed") {
        return { claimed: false };
      }
      if (materializationOperation) {
        materializationOperation = {
          ...materializationOperation,
          status: "pending",
          requestFingerprint,
          compensationStatus: "none",
          requestedAt: new Date().toISOString(),
          metadata
        };
      }
      return { claimed: true };
    }),
    reclaimStaleCandidateMaterialization: vi.fn(async (claim: Record<string, any>) => {
      const requestedAt = Date.parse(String(materializationOperation?.requestedAt ?? ""));
      if (
        input.reclaimClaimed === false ||
        materializationOperation?.status !== "pending" ||
        materializationOperation?.requestFingerprint !== claim.expectedRequestFingerprint ||
        !Number.isFinite(requestedAt) ||
        requestedAt > (claim.staleBefore as Date).getTime()
      ) return { claimed: false };
      materializationOperation = {
        ...materializationOperation,
        status: "pending",
        requestFingerprint: claim.requestFingerprint,
        compensationStatus: "none",
        requestedAt: new Date().toISOString(),
        metadata: claim.metadata
      };
      return { claimed: true };
    }),
    finalizeCandidateMaterialization: vi.fn(async (operation: Record<string, any>) => {
      if (input.terminalCasUpdated === false || materializationOperation?.status !== "pending") {
        return { updated: false };
      }
      materializationOperation = { ...materializationOperation, ...operation };
      return { updated: true };
    }),
    find: vi.fn(async (operationKey: string) => operationKey.startsWith("iam-organization-write:v1:candidate-materialization:")
      ? materializationOperation
      : {
          operationKey: "operation-1",
          mode: "dual-write",
          status: "legacy_completed",
          requestFingerprint: input.existingFingerprint ?? "unused",
          legacyUserId: 24,
          compensationStatus: input.existingCompensationStatus ?? "none"
        }),
    update: vi.fn(async (operation: Record<string, any>) => {
      if (operation.operationKey?.startsWith("iam-organization-write:v1:candidate-materialization:") && materializationOperation) {
        materializationOperation = { ...materializationOperation, ...operation };
      }
    }),
    replaceCandidate: vi.fn(async (snapshot: { legacyUserId: number; organizations: LegacyOrganization[] }) => {
      await input.replaceCandidateGate;
      if (remainingCandidateCommitAckFailures > 0) {
        remainingCandidateCommitAckFailures -= 1;
        candidateState = { legacyUserId: snapshot.legacyUserId, organizations: snapshot.organizations };
        throw new Error("candidate write acknowledgement lost");
      }
      if (remainingCandidateFailures > 0) {
        remainingCandidateFailures -= 1;
        throw new Error("candidate write failed");
      }
      if (postcheckMismatchRemaining) {
        postcheckMismatchRemaining = false;
        candidateState = { legacyUserId: snapshot.legacyUserId, organizations: [] };
      } else {
        candidateState = { legacyUserId: snapshot.legacyUserId, organizations: snapshot.organizations };
      }
    }),
    candidateForLegacyUser: vi.fn(async () => candidateState),
    countUnresolvedForLegacyUser: vi.fn(async () => input.unresolvedCount ?? 0),
    summarizeRecent: vi.fn(async () => []),
    listRecentSafe: vi.fn(async () => input.recentOperations ?? [])
  };
  const legacyUser: LegacyUserReadModel = {
    id: 24,
    username: input.username ?? "test-user",
    email: null,
    status: input.status ?? 10,
    nickname: null,
    emailVerifiedAt: null,
    createdAt: null,
    updatedAt: null,
    userInfo: {},
    roles: input.roles ?? [],
    organizations,
    source: "legacy"
  };
  let legacyReadCount = 0;
  const legacy = { getUserById: vi.fn(async () => {
    legacyReadCount += 1;
    if (legacyReadCount > 1 && Object.prototype.hasOwnProperty.call(input, "postcheckUser")) {
      return input.postcheckUser === null ? null : { ...legacyUser, ...input.postcheckUser };
    }
    return legacyUser;
  }) };
  const jwt = { verifyAccessToken: vi.fn(() => { throw new Error("not a test token"); }) };
  const service = new IamOrganizationWriteService(plugin as never, repository as never, legacy as never, jwt as never);
  return { service, plugin, repository, legacy, legacyUser };
}

function repositoryWithQuery(query: ReturnType<typeof vi.fn>): IamOrganizationWriteRepository {
  const repository = Object.create(IamOrganizationWriteRepository.prototype) as IamOrganizationWriteRepository;
  Object.defineProperty(repository, "pool", { value: { query } });
  return repository;
}

function updateRequest(organizationIds: number[] | undefined, idempotencyKey?: string) {
  return {
    method: "POST",
    headers: idempotencyKey ? { "idempotency-key": idempotencyKey, authorization: "Bearer redacted-test-token" } : {},
    body: organizationIds === undefined ? { id: 24, nickname: "preserve" } : { id: 24, organization_ids: organizationIds }
  };
}

function organization(id: number, name: string, title: string): LegacyOrganization {
  return { id, name, title, createdAt: 1, updatedAt: 2 };
}

function operationDigest(legacyUserId: number, idempotencyKey: string): string {
  return createHash("sha256")
    .update(organizationCandidateMaterializationOperationKey(legacyUserId, idempotencyKey))
    .digest("hex")
    .slice(0, 16);
}

function shortHash(value: string): string {
  return createHash("sha256").update(value).digest("hex").slice(0, 16);
}

function enableLegacyProxy(): void {
  process.env.IDENTITY_IAM_ORG_WRITE_MODE = "legacy-proxy";
  process.env.IDENTITY_IAM_ORG_WRITE_ROUTE_INTEGRATION_ENABLED = "true";
  process.env.IDENTITY_IAM_ORG_WRITE_ROLLOUT_MODE = "allowlist";
  process.env.IDENTITY_IAM_ORG_WRITE_ROLLOUT_ALLOWLIST = "legacy:24";
}

function enableDualWrite(): void {
  process.env.IDENTITY_IAM_ORG_WRITE_MODE = "dual-write";
  process.env.IDENTITY_IAM_ORG_WRITE_ROUTE_INTEGRATION_ENABLED = "true";
  process.env.IDENTITY_IAM_ORG_WRITE_DUAL_WRITE_EXECUTION_ENABLED = "true";
  process.env.IDENTITY_IAM_ORG_WRITE_ROLLOUT_MODE = "full";
}

function enableCandidateMaterialization(): void {
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
  process.env.IDENTITY_IAM_ORG_WRITE_CANDIDATE_MATERIALIZATION_ENABLED = "true";
  process.env.IDENTITY_IAM_ORG_WRITE_CANDIDATE_MATERIALIZATION_TARGET_LEGACY_USER_ID = "24";
  process.env.IDENTITY_IAM_ROLE_WRITE_MODE = "disabled";
  process.env.IDENTITY_IAM_ROLE_WRITE_DUAL_WRITE_EXECUTION_ENABLED = "false";
  process.env.IDENTITY_IAM_ROLE_WRITE_IDENTITY_NATIVE_EXECUTION_ENABLED = "false";
  process.env.IDENTITY_IAM_ROLE_WRITE_IDENTITY_NATIVE_TARGET_MODE = "single-target";
  process.env.IDENTITY_IAM_ROLE_WRITE_ROLLOUT_MODE = "off";
  process.env.IDENTITY_IAM_ROLE_WRITE_ROLLOUT_ALLOWLIST = "";
  process.env.IDENTITY_IAM_ROLE_WRITE_ROLLOUT_PERCENTAGE = "0";
  process.env.IDENTITY_IAM_ROLE_WRITE_POLICY_CHECKSUM = "";
  process.env.IDENTITY_IAM_ROLE_WRITE_CANDIDATE_RESTORE_ENABLED = "false";
  process.env.IDENTITY_IAM_ROLE_WRITE_CANDIDATE_RESTORE_TARGET_LEGACY_USER_ID = "0";
  process.env.IDENTITY_IAM_ROLE_WRITE_RECOVERY_DRILL_ENABLED = "false";
  process.env.IDENTITY_IAM_ROLE_WRITE_RECOVERY_DRILL_TARGET_LEGACY_USER_ID = "0";
  process.env.IDENTITY_IAM_ROLE_WRITE_IDENTITY_NATIVE_TARGET_LEGACY_USER_ID = "0";
  process.env.IDENTITY_IAM_ROLE_WRITE_IDENTITY_NATIVE_TARGET_ALLOWLIST = "";
  process.env.IDENTITY_IAM_AUTHZ_READ_MODE = "legacy";
  process.env.IDENTITY_IAM_AUTHZ_ROLLOUT_MODE = "off";
  process.env.IDENTITY_IAM_AUTHZ_ROLLOUT_ALLOWLIST = "";
  process.env.IDENTITY_IAM_AUTHZ_RETAINED_LEGACY_ALLOWLIST = "";
  process.env.IDENTITY_IAM_AUTHZ_ROLLOUT_PERCENTAGE = "0";
  process.env.IDENTITY_IAM_AUTHZ_FALLBACK_ENABLED = "true";
}
