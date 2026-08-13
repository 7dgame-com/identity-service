import { createHash } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { IamOrganizationWriteService } from "../src/iam-organization-write.service.js";
import {
  organizationWriteOperationKey,
  organizationWriteRequestFingerprint
} from "../src/iam-organization-write.repository.js";
import {
  identityNativeOrganizationWriteTargetDecision,
  identityNativeOrganizationWriteTargetScope
} from "../src/iam-organization-write-target-control.js";
import type { LegacyOrganization } from "../src/legacy-identity.reader.js";

const originalEnv = { ...process.env };

describe("IAM organization identity-native membership replacement", () => {
  beforeEach(() => {
    process.env = { ...originalEnv };
    process.env.IDENTITY_IAM_ORG_WRITE_MODE = "identity-native";
    process.env.IDENTITY_IAM_ORG_WRITE_ROUTE_INTEGRATION_ENABLED = "true";
    process.env.IDENTITY_IAM_ORG_WRITE_IDENTITY_NATIVE_EXECUTION_ENABLED = "true";
    process.env.IDENTITY_IAM_ORG_WRITE_ROLLOUT_MODE = "allowlist";
    process.env.IDENTITY_IAM_ORG_WRITE_ROLLOUT_ALLOWLIST = "legacy:24";
    process.env.IDENTITY_IAM_ORG_WRITE_ROLLOUT_PERCENTAGE = "0";
    process.env.IDENTITY_BUILD_REVISION = "a".repeat(40);
  });

  afterEach(() => {
    process.env = { ...originalEnv };
  });

  it("keeps Identity-native execution default-off and reports the exact missing gate", async () => {
    delete process.env.IDENTITY_IAM_ORG_WRITE_IDENTITY_NATIVE_EXECUTION_ENABLED;
    const fixture = createFixture();

    await expect(fixture.service.readiness()).resolves.toMatchObject({
      sourceOfTruth: "identity-candidate-selected-legacy-unselected",
      identityNativeExecutionEnabled: false,
      identityNativeSupported: false,
      identityNativeGate: {
        executable: false,
        missingCapabilities: ["identity-native-execution-flag"]
      }
    });
    await expect(fixture.service.proxyMembershipUpdate(request([2], "native-disabled")))
      .rejects.toMatchObject({ response: { code: "IAM_ORGANIZATION_WRITE_IDENTITY_NATIVE_NOT_READY" } });
    expect(fixture.repository.begin).not.toHaveBeenCalled();
    expect(fixture.plugin.proxy).not.toHaveBeenCalled();
  });

  it("requires the reviewed full build revision before any Identity-native repository read", async () => {
    const missing = createFixture();
    const missingRequest = request([2], "native-revision-missing");
    missingRequest.headers["x-identity-expected-revision"] = undefined;
    await expect(missing.service.proxyMembershipUpdate(missingRequest))
      .rejects.toMatchObject({ response: { code: "IDENTITY_EXPECTED_BUILD_REVISION_INVALID" } });
    expect(missing.repository.materializationSchemaReadiness).not.toHaveBeenCalled();
    expect(missing.repository.begin).not.toHaveBeenCalled();
    expect(missing.repository.candidateForLegacyUser).not.toHaveBeenCalled();

    const mismatch = createFixture();
    const mismatchRequest = request([2], "native-revision-mismatch");
    mismatchRequest.headers["x-identity-expected-revision"] = "b".repeat(40);
    await expect(mismatch.service.proxyMembershipUpdate(mismatchRequest))
      .rejects.toMatchObject({ response: { code: "IDENTITY_BUILD_REVISION_MISMATCH" } });
    expect(mismatch.repository.materializationSchemaReadiness).not.toHaveBeenCalled();
    expect(mismatch.repository.begin).not.toHaveBeenCalled();
    expect(mismatch.repository.candidateForLegacyUser).not.toHaveBeenCalled();
  });

  it("writes only the selected Identity candidate, preserves Legacy, and returns the compatible legacy-id response", async () => {
    const fixture = createFixture();

    const response = await fixture.service.proxyMembershipUpdate(request([2, 2], "native-success"));

    expect(response).toMatchObject({
      status: 200,
      mode: "identity-native",
      body: {
        code: 0,
        data: {
          id: 24,
          username: "candidate-user",
          status: 10,
          organizations: [{ id: 2, name: "two", title: "Two" }]
        }
      },
      evidence: { identityStatus: "completed" }
    });
    expect(fixture.plugin.proxy).not.toHaveBeenCalled();
    expect(fixture.legacy.getUserById).not.toHaveBeenCalled();
    expect(fixture.legacy.listUserPermissions).toHaveBeenCalledWith(9);
    expect(fixture.repository.replaceCandidate).toHaveBeenCalledTimes(1);
    expect(fixture.repository.update).toHaveBeenLastCalledWith(expect.objectContaining({
      status: "completed",
      legacyStatus: "not-called",
      identityStatus: "completed",
      compensationStatus: "none"
    }));
  });

  it("supports exact add and remove-all replacement semantics in Identity without Legacy writes", async () => {
    const add = createFixture();
    await expect(add.service.proxyMembershipUpdate(request([1, 2], "native-add"))).resolves.toMatchObject({
      body: { data: { organizations: [{ id: 1 }, { id: 2 }] } }
    });
    expect(add.candidate()?.map(({ id }) => id)).toEqual([1, 2]);
    expect(add.plugin.proxy).not.toHaveBeenCalled();

    const removeAll = createFixture();
    await expect(removeAll.service.proxyMembershipUpdate(request([], "native-remove-all"))).resolves.toMatchObject({
      body: { data: { organizations: [] } }
    });
    expect(removeAll.candidate()).toEqual([]);
    expect(removeAll.plugin.proxy).not.toHaveBeenCalled();
  });

  it("leaves an unowned target on the existing Legacy owner path", async () => {
    const fixture = createFixture({ targetLegacyUserId: 25 });

    await expect(fixture.service.proxyMembershipUpdate(request([2], "native-unowned", 25))).resolves.toBeNull();
    expect(fixture.repository.begin).not.toHaveBeenCalled();
    expect(fixture.legacy.listUserPermissions).not.toHaveBeenCalled();
    expect(fixture.plugin.proxy).not.toHaveBeenCalled();
  });

  it("requires verified root and the live Yii update-user permission before candidate reads or writes", async () => {
    const nonRoot = createFixture({ actorRoles: ["admin"] });
    await expect(nonRoot.service.proxyMembershipUpdate(request([2], "native-non-root")))
      .rejects.toMatchObject({ response: { code: "IAM_ORGANIZATION_WRITE_OPERATOR_FORBIDDEN" } });
    expect(nonRoot.repository.candidateForLegacyUser).not.toHaveBeenCalled();

    const noPermission = createFixture({ permissionNames: [] });
    await expect(noPermission.service.proxyMembershipUpdate(request([2], "native-no-permission")))
      .rejects.toMatchObject({ response: { code: "IAM_ORGANIZATION_WRITE_OPERATOR_FORBIDDEN" } });
    expect(noPermission.repository.candidateForLegacyUser).not.toHaveBeenCalled();
  });

  it("rejects protected, inactive, missing-candidate, and unknown-organization targets without Legacy writes", async () => {
    await expect(createFixture({ targetUsername: "root" }).service.proxyMembershipUpdate(request([2], "native-root")))
      .rejects.toMatchObject({ response: { code: "IAM_ORGANIZATION_WRITE_PROTECTED_SUBJECT" } });
    await expect(createFixture({ targetStatus: "inactive" }).service.proxyMembershipUpdate(request([2], "native-inactive")))
      .rejects.toMatchObject({ response: { code: "IAM_ORGANIZATION_WRITE_INACTIVE_SUBJECT" } });
    await expect(createFixture({ candidateMissing: true }).service.proxyMembershipUpdate(request([2], "native-missing")))
      .rejects.toMatchObject({ response: { code: "IAM_ORGANIZATION_WRITE_IDENTITY_CANDIDATE_MISSING" } });
    const unknown = createFixture();
    await expect(unknown.service.proxyMembershipUpdate(request([999], "native-unknown")))
      .rejects.toMatchObject({ response: { code: "IAM_ORGANIZATION_WRITE_UNKNOWN_ORGANIZATION" } });
    expect(unknown.plugin.proxy).not.toHaveBeenCalled();
    expect(unknown.repository.begin).not.toHaveBeenCalled();
  });

  it("rejects mixed profile updates and descriptor tricks instead of returning partial false success", async () => {
    const mixed = createFixture();
    await expect(mixed.service.proxyMembershipUpdate({
      method: "POST",
      headers: request([2], "native-mixed").headers,
      body: { id: 24, organization_ids: [2], nickname: "must-not-be-ignored" }
    })).rejects.toMatchObject({ response: { code: "IAM_ORGANIZATION_WRITE_MIXED_UPDATE_UNSUPPORTED" } });
    expect(mixed.repository.begin).not.toHaveBeenCalled();

    let getterReads = 0;
    const body = Object.defineProperty({ id: 24 }, "organization_ids", {
      enumerable: true,
      get() { getterReads += 1; return [2]; }
    });
    const descriptor = createFixture();
    await expect(descriptor.service.proxyMembershipUpdate({
      method: "POST",
      headers: request([2], "native-getter").headers,
      body
    })).rejects.toMatchObject({ response: { code: "IAM_ORGANIZATION_WRITE_INPUT_INVALID" } });
    expect(getterReads).toBe(0);
    expect(descriptor.repository.begin).not.toHaveBeenCalled();

    const stringId = createFixture();
    await expect(stringId.service.proxyMembershipUpdate({
      method: "POST",
      headers: request([2], "native-string-id").headers,
      body: { id: 24, organization_ids: ["2"] }
    })).rejects.toMatchObject({ response: { code: "IAM_ORGANIZATION_WRITE_INPUT_INVALID" } });
    expect(stringId.repository.begin).not.toHaveBeenCalled();
  });

  it("replays a completed exact request without a second write and rejects idempotency reuse after state drift", async () => {
    const fixture = createFixture();
    const first = await fixture.service.proxyMembershipUpdate(request([2], "native-replay"));
    const replay = await fixture.service.proxyMembershipUpdate(request([2], "native-replay"));

    expect(first?.mode).toBe("identity-native");
    expect(replay).toMatchObject({
      status: first?.status,
      mode: first?.mode,
      body: first?.body,
      evidence: {
        decision: first?.evidence.decision,
        actorFingerprint: first?.evidence.actorFingerprint,
        targetFingerprint: first?.evidence.targetFingerprint,
        matchedSelectorKind: first?.evidence.matchedSelectorKind,
        identityStatus: first?.evidence.identityStatus
      }
    });
    expect(fixture.repository.replaceCandidate).toHaveBeenCalledTimes(1);

    await expect(fixture.service.proxyMembershipUpdate(request([1], "native-replay")))
      .rejects.toMatchObject({ response: { code: "IDEMPOTENCY_KEY_REUSED_WITH_DIFFERENT_REQUEST" } });
    expect(fixture.repository.replaceCandidate).toHaveBeenCalledTimes(1);
  });

  it("restores the exact before snapshot when the postcheck fails and records recovery state", async () => {
    const fixture = createFixture({ postcheckMismatchOnce: true });

    await expect(fixture.service.proxyMembershipUpdate(request([2], "native-postcheck")))
      .rejects.toThrow("IdentityOrganizationPostcheckMismatch");
    expect(fixture.repository.replaceCandidate).toHaveBeenCalledTimes(2);
    expect(fixture.candidate()).toEqual([organization(1, "one", "One")]);
    expect(fixture.repository.update).toHaveBeenLastCalledWith(expect.objectContaining({
      status: "failed",
      legacyStatus: "not-called",
      identityStatus: "failed-restored-before-snapshot",
      compensationStatus: "completed"
    }));
    expect(fixture.plugin.proxy).not.toHaveBeenCalled();
  });

  it("detects a committed candidate after acknowledgement loss and restores the before snapshot", async () => {
    const fixture = createFixture({ commitThenThrowOnce: true });

    await expect(fixture.service.proxyMembershipUpdate(request([2], "native-ack-lost")))
      .rejects.toThrow("candidate acknowledgement lost");
    expect(fixture.repository.replaceCandidate).toHaveBeenCalledTimes(2);
    expect(fixture.candidate()).toEqual([organization(1, "one", "One")]);
    expect(fixture.repository.update).toHaveBeenLastCalledWith(expect.objectContaining({
      identityStatus: "failed-restored-before-snapshot",
      compensationStatus: "completed"
    }));
  });

  it("captures the recovery snapshot only after acquiring the subject lock", async () => {
    const queuedState = [organization(2, "two", "Two")];
    const fixture = createFixture({
      candidateAtLockAcquisition: queuedState,
      postcheckMismatchOnce: true
    });

    await expect(fixture.service.proxyMembershipUpdate(request([1], "native-queued-state")))
      .rejects.toThrow("IdentityOrganizationPostcheckMismatch");
    expect(fixture.candidate()).toEqual(queuedState);
    expect(fixture.repository.replaceCandidate).toHaveBeenCalledTimes(2);
  });

  it("pins allowlist and percentage ownership to the target, not the operator", () => {
    const allowlistConfig = {
      organizationWriteRolloutMode: "allowlist" as const,
      organizationWriteRolloutAllowlist: "legacy:24,25",
      organizationWriteRolloutPercentage: 0
    };
    expect(identityNativeOrganizationWriteTargetScope(allowlistConfig)).toEqual({
      configured: true,
      missingCapabilities: [],
      targetCount: 2
    });
    expect(identityNativeOrganizationWriteTargetDecision(allowlistConfig, 24)).toMatchObject({
      owned: true,
      reason: "target_allowlist_owned"
    });
    expect(identityNativeOrganizationWriteTargetDecision(allowlistConfig, 26)).toMatchObject({
      owned: false,
      reason: "target_not_owned"
    });
    const percentage = {
      organizationWriteRolloutMode: "percentage" as const,
      organizationWriteRolloutAllowlist: "",
      organizationWriteRolloutPercentage: 25
    };
    const decision = identityNativeOrganizationWriteTargetDecision(percentage, 24);
    const expectedBucket = Number.parseInt(createHash("sha256").update("legacy:24").digest("hex").slice(0, 8), 16) % 100;
    expect(decision).toMatchObject({ bucket: expectedBucket, owned: expectedBucket < 25, selectorKind: "percentage" });
  });

  it("uses the same target-owned selector and native readiness gate for the runtime preview", async () => {
    const fixture = createFixture();
    await expect(fixture.service.previewMembershipRollout(24)).resolves.toMatchObject({
      mutation: false,
      mode: "identity-native",
      selected: true,
      executable: true,
      decision: "selected:allowlist",
      matchedSelectorKind: "allowlist",
      sourceOfTruth: "identity-candidate-selected-legacy-unselected",
      identityNativeSupported: true,
      blockedReasons: []
    });
    await expect(fixture.service.previewMembershipRollout(25)).resolves.toMatchObject({
      selected: false,
      executable: false,
      decision: "not-selected:target_not_owned",
      matchedSelectorKind: null,
      blockedReasons: ["target-not-selected"]
    });
  });

  it("previews the exact desired snapshot from the Identity organization catalog without exposing catalog rows", async () => {
    const fixture = createFixture();
    const preview = await fixture.service.previewIdentityNativeDesiredSnapshot(24, [2, 2]);
    expect(preview).toEqual({
      mutation: false,
      sourceOfTruth: "identity-candidate-catalog",
      legacyUserIdFingerprint: expect.stringMatching(/^[a-f0-9]{16}$/),
      organizationCount: 1,
      snapshotFingerprint: expect.stringMatching(/^[a-f0-9]{64}$/)
    });
    expect(preview).not.toHaveProperty("organizationIds");
    await expect(fixture.service.previewIdentityNativeDesiredSnapshot(24, [999]))
      .rejects.toMatchObject({ response: { code: "IAM_ORGANIZATION_WRITE_UNKNOWN_ORGANIZATION" } });
  });
});

function createFixture(input: {
  targetLegacyUserId?: number;
  actorRoles?: string[];
  permissionNames?: string[];
  targetUsername?: string | null;
  targetStatus?: string;
  candidateMissing?: boolean;
  postcheckMismatchOnce?: boolean;
  commitThenThrowOnce?: boolean;
  candidateAtLockAcquisition?: LegacyOrganization[];
} = {}) {
  const baseline = [organization(1, "one", "One")];
  const catalog = [baseline[0]!, organization(2, "two", "Two")];
  let candidateState: LegacyOrganization[] | null = input.candidateMissing ? null : baseline.map(copyOrganization);
  let postcheckMismatch = input.postcheckMismatchOnce ?? false;
  let commitThenThrow = input.commitThenThrowOnce ?? false;
  let ledger: Record<string, unknown> | null = null;
  const repository = {
    isConfigured: vi.fn(() => true),
    materializationSchemaReadiness: vi.fn(async () => ({
      ready: true,
      requiredTableCount: 5,
      existingTableCount: 5,
      missingTables: []
    })),
    withCandidateMaterializationSubjectLock: vi.fn(async (_id: number, callback: () => Promise<unknown>) => {
      if (input.candidateAtLockAcquisition) {
        candidateState = input.candidateAtLockAcquisition.map(copyOrganization);
      }
      return { acquired: true as const, value: await callback() };
    }),
    candidateForLegacyUser: vi.fn(async () => candidateState === null
      ? null
      : { legacyUserId: 24, organizations: candidateState.map(copyOrganization) }),
    candidateOrganizationsByLegacyIds: vi.fn(async (ids: number[]) => catalog.filter((item) => ids.includes(item.id)).map(copyOrganization)),
    begin: vi.fn(async (operation: Record<string, unknown>) => {
      if (ledger) return { duplicate: true };
      ledger = {
        ...operation,
        mode: operation.mode,
        status: "pending",
        compensationStatus: "none"
      };
      return { duplicate: false };
    }),
    find: vi.fn(async () => ledger),
    update: vi.fn(async (operation: Record<string, unknown>) => {
      ledger = { ...ledger, ...operation };
    }),
    replaceCandidate: vi.fn(async (snapshot: { organizations: LegacyOrganization[] }) => {
      if (commitThenThrow) {
        commitThenThrow = false;
        candidateState = snapshot.organizations.map(copyOrganization);
        throw new Error("candidate acknowledgement lost");
      }
      if (postcheckMismatch) {
        postcheckMismatch = false;
        candidateState = [];
      } else {
        candidateState = snapshot.organizations.map(copyOrganization);
      }
    })
  };
  const plugin = {
    readiness: vi.fn(() => ({ mode: "legacy-proxy", legacyProxyConfigured: true, dualWriteSupported: false })),
    proxy: vi.fn()
  };
  const legacy = {
    isConfigured: vi.fn(() => true),
    getUserById: vi.fn(),
    listUserPermissions: vi.fn(async () => (input.permissionNames ?? ["user-management.update-user"])
      .map((name) => ({ name, description: null, source: "direct" })))
  };
  const iamRepository = {
    isConfigured: vi.fn(() => true),
    getIdentityUserByLegacyId: vi.fn(async (legacyUserId: number) => legacyUserId === (input.targetLegacyUserId ?? 24)
      ? {
          id: `legacy:${legacyUserId}`,
          legacyUserId,
          keycloakSubject: null,
          username: input.targetUsername === undefined ? "candidate-user" : input.targetUsername,
          email: "candidate@example.invalid",
          status: input.targetStatus ?? "active",
          source: "legacy-shadow",
          metadata: { legacyNickname: "Candidate", legacyCreatedAt: 1, legacyUpdatedAt: 2 },
          createdAt: null,
          updatedAt: null
        }
      : null),
    listRoleAssignmentsShadow: vi.fn(async () => [])
  };
  const jwt = {
    verifyAccessToken: vi.fn(() => ({
      uid: 9,
      username: "operator",
      sessionId: "session",
      roles: input.actorRoles ?? ["root"]
    }))
  };
  const service = new IamOrganizationWriteService(
    plugin as never,
    repository as never,
    legacy as never,
    jwt as never,
    iamRepository as never
  );
  return {
    service,
    plugin,
    repository,
    legacy,
    candidate: () => candidateState?.map(copyOrganization) ?? null
  };
}

function request(organizationIds: number[], idempotencyKey: string, legacyUserId = 24) {
  return {
    method: "POST",
    headers: {
      authorization: "Bearer verified",
      "idempotency-key": idempotencyKey,
      "x-identity-expected-revision": "a".repeat(40)
    } as Record<string, string | undefined>,
    body: { id: legacyUserId, organization_ids: organizationIds }
  };
}

function organization(id: number, name: string, title: string): LegacyOrganization {
  return { id, name, title, createdAt: 1, updatedAt: 2 };
}

function copyOrganization(value: LegacyOrganization): LegacyOrganization {
  return { ...value };
}
