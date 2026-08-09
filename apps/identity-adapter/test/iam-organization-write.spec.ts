import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { loadConfig } from "../src/config.js";
import { IamOrganizationWriteService } from "../src/iam-organization-write.service.js";
import { redactOrganizationWriteMetadata } from "../src/iam-organization-write.repository.js";
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
  });

  afterEach(() => {
    process.env = { ...originalEnv };
  });

  it("is disabled and route-disconnected by default", async () => {
    const fixture = createFixture();

    expect(fixture.service.readiness()).toMatchObject({
      enabled: false,
      mode: "disabled",
      routeIntegrationEnabled: false,
      sourceOfTruth: "legacy",
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
      organizationWriteRolloutPercentage: 0
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

    expect(fixture.service.readiness()).toMatchObject({
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

  it("previews selected and unselected legacy-proxy targets without reading or writing", () => {
    enableLegacyProxy();
    const fixture = createFixture();

    expect(fixture.service.previewMembershipRollout(24)).toMatchObject({
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
    expect(fixture.service.previewMembershipRollout(25)).toMatchObject({
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
});

function createFixture(input: {
  organizations?: LegacyOrganization[];
  candidateOrganizations?: LegacyOrganization[];
  duplicate?: boolean;
  existingFingerprint?: string;
  existingCompensationStatus?: "none" | "required" | "completed" | "failed";
  candidateMissing?: boolean;
  pluginResponse?: { status: number; body: unknown };
  pluginMode?: "legacy-proxy" | "dual-write";
  username?: string;
  roles?: string[];
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
  const repository = {
    isConfigured: vi.fn(() => true),
    begin: vi.fn(async () => ({ duplicate: input.duplicate ?? false })),
    find: vi.fn(async () => ({
      operationKey: "operation-1",
      requestFingerprint: input.existingFingerprint ?? "unused",
      legacyUserId: 24,
      compensationStatus: input.existingCompensationStatus ?? "none"
    })),
    update: vi.fn(async () => undefined),
    replaceCandidate: vi.fn(async () => undefined),
    candidateForLegacyUser: vi.fn(async () => input.candidateMissing
      ? null
      : { legacyUserId: 24, organizations: input.candidateOrganizations ?? organizations }),
    summarizeRecent: vi.fn(async () => []),
    listRecentSafe: vi.fn(async () => [])
  };
  const legacyUser: LegacyUserReadModel = {
    id: 24,
    username: input.username ?? "test-user",
    email: null,
    status: 10,
    nickname: null,
    emailVerifiedAt: null,
    createdAt: null,
    updatedAt: null,
    userInfo: {},
    roles: input.roles ?? [],
    organizations,
    source: "legacy"
  };
  const legacy = { getUserById: vi.fn(async () => legacyUser) };
  const jwt = { verifyAccessToken: vi.fn(() => { throw new Error("not a test token"); }) };
  const service = new IamOrganizationWriteService(plugin as never, repository as never, legacy as never, jwt as never);
  return { service, plugin, repository, legacy };
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
