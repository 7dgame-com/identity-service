import { describe, expect, it, vi } from "vitest";
import {
  parseOrganizationWriteWindowGateArgs,
  runOrganizationWriteWindowGate,
  type OrganizationWriteWindowGateOptions
} from "../../../scripts/iam-organization-write-window-gate.js";

const revision = "17f83c15855cdab4e3e4d779f5d8b99a1645ed4d";

describe("IAM organization-write read-only window gate", () => {
  it("passes a selected executable legacy-proxy target with a clean ledger", async () => {
    const fetcher = fixtureFetch();
    const result = await runOrganizationWriteWindowGate(options(), fetcher);

    expect(result).toMatchObject({
      passed: true,
      target: { fingerprint: "target-digest" },
      failures: []
    });
    expect(result.target).not.toHaveProperty("legacyUserId");
    expect(fetcher).toHaveBeenCalledTimes(5);
    for (const [url, init] of fetcher.mock.calls) {
      expect(String(url)).not.toContain("test-internal-token");
      expect(init?.method).toBeUndefined();
      if (!String(url).endsWith("/health")) {
        expect(init?.headers).toEqual({ "x-identity-internal-token": "test-internal-token" });
      }
    }
  });

  it("fails when the target is not selected or the ledger contains unresolved risk", async () => {
    const fetcher = fixtureFetch({
      decision: { selected: false, executable: false, decision: "not-selected:allowlist" },
      summaryOperations: [{ mode: "dual-write", status: "failed", compensationStatus: "required", total: 1 }]
    });
    const result = await runOrganizationWriteWindowGate(options(), fetcher);

    expect(result.passed).toBe(false);
    expect(result.failures).toEqual(expect.arrayContaining([
      "decision.selected expected true, got false",
      "decision.executable expected true, got false",
      "decision.decision expected selected:allowlist, got not-selected:allowlist",
      "ledger contains failed operations in the last 60 minutes",
      "ledger contains compensation=required in the last 60 minutes"
    ]));
  });

  it("requires zero alignment for a dual-write gate", async () => {
    const fetcher = fixtureFetch({
      mode: "dual-write",
      dualWriteExecutionEnabled: true,
      alignment: { aligned: false, P0: 0, P1: 1, P2: 0, mismatch: 1 }
    });
    const result = await runOrganizationWriteWindowGate({
      ...options(),
      expectedMode: "dual-write",
      requireAlignment: true
    }, fetcher);

    expect(result.passed).toBe(false);
    expect(result.failures).toEqual(expect.arrayContaining([
      "alignment.aligned expected true, got false",
      "alignment.P1 expected 0, got 1",
      "alignment.mismatch expected 0, got 1"
    ]));
    expect(fetcher).toHaveBeenCalledTimes(6);
  });

  it("fails closed while candidate materialization or its target remains configured", async () => {
    const result = await runOrganizationWriteWindowGate(options(), fixtureFetch({
      candidateMaterializationEnabled: true,
      candidateMaterializationTargetConfigured: true
    }));

    expect(result.passed).toBe(false);
    expect(result.failures).toEqual(expect.arrayContaining([
      "health.organizationWrite.candidateMaterializationEnabled expected false, got true",
      "health.organizationWrite.candidateMaterializationTargetConfigured expected false, got true"
    ]));
  });

  it("fails closed while candidate batch materialization remains configured", async () => {
    const result = await runOrganizationWriteWindowGate(options(), fixtureFetch({
      candidateBatchMaterializationEnabled: true,
      candidateBatchMaterializationEnvironment: "xrteeth-develop"
    }));

    expect(result.passed).toBe(false);
    expect(result.failures).toEqual(expect.arrayContaining([
      "health.organizationWrite.candidateBatchMaterializationEnabled expected false, got true",
      "health.organizationWrite.candidateBatchMaterializationEnvironment expected disabled, got xrteeth-develop"
    ]));
  });

  it("requires the exact recovery-drill posture when requested", async () => {
    const blocked = await runOrganizationWriteWindowGate({
      ...options(),
      expectedMode: "dual-write",
      expectedRecoveryDrill: true
    }, fixtureFetch({ mode: "dual-write", dualWriteExecutionEnabled: true }));
    expect(blocked.passed).toBe(false);
    expect(blocked.failures).toEqual(expect.arrayContaining([
      "health.organizationWrite.recoveryDrillEnabled expected true, got false",
      "readiness.recoveryDrill.enabled expected true, got false"
    ]));

    const passed = await runOrganizationWriteWindowGate({
      ...options(),
      expectedMode: "dual-write",
      expectedRecoveryDrill: true
    }, fixtureFetch({
      mode: "dual-write",
      dualWriteExecutionEnabled: true,
      recoveryDrillEnabled: true,
      recoveryDrillTargetConfigured: true
    }));
    expect(passed.passed).toBe(true);
  });

  it("accepts tokens only from the environment and validates explicit target input", () => {
    expect(() => parseOrganizationWriteWindowGateArgs(["--legacy-user-id=24", "--token=secret"], {})).toThrow(
      "Do not pass tokens on the command line"
    );
    expect(() => parseOrganizationWriteWindowGateArgs([], { IDENTITY_IAM_INTERNAL_API_TOKEN: "secret" })).toThrow(
      "--legacy-user-id is required"
    );
    expect(parseOrganizationWriteWindowGateArgs(
      ["--legacy-user-id=2401", `--expected-revision=${revision}`, "--expected-mode=dual-write", "--expected-recovery-drill=true"],
      { IDENTITY_IAM_INTERNAL_API_TOKEN: "secret" }
    )).toMatchObject({
      legacyUserId: 2401,
      token: "secret",
      expectedRevision: revision,
      expectedMode: "dual-write",
      expectedRecoveryDrill: true
    });
  });
});

function options(): OrganizationWriteWindowGateOptions {
  return {
    adapterUrl: "http://identity-adapter:8086",
    token: "test-internal-token",
    legacyUserId: 2401,
    expectedMode: "legacy-proxy",
    expectedRevision: revision,
    expectedAllowlistCount: 1,
    sinceMinutes: 60,
    requireAlignment: false,
    expectedRecoveryDrill: false
  };
}

function fixtureFetch(overrides: {
  mode?: "legacy-proxy" | "dual-write";
  dualWriteExecutionEnabled?: boolean;
  candidateMaterializationEnabled?: boolean;
  candidateMaterializationTargetConfigured?: boolean;
  candidateBatchMaterializationEnabled?: boolean;
  candidateBatchMaterializationEnvironment?: "disabled" | "xrteeth-develop";
  decision?: Record<string, unknown>;
  summaryOperations?: Record<string, unknown>[];
  alignment?: Record<string, unknown>;
  recoveryDrillEnabled?: boolean;
  recoveryDrillTargetConfigured?: boolean;
} = {}) {
  const mode = overrides.mode ?? "legacy-proxy";
  const dualWriteExecutionEnabled = overrides.dualWriteExecutionEnabled ?? false;
  const organizationWrite = {
    mode,
    routeIntegrationEnabled: true,
    dualWriteExecutionEnabled,
    candidateMaterializationEnabled: overrides.candidateMaterializationEnabled ?? false,
    candidateMaterializationTargetConfigured: overrides.candidateMaterializationTargetConfigured ?? false,
    candidateBatchMaterializationEnabled: overrides.candidateBatchMaterializationEnabled ?? false,
    candidateBatchMaterializationEnvironment: overrides.candidateBatchMaterializationEnvironment ?? "disabled",
    recoveryDrillEnabled: overrides.recoveryDrillEnabled ?? false,
    recoveryDrillTargetConfigured: overrides.recoveryDrillTargetConfigured ?? false,
    rolloutMode: "allowlist",
    rolloutAllowlistCount: 1,
    rolloutPercentage: 0,
    sourceOfTruth: "legacy",
    identityNativeSupported: false
  };
  const readiness = {
    mode,
    routeIntegrationEnabled: true,
    route: "/v1/plugin-user/update-user",
    scope: "membership-replace",
    sourceOfTruth: "legacy",
    recoveryDrill: {
      enabled: overrides.recoveryDrillEnabled ?? false,
      targetConfigured: overrides.recoveryDrillTargetConfigured ?? false
    },
    rollout: { mode: "allowlist", allowlistCount: 1, percentage: 0, selectionConfigured: true },
    legacyProxyGate: { executable: mode === "legacy-proxy" },
    dualWriteGate: { executable: mode === "dual-write" }
  };
  const decision = {
    mutation: false,
    mode,
    route: "/v1/plugin-user/update-user",
    scope: "membership-replace",
    targetFingerprint: "target-digest",
    selected: true,
    executable: true,
    decision: "selected:allowlist",
    sourceOfTruth: "legacy",
    ...overrides.decision
  };

  return vi.fn(async (input: string | URL | Request, _init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith("/health")) return json({ status: "ok", service: "identity-adapter", revision, capabilities: { organizationWrite } });
    if (url.endsWith("/readiness")) return json({ status: "ok", data: readiness });
    if (url.endsWith("/decision")) return json({ status: "ok", data: decision });
    if (url.includes("/operations/summary")) return json({ status: "ok", data: { configured: true, operations: overrides.summaryOperations ?? [] } });
    if (url.includes("/operations/recent")) return json({ status: "ok", data: { configured: true, operations: [] } });
    if (url.endsWith("/alignment")) return json({ status: "ok", data: overrides.alignment ?? { aligned: true, P0: 0, P1: 0, P2: 0, mismatch: 0 } });
    return json({ code: "NOT_FOUND" }, 404);
  });
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}
