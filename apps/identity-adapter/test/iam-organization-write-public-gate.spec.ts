import { describe, expect, it, vi } from "vitest";
import {
  parseOrganizationWritePublicGateArgs,
  runOrganizationWritePublicGate,
  type OrganizationWritePublicGateOptions
} from "../../../scripts/iam-organization-write-public-gate.js";

describe("IAM organization-write public posture gate", () => {
  it("requires candidate materialization and its target to be off by default", () => {
    expect(parseOrganizationWritePublicGateArgs([])).toMatchObject({
      expectedCandidateMaterializationEnabled: false,
      expectedCandidateMaterializationTargetConfigured: false,
      expectedCandidateBatchMaterializationEnabled: false,
      expectedCandidateBatchMaterializationEnvironment: "disabled"
    });
  });

  it("passes a compatible default-off public posture", async () => {
    const result = await runOrganizationWritePublicGate(options(), fixtureFetch());

    expect(result).toMatchObject({ passed: true, failures: [] });
  });

  it("fails closed when materialization is enabled or a target remains configured", async () => {
    const result = await runOrganizationWritePublicGate(options(), fixtureFetch({
      candidateMaterializationEnabled: true,
      candidateMaterializationTargetConfigured: true
    }));

    expect(result.passed).toBe(false);
    expect(result.failures).toEqual(expect.arrayContaining([
      expect.stringContaining("candidateMaterializationEnabled expected false, got true"),
      expect.stringContaining("candidateMaterializationTargetConfigured expected false, got true")
    ]));
  });

  it("supports explicit materialization expectations for a reviewed window", async () => {
    const parsed = parseOrganizationWritePublicGateArgs([
      "--expected-candidate-materialization-enabled=true",
      "--expected-candidate-materialization-target-configured=true"
    ]);
    const result = await runOrganizationWritePublicGate({
      ...options(),
      expectedCandidateMaterializationEnabled: parsed.expectedCandidateMaterializationEnabled,
      expectedCandidateMaterializationTargetConfigured: parsed.expectedCandidateMaterializationTargetConfigured
    }, fixtureFetch({
      candidateMaterializationEnabled: true,
      candidateMaterializationTargetConfigured: true
    }));

    expect(result).toMatchObject({ passed: true, failures: [] });
  });

  it("fails closed when candidate batch materialization is configured outside its reviewed window", async () => {
    const result = await runOrganizationWritePublicGate(options(), fixtureFetch({
      candidateBatchMaterializationEnabled: true,
      candidateBatchMaterializationEnvironment: "xrteeth-develop"
    }));

    expect(result.passed).toBe(false);
    expect(result.failures).toEqual(expect.arrayContaining([
      expect.stringContaining("candidateBatchMaterializationEnabled expected false, got true"),
      expect.stringContaining("candidateBatchMaterializationEnvironment expected disabled, got xrteeth-develop")
    ]));
  });

  it("rejects an older health schema that omits the materialization posture", async () => {
    const result = await runOrganizationWritePublicGate(options(), fixtureFetch({
      omitMaterializationPosture: true
    }));

    expect(result.passed).toBe(false);
    expect(result.failures).toEqual(expect.arrayContaining([
      expect.stringContaining("candidateMaterializationEnabled expected false, got undefined"),
      expect.stringContaining("candidateMaterializationTargetConfigured expected false, got undefined"),
      expect.stringContaining("candidateBatchMaterializationEnabled expected false, got undefined"),
      expect.stringContaining("candidateBatchMaterializationEnvironment expected disabled, got undefined")
    ]));
  });
});

function options(): OrganizationWritePublicGateOptions {
  return {
    urls: ["https://identity.example.test/health"],
    expectedMode: "disabled",
    expectedRouteIntegration: false,
    expectedDualWriteExecution: false,
    expectedCandidateMaterializationEnabled: false,
    expectedCandidateMaterializationTargetConfigured: false,
    expectedCandidateBatchMaterializationEnabled: false,
    expectedCandidateBatchMaterializationEnvironment: "disabled",
    expectedRolloutMode: "off",
    expectedRolloutPercentage: 0,
    expectedAllowlistCount: 0
  };
}

function fixtureFetch(overrides: {
  candidateMaterializationEnabled?: boolean;
  candidateMaterializationTargetConfigured?: boolean;
  candidateBatchMaterializationEnabled?: boolean;
  candidateBatchMaterializationEnvironment?: "disabled" | "xrteeth-develop";
  omitMaterializationPosture?: boolean;
} = {}) {
  const organizationWrite: Record<string, unknown> = {
    mode: "disabled",
    routeIntegrationEnabled: false,
    dualWriteExecutionEnabled: false,
    candidateMaterializationEnabled: overrides.candidateMaterializationEnabled ?? false,
    candidateMaterializationTargetConfigured: overrides.candidateMaterializationTargetConfigured ?? false,
    candidateBatchMaterializationEnabled: overrides.candidateBatchMaterializationEnabled ?? false,
    candidateBatchMaterializationEnvironment: overrides.candidateBatchMaterializationEnvironment ?? "disabled",
    rolloutMode: "off",
    rolloutAllowlistCount: 0,
    rolloutPercentage: 0,
    sourceOfTruth: "legacy",
    identityNativeSupported: false
  };
  if (overrides.omitMaterializationPosture) {
    delete organizationWrite.candidateMaterializationEnabled;
    delete organizationWrite.candidateMaterializationTargetConfigured;
    delete organizationWrite.candidateBatchMaterializationEnabled;
    delete organizationWrite.candidateBatchMaterializationEnvironment;
  }

  return vi.fn(async () => json({
    status: "ok",
    service: "identity-adapter",
    revision: "unknown",
    capabilities: { organizationWrite }
  }));
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}
