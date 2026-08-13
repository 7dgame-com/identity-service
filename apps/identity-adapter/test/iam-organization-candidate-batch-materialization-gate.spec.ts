import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import {
  parseOrganizationCandidateBatchGateArgs,
  runOrganizationCandidateBatchGate,
  type OrganizationCandidateBatchGateOptions
} from "../../../scripts/iam-organization-candidate-batch-materialization-gate.js";

const REVISION = "a".repeat(40);
const PLAN = "b".repeat(64);
const TOKEN = "internal-token";
const KEY = "reviewed-batch-key";

describe("organization candidate batch materialization operator gate", () => {
  it("previews a disabled write gate without sending POST or exposing subjects", async () => {
    const fetcher = batchFetcher({ applyEnabled: false });

    const result = await runOrganizationCandidateBatchGate(options(), fetcher);

    expect(result).toMatchObject({
      passed: true,
      mode: "preview",
      applyAttempted: false,
      planToken: PLAN,
      counts: {
        legacySubjects: 3,
        ordinarySubjects: 2,
        protectedSubjects: 1,
        ordinaryAligned: 1,
        ordinaryMissing: 1
      },
      safety: { sourceOfTruth: "legacy", legacyWritePerformed: false, protectedSubjectWritePerformed: false },
      failures: []
    });
    expect(fetcher).not.toHaveBeenCalledWith(
      expect.stringContaining("/apply"),
      expect.objectContaining({ method: "POST" })
    );
    expect(JSON.stringify(result)).not.toContain("legacyUserId");
    expect(JSON.stringify(result)).not.toContain("ordinary-user");
  });

  it("binds the Production operator gate to the reviewed 807/2 universe and Production contract", async () => {
    const fetcher = batchFetcher({ applyEnabled: false, environment: "xrteeth-production" });

    const result = await runOrganizationCandidateBatchGate(options({
      environment: "xrteeth-production",
      expectedLegacySubjectCount: 807,
      expectedProtectedSubjectCount: 2
    }), fetcher);

    expect(result).toMatchObject({
      passed: true,
      mode: "preview",
      counts: {
        legacySubjects: 807,
        ordinarySubjects: 805,
        protectedSubjects: 2,
        ordinaryAligned: 1,
        ordinaryMissing: 804
      },
      safety: { sourceOfTruth: "legacy", legacyWritePerformed: false, protectedSubjectWritePerformed: false }
    });
    expect(fetcher.mock.calls.some(([, init]) => init?.method === "POST")).toBe(false);
  });

  it("sends one reviewed POST and requires a fresh full-range aligned preview", async () => {
    const fetcher = batchFetcher({ applyEnabled: true });

    const result = await runOrganizationCandidateBatchGate(options({ apply: true, planToken: PLAN, idempotencyKey: KEY }), fetcher);

    expect(result).toMatchObject({
      passed: true,
      mode: "apply",
      applyAttempted: true,
      outcomeUnknown: false,
      postcheckIncomplete: false,
      planToken: null,
      counts: { ordinaryAligned: 2, ordinaryMissing: 0 },
      operation: {
        completed: true,
        mutation: true,
        appliedCount: 1,
        skippedAlignedCount: 1,
        protectedSkippedCount: 1,
        idempotencyKeyDigest: expect.stringMatching(/^[a-f0-9]{64}$/)
      },
      failures: []
    });
    const postCalls = fetcher.mock.calls.filter(([, init]) => init?.method === "POST");
    expect(postCalls).toHaveLength(1);
    expect(postCalls[0]?.[1]).toMatchObject({
      redirect: "manual",
      headers: expect.objectContaining({
        "x-identity-internal-token": TOKEN,
        "x-identity-expected-revision": REVISION,
        "idempotency-key": KEY
      }),
      body: JSON.stringify({ planToken: PLAN })
    });
    expect(JSON.stringify(result)).not.toContain(PLAN);
    expect(JSON.stringify(result)).not.toContain(KEY);
  });

  it("does not POST when the runtime plan differs from the reviewed token", async () => {
    const fetcher = batchFetcher({ applyEnabled: true, planToken: "c".repeat(64) });

    const result = await runOrganizationCandidateBatchGate(
      options({ apply: true, planToken: PLAN, idempotencyKey: KEY }),
      fetcher
    );

    expect(result).toMatchObject({ passed: false, applyAttempted: false, outcomeUnknown: false });
    expect(result.failures).toContain("preview plan token does not match the reviewed token");
    expect(JSON.stringify(result)).not.toContain(PLAN);
    expect(fetcher.mock.calls.some(([, init]) => init?.method === "POST")).toBe(false);
  });

  it("does not disclose a plan token when preview posture validation fails", async () => {
    const fetcher = batchFetcher({ applyEnabled: false, previewBlocked: true });
    const result = await runOrganizationCandidateBatchGate(options(), fetcher);

    expect(result).toMatchObject({ passed: false, applyAttempted: false, planToken: null });
    expect(JSON.stringify(result)).not.toContain(PLAN);
  });

  it("marks a transport failure as unknown and never retries POST", async () => {
    const fetcher = batchFetcher({ applyEnabled: true, postFailure: true });

    const result = await runOrganizationCandidateBatchGate(
      options({ apply: true, planToken: PLAN, idempotencyKey: KEY }),
      fetcher
    );

    expect(result).toMatchObject({ passed: false, applyAttempted: true, outcomeUnknown: true });
    expect(result.failures).toEqual(["candidate batch POST outcome is unknown; do not retry automatically"]);
    expect(fetcher.mock.calls.filter(([, init]) => init?.method === "POST")).toHaveLength(1);
  });

  it("verifies an uncertain outcome with a disabled write switch and never resends POST", async () => {
    const completed = batchFetcher({ applyEnabled: false, initiallyApplied: true });
    const result = await runOrganizationCandidateBatchGate(options({
      verifyOutcome: true,
      planToken: PLAN,
      idempotencyKey: KEY
    }), completed);
    expect(result).toMatchObject({
      passed: true,
      mode: "verify-outcome",
      applyAttempted: false,
      outcomeUnknown: false,
      counts: { ordinaryAligned: 2, ordinaryMissing: 0 },
      planToken: null,
      failures: []
    });
    expect(completed.mock.calls.some(([, init]) => init?.method === "POST")).toBe(false);

    const incomplete = batchFetcher({ applyEnabled: false });
    const blocked = await runOrganizationCandidateBatchGate(options({
      verifyOutcome: true,
      planToken: PLAN,
      idempotencyKey: KEY
    }), incomplete);
    expect(blocked).toMatchObject({ passed: false, outcomeUnknown: true, counts: { ordinaryMissing: 1 } });
    expect(blocked.failures).toContain("candidate batch outcome is not proven; do not resend POST automatically");
  });

  it("fails restored-posture verification unless all batch inputs are cleared", async () => {
    const restored = batchFetcher({ restored: true });
    await expect(runOrganizationCandidateBatchGate(options({ expectRestored: true }), restored)).resolves.toMatchObject({
      passed: true,
      mode: "expect-restored",
      failures: []
    });

    const dirty = batchFetcher({ restored: true, restoredPlanKeyConfigured: true });
    const result = await runOrganizationCandidateBatchGate(options({ expectRestored: true }), dirty);
    expect(result).toMatchObject({ passed: false, mode: "expect-restored" });
    expect(result.failures).toContain("readiness plan key expected false, got true");
  });

  it("rejects remote URLs, duplicate flags and command-line secrets before I/O", () => {
    const env = {
      IDENTITY_IAM_INTERNAL_API_TOKEN: TOKEN,
      IDENTITY_IAM_ORG_CANDIDATE_BATCH_PLAN_TOKEN: PLAN,
      IDENTITY_IAM_ORG_CANDIDATE_BATCH_IDEMPOTENCY_KEY: KEY
    };
    const required = [
      `--expected-revision=${REVISION}`,
      "--expected-legacy-subject-count=3",
      "--expected-protected-subject-count=1"
    ];
    expect(() => parseOrganizationCandidateBatchGateArgs([
      "--adapter-url=https://identity.d.xrteeth.com",
      ...required
    ], env)).toThrow("loopback");
    expect(() => parseOrganizationCandidateBatchGateArgs([
      "--adapter-url=http://127.0.0.1:8086",
      ...required,
      "--apply",
      "--apply"
    ], env)).toThrow("Duplicate --apply");
    expect(() => parseOrganizationCandidateBatchGateArgs([
      "--adapter-url=http://127.0.0.1:8086",
      ...required,
      `--plan-token=${PLAN}`
    ], env)).toThrow("Do not pass write secrets");
    expect(() => parseOrganizationCandidateBatchGateArgs([
      "--adapter-url=http://127.0.0.1:8086",
      ...required,
      `--token=${TOKEN}`
    ], env)).toThrow("Do not pass tokens");
    expect(() => parseOrganizationCandidateBatchGateArgs([
      "--environment=xrteeth-production",
      "--adapter-url=http://127.0.0.1:8086",
      `--expected-revision=${REVISION}`,
      "--expected-legacy-subject-count=806",
      "--expected-protected-subject-count=2"
    ], env)).toThrow("reviewed 807/2");
  });
});

function options(overrides: Partial<OrganizationCandidateBatchGateOptions> = {}): OrganizationCandidateBatchGateOptions {
  return {
    environment: "xrteeth-develop",
    adapterUrl: "http://127.0.0.1:8086",
    token: TOKEN,
    expectedRevision: REVISION,
    expectedLegacySubjectCount: 3,
    expectedProtectedSubjectCount: 1,
    apply: false,
    verifyOutcome: false,
    expectRestored: false,
    planToken: null,
    idempotencyKey: null,
    ...overrides
  };
}

function batchFetcher(input: {
  applyEnabled?: boolean;
  planToken?: string;
  postFailure?: boolean;
  restored?: boolean;
  restoredPlanKeyConfigured?: boolean;
  initiallyApplied?: boolean;
  previewBlocked?: boolean;
  environment?: "xrteeth-develop" | "xrteeth-production";
}) {
  let applied = input.initiallyApplied === true;
  const environment = input.environment ?? "xrteeth-develop";
  const legacySubjectCount = environment === "xrteeth-production" ? 807 : 3;
  const protectedSubjectCount = environment === "xrteeth-production" ? 2 : 1;
  const ordinarySubjectCount = legacySubjectCount - protectedSubjectCount;
  const fetcher = vi.fn(async (urlValue: string | URL | Request, init?: RequestInit) => {
    const url = String(urlValue);
    if (url.endsWith("/health")) return json(health(input));
    if (url.endsWith("/readiness")) return json(readiness(input));
    if (url.endsWith("/candidate-batch-materialization/preview")) {
      return json(preview(input, applied));
    }
    if (url.endsWith("/candidate-batch-materialization/apply") && init?.method === "POST") {
      if (input.postFailure) throw new Error("injected transport failure containing secret");
      applied = true;
      return json({
        status: "ok",
        service: "identity-adapter",
        capability: "iam-organization-candidate-batch-materialization",
        data: {
          contract: `iam-organization-candidate-batch-materialization/${environment}/v1`,
          mutation: true,
          completed: true,
          planTokenDigest: createHash("sha256").update(PLAN, "utf8").digest("hex").slice(0, 16),
          legacySubjectCount,
          ordinarySubjectCount,
          protectedSkippedCount: protectedSubjectCount,
          appliedCount: ordinarySubjectCount - 1,
          replayedCount: 0,
          skippedAlignedCount: 1,
          sourceOfTruth: "legacy",
          legacyWritePerformed: false,
          protectedSubjectWritePerformed: false,
          writeScope: "identity-candidate-only"
        }
      }, 201);
    }
    throw new Error(`unexpected URL ${url}`);
  });
  return fetcher;
}

function health(input: Parameters<typeof batchFetcher>[0]) {
  const restored = input.restored === true;
  const environment = input.environment ?? "xrteeth-develop";
  return {
    status: "ok",
    service: "identity-adapter",
    revision: REVISION,
    capabilities: {
      organizationWrite: {
        mode: "disabled",
        routeIntegrationEnabled: false,
        dualWriteExecutionEnabled: false,
        candidateMaterializationEnabled: false,
        candidateMaterializationTargetConfigured: false,
        candidateBatchMaterializationEnabled: restored ? false : input.applyEnabled === true,
        candidateBatchMaterializationEnvironment: restored ? "disabled" : environment,
        rolloutMode: "off",
        rolloutAllowlistCount: 0,
        rolloutPercentage: 0
      }
    }
  };
}

function readiness(input: Parameters<typeof batchFetcher>[0]) {
  const restored = input.restored === true;
  const applyEnabled = input.applyEnabled === true && !restored;
  const environment = input.environment ?? "xrteeth-develop";
  const legacySubjectCount = environment === "xrteeth-production" ? 807 : 3;
  const protectedSubjectCount = environment === "xrteeth-production" ? 2 : 1;
  return {
    status: "ok",
    service: "identity-adapter",
    capability: "iam-organization-write",
    data: {
      candidateBatchMaterialization: {
        contract: `iam-organization-candidate-batch-materialization/${environment}/v1`,
        enabled: applyEnabled,
        environment: restored ? "disabled" : environment,
        planHmacKeyConfigured: restored ? input.restoredPlanKeyConfigured === true : true,
        expectedLegacySubjectCount: restored ? 0 : legacySubjectCount,
        expectedProtectedSubjectCount: restored ? 0 : protectedSubjectCount,
        canPreview: !restored,
        canApply: applyEnabled,
        sourceOfTruth: "legacy",
        mutatesLegacy: false,
        protectedSubjectsWritten: false,
        writeScope: "identity-candidate-only"
      }
    }
  };
}

function preview(input: Parameters<typeof batchFetcher>[0], applied: boolean) {
  const environment = input.environment ?? "xrteeth-develop";
  const legacySubjectCount = environment === "xrteeth-production" ? 807 : 3;
  const protectedSubjectCount = environment === "xrteeth-production" ? 2 : 1;
  const ordinarySubjectCount = legacySubjectCount - protectedSubjectCount;
  const ordinaryMissing = applied ? 0 : ordinarySubjectCount - 1;
  return {
    status: "ok",
    service: "identity-adapter",
    capability: "iam-organization-candidate-batch-materialization-preview",
    data: {
      contract: `iam-organization-candidate-batch-materialization/${environment}/v1`,
      mutation: false,
      executable: true,
      applyEnabled: input.applyEnabled === true,
      planToken: input.planToken ?? PLAN,
      legacySubjectCount,
      ordinarySubjectCount,
      protectedSubjectCount,
      ordinaryAlignedCount: ordinarySubjectCount - ordinaryMissing,
      ordinaryMissingCount: ordinaryMissing,
      ordinaryBlockedCount: 0,
      inactiveOrdinaryCount: 0,
      protectedAlignedCount: 0,
      protectedMissingCount: protectedSubjectCount,
      sourceOfTruth: "legacy",
      legacyWritePerformed: false,
      identityCandidateWritePerformed: false,
      protectedSubjectWritePerformed: false,
      blockedReasons: input.previewBlocked ? ["injected-blocker-containing-private-context"] : []
    }
  };
}

function json(body: Record<string, unknown>, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}
