import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import {
  parseOrganizationCandidateMaterializationGateArgs,
  runOrganizationCandidateMaterializationGate,
  type OrganizationCandidateMaterializationGateOptions
} from "../../../scripts/iam-organization-candidate-materialization-gate.js";

const revision = "a".repeat(40);
const snapshotFingerprint = "b".repeat(64);
const operationKeyDigest = "d".repeat(16);
const fullOperationKeyDigest = `${operationKeyDigest}${"e".repeat(48)}`;
const legacyUserId = 918_273_645;
const targetFingerprint = sha256(`legacy:${legacyUserId}`).slice(0, 16);
const internalToken = "operator-internal-token-value";
const idempotencyKey = "candidate-materialization-operation-key";
const idempotencyKeyEnv = "IDENTITY_IAM_ORG_CANDIDATE_MATERIALIZATION_IDEMPOTENCY_KEY";
const requestedAt = "2026-08-09T03:00:00.000Z";
const completedAt = "2026-08-09T03:00:01.000Z";

describe("IAM organization candidate materialization operator gate", () => {
  it("parses a read-only default and rejects command-line credentials or non-loopback URLs", () => {
    expect(parseOrganizationCandidateMaterializationGateArgs(
      [`--legacy-user-id=${legacyUserId}`, `--expected-revision=${revision}`],
      { IDENTITY_IAM_INTERNAL_API_TOKEN: internalToken }
    )).toMatchObject({
      adapterUrl: "http://127.0.0.1:8086",
      token: internalToken,
      legacyUserId,
      apply: false,
      expectedRevision: revision,
      idempotencyKey: null
    });

    expect(() => parseOrganizationCandidateMaterializationGateArgs(
      [`--legacy-user-id=${legacyUserId}`, "--token=secret"],
      {}
    )).toThrow("Do not pass tokens on the command line");
    expect(() => parseOrganizationCandidateMaterializationGateArgs(
      [`--legacy-user-id=${legacyUserId}`, "--idempotency-key=secret"],
      { IDENTITY_IAM_INTERNAL_API_TOKEN: internalToken }
    )).toThrow("Do not pass idempotency keys on the command line");
    expect(() => parseOrganizationCandidateMaterializationGateArgs(
      [`--legacy-user-id=${legacyUserId}`, "--adapter-url=http://identity-adapter:8086"],
      { IDENTITY_IAM_INTERNAL_API_TOKEN: internalToken }
    )).toThrow("adapter-url must use only");
    expect(() => parseOrganizationCandidateMaterializationGateArgs(
      [`--legacy-user-id=${legacyUserId}`, "--adapter-url=http://127.0.0.1:8086/internal"],
      { IDENTITY_IAM_INTERNAL_API_TOKEN: internalToken }
    )).toThrow("adapter-url must use only");
    expect(() => parseOrganizationCandidateMaterializationGateArgs(
      [`--legacy-user-id=${legacyUserId}`],
      { IDENTITY_IAM_INTERNAL_API_TOKEN: internalToken }
    )).toThrow("--expected-revision");

    for (const adapterUrl of ["http://127.0.0.1:8086", "http://localhost:8086", "http://[::1]:8086"]) {
      expect(parseOrganizationCandidateMaterializationGateArgs(
        [`--legacy-user-id=${legacyUserId}`, `--adapter-url=${adapterUrl}`, `--expected-revision=${revision}`],
        { IDENTITY_IAM_INTERNAL_API_TOKEN: internalToken }
      ).adapterUrl).toBe(adapterUrl);
    }
  });

  it("uses only the approved GET surfaces in preview mode and emits no raw secret or subject id", async () => {
    const fetcher = fixtureFetch({ apply: false });
    const result = await runOrganizationCandidateMaterializationGate(options(false), fetcher);

    expect(result).toMatchObject({
      passed: true,
      mode: "preview",
      applyAttempted: false,
      revision,
      posture: {
        mode: "disabled",
        routeIntegrationEnabled: false,
        dualWriteExecutionEnabled: false,
        candidateMaterializationEnabled: false,
        candidateMaterializationTargetConfigured: true,
        rolloutMode: "off",
        rolloutAllowlistCount: 0,
        rolloutPercentage: 0,
        sourceOfTruth: "legacy",
        identityNativeSupported: false
      },
      readiness: {
        repositoryConfigured: true,
        materialization: {
          enabled: false,
          targetConfigured: true,
          schemaReady: true,
          canPreview: true,
          canApply: false,
          blockerCount: 1
        }
      },
      target: { fingerprint: targetFingerprint, snapshotFingerprint, organizationCount: 1 },
      preview: {
        executable: false,
        mutation: false,
        unresolvedOperationCount: 0,
        alignment: { aligned: false, P0: 0, P1: 1, P2: 0, mismatch: 1 }
      },
      ledgerBefore: { unresolvedOperationCount: 0 },
      failures: []
    });
    expect(fetcher).toHaveBeenCalledTimes(6);
    for (const [input, init] of fetcher.mock.calls) {
      const url = String(input);
      expect(init?.method).toBeUndefined();
      expect(init?.redirect).toBe("error");
      expect(url).toMatch(/\/(health|internal\/iam\/organization-write\/(readiness|subjects\/\d+\/(materialization-preview|alignment)|operations\/(summary|recent)))(\?|$)/);
      expect(url).not.toContain(internalToken);
      expect(url).not.toContain(idempotencyKey);
      if (!url.endsWith("/health")) {
        expect(init?.headers).toEqual({ "x-identity-internal-token": internalToken });
      }
    }
    assertRedacted(result);
  });

  it.each([
    ["--apply", ["--apply", "--apply"]],
    ["--expect-restored", ["--expect-restored", "--expect-restored"]],
    ["--verify-outcome", ["--verify-outcome", "--verify-outcome"]],
    ["--adapter-url", ["--adapter-url=http://127.0.0.1:8086", "--adapter-url=http://localhost:8086"]],
    ["--legacy-user-id", [`--legacy-user-id=${legacyUserId}`, `--legacy-user-id=${legacyUserId + 1}`]],
    ["--expected-revision", [`--expected-revision=${revision}`, `--expected-revision=${"b".repeat(40)}`]],
    ["--expected-snapshot-fingerprint", [
      `--expected-snapshot-fingerprint=${snapshotFingerprint}`,
      `--expected-snapshot-fingerprint=${"c".repeat(64)}`
    ]],
    ["--since-minutes", ["--since-minutes=60", "--since-minutes=120"]]
  ])("rejects duplicate %s arguments instead of accepting the last value", (name, args) => {
    expect(() => parseOrganizationCandidateMaterializationGateArgs(args, {
      IDENTITY_IAM_INTERNAL_API_TOKEN: internalToken,
      [idempotencyKeyEnv]: idempotencyKey
    })).toThrow(`Duplicate ${name} argument is not allowed.`);
  });

  it("rejects a reviewed snapshot fingerprint in ordinary preview mode", () => {
    expect(() => parseOrganizationCandidateMaterializationGateArgs([
      `--legacy-user-id=${legacyUserId}`,
      `--expected-revision=${revision}`,
      `--expected-snapshot-fingerprint=${snapshotFingerprint}`
    ], { IDENTITY_IAM_INTERNAL_API_TOKEN: internalToken })).toThrow(
      "Preview mode does not accept --expected-snapshot-fingerprint."
    );
  });

  it("fails before subject reads when posture, schema, or target readiness is unsafe", async () => {
    const fetcher = fixtureFetch({
      apply: false,
      healthPosture: { candidateMaterializationTargetConfigured: false },
      readinessMaterialization: { targetConfigured: false, schemaReady: false, canPreview: false }
    });
    const result = await runOrganizationCandidateMaterializationGate(options(false), fetcher);

    expect(result).toMatchObject({ passed: false, applyAttempted: false });
    expect(result.failures).toEqual(expect.arrayContaining([
      "health materialization target configured assertion failed",
      "readiness materialization target configured assertion failed",
      "readiness materialization schema assertion failed",
      "readiness materialization preview assertion failed"
    ]));
    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(fetcher.mock.calls.some(([, init]) => init?.method === "POST")).toBe(false);
    assertRedacted(result);
  });

  it("requires an explicit apply flag, reviewed fingerprint, full revision, and env-only idempotency key", () => {
    const env = {
      IDENTITY_IAM_INTERNAL_API_TOKEN: internalToken,
      [idempotencyKeyEnv]: idempotencyKey
    };
    const parsed = parseOrganizationCandidateMaterializationGateArgs([
      "--apply",
      `--legacy-user-id=${legacyUserId}`,
      `--expected-revision=${revision}`,
      `--expected-snapshot-fingerprint=${snapshotFingerprint}`
    ], env);
    expect(parsed).toMatchObject({
      apply: true,
      expectedRevision: revision,
      expectedSnapshotFingerprint: snapshotFingerprint,
      idempotencyKey
    });

    expect(() => parseOrganizationCandidateMaterializationGateArgs([
      "--apply",
      `--legacy-user-id=${legacyUserId}`,
      `--expected-snapshot-fingerprint=${snapshotFingerprint}`
    ], env)).toThrow("--expected-revision");
    expect(() => parseOrganizationCandidateMaterializationGateArgs([
      "--apply",
      `--legacy-user-id=${legacyUserId}`,
      `--expected-revision=${revision}`
    ], env)).toThrow("--apply requires --expected-snapshot-fingerprint");
    expect(() => parseOrganizationCandidateMaterializationGateArgs([
      "--apply",
      `--legacy-user-id=${legacyUserId}`,
      `--expected-revision=${revision}`,
      `--expected-snapshot-fingerprint=${snapshotFingerprint}`
    ], { IDENTITY_IAM_INTERNAL_API_TOKEN: internalToken })).toThrow(idempotencyKeyEnv);
  });

  it("parses a subject-independent restored-posture check and rejects mutation options", () => {
    expect(parseOrganizationCandidateMaterializationGateArgs([
      "--expect-restored",
      `--expected-revision=${revision}`
    ], { IDENTITY_IAM_INTERNAL_API_TOKEN: internalToken })).toMatchObject({
      expectRestored: true,
      legacyUserId: 0,
      apply: false,
      expectedRevision: revision
    });
    expect(() => parseOrganizationCandidateMaterializationGateArgs([
      "--expect-restored",
      "--apply",
      `--expected-revision=${revision}`,
      `--expected-snapshot-fingerprint=${snapshotFingerprint}`
    ], {
      IDENTITY_IAM_INTERNAL_API_TOKEN: internalToken,
      [idempotencyKeyEnv]: idempotencyKey
    })).toThrow("mutually exclusive");
    expect(() => parseOrganizationCandidateMaterializationGateArgs([
      "--expect-restored",
      `--expected-revision=${revision}`,
      `--expected-snapshot-fingerprint=${snapshotFingerprint}`
    ], { IDENTITY_IAM_INTERNAL_API_TOKEN: internalToken })).toThrow("does not accept --expected-snapshot-fingerprint");
    expect(() => parseOrganizationCandidateMaterializationGateArgs([
      "--expect-restored",
      `--legacy-user-id=${legacyUserId}`,
      `--expected-revision=${revision}`
    ], { IDENTITY_IAM_INTERNAL_API_TOKEN: internalToken })).toThrow("does not accept --legacy-user-id");
  });

  it("requires reviewed env-only inputs for mutually exclusive outcome verification", () => {
    const env = {
      IDENTITY_IAM_INTERNAL_API_TOKEN: internalToken,
      [idempotencyKeyEnv]: idempotencyKey
    };
    expect(parseOrganizationCandidateMaterializationGateArgs([
      "--verify-outcome",
      `--legacy-user-id=${legacyUserId}`,
      `--expected-revision=${revision}`,
      `--expected-snapshot-fingerprint=${snapshotFingerprint}`
    ], env)).toMatchObject({
      verifyOutcome: true,
      apply: false,
      legacyUserId,
      expectedRevision: revision,
      expectedSnapshotFingerprint: snapshotFingerprint,
      idempotencyKey
    });
    expect(() => parseOrganizationCandidateMaterializationGateArgs([
      "--verify-outcome",
      "--apply",
      `--legacy-user-id=${legacyUserId}`,
      `--expected-revision=${revision}`,
      `--expected-snapshot-fingerprint=${snapshotFingerprint}`
    ], env)).toThrow("mutually exclusive");
    expect(() => parseOrganizationCandidateMaterializationGateArgs([
      "--verify-outcome",
      `--legacy-user-id=${legacyUserId}`,
      `--expected-revision=${revision}`
    ], env)).toThrow("--verify-outcome requires --expected-snapshot-fingerprint");
    expect(() => parseOrganizationCandidateMaterializationGateArgs([
      "--verify-outcome",
      `--legacy-user-id=${legacyUserId}`,
      `--expected-revision=${revision}`,
      `--expected-snapshot-fingerprint=${snapshotFingerprint}`
    ], { IDENTITY_IAM_INTERNAL_API_TOKEN: internalToken })).toThrow(idempotencyKeyEnv);
  });

  it("applies only after a clean preflight, then proves fresh zero alignment and the exact completed ledger row", async () => {
    const fetcher = fixtureFetch({ apply: true });
    const result = await runOrganizationCandidateMaterializationGate(options(true), fetcher);

    expect(result).toMatchObject({
      passed: true,
      mode: "apply",
      applyAttempted: true,
      outcomeUnknown: false,
      postcheckIncomplete: false,
      freshRevision: revision,
      operation: {
        httpStatus: 201,
        materialized: true,
        idempotentReplay: false,
        operationKeyDigest,
        idempotencyKeyDigest: sha256(idempotencyKey),
        organizationCount: 1,
        before: { aligned: false, P0: 0, P1: 1, P2: 0, mismatch: 1 },
        after: { aligned: true, P0: 0, P1: 0, P2: 0, mismatch: 0 },
        safety: {
          legacyWritePerformed: false,
          identityCandidateWritePerformed: true,
          historicalMutationReplayed: false,
          legacyRemainsAuthoritative: true,
          authzInputChanged: false,
          writeScope: "identity-candidate-only"
        }
      },
      freshAlignment: { aligned: true, P0: 0, P1: 0, P2: 0, mismatch: 0 },
      ledgerAfter: {
        unresolvedOperationCount: 0,
        matchedOperation: {
          operationKeyDigest: fullOperationKeyDigest,
          idempotencyKeyDigest: sha256(idempotencyKey),
          mode: "candidate-materialization",
          status: "completed",
          legacyStatus: "read-only",
          identityStatus: "candidate-materialized",
          compensationStatus: "none",
          errorCode: null
        }
      },
      failures: []
    });
    const postCalls = fetcher.mock.calls.filter(([, init]) => init?.method === "POST");
    expect(postCalls).toHaveLength(1);
    expect(postCalls[0]?.[1]).toMatchObject({
      method: "POST",
      redirect: "error",
      headers: {
        "x-identity-internal-token": internalToken,
        "content-type": "application/json",
        "Idempotency-Key": idempotencyKey,
        "X-Identity-Expected-Revision": revision
      },
      body: JSON.stringify({ expectedSnapshotFingerprint: snapshotFingerprint })
    });
    expect(fetcher).toHaveBeenCalledTimes(11);
    for (const [, init] of fetcher.mock.calls) expect(init?.redirect).toBe("error");
    assertRedacted(result);
  });

  it.each(["redirect", "network ambiguity"])(
    "sends the candidate POST exactly once and never retries after %s",
    async (failureKind) => {
      const upstream = fixtureFetch({ apply: true });
      const fetcher = vi.fn(async (request: string | URL | Request, init?: RequestInit) => {
        if (init?.method === "POST") {
          expect(init.redirect).toBe("error");
          if (failureKind === "redirect") {
            return new Response(null, {
              status: 307,
              headers: { location: "https://example.invalid/should-not-be-followed" }
            });
          }
          throw new TypeError("connection closed after request bytes were sent");
        }
        return upstream(request, init);
      });

      const result = await runOrganizationCandidateMaterializationGate(options(true), fetcher);
      expect(result).toMatchObject({
        passed: false,
        mode: "apply",
        applyAttempted: true,
        outcomeUnknown: true,
        postcheckIncomplete: false,
        operation: {
          operationKeyDigest: null,
          idempotencyKeyDigest: sha256(idempotencyKey)
        },
        failures: ["candidate materialization POST outcome is unknown; do not retry automatically"]
      });
      const postCalls = fetcher.mock.calls.filter(([, init]) => init?.method === "POST");
      expect(postCalls).toHaveLength(1);
      expect(fetcher).toHaveBeenCalledTimes(7);
      for (const [, init] of fetcher.mock.calls) expect(init?.redirect).toBe("error");
      assertRedacted(result);
    }
  );

  it("returns non-ambiguous do-not-resend evidence when a fresh GET fails after HTTP 201", async () => {
    const upstream = fixtureFetch({ apply: true });
    let postReturned = false;
    const fetcher = vi.fn(async (request: string | URL | Request, init?: RequestInit) => {
      const url = String(request);
      if (postReturned && url.endsWith("/health")) throw new TypeError("rolling restart during postcheck");
      const response = await upstream(request, init);
      if (init?.method === "POST") postReturned = true;
      return response;
    });

    const result = await runOrganizationCandidateMaterializationGate(options(true), fetcher);
    expect(result).toMatchObject({
      passed: false,
      mode: "apply",
      applyAttempted: true,
      outcomeUnknown: false,
      postcheckIncomplete: true,
      operation: {
        httpStatus: 201,
        operationKeyDigest,
        idempotencyKeyDigest: sha256(idempotencyKey)
      },
      failures: ["candidate materialization POST returned 201 but postcheck is incomplete; do not resend POST"]
    });
    expect(fetcher.mock.calls.filter(([, init]) => init?.method === "POST")).toHaveLength(1);
    expect(fetcher).toHaveBeenCalledTimes(11);
    for (const [, init] of fetcher.mock.calls) expect(init?.redirect).toBe("error");
    assertRedacted(result);
  });

  it("fails closed without marking the known POST outcome ambiguous when the fresh build revision changed", async () => {
    const fetcher = fixtureFetch({ apply: true, postRevision: "f".repeat(40) });
    const result = await runOrganizationCandidateMaterializationGate(options(true), fetcher);

    expect(result).toMatchObject({
      passed: false,
      applyAttempted: true,
      outcomeUnknown: false,
      postcheckIncomplete: false,
      freshRevision: "f".repeat(40)
    });
    expect(result.failures).toContain("fresh health revision assertion failed");
    expect(fetcher.mock.calls.filter(([, init]) => init?.method === "POST")).toHaveLength(1);
    assertRedacted(result);
  });

  it("does not POST when the live preview fingerprint differs from the explicitly reviewed value", async () => {
    const fetcher = fixtureFetch({ apply: true });
    const result = await runOrganizationCandidateMaterializationGate({
      ...options(true),
      expectedSnapshotFingerprint: "f".repeat(64)
    }, fetcher);

    expect(result).toMatchObject({ passed: false, mode: "apply", applyAttempted: false });
    expect(result.failures).toContain("preview reviewed snapshot fingerprint assertion failed");
    expect(fetcher.mock.calls.some(([, init]) => init?.method === "POST")).toBe(false);
    assertRedacted(result);
  });

  it("requires every preview and missing alignment organization count to exist and match exactly", async () => {
    const fetcher = fixtureFetch({ apply: false, preview: { organizationCount: undefined } });
    const result = await runOrganizationCandidateMaterializationGate(options(false), fetcher);

    expect(result).toMatchObject({ passed: false, applyAttempted: false });
    expect(result.failures).toEqual(expect.arrayContaining([
      "preview organization count assertion failed",
      "preview alignment organization count assertion failed",
      "preflight alignment organization count assertion failed"
    ]));
    expect(fetcher.mock.calls.some(([, init]) => init?.method === "POST")).toBe(false);
    assertRedacted(result);
  });

  it("does not sanitize away a contradictory reason on a zero alignment", async () => {
    const fetcher = fixtureFetch({ apply: true, postAlignment: { reason: "contradictory-completed-reason" } });
    const result = await runOrganizationCandidateMaterializationGate(options(true), fetcher);

    expect(result).toMatchObject({
      passed: false,
      operation: { after: { reason: "unexpected-non-null" } },
      freshAlignment: { reason: "unexpected-non-null" }
    });
    expect(result.failures).toEqual(expect.arrayContaining([
      "apply after alignment reason assertion failed",
      "fresh alignment reason assertion failed"
    ]));
    assertRedacted(result);
  });

  it("treats any malformed unrelated recent row as unresolved and fails closed", async () => {
    const fetcher = fixtureFetch({
      apply: true,
      additionalRecentOperations: [{
        operationKeyDigest: "short",
        idempotencyKeyDigest: null,
        legacyUserId: 0,
        mode: "unknown-mode",
        status: "unknown-status",
        compensationStatus: "unknown-compensation",
        requestedAt: "not-a-timestamp",
        completedAt: null,
        metadata: []
      }]
    });
    const result = await runOrganizationCandidateMaterializationGate(options(true), fetcher);

    expect(result).toMatchObject({
      passed: false,
      ledgerAfter: { recentOperationCount: 2, unresolvedOperationCount: expect.any(Number) }
    });
    expect((result as any).ledgerAfter.unresolvedOperationCount).toBeGreaterThan(0);
    expect(result.failures).toEqual(expect.arrayContaining([
      "fresh ledger recent operation 1 operation digest assertion failed",
      "fresh ledger recent operation 1 idempotency digest assertion failed",
      "fresh ledger recent operation 1 subject assertion failed",
      "fresh ledger recent operation 1 mode-specific state assertion failed"
    ]));
    assertRedacted(result);
  });

  it("fails closed when the summary total exceeds the complete limit-200 recent set", async () => {
    const fetcher = fixtureFetch({
      apply: true,
      postSummaryOperations: [{
        mode: "candidate-materialization",
        status: "completed",
        compensationStatus: "none",
        total: 2,
        firstRequestedAt: requestedAt,
        lastRequestedAt: requestedAt
      }]
    });
    const result = await runOrganizationCandidateMaterializationGate(options(true), fetcher);

    expect(result).toMatchObject({ passed: false, ledgerAfter: { operationCount: 2, recentOperationCount: 1 } });
    expect(result.failures).toContain("fresh ledger summary total/recent length assertion failed");
    expect((result as any).ledgerAfter.unresolvedOperationCount).toBeGreaterThan(0);
    assertRedacted(result);
  });

  it("rejects a terminal ledger row whose completion predates its request", async () => {
    const fetcher = fixtureFetch({
      apply: true,
      postOperation: {
        requestedAt: "2026-08-09T03:00:02.000Z",
        completedAt: "2026-08-09T03:00:01.000Z"
      }
    });
    const result = await runOrganizationCandidateMaterializationGate(options(true), fetcher);

    expect(result).toMatchObject({ passed: false, applyAttempted: true });
    expect(result.failures).toContain("fresh ledger recent operation 0 timestamp order assertion failed");
    expect((result as any).ledgerAfter.unresolvedOperationCount).toBeGreaterThan(0);
    assertRedacted(result);
  });

  it.each([operationKeyDigest, null, "g".repeat(64)])(
    "rejects a matched ledger row with invalid full digest %s and a crossed completion pair",
    async (invalidDigest) => {
      const fetcher = fixtureFetch({
        apply: true,
        postOperation: {
          operationKeyDigest: invalidDigest,
          identityStatus: "candidate-recovered-from-current-legacy",
          compensationStatus: "none"
        }
      });
      const result = await runOrganizationCandidateMaterializationGate(options(true), fetcher);

      expect(result).toMatchObject({ passed: false, applyAttempted: true });
      expect(result.failures).toEqual(expect.arrayContaining([
        "fresh ledger recent operation 0 operation digest assertion failed",
        "fresh ledger recent operation 0 mode-specific state assertion failed",
        "fresh ledger full operation digest assertion failed",
        "fresh ledger Identity/compensation pair assertion failed"
      ]));
      assertRedacted(result);
    }
  );

  it("verifies the restored posture using only health, readiness, and strict ledger GETs", async () => {
    const fetcher = fixtureFetch({
      apply: false,
      healthPosture: { candidateMaterializationTargetConfigured: false },
      readinessMaterialization: {
        targetConfigured: false,
        canPreview: false,
        canApply: false,
        blockers: ["target-not-configured", "candidate-materialization-disabled"]
      }
    });
    const result = await runOrganizationCandidateMaterializationGate({
      ...options(false),
      legacyUserId: 0,
      expectRestored: true
    }, fetcher);

    expect(result).toMatchObject({
      passed: true,
      mode: "expect-restored",
      applyAttempted: false,
      revision,
      posture: {
        mode: "disabled",
        routeIntegrationEnabled: false,
        dualWriteExecutionEnabled: false,
        candidateMaterializationEnabled: false,
        candidateMaterializationTargetConfigured: false,
        rolloutMode: "off",
        rolloutAllowlistCount: 0,
        rolloutPercentage: 0
      },
      readiness: {
        repositoryConfigured: true,
        materialization: {
          enabled: false,
          targetConfigured: false,
          schemaReady: true,
          canPreview: false,
          canApply: false,
          blockerCount: 2,
          targetNotConfigured: true,
          candidateDisabled: true
        }
      },
      ledger: { operationCount: 0, recentOperationCount: 0, unresolvedOperationCount: 0 },
      failures: []
    });
    expect(fetcher).toHaveBeenCalledTimes(4);
    for (const [request, init] of fetcher.mock.calls) {
      const url = String(request);
      expect(init?.method).toBeUndefined();
      expect(init?.body).toBeUndefined();
      expect(init?.redirect).toBe("error");
      expect(url).not.toContain("/subjects/");
      expect(url).not.toContain("materialization-preview");
      expect(url).not.toContain("materialize-candidate");
    }
    assertRedacted(result);
  });

  it("fails restored verification when any unexpected materialization blocker remains", async () => {
    const fetcher = fixtureFetch({
      apply: false,
      healthPosture: { candidateMaterializationTargetConfigured: false },
      readinessMaterialization: {
        targetConfigured: false,
        canPreview: false,
        canApply: false,
        blockers: [
          "target-not-configured",
          "candidate-materialization-disabled",
          "role-write-unsafe"
        ]
      }
    });
    const result = await runOrganizationCandidateMaterializationGate({
      ...options(false),
      legacyUserId: 0,
      expectRestored: true
    }, fetcher);

    expect(result).toMatchObject({ passed: false, applyAttempted: false });
    expect(result.failures).toContain("restored readiness materialization blockers assertion failed");
    assertRedacted(result);
  });

  it("proves a completed outcome after restoration using only exact subject, alignment, and ledger GET evidence", async () => {
    const fetcher = restoredFixtureFetch({ initiallyApplied: true });
    const result = await runOrganizationCandidateMaterializationGate(verificationOptions(), fetcher);

    expect(result).toMatchObject({
      passed: true,
      mode: "verify-outcome",
      applyAttempted: false,
      outcomeUnknown: false,
      postcheckIncomplete: false,
      revision,
      target: {
        fingerprint: targetFingerprint,
        snapshotFingerprint,
        organizationCount: 1
      },
      alignment: { aligned: true, P0: 0, P1: 0, P2: 0, mismatch: 0, reason: null, organizationCount: 1 },
      operation: {
        operationKeyDigest: fullOperationKeyDigest,
        idempotencyKeyDigest: sha256(idempotencyKey),
        mode: "candidate-materialization",
        status: "completed",
        legacyStatus: "read-only",
        identityStatus: "candidate-materialized",
        compensationStatus: "none",
        errorCode: null
      },
      ledger: { operationCount: 1, recentOperationCount: 1, unresolvedOperationCount: 0 },
      failures: []
    });
    expect(fetcher).toHaveBeenCalledTimes(5);
    for (const [request, init] of fetcher.mock.calls) {
      const url = String(request);
      expect(init?.method).toBeUndefined();
      expect(init?.body).toBeUndefined();
      expect(init?.redirect).toBe("error");
      expect(url).not.toContain("materialization-preview");
      expect(url).not.toContain("materialize-candidate");
    }
    expect(fetcher.mock.calls.some(([, init]) => init?.method === "POST")).toBe(false);
    assertRedacted(result);
  });

  it.each([
    ["missing", { initiallyApplied: false }, "outcome verification matching operation count assertion failed"],
    ["pending", {
      initiallyApplied: true,
      postOperation: {
        status: "pending",
        identityStatus: "pending",
        compensationStatus: "none",
        errorCode: null,
        completedAt: null
      }
    }, "outcome verification ledger unresolved operation count assertion failed"],
    ["failed recovery-required", {
      initiallyApplied: true,
      postOperation: {
        status: "failed",
        identityStatus: "candidate-write-outcome-unknown",
        compensationStatus: "required",
        errorCode: "CandidateWriteUnknown"
      }
    }, "outcome verification found recovery-required state; stop and obtain separate recovery approval"],
    ["multiple matching", {
      initiallyApplied: true,
      additionalRecentOperations: [{
        operationKeyDigest: "f".repeat(64),
        idempotencyKeyDigest: sha256(idempotencyKey),
        requestFingerprintDigest: sha256(snapshotFingerprint),
        legacyUserId,
        mode: "candidate-materialization",
        status: "completed",
        legacyStatus: "read-only",
        identityStatus: "candidate-materialized",
        compensationStatus: "none",
        errorCode: null,
        requestedAt,
        completedAt,
        metadata: {
          legacyWritePerformed: false,
          snapshotFingerprint: sha256(snapshotFingerprint).slice(0, 16),
          targetFingerprint,
          organizationCount: 1
        }
      }]
    }, "outcome verification matching operation count assertion failed"]
  ])("fails closed without POST for a %s outcome", async (_label, fixtureInput, expectedFailure) => {
    const fetcher = restoredFixtureFetch(fixtureInput);
    const result = await runOrganizationCandidateMaterializationGate(verificationOptions(), fetcher);

    expect(result).toMatchObject({
      passed: false,
      mode: "verify-outcome",
      applyAttempted: false,
      outcomeUnknown: true,
      postcheckIncomplete: false
    });
    expect(result.failures).toContain(expectedFailure);
    expect(result.failures).toContain("outcome verification did not prove completion; do not resend POST automatically");
    expect(fetcher.mock.calls.some(([, init]) => init?.method === "POST")).toBe(false);
    assertRedacted(result);
  });

  it("returns redacted no-resend evidence when outcome verification GETs are incomplete", async () => {
    const upstream = restoredFixtureFetch({ initiallyApplied: true });
    const fetcher = vi.fn(async (request: string | URL | Request, init?: RequestInit) => {
      if (String(request).endsWith("/alignment")) throw new TypeError("verification transport failure");
      return upstream(request, init);
    });
    const result = await runOrganizationCandidateMaterializationGate(verificationOptions(), fetcher);

    expect(result).toMatchObject({
      passed: false,
      mode: "verify-outcome",
      applyAttempted: false,
      outcomeUnknown: true,
      postcheckIncomplete: true,
      operation: { idempotencyKeyDigest: sha256(idempotencyKey) },
      failures: ["outcome verification is incomplete; do not resend POST automatically"]
    });
    expect(fetcher.mock.calls.filter(([, init]) => init?.method === "POST")).toHaveLength(0);
    for (const [, init] of fetcher.mock.calls) expect(init?.redirect).toBe("error");
    assertRedacted(result);
  });

  it("does not echo a malformed ledger identity status during outcome verification", async () => {
    const sentinel = "sensitive-malformed-ledger-status";
    const fetcher = restoredFixtureFetch({
      initiallyApplied: true,
      postOperation: { identityStatus: sentinel }
    });
    const result = await runOrganizationCandidateMaterializationGate(verificationOptions(), fetcher);

    expect(result).toMatchObject({ passed: false, operation: { identityStatus: "unexpected-non-null" } });
    expect(JSON.stringify(result)).not.toContain(sentinel);
    assertRedacted(result);
  });

  it("fails closed after POST if any safety, fresh alignment, or completed-ledger assertion fails", async () => {
    const fetcher = fixtureFetch({
      apply: true,
      applySafety: { authzInputChanged: true },
      postAlignment: { aligned: false, P1: 1, mismatch: 1 },
      postOperation: {
        status: "failed",
        legacyStatus: "mutated",
        identityStatus: "candidate-write-outcome-unknown",
        compensationStatus: "required",
        errorCode: "WRITE_FAILED",
        metadata: { legacyWritePerformed: true }
      }
    });
    const result = await runOrganizationCandidateMaterializationGate(options(true), fetcher);

    expect(result).toMatchObject({ passed: false, applyAttempted: true });
    expect(result.failures).toEqual(expect.arrayContaining([
      "apply safety AuthZ input assertion failed",
      "fresh alignment aligned assertion failed",
      "fresh alignment P1 assertion failed",
      "fresh alignment mismatch assertion failed",
      "fresh ledger unresolved operation count assertion failed",
      "fresh ledger operation status assertion failed",
      "fresh ledger Legacy status assertion failed",
      "fresh ledger Identity status assertion failed",
      "fresh ledger compensation status assertion failed",
      "fresh ledger error code assertion failed",
      "fresh ledger legacy write safety assertion failed"
    ]));
    assertRedacted(result);
  });
});

function options(apply: boolean): OrganizationCandidateMaterializationGateOptions {
  return {
    adapterUrl: "http://127.0.0.1:8086",
    token: internalToken,
    legacyUserId,
    apply,
    expectedRevision: revision,
    expectedSnapshotFingerprint: apply ? snapshotFingerprint : undefined,
    idempotencyKey: apply ? idempotencyKey : null,
    sinceMinutes: 60
  };
}

function verificationOptions(): OrganizationCandidateMaterializationGateOptions {
  return { ...options(true), apply: false, verifyOutcome: true };
}

type FixtureFetchInput = {
  apply: boolean;
  healthPosture?: Record<string, unknown>;
  readinessMaterialization?: Record<string, unknown>;
  preview?: Record<string, unknown>;
  applySafety?: Record<string, unknown>;
  postAlignment?: Record<string, unknown>;
  postOperation?: Record<string, unknown>;
  postRevision?: string;
  additionalRecentOperations?: Record<string, unknown>[];
  postSummaryOperations?: Record<string, unknown>[];
  initiallyApplied?: boolean;
};

function restoredFixtureFetch(input: Omit<FixtureFetchInput, "apply"> = {}) {
  const { healthPosture, readinessMaterialization, ...rest } = input;
  return fixtureFetch({
    ...rest,
    apply: false,
    healthPosture: {
      candidateMaterializationTargetConfigured: false,
      ...healthPosture
    },
    readinessMaterialization: {
      targetConfigured: false,
      canPreview: false,
      canApply: false,
      blockers: ["target-not-configured", "candidate-materialization-disabled"],
      ...readinessMaterialization
    }
  });
}

function fixtureFetch(input: FixtureFetchInput) {
  let applied = input.initiallyApplied === true;
  const missingAlignment = {
    legacyUserId,
    aligned: false,
    mismatch: 1,
    P0: 0,
    P1: 1,
    P2: 0,
    reason: "identity-candidate-snapshot-missing",
    sourceOfTruth: "legacy",
    legacySnapshotFingerprint: snapshotFingerprint,
    organizationCount: 1
  };
  const zeroAlignment = {
    legacyUserId,
    aligned: true,
    mismatch: 0,
    P0: 0,
    P1: 0,
    P2: 0,
    sourceOfTruth: "legacy",
    legacySnapshotFingerprint: snapshotFingerprint,
    organizationCount: 1,
    ...input.postAlignment
  };
  const organizationWrite = {
    mode: "disabled",
    routeIntegrationEnabled: false,
    dualWriteExecutionEnabled: false,
    candidateMaterializationEnabled: input.apply,
    candidateMaterializationTargetConfigured: true,
    candidateBatchMaterializationEnabled: false,
    candidateBatchMaterializationEnvironment: "disabled",
    rolloutMode: "off",
    rolloutAllowlistCount: 0,
    rolloutPercentage: 0,
    sourceOfTruth: "legacy",
    identityNativeSupported: false,
    ...input.healthPosture
  };
  const materialization = {
    enabled: input.apply,
    targetConfigured: true,
    schemaReady: true,
    canPreview: true,
    canApply: input.apply,
    blockers: input.apply ? [] : ["candidate-materialization-disabled"],
    requiresInternalToken: true,
    requiresExpectedSnapshotFingerprint: true,
    requiresIdempotencyKey: true,
    sourceOfTruth: "legacy",
    mutatesLegacy: false,
    writeScope: "identity-candidate-only",
    ...input.readinessMaterialization
  };
  const readiness = {
    enabled: false,
    mode: "disabled",
    routeIntegrationEnabled: false,
    route: "/v1/plugin-user/update-user",
    scope: "membership-replace",
    sourceOfTruth: "legacy",
    repositoryConfigured: true,
    dualWriteExecutionEnabled: false,
    candidateMaterialization: materialization,
    candidateBatchMaterialization: {
      enabled: false,
      environment: "disabled",
      canApply: false,
      protectedSubjectsWritten: false
    },
    identityNativeSupported: false,
    rollout: { mode: "off", allowlistCount: 0, percentage: 0, selectionConfigured: false },
    blockedReasons: []
  };
  const preview = {
    mutation: false,
    executable: input.apply,
    targetFingerprint,
    expectedSnapshotFingerprint: snapshotFingerprint,
    organizationCount: 1,
    alignment: summaryAlignment(missingAlignment),
    unresolvedOperationCount: 0,
    sourceOfTruth: "legacy",
    legacyWritePerformed: false,
    identityCandidateWritePerformed: false,
    blockedReasons: input.apply ? [] : ["candidate-materialization-disabled"],
    ...input.preview
  };
  const completedOperation = {
    operationKeyDigest: fullOperationKeyDigest,
    idempotencyKeyDigest: sha256(idempotencyKey),
    requestFingerprintDigest: sha256(snapshotFingerprint),
    legacyUserId,
    mode: "candidate-materialization",
    status: "completed",
    legacyStatus: "read-only",
    identityStatus: "candidate-materialized",
    compensationStatus: "none",
    errorCode: null,
    requestedAt,
    completedAt,
    metadata: {
      legacyWritePerformed: false,
      snapshotFingerprint: sha256(snapshotFingerprint).slice(0, 16),
      targetFingerprint,
      organizationCount: 1
    },
    ...input.postOperation
  };
  const postOperations = [completedOperation, ...(input.additionalRecentOperations ?? [])];

  return vi.fn(async (request: string | URL | Request, init?: RequestInit) => {
    const url = String(request);
    if (url.endsWith("/health")) {
      return json({
        status: "ok",
        service: "identity-adapter",
        revision: applied ? input.postRevision ?? revision : revision,
        capabilities: { organizationWrite }
      });
    }
    if (url.endsWith("/readiness")) return internal("iam-organization-write", readiness);
    if (url.endsWith("/materialization-preview")) {
      return internal("iam-organization-candidate-materialization-preview", preview);
    }
    if (url.endsWith("/alignment")) {
      return internal("iam-organization-write-subject-alignment", applied ? zeroAlignment : missingAlignment);
    }
    if (url.includes("/operations/summary")) {
      return internal("iam-organization-write-operation-ledger", {
        configured: true,
        schemaReady: true,
        sinceMinutes: 60,
        operations: applied ? input.postSummaryOperations ?? summarizeOperations(postOperations) : []
      });
    }
    if (url.includes("/operations/recent")) {
      return internal("iam-organization-write-operation-ledger", {
        configured: true,
        schemaReady: true,
        sinceMinutes: 60,
        limit: 200,
        operations: applied ? postOperations : []
      });
    }
    if (url.endsWith("/materialize-candidate") && init?.method === "POST") {
      applied = true;
      return internal("iam-organization-candidate-materialization", {
        materialized: true,
        idempotentReplay: false,
        operationKeyDigest,
        subjectFingerprint: targetFingerprint,
        snapshotFingerprint: sha256(snapshotFingerprint).slice(0, 16),
        organizationCount: 1,
        before: summaryAlignment(missingAlignment),
        after: summaryAlignment(zeroAlignment),
        safety: {
          legacyWritePerformed: false,
          identityCandidateWritePerformed: true,
          historicalMutationReplayed: false,
          legacyRemainsAuthoritative: true,
          authzInputChanged: false,
          writeScope: "identity-candidate-only",
          ...input.applySafety
        }
      }, 201);
    }
    return json({ code: "NOT_FOUND" }, 404);
  });
}

function summaryAlignment(value: Record<string, unknown>) {
  return {
    aligned: value.aligned,
    mismatch: value.mismatch,
    P0: value.P0,
    P1: value.P1,
    P2: value.P2,
    reason: value.reason ?? null,
    organizationCount: value.organizationCount
  };
}

function summarizeOperations(operations: Record<string, unknown>[]) {
  const groups = new Map<string, {
    mode: unknown;
    status: unknown;
    compensationStatus: unknown;
    total: number;
    firstRequestedAt: string;
    lastRequestedAt: string;
  }>();
  for (const operation of operations) {
    const groupKey = [operation.mode, operation.status, operation.compensationStatus].join("\u0000");
    const operationRequestedAt = typeof operation.requestedAt === "string" ? operation.requestedAt : requestedAt;
    const existing = groups.get(groupKey);
    if (existing) {
      existing.total += 1;
      if (operationRequestedAt < existing.firstRequestedAt) existing.firstRequestedAt = operationRequestedAt;
      if (operationRequestedAt > existing.lastRequestedAt) existing.lastRequestedAt = operationRequestedAt;
    } else {
      groups.set(groupKey, {
        mode: operation.mode,
        status: operation.status,
        compensationStatus: operation.compensationStatus,
        total: 1,
        firstRequestedAt: operationRequestedAt,
        lastRequestedAt: operationRequestedAt
      });
    }
  }
  return [...groups.values()];
}

function internal(capability: string, data: unknown, status = 200): Response {
  return json({ status: "ok", service: "identity-adapter", capability, data }, status);
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function assertRedacted(result: unknown): void {
  const serialized = JSON.stringify(result);
  expect(serialized).not.toContain(internalToken);
  expect(serialized).not.toContain(idempotencyKey);
  expect(serialized).not.toContain(String(legacyUserId));
}
