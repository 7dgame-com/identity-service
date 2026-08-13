import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import {
  parseOrganizationIdentityNativeWindowGateArgs,
  runOrganizationIdentityNativeWindowGate,
  type OrganizationIdentityNativeWindowGateOptions
} from "../../../scripts/iam-organization-identity-native-window-gate.js";

const revision = "17f83c15855cdab4e3e4d779f5d8b99a1645ed4d";
const beforeFingerprint = "a".repeat(64);
const afterFingerprint = "b".repeat(64);

describe("IAM organization Identity-native one-shot window gate", () => {
  it("is read-only by default and reports only digests/counts", async () => {
    const fetcher = fixtureFetch();
    const output = await runOrganizationIdentityNativeWindowGate(options(), fetcher);

    expect(output).toMatchObject({
      passed: true,
      mode: "preview",
      applyAttempted: false,
      outcomeUnknown: false,
      beforeFingerprint,
      afterFingerprint: null,
      organizationCount: 1,
      failures: []
    });
    expect(JSON.stringify(output)).not.toContain("test-internal-token");
    expect(JSON.stringify(output)).not.toContain("test-operator-token");
    expect(JSON.stringify(output)).not.toContain("native-idempotency-key");
    expect(fetcher).toHaveBeenCalledTimes(7);
    expect(fetcher.mock.calls.filter(([url, init]) =>
      init?.method === "POST" && String(url).endsWith("/v1/plugin-user/update-user")
    )).toHaveLength(0);
  });

  it("performs at most one native POST and proves the exact candidate and ledger outcome", async () => {
    const fetcher = fixtureFetch();
    const output = await runOrganizationIdentityNativeWindowGate({ ...options(), apply: true }, fetcher);

    expect(output).toMatchObject({
      passed: true,
      mode: "apply",
      applyAttempted: true,
      outcomeUnknown: false,
      beforeFingerprint,
      afterFingerprint,
      operation: {
        idempotencyKeyDigest: expect.stringMatching(/^[a-f0-9]{64}$/),
        operationKeyDigest: nativeOperationKeyDigest(24, "native-idempotency-key-v1"),
        requestFingerprintDigest: nativeRequestFingerprintDigest(24, [2])
      },
      failures: []
    });
    const posts = fetcher.mock.calls.filter(([url, init]) =>
      init?.method === "POST" && String(url).endsWith("/v1/plugin-user/update-user")
    );
    expect(posts).toHaveLength(1);
    expect(posts[0]?.[0]).toBe("http://127.0.0.1:8086/v1/plugin-user/update-user");
    expect(posts[0]?.[1]).toMatchObject({
      redirect: "error",
      headers: {
        authorization: "Bearer test-operator-token",
        "content-type": "application/json",
        "idempotency-key": "native-idempotency-key-v1",
        "x-identity-expected-revision": revision
      },
      body: JSON.stringify({ id: 24, organization_ids: [2] })
    });
  });

  it("never retries an unknown POST outcome", async () => {
    const fetcher = fixtureFetch({ failPost: true });
    const output = await runOrganizationIdentityNativeWindowGate({ ...options(), apply: true }, fetcher);

    expect(output).toMatchObject({
      passed: false,
      applyAttempted: true,
      outcomeUnknown: true,
      failures: ["Identity-native POST outcome is unknown; do not retry automatically"]
    });
    expect(fetcher.mock.calls.filter(([url, init]) =>
      init?.method === "POST" && String(url).endsWith("/v1/plugin-user/update-user")
    )).toHaveLength(1);
  });

  it("blocks POST when the reviewed before digest no longer matches", async () => {
    const fetcher = fixtureFetch();
    const output = await runOrganizationIdentityNativeWindowGate({
      ...options(),
      apply: true,
      expectedBeforeFingerprint: "d".repeat(64)
    }, fetcher);

    expect(output.passed).toBe(false);
    expect(output.applyAttempted).toBe(false);
    expect(output.failures).toContain(
      `preflight candidate fingerprint expected ${"d".repeat(64)}, got ${beforeFingerprint}`
    );
    expect(fetcher.mock.calls.filter(([url, init]) =>
      init?.method === "POST" && String(url).endsWith("/v1/plugin-user/update-user")
    )).toHaveLength(0);
  });

  it("takes all secrets and organization IDs only from the environment and requires loopback", () => {
    const env = {
      IDENTITY_IAM_INTERNAL_API_TOKEN: "internal",
      IDENTITY_IAM_ORG_NATIVE_WINDOW_OPERATOR_BEARER_TOKEN: "operator",
      IDENTITY_IAM_ORG_NATIVE_WINDOW_IDEMPOTENCY_KEY: "idempotency-key-long-enough",
      IDENTITY_IAM_ORG_NATIVE_WINDOW_ORGANIZATION_IDS: "2,1,2"
    };
    expect(parseOrganizationIdentityNativeWindowGateArgs([
      "--apply",
      "--legacy-user-id=24",
      `--expected-revision=${revision}`,
      `--expected-before-fingerprint=${beforeFingerprint}`,
      `--expected-after-fingerprint=${afterFingerprint}`
    ], env)).toMatchObject({ organizationIds: [1, 2], apply: true });
    expect(() => parseOrganizationIdentityNativeWindowGateArgs([
      "--legacy-user-id=24",
      `--expected-revision=${revision}`,
      `--expected-before-fingerprint=${beforeFingerprint}`,
      "--token=secret"
    ], env)).toThrow("must be supplied through the reviewed environment variables");
    expect(() => parseOrganizationIdentityNativeWindowGateArgs([
      "--adapter-url=https://identity.example.invalid",
      "--legacy-user-id=24",
      `--expected-revision=${revision}`,
      `--expected-before-fingerprint=${beforeFingerprint}`
    ], env)).toThrow("origin-only HTTP loopback URL");
    expect(() => runOrganizationIdentityNativeWindowGate({ ...options(), organizationIds: [2, 2] }, fixtureFetch()))
      .rejects.toThrow("organizationIds must be sorted, unique, positive integers");
  });
});

function options(): OrganizationIdentityNativeWindowGateOptions {
  return {
    adapterUrl: "http://127.0.0.1:8086",
    internalToken: "test-internal-token",
    operatorBearerToken: "test-operator-token",
    idempotencyKey: "native-idempotency-key-v1",
    legacyUserId: 24,
    expectedRevision: revision,
    expectedBeforeFingerprint: beforeFingerprint,
    expectedAfterFingerprint: afterFingerprint,
    organizationIds: [2],
    expectedAllowlistCount: 1,
    sinceMinutes: 60,
    apply: false
  };
}

function fixtureFetch(input: { failPost?: boolean } = {}) {
  let applied = false;
  return vi.fn(async (request: string | URL | Request, init?: RequestInit) => {
    const url = String(request);
    if (url.endsWith("/identity-native-snapshot-preview")) return json({
      status: "ok",
      capability: "iam-organization-write-identity-native-snapshot-preview",
      data: {
        mutation: false,
        sourceOfTruth: "identity-candidate-catalog",
        organizationCount: 1,
        snapshotFingerprint: afterFingerprint
      }
    });
    if (init?.method === "POST" && url.endsWith("/v1/plugin-user/update-user")) {
      if (input.failPost) throw new Error("injected acknowledgement loss");
      applied = true;
      return json({ code: 0, data: { id: 24, organizations: [{ id: 2, name: "not-emitted", title: "not-emitted" }] } }, 200, {
        "x-identity-iam-organization-write": "identity-native",
        "x-identity-iam-organization-write-decision": "selected:allowlist",
        "x-identity-iam-organization-write-route": "membership-replace",
        "x-identity-iam-organization-write-target": sha256("legacy:24").slice(0, 16),
        "x-identity-iam-organization-write-selector-kind": "allowlist",
        "x-identity-iam-organization-write-identity-status": "completed"
      });
    }
    if (url.endsWith("/health")) return json({
      status: "ok",
      service: "identity-adapter",
      revision,
      capabilities: { organizationWrite: {
        mode: "identity-native",
        routeIntegrationEnabled: true,
        dualWriteExecutionEnabled: false,
        identityNativeExecutionEnabled: true,
        candidateMaterializationEnabled: false,
        candidateMaterializationTargetConfigured: false,
        candidateBatchMaterializationEnabled: false,
        candidateBatchMaterializationEnvironment: "disabled",
        recoveryDrillEnabled: false,
        recoveryDrillTargetConfigured: false,
        rolloutMode: "allowlist",
        rolloutAllowlistCount: 1,
        rolloutPercentage: 0,
        sourceOfTruth: "identity-candidate-selected-legacy-unselected",
        identityNativeSupported: true
      } }
    });
    if (url.endsWith("/readiness")) return json({ status: "ok", data: {
      mode: "identity-native",
      routeIntegrationEnabled: true,
      route: "/v1/plugin-user/update-user",
      scope: "membership-replace",
      sourceOfTruth: "identity-candidate-selected-legacy-unselected",
      recoveryDrill: { enabled: false, targetConfigured: false },
      rollout: { mode: "allowlist", allowlistCount: 1, percentage: 0, selectionConfigured: true },
      identityNativeGate: { executable: true }
    } });
    if (url.endsWith("/decision")) return json({ status: "ok", data: {
      mutation: false,
      mode: "identity-native",
      route: "/v1/plugin-user/update-user",
      scope: "membership-replace",
      targetFingerprint: "target-digest",
      selected: true,
      executable: true,
      decision: "selected:allowlist",
      sourceOfTruth: "identity-candidate-selected-legacy-unselected"
    } });
    if (url.endsWith("/candidate")) return json({ status: "ok", data: {
      mutation: false,
      sourceOfTruth: "identity-candidate",
      organizationCount: 1,
      snapshotFingerprint: applied ? afterFingerprint : beforeFingerprint
    } });
    if (url.includes("/operations/summary")) return json({ status: "ok", data: { configured: true, operations: [] } });
    if (url.includes("/operations/recent")) return json({ status: "ok", data: { configured: true, operations: applied ? [{
      operationKeyDigest: nativeOperationKeyDigest(24, "native-idempotency-key-v1"),
      idempotencyKeyDigest: sha256("native-idempotency-key-v1"),
      requestFingerprintDigest: nativeRequestFingerprintDigest(24, [2]),
      legacyUserId: 24,
      mode: "identity-native",
      status: "completed",
      legacyStatus: "not-called",
      identityStatus: "completed",
      compensationStatus: "none",
      errorCode: null,
      metadata: { owner: "identity", legacyWritePerformed: false, organizationCount: 1 }
    }] : [] } });
    return json({ code: "NOT_FOUND" }, 404);
  });
}

function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers }
  });
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function nativeOperationKeyDigest(legacyUserId: number, idempotencyKey: string): string {
  return sha256(`iam-organization-write:v1:membership-replace:${sha256(`${legacyUserId}\u001f${idempotencyKey}`).slice(0, 48)}`);
}

function nativeRequestFingerprintDigest(legacyUserId: number, organizationIds: number[]): string {
  return sha256(sha256(`${legacyUserId}\u001f${organizationIds.join(",")}`));
}
