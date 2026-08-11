import { createHash, generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import {
  ORGANIZATION_RECONCILIATION_DEVELOP_ATTESTATION_COLLECTOR_METADATA_CONTRACT,
  ORGANIZATION_RECONCILIATION_DEVELOP_ATTESTATION_REQUESTS_CONTRACT,
  assembleOrganizationReconciliationDevelopAttestationBundle,
  createOrganizationReconciliationDevelopAttestationRequests,
  type CreateOrganizationReconciliationDevelopAttestationRequestsOptions,
  type OrganizationReconciliationDevelopAttestationCollectorMetadata,
  type OrganizationReconciliationDevelopAttestationRequestSet,
  type OrganizationReconciliationDevelopAttestationSignatureResponse
} from "../src/iam-organization-reconciliation-develop-attestation-requests.js";
import {
  requestOrganizationReconciliationDevelopHashOnlySignatures,
  type OrganizationReconciliationDevelopFullRangeExternalSigner
} from "../src/iam-organization-reconciliation-develop-full-range.js";
import {
  createOrganizationReconciliationProvenanceBindingFromInput,
  createOrganizationReconciliationTrustPolicySha256,
  serializeOrganizationReconciliationProvenancePayload,
  verifyOrganizationReconciliationProvenance,
  type OrganizationReconciliationTrustPolicy
} from "../src/iam-organization-reconciliation-provenance.js";
import {
  createOrganizationReconciliationCollectedSnapshot,
  createOrganizationReconciliationEvidenceHash,
  ORGANIZATION_RECONCILIATION_COLLECTOR_CONTRACT,
  ORGANIZATION_RECONCILIATION_COLLECTOR_CONTRACT_HASH,
  ORGANIZATION_RECONCILIATION_DECISION_DERIVATION_CONTRACT,
  type OrganizationReconciliationInput
} from "../src/iam-organization-reconciliation-validator.js";
import {
  IDENTITY_ORGANIZATION_SURFACE_PROJECTOR_CONTRACT,
  LEGACY_ORGANIZATION_SURFACE_PROJECTOR_CONTRACT,
  ORGANIZATION_SURFACE_PROJECTION_BINDING_CONTRACT
} from "../src/iam-organization-reconciliation-projector-contract.js";
import {
  attachTestOrganizationReconciliationComponentManifest
} from "./fixtures/iam-organization-reconciliation-component-manifest.js";
import {
  createOrganizationReconciliationPolicyForTest,
  createOrganizationReconciliationTrustedProfileForTest,
  TEST_COLLECTOR_BUILD_REVISION,
  TEST_DEPLOYMENT_EVIDENCE_SHA256
} from "./iam-organization-reconciliation-provenance.test-fixture.js";

describe("Develop external-attestation signing requests", () => {
  it("sends only the exact canonical hash payload to every compiled signer identity", async () => {
    const fixture = requestFixture();
    const requestSet = createOrganizationReconciliationDevelopAttestationRequests(fixture.options);
    const observed = new Map<string, Buffer>();
    const transmittedViews = new Map<string, Uint8Array>();
    const signers = new Map<string, OrganizationReconciliationDevelopFullRangeExternalSigner>(
      fixture.policy.requiredCollectors.map((collector, index) => [collector.keyId, Object.freeze({
        collectorId: collector.collectorId,
        nodeId: collector.nodeId,
        keyId: collector.keyId,
        publicKeySha256: collector.publicKeySha256,
        buildRevision: collector.buildRevision,
        sign: (bytes: Uint8Array) => {
          expect(bytes.byteOffset).toBe(0);
          expect(bytes.buffer.byteLength).toBe(bytes.byteLength);
          transmittedViews.set(collector.keyId, bytes);
          const copy = Buffer.from(bytes);
          observed.set(collector.keyId, copy);
          return sign(null, copy, fixture.privateKeys[index]!);
        }
      })])
    );

    const responses = await requestOrganizationReconciliationDevelopHashOnlySignatures(
      requestSet,
      signers
    );
    expect(responses).toHaveLength(1);
    for (const request of requestSet.requests) {
      expect(observed.get(request.keyId)).toEqual(
        Buffer.from(request.payloadBytesBase64url, "base64url")
      );
      expect([...transmittedViews.get(request.keyId)!]).toEqual(
        Array(request.payloadBytesBase64url.length === 0 ? 0 :
          Buffer.from(request.payloadBytesBase64url, "base64url").length).fill(0)
      );
    }
    const bundle = assembleOrganizationReconciliationDevelopAttestationBundle(
      requestSet,
      responses
    );
    expect(verifyOrganizationReconciliationProvenance(
      createOrganizationReconciliationProvenanceBindingFromInput(
        fixture.input,
        TEST_DEPLOYMENT_EVIDENCE_SHA256
      ),
      {
        trustPolicy: fixture.policy,
        trustedProfile: createOrganizationReconciliationTrustedProfileForTest(fixture.policy),
        attestationBundle: bundle,
        expectedDeploymentEvidenceSha256: TEST_DEPLOYMENT_EVIDENCE_SHA256,
        now: new Date("2026-08-09T00:10:00.000Z")
      }
    )).toMatchObject({ verified: true, verifiedAttestationCount: 1 });
  });

  it("fails before bundle construction when a signer is missing or throws", async () => {
    const missingFixture = requestFixture();
    const missingSet = createOrganizationReconciliationDevelopAttestationRequests(
      missingFixture.options
    );
    await expect(requestOrganizationReconciliationDevelopHashOnlySignatures(
      missingSet,
      new Map()
    )).rejects.toMatchObject({ failureId: "signer-not-provisioned" });

    const throwingFixture = requestFixture();
    const throwingSet = createOrganizationReconciliationDevelopAttestationRequests(
      throwingFixture.options
    );
    let signerAttempted = false;
    const throwingSigners = new Map<string, OrganizationReconciliationDevelopFullRangeExternalSigner>(
      throwingFixture.policy.requiredCollectors.map((collector) => [collector.keyId, Object.freeze({
        collectorId: collector.collectorId,
        nodeId: collector.nodeId,
        keyId: collector.keyId,
        publicKeySha256: collector.publicKeySha256,
        buildRevision: collector.buildRevision,
        sign: async () => {
          signerAttempted = true;
          throw new Error("external signer unavailable");
        }
      })])
    );
    await expect(requestOrganizationReconciliationDevelopHashOnlySignatures(
      throwingSet,
      throwingSigners
    )).rejects.toMatchObject({ failureId: "signer-failed" });
    expect(signerAttempted).toBe(true);
  });

  it("creates one canonical Develop request and assembles a verifier-accepted bundle", () => {
    const fixture = requestFixture();
    const requestSet = createOrganizationReconciliationDevelopAttestationRequests(fixture.options);

    expect(requestSet).toMatchObject({
      contract: ORGANIZATION_RECONCILIATION_DEVELOP_ATTESTATION_REQUESTS_CONTRACT,
      algorithm: "Ed25519",
      profileId: fixture.policy.profileId,
      environment: fixture.policy.environment,
      trustPolicySha256: createOrganizationReconciliationTrustPolicySha256(fixture.policy),
      issuedAt: "2026-08-09T00:06:30.000Z",
      expiresAt: "2026-08-09T00:15:00.000Z"
    });
    expect(requestSet.requests).toHaveLength(1);
    expect(fixture.now).toHaveBeenCalledTimes(1);
    expect(Object.isFrozen(requestSet)).toBe(true);
    expect(Object.isFrozen(requestSet.requests)).toBe(true);
    for (const request of requestSet.requests) {
      const exactBytes = Buffer.from(request.payloadBytesBase64url, "base64url");
      expect(exactBytes).toEqual(serializeOrganizationReconciliationProvenancePayload(request.payload));
      expect(createHash("sha256").update(exactBytes).digest("hex")).toBe(request.payloadSha256);
      expect(request.payload).toMatchObject({
        collectorId: request.collectorId,
        nodeId: request.nodeId,
        keyId: request.keyId,
        environment: fixture.policy.environment,
        profileId: fixture.policy.profileId,
        collectorBuildRevision: TEST_COLLECTOR_BUILD_REVISION,
        trustPolicySha256: requestSet.trustPolicySha256
      });
      expect(Object.isFrozen(request.payload)).toBe(true);
    }
    expect("verified" in requestSet).toBe(false);
    expect("ready" in requestSet).toBe(false);

    const bundle = assembleOrganizationReconciliationDevelopAttestationBundle(
      requestSet,
      validResponses(requestSet, fixture.privateKeys).reverse()
    );
    expect(Object.isFrozen(bundle)).toBe(true);
    expect(bundle.attestations).toHaveLength(1);
    expect(verifyOrganizationReconciliationProvenance(
      createOrganizationReconciliationProvenanceBindingFromInput(
        fixture.input,
        TEST_DEPLOYMENT_EVIDENCE_SHA256
      ),
      {
        trustPolicy: fixture.policy,
        trustedProfile: createOrganizationReconciliationTrustedProfileForTest(fixture.policy),
        attestationBundle: bundle,
        expectedDeploymentEvidenceSha256: TEST_DEPLOYMENT_EVIDENCE_SHA256,
        now: new Date("2026-08-09T00:10:00.000Z")
      }
    )).toMatchObject({ verified: true, code: "verified", verifiedAttestationCount: 1 });
    expect(() => assembleOrganizationReconciliationDevelopAttestationBundle(
      requestSet,
      validResponses(requestSet, fixture.privateKeys)
    )).toThrow("invalid-request-set");
  });

  it("keeps signature authenticity at the existing verifier boundary", () => {
    const fixture = requestFixture();
    const requestSet = createOrganizationReconciliationDevelopAttestationRequests(fixture.options);
    const structurallyValidResponses = requestSet.requests.map((request) => ({
      collectorId: request.collectorId,
      keyId: request.keyId,
      payloadSha256: request.payloadSha256,
      signature: Buffer.alloc(64)
    }));
    const bundle = assembleOrganizationReconciliationDevelopAttestationBundle(
      requestSet,
      structurallyValidResponses
    );
    expect(verifyOrganizationReconciliationProvenance(
      createOrganizationReconciliationProvenanceBindingFromInput(
        fixture.input,
        TEST_DEPLOYMENT_EVIDENCE_SHA256
      ),
      {
        trustPolicy: fixture.policy,
        trustedProfile: createOrganizationReconciliationTrustedProfileForTest(fixture.policy),
        attestationBundle: bundle,
        expectedDeploymentEvidenceSha256: TEST_DEPLOYMENT_EVIDENCE_SHA256,
        now: new Date("2026-08-09T00:10:00.000Z")
      }
    )).toMatchObject({ verified: false, code: "signature-invalid" });
  });

  it("rejects cloned or JSON-shaped request-set brands", async () => {
    for (const clone of ["spread", "structured", "json"] as const) {
      const fixture = requestFixture();
      const requestSet = createOrganizationReconciliationDevelopAttestationRequests(fixture.options);
      const candidate = clone === "spread"
        ? { ...requestSet }
        : clone === "structured"
          ? structuredClone(requestSet)
          : JSON.parse(JSON.stringify(requestSet));
      expect(() => assembleOrganizationReconciliationDevelopAttestationBundle(
        candidate as OrganizationReconciliationDevelopAttestationRequestSet,
        validResponses(requestSet, fixture.privateKeys)
      )).toThrow("invalid-request-set");
      await expect(requestOrganizationReconciliationDevelopHashOnlySignatures(
        candidate as OrganizationReconciliationDevelopAttestationRequestSet,
        new Map()
      )).rejects.toThrow("invalid-request-set");
    }
  });

  it("descriptor-captures options and nested policy values without invoking accessors", () => {
    const outerFixture = requestFixture();
    let outerGetterCalls = 0;
    const outer = { ...outerFixture.options } as Record<string, unknown>;
    Object.defineProperty(outer, "input", {
      enumerable: true,
      get: () => {
        outerGetterCalls += 1;
        return outerFixture.input;
      }
    });
    expect(() => createOrganizationReconciliationDevelopAttestationRequests(
      outer as unknown as CreateOrganizationReconciliationDevelopAttestationRequestsOptions
    )).toThrow("invalid-input");
    expect(outerGetterCalls).toBe(0);

    const nestedFixture = requestFixture();
    let nestedGetterCalls = 0;
    const collectors = nestedFixture.policy.requiredCollectors.map((collector) => ({ ...collector }));
    Object.defineProperty(collectors[0], "collectorId", {
      enumerable: true,
      get: () => {
        nestedGetterCalls += 1;
        return "forged-collector";
      }
    });
    expect(() => createOrganizationReconciliationDevelopAttestationRequests({
      ...nestedFixture.options,
      trustPolicy: { ...nestedFixture.policy, requiredCollectors: collectors }
    })).toThrow();
    expect(nestedGetterCalls).toBe(0);

    const clockFixture = requestFixture();
    let clockGetterCalls = 0;
    const clock = {} as Record<string, unknown>;
    Object.defineProperty(clock, "now", {
      enumerable: true,
      get: () => {
        clockGetterCalls += 1;
        return clockFixture.now;
      }
    });
    expect(() => createOrganizationReconciliationDevelopAttestationRequests({
      ...clockFixture.options,
      clock: clock as unknown as { now: () => Date }
    })).toThrow("invalid-input");
    expect(clockGetterCalls).toBe(0);
    expect(() => createOrganizationReconciliationDevelopAttestationRequests(
      new Proxy(clockFixture.options, {})
    )).toThrow("invalid-input");

    const clockValueFixture = requestFixture();
    const clockValue = new Date("2026-08-09T00:06:30.000Z");
    let getTimeGetterCalls = 0;
    Object.defineProperty(clockValue, "getTime", {
      get: () => {
        getTimeGetterCalls += 1;
        return () => clockValue.getTime();
      }
    });
    expect(() => createOrganizationReconciliationDevelopAttestationRequests({
      ...clockValueFixture.options,
      clock: { now: () => clockValue }
    })).toThrow("invalid-clock-window");
    expect(getTimeGetterCalls).toBe(0);
  });

  it.each([
    "missing-collector",
    "extra-collector",
    "wrong-collector",
    "wrong-node",
    "wrong-key",
    "wrong-fingerprint",
    "wrong-build",
    "wrong-profile",
    "wrong-environment",
    "wrong-policy-pin",
    "non-full-build"
  ] as const)("rejects strict policy/metadata binding failure: %s", (mode) => {
    const fixture = requestFixture();
    const policy = structuredClone(fixture.policy) as OrganizationReconciliationTrustPolicy;
    const metadata = structuredClone(fixture.metadata) as MutableMetadata;
    const first = policy.requiredCollectors[0]!;
    if (mode === "missing-collector") policy.requiredCollectors.length = 0;
    if (mode === "extra-collector") policy.requiredCollectors.push({
      ...first,
      collectorId: "extra-collector",
      nodeId: "extra-node",
      keyId: "extra-key",
      publicKeySha256: "e".repeat(64)
    });
    if (mode === "wrong-collector") metadata.collectors[0]!.collectorId = "wrong-collector";
    if (mode === "wrong-node") metadata.collectors[0]!.nodeId = "wrong-node";
    if (mode === "wrong-key") metadata.collectors[0]!.keyId = "wrong-key";
    if (mode === "wrong-fingerprint") metadata.collectors[0]!.publicKeySha256 = "e".repeat(64);
    if (mode === "wrong-build") metadata.collectors[0]!.buildRevision = "b".repeat(40);
    if (mode === "wrong-profile") metadata.profileId = "other-profile";
    if (mode === "wrong-environment") metadata.environment = "other-environment";
    if (mode === "wrong-policy-pin") metadata.trustPolicySha256 = "0".repeat(64);
    if (mode === "non-full-build") first.buildRevision = "abc";
    expect(() => createOrganizationReconciliationDevelopAttestationRequests({
      ...fixture.options,
      trustPolicy: policy,
      collectorMetadata: metadata
    })).toThrow();
    expect(fixture.now).not.toHaveBeenCalled();
  });

  it.each([
    "duplicate",
    "missing",
    "extra",
    "wrong-collector",
    "wrong-key",
    "wrong-payload-hash",
    "short-signature",
    "proxy-signature",
    "response-accessor"
  ] as const)("fails closed on signature response set: %s", (mode) => {
    const fixture = requestFixture();
    const requestSet = createOrganizationReconciliationDevelopAttestationRequests(fixture.options);
    const responses = validResponses(requestSet, fixture.privateKeys) as MutableResponse[];
    let getterCalls = 0;
    if (mode === "duplicate") responses[1] = responses[0]!;
    if (mode === "missing") responses.pop();
    if (mode === "extra") responses.push({ ...responses[0]! });
    if (mode === "wrong-collector") responses[0]!.collectorId = "other-collector";
    if (mode === "wrong-key") responses[0]!.keyId = "other-key";
    if (mode === "wrong-payload-hash") responses[0]!.payloadSha256 = "0".repeat(64);
    if (mode === "short-signature") responses[0]!.signature = Buffer.alloc(63);
    if (mode === "proxy-signature") responses[0]!.signature = new Proxy(Buffer.alloc(64), {});
    if (mode === "response-accessor") {
      Object.defineProperty(responses[0], "signature", {
        enumerable: true,
        get: () => {
          getterCalls += 1;
          return Buffer.alloc(64);
        }
      });
    }
    expect(() => assembleOrganizationReconciliationDevelopAttestationBundle(
      requestSet,
      responses
    )).toThrow("invalid-signature-responses");
    expect(getterCalls).toBe(0);
    expect(() => assembleOrganizationReconciliationDevelopAttestationBundle(
      requestSet,
      validResponses(requestSet, fixture.privateKeys)
    )).toThrow("invalid-request-set");
  });

  it("rejects A+B signature splicing by exact payload hash", () => {
    const fixtureA = requestFixture("organization-a");
    const fixtureB = requestFixture("organization-b");
    const requestsA = createOrganizationReconciliationDevelopAttestationRequests(fixtureA.options);
    const requestsB = createOrganizationReconciliationDevelopAttestationRequests(fixtureB.options);
    expect(requestsA.requests[0]!.payloadSha256).not.toBe(requestsB.requests[0]!.payloadSha256);
    expect(() => assembleOrganizationReconciliationDevelopAttestationBundle(
      requestsA,
      validResponses(requestsB, fixtureB.privateKeys)
    )).toThrow("invalid-signature-responses");
  });

  it("rejects incomplete input and a clock/TTL window outside policy", () => {
    const incomplete = requestFixture();
    const { effectiveDecisions: _effectiveDecisions, ...missingSurface } = incomplete.input;
    expect(() => createOrganizationReconciliationDevelopAttestationRequests({
      ...incomplete.options,
      input: missingSurface
    })).toThrow("invalid-input");

    for (const clockOrTtl of [
      { clock: { now: () => new Date("2026-08-08T23:59:59.000Z") }, attestationTtlSeconds: 510 },
      { clock: { now: () => new Date("2026-08-09T00:06:30.000Z") }, attestationTtlSeconds: 601 },
      { clock: { now: () => new Date("invalid") }, attestationTtlSeconds: 510 }
    ]) {
      const fixture = requestFixture();
      expect(() => createOrganizationReconciliationDevelopAttestationRequests({
        ...fixture.options,
        ...clockOrTtl
      })).toThrow();
    }
  });

  it.each(["string", "key", "cumulative"] as const)(
    "rejects canonical input byte bound overflow: %s",
    (mode) => {
      const fixture = requestFixture();
      let input: OrganizationReconciliationInput;
      const withLegacyOrganizationRecord = (record: object): OrganizationReconciliationInput => ({
        ...fixture.input,
        organizationDirectory: {
          ...fixture.input.organizationDirectory!,
          legacy: {
            ...fixture.input.organizationDirectory!.legacy,
            records: [record]
          }
        }
      } as OrganizationReconciliationInput);
      if (mode === "string") {
        input = withLegacyOrganizationRecord({
          ...(fixture.input.organizationDirectory!.legacy!.records[0] as object),
          name: "x".repeat(65_537)
        });
      } else if (mode === "key") {
        input = withLegacyOrganizationRecord({
          ...(fixture.input.organizationDirectory!.legacy!.records[0] as object),
          ["k".repeat(257)]: true
        });
      } else {
        const repeated = "z".repeat(65_536);
        input = {
          ...fixture.input,
          organizationDirectory: Array.from({ length: 1_025 }, () => repeated)
        } as unknown as OrganizationReconciliationInput;
      }
      expect(() => createOrganizationReconciliationDevelopAttestationRequests({
        ...fixture.options,
        input
      })).toThrow("invalid-input");
      expect(fixture.now).not.toHaveBeenCalled();
    }
  );
});

interface MutableResponse extends Omit<OrganizationReconciliationDevelopAttestationSignatureResponse, "signature"> {
  collectorId: string;
  keyId: string;
  payloadSha256: string;
  signature: Uint8Array;
}

type MutableMetadata = {
  -readonly [K in keyof OrganizationReconciliationDevelopAttestationCollectorMetadata]:
    K extends "collectors" ? Array<{
      -readonly [P in keyof OrganizationReconciliationDevelopAttestationCollectorMetadata["collectors"][number]]:
        OrganizationReconciliationDevelopAttestationCollectorMetadata["collectors"][number][P]
    }> : OrganizationReconciliationDevelopAttestationCollectorMetadata[K]
};

function requestFixture(organizationName = "private-organization") {
  const input = completedInput(organizationName);
  const keys = [generateKeyPairSync("ed25519")];
  const basePolicy = createOrganizationReconciliationPolicyForTest(keys.map(({ publicKey }, index) => ({
    collectorId: `trusted-collector-${index + 1}`,
    nodeId: `trusted-node-${index + 1}`,
    keyId: `trusted-key-${index + 1}`,
    publicKey
  })));
  const policy = { ...basePolicy, environment: "xrteeth-develop" };
  const metadata = collectorMetadata(policy);
  const now = vi.fn(() => new Date("2026-08-09T00:06:30.000Z"));
  const options: CreateOrganizationReconciliationDevelopAttestationRequestsOptions = {
    input,
    trustPolicy: policy,
    collectorMetadata: metadata,
    clock: { now },
    attestationTtlSeconds: 510
  };
  return {
    input,
    policy,
    metadata,
    now,
    options,
    privateKeys: keys.map(({ privateKey }) => privateKey)
  } as const;
}

function collectorMetadata(
  policy: OrganizationReconciliationTrustPolicy
): OrganizationReconciliationDevelopAttestationCollectorMetadata {
  return {
    contract: ORGANIZATION_RECONCILIATION_DEVELOP_ATTESTATION_COLLECTOR_METADATA_CONTRACT,
    profileId: policy.profileId,
    environment: policy.environment,
    trustPolicySha256: createOrganizationReconciliationTrustPolicySha256(policy),
    deploymentEvidenceSha256: TEST_DEPLOYMENT_EVIDENCE_SHA256,
    collectors: policy.requiredCollectors.map((collector) => ({
      collectorId: collector.collectorId,
      nodeId: collector.nodeId,
      keyId: collector.keyId,
      publicKeySha256: collector.publicKeySha256,
      buildRevision: collector.buildRevision
    }))
  };
}

function validResponses(
  requestSet: OrganizationReconciliationDevelopAttestationRequestSet,
  privateKeys: readonly KeyObject[]
): MutableResponse[] {
  return requestSet.requests.map((request, index) => ({
    collectorId: request.collectorId,
    keyId: request.keyId,
    payloadSha256: request.payloadSha256,
    signature: sign(null, Buffer.from(request.payloadBytesBase64url, "base64url"), privateKeys[index]!)
  }));
}

function completedInput(organizationName: string): OrganizationReconciliationInput {
  const initial = attachTestOrganizationReconciliationComponentManifest(baseInput(organizationName));
  const manifest = initial.componentManifest!;
  const legacy = manifest.components.find((component) => component.componentId === "legacy-main")!;
  const identity = manifest.components.find((component) => component.componentId === "identity")!;
  const plugin = manifest.components.find((component) => component.componentId === "plugin")!;
  const { componentManifest: _componentManifest, ...evidence } = initial;
  return attachTestOrganizationReconciliationComponentManifest({
    ...evidence,
    projectionBinding: {
      contract: ORGANIZATION_SURFACE_PROJECTION_BINDING_CONTRACT,
      semanticRegistrySha256: "1".repeat(64),
      lineageManifestSha256: manifest.parentLineageManifestSha256,
      legacy: {
        projectorContract: LEGACY_ORGANIZATION_SURFACE_PROJECTOR_CONTRACT,
        evaluatorId: "legacy-test-evaluator",
        evaluatorBuildSha256: "3".repeat(64),
        primarySource: { sourceVersion: legacy.sourceVersion, snapshotId: legacy.snapshotId }
      },
      identity: {
        projectorContract: IDENTITY_ORGANIZATION_SURFACE_PROJECTOR_CONTRACT,
        evaluatorId: "identity-test-evaluator",
        evaluatorBuildSha256: "4".repeat(64),
        primarySource: { sourceVersion: identity.sourceVersion, snapshotId: identity.snapshotId }
      },
      pluginSource: { sourceVersion: plugin.sourceVersion, snapshotId: plugin.snapshotId }
    }
  });
}

function baseInput(organizationName: string): OrganizationReconciliationInput {
  const pair = <T>(records: readonly T[]) => ({
    legacy: createOrganizationReconciliationCollectedSnapshot(EVIDENCE_NONCE, "legacy-v1", "legacy-snapshot", [
      { requestCursor: null, nextCursor: null, records }
    ]),
    identity: createOrganizationReconciliationCollectedSnapshot(EVIDENCE_NONCE, "identity-v1", "identity-snapshot", [
      { requestCursor: null, nextCursor: null, records }
    ])
  });
  return {
    collectionEnvelope: {
      collectorContract: ORGANIZATION_RECONCILIATION_COLLECTOR_CONTRACT,
      collectorContractHash: ORGANIZATION_RECONCILIATION_COLLECTOR_CONTRACT_HASH,
      collectorBuildRevision: TEST_COLLECTOR_BUILD_REVISION,
      evidenceNonce: EVIDENCE_NONCE,
      logicalSnapshotId: "private-logical-snapshot",
      windowId: "private-window",
      windowStartedAt: "2026-08-09T00:05:00.000Z",
      windowEndedAt: "2026-08-09T00:06:00.000Z",
      legacy: envelopeSide("legacy-v1", "legacy-snapshot"),
      identity: envelopeSide("identity-v1", "identity-snapshot")
    },
    organizationDirectory: pair([{ legacyOrganizationId: 1, name: organizationName, title: null, active: true }]),
    organizationMappings: pair([{
      legacyOrganizationId: 1, identityOrganizationId: "identity-org-1", active: true
    }]),
    memberships: pair([{ subjectRef: "legacy-user:581", legacyOrganizationId: 1, active: true }]),
    organizationScopedRoles: pair([{
      subjectRef: "legacy-user:581", legacyOrganizationId: 1, roleRef: "role:test", active: true
    }]),
    pluginBindings: pair([{
      pluginRef: "plugin:test", bindingRef: "binding:test", organizationRef: ORGANIZATION_REF, active: true
    }]),
    pluginVisibility: pair([{
      subjectRef: "legacy-user:581", pluginRef: "plugin:test", organizationRef: ORGANIZATION_REF,
      decision: "allow" as const
    }]),
    campusContexts: pair(CONTEXTS.map(([contextKind, contextRef], index) => ({
      subjectRef: "legacy-user:581", contextKind, contextRef,
      decision: index === 0 ? "allow" as const : "deny" as const
    }))),
    effectiveDecisions: pair(CONTEXTS.map(([contextKind, contextRef], index) => ({
      subjectRef: "legacy-user:581", contextKind, contextRef,
      resourceRef: "resource:test", capabilityRef: "capability:test",
      decision: index === 0 ? "allow" as const : "deny" as const
    })))
  };
}

function envelopeSide(sourceVersion: string, snapshotId: string) {
  return {
    sourceVersion,
    snapshotId,
    subjectUniverse: { subjectCount: 1, subjectsHash: SUBJECT_UNIVERSE_HASH },
    decisionUniverses: {
      pluginVisibility: decisionUniverse(
        [["legacy-user:581", "plugin:test", ORGANIZATION_REF]],
        { subjects: ["legacy-user:581"], plugins: ["plugin:test"], organizations: [ORGANIZATION_REF] }
      ),
      campusContexts: decisionUniverse(
        CONTEXTS.map(([kind, ref]) => ["legacy-user:581", kind, ref]),
        { subjects: ["legacy-user:581"], contexts: CONTEXT_DIMENSIONS }
      ),
      effectiveDecisions: decisionUniverse(
        CONTEXTS.map(([kind, ref]) => [
          "legacy-user:581", kind, ref, "resource:test", "capability:test"
        ]),
        {
          subjects: ["legacy-user:581"],
          contexts: CONTEXT_DIMENSIONS,
          resources: ["resource:test"],
          capabilities: ["capability:test"],
          rulePairs: [JSON.stringify(["resource:test", "capability:test"])]
        }
      )
    }
  };
}

function decisionUniverse(
  keys: readonly (readonly string[])[],
  dimensions: Readonly<Record<string, readonly string[]>>
) {
  const canonicalKeys = [...new Set(keys.map((key) => JSON.stringify(key)))].sort();
  return {
    keyCount: canonicalKeys.length,
    keysHash: createOrganizationReconciliationEvidenceHash(EVIDENCE_NONCE, canonicalKeys),
    derivationContract: ORGANIZATION_RECONCILIATION_DECISION_DERIVATION_CONTRACT,
    derivationBuildRevision: TEST_COLLECTOR_BUILD_REVISION,
    dimensions: Object.fromEntries(Object.entries(dimensions).map(([name, values]) => {
      const sorted = [...new Set(values)].sort();
      return [name, {
        count: sorted.length,
        hash: createOrganizationReconciliationEvidenceHash(EVIDENCE_NONCE, sorted)
      }];
    }))
  } as const;
}

const EVIDENCE_NONCE = "c3".repeat(32);
const ORGANIZATION_REF = "legacy-org:1";
const CONTEXTS = [
  ["organization", ORGANIZATION_REF],
  ["platform-global", "org:platform-global"],
  ["public", "org:public"]
] as const;
const CONTEXT_DIMENSIONS = CONTEXTS.map((context) => JSON.stringify(context));
const SUBJECT_UNIVERSE_HASH = createOrganizationReconciliationEvidenceHash(
  EVIDENCE_NONCE,
  ["legacy-user:581"]
);
