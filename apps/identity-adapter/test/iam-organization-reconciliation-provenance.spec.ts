import { generateKeyPairSync, sign } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  createOrganizationReconciliationAttestationBundleForTest,
  createOrganizationReconciliationPolicyForTest,
  createOrganizationReconciliationTrustedProfileForTest,
  TEST_COLLECTOR_BUILD_REVISION
} from "./iam-organization-reconciliation-provenance.test-fixture.js";
import {
  createOrganizationReconciliationCollectedSnapshot,
  createOrganizationReconciliationEvidenceHash,
  ORGANIZATION_RECONCILIATION_COLLECTOR_CONTRACT,
  ORGANIZATION_RECONCILIATION_COLLECTOR_CONTRACT_HASH,
  ORGANIZATION_RECONCILIATION_DECISION_DERIVATION_CONTRACT,
  type OrganizationReconciliationInput,
  validateOrganizationReconciliation
} from "../src/iam-organization-reconciliation-validator.js";
import {
  createOrganizationReconciliationProvenanceBinding,
  ORGANIZATION_RECONCILIATION_PROVENANCE_CONTRACT,
  ORGANIZATION_RECONCILIATION_TRUST_POLICY_CONTRACT,
  serializeOrganizationReconciliationProvenancePayload,
  verifyOrganizationReconciliationProvenance,
  type OrganizationReconciliationTrustPolicy
} from "../src/iam-organization-reconciliation-provenance.js";

describe("trusted external provenance for organization reconciliation", () => {
  it("pins the v2 contracts and rejects a signature made for the v1 domain", () => {
    expect(ORGANIZATION_RECONCILIATION_PROVENANCE_CONTRACT)
      .toBe("iam-organization-reconciliation-provenance/v2");
    expect(ORGANIZATION_RECONCILIATION_TRUST_POLICY_CONTRACT)
      .toBe("iam-organization-reconciliation-trust-policy/v2");

    const fixture = provenanceFixture();
    const attestations = [...fixture.context.attestationBundle.attestations];
    const first = attestations[0]!;
    const v2Domain = Buffer.from("iam-organization-reconciliation:provenance:v2\u001f", "utf8");
    const v1Domain = Buffer.from("iam-organization-reconciliation:provenance:v1\u001f", "utf8");
    const v2Payload = serializeOrganizationReconciliationProvenancePayload(first.payload);
    expect(v2Payload.subarray(0, v2Domain.length)).toEqual(v2Domain);
    const v1Payload = Buffer.concat([v1Domain, v2Payload.subarray(v2Domain.length)]);
    attestations[0] = {
      ...first,
      signature: sign(null, v1Payload, fixture.privateKeys[0]!).toString("base64url")
    };

    expect(verifyOrganizationReconciliationProvenance(fixture.binding, {
      ...fixture.context,
      attestationBundle: { ...fixture.context.attestationBundle, attestations }
    })).toMatchObject({ verified: false, code: "signature-invalid", verifiedAttestationCount: 0 });
  });

  it("verifies complete aligned evidence but retains the compiled real-adapter blocker", () => {
    const fixture = provenanceFixture();
    const report = validateOrganizationReconciliation(fixture.input, {
      trustedProvenance: fixture.context
    });

    expect(report).toMatchObject({
      realSourceAdaptersReady: false,
      staticChecksPassed: false,
      assuranceScope: "collector-envelope-with-trusted-external-attestation",
      provenanceVerification: {
        verified: true,
        reasonCode: "verified",
        requiredAttestationCount: 2,
        verifiedAttestationCount: 2,
        trustProfileHash: expect.stringMatching(/^[a-f0-9]{24}$/),
        environmentHash: expect.stringMatching(/^[a-f0-9]{24}$/)
      },
      safetyGate: {
        passed: false,
        blocksDualWrite: true,
        externalProvenanceVerified: true,
        blockedReasons: ["coverage-incomplete"]
      }
    });
    expect(report.provenanceVerification.trustPolicyHash).toMatch(/^[a-f0-9]{24}$/);
    expectNoRawProvenance(report);
  });

  it("keeps the default path fail closed without any trusted context", () => {
    const report = validateOrganizationReconciliation(alignedInput());

    expect(report).toMatchObject({
      staticChecksPassed: false,
      provenanceVerification: {
        verified: false,
        reasonCode: "trusted-context-missing",
        requiredAttestationCount: 0,
        verifiedAttestationCount: 0
      },
      safetyGate: {
        passed: false,
        blocksDualWrite: true,
        externalProvenanceVerified: false,
        blockedReasons: ["coverage-incomplete", "external-provenance-required"]
      }
    });
  });

  it("rejects evidence changed after signing even when its internal HMAC chain is recomputed", () => {
    const fixture = provenanceFixture();
    const changed = alignedInput("changed-private-organization");
    const report = validateOrganizationReconciliation(changed, { trustedProvenance: fixture.context });

    expect(report.staticChecksPassed).toBe(false);
    expect(report.provenanceVerification.reasonCode).toBe("attestation-binding-mismatch");
    expect(report.safetyGate).toMatchObject({
      passed: false,
      externalProvenanceVerified: false,
      blockedReasons: ["coverage-incomplete", "external-provenance-required"]
    });
    expect(JSON.stringify(report)).not.toContain("changed-private-organization");
  });

  it("rejects a changed collector build even when the evidence is otherwise complete", () => {
    const fixture = provenanceFixture();
    const changedBuildInput: OrganizationReconciliationInput = {
      ...fixture.input,
      collectionEnvelope: {
        ...fixture.input.collectionEnvelope!,
        collectorBuildRevision: "b".repeat(40)
      }
    };
    const report = validateOrganizationReconciliation(changedBuildInput, {
      trustedProvenance: fixture.context
    });
    expect(report.provenanceVerification.reasonCode).toBe("attestation-binding-mismatch");
    expect(report.safetyGate.passed).toBe(false);
  });

  it("rejects a self-selected policy, a missing required node, and an invalid signature", () => {
    const fixture = provenanceFixture();
    const wrongPin = verifyOrganizationReconciliationProvenance(fixture.binding, {
      ...fixture.context,
      trustedProfile: { ...fixture.context.trustedProfile, policySha256: "0".repeat(64) }
    });
    expect(wrongPin).toMatchObject({ verified: false, code: "trust-policy-pin-mismatch" });

    expect(verifyOrganizationReconciliationProvenance(fixture.binding, {
      ...fixture.context,
      trustedProfile: {
        ...fixture.context.trustedProfile,
        expectedEnvironment: "wrong-production-environment"
      }
    })).toMatchObject({ verified: false, code: "trust-profile-mismatch" });

    expect(verifyOrganizationReconciliationProvenance(fixture.binding, {
      ...fixture.context,
      trustedProfile: {
        ...fixture.context.trustedProfile,
        profileId: "wrong-production-profile"
      }
    })).toMatchObject({ verified: false, code: "trust-profile-mismatch" });

    const missingNode = verifyOrganizationReconciliationProvenance(fixture.binding, {
      ...fixture.context,
      attestationBundle: {
        ...fixture.context.attestationBundle,
        attestations: [fixture.context.attestationBundle.attestations[0]!]
      }
    });
    expect(missingNode).toMatchObject({ verified: false, code: "attestation-set-invalid" });

    const attestations = [...fixture.context.attestationBundle.attestations];
    attestations[1] = { ...attestations[1]!, signature: "A".repeat(86) };
    const invalidSignature = verifyOrganizationReconciliationProvenance(fixture.binding, {
      ...fixture.context,
      attestationBundle: { ...fixture.context.attestationBundle, attestations }
    });
    expect(invalidSignature).toMatchObject({
      verified: false,
      code: "signature-invalid",
      verifiedAttestationCount: 1
    });
  });

  it("requires at least two distinct collectors, nodes, keys, and public-key fingerprints", () => {
    const fixture = provenanceFixture();
    const first = fixture.context.trustPolicy.requiredCollectors[0]!;

    const oneCollectorPolicy: OrganizationReconciliationTrustPolicy = {
      ...fixture.context.trustPolicy,
      requiredCollectors: [first]
    };
    expect(verifyOrganizationReconciliationProvenance(fixture.binding, {
      ...fixture.context,
      trustPolicy: oneCollectorPolicy,
      trustedProfile: {
        ...fixture.context.trustedProfile,
        requiredCollectors: [fixture.context.trustedProfile.requiredCollectors[0]!]
      }
    })).toMatchObject({ verified: false, code: "trusted-context-invalid" });

    const duplicateCollectorPolicy: OrganizationReconciliationTrustPolicy = {
      ...fixture.context.trustPolicy,
      requiredCollectors: fixture.context.trustPolicy.requiredCollectors.map((collector, index) =>
        index === 1 ? { ...collector, collectorId: first.collectorId } : collector
      )
    };
    const duplicateCollectorBundle = createOrganizationReconciliationAttestationBundleForTest(
      fixture.binding,
      duplicateCollectorPolicy,
      fixture.privateKeys.map((privateKey, index) => ({ keyId: `trusted-key-${index + 1}`, privateKey }))
    );
    expect(verifyOrganizationReconciliationProvenance(fixture.binding, {
      ...fixture.context,
      trustPolicy: duplicateCollectorPolicy,
      trustedProfile: createOrganizationReconciliationTrustedProfileForTest(duplicateCollectorPolicy),
      attestationBundle: duplicateCollectorBundle
    })).toMatchObject({ verified: false, code: "collector-policy-invalid" });

    const duplicateNodePolicy: OrganizationReconciliationTrustPolicy = {
      ...fixture.context.trustPolicy,
      requiredCollectors: fixture.context.trustPolicy.requiredCollectors.map((collector, index) =>
        index === 1 ? { ...collector, nodeId: first.nodeId } : collector
      )
    };
    const duplicateNodeBundle = createOrganizationReconciliationAttestationBundleForTest(
      fixture.binding,
      duplicateNodePolicy,
      fixture.privateKeys.map((privateKey, index) => ({ keyId: `trusted-key-${index + 1}`, privateKey }))
    );
    expect(verifyOrganizationReconciliationProvenance(fixture.binding, {
      ...fixture.context,
      trustPolicy: duplicateNodePolicy,
      trustedProfile: createOrganizationReconciliationTrustedProfileForTest(duplicateNodePolicy),
      attestationBundle: duplicateNodeBundle
    })).toMatchObject({ verified: false, code: "collector-policy-invalid" });

    const duplicateKeyPolicy: OrganizationReconciliationTrustPolicy = {
      ...fixture.context.trustPolicy,
      requiredCollectors: fixture.context.trustPolicy.requiredCollectors.map((collector, index) =>
        index === 1
          ? { ...collector, publicKeyPem: first.publicKeyPem, publicKeySha256: first.publicKeySha256 }
          : collector
      )
    };
    const duplicateKeyBundle = createOrganizationReconciliationAttestationBundleForTest(
      fixture.binding,
      duplicateKeyPolicy,
      [
        { keyId: "trusted-key-1", privateKey: fixture.privateKeys[0]! },
        { keyId: "trusted-key-2", privateKey: fixture.privateKeys[0]! }
      ]
    );
    expect(verifyOrganizationReconciliationProvenance(fixture.binding, {
      ...fixture.context,
      trustPolicy: duplicateKeyPolicy,
      trustedProfile: createOrganizationReconciliationTrustedProfileForTest(duplicateKeyPolicy),
      attestationBundle: duplicateKeyBundle
    })).toMatchObject({ verified: false, code: "collector-policy-invalid" });
  });

  it("requires the complete evidence window to fall inside both policy and signer validity", () => {
    const fixture = provenanceFixture();
    const policyStartsMidWindow: OrganizationReconciliationTrustPolicy = {
      ...fixture.context.trustPolicy,
      validFrom: "2026-08-09T00:05:30.000Z",
      requiredCollectors: fixture.context.trustPolicy.requiredCollectors.map((collector) => ({
        ...collector,
        validFrom: "2026-08-09T00:05:30.000Z"
      }))
    };
    const policyWindowBundle = createOrganizationReconciliationAttestationBundleForTest(
      fixture.binding,
      policyStartsMidWindow,
      fixture.privateKeys.map((privateKey, index) => ({ keyId: `trusted-key-${index + 1}`, privateKey }))
    );
    expect(verifyOrganizationReconciliationProvenance(fixture.binding, {
      ...fixture.context,
      trustPolicy: policyStartsMidWindow,
      trustedProfile: createOrganizationReconciliationTrustedProfileForTest(policyStartsMidWindow),
      attestationBundle: policyWindowBundle
    })).toMatchObject({ verified: false, code: "evidence-window-invalid" });

    const keyStartsMidWindow: OrganizationReconciliationTrustPolicy = {
      ...fixture.context.trustPolicy,
      requiredCollectors: fixture.context.trustPolicy.requiredCollectors.map((collector, index) =>
        index === 0 ? { ...collector, validFrom: "2026-08-09T00:05:30.000Z" } : collector
      )
    };
    const keyWindowBundle = createOrganizationReconciliationAttestationBundleForTest(
      fixture.binding,
      keyStartsMidWindow,
      fixture.privateKeys.map((privateKey, index) => ({ keyId: `trusted-key-${index + 1}`, privateKey }))
    );
    expect(verifyOrganizationReconciliationProvenance(fixture.binding, {
      ...fixture.context,
      trustPolicy: keyStartsMidWindow,
      trustedProfile: createOrganizationReconciliationTrustedProfileForTest(keyStartsMidWindow),
      attestationBundle: keyWindowBundle
    })).toMatchObject({ verified: false, code: "attestation-window-invalid" });
  });

  it("never lets a valid external attestation override a changed per-side revision or P0 gate", () => {
    const revisionInput = alignedInput();
    const revisionMismatch: OrganizationReconciliationInput = {
      ...revisionInput,
      collectionEnvelope: {
        ...revisionInput.collectionEnvelope!,
        identity: {
          ...revisionInput.collectionEnvelope!.identity,
          sourceVersion: "different-private-source-version"
        }
      }
    };
    const revisionFixture = provenanceFixture(revisionMismatch);
    const revisionReport = validateOrganizationReconciliation(revisionMismatch, {
      trustedProvenance: revisionFixture.context
    });
    expect(revisionReport.provenanceVerification.verified).toBe(true);
    expect(revisionReport.coverageBlockers).toEqual(expect.arrayContaining([
      { surface: "organization-directory", code: "source-version-envelope-mismatch", side: "identity" },
      { surface: "effective-decision", code: "source-version-envelope-mismatch", side: "identity" }
    ]));
    expect(revisionReport.safetyGate).toMatchObject({
      passed: false,
      blocksDualWrite: true,
      externalProvenanceVerified: true,
      blockedReasons: ["coverage-incomplete"]
    });

    const unsafeInput = alignedInput();
    const unsafeDecisions = unsafeInput.effectiveDecisions!;
    const legacyDecision = unsafeDecisions.legacy!.records[0]!;
    const p0Input: OrganizationReconciliationInput = {
      ...unsafeInput,
      effectiveDecisions: {
        legacy: createOrganizationReconciliationCollectedSnapshot(
          EVIDENCE_NONCE,
          LEGACY_SOURCE_VERSION,
          LEGACY_SNAPSHOT,
          [{
            requestCursor: null,
            nextCursor: null,
            records: [{ ...legacyDecision, decision: "deny" as const }]
          }]
        ),
        identity: unsafeDecisions.identity
      }
    };
    const p0Fixture = provenanceFixture(p0Input);
    const p0Report = validateOrganizationReconciliation(p0Input, { trustedProvenance: p0Fixture.context });
    expect(p0Report.provenanceVerification.verified).toBe(true);
    expect(p0Report.severity.P0).toBe(1);
    expect(p0Report.safetyGate).toMatchObject({
      passed: false,
      blocksDualWrite: true,
      blockedReasons: ["coverage-incomplete", "p0-findings"]
    });
  });

  it("rejects stale evidence, expired attestations, and a non-public-key policy", () => {
    const fixture = provenanceFixture();
    expect(verifyOrganizationReconciliationProvenance(fixture.binding, {
      ...fixture.context,
      now: new Date("2026-08-09T00:17:00.000Z")
    })).toMatchObject({ verified: false, code: "evidence-window-invalid" });

    expect(verifyOrganizationReconciliationProvenance(fixture.binding, {
      ...fixture.context,
      now: new Date("2026-08-09T00:16:00.000Z")
    })).toMatchObject({ verified: false, code: "attestation-window-invalid" });

    const fingerprintPolicy: OrganizationReconciliationTrustPolicy = {
      ...fixture.context.trustPolicy,
      requiredCollectors: fixture.context.trustPolicy.requiredCollectors.map((collector, index) =>
        index === 0 ? { ...collector, publicKeySha256: "0".repeat(64) } : collector
      )
    };
    const fingerprintBundle = createOrganizationReconciliationAttestationBundleForTest(
      fixture.binding,
      fingerprintPolicy,
      fixture.privateKeys.map((privateKey, index) => ({ keyId: `trusted-key-${index + 1}`, privateKey }))
    );
    expect(verifyOrganizationReconciliationProvenance(fixture.binding, {
      ...fixture.context,
      trustPolicy: fingerprintPolicy,
      trustedProfile: createOrganizationReconciliationTrustedProfileForTest(fingerprintPolicy),
      attestationBundle: fingerprintBundle
    })).toMatchObject({ verified: false, code: "collector-key-invalid" });

    const privatePem = fixture.privateKeys[0]!.export({ format: "pem", type: "pkcs8" }).toString();
    const unsafePolicy: OrganizationReconciliationTrustPolicy = {
      ...fixture.context.trustPolicy,
      requiredCollectors: fixture.context.trustPolicy.requiredCollectors.map((collector, index) =>
        index === 0 ? { ...collector, publicKeyPem: privatePem } : collector
      )
    };
    const unsafeBundle = createOrganizationReconciliationAttestationBundleForTest(
      fixture.binding,
      unsafePolicy,
      fixture.privateKeys.map((privateKey, index) => ({ keyId: `trusted-key-${index + 1}`, privateKey }))
    );
    expect(verifyOrganizationReconciliationProvenance(fixture.binding, {
      ...fixture.context,
      trustPolicy: unsafePolicy,
      trustedProfile: createOrganizationReconciliationTrustedProfileForTest(unsafePolicy),
      attestationBundle: unsafeBundle
    })).toMatchObject({ verified: false, code: "collector-key-invalid" });
  });

  it("assembles only a complete, ordered, terminal cursor chain", () => {
    const snapshot = createOrganizationReconciliationCollectedSnapshot(
      EVIDENCE_NONCE,
      LEGACY_SOURCE_VERSION,
      "legacy-snapshot",
      [
        { requestCursor: null, nextCursor: "cursor-2", records: [{ value: "first" }] },
        { requestCursor: "cursor-2", nextCursor: null, records: [{ value: "second" }] }
      ]
    );

    expect(snapshot).toMatchObject({
      sourceVersion: LEGACY_SOURCE_VERSION,
      nextCursor: null,
      collection: {
        firstCursor: null,
        pageCount: 2,
        recordCount: 2,
        pages: [
          { pageNumber: 1, requestCursor: null, nextCursor: "cursor-2", recordOffset: 0, recordCount: 1 },
          { pageNumber: 2, requestCursor: "cursor-2", nextCursor: null, recordOffset: 1, recordCount: 1 }
        ]
      }
    });
    expect(() => createOrganizationReconciliationCollectedSnapshot(
      EVIDENCE_NONCE,
      LEGACY_SOURCE_VERSION,
      "legacy-snapshot",
      [{ requestCursor: null, nextCursor: "not-terminal", records: [] }]
    )).toThrow(/complete cursor chain/);
    expect(() => createOrganizationReconciliationCollectedSnapshot(
      EVIDENCE_NONCE,
      LEGACY_SOURCE_VERSION,
      "legacy-snapshot",
      [
        { requestCursor: null, nextCursor: "cursor-2", records: [] },
        { requestCursor: "wrong-cursor", nextCursor: null, records: [] }
      ]
    )).toThrow(/complete cursor chain/);
  });
});

function provenanceFixture(input: OrganizationReconciliationInput = alignedInput()) {
  const binding = bindingFor(input);
  const keys = [generateKeyPairSync("ed25519"), generateKeyPairSync("ed25519")];
  const policy = createOrganizationReconciliationPolicyForTest(keys.map(({ publicKey }, index) => ({
    collectorId: `trusted-collector-${index + 1}`,
    nodeId: `trusted-node-${index + 1}`,
    keyId: `trusted-key-${index + 1}`,
    publicKey
  })));
  const attestationBundle = createOrganizationReconciliationAttestationBundleForTest(
    binding,
    policy,
    keys.map(({ privateKey }, index) => ({ keyId: `trusted-key-${index + 1}`, privateKey }))
  );
  return {
    input,
    binding,
    privateKeys: keys.map(({ privateKey }) => privateKey),
    context: {
      trustedProfile: createOrganizationReconciliationTrustedProfileForTest(policy),
      trustPolicy: policy,
      attestationBundle,
      now: new Date("2026-08-09T00:10:00.000Z")
    }
  };
}

function bindingFor(input: OrganizationReconciliationInput) {
  const envelope = input.collectionEnvelope!;
  return createOrganizationReconciliationProvenanceBinding(
    input,
    envelope.collectorContractHash,
    envelope.collectorBuildRevision,
    envelope.logicalSnapshotId,
    envelope.windowId,
    envelope.windowStartedAt,
    envelope.windowEndedAt
  );
}

function alignedInput(organizationName = "private-organization"): OrganizationReconciliationInput {
  const pair = <T>(records: readonly T[]) => ({
    legacy: createOrganizationReconciliationCollectedSnapshot(EVIDENCE_NONCE, LEGACY_SOURCE_VERSION, LEGACY_SNAPSHOT, [
      { requestCursor: null, nextCursor: null, records }
    ]),
    identity: createOrganizationReconciliationCollectedSnapshot(EVIDENCE_NONCE, IDENTITY_SOURCE_VERSION, IDENTITY_SNAPSHOT, [
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
      legacy: {
        sourceVersion: LEGACY_SOURCE_VERSION,
        snapshotId: LEGACY_SNAPSHOT,
        subjectUniverse: { subjectCount: 1, subjectsHash: SUBJECT_UNIVERSE_HASH },
        decisionUniverses: decisionUniverses(organizationName)
      },
      identity: {
        sourceVersion: IDENTITY_SOURCE_VERSION,
        snapshotId: IDENTITY_SNAPSHOT,
        subjectUniverse: { subjectCount: 1, subjectsHash: SUBJECT_UNIVERSE_HASH },
        decisionUniverses: decisionUniverses(organizationName)
      }
    },
    organizationDirectory: pair([{ legacyOrganizationId: 1, name: organizationName, title: null, active: true }]),
    organizationMappings: pair([{ legacyOrganizationId: 1, identityOrganizationId: "private-identity-org", active: true }]),
    memberships: pair([{ subjectRef: "private-subject", legacyOrganizationId: 1, active: true }]),
    organizationScopedRoles: pair([{ subjectRef: "private-subject", legacyOrganizationId: 1, roleRef: "private-role", active: true }]),
    pluginBindings: pair([{ pluginRef: "private-plugin", bindingRef: "private-binding", organizationRef: organizationName, active: true }]),
    pluginVisibility: pair([{ subjectRef: "private-subject", pluginRef: "private-plugin", organizationRef: organizationName, decision: "allow" }]),
    campusContexts: pair([{ subjectRef: "private-subject", campusRef: "private-campus", organizationRef: organizationName, decision: "allow" }]),
    effectiveDecisions: pair([{ subjectRef: "private-subject", organizationRef: organizationName, resourceRef: "private-resource", capabilityRef: "private-capability", decision: "allow" }])
  };
}

function expectNoRawProvenance(report: unknown): void {
  const serialized = JSON.stringify(report);
  for (const value of [
    "trusted-collector-1",
    "trusted-node-1",
    "trusted-key-1",
    "trusted-collector-2",
    "trusted-node-2",
    "trusted-key-2",
    "test-dual-node",
    "trusted-develop-environment",
    "private-organization",
    "private-subject"
  ]) expect(serialized).not.toContain(value);
}

const EVIDENCE_NONCE = "c3".repeat(32);
const LEGACY_SOURCE_VERSION = "private-legacy-source-version";
const IDENTITY_SOURCE_VERSION = "private-identity-source-version";
const LEGACY_SNAPSHOT = "legacy-private-snapshot";
const IDENTITY_SNAPSHOT = "identity-private-snapshot";
const SUBJECT_UNIVERSE_HASH = createOrganizationReconciliationEvidenceHash(
  EVIDENCE_NONCE,
  ["private-subject"]
);

function decisionUniverses(organizationName: string) {
  return {
    pluginVisibility: decisionUniverse(
      [["private-subject", "private-plugin", organizationName]],
      { subjects: ["private-subject"], plugins: ["private-plugin"], organizations: [organizationName] }
    ),
    campusContexts: decisionUniverse(
      [["private-subject", "private-campus"]],
      { subjects: ["private-subject"], campuses: ["private-campus"], organizations: [organizationName] }
    ),
    effectiveDecisions: decisionUniverse([
      ["private-subject", organizationName, "private-resource", "private-capability"]
    ], {
      subjects: ["private-subject"],
      organizations: [organizationName],
      resources: ["private-resource"],
      capabilities: ["private-capability"]
    })
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
      const canonicalValues = [...new Set(values)].sort();
      return [name, {
        count: canonicalValues.length,
        hash: createOrganizationReconciliationEvidenceHash(EVIDENCE_NONCE, canonicalValues)
      }];
    }))
  } as const;
}
