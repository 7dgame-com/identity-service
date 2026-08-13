import { createHash, sign, type KeyObject } from "node:crypto";
import {
  createOrganizationReconciliationProvenancePayload,
  createOrganizationReconciliationSignedAttestation,
  createOrganizationReconciliationTrustPolicySha256,
  ORGANIZATION_RECONCILIATION_PROVENANCE_ALGORITHM,
  ORGANIZATION_RECONCILIATION_PROVENANCE_AUDIENCE,
  ORGANIZATION_RECONCILIATION_PROVENANCE_CONTRACT,
  ORGANIZATION_RECONCILIATION_TRUST_POLICY_CONTRACT,
  serializeOrganizationReconciliationProvenancePayload,
  type OrganizationReconciliationAttestationBundle,
  type OrganizationReconciliationProvenanceBinding,
  type OrganizationReconciliationTrustPolicy,
  type OrganizationReconciliationTrustedProfile
} from "../src/iam-organization-reconciliation-provenance.js";

export const TEST_COLLECTOR_BUILD_REVISION = "a".repeat(40);
export const TEST_DEPLOYMENT_EVIDENCE_SHA256 = "d".repeat(64);

export function createOrganizationReconciliationPolicyForTest(
  collectors: readonly {
    readonly collectorId: string;
    readonly nodeId: string;
    readonly keyId: string;
    readonly publicKey: KeyObject;
  }[]
): OrganizationReconciliationTrustPolicy {
  return {
    contract: ORGANIZATION_RECONCILIATION_TRUST_POLICY_CONTRACT,
    profileId: "test-dual-node",
    audience: ORGANIZATION_RECONCILIATION_PROVENANCE_AUDIENCE,
    environment: "trusted-develop-environment",
    validFrom: "2026-08-09T00:00:00.000Z",
    validUntil: "2026-08-09T00:30:00.000Z",
    maxEvidenceAgeSeconds: 600,
    maxAttestationTtlSeconds: 600,
    maxCollectionWindowSeconds: 300,
    clockSkewSeconds: 0,
    requiredCollectors: collectors.map((collector) => {
      const publicKeyPem = collector.publicKey.export({ format: "pem", type: "spki" }).toString();
      const publicKeyDer = collector.publicKey.export({ format: "der", type: "spki" });
      return {
        collectorId: collector.collectorId,
        nodeId: collector.nodeId,
        keyId: collector.keyId,
        algorithm: ORGANIZATION_RECONCILIATION_PROVENANCE_ALGORITHM,
        publicKeyPem,
        publicKeySha256: createHash("sha256").update(publicKeyDer).digest("hex"),
        buildRevision: TEST_COLLECTOR_BUILD_REVISION,
        validFrom: "2026-08-09T00:00:00.000Z",
        validUntil: "2026-08-09T00:30:00.000Z"
      };
    })
  };
}

export function createOrganizationReconciliationTrustedProfileForTest(
  policy: OrganizationReconciliationTrustPolicy
): OrganizationReconciliationTrustedProfile {
  return {
    profileId: policy.profileId,
    policySha256: createOrganizationReconciliationTrustPolicySha256(policy),
    expectedEnvironment: policy.environment,
    requiredCollectors: policy.requiredCollectors.map((collector) => ({
      collectorId: collector.collectorId,
      nodeId: collector.nodeId,
      keyId: collector.keyId,
      publicKeySha256: collector.publicKeySha256,
      buildRevision: collector.buildRevision
    }))
  };
}

export function createOrganizationReconciliationAttestationBundleForTest(
  binding: OrganizationReconciliationProvenanceBinding,
  policy: OrganizationReconciliationTrustPolicy,
  signers: readonly { readonly keyId: string; readonly privateKey: KeyObject }[]
): OrganizationReconciliationAttestationBundle {
  return {
    contract: ORGANIZATION_RECONCILIATION_PROVENANCE_CONTRACT,
    attestations: signers.map((signer) => {
      const payload = createOrganizationReconciliationProvenancePayload(
        binding,
        policy,
        signer.keyId,
        "2026-08-09T00:06:30.000Z",
        "2026-08-09T00:15:00.000Z"
      );
      return createOrganizationReconciliationSignedAttestation(
        payload,
        sign(null, serializeOrganizationReconciliationProvenancePayload(payload), signer.privateKey)
      );
    })
  };
}
