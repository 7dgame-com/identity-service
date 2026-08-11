import {
  ORGANIZATION_RECONCILIATION_DEVELOP_DEPLOYMENT_EVIDENCE_CONTRACT,
  type OrganizationReconciliationDevelopDeploymentEvidence
} from "../src/iam-organization-reconciliation-develop-deployment-evidence.js";

const digest = (character: string): string => character.repeat(64);

export function createOrganizationReconciliationDevelopDeploymentEvidenceForTest(
  collectors: readonly Readonly<{
    collectorId: string;
    nodeId: string;
    keyId: string;
    publicKeySha256: string;
  }>[] = [
    { collectorId: "collector-a", nodeId: "node-a", keyId: "key-a", publicKeySha256: digest("d") }
  ],
  buildRevision = "a".repeat(40)
): OrganizationReconciliationDevelopDeploymentEvidence {
  if (collectors.length !== 1) throw new Error("test fixture requires one Develop collector");
  const ordered = [...collectors].sort((left, right) => left.keyId.localeCompare(right.keyId));
  const signer = () => ({
    collectorId: ordered[0]!.collectorId,
    nodeId: ordered[0]!.nodeId,
    keyId: ordered[0]!.keyId,
    publicKeySha256: ordered[0]!.publicKeySha256,
    tlsCertificateSha256: digest("1"),
    portainerEndpointIdHash: digest("2"),
    dockerEngineIdHash: digest("3"),
    physicalHostIdentityHash: digest("4"),
    containerIdHash: digest("5"),
    containerImageDigest: `sha256:${digest("b")}`
  });
  return {
    contract: ORGANIZATION_RECONCILIATION_DEVELOP_DEPLOYMENT_EVIDENCE_CONTRACT,
    environment: "xrteeth-develop",
    buildRevision,
    releaseImageDigest: `sha256:${digest("b")}`,
    topologyObservationSha256: digest("c"),
    physicalProbeSha256: digest("f"),
    observedAt: "2026-08-09T00:00:00.000Z",
    physicalIndependenceVerified: false,
    productionReady: false,
    productionPromotionAllowed: false,
    executor: {
      portainerEndpointIdHash: digest("d"),
      dockerEngineIdHash: digest("e"),
      physicalHostIdentityHash: digest("f"),
      containerIdHash: digest("1"),
      containerImageDigest: `sha256:${digest("b")}`
    },
    signers: [signer()]
  };
}
