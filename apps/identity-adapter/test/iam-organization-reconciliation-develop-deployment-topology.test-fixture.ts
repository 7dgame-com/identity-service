import {
  ORGANIZATION_RECONCILIATION_DEVELOP_DEPLOYMENT_TOPOLOGY_CONTRACT,
  type OrganizationReconciliationDevelopDeploymentTopologyTemplate
} from "../src/iam-organization-reconciliation-develop-deployment-topology.js";
import type {
  OrganizationReconciliationDevelopDeploymentEvidence
} from "../src/iam-organization-reconciliation-develop-deployment-evidence.js";

export function createOrganizationReconciliationDevelopDeploymentTopologyForTest(
  evidence: OrganizationReconciliationDevelopDeploymentEvidence,
  profileId = "develop-profile"
): OrganizationReconciliationDevelopDeploymentTopologyTemplate {
  return {
    contract: ORGANIZATION_RECONCILIATION_DEVELOP_DEPLOYMENT_TOPOLOGY_CONTRACT,
    environment: "xrteeth-develop",
    profileId,
    executor: {
      portainerEndpointIdHash: evidence.executor.portainerEndpointIdHash,
      dockerEngineIdHash: evidence.executor.dockerEngineIdHash,
      physicalHostIdentityHash: evidence.executor.physicalHostIdentityHash
    },
    signers: evidence.signers.map((signer) => ({
      collectorId: signer.collectorId,
      nodeId: signer.nodeId,
      keyId: signer.keyId,
      publicKeySha256: signer.publicKeySha256,
      tlsCertificateSha256: signer.tlsCertificateSha256,
      portainerEndpointIdHash: signer.portainerEndpointIdHash,
      dockerEngineIdHash: signer.dockerEngineIdHash,
      physicalHostIdentityHash: signer.physicalHostIdentityHash
    })) as unknown as OrganizationReconciliationDevelopDeploymentTopologyTemplate["signers"]
  };
}
