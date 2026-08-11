import { describe, expect, it } from "vitest";
import {
  OrganizationReconciliationDevelopDeploymentTopologyError,
  bindOrganizationReconciliationDevelopDeploymentEvidenceToCompiledTopology,
  bindOrganizationReconciliationDevelopDeploymentEvidenceToTopology,
  compileOrganizationReconciliationDevelopDeploymentTopologyTemplates,
  compiledOrganizationReconciliationDevelopDeploymentTopologyCount,
  selectSoleCompiledOrganizationReconciliationDevelopDeploymentTopology
} from "../src/iam-organization-reconciliation-develop-deployment-topology.js";
import { createOrganizationReconciliationDevelopDeploymentEvidenceForTest } from
  "./iam-organization-reconciliation-develop-deployment-evidence.test-fixture.js";
import { createOrganizationReconciliationDevelopDeploymentTopologyForTest } from
  "./iam-organization-reconciliation-develop-deployment-topology.test-fixture.js";

describe("Develop compiled deployment topology", () => {
  it("keeps production unprovisioned and compiles a revision/image-independent fixture", () => {
    expect(compiledOrganizationReconciliationDevelopDeploymentTopologyCount).toBe(0);
    const evidence = createOrganizationReconciliationDevelopDeploymentEvidenceForTest();
    const topology = createOrganizationReconciliationDevelopDeploymentTopologyForTest(evidence);
    expect(topology).not.toHaveProperty("buildRevision");
    expect(topology).not.toHaveProperty("releaseImageDigest");
    expect(topology.executor).not.toHaveProperty("containerIdHash");
    expect(topology.signers[0]).not.toHaveProperty("containerImageDigest");
    const registry = compileOrganizationReconciliationDevelopDeploymentTopologyTemplates({
      [topology.profileId]: topology
    });
    expect(selectSoleCompiledOrganizationReconciliationDevelopDeploymentTopology(registry)).toEqual(topology);
  });

  it("fails the entire registry closed on signer cardinality, unknown fields, or multiple profiles", () => {
    const evidence = createOrganizationReconciliationDevelopDeploymentEvidenceForTest();
    const topology = createOrganizationReconciliationDevelopDeploymentTopologyForTest(evidence);
    const invalid = structuredClone(topology) as unknown as {
      profileId: string;
      signers: Array<{ dockerEngineIdHash: string }>;
    };
    invalid.signers.push({ ...invalid.signers[0]! });
    expect(compileOrganizationReconciliationDevelopDeploymentTopologyTemplates({
      [topology.profileId]: invalid as never
    })).toEqual({});
    expect(compileOrganizationReconciliationDevelopDeploymentTopologyTemplates({
      [topology.profileId]: { ...topology, extra: true } as never
    })).toEqual({});
    const second = { ...topology, profileId: "second-profile" };
    expect(selectSoleCompiledOrganizationReconciliationDevelopDeploymentTopology(
      compileOrganizationReconciliationDevelopDeploymentTopologyTemplates({
        [topology.profileId]: topology,
        [second.profileId]: second
      })
    )).toBeUndefined();
  });

  it("rejects runtime evidence when production has no sole compiled topology", () => {
    expect(() => bindOrganizationReconciliationDevelopDeploymentEvidenceToCompiledTopology(
      createOrganizationReconciliationDevelopDeploymentEvidenceForTest(),
      "develop-profile"
    )).toThrowError(OrganizationReconciliationDevelopDeploymentTopologyError);
  });

  it("binds exact pins while keeping physical independence and Production promotion false", () => {
    const evidence = createOrganizationReconciliationDevelopDeploymentEvidenceForTest();
    const topology = createOrganizationReconciliationDevelopDeploymentTopologyForTest(evidence);
    expect(bindOrganizationReconciliationDevelopDeploymentEvidenceToTopology(
      evidence,
      topology.profileId,
      topology
    )).toMatchObject({
      physicalIndependenceVerified: false,
      productionPromotionAllowed: false,
      deploymentEvidence: evidence
    });

    type MutableEvidence = {
      executor: { physicalHostIdentityHash: string };
      signers: Array<{ tlsCertificateSha256: string; portainerEndpointIdHash: string }>;
    };
    for (const mutate of [
      (value: MutableEvidence) => { value.executor.physicalHostIdentityHash = "1".repeat(64); },
      (value: MutableEvidence) => { value.signers[0]!.tlsCertificateSha256 = "2".repeat(64); },
      (value: MutableEvidence) => { value.signers[0]!.portainerEndpointIdHash = "3".repeat(64); }
    ]) {
      const drifted = structuredClone(evidence) as unknown as MutableEvidence;
      mutate(drifted);
      expect(() => bindOrganizationReconciliationDevelopDeploymentEvidenceToTopology(
        drifted,
        topology.profileId,
        topology
      )).toThrowError(OrganizationReconciliationDevelopDeploymentTopologyError);
    }
  });
});
