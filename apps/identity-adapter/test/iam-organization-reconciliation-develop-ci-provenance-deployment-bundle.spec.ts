import { describe, expect, it } from "vitest";
import {
  ORGANIZATION_RECONCILIATION_DEVELOP_DOCKER_INSPECT_OBSERVATION_SET_CONTRACT,
  OrganizationReconciliationDevelopCiProvenanceDeploymentBundleError,
  createOrganizationReconciliationDevelopDockerInspectTopologyObservationSha256,
  validateOrganizationReconciliationDevelopCiProvenanceDeploymentBundle
} from "../src/iam-organization-reconciliation-develop-ci-provenance-deployment-bundle.js";
import { createOrganizationReconciliationDevelopDeploymentEvidenceForTest } from
  "./iam-organization-reconciliation-develop-deployment-evidence.test-fixture.js";

const IMAGE_REPOSITORY = "registry.private.invalid/identity/identity-service";

describe("Develop CI provenance/deployment cross-stack bundle", () => {
  it("binds one signer and runner on the same approved Develop host to one CI repo@digest", () => {
    const fixture = createFixture();
    const report = validateOrganizationReconciliationDevelopCiProvenanceDeploymentBundle(fixture.input);
    expect(report).toEqual(expect.objectContaining({
      outcome: "passed",
      gitSha: fixture.provenance.gitSha,
      image: fixture.provenance.image,
      imageDigest: fixture.provenance.imageDigest,
      topologyObservationSha256: fixture.deploymentEvidence.topologyObservationSha256,
      composeRoleCount: 2,
      dockerInspectObservationCount: 2,
      productionReady: false
    }));
  });

  it.each([
    "signer-compose", "runner-compose", "release-digest", "git-sha", "configured-image",
    "repo-digest", "container-image-id", "engine", "container-collision", "topology-hash"
  ] as const)("rejects %s drift", (mode) => {
    const fixture = createFixture();
    const input = structuredClone(fixture.input);
    if (mode === "signer-compose") input.signerCompose.services["develop-hash-signer"].image = otherImage();
    if (mode === "runner-compose") input.runnerCompose.services["develop-full-range-runner"].image = otherImage();
    if (mode === "release-digest") Object.assign(input.deploymentEvidence,
      { releaseImageDigest: `sha256:${"e".repeat(64)}` });
    if (mode === "git-sha") Object.assign(input.deploymentEvidence, { buildRevision: "e".repeat(40) });
    if (mode === "configured-image") input.dockerInspectObservationSet.observations[1].configuredImage = otherImage();
    if (mode === "repo-digest") input.dockerInspectObservationSet.observations[1].repoDigest = otherImage();
    if (mode === "container-image-id") input.dockerInspectObservationSet.observations[1].containerImageId =
      `sha256:${"d".repeat(64)}`;
    if (mode === "engine") input.dockerInspectObservationSet.observations[1].dockerEngineIdHash = "9".repeat(64);
    if (mode === "container-collision") input.dockerInspectObservationSet.observations[1].containerIdHash =
      input.dockerInspectObservationSet.observations[0].containerIdHash;
    if (mode === "topology-hash") Object.assign(input.deploymentEvidence,
      { topologyObservationSha256: "e".repeat(64) });
    expect(() => validateOrganizationReconciliationDevelopCiProvenanceDeploymentBundle(input))
      .toThrowError(OrganizationReconciliationDevelopCiProvenanceDeploymentBundleError);
  });

  it("rejects an extra service, accessor, or observation source other than Docker inspect", () => {
    const fixture = createFixture();
    const extra = structuredClone(fixture.input);
    extra.signerCompose.services.extra = { image: fixture.provenance.image };
    expect(() => validateOrganizationReconciliationDevelopCiProvenanceDeploymentBundle(extra))
      .toThrowError(OrganizationReconciliationDevelopCiProvenanceDeploymentBundleError);

    let reads = 0;
    const accessor = structuredClone(fixture.input);
    Object.defineProperty(accessor.ciProvenance, "image", {
      enumerable: true,
      get: () => { reads += 1; return fixture.provenance.image; }
    });
    expect(() => validateOrganizationReconciliationDevelopCiProvenanceDeploymentBundle(accessor))
      .toThrowError(OrganizationReconciliationDevelopCiProvenanceDeploymentBundleError);
    expect(reads).toBe(0);

    const selfReported = structuredClone(fixture.input);
    Object.assign(selfReported.dockerInspectObservationSet.observations[0],
      { source: "application-self-report" });
    expect(() => validateOrganizationReconciliationDevelopCiProvenanceDeploymentBundle(selfReported))
      .toThrowError(OrganizationReconciliationDevelopCiProvenanceDeploymentBundleError);
  });
});

function createFixture() {
  const deploymentEvidence = structuredClone(
    createOrganizationReconciliationDevelopDeploymentEvidenceForTest()
  );
  Object.assign(deploymentEvidence.signers[0], {
    portainerEndpointIdHash: deploymentEvidence.executor.portainerEndpointIdHash,
    dockerEngineIdHash: deploymentEvidence.executor.dockerEngineIdHash,
    physicalHostIdentityHash: deploymentEvidence.executor.physicalHostIdentityHash
  });
  const imageDigest = deploymentEvidence.releaseImageDigest;
  const image = `${IMAGE_REPOSITORY}@${imageDigest}`;
  const provenance = {
    contract: "identity-service/develop-image-provenance/v1" as const,
    gitSha: deploymentEvidence.buildRevision,
    image,
    imageDigest
  };
  const compose = (serviceName: string) => ({ services: { [serviceName]: { image } } });
  const observedAt = "2026-08-08T23:59:59.000Z";
  const imageId = `sha256:${"f".repeat(64)}`;
  const observation = (
    role: "runner" | "signer",
    keyId: string | null,
    source: typeof deploymentEvidence.executor
  ) => ({
    contract: "iam-organization-reconciliation-xrteeth-develop-docker-inspect-image-observation/v1" as const,
    environment: "xrteeth-develop" as const,
    role,
    keyId,
    source: "docker-inspect" as const,
    observedAt,
    configuredImage: image,
    repoDigest: image,
    containerImageId: imageId,
    imageInspectId: imageId,
    containerIdHash: source.containerIdHash,
    portainerEndpointIdHash: source.portainerEndpointIdHash,
    dockerEngineIdHash: source.dockerEngineIdHash,
    physicalHostIdentityHash: source.physicalHostIdentityHash
  });
  const dockerInspectObservationSet = {
    contract: ORGANIZATION_RECONCILIATION_DEVELOP_DOCKER_INSPECT_OBSERVATION_SET_CONTRACT,
    environment: "xrteeth-develop" as const,
    observations: [
      observation("runner", null, deploymentEvidence.executor),
      observation("signer", deploymentEvidence.signers[0].keyId, deploymentEvidence.signers[0])
    ] as const
  };
  const composeImages = {
    runner: image,
    signer: image
  };
  Object.assign(deploymentEvidence, {
    topologyObservationSha256: createOrganizationReconciliationDevelopDockerInspectTopologyObservationSha256({
      provenance,
      composeImages,
      observationSet: dockerInspectObservationSet
    })
  });
  return {
    provenance,
    deploymentEvidence,
    input: {
      ciProvenance: provenance,
      deploymentEvidence,
      signerCompose: compose("develop-hash-signer"),
      runnerCompose: compose("develop-full-range-runner"),
      dockerInspectObservationSet
    }
  };
}

function otherImage(): string {
  return `${IMAGE_REPOSITORY}@sha256:${"e".repeat(64)}`;
}
