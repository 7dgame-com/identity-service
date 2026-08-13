import { describe, expect, it } from "vitest";
import {
  ORGANIZATION_RECONCILIATION_DEVELOP_DEPLOYMENT_EVIDENCE_CONTRACT,
  OrganizationReconciliationDevelopDeploymentEvidenceError,
  assertOrganizationReconciliationDevelopDeploymentEvidenceSha256,
  createOrganizationReconciliationDevelopDeploymentEvidenceSha256,
  parseOrganizationReconciliationDevelopDeploymentEvidence
} from "../src/iam-organization-reconciliation-develop-deployment-evidence.js";

const sha = (character: string): string => character.repeat(64);
const image = (character: string): string => `sha256:${sha(character)}`;

function fixture() {
  return {
    contract: ORGANIZATION_RECONCILIATION_DEVELOP_DEPLOYMENT_EVIDENCE_CONTRACT,
    environment: "xrteeth-develop",
    buildRevision: "a".repeat(40),
    releaseImageDigest: image("a"),
    topologyObservationSha256: sha("b"),
    physicalProbeSha256: sha("d"),
    observedAt: "2026-08-11T00:00:00.000Z",
    physicalIndependenceVerified: false,
    productionReady: false,
    productionPromotionAllowed: false,
    executor: {
      portainerEndpointIdHash: sha("c"),
      dockerEngineIdHash: sha("d"),
      physicalHostIdentityHash: sha("e"),
      containerIdHash: sha("f"),
      containerImageDigest: image("a")
    },
    signers: [
      {
        collectorId: "collector-a",
        nodeId: "node-a",
        keyId: "key-a",
        publicKeySha256: sha("1"),
        tlsCertificateSha256: sha("2"),
        portainerEndpointIdHash: sha("3"),
        dockerEngineIdHash: sha("4"),
        physicalHostIdentityHash: sha("5"),
        containerIdHash: sha("6"),
        containerImageDigest: image("a")
      }
    ]
  };
}

describe("Develop deployment evidence", () => {
  it("pins one release image and one signer without claiming physical independence", () => {
    const candidate = fixture();
    const parsed = parseOrganizationReconciliationDevelopDeploymentEvidence(candidate);
    const digest = createOrganizationReconciliationDevelopDeploymentEvidenceSha256(candidate);
    expect(digest).toMatch(/^[a-f0-9]{64}$/);
    expect(assertOrganizationReconciliationDevelopDeploymentEvidenceSha256(candidate, digest)).toEqual(parsed);
    expect(Object.isFrozen(parsed)).toBe(true);
    expect(Object.isFrozen(parsed.signers)).toBe(true);
    expect(parsed).toMatchObject({
      physicalIndependenceVerified: false,
      productionReady: false,
      productionPromotionAllowed: false
    });

    const physicalProbeBitFlip = fixture();
    physicalProbeBitFlip.physicalProbeSha256 = `${sha("d").slice(0, -1)}c`;
    expect(createOrganizationReconciliationDevelopDeploymentEvidenceSha256(physicalProbeBitFlip))
      .not.toBe(digest);
  });

  it("rejects image, topology, invalid hashes, signer cardinality, or promotion claims", () => {
    const mutate = (apply: (value: ReturnType<typeof fixture>) => void) => {
      const value = fixture();
      apply(value);
      expect(() => parseOrganizationReconciliationDevelopDeploymentEvidence(value))
        .toThrowError(OrganizationReconciliationDevelopDeploymentEvidenceError);
    };
    mutate((value) => { value.signers[0]!.containerImageDigest = image("d"); });
    mutate((value) => { value.signers[0]!.publicKeySha256 = sha("0"); });
    mutate((value) => { value.signers.length = 0; });
    mutate((value) => { value.signers.push({ ...value.signers[0]! }); });
    mutate((value) => { value.physicalIndependenceVerified = true as false; });
    mutate((value) => { value.productionReady = true as false; });
    mutate((value) => { value.productionPromotionAllowed = true as false; });
    mutate((value) => { value.topologyObservationSha256 = sha("0"); });
    mutate((value) => { value.physicalProbeSha256 = sha("0"); });

    const colocated = fixture();
    colocated.signers[0]!.portainerEndpointIdHash = colocated.executor.portainerEndpointIdHash;
    colocated.signers[0]!.dockerEngineIdHash = colocated.executor.dockerEngineIdHash;
    colocated.signers[0]!.physicalHostIdentityHash = colocated.executor.physicalHostIdentityHash;
    expect(parseOrganizationReconciliationDevelopDeploymentEvidence(colocated).signers).toHaveLength(1);
  });

  it("rejects unknown, accessor, proxy, exotic, and nested-proxy input without invoking a getter", () => {
    expect(() => parseOrganizationReconciliationDevelopDeploymentEvidence({ ...fixture(), extra: true }))
      .toThrowError(OrganizationReconciliationDevelopDeploymentEvidenceError);
    let getterReads = 0;
    const accessor = Object.defineProperty(fixture(), "environment", {
      enumerable: true,
      get() {
        getterReads += 1;
        return "xrteeth-develop";
      }
    });
    expect(() => parseOrganizationReconciliationDevelopDeploymentEvidence(accessor))
      .toThrowError(OrganizationReconciliationDevelopDeploymentEvidenceError);
    expect(getterReads).toBe(0);
    expect(() => parseOrganizationReconciliationDevelopDeploymentEvidence(new Proxy(fixture(), {})))
      .toThrowError(OrganizationReconciliationDevelopDeploymentEvidenceError);
    const nested = fixture();
    nested.executor = new Proxy(nested.executor, {});
    expect(() => parseOrganizationReconciliationDevelopDeploymentEvidence(nested))
      .toThrowError(OrganizationReconciliationDevelopDeploymentEvidenceError);
    const exotic = fixture();
    exotic.executor = Object.assign(Object.create({ inherited: true }), exotic.executor);
    expect(() => parseOrganizationReconciliationDevelopDeploymentEvidence(exotic))
      .toThrowError(OrganizationReconciliationDevelopDeploymentEvidenceError);
  });

  it("rejects a wrong or zero expected digest", () => {
    const candidate = fixture();
    expect(() => assertOrganizationReconciliationDevelopDeploymentEvidenceSha256(candidate, sha("d")))
      .toThrowError(OrganizationReconciliationDevelopDeploymentEvidenceError);
    expect(() => assertOrganizationReconciliationDevelopDeploymentEvidenceSha256(candidate, sha("0")))
      .toThrowError(OrganizationReconciliationDevelopDeploymentEvidenceError);
  });
});
