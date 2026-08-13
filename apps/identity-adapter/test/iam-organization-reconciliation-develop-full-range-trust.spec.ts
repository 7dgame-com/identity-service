import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import {
  runOrganizationReconciliationDevelopFullRange,
  type OrganizationReconciliationDevelopFullRangeDependencies,
  type OrganizationReconciliationDevelopFullRangeExternalSigner
} from "../src/iam-organization-reconciliation-develop-full-range.js";
import type {
  OrganizationReconciliationTrustPolicy,
  OrganizationReconciliationTrustedProfile
} from "../src/iam-organization-reconciliation-provenance.js";
import type {
  MysqlRepeatableReadSnapshotConnectionFactory
} from "../src/iam-organization-reconciliation/mysql-repeatable-read-snapshot.js";
import {
  createOrganizationReconciliationPolicyForTest,
  createOrganizationReconciliationTrustedProfileForTest,
  TEST_COLLECTOR_BUILD_REVISION
} from "./iam-organization-reconciliation-provenance.test-fixture.js";
import {
  createOrganizationReconciliationDevelopDeploymentEvidenceForTest
} from "./iam-organization-reconciliation-develop-deployment-evidence.test-fixture.js";

const compiled = vi.hoisted(() => ({
  profile: undefined as OrganizationReconciliationTrustedProfile | undefined
}));

vi.mock("../src/generated/iam-organization-reconciliation-compiled-revision.js", () => ({
  ORGANIZATION_RECONCILIATION_COMPILED_BUILD_REVISION: "a".repeat(40)
}));

vi.mock("../src/iam-organization-reconciliation-trust-profiles.js", () => ({
  compiledOrganizationReconciliationTrustProfileCount: 1,
  resolveCompiledOrganizationReconciliationTrustProfile: (profileId: string) =>
    compiled.profile?.profileId === profileId ? structuredClone(compiled.profile) : undefined
}));

vi.mock("../src/iam-organization-reconciliation-develop-deployment-topology.js", () => ({
  bindOrganizationReconciliationDevelopDeploymentEvidenceToCompiledTopology: (candidate: unknown) =>
    Object.freeze({ topology: Object.freeze({ profileId: "test" }), deploymentEvidence: candidate,
      physicalIndependenceVerified: false as const, productionPromotionAllowed: false as const })
}));

describe("Develop full-range compiled trust/profile/signer binding", () => {
  it.each(["missing", "extra", "wrong-collector", "wrong-node", "wrong-key", "wrong-fingerprint", "wrong-build"] as const)(
    "rejects %s signer metadata before any dependency callback",
    async (mode) => {
      const fixture = trustFixture();
      compiled.profile = fixture.profile;
      const signers = fixture.signers.map((signer) => ({ ...signer }));
      if (mode === "missing") signers.pop();
      if (mode === "extra") signers.push({ ...fixture.signers[0]!, keyId: "unexpected-key" });
      if (mode === "wrong-collector") signers[0]!.collectorId = "wrong-collector";
      if (mode === "wrong-node") signers[0]!.nodeId = "wrong-node";
      if (mode === "wrong-key") signers[0]!.keyId = "wrong-key";
      if (mode === "wrong-fingerprint") signers[0]!.publicKeySha256 = "0".repeat(64);
      if (mode === "wrong-build") signers[0]!.buildRevision = "b".repeat(40);

      const observed = counters();
      await expect(runOrganizationReconciliationDevelopFullRange(
        dependencies(fixture.policy, signers, observed)
      )).rejects.toMatchObject({ failureId: "signer-not-provisioned" });
      expect(observed).toEqual(counters());
      expect(fixture.signerCalls.count).toBe(0);
    }
  );

  it.each(["policy-pin", "environment", "collector-build"] as const)(
    "rejects compiled profile/policy mismatch before signer capture: %s",
    async (mode) => {
      const fixture = trustFixture();
      compiled.profile = fixture.profile;
      const policy = structuredClone(fixture.policy) as MutablePolicy;
      if (mode === "policy-pin") policy.maxEvidenceAgeSeconds -= 1;
      if (mode === "environment") policy.environment = "other-develop";
      if (mode === "collector-build") policy.requiredCollectors[0]!.buildRevision = "b".repeat(40);
      const observed = counters();

      await expect(runOrganizationReconciliationDevelopFullRange(
        dependencies(policy, fixture.signers, observed)
      )).rejects.toMatchObject({
        failureId: mode === "environment" ? "trust-policy-invalid" : "trust-profile-mismatch"
      });
      expect(observed).toEqual(counters());
      expect(fixture.signerCalls.count).toBe(0);
    }
  );

  it("rejects deployment/profile signer drift before DB, clock, signer, or output callbacks", async () => {
    const fixture = trustFixture();
    compiled.profile = fixture.profile;
    const observed = counters();
    const candidate = dependencies(fixture.policy, fixture.signers, observed);
    const deploymentEvidence = {
      ...candidate.deploymentEvidence,
      signers: [
        { ...candidate.deploymentEvidence.signers[0], nodeId: "different-node" }
      ] as const
    };

    await expect(runOrganizationReconciliationDevelopFullRange({
      ...candidate,
      deploymentEvidence
    })).rejects.toMatchObject({ failureId: "deployment-evidence-invalid" });
    expect(observed).toEqual(counters());
    expect(fixture.signerCalls.count).toBe(0);
  });

  it("descriptor-captures nested policy and signer metadata without invoking accessors", async () => {
    const policyFixture = trustFixture();
    compiled.profile = policyFixture.profile;
    let policyGetterCalls = 0;
    const policy = structuredClone(policyFixture.policy) as MutablePolicy;
    Object.defineProperty(policy.requiredCollectors[0], "collectorId", {
      enumerable: true,
      get: () => {
        policyGetterCalls += 1;
        return "forged-collector";
      }
    });
    const policyObserved = counters();
    await expect(runOrganizationReconciliationDevelopFullRange(
      dependencies(policy, policyFixture.signers, policyObserved)
    )).rejects.toMatchObject({ failureId: "trust-policy-invalid" });
    expect(policyGetterCalls).toBe(0);
    expect(policyObserved).toEqual(counters());
    expect(policyFixture.signerCalls.count).toBe(0);

    const signerFixture = trustFixture();
    compiled.profile = signerFixture.profile;
    let signerGetterCalls = 0;
    const signer = { ...signerFixture.signers[0] } as Record<string, unknown>;
    Object.defineProperty(signer, "keyId", {
      enumerable: true,
      get: () => {
        signerGetterCalls += 1;
        return "forged-key";
      }
    });
    const signerObserved = counters();
    await expect(runOrganizationReconciliationDevelopFullRange(dependencies(
      signerFixture.policy,
      [signer as unknown as OrganizationReconciliationDevelopFullRangeExternalSigner],
      signerObserved
    ))).rejects.toMatchObject({ failureId: "signer-not-provisioned" });
    expect(signerGetterCalls).toBe(0);
    expect(signerObserved).toEqual(counters());
    expect(signerFixture.signerCalls.count).toBe(0);
  });
});

interface MutablePolicy extends Omit<OrganizationReconciliationTrustPolicy, "requiredCollectors"> {
  environment: string;
  maxEvidenceAgeSeconds: number;
  requiredCollectors: Array<{
    -readonly [K in keyof OrganizationReconciliationTrustPolicy["requiredCollectors"][number]]:
      OrganizationReconciliationTrustPolicy["requiredCollectors"][number][K]
  }>;
}

interface ObservedCallbacks {
  opens: number;
  clocks: number;
  signers: number;
  outputs: number;
}

function trustFixture() {
  const keys = [generateKeyPairSync("ed25519")];
  const base = createOrganizationReconciliationPolicyForTest(keys.map(({ publicKey }, index) => ({
    collectorId: `develop-collector-${index + 1}`,
    nodeId: `develop-node-${index + 1}`,
    keyId: `develop-key-${index + 1}`,
    publicKey
  })));
  const policy: OrganizationReconciliationTrustPolicy = {
    ...base,
    environment: "xrteeth-develop"
  };
  const profile = createOrganizationReconciliationTrustedProfileForTest(policy);
  const signerCalls = { count: 0 };
  const signers = policy.requiredCollectors.map((collector) => ({
    collectorId: collector.collectorId,
    nodeId: collector.nodeId,
    keyId: collector.keyId,
    publicKeySha256: collector.publicKeySha256,
    buildRevision: collector.buildRevision,
    sign: () => {
      signerCalls.count += 1;
      return Buffer.alloc(64);
    }
  }));
  return { policy, profile, signers, signerCalls };
}

function counters(): ObservedCallbacks {
  return { opens: 0, clocks: 0, signers: 0, outputs: 0 };
}

function dependencies(
  trustPolicy: OrganizationReconciliationTrustPolicy,
  externalSigners: readonly OrganizationReconciliationDevelopFullRangeExternalSigner[],
  observed: ObservedCallbacks
): OrganizationReconciliationDevelopFullRangeDependencies {
  const factory = (): MysqlRepeatableReadSnapshotConnectionFactory => async () => {
    observed.opens += 1;
    throw new Error("database must remain unopened");
  };
  return {
    environment: "xrteeth-develop",
    deploymentEvidence: createOrganizationReconciliationDevelopDeploymentEvidenceForTest(
      compiled.profile?.requiredCollectors
    ),
    legacyConnectionFactory: factory(),
    identityConnectionFactory: factory(),
    pluginConnectionFactory: factory(),
    expectedDatabaseUsers: {
      "legacy-main": "iam_org_legacy_ro",
      identity: "iam_org_identity_ro",
      plugin: "iam_org_plugin_ro"
    },
    trustPolicy,
    externalSigners,
    attestationTtlSeconds: 300,
    clock: {
      now: () => {
        observed.clocks += 1;
        return new Date("2026-08-09T00:06:30.000Z");
      }
    },
    output: { write: () => { observed.outputs += 1; } }
  };
}
