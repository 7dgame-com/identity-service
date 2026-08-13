import { generateKeyPairSync } from "node:crypto";
import { execFile } from "node:child_process";
import { chmod, link, mkdtemp, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { promisify } from "node:util";
import type { OrganizationReconciliationTrustedProfile } from
  "../src/iam-organization-reconciliation-provenance.js";

const compiled = vi.hoisted(() => ({
  profile: undefined as OrganizationReconciliationTrustedProfile | undefined
}));

vi.mock("../src/iam-organization-reconciliation-trust-profiles.js", () => ({
  resolveCompiledOrganizationReconciliationTrustProfile: (profileId: string) =>
    compiled.profile?.profileId === profileId ? structuredClone(compiled.profile) : undefined
}));

vi.mock("../src/iam-organization-reconciliation-develop-deployment-topology.js", () => ({
  bindOrganizationReconciliationDevelopDeploymentEvidenceToCompiledTopology: (candidate: unknown) =>
    Object.freeze({ topology: Object.freeze({ profileId: "test" }), deploymentEvidence: candidate,
      physicalIndependenceVerified: false as const, productionPromotionAllowed: false as const })
}));

import {
  loadOrganizationReconciliationDevelopHashSignerTransportConfig,
  OrganizationReconciliationDevelopHashSignerTransportConfigError,
  ORGANIZATION_RECONCILIATION_DEVELOP_HASH_SIGNER_TRANSPORT_CONFIG_CONTRACT,
  parseOrganizationReconciliationDevelopHashSignerTransportConfig
} from "../src/iam-organization-reconciliation-develop-hash-signer-transport-config.js";
import {
  createOrganizationReconciliationPolicyForTest,
  createOrganizationReconciliationTrustedProfileForTest
} from "./iam-organization-reconciliation-provenance.test-fixture.js";
import {
  createOrganizationReconciliationDevelopDeploymentEvidenceForTest
} from "./iam-organization-reconciliation-develop-deployment-evidence.test-fixture.js";

const SIGN_PATH = "/v1/iam-organization-reconciliation/sign";
const temporaryDirectories: string[] = [];
const execFileAsync = promisify(execFile);

afterEach(async () => {
  vi.unstubAllGlobals();
  compiled.profile = undefined;
  await Promise.all(temporaryDirectories.splice(0).map((path) =>
    rm(path, { recursive: true, force: true })));
});

describe("Develop full-range HTTPS signer transport config", () => {
  it("loads exactly one transport and derives every public identity pin from the compiled profile", async () => {
    const fixture = await createFixture();
    const fetchCalls = vi.fn();
    vi.stubGlobal("fetch", fetchCalls);

    const signers = await loadOrganizationReconciliationDevelopHashSignerTransportConfig(
      fixture.configPath,
      fixture.policy,
      fixture.deploymentEvidence
    );

    expect(fetchCalls).not.toHaveBeenCalled();
    expect(signers).toHaveLength(1);
    expect(signers.map(({ sign: _sign, ...metadata }) => metadata)).toEqual(
      fixture.profile.requiredCollectors
    );
    expect(signers.every((signer) => typeof signer.sign === "function")).toBe(true);
    expect(Object.isFrozen(signers)).toBe(true);
    expect(signers.every(Object.isFrozen)).toBe(true);
  });

  it("rejects missing, extra, duplicate, unknown, non-HTTPS, noncanonical, and metadata-override fields", async () => {
    const fixture = await createFixture();
    const valid = fixture.manifest;
    const cases: unknown[] = [
      { ...valid, contract: "other/v1" },
      { ...valid, environment: "production" },
      { ...valid, profileId: "other-profile" },
      { ...valid, extra: true },
      { contract: valid.contract, environment: valid.environment, profileId: valid.profileId },
      { ...valid, signers: [] },
      { ...valid, signers: [...valid.signers, { ...valid.signers[0], keyId: "second-key" }] },
      { ...valid, signers: [{ ...valid.signers[0], keyId: "unknown-key" }] },
      { ...valid, signers: [{ ...valid.signers[0], endpoint: `http://signer-1.internal${SIGN_PATH}` }] },
      { ...valid, signers: [{ ...valid.signers[0], endpoint: `https://localhost${SIGN_PATH}` }] },
      { ...valid, signers: [{ ...valid.signers[0], endpoint: `https://SIGNER-1.internal${SIGN_PATH}` }] },
      { ...valid, signers: [{ ...valid.signers[0], bearerTokenFile: "relative-token" }] },
      { ...valid, signers: [{ ...valid.signers[0], collectorId: "override" }] },
      { ...valid, signers: [{ keyId: valid.signers[0].keyId, endpoint: valid.signers[0].endpoint }] }
    ];

    for (const candidate of cases) {
      expect(() => parseOrganizationReconciliationDevelopHashSignerTransportConfig(
        candidate,
        fixture.policy,
        fixture.deploymentEvidence
      )).toThrow(OrganizationReconciliationDevelopHashSignerTransportConfigError);
    }
  });

  it("descriptor-captures config and policy without invoking proxy traps or accessors", async () => {
    const fixture = await createFixture();
    let reads = 0;
    const topAccessor = { ...fixture.manifest } as Record<string, unknown>;
    Object.defineProperty(topAccessor, "profileId", {
      enumerable: true,
      get: () => { reads += 1; return fixture.policy.profileId; }
    });
    const nestedAccessor = structuredClone(fixture.manifest) as unknown as {
      signers: Array<Record<string, unknown>>;
    };
    Object.defineProperty(nestedAccessor.signers[0], "keyId", {
      enumerable: true,
      get: () => { reads += 1; return fixture.policy.requiredCollectors[0]!.keyId; }
    });
    const configProxy = new Proxy(fixture.manifest, {
      get: () => { reads += 1; throw new Error("must not read"); }
    });
    const policyProxy = new Proxy(fixture.policy, {
      get: () => { reads += 1; throw new Error("must not read"); }
    });

    for (const [config, policy] of [
      [topAccessor, fixture.policy],
      [nestedAccessor, fixture.policy],
      [configProxy, fixture.policy],
      [fixture.manifest, policyProxy]
    ] as const) {
      expect(() => parseOrganizationReconciliationDevelopHashSignerTransportConfig(
        config,
        policy,
        fixture.deploymentEvidence
      ))
        .toThrow(OrganizationReconciliationDevelopHashSignerTransportConfigError);
    }
    expect(reads).toBe(0);
  });

  it("requires ordinary owner-0600, non-symlink, single-link manifest and token files", async () => {
    const permissiveConfig = await createFixture();
    await chmod(permissiveConfig.configPath, 0o644);
    await expect(loadOrganizationReconciliationDevelopHashSignerTransportConfig(
      permissiveConfig.configPath,
      permissiveConfig.policy,
      permissiveConfig.deploymentEvidence
    )).rejects.toBeInstanceOf(OrganizationReconciliationDevelopHashSignerTransportConfigError);

    const configSymlink = await createFixture();
    const linkedConfigPath = join(configSymlink.root, "linked-config.json");
    await symlink(configSymlink.configPath, linkedConfigPath);
    await expect(loadOrganizationReconciliationDevelopHashSignerTransportConfig(
      linkedConfigPath,
      configSymlink.policy,
      configSymlink.deploymentEvidence
    )).rejects.toBeInstanceOf(OrganizationReconciliationDevelopHashSignerTransportConfigError);

    const hardlinkedConfig = await createFixture();
    await link(hardlinkedConfig.configPath, join(hardlinkedConfig.root, "hardlinked-config.json"));
    await expect(loadOrganizationReconciliationDevelopHashSignerTransportConfig(
      hardlinkedConfig.configPath,
      hardlinkedConfig.policy,
      hardlinkedConfig.deploymentEvidence
    )).rejects.toBeInstanceOf(OrganizationReconciliationDevelopHashSignerTransportConfigError);

    const permissiveToken = await createFixture();
    await chmod(permissiveToken.tokenPaths[0], 0o644);
    await expect(loadOrganizationReconciliationDevelopHashSignerTransportConfig(
      permissiveToken.configPath,
      permissiveToken.policy,
      permissiveToken.deploymentEvidence
    )).rejects.toBeInstanceOf(OrganizationReconciliationDevelopHashSignerTransportConfigError);

    const symlinkToken = await createFixture();
    const tokenTarget = join(symlinkToken.root, "token-target");
    await writeFile(tokenTarget, "replacement-token-0123456789", { mode: 0o600 });
    await rm(symlinkToken.tokenPaths[0]);
    await symlink(tokenTarget, symlinkToken.tokenPaths[0]);
    await expect(loadOrganizationReconciliationDevelopHashSignerTransportConfig(
      symlinkToken.configPath,
      symlinkToken.policy,
      symlinkToken.deploymentEvidence
    )).rejects.toBeInstanceOf(OrganizationReconciliationDevelopHashSignerTransportConfigError);

    const hardlinkedToken = await createFixture();
    await link(hardlinkedToken.tokenPaths[0], join(hardlinkedToken.root, "hardlinked-token"));
    await expect(loadOrganizationReconciliationDevelopHashSignerTransportConfig(
      hardlinkedToken.configPath,
      hardlinkedToken.policy,
      hardlinkedToken.deploymentEvidence
    )).rejects.toBeInstanceOf(OrganizationReconciliationDevelopHashSignerTransportConfigError);
  }, 20_000);

  it("rejects duplicate JSON names and invalid token bytes before fetch", async () => {
    const duplicateJson = await createFixture();
    const duplicateBody = JSON.stringify(duplicateJson.manifest).replace(
      "{",
      `{"contract":${JSON.stringify(duplicateJson.manifest.contract)},`
    );
    await writeFile(duplicateJson.configPath, duplicateBody, { mode: 0o600 });
    const fetchCalls = vi.fn();
    vi.stubGlobal("fetch", fetchCalls);
    await expect(loadOrganizationReconciliationDevelopHashSignerTransportConfig(
      duplicateJson.configPath,
      duplicateJson.policy,
      duplicateJson.deploymentEvidence
    )).rejects.toBeInstanceOf(OrganizationReconciliationDevelopHashSignerTransportConfigError);

    const invalidToken = await createFixture();
    await writeFile(invalidToken.tokenPaths[0], "contains a space is rejected", { mode: 0o600 });
    await expect(loadOrganizationReconciliationDevelopHashSignerTransportConfig(
      invalidToken.configPath,
      invalidToken.policy,
      invalidToken.deploymentEvidence
    )).rejects.toBeInstanceOf(OrganizationReconciliationDevelopHashSignerTransportConfigError);
    expect(fetchCalls).not.toHaveBeenCalled();
  });

});

async function createFixture() {
  const root = await realpath(await mkdtemp(join(tmpdir(), "iam-signer-transport-")));
  temporaryDirectories.push(root);
  const policy = {
    ...createOrganizationReconciliationPolicyForTest([1].map((index) => ({
      collectorId: `develop-collector-${index}`,
      nodeId: `develop-node-${index}`,
      keyId: `develop-key-${index}`,
      publicKey: generateKeyPairSync("ed25519").publicKey
    }))),
    environment: "xrteeth-develop"
  };
  const profile = createOrganizationReconciliationTrustedProfileForTest(policy);
  compiled.profile = profile;
  const deploymentEvidence = createOrganizationReconciliationDevelopDeploymentEvidenceForTest(
    policy.requiredCollectors
  );
  const tokenPaths = [join(root, "signer-1.token")] as const;
  await Promise.all(tokenPaths.map((path, index) =>
    writeFile(path, `signer-${index + 1}-bearer-token-0123456789`, { mode: 0o600 })));
  const certificateAuthorityPath = join(root, "private-ca.pem");
  const certificateAuthorityKeyPath = join(root, "private-ca-key.pem");
  await execFileAsync("openssl", [
    "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes", "-days", "1",
    "-subj", "/CN=Task 7.2 Test Private CA",
    "-addext", "basicConstraints=critical,CA:TRUE",
    "-addext", "keyUsage=critical,keyCertSign,cRLSign",
    "-keyout", certificateAuthorityKeyPath,
    "-out", certificateAuthorityPath
  ]);
  await chmod(certificateAuthorityPath, 0o600);
  const manifest = {
    contract: ORGANIZATION_RECONCILIATION_DEVELOP_HASH_SIGNER_TRANSPORT_CONFIG_CONTRACT,
    environment: "xrteeth-develop" as const,
    profileId: policy.profileId,
    signers: profile.requiredCollectors.map((collector, index) => ({
      keyId: collector.keyId,
      endpoint: `https://signer-${index + 1}.internal${SIGN_PATH}`,
      bearerTokenFile: tokenPaths[index]!,
      certificateAuthorityFile: certificateAuthorityPath
    }))
  };
  const configPath = join(root, "signer-transport.json");
  await writeFile(configPath, JSON.stringify(manifest), { mode: 0o600 });
  return {
    root,
    policy,
    profile,
    deploymentEvidence,
    tokenPaths,
    certificateAuthorityPath,
    manifest,
    configPath
  };
}
