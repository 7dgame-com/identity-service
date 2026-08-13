import {
  createHash,
  createPublicKey,
  generateKeyPairSync,
  verify,
  X509Certificate,
  type KeyObject
} from "node:crypto";
import { execFile } from "node:child_process";
import { EventEmitter } from "node:events";
import { existsSync } from "node:fs";
import { chmod, link, mkdtemp, readFile, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  ORGANIZATION_RECONCILIATION_PROVENANCE_ALGORITHM,
  ORGANIZATION_RECONCILIATION_PROVENANCE_AUDIENCE,
  ORGANIZATION_RECONCILIATION_TRUST_POLICY_CONTRACT,
  createOrganizationReconciliationProvenancePayload,
  createOrganizationReconciliationTrustPolicySha256,
  serializeOrganizationReconciliationProvenancePayload,
  type OrganizationReconciliationTrustPolicy,
  type OrganizationReconciliationTrustedProfile
} from "../src/iam-organization-reconciliation-provenance.js";
import {
  createOrganizationReconciliationDevelopDeploymentEvidenceSha256
} from "../src/iam-organization-reconciliation-develop-deployment-evidence.js";
import {
  createOrganizationReconciliationDevelopDeploymentEvidenceForTest
} from "./iam-organization-reconciliation-develop-deployment-evidence.test-fixture.js";
import {
  createOrganizationReconciliationDevelopHashSignerClient
} from "../src/iam-organization-reconciliation-develop-hash-signer-client.js";

const REVISION = "a".repeat(40);
const TOKEN = "develop-hash-signer-test-token-" + "x".repeat(40);
const execFileAsync = promisify(execFile);
const OPENSSL = existsSync("/opt/homebrew/bin/openssl") ? "/opt/homebrew/bin/openssl" : "openssl";
const tempDirectories: string[] = [];
let capturedServerOptions: Record<string, unknown> | undefined;
let capturedRequestListener: ((request: never, response: never) => void) | undefined;
let capturedSidecarOptions: Record<string, unknown> | undefined;
let createServerCalls = 0;
let deferFakeClose = false;
let releaseFakeClose: (() => void) | undefined;

afterEach(async () => {
  vi.resetModules();
  vi.doUnmock("../src/generated/iam-organization-reconciliation-compiled-revision.js");
  vi.doUnmock("../src/iam-organization-reconciliation-trust-profiles.js");
  vi.doUnmock("../src/iam-organization-reconciliation-develop-deployment-topology.js");
  vi.doUnmock("../src/iam-organization-reconciliation-develop-hash-signer-sidecar.js");
  vi.doUnmock("node:https");
  capturedServerOptions = undefined;
  capturedRequestListener = undefined;
  capturedSidecarOptions = undefined;
  createServerCalls = 0;
  deferFakeClose = false;
  releaseFakeClose = undefined;
  await Promise.all(tempDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe("Develop hash-signer HTTPS launcher", () => {
  it("fails closed on the committed zero-profile build before reading config or listening", async () => {
    const {
      startOrganizationReconciliationDevelopHashSignerHttpsLauncher,
      ORGANIZATION_RECONCILIATION_DEVELOP_HASH_SIGNER_HTTPS_READY
    } = await import("../src/iam-organization-reconciliation-develop-hash-signer-https-launcher.js");
    expect(ORGANIZATION_RECONCILIATION_DEVELOP_HASH_SIGNER_HTTPS_READY).toBe(false);
    await expect(startOrganizationReconciliationDevelopHashSignerHttpsLauncher({
      configPath: "/private/tmp/this-config-must-not-be-read.json"
    })).rejects.toMatchObject({ failureId: "trust-profile-not-provisioned" });
  });

  it("derives every signer pin from the compiled profile and public policy, then serves TLS 1.2+ only", async () => {
    const fixture = await createFixture();
    installLauncherMocks(fixture.profile);
    const {
      ORGANIZATION_RECONCILIATION_DEVELOP_HASH_SIGNER_HTTPS_LIMITS,
      startOrganizationReconciliationDevelopHashSignerHttpsLauncher
    } = await import("../src/iam-organization-reconciliation-develop-hash-signer-https-launcher.js");
    const logs: unknown[] = [];
    const launcher = await startOrganizationReconciliationDevelopHashSignerHttpsLauncher({
      configPath: fixture.configPath,
      log: (event) => logs.push(event)
    });
    try {
      expect(launcher.ready).toBe(false);
      expect(ORGANIZATION_RECONCILIATION_DEVELOP_HASH_SIGNER_HTTPS_LIMITS).toMatchObject({
        minimumTlsVersion: "TLSv1.2",
        maximumRequestBytes: 65_536,
        maximumConnections: 32,
        maximumRequestsPerSocket: 4,
        requestTimeoutMs: 5_000,
        headersTimeoutMs: 3_000,
        keepAliveTimeoutMs: 1_000
      });

      expect(createServerCalls).toBe(1);
      expect(capturedServerOptions).toMatchObject({
        minVersion: "TLSv1.2",
        maxVersion: "TLSv1.3",
        maxHeaderSize: 8_192,
        requestTimeout: 5_000,
        headersTimeout: 3_000,
        keepAliveTimeout: 1_000
      });
      expect(capturedServerOptions?.key).toBeInstanceOf(Buffer);
      expect(capturedServerOptions?.cert).toBeInstanceOf(Buffer);
      expect(capturedRequestListener).toBeTypeOf("function");
      expect(capturedSidecarOptions).toMatchObject({
        privateKeyPath: fixture.signerPrivateKeyPath,
        bearerToken: TOKEN,
        ready: false,
        expected: {
          profileId: fixture.profile.profileId,
          environment: "xrteeth-develop",
          collectorId: "collector-a",
          nodeId: "node-a",
          keyId: "key-a",
          publicKeySha256: fixture.profile.requiredCollectors[0]!.publicKeySha256,
          trustPolicySha256: fixture.profile.policySha256,
          deploymentEvidenceSha256: fixture.deploymentEvidenceSha256,
          buildRevision: REVISION,
          validFrom: fixture.policy.requiredCollectors[0]!.validFrom,
          validUntil: fixture.policy.requiredCollectors[0]!.validUntil,
          maxEvidenceAgeSeconds: fixture.policy.maxEvidenceAgeSeconds,
          maxAttestationTtlSeconds: fixture.policy.maxAttestationTtlSeconds,
          maxCollectionWindowSeconds: fixture.policy.maxCollectionWindowSeconds,
          clockSkewSeconds: fixture.policy.clockSkewSeconds
        }
      });
      const response = createFakeResponse();
      capturedRequestListener?.({
        headers: { "content-length": "65537" },
        setTimeout: vi.fn(),
        destroy: vi.fn()
      } as never, response as never);
      expect(response.writeHead).toHaveBeenCalledWith(400, expect.objectContaining({ Connection: "close" }));
      expect(JSON.stringify(logs)).not.toContain(TOKEN);
      expect(JSON.stringify(logs)).not.toContain(fixture.directory);
      expect(logs).toEqual([expect.objectContaining({
        event: "listening",
        environment: "xrteeth-develop",
        ready: false,
        profileIdSha256: expect.stringMatching(/^[a-f0-9]{64}$/),
        collectorIdSha256: expect.stringMatching(/^[a-f0-9]{64}$/),
        nodeIdSha256: expect.stringMatching(/^[a-f0-9]{64}$/)
      })]);
    } finally {
      await launcher.close();
    }
    await expect(launcher.closed).resolves.toBe("requested");
    expect(logs).toEqual([
      expect.objectContaining({ event: "listening" }),
      expect.objectContaining({ event: "stopping" }),
      expect.objectContaining({ event: "stopped" })
    ]);
  });

  it("rejects runtime pin fields, proxy/accessor options, non-0600 and linked secret files before listen", async () => {
    const fixture = await createFixture();
    installLauncherMocks(fixture.profile);
    const {
      startOrganizationReconciliationDevelopHashSignerHttpsLauncher
    } = await import("../src/iam-organization-reconciliation-develop-hash-signer-https-launcher.js");

    const proxy = new Proxy({ configPath: fixture.configPath }, {});
    await expect(startOrganizationReconciliationDevelopHashSignerHttpsLauncher(proxy))
      .rejects.toMatchObject({ failureId: "invalid-launcher-options" });
    let reads = 0;
    const accessor = Object.defineProperty({}, "configPath", {
      enumerable: true,
      get: () => {
        reads += 1;
        return fixture.configPath;
      }
    });
    await expect(startOrganizationReconciliationDevelopHashSignerHttpsLauncher(accessor as never))
      .rejects.toMatchObject({ failureId: "invalid-launcher-options" });
    expect(reads).toBe(0);

    await rewriteConfig(fixture, { buildRevision: "b".repeat(40) });
    await expect(startOrganizationReconciliationDevelopHashSignerHttpsLauncher({ configPath: fixture.configPath }))
      .rejects.toMatchObject({ failureId: "invalid-launcher-config" });
    await rewriteConfig(fixture);

    await chmod(fixture.tokenPath, 0o644);
    await expect(startOrganizationReconciliationDevelopHashSignerHttpsLauncher({ configPath: fixture.configPath }))
      .rejects.toMatchObject({ failureId: "tls-material-invalid" });
    await chmod(fixture.tokenPath, 0o600);

    const tokenLink = join(fixture.directory, "token-hardlink");
    await link(fixture.tokenPath, tokenLink);
    await expect(startOrganizationReconciliationDevelopHashSignerHttpsLauncher({ configPath: fixture.configPath }))
      .rejects.toMatchObject({ failureId: "tls-material-invalid" });
    await rm(tokenLink);

    const configLink = join(fixture.directory, "config-link.json");
    await symlink(fixture.configPath, configLink);
    await expect(startOrganizationReconciliationDevelopHashSignerHttpsLauncher({ configPath: configLink }))
      .rejects.toMatchObject({ failureId: "invalid-launcher-config" });
  });

  it("rejects mismatched policy pins and TLS certificate/private-key pairs without opening a listener", async () => {
    const fixture = await createFixture();
    installLauncherMocks({ ...fixture.profile, policySha256: "f".repeat(64) });
    let module = await import("../src/iam-organization-reconciliation-develop-hash-signer-https-launcher.js");
    await expect(module.startOrganizationReconciliationDevelopHashSignerHttpsLauncher({
      configPath: fixture.configPath
    })).rejects.toMatchObject({ failureId: "trust-profile-mismatch" });

    vi.resetModules();
    installLauncherMocks(fixture.profile);
    module = await import("../src/iam-organization-reconciliation-develop-hash-signer-https-launcher.js");
    const secondDirectory = await createTlsPair(fixture.directory, "second");
    await writeFile(fixture.tlsCertificatePath, await import("node:fs/promises").then((fs) =>
      fs.readFile(secondDirectory.certificatePath)), { mode: 0o600 });
    await chmod(fixture.tlsCertificatePath, 0o600);
    await expect(module.startOrganizationReconciliationDevelopHashSignerHttpsLauncher({
      configPath: fixture.configPath
    })).rejects.toMatchObject({ failureId: "tls-material-invalid" });
  });

  it("runs a real private-CA TLS client through the launcher and sidecar with an exact leaf DER pin", async () => {
    const port = 8_443;
    const base = await createFixture(port);
    const chain = await createPrivateCaTlsPair(base.directory, "live");
    const fixture = await bindFixtureTls(base, chain);
    installCompiledProfileOnly(fixture.profile);
    const {
      startOrganizationReconciliationDevelopHashSignerHttpsLauncher
    } = await import("../src/iam-organization-reconciliation-develop-hash-signer-https-launcher.js");
    const launcher = await startOrganizationReconciliationDevelopHashSignerHttpsLauncher({
      configPath: fixture.configPath
    });
    const certificateAuthorityPem = await readFile(chain.certificateAuthorityPath);
    const now = Date.now();
    const payload = createOrganizationReconciliationProvenancePayload({
      evidenceSha256: "1".repeat(64),
      deploymentEvidenceSha256: fixture.deploymentEvidenceSha256,
      collectorContractHash: "2".repeat(64),
      collectorBuildRevision: REVISION,
      logicalSnapshotIdHash: "3".repeat(64),
      windowIdHash: "4".repeat(64),
      windowStartedAt: new Date(now - 20_000).toISOString(),
      windowEndedAt: new Date(now - 5_000).toISOString()
    }, fixture.policy, "key-a", new Date(now).toISOString(), new Date(now + 120_000).toISOString());
    const payloadBytes = serializeOrganizationReconciliationProvenancePayload(payload);
    try {
      const client = createOrganizationReconciliationDevelopHashSignerClient({
        endpointUrl: `https://localhost:${port}/v1/iam-organization-reconciliation/sign`,
        bearerToken: TOKEN,
        tlsCertificateSha256: fixture.localTlsCertificateSha256,
        certificateAuthorityPem,
        allowLocalhostForDevelopmentFixture: true
      });
      const signature = await client(payloadBytes);
      try {
        expect(verify(
          null,
          payloadBytes,
          createPublicKey(fixture.policy.requiredCollectors[0]!.publicKeyPem),
          signature
        )).toBe(true);
      } finally {
        signature.fill(0);
      }

      const wrongPinClient = createOrganizationReconciliationDevelopHashSignerClient({
        endpointUrl: `https://localhost:${port}/v1/iam-organization-reconciliation/sign`,
        bearerToken: TOKEN,
        tlsCertificateSha256: "f".repeat(64),
        certificateAuthorityPem,
        allowLocalhostForDevelopmentFixture: true
      });
      await expect(wrongPinClient(payloadBytes)).rejects.toMatchObject({ failureId: "transport-failed" });
    } finally {
      payloadBytes.fill(0);
      certificateAuthorityPem.fill(0);
      await launcher.close();
    }
    await expect(launcher.closed).resolves.toBe("requested");
  });

  it("rejects a TLS certificate whose SPKI is the attestation signing key even when the leaf pin matches", async () => {
    const fixture = await createFixture();
    await writeFile(
      fixture.tlsPrivateKeyPath,
      await readFile(fixture.signerPrivateKeyPath),
      { mode: 0o600 }
    );
    await chmod(fixture.tlsPrivateKeyPath, 0o600);
    await execFileAsync(OPENSSL, [
      "req", "-x509", "-new", "-key", fixture.tlsPrivateKeyPath, "-days", "1",
      "-subj", "/CN=localhost", "-out", fixture.tlsCertificatePath
    ]);
    await chmod(fixture.tlsCertificatePath, 0o600);
    const rebound = await bindFixtureTls(fixture, {
      privateKeyPath: fixture.tlsPrivateKeyPath,
      certificatePath: fixture.tlsCertificatePath
    });
    installCompiledProfileOnly(rebound.profile);
    const {
      startOrganizationReconciliationDevelopHashSignerHttpsLauncher
    } = await import("../src/iam-organization-reconciliation-develop-hash-signer-https-launcher.js");
    await expect(startOrganizationReconciliationDevelopHashSignerHttpsLauncher({
      configPath: rebound.configPath
    })).rejects.toMatchObject({ failureId: "tls-material-invalid" });
  });

  it("does not resolve graceful shutdown until the HTTPS server close event/callback completes", async () => {
    const fixture = await createFixture();
    installLauncherMocks(fixture.profile);
    deferFakeClose = true;
    const {
      startOrganizationReconciliationDevelopHashSignerHttpsLauncher
    } = await import("../src/iam-organization-reconciliation-develop-hash-signer-https-launcher.js");
    const launcher = await startOrganizationReconciliationDevelopHashSignerHttpsLauncher({
      configPath: fixture.configPath
    });
    let resolved = false;
    const closing = launcher.close().then(() => { resolved = true; });
    await Promise.resolve();
    await Promise.resolve();
    expect(resolved).toBe(false);
    expect(releaseFakeClose).toBeTypeOf("function");
    releaseFakeClose?.();
    await closing;
    expect(resolved).toBe(true);
    await expect(launcher.closed).resolves.toBe("requested");
  });
});

interface Fixture {
  readonly directory: string;
  readonly port: number;
  readonly configPath: string;
  readonly policyPath: string;
  readonly deploymentEvidencePath: string;
  readonly deploymentEvidenceSha256: string;
  readonly localTlsCertificateSha256: string;
  readonly signerPrivateKeyPath: string;
  readonly tlsPrivateKeyPath: string;
  readonly tlsCertificatePath: string;
  readonly tokenPath: string;
  readonly profile: OrganizationReconciliationTrustedProfile;
  readonly policy: OrganizationReconciliationTrustPolicy;
}

async function createFixture(port = 8_443): Promise<Fixture> {
  const directory = await realpath(await mkdtemp(join(tmpdir(), "identity-signer-https-")));
  tempDirectories.push(directory);
  const signerA = generateKeyPairSync("ed25519");
  const signerPrivateKeyPath = join(directory, "signer-private.pem");
  await writeFile(signerPrivateKeyPath, signerA.privateKey.export({ format: "pem", type: "pkcs8" }), { mode: 0o600 });
  await chmod(signerPrivateKeyPath, 0o600);
  const now = Date.now();
  const validFrom = new Date(now - 60_000).toISOString();
  const validUntil = new Date(now + 60 * 60_000).toISOString();
  const collector = (collectorId: string, nodeId: string, keyId: string, key: KeyObject) => ({
    collectorId,
    nodeId,
    keyId,
    algorithm: ORGANIZATION_RECONCILIATION_PROVENANCE_ALGORITHM as "Ed25519",
    publicKeyPem: key.export({ format: "pem", type: "spki" }).toString(),
    publicKeySha256: keyFingerprint(key),
    buildRevision: REVISION,
    validFrom,
    validUntil
  });
  const policy: OrganizationReconciliationTrustPolicy = {
    contract: ORGANIZATION_RECONCILIATION_TRUST_POLICY_CONTRACT,
    profileId: "xrteeth-develop-7.2",
    audience: ORGANIZATION_RECONCILIATION_PROVENANCE_AUDIENCE,
    environment: "xrteeth-develop",
    validFrom,
    validUntil,
    maxEvidenceAgeSeconds: 600,
    maxAttestationTtlSeconds: 600,
    maxCollectionWindowSeconds: 300,
    clockSkewSeconds: 30,
    requiredCollectors: [
      collector("collector-a", "node-a", "key-a", signerA.publicKey)
    ]
  };
  const policyPath = join(directory, "trust-policy.json");
  await writeFile(policyPath, `${JSON.stringify(policy, null, 2)}\n`, { mode: 0o600 });
  await chmod(policyPath, 0o600);
  const profile: OrganizationReconciliationTrustedProfile = {
    profileId: policy.profileId,
    policySha256: createOrganizationReconciliationTrustPolicySha256(policy),
    expectedEnvironment: policy.environment,
    requiredCollectors: policy.requiredCollectors.map(({ collectorId, nodeId, keyId, publicKeySha256, buildRevision }) => ({
      collectorId, nodeId, keyId, publicKeySha256, buildRevision
    }))
  };
  const tls = await createTlsPair(directory, "primary");
  const baseDeploymentEvidence =
    createOrganizationReconciliationDevelopDeploymentEvidenceForTest(policy.requiredCollectors);
  const tlsCertificate = new X509Certificate(await readFile(tls.certificatePath));
  const localTlsCertificateSha256 = createHash("sha256")
    .update(tlsCertificate.raw)
    .digest("hex");
  const deploymentEvidence = {
    ...baseDeploymentEvidence,
    signers: [
      { ...baseDeploymentEvidence.signers[0], tlsCertificateSha256: localTlsCertificateSha256 }
    ] as const
  };
  const deploymentEvidencePath = join(directory, "deployment-evidence.json");
  await writeFile(deploymentEvidencePath, `${JSON.stringify(deploymentEvidence, null, 2)}\n`, { mode: 0o600 });
  await chmod(deploymentEvidencePath, 0o600);
  const tokenPath = join(directory, "bearer-token");
  await writeFile(tokenPath, TOKEN, { mode: 0o600 });
  await chmod(tokenPath, 0o600);
  const configPath = join(directory, "launcher.json");
  const fixture: Fixture = {
    directory,
    port,
    configPath,
    policyPath,
    deploymentEvidencePath,
    deploymentEvidenceSha256:
      createOrganizationReconciliationDevelopDeploymentEvidenceSha256(deploymentEvidence),
    localTlsCertificateSha256,
    signerPrivateKeyPath,
    tlsPrivateKeyPath: tls.privateKeyPath,
    tlsCertificatePath: tls.certificatePath,
    tokenPath,
    profile,
    policy
  };
  await rewriteConfig(fixture);
  return fixture;
}

async function rewriteConfig(fixture: Fixture, extra: Record<string, unknown> = {}): Promise<void> {
  const config = {
    contract: "iam-organization-reconciliation-xrteeth-develop-hash-signer-https-launcher/v1",
    environment: "xrteeth-develop",
    collectorId: "collector-a",
    listen: { host: "127.0.0.1", port: fixture.port },
    trustPolicyPath: fixture.policyPath,
    deploymentEvidencePath: fixture.deploymentEvidencePath,
    signerPrivateKeyPath: fixture.signerPrivateKeyPath,
    tlsPrivateKeyPath: fixture.tlsPrivateKeyPath,
    tlsCertificatePath: fixture.tlsCertificatePath,
    bearerTokenPath: fixture.tokenPath,
    ...extra
  };
  await writeFile(fixture.configPath, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });
  await chmod(fixture.configPath, 0o600);
}

function installLauncherMocks(profile: OrganizationReconciliationTrustedProfile): void {
  installCompiledProfileOnly(profile);
  vi.doMock("../src/iam-organization-reconciliation-develop-hash-signer-sidecar.js", () => ({
    createOrganizationReconciliationDevelopHashSignerSidecar: async (options: Record<string, unknown>) => {
      capturedSidecarOptions = options;
      return Object.freeze({
        handle: async () => undefined,
        signHttpRequest: () => Object.freeze({ status: 400, body: Object.freeze({ status: "rejected" }) })
      });
    }
  }));
  vi.doMock("node:https", async () => {
    const actual = await vi.importActual<typeof import("node:https")>("node:https");
    return {
      ...actual,
      createServer: (options: Record<string, unknown>, listener: (request: never, response: never) => void) => {
        createServerCalls += 1;
        capturedServerOptions = options;
        capturedRequestListener = listener;
        return new FakeHttpsServer();
      }
    };
  });
}

function installCompiledProfileOnly(profile: OrganizationReconciliationTrustedProfile): void {
  vi.doMock("../src/generated/iam-organization-reconciliation-compiled-revision.js", () => ({
    ORGANIZATION_RECONCILIATION_COMPILED_BUILD_REVISION: REVISION
  }));
  vi.doMock("../src/iam-organization-reconciliation-trust-profiles.js", () => ({
    compiledOrganizationReconciliationTrustProfileCount: 1,
    resolveCompiledOrganizationReconciliationTrustProfile: (profileId: string) =>
      profileId === profile.profileId ? profile : undefined
  }));
  vi.doMock("../src/iam-organization-reconciliation-develop-deployment-topology.js", () => ({
    bindOrganizationReconciliationDevelopDeploymentEvidenceToCompiledTopology: (candidate: unknown) =>
      Object.freeze({ topology: Object.freeze({ profileId: profile.profileId }), deploymentEvidence: candidate,
        physicalIndependenceVerified: false as const, productionPromotionAllowed: false as const })
  }));
}

async function createTlsPair(directory: string, name: string): Promise<{
  privateKeyPath: string;
  certificatePath: string;
}> {
  const privateKeyPath = join(directory, `${name}-tls-private.pem`);
  const certificatePath = join(directory, `${name}-tls-certificate.pem`);
  await execFileAsync(OPENSSL, [
    "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes", "-days", "1",
    "-subj", "/CN=localhost", "-keyout", privateKeyPath, "-out", certificatePath
  ]);
  await chmod(privateKeyPath, 0o600);
  await chmod(certificatePath, 0o600);
  return { privateKeyPath, certificatePath };
}

async function createPrivateCaTlsPair(directory: string, name: string): Promise<{
  privateKeyPath: string;
  certificatePath: string;
  certificateAuthorityPath: string;
}> {
  const certificateAuthorityKeyPath = join(directory, `${name}-private-ca-key.pem`);
  const certificateAuthorityPath = join(directory, `${name}-private-ca.pem`);
  const privateKeyPath = join(directory, `${name}-tls-private.pem`);
  const requestPath = join(directory, `${name}-tls.csr`);
  const certificatePath = join(directory, `${name}-tls-certificate.pem`);
  const extensionPath = join(directory, `${name}-tls-extensions.cnf`);
  await execFileAsync(OPENSSL, [
    "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes", "-days", "1",
    "-subj", "/CN=Task 7.2 Test Private CA",
    "-addext", "basicConstraints=critical,CA:TRUE",
    "-addext", "keyUsage=critical,keyCertSign,cRLSign",
    "-keyout", certificateAuthorityKeyPath,
    "-out", certificateAuthorityPath
  ]);
  await execFileAsync(OPENSSL, [
    "req", "-newkey", "rsa:2048", "-sha256", "-nodes",
    "-subj", "/CN=localhost",
    "-addext", "subjectAltName=DNS:localhost",
    "-keyout", privateKeyPath,
    "-out", requestPath
  ]);
  await writeFile(extensionPath, [
    "basicConstraints=critical,CA:FALSE",
    "keyUsage=critical,digitalSignature,keyEncipherment",
    "extendedKeyUsage=serverAuth",
    "subjectAltName=DNS:localhost",
    ""
  ].join("\n"), { mode: 0o600 });
  await execFileAsync(OPENSSL, [
    "x509", "-req", "-in", requestPath,
    "-CA", certificateAuthorityPath,
    "-CAkey", certificateAuthorityKeyPath,
    "-CAcreateserial", "-days", "1", "-sha256",
    "-extfile", extensionPath,
    "-out", certificatePath
  ]);
  await Promise.all([
    chmod(privateKeyPath, 0o600),
    chmod(certificatePath, 0o600),
    chmod(certificateAuthorityPath, 0o600)
  ]);
  return { privateKeyPath, certificatePath, certificateAuthorityPath };
}

async function bindFixtureTls(
  fixture: Fixture,
  tls: Readonly<{ privateKeyPath: string; certificatePath: string }>
): Promise<Fixture> {
  const certificate = new X509Certificate(await readFile(tls.certificatePath));
  const localTlsCertificateSha256 = createHash("sha256").update(certificate.raw).digest("hex");
  const deploymentEvidence = JSON.parse(
    await readFile(fixture.deploymentEvidencePath, "utf8")
  ) as ReturnType<typeof createOrganizationReconciliationDevelopDeploymentEvidenceForTest>;
  const reboundEvidence = {
    ...deploymentEvidence,
    signers: [
      { ...deploymentEvidence.signers[0], tlsCertificateSha256: localTlsCertificateSha256 }
    ] as const
  };
  await writeFile(
    fixture.deploymentEvidencePath,
    `${JSON.stringify(reboundEvidence, null, 2)}\n`,
    { mode: 0o600 }
  );
  await chmod(fixture.deploymentEvidencePath, 0o600);
  const rebound: Fixture = {
    ...fixture,
    tlsPrivateKeyPath: tls.privateKeyPath,
    tlsCertificatePath: tls.certificatePath,
    localTlsCertificateSha256,
    deploymentEvidenceSha256:
      createOrganizationReconciliationDevelopDeploymentEvidenceSha256(reboundEvidence)
  };
  await rewriteConfig(rebound);
  return rebound;
}

class FakeHttpsServer extends EventEmitter {
  listening = false;
  maxConnections = 0;
  maxHeadersCount: number | null = null;
  maxRequestsPerSocket = 0;
  requestTimeout = 0;
  headersTimeout = 0;
  keepAliveTimeout = 0;
  timeout = 0;

  listen(_options: unknown): this {
    this.listening = true;
    queueMicrotask(() => this.emit("listening"));
    return this;
  }

  close(callback?: () => void): this {
    this.listening = false;
    const complete = () => {
      this.emit("close");
      callback?.();
    };
    if (deferFakeClose) releaseFakeClose = complete;
    else queueMicrotask(complete);
    return this;
  }

  closeAllConnections(): void {}
  closeIdleConnections(): void {}
}

function createFakeResponse() {
  const response = {
    headersSent: false,
    writeHead: vi.fn(),
    end: vi.fn(),
    destroy: vi.fn()
  };
  return response;
}

function keyFingerprint(key: KeyObject): string {
  return createHash("sha256").update(key.export({ format: "der", type: "spki" })).digest("hex");
}
