import { chmod, link, mkdtemp, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { createHash, generateKeyPairSync, verify, type KeyObject } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { type IncomingMessage, type ServerResponse } from "node:http";
import {
  createOrganizationReconciliationDevelopHashSignerClient,
  OrganizationReconciliationDevelopHashSignerClientError,
  ORGANIZATION_RECONCILIATION_DEVELOP_HASH_SIGNER_HTTP_CONTRACT
} from "../src/iam-organization-reconciliation-develop-hash-signer-client.js";
import {
  createOrganizationReconciliationDevelopHashSignerSidecar,
  OrganizationReconciliationDevelopHashSignerSidecarError,
  type OrganizationReconciliationDevelopHashSignerExpectedPayload
} from "../src/iam-organization-reconciliation-develop-hash-signer-sidecar.js";
import {
  createOrganizationReconciliationProvenancePayload,
  createOrganizationReconciliationTrustPolicySha256,
  ORGANIZATION_RECONCILIATION_PROVENANCE_ALGORITHM,
  ORGANIZATION_RECONCILIATION_PROVENANCE_AUDIENCE,
  ORGANIZATION_RECONCILIATION_PROVENANCE_SIGNATURE_DOMAIN,
  ORGANIZATION_RECONCILIATION_TRUST_POLICY_CONTRACT,
  serializeOrganizationReconciliationProvenancePayload,
  type OrganizationReconciliationProvenanceBinding,
  type OrganizationReconciliationTrustPolicy
} from "../src/iam-organization-reconciliation-provenance.js";
import {
  createOrganizationReconciliationDevelopDeploymentEvidenceSha256,
  type OrganizationReconciliationDevelopDeploymentEvidence
} from "../src/iam-organization-reconciliation-develop-deployment-evidence.js";
import { createOrganizationReconciliationDevelopDeploymentEvidenceForTest } from
  "./iam-organization-reconciliation-develop-deployment-evidence.test-fixture.js";

vi.mock("../src/generated/iam-organization-reconciliation-compiled-revision.js", () => ({
  ORGANIZATION_RECONCILIATION_COMPILED_BUILD_REVISION: "a".repeat(40)
}));

vi.mock("../src/iam-organization-reconciliation-develop-deployment-topology.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import(
    "../src/iam-organization-reconciliation-develop-deployment-topology.js"
  )>();
  return {
    ...actual,
    bindOrganizationReconciliationDevelopDeploymentEvidenceToCompiledTopology: (
      candidate: OrganizationReconciliationDevelopDeploymentEvidence
    ) => Object.freeze({
      topology: Object.freeze({ profileId: "test" }),
      deploymentEvidence: candidate,
      physicalIndependenceVerified: false as const,
      productionPromotionAllowed: false as const
    })
  };
});

const TEST_NOW = new Date("2026-08-09T00:10:00.000Z");
const token = "sidecar-test-token-0123456789";
const tempDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(tempDirectories.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe("Develop hash-only Ed25519 signer sidecar", () => {
  it("accepts only canonical hash-only provenance bytes and returns a verified 64-byte signature", async () => {
    const fixture = await createFixture();
    const sidecar = await createOrganizationReconciliationDevelopHashSignerSidecar({
      privateKeyPath: fixture.privateKeyPath,
      bearerToken: token,
      expected: fixture.expected,
      deploymentEvidence: fixture.deploymentEvidence,
      now: () => TEST_NOW
    });
    const client = createOrganizationReconciliationDevelopHashSignerClient({
        endpointUrl: "https://signer-a.internal/v1/iam-organization-reconciliation/sign",
        bearerToken: token,
        allowLocalhostForDevelopmentFixture: true,
        fetchImplementation: async (_url, init) => {
          const result = sidecar.signHttpRequest(httpRequestFromFetch(init));
          return new Response(JSON.stringify(result.body), {
            status: result.status, headers: { "content-type": "application/json" }
          });
        }
      });
    const bytes = serializeOrganizationReconciliationProvenancePayload(fixture.payload);
    const signature = await client(bytes);
    expect(signature).toHaveLength(64);
    expect(verify(null, bytes, fixture.publicKey, signature)).toBe(true);
    bytes.fill(0);
    signature.fill(0);
  });

  it("rejects malformed/non-canonical input and unauthorized callers without emitting signature details", async () => {
    const fixture = await createFixture();
    const sidecar = await createOrganizationReconciliationDevelopHashSignerSidecar({
      privateKeyPath: fixture.privateKeyPath,
      bearerToken: token,
      expected: fixture.expected,
      deploymentEvidence: fixture.deploymentEvidence,
      now: () => TEST_NOW
    });
    const bytes = serializeOrganizationReconciliationProvenancePayload(fixture.payload);
    const body = Buffer.from(JSON.stringify({
      contract: ORGANIZATION_RECONCILIATION_DEVELOP_HASH_SIGNER_HTTP_CONTRACT,
      payloadBytesEncoding: "base64url",
      payloadBytesBase64url: bytes.toString("base64url"),
      payloadSha256: "0".repeat(64)
    }));
    bytes.fill(0);
    expect(sidecar.signHttpRequest({
      method: "POST", url: "/v1/iam-organization-reconciliation/sign", contentType: "application/json",
      authorization: `Bearer ${token}`, body
    })).toMatchObject({ status: 400, body: { status: "rejected" } });
    expect(sidecar.signHttpRequest({
      method: "POST", url: "/v1/iam-organization-reconciliation/sign", contentType: "application/json",
      authorization: "Bearer incorrect-token-0123456789", body
    })).toMatchObject({ status: 404, body: { status: "rejected" } });
    body.fill(0);

    const wrongNodeBytes = serializeOrganizationReconciliationProvenancePayload({ ...fixture.payload, nodeId: "node-x" });
    expect(sidecar.signHttpRequest(validHttpRequest(wrongNodeBytes))).toMatchObject({ status: 400 });
    wrongNodeBytes.fill(0);
    const expiredBytes = serializeOrganizationReconciliationProvenancePayload({
      ...fixture.payload, expiresAt: "2026-08-09T00:06:01.000Z"
    });
    expect(sidecar.signHttpRequest(validHttpRequest(expiredBytes))).toMatchObject({ status: 400 });
    expiredBytes.fill(0);
    const canonicalBytes = serializeOrganizationReconciliationProvenancePayload(fixture.payload);
    const strictBody = validHttpRequest(canonicalBytes).body;
    expect(sidecar.signHttpRequest({
      method: "POST", url: "/v1/iam-organization-reconciliation/sign", contentType: "application/json",
      authorization: `Bearer ${token}`, body: Buffer.concat([Buffer.from(" "), strictBody])
    })).toMatchObject({ status: 400 });
    canonicalBytes.fill(0);
    strictBody.fill(0);
  });

  it("rejects bad authentication before reading any request body", async () => {
    const fixture = await createFixture();
    const sidecar = await createOrganizationReconciliationDevelopHashSignerSidecar({
      privateKeyPath: fixture.privateKeyPath, bearerToken: token, expected: fixture.expected,
      deploymentEvidence: fixture.deploymentEvidence, now: () => TEST_NOW
    });
    let bodyReads = 0;
    const request = {
      method: "POST",
      url: "/v1/iam-organization-reconciliation/sign",
      headers: { "content-type": "application/json", authorization: "Bearer incorrect-token-0123456789" },
      async *[Symbol.asyncIterator]() {
        bodyReads += 1;
        yield Buffer.alloc(64 * 1024);
      }
    } as unknown as IncomingMessage;
    const writeHead = vi.fn();
    const response = {
      headersSent: false,
      writeHead,
      end: vi.fn(),
      destroy: vi.fn()
    } as unknown as ServerResponse;
    await sidecar.handle(request, response);
    expect(bodyReads).toBe(0);
    expect(writeHead).toHaveBeenCalledWith(404, expect.any(Object));
  });

  it("rejects public DNS, localhost outside a fixture, redirects, and invalid response signatures", async () => {
    expect(() => createOrganizationReconciliationDevelopHashSignerClient({
      endpointUrl: "https://signer.example.com/v1/iam-organization-reconciliation/sign",
      bearerToken: token
    })).toThrowError(OrganizationReconciliationDevelopHashSignerClientError);
    expect(() => createOrganizationReconciliationDevelopHashSignerClient({
      endpointUrl: "http://localhost/v1/iam-organization-reconciliation/sign",
      bearerToken: token
    })).toThrowError(OrganizationReconciliationDevelopHashSignerClientError);
    expect(() => createOrganizationReconciliationDevelopHashSignerClient({
      endpointUrl: "http://10.0.0.8/v1/iam-organization-reconciliation/sign",
      bearerToken: token
    })).toThrowError(OrganizationReconciliationDevelopHashSignerClientError);
    expect(() => createOrganizationReconciliationDevelopHashSignerClient({
      endpointUrl: "http://signer-a/v1/iam-organization-reconciliation/sign",
      bearerToken: token
    })).toThrowError(OrganizationReconciliationDevelopHashSignerClientError);
    expect(() => createOrganizationReconciliationDevelopHashSignerClient({
      endpointUrl: "http://localhost/v1/iam-organization-reconciliation/sign",
      bearerToken: token,
      allowLocalhostForDevelopmentFixture: true,
      fetchImplementation: vi.fn()
    })).not.toThrow();

    const fixture = await createFixture();
    const client = createOrganizationReconciliationDevelopHashSignerClient({
      endpointUrl: "https://signer-a.internal/v1/iam-organization-reconciliation/sign",
      bearerToken: token,
      allowLocalhostForDevelopmentFixture: true,
      fetchImplementation: async () => new Response(JSON.stringify({
        contract: ORGANIZATION_RECONCILIATION_DEVELOP_HASH_SIGNER_HTTP_CONTRACT,
        signatureEncoding: "base64url",
        signature: Buffer.alloc(63).toString("base64url")
      }), { status: 200, headers: { "content-type": "application/json" } })
    });
    const canonical = serializeOrganizationReconciliationProvenancePayload(fixture.payload);
    await expect(client(canonical)).rejects.toBeInstanceOf(OrganizationReconciliationDevelopHashSignerClientError);
    canonical.fill(0);
  });

  it("rejects proxy/accessor client options before any fetch", () => {
    const fetchImplementation = vi.fn();
    let getterReads = 0;
    const accessorOptions = Object.defineProperty({ bearerToken: token, fetchImplementation }, "endpointUrl", {
      enumerable: true,
      get: () => {
        getterReads += 1;
        return "https://signer-a.internal/v1/iam-organization-reconciliation/sign";
      }
    });
    expect(() => createOrganizationReconciliationDevelopHashSignerClient(accessorOptions as never)).toThrowError(
      OrganizationReconciliationDevelopHashSignerClientError
    );
    expect(getterReads).toBe(0);
    expect(fetchImplementation).not.toHaveBeenCalled();
    expect(() => createOrganizationReconciliationDevelopHashSignerClient(new Proxy({
      endpointUrl: "https://signer-a.internal/v1/iam-organization-reconciliation/sign", bearerToken: token, fetchImplementation
    }, {}))).toThrowError(OrganizationReconciliationDevelopHashSignerClientError);
    expect(fetchImplementation).not.toHaveBeenCalled();
  });

  it("rejects non-canonical payloads before fetch and strictly bounds status, content type, response size, and timeout", async () => {
    const fixture = await createFixture();
    const fetchImplementation = vi.fn(async () => new Response(JSON.stringify({
      contract: ORGANIZATION_RECONCILIATION_DEVELOP_HASH_SIGNER_HTTP_CONTRACT,
      signatureEncoding: "base64url",
      signature: Buffer.alloc(64).toString("base64url")
    }), { status: 200, headers: { "content-type": "application/json" } }));
    const preflightClient = createOrganizationReconciliationDevelopHashSignerClient({
      endpointUrl: "https://signer-a.internal/v1/iam-organization-reconciliation/sign",
      bearerToken: token,
      allowLocalhostForDevelopmentFixture: true,
      fetchImplementation
    });
    const nonCanonical = Buffer.concat([
      Buffer.from(ORGANIZATION_RECONCILIATION_PROVENANCE_SIGNATURE_DOMAIN, "utf8"),
      Buffer.from(JSON.stringify(fixture.payload, null, 2), "utf8")
    ]);
    await expect(preflightClient(nonCanonical)).rejects.toMatchObject({ failureId: "invalid-payload" });
    expect(fetchImplementation).not.toHaveBeenCalled();
    nonCanonical.fill(0);

    const canonical = serializeOrganizationReconciliationProvenancePayload(fixture.payload);
    const oversizedClient = createOrganizationReconciliationDevelopHashSignerClient({
      endpointUrl: "https://signer-a.internal/v1/iam-organization-reconciliation/sign",
      bearerToken: token,
      allowLocalhostForDevelopmentFixture: true,
      fetchImplementation: async () => new Response(Buffer.alloc(16 * 1024 + 1), {
        status: 200,
        headers: { "content-type": "application/json" }
      })
    });
    await expect(oversizedClient(canonical)).rejects.toMatchObject({ failureId: "response-invalid" });
    const wrongStatusClient = createOrganizationReconciliationDevelopHashSignerClient({
      endpointUrl: "https://signer-a.internal/v1/iam-organization-reconciliation/sign",
      bearerToken: token,
      allowLocalhostForDevelopmentFixture: true,
      fetchImplementation: async () => new Response("{}", {
        status: 201,
        headers: { "content-type": "application/json" }
      })
    });
    await expect(wrongStatusClient(canonical)).rejects.toMatchObject({ failureId: "transport-failed" });
    const wrongTypeClient = createOrganizationReconciliationDevelopHashSignerClient({
      endpointUrl: "https://signer-a.internal/v1/iam-organization-reconciliation/sign",
      bearerToken: token,
      allowLocalhostForDevelopmentFixture: true,
      fetchImplementation: async () => new Response("{}", {
        status: 200,
        headers: { "content-type": "application/json; charset=utf-8" }
      })
    });
    await expect(wrongTypeClient(canonical)).rejects.toMatchObject({ failureId: "response-invalid" });
    const timeoutClient = createOrganizationReconciliationDevelopHashSignerClient({
      endpointUrl: "https://signer-a.internal/v1/iam-organization-reconciliation/sign",
      bearerToken: token,
      timeoutMs: 100,
      allowLocalhostForDevelopmentFixture: true,
      fetchImplementation: async (_url, init) => new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(new Error("aborted")), { once: true });
      })
    });
    await expect(timeoutClient(canonical)).rejects.toMatchObject({ failureId: "transport-failed" });
    canonical.fill(0);
  });

  it("requires a single ordinary 0600 PKCS#8 Ed25519 private-key file and matching public fingerprint", async () => {
    const fixture = await createFixture();
    await chmod(fixture.privateKeyPath, 0o644);
    await expect(createOrganizationReconciliationDevelopHashSignerSidecar({
      privateKeyPath: fixture.privateKeyPath,
      bearerToken: token,
      expected: fixture.expected,
      deploymentEvidence: fixture.deploymentEvidence,
      now: () => TEST_NOW
    })).rejects.toMatchObject({ failureId: "private-key-invalid" });
    await chmod(fixture.privateKeyPath, 0o600);
    const hardlinkPath = join(fixture.directory, "private-hardlink.pem");
    await link(fixture.privateKeyPath, hardlinkPath);
    await expect(createOrganizationReconciliationDevelopHashSignerSidecar({
      privateKeyPath: fixture.privateKeyPath,
      bearerToken: token,
      expected: fixture.expected,
      deploymentEvidence: fixture.deploymentEvidence,
      now: () => TEST_NOW
    })).rejects.toBeInstanceOf(OrganizationReconciliationDevelopHashSignerSidecarError);
  });

  it("rejects symlinked, wrong-fingerprint, non-Ed25519, proxy, and accessor key configurations", async () => {
    const symlinkFixture = await createFixture();
    const symlinkPath = join(symlinkFixture.directory, "private-symlink.pem");
    await symlink(symlinkFixture.privateKeyPath, symlinkPath);
    await expect(createSidecar(symlinkPath, symlinkFixture.expected, symlinkFixture.deploymentEvidence)).rejects.toMatchObject({
      failureId: "private-key-invalid"
    });

    const wrongFingerprintFixture = await createFixture();
    await expect(createSidecar(wrongFingerprintFixture.privateKeyPath, {
      ...wrongFingerprintFixture.expected,
      publicKeySha256: "f".repeat(64)
    }, wrongFingerprintFixture.deploymentEvidence)).rejects.toMatchObject({ failureId: "invalid-config" });

    const nonEdFixture = await createFixture();
    const nonEd = generateKeyPairSync("ec", { namedCurve: "P-256" });
    await writeFile(nonEdFixture.privateKeyPath, nonEd.privateKey.export({ format: "pem", type: "pkcs8" }), { mode: 0o600 });
    await chmod(nonEdFixture.privateKeyPath, 0o600);
    await expect(createSidecar(nonEdFixture.privateKeyPath, {
      ...nonEdFixture.expected,
      publicKeySha256: createFingerprint(nonEd.publicKey)
    }, nonEdFixture.deploymentEvidence)).rejects.toMatchObject({ failureId: "invalid-config" });

    const proxyFixture = await createFixture();
    await expect(createOrganizationReconciliationDevelopHashSignerSidecar(new Proxy({
      privateKeyPath: proxyFixture.privateKeyPath,
      bearerToken: token,
      expected: proxyFixture.expected,
      deploymentEvidence: proxyFixture.deploymentEvidence,
      now: () => TEST_NOW
    }, {}))).rejects.toMatchObject({ failureId: "invalid-config" });
    let getterReads = 0;
    const accessorOptions = Object.defineProperty({
      bearerToken: token,
      expected: proxyFixture.expected,
      deploymentEvidence: proxyFixture.deploymentEvidence,
      now: () => TEST_NOW
    }, "privateKeyPath", {
      enumerable: true,
      get: () => {
        getterReads += 1;
        return proxyFixture.privateKeyPath;
      }
    });
    await expect(createOrganizationReconciliationDevelopHashSignerSidecar(accessorOptions as never))
      .rejects.toMatchObject({ failureId: "invalid-config" });
    expect(getterReads).toBe(0);
  });

  it("binds signer configuration and payloads to compiled revision A and rejects B", async () => {
    const fixture = await createFixture();
    await expect(createSidecar(fixture.privateKeyPath, {
      ...fixture.expected,
      buildRevision: "b".repeat(40)
    }, fixture.deploymentEvidence)).rejects.toMatchObject({ failureId: "invalid-config" });
    const sidecar = await createSidecar(fixture.privateKeyPath, fixture.expected, fixture.deploymentEvidence);
    const revisionB = serializeOrganizationReconciliationProvenancePayload({
      ...fixture.payload,
      collectorBuildRevision: "b".repeat(40)
    });
    expect(sidecar.signHttpRequest(validHttpRequest(revisionB))).toMatchObject({ status: 400 });
    revisionB.fill(0);
  });

  it("refuses a canonical payload whose deployment evidence digest differs by one bit", async () => {
    const fixture = await createFixture();
    await expect(createSidecar(fixture.privateKeyPath, {
      ...fixture.expected,
      deploymentEvidenceSha256: `${fixture.expected.deploymentEvidenceSha256.slice(0, -1)}${
        fixture.expected.deploymentEvidenceSha256.endsWith("a") ? "b" : "a"
      }`
    }, fixture.deploymentEvidence)).rejects.toMatchObject({ failureId: "invalid-config" });
  });
});

async function createFixture(): Promise<{
  readonly directory: string;
  readonly privateKeyPath: string;
  readonly publicKey: KeyObject;
  readonly deploymentEvidence: OrganizationReconciliationDevelopDeploymentEvidence;
  readonly expected: OrganizationReconciliationDevelopHashSignerExpectedPayload;
  readonly payload: ReturnType<typeof createOrganizationReconciliationProvenancePayload>;
}> {
  const directory = await realpath(await mkdtemp(join(tmpdir(), "identity-hash-signer-")));
  tempDirectories.push(directory);
  const first = generateKeyPairSync("ed25519");
  const privateKeyPath = join(directory, "attestation-private.pem");
  await writeFile(privateKeyPath, first.privateKey.export({ format: "pem", type: "pkcs8" }), { mode: 0o600 });
  await chmod(privateKeyPath, 0o600);
  const fingerprint = (key: typeof first.publicKey) => createFingerprint(key);
  const policy: OrganizationReconciliationTrustPolicy = {
    contract: ORGANIZATION_RECONCILIATION_TRUST_POLICY_CONTRACT,
    profileId: "xrteeth-develop-7.2",
    audience: ORGANIZATION_RECONCILIATION_PROVENANCE_AUDIENCE,
    environment: "xrteeth-develop",
    validFrom: "2026-08-09T00:00:00.000Z",
    validUntil: "2026-08-09T00:30:00.000Z",
    maxEvidenceAgeSeconds: 600,
    maxAttestationTtlSeconds: 600,
    maxCollectionWindowSeconds: 300,
    clockSkewSeconds: 0,
    requiredCollectors: [
      collector("collector-a", "node-a", "key-a", first.publicKey, fingerprint(first.publicKey))
    ]
  };
  const deploymentEvidence = createOrganizationReconciliationDevelopDeploymentEvidenceForTest(
    policy.requiredCollectors
  );
  const deploymentEvidenceSha256 =
    createOrganizationReconciliationDevelopDeploymentEvidenceSha256(deploymentEvidence);
  const expected: OrganizationReconciliationDevelopHashSignerExpectedPayload = {
    profileId: policy.profileId,
    environment: "xrteeth-develop",
    collectorId: "collector-a",
    nodeId: "node-a",
    keyId: "key-a",
    publicKeySha256: fingerprint(first.publicKey),
    trustPolicySha256: createPolicyFingerprint(policy),
    deploymentEvidenceSha256,
    buildRevision: "a".repeat(40),
    validFrom: policy.validFrom,
    validUntil: policy.validUntil,
    maxEvidenceAgeSeconds: policy.maxEvidenceAgeSeconds,
    maxAttestationTtlSeconds: policy.maxAttestationTtlSeconds,
    maxCollectionWindowSeconds: policy.maxCollectionWindowSeconds,
    clockSkewSeconds: policy.clockSkewSeconds
  };
  const binding: OrganizationReconciliationProvenanceBinding = {
    evidenceSha256: "1".repeat(64), deploymentEvidenceSha256,
    collectorContractHash: "2".repeat(64), collectorBuildRevision: "a".repeat(40),
    logicalSnapshotIdHash: "3".repeat(64), windowIdHash: "4".repeat(64),
    windowStartedAt: "2026-08-09T00:01:00.000Z", windowEndedAt: "2026-08-09T00:05:00.000Z"
  };
  return {
    directory,
    privateKeyPath,
    publicKey: first.publicKey,
    deploymentEvidence,
    expected,
    payload: createOrganizationReconciliationProvenancePayload(
      binding, policy, "key-a", "2026-08-09T00:06:00.000Z", "2026-08-09T00:11:00.000Z"
    )
  };
}

function collector(
  collectorId: string,
  nodeId: string,
  keyId: string,
  publicKey: KeyObject,
  publicKeySha256: string
) {
  return {
    collectorId, nodeId, keyId, algorithm: ORGANIZATION_RECONCILIATION_PROVENANCE_ALGORITHM as "Ed25519",
    publicKeyPem: publicKey.export({ format: "pem", type: "spki" }).toString(), publicKeySha256,
    buildRevision: "a".repeat(40), validFrom: "2026-08-09T00:00:00.000Z", validUntil: "2026-08-09T00:30:00.000Z"
  };
}

function createFingerprint(key: KeyObject): string {
  return createHash("sha256").update(key.export({ format: "der", type: "spki" })).digest("hex");
}

function createPolicyFingerprint(policy: OrganizationReconciliationTrustPolicy): string {
  return createOrganizationReconciliationTrustPolicySha256(policy);
}

function httpRequestFromFetch(init: RequestInit | undefined) {
  const headers = new Headers(init?.headers);
  if (typeof init?.body !== "string") throw new Error("unexpected test body");
  return {
    method: init?.method,
    url: "/v1/iam-organization-reconciliation/sign",
    contentType: headers.get("content-type") ?? undefined,
    authorization: headers.get("authorization") ?? undefined,
    body: Buffer.from(init.body, "utf8")
  };
}

function validHttpRequest(payload: Uint8Array) {
  const encoded = Buffer.from(payload).toString("base64url");
  return {
    method: "POST",
    url: "/v1/iam-organization-reconciliation/sign",
    contentType: "application/json",
    authorization: `Bearer ${token}`,
    body: Buffer.from(JSON.stringify({
      contract: ORGANIZATION_RECONCILIATION_DEVELOP_HASH_SIGNER_HTTP_CONTRACT,
      payloadBytesEncoding: "base64url",
      payloadBytesBase64url: encoded,
      payloadSha256: createHash("sha256").update(payload).digest("hex")
    }))
  };
}

function createSidecar(
  privateKeyPath: string,
  expected: OrganizationReconciliationDevelopHashSignerExpectedPayload,
  deploymentEvidence: OrganizationReconciliationDevelopDeploymentEvidence
) {
  return createOrganizationReconciliationDevelopHashSignerSidecar({
    privateKeyPath,
    bearerToken: token,
    expected,
    deploymentEvidence,
    now: () => TEST_NOW
  });
}
