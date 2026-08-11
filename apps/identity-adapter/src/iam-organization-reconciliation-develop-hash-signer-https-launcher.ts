import {
  createHash,
  createPrivateKey,
  createPublicKey,
  timingSafeEqual,
  X509Certificate,
  type KeyObject
} from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { lstat, open, realpath, type FileHandle } from "node:fs/promises";
import { createServer, type Server as HttpsServer, type ServerOptions } from "node:https";
import { isIP, Socket } from "node:net";
import { dirname, isAbsolute, resolve } from "node:path";
import { isProxy } from "node:util/types";
import {
  ORGANIZATION_RECONCILIATION_COMPILED_BUILD_REVISION
} from "./generated/iam-organization-reconciliation-compiled-revision.js";
import {
  createOrganizationReconciliationDevelopDeploymentEvidenceSha256,
  parseOrganizationReconciliationDevelopDeploymentEvidence,
  type OrganizationReconciliationDevelopDeploymentEvidence,
  type OrganizationReconciliationDevelopDeploymentSigner
} from "./iam-organization-reconciliation-develop-deployment-evidence.js";
import {
  bindOrganizationReconciliationDevelopDeploymentEvidenceToCompiledTopology
} from "./iam-organization-reconciliation-develop-deployment-topology.js";
import {
  createOrganizationReconciliationDevelopHashSignerSidecar,
  type OrganizationReconciliationDevelopHashSignerExpectedPayload
} from "./iam-organization-reconciliation-develop-hash-signer-sidecar.js";
import {
  createOrganizationReconciliationTrustPolicySha256,
  parseOrganizationReconciliationTrustPolicy,
  type OrganizationReconciliationTrustPolicy,
  type OrganizationReconciliationTrustedCollector,
  type OrganizationReconciliationTrustedProfile
} from "./iam-organization-reconciliation-provenance.js";
import {
  compiledOrganizationReconciliationTrustProfileCount,
  resolveCompiledOrganizationReconciliationTrustProfile
} from "./iam-organization-reconciliation-trust-profiles.js";

export const ORGANIZATION_RECONCILIATION_DEVELOP_HASH_SIGNER_HTTPS_LAUNCHER_CONTRACT =
  "iam-organization-reconciliation-xrteeth-develop-hash-signer-https-launcher/v1" as const;

/** This launcher has no readiness or promotion path. */
export const ORGANIZATION_RECONCILIATION_DEVELOP_HASH_SIGNER_HTTPS_READY = false as const;

export const ORGANIZATION_RECONCILIATION_DEVELOP_HASH_SIGNER_HTTPS_LIMITS = Object.freeze({
  minimumTlsVersion: "TLSv1.2" as const,
  maximumRequestBytes: 64 * 1024,
  maximumHeaderBytes: 8 * 1024,
  maximumHeaderCount: 32,
  maximumConnections: 32,
  maximumRequestsPerSocket: 4,
  requestTimeoutMs: 5_000,
  headersTimeoutMs: 3_000,
  socketTimeoutMs: 5_000,
  keepAliveTimeoutMs: 1_000,
  gracefulShutdownMs: 5_000
});

const MAX_CONFIG_BYTES = 32 * 1024;
const MAX_POLICY_BYTES = 1024 * 1024;
const MAX_TLS_PRIVATE_KEY_BYTES = 32 * 1024;
const MAX_TLS_CERTIFICATE_BYTES = 64 * 1024;
const MAX_BEARER_TOKEN_BYTES = 256;
const MIN_BEARER_TOKEN_BYTES = 32;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const FULL_REVISION = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;

export interface OrganizationReconciliationDevelopHashSignerHttpsLauncherOptions {
  readonly configPath: string;
  readonly log?: (event: OrganizationReconciliationDevelopHashSignerHttpsLogEvent) => void;
}

export interface OrganizationReconciliationDevelopHashSignerHttpsLogEvent {
  readonly event: "listening" | "stopping" | "stopped" | "transport-failed";
  readonly environment: "xrteeth-develop";
  readonly profileIdSha256: string;
  readonly collectorIdSha256: string;
  readonly nodeIdSha256: string;
  readonly ready: false;
}

export interface OrganizationReconciliationDevelopHashSignerHttpsLauncher {
  readonly close: () => Promise<void>;
  readonly closed: Promise<"requested" | "transport-failed">;
  readonly ready: false;
}

export class OrganizationReconciliationDevelopHashSignerHttpsLauncherError extends Error {
  constructor(readonly failureId:
    | "trust-profile-not-provisioned"
    | "invalid-launcher-options"
    | "invalid-launcher-config"
    | "trust-policy-invalid"
    | "deployment-evidence-invalid"
    | "trust-profile-mismatch"
    | "bearer-token-invalid"
    | "tls-material-invalid"
    | "signer-private-key-invalid"
    | "listen-failed") {
    super(failureId);
    this.name = "OrganizationReconciliationDevelopHashSignerHttpsLauncherError";
  }
}

interface LauncherConfig {
  readonly contract: typeof ORGANIZATION_RECONCILIATION_DEVELOP_HASH_SIGNER_HTTPS_LAUNCHER_CONTRACT;
  readonly environment: "xrteeth-develop";
  readonly collectorId: string;
  readonly listen: Readonly<{ host: string; port: number }>;
  readonly trustPolicyPath: string;
  readonly deploymentEvidencePath: string;
  readonly signerPrivateKeyPath: string;
  readonly tlsPrivateKeyPath: string;
  readonly tlsCertificatePath: string;
  readonly bearerTokenPath: string;
}

interface StrictFile {
  readonly bytes: Buffer;
  readonly device: number;
  readonly inode: number;
}

interface SanitizedLogIdentity {
  readonly profileIdSha256: string;
  readonly collectorIdSha256: string;
  readonly nodeIdSha256: string;
}

/**
 * Starts exactly one Develop-only TLS signer endpoint. The compiled trust gate
 * runs before config, secret, private-key, or listener access. Runtime input
 * selects a compiled collector but cannot provide any trust pin or revision.
 */
export async function startOrganizationReconciliationDevelopHashSignerHttpsLauncher(
  candidate: OrganizationReconciliationDevelopHashSignerHttpsLauncherOptions
): Promise<OrganizationReconciliationDevelopHashSignerHttpsLauncher> {
  assertCompiledProfileProvisioned();
  const options = captureLauncherOptions(candidate);
  const config = await loadLauncherConfig(options.configPath);
  const { policy, profile, collector } = await loadAndBindPublicTrustPolicy(config);
  const deployment = await loadAndBindDeploymentEvidence(config, policy, collector);
  const expected = deriveExpectedPayload(
    policy,
    profile,
    collector,
    deployment.sha256
  );
  const logIdentity = createSanitizedLogIdentity(expected);

  let tokenBytes: Buffer | undefined;
  let tlsKeyFile: StrictFile | undefined;
  let certificateFile: StrictFile | undefined;
  let server: HttpsServer | undefined;
  try {
    tokenBytes = (await readStrictOrdinaryFile(
      config.bearerTokenPath,
      MIN_BEARER_TOKEN_BYTES,
      MAX_BEARER_TOKEN_BYTES,
      exact0600
    )).bytes;
    const bearerToken = parseBearerToken(tokenBytes);
    [tlsKeyFile, certificateFile] = await Promise.all([
      readStrictOrdinaryFile(
        config.tlsPrivateKeyPath,
        64,
        MAX_TLS_PRIVATE_KEY_BYTES,
        exact0600
      ),
      readStrictOrdinaryFile(
        config.tlsCertificatePath,
        64,
        MAX_TLS_CERTIFICATE_BYTES,
        securePublicFileMode
      )
    ]);
    assertDistinctFileIdentities([
      tlsKeyFile,
      certificateFile
    ]);
    const tlsPrivateKey = parseTlsPrivateKey(tlsKeyFile.bytes);
    const certificate = parseTlsCertificate(certificateFile.bytes, tlsPrivateKey);
    if (!safeHexEqual(
      createHash("sha256").update(certificate.raw).digest("hex"),
      deployment.signer.tlsCertificateSha256
    )) {
      throw new OrganizationReconciliationDevelopHashSignerHttpsLauncherError("tls-material-invalid");
    }
    const tlsPublicKeySha256 = createHash("sha256")
      .update(certificate.publicKey.export({ format: "der", type: "spki" }))
      .digest("hex");
    if (
      safeHexEqual(tlsPublicKeySha256, deployment.signer.publicKeySha256) ||
      safeHexEqual(tlsPublicKeySha256, collector.publicKeySha256)
    ) {
      throw new OrganizationReconciliationDevelopHashSignerHttpsLauncherError("tls-material-invalid");
    }
    const sidecar = await createOrganizationReconciliationDevelopHashSignerSidecar({
      privateKeyPath: config.signerPrivateKeyPath,
      bearerToken,
      expected,
      deploymentEvidence: deployment.evidence,
      ready: false
    }).catch(() => {
      throw new OrganizationReconciliationDevelopHashSignerHttpsLauncherError("signer-private-key-invalid");
    });

    const sockets = new Set<Socket>();
    const serverOptions: ServerOptions = {
      key: tlsKeyFile.bytes,
      cert: certificateFile.bytes,
      minVersion: ORGANIZATION_RECONCILIATION_DEVELOP_HASH_SIGNER_HTTPS_LIMITS.minimumTlsVersion,
      maxVersion: "TLSv1.3",
      maxHeaderSize: ORGANIZATION_RECONCILIATION_DEVELOP_HASH_SIGNER_HTTPS_LIMITS.maximumHeaderBytes,
      requestTimeout: ORGANIZATION_RECONCILIATION_DEVELOP_HASH_SIGNER_HTTPS_LIMITS.requestTimeoutMs,
      headersTimeout: ORGANIZATION_RECONCILIATION_DEVELOP_HASH_SIGNER_HTTPS_LIMITS.headersTimeoutMs,
      keepAliveTimeout: ORGANIZATION_RECONCILIATION_DEVELOP_HASH_SIGNER_HTTPS_LIMITS.keepAliveTimeoutMs
    };
    void certificate;
    server = createServer(serverOptions, (request, response) => {
      request.setTimeout(
        ORGANIZATION_RECONCILIATION_DEVELOP_HASH_SIGNER_HTTPS_LIMITS.requestTimeoutMs,
        () => request.destroy()
      );
      const length = request.headers["content-length"];
      if (Array.isArray(length) || (typeof length === "string" &&
        (!/^\d+$/.test(length) || Number(length) >
          ORGANIZATION_RECONCILIATION_DEVELOP_HASH_SIGNER_HTTPS_LIMITS.maximumRequestBytes))) {
        response.writeHead(400, { "Content-Type": "application/json", "Connection": "close" });
        response.end('{"status":"rejected"}');
        request.destroy();
        return;
      }
      void sidecar.handle(request, response).catch(() => {
        if (!response.headersSent) {
          response.writeHead(400, { "Content-Type": "application/json", "Connection": "close" });
          response.end('{"status":"rejected"}');
        } else {
          response.destroy();
        }
      });
    });
    configureSecureServer(server, sockets);
    await listen(server, config.listen.host, config.listen.port).catch(() => {
      throw new OrganizationReconciliationDevelopHashSignerHttpsLauncherError("listen-failed");
    });
    return createRunningLauncher(server, sockets, options.log, logIdentity);
  } catch (error) {
    if (server) {
      server.closeAllConnections?.();
      server.close();
    }
    if (error instanceof OrganizationReconciliationDevelopHashSignerHttpsLauncherError) throw error;
    throw new OrganizationReconciliationDevelopHashSignerHttpsLauncherError("tls-material-invalid");
  } finally {
    tokenBytes?.fill(0);
    tlsKeyFile?.bytes.fill(0);
    certificateFile?.bytes.fill(0);
  }
}

function assertCompiledProfileProvisioned(): void {
  if (compiledOrganizationReconciliationTrustProfileCount !== 1) {
    throw new OrganizationReconciliationDevelopHashSignerHttpsLauncherError("trust-profile-not-provisioned");
  }
}

function captureLauncherOptions(
  candidate: OrganizationReconciliationDevelopHashSignerHttpsLauncherOptions
): Readonly<{ configPath: string; log?: OrganizationReconciliationDevelopHashSignerHttpsLauncherOptions["log"] }> {
  try {
    if (!candidate || typeof candidate !== "object" || Array.isArray(candidate) || isProxy(candidate) ||
      Object.getPrototypeOf(candidate) !== Object.prototype || Object.getOwnPropertySymbols(candidate).length !== 0) {
      throw new Error("invalid");
    }
    const descriptors = Object.getOwnPropertyDescriptors(candidate);
    assertExactDescriptorKeys(descriptors, ["configPath"], ["log"]);
    const configPath = ownString(descriptors, "configPath");
    const logValue = ownOptionalValue(descriptors, "log");
    if (!safeAbsolutePath(configPath) || (logValue !== undefined &&
      (typeof logValue !== "function" || isProxy(logValue)))) throw new Error("invalid");
    return Object.freeze({ configPath, ...(logValue === undefined ? {} : { log: logValue as typeof candidate.log }) });
  } catch {
    throw new OrganizationReconciliationDevelopHashSignerHttpsLauncherError("invalid-launcher-options");
  }
}

async function loadLauncherConfig(path: string): Promise<LauncherConfig> {
  let bytes: Buffer | undefined;
  try {
    bytes = (await readStrictOrdinaryFile(path, 2, MAX_CONFIG_BYTES, exact0600)).bytes;
    const text = strictUtf8(bytes);
    const candidate = JSON.parse(text) as unknown;
    if (`${JSON.stringify(candidate, null, 2)}\n` !== text) throw new Error("invalid");
    const descriptors = exactPlainRecord(candidate, [
      "contract", "environment", "collectorId", "listen", "trustPolicyPath", "deploymentEvidencePath",
      "signerPrivateKeyPath",
      "tlsPrivateKeyPath", "tlsCertificatePath", "bearerTokenPath"
    ]);
    const listen = ownValue(descriptors, "listen");
    const listenDescriptors = exactPlainRecord(listen, ["host", "port"]);
    const config: LauncherConfig = Object.freeze({
      contract: ownString(descriptors, "contract") as LauncherConfig["contract"],
      environment: ownString(descriptors, "environment") as LauncherConfig["environment"],
      collectorId: ownString(descriptors, "collectorId"),
      listen: Object.freeze({
        host: ownString(listenDescriptors, "host"),
        port: ownNumber(listenDescriptors, "port")
      }),
      trustPolicyPath: ownString(descriptors, "trustPolicyPath"),
      deploymentEvidencePath: ownString(descriptors, "deploymentEvidencePath"),
      signerPrivateKeyPath: ownString(descriptors, "signerPrivateKeyPath"),
      tlsPrivateKeyPath: ownString(descriptors, "tlsPrivateKeyPath"),
      tlsCertificatePath: ownString(descriptors, "tlsCertificatePath"),
      bearerTokenPath: ownString(descriptors, "bearerTokenPath")
    });
    const paths = [
      path, config.trustPolicyPath, config.deploymentEvidencePath, config.signerPrivateKeyPath, config.tlsPrivateKeyPath,
      config.tlsCertificatePath, config.bearerTokenPath
    ];
    const readOnlyConfigPrefix = dirname(path);
    if (
      config.contract !== ORGANIZATION_RECONCILIATION_DEVELOP_HASH_SIGNER_HTTPS_LAUNCHER_CONTRACT ||
      config.environment !== "xrteeth-develop" || !IDENTIFIER.test(config.collectorId) ||
      !isPrivateListenAddress(config.listen.host) || config.listen.port !== 8_443 ||
      path !== resolve(readOnlyConfigPrefix, "launcher.json") ||
      config.trustPolicyPath !== resolve(readOnlyConfigPrefix, "trust-policy.json") ||
      config.deploymentEvidencePath !== resolve(readOnlyConfigPrefix, "deployment-evidence.json") ||
      paths.some((candidatePath) => !safeAbsolutePath(candidatePath)) || new Set(paths).size !== paths.length ||
      paths.slice(1).some((candidatePath) => !isStrictDescendant(candidatePath, readOnlyConfigPrefix))
    ) throw new Error("invalid");
    return config;
  } catch (error) {
    if (error instanceof OrganizationReconciliationDevelopHashSignerHttpsLauncherError) throw error;
    throw new OrganizationReconciliationDevelopHashSignerHttpsLauncherError("invalid-launcher-config");
  } finally {
    bytes?.fill(0);
  }
}

async function loadAndBindPublicTrustPolicy(config: LauncherConfig): Promise<Readonly<{
  policy: OrganizationReconciliationTrustPolicy;
  profile: OrganizationReconciliationTrustedProfile;
  collector: OrganizationReconciliationTrustedCollector;
}>> {
  let bytes: Buffer | undefined;
  let policy: OrganizationReconciliationTrustPolicy;
  try {
    bytes = (await readStrictOrdinaryFile(config.trustPolicyPath, 2, MAX_POLICY_BYTES, exact0600)).bytes;
    policy = parseOrganizationReconciliationTrustPolicy(JSON.parse(strictUtf8(bytes)));
  } catch {
    throw new OrganizationReconciliationDevelopHashSignerHttpsLauncherError("trust-policy-invalid");
  } finally {
    bytes?.fill(0);
  }
  const profile = resolveCompiledOrganizationReconciliationTrustProfile(policy.profileId);
  if (!profile || !policyMatchesCompiledProfile(policy, profile)) {
    throw new OrganizationReconciliationDevelopHashSignerHttpsLauncherError("trust-profile-mismatch");
  }
  const collector = policy.requiredCollectors.find((candidate) => candidate.collectorId === config.collectorId);
  if (!collector || !publicCollectorKeyMatchesFingerprint(collector)) {
    throw new OrganizationReconciliationDevelopHashSignerHttpsLauncherError("trust-profile-mismatch");
  }
  return Object.freeze({ policy, profile, collector });
}

async function loadAndBindDeploymentEvidence(
  config: LauncherConfig,
  policy: OrganizationReconciliationTrustPolicy,
  localCollector: OrganizationReconciliationTrustedCollector
): Promise<Readonly<{
  sha256: string;
  signer: OrganizationReconciliationDevelopDeploymentSigner;
  evidence: OrganizationReconciliationDevelopDeploymentEvidence;
}>> {
  let bytes: Buffer | undefined;
  try {
    bytes = (await readStrictOrdinaryFile(
      config.deploymentEvidencePath,
      2,
      MAX_POLICY_BYTES,
      exact0600
    )).bytes;
    const evidence = bindOrganizationReconciliationDevelopDeploymentEvidenceToCompiledTopology(
      parseOrganizationReconciliationDevelopDeploymentEvidence(JSON.parse(strictUtf8(bytes))),
      policy.profileId
    ).deploymentEvidence;
    const revision = ORGANIZATION_RECONCILIATION_COMPILED_BUILD_REVISION;
    if (
      evidence.environment !== "xrteeth-develop" ||
      evidence.buildRevision !== revision ||
      policy.requiredCollectors.length !== 1 ||
      evidence.signers.length !== policy.requiredCollectors.length
    ) throw new Error("invalid");
    const deployedByKey = new Map(evidence.signers.map((signer) => [signer.keyId, signer]));
    for (const collector of policy.requiredCollectors) {
      const signer = deployedByKey.get(collector.keyId);
      if (
        !signer || signer.collectorId !== collector.collectorId ||
        signer.nodeId !== collector.nodeId ||
        !safeHexEqual(signer.publicKeySha256, collector.publicKeySha256)
      ) throw new Error("invalid");
    }
    const signer = deployedByKey.get(localCollector.keyId);
    if (!signer) throw new Error("invalid");
    return Object.freeze({
      sha256: createOrganizationReconciliationDevelopDeploymentEvidenceSha256(evidence),
      signer,
      evidence
    });
  } catch {
    throw new OrganizationReconciliationDevelopHashSignerHttpsLauncherError(
      "deployment-evidence-invalid"
    );
  } finally {
    bytes?.fill(0);
  }
}

function policyMatchesCompiledProfile(
  policy: OrganizationReconciliationTrustPolicy,
  profile: OrganizationReconciliationTrustedProfile
): boolean {
  const revision = ORGANIZATION_RECONCILIATION_COMPILED_BUILD_REVISION;
  if (
    !FULL_REVISION.test(revision ?? "") || profile.profileId !== policy.profileId ||
    profile.expectedEnvironment !== "xrteeth-develop" || policy.environment !== profile.expectedEnvironment ||
    !safeHexEqual(createOrganizationReconciliationTrustPolicySha256(policy), profile.policySha256) ||
    policy.requiredCollectors.length !== profile.requiredCollectors.length
  ) return false;
  const policyByKey = new Map(policy.requiredCollectors.map((collector) => [collector.keyId, collector]));
  for (const expected of profile.requiredCollectors) {
    const collector = policyByKey.get(expected.keyId);
    if (
      !collector || collector.algorithm !== "Ed25519" || collector.collectorId !== expected.collectorId ||
      collector.nodeId !== expected.nodeId || !safeHexEqual(collector.publicKeySha256, expected.publicKeySha256) ||
      collector.buildRevision !== revision || collector.buildRevision !== expected.buildRevision ||
      !publicCollectorKeyMatchesFingerprint(collector)
    ) return false;
  }
  return policyByKey.size === profile.requiredCollectors.length;
}

function publicCollectorKeyMatchesFingerprint(collector: OrganizationReconciliationTrustedCollector): boolean {
  try {
    const key = createPublicKey(collector.publicKeyPem);
    if (key.asymmetricKeyType !== "ed25519") return false;
    const fingerprint = createHash("sha256").update(key.export({ format: "der", type: "spki" })).digest("hex");
    return safeHexEqual(fingerprint, collector.publicKeySha256);
  } catch {
    return false;
  }
}

function deriveExpectedPayload(
  policy: OrganizationReconciliationTrustPolicy,
  profile: OrganizationReconciliationTrustedProfile,
  collector: OrganizationReconciliationTrustedCollector,
  deploymentEvidenceSha256: string
): OrganizationReconciliationDevelopHashSignerExpectedPayload {
  const compiled = profile.requiredCollectors.find((candidate) => candidate.keyId === collector.keyId);
  if (!compiled) throw new OrganizationReconciliationDevelopHashSignerHttpsLauncherError("trust-profile-mismatch");
  return Object.freeze({
    profileId: profile.profileId,
    environment: "xrteeth-develop" as const,
    collectorId: compiled.collectorId,
    nodeId: compiled.nodeId,
    keyId: compiled.keyId,
    publicKeySha256: compiled.publicKeySha256,
    trustPolicySha256: profile.policySha256,
    deploymentEvidenceSha256,
    buildRevision: compiled.buildRevision,
    validFrom: collector.validFrom,
    validUntil: collector.validUntil,
    maxEvidenceAgeSeconds: policy.maxEvidenceAgeSeconds,
    maxAttestationTtlSeconds: policy.maxAttestationTtlSeconds,
    maxCollectionWindowSeconds: policy.maxCollectionWindowSeconds,
    clockSkewSeconds: policy.clockSkewSeconds
  });
}

function parseBearerToken(bytes: Buffer): string {
  try {
    const token = strictUtf8(bytes);
    if (!/^[\x21-\x7e]{32,256}$/.test(token)) throw new Error("invalid");
    return token;
  } catch {
    throw new OrganizationReconciliationDevelopHashSignerHttpsLauncherError("bearer-token-invalid");
  }
}

function parseTlsPrivateKey(bytes: Buffer): KeyObject {
  try {
    const key = createPrivateKey(bytes);
    const type = key.asymmetricKeyType;
    if (type === "rsa" || type === "rsa-pss") {
      if ((key.asymmetricKeyDetails?.modulusLength ?? 0) < 2_048) throw new Error("invalid");
    } else if (type === "ec") {
      if (!new Set(["prime256v1", "secp384r1", "secp521r1"]).has(key.asymmetricKeyDetails?.namedCurve ?? "")) {
        throw new Error("invalid");
      }
    } else if (type !== "ed25519" && type !== "ed448") {
      throw new Error("invalid");
    }
    return key;
  } catch {
    throw new OrganizationReconciliationDevelopHashSignerHttpsLauncherError("tls-material-invalid");
  }
}

function parseTlsCertificate(bytes: Buffer, privateKey: KeyObject): X509Certificate {
  try {
    const certificate = new X509Certificate(bytes);
    if (!certificate.checkPrivateKey(privateKey)) throw new Error("invalid");
    const now = Date.now();
    const validFrom = Date.parse(certificate.validFrom);
    const validUntil = Date.parse(certificate.validTo);
    if (!Number.isFinite(validFrom) || !Number.isFinite(validUntil) || validFrom > now || validUntil < now) {
      throw new Error("invalid");
    }
    return certificate;
  } catch {
    throw new OrganizationReconciliationDevelopHashSignerHttpsLauncherError("tls-material-invalid");
  }
}

function configureSecureServer(server: HttpsServer, sockets: Set<Socket>): void {
  const limits = ORGANIZATION_RECONCILIATION_DEVELOP_HASH_SIGNER_HTTPS_LIMITS;
  server.maxConnections = limits.maximumConnections;
  server.maxHeadersCount = limits.maximumHeaderCount;
  server.maxRequestsPerSocket = limits.maximumRequestsPerSocket;
  server.requestTimeout = limits.requestTimeoutMs;
  server.headersTimeout = limits.headersTimeoutMs;
  server.keepAliveTimeout = limits.keepAliveTimeoutMs;
  server.timeout = limits.socketTimeoutMs;
  server.on("connection", (socket) => {
    if (!(socket instanceof Socket)) {
      socket.destroy();
      return;
    }
    if (sockets.size >= limits.maximumConnections) {
      socket.destroy();
      return;
    }
    sockets.add(socket);
    socket.setTimeout(limits.socketTimeoutMs, () => socket.destroy());
    socket.once("close", () => sockets.delete(socket));
  });
  server.on("clientError", (_error, socket) => socket.destroy());
  server.on("tlsClientError", (_error, socket) => socket.destroy());
}

async function listen(server: HttpsServer, host: string, port: number): Promise<void> {
  await new Promise<void>((resolvePromise, rejectPromise) => {
    const onError = () => {
      server.off("listening", onListening);
      rejectPromise(new Error("listen-failed"));
    };
    const onListening = () => {
      server.off("error", onError);
      resolvePromise();
    };
    server.once("error", onError);
    server.once("listening", onListening);
    server.listen({ host, port, exclusive: true });
  });
}

function createRunningLauncher(
  server: HttpsServer,
  sockets: Set<Socket>,
  log: OrganizationReconciliationDevelopHashSignerHttpsLauncherOptions["log"],
  identity: SanitizedLogIdentity
): OrganizationReconciliationDevelopHashSignerHttpsLauncher {
  let requested = false;
  let closePromise: Promise<void> | undefined;
  let transportClosePromise: Promise<void> | undefined;
  let resolveClosed!: (reason: "requested" | "transport-failed") => void;
  const closed = new Promise<"requested" | "transport-failed">((resolvePromise) => {
    resolveClosed = resolvePromise;
  });
  let closedResolved = false;
  const resolveOnce = (reason: "requested" | "transport-failed") => {
    if (closedResolved) return;
    closedResolved = true;
    resolveClosed(reason);
  };
  const close = (): Promise<void> => {
    requested = true;
    if (closePromise) return closePromise;
    emitSanitizedLog(log, "stopping", identity);
    transportClosePromise ??= closeServer(server, sockets);
    closePromise = transportClosePromise.finally(() => {
      emitSanitizedLog(log, "stopped", identity);
      resolveOnce("requested");
    });
    return closePromise;
  };
  server.on("error", () => {
    if (requested) return;
    emitSanitizedLog(log, "transport-failed", identity);
    transportClosePromise ??= closeServer(server, sockets);
    void transportClosePromise.finally(() => resolveOnce("transport-failed"));
  });
  server.once("close", () => resolveOnce(requested ? "requested" : "transport-failed"));
  emitSanitizedLog(log, "listening", identity);
  return Object.freeze({ close, closed, ready: false as const });
}

async function closeServer(server: HttpsServer, sockets: Set<Socket>): Promise<void> {
  await new Promise<void>((resolvePromise) => {
    const wasListening = server.listening;
    let finished = false;
    let forced = false;
    let hardStopTimer: NodeJS.Timeout | undefined;
    const finish = () => {
      if (finished) return;
      finished = true;
      clearTimeout(gracefulTimer);
      if (hardStopTimer) clearTimeout(hardStopTimer);
      server.off("close", finish);
      resolvePromise();
    };
    const force = () => {
      if (forced) return;
      forced = true;
      for (const socket of sockets) socket.destroy();
      server.closeAllConnections?.();
      // Destroying connections is asynchronous. Wait for the server's close
      // callback/event rather than reporting a completed shutdown immediately.
      hardStopTimer = setTimeout(finish,
        ORGANIZATION_RECONCILIATION_DEVELOP_HASH_SIGNER_HTTPS_LIMITS.gracefulShutdownMs);
      hardStopTimer.unref();
    };
    const gracefulTimer = setTimeout(
      force,
      ORGANIZATION_RECONCILIATION_DEVELOP_HASH_SIGNER_HTTPS_LIMITS.gracefulShutdownMs
    );
    gracefulTimer.unref();
    server.once("close", finish);
    if (!wasListening) {
      force();
      if (sockets.size === 0) queueMicrotask(finish);
      return;
    }
    server.close(() => finish());
    server.closeIdleConnections?.();
  });
}

function createSanitizedLogIdentity(
  expected: OrganizationReconciliationDevelopHashSignerExpectedPayload
): SanitizedLogIdentity {
  return Object.freeze({
    profileIdSha256: hashIdentifier(expected.profileId),
    collectorIdSha256: hashIdentifier(expected.collectorId),
    nodeIdSha256: hashIdentifier(expected.nodeId)
  });
}

function emitSanitizedLog(
  log: OrganizationReconciliationDevelopHashSignerHttpsLauncherOptions["log"],
  event: OrganizationReconciliationDevelopHashSignerHttpsLogEvent["event"],
  identity: SanitizedLogIdentity
): void {
  if (!log) return;
  try {
    log(Object.freeze({
      event,
      environment: "xrteeth-develop" as const,
      ...identity,
      ready: false as const
    }));
  } catch {
    // A logging sink cannot change signer availability or reveal internal errors.
  }
}

function hashIdentifier(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

async function readStrictOrdinaryFile(
  path: string,
  minimumBytes: number,
  maximumBytes: number,
  validMode: (mode: number) => boolean
): Promise<StrictFile> {
  let handle: FileHandle | undefined;
  let bytes: Buffer | undefined;
  try {
    if (!safeAbsolutePath(path)) throw new Error("invalid");
    if (typeof fsConstants.O_NOFOLLOW !== "number" || typeof fsConstants.O_NONBLOCK !== "number") {
      throw new Error("invalid");
    }
    const parentPath = dirname(path);
    const [before, parent, resolvedParent, resolvedFile] = await Promise.all([
      lstat(path), lstat(parentPath), realpath(parentPath), realpath(path)
    ]);
    if (
      !before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || !validMode(before.mode & 0o777) ||
      before.size < minimumBytes || before.size > maximumBytes || !Number.isSafeInteger(before.size) ||
      !parent.isDirectory() || parent.isSymbolicLink() || resolvedParent !== parentPath || resolvedFile !== path ||
      (typeof process.getuid === "function" && before.uid !== process.getuid())
    ) throw new Error("invalid");
    handle = await open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK);
    const opened = await handle.stat();
    if (
      !opened.isFile() || opened.nlink !== 1 || !validMode(opened.mode & 0o777) ||
      opened.dev !== before.dev || opened.ino !== before.ino || opened.size !== before.size ||
      opened.mtimeMs !== before.mtimeMs || opened.ctimeMs !== before.ctimeMs ||
      (typeof process.getuid === "function" && opened.uid !== process.getuid())
    ) throw new Error("invalid");
    bytes = Buffer.alloc(opened.size);
    let offset = 0;
    while (offset < bytes.byteLength) {
      const { bytesRead } = await handle.read(bytes, offset, bytes.byteLength - offset, offset);
      if (bytesRead < 1) throw new Error("invalid");
      offset += bytesRead;
    }
    const overflow = Buffer.alloc(1);
    try {
      if ((await handle.read(overflow, 0, 1, bytes.byteLength)).bytesRead !== 0) throw new Error("invalid");
    } finally {
      overflow.fill(0);
    }
    const after = await handle.stat();
    if (
      after.dev !== opened.dev || after.ino !== opened.ino || after.size !== opened.size ||
      after.mtimeMs !== opened.mtimeMs || after.ctimeMs !== opened.ctimeMs || after.nlink !== 1 ||
      !validMode(after.mode & 0o777)
    ) throw new Error("invalid");
    const resultBytes = bytes;
    bytes = undefined;
    return Object.freeze({ bytes: resultBytes, device: opened.dev, inode: opened.ino });
  } finally {
    bytes?.fill(0);
    await handle?.close().catch(() => undefined);
  }
}

function assertDistinctFileIdentities(files: readonly StrictFile[]): void {
  const identities = files.map((file) => `${file.device}:${file.inode}`);
  if (new Set(identities).size !== identities.length) {
    throw new OrganizationReconciliationDevelopHashSignerHttpsLauncherError("tls-material-invalid");
  }
}

function exact0600(mode: number): boolean {
  return mode === 0o600;
}

function securePublicFileMode(mode: number): boolean {
  return (mode & 0o400) !== 0 && (mode & 0o022) === 0;
}

function strictUtf8(bytes: Buffer): string {
  const text = bytes.toString("utf8");
  if (Buffer.byteLength(text, "utf8") !== bytes.byteLength) throw new Error("invalid");
  return text;
}

function safeAbsolutePath(path: string): boolean {
  return typeof path === "string" && path.length > 1 && path.length <= 4_096 &&
    !/[\u0000-\u001f\u007f]/.test(path) && isAbsolute(path) && resolve(path) === path;
}

function isPrivateListenAddress(host: string): boolean {
  const family = isIP(host);
  if (family === 4) {
    const octets = host.split(".").map(Number);
    return octets.length === 4 && octets.every((value) => Number.isInteger(value) && value >= 0 && value <= 255) &&
      (octets[0] === 10 || octets[0] === 127 || octets[0] === 169 && octets[1] === 254 ||
        octets[0] === 172 && octets[1]! >= 16 && octets[1]! <= 31 ||
        octets[0] === 192 && octets[1] === 168);
  }
  if (family === 6 && host === host.toLowerCase() && !host.includes("%")) {
    return host === "::1" || /^(?:f[cd][0-9a-f]{2}|fe[89ab][0-9a-f]):/.test(host);
  }
  return false;
}

function isStrictDescendant(candidate: string, parent: string): boolean {
  return candidate !== parent && candidate.startsWith(`${parent}/`) && resolve(candidate) === candidate;
}

function exactPlainRecord(candidate: unknown, keys: readonly string[]): PropertyDescriptorMap {
  if (!candidate || typeof candidate !== "object" || Array.isArray(candidate) || isProxy(candidate) ||
    Object.getPrototypeOf(candidate) !== Object.prototype || Object.getOwnPropertySymbols(candidate).length !== 0) {
    throw new Error("invalid");
  }
  const descriptors = Object.getOwnPropertyDescriptors(candidate);
  if (JSON.stringify(Object.keys(descriptors)) !== JSON.stringify(keys)) throw new Error("invalid");
  for (const descriptor of Object.values(descriptors)) {
    if (!("value" in descriptor)) throw new Error("invalid");
  }
  return descriptors;
}

function assertExactDescriptorKeys(
  descriptors: PropertyDescriptorMap,
  required: readonly string[],
  optional: readonly string[]
): void {
  const keys = Object.keys(descriptors);
  if (required.some((key) => !keys.includes(key)) || keys.some((key) => !required.includes(key) && !optional.includes(key))) {
    throw new Error("invalid");
  }
  for (const descriptor of Object.values(descriptors)) {
    if (!("value" in descriptor)) throw new Error("invalid");
  }
}

function ownValue(descriptors: PropertyDescriptorMap, key: string): unknown {
  const descriptor = descriptors[key];
  if (!descriptor || !("value" in descriptor)) throw new Error("invalid");
  return descriptor.value;
}

function ownOptionalValue(descriptors: PropertyDescriptorMap, key: string): unknown {
  const descriptor = descriptors[key];
  if (!descriptor) return undefined;
  if (!("value" in descriptor)) throw new Error("invalid");
  return descriptor.value;
}

function ownString(descriptors: PropertyDescriptorMap, key: string): string {
  const value = ownValue(descriptors, key);
  if (typeof value !== "string") throw new Error("invalid");
  return value;
}

function ownNumber(descriptors: PropertyDescriptorMap, key: string): number {
  const value = ownValue(descriptors, key);
  if (typeof value !== "number") throw new Error("invalid");
  return value;
}

function safeHexEqual(left: string, right: string): boolean {
  if (!SHA256.test(left) || !SHA256.test(right)) return false;
  const leftBytes = Buffer.from(left, "hex");
  const rightBytes = Buffer.from(right, "hex");
  try {
    return timingSafeEqual(leftBytes, rightBytes);
  } finally {
    leftBytes.fill(0);
    rightBytes.fill(0);
  }
}
