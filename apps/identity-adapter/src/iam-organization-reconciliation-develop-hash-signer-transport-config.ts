import { createOrganizationReconciliationTrustPolicySha256, parseOrganizationReconciliationTrustPolicy, type OrganizationReconciliationTrustPolicy, type OrganizationReconciliationTrustedProfile } from
  "./iam-organization-reconciliation-provenance.js";
import { canonicalizeOrganizationReconciliationEvidenceValue } from
  "./iam-organization-reconciliation-component-manifest.js";
import {
  assertOrganizationReconciliationDevelopHashSignerProductionEndpoint,
  createOrganizationReconciliationDevelopHashSignerClient
} from "./iam-organization-reconciliation-develop-hash-signer-client.js";
import {
  parseOrganizationReconciliationDevelopDeploymentEvidence,
  type OrganizationReconciliationDevelopDeploymentEvidence
} from "./iam-organization-reconciliation-develop-deployment-evidence.js";
import {
  bindOrganizationReconciliationDevelopDeploymentEvidenceToCompiledTopology
} from "./iam-organization-reconciliation-develop-deployment-topology.js";
import {
  resolveCompiledOrganizationReconciliationTrustProfile
} from "./iam-organization-reconciliation-trust-profiles.js";
import type {
  OrganizationReconciliationDevelopFullRangeExternalSigner
} from "./iam-organization-reconciliation-develop-full-range.js";
import { createHash } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import { dirname, extname, isAbsolute, resolve } from "node:path";
import { isProxy } from "node:util/types";

export const ORGANIZATION_RECONCILIATION_DEVELOP_HASH_SIGNER_TRANSPORT_CONFIG_CONTRACT =
  "iam-organization-reconciliation-xrteeth-develop-hash-signer-transport-config/v1" as const;

const ENVIRONMENT = "xrteeth-develop" as const;
const EXPECTED_SIGNER_COUNT = 1;
const MAX_CONFIG_BYTES = 64 * 1024;
const MAX_TOKEN_BYTES = 1_024;
const MIN_TOKEN_BYTES = 16;
const MAX_CA_CERTIFICATE_BYTES = 64 * 1024;
const MIN_CA_CERTIFICATE_BYTES = 64;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

export class OrganizationReconciliationDevelopHashSignerTransportConfigError extends Error {
  constructor() {
    super("invalid-signer-transport-config");
    this.name = "OrganizationReconciliationDevelopHashSignerTransportConfigError";
  }
}

export interface OrganizationReconciliationDevelopHashSignerTransportSelection {
  readonly keyId: string;
  readonly endpoint: string;
  readonly bearerTokenFile: string;
  readonly certificateAuthorityFile: string;
}

interface CompiledTrustBinding {
  readonly trustPolicy: OrganizationReconciliationTrustPolicy;
  readonly profile: OrganizationReconciliationTrustedProfile;
}

/**
 * Loads the Develop-only signer transport. The file can select only transport
 * endpoint and local bearer-token file for the one key already pinned by
 * the compiled trust profile. All public signer identity fields are copied
 * from that profile and cannot be supplied by this file.
 */
export async function loadOrganizationReconciliationDevelopHashSignerTransportConfig(
  configPath: string,
  trustPolicyCandidate: unknown,
  deploymentEvidenceCandidate: unknown
): Promise<readonly OrganizationReconciliationDevelopFullRangeExternalSigner[]> {
  try {
    const path = assertOrganizationReconciliationDevelopHashSignerTransportConfigPath(configPath);
    const { trustPolicy, profile } = captureCompiledTrustBinding(trustPolicyCandidate);
    const deploymentEvidence = captureDeploymentBinding(
      deploymentEvidenceCandidate,
      trustPolicy,
      profile
    );

    const configBytes = await readOrdinaryOwner0600File(path, MAX_CONFIG_BYTES, 2);
    let parsed: unknown;
    try {
      const text = decodeUtf8(configBytes);
      assertJsonHasNoDuplicateObjectKeys(text);
      parsed = JSON.parse(text) as unknown;
    } finally {
      configBytes.fill(0);
    }
    const entries = captureTransportConfig(parsed, trustPolicy, profile);
    const readOnlyConfigPrefix = dirname(path);
    const entryByKey = new Map(entries.map((entry) => [entry.keyId, entry]));
    if (entries.some((entry) =>
      entry.bearerTokenFile === path || entry.certificateAuthorityFile === path ||
      entry.bearerTokenFile === entry.certificateAuthorityFile ||
      !isStrictDescendant(entry.bearerTokenFile, readOnlyConfigPrefix) ||
      !isStrictDescendant(entry.certificateAuthorityFile, readOnlyConfigPrefix)
    )) invalidConfig();

    const loaded = await Promise.all(profile.requiredCollectors.map(async (collector) => {
      const entry = entryByKey.get(collector.keyId);
      if (!entry) invalidConfig();
      const tokenBytes = await readOrdinaryOwner0600File(
        entry.bearerTokenFile,
        MAX_TOKEN_BYTES,
        MIN_TOKEN_BYTES
      );
      let certificateAuthorityBytes: Buffer | undefined;
      let bearerToken: string;
      try {
        certificateAuthorityBytes = await readOrdinaryOwner0600File(
          entry.certificateAuthorityFile,
          MAX_CA_CERTIFICATE_BYTES,
          MIN_CA_CERTIFICATE_BYTES
        );
        bearerToken = decodeUtf8(tokenBytes);
        if (!/^[\x21-\x7e]{16,1024}$/.test(bearerToken)) invalidConfig();
        const deployedSigner = deploymentEvidence.signers.find((signer) => signer.keyId === collector.keyId);
        if (!deployedSigner) invalidConfig();
        const sign = createOrganizationReconciliationDevelopHashSignerClient({
          endpointUrl: entry.endpoint,
          bearerToken,
          tlsCertificateSha256: deployedSigner.tlsCertificateSha256,
          certificateAuthorityPem: certificateAuthorityBytes
        });
        return Object.freeze({
          tokenSha256: createHash("sha256").update(tokenBytes).digest("hex"),
          signer: Object.freeze({
            collectorId: collector.collectorId,
            nodeId: collector.nodeId,
            keyId: collector.keyId,
            publicKeySha256: collector.publicKeySha256,
            buildRevision: collector.buildRevision,
            sign
          })
        });
      } finally {
        tokenBytes.fill(0);
        certificateAuthorityBytes?.fill(0);
      }
    }));
    if (new Set(loaded.map((entry) => entry.tokenSha256)).size !== EXPECTED_SIGNER_COUNT) invalidConfig();
    const signers = loaded.map((entry) => entry.signer);
    return Object.freeze(signers);
  } catch (error) {
    if (error instanceof OrganizationReconciliationDevelopHashSignerTransportConfigError) throw error;
    throw new OrganizationReconciliationDevelopHashSignerTransportConfigError();
  }
}

/** Pure descriptor-safe validation used by focused tests and config tooling. */
export function parseOrganizationReconciliationDevelopHashSignerTransportConfig(
  candidate: unknown,
  trustPolicyCandidate: unknown,
  deploymentEvidenceCandidate: unknown
): readonly OrganizationReconciliationDevelopHashSignerTransportSelection[] {
  try {
    const { trustPolicy, profile } = captureCompiledTrustBinding(trustPolicyCandidate);
    captureDeploymentBinding(deploymentEvidenceCandidate, trustPolicy, profile);
    return captureTransportConfig(candidate, trustPolicy, profile);
  } catch (error) {
    if (error instanceof OrganizationReconciliationDevelopHashSignerTransportConfigError) throw error;
    throw new OrganizationReconciliationDevelopHashSignerTransportConfigError();
  }
}

export function assertOrganizationReconciliationDevelopHashSignerTransportConfigPath(
  candidate: string
): string {
  try {
    return assertAbsoluteOrdinaryFilePath(candidate, true);
  } catch {
    invalidConfig();
  }
}

function captureTransportConfig(
  candidate: unknown,
  trustPolicy: OrganizationReconciliationTrustPolicy,
  profile: OrganizationReconciliationTrustedProfile
): readonly OrganizationReconciliationDevelopHashSignerTransportSelection[] {
  const config = exactObject(candidate, ["contract", "environment", "profileId", "signers"]);
  if (
    config.contract !== ORGANIZATION_RECONCILIATION_DEVELOP_HASH_SIGNER_TRANSPORT_CONFIG_CONTRACT ||
    config.environment !== ENVIRONMENT ||
    config.profileId !== trustPolicy.profileId
  ) {
    invalidConfig();
  }
  const signers = exactArray(config.signers, EXPECTED_SIGNER_COUNT);
  const captured = signers.map((candidateSigner) => {
    const signer = exactObject(candidateSigner, [
      "keyId", "endpoint", "bearerTokenFile", "certificateAuthorityFile"
    ]);
    if (
      typeof signer.keyId !== "string" || !IDENTIFIER.test(signer.keyId) ||
      typeof signer.endpoint !== "string" || signer.endpoint.length < 1 || signer.endpoint.length > 2_048 ||
      typeof signer.bearerTokenFile !== "string" ||
      typeof signer.certificateAuthorityFile !== "string"
    ) {
      invalidConfig();
    }
    return Object.freeze({
      keyId: signer.keyId,
      endpoint: signer.endpoint,
      bearerTokenFile: signer.bearerTokenFile,
      certificateAuthorityFile: signer.certificateAuthorityFile
    });
  });
  const expectedKeys = new Set(profile.requiredCollectors.map((collector) => collector.keyId));
  const seenKeys = new Set<string>();
  const seenEndpoints = new Set<string>();
  const seenTokenPaths = new Set<string>();
  for (const entry of captured) {
    const tokenPath = assertAbsoluteOrdinaryFilePath(entry.bearerTokenFile, false);
    const certificateAuthorityPath = assertAbsoluteOrdinaryFilePath(entry.certificateAuthorityFile, false);
    let canonicalEndpoint: string;
    try {
      canonicalEndpoint = new URL(entry.endpoint).href;
    } catch {
      invalidConfig();
    }
    if (
      canonicalEndpoint !== entry.endpoint || !expectedKeys.has(entry.keyId) || seenKeys.has(entry.keyId) ||
      seenEndpoints.has(entry.endpoint) || seenTokenPaths.has(tokenPath) ||
      certificateAuthorityPath === tokenPath
    ) {
      invalidConfig();
    }
    // Reuse the production client's HTTPS/hostname/path policy before secrets are read.
    assertOrganizationReconciliationDevelopHashSignerProductionEndpoint(entry.endpoint);
    seenKeys.add(entry.keyId);
    seenEndpoints.add(entry.endpoint);
    seenTokenPaths.add(tokenPath);
  }
  if (seenKeys.size !== EXPECTED_SIGNER_COUNT) invalidConfig();
  return Object.freeze(captured);
}

function captureDeploymentBinding(
  candidate: unknown,
  trustPolicy: OrganizationReconciliationTrustPolicy,
  profile: OrganizationReconciliationTrustedProfile
): OrganizationReconciliationDevelopDeploymentEvidence {
  assertNoProxyOrAccessorTree(candidate, new Set<object>(), 0);
  const evidence = bindOrganizationReconciliationDevelopDeploymentEvidenceToCompiledTopology(
    parseOrganizationReconciliationDevelopDeploymentEvidence(candidate),
    trustPolicy.profileId
  ).deploymentEvidence;
  if (
    evidence.environment !== ENVIRONMENT || evidence.signers.length !== EXPECTED_SIGNER_COUNT ||
    evidence.buildRevision !== profile.requiredCollectors[0]?.buildRevision ||
    trustPolicy.requiredCollectors.length !== EXPECTED_SIGNER_COUNT
  ) invalidConfig();
  const deployedByKey = new Map(evidence.signers.map((signer) => [signer.keyId, signer]));
  for (const collector of profile.requiredCollectors) {
    const deployed = deployedByKey.get(collector.keyId);
    if (
      !deployed || deployed.collectorId !== collector.collectorId || deployed.nodeId !== collector.nodeId ||
      deployed.publicKeySha256 !== collector.publicKeySha256 || collector.buildRevision !== evidence.buildRevision
    ) invalidConfig();
  }
  return evidence;
}

function captureCompiledTrustBinding(candidate: unknown): CompiledTrustBinding {
  assertNoProxyOrAccessorTree(candidate, new Set<object>(), 0);
  const canonicalPolicy = canonicalizeOrganizationReconciliationEvidenceValue(candidate);
  const trustPolicy = parseOrganizationReconciliationTrustPolicy(canonicalPolicy);
  const profile = resolveCompiledOrganizationReconciliationTrustProfile(trustPolicy.profileId);
  if (
    !profile || profile.profileId !== trustPolicy.profileId ||
    profile.expectedEnvironment !== ENVIRONMENT || trustPolicy.environment !== ENVIRONMENT ||
    profile.policySha256 !== createOrganizationReconciliationTrustPolicySha256(trustPolicy) ||
    profile.requiredCollectors.length !== EXPECTED_SIGNER_COUNT
  ) {
    invalidConfig();
  }
  return Object.freeze({ trustPolicy, profile });
}

function assertNoProxyOrAccessorTree(
  candidate: unknown,
  active: Set<object>,
  depth: number
): void {
  if (candidate === null || typeof candidate !== "object") return;
  if (depth > 16 || active.has(candidate) || isProxy(candidate)) invalidConfig();
  active.add(candidate);
  try {
    const descriptors = Object.getOwnPropertyDescriptors(candidate);
    for (const [key, descriptor] of Object.entries(descriptors)) {
      if (key === "length" && Array.isArray(candidate)) continue;
      if (!("value" in descriptor)) invalidConfig();
      assertNoProxyOrAccessorTree(descriptor.value, active, depth + 1);
    }
  } finally {
    active.delete(candidate);
  }
}

function exactObject(candidate: unknown, expectedKeys: readonly string[]): Record<string, unknown> {
  if (
    candidate === null || typeof candidate !== "object" || Array.isArray(candidate) ||
    isProxy(candidate) || Object.getPrototypeOf(candidate) !== Object.prototype ||
    Object.getOwnPropertySymbols(candidate).length !== 0
  ) {
    invalidConfig();
  }
  const descriptors = Object.getOwnPropertyDescriptors(candidate);
  if (
    Object.keys(descriptors).length !== expectedKeys.length ||
    expectedKeys.some((key) => {
      const descriptor = descriptors[key];
      return !descriptor || !("value" in descriptor) || !descriptor.enumerable;
    })
  ) {
    invalidConfig();
  }
  return Object.freeze(Object.fromEntries(expectedKeys.map((key) => [key, descriptors[key]!.value])));
}

function exactArray(candidate: unknown, expectedLength: number): readonly unknown[] {
  if (
    !Array.isArray(candidate) || isProxy(candidate) || Object.getPrototypeOf(candidate) !== Array.prototype ||
    Object.getOwnPropertySymbols(candidate).length !== 0
  ) {
    invalidConfig();
  }
  const descriptors: PropertyDescriptorMap = Object.getOwnPropertyDescriptors(candidate as object);
  const length = descriptors["length"];
  if (
    !length || !("value" in length) || length.enumerable || length.value !== expectedLength ||
    Object.keys(descriptors).length !== expectedLength + 1
  ) {
    invalidConfig();
  }
  const output: unknown[] = [];
  for (let index = 0; index < expectedLength; index += 1) {
    const descriptor = descriptors[String(index)];
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) invalidConfig();
    output.push(descriptor.value);
  }
  return Object.freeze(output);
}

function assertAbsoluteOrdinaryFilePath(candidate: string, requireJson: boolean): string {
  if (
    typeof candidate !== "string" || candidate.length < 2 || candidate.length > 4_096 ||
    candidate.includes("\0") || !isAbsolute(candidate) || resolve(candidate) !== candidate ||
    (requireJson && extname(candidate) !== ".json")
  ) {
    invalidConfig();
  }
  return candidate;
}

function isStrictDescendant(candidate: string, parent: string): boolean {
  return candidate !== parent && candidate.startsWith(`${parent}/`) && resolve(candidate) === candidate;
}

async function readOrdinaryOwner0600File(
  path: string,
  maximumBytes: number,
  minimumBytes: number
): Promise<Buffer> {
  assertAbsoluteOrdinaryFilePath(path, false);
  if (
    typeof process.getuid !== "function" || typeof fsConstants.O_NOFOLLOW !== "number" ||
    typeof fsConstants.O_NONBLOCK !== "number"
  ) {
    invalidConfig();
  }
  const flags = fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK;
  let handle: Awaited<ReturnType<typeof open>> | null = null;
  let capturedBytes: Buffer | null = null;
  try {
    const beforePath = await lstat(path, { bigint: true });
    const parentPath = dirname(path);
    const [parent, resolvedParent, resolvedFile] = await Promise.all([
      lstat(parentPath, { bigint: true }),
      realpath(parentPath),
      realpath(path)
    ]);
    if (
      !parent.isDirectory() || parent.isSymbolicLink() || resolvedParent !== parentPath || resolvedFile !== path
    ) invalidConfig();
    assertSecureFileStat(beforePath, maximumBytes, minimumBytes);
    handle = await open(path, flags);
    const beforeRead = await handle.stat({ bigint: true });
    assertSecureFileStat(beforeRead, maximumBytes, minimumBytes);
    assertSameFileState(beforePath, beforeRead);
    const expectedBytes = Number(beforeRead.size);
    capturedBytes = Buffer.alloc(expectedBytes);
    let offset = 0;
    while (offset < expectedBytes) {
      const { bytesRead } = await handle.read(
        capturedBytes,
        offset,
        expectedBytes - offset,
        offset
      );
      if (bytesRead < 1) invalidConfig();
      offset += bytesRead;
    }
    const overflowProbe = Buffer.alloc(1);
    try {
      const { bytesRead } = await handle.read(overflowProbe, 0, 1, expectedBytes);
      if (bytesRead !== 0) invalidConfig();
    } finally {
      overflowProbe.fill(0);
    }
    const afterRead = await handle.stat({ bigint: true });
    assertSecureFileStat(afterRead, maximumBytes, minimumBytes);
    assertSameFileState(beforeRead, afterRead);
    const result = capturedBytes;
    capturedBytes = null;
    return result;
  } catch (error) {
    if (error instanceof OrganizationReconciliationDevelopHashSignerTransportConfigError) throw error;
    invalidConfig();
  } finally {
    capturedBytes?.fill(0);
    await handle?.close().catch(() => undefined);
  }
  return invalidConfig();
}

interface SecureFileStat {
  readonly dev: bigint;
  readonly ino: bigint;
  readonly mode: bigint;
  readonly nlink: bigint;
  readonly uid: bigint;
  readonly size: bigint;
  readonly mtimeNs: bigint;
  readonly ctimeNs: bigint;
  isFile(): boolean;
  isSymbolicLink(): boolean;
}

function assertSecureFileStat(stat: SecureFileStat, maximumBytes: number, minimumBytes: number): void {
  if (
    !stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1n ||
    (stat.mode & 0o777n) !== 0o600n || stat.uid !== BigInt(process.getuid!()) ||
    stat.size < BigInt(minimumBytes) || stat.size > BigInt(maximumBytes)
  ) {
    invalidConfig();
  }
}

function assertSameFileState(left: SecureFileStat, right: SecureFileStat): void {
  if (
    left.dev !== right.dev || left.ino !== right.ino || left.mode !== right.mode ||
    left.nlink !== right.nlink || left.uid !== right.uid || left.size !== right.size ||
    left.mtimeNs !== right.mtimeNs || left.ctimeNs !== right.ctimeNs
  ) {
    invalidConfig();
  }
}

function decodeUtf8(bytes: Uint8Array): string {
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    invalidConfig();
  }
}

/** Rejects duplicate decoded property names before JSON.parse can overwrite one. */
function assertJsonHasNoDuplicateObjectKeys(text: string): void {
  let offset = 0;
  const whitespace = () => {
    while (offset < text.length && /[\x20\t\r\n]/.test(text[offset]!)) offset += 1;
  };
  const string = (): string => {
    if (text[offset] !== '"') invalidConfig();
    const start = offset;
    offset += 1;
    while (offset < text.length) {
      const character = text[offset]!;
      if (character === '"') {
        offset += 1;
        return JSON.parse(text.slice(start, offset)) as string;
      }
      if (character === "\\") {
        offset += 1;
        if (offset >= text.length) invalidConfig();
        if (text[offset] === "u") {
          if (!/^[a-fA-F0-9]{4}$/.test(text.slice(offset + 1, offset + 5))) invalidConfig();
          offset += 5;
        } else {
          if (!/["\\/bfnrt]/.test(text[offset]!)) invalidConfig();
          offset += 1;
        }
      } else {
        if (character.charCodeAt(0) < 0x20) invalidConfig();
        offset += 1;
      }
    }
    invalidConfig();
  };
  const value = (depth: number): void => {
    if (depth > 16) invalidConfig();
    whitespace();
    if (text[offset] === "{") {
      offset += 1;
      whitespace();
      const keys = new Set<string>();
      if (text[offset] === "}") { offset += 1; return; }
      while (true) {
        const key = string();
        if (keys.has(key)) invalidConfig();
        keys.add(key);
        whitespace();
        if (text[offset] !== ":") invalidConfig();
        offset += 1;
        value(depth + 1);
        whitespace();
        if (text[offset] === "}") { offset += 1; return; }
        if (text[offset] !== ",") invalidConfig();
        offset += 1;
        whitespace();
      }
    }
    if (text[offset] === "[") {
      offset += 1;
      whitespace();
      if (text[offset] === "]") { offset += 1; return; }
      while (true) {
        value(depth + 1);
        whitespace();
        if (text[offset] === "]") { offset += 1; return; }
        if (text[offset] !== ",") invalidConfig();
        offset += 1;
      }
    }
    if (text[offset] === '"') { string(); return; }
    for (const literal of ["true", "false", "null"]) {
      if (text.startsWith(literal, offset)) { offset += literal.length; return; }
    }
    const match = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(text.slice(offset));
    if (!match) invalidConfig();
    offset += match[0].length;
  };
  value(0);
  whitespace();
  if (offset !== text.length) invalidConfig();
}

function invalidConfig(): never {
  throw new OrganizationReconciliationDevelopHashSignerTransportConfigError();
}
