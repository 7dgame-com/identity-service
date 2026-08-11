import { timingSafeEqual } from "node:crypto";
import { isProxy } from "node:util/types";
import {
  parseOrganizationReconciliationDevelopDeploymentEvidence,
  type OrganizationReconciliationDevelopDeploymentEvidence
} from "./iam-organization-reconciliation-develop-deployment-evidence.js";

export const ORGANIZATION_RECONCILIATION_DEVELOP_DEPLOYMENT_TOPOLOGY_CONTRACT =
  "iam-organization-reconciliation-xrteeth-develop-compiled-deployment-topology/v1" as const;

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const SHA256 = /^[a-f0-9]{64}$/;

export interface OrganizationReconciliationDevelopDeploymentTopologyExecutor {
  readonly portainerEndpointIdHash: string;
  readonly dockerEngineIdHash: string;
  readonly physicalHostIdentityHash: string;
}

export interface OrganizationReconciliationDevelopDeploymentTopologySigner {
  readonly collectorId: string;
  readonly nodeId: string;
  readonly keyId: string;
  readonly publicKeySha256: string;
  readonly tlsCertificateSha256: string;
  readonly portainerEndpointIdHash: string;
  readonly dockerEngineIdHash: string;
  readonly physicalHostIdentityHash: string;
}

/**
 * Reviewed, revision-independent Develop topology root. Image/build/container
 * values are deliberately absent: putting an image digest in source that is
 * built into that same image would create a circular trust claim.
 */
export interface OrganizationReconciliationDevelopDeploymentTopologyTemplate {
  readonly contract: typeof ORGANIZATION_RECONCILIATION_DEVELOP_DEPLOYMENT_TOPOLOGY_CONTRACT;
  readonly environment: "xrteeth-develop";
  readonly profileId: string;
  readonly executor: OrganizationReconciliationDevelopDeploymentTopologyExecutor;
  readonly signers: readonly [OrganizationReconciliationDevelopDeploymentTopologySigner];
}

export type OrganizationReconciliationDevelopDeploymentTopologyRegistry =
  Readonly<Record<string, OrganizationReconciliationDevelopDeploymentTopologyTemplate>>;

export interface OrganizationReconciliationDevelopPinnedDeploymentTopology {
  readonly topology: OrganizationReconciliationDevelopDeploymentTopologyTemplate;
  readonly deploymentEvidence: OrganizationReconciliationDevelopDeploymentEvidence;
  readonly physicalIndependenceVerified: false;
  readonly productionPromotionAllowed: false;
}

export class OrganizationReconciliationDevelopDeploymentTopologyError extends Error {
  constructor() {
    super("invalid-compiled-deployment-topology");
    this.name = "OrganizationReconciliationDevelopDeploymentTopologyError";
  }
}

/**
 * Develop is intentionally unprovisioned until the approved runner/signer
 * endpoint, engine, host, key, and TLS pins are reviewed and compiled.
 * Physical independence is not part of Task 7.2; it remains a separate future
 * Production-promotion blocker.
 */
const COMPILED_DEVELOP_DEPLOYMENT_TOPOLOGY_TEMPLATES:
Readonly<Record<string, OrganizationReconciliationDevelopDeploymentTopologyTemplate>> =
  Object.freeze({});

const COMPILED_DEVELOP_DEPLOYMENT_TOPOLOGIES =
  compileOrganizationReconciliationDevelopDeploymentTopologyTemplates(
    COMPILED_DEVELOP_DEPLOYMENT_TOPOLOGY_TEMPLATES
  );

export const compiledOrganizationReconciliationDevelopDeploymentTopologyCount =
  Object.keys(COMPILED_DEVELOP_DEPLOYMENT_TOPOLOGIES).length;

export function resolveSoleCompiledOrganizationReconciliationDevelopDeploymentTopology():
OrganizationReconciliationDevelopDeploymentTopologyTemplate | undefined {
  return selectSoleCompiledOrganizationReconciliationDevelopDeploymentTopology(
    COMPILED_DEVELOP_DEPLOYMENT_TOPOLOGIES
  );
}

/** Pure compiler exported only so isolated tests can exercise the production path. */
export function compileOrganizationReconciliationDevelopDeploymentTopologyTemplates(
  candidates: Readonly<Record<string, OrganizationReconciliationDevelopDeploymentTopologyTemplate>>
): OrganizationReconciliationDevelopDeploymentTopologyRegistry {
  const empty = (): OrganizationReconciliationDevelopDeploymentTopologyRegistry => Object.freeze({});
  try {
    assertPlainDataTree(candidates, new Set<object>(), 0);
    const registry: Record<string, OrganizationReconciliationDevelopDeploymentTopologyTemplate> = {};
    for (const [profileId, candidate] of Object.entries(candidates)) {
      if (!IDENTIFIER.test(profileId) || Object.hasOwn(registry, profileId)) return empty();
      const topology = captureTopology(candidate);
      if (topology.profileId !== profileId) return empty();
      registry[profileId] = topology;
    }
    return Object.freeze(registry);
  } catch {
    return empty();
  }
}

export function selectSoleCompiledOrganizationReconciliationDevelopDeploymentTopology(
  registry: OrganizationReconciliationDevelopDeploymentTopologyRegistry
): OrganizationReconciliationDevelopDeploymentTopologyTemplate | undefined {
  try {
    assertPlainDataTree(registry, new Set<object>(), 0);
    const entries = Object.entries(registry);
    if (entries.length !== 1) return undefined;
    const [profileId, candidate] = entries[0]!;
    const topology = captureTopology(candidate);
    return topology.profileId === profileId ? topology : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Binds the sole Develop runner/signer topology. Task 7.2 deliberately makes
 * no physical-independence claim; matching all pins still leaves Production
 * promotion blocked.
 */
export function bindOrganizationReconciliationDevelopDeploymentEvidenceToCompiledTopology(
  candidate: unknown,
  profileId: string
): OrganizationReconciliationDevelopPinnedDeploymentTopology {
  try {
    if (!IDENTIFIER.test(profileId)) invalid();
    const topology = resolveSoleCompiledOrganizationReconciliationDevelopDeploymentTopology();
    if (!topology || topology.profileId !== profileId) invalid();
    return bindOrganizationReconciliationDevelopDeploymentEvidenceToTopology(
      candidate,
      profileId,
      topology
    );
  } catch (error) {
    if (error instanceof OrganizationReconciliationDevelopDeploymentTopologyError) throw error;
    throw new OrganizationReconciliationDevelopDeploymentTopologyError();
  }
}

/** Pure exact matcher; production callers use the sole-compiled wrapper above. */
export function bindOrganizationReconciliationDevelopDeploymentEvidenceToTopology(
  candidate: unknown,
  profileId: string,
  topologyCandidate: unknown
): OrganizationReconciliationDevelopPinnedDeploymentTopology {
  try {
    if (!IDENTIFIER.test(profileId)) invalid();
    const topology = captureTopology(topologyCandidate);
    if (topology.profileId !== profileId) invalid();
    const evidence = parseOrganizationReconciliationDevelopDeploymentEvidence(candidate);
    if (
      evidence.environment !== topology.environment ||
      !executorMatches(evidence.executor, topology.executor) ||
      evidence.signers.length !== topology.signers.length
    ) invalid();
    const evidenceByKey = new Map(evidence.signers.map((signer) => [signer.keyId, signer]));
    for (const expected of topology.signers) {
      const observed = evidenceByKey.get(expected.keyId);
      if (!observed || !signerMatches(observed, expected)) invalid();
    }
    if (evidenceByKey.size !== topology.signers.length) invalid();
    return Object.freeze({
      topology,
      deploymentEvidence: evidence,
      physicalIndependenceVerified: false as const,
      productionPromotionAllowed: false as const
    });
  } catch (error) {
    if (error instanceof OrganizationReconciliationDevelopDeploymentTopologyError) throw error;
    throw new OrganizationReconciliationDevelopDeploymentTopologyError();
  }
}

function captureTopology(candidate: unknown): OrganizationReconciliationDevelopDeploymentTopologyTemplate {
  const root = exactObject(candidate, ["contract", "environment", "profileId", "executor", "signers"]);
  if (
    root.contract !== ORGANIZATION_RECONCILIATION_DEVELOP_DEPLOYMENT_TOPOLOGY_CONTRACT ||
    root.environment !== "xrteeth-develop" || typeof root.profileId !== "string" ||
    !IDENTIFIER.test(root.profileId)
  ) invalid();
  const executor = captureExecutor(root.executor);
  const signerCandidates = exactArray(root.signers, 1);
  const signer = captureSigner(signerCandidates[0]);
  return Object.freeze({
    contract: ORGANIZATION_RECONCILIATION_DEVELOP_DEPLOYMENT_TOPOLOGY_CONTRACT,
    environment: "xrteeth-develop" as const,
    profileId: root.profileId,
    executor,
    signers: Object.freeze([signer]) as OrganizationReconciliationDevelopDeploymentTopologyTemplate["signers"]
  });
}

function captureExecutor(candidate: unknown): OrganizationReconciliationDevelopDeploymentTopologyExecutor {
  const value = exactObject(candidate, [
    "portainerEndpointIdHash", "dockerEngineIdHash", "physicalHostIdentityHash"
  ]);
  return Object.freeze({
    portainerEndpointIdHash: digest(value.portainerEndpointIdHash),
    dockerEngineIdHash: digest(value.dockerEngineIdHash),
    physicalHostIdentityHash: digest(value.physicalHostIdentityHash)
  });
}

function captureSigner(candidate: unknown): OrganizationReconciliationDevelopDeploymentTopologySigner {
  const value = exactObject(candidate, [
    "collectorId", "nodeId", "keyId", "publicKeySha256", "tlsCertificateSha256",
    "portainerEndpointIdHash", "dockerEngineIdHash", "physicalHostIdentityHash"
  ]);
  return Object.freeze({
    collectorId: identifier(value.collectorId),
    nodeId: identifier(value.nodeId),
    keyId: identifier(value.keyId),
    publicKeySha256: digest(value.publicKeySha256),
    tlsCertificateSha256: digest(value.tlsCertificateSha256),
    portainerEndpointIdHash: digest(value.portainerEndpointIdHash),
    dockerEngineIdHash: digest(value.dockerEngineIdHash),
    physicalHostIdentityHash: digest(value.physicalHostIdentityHash)
  });
}

function executorMatches(
  observed: OrganizationReconciliationDevelopDeploymentEvidence["executor"],
  expected: OrganizationReconciliationDevelopDeploymentTopologyExecutor
): boolean {
  return safeEqual(observed.portainerEndpointIdHash, expected.portainerEndpointIdHash) &&
    safeEqual(observed.dockerEngineIdHash, expected.dockerEngineIdHash) &&
    safeEqual(observed.physicalHostIdentityHash, expected.physicalHostIdentityHash);
}

function signerMatches(
  observed: OrganizationReconciliationDevelopDeploymentEvidence["signers"][number],
  expected: OrganizationReconciliationDevelopDeploymentTopologySigner
): boolean {
  return observed.collectorId === expected.collectorId && observed.nodeId === expected.nodeId &&
    observed.keyId === expected.keyId && safeEqual(observed.publicKeySha256, expected.publicKeySha256) &&
    safeEqual(observed.tlsCertificateSha256, expected.tlsCertificateSha256) &&
    safeEqual(observed.portainerEndpointIdHash, expected.portainerEndpointIdHash) &&
    safeEqual(observed.dockerEngineIdHash, expected.dockerEngineIdHash) &&
    safeEqual(observed.physicalHostIdentityHash, expected.physicalHostIdentityHash);
}

function exactObject(candidate: unknown, expectedKeys: readonly string[]): Record<string, unknown> {
  if (!candidate || typeof candidate !== "object" || Array.isArray(candidate) || isProxy(candidate) ||
    Object.getPrototypeOf(candidate) !== Object.prototype || Object.getOwnPropertySymbols(candidate).length !== 0) {
    invalid();
  }
  const descriptors: PropertyDescriptorMap = Object.getOwnPropertyDescriptors(candidate as object);
  const keys = Object.keys(descriptors).sort();
  if (JSON.stringify(keys) !== JSON.stringify([...expectedKeys].sort())) invalid();
  const output: Record<string, unknown> = {};
  for (const key of expectedKeys) {
    const descriptor = descriptors[key];
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) invalid();
    output[key] = descriptor.value;
  }
  return Object.freeze(output);
}

function exactArray(candidate: unknown, length: number): readonly unknown[] {
  if (!Array.isArray(candidate) || isProxy(candidate) || Object.getPrototypeOf(candidate) !== Array.prototype ||
    Object.getOwnPropertySymbols(candidate).length !== 0) invalid();
  const descriptors: PropertyDescriptorMap = Object.getOwnPropertyDescriptors(candidate as object);
  if (descriptors["length"]?.value !== length || Object.keys(descriptors).length !== length + 1) invalid();
  const output: unknown[] = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) invalid();
    output.push(descriptor.value);
  }
  return Object.freeze(output);
}

function assertPlainDataTree(candidate: unknown, active: Set<object>, depth: number): void {
  if (candidate === null || typeof candidate !== "object") return;
  if (depth > 16 || active.has(candidate) || isProxy(candidate) || Object.getOwnPropertySymbols(candidate).length !== 0) {
    invalid();
  }
  const prototype = Object.getPrototypeOf(candidate);
  if (prototype !== Object.prototype && prototype !== Array.prototype) invalid();
  active.add(candidate);
  try {
    for (const [key, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(candidate))) {
      if (Array.isArray(candidate) && key === "length") continue;
      if (!("value" in descriptor) || !descriptor.enumerable) invalid();
      assertPlainDataTree(descriptor.value, active, depth + 1);
    }
  } finally {
    active.delete(candidate);
  }
}

function identifier(candidate: unknown): string {
  if (typeof candidate !== "string" || !IDENTIFIER.test(candidate)) invalid();
  return candidate;
}

function digest(candidate: unknown): string {
  if (typeof candidate !== "string" || !SHA256.test(candidate) || /^0+$/.test(candidate)) invalid();
  return candidate;
}

function safeEqual(left: string, right: string): boolean {
  const leftBytes = Buffer.from(left, "utf8");
  const rightBytes = Buffer.from(right, "utf8");
  return leftBytes.length === rightBytes.length && timingSafeEqual(leftBytes, rightBytes);
}

function invalid(): never {
  throw new OrganizationReconciliationDevelopDeploymentTopologyError();
}
