import { createHash, timingSafeEqual } from "node:crypto";
import { isProxy } from "node:util/types";
import {
  canonicalizeOrganizationReconciliationEvidenceValue,
  type OrganizationReconciliationEvidenceJsonValue
} from "./iam-organization-reconciliation-component-manifest.js";

export const ORGANIZATION_RECONCILIATION_DEVELOP_DEPLOYMENT_EVIDENCE_CONTRACT =
  "iam-organization-reconciliation-xrteeth-develop-deployment-evidence/v2" as const;

const DEPLOYMENT_EVIDENCE_HASH_DOMAIN = Buffer.from(
  "iam-organization-reconciliation:xrteeth-develop:deployment-evidence:v2\u001f",
  "utf8"
);
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const IMAGE_DIGEST = /^sha256:[a-f0-9]{64}$/;
const FULL_REVISION = /^[a-f0-9]{40}$/;

export interface OrganizationReconciliationDevelopDeploymentExecutor {
  readonly portainerEndpointIdHash: string;
  readonly dockerEngineIdHash: string;
  readonly physicalHostIdentityHash: string;
  readonly containerIdHash: string;
  readonly containerImageDigest: string;
}

export interface OrganizationReconciliationDevelopDeploymentSigner {
  readonly collectorId: string;
  readonly nodeId: string;
  readonly keyId: string;
  readonly publicKeySha256: string;
  readonly tlsCertificateSha256: string;
  readonly portainerEndpointIdHash: string;
  readonly dockerEngineIdHash: string;
  readonly physicalHostIdentityHash: string;
  readonly containerIdHash: string;
  readonly containerImageDigest: string;
}

/**
 * Public, hash-only observation of the exact Develop deployment used for one
 * Task 7.2 run. It intentionally excludes host names, IPs, URLs, tokens,
 * private keys, database settings, organization records, and user records.
 */
export interface OrganizationReconciliationDevelopDeploymentEvidence {
  readonly contract: typeof ORGANIZATION_RECONCILIATION_DEVELOP_DEPLOYMENT_EVIDENCE_CONTRACT;
  readonly environment: "xrteeth-develop";
  readonly buildRevision: string;
  readonly releaseImageDigest: string;
  readonly topologyObservationSha256: string;
  readonly physicalProbeSha256: string;
  readonly observedAt: string;
  readonly physicalIndependenceVerified: false;
  readonly productionReady: false;
  readonly productionPromotionAllowed: false;
  readonly executor: OrganizationReconciliationDevelopDeploymentExecutor;
  readonly signers: readonly [OrganizationReconciliationDevelopDeploymentSigner];
}

export class OrganizationReconciliationDevelopDeploymentEvidenceError extends Error {
  constructor() {
    super("invalid-deployment-evidence");
    this.name = "OrganizationReconciliationDevelopDeploymentEvidenceError";
  }
}

export function parseOrganizationReconciliationDevelopDeploymentEvidence(
  candidate: unknown
): OrganizationReconciliationDevelopDeploymentEvidence {
  try {
    rejectProxyAccessorOrExoticTree(candidate, new Set<object>(), { nodes: 0 }, 0);
    const value = canonicalizeOrganizationReconciliationEvidenceValue(candidate);
    const root = exactRecord(value, [
      "buildRevision",
      "contract",
      "environment",
      "executor",
      "observedAt",
      "physicalIndependenceVerified",
      "physicalProbeSha256",
      "productionPromotionAllowed",
      "productionReady",
      "releaseImageDigest",
      "signers",
      "topologyObservationSha256"
    ]);
    if (
      root.contract !== ORGANIZATION_RECONCILIATION_DEVELOP_DEPLOYMENT_EVIDENCE_CONTRACT ||
      root.environment !== "xrteeth-develop" ||
      typeof root.buildRevision !== "string" || !FULL_REVISION.test(root.buildRevision) ||
      /^0+$/.test(root.buildRevision) ||
      typeof root.releaseImageDigest !== "string" || !IMAGE_DIGEST.test(root.releaseImageDigest) ||
      /^sha256:0+$/.test(root.releaseImageDigest) ||
      typeof root.topologyObservationSha256 !== "string" || !SHA256.test(root.topologyObservationSha256) ||
      /^0+$/.test(root.topologyObservationSha256) ||
      typeof root.physicalProbeSha256 !== "string" || !SHA256.test(root.physicalProbeSha256) ||
      /^0+$/.test(root.physicalProbeSha256) ||
      !canonicalTimestamp(root.observedAt) ||
      root.physicalIndependenceVerified !== false ||
      root.productionReady !== false ||
      root.productionPromotionAllowed !== false
    ) invalid();

    const executor = parseExecutor(root.executor, root.releaseImageDigest);
    if (!Array.isArray(root.signers) || root.signers.length !== 1) invalid();
    const signer = parseSigner(root.signers[0], root.releaseImageDigest);

    return Object.freeze({
      contract: ORGANIZATION_RECONCILIATION_DEVELOP_DEPLOYMENT_EVIDENCE_CONTRACT,
      environment: "xrteeth-develop",
      buildRevision: root.buildRevision,
      releaseImageDigest: root.releaseImageDigest,
      topologyObservationSha256: root.topologyObservationSha256,
      physicalProbeSha256: root.physicalProbeSha256,
      observedAt: root.observedAt as string,
      physicalIndependenceVerified: false,
      productionReady: false,
      productionPromotionAllowed: false,
      executor,
      signers: Object.freeze([signer]) as OrganizationReconciliationDevelopDeploymentEvidence["signers"]
    });
  } catch (error) {
    if (error instanceof OrganizationReconciliationDevelopDeploymentEvidenceError) throw error;
    throw new OrganizationReconciliationDevelopDeploymentEvidenceError();
  }
}

export function createOrganizationReconciliationDevelopDeploymentEvidenceSha256(
  candidate: unknown
): string {
  const parsed = parseOrganizationReconciliationDevelopDeploymentEvidence(candidate);
  return createHash("sha256")
    .update(DEPLOYMENT_EVIDENCE_HASH_DOMAIN)
    .update(JSON.stringify(parsed), "utf8")
    .digest("hex");
}

export function assertOrganizationReconciliationDevelopDeploymentEvidenceSha256(
  candidate: unknown,
  expectedSha256: string
): OrganizationReconciliationDevelopDeploymentEvidence {
  if (!SHA256.test(expectedSha256) || /^0+$/.test(expectedSha256)) invalid();
  const parsed = parseOrganizationReconciliationDevelopDeploymentEvidence(candidate);
  const actual = createOrganizationReconciliationDevelopDeploymentEvidenceSha256(parsed);
  if (!safeDigestEqual(actual, expectedSha256)) invalid();
  return parsed;
}

function parseExecutor(
  candidate: OrganizationReconciliationEvidenceJsonValue,
  releaseImageDigest: string
): OrganizationReconciliationDevelopDeploymentExecutor {
  const value = exactRecord(candidate, [
    "containerIdHash",
    "containerImageDigest",
    "dockerEngineIdHash",
    "physicalHostIdentityHash",
    "portainerEndpointIdHash"
  ]);
  const output = {
    portainerEndpointIdHash: digest(value.portainerEndpointIdHash),
    dockerEngineIdHash: digest(value.dockerEngineIdHash),
    physicalHostIdentityHash: digest(value.physicalHostIdentityHash),
    containerIdHash: digest(value.containerIdHash),
    containerImageDigest: imageDigest(value.containerImageDigest)
  };
  if (output.containerImageDigest !== releaseImageDigest) invalid();
  return Object.freeze(output);
}

function parseSigner(
  candidate: OrganizationReconciliationEvidenceJsonValue,
  releaseImageDigest: string
): OrganizationReconciliationDevelopDeploymentSigner {
  const value = exactRecord(candidate, [
    "collectorId",
    "containerIdHash",
    "containerImageDigest",
    "dockerEngineIdHash",
    "keyId",
    "nodeId",
    "physicalHostIdentityHash",
    "portainerEndpointIdHash",
    "publicKeySha256",
    "tlsCertificateSha256"
  ]);
  const output = {
    collectorId: identifier(value.collectorId),
    nodeId: identifier(value.nodeId),
    keyId: identifier(value.keyId),
    publicKeySha256: digest(value.publicKeySha256),
    tlsCertificateSha256: digest(value.tlsCertificateSha256),
    portainerEndpointIdHash: digest(value.portainerEndpointIdHash),
    dockerEngineIdHash: digest(value.dockerEngineIdHash),
    physicalHostIdentityHash: digest(value.physicalHostIdentityHash),
    containerIdHash: digest(value.containerIdHash),
    containerImageDigest: imageDigest(value.containerImageDigest)
  };
  if (output.containerImageDigest !== releaseImageDigest) invalid();
  return Object.freeze(output);
}

function rejectProxyAccessorOrExoticTree(
  value: unknown,
  active: Set<object>,
  state: { nodes: number },
  depth: number
): void {
  state.nodes += 1;
  if (state.nodes > 10_000 || depth > 32) invalid();
  if (value === null || typeof value !== "object") return;
  if (isProxy(value) || active.has(value)) invalid();
  active.add(value);
  try {
    const prototype = Object.getPrototypeOf(value);
    if (Array.isArray(value)) {
      if (prototype !== Array.prototype) invalid();
      const descriptors = Object.getOwnPropertyDescriptors(value);
      const keys = Object.keys(descriptors);
      if (keys.length !== value.length + 1 || !Object.hasOwn(descriptors, "length")) invalid();
      for (let index = 0; index < value.length; index += 1) {
        const descriptor = descriptors[String(index)];
        if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) invalid();
        rejectProxyAccessorOrExoticTree(descriptor.value, active, state, depth + 1);
      }
      return;
    }
    if (prototype !== Object.prototype && prototype !== null) invalid();
    if (Object.getOwnPropertySymbols(value).length !== 0) invalid();
    for (const descriptor of Object.values(Object.getOwnPropertyDescriptors(value))) {
      if (!("value" in descriptor) || !descriptor.enumerable) invalid();
      rejectProxyAccessorOrExoticTree(descriptor.value, active, state, depth + 1);
    }
  } finally {
    active.delete(value);
  }
}

function exactRecord(
  candidate: OrganizationReconciliationEvidenceJsonValue,
  keys: readonly string[]
): Record<string, OrganizationReconciliationEvidenceJsonValue> {
  if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) invalid();
  const actual = Object.keys(candidate).sort();
  const expected = [...keys].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) invalid();
  return candidate as Record<string, OrganizationReconciliationEvidenceJsonValue>;
}

function identifier(value: unknown): string {
  if (typeof value !== "string" || !IDENTIFIER.test(value)) invalid();
  return value;
}

function digest(value: unknown): string {
  if (typeof value !== "string" || !SHA256.test(value) || /^0+$/.test(value)) invalid();
  return value;
}

function imageDigest(value: unknown): string {
  if (typeof value !== "string" || !IMAGE_DIGEST.test(value) || /^sha256:0+$/.test(value)) invalid();
  return value;
}

function canonicalTimestamp(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
}

function safeDigestEqual(left: string, right: string): boolean {
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

function invalid(): never {
  throw new OrganizationReconciliationDevelopDeploymentEvidenceError();
}
