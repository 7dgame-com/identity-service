import { createHash, timingSafeEqual } from "node:crypto";
import { isProxy } from "node:util/types";
import {
  parseOrganizationReconciliationDevelopDeploymentEvidence,
  type OrganizationReconciliationDevelopDeploymentEvidence
} from "./iam-organization-reconciliation-develop-deployment-evidence.js";

export const ORGANIZATION_RECONCILIATION_DEVELOP_DOCKER_INSPECT_OBSERVATION_SET_CONTRACT =
  "iam-organization-reconciliation-xrteeth-develop-docker-inspect-observation-set/v1" as const;
export const ORGANIZATION_RECONCILIATION_DEVELOP_CI_PROVENANCE_DEPLOYMENT_BUNDLE_CONTRACT =
  "iam-organization-reconciliation-xrteeth-develop-ci-provenance-deployment-bundle/v1" as const;

const CI_PROVENANCE_CONTRACT = "identity-service/develop-image-provenance/v1" as const;
const TOPOLOGY_OBSERVATION_HASH_DOMAIN = Buffer.from(
  "iam-organization-reconciliation:xrteeth-develop:docker-inspect-topology-observation:v1\u001f",
  "utf8"
);
const REVISION = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const SHA256_DIGEST = /^sha256:[a-f0-9]{64}$/;
const IMAGE_REPOSITORY = /^[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]{1,5})?(?:\/[a-z0-9]+(?:[._-][a-z0-9]+)*)+$/;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const ROLES = Object.freeze(["runner", "signer"] as const);

export interface OrganizationReconciliationDevelopCiImageProvenance {
  readonly contract: typeof CI_PROVENANCE_CONTRACT;
  readonly gitSha: string;
  readonly image: string;
  readonly imageDigest: string;
}

export interface OrganizationReconciliationDevelopDockerInspectImageObservation {
  readonly contract: "iam-organization-reconciliation-xrteeth-develop-docker-inspect-image-observation/v1";
  readonly environment: "xrteeth-develop";
  readonly role: typeof ROLES[number];
  readonly keyId: string | null;
  readonly source: "docker-inspect";
  readonly observedAt: string;
  readonly configuredImage: string;
  readonly repoDigest: string;
  readonly containerImageId: string;
  readonly imageInspectId: string;
  readonly containerIdHash: string;
  readonly portainerEndpointIdHash: string;
  readonly dockerEngineIdHash: string;
  readonly physicalHostIdentityHash: string;
}

export interface OrganizationReconciliationDevelopDockerInspectObservationSet {
  readonly contract: typeof ORGANIZATION_RECONCILIATION_DEVELOP_DOCKER_INSPECT_OBSERVATION_SET_CONTRACT;
  readonly environment: "xrteeth-develop";
  readonly observations: readonly [
    OrganizationReconciliationDevelopDockerInspectImageObservation,
    OrganizationReconciliationDevelopDockerInspectImageObservation
  ];
}

export interface OrganizationReconciliationDevelopCiProvenanceDeploymentBundleInput {
  readonly ciProvenance: unknown;
  readonly deploymentEvidence: unknown;
  readonly signerCompose: unknown;
  readonly runnerCompose: unknown;
  readonly dockerInspectObservationSet: unknown;
}

export interface OrganizationReconciliationDevelopCiProvenanceDeploymentBundleReport {
  readonly contract: typeof ORGANIZATION_RECONCILIATION_DEVELOP_CI_PROVENANCE_DEPLOYMENT_BUNDLE_CONTRACT;
  readonly environment: "xrteeth-develop";
  readonly outcome: "passed";
  readonly gitSha: string;
  readonly image: string;
  readonly imageDigest: string;
  readonly topologyObservationSha256: string;
  readonly composeRoleCount: 2;
  readonly dockerInspectObservationCount: 2;
  readonly productionReady: false;
}

export class OrganizationReconciliationDevelopCiProvenanceDeploymentBundleError extends Error {
  constructor() {
    super("invalid-ci-provenance-deployment-bundle");
    this.name = "OrganizationReconciliationDevelopCiProvenanceDeploymentBundleError";
  }
}

/**
 * Cross-stack gate driven exclusively by CI output, rendered Compose output,
 * and externally captured Docker inspect observations. The application image
 * never self-attests its own digest.
 */
export function validateOrganizationReconciliationDevelopCiProvenanceDeploymentBundle(
  candidate: OrganizationReconciliationDevelopCiProvenanceDeploymentBundleInput
): OrganizationReconciliationDevelopCiProvenanceDeploymentBundleReport {
  try {
    const input = exactObject(candidate, [
      "ciProvenance", "deploymentEvidence", "signerCompose", "runnerCompose",
      "dockerInspectObservationSet"
    ]);
    const provenance = parseCiProvenance(input.ciProvenance);
    const deployment = parseOrganizationReconciliationDevelopDeploymentEvidence(input.deploymentEvidence);
    if (deployment.buildRevision !== provenance.gitSha || deployment.releaseImageDigest !== provenance.imageDigest) {
      invalid();
    }
    const composeImages = Object.freeze({
      runner: parseComposeImage(input.runnerCompose, "develop-full-range-runner"),
      signer: parseComposeImage(input.signerCompose, "develop-hash-signer")
    });
    if (Object.values(composeImages).some((image) => image !== provenance.image)) invalid();

    const observationSet = parseObservationSet(input.dockerInspectObservationSet);
    bindObservations(provenance, deployment, observationSet);
    const topologyObservationSha256 =
      createOrganizationReconciliationDevelopDockerInspectTopologyObservationSha256({
        provenance,
        composeImages,
        observationSet
      });
    if (!safeEqual(topologyObservationSha256, deployment.topologyObservationSha256)) invalid();

    return Object.freeze({
      contract: ORGANIZATION_RECONCILIATION_DEVELOP_CI_PROVENANCE_DEPLOYMENT_BUNDLE_CONTRACT,
      environment: "xrteeth-develop" as const,
      outcome: "passed" as const,
      gitSha: provenance.gitSha,
      image: provenance.image,
      imageDigest: provenance.imageDigest,
      topologyObservationSha256,
      composeRoleCount: 2 as const,
      dockerInspectObservationCount: 2 as const,
      productionReady: false as const
    });
  } catch (error) {
    if (error instanceof OrganizationReconciliationDevelopCiProvenanceDeploymentBundleError) throw error;
    throw new OrganizationReconciliationDevelopCiProvenanceDeploymentBundleError();
  }
}

export function createOrganizationReconciliationDevelopDockerInspectTopologyObservationSha256(
  candidate: Readonly<{
    provenance: OrganizationReconciliationDevelopCiImageProvenance;
    composeImages: Readonly<Record<typeof ROLES[number], string>>;
    observationSet: OrganizationReconciliationDevelopDockerInspectObservationSet;
  }>
): string {
  try {
    assertPlainDataTree(candidate, new Set<object>(), 0);
    const provenance = parseCiProvenance(candidate.provenance);
    const compose = exactObject(candidate.composeImages, ROLES);
    const observationSet = parseObservationSet(candidate.observationSet);
    const canonical = Object.freeze({
      contract: "iam-organization-reconciliation-xrteeth-develop-docker-inspect-topology-observation/v1",
      environment: "xrteeth-develop",
      gitSha: provenance.gitSha,
      image: provenance.image,
      composeImages: Object.freeze({
        runner: requiredString(compose.runner),
        signer: requiredString(compose.signer)
      }),
      dockerInspectObservationSet: observationSet
    });
    return createHash("sha256").update(TOPOLOGY_OBSERVATION_HASH_DOMAIN)
      .update(JSON.stringify(canonical), "utf8").digest("hex");
  } catch (error) {
    if (error instanceof OrganizationReconciliationDevelopCiProvenanceDeploymentBundleError) throw error;
    throw new OrganizationReconciliationDevelopCiProvenanceDeploymentBundleError();
  }
}

function parseCiProvenance(candidate: unknown): OrganizationReconciliationDevelopCiImageProvenance {
  const value = exactObject(candidate, ["contract", "gitSha", "image", "imageDigest"]);
  if (
    value.contract !== CI_PROVENANCE_CONTRACT || typeof value.gitSha !== "string" || !REVISION.test(value.gitSha) ||
    /^0+$/.test(value.gitSha) || typeof value.imageDigest !== "string" || !SHA256_DIGEST.test(value.imageDigest) ||
    /^sha256:0+$/.test(value.imageDigest) || typeof value.image !== "string"
  ) invalid();
  const delimiter = value.image.lastIndexOf("@");
  const repository = value.image.slice(0, delimiter);
  const digest = value.image.slice(delimiter + 1);
  if (delimiter < 1 || !IMAGE_REPOSITORY.test(repository) || digest !== value.imageDigest ||
    value.image !== `${repository}@${value.imageDigest}`) invalid();
  return Object.freeze({
    contract: CI_PROVENANCE_CONTRACT,
    gitSha: value.gitSha,
    image: value.image,
    imageDigest: value.imageDigest
  });
}

function parseComposeImage(candidate: unknown, serviceName: string): string {
  assertPlainDataTree(candidate, new Set<object>(), 0);
  const root = candidate as Record<string, unknown>;
  const services = root.services;
  if (!services || typeof services !== "object" || Array.isArray(services)) invalid();
  const serviceDescriptors = Object.getOwnPropertyDescriptors(services);
  if (JSON.stringify(Object.keys(serviceDescriptors)) !== JSON.stringify([serviceName])) invalid();
  const serviceDescriptor = serviceDescriptors[serviceName];
  if (!serviceDescriptor || !("value" in serviceDescriptor)) invalid();
  const service = serviceDescriptor.value;
  if (!service || typeof service !== "object" || Array.isArray(service)) invalid();
  const imageDescriptor = Object.getOwnPropertyDescriptor(service, "image");
  if (!imageDescriptor || !("value" in imageDescriptor) || typeof imageDescriptor.value !== "string") invalid();
  return imageDescriptor.value;
}

function parseObservationSet(candidate: unknown): OrganizationReconciliationDevelopDockerInspectObservationSet {
  const value = exactObject(candidate, ["contract", "environment", "observations"]);
  if (value.contract !== ORGANIZATION_RECONCILIATION_DEVELOP_DOCKER_INSPECT_OBSERVATION_SET_CONTRACT ||
    value.environment !== "xrteeth-develop") invalid();
  const candidates = exactArray(value.observations, 2);
  const observations = candidates.map((observation, index) => parseObservation(observation, ROLES[index]!));
  return Object.freeze({
    contract: ORGANIZATION_RECONCILIATION_DEVELOP_DOCKER_INSPECT_OBSERVATION_SET_CONTRACT,
    environment: "xrteeth-develop" as const,
    observations: Object.freeze(observations) as OrganizationReconciliationDevelopDockerInspectObservationSet["observations"]
  });
}

function parseObservation(
  candidate: unknown,
  expectedRole: typeof ROLES[number]
): OrganizationReconciliationDevelopDockerInspectImageObservation {
  const value = exactObject(candidate, [
    "contract", "environment", "role", "keyId", "source", "observedAt", "configuredImage", "repoDigest",
    "containerImageId", "imageInspectId", "containerIdHash", "portainerEndpointIdHash", "dockerEngineIdHash",
    "physicalHostIdentityHash"
  ]);
  if (
    value.contract !== "iam-organization-reconciliation-xrteeth-develop-docker-inspect-image-observation/v1" ||
    value.environment !== "xrteeth-develop" || value.role !== expectedRole || value.source !== "docker-inspect" ||
    !canonicalTimestamp(value.observedAt) || typeof value.configuredImage !== "string" ||
    typeof value.repoDigest !== "string" || typeof value.containerImageId !== "string" ||
    !SHA256_DIGEST.test(value.containerImageId) || /^sha256:0+$/.test(value.containerImageId) ||
    value.imageInspectId !== value.containerImageId ||
    (expectedRole === "runner" ? value.keyId !== null : typeof value.keyId !== "string" || !IDENTIFIER.test(value.keyId))
  ) invalid();
  return Object.freeze({
    contract: "iam-organization-reconciliation-xrteeth-develop-docker-inspect-image-observation/v1" as const,
    environment: "xrteeth-develop" as const,
    role: expectedRole,
    keyId: value.keyId as string | null,
    source: "docker-inspect" as const,
    observedAt: value.observedAt as string,
    configuredImage: value.configuredImage,
    repoDigest: value.repoDigest,
    containerImageId: value.containerImageId,
    imageInspectId: value.imageInspectId,
    containerIdHash: digest(value.containerIdHash),
    portainerEndpointIdHash: digest(value.portainerEndpointIdHash),
    dockerEngineIdHash: digest(value.dockerEngineIdHash),
    physicalHostIdentityHash: digest(value.physicalHostIdentityHash)
  });
}

function bindObservations(
  provenance: OrganizationReconciliationDevelopCiImageProvenance,
  deployment: OrganizationReconciliationDevelopDeploymentEvidence,
  set: OrganizationReconciliationDevelopDockerInspectObservationSet
): void {
  const deploymentTime = Date.parse(deployment.observedAt);
  const runner = set.observations[0];
  const signerObservation = set.observations[1];
  if (set.observations.some((observation) =>
    observation.configuredImage !== provenance.image || observation.repoDigest !== provenance.image ||
    Date.parse(observation.observedAt) > deploymentTime
  )) invalid();
  if (!deploymentExecutorMatchesObservation(deployment.executor, runner)) invalid();
  if (!signerObservation.keyId || signerObservation.keyId !== deployment.signers[0].keyId ||
    !deploymentSignerMatchesObservation(deployment.signers[0], signerObservation) ||
    safeEqual(runner.containerIdHash, signerObservation.containerIdHash)) invalid();
  if (new Set(set.observations.map((observation) => observation.containerImageId)).size !== 1) invalid();
}

function deploymentExecutorMatchesObservation(
  deployment: OrganizationReconciliationDevelopDeploymentEvidence["executor"],
  observation: OrganizationReconciliationDevelopDockerInspectImageObservation
): boolean {
  return safeEqual(deployment.containerIdHash, observation.containerIdHash) &&
    safeEqual(deployment.portainerEndpointIdHash, observation.portainerEndpointIdHash) &&
    safeEqual(deployment.dockerEngineIdHash, observation.dockerEngineIdHash) &&
    safeEqual(deployment.physicalHostIdentityHash, observation.physicalHostIdentityHash);
}

function deploymentSignerMatchesObservation(
  deployment: OrganizationReconciliationDevelopDeploymentEvidence["signers"][number],
  observation: OrganizationReconciliationDevelopDockerInspectImageObservation
): boolean {
  return safeEqual(deployment.containerIdHash, observation.containerIdHash) &&
    safeEqual(deployment.portainerEndpointIdHash, observation.portainerEndpointIdHash) &&
    safeEqual(deployment.dockerEngineIdHash, observation.dockerEngineIdHash) &&
    safeEqual(deployment.physicalHostIdentityHash, observation.physicalHostIdentityHash);
}

function exactObject(candidate: unknown, expectedKeys: readonly string[]): Record<string, unknown> {
  if (!candidate || typeof candidate !== "object" || Array.isArray(candidate) || isProxy(candidate) ||
    Object.getPrototypeOf(candidate) !== Object.prototype || Object.getOwnPropertySymbols(candidate).length !== 0) invalid();
  const descriptors: PropertyDescriptorMap = Object.getOwnPropertyDescriptors(candidate as object);
  if (JSON.stringify(Object.keys(descriptors)) !== JSON.stringify(expectedKeys)) invalid();
  const output: Record<string, unknown> = {};
  for (const key of expectedKeys) {
    const descriptor = descriptors[key];
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) invalid();
    output[key] = descriptor.value;
  }
  return Object.freeze(output);
}

function exactArray(candidate: unknown, expectedLength: number): readonly unknown[] {
  if (!Array.isArray(candidate) || isProxy(candidate) || Object.getPrototypeOf(candidate) !== Array.prototype ||
    Object.getOwnPropertySymbols(candidate).length !== 0) invalid();
  const descriptors: PropertyDescriptorMap = Object.getOwnPropertyDescriptors(candidate as object);
  if (descriptors["length"]?.value !== expectedLength || Object.keys(descriptors).length !== expectedLength + 1) invalid();
  const output: unknown[] = [];
  for (let index = 0; index < expectedLength; index += 1) {
    const descriptor = descriptors[String(index)];
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) invalid();
    output.push(descriptor.value);
  }
  return Object.freeze(output);
}

function assertPlainDataTree(candidate: unknown, active: Set<object>, depth: number): void {
  if (candidate === null || typeof candidate !== "object") return;
  if (depth > 32 || active.has(candidate) || isProxy(candidate) || Object.getOwnPropertySymbols(candidate).length !== 0) invalid();
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

function digest(candidate: unknown): string {
  if (typeof candidate !== "string" || !SHA256.test(candidate) || /^0+$/.test(candidate)) invalid();
  return candidate;
}

function requiredString(candidate: unknown): string {
  if (typeof candidate !== "string" || candidate.length < 1) invalid();
  return candidate;
}

function canonicalTimestamp(candidate: unknown): candidate is string {
  if (typeof candidate !== "string") return false;
  const milliseconds = Date.parse(candidate);
  return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === candidate;
}

function safeEqual(left: string, right: string): boolean {
  const leftBytes = Buffer.from(left, "utf8");
  const rightBytes = Buffer.from(right, "utf8");
  return leftBytes.length === rightBytes.length && timingSafeEqual(leftBytes, rightBytes);
}

function invalid(): never {
  throw new OrganizationReconciliationDevelopCiProvenanceDeploymentBundleError();
}
