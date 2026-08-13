import {
  createHash,
  createPublicKey,
  timingSafeEqual
} from "node:crypto";
import { isProxy } from "node:util/types";
import {
  canonicalizeOrganizationReconciliationEvidenceValue,
  type OrganizationReconciliationEvidenceJsonValue
} from "./iam-organization-reconciliation-component-manifest.js";
import {
  ORGANIZATION_RECONCILIATION_PROVENANCE_CONTRACT,
  createOrganizationReconciliationProvenanceBindingFromInput,
  createOrganizationReconciliationProvenancePayload,
  createOrganizationReconciliationSignedAttestation,
  createOrganizationReconciliationTrustPolicySha256,
  parseOrganizationReconciliationAttestationBundle,
  parseOrganizationReconciliationTrustPolicy,
  serializeOrganizationReconciliationProvenancePayload,
  type OrganizationReconciliationAttestationBundle,
  type OrganizationReconciliationProvenancePayload,
  type OrganizationReconciliationSignedAttestation,
  type OrganizationReconciliationTrustPolicy
} from "./iam-organization-reconciliation-provenance.js";
import {
  validateOrganizationReconciliation,
  type OrganizationReconciliationInput
} from "./iam-organization-reconciliation-validator.js";

export const ORGANIZATION_RECONCILIATION_DEVELOP_ATTESTATION_REQUESTS_CONTRACT =
  "iam-organization-reconciliation-xrteeth-develop-attestation-requests/v2" as const;
export const ORGANIZATION_RECONCILIATION_DEVELOP_ATTESTATION_COLLECTOR_METADATA_CONTRACT =
  "iam-organization-reconciliation-xrteeth-develop-attestation-collector-metadata/v2" as const;

export interface OrganizationReconciliationDevelopAttestationCollectorMetadataEntry {
  readonly collectorId: string;
  readonly nodeId: string;
  readonly keyId: string;
  readonly publicKeySha256: string;
  readonly buildRevision: string;
}

/**
 * Separately supplied collector/profile pins. This is construction metadata,
 * not proof that the policy is trusted; the existing provenance verifier must
 * still receive the independently compiled trusted profile.
 */
export interface OrganizationReconciliationDevelopAttestationCollectorMetadata {
  readonly contract: typeof ORGANIZATION_RECONCILIATION_DEVELOP_ATTESTATION_COLLECTOR_METADATA_CONTRACT;
  readonly profileId: string;
  readonly environment: string;
  readonly trustPolicySha256: string;
  readonly deploymentEvidenceSha256: string;
  readonly collectors: readonly OrganizationReconciliationDevelopAttestationCollectorMetadataEntry[];
}

export interface OrganizationReconciliationDevelopAttestationClock {
  readonly now: () => Date;
}

export interface CreateOrganizationReconciliationDevelopAttestationRequestsOptions {
  readonly input: OrganizationReconciliationInput;
  readonly trustPolicy: OrganizationReconciliationTrustPolicy;
  readonly collectorMetadata: OrganizationReconciliationDevelopAttestationCollectorMetadata;
  readonly clock: OrganizationReconciliationDevelopAttestationClock;
  readonly attestationTtlSeconds: number;
}

export interface OrganizationReconciliationDevelopAttestationSigningRequest {
  readonly collectorId: string;
  readonly nodeId: string;
  readonly keyId: string;
  readonly publicKeySha256: string;
  readonly collectorBuildRevision: string;
  readonly payload: OrganizationReconciliationProvenancePayload;
  readonly payloadBytesEncoding: "base64url";
  /** Exact output of serializeOrganizationReconciliationProvenancePayload. */
  readonly payloadBytesBase64url: string;
  /** SHA-256 over those exact domain-separated bytes. */
  readonly payloadSha256: string;
}

export interface OrganizationReconciliationDevelopAttestationRequestSet {
  readonly contract: typeof ORGANIZATION_RECONCILIATION_DEVELOP_ATTESTATION_REQUESTS_CONTRACT;
  readonly algorithm: "Ed25519";
  readonly profileId: string;
  readonly environment: string;
  readonly trustPolicySha256: string;
  readonly deploymentEvidenceSha256: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly requests: readonly OrganizationReconciliationDevelopAttestationSigningRequest[];
}

export interface OrganizationReconciliationDevelopAttestationSignatureResponse {
  readonly collectorId: string;
  readonly keyId: string;
  readonly payloadSha256: string;
  readonly signature: Uint8Array;
}

export class OrganizationReconciliationDevelopAttestationRequestError extends Error {
  constructor(readonly failureId:
    | "invalid-input"
    | "invalid-trust-policy"
    | "invalid-collector-metadata"
    | "invalid-clock-window"
    | "invalid-request-set"
    | "invalid-signature-responses") {
    super(failureId);
    this.name = "OrganizationReconciliationDevelopAttestationRequestError";
  }
}

interface ExpectedSigningRequest {
  readonly collectorId: string;
  readonly keyId: string;
  readonly payloadSha256: string;
  readonly payload: OrganizationReconciliationProvenancePayload;
}

interface RequestSetBrand {
  readonly requestSet: OrganizationReconciliationDevelopAttestationRequestSet;
  readonly requests: OrganizationReconciliationDevelopAttestationRequestSet["requests"];
  readonly expected: readonly ExpectedSigningRequest[];
  phase: "open" | "assembling" | "consumed" | "poisoned";
}

interface CapturedCreationInput {
  readonly input: OrganizationReconciliationInput;
  readonly policy: OrganizationReconciliationTrustPolicy;
  readonly metadata: OrganizationReconciliationDevelopAttestationCollectorMetadata;
  readonly clockNow: () => unknown;
  readonly ttlSeconds: number;
}

interface CapturedSignatureResponse {
  readonly collectorId: string;
  readonly keyId: string;
  readonly payloadSha256: string;
  readonly signature: Buffer;
}

const COMPLETED_INPUT_KEYS = Object.freeze([
  "componentManifest",
  "projectionBinding",
  "collectionEnvelope",
  "organizationDirectory",
  "organizationMappings",
  "memberships",
  "organizationScopedRoles",
  "pluginBindings",
  "pluginVisibility",
  "campusContexts",
  "effectiveDecisions"
] as const);
const MAX_CANONICAL_NODES = 1_000_000;
const MAX_CANONICAL_DEPTH = 64;
const MAX_CANONICAL_STRING_BYTES = 65_536;
const MAX_CANONICAL_OBJECT_KEY_BYTES = 256;
const MAX_CANONICAL_BYTES = 64 * 1024 * 1024;
const requestSetBrands = new WeakMap<object, RequestSetBrand>();

/**
 * Creates deterministic requests for an external Ed25519 signer. This module
 * never accepts or accesses a private key and does not verify provenance.
 */
export function createOrganizationReconciliationDevelopAttestationRequests(
  candidate: CreateOrganizationReconciliationDevelopAttestationRequestsOptions
): OrganizationReconciliationDevelopAttestationRequestSet {
  const captured = captureCreationInput(candidate);
  const binding = createOrganizationReconciliationProvenanceBindingFromInput(
    captured.input,
    captured.metadata.deploymentEvidenceSha256
  );
  validateStaticPolicyBindings(
    captured,
    binding.collectorBuildRevision,
    binding.windowStartedAt,
    binding.windowEndedAt
  );
  const now = readTrustedClock(captured.clockNow);
  validateTrustedClockWindow(captured, now, binding.windowStartedAt, binding.windowEndedAt);

  const policySha256 = createOrganizationReconciliationTrustPolicySha256(captured.policy);
  const issuedAt = now.toISOString();
  const expiresAt = new Date(now.getTime() + captured.ttlSeconds * 1_000).toISOString();
  const metadataByKey = new Map(captured.metadata.collectors.map((collector) => [collector.keyId, collector]));
  const requests: OrganizationReconciliationDevelopAttestationSigningRequest[] = [];
  const expected: ExpectedSigningRequest[] = [];

  try {
    for (const collector of captured.policy.requiredCollectors) {
      const metadata = metadataByKey.get(collector.keyId)!;
      const payload = captureCanonicalJson(createOrganizationReconciliationProvenancePayload(
        binding,
        captured.policy,
        collector.keyId,
        issuedAt,
        expiresAt
      )) as unknown as OrganizationReconciliationProvenancePayload;
      const bytes = serializeOrganizationReconciliationProvenancePayload(payload);
      try {
        const payloadSha256 = createHash("sha256").update(bytes).digest("hex");
        const request = Object.freeze({
          collectorId: collector.collectorId,
          nodeId: collector.nodeId,
          keyId: collector.keyId,
          publicKeySha256: metadata.publicKeySha256,
          collectorBuildRevision: collector.buildRevision,
          payload,
          payloadBytesEncoding: "base64url" as const,
          payloadBytesBase64url: bytes.toString("base64url"),
          payloadSha256
        });
        requests.push(request);
        expected.push(Object.freeze({
          collectorId: request.collectorId,
          keyId: request.keyId,
          payloadSha256,
          payload
        }));
      } finally {
        bytes.fill(0);
      }
    }
  } catch (error) {
    if (error instanceof OrganizationReconciliationDevelopAttestationRequestError) throw error;
    throw new OrganizationReconciliationDevelopAttestationRequestError("invalid-trust-policy");
  }

  const frozenRequests = Object.freeze(requests);
  const requestSet = Object.freeze({
    contract: ORGANIZATION_RECONCILIATION_DEVELOP_ATTESTATION_REQUESTS_CONTRACT,
    algorithm: "Ed25519" as const,
    profileId: captured.metadata.profileId,
    environment: captured.metadata.environment,
    trustPolicySha256: policySha256,
    deploymentEvidenceSha256: binding.deploymentEvidenceSha256,
    issuedAt,
    expiresAt,
    requests: frozenRequests
  });
  requestSetBrands.set(requestSet, {
    requestSet,
    requests: frozenRequests,
    expected: Object.freeze(expected),
    phase: "open"
  });
  return requestSet;
}

/** Verifies the private WeakMap request-set brand without consuming it. */
export function assertOrganizationReconciliationDevelopAttestationRequestSet(
  candidate: unknown
): asserts candidate is OrganizationReconciliationDevelopAttestationRequestSet {
  requireOpenRequestSet(candidate);
}

/**
 * Binds one exact response to every branded request and constructs a bundle.
 * Signature authenticity is deliberately left to verifyOrganizationReconciliationProvenance.
 */
export function assembleOrganizationReconciliationDevelopAttestationBundle(
  requestSet: OrganizationReconciliationDevelopAttestationRequestSet,
  candidateResponses: readonly OrganizationReconciliationDevelopAttestationSignatureResponse[]
): OrganizationReconciliationAttestationBundle {
  const brand = requireOpenRequestSet(requestSet);
  brand.phase = "assembling";
  const responses: CapturedSignatureResponse[] = [];
  try {
    responses.push(...captureSignatureResponses(candidateResponses, brand.expected.length));
    const responsesByKey = new Map<string, CapturedSignatureResponse>();
    const collectorIds = new Set<string>();
    for (const response of responses) {
      if (responsesByKey.has(response.keyId) || collectorIds.has(response.collectorId)) {
        invalid("invalid-signature-responses");
      }
      responsesByKey.set(response.keyId, response);
      collectorIds.add(response.collectorId);
    }

    const attestations: OrganizationReconciliationSignedAttestation[] = [];
    for (const expected of brand.expected) {
      const response = responsesByKey.get(expected.keyId);
      if (!response || response.collectorId !== expected.collectorId ||
        !safeSha256Equal(response.payloadSha256, expected.payloadSha256)) {
        invalid("invalid-signature-responses");
      }
      attestations.push(createOrganizationReconciliationSignedAttestation(
        expected.payload,
        response.signature
      ));
    }
    if (responsesByKey.size !== brand.expected.length) invalid("invalid-signature-responses");

    const parsed = parseOrganizationReconciliationAttestationBundle({
      contract: ORGANIZATION_RECONCILIATION_PROVENANCE_CONTRACT,
      attestations
    });
    const bundle = captureCanonicalJson(parsed) as unknown as OrganizationReconciliationAttestationBundle;
    brand.phase = "consumed";
    return bundle;
  } catch (error) {
    brand.phase = "poisoned";
    if (error instanceof OrganizationReconciliationDevelopAttestationRequestError) throw error;
    throw new OrganizationReconciliationDevelopAttestationRequestError("invalid-signature-responses");
  } finally {
    for (const response of responses) response.signature.fill(0);
  }
}

function captureCreationInput(candidate: unknown): CapturedCreationInput {
  try {
    const options = exactObject(candidate, [
      "input", "trustPolicy", "collectorMetadata", "clock", "attestationTtlSeconds"
    ], "invalid-input");
    const input = captureCompletedInput(options.input);
    const policy = captureTrustPolicy(options.trustPolicy);
    const metadata = captureCollectorMetadata(options.collectorMetadata);
    const clock = exactObject(options.clock, ["now"], "invalid-input");
    if (typeof clock.now !== "function" || !Number.isSafeInteger(options.attestationTtlSeconds) ||
      (options.attestationTtlSeconds as number) < 1 || (options.attestationTtlSeconds as number) > 3_600) {
      invalid("invalid-input");
    }
    return Object.freeze({
      input,
      policy,
      metadata,
      clockNow: clock.now as () => unknown,
      ttlSeconds: options.attestationTtlSeconds as number
    });
  } catch (error) {
    if (error instanceof OrganizationReconciliationDevelopAttestationRequestError) throw error;
    throw new OrganizationReconciliationDevelopAttestationRequestError("invalid-input");
  }
}

function captureCompletedInput(candidate: unknown): OrganizationReconciliationInput {
  const canonical = captureCanonicalJson(candidate);
  exactCanonicalObject(canonical, COMPLETED_INPUT_KEYS, "invalid-input");
  const input = canonicalizeOrganizationReconciliationEvidenceValue(canonical) as unknown as
    OrganizationReconciliationInput;
  const report = validateOrganizationReconciliation(input);
  const unexpectedBlockers = report.coverageBlockers.filter((blocker) =>
    blocker.code !== "real-source-adapters-not-ready"
  );
  if (unexpectedBlockers.length !== 0 || report.coverage.length !== 8 ||
    report.coverage.some((surface) => !surface.paginationComplete)) {
    invalid("invalid-input");
  }
  return input;
}

function captureTrustPolicy(candidate: unknown): OrganizationReconciliationTrustPolicy {
  try {
    const canonical = captureCanonicalJson(candidate);
    const parsed = parseOrganizationReconciliationTrustPolicy(canonical);
    return captureCanonicalJson(parsed) as unknown as OrganizationReconciliationTrustPolicy;
  } catch {
    invalid("invalid-trust-policy");
  }
}

function captureCollectorMetadata(
  candidate: unknown
): OrganizationReconciliationDevelopAttestationCollectorMetadata {
  const canonical = captureCanonicalJson(candidate);
  const metadata = exactCanonicalObject(canonical, [
    "contract", "profileId", "environment", "trustPolicySha256", "deploymentEvidenceSha256", "collectors"
  ], "invalid-collector-metadata");
  if (metadata.contract !== ORGANIZATION_RECONCILIATION_DEVELOP_ATTESTATION_COLLECTOR_METADATA_CONTRACT ||
    !isIdentifier(metadata.profileId) || !isIdentifier(metadata.environment) ||
    !isSha256(metadata.trustPolicySha256) || !isSha256(metadata.deploymentEvidenceSha256) ||
    !Array.isArray(metadata.collectors) ||
    metadata.collectors.length !== 1) {
    invalid("invalid-collector-metadata");
  }
  const collectors = metadata.collectors.map((candidateCollector) => {
    const collector = exactCanonicalObject(candidateCollector, [
      "collectorId", "nodeId", "keyId", "publicKeySha256", "buildRevision"
    ], "invalid-collector-metadata");
    if (!isIdentifier(collector.collectorId) || !isIdentifier(collector.nodeId) ||
      !isIdentifier(collector.keyId) || !isSha256(collector.publicKeySha256) ||
      !isFullBuildRevision(collector.buildRevision)) {
      invalid("invalid-collector-metadata");
    }
    return Object.freeze({
      collectorId: collector.collectorId as string,
      nodeId: collector.nodeId as string,
      keyId: collector.keyId as string,
      publicKeySha256: collector.publicKeySha256 as string,
      buildRevision: collector.buildRevision as string
    });
  });
  if (!uniqueCollectorFields(collectors)) invalid("invalid-collector-metadata");
  return Object.freeze({
    contract: ORGANIZATION_RECONCILIATION_DEVELOP_ATTESTATION_COLLECTOR_METADATA_CONTRACT,
    profileId: metadata.profileId as string,
    environment: metadata.environment as string,
    trustPolicySha256: metadata.trustPolicySha256 as string,
    deploymentEvidenceSha256: metadata.deploymentEvidenceSha256 as string,
    collectors: Object.freeze(collectors)
  });
}

function validateStaticPolicyBindings(
  captured: CapturedCreationInput,
  collectorBuildRevision: string,
  windowStartedAt: string,
  windowEndedAt: string
): void {
  const { policy, metadata, ttlSeconds } = captured;
  const policySha256 = createOrganizationReconciliationTrustPolicySha256(policy);
  if (!safeSha256Equal(policySha256, metadata.trustPolicySha256) ||
    policy.profileId !== metadata.profileId || policy.environment !== metadata.environment ||
    policy.requiredCollectors.length !== metadata.collectors.length ||
    !isFullBuildRevision(collectorBuildRevision) || ttlSeconds > policy.maxAttestationTtlSeconds) {
    invalid("invalid-collector-metadata");
  }
  if (!uniqueCollectorFields(policy.requiredCollectors)) invalid("invalid-trust-policy");

  const metadataByKey = new Map(metadata.collectors.map((collector) => [collector.keyId, collector]));
  const policyStart = Date.parse(policy.validFrom);
  const policyEnd = Date.parse(policy.validUntil);
  const windowStart = Date.parse(windowStartedAt);
  const windowEnd = Date.parse(windowEndedAt);
  if (!Number.isFinite(policyStart) || !Number.isFinite(policyEnd) || policyStart >= policyEnd ||
    !Number.isFinite(windowStart) || !Number.isFinite(windowEnd) || windowStart > windowEnd ||
    windowStart < policyStart || windowEnd > policyEnd ||
    windowEnd - windowStart > policy.maxCollectionWindowSeconds * 1_000) {
    invalid("invalid-clock-window");
  }

  for (const collector of policy.requiredCollectors) {
    const metadataCollector = metadataByKey.get(collector.keyId);
    if (!metadataCollector || collector.collectorId !== metadataCollector.collectorId ||
      collector.nodeId !== metadataCollector.nodeId ||
      !safeSha256Equal(collector.publicKeySha256, metadataCollector.publicKeySha256) ||
      collector.buildRevision !== metadataCollector.buildRevision ||
      collector.buildRevision !== collectorBuildRevision ||
      !isCanonicalEd25519CollectorKey(collector.publicKeyPem, collector.publicKeySha256)) {
      invalid("invalid-collector-metadata");
    }
    const validFrom = Date.parse(collector.validFrom);
    const validUntil = Date.parse(collector.validUntil);
    if (!Number.isFinite(validFrom) || !Number.isFinite(validUntil) || validFrom >= validUntil ||
      validFrom < policyStart || validUntil > policyEnd || windowStart < validFrom ||
      windowEnd > validUntil) {
      invalid("invalid-clock-window");
    }
  }
}

function readTrustedClock(now: () => unknown): Date {
  let value: unknown;
  try {
    value = now.call(undefined);
  } catch {
    invalid("invalid-clock-window");
  }
  if (!value || typeof value !== "object" || isProxy(value) ||
    Object.getPrototypeOf(value) !== Date.prototype ||
    Object.getOwnPropertyNames(value).length !== 0 || Object.getOwnPropertySymbols(value).length !== 0) {
    invalid("invalid-clock-window");
  }
  const timestamp = Date.prototype.getTime.call(value);
  if (!Number.isFinite(timestamp)) invalid("invalid-clock-window");
  return new Date(timestamp);
}

function validateTrustedClockWindow(
  captured: CapturedCreationInput,
  now: Date,
  windowStartedAt: string,
  windowEndedAt: string
): void {
  const { policy, ttlSeconds } = captured;
  const policyStart = Date.parse(policy.validFrom);
  const policyEnd = Date.parse(policy.validUntil);
  const windowStart = Date.parse(windowStartedAt);
  const windowEnd = Date.parse(windowEndedAt);
  const issuedAt = now.getTime();
  const expiresAt = issuedAt + ttlSeconds * 1_000;
  if (issuedAt < windowEnd || issuedAt < policyStart || expiresAt > policyEnd ||
    issuedAt - windowEnd > policy.maxEvidenceAgeSeconds * 1_000) {
    invalid("invalid-clock-window");
  }
  for (const collector of policy.requiredCollectors) {
    if (issuedAt < Date.parse(collector.validFrom) || expiresAt > Date.parse(collector.validUntil) ||
      windowStart < Date.parse(collector.validFrom)) {
      invalid("invalid-clock-window");
    }
  }
}

function requireOpenRequestSet(candidate: unknown): RequestSetBrand {
  if (!candidate || typeof candidate !== "object" || isProxy(candidate)) {
    invalid("invalid-request-set");
  }
  const brand = requestSetBrands.get(candidate);
  if (!brand || brand.requestSet !== candidate ||
    (candidate as OrganizationReconciliationDevelopAttestationRequestSet).requests !== brand.requests ||
    brand.phase !== "open") {
    invalid("invalid-request-set");
  }
  return brand;
}

function captureSignatureResponses(candidate: unknown, expectedCount: number): CapturedSignatureResponse[] {
  const values = exactArray(candidate, expectedCount, "invalid-signature-responses");
  return values.map((value) => {
    const response = exactObject(value, [
      "collectorId", "keyId", "payloadSha256", "signature"
    ], "invalid-signature-responses");
    if (!isIdentifier(response.collectorId) || !isIdentifier(response.keyId) ||
      !isSha256(response.payloadSha256)) {
      invalid("invalid-signature-responses");
    }
    return Object.freeze({
      collectorId: response.collectorId as string,
      keyId: response.keyId as string,
      payloadSha256: response.payloadSha256 as string,
      signature: captureSignature(response.signature)
    });
  });
}

function captureSignature(candidate: unknown): Buffer {
  if (!candidate || typeof candidate !== "object" || isProxy(candidate) ||
    !(candidate instanceof Uint8Array)) {
    invalid("invalid-signature-responses");
  }
  const prototype = Object.getPrototypeOf(candidate);
  if ((prototype !== Uint8Array.prototype && prototype !== Buffer.prototype) ||
    Object.getOwnPropertySymbols(candidate).length !== 0) {
    invalid("invalid-signature-responses");
  }
  const descriptors = Object.getOwnPropertyDescriptors(candidate);
  const keys = Object.keys(descriptors);
  if (keys.length !== 64 || keys.some((key, index) => key !== String(index))) {
    invalid("invalid-signature-responses");
  }
  const copy = Buffer.alloc(64);
  for (let index = 0; index < 64; index += 1) {
    const descriptor = descriptors[String(index)];
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable ||
      !Number.isInteger(descriptor.value) || descriptor.value < 0 || descriptor.value > 255) {
      copy.fill(0);
      invalid("invalid-signature-responses");
    }
    copy[index] = descriptor.value as number;
  }
  return copy;
}

function captureCanonicalJson(candidate: unknown): OrganizationReconciliationEvidenceJsonValue {
  return captureJson(candidate, new Set<object>(), { nodes: 0, bytes: 0 }, 0);
}

function captureJson(
  candidate: unknown,
  active: Set<object>,
  state: { nodes: number; bytes: number },
  depth: number
): OrganizationReconciliationEvidenceJsonValue {
  state.nodes += 1;
  if (state.nodes > MAX_CANONICAL_NODES || depth > MAX_CANONICAL_DEPTH) invalid("invalid-input");
  if (candidate === null) {
    addCanonicalBytes(state, 4);
    return candidate;
  }
  if (typeof candidate === "string") {
    if (Buffer.byteLength(candidate, "utf8") > MAX_CANONICAL_STRING_BYTES) invalid("invalid-input");
    addCanonicalBytes(state, Buffer.byteLength(JSON.stringify(candidate), "utf8"));
    return candidate;
  }
  if (typeof candidate === "boolean") {
    addCanonicalBytes(state, candidate ? 4 : 5);
    return candidate;
  }
  if (typeof candidate === "number") {
    if (!Number.isFinite(candidate)) invalid("invalid-input");
    addCanonicalBytes(state, Buffer.byteLength(JSON.stringify(candidate), "utf8"));
    return Object.is(candidate, -0) ? 0 : candidate;
  }
  if (typeof candidate !== "object" || isProxy(candidate) || active.has(candidate)) invalid("invalid-input");
  active.add(candidate);
  try {
    if (Array.isArray(candidate)) {
      if (Object.getPrototypeOf(candidate) !== Array.prototype || Object.getOwnPropertySymbols(candidate).length !== 0) {
        invalid("invalid-input");
      }
      const descriptors = Object.getOwnPropertyDescriptors(candidate);
      const lengthDescriptor = descriptors["length"] as PropertyDescriptor | undefined;
      if (!lengthDescriptor || !("value" in lengthDescriptor) || lengthDescriptor.enumerable ||
        !Number.isSafeInteger(lengthDescriptor.value) || lengthDescriptor.value < 0 ||
        lengthDescriptor.value > MAX_CANONICAL_NODES ||
        Object.keys(descriptors).length !== (lengthDescriptor.value as number) + 1) {
        invalid("invalid-input");
      }
      addCanonicalBytes(state, 2 + Math.max(0, (lengthDescriptor.value as number) - 1));
      const output: OrganizationReconciliationEvidenceJsonValue[] = [];
      for (let index = 0; index < lengthDescriptor.value; index += 1) {
        const descriptor = descriptors[String(index)];
        if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) invalid("invalid-input");
        output.push(captureJson(descriptor.value, active, state, depth + 1));
      }
      return Object.freeze(output);
    }
    const prototype = Object.getPrototypeOf(candidate);
    if ((prototype !== Object.prototype && prototype !== null) ||
      Object.getOwnPropertySymbols(candidate).length !== 0) {
      invalid("invalid-input");
    }
    const descriptors = Object.getOwnPropertyDescriptors(candidate);
    const keys = Object.keys(descriptors).sort();
    addCanonicalBytes(state, 2 + Math.max(0, keys.length - 1));
    for (const key of keys) {
      if (Buffer.byteLength(key, "utf8") > MAX_CANONICAL_OBJECT_KEY_BYTES) invalid("invalid-input");
      addCanonicalBytes(state, Buffer.byteLength(JSON.stringify(key), "utf8") + 1);
    }
    const output: Record<string, OrganizationReconciliationEvidenceJsonValue> = Object.create(null);
    for (const key of keys) {
      const descriptor = descriptors[key]!;
      if (!("value" in descriptor) || !descriptor.enumerable) invalid("invalid-input");
      output[key] = captureJson(descriptor.value, active, state, depth + 1);
    }
    return Object.freeze(output);
  } finally {
    active.delete(candidate);
  }
}

function addCanonicalBytes(state: { bytes: number }, bytes: number): void {
  if (!Number.isSafeInteger(bytes) || bytes < 0 || state.bytes > MAX_CANONICAL_BYTES - bytes) {
    invalid("invalid-input");
  }
  state.bytes += bytes;
}

function exactObject(
  candidate: unknown,
  expectedKeys: readonly string[],
  failureId: OrganizationReconciliationDevelopAttestationRequestError["failureId"]
): Readonly<Record<string, unknown>> {
  if (!candidate || typeof candidate !== "object" || Array.isArray(candidate) || isProxy(candidate) ||
    (Object.getPrototypeOf(candidate) !== Object.prototype && Object.getPrototypeOf(candidate) !== null) ||
    Object.getOwnPropertySymbols(candidate).length !== 0) {
    invalid(failureId);
  }
  const descriptors = Object.getOwnPropertyDescriptors(candidate);
  if (Object.keys(descriptors).sort().join("\u001f") !== [...expectedKeys].sort().join("\u001f")) {
    invalid(failureId);
  }
  const output: Record<string, unknown> = Object.create(null);
  for (const key of expectedKeys) {
    const descriptor = descriptors[key];
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) invalid(failureId);
    output[key] = descriptor.value;
  }
  return Object.freeze(output);
}

function exactCanonicalObject(
  candidate: unknown,
  expectedKeys: readonly string[],
  failureId: OrganizationReconciliationDevelopAttestationRequestError["failureId"]
): Readonly<Record<string, OrganizationReconciliationEvidenceJsonValue>> {
  if (!candidate || typeof candidate !== "object" || Array.isArray(candidate) ||
    Object.keys(candidate).sort().join("\u001f") !== [...expectedKeys].sort().join("\u001f")) {
    invalid(failureId);
  }
  return candidate as Readonly<Record<string, OrganizationReconciliationEvidenceJsonValue>>;
}

function exactArray(
  candidate: unknown,
  expectedLength: number,
  failureId: OrganizationReconciliationDevelopAttestationRequestError["failureId"]
): readonly unknown[] {
  if (!Array.isArray(candidate) || isProxy(candidate) || Object.getPrototypeOf(candidate) !== Array.prototype ||
    Object.getOwnPropertySymbols(candidate).length !== 0) {
    invalid(failureId);
  }
  const descriptors = Object.getOwnPropertyDescriptors(candidate);
  const lengthDescriptor = descriptors["length"] as PropertyDescriptor | undefined;
  if (!lengthDescriptor || !("value" in lengthDescriptor) || lengthDescriptor.enumerable ||
    lengthDescriptor.value !== expectedLength ||
    Object.keys(descriptors).length !== expectedLength + 1) {
    invalid(failureId);
  }
  const output: unknown[] = [];
  for (let index = 0; index < expectedLength; index += 1) {
    const descriptor = descriptors[String(index)];
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) invalid(failureId);
    output.push(descriptor.value);
  }
  return Object.freeze(output);
}

function uniqueCollectorFields(collectors: readonly {
  readonly collectorId: string;
  readonly nodeId: string;
  readonly keyId: string;
  readonly publicKeySha256: string;
}[]): boolean {
  return new Set(collectors.map((collector) => collector.collectorId)).size === collectors.length &&
    new Set(collectors.map((collector) => collector.nodeId)).size === collectors.length &&
    new Set(collectors.map((collector) => collector.keyId)).size === collectors.length &&
    new Set(collectors.map((collector) => collector.publicKeySha256)).size === collectors.length;
}

function isCanonicalEd25519CollectorKey(publicKeyPem: string, expectedSha256: string): boolean {
  try {
    if (!publicKeyPem.startsWith("-----BEGIN PUBLIC KEY-----\n")) return false;
    const key = createPublicKey(publicKeyPem);
    if (key.asymmetricKeyType !== "ed25519" ||
      key.export({ format: "pem", type: "spki" }).toString() !== publicKeyPem) return false;
    const fingerprint = createHash("sha256")
      .update(key.export({ format: "der", type: "spki" }))
      .digest("hex");
    return safeSha256Equal(fingerprint, expectedSha256);
  } catch {
    return false;
  }
}

function isIdentifier(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value);
}

function isSha256(value: unknown): value is string {
  return typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
}

function isFullBuildRevision(value: unknown): value is string {
  return typeof value === "string" && /^[a-f0-9]{40}$/.test(value);
}

function safeSha256Equal(left: string, right: string): boolean {
  return isSha256(left) && isSha256(right) &&
    timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

function invalid(failureId: OrganizationReconciliationDevelopAttestationRequestError["failureId"]): never {
  throw new OrganizationReconciliationDevelopAttestationRequestError(failureId);
}
