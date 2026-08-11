import {
  createHash,
  createPublicKey,
  timingSafeEqual,
  verify as verifySignature,
  type KeyObject
} from "node:crypto";
import { z } from "zod";
import type { OrganizationReconciliationInput } from "./iam-organization-reconciliation-validator.js";

export const ORGANIZATION_RECONCILIATION_PROVENANCE_CONTRACT =
  "iam-organization-reconciliation-provenance/v4";
export const ORGANIZATION_RECONCILIATION_TRUST_POLICY_CONTRACT =
  "iam-organization-reconciliation-trust-policy/v3";
export const ORGANIZATION_RECONCILIATION_PROVENANCE_AUDIENCE =
  "identity-service/iam-organization-reconciliation";
export const ORGANIZATION_RECONCILIATION_PROVENANCE_ALGORITHM = "Ed25519";
/** Immutable prefix for the exact bytes accepted by external hash-only signers. */
export const ORGANIZATION_RECONCILIATION_PROVENANCE_SIGNATURE_DOMAIN =
  "iam-organization-reconciliation:provenance:v4\u001f";

const identifier = z.string().min(1).max(128).regex(/^[A-Za-z0-9][A-Za-z0-9._:-]*$/);
const sha256 = z.string().regex(/^[a-f0-9]{64}$/);
const fullBuildRevision = z.string().regex(/^[a-f0-9]{40}$/);
const canonicalTimestamp = z.string().refine((value) => {
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) && new Date(timestamp).toISOString() === value;
});
const publicKeyPem = z.string().min(1).max(8192);

const provenanceBindingSchema = z.object({
  evidenceSha256: sha256,
  deploymentEvidenceSha256: sha256,
  collectorContractHash: sha256,
  collectorBuildRevision: fullBuildRevision,
  logicalSnapshotIdHash: sha256,
  windowIdHash: sha256,
  windowStartedAt: canonicalTimestamp,
  windowEndedAt: canonicalTimestamp
}).strict();

const trustedCollectorSchema = z.object({
  collectorId: identifier,
  nodeId: identifier,
  keyId: identifier,
  algorithm: z.literal(ORGANIZATION_RECONCILIATION_PROVENANCE_ALGORITHM),
  publicKeyPem,
  publicKeySha256: sha256,
  buildRevision: fullBuildRevision,
  validFrom: canonicalTimestamp,
  validUntil: canonicalTimestamp
}).strict();

const trustPolicySchema = z.object({
  contract: z.literal(ORGANIZATION_RECONCILIATION_TRUST_POLICY_CONTRACT),
  profileId: identifier,
  audience: z.literal(ORGANIZATION_RECONCILIATION_PROVENANCE_AUDIENCE),
  environment: identifier,
  validFrom: canonicalTimestamp,
  validUntil: canonicalTimestamp,
  maxEvidenceAgeSeconds: z.number().int().min(1).max(86_400),
  maxAttestationTtlSeconds: z.number().int().min(1).max(3_600),
  maxCollectionWindowSeconds: z.number().int().min(1).max(3_600),
  clockSkewSeconds: z.number().int().min(0).max(300),
  requiredCollectors: z.array(trustedCollectorSchema).min(1).max(8)
}).strict().superRefine((policy, context) => {
  if ((policy.environment === "xrteeth-develop" && policy.requiredCollectors.length !== 1) ||
    (policy.environment !== "xrteeth-develop" && policy.requiredCollectors.length < 2)) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ["requiredCollectors"] });
  }
});

const provenancePayloadSchema = provenanceBindingSchema.extend({
  contract: z.literal(ORGANIZATION_RECONCILIATION_PROVENANCE_CONTRACT),
  profileId: identifier,
  audience: z.literal(ORGANIZATION_RECONCILIATION_PROVENANCE_AUDIENCE),
  environment: identifier,
  collectorId: identifier,
  nodeId: identifier,
  keyId: identifier,
  algorithm: z.literal(ORGANIZATION_RECONCILIATION_PROVENANCE_ALGORITHM),
  trustPolicySha256: sha256,
  issuedAt: canonicalTimestamp,
  expiresAt: canonicalTimestamp
}).strict();

const signedAttestationSchema = z.object({
  payload: provenancePayloadSchema,
  signature: z.string().min(1).max(256).regex(/^[A-Za-z0-9_-]+$/)
}).strict();

const attestationBundleSchema = z.object({
  contract: z.literal(ORGANIZATION_RECONCILIATION_PROVENANCE_CONTRACT),
  attestations: z.array(signedAttestationSchema).min(1).max(8)
}).strict();

const trustedProfileCollectorSchema = z.object({
  collectorId: identifier,
  nodeId: identifier,
  keyId: identifier,
  publicKeySha256: sha256,
  buildRevision: fullBuildRevision
}).strict();

const trustedProfileSchema = z.object({
  profileId: identifier,
  policySha256: sha256,
  expectedEnvironment: identifier,
  requiredCollectors: z.array(trustedProfileCollectorSchema).min(1).max(8)
}).strict().superRefine((profile, context) => {
  if ((profile.expectedEnvironment === "xrteeth-develop" && profile.requiredCollectors.length !== 1) ||
    (profile.expectedEnvironment !== "xrteeth-develop" && profile.requiredCollectors.length < 2)) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ["requiredCollectors"] });
  }
});

export type OrganizationReconciliationProvenanceBinding = z.infer<typeof provenanceBindingSchema>;
export type OrganizationReconciliationTrustedCollector = z.infer<typeof trustedCollectorSchema>;
export type OrganizationReconciliationTrustPolicy = z.infer<typeof trustPolicySchema>;
export type OrganizationReconciliationProvenancePayload = z.infer<typeof provenancePayloadSchema>;
export type OrganizationReconciliationSignedAttestation = z.infer<typeof signedAttestationSchema>;
export type OrganizationReconciliationAttestationBundle = z.infer<typeof attestationBundleSchema>;
export type OrganizationReconciliationTrustedProfile = z.infer<typeof trustedProfileSchema>;

export interface OrganizationReconciliationTrustedProvenanceContext {
  /** Immutable, compiled profile supplied outside evidence, policy, argv, and environment. */
  readonly trustedProfile: OrganizationReconciliationTrustedProfile;
  readonly trustPolicy: OrganizationReconciliationTrustPolicy;
  readonly attestationBundle: OrganizationReconciliationAttestationBundle;
  /** Independently parsed deployment-evidence digest; it is not supplied by the policy or payload. */
  readonly expectedDeploymentEvidenceSha256: string;
  /** Trusted verifier time. It must not be read from caller-controlled evidence. */
  readonly now: Date;
}

export type OrganizationReconciliationProvenanceFailureCode =
  | "trusted-context-missing"
  | "trusted-context-invalid"
  | "trust-policy-pin-mismatch"
  | "trust-profile-mismatch"
  | "trust-policy-window-invalid"
  | "collector-policy-invalid"
  | "evidence-binding-invalid"
  | "evidence-window-invalid"
  | "attestation-set-invalid"
  | "attestation-binding-mismatch"
  | "attestation-window-invalid"
  | "collector-key-invalid"
  | "signature-invalid";

export interface OrganizationReconciliationProvenanceVerification {
  readonly verified: boolean;
  readonly code: "verified" | OrganizationReconciliationProvenanceFailureCode;
  readonly requiredAttestationCount: number;
  readonly verifiedAttestationCount: number;
  /** Safe to hash into a report; never includes a key, signature, collector, node, or environment. */
  readonly trustPolicySha256?: string;
  /** Internal verified metadata; callers must hash it before report output. */
  readonly trustProfileId?: string;
  readonly environment?: string;
}

const SIGNATURE_DOMAIN = Buffer.from(ORGANIZATION_RECONCILIATION_PROVENANCE_SIGNATURE_DOMAIN, "utf8");

/**
 * Verifies a complete evidence digest against a separately pinned trust policy.
 * No boolean or public key carried by the evidence can promote the result.
 */
export function verifyOrganizationReconciliationProvenance(
  binding: OrganizationReconciliationProvenanceBinding | undefined,
  context: OrganizationReconciliationTrustedProvenanceContext | undefined
): OrganizationReconciliationProvenanceVerification {
  if (!context) return failed("trusted-context-missing");
  const policyResult = trustPolicySchema.safeParse(context.trustPolicy);
  const bundleResult = attestationBundleSchema.safeParse(context.attestationBundle);
  const trustedProfileResult = trustedProfileSchema.safeParse(context.trustedProfile);
  if (
    !policyResult.success ||
    !bundleResult.success ||
    !trustedProfileResult.success ||
    !sha256.safeParse(context.expectedDeploymentEvidenceSha256).success ||
    !(context.now instanceof Date) ||
    !Number.isFinite(context.now.getTime())
  ) {
    return failed("trusted-context-invalid");
  }
  const bindingResult = provenanceBindingSchema.safeParse(binding);
  if (!bindingResult.success) return failed("evidence-binding-invalid", policyResult.data.requiredCollectors.length);

  const policy = policyResult.data;
  const bundle = bundleResult.data;
  const trustedProfile = trustedProfileResult.data;
  const requiredCount = policy.requiredCollectors.length;
  const policySha256 = createOrganizationReconciliationTrustPolicySha256(policy);
  if (!safeHexEqual(policySha256, trustedProfile.policySha256)) {
    return failed("trust-policy-pin-mismatch", requiredCount);
  }
  const now = context.now.getTime();
  const skewMs = policy.clockSkewSeconds * 1_000;
  const policyStart = Date.parse(policy.validFrom);
  const policyEnd = Date.parse(policy.validUntil);
  if (policyStart >= policyEnd || now + skewMs < policyStart || now - skewMs > policyEnd) {
    return failed("trust-policy-window-invalid", requiredCount, policySha256);
  }
  if (!collectorsAreUniqueAndValid(policy.requiredCollectors, policyStart, policyEnd)) {
    return failed("collector-policy-invalid", requiredCount, policySha256);
  }
  if (!trustedProfileMatchesPolicy(trustedProfile, policy)) {
    return failed("trust-profile-mismatch", requiredCount, policySha256);
  }

  const evidence = bindingResult.data;
  if (
    !safeHexEqual(evidence.deploymentEvidenceSha256, context.expectedDeploymentEvidenceSha256)
  ) {
    return failed("evidence-binding-invalid", requiredCount, policySha256);
  }
  const windowStart = Date.parse(evidence.windowStartedAt);
  const windowEnd = Date.parse(evidence.windowEndedAt);
  if (
    windowStart > windowEnd ||
    windowStart < policyStart ||
    windowEnd > policyEnd ||
    windowEnd - windowStart > policy.maxCollectionWindowSeconds * 1_000 ||
    windowEnd > now + skewMs ||
    now - windowEnd > policy.maxEvidenceAgeSeconds * 1_000 + skewMs
  ) {
    return failed("evidence-window-invalid", requiredCount, policySha256);
  }

  const attestationsByKey = new Map<string, OrganizationReconciliationSignedAttestation>();
  for (const attestation of bundle.attestations) {
    if (attestationsByKey.has(attestation.payload.keyId)) {
      return failed("attestation-set-invalid", requiredCount, policySha256);
    }
    attestationsByKey.set(attestation.payload.keyId, attestation);
  }
  if (bundle.attestations.length !== requiredCount) {
    return failed("attestation-set-invalid", requiredCount, policySha256);
  }

  let verifiedCount = 0;
  for (const collector of policy.requiredCollectors) {
    const attestation = attestationsByKey.get(collector.keyId);
    if (!attestation) return failed("attestation-set-invalid", requiredCount, policySha256, verifiedCount);
    const payload = attestation.payload;
    if (
      payload.audience !== policy.audience ||
      payload.profileId !== policy.profileId ||
      payload.environment !== policy.environment ||
      payload.collectorId !== collector.collectorId ||
      payload.nodeId !== collector.nodeId ||
      payload.keyId !== collector.keyId ||
      payload.algorithm !== collector.algorithm ||
      payload.collectorBuildRevision !== collector.buildRevision ||
      !safeHexEqual(payload.trustPolicySha256, policySha256) ||
      !payloadMatchesBinding(payload, evidence)
    ) {
      return failed("attestation-binding-mismatch", requiredCount, policySha256, verifiedCount);
    }

    const issuedAt = Date.parse(payload.issuedAt);
    const expiresAt = Date.parse(payload.expiresAt);
    const collectorStart = Date.parse(collector.validFrom);
    const collectorEnd = Date.parse(collector.validUntil);
    if (
      windowStart < collectorStart ||
      windowEnd > collectorEnd ||
      issuedAt < windowEnd ||
      issuedAt > now + skewMs ||
      expiresAt < now - skewMs ||
      expiresAt <= issuedAt ||
      expiresAt - issuedAt > policy.maxAttestationTtlSeconds * 1_000 ||
      issuedAt < policyStart ||
      expiresAt > policyEnd ||
      issuedAt < collectorStart ||
      expiresAt > collectorEnd
    ) {
      return failed("attestation-window-invalid", requiredCount, policySha256, verifiedCount);
    }

    const key = parseTrustedEd25519Key(collector);
    if (!key) return failed("collector-key-invalid", requiredCount, policySha256, verifiedCount);
    const signature = decodeEd25519Signature(attestation.signature);
    if (!signature || !verifySignature(null, serializeOrganizationReconciliationProvenancePayload(payload), key, signature)) {
      return failed("signature-invalid", requiredCount, policySha256, verifiedCount);
    }
    verifiedCount += 1;
  }

  return {
    verified: true,
    code: "verified",
    requiredAttestationCount: requiredCount,
    verifiedAttestationCount: verifiedCount,
    trustPolicySha256: policySha256,
    trustProfileId: trustedProfile.profileId,
    environment: trustedProfile.expectedEnvironment
  };
}

/** Builds the exact payload a trusted collector must sign. Private-key access stays outside this module. */
export function createOrganizationReconciliationProvenancePayload(
  binding: OrganizationReconciliationProvenanceBinding,
  policy: OrganizationReconciliationTrustPolicy,
  collectorKeyId: string,
  issuedAt: string,
  expiresAt: string
): OrganizationReconciliationProvenancePayload {
  const parsedBinding = provenanceBindingSchema.parse(binding);
  const parsedPolicy = trustPolicySchema.parse(policy);
  const collector = parsedPolicy.requiredCollectors.find((candidate) => candidate.keyId === collectorKeyId);
  if (!collector) throw new Error("Collector key is not present in the trusted policy.");
  if (collector.buildRevision !== parsedBinding.collectorBuildRevision) {
    throw new Error("Collector build revision is not pinned by the trusted policy.");
  }
  const trustPolicySha256 = createOrganizationReconciliationTrustPolicySha256(parsedPolicy);
  return provenancePayloadSchema.parse({
    ...parsedBinding,
    contract: ORGANIZATION_RECONCILIATION_PROVENANCE_CONTRACT,
    profileId: parsedPolicy.profileId,
    audience: parsedPolicy.audience,
    environment: parsedPolicy.environment,
    collectorId: collector.collectorId,
    nodeId: collector.nodeId,
    keyId: collector.keyId,
    algorithm: collector.algorithm,
    trustPolicySha256,
    issuedAt,
    expiresAt
  });
}

/** Domain-separated canonical bytes suitable for an HSM, KMS, or local Ed25519 signer. */
export function serializeOrganizationReconciliationProvenancePayload(
  payload: OrganizationReconciliationProvenancePayload
): Buffer {
  const parsed = provenancePayloadSchema.parse(payload);
  return Buffer.concat([SIGNATURE_DOMAIN, Buffer.from(canonicalJson(parsed), "utf8")]);
}

export function createOrganizationReconciliationSignedAttestation(
  payload: OrganizationReconciliationProvenancePayload,
  signature: Uint8Array
): OrganizationReconciliationSignedAttestation {
  if (signature.byteLength !== 64) throw new Error("Ed25519 signatures must be exactly 64 bytes.");
  return signedAttestationSchema.parse({ payload, signature: Buffer.from(signature).toString("base64url") });
}

export function parseOrganizationReconciliationTrustPolicy(value: unknown): OrganizationReconciliationTrustPolicy {
  return trustPolicySchema.parse(value);
}

export function parseOrganizationReconciliationAttestationBundle(
  value: unknown
): OrganizationReconciliationAttestationBundle {
  return attestationBundleSchema.parse(value);
}

export function createOrganizationReconciliationTrustPolicySha256(
  policy: OrganizationReconciliationTrustPolicy
): string {
  return createCanonicalSha256(trustPolicySchema.parse(policy));
}

export function createOrganizationReconciliationProvenanceBinding(
  evidence: unknown,
  collectorContractHash: string,
  collectorBuildRevision: string,
  logicalSnapshotId: string,
  windowId: string,
  windowStartedAt: string,
  windowEndedAt: string,
  deploymentEvidenceSha256: string
): OrganizationReconciliationProvenanceBinding {
  return provenanceBindingSchema.parse({
    evidenceSha256: createCanonicalSha256(evidence),
    deploymentEvidenceSha256,
    collectorContractHash: collectorContractHash.toLowerCase(),
    collectorBuildRevision,
    logicalSnapshotIdHash: createSha256(logicalSnapshotId),
    windowIdHash: createSha256(windowId),
    windowStartedAt,
    windowEndedAt
  });
}

/**
 * Builds the provenance binding for one canonical, validated reconciliation
 * input. The signed time range is the physical composite-manifest window, not
 * the narrower logical collection-envelope window nested inside the evidence.
 */
export function createOrganizationReconciliationProvenanceBindingFromInput(
  input: OrganizationReconciliationInput,
  deploymentEvidenceSha256: string
): OrganizationReconciliationProvenanceBinding {
  const envelope = input.collectionEnvelope;
  const componentManifest = input.componentManifest;
  if (!envelope || !componentManifest) {
    throw new Error("Canonical reconciliation input requires an envelope and component manifest.");
  }
  return createOrganizationReconciliationProvenanceBinding(
    input,
    envelope.collectorContractHash,
    envelope.collectorBuildRevision,
    envelope.logicalSnapshotId,
    envelope.windowId,
    componentManifest.windowStartedAt,
    componentManifest.windowEndedAt,
    deploymentEvidenceSha256
  );
}

export function createCanonicalSha256(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value), "utf8").digest("hex");
}

function canonicalJson(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "string") return JSON.stringify(value)!;
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("Canonical JSON does not support non-finite numbers.");
    return Object.is(value, -0) ? "0" : String(value);
  }
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    const prototype = Object.getPrototypeOf(record);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new Error("Canonical JSON accepts only plain objects.");
    }
    const keys = Object.keys(record).sort();
    for (const key of keys) {
      if (record[key] === undefined) throw new Error("Canonical JSON does not support undefined values.");
    }
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(",")}}`;
  }
  throw new Error("Canonical JSON contains an unsupported value.");
}

function collectorsAreUniqueAndValid(
  collectors: readonly OrganizationReconciliationTrustedCollector[],
  policyStart: number,
  policyEnd: number
): boolean {
  const keyIds = new Set<string>();
  const collectorIds = new Set<string>();
  const nodeIds = new Set<string>();
  const publicKeyFingerprints = new Set<string>();
  for (const collector of collectors) {
    const validFrom = Date.parse(collector.validFrom);
    const validUntil = Date.parse(collector.validUntil);
    if (
      keyIds.has(collector.keyId) ||
      collectorIds.has(collector.collectorId) ||
      nodeIds.has(collector.nodeId) ||
      publicKeyFingerprints.has(collector.publicKeySha256) ||
      validFrom >= validUntil ||
      validFrom < policyStart ||
      validUntil > policyEnd
    ) return false;
    keyIds.add(collector.keyId);
    collectorIds.add(collector.collectorId);
    nodeIds.add(collector.nodeId);
    publicKeyFingerprints.add(collector.publicKeySha256);
  }
  return true;
}

function trustedProfileMatchesPolicy(
  profile: OrganizationReconciliationTrustedProfile,
  policy: OrganizationReconciliationTrustPolicy
): boolean {
  if (
    profile.profileId !== policy.profileId ||
    profile.expectedEnvironment !== policy.environment ||
    profile.requiredCollectors.length !== policy.requiredCollectors.length
  ) return false;

  const profileCollectorIds = new Set<string>();
  const profileNodeIds = new Set<string>();
  const profileKeyIds = new Set<string>();
  const profileKeyFingerprints = new Set<string>();
  const policyByKeyId = new Map(policy.requiredCollectors.map((collector) => [collector.keyId, collector]));
  for (const expected of profile.requiredCollectors) {
    if (
      profileCollectorIds.has(expected.collectorId) ||
      profileNodeIds.has(expected.nodeId) ||
      profileKeyIds.has(expected.keyId) ||
      profileKeyFingerprints.has(expected.publicKeySha256)
    ) return false;
    profileCollectorIds.add(expected.collectorId);
    profileNodeIds.add(expected.nodeId);
    profileKeyIds.add(expected.keyId);
    profileKeyFingerprints.add(expected.publicKeySha256);

    const actual = policyByKeyId.get(expected.keyId);
    if (
      !actual ||
      actual.collectorId !== expected.collectorId ||
      actual.nodeId !== expected.nodeId ||
      actual.buildRevision !== expected.buildRevision ||
      !safeHexEqual(actual.publicKeySha256, expected.publicKeySha256)
    ) return false;
  }
  return true;
}

function payloadMatchesBinding(
  payload: OrganizationReconciliationProvenancePayload,
  binding: OrganizationReconciliationProvenanceBinding
): boolean {
  return safeHexEqual(payload.evidenceSha256, binding.evidenceSha256) &&
    safeHexEqual(payload.deploymentEvidenceSha256, binding.deploymentEvidenceSha256) &&
    safeHexEqual(payload.collectorContractHash, binding.collectorContractHash) &&
    payload.collectorBuildRevision === binding.collectorBuildRevision &&
    safeHexEqual(payload.logicalSnapshotIdHash, binding.logicalSnapshotIdHash) &&
    safeHexEqual(payload.windowIdHash, binding.windowIdHash) &&
    payload.windowStartedAt === binding.windowStartedAt &&
    payload.windowEndedAt === binding.windowEndedAt;
}

function parseTrustedEd25519Key(collector: OrganizationReconciliationTrustedCollector): KeyObject | null {
  try {
    if (!collector.publicKeyPem.startsWith("-----BEGIN PUBLIC KEY-----\n")) return null;
    const key = createPublicKey(collector.publicKeyPem);
    if (key.asymmetricKeyType !== "ed25519") return null;
    const canonicalPem = key.export({ format: "pem", type: "spki" }).toString();
    if (collector.publicKeyPem !== canonicalPem) return null;
    const der = key.export({ format: "der", type: "spki" });
    const fingerprint = createHash("sha256").update(der).digest("hex");
    return safeHexEqual(fingerprint, collector.publicKeySha256) ? key : null;
  } catch {
    return null;
  }
}

function decodeEd25519Signature(encoded: string): Buffer | null {
  try {
    const signature = Buffer.from(encoded, "base64url");
    if (signature.length !== 64 || signature.toString("base64url") !== encoded) return null;
    return signature;
  } catch {
    return null;
  }
}

function createSha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function safeHexEqual(left: string, right: string): boolean {
  if (!/^[a-f0-9]{64}$/.test(left) || !/^[a-f0-9]{64}$/.test(right)) return false;
  return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

function failed(
  code: OrganizationReconciliationProvenanceFailureCode,
  requiredAttestationCount = 0,
  trustPolicySha256?: string,
  verifiedAttestationCount = 0
): OrganizationReconciliationProvenanceVerification {
  return {
    verified: false,
    code,
    requiredAttestationCount,
    verifiedAttestationCount,
    ...(trustPolicySha256 ? { trustPolicySha256 } : {})
  };
}
