import { createHash, timingSafeEqual } from "node:crypto";
import { isProxy } from "node:util/types";
import {
  canonicalizeOrganizationReconciliationEvidenceValue,
  validateOrganizationReconciliationCompositeManifest,
  validateOrganizationReconciliationOperationCompositeManifest,
  validateOrganizationReconciliationOperationCompositeManifestEvidenceBinding,
  type OrganizationReconciliationEvidenceJsonValue
} from "./iam-organization-reconciliation-component-manifest.js";
import {
  createOrganizationReconciliationDevelopDeploymentEvidenceSha256,
  parseOrganizationReconciliationDevelopDeploymentEvidence,
  type OrganizationReconciliationDevelopDeploymentEvidence
} from "./iam-organization-reconciliation-develop-deployment-evidence.js";
import {
  bindOrganizationReconciliationDevelopDeploymentEvidenceToCompiledTopology
} from "./iam-organization-reconciliation-develop-deployment-topology.js";
import {
  ORGANIZATION_RECONCILIATION_DEVELOP_FULL_RANGE_CONTRACT
} from "./iam-organization-reconciliation-develop-full-range.js";
import {
  ORGANIZATION_RECONCILIATION_DEVELOP_PHYSICAL_CATALOG,
  ORGANIZATION_RECONCILIATION_DEVELOP_PHYSICAL_CATALOG_SHA256,
  ORGANIZATION_RECONCILIATION_DEVELOP_PHYSICAL_PROBE_CONTRACT,
  type OrganizationReconciliationDevelopPhysicalProbeReport
} from "./iam-organization-reconciliation-develop-physical-probe.js";
import {
  ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG,
  ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG_SHA256
} from "./iam-organization-reconciliation-develop-source-catalog.js";
import {
  createCanonicalSha256,
  createOrganizationReconciliationTrustPolicySha256,
  ORGANIZATION_RECONCILIATION_PROVENANCE_CONTRACT,
  parseOrganizationReconciliationAttestationBundle,
  parseOrganizationReconciliationTrustPolicy,
  serializeOrganizationReconciliationProvenancePayload,
  type OrganizationReconciliationAttestationBundle,
  type OrganizationReconciliationTrustPolicy,
  type OrganizationReconciliationTrustedProfile
} from "./iam-organization-reconciliation-provenance.js";
import {
  validateOrganizationReconciliation,
  type OrganizationReconciliationInput,
  type OrganizationReconciliationReport
} from "./iam-organization-reconciliation-validator.js";

export const ORGANIZATION_RECONCILIATION_DEVELOP_RUNTIME_VERIFICATION_CERTIFICATE_CONTRACT =
  "iam-organization-reconciliation-xrteeth-develop-runtime-verification-certificate/v1" as const;
export const ORGANIZATION_RECONCILIATION_DEVELOP_RUNTIME_VERIFICATION_CLOSEOUT_CONTRACT =
  "iam-organization-reconciliation-xrteeth-develop-runtime-verification-closeout/v1" as const;

const CERTIFICATE_HASH_DOMAIN = Buffer.from(
  "iam-organization-reconciliation:xrteeth-develop:runtime-verification-certificate:v1\u001f",
  "utf8"
);
const CLOSEOUT_HASH_DOMAIN = Buffer.from(
  "iam-organization-reconciliation:xrteeth-develop:runtime-verification-closeout:v1\u001f",
  "utf8"
);
const AUTHORITATIVE_CERTIFICATE_HASH_DOMAIN = Buffer.from(
  "iam-organization-reconciliation:xrteeth-develop:runtime-verification-certificate-authoritative:v1\u001f",
  "utf8"
);
const OPAQUE_HASH_DOMAIN =
  "iam-organization-reconciliation:xrteeth-develop:runtime-verification-opaque:v1\u001f";
const CURSOR_CHAIN_HASH_DOMAIN = Buffer.from(
  "iam-organization-reconciliation:xrteeth-develop:runtime-verification-cursor-chain:v1\u001f",
  "utf8"
);
const PHYSICAL_BUILD_REVISION_HASH_DOMAIN =
  "iam-organization-reconciliation:xrteeth-develop:build-revision/v1\u001f";
const SHA256 = /^[a-f0-9]{64}$/;
const FULL_REVISION = /^[a-f0-9]{40}$/;
const IMAGE_DIGEST = /^sha256:[a-f0-9]{64}$/;
const MAX_RAW_ARTIFACT_BYTES = 512 * 1024 * 1024;
const MAX_PUBLIC_ARTIFACT_BYTES = 4 * 1024 * 1024;

export interface OrganizationReconciliationDevelopRuntimeCertificateInputFiles {
  readonly rawArtifactBytes: Buffer;
  readonly deploymentEvidenceBytes: Buffer;
  readonly physicalProbeBytes: Buffer;
  readonly trustPolicyBytes: Buffer;
  /** Immutable compiled profile resolved outside every evidence file. */
  readonly trustedProfile: OrganizationReconciliationTrustedProfile;
}

export interface CreateOrganizationReconciliationDevelopRuntimeCertificateInput
  extends OrganizationReconciliationDevelopRuntimeCertificateInputFiles {
  /** Trusted current time. Create performs a freshness check before historical replay. */
  readonly now: Date;
}

export interface VerifyOrganizationReconciliationDevelopRuntimeCertificateInput
  extends OrganizationReconciliationDevelopRuntimeCertificateInputFiles {
  readonly certificateBytes: Buffer;
  readonly closeoutBytes: Buffer;
}

export interface OrganizationReconciliationDevelopRuntimeCertificateAttestation {
  readonly collectorIdSha256: string;
  readonly nodeIdSha256: string;
  readonly keyIdSha256: string;
  readonly publicKeySha256: string;
  readonly payloadSha256: string;
  readonly signatureSha256: string;
}

export interface OrganizationReconciliationDevelopRuntimeCertificateCursorChain {
  readonly componentIdSha256: string;
  readonly datasetIdSha256: string;
  readonly recordCount: number;
  readonly pageCount: number;
  readonly recordsCommitmentSha256: string;
  readonly cursorChainSha256: string;
  readonly lineageSha256: string;
  readonly complete: true;
}

export interface OrganizationReconciliationDevelopRuntimeCertificateSurface {
  readonly surfaceSha256: string;
  readonly legacyRecordCount: number;
  readonly identityRecordCount: number;
  readonly paginationComplete: true;
}

export interface OrganizationReconciliationDevelopRuntimeVerificationCertificate {
  readonly contract:
    typeof ORGANIZATION_RECONCILIATION_DEVELOP_RUNTIME_VERIFICATION_CERTIFICATE_CONTRACT;
  readonly task: "7.2";
  readonly environment: "xrteeth-develop";
  readonly mode: "read-only";
  readonly scope: "full-range";
  readonly outcome: "completed";
  readonly buildRevision: string;
  readonly raw: Readonly<{
    contract: typeof ORGANIZATION_RECONCILIATION_DEVELOP_FULL_RANGE_CONTRACT;
    verificationScope: "signed-reconciliation-input-only";
    wrapperDataCertified: false;
    signedEvidenceSha256: string;
    transientRawLocator: Readonly<{ sourceFileSha256: string }>;
  }>;
  readonly provenance: Readonly<{
    contract: typeof ORGANIZATION_RECONCILIATION_PROVENANCE_CONTRACT;
    trustPolicySha256: string;
    deploymentEvidenceSha256: string;
    attestationBundleSha256: string;
    requiredAttestationCount: 1;
    verifiedAttestationCount: 1;
    replayMode: "historical-at-shared-signed-issued-at";
    attestedAt: string;
    attestations: readonly [OrganizationReconciliationDevelopRuntimeCertificateAttestation];
  }>;
  readonly deployment: Readonly<{
    contract: "iam-organization-reconciliation-xrteeth-develop-deployment-evidence/v2";
    releaseImageDigest: string;
    evidenceSha256: string;
    topologyObservationSha256: string;
    physicalProbeSha256: string;
    executorBindingSha256: string;
    signerSetSha256: string;
    signerCount: 1;
    physicalIndependenceVerified: false;
  }>;
  readonly collection: Readonly<{
    sourceCatalogSha256: string;
    semanticRegistrySha256: string;
    logicalSnapshotIdSha256: string;
    windowIdSha256: string;
    windowStartedAt: string;
    windowEndedAt: string;
    operationEvidenceSha256: string;
    operationManifestSha256: string;
    parentLineageManifestSha256: string;
    cursorChainCount: 21;
    cursorChains: readonly OrganizationReconciliationDevelopRuntimeCertificateCursorChain[];
  }>;
  readonly physicalProbe: Readonly<{
    contract: typeof ORGANIZATION_RECONCILIATION_DEVELOP_PHYSICAL_PROBE_CONTRACT;
    reportFileSha256: string;
    sourceCatalogSha256: string;
    statementCatalogSha256: string;
    physicalCatalogSha256: string;
    componentCount: 3;
    datasetCount: 21;
    physicalTableCount: 19;
    derivedDatasetCount: 1;
    completedProbePassCount: 6;
    passed: true;
  }>;
  readonly verification: Readonly<{
    verifiedSurfaceCount: 8;
    surfaces: readonly OrganizationReconciliationDevelopRuntimeCertificateSurface[];
    severity: Readonly<{ P0: 0; P1: 0; P2: 0; info: number }>;
    mismatchCount: 0;
    allowedCoverageBlockerCount: 1;
    allowedCoverageBlockerCodeSha256: string;
    reportHash: string;
    reportSha256: string;
  }>;
  readonly safety: Readonly<{
    runtimeSafetyGatePassed: false;
    blocksDualWrite: true;
    writeSideEffects: "none";
    physicalIndependenceVerified: false;
    productionReady: false;
    productionPromotionAllowed: false;
  }>;
  readonly certificateSha256: string;
}

export interface OrganizationReconciliationDevelopRuntimeVerificationCloseout {
  readonly contract:
    typeof ORGANIZATION_RECONCILIATION_DEVELOP_RUNTIME_VERIFICATION_CLOSEOUT_CONTRACT;
  readonly task: "7.2";
  readonly environment: "xrteeth-develop";
  readonly mode: "read-only";
  readonly scope: "full-range";
  readonly outcome: "completed";
  readonly authoritativeCertificateSha256: string;
  readonly datasets: Readonly<{ verified: 21; required: 21 }>;
  readonly surfaces: Readonly<{ verified: 8; required: 8 }>;
  readonly attestations: Readonly<{ verified: 1; required: 1 }>;
  readonly physicalProbePasses: Readonly<{ verified: 6; required: 6 }>;
  readonly severity: Readonly<{ P0: 0; P1: 0; P2: 0 }>;
  readonly mismatchCount: 0;
  readonly safety: Readonly<{
    runtimeSafetyGatePassed: false;
    blocksDualWrite: true;
    physicalIndependenceVerified: false;
    productionReady: false;
    productionPromotionAllowed: false;
  }>;
  readonly closeoutSha256: string;
}

export interface OrganizationReconciliationDevelopRuntimeCertificateArtifacts {
  readonly certificate: OrganizationReconciliationDevelopRuntimeVerificationCertificate;
  readonly closeout: OrganizationReconciliationDevelopRuntimeVerificationCloseout;
}

export type OrganizationReconciliationDevelopRuntimeCertificateFailureId =
  | "invalid-input"
  | "invalid-json-artifact"
  | "raw-artifact-invalid"
  | "deployment-binding-invalid"
  | "physical-probe-invalid"
  | "collection-binding-invalid"
  | "current-provenance-invalid"
  | "historical-replay-invalid"
  | "raw-verification-report-mismatch"
  | "certificate-invalid"
  | "closeout-invalid"
  | "certificate-source-mismatch";

export class OrganizationReconciliationDevelopRuntimeCertificateError extends Error {
  constructor(readonly failureId: OrganizationReconciliationDevelopRuntimeCertificateFailureId) {
    super(failureId);
    this.name = "OrganizationReconciliationDevelopRuntimeCertificateError";
  }
}

interface EvaluatedSources {
  readonly rawFileSha256: string;
  readonly raw: Readonly<Record<string, OrganizationReconciliationEvidenceJsonValue>>;
  readonly input: OrganizationReconciliationInput;
  readonly deployment: OrganizationReconciliationDevelopDeploymentEvidence;
  readonly deploymentSha256: string;
  readonly physicalProbe: OrganizationReconciliationDevelopPhysicalProbeReport;
  readonly physicalProbeFileSha256: string;
  readonly policy: OrganizationReconciliationTrustPolicy;
  readonly profile: OrganizationReconciliationTrustedProfile;
  readonly bundle: OrganizationReconciliationAttestationBundle;
}

/**
 * Pure Develop-only certificate creation. It performs no file, network,
 * database, environment, key, or clock reads. The supplied trusted current
 * time is checked first for freshness; the persisted report is then replayed
 * deterministically at the two signatures' shared issuedAt timestamp.
 */
export function createOrganizationReconciliationDevelopRuntimeCertificate(
  candidate: CreateOrganizationReconciliationDevelopRuntimeCertificateInput
): OrganizationReconciliationDevelopRuntimeCertificateArtifacts {
  try {
    const input = captureCreateInput(candidate);
    const sources = evaluateSourceFiles(input);
    if (input.now.getTime() < canonicalTime(sources.raw.completedAt)) {
      fail("current-provenance-invalid");
    }
    const current = replay(sources, input.now);
    assertSuccessfulReport(current, "current-provenance-invalid");
    return buildArtifacts(sources);
  } catch (error) {
    rethrow(error);
  }
}

/**
 * Pure offline verification. Unlike first creation it intentionally uses only
 * historical signed time, so an already issued certificate does not become
 * unverifiable merely because its short-lived attestations later expire.
 */
export function verifyOrganizationReconciliationDevelopRuntimeCertificate(
  candidate: VerifyOrganizationReconciliationDevelopRuntimeCertificateInput
): OrganizationReconciliationDevelopRuntimeCertificateArtifacts {
  try {
    const input = captureVerifyInput(candidate);
    const expectedCertificate = parseCertificateBytes(input.certificateBytes);
    const expectedCloseout = parseCloseoutBytes(input.closeoutBytes, expectedCertificate);
    const sources = evaluateSourceFiles(input);
    const actual = buildArtifacts(sources);
    if (!sameJson(actual.certificate, expectedCertificate) ||
      !sameJson(actual.closeout, expectedCloseout)) {
      fail("certificate-source-mismatch");
    }
    return actual;
  } catch (error) {
    rethrow(error);
  }
}

export function serializeOrganizationReconciliationDevelopRuntimeCertificate(
  certificate: OrganizationReconciliationDevelopRuntimeVerificationCertificate
): string {
  const parsed = parseCertificateCandidate(certificate);
  return `${JSON.stringify(parsed)}\n`;
}

export function serializeOrganizationReconciliationDevelopRuntimeCloseout(
  closeout: OrganizationReconciliationDevelopRuntimeVerificationCloseout,
  certificate: OrganizationReconciliationDevelopRuntimeVerificationCertificate
): string {
  const parsedCertificate = parseCertificateCandidate(certificate);
  const parsed = parseCloseoutCandidate(closeout, parsedCertificate);
  return `${JSON.stringify(parsed)}\n`;
}

export function createOrganizationReconciliationDevelopAuthoritativeCertificateSha256(
  certificate: OrganizationReconciliationDevelopRuntimeVerificationCertificate
): string {
  return authoritativeCertificateProjectionSha256(parseCertificateCandidate(certificate));
}

export function createOrganizationReconciliationDevelopPhysicalProbeFileSha256(
  bytes: Buffer
): string {
  return fileSha256(captureBuffer(bytes, MAX_PUBLIC_ARTIFACT_BYTES));
}

function captureCreateInput(
  candidate: CreateOrganizationReconciliationDevelopRuntimeCertificateInput
): CreateOrganizationReconciliationDevelopRuntimeCertificateInput {
  const value = exactDataObject(candidate, [
    "rawArtifactBytes", "deploymentEvidenceBytes", "physicalProbeBytes", "trustPolicyBytes",
    "trustedProfile", "now"
  ], "invalid-input");
  const now = captureDate(value.now);
  return Object.freeze({
    rawArtifactBytes: captureBuffer(value.rawArtifactBytes, MAX_RAW_ARTIFACT_BYTES),
    deploymentEvidenceBytes: captureBuffer(value.deploymentEvidenceBytes, MAX_PUBLIC_ARTIFACT_BYTES),
    physicalProbeBytes: captureBuffer(value.physicalProbeBytes, MAX_PUBLIC_ARTIFACT_BYTES),
    trustPolicyBytes: captureBuffer(value.trustPolicyBytes, MAX_PUBLIC_ARTIFACT_BYTES),
    trustedProfile: captureProfile(value.trustedProfile),
    now
  });
}

function captureVerifyInput(
  candidate: VerifyOrganizationReconciliationDevelopRuntimeCertificateInput
): VerifyOrganizationReconciliationDevelopRuntimeCertificateInput {
  const value = exactDataObject(candidate, [
    "rawArtifactBytes", "deploymentEvidenceBytes", "physicalProbeBytes", "trustPolicyBytes",
    "trustedProfile", "certificateBytes", "closeoutBytes"
  ], "invalid-input");
  return Object.freeze({
    rawArtifactBytes: captureBuffer(value.rawArtifactBytes, MAX_RAW_ARTIFACT_BYTES),
    deploymentEvidenceBytes: captureBuffer(value.deploymentEvidenceBytes, MAX_PUBLIC_ARTIFACT_BYTES),
    physicalProbeBytes: captureBuffer(value.physicalProbeBytes, MAX_PUBLIC_ARTIFACT_BYTES),
    trustPolicyBytes: captureBuffer(value.trustPolicyBytes, MAX_PUBLIC_ARTIFACT_BYTES),
    trustedProfile: captureProfile(value.trustedProfile),
    certificateBytes: captureBuffer(value.certificateBytes, MAX_PUBLIC_ARTIFACT_BYTES),
    closeoutBytes: captureBuffer(value.closeoutBytes, MAX_PUBLIC_ARTIFACT_BYTES)
  });
}

function evaluateSourceFiles(
  input: OrganizationReconciliationDevelopRuntimeCertificateInputFiles
): EvaluatedSources {
  const rawFileSha256 = fileSha256(input.rawArtifactBytes);
  const physicalProbeFileSha256 = fileSha256(input.physicalProbeBytes);
  const rawValue = parseJsonBytes(input.rawArtifactBytes, MAX_RAW_ARTIFACT_BYTES);
  const deploymentValue = parseJsonBytes(input.deploymentEvidenceBytes, MAX_PUBLIC_ARTIFACT_BYTES);
  const physicalProbeValue = parseJsonBytes(input.physicalProbeBytes, MAX_PUBLIC_ARTIFACT_BYTES);
  const trustPolicyValue = parseJsonBytes(input.trustPolicyBytes, MAX_PUBLIC_ARTIFACT_BYTES);

  const raw = parseRawArtifact(rawValue);
  let deployment: OrganizationReconciliationDevelopDeploymentEvidence;
  let policy: OrganizationReconciliationTrustPolicy;
  let bundle: OrganizationReconciliationAttestationBundle;
  try {
    policy = parseOrganizationReconciliationTrustPolicy(trustPolicyValue);
    deployment = bindOrganizationReconciliationDevelopDeploymentEvidenceToCompiledTopology(
      parseOrganizationReconciliationDevelopDeploymentEvidence(deploymentValue),
      policy.profileId
    ).deploymentEvidence;
    bundle = parseOrganizationReconciliationAttestationBundle(raw.attestationBundle);
  } catch {
    fail("deployment-binding-invalid");
  }
  const deploymentSha256 = createOrganizationReconciliationDevelopDeploymentEvidenceSha256(deployment);
  const profile = input.trustedProfile;
  const inputValue = raw.reconciliationInput as unknown as OrganizationReconciliationInput;
  const physicalProbe = parsePhysicalProbe(physicalProbeValue, raw.buildRevision as string);

  if (
    raw.deploymentEvidenceSha256 !== deploymentSha256 ||
    raw.releaseImageDigest !== deployment.releaseImageDigest ||
    raw.buildRevision !== deployment.buildRevision ||
    deployment.physicalProbeSha256 !== physicalProbeFileSha256 ||
    raw.trustPolicySha256 !== createOrganizationReconciliationTrustPolicySha256(policy) ||
    policy.environment !== "xrteeth-develop" ||
    policy.requiredCollectors.length !== 1 ||
    bundle.attestations.length !== 1 ||
    raw.verifiedAttestationCount !== 1 ||
    !deploymentMatchesPolicy(deployment, policy, raw.buildRevision as string)
  ) {
    fail("deployment-binding-invalid");
  }

  return Object.freeze({
    rawFileSha256,
    raw,
    input: inputValue,
    deployment,
    deploymentSha256,
    physicalProbe,
    physicalProbeFileSha256,
    policy,
    profile,
    bundle
  });
}

function buildArtifacts(sources: EvaluatedSources): OrganizationReconciliationDevelopRuntimeCertificateArtifacts {
  const attestedAt = sharedAttestedAt(sources.bundle);
  const historical = replay(sources, new Date(attestedAt));
  assertSuccessfulReport(historical, "historical-replay-invalid");
  if (!sameJson(historical, sources.raw.verificationReport)) {
    fail("raw-verification-report-mismatch");
  }
  const collection = validateCollectionBindings(sources, attestedAt);
  const certificate = createCertificate(sources, historical, attestedAt, collection);
  const closeout = createCloseout(certificate);
  return Object.freeze({ certificate, closeout });
}

function replay(sources: EvaluatedSources, now: Date): OrganizationReconciliationReport {
  return validateOrganizationReconciliation(sources.input, {
    trustedProvenance: {
      trustedProfile: sources.profile,
      trustPolicy: sources.policy,
      attestationBundle: sources.bundle,
      expectedDeploymentEvidenceSha256: sources.deploymentSha256,
      now
    }
  });
}

function assertSuccessfulReport(
  report: OrganizationReconciliationReport,
  failureId: "current-provenance-invalid" | "historical-replay-invalid"
): void {
  const blockers = report.coverageBlockers;
  if (
    !report.provenanceVerification.verified ||
    report.provenanceVerification.reasonCode !== "verified" ||
    report.provenanceVerification.requiredAttestationCount !== 1 ||
    report.provenanceVerification.verifiedAttestationCount !== 1 ||
    report.coverage.length !== 8 ||
    report.coverage.some((entry) => !entry.paginationComplete) ||
    blockers.length !== 1 || blockers[0]?.code !== "real-source-adapters-not-ready" ||
    report.severity.P0 !== 0 || report.severity.P1 !== 0 ||
    report.severity.P2 !== 0 || !Number.isSafeInteger(report.severity.info) ||
    report.severity.info < 0 || report.severity.info !== report.findings.length ||
    report.findings.some((finding) => finding.severity !== "info" ||
      (finding.reasonCode !== "record-aligned" && finding.reasonCode !== "decision-aligned")) ||
    report.realSourceAdaptersReady !== false ||
    report.staticChecksPassed !== false ||
    report.safetyGate.passed !== false ||
    report.safetyGate.blocksDualWrite !== true ||
    report.safetyGate.externalProvenanceVerified !== true ||
    !report.safetyGate.blockedReasons.includes("coverage-incomplete")
  ) fail(failureId);
}

interface ValidatedCollection {
  readonly logicalSnapshotId: string;
  readonly windowId: string;
  readonly windowStartedAt: string;
  readonly windowEndedAt: string;
  readonly operationEvidenceSha256: string;
  readonly operationManifestSha256: string;
  readonly parentLineageManifestSha256: string;
  readonly cursorChains: readonly OrganizationReconciliationDevelopRuntimeCertificateCursorChain[];
}

function validateCollectionBindings(sources: EvaluatedSources, attestedAt: string): ValidatedCollection {
  try {
    const raw = sources.raw;
    const input = exactRecord(raw.reconciliationInput, [
      "campusContexts", "collectionEnvelope", "componentManifest", "effectiveDecisions",
      "memberships", "organizationDirectory", "organizationMappings", "organizationScopedRoles",
      "pluginBindings", "pluginVisibility", "projectionBinding"
    ]);
    const operation = exactRecord(raw.operationEvidence, [
      "blockers", "componentManifest", "contract", "evidence", "implemented",
      "lineageManifestSha256", "observableDecisionCartesianCoverage", "outcome",
      "projectionBinding", "ready", "semanticRegistrySha256", "verifiedSurfaceCount"
    ]);
    const lineageRun = exactRecord(raw.lineageRun, [
      "artifacts", "catalogTrust", "contract", "coordinatorManifest", "crossDatabaseAtomic", "readiness"
    ]);
    const { componentManifest: _manifest, ...evidenceBody } = input;
    if (operation.contract !==
        "iam-organization-reconciliation-xrteeth-develop-operation-evidence-boundary/v3" ||
      operation.implemented !== true || operation.ready !== false || operation.outcome !== "blocked" ||
      operation.observableDecisionCartesianCoverage !== true ||
      !sameJson(evidenceBody, operation.evidence) ||
      !sameJson(input.componentManifest, operation.componentManifest) ||
      !sameJson(input.projectionBinding, operation.projectionBinding) ||
      operation.verifiedSurfaceCount !== 8 || operation.semanticRegistrySha256 !== raw.semanticRegistrySha256) {
      fail("collection-binding-invalid");
    }
    const operationManifest = validateOrganizationReconciliationOperationCompositeManifestEvidenceBinding(
      input.componentManifest,
      evidenceBody
    );
    const wrapperManifest = validateOrganizationReconciliationOperationCompositeManifest(
      operation.componentManifest
    );
    const lineageManifest = validateOrganizationReconciliationCompositeManifest(
      lineageRun.coordinatorManifest
    );
    const projection = exactRecord(input.projectionBinding, [
      "contract", "identity", "legacy", "lineageManifestSha256", "pluginSource", "semanticRegistrySha256"
    ]);
    const envelope = exactRecord(input.collectionEnvelope, [
      "collectorBuildRevision", "collectorContract", "collectorContractHash", "evidenceNonce",
      "identity", "legacy", "logicalSnapshotId", "windowEndedAt", "windowId", "windowStartedAt"
    ]);
    validateProjectionDuplicates(raw, input, projection);
    const envelopeWindowStartedAt = requireBoundString(envelope.windowStartedAt);
    const envelopeWindowEndedAt = requireBoundString(envelope.windowEndedAt);
    const envelopeWindowStart = canonicalTime(envelopeWindowStartedAt);
    const envelopeWindowEnd = canonicalTime(envelopeWindowEndedAt);
    const expectedIntersectionStart = Math.max(
      ...operationManifest.components.map((component) => canonicalTime(component.openedAt))
    );
    const expectedIntersectionEnd = Math.min(
      ...operationManifest.components.map((component) => canonicalTime(component.closedAt))
    );
    const expectedUnionStart = Math.min(
      ...operationManifest.components.map((component) => canonicalTime(component.openedAt))
    );
    const expectedUnionEnd = Math.max(
      ...operationManifest.components.map((component) => canonicalTime(component.closedAt))
    );
    if (
      !sameJson(operationManifest, wrapperManifest) ||
      operationManifest.parentLineageManifestSha256 !== lineageManifest.manifestSha256 ||
      operation.lineageManifestSha256 !== lineageManifest.manifestSha256 ||
      projection.lineageManifestSha256 !== lineageManifest.manifestSha256 ||
      projection.semanticRegistrySha256 !== raw.semanticRegistrySha256 ||
      !sameJson(operationManifest.components, lineageManifest.components) ||
      operationManifest.windowStartedAt !== lineageManifest.windowStartedAt ||
      operationManifest.windowEndedAt !== lineageManifest.windowEndedAt ||
      canonicalTime(operationManifest.windowStartedAt) !== expectedUnionStart ||
      canonicalTime(operationManifest.windowEndedAt) !== expectedUnionEnd ||
      envelopeWindowStart !== expectedIntersectionStart ||
      envelopeWindowEnd !== expectedIntersectionEnd ||
      envelopeWindowStart > envelopeWindowEnd ||
      raw.sourceCatalogSha256 !== ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG_SHA256 ||
      raw.datasetCount !== 21 || raw.verifiedSurfaceCount !== 8
    ) fail("collection-binding-invalid");

    assertOrganizationReconciliationDevelopRuntimeCertificateChronology({
      deploymentObservedAt: sources.deployment.observedAt,
      rawStartedAt: requireBoundString(raw.startedAt),
      unionStartedAt: new Date(expectedUnionStart).toISOString(),
      intersectionStartedAt: envelopeWindowStartedAt,
      intersectionEndedAt: envelopeWindowEndedAt,
      unionEndedAt: new Date(expectedUnionEnd).toISOString(),
      signedAt: attestedAt,
      rawCompletedAt: requireBoundString(raw.completedAt)
    });

    const cursorChains = createCursorChains(operationManifest.components);
    if (cursorChains.length !== 21) fail("collection-binding-invalid");
    return Object.freeze({
      logicalSnapshotId: requireBoundString(envelope.logicalSnapshotId),
      windowId: requireBoundString(envelope.windowId),
      windowStartedAt: envelopeWindowStartedAt,
      windowEndedAt: envelopeWindowEndedAt,
      operationEvidenceSha256: operationManifest.evidenceSha256,
      operationManifestSha256: operationManifest.manifestSha256,
      parentLineageManifestSha256: operationManifest.parentLineageManifestSha256,
      cursorChains
    });
  } catch (error) {
    if (error instanceof OrganizationReconciliationDevelopRuntimeCertificateError) throw error;
    fail("collection-binding-invalid");
  }
}

function validateProjectionDuplicates(
  raw: Readonly<Record<string, OrganizationReconciliationEvidenceJsonValue>>,
  input: Readonly<Record<string, OrganizationReconciliationEvidenceJsonValue>>,
  projectionBinding: Readonly<Record<string, OrganizationReconciliationEvidenceJsonValue>>
): void {
  const legacyProjection = exactRecord(raw.legacyProjection, [
    "contract", "evaluatorBuildSha256", "evaluatorId", "semanticRegistrySha256", "side", "surfaces"
  ]);
  const identityProjection = exactRecord(raw.identityProjection, [
    "contract", "evaluatorBuildSha256", "evaluatorId", "semanticRegistrySha256", "side", "surfaces"
  ]);
  const legacyBinding = exactRecord(projectionBinding.legacy, [
    "evaluatorBuildSha256", "evaluatorId", "primarySource", "projectorContract"
  ]);
  const identityBinding = exactRecord(projectionBinding.identity, [
    "evaluatorBuildSha256", "evaluatorId", "primarySource", "projectorContract"
  ]);
  if (
    legacyProjection.side !== "legacy" || identityProjection.side !== "identity" ||
    legacyProjection.contract !== legacyBinding.projectorContract ||
    identityProjection.contract !== identityBinding.projectorContract ||
    legacyProjection.evaluatorId !== legacyBinding.evaluatorId ||
    identityProjection.evaluatorId !== identityBinding.evaluatorId ||
    legacyProjection.evaluatorBuildSha256 !== legacyBinding.evaluatorBuildSha256 ||
    identityProjection.evaluatorBuildSha256 !== identityBinding.evaluatorBuildSha256 ||
    legacyProjection.semanticRegistrySha256 !== projectionBinding.semanticRegistrySha256 ||
    identityProjection.semanticRegistrySha256 !== projectionBinding.semanticRegistrySha256
  ) fail("collection-binding-invalid");
  const surfaceNames = [
    "organizationDirectory", "organizationMappings", "memberships", "organizationScopedRoles",
    "pluginBindings", "pluginVisibility", "campusContexts", "effectiveDecisions"
  ] as const;
  const legacySurfaces = exactRecord(legacyProjection.surfaces, surfaceNames);
  const identitySurfaces = exactRecord(identityProjection.surfaces, surfaceNames);
  for (const surface of surfaceNames) {
    const pair = exactRecord(input[surface], ["identity", "legacy"]);
    const legacy = exactRecord(pair.legacy, ["collection", "nextCursor", "records", "sourceVersion"]);
    const identity = exactRecord(pair.identity, ["collection", "nextCursor", "records", "sourceVersion"]);
    if (!sameJson(legacySurfaces[surface], legacy.records) ||
      !sameJson(identitySurfaces[surface], identity.records)) {
      fail("collection-binding-invalid");
    }
  }
}

export function assertOrganizationReconciliationDevelopRuntimeCertificateChronology(
  candidate: Readonly<{
    deploymentObservedAt: string;
    rawStartedAt: string;
    unionStartedAt: string;
    intersectionStartedAt: string;
    intersectionEndedAt: string;
    unionEndedAt: string;
    signedAt: string;
    rawCompletedAt: string;
  }>
): void {
  try {
    const value = exactDataObject(candidate, [
      "deploymentObservedAt", "rawStartedAt", "unionStartedAt", "intersectionStartedAt",
      "intersectionEndedAt", "unionEndedAt", "signedAt", "rawCompletedAt"
    ], "collection-binding-invalid");
    const ordered = [
      value.deploymentObservedAt,
      value.rawStartedAt,
      value.unionStartedAt,
      value.intersectionStartedAt,
      value.intersectionEndedAt,
      value.unionEndedAt,
      value.signedAt,
      value.rawCompletedAt
    ].map((timestamp) => canonicalTime(timestamp));
    if (ordered.some((timestamp, index) => index > 0 && timestamp < ordered[index - 1]!)) {
      fail("collection-binding-invalid");
    }
  } catch (error) {
    if (error instanceof OrganizationReconciliationDevelopRuntimeCertificateError) throw error;
    fail("collection-binding-invalid");
  }
}

function createCursorChains(
  components: ReturnType<typeof validateOrganizationReconciliationOperationCompositeManifest>["components"]
): readonly OrganizationReconciliationDevelopRuntimeCertificateCursorChain[] {
  const expected = new Map(ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG.components.map((component) => [
    component.componentId,
    component.datasetCatalog.datasets.map((dataset) => dataset.datasetId)
  ]));
  const output: Array<OrganizationReconciliationDevelopRuntimeCertificateCursorChain & {
    readonly sortKey: string;
  }> = [];
  for (const component of components) {
    const datasets = component.datasetInventory.datasets;
    const expectedDatasets = expected.get(component.componentId);
    if (!expectedDatasets || !sameStringSet(datasets.map((dataset) => dataset.datasetId), expectedDatasets)) {
      fail("collection-binding-invalid");
    }
    for (const dataset of datasets) {
      const pages = dataset.pages;
      const complete = pages.length === dataset.pageCount && pages.length > 0 &&
        pages[0]?.requestCursorCommitment === null && pages.at(-1)?.nextCursorCommitment === null &&
        pages.every((page, index) => page.pageNumber === index + 1 &&
          (index === 0 || pages[index - 1]?.nextCursorCommitment === page.requestCursorCommitment));
      if (!complete) fail("collection-binding-invalid");
      output.push(Object.freeze({
        sortKey: `${component.componentId}\u001f${dataset.datasetId}`,
        componentIdSha256: opaqueSha256("component-id", component.componentId),
        datasetIdSha256: opaqueSha256("dataset-id", dataset.datasetId),
        recordCount: dataset.recordCount,
        pageCount: dataset.pageCount,
        recordsCommitmentSha256: dataset.recordsCommitment,
        cursorChainSha256: domainJsonSha256(CURSOR_CHAIN_HASH_DOMAIN, pages),
        lineageSha256: dataset.lineageSha256,
        complete: true
      }));
    }
  }
  output.sort((left, right) => binaryCompare(left.sortKey, right.sortKey));
  return Object.freeze(output.map(({ sortKey: _sortKey, ...entry }) => Object.freeze(entry)));
}

function createCertificate(
  sources: EvaluatedSources,
  report: OrganizationReconciliationReport,
  attestedAt: string,
  collection: ValidatedCollection
): OrganizationReconciliationDevelopRuntimeVerificationCertificate {
  const signedEvidenceSha256 = createCanonicalSha256(sources.input);
  if (sources.bundle.attestations.some((entry) => entry.payload.evidenceSha256 !== signedEvidenceSha256 ||
    entry.payload.deploymentEvidenceSha256 !== sources.deploymentSha256)) {
    fail("historical-replay-invalid");
  }
  const attestations = sources.bundle.attestations.map((entry) => Object.freeze({
    sortKey: entry.payload.keyId,
    collectorIdSha256: opaqueSha256("collector-id", entry.payload.collectorId),
    nodeIdSha256: opaqueSha256("node-id", entry.payload.nodeId),
    keyIdSha256: opaqueSha256("key-id", entry.payload.keyId),
    publicKeySha256: sources.policy.requiredCollectors.find(
      (collector) => collector.keyId === entry.payload.keyId
    )?.publicKeySha256 ?? fail("historical-replay-invalid"),
    payloadSha256: createHash("sha256")
      .update(serializeOrganizationReconciliationProvenancePayload(entry.payload))
      .digest("hex"),
    signatureSha256: createHash("sha256")
      .update(Buffer.from(entry.signature, "base64url"))
      .digest("hex")
  })).sort((left, right) => binaryCompare(left.sortKey, right.sortKey))
    .map(({ sortKey: _sortKey, ...entry }) => Object.freeze(entry));
  if (attestations.length !== 1) fail("historical-replay-invalid");

  const surfaces = report.coverage.map((entry) => Object.freeze({
    sortKey: entry.surface,
    surfaceSha256: opaqueSha256("surface", entry.surface),
    legacyRecordCount: entry.legacyRecordCount,
    identityRecordCount: entry.identityRecordCount,
    paginationComplete: true as const
  })).sort((left, right) => binaryCompare(left.sortKey, right.sortKey))
    .map(({ sortKey: _sortKey, ...entry }) => Object.freeze(entry));
  const core = canonicalizeOrganizationReconciliationEvidenceValue({
    contract: ORGANIZATION_RECONCILIATION_DEVELOP_RUNTIME_VERIFICATION_CERTIFICATE_CONTRACT,
    task: "7.2",
    environment: "xrteeth-develop",
    mode: "read-only",
    scope: "full-range",
    outcome: "completed",
    buildRevision: sources.raw.buildRevision,
    raw: {
      contract: ORGANIZATION_RECONCILIATION_DEVELOP_FULL_RANGE_CONTRACT,
      verificationScope: "signed-reconciliation-input-only",
      wrapperDataCertified: false,
      signedEvidenceSha256,
      transientRawLocator: { sourceFileSha256: sources.rawFileSha256 }
    },
    provenance: {
      contract: ORGANIZATION_RECONCILIATION_PROVENANCE_CONTRACT,
      trustPolicySha256: createOrganizationReconciliationTrustPolicySha256(sources.policy),
      deploymentEvidenceSha256: sources.deploymentSha256,
      attestationBundleSha256: createCanonicalSha256(sources.bundle),
      requiredAttestationCount: 1,
      verifiedAttestationCount: 1,
      replayMode: "historical-at-shared-signed-issued-at",
      attestedAt,
      attestations
    },
    deployment: {
      contract: sources.deployment.contract,
      releaseImageDigest: sources.deployment.releaseImageDigest,
      evidenceSha256: sources.deploymentSha256,
      topologyObservationSha256: sources.deployment.topologyObservationSha256,
      physicalProbeSha256: sources.deployment.physicalProbeSha256,
      executorBindingSha256: opaqueValueSha256("deployment-executor", sources.deployment.executor),
      signerSetSha256: opaqueValueSha256("deployment-signer-set", sources.deployment.signers),
      signerCount: 1,
      physicalIndependenceVerified: false
    },
    collection: {
      sourceCatalogSha256: sources.raw.sourceCatalogSha256,
      semanticRegistrySha256: sources.raw.semanticRegistrySha256,
      logicalSnapshotIdSha256: opaqueSha256("logical-snapshot-id", collection.logicalSnapshotId),
      windowIdSha256: opaqueSha256("window-id", collection.windowId),
      windowStartedAt: collection.windowStartedAt,
      windowEndedAt: collection.windowEndedAt,
      operationEvidenceSha256: collection.operationEvidenceSha256,
      operationManifestSha256: collection.operationManifestSha256,
      parentLineageManifestSha256: collection.parentLineageManifestSha256,
      cursorChainCount: 21,
      cursorChains: collection.cursorChains
    },
    physicalProbe: {
      contract: ORGANIZATION_RECONCILIATION_DEVELOP_PHYSICAL_PROBE_CONTRACT,
      reportFileSha256: sources.physicalProbeFileSha256,
      sourceCatalogSha256: sources.physicalProbe.sourceCatalogSha256,
      statementCatalogSha256: sources.physicalProbe.statementCatalogSha256,
      physicalCatalogSha256: sources.physicalProbe.physicalCatalogSha256,
      componentCount: 3,
      datasetCount: 21,
      physicalTableCount: 19,
      derivedDatasetCount: 1,
      completedProbePassCount: 6,
      passed: true
    },
    verification: {
      verifiedSurfaceCount: 8,
      surfaces,
      severity: { P0: 0, P1: 0, P2: 0, info: report.severity.info },
      mismatchCount: 0,
      allowedCoverageBlockerCount: 1,
      allowedCoverageBlockerCodeSha256: opaqueSha256(
        "coverage-blocker-code",
        "real-source-adapters-not-ready"
      ),
      reportHash: report.reportHash,
      reportSha256: createCanonicalSha256(report)
    },
    safety: {
      runtimeSafetyGatePassed: false,
      blocksDualWrite: true,
      writeSideEffects: "none",
      physicalIndependenceVerified: false,
      productionReady: false,
      productionPromotionAllowed: false
    }
  });
  const certificateSha256 = domainJsonSha256(CERTIFICATE_HASH_DOMAIN, core);
  return canonicalizeOrganizationReconciliationEvidenceValue({
    ...(core as Record<string, OrganizationReconciliationEvidenceJsonValue>),
    certificateSha256
  }) as unknown as OrganizationReconciliationDevelopRuntimeVerificationCertificate;
}

function createCloseout(
  certificate: OrganizationReconciliationDevelopRuntimeVerificationCertificate
): OrganizationReconciliationDevelopRuntimeVerificationCloseout {
  const authoritativeCertificateSha256 =
    authoritativeCertificateProjectionSha256(certificate);
  const core = canonicalizeOrganizationReconciliationEvidenceValue({
    contract: ORGANIZATION_RECONCILIATION_DEVELOP_RUNTIME_VERIFICATION_CLOSEOUT_CONTRACT,
    task: "7.2",
    environment: certificate.environment,
    mode: certificate.mode,
    scope: certificate.scope,
    outcome: certificate.outcome,
    authoritativeCertificateSha256,
    datasets: { verified: 21, required: 21 },
    surfaces: { verified: 8, required: 8 },
    attestations: { verified: 1, required: 1 },
    physicalProbePasses: { verified: 6, required: 6 },
    severity: { P0: 0, P1: 0, P2: 0 },
    mismatchCount: 0,
    safety: {
      runtimeSafetyGatePassed: false,
      blocksDualWrite: true,
      physicalIndependenceVerified: false,
      productionReady: false,
      productionPromotionAllowed: false
    }
  });
  return canonicalizeOrganizationReconciliationEvidenceValue({
    ...(core as Record<string, OrganizationReconciliationEvidenceJsonValue>),
    closeoutSha256: domainJsonSha256(CLOSEOUT_HASH_DOMAIN, core)
  }) as unknown as OrganizationReconciliationDevelopRuntimeVerificationCloseout;
}

function authoritativeCertificateProjectionSha256(
  certificate: OrganizationReconciliationDevelopRuntimeVerificationCertificate
): string {
  const canonical = canonicalizeOrganizationReconciliationEvidenceValue(certificate) as Readonly<
    Record<string, OrganizationReconciliationEvidenceJsonValue>
  >;
  const { certificateSha256: _certificateSha256, raw: candidateRaw, ...authoritative } = canonical;
  const raw = exactRecord(candidateRaw, [
    "contract", "signedEvidenceSha256", "transientRawLocator", "verificationScope",
    "wrapperDataCertified"
  ]);
  const { transientRawLocator: _transientRawLocator, ...authoritativeRaw } = raw;
  return domainJsonSha256(AUTHORITATIVE_CERTIFICATE_HASH_DOMAIN, {
    ...authoritative,
    raw: authoritativeRaw
  });
}

function parseRawArtifact(
  candidate: OrganizationReconciliationEvidenceJsonValue
): Readonly<Record<string, OrganizationReconciliationEvidenceJsonValue>> {
  try {
    const raw = exactRecord(candidate, [
      "attestationBundle", "buildRevision", "completedAt", "contract", "datasetCount",
      "deploymentEvidenceSha256", "dryRun", "environment", "externalProvenanceVerified",
      "identityProjection", "legacyProjection", "lineageRun", "mode", "nodeId",
      "operationEvidence", "physicalIndependenceVerified", "productionPromotionAllowed",
      "productionReady", "productionWritePerformed", "reconciliationInput",
      "releaseImageDigest", "scope", "semanticRegistrySha256", "sourceCatalogSha256",
      "sourcePreflight", "startedAt", "tmrppUntouched", "transactionFactoryProvenance",
      "trustPolicySha256", "verificationReport", "verifiedAttestationCount",
      "verifiedSurfaceCount", "writeSideEffects"
    ]);
    if (
      raw.contract !== ORGANIZATION_RECONCILIATION_DEVELOP_FULL_RANGE_CONTRACT ||
      raw.environment !== "xrteeth-develop" || raw.nodeId !== "xrteeth" ||
      raw.mode !== "read-only" || raw.scope !== "full-range" ||
      typeof raw.buildRevision !== "string" || !FULL_REVISION.test(raw.buildRevision) ||
      typeof raw.deploymentEvidenceSha256 !== "string" || !validSha(raw.deploymentEvidenceSha256) ||
      typeof raw.releaseImageDigest !== "string" || !IMAGE_DIGEST.test(raw.releaseImageDigest) ||
      typeof raw.sourceCatalogSha256 !== "string" || !validSha(raw.sourceCatalogSha256) ||
      typeof raw.semanticRegistrySha256 !== "string" || !validSha(raw.semanticRegistrySha256) ||
      raw.datasetCount !== 21 || raw.verifiedSurfaceCount !== 8 || raw.dryRun !== true ||
      raw.writeSideEffects !== "none" || raw.productionWritePerformed !== false ||
      raw.tmrppUntouched !== true || raw.physicalIndependenceVerified !== false ||
      raw.productionReady !== false || raw.productionPromotionAllowed !== false ||
      raw.externalProvenanceVerified !== true || raw.verifiedAttestationCount !== 1 ||
      typeof raw.trustPolicySha256 !== "string" || !validSha(raw.trustPolicySha256)
    ) fail("raw-artifact-invalid");
    const start = canonicalTime(raw.startedAt);
    const end = canonicalTime(raw.completedAt);
    if (start > end) fail("raw-artifact-invalid");
    return raw;
  } catch (error) {
    if (error instanceof OrganizationReconciliationDevelopRuntimeCertificateError) throw error;
    fail("raw-artifact-invalid");
  }
}

function parsePhysicalProbe(
  candidate: OrganizationReconciliationEvidenceJsonValue,
  buildRevision: string
): OrganizationReconciliationDevelopPhysicalProbeReport {
  try {
    const report = exactRecord(candidate, [
      "assuranceScope", "buildRevisionSha256", "componentCount", "completedProbePassCount",
      "components", "contract", "currentTransactionVariableIntrospectionClaimed", "datasetCount",
      "derivedDatasetCount", "environment", "failedIds", "mode", "optimizerOrderPerformanceClaimed",
      "passed", "physicalCatalogSha256", "physicalTableCount", "productionReady",
      "sourceCatalogSha256", "statementCatalogSha256"
    ]);
    const expectedBuildSha = createHash("sha256")
      .update(PHYSICAL_BUILD_REVISION_HASH_DOMAIN, "utf8")
      .update(JSON.stringify(buildRevision), "utf8")
      .digest("hex");
    if (
      report.contract !== ORGANIZATION_RECONCILIATION_DEVELOP_PHYSICAL_PROBE_CONTRACT ||
      report.environment !== "xrteeth-develop" || report.mode !== "read-only" ||
      report.assuranceScope !==
        "compiled-21-dataset-physical-metadata-and-deterministic-cursor-keys-only" ||
      report.optimizerOrderPerformanceClaimed !== false ||
      report.currentTransactionVariableIntrospectionClaimed !== false ||
      report.sourceCatalogSha256 !== ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG_SHA256 ||
      report.statementCatalogSha256 !== ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG.statementCatalogSha256 ||
      report.physicalCatalogSha256 !== ORGANIZATION_RECONCILIATION_DEVELOP_PHYSICAL_CATALOG_SHA256 ||
      report.buildRevisionSha256 !== expectedBuildSha || report.componentCount !== 3 ||
      report.datasetCount !== 21 || report.physicalTableCount !== 19 ||
      report.derivedDatasetCount !== 1 || report.completedProbePassCount !== 6 ||
      report.passed !== true || report.productionReady !== false ||
      !Array.isArray(report.failedIds) || report.failedIds.length !== 0 ||
      !Array.isArray(report.components) || report.components.length !== 3
    ) fail("physical-probe-invalid");
    const expectedByComponent = new Map(
      ORGANIZATION_RECONCILIATION_DEVELOP_PHYSICAL_CATALOG.components.map((component) => [
        component.componentId,
        component
      ])
    );
    const seen = new Set<string>();
    let datasetCount = 0;
    let physicalTableCount = 0;
    for (const candidateComponent of report.components) {
      const component = exactRecord(candidateComponent, [
        "aBAligned", "binaryOrderWitnessPassed", "binaryOrderWitnessSha256", "collationPassed",
        "columnShapePassed", "completedProbePassCount", "componentId", "databaseBindingPassed",
        "datasetCount", "deterministicUniqueKeysPassed", "grantPassed", "grantScopeSha256",
        "observedColumnCount", "observedIndexCount", "observedTableCount", "physicalIndexSha256",
        "physicalSchemaSha256", "physicalTableCount", "requiredColumnCount",
        "requiredDeterministicUniqueKeyCount", "snapshotProtocolPassed", "snapshotProtocolSha256",
        "sourceIdentitySha256", "tableShapePassed"
      ]);
      if (typeof component.componentId !== "string" || seen.has(component.componentId)) {
        fail("physical-probe-invalid");
      }
      const expected = expectedByComponent.get(component.componentId as never);
      if (!expected) fail("physical-probe-invalid");
      seen.add(component.componentId);
      const expectedDatasetCount = Object.keys(expected.datasets).length;
      const expectedTableCount = Object.keys(expected.tables).length;
      if (
        component.datasetCount !== expectedDatasetCount || component.physicalTableCount !== expectedTableCount ||
        component.completedProbePassCount !== 2 || component.databaseBindingPassed !== true ||
        component.grantPassed !== true || component.snapshotProtocolPassed !== true ||
        component.tableShapePassed !== true || component.columnShapePassed !== true ||
        component.deterministicUniqueKeysPassed !== true || component.collationPassed !== true ||
        component.binaryOrderWitnessPassed !== true || component.aBAligned !== true ||
        !validSha(component.sourceIdentitySha256) || !validSha(component.grantScopeSha256) ||
        !validSha(component.physicalSchemaSha256) || !validSha(component.physicalIndexSha256) ||
        !validSha(component.snapshotProtocolSha256) || !validSha(component.binaryOrderWitnessSha256) ||
        !positiveInteger(component.requiredColumnCount) ||
        !positiveInteger(component.requiredDeterministicUniqueKeyCount) ||
        !positiveInteger(component.observedTableCount) || !positiveInteger(component.observedColumnCount) ||
        !positiveInteger(component.observedIndexCount) || component.observedTableCount !== expectedTableCount
      ) fail("physical-probe-invalid");
      datasetCount += expectedDatasetCount;
      physicalTableCount += expectedTableCount;
    }
    if (seen.size !== 3 || datasetCount !== 21 || physicalTableCount !== 19) {
      fail("physical-probe-invalid");
    }
    return report as unknown as OrganizationReconciliationDevelopPhysicalProbeReport;
  } catch (error) {
    if (error instanceof OrganizationReconciliationDevelopRuntimeCertificateError) throw error;
    fail("physical-probe-invalid");
  }
}

function deploymentMatchesPolicy(
  deployment: OrganizationReconciliationDevelopDeploymentEvidence,
  policy: OrganizationReconciliationTrustPolicy,
  buildRevision: string
): boolean {
  if (deployment.buildRevision !== buildRevision || policy.requiredCollectors.length !== 1) return false;
  const deployedByKey = new Map(deployment.signers.map((signer) => [signer.keyId, signer]));
  return policy.requiredCollectors.every((collector) => {
    const deployed = deployedByKey.get(collector.keyId);
    return deployed !== undefined && collector.buildRevision === buildRevision &&
      deployed.collectorId === collector.collectorId && deployed.nodeId === collector.nodeId &&
      deployed.publicKeySha256 === collector.publicKeySha256;
  }) && deployedByKey.size === 1;
}

function sharedAttestedAt(bundle: OrganizationReconciliationAttestationBundle): string {
  const issuedAt = new Set(bundle.attestations.map((entry) => entry.payload.issuedAt));
  if (bundle.attestations.length !== 1 || issuedAt.size !== 1) fail("historical-replay-invalid");
  const value = bundle.attestations[0]?.payload.issuedAt;
  canonicalTime(value);
  return value as string;
}

function parseCertificateBytes(
  bytes: Buffer
): OrganizationReconciliationDevelopRuntimeVerificationCertificate {
  return parseCertificateCandidate(parseJsonBytes(bytes, MAX_PUBLIC_ARTIFACT_BYTES));
}

function parseCertificateCandidate(
  candidate: unknown
): OrganizationReconciliationDevelopRuntimeVerificationCertificate {
  try {
    const canonical = canonicalizeOrganizationReconciliationEvidenceValue(candidate);
    const root = exactRecord(canonical, [
      "buildRevision", "certificateSha256", "collection", "contract", "deployment", "environment",
      "mode", "outcome", "physicalProbe", "provenance", "raw", "safety", "scope", "task",
      "verification"
    ]);
    if (root.contract !== ORGANIZATION_RECONCILIATION_DEVELOP_RUNTIME_VERIFICATION_CERTIFICATE_CONTRACT ||
      root.task !== "7.2" || root.environment !== "xrteeth-develop" || root.mode !== "read-only" ||
      root.scope !== "full-range" || root.outcome !== "completed" ||
      typeof root.buildRevision !== "string" || !FULL_REVISION.test(root.buildRevision) ||
      typeof root.certificateSha256 !== "string" || !validSha(root.certificateSha256)) {
      fail("certificate-invalid");
    }
    validateCertificateStructure(root);
    const { certificateSha256, ...core } = root;
    if (!safeDigestEqual(certificateSha256 as string, domainJsonSha256(CERTIFICATE_HASH_DOMAIN, core))) {
      fail("certificate-invalid");
    }
    return canonical as unknown as OrganizationReconciliationDevelopRuntimeVerificationCertificate;
  } catch (error) {
    if (error instanceof OrganizationReconciliationDevelopRuntimeCertificateError) throw error;
    fail("certificate-invalid");
  }
}

function validateCertificateStructure(
  root: Readonly<Record<string, OrganizationReconciliationEvidenceJsonValue>>
): void {
  const raw = exactRecord(root.raw, [
    "contract", "signedEvidenceSha256", "transientRawLocator", "verificationScope",
    "wrapperDataCertified"
  ]);
  const transientRawLocator = exactRecord(raw.transientRawLocator, ["sourceFileSha256"]);
  const provenance = exactRecord(root.provenance, [
    "attestationBundleSha256", "attestations", "attestedAt", "contract",
    "deploymentEvidenceSha256", "replayMode", "requiredAttestationCount",
    "trustPolicySha256", "verifiedAttestationCount"
  ]);
  const deployment = exactRecord(root.deployment, [
    "contract", "evidenceSha256", "executorBindingSha256", "physicalProbeSha256",
    "physicalIndependenceVerified", "releaseImageDigest", "signerCount", "signerSetSha256",
    "topologyObservationSha256"
  ]);
  const collection = exactRecord(root.collection, [
    "cursorChainCount", "cursorChains", "logicalSnapshotIdSha256", "operationEvidenceSha256",
    "operationManifestSha256", "parentLineageManifestSha256", "semanticRegistrySha256",
    "sourceCatalogSha256", "windowEndedAt", "windowIdSha256", "windowStartedAt"
  ]);
  const physical = exactRecord(root.physicalProbe, [
    "completedProbePassCount", "componentCount", "contract", "datasetCount", "derivedDatasetCount",
    "passed", "physicalCatalogSha256", "physicalTableCount", "reportFileSha256",
    "sourceCatalogSha256", "statementCatalogSha256"
  ]);
  const verification = exactRecord(root.verification, [
    "allowedCoverageBlockerCodeSha256", "allowedCoverageBlockerCount", "mismatchCount",
    "reportHash", "reportSha256", "severity", "surfaces", "verifiedSurfaceCount"
  ]);
  const safety = exactRecord(root.safety, [
    "blocksDualWrite", "physicalIndependenceVerified", "productionPromotionAllowed",
    "productionReady", "runtimeSafetyGatePassed", "writeSideEffects"
  ]);
  if (
    raw.contract !== ORGANIZATION_RECONCILIATION_DEVELOP_FULL_RANGE_CONTRACT ||
    raw.verificationScope !== "signed-reconciliation-input-only" ||
    raw.wrapperDataCertified !== false || !validSha(raw.signedEvidenceSha256) ||
    !validSha(transientRawLocator.sourceFileSha256) ||
    provenance.contract !== ORGANIZATION_RECONCILIATION_PROVENANCE_CONTRACT ||
    !validSha(provenance.trustPolicySha256) || !validSha(provenance.deploymentEvidenceSha256) ||
    !validSha(provenance.attestationBundleSha256) || provenance.requiredAttestationCount !== 1 ||
    provenance.verifiedAttestationCount !== 1 ||
    provenance.replayMode !== "historical-at-shared-signed-issued-at" ||
    deployment.contract !== "iam-organization-reconciliation-xrteeth-develop-deployment-evidence/v2" ||
    typeof deployment.releaseImageDigest !== "string" || !IMAGE_DIGEST.test(deployment.releaseImageDigest) ||
    !validSha(deployment.evidenceSha256) || !validSha(deployment.topologyObservationSha256) ||
    !validSha(deployment.physicalProbeSha256) || !validSha(deployment.executorBindingSha256) ||
    !validSha(deployment.signerSetSha256) || deployment.signerCount !== 1 ||
    deployment.physicalIndependenceVerified !== false ||
    deployment.evidenceSha256 !== provenance.deploymentEvidenceSha256 ||
    collection.cursorChainCount !== 21 || !validSha(collection.sourceCatalogSha256) ||
    !validSha(collection.semanticRegistrySha256) || !validSha(collection.logicalSnapshotIdSha256) ||
    !validSha(collection.windowIdSha256) || !validSha(collection.operationEvidenceSha256) ||
    !validSha(collection.operationManifestSha256) || !validSha(collection.parentLineageManifestSha256) ||
    physical.contract !== ORGANIZATION_RECONCILIATION_DEVELOP_PHYSICAL_PROBE_CONTRACT ||
    !validSha(physical.reportFileSha256) || !validSha(physical.sourceCatalogSha256) ||
    !validSha(physical.statementCatalogSha256) || !validSha(physical.physicalCatalogSha256) ||
    physical.componentCount !== 3 || physical.datasetCount !== 21 || physical.physicalTableCount !== 19 ||
    physical.derivedDatasetCount !== 1 || physical.completedProbePassCount !== 6 || physical.passed !== true ||
    physical.reportFileSha256 !== deployment.physicalProbeSha256 ||
    physical.sourceCatalogSha256 !== collection.sourceCatalogSha256 ||
    verification.verifiedSurfaceCount !== 8 || verification.mismatchCount !== 0 ||
    verification.allowedCoverageBlockerCount !== 1 ||
    !validSha(verification.allowedCoverageBlockerCodeSha256) ||
    typeof verification.reportHash !== "string" || !/^[a-f0-9]{24}$/.test(verification.reportHash) ||
    !validSha(verification.reportSha256) || safety.runtimeSafetyGatePassed !== false ||
    safety.blocksDualWrite !== true || safety.writeSideEffects !== "none" ||
    safety.physicalIndependenceVerified !== false || safety.productionReady !== false ||
    safety.productionPromotionAllowed !== false
  ) fail("certificate-invalid");
  const windowStart = canonicalTime(collection.windowStartedAt);
  const windowEnd = canonicalTime(collection.windowEndedAt);
  const attestedAt = canonicalTime(provenance.attestedAt);
  if (windowStart > windowEnd || windowEnd > attestedAt) fail("certificate-invalid");

  if (!Array.isArray(provenance.attestations) || provenance.attestations.length !== 1) {
    fail("certificate-invalid");
  }
  const attestationKeys = new Set<string>();
  for (const candidate of provenance.attestations) {
    const attestation = exactRecord(candidate, [
      "collectorIdSha256", "keyIdSha256", "nodeIdSha256", "payloadSha256",
      "publicKeySha256", "signatureSha256"
    ]);
    if ([
      attestation.collectorIdSha256, attestation.nodeIdSha256, attestation.keyIdSha256,
      attestation.publicKeySha256, attestation.payloadSha256, attestation.signatureSha256
    ].some((value) => !validSha(value)) ||
      attestationKeys.has(attestation.keyIdSha256 as string)) fail("certificate-invalid");
    attestationKeys.add(attestation.keyIdSha256 as string);
  }

  if (!Array.isArray(collection.cursorChains) || collection.cursorChains.length !== 21) {
    fail("certificate-invalid");
  }
  const cursorKeys = new Set<string>();
  for (const candidate of collection.cursorChains) {
    const cursor = exactRecord(candidate, [
      "complete", "componentIdSha256", "cursorChainSha256", "datasetIdSha256", "lineageSha256",
      "pageCount", "recordCount", "recordsCommitmentSha256"
    ]);
    const key = `${cursor.componentIdSha256}\u001f${cursor.datasetIdSha256}`;
    if (!validSha(cursor.componentIdSha256) || !validSha(cursor.datasetIdSha256) ||
      !validSha(cursor.recordsCommitmentSha256) || !validSha(cursor.cursorChainSha256) ||
      !validSha(cursor.lineageSha256) || !nonNegativeInteger(cursor.recordCount) ||
      !positiveInteger(cursor.pageCount) || cursor.complete !== true || cursorKeys.has(key)) {
      fail("certificate-invalid");
    }
    cursorKeys.add(key);
  }

  if (!Array.isArray(verification.surfaces) || verification.surfaces.length !== 8) {
    fail("certificate-invalid");
  }
  const surfaceKeys = new Set<string>();
  for (const candidate of verification.surfaces) {
    const surface = exactRecord(candidate, [
      "identityRecordCount", "legacyRecordCount", "paginationComplete", "surfaceSha256"
    ]);
    if (!validSha(surface.surfaceSha256) || !nonNegativeInteger(surface.legacyRecordCount) ||
      !nonNegativeInteger(surface.identityRecordCount) || surface.paginationComplete !== true ||
      surfaceKeys.has(surface.surfaceSha256 as string)) fail("certificate-invalid");
    surfaceKeys.add(surface.surfaceSha256 as string);
  }
  const severity = exactRecord(verification.severity, ["P0", "P1", "P2", "info"]);
  if (severity.P0 !== 0 || severity.P1 !== 0 || severity.P2 !== 0 ||
    !nonNegativeInteger(severity.info)) fail("certificate-invalid");
}

function parseCloseoutBytes(
  bytes: Buffer,
  certificate: OrganizationReconciliationDevelopRuntimeVerificationCertificate
): OrganizationReconciliationDevelopRuntimeVerificationCloseout {
  return parseCloseoutCandidate(parseJsonBytes(bytes, MAX_PUBLIC_ARTIFACT_BYTES), certificate);
}

function parseCloseoutCandidate(
  candidate: unknown,
  certificate: OrganizationReconciliationDevelopRuntimeVerificationCertificate
): OrganizationReconciliationDevelopRuntimeVerificationCloseout {
  try {
    const canonical = canonicalizeOrganizationReconciliationEvidenceValue(candidate);
    const root = exactRecord(canonical, [
      "attestations", "authoritativeCertificateSha256", "closeoutSha256", "contract", "datasets",
      "environment", "mismatchCount", "mode", "outcome", "physicalProbePasses", "safety", "scope",
      "severity", "surfaces", "task"
    ]);
    if (root.contract !== ORGANIZATION_RECONCILIATION_DEVELOP_RUNTIME_VERIFICATION_CLOSEOUT_CONTRACT ||
      root.task !== "7.2" || root.environment !== "xrteeth-develop" || root.mode !== "read-only" ||
      root.scope !== "full-range" || root.outcome !== "completed" ||
      root.authoritativeCertificateSha256 !== authoritativeCertificateProjectionSha256(certificate) ||
      typeof root.closeoutSha256 !== "string" || !validSha(root.closeoutSha256)) {
      fail("closeout-invalid");
    }
    const { closeoutSha256, ...core } = root;
    if (!safeDigestEqual(closeoutSha256 as string, domainJsonSha256(CLOSEOUT_HASH_DOMAIN, core)) ||
      !sameJson(canonical, createCloseout(certificate))) {
      fail("closeout-invalid");
    }
    return canonical as unknown as OrganizationReconciliationDevelopRuntimeVerificationCloseout;
  } catch (error) {
    if (error instanceof OrganizationReconciliationDevelopRuntimeCertificateError) throw error;
    fail("closeout-invalid");
  }
}

function captureProfile(candidate: unknown): OrganizationReconciliationTrustedProfile {
  try {
    return canonicalizeOrganizationReconciliationEvidenceValue(candidate) as unknown as
      OrganizationReconciliationTrustedProfile;
  } catch {
    fail("invalid-input");
  }
}

function captureBuffer(candidate: unknown, maximum: number): Buffer {
  if (!Buffer.isBuffer(candidate) || isProxy(candidate) ||
    candidate.byteLength < 2 || candidate.byteLength > maximum) fail("invalid-input");
  return Buffer.from(candidate);
}

function captureDate(candidate: unknown): Date {
  if (!(candidate instanceof Date) || isProxy(candidate) ||
    Object.getPrototypeOf(candidate) !== Date.prototype || !Number.isFinite(candidate.getTime())) {
    fail("invalid-input");
  }
  return new Date(candidate.getTime());
}

function parseJsonBytes(bytes: Buffer, maximum: number): OrganizationReconciliationEvidenceJsonValue {
  if (bytes.byteLength < 2 || bytes.byteLength > maximum) fail("invalid-json-artifact");
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes);
  } catch {
    fail("invalid-json-artifact");
  }
  if (text.startsWith("\uFEFF") || text.includes("\u0000")) fail("invalid-json-artifact");
  try {
    assertNoDuplicateJsonKeys(text);
    return canonicalizeOrganizationReconciliationEvidenceValue(JSON.parse(text) as unknown);
  } catch (error) {
    if (error instanceof OrganizationReconciliationDevelopRuntimeCertificateError) throw error;
    fail("invalid-json-artifact");
  }
}

/** Minimal structural JSON scanner used only to reject duplicate object keys. */
function assertNoDuplicateJsonKeys(text: string): void {
  let index = 0;
  let nodes = 0;
  const whitespace = (): void => {
    while (index < text.length && /[\u0009\u000A\u000D\u0020]/.test(text[index]!)) index += 1;
  };
  const string = (): string => {
    if (text[index] !== '"') throw new Error("json-string");
    const start = index;
    index += 1;
    while (index < text.length) {
      const character = text[index]!;
      if (character === '"') {
        index += 1;
        return JSON.parse(text.slice(start, index)) as string;
      }
      if (character === "\\") {
        index += 2;
        continue;
      }
      if (character < " ") throw new Error("json-control");
      index += 1;
    }
    throw new Error("json-string");
  };
  const value = (depth: number): void => {
    nodes += 1;
    if (nodes > 1_000_000 || depth > 64) throw new Error("json-bound");
    whitespace();
    const character = text[index];
    if (character === '"') {
      string();
      return;
    }
    if (character === "{") {
      index += 1;
      whitespace();
      const keys = new Set<string>();
      if (text[index] === "}") {
        index += 1;
        return;
      }
      while (index < text.length) {
        whitespace();
        const key = string();
        if (keys.has(key)) throw new Error("json-duplicate-key");
        keys.add(key);
        whitespace();
        if (text[index] !== ":") throw new Error("json-colon");
        index += 1;
        value(depth + 1);
        whitespace();
        if (text[index] === "}") {
          index += 1;
          return;
        }
        if (text[index] !== ",") throw new Error("json-comma");
        index += 1;
      }
      throw new Error("json-object");
    }
    if (character === "[") {
      index += 1;
      whitespace();
      if (text[index] === "]") {
        index += 1;
        return;
      }
      while (index < text.length) {
        value(depth + 1);
        whitespace();
        if (text[index] === "]") {
          index += 1;
          return;
        }
        if (text[index] !== ",") throw new Error("json-comma");
        index += 1;
      }
      throw new Error("json-array");
    }
    const rest = text.slice(index);
    const match = /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(rest);
    if (!match) throw new Error("json-value");
    index += match[0].length;
  };
  value(0);
  whitespace();
  if (index !== text.length) throw new Error("json-trailing");
}

function exactDataObject(
  candidate: unknown,
  expectedKeys: readonly string[],
  failureId: OrganizationReconciliationDevelopRuntimeCertificateFailureId
): Readonly<Record<string, unknown>> {
  if (candidate === null || typeof candidate !== "object" || Array.isArray(candidate) || isProxy(candidate) ||
    (Object.getPrototypeOf(candidate) !== Object.prototype && Object.getPrototypeOf(candidate) !== null) ||
    Object.getOwnPropertySymbols(candidate).length !== 0) fail(failureId);
  const descriptors = Object.getOwnPropertyDescriptors(candidate as object);
  if (!sameStringSet(Object.keys(descriptors), expectedKeys)) fail(failureId);
  const output: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const key of expectedKeys) {
    const descriptor = descriptors[key];
    if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) fail(failureId);
    output[key] = descriptor.value;
  }
  return Object.freeze(output);
}

function exactRecord(
  candidate: OrganizationReconciliationEvidenceJsonValue,
  expectedKeys: readonly string[]
): Readonly<Record<string, OrganizationReconciliationEvidenceJsonValue>> {
  if (candidate === null || typeof candidate !== "object" || Array.isArray(candidate)) {
    throw new Error("not-record");
  }
  const descriptors = Object.getOwnPropertyDescriptors(candidate);
  if (!sameStringSet(Object.keys(descriptors), expectedKeys)) throw new Error("record-keys");
  const output: Record<string, OrganizationReconciliationEvidenceJsonValue> = Object.create(null);
  for (const key of expectedKeys) {
    const descriptor = descriptors[key];
    if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) throw new Error("record-value");
    output[key] = descriptor.value as OrganizationReconciliationEvidenceJsonValue;
  }
  return Object.freeze(output);
}

function canonicalTime(candidate: unknown): number {
  if (typeof candidate !== "string") throw new Error("timestamp");
  const timestamp = Date.parse(candidate);
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== candidate) {
    throw new Error("timestamp");
  }
  return timestamp;
}

function requireBoundString(candidate: unknown): string {
  if (typeof candidate !== "string" || candidate.length < 1 || candidate.length > 1_024 ||
    candidate.normalize("NFC") !== candidate) throw new Error("string");
  return candidate;
}

function validSha(candidate: unknown): candidate is string {
  return typeof candidate === "string" && SHA256.test(candidate) && !/^0+$/.test(candidate);
}

function positiveInteger(candidate: unknown): candidate is number {
  return typeof candidate === "number" && Number.isSafeInteger(candidate) && candidate > 0;
}

function nonNegativeInteger(candidate: unknown): candidate is number {
  return typeof candidate === "number" && Number.isSafeInteger(candidate) && candidate >= 0;
}

function sameStringSet(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length &&
    [...left].sort(binaryCompare).join("\u001f") === [...right].sort(binaryCompare).join("\u001f");
}

function sameJson(left: unknown, right: unknown): boolean {
  try {
    return JSON.stringify(canonicalizeOrganizationReconciliationEvidenceValue(left)) ===
      JSON.stringify(canonicalizeOrganizationReconciliationEvidenceValue(right));
  } catch {
    return false;
  }
}

function fileSha256(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function opaqueSha256(scope: string, value: string): string {
  return createHash("sha256")
    .update(OPAQUE_HASH_DOMAIN, "utf8")
    .update(scope, "utf8")
    .update("\u001f", "utf8")
    .update(value, "utf8")
    .digest("hex");
}

function opaqueValueSha256(scope: string, value: unknown): string {
  return opaqueSha256(scope, JSON.stringify(canonicalizeOrganizationReconciliationEvidenceValue(value)));
}

function domainJsonSha256(domain: Buffer, value: unknown): string {
  const canonical = canonicalizeOrganizationReconciliationEvidenceValue(value);
  return createHash("sha256").update(domain).update(JSON.stringify(canonical), "utf8").digest("hex");
}

function safeDigestEqual(left: string, right: string): boolean {
  if (!SHA256.test(left) || !SHA256.test(right)) return false;
  return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

function binaryCompare(left: string, right: string): number {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function fail(failureId: OrganizationReconciliationDevelopRuntimeCertificateFailureId): never {
  throw new OrganizationReconciliationDevelopRuntimeCertificateError(failureId);
}

function rethrow(error: unknown): never {
  if (error instanceof OrganizationReconciliationDevelopRuntimeCertificateError) throw error;
  throw new OrganizationReconciliationDevelopRuntimeCertificateError("invalid-input");
}
