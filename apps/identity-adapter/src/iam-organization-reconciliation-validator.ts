import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import {
  createOrganizationReconciliationProvenanceBinding,
  verifyOrganizationReconciliationProvenance,
  type OrganizationReconciliationProvenanceVerification,
  type OrganizationReconciliationTrustedProvenanceContext
} from "./iam-organization-reconciliation-provenance.js";

export type OrganizationReconciliationSeverity = "P0" | "P1" | "P2" | "info";
export type OrganizationDecision = "allow" | "deny";
export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | { readonly [key: string]: JsonValue } | readonly JsonValue[];

export type OrganizationReconciliationSurface =
  | "organization-directory"
  | "organization-mapping"
  | "membership"
  | "organization-scoped-role"
  | "plugin-binding"
  | "plugin-visibility"
  | "campus-context"
  | "effective-decision";

export const ORGANIZATION_RECONCILIATION_COLLECTOR_CONTRACT =
  "iam-organization-reconciliation-collector/v2";
export const ORGANIZATION_RECONCILIATION_COLLECTOR_CONTRACT_HASH = createHash("sha256")
  .update(ORGANIZATION_RECONCILIATION_COLLECTOR_CONTRACT)
  .digest("hex");
export const ORGANIZATION_RECONCILIATION_DECISION_DERIVATION_CONTRACT =
  "iam-organization-reconciliation-decision-universe/v2";
/**
 * Deliberate production blocker. A reviewed change may set this true only when
 * every authoritative Legacy/Identity/plugin/rule adapter is registered.
 */
export const ORGANIZATION_RECONCILIATION_REAL_SOURCE_ADAPTERS_READY = false as const;

export interface OrganizationReconciliationPageEvidence {
  readonly pageNumber: number;
  readonly requestCursor: string | null;
  readonly nextCursor: string | null;
  readonly recordOffset: number;
  readonly recordCount: number;
  /** HMAC-SHA256 over the ordered records in this page. */
  readonly recordsHash: string;
}

export interface OrganizationReconciliationPageCollection {
  readonly snapshotId: string;
  readonly firstCursor: string | null;
  readonly pageCount: number;
  readonly recordCount: number;
  /** HMAC-SHA256 over the complete ordered record array. */
  readonly recordsHash: string;
  readonly pages: readonly OrganizationReconciliationPageEvidence[];
}

export interface ReconciliationPage<T> {
  readonly records: readonly T[];
  /**
   * A source-owned opaque version. It is only emitted as a digest. Legacy and
   * Identity versions may differ; each must match its own envelope side.
   */
  readonly sourceVersion?: string | null;
  /** Only null means that the supplied page set is complete. */
  readonly nextCursor?: string | null;
  readonly collection?: OrganizationReconciliationPageCollection;
}

export interface ReconciliationPair<T> {
  readonly legacy?: ReconciliationPage<T>;
  readonly identity?: ReconciliationPage<T>;
}

export interface OrganizationReconciliationCollectedPage<T> {
  readonly requestCursor: string | null;
  readonly nextCursor: string | null;
  readonly records: readonly T[];
}

export interface OrganizationDirectoryRecord {
  readonly legacyOrganizationId: string | number;
  readonly name: string;
  /** Display-only directory metadata; a mismatch is classified as P2. */
  readonly title: string | null;
  readonly active: boolean;
}

export interface OrganizationMappingRecord {
  readonly legacyOrganizationId: string | number;
  readonly identityOrganizationId: string;
  readonly active: boolean;
}

export interface OrganizationMembershipRecord {
  readonly subjectRef: string;
  readonly legacyOrganizationId: string | number;
  readonly active: boolean;
}

export interface OrganizationScopedRoleRecord {
  readonly subjectRef: string;
  readonly legacyOrganizationId: string | number;
  readonly roleRef: string;
  readonly active: boolean;
}

export interface PluginBindingRecord {
  readonly pluginRef: string;
  readonly bindingRef: string;
  readonly organizationRef: string;
  readonly active: boolean;
}

export interface PluginVisibilityRecord {
  readonly subjectRef: string;
  readonly pluginRef: string;
  readonly organizationRef: string;
  readonly decision: OrganizationDecision;
}

export interface CampusContextRecord {
  readonly subjectRef: string;
  readonly campusRef: string;
  readonly organizationRef: string;
  readonly decision: OrganizationDecision;
}

export interface EffectiveOrganizationDecisionRecord {
  readonly subjectRef: string;
  readonly organizationRef: string;
  readonly resourceRef: string;
  readonly capabilityRef: string;
  readonly decision: OrganizationDecision;
}

export interface OrganizationReconciliationDecisionUniverseEvidence {
  readonly keyCount: number;
  /** HMAC-SHA256 over sorted canonical decision keys, including deny rows. */
  readonly keysHash: string;
  readonly derivationContract: typeof ORGANIZATION_RECONCILIATION_DECISION_DERIVATION_CONTRACT;
  /** Reviewed projection implementation; it must match the collector artifact. */
  readonly derivationBuildRevision: string;
  /** Strict surface-specific authoritative input dimensions. */
  readonly dimensions: Readonly<Record<string, OrganizationReconciliationDimensionEvidence>>;
}

export interface OrganizationReconciliationDimensionEvidence {
  readonly count: number;
  /** HMAC-SHA256 over the sorted complete canonical values for this dimension. */
  readonly hash: string;
}

export interface OrganizationReconciliationCollectionEnvelope {
  readonly collectorContract: typeof ORGANIZATION_RECONCILIATION_COLLECTOR_CONTRACT;
  readonly collectorContractHash: string;
  /** Exact reviewed collector binary revision; trusted policy pins this value. */
  readonly collectorBuildRevision: string;
  /** Per-run high-entropy value used as the HMAC key; it is never emitted raw. */
  readonly evidenceNonce: string;
  readonly logicalSnapshotId: string;
  readonly windowId: string;
  readonly windowStartedAt: string;
  readonly windowEndedAt: string;
  readonly legacy: {
    readonly sourceVersion: string;
    readonly snapshotId: string;
    readonly subjectUniverse: {
      readonly subjectCount: number;
      /** HMAC-SHA256 over the sorted complete subject reference set. */
      readonly subjectsHash: string;
    };
    readonly decisionUniverses: {
      readonly pluginVisibility: OrganizationReconciliationDecisionUniverseEvidence;
      readonly campusContexts: OrganizationReconciliationDecisionUniverseEvidence;
      readonly effectiveDecisions: OrganizationReconciliationDecisionUniverseEvidence;
    };
  };
  readonly identity: {
    readonly sourceVersion: string;
    readonly snapshotId: string;
    readonly subjectUniverse: {
      readonly subjectCount: number;
      /** HMAC-SHA256 over the sorted complete subject reference set. */
      readonly subjectsHash: string;
    };
    readonly decisionUniverses: {
      readonly pluginVisibility: OrganizationReconciliationDecisionUniverseEvidence;
      readonly campusContexts: OrganizationReconciliationDecisionUniverseEvidence;
      readonly effectiveDecisions: OrganizationReconciliationDecisionUniverseEvidence;
    };
  };
}

export interface OrganizationReconciliationInput {
  readonly collectionEnvelope?: OrganizationReconciliationCollectionEnvelope;
  readonly organizationDirectory?: ReconciliationPair<OrganizationDirectoryRecord>;
  readonly organizationMappings?: ReconciliationPair<OrganizationMappingRecord>;
  readonly memberships?: ReconciliationPair<OrganizationMembershipRecord>;
  readonly organizationScopedRoles?: ReconciliationPair<OrganizationScopedRoleRecord>;
  readonly pluginBindings?: ReconciliationPair<PluginBindingRecord>;
  readonly pluginVisibility?: ReconciliationPair<PluginVisibilityRecord>;
  readonly campusContexts?: ReconciliationPair<CampusContextRecord>;
  readonly effectiveDecisions?: ReconciliationPair<EffectiveOrganizationDecisionRecord>;
}

export interface OrganizationReconciliationFinding {
  readonly surface: OrganizationReconciliationSurface;
  readonly severity: OrganizationReconciliationSeverity;
  readonly reasonCode: string;
  readonly entityHash: string;
  readonly legacyValueHash?: string;
  readonly identityValueHash?: string;
}

export interface OrganizationReconciliationCoverageBlocker {
  readonly surface: OrganizationReconciliationSurface | "collection-envelope";
  readonly code:
    | "collection-envelope-missing"
    | "collector-contract-invalid"
    | "collector-build-revision-invalid"
    | "real-source-adapters-not-ready"
    | "evidence-nonce-invalid"
    | "logical-snapshot-invalid"
    | "collection-window-invalid"
    | "surface-missing"
    | "source-side-missing"
    | "source-version-missing"
    | "source-version-envelope-mismatch"
    | "snapshot-id-missing"
    | "snapshot-id-envelope-mismatch"
    | "page-envelope-missing"
    | "page-count-invalid"
    | "record-count-mismatch"
    | "cursor-chain-invalid"
    | "page-record-hash-mismatch"
    | "aggregate-record-hash-mismatch"
    | "pagination-state-missing"
    | "pagination-incomplete"
    | "duplicate-key"
    | "mapping-target-reused"
    | "cross-surface-reference-invalid"
    | "subject-universe-invalid"
    | "subject-universe-side-mismatch"
    | "decision-universe-invalid"
    | "decision-universe-derivation-invalid"
    | "decision-universe-side-mismatch"
    | "decision-universe-coverage-mismatch"
    | "decision-dimension-coverage-mismatch"
    | "decision-subject-universe-coverage-mismatch";
  readonly side?: "legacy" | "identity";
  readonly entityHash?: string;
}

export interface OrganizationReconciliationSurfaceCoverage {
  readonly surface: OrganizationReconciliationSurface;
  readonly legacyRecordCount: number;
  readonly identityRecordCount: number;
  readonly legacySourceVersionHash?: string;
  readonly identitySourceVersionHash?: string;
  readonly paginationComplete: boolean;
}

export interface OrganizationReconciliationReport {
  readonly dryRun: true;
  readonly writeSideEffects: "none";
  readonly evidencePolicy: "hash-only";
  readonly assuranceScope:
    | "collector-envelope-self-consistency"
    | "collector-envelope-with-trusted-external-attestation";
  readonly externalProvenanceRequired: true;
  readonly realSourceAdaptersReady: false;
  readonly comparisonPolicy: "pairwise-no-union";
  /** True only when the caller-supplied envelope is internally consistent. */
  readonly staticChecksPassed: boolean;
  readonly severity: Readonly<Record<OrganizationReconciliationSeverity, number>>;
  readonly findings: readonly OrganizationReconciliationFinding[];
  readonly coverage: readonly OrganizationReconciliationSurfaceCoverage[];
  readonly coverageBlockers: readonly OrganizationReconciliationCoverageBlocker[];
  readonly provenanceVerification: {
    readonly verified: boolean;
    readonly reasonCode: OrganizationReconciliationProvenanceVerification["code"];
    readonly requiredAttestationCount: number;
    readonly verifiedAttestationCount: number;
    readonly trustPolicyHash?: string;
    readonly trustProfileHash?: string;
    readonly environmentHash?: string;
  };
  readonly safetyGate: {
    readonly passed: boolean;
    readonly blocksDualWrite: boolean;
    readonly coverageComplete: boolean;
    readonly p0Blocks: true;
    readonly p1Blocks: true;
    readonly p2Classified: true;
    readonly unionForbidden: true;
    readonly externalProvenanceVerified: boolean;
    readonly blockedReasons: readonly (
      | "coverage-incomplete"
      | "p0-findings"
      | "p1-findings"
      | "external-provenance-required"
    )[];
  };
  readonly reportHash: string;
}

interface ValidationAccumulator {
  findings: OrganizationReconciliationFinding[];
  blockers: OrganizationReconciliationCoverageBlocker[];
  coverage: OrganizationReconciliationSurfaceCoverage[];
  evidenceNonce: string;
  collectionEnvelope?: OrganizationReconciliationCollectionEnvelope;
  provenanceVerification: OrganizationReconciliationProvenanceVerification;
}

export interface OrganizationReconciliationValidationOptions {
  /** Trusted context is separate from caller-controlled evidence and is cryptographically verified. */
  readonly trustedProvenance?: OrganizationReconciliationTrustedProvenanceContext;
}

interface ComparableRecordOptions<T> {
  key(record: T): JsonValue;
  semantic(record: T): JsonValue;
  display(record: T): JsonValue;
  semanticMismatchSeverity: "P0" | "P1";
  semanticMismatchReason: string;
}

interface DecisionRecordOptions<T> {
  key(record: T): JsonValue;
  decision(record: T): OrganizationDecision;
  context(record: T): JsonValue;
}

const REQUIRED_SURFACES: readonly OrganizationReconciliationSurface[] = [
  "organization-directory",
  "organization-mapping",
  "membership",
  "organization-scoped-role",
  "plugin-binding",
  "plugin-visibility",
  "campus-context",
  "effective-decision"
];

/**
 * Pure, deterministic validation over caller-supplied snapshots. It never reads
 * configuration, time, network, files, databases, or process state, and it
 * never returns raw subjects, organization IDs, names, bindings, or versions.
 */
export function validateOrganizationReconciliation(
  input: OrganizationReconciliationInput,
  options: OrganizationReconciliationValidationOptions = {}
): OrganizationReconciliationReport {
  const provenanceVerification = verifyTrustedProvenance(input, options.trustedProvenance);
  const accumulator: ValidationAccumulator = {
    findings: [],
    blockers: [],
    coverage: [],
    collectionEnvelope: input.collectionEnvelope,
    evidenceNonce: validEvidenceNonce(input.collectionEnvelope?.evidenceNonce)
      ? input.collectionEnvelope.evidenceNonce
      : "invalid-evidence-nonce",
    provenanceVerification
  };
  validateCollectionEnvelope(accumulator, input.collectionEnvelope);
  if (!validEvidenceNonce(input.collectionEnvelope?.evidenceNonce)) {
    addUntrustedCoverage(accumulator, input);
    return finalizeReport(accumulator);
  }

  compareRecords(
    accumulator,
    "organization-directory",
    input.organizationDirectory,
    {
      key: (record) => [record.legacyOrganizationId],
      semantic: (record) => ({ name: record.name, active: record.active }),
      display: (record) => ({ title: record.title }),
      semanticMismatchSeverity: "P1",
      semanticMismatchReason: "directory-semantic-mismatch"
    }
  );
  compareRecords(
    accumulator,
    "organization-mapping",
    input.organizationMappings,
    {
      key: (record) => [record.legacyOrganizationId],
      semantic: (record) => ({ identityOrganizationId: record.identityOrganizationId, active: record.active }),
      display: () => null,
      semanticMismatchSeverity: "P0",
      semanticMismatchReason: "organization-id-mapping-mismatch"
    }
  );
  validateMappingUniqueness(accumulator, input.organizationMappings);
  compareRecords(
    accumulator,
    "membership",
    input.memberships,
    {
      key: (record) => [record.subjectRef, record.legacyOrganizationId],
      semantic: (record) => ({ active: record.active }),
      display: () => null,
      semanticMismatchSeverity: "P1",
      semanticMismatchReason: "membership-state-mismatch"
    }
  );
  compareRecords(
    accumulator,
    "organization-scoped-role",
    input.organizationScopedRoles,
    {
      key: (record) => [record.subjectRef, record.legacyOrganizationId, record.roleRef],
      semantic: (record) => ({ active: record.active }),
      display: () => null,
      semanticMismatchSeverity: "P1",
      semanticMismatchReason: "organization-scoped-role-state-mismatch"
    }
  );
  compareRecords(
    accumulator,
    "plugin-binding",
    input.pluginBindings,
    {
      key: (record) => [record.pluginRef, record.bindingRef],
      semantic: (record) => ({ organizationRef: record.organizationRef, active: record.active }),
      display: () => null,
      semanticMismatchSeverity: "P0",
      semanticMismatchReason: "plugin-binding-scope-mismatch"
    }
  );
  compareDecisions(
    accumulator,
    "plugin-visibility",
    input.pluginVisibility,
    {
      key: (record) => [record.subjectRef, record.pluginRef, record.organizationRef],
      decision: (record) => record.decision,
      context: () => null
    }
  );
  compareDecisions(
    accumulator,
    "campus-context",
    input.campusContexts,
    {
      key: (record) => [record.subjectRef, record.campusRef],
      decision: (record) => record.decision,
      context: (record) => ({ organizationRef: record.organizationRef })
    }
  );
  compareDecisions(
    accumulator,
    "effective-decision",
    input.effectiveDecisions,
    {
      key: (record) => [record.subjectRef, record.organizationRef, record.resourceRef, record.capabilityRef],
      decision: (record) => record.decision,
      context: () => null
    }
  );
  validateCrossSurfaceReferences(accumulator, input);
  validateDecisionUniverseCoverage(accumulator, input);

  return finalizeReport(accumulator);
}

function finalizeReport(accumulator: ValidationAccumulator): OrganizationReconciliationReport {
  accumulator.findings.sort(compareFinding);
  accumulator.blockers.sort(compareBlocker);
  accumulator.coverage.sort((left, right) => left.surface.localeCompare(right.surface));

  const severity: Record<OrganizationReconciliationSeverity, number> = { P0: 0, P1: 0, P2: 0, info: 0 };
  for (const finding of accumulator.findings) severity[finding.severity] += 1;
  const coverageComplete = accumulator.blockers.length === 0;
  const blockedReasons: (
    | "coverage-incomplete"
    | "p0-findings"
    | "p1-findings"
    | "external-provenance-required"
  )[] = [];
  if (!coverageComplete) blockedReasons.push("coverage-incomplete");
  if (severity.P0 > 0) blockedReasons.push("p0-findings");
  if (severity.P1 > 0) blockedReasons.push("p1-findings");
  const staticChecksPassed = blockedReasons.length === 0;
  if (!accumulator.provenanceVerification.verified) blockedReasons.push("external-provenance-required");
  const provenanceVerification = {
    verified: accumulator.provenanceVerification.verified,
    reasonCode: accumulator.provenanceVerification.code,
    requiredAttestationCount: accumulator.provenanceVerification.requiredAttestationCount,
    verifiedAttestationCount: accumulator.provenanceVerification.verifiedAttestationCount,
    ...(accumulator.provenanceVerification.trustPolicySha256
      ? { trustPolicyHash: evidenceHash(accumulator, accumulator.provenanceVerification.trustPolicySha256) }
      : {}),
    ...(accumulator.provenanceVerification.trustProfileId
      ? { trustProfileHash: evidenceHash(accumulator, accumulator.provenanceVerification.trustProfileId) }
      : {}),
    ...(accumulator.provenanceVerification.environment
      ? { environmentHash: evidenceHash(accumulator, accumulator.provenanceVerification.environment) }
      : {})
  };
  const reportCore = {
    severity,
    findings: accumulator.findings,
    coverage: accumulator.coverage,
    coverageBlockers: accumulator.blockers,
    provenanceVerification,
    comparisonPolicy: "pairwise-no-union" as const
  };
  const passed = staticChecksPassed && accumulator.provenanceVerification.verified;
  return {
    dryRun: true,
    writeSideEffects: "none",
    evidencePolicy: "hash-only",
    assuranceScope: accumulator.provenanceVerification.verified
      ? "collector-envelope-with-trusted-external-attestation"
      : "collector-envelope-self-consistency",
    externalProvenanceRequired: true,
    realSourceAdaptersReady: ORGANIZATION_RECONCILIATION_REAL_SOURCE_ADAPTERS_READY,
    staticChecksPassed,
    ...reportCore,
    safetyGate: {
      passed,
      blocksDualWrite: !passed,
      coverageComplete,
      p0Blocks: true,
      p1Blocks: true,
      p2Classified: true,
      unionForbidden: true,
      externalProvenanceVerified: accumulator.provenanceVerification.verified,
      blockedReasons
    },
    reportHash: evidenceHash(accumulator, reportCore)
  };
}

function verifyTrustedProvenance(
  input: OrganizationReconciliationInput,
  context: OrganizationReconciliationTrustedProvenanceContext | undefined
): OrganizationReconciliationProvenanceVerification {
  if (!context) return verifyOrganizationReconciliationProvenance(undefined, undefined);
  const envelope = input.collectionEnvelope;
  if (!envelope) return verifyOrganizationReconciliationProvenance(undefined, context);
  try {
    const binding = createOrganizationReconciliationProvenanceBinding(
      input,
      envelope.collectorContractHash,
      envelope.collectorBuildRevision,
      envelope.logicalSnapshotId,
      envelope.windowId,
      envelope.windowStartedAt,
      envelope.windowEndedAt
    );
    return verifyOrganizationReconciliationProvenance(binding, context);
  } catch {
    return verifyOrganizationReconciliationProvenance(undefined, context);
  }
}

function addUntrustedCoverage(
  accumulator: ValidationAccumulator,
  input: OrganizationReconciliationInput
): void {
  const pairs: readonly [OrganizationReconciliationSurface, ReconciliationPair<unknown> | undefined][] = [
    ["organization-directory", input.organizationDirectory],
    ["organization-mapping", input.organizationMappings],
    ["membership", input.memberships],
    ["organization-scoped-role", input.organizationScopedRoles],
    ["plugin-binding", input.pluginBindings],
    ["plugin-visibility", input.pluginVisibility],
    ["campus-context", input.campusContexts],
    ["effective-decision", input.effectiveDecisions]
  ];
  for (const [surface, pair] of pairs) {
    accumulator.coverage.push({
      surface,
      legacyRecordCount: pair?.legacy?.records.length ?? 0,
      identityRecordCount: pair?.identity?.records.length ?? 0,
      paginationComplete: false
    });
  }
}

function compareRecords<T>(
  accumulator: ValidationAccumulator,
  surface: OrganizationReconciliationSurface,
  pair: ReconciliationPair<T> | undefined,
  options: ComparableRecordOptions<T>
): void {
  const validated = validateCoverage(accumulator, surface, pair, options.key);
  if (!validated) return;
  const { legacy, identity } = validated;
  const keys = new Set([...legacy.keys(), ...identity.keys()]);
  for (const key of [...keys].sort()) {
    const legacyRecord = legacy.get(key);
    const identityRecord = identity.get(key);
    const entityHash = evidenceHash(accumulator, [surface, key]);
    if (!legacyRecord && identityRecord) {
      addFinding(accumulator, surface, "P0", "identity-only-record", entityHash, undefined, options.semantic(identityRecord));
      continue;
    }
    if (legacyRecord && !identityRecord) {
      addFinding(accumulator, surface, "P1", "identity-record-missing", entityHash, options.semantic(legacyRecord), undefined);
      continue;
    }
    if (!legacyRecord || !identityRecord) continue;

    const legacySemantic = options.semantic(legacyRecord);
    const identitySemantic = options.semantic(identityRecord);
    const legacyDisplay = options.display(legacyRecord);
    const identityDisplay = options.display(identityRecord);
    const semanticAligned = stableSerialize(legacySemantic) === stableSerialize(identitySemantic);
    const displayAligned = stableSerialize(legacyDisplay) === stableSerialize(identityDisplay);
    if (!semanticAligned) {
      addFinding(
        accumulator,
        surface,
        options.semanticMismatchSeverity,
        options.semanticMismatchReason,
        entityHash,
        legacySemantic,
        identitySemantic
      );
    }
    if (!displayAligned) {
      addFinding(accumulator, surface, "P2", "display-only-mismatch", entityHash, legacyDisplay, identityDisplay);
    }
    if (semanticAligned && displayAligned) {
      addFinding(accumulator, surface, "info", "record-aligned", entityHash, legacySemantic, identitySemantic);
    }
  }
}

function compareDecisions<T>(
  accumulator: ValidationAccumulator,
  surface: OrganizationReconciliationSurface,
  pair: ReconciliationPair<T> | undefined,
  options: DecisionRecordOptions<T>
): void {
  const validated = validateCoverage(accumulator, surface, pair, options.key);
  if (!validated) return;
  const { legacy, identity } = validated;
  const keys = new Set([...legacy.keys(), ...identity.keys()]);
  for (const key of [...keys].sort()) {
    const legacyRecord = legacy.get(key);
    const identityRecord = identity.get(key);
    const entityHash = evidenceHash(accumulator, [surface, key]);
    if (!legacyRecord && identityRecord) {
      addFinding(accumulator, surface, "P0", "identity-only-decision", entityHash, undefined, options.decision(identityRecord));
      continue;
    }
    if (legacyRecord && !identityRecord) {
      addFinding(accumulator, surface, "P1", "identity-decision-missing", entityHash, options.decision(legacyRecord), undefined);
      continue;
    }
    if (!legacyRecord || !identityRecord) continue;

    const legacyDecision = options.decision(legacyRecord);
    const identityDecision = options.decision(identityRecord);
    const legacyContext = options.context(legacyRecord);
    const identityContext = options.context(identityRecord);
    let primaryMismatch = false;

    if (stableSerialize(legacyContext) !== stableSerialize(identityContext)) {
      primaryMismatch = true;
      addFinding(accumulator, surface, "P0", "authorization-context-mismatch", entityHash, legacyContext, identityContext);
    }
    if (legacyDecision === "deny" && identityDecision === "allow") {
      primaryMismatch = true;
      addFinding(accumulator, surface, "P0", "identity-allow-legacy-deny", entityHash, legacyDecision, identityDecision);
    } else if (legacyDecision === "allow" && identityDecision === "deny") {
      primaryMismatch = true;
      addFinding(accumulator, surface, "P1", "legacy-allow-identity-deny", entityHash, legacyDecision, identityDecision);
    }

    if (!primaryMismatch) {
      addFinding(accumulator, surface, "info", "decision-aligned", entityHash, legacyDecision, identityDecision);
    }
  }
}

function validateCoverage<T>(
  accumulator: ValidationAccumulator,
  surface: OrganizationReconciliationSurface,
  pair: ReconciliationPair<T> | undefined,
  keyFor: (record: T) => JsonValue
): { legacy: Map<string, T>; identity: Map<string, T> } | null {
  if (!pair) {
    accumulator.blockers.push({ surface, code: "surface-missing" });
    accumulator.coverage.push({
      surface,
      legacyRecordCount: 0,
      identityRecordCount: 0,
      paginationComplete: false
    });
    return null;
  }
  const legacy = pair.legacy;
  const identity = pair.identity;
  if (!legacy) accumulator.blockers.push({ surface, code: "source-side-missing", side: "legacy" });
  if (!identity) accumulator.blockers.push({ surface, code: "source-side-missing", side: "identity" });
  if (!legacy || !identity) {
    accumulator.coverage.push({
      surface,
      legacyRecordCount: legacy?.records.length ?? 0,
      identityRecordCount: identity?.records.length ?? 0,
      legacySourceVersionHash: versionHash(accumulator, legacy?.sourceVersion),
      identitySourceVersionHash: versionHash(accumulator, identity?.sourceVersion),
      paginationComplete: false
    });
    return null;
  }

  // Evaluate both sides even when the first side is incomplete so the caller
  // receives the complete blocker set in one pure validation pass.
  const legacyPageComplete = validatePageCoverage(accumulator, surface, "legacy", legacy);
  const identityPageComplete = validatePageCoverage(accumulator, surface, "identity", identity);
  const paginationComplete = legacyPageComplete && identityPageComplete;
  accumulator.coverage.push({
    surface,
    legacyRecordCount: legacy.records.length,
    identityRecordCount: identity.records.length,
    legacySourceVersionHash: versionHash(accumulator, legacy.sourceVersion),
    identitySourceVersionHash: versionHash(accumulator, identity.sourceVersion),
    paginationComplete
  });

  if (
    hasVersion(legacy.sourceVersion) &&
    hasVersion(identity.sourceVersion) &&
    legacy.sourceVersion === identity.sourceVersion
  ) {
    addFinding(
      accumulator,
      surface,
      "info",
      "source-version-aligned",
      evidenceHash(accumulator, [surface, "source-version"]),
      legacy.sourceVersion,
      identity.sourceVersion
    );
  }

  const legacyIndex = indexRecords(accumulator, surface, "legacy", legacy.records, keyFor);
  const identityIndex = indexRecords(accumulator, surface, "identity", identity.records, keyFor);
  return { legacy: legacyIndex, identity: identityIndex };
}

function validatePageCoverage<T>(
  accumulator: ValidationAccumulator,
  surface: OrganizationReconciliationSurface,
  side: "legacy" | "identity",
  page: ReconciliationPage<T>
): boolean {
  let complete = true;
  const block = (code: OrganizationReconciliationCoverageBlocker["code"]): void => {
    accumulator.blockers.push({ surface, code, side });
    complete = false;
  };
  if (!hasVersion(page.sourceVersion)) {
    block("source-version-missing");
  } else if (
    accumulator.collectionEnvelope &&
    page.sourceVersion !== accumulator.collectionEnvelope[side].sourceVersion
  ) {
    block("source-version-envelope-mismatch");
  }
  if (!("nextCursor" in page)) {
    block("pagination-state-missing");
  } else if (!isTerminalCursor(page.nextCursor)) {
    block("pagination-incomplete");
  }

  const collection = page.collection;
  if (!collection) {
    block("page-envelope-missing");
    return false;
  }
  if (!hasVersion(collection.snapshotId)) {
    block("snapshot-id-missing");
  } else if (
    accumulator.collectionEnvelope &&
    collection.snapshotId !== accumulator.collectionEnvelope[side].snapshotId
  ) {
    block("snapshot-id-envelope-mismatch");
  }
  if (!Number.isSafeInteger(collection.pageCount) || collection.pageCount < 1 || collection.pages.length !== collection.pageCount) {
    block("page-count-invalid");
  }
  if (
    !Number.isSafeInteger(collection.recordCount) ||
    collection.recordCount < 0 ||
    collection.recordCount !== page.records.length
  ) {
    block("record-count-mismatch");
  }
  if (!isTerminalCursor(collection.firstCursor)) {
    block("cursor-chain-invalid");
  }

  let expectedOffset = 0;
  let expectedRequestCursor: string | null = collection.firstCursor;
  const observedCursors = new Set<string>();
  for (let index = 0; index < collection.pages.length; index += 1) {
    const pageEvidence = collection.pages[index]!;
    const isLast = index === collection.pages.length - 1;
    const cursorValid = pageEvidence.requestCursor === expectedRequestCursor &&
      (index === 0 ? isTerminalCursor(pageEvidence.requestCursor) : isContinuationCursor(pageEvidence.requestCursor)) &&
      (isLast ? isTerminalCursor(pageEvidence.nextCursor) : isContinuationCursor(pageEvidence.nextCursor));
    if (!cursorValid || pageEvidence.pageNumber !== index + 1 || pageEvidence.recordOffset !== expectedOffset) {
      block("cursor-chain-invalid");
    }
    if (!Number.isSafeInteger(pageEvidence.recordCount) || pageEvidence.recordCount < 0) {
      block("record-count-mismatch");
      continue;
    }
    const pageRecords = page.records.slice(pageEvidence.recordOffset, pageEvidence.recordOffset + pageEvidence.recordCount);
    if (pageRecords.length !== pageEvidence.recordCount) {
      block("record-count-mismatch");
    }
    if (!hashesEqual(
      pageEvidence.recordsHash,
      createOrganizationReconciliationEvidenceHash(accumulator.evidenceNonce, pageRecords as JsonValue)
    )) {
      block("page-record-hash-mismatch");
    }
    if (isContinuationCursor(pageEvidence.nextCursor)) {
      if (observedCursors.has(pageEvidence.nextCursor)) block("cursor-chain-invalid");
      observedCursors.add(pageEvidence.nextCursor);
    }
    expectedOffset += pageEvidence.recordCount;
    expectedRequestCursor = pageEvidence.nextCursor;
  }
  if (expectedOffset !== page.records.length) block("record-count-mismatch");
  if (collection.pages.length > 0 && collection.pages.at(-1)!.nextCursor !== page.nextCursor) {
    block("cursor-chain-invalid");
  }
  if (!hashesEqual(
    collection.recordsHash,
    createOrganizationReconciliationEvidenceHash(accumulator.evidenceNonce, page.records as JsonValue)
  )) {
    block("aggregate-record-hash-mismatch");
  }
  return complete;
}

function validateCollectionEnvelope(
  accumulator: ValidationAccumulator,
  envelope: OrganizationReconciliationCollectionEnvelope | undefined
): void {
  const block = (code: OrganizationReconciliationCoverageBlocker["code"]): void => {
    accumulator.blockers.push({ surface: "collection-envelope", code });
  };
  if (!ORGANIZATION_RECONCILIATION_REAL_SOURCE_ADAPTERS_READY) {
    block("real-source-adapters-not-ready");
  }
  if (!envelope) {
    block("collection-envelope-missing");
    block("evidence-nonce-invalid");
    return;
  }
  if (
    envelope.collectorContract !== ORGANIZATION_RECONCILIATION_COLLECTOR_CONTRACT ||
    !hashesEqual(envelope.collectorContractHash, ORGANIZATION_RECONCILIATION_COLLECTOR_CONTRACT_HASH)
  ) {
    block("collector-contract-invalid");
  }
  if (!/^[a-f0-9]{40}$/.test(envelope.collectorBuildRevision)) {
    block("collector-build-revision-invalid");
  }
  if (!validEvidenceNonce(envelope.evidenceNonce)) block("evidence-nonce-invalid");
  if (!hasVersion(envelope.logicalSnapshotId) || !hasVersion(envelope.windowId)) {
    block("logical-snapshot-invalid");
  }
  const windowStart = Date.parse(envelope.windowStartedAt);
  const windowEnd = Date.parse(envelope.windowEndedAt);
  if (!Number.isFinite(windowStart) || !Number.isFinite(windowEnd) || windowStart > windowEnd) {
    block("collection-window-invalid");
  }
  if (
    !hasVersion(envelope.legacy.sourceVersion) ||
    !hasVersion(envelope.identity.sourceVersion) ||
    !hasVersion(envelope.legacy.snapshotId) ||
    !hasVersion(envelope.identity.snapshotId)
  ) {
    block("logical-snapshot-invalid");
  }
  for (const side of ["legacy", "identity"] as const) {
    const universe = envelope[side].subjectUniverse;
    if (
      !Number.isSafeInteger(universe.subjectCount) ||
      universe.subjectCount < 1 ||
      !/^[a-f0-9]{64}$/.test(universe.subjectsHash)
    ) {
      accumulator.blockers.push({ surface: "collection-envelope", code: "subject-universe-invalid", side });
    }
  }
  if (
    envelope.legacy.subjectUniverse.subjectCount !== envelope.identity.subjectUniverse.subjectCount ||
    !hashesEqual(
      envelope.legacy.subjectUniverse.subjectsHash,
      envelope.identity.subjectUniverse.subjectsHash
    )
  ) {
    block("subject-universe-side-mismatch");
  }
  const dimensionsByUniverse = {
    pluginVisibility: ["organizations", "plugins", "subjects"],
    campusContexts: ["campuses", "organizations", "subjects"],
    effectiveDecisions: ["capabilities", "organizations", "resources", "subjects"]
  } as const;
  for (const name of ["pluginVisibility", "campusContexts", "effectiveDecisions"] as const) {
    const requiredDimensions = [...dimensionsByUniverse[name]].sort();
    for (const side of ["legacy", "identity"] as const) {
      const universe = envelope[side].decisionUniverses[name];
      const actualDimensions = Object.keys(universe.dimensions).sort();
      let derivationInvalid =
        universe.derivationContract !== ORGANIZATION_RECONCILIATION_DECISION_DERIVATION_CONTRACT ||
        universe.derivationBuildRevision !== envelope.collectorBuildRevision ||
        stableSerialize(actualDimensions) !== stableSerialize(requiredDimensions);
      if (
        !Number.isSafeInteger(universe.keyCount) ||
        universe.keyCount < 0 ||
        !/^[a-f0-9]{64}$/.test(universe.keysHash)
      ) {
        accumulator.blockers.push({ surface: "collection-envelope", code: "decision-universe-invalid", side });
      }
      for (const dimensionName of requiredDimensions) {
        const dimension = universe.dimensions[dimensionName];
        if (
          !dimension ||
          !Number.isSafeInteger(dimension.count) ||
          dimension.count < 0 ||
          !/^[a-f0-9]{64}$/.test(dimension.hash)
        ) {
          derivationInvalid = true;
        }
      }
      const subjectDimension = universe.dimensions.subjects;
      if (
        !subjectDimension ||
        subjectDimension.count !== envelope[side].subjectUniverse.subjectCount ||
        !hashesEqual(subjectDimension.hash, envelope[side].subjectUniverse.subjectsHash)
      ) {
        derivationInvalid = true;
      }
      const nonSubjectDimensions = requiredDimensions
        .filter((dimensionName) => dimensionName !== "subjects")
        .map((dimensionName) => universe.dimensions[dimensionName]);
      const mustBeEmpty = nonSubjectDimensions.some((dimension) => dimension?.count === 0);
      if ((universe.keyCount === 0) !== mustBeEmpty) derivationInvalid = true;
      if (derivationInvalid) {
        accumulator.blockers.push({
          surface: "collection-envelope",
          code: "decision-universe-derivation-invalid",
          side
        });
      }
    }
    const legacy = envelope.legacy.decisionUniverses[name];
    const identity = envelope.identity.decisionUniverses[name];
    if (
      stableSerialize(legacy as unknown as JsonValue) !==
      stableSerialize(identity as unknown as JsonValue)
    ) {
      block("decision-universe-side-mismatch");
    }
  }
  // Heterogeneous sources do not share a native revision namespace. Each page
  // is bound to its own side above; logicalSnapshotId, the bounded window, and
  // trusted provenance attest that the two immutable snapshots belong to one
  // comparison run.
}

function validateDecisionUniverseCoverage(
  accumulator: ValidationAccumulator,
  input: OrganizationReconciliationInput
): void {
  const decisionSurfaces: readonly [
    OrganizationReconciliationSurface,
    "pluginVisibility" | "campusContexts" | "effectiveDecisions",
    ReconciliationPair<PluginVisibilityRecord | CampusContextRecord | EffectiveOrganizationDecisionRecord> | undefined,
    (record: PluginVisibilityRecord | CampusContextRecord | EffectiveOrganizationDecisionRecord) => JsonValue,
    (record: PluginVisibilityRecord | CampusContextRecord | EffectiveOrganizationDecisionRecord) => Readonly<Record<string, string>>
  ][] = [
    [
      "plugin-visibility",
      "pluginVisibility",
      input.pluginVisibility,
      (record) => {
        const value = record as PluginVisibilityRecord;
        return [value.subjectRef, value.pluginRef, value.organizationRef];
      },
      (record) => {
        const value = record as PluginVisibilityRecord;
        return { subjects: value.subjectRef, plugins: value.pluginRef, organizations: value.organizationRef };
      }
    ],
    [
      "campus-context",
      "campusContexts",
      input.campusContexts,
      (record) => {
        const value = record as CampusContextRecord;
        return [value.subjectRef, value.campusRef];
      },
      (record) => {
        const value = record as CampusContextRecord;
        return { subjects: value.subjectRef, campuses: value.campusRef, organizations: value.organizationRef };
      }
    ],
    [
      "effective-decision",
      "effectiveDecisions",
      input.effectiveDecisions,
      (record) => {
        const value = record as EffectiveOrganizationDecisionRecord;
        return [value.subjectRef, value.organizationRef, value.resourceRef, value.capabilityRef];
      },
      (record) => {
        const value = record as EffectiveOrganizationDecisionRecord;
        return {
          subjects: value.subjectRef,
          organizations: value.organizationRef,
          resources: value.resourceRef,
          capabilities: value.capabilityRef
        };
      }
    ]
  ];
  for (const side of ["legacy", "identity"] as const) {
    for (const [surface, universeName, pair, keyFor, dimensionsFor] of decisionSurfaces) {
      const universe = input.collectionEnvelope?.[side].decisionUniverses[universeName];
      if (!universe) continue;
      const page = pair?.[side];
      if (!page) continue;
      const keys = [...new Set(page.records.map((record) => stableSerialize(keyFor(record))))].sort();
      const keysHash = createOrganizationReconciliationEvidenceHash(
        accumulator.evidenceNonce,
        keys
      );
      if (keys.length !== universe.keyCount || !hashesEqual(universe.keysHash, keysHash)) {
        accumulator.blockers.push({ surface, code: "decision-universe-coverage-mismatch", side });
      }
      if (universe.keyCount > 0) {
        const dimensionValues = new Map<string, Set<string>>();
        for (const record of page.records) {
          for (const [dimensionName, value] of Object.entries(dimensionsFor(record))) {
            const values = dimensionValues.get(dimensionName) ?? new Set<string>();
            values.add(value);
            dimensionValues.set(dimensionName, values);
          }
        }
        for (const [dimensionName, dimension] of Object.entries(universe.dimensions)) {
          const values = [...(dimensionValues.get(dimensionName) ?? [])].sort();
          const hash = createOrganizationReconciliationEvidenceHash(accumulator.evidenceNonce, values);
          if (values.length !== dimension.count || !hashesEqual(hash, dimension.hash)) {
            accumulator.blockers.push({
              surface,
              code: "decision-dimension-coverage-mismatch",
              side
            });
            break;
          }
        }
        const subjects = [...new Set(page.records.map((record) => record.subjectRef))].sort();
        const subjectsHash = createOrganizationReconciliationEvidenceHash(
          accumulator.evidenceNonce,
          subjects
        );
        const subjectUniverse = input.collectionEnvelope?.[side].subjectUniverse;
        if (
          !subjectUniverse ||
          subjects.length !== subjectUniverse.subjectCount ||
          !hashesEqual(subjectsHash, subjectUniverse.subjectsHash)
        ) {
          accumulator.blockers.push({
            surface,
            code: "decision-subject-universe-coverage-mismatch",
            side
          });
        }
      }
    }
  }
}

function validateMappingUniqueness(
  accumulator: ValidationAccumulator,
  pair: ReconciliationPair<OrganizationMappingRecord> | undefined
): void {
  for (const side of ["legacy", "identity"] as const) {
    const page = pair?.[side];
    if (!page) continue;
    const targets = new Map<string, string>();
    for (const record of page.records) {
      const target = stableSerialize(record.identityOrganizationId);
      const legacyKey = stableSerialize(record.legacyOrganizationId);
      const existing = targets.get(target);
      if (existing !== undefined && existing !== legacyKey) {
        accumulator.blockers.push({
          surface: "organization-mapping",
          code: "mapping-target-reused",
          side,
          entityHash: evidenceHash(accumulator, ["organization-mapping-target", target])
        });
        continue;
      }
      targets.set(target, legacyKey);
    }
  }
}

function validateCrossSurfaceReferences(
  accumulator: ValidationAccumulator,
  input: OrganizationReconciliationInput
): void {
  for (const side of ["legacy", "identity"] as const) {
    const directories = input.organizationDirectory?.[side]?.records;
    const mappings = input.organizationMappings?.[side]?.records;
    const memberships = input.memberships?.[side]?.records;
    const roles = input.organizationScopedRoles?.[side]?.records;
    const bindings = input.pluginBindings?.[side]?.records;
    const visibility = input.pluginVisibility?.[side]?.records;
    const campuses = input.campusContexts?.[side]?.records;
    const decisions = input.effectiveDecisions?.[side]?.records;
    if (!directories || !mappings || !memberships || !roles || !bindings || !visibility || !campuses || !decisions) {
      continue;
    }

    const directoryById = new Map(directories.map((record) => [stableSerialize(record.legacyOrganizationId), record]));
    const directoryByName = new Map(directories.map((record) => [record.name, record]));
    const mappingById = new Map(mappings.map((record) => [stableSerialize(record.legacyOrganizationId), record]));
    const activeMemberships = new Set(
      memberships
        .filter((record) => record.active)
        .map((record) => stableSerialize([record.subjectRef, record.legacyOrganizationId]))
    );
    const invalid = (kind: string, value: JsonValue): void => {
      accumulator.blockers.push({
        surface: "organization-mapping",
        code: "cross-surface-reference-invalid",
        side,
        entityHash: evidenceHash(accumulator, [kind, value])
      });
    };
    const validActiveOrganizationId = (legacyOrganizationId: string | number): boolean => {
      const key = stableSerialize(legacyOrganizationId);
      return directoryById.get(key)?.active === true && mappingById.get(key)?.active === true;
    };
    const validActiveOrganizationName = (organizationRef: string): boolean =>
      directoryByName.get(organizationRef)?.active === true;

    for (const directory of directories) {
      const key = stableSerialize(directory.legacyOrganizationId);
      const mapping = mappingById.get(key);
      if (directory.active && mapping?.active !== true) invalid("active-directory-without-active-mapping", key);
    }
    for (const mapping of mappings) {
      const key = stableSerialize(mapping.legacyOrganizationId);
      const directory = directoryById.get(key);
      if (mapping.active && directory?.active !== true) invalid("active-mapping-without-active-directory", key);
    }
    for (const membership of memberships) {
      if (membership.active && !validActiveOrganizationId(membership.legacyOrganizationId)) {
        invalid("active-membership-without-active-organization", [membership.subjectRef, membership.legacyOrganizationId]);
      }
    }
    for (const role of roles) {
      if (!role.active) continue;
      if (!validActiveOrganizationId(role.legacyOrganizationId)) {
        invalid("active-role-without-active-organization", [role.subjectRef, role.legacyOrganizationId, role.roleRef]);
      }
      if (!activeMemberships.has(stableSerialize([role.subjectRef, role.legacyOrganizationId]))) {
        invalid("active-role-without-active-membership", [role.subjectRef, role.legacyOrganizationId, role.roleRef]);
      }
    }
    for (const binding of bindings) {
      if (binding.active && !validActiveOrganizationName(binding.organizationRef)) {
        invalid("active-plugin-binding-without-active-organization", [binding.pluginRef, binding.organizationRef]);
      }
    }
    for (const record of [...visibility, ...campuses, ...decisions]) {
      if (record.decision === "allow" && !validActiveOrganizationName(record.organizationRef)) {
        invalid("allow-without-active-organization", [record.subjectRef, record.organizationRef]);
      }
    }
  }
}

function isTerminalCursor(value: string | null | undefined): value is string | null {
  return value === null;
}

function isContinuationCursor(value: string | null | undefined): value is string {
  return typeof value === "string" && value.length > 0 && value.trim() === value;
}

function indexRecords<T>(
  accumulator: ValidationAccumulator,
  surface: OrganizationReconciliationSurface,
  side: "legacy" | "identity",
  records: readonly T[],
  keyFor: (record: T) => JsonValue
): Map<string, T> {
  const index = new Map<string, T>();
  for (const record of records) {
    const key = stableSerialize(keyFor(record));
    if (index.has(key)) {
      accumulator.blockers.push({
        surface,
        code: "duplicate-key",
        side,
        entityHash: evidenceHash(accumulator, [surface, key])
      });
      continue;
    }
    index.set(key, record);
  }
  return index;
}

function addFinding(
  accumulator: ValidationAccumulator,
  surface: OrganizationReconciliationSurface,
  severity: OrganizationReconciliationSeverity,
  reasonCode: string,
  entityHash: string,
  legacyValue?: JsonValue,
  identityValue?: JsonValue
): void {
  accumulator.findings.push({
    surface,
    severity,
    reasonCode,
    entityHash,
    ...(legacyValue === undefined ? {} : { legacyValueHash: evidenceHash(accumulator, legacyValue) }),
    ...(identityValue === undefined ? {} : { identityValueHash: evidenceHash(accumulator, identityValue) })
  });
}

function hasVersion(value: string | null | undefined): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function versionHash(accumulator: ValidationAccumulator, value: string | null | undefined): string | undefined {
  return hasVersion(value) ? evidenceHash(accumulator, value) : undefined;
}

export function createOrganizationReconciliationEvidenceHash(
  evidenceNonce: string,
  value: JsonValue
): string {
  return createHmac("sha256", evidenceNonce)
    .update("iam-organization-reconciliation:v2\u001f")
    .update(stableSerialize(value))
    .digest("hex");
}

/**
 * Assembles a complete cursor chain from source-owned page results. It does no
 * I/O and refuses truncated, reordered, repeated, or non-terminal page sets.
 */
export function createOrganizationReconciliationCollectedSnapshot<T>(
  evidenceNonce: string,
  sourceVersion: string,
  snapshotId: string,
  pages: readonly OrganizationReconciliationCollectedPage<T>[]
): ReconciliationPage<T> {
  if (!validEvidenceNonce(evidenceNonce)) throw new Error("A high-entropy evidence nonce is required.");
  if (!hasVersion(sourceVersion) || !hasVersion(snapshotId)) {
    throw new Error("Source version and snapshot ID are required.");
  }
  if (pages.length < 1 || pages.length > 10_000) throw new Error("A bounded, non-empty page chain is required.");

  const records: T[] = [];
  const evidence: OrganizationReconciliationPageEvidence[] = [];
  const observedContinuationCursors = new Set<string>();
  let expectedRequestCursor: string | null = null;
  for (let index = 0; index < pages.length; index += 1) {
    const page = pages[index]!;
    const isLast = index === pages.length - 1;
    if (
      page.requestCursor !== expectedRequestCursor ||
      (index === 0 ? page.requestCursor !== null : !isContinuationCursor(page.requestCursor)) ||
      (isLast ? page.nextCursor !== null : !isContinuationCursor(page.nextCursor))
    ) {
      throw new Error("Collected pages do not form one complete cursor chain.");
    }
    if (isContinuationCursor(page.nextCursor)) {
      if (observedContinuationCursors.has(page.nextCursor)) {
        throw new Error("Collected pages repeat a continuation cursor.");
      }
      observedContinuationCursors.add(page.nextCursor);
    }
    const recordOffset = records.length;
    records.push(...page.records);
    evidence.push({
      pageNumber: index + 1,
      requestCursor: page.requestCursor,
      nextCursor: page.nextCursor,
      recordOffset,
      recordCount: page.records.length,
      recordsHash: createOrganizationReconciliationEvidenceHash(evidenceNonce, page.records as JsonValue)
    });
    expectedRequestCursor = page.nextCursor;
  }

  return {
    records,
    sourceVersion,
    nextCursor: null,
    collection: {
      snapshotId,
      firstCursor: null,
      pageCount: pages.length,
      recordCount: records.length,
      recordsHash: createOrganizationReconciliationEvidenceHash(evidenceNonce, records as JsonValue),
      pages: evidence
    }
  };
}

function evidenceHash(accumulator: ValidationAccumulator, value: JsonValue | object): string {
  return createOrganizationReconciliationEvidenceHash(accumulator.evidenceNonce, value as JsonValue).slice(0, 24);
}

function validEvidenceNonce(value: string | undefined): value is string {
  return typeof value === "string" && /^[a-f0-9]{32,128}$/i.test(value);
}

function hashesEqual(actual: string | undefined, expected: string): boolean {
  if (typeof actual !== "string" || !/^[a-f0-9]{64}$/i.test(actual) || expected.length !== 64) return false;
  return timingSafeEqual(Buffer.from(actual.toLowerCase(), "hex"), Buffer.from(expected.toLowerCase(), "hex"));
}

function stableSerialize(value: JsonValue | undefined): string {
  if (value === undefined) return "null";
  if (value === null) return "null";
  if (typeof value === "string") return JSON.stringify(value)!;
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") return Number.isFinite(value) ? String(value) : "null";
  if (Array.isArray(value)) return `[${value.map((item) => stableSerialize(item)).join(",")}]`;
  const record = value as Readonly<Record<string, JsonValue | undefined>>;
  return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${stableSerialize(record[key])}`).join(",")}}`;
}

function compareFinding(left: OrganizationReconciliationFinding, right: OrganizationReconciliationFinding): number {
  return [left.surface, left.severity, left.reasonCode, left.entityHash].join("\u001f")
    .localeCompare([right.surface, right.severity, right.reasonCode, right.entityHash].join("\u001f"));
}

function compareBlocker(
  left: OrganizationReconciliationCoverageBlocker,
  right: OrganizationReconciliationCoverageBlocker
): number {
  return [left.surface, left.code, left.side ?? "", left.entityHash ?? ""].join("\u001f")
    .localeCompare([right.surface, right.code, right.side ?? "", right.entityHash ?? ""].join("\u001f"));
}

export const organizationReconciliationRequiredSurfaces = REQUIRED_SURFACES;
