import { createHash, createHmac, timingSafeEqual } from "node:crypto";

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
  "iam-organization-reconciliation-collector/v1";
export const ORGANIZATION_RECONCILIATION_COLLECTOR_CONTRACT_HASH = createHash("sha256")
  .update(ORGANIZATION_RECONCILIATION_COLLECTOR_CONTRACT)
  .digest("hex");

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
  /** A source-owned opaque version. It is only emitted as a digest. */
  readonly sourceVersion?: string | null;
  /** Only null means that the supplied page set is complete. */
  readonly nextCursor?: string | null;
  readonly collection?: OrganizationReconciliationPageCollection;
}

export interface ReconciliationPair<T> {
  readonly legacy?: ReconciliationPage<T>;
  readonly identity?: ReconciliationPage<T>;
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

export interface OrganizationReconciliationCollectionEnvelope {
  readonly collectorContract: typeof ORGANIZATION_RECONCILIATION_COLLECTOR_CONTRACT;
  readonly collectorContractHash: string;
  /** Per-run high-entropy value used as the HMAC key; it is never emitted raw. */
  readonly evidenceNonce: string;
  readonly logicalSnapshotId: string;
  readonly windowId: string;
  readonly windowStartedAt: string;
  readonly windowEndedAt: string;
  readonly legacy: {
    readonly sourceVersion: string;
    readonly snapshotId: string;
  };
  readonly identity: {
    readonly sourceVersion: string;
    readonly snapshotId: string;
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
    | "evidence-nonce-invalid"
    | "logical-snapshot-invalid"
    | "collection-window-invalid"
    | "source-revision-mismatch"
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
    | "cross-surface-reference-invalid";
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
  readonly assuranceScope: "collector-envelope-self-consistency";
  readonly externalProvenanceRequired: true;
  readonly comparisonPolicy: "pairwise-no-union";
  /** True only when the caller-supplied envelope is internally consistent. */
  readonly staticChecksPassed: boolean;
  readonly severity: Readonly<Record<OrganizationReconciliationSeverity, number>>;
  readonly findings: readonly OrganizationReconciliationFinding[];
  readonly coverage: readonly OrganizationReconciliationSurfaceCoverage[];
  readonly coverageBlockers: readonly OrganizationReconciliationCoverageBlocker[];
  readonly safetyGate: {
    readonly passed: boolean;
    readonly blocksDualWrite: boolean;
    readonly coverageComplete: boolean;
    readonly p0Blocks: true;
    readonly p1Blocks: true;
    readonly p2Classified: true;
    readonly unionForbidden: true;
    readonly externalProvenanceVerified: false;
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
  input: OrganizationReconciliationInput
): OrganizationReconciliationReport {
  const accumulator: ValidationAccumulator = {
    findings: [],
    blockers: [],
    coverage: [],
    collectionEnvelope: input.collectionEnvelope,
    evidenceNonce: validEvidenceNonce(input.collectionEnvelope?.evidenceNonce)
      ? input.collectionEnvelope.evidenceNonce
      : "invalid-evidence-nonce"
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
  // This offline validator has no trusted collector key or attestation verifier.
  // No field in the caller-controlled JSON may promote self-consistent evidence.
  blockedReasons.push("external-provenance-required");
  const reportCore = {
    severity,
    findings: accumulator.findings,
    coverage: accumulator.coverage,
    coverageBlockers: accumulator.blockers,
    comparisonPolicy: "pairwise-no-union" as const
  };
  return {
    dryRun: true,
    writeSideEffects: "none",
    evidencePolicy: "hash-only",
    assuranceScope: "collector-envelope-self-consistency",
    externalProvenanceRequired: true,
    staticChecksPassed,
    ...reportCore,
    safetyGate: {
      passed: false,
      blocksDualWrite: true,
      coverageComplete,
      p0Blocks: true,
      p1Blocks: true,
      p2Classified: true,
      unionForbidden: true,
      externalProvenanceVerified: false,
      blockedReasons
    },
    reportHash: evidenceHash(accumulator, reportCore)
  };
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
  if (envelope.legacy.sourceVersion !== envelope.identity.sourceVersion) {
    block("source-revision-mismatch");
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
