import { isProxy } from "node:util/types";
import {
  ORGANIZATION_OWNER_DEVELOP_APPROVED_REGISTRY_CANDIDATE,
  ORGANIZATION_OWNER_DEVELOP_DECISION_CATALOGS
} from "./iam-organization-owner-semantic-registry.js";
import {
  canonicalizeOrganizationReconciliationEvidenceValue,
  createOrganizationReconciliationCompositeManifestForEvidence,
  type OrganizationReconciliationCompositeManifest,
  type OrganizationReconciliationOperationCompositeManifest,
  validateOrganizationReconciliationCompositeManifest,
  validateOrganizationReconciliationCompositeManifestEvidenceBinding,
  validateOrganizationReconciliationOperationCompositeManifestEvidenceBinding
} from "./iam-organization-reconciliation-component-manifest.js";
import {
  assertOrganizationReconciliationDatasetArtifactBelongsToRun,
  type OrganizationReconciliationDatasetLineageArtifact,
  type OrganizationReconciliationDatasetLineageRun
} from "./iam-organization-reconciliation-dataset-lineage.js";
import {
  ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG
} from "./iam-organization-reconciliation-develop-source-catalog.js";
import {
  assertIndependentOrganizationSurfaceProjections,
  createOrganizationSurfaceProjectionBinding,
  type IdentityOrganizationSurfaceProjection,
  type LegacyOrganizationSurfaceProjection,
  type OrganizationSurfaceProjectionBinding,
  type OrganizationSurfaceProjectionRecords
} from "./iam-organization-reconciliation-projector-contract.js";
import {
  ORGANIZATION_RECONCILIATION_PLATFORM_GLOBAL_CONTEXT_REF,
  ORGANIZATION_RECONCILIATION_PUBLIC_CONTEXT_REF,
  isCanonicalAuthorizationContext,
  isCanonicalLegacyOrganizationId,
  isCanonicalLegacyUserSubjectRef,
  isCanonicalOrganizationRef,
  isCanonicalPluginRef,
  isCanonicalReconciliationToken,
  canonicalLegacyOrganizationId,
  organizationRefForLegacyId,
  pluginRefForId,
  subjectRefForLegacyUserId
} from "./iam-organization-reconciliation-refs.js";
import {
  identityOrganizationIdForCanonicalLegacyId
} from "./iam-organization-reconciliation-pure-rules.js";
import {
  ORGANIZATION_RECONCILIATION_COLLECTOR_CONTRACT,
  ORGANIZATION_RECONCILIATION_COLLECTOR_CONTRACT_HASH,
  ORGANIZATION_RECONCILIATION_DECISION_DERIVATION_CONTRACT,
  createOrganizationReconciliationCollectedSnapshot,
  createOrganizationReconciliationEvidenceHash,
  type OrganizationReconciliationCollectionEnvelope,
  type OrganizationReconciliationDecisionUniverseEvidence,
  type OrganizationReconciliationOperationEvidence,
  type ReconciliationPair
} from "./iam-organization-reconciliation-validator.js";

export const ORGANIZATION_RECONCILIATION_DEVELOP_OPERATION_EVIDENCE_CONTRACT =
  "iam-organization-reconciliation-xrteeth-develop-operation-evidence-boundary/v3" as const;
export const ORGANIZATION_RECONCILIATION_DEVELOP_OPERATION_EVIDENCE_IMPLEMENTED = true as const;
export const ORGANIZATION_RECONCILIATION_DEVELOP_OPERATION_EVIDENCE_READY = false as const;

export const ORGANIZATION_RECONCILIATION_DEVELOP_OPERATION_EVIDENCE_SURFACES = Object.freeze([
  "organizationDirectory",
  "organizationMappings",
  "memberships",
  "organizationScopedRoles",
  "pluginBindings",
  "pluginVisibility",
  "campusContexts",
  "effectiveDecisions"
] as const satisfies readonly (keyof OrganizationSurfaceProjectionRecords)[]);

export type DevelopOperationEvidenceSurfaceName =
  (typeof ORGANIZATION_RECONCILIATION_DEVELOP_OPERATION_EVIDENCE_SURFACES)[number];

export const ORGANIZATION_RECONCILIATION_DEVELOP_OPERATION_EVIDENCE_BLOCKERS = Object.freeze([
  "dataset-lineage-catalog-caller-structured-untrusted",
  "develop-physical-schema-fingerprints-not-pinned",
  "develop-physical-source-attestation-not-recorded",
  "static-plugin-artifact-deployment-digest-not-attested",
  "independent-projector-artifact-provenance-not-attested",
  "production-operation-evidence-assembly-disabled",
  "runtime-pipeline-not-registered"
] as const);

export type DevelopOperationEvidenceBlocker =
  (typeof ORGANIZATION_RECONCILIATION_DEVELOP_OPERATION_EVIDENCE_BLOCKERS)[number];

export interface DevelopOperationEvidenceReadiness {
  readonly implemented: true;
  readonly ready: false;
  readonly blockers: readonly DevelopOperationEvidenceBlocker[];
}

export interface DevelopOperationEvidenceSurfaceEntry {
  readonly surface: DevelopOperationEvidenceSurfaceName;
  readonly legacyRecords: readonly unknown[];
  readonly identityRecords: readonly unknown[];
}

declare const DEVELOP_EIGHT_SURFACE_COLLECTION_BRAND: unique symbol;

export interface DevelopOperationEvidenceEightSurfaceCollection {
  readonly contract: typeof ORGANIZATION_RECONCILIATION_DEVELOP_OPERATION_EVIDENCE_CONTRACT;
  readonly entries: readonly DevelopOperationEvidenceSurfaceEntry[];
  readonly [DEVELOP_EIGHT_SURFACE_COLLECTION_BRAND]: true;
}

export interface AssembleDevelopOperationEvidenceInput {
  readonly run: OrganizationReconciliationDatasetLineageRun;
  readonly legacyProjection: LegacyOrganizationSurfaceProjection;
  readonly identityProjection: IdentityOrganizationSurfaceProjection;
  readonly surfaceCollection: DevelopOperationEvidenceEightSurfaceCollection;
  readonly semanticRegistrySha256: string;
  /** Same per-run nonce supplied to all three transaction adapters. */
  readonly evidenceNonce: string;
  /** Full reviewed collector artifact revision. */
  readonly collectorBuildRevision: string;
}

declare const DEVELOP_OPERATION_EVIDENCE_BLOCKED_ASSEMBLY_BRAND: unique symbol;

export interface DevelopMaterializedOperationEvidence
  extends OrganizationReconciliationOperationEvidence {
  readonly projectionBinding: OrganizationSurfaceProjectionBinding;
  readonly collectionEnvelope: OrganizationReconciliationCollectionEnvelope;
  readonly organizationDirectory: NonNullable<
    OrganizationReconciliationOperationEvidence["organizationDirectory"]
  >;
  readonly organizationMappings: NonNullable<
    OrganizationReconciliationOperationEvidence["organizationMappings"]
  >;
  readonly memberships: NonNullable<OrganizationReconciliationOperationEvidence["memberships"]>;
  readonly organizationScopedRoles: NonNullable<
    OrganizationReconciliationOperationEvidence["organizationScopedRoles"]
  >;
  readonly pluginBindings: NonNullable<
    OrganizationReconciliationOperationEvidence["pluginBindings"]
  >;
  readonly pluginVisibility: NonNullable<
    OrganizationReconciliationOperationEvidence["pluginVisibility"]
  >;
  readonly campusContexts: NonNullable<
    OrganizationReconciliationOperationEvidence["campusContexts"]
  >;
  readonly effectiveDecisions: NonNullable<
    OrganizationReconciliationOperationEvidence["effectiveDecisions"]
  >;
}

export interface DevelopOperationEvidenceCollectionWindow {
  readonly windowStartedAt: string;
  readonly windowEndedAt: string;
}

/**
 * Materialization is complete while production use remains explicitly
 * blocked by the readiness list. The returned manifest binds the exact
 * canonical evidence body, including the projection binding.
 */
export interface DevelopOperationEvidenceBlockedAssembly {
  readonly contract: typeof ORGANIZATION_RECONCILIATION_DEVELOP_OPERATION_EVIDENCE_CONTRACT;
  readonly implemented: true;
  readonly ready: false;
  readonly outcome: "blocked";
  readonly semanticRegistrySha256: string;
  readonly lineageManifestSha256: string;
  readonly projectionBinding: OrganizationSurfaceProjectionBinding;
  readonly verifiedSurfaceCount: 8;
  readonly observableDecisionCartesianCoverage: true;
  readonly evidence: DevelopMaterializedOperationEvidence;
  readonly componentManifest: OrganizationReconciliationOperationCompositeManifest;
  readonly blockers: readonly DevelopOperationEvidenceBlocker[];
  readonly [DEVELOP_OPERATION_EVIDENCE_BLOCKED_ASSEMBLY_BRAND]: true;
}

interface SurfaceCollectionBrand {
  readonly legacy: LegacyOrganizationSurfaceProjection;
  readonly identity: IdentityOrganizationSurfaceProjection;
}

interface ValidatedSurfaceState {
  readonly keys: Readonly<Record<DevelopOperationEvidenceSurfaceName, ReadonlySet<string>>>;
}

interface AuthoritativeOrganization {
  readonly legacyOrganizationId: string;
  readonly organizationRef: string;
  readonly identityOrganizationId: string;
  readonly name: string;
  readonly title: string | null;
  readonly active: true;
}

interface AuthoritativePluginBinding {
  readonly pluginRef: string;
  readonly bindingRef: string;
  readonly organizationRef: string;
  readonly active: boolean;
}

interface AuthoritativeSurfaceUniverse {
  readonly subjects: readonly string[];
  readonly organizations: ReadonlyMap<string, AuthoritativeOrganization>;
  readonly organizationsByName: ReadonlyMap<string, AuthoritativeOrganization>;
  readonly pluginBindings: ReadonlyMap<string, AuthoritativePluginBinding>;
  readonly capabilityPairs: ReadonlyMap<string, Readonly<{ resourceRef: string; capabilityRef: string }>>;
}

const surfaceCollectionBrands = new WeakMap<object, SurfaceCollectionBrand>();
const blockedAssemblyBrands = new WeakSet<object>();

export class DevelopOperationEvidenceAssemblyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DevelopOperationEvidenceAssemblyError";
  }
}

export function organizationReconciliationDevelopOperationEvidenceReadiness():
DevelopOperationEvidenceReadiness {
  return Object.freeze({
    implemented: ORGANIZATION_RECONCILIATION_DEVELOP_OPERATION_EVIDENCE_IMPLEMENTED,
    ready: ORGANIZATION_RECONCILIATION_DEVELOP_OPERATION_EVIDENCE_READY,
    blockers: ORGANIZATION_RECONCILIATION_DEVELOP_OPERATION_EVIDENCE_BLOCKERS
  });
}

/**
 * Brands one exact eight-surface pairing. The optional set exists so tests and
 * future callers cannot silently omit, repeat, or rename a surface while
 * retaining two otherwise valid projection brands.
 */
export function createDevelopOperationEvidenceEightSurfaceCollection(
  legacy: LegacyOrganizationSurfaceProjection,
  identity: IdentityOrganizationSurfaceProjection,
  requestedSurfaceSet: readonly DevelopOperationEvidenceSurfaceName[] =
    ORGANIZATION_RECONCILIATION_DEVELOP_OPERATION_EVIDENCE_SURFACES
): DevelopOperationEvidenceEightSurfaceCollection {
  assertIndependentOrganizationSurfaceProjections(legacy, identity);
  assertExactSurfaceObject(legacy.surfaces, "Legacy");
  assertExactSurfaceObject(identity.surfaces, "Identity");
  const requested = captureSurfaceSet(requestedSurfaceSet);
  const requestedNames = new Set(requested);
  if (
    requested.length !== ORGANIZATION_RECONCILIATION_DEVELOP_OPERATION_EVIDENCE_SURFACES.length ||
    requestedNames.size !== requested.length ||
    ORGANIZATION_RECONCILIATION_DEVELOP_OPERATION_EVIDENCE_SURFACES
      .some((surface) => !requestedNames.has(surface))
  ) {
    throw new DevelopOperationEvidenceAssemblyError(
      "The Develop operation-evidence surface set is missing, duplicate, or unknown."
    );
  }
  const entries = Object.freeze(
    ORGANIZATION_RECONCILIATION_DEVELOP_OPERATION_EVIDENCE_SURFACES.map((surface) =>
      Object.freeze({
        surface,
        legacyRecords: legacy.surfaces[surface],
        identityRecords: identity.surfaces[surface]
      })
    )
  );
  const collection = Object.freeze({
    contract: ORGANIZATION_RECONCILIATION_DEVELOP_OPERATION_EVIDENCE_CONTRACT,
    entries
  }) as unknown as DevelopOperationEvidenceEightSurfaceCollection;
  surfaceCollectionBrands.set(collection, Object.freeze({ legacy, identity }));
  return collection;
}

/**
 * Performs every check expressible by the current brands and materializes a
 * canonical evidence body plus a newly rebound composite manifest. Production
 * remains blocked; the original lineage manifest is never reused as though it
 * covered the projected surfaces.
 */
export function assembleDevelopOperationEvidence(
  candidate: AssembleDevelopOperationEvidenceInput
): DevelopOperationEvidenceBlockedAssembly {
  const input = captureAssemblyInput(candidate);
  const manifest = validateBrandedDevelopLineageRun(input.run);
  assertIndependentOrganizationSurfaceProjections(
    input.legacyProjection,
    input.identityProjection
  );
  requireApprovedRegistry(input);
  assertSurfaceCollectionPair(input);
  const legacyComponent = manifest.components.find((component) => component.componentId === "legacy-main")!;
  const identityComponent = manifest.components.find((component) => component.componentId === "identity")!;
  const pluginComponent = manifest.components.find((component) => component.componentId === "plugin")!;
  const projectionBinding = createOrganizationSurfaceProjectionBinding({
    legacyProjection: input.legacyProjection,
    identityProjection: input.identityProjection,
    semanticRegistrySha256: input.semanticRegistrySha256,
    lineageManifestSha256: manifest.manifestSha256,
    legacyPrimarySource: {
      sourceVersion: legacyComponent.sourceVersion,
      snapshotId: legacyComponent.snapshotId
    },
    identityPrimarySource: {
      sourceVersion: identityComponent.sourceVersion,
      snapshotId: identityComponent.snapshotId
    },
    pluginSource: {
      sourceVersion: pluginComponent.sourceVersion,
      snapshotId: pluginComponent.snapshotId
    }
  });

  const subjects = extractRunSubjectUniverses(input.run);
  const capabilityPairs = approvedCapabilityPairs();
  const legacyUniverse = extractAuthoritativeSurfaceUniverse(
    input.run,
    "legacy-main",
    subjects.legacy,
    capabilityPairs
  );
  const identityUniverse = extractAuthoritativeSurfaceUniverse(
    input.run,
    "identity",
    subjects.identity,
    capabilityPairs
  );
  const legacyState = validateSurfaceState(
    "Legacy",
    input.legacyProjection.surfaces,
    legacyUniverse
  );
  const identityState = validateSurfaceState(
    "Identity",
    input.identityProjection.surfaces,
    identityUniverse
  );
  for (const surface of ["pluginVisibility", "campusContexts", "effectiveDecisions"] as const) {
    if (!equalSets(legacyState.keys[surface], identityState.keys[surface])) {
      throw new DevelopOperationEvidenceAssemblyError(
        `The ${surface} decision universes are not the same comparison universe.`
      );
    }
  }

  const evidence = materializeOperationEvidence({
    manifest,
    projectionBinding,
    legacySurfaces: input.legacyProjection.surfaces,
    identitySurfaces: input.identityProjection.surfaces,
    legacySubjects: subjects.legacy,
    identitySubjects: subjects.identity,
    legacyUniverse,
    identityUniverse,
    evidenceNonce: input.evidenceNonce,
    collectorBuildRevision: input.collectorBuildRevision
  });
  const componentManifest = createOrganizationReconciliationCompositeManifestForEvidence(
    manifest,
    evidence
  );
  try {
    validateOrganizationReconciliationOperationCompositeManifestEvidenceBinding(
      componentManifest,
      evidence
    );
  } catch {
    throw new DevelopOperationEvidenceAssemblyError(
      "The materialized operation evidence is not bound to its final composite manifest."
    );
  }

  const result = Object.freeze({
    contract: ORGANIZATION_RECONCILIATION_DEVELOP_OPERATION_EVIDENCE_CONTRACT,
    implemented: true as const,
    ready: false as const,
    outcome: "blocked" as const,
    semanticRegistrySha256: input.semanticRegistrySha256,
    lineageManifestSha256: manifest.manifestSha256,
    projectionBinding,
    verifiedSurfaceCount: 8 as const,
    observableDecisionCartesianCoverage: true as const,
    evidence,
    componentManifest,
    blockers: ORGANIZATION_RECONCILIATION_DEVELOP_OPERATION_EVIDENCE_BLOCKERS
  }) as unknown as DevelopOperationEvidenceBlockedAssembly;
  blockedAssemblyBrands.add(result);
  return result;
}

export function assertDevelopOperationEvidenceBlockedAssembly(
  candidate: unknown
): asserts candidate is DevelopOperationEvidenceBlockedAssembly {
  if (!candidate || typeof candidate !== "object" || !blockedAssemblyBrands.has(candidate)) {
    throw new DevelopOperationEvidenceAssemblyError(
      "The Develop operation-evidence blocked assembly is forged or cloned."
    );
  }
}

function captureAssemblyInput(candidate: AssembleDevelopOperationEvidenceInput):
AssembleDevelopOperationEvidenceInput {
  const captured = captureExactDataObject(candidate, [
    "run",
    "legacyProjection",
    "identityProjection",
    "surfaceCollection",
    "semanticRegistrySha256",
    "evidenceNonce",
    "collectorBuildRevision"
  ], "assembly input");
  return Object.freeze({
    run: captured.run as OrganizationReconciliationDatasetLineageRun,
    legacyProjection: captured.legacyProjection as LegacyOrganizationSurfaceProjection,
    identityProjection: captured.identityProjection as IdentityOrganizationSurfaceProjection,
    surfaceCollection: captured.surfaceCollection as DevelopOperationEvidenceEightSurfaceCollection,
    semanticRegistrySha256: captured.semanticRegistrySha256 as string,
    evidenceNonce: requireEvidenceNonce(captured.evidenceNonce),
    collectorBuildRevision: requireCollectorBuildRevision(captured.collectorBuildRevision)
  });
}

interface MaterializeOperationEvidenceInput {
  readonly manifest: OrganizationReconciliationCompositeManifest;
  readonly projectionBinding: OrganizationSurfaceProjectionBinding;
  readonly legacySurfaces: OrganizationSurfaceProjectionRecords;
  readonly identitySurfaces: OrganizationSurfaceProjectionRecords;
  readonly legacySubjects: readonly string[];
  readonly identitySubjects: readonly string[];
  readonly legacyUniverse: AuthoritativeSurfaceUniverse;
  readonly identityUniverse: AuthoritativeSurfaceUniverse;
  readonly evidenceNonce: string;
  readonly collectorBuildRevision: string;
}

function materializeOperationEvidence(
  input: MaterializeOperationEvidenceInput
): DevelopMaterializedOperationEvidence {
  const legacyComponent = input.manifest.components.find(
    (component) => component.componentId === "legacy-main"
  )!;
  const identityComponent = input.manifest.components.find(
    (component) => component.componentId === "identity"
  )!;
  const legacySubjects = canonicalStringSet(input.legacySubjects);
  const identitySubjects = canonicalStringSet(input.identitySubjects);
  const legacySubjectsHash = createOrganizationReconciliationEvidenceHash(
    input.evidenceNonce,
    legacySubjects
  );
  const identitySubjectsHash = createOrganizationReconciliationEvidenceHash(
    input.evidenceNonce,
    identitySubjects
  );
  if (
    legacySubjects.length !== legacyComponent.subjectUniverse.count ||
    identitySubjects.length !== identityComponent.subjectUniverse.count ||
    legacySubjectsHash !== legacyComponent.subjectUniverse.sha256 ||
    identitySubjectsHash !== identityComponent.subjectUniverse.sha256
  ) {
    throw new DevelopOperationEvidenceAssemblyError(
      "The assembly nonce does not reproduce the lineage subject-universe commitments."
    );
  }
  const collectionWindow = createDevelopOperationEvidenceCollectionWindow(input.manifest);

  const envelope: OrganizationReconciliationCollectionEnvelope = {
    collectorContract: ORGANIZATION_RECONCILIATION_COLLECTOR_CONTRACT,
    collectorContractHash: ORGANIZATION_RECONCILIATION_COLLECTOR_CONTRACT_HASH,
    collectorBuildRevision: input.collectorBuildRevision,
    evidenceNonce: input.evidenceNonce,
    logicalSnapshotId: `lineage:${input.manifest.manifestSha256}`,
    windowId: `window:${input.manifest.manifestSha256}`,
    windowStartedAt: collectionWindow.windowStartedAt,
    windowEndedAt: collectionWindow.windowEndedAt,
    legacy: {
      sourceVersion: legacyComponent.sourceVersion,
      snapshotId: legacyComponent.snapshotId,
      subjectUniverse: {
        subjectCount: legacySubjects.length,
        subjectsHash: legacySubjectsHash
      },
      decisionUniverses: createDecisionUniverses(
        input.evidenceNonce,
        input.collectorBuildRevision,
        input.legacySurfaces,
        input.legacyUniverse
      )
    },
    identity: {
      sourceVersion: identityComponent.sourceVersion,
      snapshotId: identityComponent.snapshotId,
      subjectUniverse: {
        subjectCount: identitySubjects.length,
        subjectsHash: identitySubjectsHash
      },
      decisionUniverses: createDecisionUniverses(
        input.evidenceNonce,
        input.collectorBuildRevision,
        input.identitySurfaces,
        input.identityUniverse
      )
    }
  };

  const evidenceCandidate = {
    projectionBinding: input.projectionBinding,
    collectionEnvelope: envelope,
    organizationDirectory: createCollectedSurfacePair(
      input.evidenceNonce,
      legacyComponent,
      identityComponent,
      input.legacySurfaces.organizationDirectory,
      input.identitySurfaces.organizationDirectory
    ),
    organizationMappings: createCollectedSurfacePair(
      input.evidenceNonce,
      legacyComponent,
      identityComponent,
      input.legacySurfaces.organizationMappings,
      input.identitySurfaces.organizationMappings
    ),
    memberships: createCollectedSurfacePair(
      input.evidenceNonce,
      legacyComponent,
      identityComponent,
      input.legacySurfaces.memberships,
      input.identitySurfaces.memberships
    ),
    organizationScopedRoles: createCollectedSurfacePair(
      input.evidenceNonce,
      legacyComponent,
      identityComponent,
      input.legacySurfaces.organizationScopedRoles,
      input.identitySurfaces.organizationScopedRoles
    ),
    pluginBindings: createCollectedSurfacePair(
      input.evidenceNonce,
      legacyComponent,
      identityComponent,
      input.legacySurfaces.pluginBindings,
      input.identitySurfaces.pluginBindings
    ),
    pluginVisibility: createCollectedSurfacePair(
      input.evidenceNonce,
      legacyComponent,
      identityComponent,
      input.legacySurfaces.pluginVisibility,
      input.identitySurfaces.pluginVisibility
    ),
    campusContexts: createCollectedSurfacePair(
      input.evidenceNonce,
      legacyComponent,
      identityComponent,
      input.legacySurfaces.campusContexts,
      input.identitySurfaces.campusContexts
    ),
    effectiveDecisions: createCollectedSurfacePair(
      input.evidenceNonce,
      legacyComponent,
      identityComponent,
      input.legacySurfaces.effectiveDecisions,
      input.identitySurfaces.effectiveDecisions
    )
  };
  return canonicalizeOrganizationReconciliationEvidenceValue(evidenceCandidate) as unknown as
    DevelopMaterializedOperationEvidence;
}

/**
 * The composite manifest binds the outer union of all physical component
 * lifecycles. Surface evidence, however, may only claim the interval during
 * which all three immutable snapshots were simultaneously open. Validating
 * the complete manifest before deriving the intersection also prevents A/B
 * component-window splicing from becoming a new trust input.
 */
export function createDevelopOperationEvidenceCollectionWindow(
  candidate: unknown
): DevelopOperationEvidenceCollectionWindow {
  let manifest: OrganizationReconciliationCompositeManifest;
  try {
    manifest = validateOrganizationReconciliationCompositeManifest(candidate);
  } catch {
    throw new DevelopOperationEvidenceAssemblyError(
      "The Develop collection window requires one validated, non-spliced composite manifest."
    );
  }
  const opened = manifest.components.map((component) => ({
    timestamp: Date.parse(component.openedAt),
    value: component.openedAt
  }));
  const closed = manifest.components.map((component) => ({
    timestamp: Date.parse(component.closedAt),
    value: component.closedAt
  }));
  const latestOpened = opened.reduce((latest, value) =>
    value.timestamp > latest.timestamp ? value : latest);
  const earliestClosed = closed.reduce((earliest, value) =>
    value.timestamp < earliest.timestamp ? value : earliest);
  if (
    manifest.components.length !== 3 ||
    !Number.isFinite(latestOpened.timestamp) ||
    !Number.isFinite(earliestClosed.timestamp) ||
    latestOpened.timestamp > earliestClosed.timestamp
  ) {
    throw new DevelopOperationEvidenceAssemblyError(
      "The Develop component snapshots do not share a non-empty collection window."
    );
  }
  return Object.freeze({
    windowStartedAt: latestOpened.value,
    windowEndedAt: earliestClosed.value
  });
}

function createCollectedSurfacePair<T>(
  evidenceNonce: string,
  legacyComponent: OrganizationReconciliationCompositeManifest["components"][number],
  identityComponent: OrganizationReconciliationCompositeManifest["components"][number],
  legacyRecords: readonly T[],
  identityRecords: readonly T[]
): ReconciliationPair<T> {
  return {
    legacy: createOrganizationReconciliationCollectedSnapshot(
      evidenceNonce,
      legacyComponent.sourceVersion,
      legacyComponent.snapshotId,
      [{ requestCursor: null, nextCursor: null, records: legacyRecords }]
    ),
    identity: createOrganizationReconciliationCollectedSnapshot(
      evidenceNonce,
      identityComponent.sourceVersion,
      identityComponent.snapshotId,
      [{ requestCursor: null, nextCursor: null, records: identityRecords }]
    )
  };
}

function createDecisionUniverses(
  evidenceNonce: string,
  collectorBuildRevision: string,
  surfaces: OrganizationSurfaceProjectionRecords,
  universe: AuthoritativeSurfaceUniverse
): OrganizationReconciliationCollectionEnvelope["legacy"]["decisionUniverses"] {
  const subjects = canonicalStringSet(universe.subjects);
  const pluginBindings = [...universe.pluginBindings.values()];
  const contexts = authorizationContextDimensions(universe);
  const capabilityPairs = [...universe.capabilityPairs.values()];
  return {
    pluginVisibility: createDecisionUniverse(
      evidenceNonce,
      collectorBuildRevision,
      surfaces.pluginVisibility.map((record) => canonicalTuple([
        record.subjectRef,
        record.pluginRef,
        record.organizationRef
      ])),
      {
        subjects,
        plugins: pluginBindings.map((record) => record.pluginRef),
        organizations: pluginBindings.map((record) => record.organizationRef)
      }
    ),
    campusContexts: createDecisionUniverse(
      evidenceNonce,
      collectorBuildRevision,
      surfaces.campusContexts.map((record) => canonicalTuple([
        record.subjectRef,
        record.contextKind,
        record.contextRef
      ])),
      { subjects, contexts }
    ),
    effectiveDecisions: createDecisionUniverse(
      evidenceNonce,
      collectorBuildRevision,
      surfaces.effectiveDecisions.map((record) => canonicalTuple([
        record.subjectRef,
        record.contextKind,
        record.contextRef,
        record.resourceRef,
        record.capabilityRef
      ])),
      {
        subjects,
        contexts,
        resources: capabilityPairs.map((record) => record.resourceRef),
        capabilities: capabilityPairs.map((record) => record.capabilityRef),
        rulePairs: capabilityPairs.map((record) => canonicalTuple([
          record.resourceRef,
          record.capabilityRef
        ]))
      }
    )
  };
}

function createDecisionUniverse(
  evidenceNonce: string,
  collectorBuildRevision: string,
  keys: readonly string[],
  dimensions: Readonly<Record<string, readonly string[]>>
): OrganizationReconciliationDecisionUniverseEvidence {
  const canonicalKeys = canonicalStringSet(keys);
  return {
    keyCount: canonicalKeys.length,
    keysHash: createOrganizationReconciliationEvidenceHash(evidenceNonce, canonicalKeys),
    derivationContract: ORGANIZATION_RECONCILIATION_DECISION_DERIVATION_CONTRACT,
    derivationBuildRevision: collectorBuildRevision,
    dimensions: Object.freeze(Object.fromEntries(
      Object.entries(dimensions).map(([name, values]) => {
        const canonicalValues = canonicalStringSet(values);
        return [name, Object.freeze({
          count: canonicalValues.length,
          hash: createOrganizationReconciliationEvidenceHash(evidenceNonce, canonicalValues)
        })];
      })
    ))
  };
}

function authorizationContextDimensions(universe: AuthoritativeSurfaceUniverse): readonly string[] {
  return [
    ...[...universe.organizations.values()].map((record) =>
      canonicalTuple(["organization", record.organizationRef])
    ),
    canonicalTuple(["platform-global", ORGANIZATION_RECONCILIATION_PLATFORM_GLOBAL_CONTEXT_REF]),
    canonicalTuple(["public", ORGANIZATION_RECONCILIATION_PUBLIC_CONTEXT_REF])
  ];
}

function canonicalTuple(values: readonly string[]): string {
  return JSON.stringify(values);
}

function canonicalStringSet(values: readonly string[]): readonly string[] {
  return Object.freeze([...new Set(values)].sort());
}

function requireEvidenceNonce(value: unknown): string {
  if (typeof value !== "string" || !/^[a-f0-9]{32,128}$/.test(value)) {
    throw new DevelopOperationEvidenceAssemblyError(
      "The assembly evidence nonce must be 32-128 lowercase hexadecimal characters."
    );
  }
  return value;
}

function requireCollectorBuildRevision(value: unknown): string {
  if (typeof value !== "string" || !/^[a-f0-9]{40}$/.test(value)) {
    throw new DevelopOperationEvidenceAssemblyError(
      "The assembly collector build revision must be a full lowercase 40-character revision."
    );
  }
  return value;
}

function validateBrandedDevelopLineageRun(run: OrganizationReconciliationDatasetLineageRun) {
  if (!run || typeof run !== "object" || isProxy(run) || !Array.isArray(run.artifacts)) {
    throw new DevelopOperationEvidenceAssemblyError("A branded Develop dataset-lineage run is required.");
  }
  const expected = new Set(
    ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG.components.flatMap((component) =>
      component.datasetCatalog.datasets.map((dataset) => `${component.componentId}\u0000${dataset.datasetId}`)
    )
  );
  const actual = new Map<string, OrganizationReconciliationDatasetLineageArtifact>();
  try {
    for (const artifact of run.artifacts) {
      const accepted = assertOrganizationReconciliationDatasetArtifactBelongsToRun(run, artifact);
      const key = `${accepted.componentId}\u0000${accepted.datasetId}`;
      if (!expected.has(key) || actual.has(key)) {
        throw new DevelopOperationEvidenceAssemblyError(
          "The branded lineage run has an unexpected or duplicate Develop dataset artifact."
        );
      }
      actual.set(key, accepted);
    }
  } catch (error) {
    if (error instanceof DevelopOperationEvidenceAssemblyError) throw error;
    throw new DevelopOperationEvidenceAssemblyError(
      "The Develop dataset-lineage run is forged, cloned, or cross-run."
    );
  }
  if (actual.size !== expected.size || [...expected].some((key) => !actual.has(key))) {
    throw new DevelopOperationEvidenceAssemblyError(
      "The branded lineage run does not cover the exact compiled Develop dataset catalog."
    );
  }
  let manifest;
  try {
    manifest = validateOrganizationReconciliationCompositeManifestEvidenceBinding(
      run.coordinatorManifest,
      {
        contract: run.contract,
        catalogTrust: run.catalogTrust,
        crossDatabaseAtomic: run.crossDatabaseAtomic,
        readiness: run.readiness,
        artifacts: run.artifacts
      }
    );
  } catch {
    throw new DevelopOperationEvidenceAssemblyError(
      "The branded lineage run is not bound to its coordinator manifest."
    );
  }
  for (const component of ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG.components) {
    const manifestComponent = manifest.components.find(
      (candidate) => candidate.componentId === component.componentId
    );
    if (
      !manifestComponent ||
      manifestComponent.sourceId !== component.expectedSourceId ||
      manifestComponent.catalogSha256 !== component.declaredCatalogSha256
    ) {
      throw new DevelopOperationEvidenceAssemblyError(
        "The lineage manifest does not select the compiled Develop physical source catalog."
      );
    }
    const componentArtifacts = [...actual.values()].filter(
      (artifact) => artifact.componentId === component.componentId
    );
    if (
      componentArtifacts.some((artifact) =>
        artifact.sourceVersion !== manifestComponent.sourceVersion ||
        artifact.snapshotId !== manifestComponent.snapshotId
      ) ||
      componentArtifacts.reduce((sum, artifact) => sum + artifact.recordCount, 0) !==
        manifestComponent.recordCount
    ) {
      throw new DevelopOperationEvidenceAssemblyError(
        "The lineage artifacts do not match their branded manifest component snapshot."
      );
    }
  }
  return manifest;
}

function requireApprovedRegistry(input: AssembleDevelopOperationEvidenceInput): void {
  const approved = ORGANIZATION_OWNER_DEVELOP_APPROVED_REGISTRY_CANDIDATE.registrySha256;
  if (
    input.semanticRegistrySha256 !== approved ||
    input.legacyProjection.semanticRegistrySha256 !== approved ||
    input.identityProjection.semanticRegistrySha256 !== approved
  ) {
    throw new DevelopOperationEvidenceAssemblyError(
      "The operation-evidence assembly is not bound to the approved Develop semantic registry candidate."
    );
  }
}

function assertSurfaceCollectionPair(input: AssembleDevelopOperationEvidenceInput): void {
  const collection = input.surfaceCollection;
  const brand = collection && typeof collection === "object"
    ? surfaceCollectionBrands.get(collection)
    : undefined;
  if (
    !brand ||
    brand.legacy !== input.legacyProjection ||
    brand.identity !== input.identityProjection
  ) {
    throw new DevelopOperationEvidenceAssemblyError(
      "The eight-surface collection is forged, cloned, or belongs to another A+B projection pair."
    );
  }
  if (
    collection.contract !== ORGANIZATION_RECONCILIATION_DEVELOP_OPERATION_EVIDENCE_CONTRACT ||
    collection.entries.length !== ORGANIZATION_RECONCILIATION_DEVELOP_OPERATION_EVIDENCE_SURFACES.length
  ) {
    throw new DevelopOperationEvidenceAssemblyError("The branded eight-surface collection is invalid.");
  }
  collection.entries.forEach((entry, index) => {
    const surface = ORGANIZATION_RECONCILIATION_DEVELOP_OPERATION_EVIDENCE_SURFACES[index]!;
    if (
      entry.surface !== surface ||
      entry.legacyRecords !== input.legacyProjection.surfaces[surface] ||
      entry.identityRecords !== input.identityProjection.surfaces[surface]
    ) {
      throw new DevelopOperationEvidenceAssemblyError(
        "The branded eight-surface collection no longer matches its projection pair."
      );
    }
  });
}

function extractRunSubjectUniverses(run: OrganizationReconciliationDatasetLineageRun): {
  readonly legacy: readonly string[];
  readonly identity: readonly string[];
} {
  const legacy = subjectRefsFromArtifact(run, "legacy-main", "legacy-subject-universe");
  const identity = subjectRefsFromArtifact(run, "identity", "identity-subject-universe");
  if (!equalSets(new Set(legacy), new Set(identity))) {
    throw new DevelopOperationEvidenceAssemblyError(
      "The Legacy and Identity branded run subject universes differ."
    );
  }
  for (const [componentId, values] of [["legacy-main", legacy], ["identity", identity]] as const) {
    const component = run.coordinatorManifest.components.find(
      (candidate) => candidate.componentId === componentId
    );
    if (!component || component.subjectUniverse.count !== values.length) {
      throw new DevelopOperationEvidenceAssemblyError(
        "The observable subject universe does not match the lineage manifest count."
      );
    }
  }
  return Object.freeze({ legacy, identity });
}

function subjectRefsFromArtifact(
  run: OrganizationReconciliationDatasetLineageRun,
  componentId: "legacy-main" | "identity",
  datasetId: "legacy-subject-universe" | "identity-subject-universe"
): readonly string[] {
  const artifact = run.artifacts.find(
    (candidate) => candidate.componentId === componentId && candidate.datasetId === datasetId
  );
  if (!artifact) throw new DevelopOperationEvidenceAssemblyError("A subject-universe artifact is missing.");
  const refs = artifact.records.map((record) => {
    if (!isPlainRecord(record) || !("legacyUserId" in record)) {
      throw new DevelopOperationEvidenceAssemblyError("A subject-universe record is invalid.");
    }
    try {
      return subjectRefForLegacyUserId(record.legacyUserId as string | number);
    } catch {
      throw new DevelopOperationEvidenceAssemblyError("A subject-universe record is invalid.");
    }
  }).sort();
  if (new Set(refs).size !== refs.length) {
    throw new DevelopOperationEvidenceAssemblyError("A subject-universe artifact contains duplicates.");
  }
  return Object.freeze(refs);
}

function extractAuthoritativeSurfaceUniverse(
  run: OrganizationReconciliationDatasetLineageRun,
  componentId: "legacy-main" | "identity",
  subjects: readonly string[],
  capabilityPairs: ReadonlyMap<string, Readonly<{ resourceRef: string; capabilityRef: string }>>
): AuthoritativeSurfaceUniverse {
  const organizationState = componentId === "legacy-main"
    ? authoritativeLegacyOrganizations(run)
    : authoritativeIdentityOrganizations(run);
  return Object.freeze({
    subjects,
    organizations: organizationState.byId,
    organizationsByName: organizationState.byName,
    pluginBindings: authoritativePluginBindings(run, organizationState.byName),
    capabilityPairs
  });
}

function authoritativeLegacyOrganizations(run: OrganizationReconciliationDatasetLineageRun): {
  readonly byId: ReadonlyMap<string, AuthoritativeOrganization>;
  readonly byName: ReadonlyMap<string, AuthoritativeOrganization>;
} {
  const records = artifactRecords(run, "legacy-main", "legacy-organization-directory");
  return authoritativeOrganizations(records.map((value) => {
    const row = exactRecord(value, [
      "legacyOrganizationId", "name", "title", "createdAt", "updatedAt"
    ]);
    const legacyOrganizationId = canonicalLegacyOrganizationIdValue(row.legacyOrganizationId);
    const name = organizationNameValue(row.name);
    const title = tokenValue(row.title, "Legacy organization title");
    requireFiniteInteger(row.createdAt);
    requireFiniteInteger(row.updatedAt);
    return Object.freeze({
      legacyOrganizationId,
      organizationRef: organizationRefForLegacyId(legacyOrganizationId),
      identityOrganizationId: identityOrganizationIdForCanonicalLegacyId(legacyOrganizationId),
      name,
      title,
      active: true as const
    });
  }));
}

function authoritativeIdentityOrganizations(run: OrganizationReconciliationDatasetLineageRun): {
  readonly byId: ReadonlyMap<string, AuthoritativeOrganization>;
  readonly byName: ReadonlyMap<string, AuthoritativeOrganization>;
} {
  const candidates = artifactRecords(run, "identity", "identity-organization-candidate");
  const mappings = artifactRecords(run, "identity", "identity-organization-id-map");
  const mappingById = new Map<string, string>();
  const targetIds = new Set<string>();
  for (const value of mappings) {
    const row = exactRecord(value, [
      "legacyOrganizationId", "identityOrganizationId", "source", "mappingStatus"
    ]);
    if (row.source !== "legacy" || row.mappingStatus !== "active") {
      throw new DevelopOperationEvidenceAssemblyError(
        "An Identity organization mapping is outside the approved candidate selector."
      );
    }
    const legacyOrganizationId = canonicalLegacyOrganizationIdValue(row.legacyOrganizationId);
    const identityOrganizationId = tokenValue(
      row.identityOrganizationId,
      "Identity organization ID"
    );
    if (mappingById.has(legacyOrganizationId) || targetIds.has(identityOrganizationId)) {
      throw new DevelopOperationEvidenceAssemblyError(
        "The authoritative Identity organization mapping is not bidirectionally one-to-one."
      );
    }
    mappingById.set(legacyOrganizationId, identityOrganizationId);
    targetIds.add(identityOrganizationId);
  }
  const state = authoritativeOrganizations(candidates.map((value) => {
    const row = exactRecord(value, [
      "legacyOrganizationId", "identityOrganizationId", "name", "title", "source",
      "candidateStatus"
    ]);
    if (row.source !== "legacy" || row.candidateStatus !== "candidate") {
      throw new DevelopOperationEvidenceAssemblyError(
        "An Identity organization is outside the approved candidate selector."
      );
    }
    const legacyOrganizationId = canonicalLegacyOrganizationIdValue(row.legacyOrganizationId);
    const identityOrganizationId = tokenValue(
      row.identityOrganizationId,
      "Identity organization ID"
    );
    if (mappingById.get(legacyOrganizationId) !== identityOrganizationId) {
      throw new DevelopOperationEvidenceAssemblyError(
        "An Identity organization candidate does not match its exact ID mapping."
      );
    }
    return Object.freeze({
      legacyOrganizationId,
      organizationRef: organizationRefForLegacyId(legacyOrganizationId),
      identityOrganizationId,
      name: organizationNameValue(row.name),
      title: tokenValue(row.title, "Identity organization title"),
      active: true as const
    });
  }));
  if (state.byId.size !== mappingById.size) {
    throw new DevelopOperationEvidenceAssemblyError(
      "The Identity organization candidate and mapping universes differ."
    );
  }
  return state;
}

function authoritativeOrganizations(records: readonly AuthoritativeOrganization[]): {
  readonly byId: ReadonlyMap<string, AuthoritativeOrganization>;
  readonly byName: ReadonlyMap<string, AuthoritativeOrganization>;
} {
  const byId = new Map<string, AuthoritativeOrganization>();
  const byName = new Map<string, AuthoritativeOrganization>();
  for (const record of records) {
    if (byId.has(record.legacyOrganizationId) || byName.has(record.name)) {
      throw new DevelopOperationEvidenceAssemblyError(
        "The authoritative organization universe is duplicate or name-ambiguous."
      );
    }
    byId.set(record.legacyOrganizationId, record);
    byName.set(record.name, record);
  }
  return Object.freeze({ byId, byName });
}

function authoritativePluginBindings(
  run: OrganizationReconciliationDatasetLineageRun,
  organizationsByName: ReadonlyMap<string, AuthoritativeOrganization>
): ReadonlyMap<string, AuthoritativePluginBinding> {
  type PluginState = Readonly<{
    pluginRef: string;
    enabled: boolean;
    accessScope: string;
    organizationName: string | null;
  }>;
  const plugins = new Map<string, PluginState>();
  for (const value of artifactRecords(run, "plugin", "plugin-registry")) {
    const row = exactRecord(value, ["pluginId", "enabled", "accessScope", "organizationName"]);
    const plugin = pluginState(row);
    if (plugins.has(plugin.pluginRef)) {
      throw new DevelopOperationEvidenceAssemblyError(
        "The authoritative plugin database baseline contains a duplicate ID."
      );
    }
    plugins.set(plugin.pluginRef, plugin);
  }
  const overlay = ORGANIZATION_OWNER_DEVELOP_DECISION_CATALOGS.pluginOverlay as unknown as {
    readonly staticBuiltIns?: readonly unknown[];
  };
  if (!Array.isArray(overlay.staticBuiltIns)) {
    throw new DevelopOperationEvidenceAssemblyError(
      "The compiled static plugin catalog is unavailable."
    );
  }
  for (const value of overlay.staticBuiltIns) {
    if (!isPlainRecord(value)) {
      throw new DevelopOperationEvidenceAssemblyError("A compiled static plugin entry is invalid.");
    }
    const plugin = pluginState({
      pluginId: value.id,
      enabled: value.enabled,
      accessScope: value.accessScope,
      organizationName: value.organizationName === undefined ? null : value.organizationName
    });
    const baseline = plugins.get(plugin.pluginRef);
    if (baseline && (
      baseline.enabled !== plugin.enabled ||
      baseline.accessScope !== plugin.accessScope ||
      baseline.organizationName !== plugin.organizationName
    )) {
      throw new DevelopOperationEvidenceAssemblyError(
        "A static plugin collision changes an authorization-relevant field."
      );
    }
    plugins.set(plugin.pluginRef, plugin);
  }
  const bindings = new Map<string, AuthoritativePluginBinding>();
  for (const plugin of plugins.values()) {
    const organizationRef = plugin.organizationName === null
      ? "org:public"
      : organizationsByName.get(plugin.organizationName)?.organizationRef;
    if (organizationRef === undefined) {
      throw new DevelopOperationEvidenceAssemblyError(
        "An authoritative plugin organization binding is unresolved or ambiguous."
      );
    }
    bindings.set(plugin.pluginRef, Object.freeze({
      pluginRef: plugin.pluginRef,
      bindingRef: `${plugin.pluginRef}:${organizationRef}`,
      organizationRef,
      active: plugin.enabled
    }));
  }
  return bindings;
}

function pluginState(row: Record<string, unknown>): Readonly<{
  pluginRef: string;
  enabled: boolean;
  accessScope: string;
  organizationName: string | null;
}> {
  if (typeof row.pluginId !== "string") invalidRecord();
  let pluginRef: string;
  try {
    pluginRef = pluginRefForId(row.pluginId);
  } catch {
    invalidRecord();
  }
  requireBoolean(row.enabled);
  if (![
    "auth-only", "manager-only", "admin-only", "root-only"
  ].includes(String(row.accessScope))) invalidRecord();
  const organizationName = row.organizationName === null
    ? null
    : organizationNameValue(row.organizationName);
  return Object.freeze({
    pluginRef: pluginRef!,
    enabled: row.enabled,
    accessScope: String(row.accessScope),
    organizationName
  });
}

function approvedCapabilityPairs(): ReadonlyMap<
string,
Readonly<{ resourceRef: string; capabilityRef: string }>
> {
  const campusCatalog = ORGANIZATION_OWNER_DEVELOP_DECISION_CATALOGS.campusPublicContext as unknown as
    Record<string, unknown>;
  if (campusCatalog.executionState !== "owner-bound-campus-context-decision-execution") {
    throw new DevelopOperationEvidenceAssemblyError(
      "The compiled campus context-decision execution is not authorized."
    );
  }
  const catalog = ORGANIZATION_OWNER_DEVELOP_DECISION_CATALOGS.capabilityCatalog as unknown as
    Record<string, unknown>;
  const inputs: Array<Readonly<{ resourceRef: string; capabilityRef: string }>> = [];
  if (catalog.executionState !== "owner-bound-context-decision-execution") {
    throw new DevelopOperationEvidenceAssemblyError(
      "The compiled exact capability context-decision execution is not authorized."
    );
  }
  if (!Array.isArray(catalog.entries)) {
    throw new DevelopOperationEvidenceAssemblyError(
      "The compiled exact capability catalog entries are unavailable."
    );
  }
  for (const value of catalog.entries) {
    if (!isPlainRecord(value)) {
      throw new DevelopOperationEvidenceAssemblyError(
        "The compiled capability catalog contains an invalid exact entry."
      );
    }
    inputs.push(Object.freeze({
      resourceRef: tokenValue(value.resourceId, "capability resource ID"),
      capabilityRef: tokenValue(value.capabilityId, "capability ID")
    }));
  }
  if (inputs.length !== 20) {
    throw new DevelopOperationEvidenceAssemblyError(
      "The compiled capability catalog must contain exactly 20 exact decision pairs."
    );
  }
  const pairs = new Map<string, Readonly<{ resourceRef: string; capabilityRef: string }>>();
  const capabilities = new Set<string>();
  for (const input of inputs) {
    const key = `${input.resourceRef}\u0000${input.capabilityRef}`;
    if (pairs.has(key) || capabilities.has(input.capabilityRef)) {
      throw new DevelopOperationEvidenceAssemblyError(
        "The compiled capability catalog contains a duplicate or ambiguous decision pair."
      );
    }
    pairs.set(key, input);
    capabilities.add(input.capabilityRef);
  }
  return pairs;
}

function artifactRecords(
  run: OrganizationReconciliationDatasetLineageRun,
  componentId: "legacy-main" | "identity" | "plugin",
  datasetId: string
): readonly unknown[] {
  const artifact = run.artifacts.find(
    (candidate) => candidate.componentId === componentId && candidate.datasetId === datasetId
  );
  if (!artifact) {
    throw new DevelopOperationEvidenceAssemblyError(
      `The authoritative ${componentId}/${datasetId} lineage artifact is missing.`
    );
  }
  return artifact.records;
}

function assertCrossSurfaceIntegrity(
  side: "Legacy" | "Identity",
  surfaces: OrganizationSurfaceProjectionRecords,
  universe: AuthoritativeSurfaceUniverse
): void {
  const subjectRefs = new Set(universe.subjects);
  const directoryById = new Map<string, (typeof surfaces.organizationDirectory)[number]>();
  for (const record of surfaces.organizationDirectory) {
    const legacyOrganizationId = canonicalLegacyOrganizationId(record.legacyOrganizationId);
    const expected = universe.organizations.get(legacyOrganizationId);
    if (
      !expected || record.name !== expected.name || record.title !== expected.title ||
      record.active !== expected.active
    ) {
      throw new DevelopOperationEvidenceAssemblyError(
        `The ${side} organizationDirectory does not cover the authoritative raw organization universe.`
      );
    }
    directoryById.set(legacyOrganizationId, record);
  }
  if (directoryById.size !== universe.organizations.size) {
    throw new DevelopOperationEvidenceAssemblyError(
      `The ${side} organizationDirectory does not cover the authoritative raw organization universe.`
    );
  }

  const mappingById = new Map<string, (typeof surfaces.organizationMappings)[number]>();
  const mappingTargets = new Set<string>();
  for (const record of surfaces.organizationMappings) {
    const legacyOrganizationId = canonicalLegacyOrganizationId(record.legacyOrganizationId);
    if (mappingTargets.has(record.identityOrganizationId)) {
      throw new DevelopOperationEvidenceAssemblyError(
        `The ${side} organizationMappings target is reused and not bidirectionally one-to-one.`
      );
    }
    mappingTargets.add(record.identityOrganizationId);
    const expected = universe.organizations.get(legacyOrganizationId);
    if (
      !expected || record.identityOrganizationId !== expected.identityOrganizationId ||
      record.active !== expected.active
    ) {
      throw new DevelopOperationEvidenceAssemblyError(
        `The ${side} organizationMappings does not cover the authoritative mapping universe.`
      );
    }
    mappingById.set(legacyOrganizationId, record);
  }
  if (mappingById.size !== universe.organizations.size) {
    throw new DevelopOperationEvidenceAssemblyError(
      `The ${side} organizationMappings does not cover the authoritative mapping universe.`
    );
  }

  const activeMemberships = new Set<string>();
  for (const record of surfaces.memberships) {
    const organizationId = canonicalLegacyOrganizationId(record.legacyOrganizationId);
    const organization = directoryById.get(organizationId);
    const mapping = mappingById.get(organizationId);
    if (!subjectRefs.has(record.subjectRef) || !organization || !mapping) {
      throw new DevelopOperationEvidenceAssemblyError(
        `The ${side} membership references an unknown subject or organization.`
      );
    }
    if (record.active && (!organization.active || !mapping.active)) {
      throw new DevelopOperationEvidenceAssemblyError(
        `The ${side} active membership references an inactive organization mapping.`
      );
    }
    if (record.active) activeMemberships.add(`${record.subjectRef}\u0000${organizationId}`);
  }
  for (const record of surfaces.organizationScopedRoles) {
    const organizationId = canonicalLegacyOrganizationId(record.legacyOrganizationId);
    if (
      !subjectRefs.has(record.subjectRef) || !directoryById.has(organizationId) ||
      !mappingById.has(organizationId)
    ) {
      throw new DevelopOperationEvidenceAssemblyError(
        `The ${side} organization role references an unknown subject or organization.`
      );
    }
    if (
      record.active &&
      !activeMemberships.has(`${record.subjectRef}\u0000${organizationId}`)
    ) {
      throw new DevelopOperationEvidenceAssemblyError(
        `The ${side} active organization role has no active membership.`
      );
    }
  }

  const bindingByPlugin = new Map<string, (typeof surfaces.pluginBindings)[number]>();
  for (const record of surfaces.pluginBindings) {
    const expected = universe.pluginBindings.get(record.pluginRef);
    if (
      !expected || record.bindingRef !== expected.bindingRef ||
      record.organizationRef !== expected.organizationRef || record.active !== expected.active
    ) {
      throw new DevelopOperationEvidenceAssemblyError(
        `The ${side} pluginBindings does not cover the compiled/raw authoritative plugin universe.`
      );
    }
    if (
      record.organizationRef !== "org:public" &&
      !organizationForRef(universe, record.organizationRef)
    ) {
      throw new DevelopOperationEvidenceAssemblyError(
        `The ${side} plugin binding references an unknown organization.`
      );
    }
    bindingByPlugin.set(record.pluginRef, record);
  }
  if (bindingByPlugin.size !== universe.pluginBindings.size) {
    throw new DevelopOperationEvidenceAssemblyError(
      `The ${side} pluginBindings does not cover the compiled/raw authoritative plugin universe.`
    );
  }

  for (const record of surfaces.pluginVisibility) {
    const binding = bindingByPlugin.get(record.pluginRef);
    if (
      !subjectRefs.has(record.subjectRef) || !binding ||
      binding.organizationRef !== record.organizationRef
    ) {
      throw new DevelopOperationEvidenceAssemblyError(
        `The ${side} plugin visibility record has no matching subject and plugin binding.`
      );
    }
    if (record.decision === "allow" && !binding.active) {
      throw new DevelopOperationEvidenceAssemblyError(
        `The ${side} plugin visibility allows an inactive binding.`
      );
    }
  }
  for (const record of surfaces.campusContexts) {
    if (
      !subjectRefs.has(record.subjectRef) ||
      (record.contextKind === "organization" && !organizationForRef(universe, record.contextRef))
    ) {
      throw new DevelopOperationEvidenceAssemblyError(
        `The ${side} campus context is outside the authoritative S x (O + 2) universe.`
      );
    }
  }
  for (const record of surfaces.effectiveDecisions) {
    if (
      !subjectRefs.has(record.subjectRef) ||
      (record.contextKind === "organization" && !organizationForRef(universe, record.contextRef)) ||
      !universe.capabilityPairs.has(`${record.resourceRef}\u0000${record.capabilityRef}`)
    ) {
      throw new DevelopOperationEvidenceAssemblyError(
        `The ${side} effective decision is outside the authoritative organization/capability universe.`
      );
    }
  }
}

function organizationForRef(
  universe: AuthoritativeSurfaceUniverse,
  organizationRef: string
): AuthoritativeOrganization | undefined {
  for (const organization of universe.organizations.values()) {
    if (organization.organizationRef === organizationRef) return organization;
  }
  return undefined;
}

function canonicalLegacyOrganizationIdValue(value: unknown): string {
  if (!isCanonicalLegacyOrganizationId(value)) invalidRecord();
  return canonicalLegacyOrganizationId(value);
}

function organizationNameValue(value: unknown): string {
  const result = tokenValue(value, "organization name");
  if (!/^[a-z0-9][a-z0-9-]*$/.test(result)) invalidRecord();
  return result;
}

function tokenValue(value: unknown, _label: string): string {
  if (!isCanonicalReconciliationToken(value)) invalidRecord();
  return value;
}

function requireFiniteInteger(value: unknown): void {
  if (!Number.isSafeInteger(value) || (value as number) < 0) invalidRecord();
}

function validateSurfaceState(
  side: "Legacy" | "Identity",
  surfaces: OrganizationSurfaceProjectionRecords,
  universe: AuthoritativeSurfaceUniverse
): ValidatedSurfaceState {
  assertExactSurfaceObject(surfaces, side);
  const keys = {} as Record<DevelopOperationEvidenceSurfaceName, ReadonlySet<string>>;
  for (const surface of ORGANIZATION_RECONCILIATION_DEVELOP_OPERATION_EVIDENCE_SURFACES) {
    const records = surfaces[surface];
    const recordKeys = records.map((record) => validateRecordAndKey(surface, record));
    const keySet = new Set(recordKeys);
    if (keySet.size !== recordKeys.length) {
      throw new DevelopOperationEvidenceAssemblyError(
        `The ${side} ${surface} surface contains a duplicate record key.`
      );
    }
    keys[surface] = keySet;
  }
  assertCrossSurfaceIntegrity(side, surfaces, universe);
  assertObservableDecisionUniverseComplete(side, surfaces, universe, keys);
  return Object.freeze({ keys: Object.freeze(keys) });
}

function assertObservableDecisionUniverseComplete(
  side: "Legacy" | "Identity",
  surfaces: OrganizationSurfaceProjectionRecords,
  universe: AuthoritativeSurfaceUniverse,
  keys: Readonly<Record<DevelopOperationEvidenceSurfaceName, ReadonlySet<string>>>
): void {
  const expectedPluginKeys = productKeys(
    universe.subjects,
    [...universe.pluginBindings.values()].map(
      (record) => `${record.pluginRef}\u0000${record.organizationRef}`
    )
  );
  requireEqualDecisionUniverse(side, "pluginVisibility", keys.pluginVisibility, expectedPluginKeys);

  const expectedCampusKeys = productKeys(
    universe.subjects,
    authorizationContextKeys(universe)
  );
  requireEqualDecisionUniverse(side, "campusContexts", keys.campusContexts, expectedCampusKeys);

  const contexts = authorizationContextKeys(universe);
  const rules = [...universe.capabilityPairs.keys()];
  const expectedEffectiveKeys = new Set<string>();
  for (const subject of universe.subjects) {
    for (const context of contexts) {
      for (const rule of rules) expectedEffectiveKeys.add(`${subject}\u0000${context}\u0000${rule}`);
    }
  }
  requireEqualDecisionUniverse(side, "effectiveDecisions", keys.effectiveDecisions, expectedEffectiveKeys);
}

function authorizationContextKeys(universe: AuthoritativeSurfaceUniverse): string[] {
  return [
    ...[...universe.organizations.values()].map(
      (record) => `organization\u0000${record.organizationRef}`
    ),
    `platform-global\u0000${ORGANIZATION_RECONCILIATION_PLATFORM_GLOBAL_CONTEXT_REF}`,
    `public\u0000${ORGANIZATION_RECONCILIATION_PUBLIC_CONTEXT_REF}`
  ];
}

function requireEqualDecisionUniverse(
  side: "Legacy" | "Identity",
  surface: "pluginVisibility" | "campusContexts" | "effectiveDecisions",
  actual: ReadonlySet<string>,
  expected: ReadonlySet<string>
): void {
  if (!equalSets(actual, expected)) {
    throw new DevelopOperationEvidenceAssemblyError(
      `The ${side} ${surface} decision universe is incomplete or contains unknown keys.`
    );
  }
}

function productKeys(left: readonly string[], right: readonly string[]): Set<string> {
  const result = new Set<string>();
  for (const first of left) for (const second of right) result.add(`${first}\u0000${second}`);
  return result;
}

function validateRecordAndKey(surface: DevelopOperationEvidenceSurfaceName, value: unknown): string {
  switch (surface) {
    case "organizationDirectory": {
      const record = exactRecord(value, ["legacyOrganizationId", "name", "title", "active"]);
      requireLegacyOrganizationId(record.legacyOrganizationId);
      requireToken(record.name);
      if (record.title !== null) requireToken(record.title);
      requireBoolean(record.active);
      return String(record.legacyOrganizationId);
    }
    case "organizationMappings": {
      const record = exactRecord(value, ["legacyOrganizationId", "identityOrganizationId", "active"]);
      requireLegacyOrganizationId(record.legacyOrganizationId);
      requireToken(record.identityOrganizationId);
      requireBoolean(record.active);
      return String(record.legacyOrganizationId);
    }
    case "memberships": {
      const record = exactRecord(value, ["subjectRef", "legacyOrganizationId", "active"]);
      requireSubjectRef(record.subjectRef);
      requireLegacyOrganizationId(record.legacyOrganizationId);
      requireBoolean(record.active);
      return `${record.subjectRef}\u0000${record.legacyOrganizationId}`;
    }
    case "organizationScopedRoles": {
      const record = exactRecord(value, ["subjectRef", "legacyOrganizationId", "roleRef", "active"]);
      requireSubjectRef(record.subjectRef);
      requireLegacyOrganizationId(record.legacyOrganizationId);
      requireToken(record.roleRef);
      requireBoolean(record.active);
      return `${record.subjectRef}\u0000${record.legacyOrganizationId}\u0000${record.roleRef}`;
    }
    case "pluginBindings": {
      const record = exactRecord(value, ["pluginRef", "bindingRef", "organizationRef", "active"]);
      requirePluginRef(record.pluginRef);
      requireToken(record.bindingRef);
      requireOrganizationRef(record.organizationRef, true);
      requireBoolean(record.active);
      return String(record.pluginRef);
    }
    case "pluginVisibility": {
      const record = exactRecord(value, ["subjectRef", "pluginRef", "organizationRef", "decision"]);
      requireSubjectRef(record.subjectRef);
      requirePluginRef(record.pluginRef);
      requireOrganizationRef(record.organizationRef, true);
      requireDecision(record.decision);
      return `${record.subjectRef}\u0000${record.pluginRef}\u0000${record.organizationRef}`;
    }
    case "campusContexts": {
      const record = exactRecord(value, ["subjectRef", "contextKind", "contextRef", "decision"]);
      requireSubjectRef(record.subjectRef);
      requireAuthorizationContext(record.contextKind, record.contextRef);
      requireDecision(record.decision);
      return `${record.subjectRef}\u0000${record.contextKind}\u0000${record.contextRef}`;
    }
    case "effectiveDecisions": {
      const record = exactRecord(
        value,
        ["subjectRef", "contextKind", "contextRef", "resourceRef", "capabilityRef", "decision"]
      );
      requireSubjectRef(record.subjectRef);
      requireAuthorizationContext(record.contextKind, record.contextRef);
      requireToken(record.resourceRef);
      requireToken(record.capabilityRef);
      requireDecision(record.decision);
      return [
        record.subjectRef,
        record.contextKind,
        record.contextRef,
        record.resourceRef,
        record.capabilityRef
      ].join("\u0000");
    }
  }
}

function assertExactSurfaceObject(value: OrganizationSurfaceProjectionRecords, side: string): void {
  if (!isPlainRecord(value)) {
    throw new DevelopOperationEvidenceAssemblyError(`The ${side} surface object is invalid.`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...ORGANIZATION_RECONCILIATION_DEVELOP_OPERATION_EVIDENCE_SURFACES].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new DevelopOperationEvidenceAssemblyError(
      `The ${side} surface object has a missing, duplicate, or unknown surface.`
    );
  }
  for (const surface of expected) {
    if (!Array.isArray(value[surface]) || !Object.isFrozen(value[surface])) {
      throw new DevelopOperationEvidenceAssemblyError(
        `The ${side} ${surface} surface is not a detached frozen record array.`
      );
    }
  }
}

function captureSurfaceSet(candidate: readonly DevelopOperationEvidenceSurfaceName[]):
readonly DevelopOperationEvidenceSurfaceName[] {
  if (!Array.isArray(candidate) || isProxy(candidate)) {
    throw new DevelopOperationEvidenceAssemblyError("The requested surface set is invalid.");
  }
  const keys = Reflect.ownKeys(candidate);
  if (
    keys.some((key) => typeof key !== "string") ||
    keys.length !== candidate.length + 1 ||
    !keys.includes("length")
  ) {
    throw new DevelopOperationEvidenceAssemblyError("The requested surface set is non-canonical.");
  }
  const values: DevelopOperationEvidenceSurfaceName[] = [];
  for (let index = 0; index < candidate.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(candidate, String(index));
    if (!descriptor || !("value" in descriptor) || descriptor.enumerable !== true) {
      throw new DevelopOperationEvidenceAssemblyError("The requested surface set has an accessor or hole.");
    }
    if (typeof descriptor.value !== "string") {
      throw new DevelopOperationEvidenceAssemblyError("The requested surface set is invalid.");
    }
    values.push(descriptor.value as DevelopOperationEvidenceSurfaceName);
  }
  return Object.freeze(values);
}

function captureExactDataObject(
  candidate: unknown,
  expectedKeys: readonly string[],
  label: string
): Record<string, unknown> {
  if (!isPlainRecord(candidate)) {
    throw new DevelopOperationEvidenceAssemblyError(`The ${label} is invalid.`);
  }
  const ownKeys = Reflect.ownKeys(candidate);
  if (
    ownKeys.some((key) => typeof key !== "string") ||
    JSON.stringify((ownKeys as string[]).sort()) !== JSON.stringify([...expectedKeys].sort())
  ) {
    throw new DevelopOperationEvidenceAssemblyError(`The ${label} has missing or unknown fields.`);
  }
  const result: Record<string, unknown> = {};
  const descriptors = Object.getOwnPropertyDescriptors(candidate);
  for (const key of expectedKeys) {
    const descriptor = descriptors[key];
    if (!descriptor || !("value" in descriptor) || descriptor.enumerable !== true) {
      throw new DevelopOperationEvidenceAssemblyError(`The ${label} must use enumerable data fields.`);
    }
    result[key] = descriptor.value;
  }
  return result;
}

function exactRecord(value: unknown, keys: readonly string[]): Record<string, unknown> {
  const record = captureExactDataObject(value, keys, "surface record");
  if (!Object.isFrozen(value)) {
    throw new DevelopOperationEvidenceAssemblyError("A surface record is not detached and frozen.");
  }
  return record;
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value) || isProxy(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function requireLegacyOrganizationId(value: unknown): asserts value is string | number {
  if (!isCanonicalLegacyOrganizationId(value)) invalidRecord();
}

function requireSubjectRef(value: unknown): asserts value is string {
  if (!isCanonicalLegacyUserSubjectRef(value)) invalidRecord();
}

function requirePluginRef(value: unknown): asserts value is string {
  if (!isCanonicalPluginRef(value)) invalidRecord();
}

function requireOrganizationRef(value: unknown, publicAllowed: boolean): asserts value is string {
  if (!isCanonicalOrganizationRef(value, publicAllowed)) invalidRecord();
}

function requireAuthorizationContext(
  contextKind: unknown,
  contextRef: unknown
): void {
  if (!isCanonicalAuthorizationContext(contextKind, contextRef)) invalidRecord();
}

function requireToken(value: unknown): asserts value is string {
  if (!isCanonicalReconciliationToken(value)) invalidRecord();
}

function requireBoolean(value: unknown): asserts value is boolean {
  if (typeof value !== "boolean") invalidRecord();
}

function requireDecision(value: unknown): asserts value is "allow" | "deny" {
  if (value !== "allow" && value !== "deny") invalidRecord();
}

function invalidRecord(): never {
  throw new DevelopOperationEvidenceAssemblyError("A surface record has an invalid schema.");
}

function equalSets(left: ReadonlySet<string>, right: ReadonlySet<string>): boolean {
  return left.size === right.size && [...left].every((value) => right.has(value));
}
