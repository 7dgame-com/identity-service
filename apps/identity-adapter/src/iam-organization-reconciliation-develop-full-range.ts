import { createHash, randomBytes } from "node:crypto";
import { isProxy } from "node:util/types";
import {
  ORGANIZATION_OWNER_DEVELOP_APPROVED_REGISTRY_CANDIDATE,
  ORGANIZATION_OWNER_DEVELOP_DECISION_CATALOGS,
  assertOrganizationOwnerDevelopDecisionCatalogReviewPins
} from "./iam-organization-owner-semantic-registry.js";
import {
  canonicalizeOrganizationReconciliationEvidenceValue
} from "./iam-organization-reconciliation-component-manifest.js";
import {
  type OrganizationReconciliationDatasetComponentBinding
} from "./iam-organization-reconciliation-dataset-lineage.js";
import {
  ORGANIZATION_RECONCILIATION_COMPILED_BUILD_REVISION
} from "./generated/iam-organization-reconciliation-compiled-revision.js";
import {
  ORGANIZATION_RECONCILIATION_DEVELOP_ATTESTATION_COLLECTOR_METADATA_CONTRACT,
  assertOrganizationReconciliationDevelopAttestationRequestSet,
  assembleOrganizationReconciliationDevelopAttestationBundle,
  createOrganizationReconciliationDevelopAttestationRequests,
  type OrganizationReconciliationDevelopAttestationCollectorMetadata,
  type OrganizationReconciliationDevelopAttestationRequestSet,
  type OrganizationReconciliationDevelopAttestationSignatureResponse
} from "./iam-organization-reconciliation-develop-attestation-requests.js";
import {
  projectDevelopIdentityBasicSurfaces,
  projectDevelopLegacyBasicSurfaces,
  type DevelopBasicSurfaces
} from "./iam-organization-reconciliation-develop-basic-surfaces.js";
import {
  projectDevelopIdentityEffectiveDecisions,
  projectDevelopLegacyEffectiveDecisions,
  type DevelopEffectiveDecisionProjection
} from "./iam-organization-reconciliation-develop-effective-decisions.js";
import {
  createOrganizationReconciliationDevelopDeploymentEvidenceSha256,
  parseOrganizationReconciliationDevelopDeploymentEvidence,
  type OrganizationReconciliationDevelopDeploymentEvidence
} from "./iam-organization-reconciliation-develop-deployment-evidence.js";
import {
  bindOrganizationReconciliationDevelopDeploymentEvidenceToCompiledTopology
} from "./iam-organization-reconciliation-develop-deployment-topology.js";
import {
  assertDevelopOperationEvidenceBlockedAssembly,
  assembleDevelopOperationEvidence,
  createDevelopOperationEvidenceEightSurfaceCollection
} from "./iam-organization-reconciliation-develop-operation-evidence.js";
import {
  projectDevelopIdentityPluginCampusSurfaces,
  projectDevelopLegacyPluginCampusSurfaces,
  type DevelopPluginCampusSurfaces
} from "./iam-organization-reconciliation-develop-plugin-campus-surfaces.js";
import {
  createDevelopProjectionSnapshotViews,
  type IdentityDevelopProjectionSnapshotView,
  type LegacyDevelopProjectionSnapshotView
} from "./iam-organization-reconciliation-develop-projection-views.js";
import {
  ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG,
  ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG_SHA256
} from "./iam-organization-reconciliation-develop-source-catalog.js";
import {
  createVerifiedOrganizationReconciliationDevelopSourceConnectionFactory,
  runOrganizationReconciliationDevelopSourcePreflight,
  type OrganizationReconciliationDevelopSourcePreflightReport
} from "./iam-organization-reconciliation-develop-source-preflight.js";
import {
  IDENTITY_ORGANIZATION_SURFACE_PROJECTOR_CONTRACT,
  LEGACY_ORGANIZATION_SURFACE_PROJECTOR_CONTRACT,
  executeIdentityOrganizationSurfaceProjector,
  executeLegacyOrganizationSurfaceProjector,
  type IdentityOrganizationSurfaceProjection,
  type LegacyOrganizationSurfaceProjection,
  type OrganizationSurfaceProjectionDraft,
  type OrganizationSurfaceProjectionRunDescriptor
} from "./iam-organization-reconciliation-projector-contract.js";
import {
  createOrganizationReconciliationTrustPolicySha256,
  parseOrganizationReconciliationTrustPolicy,
  type OrganizationReconciliationAttestationBundle,
  type OrganizationReconciliationTrustPolicy,
  type OrganizationReconciliationTrustedProfile
} from "./iam-organization-reconciliation-provenance.js";
import {
  compiledOrganizationReconciliationTrustProfileCount,
  resolveCompiledOrganizationReconciliationTrustProfile
} from "./iam-organization-reconciliation-trust-profiles.js";
import {
  assertOrganizationReconciliationTransactionDatasetLineageFactoryProvenance,
  collectOrganizationReconciliationFactoryBoundTransactionDatasetLineage
} from "./iam-organization-reconciliation-transaction-dataset-lineage-capability.js";
import {
  validateOrganizationReconciliation,
  type OrganizationReconciliationInput,
  type OrganizationReconciliationReport
} from "./iam-organization-reconciliation-validator.js";
import {
  createOrganizationReconciliationMysqlTransactionDatasetAdapter
} from "./iam-organization-reconciliation/mysql-source-adapters/transaction-dataset-adapter.js";
import type {
  OrganizationReconciliationMysqlRawComponentId
} from "./iam-organization-reconciliation/mysql-source-adapters/raw-source-snapshots.js";
import type {
  MysqlRepeatableReadSnapshotConnectionFactory
} from "./iam-organization-reconciliation/mysql-repeatable-read-snapshot.js";

export const ORGANIZATION_RECONCILIATION_DEVELOP_FULL_RANGE_CONTRACT =
  "iam-organization-reconciliation-xrteeth-develop-full-range/v2" as const;

const MAX_WINDOW_MILLISECONDS = 3_600_000;
const REQUIRED_COMPONENTS = Object.freeze([
  "legacy-main",
  "identity",
  "plugin"
] as const satisfies readonly OrganizationReconciliationMysqlRawComponentId[]);

export interface OrganizationReconciliationDevelopFullRangeClock {
  readonly now: () => Date;
}

export interface OrganizationReconciliationDevelopFullRangeOutput {
  /** Receives the exact UTF-8 file bytes, including one terminal newline. */
  readonly write: (payload: string) => Promise<void> | void;
}

/**
 * One externally owned Ed25519 signer. The callback receives only the exact
 * domain-separated, hash-only provenance payload produced by the reviewed
 * attestation request module. It never receives organization records or the
 * reconciliation input. Private keys never enter this process/configuration.
 */
export interface OrganizationReconciliationDevelopFullRangeExternalSigner {
  readonly collectorId: string;
  readonly nodeId: string;
  readonly keyId: string;
  readonly publicKeySha256: string;
  readonly buildRevision: string;
  readonly sign: (canonicalPayloadBytes: Uint8Array) => Promise<Uint8Array> | Uint8Array;
}

export interface OrganizationReconciliationDevelopFullRangeAttestationDependencies {
  readonly environment: "xrteeth-develop";
  readonly deploymentEvidence: OrganizationReconciliationDevelopDeploymentEvidence;
  readonly trustPolicy: OrganizationReconciliationTrustPolicy;
  readonly externalSigners: readonly OrganizationReconciliationDevelopFullRangeExternalSigner[];
  readonly attestationTtlSeconds: number;
  readonly clock: OrganizationReconciliationDevelopFullRangeClock;
}

export interface OrganizationReconciliationDevelopFullRangeDependencies {
  readonly environment: "xrteeth-develop";
  readonly deploymentEvidence: OrganizationReconciliationDevelopDeploymentEvidence;
  readonly legacyConnectionFactory: MysqlRepeatableReadSnapshotConnectionFactory;
  readonly identityConnectionFactory: MysqlRepeatableReadSnapshotConnectionFactory;
  readonly pluginConnectionFactory: MysqlRepeatableReadSnapshotConnectionFactory;
  readonly expectedDatabaseUsers: Readonly<Record<OrganizationReconciliationMysqlRawComponentId, string>>;
  readonly trustPolicy: OrganizationReconciliationTrustPolicy;
  readonly externalSigners: readonly OrganizationReconciliationDevelopFullRangeExternalSigner[];
  readonly attestationTtlSeconds: number;
  readonly clock: OrganizationReconciliationDevelopFullRangeClock;
  readonly output: OrganizationReconciliationDevelopFullRangeOutput;
}

export interface OrganizationReconciliationDevelopFullRangeResult {
  readonly contract: typeof ORGANIZATION_RECONCILIATION_DEVELOP_FULL_RANGE_CONTRACT;
  readonly environment: "xrteeth-develop";
  readonly mode: "read-only";
  readonly scope: "full-range";
  readonly outcome: "completed";
  readonly buildRevision: string;
  readonly deploymentEvidenceSha256: string;
  readonly releaseImageDigest: string;
  readonly outputSha256: string;
  readonly lineageManifestSha256: string;
  readonly datasetCount: 21;
  readonly verifiedSurfaceCount: 8;
  readonly externalProvenanceVerified: true;
  readonly verifiedAttestationCount: number;
  readonly trustPolicySha256: string;
  readonly physicalIndependenceVerified: false;
  readonly productionReady: false;
  readonly productionPromotionAllowed: false;
}

export interface OrganizationReconciliationDevelopFullRangeVerifiedAttestation {
  readonly input: OrganizationReconciliationInput;
  readonly attestationBundle: OrganizationReconciliationAttestationBundle;
  readonly verificationReport: OrganizationReconciliationReport;
  readonly verifiedAt: string;
  readonly trustPolicySha256: string;
  readonly verifiedAttestationCount: number;
}

export class OrganizationReconciliationDevelopFullRangeError extends Error {
  constructor(readonly failureId:
    | "invalid-input"
    | "compiled-revision-unavailable"
    | "compiled-revision-mismatch"
    | "deployment-evidence-invalid"
    | "trust-profile-not-provisioned"
    | "trust-profile-mismatch"
    | "trust-policy-invalid"
    | "signer-not-provisioned"
    | "signer-failed"
    | "attestation-verification-failed"
    | "execution-not-authorized"
    | "source-preflight-failed"
    | "clock-invalid"
    | "output-failed") {
    super(failureId);
    this.name = "OrganizationReconciliationDevelopFullRangeError";
  }
}

interface CapturedDependencies {
  readonly environment: "xrteeth-develop";
  readonly buildRevision: string;
  readonly deploymentEvidenceCandidate: unknown;
  readonly factories: Readonly<Record<
    OrganizationReconciliationMysqlRawComponentId,
    MysqlRepeatableReadSnapshotConnectionFactory
  >>;
  readonly expectedDatabaseUsers: Readonly<Record<OrganizationReconciliationMysqlRawComponentId, string>>;
  readonly trustPolicyCandidate: unknown;
  readonly externalSignerCandidates: unknown;
  readonly attestationTtlSecondsCandidate: unknown;
  readonly now: () => Date;
  readonly write: OrganizationReconciliationDevelopFullRangeOutput["write"];
}

interface PreparedAttestationTrust {
  readonly policy: OrganizationReconciliationTrustPolicy;
  readonly trustedProfile: OrganizationReconciliationTrustedProfile;
  readonly deploymentEvidence: OrganizationReconciliationDevelopDeploymentEvidence;
  readonly deploymentEvidenceSha256: string;
  readonly collectorMetadata: OrganizationReconciliationDevelopAttestationCollectorMetadata;
  readonly signersByKey: ReadonlyMap<string, OrganizationReconciliationDevelopFullRangeExternalSigner>;
  readonly attestationTtlSeconds: number;
  readonly now: () => Date;
}

interface PendingHashOnlyAttestation {
  readonly input: OrganizationReconciliationInput;
  readonly requestSet: OrganizationReconciliationDevelopAttestationRequestSet;
  readonly trust: PreparedAttestationTrust;
}

interface PreparedDeploymentEvidence {
  readonly evidence: OrganizationReconciliationDevelopDeploymentEvidence;
  readonly sha256: string;
}

/**
 * Develop-only, read-only full-range pipeline. The two owner execution states
 * are checked after descriptor-safe input capture and before clock, output or
 * connection dependencies are invoked. While either state is blocked, this
 * function has exactly zero source opens and throws `execution-not-authorized`.
 */
export async function runOrganizationReconciliationDevelopFullRange(
  candidate: OrganizationReconciliationDevelopFullRangeDependencies
): Promise<OrganizationReconciliationDevelopFullRangeResult> {
  const compiledBuildRevision = assertOrganizationReconciliationDevelopFullRangeCompiledRevision();
  const dependencies = captureDependencies(candidate, compiledBuildRevision);
  const deployment = prepareDeploymentEvidence(
    dependencies.deploymentEvidenceCandidate,
    dependencies.buildRevision
  );
  const attestationTrust = prepareAttestationTrust({
    environment: dependencies.environment,
    buildRevision: dependencies.buildRevision,
    trustPolicy: dependencies.trustPolicyCandidate,
    externalSigners: dependencies.externalSignerCandidates,
    attestationTtlSeconds: dependencies.attestationTtlSecondsCandidate,
    now: dependencies.now,
    deployment
  });
  requireAuthorizedExecution();

  const startedAt = readClock(dependencies.now).toISOString();
  const preflight = await runOrganizationReconciliationDevelopSourcePreflight({
    legacyConnectionFactory: dependencies.factories["legacy-main"],
    identityConnectionFactory: dependencies.factories.identity,
    pluginConnectionFactory: dependencies.factories.plugin,
    expectedDatabaseUsers: dependencies.expectedDatabaseUsers,
    buildRevision: dependencies.buildRevision,
    now: () => readClock(dependencies.now)
  });
  if (!preflight.passed) {
    throw new OrganizationReconciliationDevelopFullRangeError("source-preflight-failed");
  }

  const evidenceNonce = randomBytes(32).toString("hex");
  const components = createComponentBindings(dependencies, preflight, evidenceNonce);
  const run = await collectOrganizationReconciliationFactoryBoundTransactionDatasetLineage({
    components,
    maxWindowMilliseconds: MAX_WINDOW_MILLISECONDS,
    clock: Object.freeze({ now: () => readClock(dependencies.now) })
  });
  const transactionFactoryProvenance =
    assertOrganizationReconciliationTransactionDatasetLineageFactoryProvenance(run);
  const views = createDevelopProjectionSnapshotViews(run);
  const semanticRegistrySha256 =
    ORGANIZATION_OWNER_DEVELOP_APPROVED_REGISTRY_CANDIDATE.registrySha256;

  const legacyBasic = projectDevelopLegacyBasicSurfaces(views.legacy, semanticRegistrySha256);
  const identityBasic = projectDevelopIdentityBasicSurfaces(views.identity, semanticRegistrySha256);
  const legacyPluginCampus = projectDevelopLegacyPluginCampusSurfaces(views.legacy);
  const identityPluginCampus = projectDevelopIdentityPluginCampusSurfaces(views.identity);
  const legacyEffective = projectDevelopLegacyEffectiveDecisions(views.legacy, semanticRegistrySha256);
  const identityEffective = projectDevelopIdentityEffectiveDecisions(views.identity, semanticRegistrySha256);

  const projections = await executeProjectionPair({
    buildRevision: dependencies.buildRevision,
    semanticRegistrySha256,
    legacyView: views.legacy,
    identityView: views.identity,
    legacyDraft: combineSurfaces(legacyBasic, legacyPluginCampus, legacyEffective),
    identityDraft: combineSurfaces(identityBasic, identityPluginCampus, identityEffective)
  });
  const surfaceCollection = createDevelopOperationEvidenceEightSurfaceCollection(
    projections.legacy,
    projections.identity
  );
  const operationEvidence = assembleDevelopOperationEvidence({
    run,
    legacyProjection: projections.legacy,
    identityProjection: projections.identity,
    surfaceCollection,
    semanticRegistrySha256,
    evidenceNonce,
    collectorBuildRevision: dependencies.buildRevision
  });
  assertDevelopOperationEvidenceBlockedAssembly(operationEvidence);
  const reconciliationInput = canonicalizeOrganizationReconciliationEvidenceValue({
    ...operationEvidence.evidence,
    componentManifest: operationEvidence.componentManifest
  }) as unknown as OrganizationReconciliationInput;
  const verifiedAttestation = await requestSignaturesAndVerify(
    createHashOnlyAttestationRequests(reconciliationInput, attestationTrust)
  );
  const completedAt = readClock(dependencies.now).toISOString();
  const artifact = canonicalizeOrganizationReconciliationEvidenceValue({
    contract: ORGANIZATION_RECONCILIATION_DEVELOP_FULL_RANGE_CONTRACT,
    environment: dependencies.environment,
    nodeId: "xrteeth",
    mode: "read-only",
    scope: "full-range",
    buildRevision: dependencies.buildRevision,
    deploymentEvidenceSha256: attestationTrust.deploymentEvidenceSha256,
    releaseImageDigest: attestationTrust.deploymentEvidence.releaseImageDigest,
    startedAt,
    completedAt,
    sourceCatalogSha256: ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG_SHA256,
    semanticRegistrySha256,
    datasetCount: 21,
    verifiedSurfaceCount: 8,
    dryRun: true,
    writeSideEffects: "none",
    productionWritePerformed: false,
    tmrppUntouched: true,
    physicalIndependenceVerified: false,
    productionReady: false,
    productionPromotionAllowed: false,
    sourcePreflight: preflight,
    transactionFactoryProvenance,
    lineageRun: run,
    legacyProjection: projections.legacy,
    identityProjection: projections.identity,
    operationEvidence,
    reconciliationInput: verifiedAttestation.input,
    externalProvenanceVerified: true,
    verifiedAttestationCount: verifiedAttestation.verifiedAttestationCount,
    trustPolicySha256: verifiedAttestation.trustPolicySha256,
    attestationBundle: verifiedAttestation.attestationBundle,
    verificationReport: verifiedAttestation.verificationReport
  });
  const payload = `${JSON.stringify(artifact)}\n`;
  const outputSha256 = createHash("sha256").update(payload, "utf8").digest("hex");
  try {
    await dependencies.write.call(undefined, payload);
  } catch {
    throw new OrganizationReconciliationDevelopFullRangeError("output-failed");
  }
  return Object.freeze({
    contract: ORGANIZATION_RECONCILIATION_DEVELOP_FULL_RANGE_CONTRACT,
    environment: dependencies.environment,
    mode: "read-only",
    scope: "full-range",
    outcome: "completed",
    buildRevision: dependencies.buildRevision,
    deploymentEvidenceSha256: attestationTrust.deploymentEvidenceSha256,
    releaseImageDigest: attestationTrust.deploymentEvidence.releaseImageDigest,
    outputSha256,
    lineageManifestSha256: run.coordinatorManifest.manifestSha256,
    datasetCount: 21,
    verifiedSurfaceCount: 8,
    externalProvenanceVerified: true,
    verifiedAttestationCount: verifiedAttestation.verifiedAttestationCount,
    trustPolicySha256: verifiedAttestation.trustPolicySha256,
    physicalIndependenceVerified: false,
    productionReady: false,
    productionPromotionAllowed: false
  });
}

function createComponentBindings(
  dependencies: CapturedDependencies,
  preflight: OrganizationReconciliationDevelopSourcePreflightReport,
  evidenceNonce: string
): readonly OrganizationReconciliationDatasetComponentBinding[] {
  const preflightByComponent = new Map(
    preflight.components.map((component) => [component.componentId, component])
  );
  return Object.freeze(ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG.components.map((component) => {
    const inspected = preflightByComponent.get(component.componentId);
    if (!inspected || !inspected.databaseBindingPassed || !inspected.readOnlyGrantPassed ||
      !inspected.schemaShapePassed || !/^[a-f0-9]{64}$/.test(inspected.physicalSchemaSha256)) {
      throw new OrganizationReconciliationDevelopFullRangeError("source-preflight-failed");
    }
    const connectionFactory =
      createVerifiedOrganizationReconciliationDevelopSourceConnectionFactory(
        component.componentId,
        dependencies.factories[component.componentId],
        dependencies.expectedDatabaseUsers[component.componentId]
      );
    const adapter = createOrganizationReconciliationMysqlTransactionDatasetAdapter({
      componentId: component.componentId,
      expectedSourceId: component.expectedSourceId,
      connectionFactory,
      evidenceNonce,
      catalogSha256: component.declaredCatalogSha256,
      datasetCatalog: component.datasetCatalog
    });
    return Object.freeze({
      componentId: component.componentId,
      expectedSourceId: component.expectedSourceId,
      schemaSha256: inspected.physicalSchemaSha256,
      catalogSha256: component.declaredCatalogSha256,
      buildSha256: scopedDigest("component-build", dependencies.buildRevision, component.componentId),
      adapter,
      datasetCatalog: component.datasetCatalog
    } satisfies OrganizationReconciliationDatasetComponentBinding);
  }));
}

function combineSurfaces(
  basic: DevelopBasicSurfaces,
  pluginCampus: DevelopPluginCampusSurfaces,
  effective: DevelopEffectiveDecisionProjection
): OrganizationSurfaceProjectionDraft {
  if (
    basic.semanticRegistrySha256 !== pluginCampus.semanticRegistrySha256 ||
    basic.semanticRegistrySha256 !== effective.semanticRegistrySha256
  ) {
    throw new Error("The fixed Develop surface stages use different semantic registries.");
  }
  return Object.freeze({
    surfaces: Object.freeze({
      organizationDirectory: basic.organizationDirectory,
      organizationMappings: basic.organizationMappings,
      memberships: basic.memberships,
      organizationScopedRoles: basic.organizationScopedRoles,
      pluginBindings: pluginCampus.pluginBindings,
      pluginVisibility: pluginCampus.pluginVisibility,
      campusContexts: pluginCampus.campusContexts,
      effectiveDecisions: effective.effectiveDecisions
    })
  });
}

async function executeProjectionPair(input: Readonly<{
  buildRevision: string;
  semanticRegistrySha256: string;
  legacyView: LegacyDevelopProjectionSnapshotView;
  identityView: IdentityDevelopProjectionSnapshotView;
  legacyDraft: OrganizationSurfaceProjectionDraft;
  identityDraft: OrganizationSurfaceProjectionDraft;
}>): Promise<Readonly<{
  legacy: LegacyOrganizationSurfaceProjection;
  identity: IdentityOrganizationSurfaceProjection;
}>> {
  const legacyDescriptor = projectionRunDescriptor(input.legacyView);
  const identityDescriptor = projectionRunDescriptor(input.identityView);
  const legacyProjector = Object.freeze({
    side: "legacy" as const,
    contract: LEGACY_ORGANIZATION_SURFACE_PROJECTOR_CONTRACT,
    evaluatorId: "xrteeth-develop/full-range/legacy/v1",
    evaluatorBuildSha256: scopedDigest("legacy-projector", input.buildRevision),
    project: ({ snapshotView, semanticRegistrySha256 }: Readonly<{
      snapshotView: LegacyDevelopProjectionSnapshotView;
      semanticRegistrySha256: string;
    }>) => {
      if (snapshotView !== input.legacyView || semanticRegistrySha256 !== input.semanticRegistrySha256) {
        throw new Error("The Legacy full-range projector received a different run binding.");
      }
      return input.legacyDraft;
    }
  });
  const identityProjector = Object.freeze({
    side: "identity" as const,
    contract: IDENTITY_ORGANIZATION_SURFACE_PROJECTOR_CONTRACT,
    evaluatorId: "xrteeth-develop/full-range/identity/v1",
    evaluatorBuildSha256: scopedDigest("identity-projector", input.buildRevision),
    project: ({ snapshotView, semanticRegistrySha256 }: Readonly<{
      snapshotView: IdentityDevelopProjectionSnapshotView;
      semanticRegistrySha256: string;
    }>) => {
      if (snapshotView !== input.identityView || semanticRegistrySha256 !== input.semanticRegistrySha256) {
        throw new Error("The Identity full-range projector received a different run binding.");
      }
      return input.identityDraft;
    }
  });
  const [legacy, identity] = await Promise.all([
    executeLegacyOrganizationSurfaceProjector(
      legacyProjector,
      input.legacyView,
      input.semanticRegistrySha256,
      legacyDescriptor
    ),
    executeIdentityOrganizationSurfaceProjector(
      identityProjector,
      input.identityView,
      input.semanticRegistrySha256,
      identityDescriptor
    )
  ]);
  return Object.freeze({ legacy, identity });
}

function projectionRunDescriptor(
  view: LegacyDevelopProjectionSnapshotView | IdentityDevelopProjectionSnapshotView
): OrganizationSurfaceProjectionRunDescriptor {
  return Object.freeze({
    lineageManifestSha256: view.lineageManifestSha256,
    primarySource: Object.freeze({
      sourceVersion: view.sourceVersion,
      snapshotId: view.snapshotId
    }),
    pluginSource: Object.freeze({
      sourceVersion: view.pluginSourceVersion,
      snapshotId: view.pluginSnapshotId
    })
  });
}

function captureDependencies(candidate: unknown, compiledBuildRevision: string): CapturedDependencies {
  try {
    const input = exactObject(candidate, [
      "environment",
      "deploymentEvidence",
      "legacyConnectionFactory",
      "identityConnectionFactory",
      "pluginConnectionFactory",
      "expectedDatabaseUsers",
      "trustPolicy",
      "externalSigners",
      "attestationTtlSeconds",
      "clock",
      "output"
    ]);
    if (input.environment !== "xrteeth-develop") {
      invalidInput();
    }
    const factories = [
      input.legacyConnectionFactory,
      input.identityConnectionFactory,
      input.pluginConnectionFactory
    ];
    if (factories.some((factory) => typeof factory !== "function") || new Set(factories).size !== 3) {
      invalidInput();
    }
    const users = exactObject(input.expectedDatabaseUsers, REQUIRED_COMPONENTS);
    const userValues = REQUIRED_COMPONENTS.map((componentId) => users[componentId]);
    if (userValues.some((user) => typeof user !== "string" || !/^[A-Za-z0-9_.-]{1,64}$/.test(user)) ||
      new Set(userValues).size !== REQUIRED_COMPONENTS.length) {
      invalidInput();
    }
    const clock = exactObject(input.clock, ["now"]);
    const output = exactObject(input.output, ["write"]);
    if (typeof clock.now !== "function" || typeof output.write !== "function") invalidInput();
    return Object.freeze({
      environment: "xrteeth-develop",
      buildRevision: compiledBuildRevision,
      deploymentEvidenceCandidate: input.deploymentEvidence,
      factories: Object.freeze({
        "legacy-main": factories[0] as MysqlRepeatableReadSnapshotConnectionFactory,
        identity: factories[1] as MysqlRepeatableReadSnapshotConnectionFactory,
        plugin: factories[2] as MysqlRepeatableReadSnapshotConnectionFactory
      }),
      expectedDatabaseUsers: Object.freeze({
        "legacy-main": userValues[0] as string,
        identity: userValues[1] as string,
        plugin: userValues[2] as string
      }),
      trustPolicyCandidate: input.trustPolicy,
      externalSignerCandidates: input.externalSigners,
      attestationTtlSecondsCandidate: input.attestationTtlSeconds,
      now: clock.now as () => Date,
      write: output.write as OrganizationReconciliationDevelopFullRangeOutput["write"]
    });
  } catch (error) {
    if (error instanceof OrganizationReconciliationDevelopFullRangeError) throw error;
    invalidInput();
  }
}

/**
 * Returns the immutable build-stage revision. Runtime environment, argv and
 * caller dependencies are intentionally not consulted.
 */
export function assertOrganizationReconciliationDevelopFullRangeCompiledRevision(
  expectedBuildRevision?: string
): string {
  const compiledBuildRevision = ORGANIZATION_RECONCILIATION_COMPILED_BUILD_REVISION;
  if (typeof compiledBuildRevision !== "string" ||
    !/^[a-f0-9]{40}$/.test(compiledBuildRevision)) {
    throw new OrganizationReconciliationDevelopFullRangeError("compiled-revision-unavailable");
  }
  if (expectedBuildRevision !== undefined &&
    expectedBuildRevision !== compiledBuildRevision) {
    throw new OrganizationReconciliationDevelopFullRangeError("compiled-revision-mismatch");
  }
  return compiledBuildRevision;
}

/**
 * Static release gate used by the core runner and CLI before any database,
 * random, clock, signer, or output dependency can be invoked.
 */
export function assertOrganizationReconciliationDevelopFullRangeTrustProfileProvisioned(): void {
  if (compiledOrganizationReconciliationTrustProfileCount !== 1) {
    throw new OrganizationReconciliationDevelopFullRangeError("trust-profile-not-provisioned");
  }
}

function prepareDeploymentEvidence(
  candidate: unknown,
  buildRevision: string
): PreparedDeploymentEvidence {
  try {
    const evidence = parseOrganizationReconciliationDevelopDeploymentEvidence(candidate);
    if (evidence.environment !== "xrteeth-develop" || evidence.buildRevision !== buildRevision) {
      throw new Error("deployment binding mismatch");
    }
    return Object.freeze({
      evidence,
      sha256: createOrganizationReconciliationDevelopDeploymentEvidenceSha256(evidence)
    });
  } catch {
    throw new OrganizationReconciliationDevelopFullRangeError("deployment-evidence-invalid");
  }
}

function prepareAttestationTrust(input: Readonly<{
  environment: "xrteeth-develop";
  buildRevision: string;
  trustPolicy: unknown;
  externalSigners: unknown;
  attestationTtlSeconds: unknown;
  now: () => Date;
  deployment: PreparedDeploymentEvidence;
}>): PreparedAttestationTrust {
  assertOrganizationReconciliationDevelopFullRangeTrustProfileProvisioned();

  let policy: OrganizationReconciliationTrustPolicy;
  try {
    const canonicalPolicy = canonicalizeOrganizationReconciliationEvidenceValue(input.trustPolicy);
    policy = parseOrganizationReconciliationTrustPolicy(canonicalPolicy);
  } catch {
    throw new OrganizationReconciliationDevelopFullRangeError("trust-policy-invalid");
  }
  const trustedProfile = resolveCompiledOrganizationReconciliationTrustProfile(policy.profileId);
  if (!trustedProfile || trustedProfile.expectedEnvironment !== input.environment) {
    throw new OrganizationReconciliationDevelopFullRangeError("trust-profile-mismatch");
  }
  if (!policyMatchesCompiledProfile(policy, trustedProfile, input.buildRevision)) {
    throw new OrganizationReconciliationDevelopFullRangeError("trust-profile-mismatch");
  }
  let pinnedDeployment: OrganizationReconciliationDevelopDeploymentEvidence;
  try {
    pinnedDeployment = bindOrganizationReconciliationDevelopDeploymentEvidenceToCompiledTopology(
      input.deployment.evidence,
      policy.profileId
    ).deploymentEvidence;
  } catch {
    throw new OrganizationReconciliationDevelopFullRangeError("deployment-evidence-invalid");
  }
  if (!deploymentMatchesPolicy(pinnedDeployment, policy, input.buildRevision)) {
    throw new OrganizationReconciliationDevelopFullRangeError("deployment-evidence-invalid");
  }
  if (!Number.isSafeInteger(input.attestationTtlSeconds) ||
    (input.attestationTtlSeconds as number) < 1 ||
    (input.attestationTtlSeconds as number) > policy.maxAttestationTtlSeconds) {
    throw new OrganizationReconciliationDevelopFullRangeError("trust-policy-invalid");
  }

  const signers = captureExternalSigners(
    input.externalSigners,
    trustedProfile,
    pinnedDeployment
  );
  return Object.freeze({
    policy,
    trustedProfile,
    deploymentEvidence: pinnedDeployment,
    deploymentEvidenceSha256: input.deployment.sha256,
    collectorMetadata: collectorMetadataForCompiledProfile(
      trustedProfile,
      input.deployment.sha256
    ),
    signersByKey: new Map(signers.map((signer) => [signer.keyId, signer])),
    attestationTtlSeconds: input.attestationTtlSeconds as number,
    now: input.now
  });
}

function policyMatchesCompiledProfile(
  policy: OrganizationReconciliationTrustPolicy,
  profile: OrganizationReconciliationTrustedProfile,
  buildRevision: string
): boolean {
  if (
    policy.profileId !== profile.profileId ||
    policy.environment !== profile.expectedEnvironment ||
    policy.environment !== "xrteeth-develop" ||
    createOrganizationReconciliationTrustPolicySha256(policy) !== profile.policySha256 ||
    policy.requiredCollectors.length !== profile.requiredCollectors.length
  ) return false;
  const policyByKey = new Map(policy.requiredCollectors.map((collector) => [collector.keyId, collector]));
  for (const expected of profile.requiredCollectors) {
    const collector = policyByKey.get(expected.keyId);
    if (
      !collector ||
      collector.collectorId !== expected.collectorId ||
      collector.nodeId !== expected.nodeId ||
      collector.publicKeySha256 !== expected.publicKeySha256 ||
      collector.buildRevision !== expected.buildRevision ||
      collector.buildRevision !== buildRevision ||
      collector.algorithm !== "Ed25519"
    ) return false;
  }
  return policyByKey.size === profile.requiredCollectors.length;
}

function deploymentMatchesPolicy(
  deployment: OrganizationReconciliationDevelopDeploymentEvidence,
  policy: OrganizationReconciliationTrustPolicy,
  buildRevision: string
): boolean {
  if (
    deployment.environment !== "xrteeth-develop" ||
    deployment.buildRevision !== buildRevision ||
    policy.requiredCollectors.length !== 1 ||
    deployment.signers.length !== policy.requiredCollectors.length
  ) return false;
  const deployedByKey = new Map(deployment.signers.map((signer) => [signer.keyId, signer]));
  for (const collector of policy.requiredCollectors) {
    const deployed = deployedByKey.get(collector.keyId);
    if (
      !deployed ||
      deployed.collectorId !== collector.collectorId ||
      deployed.nodeId !== collector.nodeId ||
      deployed.publicKeySha256 !== collector.publicKeySha256 ||
      collector.buildRevision !== buildRevision
    ) return false;
  }
  return deployedByKey.size === policy.requiredCollectors.length;
}

function collectorMetadataForCompiledProfile(
  profile: OrganizationReconciliationTrustedProfile,
  deploymentEvidenceSha256: string
): OrganizationReconciliationDevelopAttestationCollectorMetadata {
  return Object.freeze({
    contract: ORGANIZATION_RECONCILIATION_DEVELOP_ATTESTATION_COLLECTOR_METADATA_CONTRACT,
    profileId: profile.profileId,
    environment: profile.expectedEnvironment,
    trustPolicySha256: profile.policySha256,
    deploymentEvidenceSha256,
    collectors: Object.freeze(profile.requiredCollectors.map((collector) => Object.freeze({
      collectorId: collector.collectorId,
      nodeId: collector.nodeId,
      keyId: collector.keyId,
      publicKeySha256: collector.publicKeySha256,
      buildRevision: collector.buildRevision
    })))
  });
}

function captureExternalSigners(
  candidate: unknown,
  profile: OrganizationReconciliationTrustedProfile,
  deploymentEvidence: OrganizationReconciliationDevelopDeploymentEvidence
): readonly OrganizationReconciliationDevelopFullRangeExternalSigner[] {
  try {
    if (!Array.isArray(candidate) || isProxy(candidate) || Object.getPrototypeOf(candidate) !== Array.prototype ||
      Object.getOwnPropertySymbols(candidate).length !== 0) {
      throw new Error("invalid signer set");
    }
    const descriptors = Object.getOwnPropertyDescriptors(candidate);
    const lengthDescriptor = descriptors["length"] as PropertyDescriptor | undefined;
    if (!lengthDescriptor || !("value" in lengthDescriptor) || lengthDescriptor.enumerable ||
      lengthDescriptor.value !== profile.requiredCollectors.length ||
      Object.keys(descriptors).length !== profile.requiredCollectors.length + 1) {
      throw new Error("invalid signer set");
    }
    const expectedByKey = new Map(profile.requiredCollectors.map((collector) => [collector.keyId, collector]));
    const deployedByKey = new Map(deploymentEvidence.signers.map((signer) => [signer.keyId, signer]));
    const seenKeys = new Set<string>();
    const signers: OrganizationReconciliationDevelopFullRangeExternalSigner[] = [];
    for (let index = 0; index < profile.requiredCollectors.length; index += 1) {
      const itemDescriptor = descriptors[String(index)];
      if (!itemDescriptor || !("value" in itemDescriptor) || !itemDescriptor.enumerable) {
        throw new Error("invalid signer set");
      }
      const signer = captureExternalSigner(itemDescriptor.value);
      const expected = expectedByKey.get(signer.keyId);
      const deployed = deployedByKey.get(signer.keyId);
      if (!expected || seenKeys.has(signer.keyId) ||
        !deployed ||
        signer.collectorId !== expected.collectorId || signer.nodeId !== expected.nodeId ||
        signer.publicKeySha256 !== expected.publicKeySha256 ||
        signer.buildRevision !== expected.buildRevision ||
        signer.collectorId !== deployed.collectorId || signer.nodeId !== deployed.nodeId ||
        signer.publicKeySha256 !== deployed.publicKeySha256) {
        throw new Error("invalid signer set");
      }
      seenKeys.add(signer.keyId);
      signers.push(signer);
    }
    if (seenKeys.size !== profile.requiredCollectors.length) throw new Error("invalid signer set");
    return Object.freeze(signers);
  } catch {
    throw new OrganizationReconciliationDevelopFullRangeError("signer-not-provisioned");
  }
}

function captureExternalSigner(candidate: unknown): OrganizationReconciliationDevelopFullRangeExternalSigner {
  const signer = exactObject(candidate, [
    "collectorId", "nodeId", "keyId", "publicKeySha256", "buildRevision", "sign"
  ]);
  if (
    typeof signer.collectorId !== "string" ||
    typeof signer.nodeId !== "string" ||
    typeof signer.keyId !== "string" ||
    typeof signer.publicKeySha256 !== "string" ||
    typeof signer.buildRevision !== "string" ||
    typeof signer.sign !== "function"
  ) throw new Error("invalid signer");
  return Object.freeze({
    collectorId: signer.collectorId,
    nodeId: signer.nodeId,
    keyId: signer.keyId,
    publicKeySha256: signer.publicKeySha256,
    buildRevision: signer.buildRevision,
    sign: signer.sign as OrganizationReconciliationDevelopFullRangeExternalSigner["sign"]
  });
}

function createHashOnlyAttestationRequests(
  input: OrganizationReconciliationInput,
  trust: PreparedAttestationTrust
): PendingHashOnlyAttestation {
  try {
    const requestSet = createOrganizationReconciliationDevelopAttestationRequests({
      input,
      trustPolicy: trust.policy,
      collectorMetadata: trust.collectorMetadata,
      clock: Object.freeze({ now: () => readClock(trust.now) }),
      attestationTtlSeconds: trust.attestationTtlSeconds
    });
    if (requestSet.requests.length !== trust.trustedProfile.requiredCollectors.length) {
      throw new Error("request count mismatch");
    }
    return Object.freeze({ input, requestSet, trust });
  } catch (error) {
    if (error instanceof OrganizationReconciliationDevelopFullRangeError) throw error;
    throw new OrganizationReconciliationDevelopFullRangeError("attestation-verification-failed");
  }
}

async function requestSignaturesAndVerify(
  pending: PendingHashOnlyAttestation
): Promise<OrganizationReconciliationDevelopFullRangeVerifiedAttestation> {
  const responses = await requestOrganizationReconciliationDevelopHashOnlySignatures(
    pending.requestSet,
    pending.trust.signersByKey
  );
  return assembleAndVerifyHashOnlyAttestation(pending, responses);
}

/**
 * Authorized Develop-only transport boundary. It sends only the canonical,
 * domain-separated provenance bytes already exposed by the request set. The
 * returned signatures carry no trust claim until the caller assembles and
 * verifies the complete bundle against the compiled profile.
 */
export async function requestOrganizationReconciliationDevelopHashOnlySignatures(
  requestSet: OrganizationReconciliationDevelopAttestationRequestSet,
  signersByKey: ReadonlyMap<string, OrganizationReconciliationDevelopFullRangeExternalSigner>
): Promise<readonly OrganizationReconciliationDevelopAttestationSignatureResponse[]> {
  assertOrganizationReconciliationDevelopAttestationRequestSet(requestSet);
  const boundRequests = requestSet.requests.map((request) => {
    const signer = signersByKey.get(request.keyId);
    if (
      !signer ||
      signer.collectorId !== request.collectorId ||
      signer.nodeId !== request.nodeId ||
      signer.publicKeySha256 !== request.publicKeySha256 ||
      signer.buildRevision !== request.collectorBuildRevision
    ) {
      throw new OrganizationReconciliationDevelopFullRangeError("signer-not-provisioned");
    }
    return Object.freeze({ request, signer });
  });
  try {
    const settled = await Promise.allSettled(boundRequests.map(async ({ request, signer }) => {
      const decoded = Buffer.from(request.payloadBytesBase64url, "base64url");
      const payloadBytes = Uint8Array.from(decoded);
      decoded.fill(0);
      try {
        const signature = await signer.sign.call(undefined, payloadBytes);
        return Object.freeze({
          collectorId: request.collectorId,
          keyId: request.keyId,
          payloadSha256: request.payloadSha256,
          signature
        });
      } finally {
        payloadBytes.fill(0);
      }
    }));
    if (settled.some((result) => result.status === "rejected")) {
      throw new OrganizationReconciliationDevelopFullRangeError("signer-failed");
    }
    return Object.freeze(settled.map((result) =>
      (result as PromiseFulfilledResult<OrganizationReconciliationDevelopAttestationSignatureResponse>).value
    ));
  } catch (error) {
    if (error instanceof OrganizationReconciliationDevelopFullRangeError) throw error;
    throw new OrganizationReconciliationDevelopFullRangeError("signer-failed");
  }
}

function assembleAndVerifyHashOnlyAttestation(
  pending: PendingHashOnlyAttestation,
  responses: readonly OrganizationReconciliationDevelopAttestationSignatureResponse[]
): OrganizationReconciliationDevelopFullRangeVerifiedAttestation {
  let bundle: OrganizationReconciliationAttestationBundle;
  try {
    bundle = assembleOrganizationReconciliationDevelopAttestationBundle(
      pending.requestSet,
      responses
    );
  } catch {
    throw new OrganizationReconciliationDevelopFullRangeError("signer-failed");
  }
  const verifiedAt = readClock(pending.trust.now);
  const verificationReport = validateOrganizationReconciliation(pending.input, {
    trustedProvenance: {
      trustedProfile: pending.trust.trustedProfile,
      trustPolicy: pending.trust.policy,
      attestationBundle: bundle,
      expectedDeploymentEvidenceSha256: pending.trust.deploymentEvidenceSha256,
      now: verifiedAt
    }
  });
  const unexpectedBlockers = verificationReport.coverageBlockers.filter((blocker) =>
    blocker.code !== "real-source-adapters-not-ready"
  );
  if (
    !verificationReport.provenanceVerification.verified ||
    verificationReport.provenanceVerification.reasonCode !== "verified" ||
    verificationReport.provenanceVerification.requiredAttestationCount !==
      pending.trust.trustedProfile.requiredCollectors.length ||
    verificationReport.provenanceVerification.verifiedAttestationCount !==
      pending.trust.trustedProfile.requiredCollectors.length ||
    verificationReport.coverage.length !== 8 ||
    verificationReport.coverage.some((surface) => !surface.paginationComplete) ||
    unexpectedBlockers.length !== 0 ||
    verificationReport.severity.P0 !== 0 ||
    verificationReport.severity.P1 !== 0 ||
    verificationReport.severity.P2 !== 0
  ) {
    throw new OrganizationReconciliationDevelopFullRangeError("attestation-verification-failed");
  }
  return Object.freeze({
    input: pending.input,
    attestationBundle: bundle,
    verificationReport,
    verifiedAt: verifiedAt.toISOString(),
    trustPolicySha256: pending.requestSet.trustPolicySha256,
    verifiedAttestationCount: verificationReport.provenanceVerification.verifiedAttestationCount
  });
}

function requireAuthorizedExecution(): void {
  assertOrganizationOwnerDevelopDecisionCatalogReviewPins(
    ORGANIZATION_OWNER_DEVELOP_DECISION_CATALOGS
  );
  const campus = ORGANIZATION_OWNER_DEVELOP_DECISION_CATALOGS.campusPublicContext as unknown as {
    readonly executionState?: unknown;
  };
  const capability = ORGANIZATION_OWNER_DEVELOP_DECISION_CATALOGS.capabilityCatalog as unknown as {
    readonly executionState?: unknown;
  };
  if (campus.executionState !== "owner-bound-campus-context-decision-execution" ||
    capability.executionState !== "owner-bound-context-decision-execution") {
    throw new OrganizationReconciliationDevelopFullRangeError("execution-not-authorized");
  }
}

function readClock(now: () => Date): Date {
  let value: unknown;
  try {
    value = now.call(undefined);
  } catch {
    throw new OrganizationReconciliationDevelopFullRangeError("clock-invalid");
  }
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
    throw new OrganizationReconciliationDevelopFullRangeError("clock-invalid");
  }
  return new Date(value.getTime());
}

function exactObject(candidate: unknown, expectedKeys: readonly string[]): Readonly<Record<string, unknown>> {
  if (
    candidate === null || typeof candidate !== "object" || Array.isArray(candidate) || isProxy(candidate) ||
    (Object.getPrototypeOf(candidate) !== Object.prototype && Object.getPrototypeOf(candidate) !== null) ||
    Object.getOwnPropertySymbols(candidate).length > 0
  ) {
    invalidInput();
  }
  const descriptors = Object.getOwnPropertyDescriptors(candidate as object);
  if (Object.keys(descriptors).sort().join("\u001f") !== [...expectedKeys].sort().join("\u001f")) {
    invalidInput();
  }
  const captured: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const key of expectedKeys) {
    const descriptor = descriptors[key];
    if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) invalidInput();
    captured[key] = descriptor.value;
  }
  return Object.freeze(captured);
}

function invalidInput(): never {
  throw new OrganizationReconciliationDevelopFullRangeError("invalid-input");
}

function scopedDigest(scope: string, ...parts: readonly string[]): string {
  return createHash("sha256")
    .update(`iam-organization-reconciliation:xrteeth-develop-full-range:${scope}:v1\u001f`, "utf8")
    .update(parts.join("\u001f"), "utf8")
    .digest("hex");
}
