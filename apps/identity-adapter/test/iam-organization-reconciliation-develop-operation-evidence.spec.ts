import { describe, expect, it } from "vitest";
import {
  ORGANIZATION_OWNER_DEVELOP_APPROVED_REGISTRY_CANDIDATE,
  ORGANIZATION_OWNER_DEVELOP_DECISION_CATALOGS
} from "../src/iam-organization-owner-semantic-registry.js";
import {
  collectOrganizationReconciliationDatasetLineage,
  type OrganizationReconciliationDatasetComponentBinding,
  type OrganizationReconciliationDatasetPage,
  type OrganizationReconciliationDatasetSourceAdapter,
  type OrganizationReconciliationDatasetLineageRun
} from "../src/iam-organization-reconciliation-dataset-lineage.js";
import {
  ORGANIZATION_RECONCILIATION_DEVELOP_OPERATION_EVIDENCE_BLOCKERS,
  ORGANIZATION_RECONCILIATION_DEVELOP_OPERATION_EVIDENCE_IMPLEMENTED,
  ORGANIZATION_RECONCILIATION_DEVELOP_OPERATION_EVIDENCE_READY,
  ORGANIZATION_RECONCILIATION_DEVELOP_OPERATION_EVIDENCE_SURFACES,
  assembleDevelopOperationEvidence,
  assertDevelopOperationEvidenceBlockedAssembly,
  createDevelopOperationEvidenceCollectionWindow,
  createDevelopOperationEvidenceEightSurfaceCollection,
  organizationReconciliationDevelopOperationEvidenceReadiness,
  type AssembleDevelopOperationEvidenceInput,
  type DevelopOperationEvidenceEightSurfaceCollection,
  type DevelopOperationEvidenceSurfaceName
} from "../src/iam-organization-reconciliation-develop-operation-evidence.js";
import {
  createDevelopProjectionSnapshotViews,
  type DevelopProjectionSnapshotViews
} from "../src/iam-organization-reconciliation-develop-projection-views.js";
import {
  ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG
} from "../src/iam-organization-reconciliation-develop-source-catalog.js";
import {
  IDENTITY_ORGANIZATION_SURFACE_PROJECTOR_CONTRACT,
  LEGACY_ORGANIZATION_SURFACE_PROJECTOR_CONTRACT,
  executeIdentityOrganizationSurfaceProjector,
  executeLegacyOrganizationSurfaceProjector,
  type IdentityOrganizationSurfaceProjection,
  type LegacyOrganizationSurfaceProjection,
  type OrganizationSurfaceProjectionDraft
} from "../src/iam-organization-reconciliation-projector-contract.js";
import {
  ORGANIZATION_RECONCILIATION_PAGINATION_MODE,
  ORGANIZATION_RECONCILIATION_SNAPSHOT_MODE,
  type OrganizationReconciliationSourceSnapshot
} from "../src/iam-organization-reconciliation-collector.js";
import {
  createOrganizationReconciliationComponentDatasetInventory,
  createOrganizationReconciliationContentSnapshotId,
  createOrganizationReconciliationContentSourceVersion,
  type OrganizationReconciliationDatasetInventoryPageInput,
  type OrganizationReconciliationInventoryJsonValue
} from "../src/iam-organization-reconciliation-dataset-inventory.js";
import type {
  OrganizationReconciliationPhysicalSource
} from "../src/iam-organization-reconciliation-component-manifest.js";
import {
  validateOrganizationReconciliationOperationCompositeManifestEvidenceBinding
} from "../src/iam-organization-reconciliation-component-manifest.js";
import {
  createOrganizationReconciliationEvidenceHash
} from "../src/iam-organization-reconciliation-validator.js";

type JsonRecord = Readonly<Record<string, string | number | boolean | null>>;
type Mutable<T> = { -readonly [K in keyof T]: T[K] };

const REGISTRY_SHA256 = ORGANIZATION_OWNER_DEVELOP_APPROVED_REGISTRY_CANDIDATE.registrySha256;
const LEGACY_BUILD_SHA256 = "a".repeat(64);
const IDENTITY_BUILD_SHA256 = "b".repeat(64);
const SUBJECTS = Object.freeze(["legacy-user:1", "legacy-user:2"]);
const EVIDENCE_NONCE = "c3".repeat(32);
const COLLECTOR_BUILD_REVISION = "c".repeat(40);
const EXACT_CAPABILITY_EXECUTION_AUTHORIZED =
  (ORGANIZATION_OWNER_DEVELOP_DECISION_CATALOGS.capabilityCatalog as unknown as {
    executionState?: unknown;
  }).executionState === "owner-bound-context-decision-execution";
const CAMPUS_CONTEXT_EXECUTION_AUTHORIZED =
  (ORGANIZATION_OWNER_DEVELOP_DECISION_CATALOGS.campusPublicContext as unknown as {
    executionState?: unknown;
  }).executionState === "owner-bound-campus-context-decision-execution";

describe("xrteeth Develop operation-evidence readiness with authorized read-only decisions", () => {
  it("keeps production readiness blocked after exact Develop execution authorization", () => {
    expect(ORGANIZATION_OWNER_DEVELOP_DECISION_CATALOGS.capabilityCatalog.entries).toHaveLength(20);
    expect(EXACT_CAPABILITY_EXECUTION_AUTHORIZED).toBe(true);
    expect(CAMPUS_CONTEXT_EXECUTION_AUTHORIZED).toBe(true);
    expect(ORGANIZATION_RECONCILIATION_DEVELOP_OPERATION_EVIDENCE_IMPLEMENTED).toBe(true);
    expect(ORGANIZATION_RECONCILIATION_DEVELOP_OPERATION_EVIDENCE_READY).toBe(false);
    expect(ORGANIZATION_RECONCILIATION_DEVELOP_OPERATION_EVIDENCE_BLOCKERS).toEqual(
      expect.arrayContaining([
        "develop-physical-source-attestation-not-recorded",
        "independent-projector-artifact-provenance-not-attested",
        "production-operation-evidence-assembly-disabled"
      ])
    );
    expect(ORGANIZATION_RECONCILIATION_DEVELOP_OPERATION_EVIDENCE_BLOCKERS)
      .not.toContain("projection-binding-not-in-signed-operation-evidence");
    expect(ORGANIZATION_RECONCILIATION_DEVELOP_OPERATION_EVIDENCE_BLOCKERS)
      .not.toContain("campus-public-context-execution-not-authorized");
    expect(ORGANIZATION_RECONCILIATION_DEVELOP_OPERATION_EVIDENCE_BLOCKERS)
      .not.toContain("exact-capability-context-execution-not-authorized");
  });

  it("materializes signed evidence while the production outcome remains blocked", async () => {
    const { run, views } = await collectRunAndViews(99);
    const projections = await projectPair(views, completeDraft("deny"), completeDraft("deny"));
    const collection = createDevelopOperationEvidenceEightSurfaceCollection(
      projections.legacy,
      projections.identity
    );
    const result = assemble(run, projections, collection);
    expect(result).toMatchObject({ outcome: "blocked", ready: false, verifiedSurfaceCount: 8 });
    expect(result.evidence).not.toBeNull();
  }, 20_000);

  it("requires the exact run nonce and full collector revision before materialization", async () => {
    const { run, views } = await collectRunAndViews(98);
    const projections = await projectPair(views, completeDraft("deny"), completeDraft("deny"));
    const collection = createDevelopOperationEvidenceEightSurfaceCollection(
      projections.legacy,
      projections.identity
    );
    const baseline = input(run, projections, collection);

    expect(() => assembleDevelopOperationEvidence({
      ...baseline,
      evidenceNonce: "A".repeat(32)
    })).toThrow("32-128 lowercase hexadecimal");
    expect(() => assembleDevelopOperationEvidence({
      ...baseline,
      collectorBuildRevision: "c".repeat(39)
    })).toThrow("full lowercase 40-character revision");
  }, 20_000);
});

describe(
  "xrteeth Develop operation-evidence boundary",
() => {
  it("is implemented as a permanently fail-closed Develop primitive", () => {
    expect(ORGANIZATION_RECONCILIATION_DEVELOP_OPERATION_EVIDENCE_IMPLEMENTED).toBe(true);
    expect(ORGANIZATION_RECONCILIATION_DEVELOP_OPERATION_EVIDENCE_READY).toBe(false);
    expect(organizationReconciliationDevelopOperationEvidenceReadiness()).toEqual({
      implemented: true,
      ready: false,
      blockers: ORGANIZATION_RECONCILIATION_DEVELOP_OPERATION_EVIDENCE_BLOCKERS
    });
    expect(ORGANIZATION_RECONCILIATION_DEVELOP_OPERATION_EVIDENCE_BLOCKERS).toEqual(
      expect.arrayContaining([
        "dataset-lineage-catalog-caller-structured-untrusted",
        "develop-physical-schema-fingerprints-not-pinned",
        "develop-physical-source-attestation-not-recorded",
        "static-plugin-artifact-deployment-digest-not-attested",
        "independent-projector-artifact-provenance-not-attested",
        "production-operation-evidence-assembly-disabled",
        "runtime-pipeline-not-registered"
      ])
    );
  });

  it("brands an exact eight-surface pair and materializes evidence under a blocked readiness result", async () => {
    const { run, views } = await collectRunAndViews(0);
    const projections = await projectPair(views, completeDraft("deny"), completeDraft("deny"));
    const surfaceCollection = createDevelopOperationEvidenceEightSurfaceCollection(
      projections.legacy,
      projections.identity
    );
    const result = assemble(run, projections, surfaceCollection);

    expect(surfaceCollection.entries.map((entry) => entry.surface)).toEqual(
      ORGANIZATION_RECONCILIATION_DEVELOP_OPERATION_EVIDENCE_SURFACES
    );
    expect(surfaceCollection.entries[0]!.legacyRecords)
      .toBe(projections.legacy.surfaces.organizationDirectory);
    expect(result).toMatchObject({
      implemented: true,
      ready: false,
      outcome: "blocked",
      semanticRegistrySha256: REGISTRY_SHA256,
      lineageManifestSha256: run.coordinatorManifest.manifestSha256,
      verifiedSurfaceCount: 8,
      observableDecisionCartesianCoverage: true,
      blockers: ORGANIZATION_RECONCILIATION_DEVELOP_OPERATION_EVIDENCE_BLOCKERS
    });
    expect(result.evidence.projectionBinding).toEqual(result.projectionBinding);
    const expectedWindowStartedAt = run.coordinatorManifest.components.reduce(
      (latest, component) => Date.parse(component.openedAt) > Date.parse(latest)
        ? component.openedAt
        : latest,
      run.coordinatorManifest.components[0]!.openedAt
    );
    const expectedWindowEndedAt = run.coordinatorManifest.components.reduce(
      (earliest, component) => Date.parse(component.closedAt) < Date.parse(earliest)
        ? component.closedAt
        : earliest,
      run.coordinatorManifest.components[0]!.closedAt
    );
    expect(result.evidence.collectionEnvelope).toMatchObject({
      evidenceNonce: EVIDENCE_NONCE,
      collectorBuildRevision: COLLECTOR_BUILD_REVISION,
      windowStartedAt: expectedWindowStartedAt,
      windowEndedAt: expectedWindowEndedAt
    });
    expect(result.componentManifest).toMatchObject({
      windowStartedAt: run.coordinatorManifest.windowStartedAt,
      windowEndedAt: run.coordinatorManifest.windowEndedAt
    });
    expect(Date.parse(result.evidence.collectionEnvelope.windowStartedAt))
      .toBeGreaterThan(Date.parse(result.componentManifest.windowStartedAt));
    expect(Date.parse(result.evidence.collectionEnvelope.windowEndedAt))
      .toBeLessThan(Date.parse(result.componentManifest.windowEndedAt));
    expect(() => validateOrganizationReconciliationOperationCompositeManifestEvidenceBinding(
      result.componentManifest,
      result.evidence
    )).not.toThrow();
    expect(Object.isFrozen(result)).toBe(true);
    expect(() => assertDevelopOperationEvidenceBlockedAssembly(result)).not.toThrow();
    expect(() => assertDevelopOperationEvidenceBlockedAssembly({ ...result }))
      .toThrow("forged or cloned");
  });

  it("rejects arbitrary JSON, projection clones, collection clones, and lineage clones", async () => {
    const { run, views } = await collectRunAndViews(1);
    const projections = await projectPair(views, completeDraft("deny"), completeDraft("deny"));
    const collection = createDevelopOperationEvidenceEightSurfaceCollection(
      projections.legacy,
      projections.identity
    );
    const valid = input(run, projections, collection);

    expect(() => assembleDevelopOperationEvidence({} as AssembleDevelopOperationEvidenceInput))
      .toThrow("missing or unknown fields");
    expect(() => assembleDevelopOperationEvidence({
      ...valid,
      legacyProjection: { ...projections.legacy }
    } as AssembleDevelopOperationEvidenceInput)).toThrow("trusted side brand");
    expect(() => assembleDevelopOperationEvidence({
      ...valid,
      surfaceCollection: { ...collection }
    } as AssembleDevelopOperationEvidenceInput)).toThrow("forged, cloned");
    expect(() => assembleDevelopOperationEvidence({
      ...valid,
      run: { ...run }
    } as AssembleDevelopOperationEvidenceInput)).toThrow("forged, cloned, or cross-run");
  });

  it("rejects missing, duplicate, and unknown surface selections", async () => {
    const { views } = await collectRunAndViews(2);
    const projections = await projectPair(views, completeDraft("deny"), completeDraft("deny"));
    const missing = ORGANIZATION_RECONCILIATION_DEVELOP_OPERATION_EVIDENCE_SURFACES.slice(1);
    const duplicate = [
      ...ORGANIZATION_RECONCILIATION_DEVELOP_OPERATION_EVIDENCE_SURFACES.slice(0, 7),
      ORGANIZATION_RECONCILIATION_DEVELOP_OPERATION_EVIDENCE_SURFACES[0]
    ];
    const unknown = [
      ...ORGANIZATION_RECONCILIATION_DEVELOP_OPERATION_EVIDENCE_SURFACES.slice(0, 7),
      "runtimeOverride"
    ];

    for (const requested of [missing, duplicate, unknown]) {
      expect(() => createDevelopOperationEvidenceEightSurfaceCollection(
        projections.legacy,
        projections.identity,
        requested as readonly DevelopOperationEvidenceSurfaceName[]
      )).toThrow("missing, duplicate, or unknown");
    }
  });

  it("rejects registry mismatch at both projection-pair and approved-candidate boundaries", async () => {
    const { run, views } = await collectRunAndViews(3);
    const wrongRegistry = "c".repeat(64);
    const legacy = await legacyProjection(views, completeDraft("deny"), REGISTRY_SHA256);
    const mismatchedIdentity = await identityProjection(views, completeDraft("deny"), wrongRegistry);
    expect(() => createDevelopOperationEvidenceEightSurfaceCollection(legacy, mismatchedIdentity))
      .toThrow("same semantic registry");

    const projections = {
      legacy: await legacyProjection(views, completeDraft("deny"), wrongRegistry),
      identity: await identityProjection(views, completeDraft("deny"), wrongRegistry)
    };
    const collection = createDevelopOperationEvidenceEightSurfaceCollection(
      projections.legacy,
      projections.identity
    );
    expect(() => assembleDevelopOperationEvidence({
      ...input(run, projections, collection),
      semanticRegistrySha256: wrongRegistry
    })).toThrow("approved Develop semantic registry candidate");
  });

  it.each([
    {
      name: "plugin visibility",
      seed: 10,
      mutate: (draft: OrganizationSurfaceProjectionDraft): OrganizationSurfaceProjectionDraft => ({
        surfaces: { ...draft.surfaces, pluginVisibility: draft.surfaces.pluginVisibility.slice(0, -1) }
      }),
      error: "pluginVisibility decision universe is incomplete"
    },
    {
      name: "campus context",
      seed: 11,
      mutate: (draft: OrganizationSurfaceProjectionDraft): OrganizationSurfaceProjectionDraft => ({
        surfaces: { ...draft.surfaces, campusContexts: draft.surfaces.campusContexts.slice(0, -1) }
      }),
      error: "campusContexts decision universe is incomplete"
    },
    {
      name: "effective decision",
      seed: 12,
      mutate: (draft: OrganizationSurfaceProjectionDraft): OrganizationSurfaceProjectionDraft => ({
        surfaces: { ...draft.surfaces, effectiveDecisions: draft.surfaces.effectiveDecisions.slice(0, -1) }
      }),
      error: "effectiveDecisions decision universe is incomplete"
    }
  ])("rejects an incomplete $name universe", async ({ mutate, error, seed }) => {
    const { run, views } = await collectRunAndViews(seed);
    const legacyDraft = completeDraft("deny");
    const projections = await projectPair(views, legacyDraft, mutate(completeDraft("deny")));
    const collection = createDevelopOperationEvidenceEightSurfaceCollection(
      projections.legacy,
      projections.identity
    );
    expect(() => assemble(run, projections, collection)).toThrow(error);
  }, 20_000);

  it("rejects self-derived plugin/campus/organization omissions and a wrong resource pair", async () => {
    const { run, views } = await collectRunAndViews(13);
    const baseline = completeDraft("deny");
    const mutations: readonly Readonly<{
      draft: OrganizationSurfaceProjectionDraft;
      error: string;
    }>[] = [
      {
        draft: {
          surfaces: {
            ...baseline.surfaces,
            pluginBindings: baseline.surfaces.pluginBindings.filter(
              (record) => record.pluginRef !== "plugin:user-management"
            ),
            pluginVisibility: baseline.surfaces.pluginVisibility.filter(
              (record) => record.pluginRef !== "plugin:user-management"
            )
          }
        },
        error: "compiled/raw authoritative plugin universe"
      },
      {
        draft: { surfaces: { ...baseline.surfaces, campusContexts: [] } },
        error: "campusContexts decision universe is incomplete"
      },
      {
        draft: { surfaces: { ...baseline.surfaces, organizationDirectory: [] } },
        error: "authoritative raw organization universe"
      },
      {
        draft: {
          surfaces: {
            ...baseline.surfaces,
            effectiveDecisions: baseline.surfaces.effectiveDecisions.map((record, index) =>
              index === 0 ? { ...record, resourceRef: "wrong-resource" } : record
            )
          }
        },
        error: "authoritative organization/capability universe"
      }
    ];
    for (const [index, mutation] of mutations.entries()) {
      const projections = await projectPair(
        views,
        baseline,
        mutation.draft,
        `authoritative-universe-${index}`
      );
      const collection = createDevelopOperationEvidenceEightSurfaceCollection(
        projections.legacy,
        projections.identity
      );
      expect(() => assemble(run, projections, collection)).toThrow(mutation.error);
    }
  }, 20_000);

  it("rejects reused mapping targets and active roles without memberships", async () => {
    const { run, views } = await collectRunAndViews(14);
    const baseline = completeDraft("deny");
    const reusedTarget: OrganizationSurfaceProjectionDraft = {
      surfaces: {
        ...baseline.surfaces,
        organizationMappings: [
          ...baseline.surfaces.organizationMappings,
          { legacyOrganizationId: "8", identityOrganizationId: "legacy:7", active: true }
        ]
      }
    };
    const reusedPair = await projectPair(views, baseline, reusedTarget, "reused-target");
    const reusedCollection = createDevelopOperationEvidenceEightSurfaceCollection(
      reusedPair.legacy,
      reusedPair.identity
    );
    expect(() => assemble(run, reusedPair, reusedCollection)).toThrow(
      "target is reused and not bidirectionally one-to-one"
    );

    const orphanRole: OrganizationSurfaceProjectionDraft = {
      surfaces: { ...baseline.surfaces, memberships: [] }
    };
    const orphanPair = await projectPair(views, baseline, orphanRole, "orphan-role");
    const orphanCollection = createDevelopOperationEvidenceEightSurfaceCollection(
      orphanPair.legacy,
      orphanPair.identity
    );
    expect(() => assemble(run, orphanPair, orphanCollection)).toThrow(
      "active organization role has no active membership"
    );
  }, 20_000);

  it("matches the validator by rejecting kind/ref-mismatched contexts", async () => {
    const { run, views } = await collectRunAndViews(15);
    const baseline = completeDraft("deny");
    for (const [suffix, draft] of [
      ["public-campus", {
        surfaces: {
          ...baseline.surfaces,
          campusContexts: baseline.surfaces.campusContexts.map((record, index) =>
            index === 0 ? { ...record, contextKind: "organization" as const, contextRef: "org:public" } : record
          )
        }
      }],
      ["public-effective", {
        surfaces: {
          ...baseline.surfaces,
          effectiveDecisions: baseline.surfaces.effectiveDecisions.map((record, index) =>
            index === 0 ? { ...record, contextKind: "organization" as const, contextRef: "org:public" } : record
          )
        }
      }]
    ] as const) {
      const projections = await projectPair(views, baseline, draft, suffix);
      const collection = createDevelopOperationEvidenceEightSurfaceCollection(
        projections.legacy,
        projections.identity
      );
      expect(() => assemble(run, projections, collection)).toThrow(
        "surface record has an invalid schema"
      );
    }
  }, 20_000);

  it("rejects an A+B surface collection and never blesses indistinguishable cross-run projections", async () => {
    const first = await collectRunAndViews(20);
    const second = await collectRunAndViews(21);
    const firstPair = await projectPair(
      first.views,
      completeDraft("deny"),
      completeDraft("deny"),
      "first"
    );
    const secondPair = await projectPair(
      second.views,
      completeDraft("deny"),
      completeDraft("deny"),
      "second"
    );
    const firstCollection = createDevelopOperationEvidenceEightSurfaceCollection(
      firstPair.legacy,
      firstPair.identity
    );
    expect(() => assembleDevelopOperationEvidence({
      ...input(first.run, firstPair, firstCollection),
      identityProjection: secondPair.identity
    })).toThrow("another A+B projection pair");

    const crossRunPair = { legacy: firstPair.legacy, identity: secondPair.identity };
    const crossRunCollection = createDevelopOperationEvidenceEightSurfaceCollection(
      crossRunPair.legacy,
      crossRunPair.identity
    );
    expect(() => assemble(first.run, crossRunPair, crossRunCollection)).toThrow(
      "projection pair, manifest, registry, or physical snapshot run binding does not match"
    );
  });

  it("fails closed for an empty component intersection and an A+B-spliced manifest", async () => {
    const first = await collectRunAndViews(22);
    const second = await collectRunAndViews(23);
    const validWindow = createDevelopOperationEvidenceCollectionWindow(
      first.run.coordinatorManifest
    );
    expect(validWindow).toEqual({
      windowStartedAt: first.run.coordinatorManifest.components[2]!.openedAt,
      windowEndedAt: first.run.coordinatorManifest.components[2]!.closedAt
    });

    const emptyIntersection = structuredClone(first.run.coordinatorManifest) as Mutable<
      OrganizationReconciliationDatasetLineageRun["coordinatorManifest"]
    >;
    const mutableComponents = emptyIntersection.components as unknown as Mutable<
      OrganizationReconciliationDatasetLineageRun["coordinatorManifest"]["components"]
    >;
    mutableComponents[2] = {
      ...mutableComponents[2]!,
      openedAt: new Date(
        Date.parse(mutableComponents[1]!.closedAt) + 1
      ).toISOString()
    };
    expect(() => createDevelopOperationEvidenceCollectionWindow(emptyIntersection))
      .toThrow("validated, non-spliced composite manifest");

    const spliced = structuredClone(first.run.coordinatorManifest) as Mutable<
      OrganizationReconciliationDatasetLineageRun["coordinatorManifest"]
    >;
    (spliced as unknown as { components: unknown }).components =
      structuredClone(second.run.coordinatorManifest.components);
    expect(() => createDevelopOperationEvidenceCollectionWindow(spliced))
      .toThrow("validated, non-spliced composite manifest");
  });

  it("rejects a hand-assembled shared object graph because it has no side brands", async () => {
    const { run, views } = await collectRunAndViews(30);
    const projections = await projectPair(views, completeDraft("deny"), completeDraft("deny"));
    const sharedSurfaces = projections.legacy.surfaces;
    const forgedLegacy = { ...projections.legacy, surfaces: sharedSurfaces };
    const forgedIdentity = { ...projections.identity, surfaces: sharedSurfaces };
    const collection = createDevelopOperationEvidenceEightSurfaceCollection(
      projections.legacy,
      projections.identity
    );
    expect(() => assembleDevelopOperationEvidence({
      run,
      legacyProjection: forgedLegacy as LegacyOrganizationSurfaceProjection,
      identityProjection: forgedIdentity as IdentityOrganizationSurfaceProjection,
      surfaceCollection: collection,
      semanticRegistrySha256: REGISTRY_SHA256,
      evidenceNonce: EVIDENCE_NONCE,
      collectorBuildRevision: COLLECTOR_BUILD_REVISION
    })).toThrow("trusted side brand");
  });
});

function input(
  run: OrganizationReconciliationDatasetLineageRun,
  projections: Readonly<{
    legacy: LegacyOrganizationSurfaceProjection;
    identity: IdentityOrganizationSurfaceProjection;
  }>,
  surfaceCollection: DevelopOperationEvidenceEightSurfaceCollection
): AssembleDevelopOperationEvidenceInput {
  return {
    run,
    legacyProjection: projections.legacy,
    identityProjection: projections.identity,
    surfaceCollection,
    semanticRegistrySha256: REGISTRY_SHA256,
    evidenceNonce: EVIDENCE_NONCE,
    collectorBuildRevision: COLLECTOR_BUILD_REVISION
  };
}

function assemble(
  run: OrganizationReconciliationDatasetLineageRun,
  projections: Readonly<{
    legacy: LegacyOrganizationSurfaceProjection;
    identity: IdentityOrganizationSurfaceProjection;
  }>,
  surfaceCollection: DevelopOperationEvidenceEightSurfaceCollection
) {
  return assembleDevelopOperationEvidence(input(run, projections, surfaceCollection));
}

async function projectPair(
  views: DevelopProjectionSnapshotViews,
  legacyDraft: OrganizationSurfaceProjectionDraft,
  identityDraft: OrganizationSurfaceProjectionDraft,
  suffix = "default"
) {
  return {
    legacy: await legacyProjection(views, legacyDraft, REGISTRY_SHA256, suffix),
    identity: await identityProjection(views, identityDraft, REGISTRY_SHA256, suffix)
  };
}

function legacyProjection(
  views: DevelopProjectionSnapshotViews,
  draft: OrganizationSurfaceProjectionDraft,
  registrySha256: string,
  suffix = "default"
) {
  return executeLegacyOrganizationSurfaceProjector({
    side: "legacy",
    contract: LEGACY_ORGANIZATION_SURFACE_PROJECTOR_CONTRACT,
    evaluatorId: `test/legacy/${suffix}`,
    evaluatorBuildSha256: LEGACY_BUILD_SHA256,
    project: () => draft
  }, views.legacy, registrySha256, {
    lineageManifestSha256: views.legacy.lineageManifestSha256,
    primarySource: {
      sourceVersion: views.legacy.sourceVersion,
      snapshotId: views.legacy.snapshotId
    },
    pluginSource: {
      sourceVersion: views.legacy.pluginSourceVersion,
      snapshotId: views.legacy.pluginSnapshotId
    }
  });
}

function identityProjection(
  views: DevelopProjectionSnapshotViews,
  draft: OrganizationSurfaceProjectionDraft,
  registrySha256: string,
  suffix = "default"
) {
  return executeIdentityOrganizationSurfaceProjector({
    side: "identity",
    contract: IDENTITY_ORGANIZATION_SURFACE_PROJECTOR_CONTRACT,
    evaluatorId: `test/identity/${suffix}`,
    evaluatorBuildSha256: IDENTITY_BUILD_SHA256,
    project: () => draft
  }, views.identity, registrySha256, {
    lineageManifestSha256: views.identity.lineageManifestSha256,
    primarySource: {
      sourceVersion: views.identity.sourceVersion,
      snapshotId: views.identity.snapshotId
    },
    pluginSource: {
      sourceVersion: views.identity.pluginSourceVersion,
      snapshotId: views.identity.pluginSnapshotId
    }
  });
}

function completeDraft(decision: "allow" | "deny"): OrganizationSurfaceProjectionDraft {
  const capabilities = approvedCapabilityPairsForFixture();
  const pluginBindings = [
    {
      pluginRef: "plugin:system-admin",
      bindingRef: "plugin:system-admin:org:public",
      organizationRef: "org:public",
      active: true
    },
    {
      pluginRef: "plugin:user-management",
      bindingRef: "plugin:user-management:org:public",
      organizationRef: "org:public",
      active: true
    }
  ] as const;
  return {
    surfaces: {
      organizationDirectory: [
        { legacyOrganizationId: "7", name: "north", title: "North", active: true }
      ],
      organizationMappings: [
        { legacyOrganizationId: "7", identityOrganizationId: "legacy:7", active: true }
      ],
      memberships: [
        { subjectRef: SUBJECTS[0]!, legacyOrganizationId: "7", active: true }
      ],
      organizationScopedRoles: [
        { subjectRef: SUBJECTS[0]!, legacyOrganizationId: "7", roleRef: "admin", active: true }
      ],
      pluginBindings,
      pluginVisibility: SUBJECTS.flatMap((subjectRef) => pluginBindings.map((binding) => ({
        subjectRef,
        pluginRef: binding.pluginRef,
        organizationRef: binding.organizationRef,
        decision
      }))),
      campusContexts: SUBJECTS.flatMap((subjectRef) => [
        { subjectRef, contextKind: "organization" as const, contextRef: "legacy-org:7", decision },
        { subjectRef, contextKind: "platform-global" as const, contextRef: "org:platform-global", decision: "deny" as const },
        { subjectRef, contextKind: "public" as const, contextRef: "org:public", decision: "deny" as const }
      ]),
      effectiveDecisions: SUBJECTS.flatMap((subjectRef) => capabilities.flatMap((rule) => [
        {
          subjectRef,
          contextKind: "organization" as const,
          contextRef: "legacy-org:7",
          resourceRef: rule.resourceRef,
          capabilityRef: rule.capabilityRef,
          decision
        },
        {
          subjectRef,
          contextKind: "platform-global" as const,
          contextRef: "org:platform-global",
          resourceRef: rule.resourceRef,
          capabilityRef: rule.capabilityRef,
          decision: "deny" as const
        },
        {
          subjectRef,
          contextKind: "public" as const,
          contextRef: "org:public",
          resourceRef: rule.resourceRef,
          capabilityRef: rule.capabilityRef,
          decision: "deny" as const
        }
      ]))
    }
  };
}

function approvedCapabilityPairsForFixture(): readonly Readonly<{
  resourceRef: string;
  capabilityRef: string;
}>[] {
  const catalog = ORGANIZATION_OWNER_DEVELOP_DECISION_CATALOGS.capabilityCatalog as unknown as
    Record<string, unknown>;
  if (Array.isArray(catalog.entries)) {
    return catalog.entries.map((value) => {
      const entry = value as Readonly<Record<string, unknown>>;
      return {
        resourceRef: String(entry.resourceId),
        capabilityRef: String(entry.capabilityId)
      };
    });
  }
  return [
    ...((catalog.campus as readonly string[]) ?? [])
      .map((capabilityRef) => ({ resourceRef: "campus", capabilityRef })),
    ...((catalog.organization as readonly string[]) ?? [])
      .map((capabilityRef) => ({ resourceRef: "organization", capabilityRef })),
    ...((catalog.userManagement as readonly string[]) ?? [])
      .map((capabilityRef) => ({ resourceRef: "user-management", capabilityRef }))
  ];
}

async function collectRunAndViews(seed: number): Promise<{
  readonly run: OrganizationReconciliationDatasetLineageRun;
  readonly views: DevelopProjectionSnapshotViews;
}> {
  const bindings = createBindings(seed);
  let tick = 0;
  const run = await collectOrganizationReconciliationDatasetLineage({
    components: bindings,
    maxWindowMilliseconds: 1_000,
    clock: { now: () => new Date(Date.parse("2026-08-11T00:00:00.000Z") + tick++ * 10) }
  });
  return { run, views: createDevelopProjectionSnapshotViews(run) };
}

function createBindings(seed: number): OrganizationReconciliationDatasetComponentBinding[] {
  const recordsByComponent: Record<OrganizationReconciliationPhysicalSource, Record<string, JsonRecord[]>> = {
    "legacy-main": {
      "legacy-organization-directory": [{
        legacyOrganizationId: "7", name: "north", title: "North", createdAt: 1, updatedAt: 2
      }],
      "legacy-subject-universe": [
        { legacyUserId: "1", status: 10 },
        { legacyUserId: "2", status: 0 }
      ]
    },
    identity: {
      "identity-subject-universe": [
        { legacyUserId: "1", status: "active", source: "legacy-shadow" },
        { legacyUserId: "2", status: "inactive", source: "legacy-shadow" }
      ],
      "identity-organization-candidate": [{
        legacyOrganizationId: "7",
        identityOrganizationId: "legacy:7",
        name: "north",
        title: "North",
        source: "legacy",
        candidateStatus: "candidate"
      }],
      "identity-organization-id-map": [{
        legacyOrganizationId: "7",
        identityOrganizationId: "legacy:7",
        source: "legacy",
        mappingStatus: "active"
      }]
    },
    plugin: {
      "plugin-registry": [{
        pluginId: "system-admin", enabled: true, accessScope: "root-only", organizationName: null
      }]
    }
  };

  return ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG.components.map((component, index) => {
    const sourceId = component.expectedSourceId;
    const records = new Map<string, JsonRecord[]>();
    for (const dataset of component.datasetCatalog.datasets) {
      records.set(dataset.datasetId, recordsByComponent[component.componentId][dataset.datasetId] ?? []);
    }
    const commitmentKey = Buffer.alloc(32, seed + index + 1);
    const inventory = createOrganizationReconciliationComponentDatasetInventory({
      componentId: component.componentId,
      sourceId,
      catalogSha256: component.declaredCatalogSha256,
      datasets: [...records].map(([datasetId, values]) => ({
        datasetId,
        pages: [{ requestCursor: null, nextCursor: null, recordOffset: 0, records: values }]
      })),
      commitmentKey
    });
    const snapshot: Mutable<OrganizationReconciliationSourceSnapshot> = {
      sourceId,
      sourceVersion: createOrganizationReconciliationContentSourceVersion(sourceId, inventory),
      snapshotId: createOrganizationReconciliationContentSnapshotId(sourceId, inventory),
      recordCount: inventory.recordCount,
      subjectUniverseCount: component.componentId === "plugin" ? 0 : SUBJECTS.length,
      subjectUniverseHash: component.componentId === "plugin"
        ? ""
        : createOrganizationReconciliationEvidenceHash(EVIDENCE_NONCE, SUBJECTS),
      snapshotMode: ORGANIZATION_RECONCILIATION_SNAPSHOT_MODE,
      paginationMode: ORGANIZATION_RECONCILIATION_PAGINATION_MODE,
      datasetInventory: inventory
    };
    const delivered = new Set<string>();
    const adapter: OrganizationReconciliationDatasetSourceAdapter<unknown> = {
      sourceId,
      openSnapshot: async () => snapshot,
      readSnapshotPage: async (request) => {
        if (request.snapshot !== snapshot || request.requestCursor !== null || delivered.has(request.datasetId)) {
          throw new Error("invalid fixture cursor");
        }
        delivered.add(request.datasetId);
        const values = records.get(request.datasetId);
        if (!values) throw new Error("unknown fixture dataset");
        return datasetPage(snapshot, request.datasetId, values);
      },
      verifySnapshotDatasetReplay: (request) => {
        const observed = createOrganizationReconciliationComponentDatasetInventory({
          componentId: component.componentId,
          sourceId,
          catalogSha256: component.declaredCatalogSha256,
          datasets: [{
            datasetId: request.datasetId,
            pages: request.pages as readonly OrganizationReconciliationDatasetInventoryPageInput[]
          }],
          commitmentKey
        }).datasets[0];
        const expected = inventory.datasets.find((dataset) => dataset.datasetId === request.datasetId);
        if (request.snapshot !== snapshot || !observed || !expected ||
          observed.lineageSha256 !== expected.lineageSha256) {
          throw new Error("fixture replay mismatch");
        }
      },
      closeSnapshot: async () => undefined
    };
    return {
      componentId: component.componentId,
      expectedSourceId: sourceId,
      schemaSha256: String(index + 4).repeat(64),
      catalogSha256: component.declaredCatalogSha256,
      buildSha256: ["4", "5", "6"][index]!.repeat(64),
      adapter,
      datasetCatalog: component.datasetCatalog
    };
  });
}

function datasetPage(
  snapshot: OrganizationReconciliationSourceSnapshot,
  datasetId: string,
  records: readonly OrganizationReconciliationInventoryJsonValue[]
): OrganizationReconciliationDatasetPage<OrganizationReconciliationInventoryJsonValue> {
  return {
    sourceId: snapshot.sourceId,
    sourceVersion: snapshot.sourceVersion,
    snapshotId: snapshot.snapshotId,
    snapshotRecordCount: snapshot.recordCount,
    subjectUniverseCount: snapshot.subjectUniverseCount,
    subjectUniverseHash: snapshot.subjectUniverseHash,
    datasetId,
    datasetRecordCount: records.length,
    requestCursor: null,
    nextCursor: null,
    recordOffset: 0,
    records
  };
}
