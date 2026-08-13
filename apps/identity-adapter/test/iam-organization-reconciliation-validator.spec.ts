import { createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  createOrganizationReconciliationEvidenceHash,
  ORGANIZATION_RECONCILIATION_COLLECTOR_CONTRACT,
  ORGANIZATION_RECONCILIATION_COLLECTOR_CONTRACT_HASH,
  ORGANIZATION_RECONCILIATION_DECISION_DERIVATION_CONTRACT,
  ORGANIZATION_RECONCILIATION_REAL_SOURCE_ADAPTERS_READY,
  OrganizationReconciliationInput,
  ReconciliationPair,
  validateOrganizationReconciliation as validateOrganizationReconciliationRaw,
  type OrganizationReconciliationValidationOptions
} from "../src/iam-organization-reconciliation-validator.js";
import {
  attachTestOrganizationReconciliationComponentManifest
} from "./fixtures/iam-organization-reconciliation-component-manifest.js";
import {
  createOrganizationReconciliationCompositeManifestSha256,
  createOrganizationReconciliationCompositeManifestForEvidence,
  createOrganizationReconciliationOperationEvidenceSha256,
  createOrganizationReconciliationOperationCompositeManifestSha256,
  ORGANIZATION_RECONCILIATION_COMPOSITE_MANIFEST_CONTRACT,
  ORGANIZATION_RECONCILIATION_PAGINATION_MODE,
  ORGANIZATION_RECONCILIATION_SNAPSHOT_MODE,
  type OrganizationReconciliationEvidenceJsonValue,
  type OrganizationReconciliationCompositeManifest,
  type OrganizationReconciliationOperationCompositeManifest,
  type OrganizationReconciliationCompositeManifestUnsigned,
  type OrganizationReconciliationOperationCompositeManifestUnsigned
} from "../src/iam-organization-reconciliation-component-manifest.js";
import {
  assembleCoordinatedOrganizationReconciliationInput,
  coordinateOrganizationReconciliationSnapshots,
  ORGANIZATION_RECONCILIATION_OPERATION_EVIDENCE_PROJECTOR_READY
} from "../src/iam-organization-reconciliation-coordinator.js";
import { ORGANIZATION_RECONCILIATION_DATASET_LINEAGE_PRODUCTION_READY } from
  "../src/iam-organization-reconciliation-dataset-lineage.js";
import { ORGANIZATION_RECONCILIATION_PROJECTION_CATALOGS_READY } from
  "../src/iam-organization-reconciliation-refs.js";
import {
  ORGANIZATION_RECONCILIATION_COMPILED_PIPELINE_REGISTRATION_READY,
  ORGANIZATION_RECONCILIATION_RAW_SOURCE_CAPABILITY_READY,
  ORGANIZATION_RECONCILIATION_TRANSACTION_ADAPTER_FACTORY_CAPABILITY_READY,
  ORGANIZATION_RECONCILIATION_TRANSACTION_DATASET_SPOOL_IMPLEMENTED,
  ORGANIZATION_RECONCILIATION_TRANSACTION_DATASET_SPOOL_READY
} from "../src/iam-organization-reconciliation-runtime-readiness.js";

describe("work-package 4 full-scope organization reconciliation validator", () => {
  it("keeps the total compiled readiness conjunction fail-closed", () => {
    expect([
      ORGANIZATION_RECONCILIATION_RAW_SOURCE_CAPABILITY_READY,
      ORGANIZATION_RECONCILIATION_PROJECTION_CATALOGS_READY,
      ORGANIZATION_RECONCILIATION_DATASET_LINEAGE_PRODUCTION_READY,
      ORGANIZATION_RECONCILIATION_TRANSACTION_ADAPTER_FACTORY_CAPABILITY_READY,
      ORGANIZATION_RECONCILIATION_TRANSACTION_DATASET_SPOOL_READY,
      ORGANIZATION_RECONCILIATION_OPERATION_EVIDENCE_PROJECTOR_READY,
      ORGANIZATION_RECONCILIATION_COMPILED_PIPELINE_REGISTRATION_READY
    ]).toEqual([false, false, false, false, false, false, false]);
    expect(ORGANIZATION_RECONCILIATION_TRANSACTION_DATASET_SPOOL_IMPLEMENTED).toBe(true);
    expect(ORGANIZATION_RECONCILIATION_REAL_SOURCE_ADAPTERS_READY).toBe(false);
  });
  it("passes only when every required surface is complete and pairwise aligned", () => {
    const report = validateOrganizationReconciliation(alignedInput());

    expect(report).toMatchObject({
      dryRun: true,
      writeSideEffects: "none",
      evidencePolicy: "hash-only",
      assuranceScope: "collector-envelope-self-consistency",
      externalProvenanceRequired: true,
      realSourceAdaptersReady: false,
      staticChecksPassed: false,
      comparisonPolicy: "pairwise-no-union",
      severity: { P0: 0, P1: 0, P2: 0 },
      coverageBlockers: [{ surface: "collection-envelope", code: "real-source-adapters-not-ready" }],
      safetyGate: {
        passed: false,
        blocksDualWrite: true,
        coverageComplete: false,
        p0Blocks: true,
        p1Blocks: true,
        p2Classified: true,
        unionForbidden: true,
        externalProvenanceVerified: false,
        blockedReasons: ["coverage-incomplete", "external-provenance-required"]
      }
    });
    expect(report.coverage).toHaveLength(8);
    expect(report.coverage.every((surface) => surface.paginationComplete)).toBe(true);
    expect(report.componentManifestHash).toMatch(/^[a-f0-9]{24}$/);
    expect(report.reportHash).toMatch(/^[a-f0-9]{24}$/);
    expectNoRawEvidence(report);
  });

  it("requires one canonical composite manifest and rejects A/B evidence pairing", () => {
    const input = alignedInput();
    const { componentManifest, ...evidenceBody } = input;

    const missing = validateOrganizationReconciliationRaw(evidenceBody);
    expect(missing.coverageBlockers).toContainEqual({
      surface: "collection-envelope",
      code: "component-manifest-missing"
    });

    const changedBody = {
      ...evidenceBody,
      memberships: {
        ...evidenceBody.memberships!,
        identity: {
          ...evidenceBody.memberships!.identity!,
          records: []
        }
      }
    };
    const mismatched = validateOrganizationReconciliationRaw({
      ...changedBody,
      componentManifest
    });
    expect(mismatched.coverageBlockers).toContainEqual({
      surface: "collection-envelope",
      code: "component-manifest-evidence-mismatch"
    });

    const oldManifestContract = validateOrganizationReconciliationRaw({
      ...evidenceBody,
      componentManifest: {
        ...componentManifest!,
        contract: "iam-organization-reconciliation-composite-manifest/v1"
      } as never
    });
    expect(oldManifestContract.coverageBlockers).toContainEqual({
      surface: "collection-envelope",
      code: "component-manifest-invalid"
    });

    const oldOperationEvidenceContract = validateOrganizationReconciliationRaw({
      ...evidenceBody,
      componentManifest: {
        ...componentManifest!,
        evidenceContract: "iam-organization-reconciliation-operation-evidence/v1"
      } as never
    });
    expect(oldOperationEvidenceContract.coverageBlockers).toContainEqual({
      surface: "collection-envelope",
      code: "component-manifest-invalid"
    });

    const fourthCampusComponent = validateOrganizationReconciliationRaw({
      ...evidenceBody,
      componentManifest: {
        ...componentManifest!,
        components: [
          ...componentManifest!.components,
          { ...componentManifest!.components[0]!, componentId: "campus" }
        ]
      } as never
    });
    expect(fourthCampusComponent.coverageBlockers).toContainEqual({
      surface: "collection-envelope",
      code: "component-manifest-invalid"
    });

    const { manifestSha256: _manifestSha256, ...unsignedManifest } = componentManifest!;
    const wrongSourceManifest = {
      ...unsignedManifest,
      components: unsignedManifest.components.map((component) =>
        component.componentId === "legacy-main"
          ? { ...component, sourceVersion: "other-legacy-source-version" }
          : component
      )
    } satisfies OrganizationReconciliationOperationCompositeManifestUnsigned;
    expect(() => createOrganizationReconciliationOperationCompositeManifestSha256(wrongSourceManifest))
      .toThrow("content binding is invalid");
    const wrongSnapshotManifest = {
      ...unsignedManifest,
      components: unsignedManifest.components.map((component) =>
        component.componentId === "identity"
          ? { ...component, snapshotId: "other-identity-snapshot" }
          : component
      )
    } satisfies OrganizationReconciliationOperationCompositeManifestUnsigned;
    expect(() => createOrganizationReconciliationOperationCompositeManifestSha256(wrongSnapshotManifest))
      .toThrow("content binding is invalid");

    const wrongSubjectManifest = {
      ...unsignedManifest,
      components: unsignedManifest.components.map((component) =>
        component.componentId === "plugin"
          ? component
          : { ...component, subjectUniverse: { ...component.subjectUniverse, sha256: "f".repeat(64) } }
      )
    } satisfies OrganizationReconciliationOperationCompositeManifestUnsigned;
    const subjectMismatch = validateOrganizationReconciliationRaw({
      ...evidenceBody,
      componentManifest: {
        ...wrongSubjectManifest,
        manifestSha256: createOrganizationReconciliationOperationCompositeManifestSha256(wrongSubjectManifest)
      }
    });
    expect(subjectMismatch.coverageBlockers).toContainEqual({
      surface: "collection-envelope",
      code: "component-manifest-envelope-mismatch"
    });

    const envelopeOutsidePluginSnapshot = {
      ...unsignedManifest,
      components: unsignedManifest.components.map((component) =>
        component.componentId === "plugin"
          ? { ...component, openedAt: "2026-08-09T00:01:00.000Z" }
          : component
      )
    } satisfies OrganizationReconciliationOperationCompositeManifestUnsigned;
    const intervalMismatch = validateOrganizationReconciliationRaw({
      ...evidenceBody,
      componentManifest: {
        ...envelopeOutsidePluginSnapshot,
        manifestSha256: createOrganizationReconciliationOperationCompositeManifestSha256(envelopeOutsidePluginSnapshot)
      }
    });
    expect(intervalMismatch.coverageBlockers).toContainEqual({
      surface: "collection-envelope",
      code: "component-manifest-envelope-mismatch"
    });
  });

  it("binds the exact projection metadata and rejects projection A/evidence B splices", () => {
    const input = alignedInput();
    const { componentManifest, ...evidenceBody } = input;
    const lineageManifest = lineageManifestForFinal(componentManifest!);
    const projectionBinding = evidenceBody.projectionBinding!;
    const changedProjectionEvidence = {
      ...evidenceBody,
      projectionBinding: {
        ...projectionBinding,
        identity: {
          ...projectionBinding.identity,
          evaluatorId: "test/identity/spliced"
        }
      }
    };

    const staleManifest = validateOrganizationReconciliationRaw({
      ...changedProjectionEvidence,
      componentManifest
    });
    expect(staleManifest.coverageBlockers).toContainEqual({
      surface: "collection-envelope",
      code: "component-manifest-evidence-mismatch"
    });

    const foreignSourceEvidence = {
      ...evidenceBody,
      projectionBinding: {
        ...projectionBinding,
        identity: {
          ...projectionBinding.identity,
          primarySource: {
            ...projectionBinding.identity.primarySource,
            snapshotId: "foreign-identity-snapshot"
          }
        }
      }
    };
    const reboundManifest = createOrganizationReconciliationCompositeManifestForEvidence(
      lineageManifest,
      foreignSourceEvidence
    );
    expect(reboundManifest.components).toEqual(componentManifest!.components);
    expect(reboundManifest.manifestSha256).not.toBe(componentManifest!.manifestSha256);
    const foreignSource = validateOrganizationReconciliationRaw({
      ...foreignSourceEvidence,
      componentManifest: reboundManifest
    });
    expect(foreignSource.coverageBlockers).toContainEqual({
      surface: "collection-envelope",
      code: "projection-binding-component-mismatch"
    });

    const { projectionBinding: _missingProjection, ...missingProjectionEvidence } = evidenceBody;
    const missingProjectionManifest = createOrganizationReconciliationCompositeManifestForEvidence(
      lineageManifest,
      missingProjectionEvidence
    );
    const missingProjection = validateOrganizationReconciliationRaw({
      ...missingProjectionEvidence,
      componentManifest: missingProjectionManifest
    });
    expect(missingProjection.coverageBlockers).toContainEqual({
      surface: "collection-envelope",
      code: "projection-binding-missing"
    });

    const invalidProjectionEvidence = {
      ...evidenceBody,
      projectionBinding: {
        ...projectionBinding,
        untrustedOverride: true
      }
    } as unknown as OrganizationReconciliationInput;
    const invalidProjectionManifest = createOrganizationReconciliationCompositeManifestForEvidence(
      lineageManifest,
      invalidProjectionEvidence
    );
    const invalidProjection = validateOrganizationReconciliationRaw({
      ...invalidProjectionEvidence,
      componentManifest: invalidProjectionManifest
    });
    expect(invalidProjection.coverageBlockers).toContainEqual({
      surface: "collection-envelope",
      code: "projection-binding-invalid"
    });

    const changedLineageEvidence = {
      ...evidenceBody,
      projectionBinding: {
        ...projectionBinding,
        lineageManifestSha256: "a".repeat(64)
      }
    };
    const changedLineageManifest = createOrganizationReconciliationCompositeManifestForEvidence(
      lineageManifest,
      changedLineageEvidence
    );
    const changedLineage = validateOrganizationReconciliationRaw({
      ...changedLineageEvidence,
      componentManifest: changedLineageManifest
    });
    expect(changedLineage.coverageBlockers).toContainEqual({
      surface: "collection-envelope",
      code: "projection-binding-lineage-mismatch"
    });

    const { manifestSha256: _lineageSha, ...lineageUnsigned } = lineageManifest;
    const alternateLineageUnsigned = {
      ...lineageUnsigned,
      evidenceSha256: "f".repeat(64)
    } satisfies OrganizationReconciliationCompositeManifestUnsigned;
    const alternateLineageManifest = {
      ...alternateLineageUnsigned,
      manifestSha256: createOrganizationReconciliationCompositeManifestSha256(
        alternateLineageUnsigned
      )
    };
    const parentSplicedManifest = createOrganizationReconciliationCompositeManifestForEvidence(
      alternateLineageManifest,
      evidenceBody
    );
    const parentSplice = validateOrganizationReconciliationRaw({
      ...evidenceBody,
      componentManifest: parentSplicedManifest
    });
    expect(parentSplice.coverageBlockers).toContainEqual({
      surface: "collection-envelope",
      code: "projection-binding-lineage-mismatch"
    });
    expect(parentSplice.coverageBlockers).not.toContainEqual({
      surface: "collection-envelope",
      code: "projection-binding-component-mismatch"
    });

    const oldV3Final = validateOrganizationReconciliationRaw({
      ...evidenceBody,
      componentManifest: lineageManifest as never
    });
    expect(oldV3Final.coverageBlockers).toContainEqual({
      surface: "collection-envelope",
      code: "component-manifest-invalid"
    });
  });

  it("assembles one real coordinator lifecycle result into the validator boundary", async () => {
    const baseline = alignedInput();
    const { componentManifest: baselineManifest, ...evidenceBody } = baseline;
    const envelope = evidenceBody.collectionEnvelope!;
    const originalComponents = new Map(
      baselineManifest!.components.map((component) => [component.componentId, component])
    );
    const componentIds = ["legacy-main", "identity", "plugin"] as const;
    const components = componentIds.map((componentId, index) => {
      const original = originalComponents.get(componentId)!;
      const snapshot = {
        sourceId: original.sourceId,
        sourceVersion: original.sourceVersion,
        snapshotId: original.snapshotId,
        recordCount: original.recordCount,
        subjectUniverseCount: original.subjectUniverse.count,
        subjectUniverseHash: original.subjectUniverse.sha256,
        snapshotMode: ORGANIZATION_RECONCILIATION_SNAPSHOT_MODE,
        paginationMode: ORGANIZATION_RECONCILIATION_PAGINATION_MODE,
        datasetInventory: original.datasetInventory
      } as const;
      return {
        componentId,
        expectedSourceId: snapshot.sourceId,
        schemaSha256: original.schemaSha256,
        catalogSha256: original.catalogSha256,
        buildSha256: original.buildSha256,
        adapter: {
          sourceId: snapshot.sourceId,
          openSnapshot: async () => snapshot,
          closeSnapshot: async () => undefined
        }
      };
    });
    const timestamps = [
      "2026-08-08T23:59:00.000Z",
      "2026-08-08T23:59:10.000Z",
      "2026-08-08T23:59:20.000Z",
      "2026-08-09T00:05:10.000Z",
      "2026-08-09T00:05:20.000Z",
      "2026-08-09T00:05:30.000Z"
    ];
    let clockIndex = 0;
    const coordinated = await coordinateOrganizationReconciliationSnapshots({
      components,
      maxWindowMilliseconds: 390_000,
      clock: { now: () => new Date(timestamps[clockIndex++]!) }
    }, async () => evidenceBody as unknown as OrganizationReconciliationEvidenceJsonValue);

    expect(() => assembleCoordinatedOrganizationReconciliationInput(coordinated))
      .toThrow("disabled until a branded operation-evidence projector is implemented");
  });

  it("rejects accessor evidence without invoking it", () => {
    const input = alignedInput() as Record<string, unknown>;
    let invoked = false;
    Object.defineProperty(input, "unexpected", {
      enumerable: true,
      get: () => {
        invoked = true;
        return "private-secret";
      }
    });

    const report = validateOrganizationReconciliationRaw(input as never);
    expect(invoked).toBe(false);
    expect(report.coverageBlockers).toEqual([
      { surface: "collection-envelope", code: "input-schema-invalid" }
    ]);
    expect(JSON.stringify(report)).not.toContain("private-secret");
  });

  it("accepts only the explicit public plugin context and rejects name-based organization refs", () => {
    const input = alignedInput();
    const publicUniverse = decisionUniverse(
      [["legacy-user:581", "plugin:campus", "org:public"]],
      { subjects: ["legacy-user:581"], plugins: ["plugin:campus"], organizations: ["org:public"] }
    );
    const publicReport = validateOrganizationReconciliation({
      ...input,
      pluginBindings: pair(
        [{ pluginRef: "plugin:campus", bindingRef: "binding-public", organizationRef: "org:public", active: true }],
        [{ pluginRef: "plugin:campus", bindingRef: "binding-public", organizationRef: "org:public", active: true }]
      ),
      pluginVisibility: pair(
        [{ subjectRef: "legacy-user:581", pluginRef: "plugin:campus", organizationRef: "org:public", decision: "allow" }],
        [{ subjectRef: "legacy-user:581", pluginRef: "plugin:campus", organizationRef: "org:public", decision: "allow" }]
      ),
      collectionEnvelope: {
        ...input.collectionEnvelope!,
        legacy: {
          ...input.collectionEnvelope!.legacy,
          decisionUniverses: {
            ...input.collectionEnvelope!.legacy.decisionUniverses,
            pluginVisibility: publicUniverse
          }
        },
        identity: {
          ...input.collectionEnvelope!.identity,
          decisionUniverses: {
            ...input.collectionEnvelope!.identity.decisionUniverses,
            pluginVisibility: publicUniverse
          }
        }
      }
    });
    expect(publicReport.coverageBlockers).toEqual([
      { surface: "collection-envelope", code: "real-source-adapters-not-ready" }
    ]);

    const nameRefReport = validateOrganizationReconciliation({
      ...input,
      pluginBindings: pair(
        [{ pluginRef: "plugin:campus", bindingRef: "binding-one", organizationRef: "test-university", active: true }],
        [{ pluginRef: "plugin:campus", bindingRef: "binding-one", organizationRef: "test-university", active: true }]
      ),
      pluginVisibility: pair(
        [{ subjectRef: "legacy-user:581", pluginRef: "plugin:campus", organizationRef: "test-university", decision: "allow" }],
        [{ subjectRef: "legacy-user:581", pluginRef: "plugin:campus", organizationRef: "test-university", decision: "allow" }]
      )
    });
    expect(nameRefReport.coverageBlockers).toEqual(expect.arrayContaining([
      { surface: "plugin-binding", code: "record-schema-invalid", side: "legacy" },
      { surface: "plugin-binding", code: "record-schema-invalid", side: "identity" },
      { surface: "plugin-visibility", code: "record-schema-invalid", side: "legacy" },
      { surface: "plugin-visibility", code: "record-schema-invalid", side: "identity" }
    ]));
  });

  it("accepts only strict authorization context kind/ref bijections and rejects the old record shape", () => {
    const input = alignedInput();
    for (const [contextKind, contextRef] of [
      ["organization", "org:public"],
      ["organization", "org:platform-global"],
      ["public", "legacy-org:1"],
      ["public", "org:platform-global"],
      ["platform-global", "legacy-org:1"],
      ["platform-global", "org:public"]
    ] as const) {
      const campus = { subjectRef: "legacy-user:581", contextKind, contextRef, decision: "deny" };
      const effective = {
        subjectRef: "legacy-user:581",
        contextKind,
        contextRef,
        resourceRef: "organization-one",
        capabilityRef: "read",
        decision: "deny"
      };
      const report = validateOrganizationReconciliation({
        ...input,
        campusContexts: pair([campus], [campus]),
        effectiveDecisions: pair([effective], [effective])
      } as never);
      expect(report.coverageBlockers).toEqual(expect.arrayContaining([
        { surface: "campus-context", code: "record-schema-invalid", side: "legacy" },
        { surface: "campus-context", code: "record-schema-invalid", side: "identity" },
        { surface: "effective-decision", code: "record-schema-invalid", side: "legacy" },
        { surface: "effective-decision", code: "record-schema-invalid", side: "identity" }
      ]));
    }

    const oldCampus = {
      subjectRef: "legacy-user:581",
      campusRef: "campus-one",
      organizationRef: "legacy-org:1",
      decision: "deny"
    };
    const oldEffective = {
      subjectRef: "legacy-user:581",
      organizationRef: "legacy-org:1",
      resourceRef: "organization-one",
      capabilityRef: "read",
      decision: "deny"
    };
    const oldShape = validateOrganizationReconciliation({
      ...input,
      campusContexts: pair([oldCampus], [oldCampus]),
      effectiveDecisions: pair([oldEffective], [oldEffective])
    } as never);
    expect(oldShape.coverageBlockers).toEqual(expect.arrayContaining([
      { surface: "campus-context", code: "record-schema-invalid", side: "legacy" },
      { surface: "campus-context", code: "record-schema-invalid", side: "identity" },
      { surface: "effective-decision", code: "record-schema-invalid", side: "legacy" },
      { surface: "effective-decision", code: "record-schema-invalid", side: "identity" }
    ]));
  });

  it("retains exactly two reserved contexts when the organization directory is empty", () => {
    const input = alignedInput();
    const contexts = AUTHORIZATION_CONTEXTS.slice(1);
    const contextDimensions = contexts.map((context) => JSON.stringify(context));
    const campuses = contexts.map(([contextKind, contextRef]) => ({
      subjectRef: "legacy-user:581",
      contextKind,
      contextRef,
      decision: "deny" as const
    }));
    const effective = contexts.map(([contextKind, contextRef]) => ({
      subjectRef: "legacy-user:581",
      contextKind,
      contextRef,
      resourceRef: "organization-one",
      capabilityRef: "read",
      decision: "deny" as const
    }));
    const campusUniverse = decisionUniverse(
      campuses.map((record) => [record.subjectRef, record.contextKind, record.contextRef]),
      { subjects: ["legacy-user:581"], contexts: contextDimensions }
    );
    const effectiveUniverse = decisionUniverse(
      effective.map((record) => [
        record.subjectRef,
        record.contextKind,
        record.contextRef,
        record.resourceRef,
        record.capabilityRef
      ]),
      {
        subjects: ["legacy-user:581"],
        contexts: contextDimensions,
        resources: ["organization-one"],
        capabilities: ["read"],
        rulePairs: [JSON.stringify(["organization-one", "read"])]
      }
    );
    const publicPluginUniverse = decisionUniverse(
      [["legacy-user:581", "plugin:campus", "org:public"]],
      { subjects: ["legacy-user:581"], plugins: ["plugin:campus"], organizations: ["org:public"] }
    );
    const report = validateOrganizationReconciliation({
      ...input,
      organizationDirectory: pair([], []),
      organizationMappings: pair([], []),
      memberships: pair([], []),
      organizationScopedRoles: pair([], []),
      pluginBindings: pair(
        [{ pluginRef: "plugin:campus", bindingRef: "binding-public", organizationRef: "org:public", active: true }],
        [{ pluginRef: "plugin:campus", bindingRef: "binding-public", organizationRef: "org:public", active: true }]
      ),
      pluginVisibility: pair(
        [{ subjectRef: "legacy-user:581", pluginRef: "plugin:campus", organizationRef: "org:public", decision: "allow" }],
        [{ subjectRef: "legacy-user:581", pluginRef: "plugin:campus", organizationRef: "org:public", decision: "allow" }]
      ),
      campusContexts: pair(campuses, campuses),
      effectiveDecisions: pair(effective, effective),
      collectionEnvelope: {
        ...input.collectionEnvelope!,
        legacy: {
          ...input.collectionEnvelope!.legacy,
          decisionUniverses: {
            pluginVisibility: publicPluginUniverse,
            campusContexts: campusUniverse,
            effectiveDecisions: effectiveUniverse
          }
        },
        identity: {
          ...input.collectionEnvelope!.identity,
          decisionUniverses: {
            pluginVisibility: publicPluginUniverse,
            campusContexts: campusUniverse,
            effectiveDecisions: effectiveUniverse
          }
        }
      }
    });
    expect(report.coverageBlockers).toEqual([
      { surface: "collection-envelope", code: "real-source-adapters-not-ready" }
    ]);
  });

  it.each(["organization", "platform-global", "public"] as const)(
    "rejects a re-signed input with the entire %s context group deleted",
    (deletedKind) => {
      const input = alignedInput();
      const campuses = baselineCampusRecords("legacy-user:581")
        .filter((record) => record.contextKind !== deletedKind);
      const effective = baselineEffectiveDecisionRecords("legacy-user:581")
        .filter((record) => record.contextKind !== deletedKind);
      const remainingContexts = AUTHORIZATION_CONTEXTS.filter(([contextKind]) => contextKind !== deletedKind);
      const campusUniverse = decisionUniverse(
        campuses.map((record) => [record.subjectRef, record.contextKind, record.contextRef]),
        {
          subjects: ["legacy-user:581"],
          contexts: remainingContexts.map((context) => JSON.stringify(context))
        }
      );
      const effectiveUniverse = decisionUniverse(
        effective.map((record) => [
          record.subjectRef,
          record.contextKind,
          record.contextRef,
          record.resourceRef,
          record.capabilityRef
        ]),
        {
          subjects: ["legacy-user:581"],
          contexts: remainingContexts.map((context) => JSON.stringify(context)),
          resources: ["organization-one"],
          capabilities: ["read"],
          rulePairs: [JSON.stringify(["organization-one", "read"])]
        }
      );
      const report = validateOrganizationReconciliation({
        ...input,
        campusContexts: pair(campuses, campuses),
        effectiveDecisions: pair(effective, effective),
        collectionEnvelope: {
          ...input.collectionEnvelope!,
          legacy: {
            ...input.collectionEnvelope!.legacy,
            decisionUniverses: {
              ...input.collectionEnvelope!.legacy.decisionUniverses,
              campusContexts: campusUniverse,
              effectiveDecisions: effectiveUniverse
            }
          },
          identity: {
            ...input.collectionEnvelope!.identity,
            decisionUniverses: {
              ...input.collectionEnvelope!.identity.decisionUniverses,
              campusContexts: campusUniverse,
              effectiveDecisions: effectiveUniverse
            }
          }
        }
      });
      for (const side of ["legacy", "identity"] as const) {
        expect(report.coverageBlockers).toEqual(expect.arrayContaining([
          { surface: "campus-context", code: "decision-universe-coverage-mismatch", side },
          { surface: "effective-decision", code: "decision-universe-coverage-mismatch", side }
        ]));
      }
    }
  );

  it("fixed-rejects retired v3 collector and decision-universe contracts", () => {
    const input = alignedInput();
    const oldCollector = validateOrganizationReconciliation({
      ...input,
      collectionEnvelope: {
        ...input.collectionEnvelope!,
        collectorContract: "iam-organization-reconciliation-collector/v3"
      }
    } as never);
    expect(oldCollector.coverageBlockers).toContainEqual({
      surface: "collection-envelope",
      code: "collector-contract-invalid"
    });

    const oldDecision = {
      ...input.collectionEnvelope!.legacy.decisionUniverses.campusContexts,
      derivationContract: "iam-organization-reconciliation-decision-universe/v3"
    };
    const oldDecisionReport = validateOrganizationReconciliation({
      ...input,
      collectionEnvelope: {
        ...input.collectionEnvelope!,
        legacy: {
          ...input.collectionEnvelope!.legacy,
          decisionUniverses: {
            ...input.collectionEnvelope!.legacy.decisionUniverses,
            campusContexts: oldDecision
          }
        },
        identity: {
          ...input.collectionEnvelope!.identity,
          decisionUniverses: {
            ...input.collectionEnvelope!.identity.decisionUniverses,
            campusContexts: oldDecision
          }
        }
      }
    } as never);
    expect(oldDecisionReport.coverageBlockers).toEqual(expect.arrayContaining([
      { surface: "collection-envelope", code: "decision-universe-derivation-invalid", side: "legacy" },
      { surface: "collection-envelope", code: "decision-universe-derivation-invalid", side: "identity" }
    ]));
  });

  it("domain-separates v4 evidence HMACs from the retired v3 contract", () => {
    const value = "domain-test";
    const current = createOrganizationReconciliationEvidenceHash(EVIDENCE_NONCE, value);
    const retired = createHmac("sha256", EVIDENCE_NONCE)
      .update("iam-organization-reconciliation:v3\u001f")
      .update(JSON.stringify(value))
      .digest("hex");
    expect(current).not.toBe(retired);
  });

  it("rejects plugin visibility allows without the exact active binding", () => {
    const input = alignedInput();
    const report = validateOrganizationReconciliation({
      ...input,
      pluginBindings: pair(
        [{ pluginRef: "plugin:campus", bindingRef: "binding-one", organizationRef: "legacy-org:1", active: false }],
        [{ pluginRef: "plugin:campus", bindingRef: "binding-one", organizationRef: "legacy-org:1", active: false }]
      )
    });
    expect(report.coverageBlockers).toEqual(expect.arrayContaining([
      expect.objectContaining({ surface: "organization-mapping", code: "cross-surface-reference-invalid", side: "legacy" }),
      expect.objectContaining({ surface: "organization-mapping", code: "cross-surface-reference-invalid", side: "identity" })
    ]));
  });

  it("requires every non-public binding and deny decision to resolve an organization", () => {
    const input = alignedInput();
    const report = validateOrganizationReconciliation({
      ...input,
      pluginBindings: pair(
        [{ pluginRef: "plugin:campus", bindingRef: "binding-one", organizationRef: "legacy-org:999", active: false }],
        [{ pluginRef: "plugin:campus", bindingRef: "binding-one", organizationRef: "legacy-org:999", active: false }]
      ),
      pluginVisibility: pair(
        [{ subjectRef: "legacy-user:581", pluginRef: "plugin:campus", organizationRef: "legacy-org:999", decision: "deny" }],
        [{ subjectRef: "legacy-user:581", pluginRef: "plugin:campus", organizationRef: "legacy-org:999", decision: "deny" }]
      ),
      campusContexts: pair(
        [{ subjectRef: "legacy-user:581", contextKind: "organization", contextRef: "legacy-org:999", decision: "deny" }],
        [{ subjectRef: "legacy-user:581", contextKind: "organization", contextRef: "legacy-org:999", decision: "deny" }]
      ),
      effectiveDecisions: pair(
        [{ subjectRef: "legacy-user:581", contextKind: "organization", contextRef: "legacy-org:999", resourceRef: "organization-one", capabilityRef: "read", decision: "deny" }],
        [{ subjectRef: "legacy-user:581", contextKind: "organization", contextRef: "legacy-org:999", resourceRef: "organization-one", capabilityRef: "read", decision: "deny" }]
      )
    });

    expect(report.coverageBlockers).toEqual(expect.arrayContaining([
      expect.objectContaining({ surface: "organization-mapping", code: "cross-surface-reference-invalid", side: "legacy" }),
      expect.objectContaining({ surface: "organization-mapping", code: "cross-surface-reference-invalid", side: "identity" })
    ]));
    expect(report.safetyGate).toMatchObject({ passed: false, blocksDualWrite: true });
  });

  it("rejects runtime-invalid records even when both sides carry the same value", () => {
    const input = alignedInput();
    const bogusDecision = {
      subjectRef: "legacy-user:581",
      pluginRef: "plugin:campus",
      organizationRef: "legacy-org:1",
      decision: "bogus"
    } as never;
    const decisionReport = validateOrganizationReconciliation({
      ...input,
      pluginVisibility: pair([bogusDecision], [bogusDecision])
    });
    expect(decisionReport.coverageBlockers).toEqual(expect.arrayContaining([
      { surface: "plugin-visibility", code: "record-schema-invalid", side: "legacy" },
      { surface: "plugin-visibility", code: "record-schema-invalid", side: "identity" }
    ]));

    const stringActive = {
      subjectRef: "legacy-user:581",
      legacyOrganizationId: 1,
      active: "true"
    } as never;
    const activeReport = validateOrganizationReconciliation({
      ...input,
      memberships: pair([stringActive], [stringActive])
    });
    expect(activeReport.coverageBlockers).toEqual(expect.arrayContaining([
      { surface: "membership", code: "record-schema-invalid", side: "legacy" },
      { surface: "membership", code: "record-schema-invalid", side: "identity" }
    ]));
  });

  it("rejects non-canonical subject and plugin refs at the direct validator boundary", () => {
    const input = alignedInput();
    for (const subjectRef of [
      "private-user-581",
      "legacy-user:0",
      "legacy-user:01",
      "identity-user:581",
      "legacy-user:legacy-user:581",
      " legacy-user:581",
      "legacy-user:581 ",
      "legacy-user:\u0001581"
    ]) {
      const report = validateOrganizationReconciliation({
        ...input,
        memberships: pair(
          [{ subjectRef, legacyOrganizationId: 1, active: true }],
          [{ subjectRef, legacyOrganizationId: 1, active: true }]
        )
      });
      expect(report.coverageBlockers).toEqual(expect.arrayContaining([
        { surface: "membership", code: "record-schema-invalid", side: "legacy" },
        { surface: "membership", code: "record-schema-invalid", side: "identity" }
      ]));
    }

    for (const pluginRef of [
      "campus-plugin",
      "",
      " plugin:campus",
      "plugin:campus ",
      "plugin:campus tool",
      "plugin:campus:tool",
      "plugin:campus/tool",
      "plugin:campus.tool",
      "plugin:campus_tool",
      "plugin:café",
      "plugin:cafe\u0301",
      "plugin:campus\u0000",
      "plugin:plugin:campus",
      `plugin:${"a".repeat(65)}`
    ]) {
      const report = validateOrganizationReconciliation({
        ...input,
        pluginBindings: pair(
          [{ pluginRef, bindingRef: "binding-one", organizationRef: "legacy-org:1", active: true }],
          [{ pluginRef, bindingRef: "binding-one", organizationRef: "legacy-org:1", active: true }]
        )
      });
      expect(report.coverageBlockers).toEqual(expect.arrayContaining([
        { surface: "plugin-binding", code: "record-schema-invalid", side: "legacy" },
        { surface: "plugin-binding", code: "record-schema-invalid", side: "identity" }
      ]));
    }
  });

  it("returns a deterministic fail-closed report for malformed direct API containers", () => {
    for (const malformed of [
      null,
      { collectionEnvelope: {} },
      {
        ...alignedInput(),
        memberships: {
          legacy: { records: null },
          identity: { records: null }
        }
      },
      {
        ...alignedInput(),
        memberships: {
          ...alignedInput().memberships,
          legacy: {
            ...alignedInput().memberships!.legacy,
            collection: { pages: null }
          }
        }
      }
    ]) {
      const report = validateOrganizationReconciliation(malformed as never);
      expect(report.coverageBlockers.some((blocker) =>
        blocker.code === "input-schema-invalid" || blocker.code === "record-schema-invalid"
      )).toBe(true);
      expect(report.safetyGate).toMatchObject({ passed: false, blocksDualWrite: true });
      expect(report.reportHash).toMatch(/^[a-f0-9]{24}$/);
    }
  });

  it("rejects more than one binding for the same plugin even when binding refs differ", () => {
    const input = alignedInput();
    const bindings = [
      { pluginRef: "plugin:campus", bindingRef: "binding-one", organizationRef: "legacy-org:1", active: true },
      { pluginRef: "plugin:campus", bindingRef: "binding-two", organizationRef: "org:public", active: true }
    ] as const;
    const report = validateOrganizationReconciliation({
      ...input,
      pluginBindings: pair(bindings, bindings)
    });
    expect(report.coverageBlockers).toEqual(expect.arrayContaining([
      expect.objectContaining({ surface: "plugin-binding", code: "duplicate-key", side: "legacy" }),
      expect.objectContaining({ surface: "plugin-binding", code: "duplicate-key", side: "identity" })
    ]));
  });

  it("classifies identity allow plus Legacy deny as P0 and never unions decisions", () => {
    const input = alignedInput();
    const report = validateOrganizationReconciliation({
      ...input,
      pluginVisibility: pair(
        [{ subjectRef: "legacy-user:581", pluginRef: "plugin:campus", organizationRef: "legacy-org:1", decision: "deny" }],
        [{ subjectRef: "legacy-user:581", pluginRef: "plugin:campus", organizationRef: "legacy-org:1", decision: "allow" }]
      )
    });

    expect(report.findings).toContainEqual(expect.objectContaining({
      surface: "plugin-visibility",
      severity: "P0",
      reasonCode: "identity-allow-legacy-deny"
    }));
    expect(report.severity.P0).toBe(1);
    expect(report.coverageBlockers).toContainEqual({
      surface: "collection-envelope",
      code: "real-source-adapters-not-ready"
    });
    expect(report.safetyGate).toMatchObject({
      passed: false,
      blocksDualWrite: true,
      unionForbidden: true,
      blockedReasons: ["coverage-incomplete", "p0-findings", "external-provenance-required"]
    });
    expect(JSON.stringify(report)).not.toContain("legacy-user:581");
    expect(JSON.stringify(report)).not.toContain("plugin:campus");
  });

  it("classifies Legacy allow plus Identity deny as P1", () => {
    const input = alignedInput();
    const report = validateOrganizationReconciliation({
      ...input,
      effectiveDecisions: pair(
        [{ subjectRef: "legacy-user:581", contextKind: "organization", contextRef: "legacy-org:1", resourceRef: "organization-one", capabilityRef: "read", decision: "allow" }],
        [{ subjectRef: "legacy-user:581", contextKind: "organization", contextRef: "legacy-org:1", resourceRef: "organization-one", capabilityRef: "read", decision: "deny" }]
      )
    });

    expect(report.findings).toContainEqual(expect.objectContaining({
      surface: "effective-decision",
      severity: "P1",
      reasonCode: "legacy-allow-identity-deny"
    }));
    expect(report.severity.P1).toBe(1);
    expect(report.safetyGate).toMatchObject({
      passed: false,
      blocksDualWrite: true,
      blockedReasons: ["coverage-incomplete", "p1-findings", "external-provenance-required"]
    });
  });

  it("keeps the explicitly allowlisted display title at classified P2", () => {
    const input = alignedInput();
    const legacyRecord = {
      legacyOrganizationId: 1,
      name: "test-university",
      title: "Legacy private title",
      active: true,
    };
    const identityRecord = {
      legacyOrganizationId: 1,
      name: "test-university",
      title: "Identity private title",
      active: true,
    };
    const report = validateOrganizationReconciliation({
      ...input,
      organizationDirectory: pair([legacyRecord], [identityRecord])
    });

    expect(report.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ surface: "organization-directory", severity: "P2", reasonCode: "display-only-mismatch" })
    ]));
    expect(report.severity).toMatchObject({ P0: 0, P1: 0, P2: 1 });
    expect(report).toMatchObject({
      staticChecksPassed: false,
      safetyGate: {
        passed: false,
        p2Classified: true,
        blockedReasons: ["coverage-incomplete", "p2-findings", "external-provenance-required"]
      }
    });
    const serialized = JSON.stringify(report);
    expect(serialized).not.toContain("Legacy private title");
    expect(serialized).not.toContain("Identity private title");
  });

  it("blocks on a missing surface or any non-empty next cursor", () => {
    const { pluginBindings: _omitted, ...withoutPluginBindings } = alignedInput();
    const campus = withoutPluginBindings.campusContexts!;
    const report = validateOrganizationReconciliation({
      ...withoutPluginBindings,
      campusContexts: {
        legacy: campus.legacy,
        identity: {
          ...campus.identity!,
          nextCursor: "opaque-secret-next-page"
        }
      }
    });

    expect(report.coverageBlockers).toEqual(expect.arrayContaining([
      { surface: "plugin-binding", code: "surface-missing" },
      { surface: "campus-context", code: "pagination-incomplete", side: "identity" }
    ]));
    expect(report.safetyGate).toMatchObject({
      passed: false,
      coverageComplete: false,
      blockedReasons: ["coverage-incomplete", "external-provenance-required"]
    });
    expect(JSON.stringify(report)).not.toContain("opaque-secret-next-page");
  });

  it("blocks when source-version or pagination-completion evidence is absent", () => {
    const input = alignedInput();
    const membership = input.memberships!;
    const report = validateOrganizationReconciliation({
      ...input,
      memberships: {
        legacy: {
          records: membership.legacy!.records,
          nextCursor: null
        },
        identity: {
          records: membership.identity!.records,
          sourceVersion: "identity-membership-v1"
        }
      }
    });

    expect(report.coverageBlockers).toEqual(expect.arrayContaining([
      { surface: "membership", code: "source-version-missing", side: "legacy" },
      { surface: "membership", code: "pagination-state-missing", side: "identity" }
    ]));
    expect(report.safetyGate.passed).toBe(false);
  });

  it("classifies extra authorization-bearing state as P0 and missing state as P1", () => {
    const input = alignedInput();
    const report = validateOrganizationReconciliation({
      ...input,
      memberships: pair(
        [
          { subjectRef: "legacy-user:581", legacyOrganizationId: 1, active: true },
          { subjectRef: "legacy-user:101", legacyOrganizationId: 1, active: true },
          { subjectRef: "legacy-user:102", legacyOrganizationId: 1, active: true }
        ],
        [
          { subjectRef: "legacy-user:581", legacyOrganizationId: 1, active: true },
          { subjectRef: "legacy-user:101", legacyOrganizationId: 1, active: true },
          { subjectRef: "legacy-user:103", legacyOrganizationId: 1, active: true }
        ]
      ),
      organizationMappings: pair(
        [{ legacyOrganizationId: 1, identityOrganizationId: "identity-org-one", active: true }],
        [{ legacyOrganizationId: 1, identityOrganizationId: "identity-org-wrong", active: true }]
      )
    });

    expect(report.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ surface: "membership", severity: "P0", reasonCode: "identity-only-record" }),
      expect.objectContaining({ surface: "membership", severity: "P1", reasonCode: "identity-record-missing" }),
      expect.objectContaining({ surface: "organization-mapping", severity: "P0", reasonCode: "organization-id-mapping-mismatch" })
    ]));
    expect(report.safetyGate.blockedReasons).toEqual([
      "coverage-incomplete",
      "p0-findings",
      "p1-findings",
      "external-provenance-required"
    ]);
    expect(JSON.stringify(report)).not.toContain("identity-org-wrong");
    expect(JSON.stringify(report)).not.toContain("legacy-user:103");
  });

  it("blocks ambiguous duplicate keys without exposing the duplicate identity", () => {
    const input = alignedInput();
    const duplicate = { subjectRef: "legacy-user:9003", legacyOrganizationId: 1, active: true } as const;
    const report = validateOrganizationReconciliation({
      ...input,
      memberships: pair([duplicate, duplicate], [duplicate])
    });

    expect(report.coverageBlockers).toContainEqual(expect.objectContaining({
      surface: "membership",
      code: "duplicate-key",
      side: "legacy",
      entityHash: expect.stringMatching(/^[a-f0-9]{24}$/)
    }));
    expect(report.safetyGate).toMatchObject({ passed: false, coverageComplete: false });
    expect(JSON.stringify(report)).not.toContain("legacy-user:9003");
  });

  it("blocks two Legacy organizations from reusing one Identity organization target", () => {
    const input = alignedInput();
    const ambiguous = [
      { legacyOrganizationId: 1, identityOrganizationId: "shared-private-identity-org", active: true },
      { legacyOrganizationId: 2, identityOrganizationId: "shared-private-identity-org", active: true }
    ] as const;
    const report = validateOrganizationReconciliation({
      ...input,
      organizationMappings: pair(ambiguous, ambiguous)
    });

    expect(report.coverageBlockers).toEqual(expect.arrayContaining([
      expect.objectContaining({ surface: "organization-mapping", code: "mapping-target-reused", side: "legacy" }),
      expect.objectContaining({ surface: "organization-mapping", code: "mapping-target-reused", side: "identity" })
    ]));
    expect(report.safetyGate).toMatchObject({ passed: false, coverageComplete: false });
    expect(JSON.stringify(report)).not.toContain("shared-private-identity-org");
  });

  it("allows heterogeneous source-owned revisions but blocks a changed per-side envelope revision", () => {
    const aligned = validateOrganizationReconciliation(alignedInput());
    expect(aligned.coverageBlockers).not.toEqual(expect.arrayContaining([
      expect.objectContaining({ code: "source-version-envelope-mismatch" })
    ]));

    const input = alignedInput();
    const report = validateOrganizationReconciliationRaw({
      ...input,
      collectionEnvelope: {
        ...input.collectionEnvelope!,
        identity: { ...input.collectionEnvelope!.identity, sourceVersion: "identity-source-v2" }
      }
    });

    expect(report.coverageBlockers).toEqual(expect.arrayContaining([
      { surface: "organization-directory", code: "source-version-envelope-mismatch", side: "identity" },
      { surface: "effective-decision", code: "source-version-envelope-mismatch", side: "identity" }
    ]));
    expect(report.safetyGate.passed).toBe(false);
    expect(JSON.stringify(report)).not.toContain("identity-source-v2");
  });

  it("requires a reviewed collector build and the same complete subject universe on both sides", () => {
    const input = alignedInput();
    const invalidBuild = validateOrganizationReconciliation({
      ...input,
      collectionEnvelope: { ...input.collectionEnvelope!, collectorBuildRevision: "short" }
    });
    expect(invalidBuild.coverageBlockers).toContainEqual({
      surface: "collection-envelope",
      code: "collector-build-revision-invalid"
    });

    const secondSubject = "legacy-user:9001";
    const expandedHash = createOrganizationReconciliationEvidenceHash(
      EVIDENCE_NONCE,
      ["legacy-user:581", secondSubject].sort()
    );
    const expandedDecisionUniverses = {
      pluginVisibility: decisionUniverse([
        ["legacy-user:581", "plugin:campus", "legacy-org:1"],
        [secondSubject, "plugin:campus", "legacy-org:1"]
      ], {
        subjects: ["legacy-user:581", secondSubject],
        plugins: ["plugin:campus"],
        organizations: ["legacy-org:1"]
      }),
      campusContexts: decisionUniverse([
        ["legacy-user:581", "campus-one"],
        [secondSubject, "campus-one"]
      ], {
        subjects: ["legacy-user:581", secondSubject],
        campuses: ["campus-one"],
        organizations: ["legacy-org:1"]
      }),
      effectiveDecisions: decisionUniverse([
        ["legacy-user:581", "legacy-org:1", "organization-one", "read"],
        [secondSubject, "legacy-org:1", "organization-one", "read"]
      ], {
        subjects: ["legacy-user:581", secondSubject],
        organizations: ["legacy-org:1"],
        resources: ["organization-one"],
        capabilities: ["read"],
        rulePairs: [JSON.stringify(["organization-one", "read"])]
      })
    };
    const omittedSubject = validateOrganizationReconciliation({
      ...input,
      collectionEnvelope: {
        ...input.collectionEnvelope!,
        legacy: {
          ...input.collectionEnvelope!.legacy,
          subjectUniverse: { subjectCount: 2, subjectsHash: expandedHash },
          decisionUniverses: expandedDecisionUniverses
        },
        identity: {
          ...input.collectionEnvelope!.identity,
          subjectUniverse: { subjectCount: 2, subjectsHash: expandedHash },
          decisionUniverses: expandedDecisionUniverses
        }
      }
    });
    expect(omittedSubject.coverageBlockers).toEqual(expect.arrayContaining([
      { surface: "plugin-visibility", code: "decision-universe-coverage-mismatch", side: "legacy" },
      { surface: "campus-context", code: "decision-universe-coverage-mismatch", side: "identity" },
      { surface: "effective-decision", code: "decision-universe-coverage-mismatch", side: "legacy" }
    ]));
    expect(omittedSubject.safetyGate.passed).toBe(false);
    expect(JSON.stringify(omittedSubject)).not.toContain(secondSubject);

    const mismatchedSides = validateOrganizationReconciliation({
      ...input,
      collectionEnvelope: {
        ...input.collectionEnvelope!,
        identity: {
          ...input.collectionEnvelope!.identity,
          subjectUniverse: { subjectCount: 2, subjectsHash: expandedHash }
        }
      }
    });
    expect(mismatchedSides.coverageBlockers).toContainEqual({
      surface: "collection-envelope",
      code: "subject-universe-side-mismatch"
    });
  });

  it("accepts an internally valid attested empty dimension while retaining the real-adapter blocker", () => {
    const input = alignedInput();
    const emptyUniverse = decisionUniverse([], {
      subjects: ["legacy-user:581"],
      plugins: [],
      organizations: []
    });
    const report = validateOrganizationReconciliation({
      ...input,
      pluginBindings: pair([], []),
      pluginVisibility: pair([], []),
      collectionEnvelope: {
        ...input.collectionEnvelope!,
        legacy: {
          ...input.collectionEnvelope!.legacy,
          decisionUniverses: {
            ...input.collectionEnvelope!.legacy.decisionUniverses,
            pluginVisibility: emptyUniverse
          }
        },
        identity: {
          ...input.collectionEnvelope!.identity,
          decisionUniverses: {
            ...input.collectionEnvelope!.identity.decisionUniverses,
            pluginVisibility: emptyUniverse
          }
        }
      }
    });
    expect(report.coverageBlockers).toEqual([
      { surface: "collection-envelope", code: "real-source-adapters-not-ready" }
    ]);
    expect(report.staticChecksPassed).toBe(false);
    expect(report.safetyGate.blockedReasons).toEqual([
      "coverage-incomplete",
      "external-provenance-required"
    ]);
  });

  it("rejects self-reported decision dimensions that are missing, changed, or falsely empty", () => {
    const input = alignedInput();
    const pluginUniverse = input.collectionEnvelope!.legacy.decisionUniverses.pluginVisibility;
    const missingDimension = {
      ...pluginUniverse,
      dimensions: { ...pluginUniverse.dimensions }
    } as { dimensions: Record<string, unknown> } & typeof pluginUniverse;
    delete missingDimension.dimensions.plugins;
    const missing = validateOrganizationReconciliation({
      ...input,
      collectionEnvelope: {
        ...input.collectionEnvelope!,
        legacy: {
          ...input.collectionEnvelope!.legacy,
          decisionUniverses: {
            ...input.collectionEnvelope!.legacy.decisionUniverses,
            pluginVisibility: missingDimension
          }
        }
      }
    });
    expect(missing.coverageBlockers).toEqual(expect.arrayContaining([
      { surface: "collection-envelope", code: "decision-universe-derivation-invalid", side: "legacy" },
      { surface: "collection-envelope", code: "decision-universe-side-mismatch" }
    ]));

    const changed = validateOrganizationReconciliation({
      ...input,
      collectionEnvelope: {
        ...input.collectionEnvelope!,
        legacy: {
          ...input.collectionEnvelope!.legacy,
          decisionUniverses: {
            ...input.collectionEnvelope!.legacy.decisionUniverses,
            effectiveDecisions: {
              ...input.collectionEnvelope!.legacy.decisionUniverses.effectiveDecisions,
              derivationBuildRevision: "b".repeat(40),
              dimensions: {
                ...input.collectionEnvelope!.legacy.decisionUniverses.effectiveDecisions.dimensions,
                capabilities: { count: 1, hash: "b".repeat(64) }
              }
            }
          }
        }
      }
    });
    expect(changed.coverageBlockers).toEqual(expect.arrayContaining([
      { surface: "collection-envelope", code: "decision-universe-derivation-invalid", side: "legacy" },
      { surface: "effective-decision", code: "decision-dimension-coverage-mismatch", side: "legacy" }
    ]));

    const falselyEmpty = decisionUniverse([], {
      subjects: ["legacy-user:581"],
      plugins: ["plugin:campus"],
      organizations: ["legacy-org:1"]
    });
    const emptyReport = validateOrganizationReconciliation({
      ...input,
      pluginVisibility: pair([], []),
      collectionEnvelope: {
        ...input.collectionEnvelope!,
        legacy: {
          ...input.collectionEnvelope!.legacy,
          decisionUniverses: {
            ...input.collectionEnvelope!.legacy.decisionUniverses,
            pluginVisibility: falselyEmpty
          }
        },
        identity: {
          ...input.collectionEnvelope!.identity,
          decisionUniverses: {
            ...input.collectionEnvelope!.identity.decisionUniverses,
            pluginVisibility: falselyEmpty
          }
        }
      }
    });
    expect(emptyReport.coverageBlockers).toEqual(expect.arrayContaining([
      { surface: "collection-envelope", code: "decision-universe-derivation-invalid", side: "legacy" },
      { surface: "collection-envelope", code: "decision-universe-derivation-invalid", side: "identity" }
    ]));
  });

  it("blocks a non-empty decision surface when its records and key universe omit a subject", () => {
    const input = alignedInput();
    const secondSubject = "legacy-user:9001";
    const expandedHash = createOrganizationReconciliationEvidenceHash(
      EVIDENCE_NONCE,
      ["legacy-user:581", secondSubject].sort()
    );
    const report = validateOrganizationReconciliation({
      ...input,
      collectionEnvelope: {
        ...input.collectionEnvelope!,
        legacy: {
          ...input.collectionEnvelope!.legacy,
          subjectUniverse: { subjectCount: 2, subjectsHash: expandedHash }
        },
        identity: {
          ...input.collectionEnvelope!.identity,
          subjectUniverse: { subjectCount: 2, subjectsHash: expandedHash }
        }
      }
    });

    for (const surface of ["plugin-visibility", "campus-context", "effective-decision"] as const) {
      expect(report.coverageBlockers).toEqual(expect.arrayContaining([
        { surface, code: "decision-subject-universe-coverage-mismatch", side: "legacy" },
        { surface, code: "decision-subject-universe-coverage-mismatch", side: "identity" }
      ]));
    }
    expect(report.safetyGate.passed).toBe(false);
    expect(JSON.stringify(report)).not.toContain(secondSubject);
  });

  it("blocks a missing collector envelope and an internally truncated aggregate", () => {
    const input = alignedInput();
    const {
      collectionEnvelope: _missingEnvelope,
      componentManifest: _missingManifest,
      ...withoutEnvelopeBody
    } = input;
    const withoutEnvelope = validateOrganizationReconciliation(withoutEnvelopeBody);
    expect(withoutEnvelope.coverageBlockers).toContainEqual({
      surface: "collection-envelope",
      code: "collection-envelope-missing"
    });
    expect(withoutEnvelope.coverageBlockers).toContainEqual({
      surface: "collection-envelope",
      code: "evidence-nonce-invalid"
    });
    expect(withoutEnvelope.findings).toEqual([]);
    expect(JSON.stringify(withoutEnvelope)).not.toContain("legacy-user:581");
    expect(withoutEnvelope.safetyGate.passed).toBe(false);

    const membership = input.memberships!;
    const truncated = validateOrganizationReconciliation({
      ...input,
      memberships: {
        legacy: membership.legacy,
        identity: { ...membership.identity!, records: [] }
      }
    });
    expect(truncated.coverageBlockers).toEqual(expect.arrayContaining([
      { surface: "membership", code: "record-count-mismatch", side: "identity" },
      { surface: "membership", code: "page-record-hash-mismatch", side: "identity" },
      { surface: "membership", code: "aggregate-record-hash-mismatch", side: "identity" }
    ]));
    expect(truncated.safetyGate.passed).toBe(false);
  });

  it("accepts only null as the terminal cursor", () => {
    const input = alignedInput();
    const identity = input.memberships!.identity!;
    const report = validateOrganizationReconciliation({
      ...input,
      memberships: {
        legacy: input.memberships!.legacy,
        identity: {
          ...identity,
          nextCursor: " ",
          collection: {
            ...identity.collection!,
            pages: [{ ...identity.collection!.pages[0]!, nextCursor: " " }]
          }
        }
      }
    });

    expect(report.coverageBlockers).toEqual(expect.arrayContaining([
      { surface: "membership", code: "pagination-incomplete", side: "identity" },
      { surface: "membership", code: "cursor-chain-invalid", side: "identity" }
    ]));
    expect(report.safetyGate.passed).toBe(false);
  });

  it("blocks a partial subject-by-plugin product even when every distinct dimension appears", () => {
    const input = alignedInput();
    const secondSubject = "legacy-user:582";
    const subjects = ["legacy-user:581", secondSubject].sort();
    const subjectsHash = createOrganizationReconciliationEvidenceHash(EVIDENCE_NONCE, subjects);
    const bindings = [
      { pluginRef: "plugin:campus", bindingRef: "binding-one", organizationRef: "legacy-org:1", active: true },
      { pluginRef: "plugin:public", bindingRef: "binding-public", organizationRef: "org:public", active: true }
    ] as const;
    const visibility = [
      { subjectRef: "legacy-user:581", pluginRef: "plugin:campus", organizationRef: "legacy-org:1", decision: "allow" },
      { subjectRef: "legacy-user:581", pluginRef: "plugin:public", organizationRef: "org:public", decision: "allow" },
      { subjectRef: secondSubject, pluginRef: "plugin:campus", organizationRef: "legacy-org:1", decision: "deny" }
    ] as const;
    const campuses = subjects.flatMap((subjectRef) => AUTHORIZATION_CONTEXTS.map(
      ([contextKind, contextRef], index) => ({
        subjectRef,
        contextKind,
        contextRef,
        decision: subjectRef === "legacy-user:581" && index === 0 ? "allow" as const : "deny" as const
      })
    ));
    const decisions = subjects.flatMap((subjectRef) => AUTHORIZATION_CONTEXTS.map(
      ([contextKind, contextRef], index) => ({
        subjectRef,
        contextKind,
        contextRef,
        resourceRef: "organization-one",
        capabilityRef: "read",
        decision: subjectRef === "legacy-user:581" && index === 0 ? "allow" as const : "deny" as const
      })
    ));
    const universes = {
      pluginVisibility: decisionUniverse(
        visibility.map((record) => [record.subjectRef, record.pluginRef, record.organizationRef]),
        {
          subjects,
          plugins: ["plugin:campus", "plugin:public"],
          organizations: ["legacy-org:1", "org:public"]
        }
      ),
      campusContexts: decisionUniverse(
        campuses.map((record) => [record.subjectRef, record.contextKind, record.contextRef]),
        { subjects, contexts: AUTHORIZATION_CONTEXT_DIMENSIONS }
      ),
      effectiveDecisions: decisionUniverse(
        decisions.map((record) => [
          record.subjectRef,
          record.contextKind,
          record.contextRef,
          record.resourceRef,
          record.capabilityRef
        ]),
        {
          subjects,
          contexts: AUTHORIZATION_CONTEXT_DIMENSIONS,
          resources: ["organization-one"],
          capabilities: ["read"],
          rulePairs: [JSON.stringify(["organization-one", "read"])]
        }
      )
    };
    const report = validateOrganizationReconciliation({
      ...input,
      pluginBindings: pair(bindings, bindings),
      pluginVisibility: pair(visibility, visibility),
      campusContexts: pair(campuses, campuses),
      effectiveDecisions: pair(decisions, decisions),
      collectionEnvelope: {
        ...input.collectionEnvelope!,
        legacy: {
          ...input.collectionEnvelope!.legacy,
          subjectUniverse: { subjectCount: 2, subjectsHash },
          decisionUniverses: universes
        },
        identity: {
          ...input.collectionEnvelope!.identity,
          subjectUniverse: { subjectCount: 2, subjectsHash },
          decisionUniverses: universes
        }
      }
    });
    expect(report.coverageBlockers).toEqual(expect.arrayContaining([
      { surface: "plugin-visibility", code: "decision-universe-coverage-mismatch", side: "legacy" },
      { surface: "plugin-visibility", code: "decision-universe-coverage-mismatch", side: "identity" }
    ]));
  });

  it("keeps semantic output deterministic while the manifest binds exact record order", () => {
    const input = alignedInput();
    const membership = input.memberships!;
    const extra = { subjectRef: "legacy-user:9002", legacyOrganizationId: 2, active: true } as const;
    const first = validateOrganizationReconciliation({
      ...input,
      memberships: pair([...membership.legacy!.records, extra], [...membership.identity!.records, extra])
    });
    const second = validateOrganizationReconciliation({
      ...input,
      memberships: pair([extra, ...membership.legacy!.records], [extra, ...membership.identity!.records])
    });

    const {
      componentManifestHash: firstManifestHash,
      reportHash: firstReportHash,
      ...firstSemanticReport
    } = first;
    const {
      componentManifestHash: secondManifestHash,
      reportHash: secondReportHash,
      ...secondSemanticReport
    } = second;
    expect(secondSemanticReport).toEqual(firstSemanticReport);
    expect(secondManifestHash).not.toBe(firstManifestHash);
    expect(secondReportHash).not.toBe(firstReportHash);
    expect(JSON.stringify(first)).not.toContain("legacy-user:9002");
  });
});

function alignedInput(): OrganizationReconciliationInput {
  return attachProjectionBoundTestManifest({
    collectionEnvelope: collectionEnvelope(),
    organizationDirectory: pair(
      [{ legacyOrganizationId: 1, name: "test-university", title: "Private title", active: true }],
      [{ legacyOrganizationId: 1, name: "test-university", title: "Private title", active: true }]
    ),
    organizationMappings: pair(
      [{ legacyOrganizationId: 1, identityOrganizationId: "identity-org-one", active: true }],
      [{ legacyOrganizationId: 1, identityOrganizationId: "identity-org-one", active: true }]
    ),
    memberships: pair(
      [{ subjectRef: "legacy-user:581", legacyOrganizationId: 1, active: true }],
      [{ subjectRef: "legacy-user:581", legacyOrganizationId: 1, active: true }]
    ),
    organizationScopedRoles: pair(
      [{ subjectRef: "legacy-user:581", legacyOrganizationId: 1, roleRef: "private-role-alpha", active: true }],
      [{ subjectRef: "legacy-user:581", legacyOrganizationId: 1, roleRef: "private-role-alpha", active: true }]
    ),
    pluginBindings: pair(
      [{ pluginRef: "plugin:campus", bindingRef: "binding-one", organizationRef: "legacy-org:1", active: true }],
      [{ pluginRef: "plugin:campus", bindingRef: "binding-one", organizationRef: "legacy-org:1", active: true }]
    ),
    pluginVisibility: pair(
      [{ subjectRef: "legacy-user:581", pluginRef: "plugin:campus", organizationRef: "legacy-org:1", decision: "allow" }],
      [{ subjectRef: "legacy-user:581", pluginRef: "plugin:campus", organizationRef: "legacy-org:1", decision: "allow" }]
    ),
    campusContexts: pair(
      baselineCampusRecords("legacy-user:581"),
      baselineCampusRecords("legacy-user:581")
    ),
    effectiveDecisions: pair(
      baselineEffectiveDecisionRecords("legacy-user:581"),
      baselineEffectiveDecisionRecords("legacy-user:581")
    )
  });
}

function validateOrganizationReconciliation(
  input: OrganizationReconciliationInput,
  options?: OrganizationReconciliationValidationOptions
) {
  let rebound = input;
  try {
    rebound = attachProjectionBoundTestManifest(input);
  } catch {
    // Malformed-input tests must reach the production fail-closed boundary.
  }
  return validateOrganizationReconciliationRaw(rebound, options);
}

function attachProjectionBoundTestManifest(
  candidate: OrganizationReconciliationInput
): OrganizationReconciliationInput {
  const lineage = attachTestOrganizationReconciliationComponentManifest(candidate);
  const manifest = lineage.componentManifest;
  if (!manifest) return lineage;
  const legacy = manifest.components.find((component) => component.componentId === "legacy-main")!;
  const identity = manifest.components.find((component) => component.componentId === "identity")!;
  const plugin = manifest.components.find((component) => component.componentId === "plugin")!;
  return attachTestOrganizationReconciliationComponentManifest({
    ...candidate,
    projectionBinding: {
      contract: "iam-organization-reconciliation-projection-binding/v1",
      semanticRegistrySha256: "7".repeat(64),
      lineageManifestSha256: manifest.parentLineageManifestSha256,
      legacy: {
        projectorContract: "iam-organization-legacy-surface-projector/v2",
        evaluatorId: "test/legacy/validator",
        evaluatorBuildSha256: "8".repeat(64),
        primarySource: {
          sourceVersion: legacy.sourceVersion,
          snapshotId: legacy.snapshotId
        }
      },
      identity: {
        projectorContract: "iam-organization-identity-surface-projector/v2",
        evaluatorId: "test/identity/validator",
        evaluatorBuildSha256: "9".repeat(64),
        primarySource: {
          sourceVersion: identity.sourceVersion,
          snapshotId: identity.snapshotId
        }
      },
      pluginSource: {
        sourceVersion: plugin.sourceVersion,
        snapshotId: plugin.snapshotId
      }
    }
  });
}

function lineageManifestForFinal(
  manifest: OrganizationReconciliationOperationCompositeManifest
): OrganizationReconciliationCompositeManifest {
  const unsigned: OrganizationReconciliationCompositeManifestUnsigned = {
    contract: ORGANIZATION_RECONCILIATION_COMPOSITE_MANIFEST_CONTRACT,
    consistencyModel: manifest.consistencyModel,
    crossDatabaseAtomic: manifest.crossDatabaseAtomic,
    windowStartedAt: manifest.windowStartedAt,
    windowEndedAt: manifest.windowEndedAt,
    maxWindowMilliseconds: manifest.maxWindowMilliseconds,
    evidenceContract: manifest.evidenceContract,
    evidenceSha256: createOrganizationReconciliationOperationEvidenceSha256({
      contract: "iam-organization-reconciliation-test-lineage-root/v1"
    }),
    components: manifest.components
  };
  const lineage = {
    ...unsigned,
    manifestSha256: createOrganizationReconciliationCompositeManifestSha256(unsigned)
  };
  expect(lineage.manifestSha256).toBe(manifest.parentLineageManifestSha256);
  return lineage;
}

function pair<T>(legacy: readonly T[], identity: readonly T[]): ReconciliationPair<T> {
  return {
    legacy: page(legacy, "legacy-source-v1", "legacy-snapshot-v1"),
    identity: page(identity, "identity-source-v1", "identity-snapshot-v1")
  };
}

function page<T>(records: readonly T[], sourceVersion: string, snapshotId: string) {
  const recordsHash = createOrganizationReconciliationEvidenceHash(EVIDENCE_NONCE, records as never);
  return {
    records,
    sourceVersion,
    nextCursor: null,
    collection: {
      snapshotId,
      firstCursor: null,
      pageCount: 1,
      recordCount: records.length,
      recordsHash,
      pages: [{
        pageNumber: 1,
        requestCursor: null,
        nextCursor: null,
        recordOffset: 0,
        recordCount: records.length,
        recordsHash
      }]
    }
  } as const;
}

const EVIDENCE_NONCE = "a1".repeat(32);
const AUTHORIZATION_CONTEXTS = [
  ["organization", "legacy-org:1"],
  ["platform-global", "org:platform-global"],
  ["public", "org:public"]
] as const;
const AUTHORIZATION_CONTEXT_DIMENSIONS = AUTHORIZATION_CONTEXTS.map((context) => JSON.stringify(context));

function collectionEnvelope() {
  return {
    collectorContract: ORGANIZATION_RECONCILIATION_COLLECTOR_CONTRACT,
    collectorContractHash: ORGANIZATION_RECONCILIATION_COLLECTOR_CONTRACT_HASH,
    collectorBuildRevision: COLLECTOR_BUILD_REVISION,
    evidenceNonce: EVIDENCE_NONCE,
    logicalSnapshotId: "logical-snapshot-v1",
    windowId: "window-v1",
    windowStartedAt: "2026-08-09T00:00:00.000Z",
    windowEndedAt: "2026-08-09T00:05:00.000Z",
    legacy: {
      sourceVersion: "legacy-source-v1",
      snapshotId: "legacy-snapshot-v1",
      subjectUniverse: { subjectCount: 1, subjectsHash: SUBJECT_UNIVERSE_HASH },
      decisionUniverses: DECISION_UNIVERSES
    },
    identity: {
      sourceVersion: "identity-source-v1",
      snapshotId: "identity-snapshot-v1",
      subjectUniverse: { subjectCount: 1, subjectsHash: SUBJECT_UNIVERSE_HASH },
      decisionUniverses: DECISION_UNIVERSES
    }
  } as const;
}

const COLLECTOR_BUILD_REVISION = "a".repeat(40);
const SUBJECT_UNIVERSE_HASH = createOrganizationReconciliationEvidenceHash(
  EVIDENCE_NONCE,
  ["legacy-user:581"]
);
const DECISION_UNIVERSES = {
  pluginVisibility: decisionUniverse(
    [["legacy-user:581", "plugin:campus", "legacy-org:1"]],
    { subjects: ["legacy-user:581"], plugins: ["plugin:campus"], organizations: ["legacy-org:1"] }
  ),
  campusContexts: decisionUniverse(
    AUTHORIZATION_CONTEXTS.map(([contextKind, contextRef]) =>
      ["legacy-user:581", contextKind, contextRef]
    ),
    {
      subjects: ["legacy-user:581"],
      contexts: AUTHORIZATION_CONTEXT_DIMENSIONS
    }
  ),
  effectiveDecisions: decisionUniverse(
    AUTHORIZATION_CONTEXTS.map(([contextKind, contextRef]) =>
      ["legacy-user:581", contextKind, contextRef, "organization-one", "read"]
    ),
    {
      subjects: ["legacy-user:581"],
      contexts: AUTHORIZATION_CONTEXT_DIMENSIONS,
      resources: ["organization-one"],
      capabilities: ["read"],
      rulePairs: [JSON.stringify(["organization-one", "read"])]
    }
  )
};

function baselineCampusRecords(subjectRef: string) {
  return [
    { subjectRef, contextKind: "organization", contextRef: "legacy-org:1", decision: "allow" },
    { subjectRef, contextKind: "platform-global", contextRef: "org:platform-global", decision: "deny" },
    { subjectRef, contextKind: "public", contextRef: "org:public", decision: "deny" }
  ] as const;
}

function baselineEffectiveDecisionRecords(subjectRef: string) {
  return [
    { subjectRef, contextKind: "organization", contextRef: "legacy-org:1", resourceRef: "organization-one", capabilityRef: "read", decision: "allow" },
    { subjectRef, contextKind: "platform-global", contextRef: "org:platform-global", resourceRef: "organization-one", capabilityRef: "read", decision: "deny" },
    { subjectRef, contextKind: "public", contextRef: "org:public", resourceRef: "organization-one", capabilityRef: "read", decision: "deny" }
  ] as const;
}

function decisionUniverse(
  keys: readonly (readonly string[])[],
  dimensions: Readonly<Record<string, readonly string[]>>
) {
  const canonicalKeys = [...new Set(keys.map((key) => JSON.stringify(key)))].sort();
  return {
    keyCount: canonicalKeys.length,
    keysHash: createOrganizationReconciliationEvidenceHash(EVIDENCE_NONCE, canonicalKeys),
    derivationContract: ORGANIZATION_RECONCILIATION_DECISION_DERIVATION_CONTRACT,
    derivationBuildRevision: COLLECTOR_BUILD_REVISION,
    dimensions: Object.fromEntries(Object.entries(dimensions).map(([name, values]) => {
      const canonicalValues = [...new Set(values)].sort();
      return [name, {
        count: canonicalValues.length,
        hash: createOrganizationReconciliationEvidenceHash(EVIDENCE_NONCE, canonicalValues)
      }];
    }))
  } as const;
}

function expectNoRawEvidence(report: unknown): void {
  const serialized = JSON.stringify(report);
  for (const rawValue of [
    "test-university",
    "legacy-org:1",
    "Private title",
    "identity-org-one",
    "legacy-user:581",
    "private-role-alpha",
    "plugin:campus",
    "binding-one",
    "campus-one",
    "organization-one",
    "legacy-source-v1",
    "identity-source-v1"
  ]) {
    expect(serialized).not.toContain(rawValue);
  }
}
