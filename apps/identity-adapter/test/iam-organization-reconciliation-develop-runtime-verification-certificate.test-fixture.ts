import { createHash, generateKeyPairSync } from "node:crypto";
import {
  createOrganizationReconciliationCompositeManifestForEvidence,
  createOrganizationReconciliationCompositeManifestSha256,
  createOrganizationReconciliationOperationEvidenceSha256,
  ORGANIZATION_RECONCILIATION_COMPOSITE_CONSISTENCY_MODEL,
  ORGANIZATION_RECONCILIATION_COMPOSITE_MANIFEST_CONTRACT,
  ORGANIZATION_RECONCILIATION_OPERATION_EVIDENCE_CONTRACT,
  ORGANIZATION_RECONCILIATION_PAGINATION_MODE,
  ORGANIZATION_RECONCILIATION_SNAPSHOT_MODE,
  type OrganizationReconciliationCompositeManifestUnsigned
} from "../src/iam-organization-reconciliation-component-manifest.js";
import {
  createOrganizationReconciliationComponentDatasetInventory,
  createOrganizationReconciliationContentSnapshotId,
  createOrganizationReconciliationContentSourceVersion
} from "../src/iam-organization-reconciliation-dataset-inventory.js";
import {
  createOrganizationReconciliationDevelopDeploymentEvidenceSha256
} from "../src/iam-organization-reconciliation-develop-deployment-evidence.js";
import {
  ORGANIZATION_RECONCILIATION_DEVELOP_FULL_RANGE_CONTRACT
} from "../src/iam-organization-reconciliation-develop-full-range.js";
import {
  ORGANIZATION_RECONCILIATION_DEVELOP_OPERATION_EVIDENCE_BLOCKERS,
  ORGANIZATION_RECONCILIATION_DEVELOP_OPERATION_EVIDENCE_CONTRACT
} from "../src/iam-organization-reconciliation-develop-operation-evidence.js";
import {
  ORGANIZATION_RECONCILIATION_DEVELOP_PHYSICAL_CATALOG,
  ORGANIZATION_RECONCILIATION_DEVELOP_PHYSICAL_CATALOG_SHA256,
  ORGANIZATION_RECONCILIATION_DEVELOP_PHYSICAL_PROBE_CONTRACT
} from "../src/iam-organization-reconciliation-develop-physical-probe.js";
import {
  ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG,
  ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG_SHA256
} from "../src/iam-organization-reconciliation-develop-source-catalog.js";
import {
  createOrganizationReconciliationDevelopPhysicalProbeFileSha256,
  type CreateOrganizationReconciliationDevelopRuntimeCertificateInput
} from "../src/iam-organization-reconciliation-develop-runtime-verification-certificate.js";
import {
  createOrganizationReconciliationProvenanceBindingFromInput,
  createOrganizationReconciliationTrustPolicySha256
} from "../src/iam-organization-reconciliation-provenance.js";
import {
  IDENTITY_ORGANIZATION_SURFACE_PROJECTOR_CONTRACT,
  LEGACY_ORGANIZATION_SURFACE_PROJECTOR_CONTRACT,
  ORGANIZATION_SURFACE_PROJECTION_BINDING_CONTRACT
} from "../src/iam-organization-reconciliation-projector-contract.js";
import {
  createOrganizationReconciliationCollectedSnapshot,
  createOrganizationReconciliationEvidenceHash,
  ORGANIZATION_RECONCILIATION_COLLECTOR_CONTRACT,
  ORGANIZATION_RECONCILIATION_COLLECTOR_CONTRACT_HASH,
  ORGANIZATION_RECONCILIATION_DECISION_DERIVATION_CONTRACT,
  validateOrganizationReconciliation,
  type OrganizationReconciliationInput
} from "../src/iam-organization-reconciliation-validator.js";
import {
  createOrganizationReconciliationAttestationBundleForTest,
  createOrganizationReconciliationPolicyForTest,
  createOrganizationReconciliationTrustedProfileForTest,
  TEST_COLLECTOR_BUILD_REVISION
} from "./iam-organization-reconciliation-provenance.test-fixture.js";
import {
  createOrganizationReconciliationDevelopDeploymentEvidenceForTest
} from "./iam-organization-reconciliation-develop-deployment-evidence.test-fixture.js";

const EVIDENCE_NONCE = "b2".repeat(32);
const SEMANTIC_REGISTRY_SHA256 = "6".repeat(64);
const PRIVATE_VALUES = Object.freeze([
  "private-org-name",
  "private-org-title",
  "private-identity-org",
  "legacy-user:581",
  "private-role",
  "plugin:private",
  "private-binding",
  "legacy-org:1",
  "private-resource",
  "private-capability",
  "private-source-host"
]);
const CONTEXTS = Object.freeze([
  ["organization", "legacy-org:1"],
  ["platform-global", "org:platform-global"],
  ["public", "org:public"]
] as const);
const CONTEXT_DIMENSIONS = CONTEXTS.map((context) => JSON.stringify(context));
const SUBJECT_UNIVERSE_HASH = createOrganizationReconciliationEvidenceHash(
  EVIDENCE_NONCE,
  ["legacy-user:581"]
);

export interface OrganizationReconciliationDevelopRuntimeCertificateTestFixture {
  readonly input: CreateOrganizationReconciliationDevelopRuntimeCertificateInput;
  readonly privateValues: readonly string[];
}

export function createOrganizationReconciliationDevelopRuntimeCertificateTestFixture():
OrganizationReconciliationDevelopRuntimeCertificateTestFixture {
  const reconciliationInput = alignedTwentyOneDatasetInput();
  const keys = [generateKeyPairSync("ed25519")];
  const basePolicy = createOrganizationReconciliationPolicyForTest(keys.map(({ publicKey }, index) => ({
    collectorId: `private-collector-${index + 1}`,
    nodeId: `private-node-${index + 1}`,
    keyId: `private-key-${index + 1}`,
    publicKey
  })));
  const trustPolicy = { ...basePolicy, environment: "xrteeth-develop" };
  const physicalProbe = successfulPhysicalProbe();
  const physicalProbeBytes = Buffer.from(`${JSON.stringify(physicalProbe)}\n`, "utf8");
  const baseDeployment = createOrganizationReconciliationDevelopDeploymentEvidenceForTest(
    trustPolicy.requiredCollectors
  );
  const deploymentEvidence = {
    ...baseDeployment,
    observedAt: "2026-08-09T00:00:00.000Z",
    physicalProbeSha256:
      createOrganizationReconciliationDevelopPhysicalProbeFileSha256(physicalProbeBytes)
  };
  const deploymentSha256 =
    createOrganizationReconciliationDevelopDeploymentEvidenceSha256(deploymentEvidence);
  const binding = createOrganizationReconciliationProvenanceBindingFromInput(
    reconciliationInput,
    deploymentSha256
  );
  const attestationBundle = createOrganizationReconciliationAttestationBundleForTest(
    binding,
    trustPolicy,
    keys.map(({ privateKey }, index) => ({
      keyId: `private-key-${index + 1}`,
      privateKey
    }))
  );
  const trustedProfile = createOrganizationReconciliationTrustedProfileForTest(trustPolicy);
  const verificationReport = validateOrganizationReconciliation(reconciliationInput, {
    trustedProvenance: {
      trustedProfile,
      trustPolicy,
      attestationBundle,
      expectedDeploymentEvidenceSha256: deploymentSha256,
      now: new Date("2026-08-09T00:07:00.000Z")
    }
  });
  if (verificationReport.coverage.length !== 8 ||
    verificationReport.coverageBlockers.length !== 1 ||
    verificationReport.coverageBlockers[0]?.code !== "real-source-adapters-not-ready" ||
    !verificationReport.provenanceVerification.verified) {
    throw new Error("runtime certificate test fixture did not produce one valid signed replay");
  }
  const componentManifest = reconciliationInput.componentManifest!;
  const { componentManifest: _componentManifest, ...evidence } = reconciliationInput;
  const lineageManifest = lineageManifestFromInput(reconciliationInput);
  const rawArtifact = {
    contract: ORGANIZATION_RECONCILIATION_DEVELOP_FULL_RANGE_CONTRACT,
    environment: "xrteeth-develop",
    nodeId: "xrteeth",
    mode: "read-only",
    scope: "full-range",
    buildRevision: TEST_COLLECTOR_BUILD_REVISION,
    deploymentEvidenceSha256: deploymentSha256,
    releaseImageDigest: deploymentEvidence.releaseImageDigest,
    startedAt: "2026-08-09T00:00:30.000Z",
    completedAt: "2026-08-09T00:07:00.000Z",
    sourceCatalogSha256: ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG_SHA256,
    semanticRegistrySha256: SEMANTIC_REGISTRY_SHA256,
    datasetCount: 21,
    verifiedSurfaceCount: 8,
    dryRun: true,
    writeSideEffects: "none",
    productionWritePerformed: false,
    tmrppUntouched: true,
    physicalIndependenceVerified: false,
    productionReady: false,
    productionPromotionAllowed: false,
    sourcePreflight: {
      passed: true,
      privateDatabaseIdentity: "private-source-host"
    },
    transactionFactoryProvenance: {
      contract: "iam-organization-reconciliation-transaction-dataset-lineage-factory-provenance/v1",
      trust: "factory-origin-only",
      privateSourceIdentity: "private-source-host"
    },
    lineageRun: {
      contract: "iam-organization-reconciliation-snapshot-dataset-lineage/v1",
      catalogTrust: "caller-structured-untrusted",
      crossDatabaseAtomic: false,
      readiness: { ready: false, blockers: ["not-production"] },
      artifacts: [{ records: [{ name: "private-org-name", subject: "legacy-user:581" }] }],
      coordinatorManifest: lineageManifest
    },
    legacyProjection: rawProjection(reconciliationInput, "legacy"),
    identityProjection: rawProjection(reconciliationInput, "identity"),
    operationEvidence: {
      contract: ORGANIZATION_RECONCILIATION_DEVELOP_OPERATION_EVIDENCE_CONTRACT,
      implemented: true,
      ready: false,
      outcome: "blocked",
      semanticRegistrySha256: SEMANTIC_REGISTRY_SHA256,
      lineageManifestSha256: lineageManifest.manifestSha256,
      projectionBinding: reconciliationInput.projectionBinding,
      verifiedSurfaceCount: 8,
      observableDecisionCartesianCoverage: true,
      evidence,
      componentManifest,
      blockers: ORGANIZATION_RECONCILIATION_DEVELOP_OPERATION_EVIDENCE_BLOCKERS
    },
    reconciliationInput,
    externalProvenanceVerified: true,
    verifiedAttestationCount: 1,
    trustPolicySha256: createOrganizationReconciliationTrustPolicySha256(trustPolicy),
    attestationBundle,
    verificationReport
  };
  return Object.freeze({
    input: Object.freeze({
      rawArtifactBytes: Buffer.from(`${JSON.stringify(rawArtifact)}\n`, "utf8"),
      deploymentEvidenceBytes: Buffer.from(`${JSON.stringify(deploymentEvidence)}\n`, "utf8"),
      physicalProbeBytes,
      trustPolicyBytes: Buffer.from(`${JSON.stringify(trustPolicy)}\n`, "utf8"),
      trustedProfile,
      now: new Date("2026-08-09T00:07:00.000Z")
    }),
    privateValues: PRIVATE_VALUES
  });
}

function alignedTwentyOneDatasetInput(): OrganizationReconciliationInput {
  const records = alignedRecords();
  const componentRecordCounts = {
    "legacy-main": totalSurfaceRecords(records, "legacy"),
    identity: totalSurfaceRecords(records, "identity"),
    plugin: records.pluginBindings.legacy.length + records.pluginVisibility.legacy.length
  } as const;
  const inventories = Object.fromEntries(
    ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG.components.map((component, componentIndex) => {
      const sourceId = `private-${component.componentId}-source`;
      const total = componentRecordCounts[component.componentId];
      return [component.componentId, createOrganizationReconciliationComponentDatasetInventory({
        componentId: component.componentId,
        sourceId,
        catalogSha256: component.declaredCatalogSha256,
        datasets: component.datasetCatalog.datasets.map((dataset, index) => ({
          datasetId: dataset.datasetId,
          pages: [{
            requestCursor: null,
            nextCursor: null,
            recordOffset: 0,
            records: Array.from({ length: index === 0 ? total : 0 }, (_, recordIndex) => ({ recordIndex }))
          }]
        })),
        commitmentKey: Buffer.alloc(32, componentIndex + 1)
      })];
    })
  ) as Record<"legacy-main" | "identity" | "plugin", ReturnType<
    typeof createOrganizationReconciliationComponentDatasetInventory
  >>;
  const source = (componentId: "legacy-main" | "identity" | "plugin") => {
    const sourceId = `private-${componentId}-source`;
    const inventory = inventories[componentId];
    return {
      sourceId,
      sourceVersion: createOrganizationReconciliationContentSourceVersion(sourceId, inventory),
      snapshotId: createOrganizationReconciliationContentSnapshotId(sourceId, inventory),
      inventory
    };
  };
  const legacy = source("legacy-main");
  const identity = source("identity");
  const plugin = source("plugin");
  const envelope = collectionEnvelope(legacy, identity);
  const evidenceWithoutProjection = surfaceEvidence(records, envelope);
  const lineageUnsigned = {
    contract: ORGANIZATION_RECONCILIATION_COMPOSITE_MANIFEST_CONTRACT,
    consistencyModel: ORGANIZATION_RECONCILIATION_COMPOSITE_CONSISTENCY_MODEL,
    crossDatabaseAtomic: false,
    windowStartedAt: envelope.windowStartedAt,
    windowEndedAt: envelope.windowEndedAt,
    maxWindowMilliseconds: 240_000,
    evidenceContract: ORGANIZATION_RECONCILIATION_OPERATION_EVIDENCE_CONTRACT,
    evidenceSha256: createOrganizationReconciliationOperationEvidenceSha256({
      contract: "iam-organization-reconciliation-test-lineage-root/v1"
    }),
    components: [
      componentManifest("legacy-main", legacy, componentRecordCounts["legacy-main"], true),
      componentManifest("identity", identity, componentRecordCounts.identity, true),
      componentManifest("plugin", plugin, componentRecordCounts.plugin, false)
    ]
  } as const satisfies OrganizationReconciliationCompositeManifestUnsigned;
  const lineageManifest = {
    ...lineageUnsigned,
    manifestSha256: createOrganizationReconciliationCompositeManifestSha256(lineageUnsigned)
  };
  const projectionBinding = {
    contract: ORGANIZATION_SURFACE_PROJECTION_BINDING_CONTRACT,
    semanticRegistrySha256: SEMANTIC_REGISTRY_SHA256,
    lineageManifestSha256: lineageManifest.manifestSha256,
    legacy: {
      projectorContract: LEGACY_ORGANIZATION_SURFACE_PROJECTOR_CONTRACT,
      evaluatorId: "test/runtime-certificate/legacy",
      evaluatorBuildSha256: "7".repeat(64),
      primarySource: { sourceVersion: legacy.sourceVersion, snapshotId: legacy.snapshotId }
    },
    identity: {
      projectorContract: IDENTITY_ORGANIZATION_SURFACE_PROJECTOR_CONTRACT,
      evaluatorId: "test/runtime-certificate/identity",
      evaluatorBuildSha256: "8".repeat(64),
      primarySource: { sourceVersion: identity.sourceVersion, snapshotId: identity.snapshotId }
    },
    pluginSource: { sourceVersion: plugin.sourceVersion, snapshotId: plugin.snapshotId }
  };
  const evidence = { projectionBinding, ...evidenceWithoutProjection };
  return {
    ...evidence,
    componentManifest: createOrganizationReconciliationCompositeManifestForEvidence(
      lineageManifest,
      evidence
    )
  };
}

function rawProjection(input: OrganizationReconciliationInput, side: "legacy" | "identity") {
  const binding = input.projectionBinding!;
  const metadata = binding[side];
  const surfaces = Object.fromEntries([
    "organizationDirectory", "organizationMappings", "memberships", "organizationScopedRoles",
    "pluginBindings", "pluginVisibility", "campusContexts", "effectiveDecisions"
  ].map((name) => [
    name,
    (input[name as keyof OrganizationReconciliationInput] as Record<
      "legacy" | "identity",
      { readonly records: readonly unknown[] }
    >)[side].records
  ]));
  return {
    side,
    contract: metadata.projectorContract,
    evaluatorId: metadata.evaluatorId,
    evaluatorBuildSha256: metadata.evaluatorBuildSha256,
    semanticRegistrySha256: binding.semanticRegistrySha256,
    surfaces
  };
}

function alignedRecords() {
  const campus = CONTEXTS.map(([contextKind, contextRef], index) => ({
    subjectRef: "legacy-user:581",
    contextKind,
    contextRef,
    decision: index === 0 ? "allow" as const : "deny" as const
  }));
  const effective = CONTEXTS.map(([contextKind, contextRef], index) => ({
    subjectRef: "legacy-user:581",
    contextKind,
    contextRef,
    resourceRef: "private-resource",
    capabilityRef: "private-capability",
    decision: index === 0 ? "allow" as const : "deny" as const
  }));
  const same = <T>(value: readonly T[]) => ({ legacy: value, identity: structuredClone(value) });
  return {
    organizationDirectory: same([{
      legacyOrganizationId: 1, name: "private-org-name", title: "private-org-title", active: true
    }]),
    organizationMappings: same([{
      legacyOrganizationId: 1, identityOrganizationId: "private-identity-org", active: true
    }]),
    memberships: same([{
      subjectRef: "legacy-user:581", legacyOrganizationId: 1, active: true
    }]),
    organizationScopedRoles: same([{
      subjectRef: "legacy-user:581", legacyOrganizationId: 1, roleRef: "private-role", active: true
    }]),
    pluginBindings: same([{
      pluginRef: "plugin:private", bindingRef: "private-binding", organizationRef: "legacy-org:1", active: true
    }]),
    pluginVisibility: same([{
      subjectRef: "legacy-user:581", pluginRef: "plugin:private", organizationRef: "legacy-org:1",
      decision: "allow" as const
    }]),
    campusContexts: same(campus),
    effectiveDecisions: same(effective)
  };
}

function collectionEnvelope(
  legacy: Readonly<{ sourceVersion: string; snapshotId: string }>,
  identity: Readonly<{ sourceVersion: string; snapshotId: string }>
) {
  const decisionUniverses = {
    pluginVisibility: decisionUniverse(
      [["legacy-user:581", "plugin:private", "legacy-org:1"]],
      { subjects: ["legacy-user:581"], plugins: ["plugin:private"], organizations: ["legacy-org:1"] }
    ),
    campusContexts: decisionUniverse(
      CONTEXTS.map(([kind, ref]) => ["legacy-user:581", kind, ref]),
      { subjects: ["legacy-user:581"], contexts: CONTEXT_DIMENSIONS }
    ),
    effectiveDecisions: decisionUniverse(
      CONTEXTS.map(([kind, ref]) => [
        "legacy-user:581", kind, ref, "private-resource", "private-capability"
      ]),
      {
        subjects: ["legacy-user:581"], contexts: CONTEXT_DIMENSIONS,
        resources: ["private-resource"], capabilities: ["private-capability"],
        rulePairs: [JSON.stringify(["private-resource", "private-capability"])]
      }
    )
  };
  return {
    collectorContract: ORGANIZATION_RECONCILIATION_COLLECTOR_CONTRACT,
    collectorContractHash: ORGANIZATION_RECONCILIATION_COLLECTOR_CONTRACT_HASH,
    collectorBuildRevision: TEST_COLLECTOR_BUILD_REVISION,
    evidenceNonce: EVIDENCE_NONCE,
    logicalSnapshotId: "private-logical-snapshot",
    windowId: "private-window",
    windowStartedAt: "2026-08-09T00:01:00.000Z",
    windowEndedAt: "2026-08-09T00:05:00.000Z",
    legacy: {
      sourceVersion: legacy.sourceVersion,
      snapshotId: legacy.snapshotId,
      subjectUniverse: { subjectCount: 1, subjectsHash: SUBJECT_UNIVERSE_HASH },
      decisionUniverses
    },
    identity: {
      sourceVersion: identity.sourceVersion,
      snapshotId: identity.snapshotId,
      subjectUniverse: { subjectCount: 1, subjectsHash: SUBJECT_UNIVERSE_HASH },
      decisionUniverses
    }
  };
}

function surfaceEvidence(
  records: ReturnType<typeof alignedRecords>,
  envelope: ReturnType<typeof collectionEnvelope>
): Omit<OrganizationReconciliationInput, "componentManifest" | "projectionBinding"> {
  const output: Record<string, unknown> = { collectionEnvelope: envelope };
  for (const [name, pair] of Object.entries(records)) {
    output[name] = {
      legacy: createOrganizationReconciliationCollectedSnapshot<unknown>(
        EVIDENCE_NONCE,
        envelope.legacy.sourceVersion,
        envelope.legacy.snapshotId,
        [{ requestCursor: null, nextCursor: null, records: pair.legacy as readonly unknown[] }]
      ),
      identity: createOrganizationReconciliationCollectedSnapshot<unknown>(
        EVIDENCE_NONCE,
        envelope.identity.sourceVersion,
        envelope.identity.snapshotId,
        [{ requestCursor: null, nextCursor: null, records: pair.identity as readonly unknown[] }]
      )
    };
  }
  return output as Omit<OrganizationReconciliationInput, "componentManifest" | "projectionBinding">;
}

function componentManifest(
  componentId: "legacy-main" | "identity" | "plugin",
  source: Readonly<{
    sourceId: string;
    sourceVersion: string;
    snapshotId: string;
    inventory: ReturnType<typeof createOrganizationReconciliationComponentDatasetInventory>;
  }>,
  recordCount: number,
  hasSubjectUniverse: boolean
) {
  const catalog = ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG.components.find(
    (component) => component.componentId === componentId
  )!;
  return {
    componentId,
    sourceId: source.sourceId,
    sourceVersion: source.sourceVersion,
    snapshotId: source.snapshotId,
    recordCount,
    subjectUniverseScope: hasSubjectUniverse ? "complete" as const : "not-applicable" as const,
    subjectUniverse: hasSubjectUniverse
      ? { count: 1, sha256: SUBJECT_UNIVERSE_HASH }
      : { count: 0, sha256: "" },
    snapshotMode: ORGANIZATION_RECONCILIATION_SNAPSHOT_MODE,
    paginationMode: ORGANIZATION_RECONCILIATION_PAGINATION_MODE,
    schemaSha256: "d".repeat(64),
    catalogSha256: catalog.declaredCatalogSha256,
    buildSha256: createHash("sha256").update(TEST_COLLECTOR_BUILD_REVISION, "utf8").digest("hex"),
    datasetInventory: source.inventory,
    openedAt: "2026-08-09T00:01:00.000Z",
    closedAt: "2026-08-09T00:05:00.000Z"
  };
}

function lineageManifestFromInput(input: OrganizationReconciliationInput) {
  const operation = input.componentManifest!;
  const unsigned = {
    contract: ORGANIZATION_RECONCILIATION_COMPOSITE_MANIFEST_CONTRACT,
    consistencyModel: operation.consistencyModel,
    crossDatabaseAtomic: false,
    windowStartedAt: operation.windowStartedAt,
    windowEndedAt: operation.windowEndedAt,
    maxWindowMilliseconds: operation.maxWindowMilliseconds,
    evidenceContract: operation.evidenceContract,
    evidenceSha256: createOrganizationReconciliationOperationEvidenceSha256({
      contract: "iam-organization-reconciliation-test-lineage-root/v1"
    }),
    components: operation.components
  } as const satisfies OrganizationReconciliationCompositeManifestUnsigned;
  const manifest = {
    ...unsigned,
    manifestSha256: createOrganizationReconciliationCompositeManifestSha256(unsigned)
  };
  if (manifest.manifestSha256 !== operation.parentLineageManifestSha256) {
    throw new Error("test fixture parent lineage mismatch");
  }
  return manifest;
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
    derivationBuildRevision: TEST_COLLECTOR_BUILD_REVISION,
    dimensions: Object.fromEntries(Object.entries(dimensions).map(([name, values]) => {
      const canonicalValues = [...new Set(values)].sort();
      return [name, {
        count: canonicalValues.length,
        hash: createOrganizationReconciliationEvidenceHash(EVIDENCE_NONCE, canonicalValues)
      }];
    }))
  };
}

function totalSurfaceRecords(records: ReturnType<typeof alignedRecords>, side: "legacy" | "identity"): number {
  return Object.values(records).reduce((sum, pair) => sum + pair[side].length, 0);
}

function successfulPhysicalProbe() {
  const digest = (character: string) => character.repeat(64);
  return {
    contract: ORGANIZATION_RECONCILIATION_DEVELOP_PHYSICAL_PROBE_CONTRACT,
    environment: "xrteeth-develop",
    mode: "read-only",
    assuranceScope: "compiled-21-dataset-physical-metadata-and-deterministic-cursor-keys-only",
    optimizerOrderPerformanceClaimed: false,
    currentTransactionVariableIntrospectionClaimed: false,
    sourceCatalogSha256: ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG_SHA256,
    statementCatalogSha256: ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG.statementCatalogSha256,
    physicalCatalogSha256: ORGANIZATION_RECONCILIATION_DEVELOP_PHYSICAL_CATALOG_SHA256,
    buildRevisionSha256: createHash("sha256")
      .update("iam-organization-reconciliation:xrteeth-develop:build-revision/v1\u001f", "utf8")
      .update(JSON.stringify(TEST_COLLECTOR_BUILD_REVISION), "utf8")
      .digest("hex"),
    componentCount: 3,
    datasetCount: 21,
    physicalTableCount: 19,
    derivedDatasetCount: 1,
    completedProbePassCount: 6,
    components: ORGANIZATION_RECONCILIATION_DEVELOP_PHYSICAL_CATALOG.components.map(
      (component, index) => {
        const requiredColumnCount = Object.values(component.tables)
          .reduce((sum, table) => sum + table.columns.length, 0);
        const requiredKeyCount = Object.values(component.datasets)
          .reduce((sum, dataset) => sum + dataset.deterministicUniqueKeys.length, 0);
        return {
          componentId: component.componentId,
          datasetCount: Object.keys(component.datasets).length,
          physicalTableCount: Object.keys(component.tables).length,
          requiredColumnCount,
          requiredDeterministicUniqueKeyCount: requiredKeyCount,
          completedProbePassCount: 2,
          databaseBindingPassed: true,
          grantPassed: true,
          snapshotProtocolPassed: true,
          tableShapePassed: true,
          columnShapePassed: true,
          deterministicUniqueKeysPassed: true,
          collationPassed: true,
          binaryOrderWitnessPassed: true,
          aBAligned: true,
          sourceIdentitySha256: digest(String(index + 1)),
          grantScopeSha256: digest(String(index + 4)),
          physicalSchemaSha256: digest(String(index + 7)),
          physicalIndexSha256: digest(index === 0 ? "a" : index === 1 ? "b" : "c"),
          snapshotProtocolSha256: digest(index === 0 ? "d" : index === 1 ? "e" : "f"),
          binaryOrderWitnessSha256: digest(index === 0 ? "1" : index === 1 ? "2" : "3"),
          observedTableCount: Object.keys(component.tables).length,
          observedColumnCount: requiredColumnCount,
          observedIndexCount: requiredKeyCount
        };
      }
    ),
    failedIds: [],
    passed: true,
    productionReady: false
  };
}
