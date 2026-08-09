import { createHash } from "node:crypto";
import {
  createOrganizationReconciliationCompositeManifestSha256,
  createOrganizationReconciliationOperationEvidenceSha256,
  ORGANIZATION_RECONCILIATION_COMPOSITE_CONSISTENCY_MODEL,
  ORGANIZATION_RECONCILIATION_COMPOSITE_MANIFEST_CONTRACT,
  ORGANIZATION_RECONCILIATION_OPERATION_EVIDENCE_CONTRACT,
  ORGANIZATION_RECONCILIATION_PAGINATION_MODE,
  ORGANIZATION_RECONCILIATION_SNAPSHOT_MODE,
  type OrganizationReconciliationCompositeManifestUnsigned
} from "../../src/iam-organization-reconciliation-component-manifest.js";
import type {
  OrganizationReconciliationInput,
  ReconciliationPair
} from "../../src/iam-organization-reconciliation-validator.js";
import { createOrganizationReconciliationComponentDatasetInventory } from
  "../../src/iam-organization-reconciliation-dataset-inventory.js";
import {
  createOrganizationReconciliationContentSnapshotId,
  createOrganizationReconciliationContentSourceVersion
} from "../../src/iam-organization-reconciliation-dataset-inventory.js";

const SCHEMA_SHA256 = "d".repeat(64);
const CATALOG_SHA256 = "e".repeat(64);

/**
 * Builds the exact coordinator-owned manifest shape around a test evidence
 * body. Production code must obtain this manifest from the coordinator.
 */
export function attachTestOrganizationReconciliationComponentManifest(
  candidate: OrganizationReconciliationInput
): OrganizationReconciliationInput {
  const { componentManifest: _existingManifest, ...evidenceBody } = candidate;
  const envelope = evidenceBody.collectionEnvelope;
  if (!envelope) return evidenceBody;

  const buildSha256 = createHash("sha256")
    .update(envelope.collectorBuildRevision, "utf8")
    .digest("hex");
  const legacyRecordCount = sideRecordCount(evidenceBody, "legacy");
  const identityRecordCount = sideRecordCount(evidenceBody, "identity");
  const pluginRecordCount = sideRecordCount(evidenceBody, "legacy", ["pluginBindings", "pluginVisibility"]);
  const legacySourceId = "test-legacy-main";
  const identitySourceId = "test-identity";
  const pluginSourceId = "test-plugin";
  const legacyInventory = testInventory("legacy-main", legacySourceId, "legacy-fixture", legacyRecordCount, 1);
  const identityInventory = testInventory("identity", identitySourceId, "identity-fixture", identityRecordCount, 2);
  const pluginInventory = testInventory("plugin", pluginSourceId, "plugin-fixture", pluginRecordCount, 3);
  const boundEnvelope = {
    ...envelope,
    legacy: {
      ...envelope.legacy,
      sourceVersion: createOrganizationReconciliationContentSourceVersion(legacySourceId, legacyInventory),
      snapshotId: createOrganizationReconciliationContentSnapshotId(legacySourceId, legacyInventory)
    },
    identity: {
      ...envelope.identity,
      sourceVersion: createOrganizationReconciliationContentSourceVersion(identitySourceId, identityInventory),
      snapshotId: createOrganizationReconciliationContentSnapshotId(identitySourceId, identityInventory)
    }
  };
  const boundEvidenceBody = bindSurfaceMetadata(evidenceBody, envelope, boundEnvelope);
  const unsigned = {
    contract: ORGANIZATION_RECONCILIATION_COMPOSITE_MANIFEST_CONTRACT,
    consistencyModel: ORGANIZATION_RECONCILIATION_COMPOSITE_CONSISTENCY_MODEL,
    crossDatabaseAtomic: false,
    windowStartedAt: envelope.windowStartedAt,
    windowEndedAt: envelope.windowEndedAt,
    maxWindowMilliseconds: Math.max(
      1,
      Date.parse(envelope.windowEndedAt) - Date.parse(envelope.windowStartedAt)
    ),
    evidenceContract: ORGANIZATION_RECONCILIATION_OPERATION_EVIDENCE_CONTRACT,
    evidenceSha256: createOrganizationReconciliationOperationEvidenceSha256(boundEvidenceBody),
    components: [
      {
        componentId: "legacy-main",
        sourceId: legacySourceId,
        sourceVersion: boundEnvelope.legacy.sourceVersion,
        snapshotId: boundEnvelope.legacy.snapshotId,
        recordCount: legacyRecordCount,
        subjectUniverseScope: "complete",
        subjectUniverse: {
          count: envelope.legacy.subjectUniverse.subjectCount,
          sha256: envelope.legacy.subjectUniverse.subjectsHash
        },
        snapshotMode: ORGANIZATION_RECONCILIATION_SNAPSHOT_MODE,
        paginationMode: ORGANIZATION_RECONCILIATION_PAGINATION_MODE,
        schemaSha256: SCHEMA_SHA256,
        catalogSha256: CATALOG_SHA256,
        buildSha256,
        datasetInventory: legacyInventory,
        openedAt: envelope.windowStartedAt,
        closedAt: envelope.windowEndedAt
      },
      {
        componentId: "identity",
        sourceId: identitySourceId,
        sourceVersion: boundEnvelope.identity.sourceVersion,
        snapshotId: boundEnvelope.identity.snapshotId,
        recordCount: identityRecordCount,
        subjectUniverseScope: "complete",
        subjectUniverse: {
          count: envelope.identity.subjectUniverse.subjectCount,
          sha256: envelope.identity.subjectUniverse.subjectsHash
        },
        snapshotMode: ORGANIZATION_RECONCILIATION_SNAPSHOT_MODE,
        paginationMode: ORGANIZATION_RECONCILIATION_PAGINATION_MODE,
        schemaSha256: SCHEMA_SHA256,
        catalogSha256: CATALOG_SHA256,
        buildSha256,
        datasetInventory: identityInventory,
        openedAt: envelope.windowStartedAt,
        closedAt: envelope.windowEndedAt
      },
      {
        componentId: "plugin",
        sourceId: pluginSourceId,
        sourceVersion: createOrganizationReconciliationContentSourceVersion(pluginSourceId, pluginInventory),
        snapshotId: createOrganizationReconciliationContentSnapshotId(pluginSourceId, pluginInventory),
        recordCount: pluginRecordCount,
        subjectUniverseScope: "not-applicable",
        subjectUniverse: { count: 0, sha256: "" },
        snapshotMode: ORGANIZATION_RECONCILIATION_SNAPSHOT_MODE,
        paginationMode: ORGANIZATION_RECONCILIATION_PAGINATION_MODE,
        schemaSha256: SCHEMA_SHA256,
        catalogSha256: CATALOG_SHA256,
        buildSha256,
        datasetInventory: pluginInventory,
        openedAt: envelope.windowStartedAt,
        closedAt: envelope.windowEndedAt
      }
    ]
  } as const satisfies OrganizationReconciliationCompositeManifestUnsigned;

  return {
    ...boundEvidenceBody,
    componentManifest: {
      ...unsigned,
      manifestSha256: createOrganizationReconciliationCompositeManifestSha256(unsigned)
    }
  };
}

function bindSurfaceMetadata(
  evidenceBody: Omit<OrganizationReconciliationInput, "componentManifest">,
  originalEnvelope: NonNullable<OrganizationReconciliationInput["collectionEnvelope"]>,
  boundEnvelope: NonNullable<OrganizationReconciliationInput["collectionEnvelope"]>
): Omit<OrganizationReconciliationInput, "componentManifest"> {
  const output = { ...evidenceBody, collectionEnvelope: boundEnvelope } as Record<string, unknown>;
  for (const key of [
    "organizationDirectory", "organizationMappings", "memberships", "organizationScopedRoles",
    "pluginBindings", "pluginVisibility", "campusContexts", "effectiveDecisions"
  ] as const) {
    const pair = evidenceBody[key];
    if (!pair) continue;
    output[key] = {
      ...(pair.legacy ? { legacy: {
        ...pair.legacy,
        ...((pair.legacy.sourceVersion === originalEnvelope.legacy.sourceVersion ||
          pair.legacy.sourceVersion === "legacy-source-v1") ? {
          sourceVersion: boundEnvelope.legacy.sourceVersion
        } : {}),
        ...((pair.legacy.collection?.snapshotId === originalEnvelope.legacy.snapshotId ||
          pair.legacy.collection?.snapshotId === "legacy-snapshot-v1") ? { collection: {
          ...pair.legacy.collection,
          snapshotId: boundEnvelope.legacy.snapshotId
        } } : {})
      } } : {}),
      ...(pair.identity ? { identity: {
        ...pair.identity,
        ...((pair.identity.sourceVersion === originalEnvelope.identity.sourceVersion ||
          pair.identity.sourceVersion === "identity-source-v1") ? {
          sourceVersion: boundEnvelope.identity.sourceVersion
        } : {}),
        ...((pair.identity.collection?.snapshotId === originalEnvelope.identity.snapshotId ||
          pair.identity.collection?.snapshotId === "identity-snapshot-v1") ? { collection: {
          ...pair.identity.collection,
          snapshotId: boundEnvelope.identity.snapshotId
        } } : {})
      } } : {})
    };
  }
  return output as Omit<OrganizationReconciliationInput, "componentManifest">;
}

function testInventory(
  componentId: "legacy-main" | "identity" | "plugin",
  sourceId: string,
  datasetId: string,
  recordCount: number,
  keyByte: number
) {
  return createOrganizationReconciliationComponentDatasetInventory({
    componentId,
    sourceId,
    catalogSha256: CATALOG_SHA256,
    datasets: [{
      datasetId,
      pages: [{
      requestCursor: null,
      nextCursor: null,
      recordOffset: 0,
      records: Array.from({ length: recordCount }, (_, index) => ({ index }))
      }]
    }],
    commitmentKey: Buffer.alloc(32, keyByte)
  });
}

function sideRecordCount(
  input: Omit<OrganizationReconciliationInput, "componentManifest">,
  side: "legacy" | "identity",
  selectedKeys?: readonly (keyof Omit<OrganizationReconciliationInput, "componentManifest">)[]
): number {
  const keys = selectedKeys ?? [
    "organizationDirectory",
    "organizationMappings",
    "memberships",
    "organizationScopedRoles",
    "pluginBindings",
    "pluginVisibility",
    "campusContexts",
    "effectiveDecisions"
  ];
  return keys.reduce((count, key) => {
    const pair = input[key] as ReconciliationPair<unknown> | undefined;
    return count + (pair?.[side]?.records.length ?? 0);
  }, 0);
}
