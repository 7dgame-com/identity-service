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
    evidenceSha256: createOrganizationReconciliationOperationEvidenceSha256(evidenceBody),
    components: [
      {
        componentId: "legacy-main",
        sourceId: "test-legacy-main",
        sourceVersion: envelope.legacy.sourceVersion,
        snapshotId: envelope.legacy.snapshotId,
        recordCount: sideRecordCount(evidenceBody, "legacy"),
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
        openedAt: envelope.windowStartedAt,
        closedAt: envelope.windowEndedAt
      },
      {
        componentId: "identity",
        sourceId: "test-identity",
        sourceVersion: envelope.identity.sourceVersion,
        snapshotId: envelope.identity.snapshotId,
        recordCount: sideRecordCount(evidenceBody, "identity"),
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
        openedAt: envelope.windowStartedAt,
        closedAt: envelope.windowEndedAt
      },
      {
        componentId: "plugin",
        sourceId: "test-plugin",
        sourceVersion: "test-plugin-source-version",
        snapshotId: "test-plugin-snapshot",
        recordCount: sideRecordCount(evidenceBody, "legacy", ["pluginBindings", "pluginVisibility"]),
        subjectUniverseScope: "not-applicable",
        subjectUniverse: { count: 0, sha256: "" },
        snapshotMode: ORGANIZATION_RECONCILIATION_SNAPSHOT_MODE,
        paginationMode: ORGANIZATION_RECONCILIATION_PAGINATION_MODE,
        schemaSha256: SCHEMA_SHA256,
        catalogSha256: CATALOG_SHA256,
        buildSha256,
        openedAt: envelope.windowStartedAt,
        closedAt: envelope.windowEndedAt
      }
    ]
  } as const satisfies OrganizationReconciliationCompositeManifestUnsigned;

  return {
    ...evidenceBody,
    componentManifest: {
      ...unsigned,
      manifestSha256: createOrganizationReconciliationCompositeManifestSha256(unsigned)
    }
  };
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
