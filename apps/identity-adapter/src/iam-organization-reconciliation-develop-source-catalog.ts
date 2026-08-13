import { createHash } from "node:crypto";
import {
  ORGANIZATION_RECONCILIATION_DATASET_CATALOG_TRUST,
  ORGANIZATION_RECONCILIATION_DATASET_LINEAGE_CONTRACT,
  type OrganizationReconciliationDatasetCatalog
} from "./iam-organization-reconciliation-dataset-lineage.js";
import {
  ORGANIZATION_RECONCILIATION_DEVELOP_IAM_POLICY_CHECKSUM,
  ORGANIZATION_RECONCILIATION_MYSQL_STATEMENT_CATALOG_SHA256
} from "./iam-organization-reconciliation/mysql-repeatable-read-snapshot.js";
import type {
  OrganizationReconciliationMysqlRawComponentId
} from "./iam-organization-reconciliation/mysql-source-adapters/raw-source-snapshots.js";

export const ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG_CONTRACT =
  "iam-organization-reconciliation-xrteeth-develop-source-catalog/v1" as const;
export const ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG_IMPLEMENTED = true as const;
/** Physical fingerprints and the owner semantic registry are not pinned yet. */
export const ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG_READY = false as const;
export const ORGANIZATION_RECONCILIATION_DEVELOP_LEGACY_DATABASE = "bujiaban_development" as const;
export const ORGANIZATION_RECONCILIATION_DEVELOP_IDENTITY_DATABASE = "xrugc_identity_dev" as const;
export const ORGANIZATION_RECONCILIATION_DEVELOP_PLUGIN_DATABASE =
  "bujiaban_development_plugin" as const;

const PAGE_SIZE = 1_000;
const MAX_PAGES_PER_DATASET = 700;
const MAX_RECORDS_PER_DATASET = 700_000;

const DATASET_IDS = Object.freeze({
  "legacy-main": Object.freeze([
    "legacy-membership",
    "legacy-organization-directory",
    "legacy-rbac-assignment",
    "legacy-rbac-edge",
    "legacy-rbac-item",
    "legacy-role-assignment",
    "legacy-subject-universe"
  ]),
  identity: Object.freeze([
    "identity-iam-item-relation",
    "identity-iam-permission",
    "identity-iam-policy-version",
    "identity-iam-role",
    "identity-iam-subject-assignment",
    "identity-iam-subject-assignment-snapshot",
    "identity-membership-candidate",
    "identity-membership-candidate-snapshot",
    "identity-membership-shadow",
    "identity-organization-candidate",
    "identity-organization-id-map",
    "identity-role-shadow",
    "identity-subject-universe"
  ]),
  plugin: Object.freeze(["plugin-registry"])
} satisfies Record<OrganizationReconciliationMysqlRawComponentId, readonly string[]>);

const SOURCE_IDS = Object.freeze({
  "legacy-main": "legacy-main/xrteeth-develop",
  identity: "identity/xrteeth-develop",
  plugin: "plugin-registry/xrteeth-develop"
} satisfies Record<OrganizationReconciliationMysqlRawComponentId, string>);

export interface OrganizationReconciliationDevelopSourceComponentCatalog {
  readonly componentId: OrganizationReconciliationMysqlRawComponentId;
  readonly expectedSourceId: string;
  readonly declaredCatalogSha256: string;
  readonly datasetCatalog: OrganizationReconciliationDatasetCatalog;
  readonly physicalSchemaSha256: null;
  readonly physicalSourceAttestation: "pending-develop-read-only-preflight";
}

export interface OrganizationReconciliationDevelopSourceCatalog {
  readonly contract: typeof ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG_CONTRACT;
  readonly environment: "xrteeth-develop";
  readonly trust: "compiled-source-shape-only";
  readonly implementationReady: true;
  readonly productionReady: false;
  readonly statementCatalogSha256: string;
  readonly iamPolicyChecksum: typeof ORGANIZATION_RECONCILIATION_DEVELOP_IAM_POLICY_CHECKSUM;
  readonly components: readonly OrganizationReconciliationDevelopSourceComponentCatalog[];
  readonly blockers: readonly [
    "develop-physical-schema-fingerprints-not-pinned",
    "develop-read-only-source-preflight-not-recorded",
    "owner-semantic-registry-not-compiled",
    "surface-projectors-not-production-registered",
    "operation-evidence-projector-not-production-registered",
    "external-provenance-trust-profile-not-compiled",
    "runtime-pipeline-not-registered"
  ];
}

function datasetCatalog(
  componentId: OrganizationReconciliationMysqlRawComponentId
): OrganizationReconciliationDatasetCatalog {
  return Object.freeze({
    contract: ORGANIZATION_RECONCILIATION_DATASET_LINEAGE_CONTRACT,
    trust: ORGANIZATION_RECONCILIATION_DATASET_CATALOG_TRUST,
    datasets: Object.freeze(DATASET_IDS[componentId].map((datasetId) => Object.freeze({
      datasetId,
      pageSize: PAGE_SIZE,
      maxPages: MAX_PAGES_PER_DATASET,
      maxRecords: MAX_RECORDS_PER_DATASET
    })))
  });
}

function componentCatalog(
  componentId: OrganizationReconciliationMysqlRawComponentId
): OrganizationReconciliationDevelopSourceComponentCatalog {
  const catalog = datasetCatalog(componentId);
  const declaredCatalogSha256 = createHash("sha256")
    .update("iam-organization-reconciliation:xrteeth-develop-component-catalog:v1\u001f", "utf8")
    .update(JSON.stringify({
      componentId,
      expectedSourceId: SOURCE_IDS[componentId],
      statementCatalogSha256: ORGANIZATION_RECONCILIATION_MYSQL_STATEMENT_CATALOG_SHA256,
      iamPolicyChecksum: ORGANIZATION_RECONCILIATION_DEVELOP_IAM_POLICY_CHECKSUM,
      datasetCatalog: catalog
    }), "utf8")
    .digest("hex");
  return Object.freeze({
    componentId,
    expectedSourceId: SOURCE_IDS[componentId],
    declaredCatalogSha256,
    datasetCatalog: catalog,
    physicalSchemaSha256: null,
    physicalSourceAttestation: "pending-develop-read-only-preflight"
  });
}

export const ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG: OrganizationReconciliationDevelopSourceCatalog =
  Object.freeze({
    contract: ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG_CONTRACT,
    environment: "xrteeth-develop",
    trust: "compiled-source-shape-only",
    implementationReady: ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG_IMPLEMENTED,
    productionReady: ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG_READY,
    statementCatalogSha256: ORGANIZATION_RECONCILIATION_MYSQL_STATEMENT_CATALOG_SHA256,
    iamPolicyChecksum: ORGANIZATION_RECONCILIATION_DEVELOP_IAM_POLICY_CHECKSUM,
    components: Object.freeze([
      componentCatalog("legacy-main"),
      componentCatalog("identity"),
      componentCatalog("plugin")
    ]),
    blockers: Object.freeze([
      "develop-physical-schema-fingerprints-not-pinned",
      "develop-read-only-source-preflight-not-recorded",
      "owner-semantic-registry-not-compiled",
      "surface-projectors-not-production-registered",
      "operation-evidence-projector-not-production-registered",
      "external-provenance-trust-profile-not-compiled",
      "runtime-pipeline-not-registered"
    ] as const)
  });

export const ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG_SHA256 = createHash("sha256")
  .update("iam-organization-reconciliation:xrteeth-develop-source-catalog:v1\u001f", "utf8")
  .update(JSON.stringify(ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG), "utf8")
  .digest("hex");

export function resolveOrganizationReconciliationDevelopSourceComponent(
  componentId: OrganizationReconciliationMysqlRawComponentId
): OrganizationReconciliationDevelopSourceComponentCatalog {
  const component = ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG.components
    .find((candidate) => candidate.componentId === componentId);
  if (component === undefined) throw new Error("The Develop source component is not compiled.");
  return component;
}
