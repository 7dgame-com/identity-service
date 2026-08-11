import { createHash } from "node:crypto";
import {
  ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG,
  ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG_SHA256,
  ORGANIZATION_RECONCILIATION_DEVELOP_IDENTITY_DATABASE,
  ORGANIZATION_RECONCILIATION_DEVELOP_LEGACY_DATABASE,
  ORGANIZATION_RECONCILIATION_DEVELOP_PLUGIN_DATABASE,
  resolveOrganizationReconciliationDevelopSourceComponent
} from "./iam-organization-reconciliation-develop-source-catalog.js";
import {
  openIdentityMysqlRawSnapshot,
  openLegacyMainMysqlRawSnapshot,
  openPluginRegistryMysqlRawSnapshot,
  type IdentityMysqlRawSnapshot,
  type LegacyMainMysqlRawSnapshot,
  type OrganizationReconciliationMysqlRawComponentId,
  type OrganizationReconciliationMysqlRawPage,
  type OrganizationReconciliationMysqlRawSurface,
  type PluginRegistryMysqlRawSnapshot
} from "./iam-organization-reconciliation/mysql-source-adapters/raw-source-snapshots.js";
import type {
  MysqlRepeatableReadSnapshotConnectionFactory
} from "./iam-organization-reconciliation/mysql-repeatable-read-snapshot.js";

export const ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_PREFLIGHT_CONTRACT =
  "iam-organization-reconciliation-xrteeth-develop-source-preflight/v4" as const;

const SET_REPEATABLE_READ = "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ";
const START_READ_ONLY = "START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY";
const ROLLBACK = "ROLLBACK";
const SHOW_CURRENT_GRANTS = "SHOW GRANTS FOR CURRENT_USER()";
const MAX_SCHEMA_ROWS = 512;
const MAX_SUBJECT_ROWS = 1_000_000;
const MAX_RBAC_ITEM_ROWS = 4_096;
const MAX_RBAC_EDGE_ROWS = 16_384;

const LEGACY_SUBJECT_IDS_QUERY = "SELECT id AS subject_id FROM `user` ORDER BY id ASC";
const LEGACY_PROTECTED_SUBJECT_IDS_QUERY =
  "SELECT DISTINCT u.id AS subject_id FROM `user` AS u LEFT JOIN auth_assignment AS aa ON aa.user_id = CAST(u.id AS CHAR) LEFT JOIN auth_item AS ai ON ai.name = aa.item_name AND ai.type = 1 WHERE LOWER(TRIM(COALESCE(u.username, ''))) = 'root' OR LOWER(TRIM(COALESCE(ai.name, ''))) = 'root' ORDER BY u.id ASC";
const IDENTITY_SUBJECT_IDS_QUERY =
  "SELECT legacy_user_id AS subject_id FROM identity_users WHERE legacy_user_id IS NOT NULL AND source = 'legacy-shadow' AND status IN ('active', 'inactive') ORDER BY legacy_user_id ASC";
const IDENTITY_MEMBERSHIP_SNAPSHOT_SUBJECT_IDS_QUERY =
  "SELECT legacy_user_id AS subject_id FROM identity_organization_membership_snapshots WHERE source = 'legacy' AND candidate_status = 'candidate' ORDER BY legacy_user_id ASC";
const LEGACY_RBAC_ITEMS_QUERY =
  "SELECT name, type, rule_name FROM auth_item WHERE type IN (1, 2) ORDER BY CAST(name AS BINARY) ASC";
const LEGACY_RBAC_EDGES_QUERY =
  "SELECT parent, child FROM auth_item_child ORDER BY CAST(parent AS BINARY) ASC, CAST(child AS BINARY) ASC";
const DEVELOP_RECONCILIATION_CAPABILITY_ITEMS = Object.freeze([
  "organization.bind-user",
  "organization.create",
  "organization.list",
  "organization.update",
  "user-management.change-role",
  "user-management.create-user",
  "user-management.delete-user",
  "user-management.list-users",
  "user-management.manage-invitations",
  "user-management.update-user",
  "user-management.view-user"
]);

const SOURCE_IDENTITY_QUERY =
  "SELECT DATABASE() AS database_name, CURRENT_USER() AS `current_user`, @@hostname AS server_hostname, @@port AS server_port, @@version AS server_version";

const EXPECTED_DATABASES = Object.freeze({
  "legacy-main": ORGANIZATION_RECONCILIATION_DEVELOP_LEGACY_DATABASE,
  identity: ORGANIZATION_RECONCILIATION_DEVELOP_IDENTITY_DATABASE,
  plugin: ORGANIZATION_RECONCILIATION_DEVELOP_PLUGIN_DATABASE
} satisfies Record<OrganizationReconciliationMysqlRawComponentId, string>);

const SCHEMA_QUERIES = Object.freeze({
  "legacy-main":
    "SELECT TABLE_NAME AS table_name, COLUMN_NAME AS column_name, DATA_TYPE AS data_type, COLUMN_TYPE AS column_type, IS_NULLABLE AS is_nullable, COALESCE(COLLATION_NAME, '') AS collation_name, ORDINAL_POSITION AS ordinal_position FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME IN ('organization', 'user', 'user_organization', 'auth_assignment', 'auth_item', 'auth_item_child') ORDER BY CAST(TABLE_NAME AS BINARY) ASC, ORDINAL_POSITION ASC",
  identity:
    "SELECT TABLE_NAME AS table_name, COLUMN_NAME AS column_name, DATA_TYPE AS data_type, COLUMN_TYPE AS column_type, IS_NULLABLE AS is_nullable, COALESCE(COLLATION_NAME, '') AS collation_name, ORDINAL_POSITION AS ordinal_position FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME IN ('identity_users', 'identity_organizations_candidate', 'identity_organization_id_map', 'identity_organization_memberships_shadow', 'identity_organization_memberships_candidate', 'identity_organization_membership_snapshots', 'identity_role_assignments_shadow', 'identity_iam_policy_versions', 'identity_iam_roles', 'identity_iam_permissions', 'identity_iam_item_relations', 'identity_iam_subject_assignments') ORDER BY CAST(TABLE_NAME AS BINARY) ASC, ORDINAL_POSITION ASC",
  plugin:
    "SELECT TABLE_NAME AS table_name, COLUMN_NAME AS column_name, DATA_TYPE AS data_type, COLUMN_TYPE AS column_type, IS_NULLABLE AS is_nullable, COALESCE(COLLATION_NAME, '') AS collation_name, ORDINAL_POSITION AS ordinal_position FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'plugins' ORDER BY ORDINAL_POSITION ASC"
} satisfies Record<OrganizationReconciliationMysqlRawComponentId, string>);

const AGGREGATE_QUERIES = Object.freeze({
  "legacy-main":
    "SELECT 'legacy_organization_count' AS metric, COUNT(*) AS metric_value FROM organization UNION ALL SELECT 'legacy_subject_count', COUNT(*) FROM `user` UNION ALL SELECT 'legacy_active_subject_count', COUNT(*) FROM `user` WHERE status = 10 UNION ALL SELECT 'legacy_membership_count', COUNT(*) FROM user_organization UNION ALL SELECT 'legacy_rbac_item_count', COUNT(*) FROM auth_item WHERE type IN (1, 2) UNION ALL SELECT 'legacy_named_rule_count', COUNT(*) FROM auth_item WHERE type IN (1, 2) AND rule_name IS NOT NULL UNION ALL SELECT 'legacy_rbac_edge_count', COUNT(*) FROM auth_item_child UNION ALL SELECT 'legacy_role_assignment_count', COUNT(*) FROM auth_assignment AS aa INNER JOIN auth_item AS ai ON ai.name = aa.item_name AND ai.type = 1 INNER JOIN `user` AS u ON aa.user_id = CAST(u.id AS CHAR) UNION ALL SELECT 'legacy_rbac_assignment_count', COUNT(*) FROM auth_assignment AS aa INNER JOIN auth_item AS ai ON ai.name = aa.item_name AND ai.type IN (1, 2) INNER JOIN `user` AS u ON aa.user_id = CAST(u.id AS CHAR) ORDER BY CAST(metric AS BINARY) ASC",
  identity:
    "SELECT 'identity_subject_count' AS metric, COUNT(*) AS metric_value FROM identity_users WHERE legacy_user_id IS NOT NULL AND source = 'legacy-shadow' AND status IN ('active', 'inactive') UNION ALL SELECT 'identity_subject_collision_count', COUNT(*) FROM (SELECT legacy_user_id FROM identity_users WHERE legacy_user_id IS NOT NULL AND source = 'legacy-shadow' AND status IN ('active', 'inactive') GROUP BY legacy_user_id HAVING COUNT(*) <> 1) AS subject_collisions UNION ALL SELECT 'identity_organization_candidate_count', COUNT(*) FROM identity_organizations_candidate WHERE source = 'legacy' AND candidate_status = 'candidate' UNION ALL SELECT 'identity_organization_id_map_count', COUNT(*) FROM identity_organization_id_map WHERE source = 'legacy' AND mapping_status = 'active' UNION ALL SELECT 'identity_membership_candidate_count', COUNT(*) FROM identity_organization_memberships_candidate WHERE source = 'legacy' AND candidate_status = 'candidate' UNION ALL SELECT 'identity_membership_snapshot_count', COUNT(*) FROM identity_organization_membership_snapshots WHERE source = 'legacy' AND candidate_status = 'candidate' UNION ALL SELECT 'identity_membership_snapshot_organization_sum', COALESCE(SUM(organization_count), 0) FROM identity_organization_membership_snapshots WHERE source = 'legacy' AND candidate_status = 'candidate' UNION ALL SELECT 'identity_membership_shadow_count', COUNT(*) FROM identity_organization_memberships_shadow WHERE source = 'legacy-shadow' AND status = 'shadow' UNION ALL SELECT 'identity_role_shadow_count', COUNT(*) FROM identity_role_assignments_shadow WHERE source = 'legacy-shadow' AND status = 'shadow' UNION ALL SELECT 'identity_iam_policy_version_count', COUNT(*) FROM identity_iam_policy_versions WHERE checksum = ? AND source = 'legacy-import-candidate' AND status = 'candidate' UNION ALL SELECT 'identity_iam_declared_role_count', COALESCE(SUM(role_count), 0) FROM identity_iam_policy_versions WHERE checksum = ? AND source = 'legacy-import-candidate' AND status = 'candidate' UNION ALL SELECT 'identity_iam_declared_permission_count', COALESCE(SUM(permission_count), 0) FROM identity_iam_policy_versions WHERE checksum = ? AND source = 'legacy-import-candidate' AND status = 'candidate' UNION ALL SELECT 'identity_iam_declared_relation_count', COALESCE(SUM(relation_count), 0) FROM identity_iam_policy_versions WHERE checksum = ? AND source = 'legacy-import-candidate' AND status = 'candidate' UNION ALL SELECT 'identity_iam_role_count', COUNT(*) FROM identity_iam_roles WHERE policy_checksum = ? AND source = 'legacy-import-candidate' AND status = 'candidate' UNION ALL SELECT 'identity_iam_permission_count', COUNT(*) FROM identity_iam_permissions WHERE policy_checksum = ? AND source = 'legacy-import-candidate' AND status = 'candidate' UNION ALL SELECT 'identity_iam_relation_count', COUNT(*) FROM identity_iam_item_relations WHERE policy_checksum = ? AND source = 'legacy-import-candidate' AND status = 'candidate' UNION ALL SELECT 'identity_iam_subject_assignment_count', COUNT(*) FROM identity_iam_subject_assignments WHERE policy_checksum = ? AND source = 'legacy-import-candidate' AND status = 'candidate' AND legacy_user_id IS NOT NULL ORDER BY CAST(metric AS BINARY) ASC",
  plugin:
    "SELECT 'plugin_count' AS metric, COUNT(*) AS metric_value FROM plugins UNION ALL SELECT 'plugin_enabled_count', COUNT(*) FROM plugins WHERE enabled = 1 UNION ALL SELECT 'plugin_invalid_scope_count', COUNT(*) FROM plugins WHERE access_scope NOT IN ('auth-only', 'manager-only', 'admin-only', 'root-only') UNION ALL SELECT 'plugin_empty_organization_name_count', COUNT(*) FROM plugins WHERE organization_name = '' ORDER BY CAST(metric AS BINARY) ASC"
} satisfies Record<OrganizationReconciliationMysqlRawComponentId, string>);

const REQUIRED_COLUMNS = Object.freeze({
  "legacy-main": Object.freeze({
    organization: Object.freeze(["id", "name", "title", "created_at", "updated_at"]),
    user: Object.freeze(["id", "status"]),
    user_organization: Object.freeze(["user_id", "organization_id"]),
    auth_assignment: Object.freeze(["item_name", "user_id"]),
    auth_item: Object.freeze(["name", "type", "description", "rule_name"]),
    auth_item_child: Object.freeze(["parent", "child"])
  }),
  identity: Object.freeze({
    identity_users: Object.freeze(["id", "legacy_user_id", "status", "source"]),
    identity_organizations_candidate: Object.freeze([
      "legacy_organization_id", "identity_organization_id", "name", "title", "source", "candidate_status"
    ]),
    identity_organization_id_map: Object.freeze([
      "legacy_organization_id", "identity_organization_id", "source", "mapping_status"
    ]),
    identity_organization_memberships_shadow: Object.freeze([
      "legacy_user_id", "organization_id", "organization_role", "source", "status"
    ]),
    identity_organization_memberships_candidate: Object.freeze([
      "legacy_user_id", "legacy_organization_id", "identity_user_id", "identity_organization_id",
      "organization_role", "source", "candidate_status", "operation_key"
    ]),
    identity_organization_membership_snapshots: Object.freeze([
      "identity_user_id", "legacy_user_id", "operation_key", "organization_count", "source", "candidate_status"
    ]),
    identity_role_assignments_shadow: Object.freeze(["legacy_user_id", "role_name", "source", "status"]),
    identity_iam_policy_versions: Object.freeze([
      "checksum", "source", "status", "role_count", "permission_count", "relation_count"
    ]),
    identity_iam_roles: Object.freeze(["policy_checksum", "role_name", "description", "source", "status"]),
    identity_iam_permissions: Object.freeze([
      "policy_checksum", "permission_name", "description", "source", "status"
    ]),
    identity_iam_item_relations: Object.freeze([
      "policy_checksum", "parent_name", "parent_type", "child_name", "child_type", "source", "status"
    ]),
    identity_iam_subject_assignments: Object.freeze([
      "identity_user_id", "legacy_user_id", "item_name", "item_type", "policy_checksum", "source", "status"
    ])
  }),
  plugin: Object.freeze({
    plugins: Object.freeze(["id", "enabled", "access_scope", "organization_name"])
  })
} satisfies Record<OrganizationReconciliationMysqlRawComponentId, Record<string, readonly string[]>>);

export interface OrganizationReconciliationDevelopSourcePreflightDependencies {
  readonly legacyConnectionFactory: MysqlRepeatableReadSnapshotConnectionFactory;
  readonly identityConnectionFactory: MysqlRepeatableReadSnapshotConnectionFactory;
  readonly pluginConnectionFactory: MysqlRepeatableReadSnapshotConnectionFactory;
  readonly expectedDatabaseUsers: Readonly<Record<OrganizationReconciliationMysqlRawComponentId, string>>;
  readonly buildRevision: string;
  readonly now: () => Date;
}

export interface OrganizationReconciliationDevelopSourcePreflightReport {
  readonly contract: typeof ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_PREFLIGHT_CONTRACT;
  readonly environment: "xrteeth-develop";
  readonly mode: "read-only";
  readonly checkedAt: string;
  readonly buildRevision: string;
  readonly sourceCatalogSha256: string;
  readonly statementCatalogSha256: string;
  readonly iamPolicyChecksum: string;
  readonly components: readonly {
    readonly componentId: OrganizationReconciliationMysqlRawComponentId;
    readonly sourceIdentitySha256: string;
    readonly databaseBindingPassed: boolean;
    readonly readOnlyGrantPassed: boolean;
    readonly grantScopeSha256: string;
    readonly physicalSchemaSha256: string;
    readonly schemaShapePassed: boolean;
    readonly requiredColumnCount: number;
    readonly observedColumnCount: number;
    readonly datasetProbeCount: number;
    readonly nonEmptyDatasetProbeCount: number;
    readonly aggregateCounts: Readonly<Record<string, number>>;
  }[];
  readonly subjectUniverseComparison: {
    readonly legacySubjectCount: number;
    readonly identitySelectedSubjectCount: number;
    readonly missingInIdentityCount: number;
    readonly extraInIdentityCount: number;
  };
  readonly legacyRbacScope: {
    readonly targetCount: number;
    readonly presentTargetCount: number;
    readonly namedRuleIntersectionCount: number;
  };
  readonly membershipSnapshotComparison: {
    readonly legacySubjectCount: number;
    readonly protectedLegacySubjectCount: number;
    readonly expectedSnapshotSubjectCount: number;
    readonly snapshotSubjectCount: number;
    readonly missingExpectedSnapshotCount: number;
    readonly unexpectedProtectedSnapshotCount: number;
    readonly extraSnapshotCount: number;
  };
  readonly checks: readonly { readonly checkId: string; readonly passed: boolean }[];
  readonly failures: readonly string[];
  readonly passed: boolean;
  readonly productionReady: false;
}

type RawSnapshot = LegacyMainMysqlRawSnapshot | IdentityMysqlRawSnapshot | PluginRegistryMysqlRawSnapshot;

export async function runOrganizationReconciliationDevelopSourcePreflight(
  dependencies: OrganizationReconciliationDevelopSourcePreflightDependencies
): Promise<OrganizationReconciliationDevelopSourcePreflightReport> {
  const checkedAt = dependencies.now().toISOString();
  const componentInputs = [
    {
      componentId: "legacy-main",
      factory: dependencies.legacyConnectionFactory,
      expectedDatabaseUser: dependencies.expectedDatabaseUsers["legacy-main"]
    },
    {
      componentId: "identity",
      factory: dependencies.identityConnectionFactory,
      expectedDatabaseUser: dependencies.expectedDatabaseUsers.identity
    },
    {
      componentId: "plugin",
      factory: dependencies.pluginConnectionFactory,
      expectedDatabaseUser: dependencies.expectedDatabaseUsers.plugin
    }
  ] as const;
  const failures: string[] = [];
  const components = [] as Array<OrganizationReconciliationDevelopSourcePreflightReport["components"][number]>;
  const inspections = new Map<OrganizationReconciliationMysqlRawComponentId, PhysicalSourceInspection>();
  const probeCounts = new Map<OrganizationReconciliationMysqlRawComponentId, Readonly<Record<string, number>>>();

  for (const input of componentInputs) {
    try {
      const metadata = await inspectPhysicalSource(
        input.componentId,
        input.factory,
        input.expectedDatabaseUser
      );
      inspections.set(input.componentId, metadata);
      const probes = metadata.databaseBindingPassed && metadata.readOnlyGrantPassed && metadata.schemaShapePassed
        ? await probeRawDatasets(
          input.componentId,
          createVerifiedOrganizationReconciliationDevelopSourceConnectionFactory(
            input.componentId,
            input.factory,
            input.expectedDatabaseUser
          )
        )
        : Object.freeze({} as Readonly<Record<string, number>>);
      probeCounts.set(input.componentId, probes);
      components.push(Object.freeze({
        componentId: input.componentId,
        sourceIdentitySha256: metadata.sourceIdentitySha256,
        databaseBindingPassed: metadata.databaseBindingPassed,
        readOnlyGrantPassed: metadata.readOnlyGrantPassed,
        grantScopeSha256: metadata.grantScopeSha256,
        physicalSchemaSha256: metadata.physicalSchemaSha256,
        schemaShapePassed: metadata.schemaShapePassed,
        requiredColumnCount: metadata.requiredColumnCount,
        observedColumnCount: metadata.observedColumnCount,
        datasetProbeCount: Object.keys(probes).length,
        nonEmptyDatasetProbeCount: Object.values(probes).filter((count) => count === 1).length,
        aggregateCounts: metadata.aggregateCounts
      }));
      if (!metadata.databaseBindingPassed) failures.push(`${input.componentId}:database-binding`);
      if (!metadata.readOnlyGrantPassed) failures.push(`${input.componentId}:read-only-grant`);
      if (!metadata.schemaShapePassed) failures.push(`${input.componentId}:schema-shape`);
    } catch {
      failures.push(`${input.componentId}:read-only-preflight`);
    }
  }

  const byComponent = new Map(components.map((component) => [component.componentId, component]));
  const legacy = byComponent.get("legacy-main")?.aggregateCounts ?? {};
  const identity = byComponent.get("identity")?.aggregateCounts ?? {};
  const plugin = byComponent.get("plugin")?.aggregateCounts ?? {};
  const identityProbes = probeCounts.get("identity") ?? {};
  const legacyInspection = inspections.get("legacy-main");
  const identityInspection = inspections.get("identity");
  const subjectUniverseComparison = compareSubjectUniverses(
    legacyInspection?.subjectIds ?? [],
    identityInspection?.subjectIds ?? []
  );
  const legacyRbacScope = legacyInspection?.legacyRbacScope ?? Object.freeze({
    targetCount: DEVELOP_RECONCILIATION_CAPABILITY_ITEMS.length,
    presentTargetCount: 0,
    namedRuleIntersectionCount: 0
  });
  const membershipSnapshotComparison = compareMembershipSnapshotSubjects(
    legacyInspection?.subjectIds ?? [],
    legacyInspection?.protectedLegacySubjectIds ?? [],
    identityInspection?.membershipSnapshotSubjectIds ?? []
  );
  const checks = Object.freeze([
    check("all-components-probed", components.length === 3),
    check("all-component-database-bindings-exact",
      components.length === 3 && components.every((component) => component.databaseBindingPassed)),
    check("all-component-grants-read-only-and-table-bounded",
      components.length === 3 && components.every((component) => component.readOnlyGrantPassed)),
    check("all-21-datasets-probed", components.reduce((sum, component) => sum + component.datasetProbeCount, 0) === 21),
    check("legacy-reconciliation-capability-catalog-present",
      legacyRbacScope.presentTargetCount === legacyRbacScope.targetCount),
    check("legacy-reconciliation-scope-rule-free",
      legacyRbacScope.presentTargetCount === legacyRbacScope.targetCount &&
      legacyRbacScope.namedRuleIntersectionCount === 0),
    check("identity-legacy-subjects-complete",
      legacyInspection !== undefined && identityInspection !== undefined &&
      subjectUniverseComparison.missingInIdentityCount === 0),
    check("identity-subjects-unique", identity.identity_subject_collision_count === 0),
    check("identity-organizations-complete",
      identity.identity_organization_candidate_count === legacy.legacy_organization_count &&
      identity.identity_organization_id_map_count === legacy.legacy_organization_count),
    check("identity-legacy-membership-snapshots-complete",
      legacyInspection !== undefined && identityInspection !== undefined &&
      membershipSnapshotComparison.missingExpectedSnapshotCount === 0 &&
      membershipSnapshotComparison.unexpectedProtectedSnapshotCount === 0 &&
      membershipSnapshotComparison.extraSnapshotCount === 0),
    check("identity-membership-counts-complete",
      identity.identity_membership_candidate_count === identity.identity_membership_snapshot_organization_sum),
    check("identity-policy-version-pinned", identity.identity_iam_policy_version_count === 1),
    check("identity-policy-version-decoder-probed", identityProbes["identity-iam-policy-version"] === 1),
    check("identity-policy-role-count",
      identity.identity_iam_role_count === identity.identity_iam_declared_role_count),
    check("identity-policy-permission-count",
      identity.identity_iam_permission_count === identity.identity_iam_declared_permission_count),
    check("identity-policy-relation-count",
      identity.identity_iam_relation_count === identity.identity_iam_declared_relation_count),
    check("plugin-scopes-valid", plugin.plugin_invalid_scope_count === 0),
    check("plugin-empty-organization-name-absent", plugin.plugin_empty_organization_name_count === 0),
    check("build-revision-pinned", /^[a-f0-9]{40}$/.test(dependencies.buildRevision))
  ]);
  for (const result of checks) if (!result.passed) failures.push(result.checkId);

  return Object.freeze({
    contract: ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_PREFLIGHT_CONTRACT,
    environment: "xrteeth-develop",
    mode: "read-only",
    checkedAt,
    buildRevision: dependencies.buildRevision,
    sourceCatalogSha256: ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG_SHA256,
    statementCatalogSha256: ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG.statementCatalogSha256,
    iamPolicyChecksum: ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG.iamPolicyChecksum,
    components: Object.freeze(components),
    subjectUniverseComparison,
    legacyRbacScope,
    membershipSnapshotComparison,
    checks,
    failures: Object.freeze([...new Set(failures)].sort()),
    passed: failures.length === 0,
    productionReady: false
  });
}

interface PhysicalSourceInspection {
  readonly sourceIdentitySha256: string;
  readonly databaseBindingPassed: boolean;
  readonly readOnlyGrantPassed: boolean;
  readonly grantScopeSha256: string;
  readonly physicalSchemaSha256: string;
  readonly schemaShapePassed: boolean;
  readonly requiredColumnCount: number;
  readonly observedColumnCount: number;
  readonly aggregateCounts: Readonly<Record<string, number>>;
  readonly subjectIds: readonly string[];
  readonly protectedLegacySubjectIds: readonly string[];
  readonly membershipSnapshotSubjectIds: readonly string[];
  readonly legacyRbacScope: OrganizationReconciliationDevelopSourcePreflightReport["legacyRbacScope"] | null;
}

async function inspectPhysicalSource(
  componentId: OrganizationReconciliationMysqlRawComponentId,
  factory: MysqlRepeatableReadSnapshotConnectionFactory,
  expectedDatabaseUser: string
): Promise<PhysicalSourceInspection> {
  const connection = await factory();
  let failed = false;
  let transactionStarted = false;
  try {
    const grantRows = rows(await connection.query(SHOW_CURRENT_GRANTS));
    const grantInspection = inspectReadOnlyGrants(componentId, grantRows);
    await connection.query(SET_REPEATABLE_READ);
    await connection.query(START_READ_ONLY);
    transactionStarted = true;
    const identityRows = rows(await connection.query(SOURCE_IDENTITY_QUERY));
    const databaseBindingPassed = captureDatabaseBinding(componentId, identityRows, expectedDatabaseUser);
    const schemaRows = rows(await connection.query(SCHEMA_QUERIES[componentId]));
    const checksum = ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG.iamPolicyChecksum;
    const aggregateParameters = componentId === "identity" ? Array(8).fill(checksum) : [];
    const aggregateRows = rows(await connection.query(AGGREGATE_QUERIES[componentId], aggregateParameters));
    const subjectIds = componentId === "legacy-main"
      ? captureSubjectIds(rows(await connection.query(LEGACY_SUBJECT_IDS_QUERY)))
      : componentId === "identity"
        ? captureSubjectIds(rows(await connection.query(IDENTITY_SUBJECT_IDS_QUERY)))
        : Object.freeze([] as string[]);
    const protectedLegacySubjectIds = componentId === "legacy-main"
      ? captureSubjectIds(rows(await connection.query(LEGACY_PROTECTED_SUBJECT_IDS_QUERY)))
      : Object.freeze([] as string[]);
    const membershipSnapshotSubjectIds = componentId === "identity"
      ? captureSubjectIds(rows(await connection.query(IDENTITY_MEMBERSHIP_SNAPSHOT_SUBJECT_IDS_QUERY)))
      : Object.freeze([] as string[]);
    const legacyRbacScope = componentId === "legacy-main"
      ? captureLegacyRbacScope(
        rows(await connection.query(LEGACY_RBAC_ITEMS_QUERY)),
        rows(await connection.query(LEGACY_RBAC_EDGES_QUERY))
      )
      : null;
    const schema = captureSchemaRows(schemaRows);
    const required = REQUIRED_COLUMNS[componentId];
    const requiredColumnCount = Object.values(required).reduce((sum, columns) => sum + columns.length, 0);
    const schemaShapePassed = Object.entries(required).every(([table, columns]) =>
      columns.every((column) => schema.some((row) => row.tableName === table && row.columnName === column))
    );
    return Object.freeze({
      sourceIdentitySha256: digest(identityRows),
      databaseBindingPassed,
      readOnlyGrantPassed: grantInspection.passed,
      grantScopeSha256: grantInspection.sha256,
      physicalSchemaSha256: digest(schema),
      schemaShapePassed,
      requiredColumnCount,
      observedColumnCount: schema.length,
      aggregateCounts: captureAggregateRows(aggregateRows),
      subjectIds,
      protectedLegacySubjectIds,
      membershipSnapshotSubjectIds,
      legacyRbacScope
    });
  } catch (error) {
    failed = true;
    throw error;
  } finally {
    let cleanupFailed = false;
    if (transactionStarted) {
      try {
        await connection.query(ROLLBACK);
      } catch {
        cleanupFailed = true;
      }
    }
    try {
      await connection.release();
    } catch {
      cleanupFailed = true;
    }
    if (cleanupFailed && !failed) throw new Error("The Develop source preflight cleanup failed.");
  }
}

function captureDatabaseBinding(
  componentId: OrganizationReconciliationMysqlRawComponentId,
  candidate: readonly unknown[],
  expectedDatabaseUser: string
): boolean {
  if (!/^[A-Za-z0-9_.-]{1,64}$/.test(expectedDatabaseUser)) {
    throw new Error("The expected database user is invalid.");
  }
  if (candidate.length !== 1) throw new Error("The physical source identity is invalid.");
  const row = record(candidate[0]);
  const databaseName = metadata(row.database_name);
  const currentUser = metadata(row.current_user);
  metadata(row.server_hostname);
  integer(row.server_port);
  metadata(row.server_version);
  const separator = currentUser.lastIndexOf("@");
  const currentDatabaseUser = separator > 0 ? currentUser.slice(0, separator) : "";
  const currentDatabaseHost = separator > 0 ? currentUser.slice(separator + 1) : "";
  return databaseName === EXPECTED_DATABASES[componentId] &&
    currentDatabaseUser === expectedDatabaseUser &&
    currentDatabaseHost.length > 0;
}

function inspectReadOnlyGrants(
  componentId: OrganizationReconciliationMysqlRawComponentId,
  candidate: readonly unknown[]
): { readonly passed: boolean; readonly sha256: string } {
  if (candidate.length < 1 || candidate.length > 32) {
    throw new Error("The current-user grant set is outside the reviewed bound.");
  }
  const expectedDatabase = EXPECTED_DATABASES[componentId];
  const requiredTables = Object.keys(REQUIRED_COLUMNS[componentId]);
  const coveredTables = new Set<string>();
  let passed = true;
  const statements: string[] = [];
  for (const value of candidate) {
    const row = record(value);
    const values = Object.values(row);
    if (values.length !== 1 || typeof values[0] !== "string") {
      throw new Error("A current-user grant row is invalid.");
    }
    const statement = values[0].replace(/\s+/g, " ").trim();
    if (statement.length < 1 || statement.length > 4_096 || statement.normalize("NFC") !== statement) {
      throw new Error("A current-user grant statement is invalid.");
    }
    statements.push(statement);
    if (/\bWITH\s+GRANT\s+OPTION\b/i.test(statement)) {
      passed = false;
      continue;
    }
    const match = /^GRANT\s+(.+?)\s+ON\s+(\S+)\s+TO\s+.+$/i.exec(statement);
    if (!match) {
      passed = false;
      continue;
    }
    const privileges = (match[1] as string).split(",").map((privilege) => privilege.trim().toUpperCase());
    const scope = match[2] as string;
    if (privileges.length === 1 && privileges[0] === "USAGE" && scope === "*.*") continue;
    if (privileges.length < 1 || privileges.some((privilege) => privilege !== "SELECT" && privilege !== "SHOW VIEW") ||
      !privileges.includes("SELECT")) {
      passed = false;
      continue;
    }
    const databaseScope = `\`${expectedDatabase}\`.*`;
    if (scope === databaseScope || scope === `${expectedDatabase}.*`) {
      for (const table of requiredTables) coveredTables.add(table);
      continue;
    }
    const matchedTable = requiredTables.find((table) =>
      scope === `\`${expectedDatabase}\`.\`${table}\`` || scope === `${expectedDatabase}.${table}`
    );
    if (matchedTable) coveredTables.add(matchedTable);
    else passed = false;
  }
  if (requiredTables.some((table) => !coveredTables.has(table))) passed = false;
  statements.sort((left, right) => Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8")));
  return Object.freeze({ passed, sha256: digest(statements) });
}

/**
 * Wraps one reviewed Develop read-only factory with the same exact database
 * and grant checks used by the source preflight. The wrapper performs no I/O
 * until its returned factory is invoked.
 */
export function createVerifiedOrganizationReconciliationDevelopSourceConnectionFactory(
  componentId: OrganizationReconciliationMysqlRawComponentId,
  factory: MysqlRepeatableReadSnapshotConnectionFactory,
  expectedDatabaseUser: string
): MysqlRepeatableReadSnapshotConnectionFactory {
  return async () => {
    const connection = await factory();
    let accepted = false;
    try {
      const grantInspection = inspectReadOnlyGrants(
        componentId,
        rows(await connection.query(SHOW_CURRENT_GRANTS))
      );
      const databaseBindingPassed = captureDatabaseBinding(
        componentId,
        rows(await connection.query(SOURCE_IDENTITY_QUERY)),
        expectedDatabaseUser
      );
      if (!grantInspection.passed || !databaseBindingPassed) {
        throw new Error("The dataset probe source identity is not accepted.");
      }
      accepted = true;
      return connection;
    } finally {
      if (!accepted) await connection.release();
    }
  };
}

function captureSubjectIds(candidate: readonly unknown[]): readonly string[] {
  if (candidate.length > MAX_SUBJECT_ROWS) throw new Error("The subject universe exceeded its bound.");
  const output: string[] = [];
  let previous = 0;
  for (const value of candidate) {
    const row = record(value);
    const subjectId = integer(row.subject_id);
    if (subjectId < 1 || subjectId <= previous) throw new Error("The subject universe order is invalid.");
    output.push(String(subjectId));
    previous = subjectId;
  }
  return Object.freeze(output);
}

function compareSubjectUniverses(
  legacySubjectIds: readonly string[],
  identitySubjectIds: readonly string[]
): OrganizationReconciliationDevelopSourcePreflightReport["subjectUniverseComparison"] {
  const legacy = new Set(legacySubjectIds);
  const identity = new Set(identitySubjectIds);
  let missingInIdentityCount = 0;
  let extraInIdentityCount = 0;
  for (const subjectId of legacy) if (!identity.has(subjectId)) missingInIdentityCount += 1;
  for (const subjectId of identity) if (!legacy.has(subjectId)) extraInIdentityCount += 1;
  return Object.freeze({
    legacySubjectCount: legacy.size,
    identitySelectedSubjectCount: identity.size,
    missingInIdentityCount,
    extraInIdentityCount
  });
}

function compareMembershipSnapshotSubjects(
  legacySubjectIds: readonly string[],
  protectedLegacySubjectIds: readonly string[],
  snapshotSubjectIds: readonly string[]
): OrganizationReconciliationDevelopSourcePreflightReport["membershipSnapshotComparison"] {
  const legacy = new Set(legacySubjectIds);
  const protectedLegacy = new Set(protectedLegacySubjectIds);
  if ([...protectedLegacy].some((subjectId) => !legacy.has(subjectId))) {
    throw new Error("The protected Legacy subject universe is invalid.");
  }
  const expectedSnapshots = new Set([...legacy].filter((subjectId) => !protectedLegacy.has(subjectId)));
  const snapshots = new Set(snapshotSubjectIds);
  let missingExpectedSnapshotCount = 0;
  let unexpectedProtectedSnapshotCount = 0;
  let extraSnapshotCount = 0;
  for (const subjectId of expectedSnapshots) if (!snapshots.has(subjectId)) missingExpectedSnapshotCount += 1;
  for (const subjectId of snapshots) {
    if (protectedLegacy.has(subjectId)) unexpectedProtectedSnapshotCount += 1;
  }
  for (const subjectId of snapshots) if (!legacy.has(subjectId)) extraSnapshotCount += 1;
  return Object.freeze({
    legacySubjectCount: legacy.size,
    protectedLegacySubjectCount: protectedLegacy.size,
    expectedSnapshotSubjectCount: expectedSnapshots.size,
    snapshotSubjectCount: snapshots.size,
    missingExpectedSnapshotCount,
    unexpectedProtectedSnapshotCount,
    extraSnapshotCount
  });
}

function captureLegacyRbacScope(
  itemRows: readonly unknown[],
  edgeRows: readonly unknown[]
): OrganizationReconciliationDevelopSourcePreflightReport["legacyRbacScope"] {
  if (itemRows.length > MAX_RBAC_ITEM_ROWS || edgeRows.length > MAX_RBAC_EDGE_ROWS) {
    throw new Error("The RBAC graph exceeded its bound.");
  }
  const items = new Map<string, { readonly ruleName: string | null }>();
  for (const value of itemRows) {
    const row = record(value);
    const name = metadata(row.name);
    const type = integer(row.type);
    if ((type !== 1 && type !== 2) || items.has(name)) throw new Error("An RBAC item is invalid.");
    const ruleName = row.rule_name === null ? null : metadata(row.rule_name);
    items.set(name, Object.freeze({ ruleName }));
  }
  const parents = new Map<string, string[]>();
  const edgeKeys = new Set<string>();
  for (const value of edgeRows) {
    const row = record(value);
    const parent = metadata(row.parent);
    const child = metadata(row.child);
    if (!items.has(parent) || !items.has(child)) throw new Error("An RBAC edge references an unknown item.");
    const key = `${parent}\u001f${child}`;
    if (edgeKeys.has(key)) throw new Error("An RBAC edge is duplicated.");
    edgeKeys.add(key);
    const list = parents.get(child) ?? [];
    list.push(parent);
    parents.set(child, list);
  }
  let presentTargetCount = 0;
  const namedRuleItems = new Set<string>();
  for (const target of DEVELOP_RECONCILIATION_CAPABILITY_ITEMS) {
    if (!items.has(target)) continue;
    presentTargetCount += 1;
    const visited = new Set([target]);
    const queue = [target];
    for (let index = 0; index < queue.length; index += 1) {
      const current = queue[index] as string;
      if (typeof items.get(current)?.ruleName === "string") namedRuleItems.add(current);
      for (const parent of parents.get(current) ?? []) {
        if (!visited.has(parent)) {
          visited.add(parent);
          queue.push(parent);
        }
      }
    }
  }
  return Object.freeze({
    targetCount: DEVELOP_RECONCILIATION_CAPABILITY_ITEMS.length,
    presentTargetCount,
    namedRuleIntersectionCount: namedRuleItems.size
  });
}

async function probeRawDatasets(
  componentId: OrganizationReconciliationMysqlRawComponentId,
  factory: MysqlRepeatableReadSnapshotConnectionFactory
): Promise<Readonly<Record<string, number>>> {
  const source = resolveOrganizationReconciliationDevelopSourceComponent(componentId);
  let snapshot: RawSnapshot | null = null;
  try {
    snapshot = componentId === "legacy-main"
      ? await openLegacyMainMysqlRawSnapshot({ expectedSourceId: source.expectedSourceId, connectionFactory: factory })
      : componentId === "identity"
        ? await openIdentityMysqlRawSnapshot({ expectedSourceId: source.expectedSourceId, connectionFactory: factory })
        : await openPluginRegistryMysqlRawSnapshot({ expectedSourceId: source.expectedSourceId, connectionFactory: factory });
    const counts: Record<string, number> = Object.create(null) as Record<string, number>;
    for (const dataset of source.datasetCatalog.datasets) {
      const page = await readProbePage(snapshot, dataset.datasetId);
      if (page.records.length > 1) throw new Error("A one-row dataset probe exceeded its bound.");
      counts[dataset.datasetId] = page.records.length;
    }
    await snapshot.close("completed");
    snapshot = null;
    return Object.freeze(counts);
  } finally {
    if (snapshot !== null) await snapshot.close("failed").catch(() => undefined);
  }
}

function readProbePage(
  snapshot: RawSnapshot,
  datasetId: string
): Promise<OrganizationReconciliationMysqlRawPage<OrganizationReconciliationMysqlRawSurface, unknown>> {
  const request = { requestCursor: null, pageSize: 1 };
  if (snapshot.metadata.componentId === "legacy-main") {
    const legacy = snapshot as LegacyMainMysqlRawSnapshot;
    switch (datasetId) {
      case "legacy-membership": return legacy.readMembershipPage(request);
      case "legacy-organization-directory": return legacy.readOrganizationDirectoryPage(request);
      case "legacy-rbac-assignment": return legacy.readRbacAssignmentPage(request);
      case "legacy-rbac-edge": return legacy.readRbacEdgePage(request);
      case "legacy-rbac-item": return legacy.readRbacItemPage(request);
      case "legacy-role-assignment": return legacy.readRoleAssignmentPage(request);
      case "legacy-subject-universe": return legacy.readSubjectUniversePage(request);
    }
  } else if (snapshot.metadata.componentId === "identity") {
    const identity = snapshot as IdentityMysqlRawSnapshot;
    switch (datasetId) {
      case "identity-iam-item-relation": return identity.readIamItemRelationPage(request);
      case "identity-iam-permission": return identity.readIamPermissionPage(request);
      case "identity-iam-policy-version": return identity.readIamPolicyVersionPage(request);
      case "identity-iam-role": return identity.readIamRolePage(request);
      case "identity-iam-subject-assignment": return identity.readIamSubjectAssignmentPage(request);
      case "identity-iam-subject-assignment-snapshot": return identity.readIamSubjectAssignmentSnapshotPage(request);
      case "identity-membership-candidate": return identity.readMembershipCandidatePage(request);
      case "identity-membership-candidate-snapshot": return identity.readMembershipCandidateSnapshotPage(request);
      case "identity-membership-shadow": return identity.readMembershipShadowPage(request);
      case "identity-organization-candidate": return identity.readOrganizationCandidatePage(request);
      case "identity-organization-id-map": return identity.readOrganizationIdMapPage(request);
      case "identity-role-shadow": return identity.readRoleShadowPage(request);
      case "identity-subject-universe": return identity.readSubjectUniversePage(request);
    }
  } else if (datasetId === "plugin-registry") {
    return (snapshot as PluginRegistryMysqlRawSnapshot).readPluginRegistryPage(request);
  }
  return Promise.reject(new Error("The Develop dataset probe is not compiled."));
}

function rows(result: readonly [unknown, unknown]): readonly unknown[] {
  if (!Array.isArray(result) || !Array.isArray(result[0])) throw new Error("A preflight query result is invalid.");
  return result[0] as readonly unknown[];
}

function captureSchemaRows(candidate: readonly unknown[]): readonly {
  tableName: string;
  columnName: string;
  dataType: string;
  columnType: string;
  nullable: string;
  collation: string;
  ordinal: number;
}[] {
  if (candidate.length > MAX_SCHEMA_ROWS) throw new Error("The schema result exceeded its bound.");
  return Object.freeze(candidate.map((value) => {
    const row = record(value);
    return Object.freeze({
      tableName: metadata(row.table_name),
      columnName: metadata(row.column_name),
      dataType: metadata(row.data_type),
      columnType: metadata(row.column_type),
      nullable: metadata(row.is_nullable),
      collation: typeof row.collation_name === "string" ? row.collation_name : "",
      ordinal: integer(row.ordinal_position)
    });
  }));
}

function captureAggregateRows(candidate: readonly unknown[]): Readonly<Record<string, number>> {
  if (candidate.length > 128) throw new Error("The aggregate result exceeded its bound.");
  const output: Record<string, number> = Object.create(null) as Record<string, number>;
  for (const value of candidate) {
    const row = record(value);
    const metric = metadata(row.metric);
    if (!/^[a-z][a-z0-9_]{0,127}$/.test(metric) || Object.prototype.hasOwnProperty.call(output, metric)) {
      throw new Error("An aggregate metric is invalid.");
    }
    output[metric] = integer(row.metric_value);
  }
  return Object.freeze(output);
}

function record(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("A preflight row is invalid.");
  }
  return value as Record<string, unknown>;
}

function metadata(value: unknown): string {
  if (typeof value !== "string" || value.length < 1 || value.length > 1_024 || value.normalize("NFC") !== value) {
    throw new Error("Preflight metadata is invalid.");
  }
  return value;
}

function integer(value: unknown): number {
  const normalized = typeof value === "bigint" ? value.toString() : value;
  const parsed = typeof normalized === "string" && /^[0-9]+$/.test(normalized)
    ? Number(normalized)
    : normalized;
  if (typeof parsed !== "number" || !Number.isSafeInteger(parsed) || parsed < 0) {
    throw new Error("A preflight count is invalid.");
  }
  return parsed;
}

function check(checkId: string, passed: boolean): { readonly checkId: string; readonly passed: boolean } {
  return Object.freeze({ checkId, passed });
}

function digest(value: unknown): string {
  return createHash("sha256")
    .update("iam-organization-reconciliation:xrteeth-develop-preflight:v1\u001f", "utf8")
    .update(JSON.stringify(value), "utf8")
    .digest("hex");
}
