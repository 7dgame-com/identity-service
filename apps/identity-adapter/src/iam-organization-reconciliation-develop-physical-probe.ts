import { createHash } from "node:crypto";
import {
  ORGANIZATION_RECONCILIATION_DEVELOP_IDENTITY_DATABASE,
  ORGANIZATION_RECONCILIATION_DEVELOP_LEGACY_DATABASE,
  ORGANIZATION_RECONCILIATION_DEVELOP_PLUGIN_DATABASE,
  ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG,
  ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG_SHA256
} from "./iam-organization-reconciliation-develop-source-catalog.js";
import type {
  OrganizationReconciliationMysqlRawComponentId
} from "./iam-organization-reconciliation/mysql-source-adapters/raw-source-snapshots.js";
import type {
  MysqlRepeatableReadSnapshotConnectionFactory
} from "./iam-organization-reconciliation/mysql-repeatable-read-snapshot.js";
import {
  ORGANIZATION_RECONCILIATION_MYSQL_STATEMENTS
} from "./iam-organization-reconciliation/mysql-repeatable-read-snapshot.js";

export const ORGANIZATION_RECONCILIATION_DEVELOP_PHYSICAL_PROBE_CONTRACT =
  "iam-organization-reconciliation-xrteeth-develop-physical-probe/v1" as const;
export const ORGANIZATION_RECONCILIATION_DEVELOP_PHYSICAL_PROBE_READY = false as const;

const SET_SESSION_REPEATABLE_READ = "SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ";
const START_READ_ONLY = "START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY";
const ROLLBACK = "ROLLBACK";
const SHOW_CURRENT_GRANTS = "SHOW GRANTS FOR CURRENT_USER()";
const SOURCE_IDENTITY_QUERY =
  "SELECT DATABASE() AS database_name, CURRENT_USER() AS `current_user`";
const SESSION_ISOLATION_QUERY =
  "SELECT @@SESSION.transaction_isolation AS session_transaction_isolation";
// U+E000 sorts after U+10000 by JavaScript UTF-16 code units but before it by
// UTF-8 bytes. Keeping both prevents a default Array.sort() from masquerading
// as the Node Buffer.compare order used by reconciliation canonicalization.
const UTF8_BINARY_ORDER_WITNESS_HEX = Object.freeze([
  "41",
  "61",
  "C3A9",
  "E4B8AD",
  "EE8080",
  "F0908080"
]);
const UTF8_BINARY_ORDER_WITNESS_QUERY =
  `SELECT HEX(witness_value) AS value_hex FROM (` +
  UTF8_BINARY_ORDER_WITNESS_HEX.map((hex, index) =>
    `${index === 0 ? "SELECT" : "UNION ALL SELECT"} CONVERT(0x${hex} USING utf8mb4) AS witness_value`
  ).join(" ") +
  ") AS binary_order_witness ORDER BY CAST(witness_value AS BINARY) ASC";

const MAX_GRANT_ROWS = 32;
const MAX_GRANT_LENGTH = 4_096;
const MAX_TABLE_ROWS = 64;
const MAX_COLUMN_ROWS = 512;
const MAX_INDEX_ROWS = 512;
const SHA256_PATTERN = /^[a-f0-9]{64}$/;

const EXPECTED_DATABASES = Object.freeze({
  "legacy-main": ORGANIZATION_RECONCILIATION_DEVELOP_LEGACY_DATABASE,
  identity: ORGANIZATION_RECONCILIATION_DEVELOP_IDENTITY_DATABASE,
  plugin: ORGANIZATION_RECONCILIATION_DEVELOP_PLUGIN_DATABASE
} satisfies Record<OrganizationReconciliationMysqlRawComponentId, string>);

type PhysicalStatementId = keyof typeof ORGANIZATION_RECONCILIATION_MYSQL_STATEMENTS;

interface PhysicalTableRequirement {
  readonly columns: readonly string[];
}

interface PhysicalCursorColumn {
  readonly tableName: string;
  readonly columnName: string;
  readonly comparison: "numeric" | "utf8-binary" | "numeric-via-user-id";
}

interface PhysicalUniqueKeyRequirement {
  readonly tableName: string;
  readonly columns: readonly string[];
  readonly purpose: "cursor-uniqueness" | "join-cardinality";
}

interface PhysicalDatasetRequirement {
  readonly statementId: PhysicalStatementId;
  readonly tables: readonly string[];
  readonly cursorOrder: readonly PhysicalCursorColumn[];
  /** Columns constrained by an equality or fixed finite-set predicate. */
  readonly fixedEqualityColumns: readonly {
    readonly tableName: string;
    readonly columnName: string;
  }[];
  /**
   * Exact full-length visible UNIQUE BTREE keys which close the cursor and
   * joined-row determinism contract. They are correctness witnesses, not a
   * claim that MySQL will use an index to execute the ORDER BY.
   */
  readonly deterministicUniqueKeys: readonly PhysicalUniqueKeyRequirement[];
}

interface PhysicalComponentRequirement {
  readonly componentId: OrganizationReconciliationMysqlRawComponentId;
  readonly datasets: Readonly<Record<string, PhysicalDatasetRequirement>>;
  readonly tables: Readonly<Record<string, PhysicalTableRequirement>>;
}

function table(columns: readonly string[]): PhysicalTableRequirement {
  return Object.freeze({
    columns: Object.freeze([...columns].sort(binaryCompare))
  });
}

function cursor(
  tableName: string,
  columnName: string,
  comparison: PhysicalCursorColumn["comparison"]
): PhysicalCursorColumn {
  return Object.freeze({ tableName, columnName, comparison });
}

function fixed(tableName: string, columnName: string): { readonly tableName: string; readonly columnName: string } {
  return Object.freeze({ tableName, columnName });
}

function uniqueKey(
  tableName: string,
  columns: readonly string[],
  purpose: PhysicalUniqueKeyRequirement["purpose"] = "cursor-uniqueness"
): PhysicalUniqueKeyRequirement {
  return Object.freeze({ tableName, columns: Object.freeze([...columns]), purpose });
}

function dataset(
  statementId: PhysicalStatementId,
  tables: readonly string[],
  cursorOrder: readonly PhysicalCursorColumn[],
  deterministicUniqueKeys: readonly PhysicalUniqueKeyRequirement[],
  fixedEqualityColumns: readonly { readonly tableName: string; readonly columnName: string }[] = []
): PhysicalDatasetRequirement {
  return Object.freeze({
    statementId,
    tables: Object.freeze([...tables].sort(binaryCompare)),
    cursorOrder: Object.freeze([...cursorOrder]),
    fixedEqualityColumns: Object.freeze([...fixedEqualityColumns].sort((left, right) =>
      binaryCompare(`${left.tableName}\u001f${left.columnName}`, `${right.tableName}\u001f${right.columnName}`))),
    deterministicUniqueKeys: Object.freeze([...deterministicUniqueKeys].sort((left, right) =>
      binaryCompare(
        `${left.tableName}\u001f${left.columns.join("\u001f")}\u001f${left.purpose}`,
        `${right.tableName}\u001f${right.columns.join("\u001f")}\u001f${right.purpose}`
      )))
  });
}

/**
 * This is the physical dependency closure of the compiled 7 + 13 + 1 dataset
 * statements. It is deliberately not a proposed schema. In particular,
 * identity-iam-subject-assignment-snapshot is a derived dataset backed by the
 * existing identity_users LEFT JOIN identity_iam_subject_assignments query.
 */
export const ORGANIZATION_RECONCILIATION_DEVELOP_PHYSICAL_CATALOG = Object.freeze({
  contract: "iam-organization-reconciliation-xrteeth-develop-physical-catalog/v1" as const,
  environment: "xrteeth-develop" as const,
  statementCatalogSha256: ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG.statementCatalogSha256,
  datasetCount: 21,
  uniquePhysicalTableCount: 19,
  derivedDatasetCount: 1,
  derivedDatasets: Object.freeze({
    "identity-iam-subject-assignment-snapshot": Object.freeze({
      relation: "left-join" as const,
      tables: Object.freeze(["identity_users", "identity_iam_subject_assignments"]),
      requiresDedicatedPhysicalTable: false as const
    })
  }),
  components: Object.freeze([
    Object.freeze({
      componentId: "legacy-main" as const,
      datasets: Object.freeze({
        "legacy-membership": dataset(
          "legacy-membership-page/v3",
          ["user_organization"],
          [cursor("user_organization", "user_id", "numeric"), cursor("user_organization", "organization_id", "numeric")],
          [uniqueKey("user_organization", ["user_id", "organization_id"])]
        ),
        "legacy-organization-directory": dataset(
          "legacy-organization-directory-page/v3",
          ["organization"],
          [cursor("organization", "id", "numeric")],
          [uniqueKey("organization", ["id"])]
        ),
        "legacy-rbac-assignment": dataset(
          "legacy-rbac-assignment-page/v1",
          ["auth_assignment", "auth_item", "user"],
          [cursor("auth_assignment", "user_id", "numeric-via-user-id"), cursor("auth_assignment", "item_name", "utf8-binary")],
          [
            uniqueKey("auth_assignment", ["item_name", "user_id"]),
            uniqueKey("auth_item", ["name"], "join-cardinality"),
            uniqueKey("user", ["id"], "join-cardinality")
          ],
          [fixed("auth_item", "type")]
        ),
        "legacy-rbac-edge": dataset(
          "legacy-rbac-edge-page/v1",
          ["auth_item_child"],
          [cursor("auth_item_child", "parent", "utf8-binary"), cursor("auth_item_child", "child", "utf8-binary")],
          [uniqueKey("auth_item_child", ["parent", "child"])]
        ),
        "legacy-rbac-item": dataset(
          "legacy-rbac-item-page/v1",
          ["auth_item"],
          [cursor("auth_item", "name", "utf8-binary")],
          [uniqueKey("auth_item", ["name"])],
          [fixed("auth_item", "type")]
        ),
        "legacy-role-assignment": dataset(
          "legacy-role-assignment-page/v3",
          ["auth_assignment", "auth_item", "user"],
          [cursor("auth_assignment", "user_id", "numeric-via-user-id"), cursor("auth_assignment", "item_name", "utf8-binary")],
          [
            uniqueKey("auth_assignment", ["item_name", "user_id"]),
            uniqueKey("auth_item", ["name"], "join-cardinality"),
            uniqueKey("user", ["id"], "join-cardinality")
          ],
          [fixed("auth_item", "type")]
        ),
        "legacy-subject-universe": dataset(
          "legacy-subject-universe-page/v3",
          ["user"],
          [cursor("user", "id", "numeric")],
          [uniqueKey("user", ["id"])]
        )
      }),
      tables: Object.freeze({
        organization: table(["id", "name", "title", "created_at", "updated_at"]),
        user: table(["id", "status"]),
        user_organization: table(["user_id", "organization_id"]),
        auth_assignment: table(["item_name", "user_id"]),
        auth_item: table(["name", "type", "description", "rule_name"]),
        auth_item_child: table(["parent", "child"])
      })
    }),
    Object.freeze({
      componentId: "identity" as const,
      datasets: Object.freeze({
        "identity-iam-item-relation": dataset(
          "identity-iam-item-relation-page/v1",
          ["identity_iam_item_relations"],
          [
            cursor("identity_iam_item_relations", "parent_name", "utf8-binary"),
            cursor("identity_iam_item_relations", "child_name", "utf8-binary")
          ],
          [uniqueKey("identity_iam_item_relations", ["policy_checksum", "parent_name", "child_name"])],
          [
            fixed("identity_iam_item_relations", "policy_checksum"),
            fixed("identity_iam_item_relations", "source"),
            fixed("identity_iam_item_relations", "status")
          ]
        ),
        "identity-iam-permission": dataset(
          "identity-iam-permission-page/v1",
          ["identity_iam_permissions"],
          [cursor("identity_iam_permissions", "permission_name", "utf8-binary")],
          [uniqueKey("identity_iam_permissions", ["policy_checksum", "permission_name"])],
          [
            fixed("identity_iam_permissions", "policy_checksum"),
            fixed("identity_iam_permissions", "source"),
            fixed("identity_iam_permissions", "status")
          ]
        ),
        "identity-iam-policy-version": dataset(
          "identity-iam-policy-version-page/v1",
          ["identity_iam_policy_versions"],
          [cursor("identity_iam_policy_versions", "checksum", "utf8-binary")],
          [uniqueKey("identity_iam_policy_versions", ["checksum"])],
          [
            fixed("identity_iam_policy_versions", "checksum"),
            fixed("identity_iam_policy_versions", "source"),
            fixed("identity_iam_policy_versions", "status")
          ]
        ),
        "identity-iam-role": dataset(
          "identity-iam-role-page/v1",
          ["identity_iam_roles"],
          [cursor("identity_iam_roles", "role_name", "utf8-binary")],
          [uniqueKey("identity_iam_roles", ["policy_checksum", "role_name"])],
          [
            fixed("identity_iam_roles", "policy_checksum"),
            fixed("identity_iam_roles", "source"),
            fixed("identity_iam_roles", "status")
          ]
        ),
        "identity-iam-subject-assignment": dataset(
          "identity-iam-subject-assignment-page/v1",
          ["identity_iam_subject_assignments"],
          [
            cursor("identity_iam_subject_assignments", "legacy_user_id", "numeric"),
            cursor("identity_iam_subject_assignments", "identity_user_id", "utf8-binary"),
            cursor("identity_iam_subject_assignments", "item_name", "utf8-binary")
          ],
          [uniqueKey("identity_iam_subject_assignments", ["identity_user_id", "item_name", "policy_checksum", "source"])],
          [
            fixed("identity_iam_subject_assignments", "policy_checksum"),
            fixed("identity_iam_subject_assignments", "source"),
            fixed("identity_iam_subject_assignments", "status")
          ]
        ),
        "identity-iam-subject-assignment-snapshot": dataset(
          "identity-iam-subject-assignment-snapshot-page/v1",
          ["identity_users", "identity_iam_subject_assignments"],
          [cursor("identity_users", "legacy_user_id", "numeric"), cursor("identity_users", "id", "utf8-binary")],
          [
            uniqueKey("identity_users", ["legacy_user_id"]),
            uniqueKey(
              "identity_iam_subject_assignments",
              ["identity_user_id", "item_name", "policy_checksum", "source"],
              "join-cardinality"
            )
          ],
          [
            fixed("identity_users", "source"),
            fixed("identity_users", "status"),
            fixed("identity_iam_subject_assignments", "policy_checksum"),
            fixed("identity_iam_subject_assignments", "source"),
            fixed("identity_iam_subject_assignments", "status")
          ]
        ),
        "identity-membership-candidate": dataset(
          "identity-membership-candidate-page/v3",
          ["identity_organization_memberships_candidate"],
          [
            cursor("identity_organization_memberships_candidate", "legacy_user_id", "numeric"),
            cursor("identity_organization_memberships_candidate", "legacy_organization_id", "numeric"),
            cursor("identity_organization_memberships_candidate", "identity_user_id", "utf8-binary"),
            cursor("identity_organization_memberships_candidate", "identity_organization_id", "utf8-binary"),
            cursor("identity_organization_memberships_candidate", "operation_key", "utf8-binary")
          ],
          [uniqueKey("identity_organization_memberships_candidate", ["identity_user_id", "identity_organization_id"])],
          [
            fixed("identity_organization_memberships_candidate", "source"),
            fixed("identity_organization_memberships_candidate", "candidate_status")
          ]
        ),
        "identity-membership-candidate-snapshot": dataset(
          "identity-membership-candidate-snapshot-page/v1",
          ["identity_organization_membership_snapshots"],
          [
            cursor("identity_organization_membership_snapshots", "legacy_user_id", "numeric"),
            cursor("identity_organization_membership_snapshots", "operation_key", "utf8-binary")
          ],
          [uniqueKey("identity_organization_membership_snapshots", ["legacy_user_id"])],
          [
            fixed("identity_organization_membership_snapshots", "source"),
            fixed("identity_organization_membership_snapshots", "candidate_status")
          ]
        ),
        "identity-membership-shadow": dataset(
          "identity-membership-shadow-page/v3",
          ["identity_organization_memberships_shadow"],
          [
            cursor("identity_organization_memberships_shadow", "legacy_user_id", "numeric"),
            cursor("identity_organization_memberships_shadow", "organization_id", "numeric")
          ],
          [uniqueKey("identity_organization_memberships_shadow", ["legacy_user_id", "organization_id", "source"])],
          [
            fixed("identity_organization_memberships_shadow", "source"),
            fixed("identity_organization_memberships_shadow", "status")
          ]
        ),
        "identity-organization-candidate": dataset(
          "identity-organization-candidate-page/v3",
          ["identity_organizations_candidate"],
          [cursor("identity_organizations_candidate", "legacy_organization_id", "numeric")],
          [uniqueKey("identity_organizations_candidate", ["legacy_organization_id"])],
          [
            fixed("identity_organizations_candidate", "source"),
            fixed("identity_organizations_candidate", "candidate_status")
          ]
        ),
        "identity-organization-id-map": dataset(
          "identity-organization-id-map-page/v3",
          ["identity_organization_id_map"],
          [cursor("identity_organization_id_map", "legacy_organization_id", "numeric")],
          [uniqueKey("identity_organization_id_map", ["legacy_organization_id"])],
          [
            fixed("identity_organization_id_map", "source"),
            fixed("identity_organization_id_map", "mapping_status")
          ]
        ),
        "identity-role-shadow": dataset(
          "identity-role-shadow-page/v3",
          ["identity_role_assignments_shadow"],
          [
            cursor("identity_role_assignments_shadow", "legacy_user_id", "numeric"),
            cursor("identity_role_assignments_shadow", "role_name", "utf8-binary")
          ],
          [uniqueKey("identity_role_assignments_shadow", ["legacy_user_id", "role_name", "source"])],
          [
            fixed("identity_role_assignments_shadow", "source"),
            fixed("identity_role_assignments_shadow", "status")
          ]
        ),
        "identity-subject-universe": dataset(
          "identity-subject-universe-page/v3",
          ["identity_users"],
          [cursor("identity_users", "legacy_user_id", "numeric")],
          [uniqueKey("identity_users", ["legacy_user_id"])],
          [fixed("identity_users", "source"), fixed("identity_users", "status")]
        )
      }),
      tables: Object.freeze({
        identity_users: table(["id", "legacy_user_id", "status", "source"]),
        identity_organizations_candidate: table([
          "legacy_organization_id", "identity_organization_id", "name", "title", "source", "candidate_status"
        ]),
        identity_organization_id_map: table([
          "legacy_organization_id", "identity_organization_id", "source", "mapping_status"
        ]),
        identity_organization_memberships_shadow: table([
          "legacy_user_id", "organization_id", "organization_role", "source", "status"
        ]),
        identity_organization_memberships_candidate: table([
          "legacy_user_id", "legacy_organization_id", "identity_user_id", "identity_organization_id",
          "organization_role", "source", "candidate_status", "operation_key"
        ]),
        identity_organization_membership_snapshots: table([
          "identity_user_id", "legacy_user_id", "operation_key", "organization_count", "source", "candidate_status"
        ]),
        identity_role_assignments_shadow: table(["legacy_user_id", "role_name", "source", "status"]),
        identity_iam_policy_versions: table([
          "checksum", "source", "status", "role_count", "permission_count", "relation_count"
        ]),
        identity_iam_roles: table(["policy_checksum", "role_name", "description", "source", "status"]),
        identity_iam_permissions: table([
          "policy_checksum", "permission_name", "description", "source", "status"
        ]),
        identity_iam_item_relations: table([
          "policy_checksum", "parent_name", "parent_type", "child_name", "child_type", "source", "status"
        ]),
        identity_iam_subject_assignments: table([
          "id", "identity_user_id", "legacy_user_id", "item_name", "item_type", "policy_checksum", "source", "status"
        ])
      })
    }),
    Object.freeze({
      componentId: "plugin" as const,
      datasets: Object.freeze({
        "plugin-registry": dataset(
          "plugin-registry-page/v3",
          ["plugins"],
          [cursor("plugins", "id", "utf8-binary")],
          [uniqueKey("plugins", ["id"])]
        )
      }),
      tables: Object.freeze({
        plugins: table(["id", "enabled", "access_scope", "organization_name"])
      })
    })
  ] satisfies readonly PhysicalComponentRequirement[])
});

export const ORGANIZATION_RECONCILIATION_DEVELOP_PHYSICAL_CATALOG_SHA256 = digest(
  "physical-catalog/v1",
  ORGANIZATION_RECONCILIATION_DEVELOP_PHYSICAL_CATALOG
);
export const ORGANIZATION_RECONCILIATION_DEVELOP_PHYSICAL_CATALOG_PINNED_SHA256 =
  "3d4243a7a894203bd5371d5f9ebd41e45d54e2daba8a631f0e4793b58cce68b3" as const;

export interface OrganizationReconciliationDevelopPhysicalProbeDependencies {
  readonly legacyConnectionFactory: MysqlRepeatableReadSnapshotConnectionFactory;
  readonly identityConnectionFactory: MysqlRepeatableReadSnapshotConnectionFactory;
  readonly pluginConnectionFactory: MysqlRepeatableReadSnapshotConnectionFactory;
  readonly expectedDatabaseUsers: Readonly<Record<OrganizationReconciliationMysqlRawComponentId, string>>;
  readonly buildRevision: string;
}

interface PhysicalProbePass {
  readonly databaseBindingPassed: boolean;
  readonly grantPassed: boolean;
  readonly snapshotProtocolPassed: boolean;
  readonly tableShapePassed: boolean;
  readonly columnShapePassed: boolean;
  readonly deterministicUniqueKeysPassed: boolean;
  readonly collationPassed: boolean;
  readonly binaryOrderWitnessPassed: boolean;
  readonly sourceIdentitySha256: string;
  readonly grantScopeSha256: string;
  readonly tableShapeSha256: string;
  readonly columnShapeSha256: string;
  readonly indexShapeSha256: string;
  readonly snapshotProtocolSha256: string;
  readonly binaryOrderWitnessSha256: string;
  readonly observedTableCount: number;
  readonly observedColumnCount: number;
  readonly observedIndexCount: number;
}

export interface OrganizationReconciliationDevelopPhysicalProbeReport {
  readonly contract: typeof ORGANIZATION_RECONCILIATION_DEVELOP_PHYSICAL_PROBE_CONTRACT;
  readonly environment: "xrteeth-develop";
  readonly mode: "read-only";
  readonly assuranceScope: "compiled-21-dataset-physical-metadata-and-deterministic-cursor-keys-only";
  readonly optimizerOrderPerformanceClaimed: false;
  readonly currentTransactionVariableIntrospectionClaimed: false;
  readonly sourceCatalogSha256: string;
  readonly statementCatalogSha256: string;
  readonly physicalCatalogSha256: string;
  readonly buildRevisionSha256: string | null;
  readonly componentCount: 3;
  readonly datasetCount: 21;
  readonly physicalTableCount: 19;
  readonly derivedDatasetCount: 1;
  readonly completedProbePassCount: number;
  readonly components: readonly {
    readonly componentId: OrganizationReconciliationMysqlRawComponentId;
    readonly datasetCount: number;
    readonly physicalTableCount: number;
    readonly requiredColumnCount: number;
    readonly requiredDeterministicUniqueKeyCount: number;
    readonly completedProbePassCount: number;
    readonly databaseBindingPassed: boolean;
    readonly grantPassed: boolean;
    readonly snapshotProtocolPassed: boolean;
    readonly tableShapePassed: boolean;
    readonly columnShapePassed: boolean;
    readonly deterministicUniqueKeysPassed: boolean;
    readonly collationPassed: boolean;
    readonly binaryOrderWitnessPassed: boolean;
    readonly aBAligned: boolean;
    readonly sourceIdentitySha256: string | null;
    readonly grantScopeSha256: string | null;
    readonly physicalSchemaSha256: string | null;
    readonly physicalIndexSha256: string | null;
    readonly snapshotProtocolSha256: string | null;
    readonly binaryOrderWitnessSha256: string | null;
    readonly observedTableCount: number;
    readonly observedColumnCount: number;
    readonly observedIndexCount: number;
  }[];
  readonly failedIds: readonly string[];
  readonly passed: boolean;
  readonly productionReady: false;
}

export async function runOrganizationReconciliationDevelopPhysicalProbe(
  dependencies: OrganizationReconciliationDevelopPhysicalProbeDependencies
): Promise<OrganizationReconciliationDevelopPhysicalProbeReport> {
  const failedIds: string[] = [];
  if (!compiledCatalogMatchesPhysicalCatalog()) failedIds.push("compiled-catalog:physical-closure-mismatch");
  const buildRevisionSha256 = /^[a-f0-9]{40}$/.test(dependencies.buildRevision)
    ? digest("build-revision/v1", dependencies.buildRevision)
    : null;
  if (buildRevisionSha256 === null) failedIds.push("build-revision:invalid");

  const inputs = [
    Object.freeze({
      componentId: "legacy-main" as const,
      factory: dependencies.legacyConnectionFactory,
      expectedDatabaseUser: dependencies.expectedDatabaseUsers["legacy-main"]
    }),
    Object.freeze({
      componentId: "identity" as const,
      factory: dependencies.identityConnectionFactory,
      expectedDatabaseUser: dependencies.expectedDatabaseUsers.identity
    }),
    Object.freeze({
      componentId: "plugin" as const,
      factory: dependencies.pluginConnectionFactory,
      expectedDatabaseUser: dependencies.expectedDatabaseUsers.plugin
    })
  ];
  const components: Array<OrganizationReconciliationDevelopPhysicalProbeReport["components"][number]> = [];

  for (const input of inputs) {
    const requirement = physicalRequirement(input.componentId);
    const passes: Array<PhysicalProbePass | null> = [];
    for (const passId of ["a", "b"] as const) {
      try {
        const pass = await inspectPhysicalProbePass(
          requirement,
          input.factory,
          input.expectedDatabaseUser
        );
        passes.push(pass);
        appendPassFailures(failedIds, input.componentId, passId, pass);
      } catch {
        passes.push(null);
        failedIds.push(`${input.componentId}:${passId}:probe-unavailable`);
      }
    }
    const completed = passes.filter((candidate): candidate is PhysicalProbePass => candidate !== null);
    const aBAligned = completed.length === 2 && samePassEvidence(completed[0], completed[1]);
    if (!aBAligned) failedIds.push(`${input.componentId}:a-b-alignment`);
    const aligned = aBAligned ? completed[0] : null;
    const all = (field: keyof PhysicalProbePass): boolean =>
      completed.length === 2 && completed.every((candidate) => candidate[field] === true);
    components.push(Object.freeze({
      componentId: input.componentId,
      datasetCount: Object.keys(requirement.datasets).length,
      physicalTableCount: Object.keys(requirement.tables).length,
      requiredColumnCount: Object.values(requirement.tables)
        .reduce((sum, candidate) => sum + candidate.columns.length, 0),
      requiredDeterministicUniqueKeyCount: Object.values(requirement.datasets)
        .reduce((sum, candidate) => sum + candidate.deterministicUniqueKeys.length, 0),
      completedProbePassCount: completed.length,
      databaseBindingPassed: all("databaseBindingPassed"),
      grantPassed: all("grantPassed"),
      snapshotProtocolPassed: all("snapshotProtocolPassed"),
      tableShapePassed: all("tableShapePassed"),
      columnShapePassed: all("columnShapePassed"),
      deterministicUniqueKeysPassed: all("deterministicUniqueKeysPassed"),
      collationPassed: all("collationPassed"),
      binaryOrderWitnessPassed: all("binaryOrderWitnessPassed"),
      aBAligned,
      sourceIdentitySha256: aligned?.sourceIdentitySha256 ?? null,
      grantScopeSha256: aligned?.grantScopeSha256 ?? null,
      physicalSchemaSha256: aligned === null
        ? null
        : digest("physical-schema/v1", [aligned.tableShapeSha256, aligned.columnShapeSha256]),
      physicalIndexSha256: aligned?.indexShapeSha256 ?? null,
      snapshotProtocolSha256: aligned?.snapshotProtocolSha256 ?? null,
      binaryOrderWitnessSha256: aligned?.binaryOrderWitnessSha256 ?? null,
      observedTableCount: aligned?.observedTableCount ?? 0,
      observedColumnCount: aligned?.observedColumnCount ?? 0,
      observedIndexCount: aligned?.observedIndexCount ?? 0
    }));
  }

  const uniqueFailedIds = Object.freeze([...new Set(failedIds)].sort(binaryCompare));
  return Object.freeze({
    contract: ORGANIZATION_RECONCILIATION_DEVELOP_PHYSICAL_PROBE_CONTRACT,
    environment: "xrteeth-develop",
    mode: "read-only",
    assuranceScope: "compiled-21-dataset-physical-metadata-and-deterministic-cursor-keys-only",
    optimizerOrderPerformanceClaimed: false,
    currentTransactionVariableIntrospectionClaimed: false,
    sourceCatalogSha256: ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG_SHA256,
    statementCatalogSha256: ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG.statementCatalogSha256,
    physicalCatalogSha256: ORGANIZATION_RECONCILIATION_DEVELOP_PHYSICAL_CATALOG_SHA256,
    buildRevisionSha256,
    componentCount: 3,
    datasetCount: 21,
    physicalTableCount: 19,
    derivedDatasetCount: 1,
    completedProbePassCount: components.reduce((sum, component) => sum + component.completedProbePassCount, 0),
    components: Object.freeze(components),
    failedIds: uniqueFailedIds,
    passed: uniqueFailedIds.length === 0,
    productionReady: false
  });
}

async function inspectPhysicalProbePass(
  requirement: PhysicalComponentRequirement,
  factory: MysqlRepeatableReadSnapshotConnectionFactory,
  expectedDatabaseUser: string
): Promise<PhysicalProbePass> {
  if (!/^[A-Za-z0-9_.-]{1,64}$/.test(expectedDatabaseUser)) throw new Error("invalid-probe-input");
  const connection = await factory();
  let transactionStarted = false;
  let failed = false;
  try {
    const grants = captureGrants(rows(await connection.query(SHOW_CURRENT_GRANTS)));
    const grantInspection = inspectGrants(requirement, grants, expectedDatabaseUser);
    await connection.query(SET_SESSION_REPEATABLE_READ);
    await connection.query(START_READ_ONLY);
    transactionStarted = true;
    const sourceIdentity = captureSourceIdentity(
      requirement.componentId,
      rows(await connection.query(SOURCE_IDENTITY_QUERY)),
      expectedDatabaseUser
    );
    const grantPassed = grantInspection.passed &&
      grantInspection.principalAccount === sourceIdentity.currentAccount;
    const sessionIsolation = captureSessionIsolation(rows(await connection.query(SESSION_ISOLATION_QUERY)));
    const tables = captureTableRows(rows(await connection.query(tableQuery(requirement))));
    const columns = captureColumnRows(rows(await connection.query(columnQuery(requirement))));
    const indexes = captureIndexRows(rows(await connection.query(indexQuery(requirement))));
    const witness = captureUtf8BinaryOrderWitness(rows(await connection.query(UTF8_BINARY_ORDER_WITNESS_QUERY)));
    const tableShapePassed = inspectTableShape(requirement, tables);
    const columnShapePassed = inspectColumnShape(requirement, columns);
    const deterministicUniqueKeysPassed = inspectDeterministicUniqueKeys(requirement, indexes);
    const collationPassed = inspectCollation(tables, columns);
    return Object.freeze({
      databaseBindingPassed: sourceIdentity.passed,
      grantPassed,
      snapshotProtocolPassed: sessionIsolation.passed,
      tableShapePassed,
      columnShapePassed,
      deterministicUniqueKeysPassed,
      collationPassed,
      binaryOrderWitnessPassed: witness.passed,
      sourceIdentitySha256: digest("source-identity/v1", sourceIdentity.canonical),
      grantScopeSha256: digest("grant-scope/v1", grants),
      tableShapeSha256: digest("table-shape/v1", tables),
      columnShapeSha256: digest("column-shape/v1", columns),
      indexShapeSha256: digest("index-shape/v1", indexes),
      snapshotProtocolSha256: digest("snapshot-protocol/v1", Object.freeze({
        setSessionIsolation: SET_SESSION_REPEATABLE_READ,
        startReadOnlySnapshot: START_READ_ONLY,
        observedSessionIsolation: sessionIsolation.canonical
      })),
      binaryOrderWitnessSha256: digest("utf8-binary-order-witness/v1", witness.canonical),
      observedTableCount: tables.length,
      observedColumnCount: columns.length,
      observedIndexCount: indexes.length
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
    if (cleanupFailed && !failed) throw new Error("physical-probe-cleanup-failed");
  }
}

function appendPassFailures(
  failures: string[],
  componentId: OrganizationReconciliationMysqlRawComponentId,
  passId: "a" | "b",
  pass: PhysicalProbePass
): void {
  const checks = [
    ["database-binding", pass.databaseBindingPassed],
    ["grant-bound", pass.grantPassed],
    ["snapshot-protocol", pass.snapshotProtocolPassed],
    ["table-shape", pass.tableShapePassed],
    ["column-shape", pass.columnShapePassed],
    ["deterministic-unique-keys", pass.deterministicUniqueKeysPassed],
    ["collation", pass.collationPassed],
    ["utf8-binary-order-witness", pass.binaryOrderWitnessPassed]
  ] as const;
  for (const [checkId, passed] of checks) if (!passed) failures.push(`${componentId}:${passId}:${checkId}`);
}

function samePassEvidence(left: PhysicalProbePass, right: PhysicalProbePass): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function compiledCatalogMatchesPhysicalCatalog(): boolean {
  if (ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG.components.length !== 3 ||
    ORGANIZATION_RECONCILIATION_DEVELOP_PHYSICAL_CATALOG.components.length !== 3) return false;
  let datasetCount = 0;
  const physicalTables = new Set<string>();
  const statementIds = new Set<string>();
  for (const physical of ORGANIZATION_RECONCILIATION_DEVELOP_PHYSICAL_CATALOG.components) {
    const compiled = ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG.components
      .find((candidate) => candidate.componentId === physical.componentId);
    if (compiled === undefined) return false;
    const compiledIds = compiled.datasetCatalog.datasets.map((candidate) => candidate.datasetId).sort(binaryCompare);
    const physicalIds = Object.keys(physical.datasets).sort(binaryCompare);
    if (JSON.stringify(compiledIds) !== JSON.stringify(physicalIds)) return false;
    datasetCount += physicalIds.length;
    for (const name of Object.keys(physical.tables)) physicalTables.add(`${physical.componentId}\u001f${name}`);
    const componentTables = physical.tables as Readonly<Record<string, PhysicalTableRequirement>>;
    for (const requirement of Object.values(physical.datasets) as readonly PhysicalDatasetRequirement[]) {
      if (statementIds.has(requirement.statementId) ||
        !Object.prototype.hasOwnProperty.call(ORGANIZATION_RECONCILIATION_MYSQL_STATEMENTS, requirement.statementId) ||
        !validPhysicalDatasetRequirement(requirement, componentTables)) return false;
      statementIds.add(requirement.statementId);
    }
  }
  const compiledStatementIds = Object.keys(ORGANIZATION_RECONCILIATION_MYSQL_STATEMENTS).sort(binaryCompare);
  const catalogStatementIds = [...statementIds].sort(binaryCompare);
  const derived = ORGANIZATION_RECONCILIATION_DEVELOP_PHYSICAL_CATALOG.derivedDatasets[
    "identity-iam-subject-assignment-snapshot"
  ];
  return datasetCount === ORGANIZATION_RECONCILIATION_DEVELOP_PHYSICAL_CATALOG.datasetCount &&
    physicalTables.size === ORGANIZATION_RECONCILIATION_DEVELOP_PHYSICAL_CATALOG.uniquePhysicalTableCount &&
    JSON.stringify(compiledStatementIds) === JSON.stringify(catalogStatementIds) &&
    ORGANIZATION_RECONCILIATION_DEVELOP_PHYSICAL_CATALOG.derivedDatasetCount === 1 &&
    derived.relation === "left-join" &&
    derived.requiresDedicatedPhysicalTable === false &&
    JSON.stringify(derived.tables) === JSON.stringify(["identity_users", "identity_iam_subject_assignments"]);
}

function validPhysicalDatasetRequirement(
  requirement: PhysicalDatasetRequirement,
  componentTables: Readonly<Record<string, PhysicalTableRequirement>>
): boolean {
  const tableNames = new Set(requirement.tables);
  if (requirement.tables.length < 1 || tableNames.size !== requirement.tables.length ||
    requirement.tables.some((name) => componentTables[name] === undefined) ||
    requirement.cursorOrder.length < 1 || requirement.deterministicUniqueKeys.length < 1 ||
    !requirement.deterministicUniqueKeys.some((key) => key.purpose === "cursor-uniqueness")) return false;
  const validColumn = (tableName: string, columnName: string): boolean =>
    tableNames.has(tableName) && componentTables[tableName]?.columns.includes(columnName) === true;
  if (requirement.cursorOrder.some((entry) => !validColumn(entry.tableName, entry.columnName)) ||
    requirement.fixedEqualityColumns.some((entry) => !validColumn(entry.tableName, entry.columnName))) return false;
  const cursorRefs = requirement.cursorOrder.map((entry) => `${entry.tableName}\u001f${entry.columnName}`);
  if (new Set(cursorRefs).size !== cursorRefs.length) return false;
  const deterministicClosure = new Set([
    ...cursorRefs,
    ...requirement.fixedEqualityColumns.map((entry) => `${entry.tableName}\u001f${entry.columnName}`)
  ]);
  for (const key of requirement.deterministicUniqueKeys) {
    if (!tableNames.has(key.tableName) || key.columns.length < 1 ||
      new Set(key.columns).size !== key.columns.length ||
      key.columns.some((columnName) => !validColumn(key.tableName, columnName)) ||
      (key.purpose === "cursor-uniqueness" && key.columns.some((columnName) =>
        !deterministicClosure.has(`${key.tableName}\u001f${columnName}`)))) return false;
  }
  return true;
}

function physicalRequirement(componentId: OrganizationReconciliationMysqlRawComponentId): PhysicalComponentRequirement {
  const requirement = ORGANIZATION_RECONCILIATION_DEVELOP_PHYSICAL_CATALOG.components
    .find((candidate) => candidate.componentId === componentId);
  if (requirement === undefined) throw new Error("physical-catalog-missing");
  return requirement;
}

function tableQuery(requirement: PhysicalComponentRequirement): string {
  return `SELECT TABLE_NAME AS table_name, TABLE_TYPE AS table_type, COALESCE(ENGINE, '') AS engine, COALESCE(TABLE_COLLATION, '') AS table_collation FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME IN (${sqlNames(requirement)}) ORDER BY CAST(TABLE_NAME AS BINARY) ASC LIMIT ${MAX_TABLE_ROWS + 1}`;
}

function columnQuery(requirement: PhysicalComponentRequirement): string {
  return `SELECT TABLE_NAME AS table_name, COLUMN_NAME AS column_name, DATA_TYPE AS data_type, COLUMN_TYPE AS column_type, IS_NULLABLE AS is_nullable, COALESCE(CHARACTER_SET_NAME, '') AS character_set_name, COALESCE(COLLATION_NAME, '') AS collation_name, ORDINAL_POSITION AS ordinal_position FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME IN (${sqlNames(requirement)}) ORDER BY CAST(TABLE_NAME AS BINARY) ASC, ORDINAL_POSITION ASC LIMIT ${MAX_COLUMN_ROWS + 1}`;
}

function indexQuery(requirement: PhysicalComponentRequirement): string {
  return `SELECT TABLE_NAME AS table_name, INDEX_NAME AS index_name, NON_UNIQUE AS non_unique, SEQ_IN_INDEX AS seq_in_index, COLUMN_NAME AS column_name, COALESCE(COLLATION, '') AS index_collation, COALESCE(SUB_PART, 0) AS sub_part, INDEX_TYPE AS index_type, IS_VISIBLE AS is_visible FROM INFORMATION_SCHEMA.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME IN (${sqlNames(requirement)}) ORDER BY CAST(TABLE_NAME AS BINARY) ASC, CAST(INDEX_NAME AS BINARY) ASC, SEQ_IN_INDEX ASC LIMIT ${MAX_INDEX_ROWS + 1}`;
}

function sqlNames(requirement: PhysicalComponentRequirement): string {
  return Object.keys(requirement.tables).sort(binaryCompare).map((name) => `'${name}'`).join(", ");
}

interface CapturedTableRow {
  readonly tableName: string;
  readonly tableType: string;
  readonly engine: string;
  readonly tableCollation: string;
}

interface CapturedColumnRow {
  readonly tableName: string;
  readonly columnName: string;
  readonly dataType: string;
  readonly columnType: string;
  readonly nullable: string;
  readonly characterSet: string;
  readonly collation: string;
  readonly ordinal: number;
}

interface CapturedIndexRow {
  readonly tableName: string;
  readonly indexName: string;
  readonly nonUnique: number;
  readonly sequence: number;
  readonly columnName: string;
  readonly collation: string;
  readonly subPart: number;
  readonly indexType: string;
  readonly visible: string;
}

function captureTableRows(candidate: readonly unknown[]): readonly CapturedTableRow[] {
  bounded(candidate, 0, MAX_TABLE_ROWS);
  const output = candidate.map((value) => {
    const row = record(value, ["table_name", "table_type", "engine", "table_collation"]);
    return Object.freeze({
      tableName: metadata(row.table_name),
      tableType: metadata(row.table_type),
      engine: metadata(row.engine),
      tableCollation: metadata(row.table_collation)
    });
  });
  requireOrdered(output, (row) => [row.tableName]);
  return Object.freeze(output);
}

function captureColumnRows(candidate: readonly unknown[]): readonly CapturedColumnRow[] {
  bounded(candidate, 0, MAX_COLUMN_ROWS);
  const output = candidate.map((value) => {
    const row = record(value, [
      "table_name", "column_name", "data_type", "column_type", "is_nullable",
      "character_set_name", "collation_name", "ordinal_position"
    ]);
    return Object.freeze({
      tableName: metadata(row.table_name),
      columnName: metadata(row.column_name),
      dataType: metadata(row.data_type),
      columnType: metadata(row.column_type),
      nullable: metadata(row.is_nullable),
      characterSet: optionalMetadata(row.character_set_name),
      collation: optionalMetadata(row.collation_name),
      ordinal: positiveInteger(row.ordinal_position)
    });
  });
  requireOrdered(output, (row) => [row.tableName, row.ordinal]);
  return Object.freeze(output);
}

function captureIndexRows(candidate: readonly unknown[]): readonly CapturedIndexRow[] {
  bounded(candidate, 0, MAX_INDEX_ROWS);
  const output = candidate.map((value) => {
    const row = record(value, [
      "table_name", "index_name", "non_unique", "seq_in_index", "column_name",
      "index_collation", "sub_part", "index_type", "is_visible"
    ]);
    return Object.freeze({
      tableName: metadata(row.table_name),
      indexName: metadata(row.index_name),
      nonUnique: zeroOrOne(row.non_unique),
      sequence: positiveInteger(row.seq_in_index),
      columnName: metadata(row.column_name),
      collation: optionalMetadata(row.index_collation),
      subPart: nonNegativeInteger(row.sub_part),
      indexType: metadata(row.index_type),
      visible: metadata(row.is_visible)
    });
  });
  requireOrdered(output, (row) => [row.tableName, row.indexName, row.sequence]);
  return Object.freeze(output);
}

function inspectTableShape(
  requirement: PhysicalComponentRequirement,
  rows: readonly CapturedTableRow[]
): boolean {
  const expected = Object.keys(requirement.tables).sort(binaryCompare);
  return JSON.stringify(rows.map((row) => row.tableName)) === JSON.stringify(expected) &&
    rows.every((row) => row.tableType === "BASE TABLE" && row.engine.toUpperCase() === "INNODB");
}

function inspectColumnShape(
  requirement: PhysicalComponentRequirement,
  rows: readonly CapturedColumnRow[]
): boolean {
  return Object.entries(requirement.tables).every(([tableName, expected]) =>
    expected.columns.every((columnName) =>
      rows.some((row) => row.tableName === tableName && row.columnName === columnName)
    )
  );
}

function inspectDeterministicUniqueKeys(
  requirement: PhysicalComponentRequirement,
  rows: readonly CapturedIndexRow[]
): boolean {
  const byTable = new Map<string, Map<string, CapturedIndexRow[]>>();
  for (const row of rows) {
    const byIndex = byTable.get(row.tableName) ?? new Map<string, CapturedIndexRow[]>();
    const entries = byIndex.get(row.indexName) ?? [];
    entries.push(row);
    byIndex.set(row.indexName, entries);
    byTable.set(row.tableName, byIndex);
  }
  return Object.values(requirement.datasets).every((datasetRequirement) =>
    datasetRequirement.deterministicUniqueKeys.every((requiredKey) =>
      [...(byTable.get(requiredKey.tableName)?.values() ?? [])].some((entries) =>
        entries.length === requiredKey.columns.length &&
        entries.every((entry, index) =>
          entry.sequence === index + 1 &&
          entry.columnName === requiredKey.columns[index] &&
          entry.nonUnique === 0 &&
          entry.subPart === 0 &&
          entry.collation.toUpperCase() === "A" &&
          entry.indexType.toUpperCase() === "BTREE" &&
          entry.visible.toUpperCase() === "YES"
        )
      )
    )
  );
}

function inspectCollation(
  tables: readonly CapturedTableRow[],
  columns: readonly CapturedColumnRow[]
): boolean {
  return tables.every((row) => /^(?:utf8|utf8mb3|utf8mb4)_/i.test(row.tableCollation)) &&
    columns.every((row) => {
      if (row.characterSet === "" && row.collation === "") return true;
      return (row.characterSet === "utf8" || row.characterSet === "utf8mb3" || row.characterSet === "utf8mb4") &&
        row.collation.startsWith(`${row.characterSet}_`);
    });
}

function captureSourceIdentity(
  componentId: OrganizationReconciliationMysqlRawComponentId,
  candidate: readonly unknown[],
  expectedDatabaseUser: string
): { readonly passed: boolean; readonly canonical: readonly string[]; readonly currentAccount: string } {
  bounded(candidate, 1, 1);
  const row = record(candidate[0], ["database_name", "current_user"]);
  const databaseName = metadata(row.database_name);
  const currentUser = metadata(row.current_user);
  const separator = currentUser.lastIndexOf("@");
  const user = separator > 0 ? currentUser.slice(0, separator) : "";
  const host = separator > 0 ? currentUser.slice(separator + 1) : "";
  return Object.freeze({
    passed: databaseName === EXPECTED_DATABASES[componentId] && user === expectedDatabaseUser && host.length > 0,
    canonical: Object.freeze([databaseName, currentUser]),
    currentAccount: `${user}@${host}`
  });
}

function captureSessionIsolation(candidate: readonly unknown[]): {
  readonly passed: boolean;
  readonly canonical: readonly string[];
} {
  bounded(candidate, 1, 1);
  const row = record(candidate[0], ["session_transaction_isolation"]);
  const isolation = metadata(row.session_transaction_isolation).toUpperCase().replace(/_/g, "-").replace(/ /g, "-");
  return Object.freeze({
    passed: isolation === "REPEATABLE-READ",
    canonical: Object.freeze([isolation])
  });
}

function captureUtf8BinaryOrderWitness(candidate: readonly unknown[]): {
  readonly passed: boolean;
  readonly canonical: Readonly<{
    observedHex: readonly string[];
    nodeBufferOrderHex: readonly string[];
  }>;
} {
  bounded(candidate, UTF8_BINARY_ORDER_WITNESS_HEX.length, UTF8_BINARY_ORDER_WITNESS_HEX.length);
  const observedHex = Object.freeze(candidate.map((value) => {
    const row = record(value, ["value_hex"]);
    const hex = metadata(row.value_hex).toUpperCase();
    if (!/^(?:[A-F0-9]{2}){1,8}$/.test(hex)) throw new Error("invalid-binary-order-witness");
    return hex;
  }));
  const nodeBufferOrderHex = Object.freeze([...UTF8_BINARY_ORDER_WITNESS_HEX]
    .sort((left, right) => Buffer.compare(Buffer.from(left, "hex"), Buffer.from(right, "hex"))));
  return Object.freeze({
    passed: JSON.stringify(observedHex) === JSON.stringify(nodeBufferOrderHex),
    canonical: Object.freeze({ observedHex, nodeBufferOrderHex })
  });
}

function captureGrants(candidate: readonly unknown[]): readonly string[] {
  bounded(candidate, 1, MAX_GRANT_ROWS);
  const grants = candidate.map((value) => {
    const rawGrant = singleStringProperty(value);
    const normalized = rawGrant.replace(/\s+/g, " ").trim();
    if (normalized.length < 1 || normalized.length > MAX_GRANT_LENGTH || normalized.normalize("NFC") !== normalized) {
      throw new Error("invalid-grant-row");
    }
    return normalized;
  });
  return Object.freeze(grants.sort(binaryCompare));
}

function inspectGrants(
  requirement: PhysicalComponentRequirement,
  grants: readonly string[],
  expectedDatabaseUser: string
): { readonly passed: boolean; readonly principalAccount: string | null } {
  const expectedDatabase = EXPECTED_DATABASES[requirement.componentId];
  const requiredTables = Object.keys(requirement.tables);
  const covered = new Set<string>();
  const principals = new Set<string>();
  let passed = true;
  for (const statement of grants) {
    const match = /^GRANT\s+(.+?)\s+ON\s+(\S+)\s+TO\s+(?:`([^`]+)`|'([^']+)'|([A-Za-z0-9_.-]+))@(?:`([^`]+)`|'([^']+)'|([^\s;]+))$/i.exec(statement);
    if (match === null) {
      passed = false;
      continue;
    }
    const privileges = (match[1] as string).split(",").map((value) => value.trim().toUpperCase());
    const scope = match[2] as string;
    const principalUser = (match[3] ?? match[4] ?? match[5]) as string;
    const principalHost = (match[6] ?? match[7] ?? match[8]) as string;
    principals.add(`${principalUser}\u001f${principalHost}`);
    if (principalUser !== expectedDatabaseUser || principalHost.length < 1 ||
      new Set(privileges).size !== privileges.length) {
      passed = false;
      continue;
    }
    if (privileges.length === 1 && privileges[0] === "USAGE" && scope === "*.*") continue;
    if (privileges.length < 1 || !privileges.includes("SELECT") ||
      privileges.some((value) => value !== "SELECT" && value !== "SHOW VIEW")) {
      passed = false;
      continue;
    }
    if (scope === `${expectedDatabase}.*` || scope === `\`${expectedDatabase}\`.*`) {
      for (const tableName of requiredTables) covered.add(tableName);
      continue;
    }
    const tableName = requiredTables.find((candidate) =>
      scope === `${expectedDatabase}.${candidate}` ||
      scope === `\`${expectedDatabase}\`.\`${candidate}\``
    );
    if (tableName === undefined) passed = false;
    else covered.add(tableName);
  }
  if (requiredTables.some((tableName) => !covered.has(tableName)) || principals.size !== 1) passed = false;
  const principal = principals.size === 1 ? [...principals][0] as string : null;
  return Object.freeze({
    passed,
    principalAccount: principal === null ? null : principal.replace("\u001f", "@")
  });
}

function rows(result: readonly [unknown, unknown]): readonly unknown[] {
  if (!Array.isArray(result) || !Array.isArray(result[0])) throw new Error("invalid-query-result");
  return result[0] as readonly unknown[];
}

function record(value: unknown, expectedKeys: readonly string[]): Readonly<Record<string, unknown>> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("invalid-metadata-row");
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw new Error("invalid-metadata-row");
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== "string")) throw new Error("invalid-metadata-row");
  const stringKeys = keys as string[];
  if (JSON.stringify([...stringKeys].sort(binaryCompare)) !==
    JSON.stringify([...expectedKeys].sort(binaryCompare))) throw new Error("invalid-metadata-row");
  const output = Object.create(null) as Record<string, unknown>;
  for (const key of stringKeys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !("value" in descriptor) || descriptor.enumerable !== true) {
      throw new Error("invalid-metadata-row");
    }
    Object.defineProperty(output, key, {
      value: descriptor.value,
      enumerable: true,
      configurable: false,
      writable: false
    });
  }
  return Object.freeze(output);
}

function singleStringProperty(value: unknown): string {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid-grant-row");
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw new Error("invalid-grant-row");
  const keys = Reflect.ownKeys(value);
  if (keys.length !== 1 || typeof keys[0] !== "string") throw new Error("invalid-grant-row");
  const descriptor = Object.getOwnPropertyDescriptor(value, keys[0]);
  if (descriptor === undefined || !("value" in descriptor) || descriptor.enumerable !== true ||
    typeof descriptor.value !== "string") throw new Error("invalid-grant-row");
  return descriptor.value;
}

function metadata(value: unknown): string {
  if (typeof value !== "string" || value.length < 1 || value.length > 1_024 || value.normalize("NFC") !== value) {
    throw new Error("invalid-metadata-value");
  }
  return value;
}

function optionalMetadata(value: unknown): string {
  if (value === "") return "";
  return metadata(value);
}

function positiveInteger(value: unknown): number {
  const result = nonNegativeInteger(value);
  if (result < 1) throw new Error("invalid-metadata-integer");
  return result;
}

function nonNegativeInteger(value: unknown): number {
  const normalized = typeof value === "bigint" ? value.toString() : value;
  const result = typeof normalized === "string" && /^[0-9]+$/.test(normalized) ? Number(normalized) : normalized;
  if (typeof result !== "number" || !Number.isSafeInteger(result) || result < 0) {
    throw new Error("invalid-metadata-integer");
  }
  return result;
}

function zeroOrOne(value: unknown): number {
  const result = nonNegativeInteger(value);
  if (result !== 0 && result !== 1) throw new Error("invalid-metadata-boolean");
  return result;
}

function bounded(candidate: readonly unknown[], minimum: number, maximum: number): void {
  if (candidate.length < minimum || candidate.length > maximum) throw new Error("metadata-row-limit-exceeded");
}

function requireOrdered<T>(rows: readonly T[], key: (row: T) => readonly (string | number)[]): void {
  let previous: readonly (string | number)[] | null = null;
  for (const row of rows) {
    const current = key(row);
    if (previous !== null && compareKeys(previous, current) >= 0) throw new Error("metadata-order-invalid");
    previous = current;
  }
}

function compareKeys(left: readonly (string | number)[], right: readonly (string | number)[]): number {
  for (let index = 0; index < Math.max(left.length, right.length); index += 1) {
    const a = left[index];
    const b = right[index];
    if (a === b) continue;
    if (a === undefined) return -1;
    if (b === undefined) return 1;
    if (typeof a === "number" && typeof b === "number") return a - b;
    return binaryCompare(String(a), String(b));
  }
  return 0;
}

function binaryCompare(left: string, right: string): number {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function digest(domain: string, value: unknown): string {
  return createHash("sha256")
    .update(`iam-organization-reconciliation:xrteeth-develop:${domain}\u001f`, "utf8")
    .update(JSON.stringify(canonicalDigestValue(value)), "utf8")
    .digest("hex");
}

function canonicalDigestValue(value: unknown): unknown {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("noncanonical-digest-value");
    return value;
  }
  if (Array.isArray(value)) return value.map((entry) => canonicalDigestValue(entry));
  if (typeof value !== "object") throw new Error("noncanonical-digest-value");
  const output = Object.create(null) as Record<string, unknown>;
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== "string")) throw new Error("noncanonical-digest-value");
  for (const key of (keys as string[]).sort(binaryCompare)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !("value" in descriptor) || descriptor.enumerable !== true) {
      throw new Error("noncanonical-digest-value");
    }
    output[key] = canonicalDigestValue(descriptor.value);
  }
  return output;
}

if (!SHA256_PATTERN.test(ORGANIZATION_RECONCILIATION_DEVELOP_PHYSICAL_CATALOG_SHA256) ||
  ORGANIZATION_RECONCILIATION_DEVELOP_PHYSICAL_CATALOG_SHA256 !==
    ORGANIZATION_RECONCILIATION_DEVELOP_PHYSICAL_CATALOG_PINNED_SHA256) {
  throw new Error("physical-catalog-digest-invalid");
}
