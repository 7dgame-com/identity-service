import { describe, expect, it } from "vitest";
import {
  ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG,
  ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG_READY,
  ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG_SHA256,
  resolveOrganizationReconciliationDevelopSourceComponent
} from "../src/iam-organization-reconciliation-develop-source-catalog.js";
import {
  runOrganizationReconciliationDevelopSourcePreflight
} from "../src/iam-organization-reconciliation-develop-source-preflight.js";
import {
  ORGANIZATION_RECONCILIATION_DEVELOP_IAM_POLICY_CHECKSUM,
  ORGANIZATION_RECONCILIATION_MYSQL_STATEMENTS,
  type MysqlRepeatableReadSnapshotConnectionFactory
} from "../src/iam-organization-reconciliation/mysql-repeatable-read-snapshot.js";
import {
  runOrganizationReconciliationDevelopPreflightCli
} from "../../../scripts/iam-organization-reconciliation-develop-preflight.js";

describe("xrteeth Develop organization reconciliation source preflight", () => {
  it("compiles the exact bounded 21-dataset catalog while remaining not ready", () => {
    expect(ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG_READY).toBe(false);
    expect(ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG_SHA256).toMatch(/^[a-f0-9]{64}$/);
    expect(ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG).toMatchObject({
      environment: "xrteeth-develop",
      trust: "compiled-source-shape-only",
      implementationReady: true,
      productionReady: false,
      iamPolicyChecksum: ORGANIZATION_RECONCILIATION_DEVELOP_IAM_POLICY_CHECKSUM
    });
    expect(ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG.components
      .map((component) => component.datasetCatalog.datasets.length)).toEqual([7, 13, 1]);
    expect(ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG.components
      .flatMap((component) => component.datasetCatalog.datasets)).toHaveLength(21);
    for (const component of ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG.components) {
      expect(component.physicalSchemaSha256).toBeNull();
      expect(component.physicalSourceAttestation).toBe("pending-develop-read-only-preflight");
      expect(component.declaredCatalogSha256).toMatch(/^[a-f0-9]{64}$/);
      expect(Object.isFrozen(component.datasetCatalog.datasets)).toBe(true);
    }
    expect(resolveOrganizationReconciliationDevelopSourceComponent("identity").datasetCatalog.datasets)
      .toHaveLength(13);
  });

  it("runs fixed schema, aggregate, and strict decoder probes without returning raw rows", async () => {
    const legacy = fakeFactory("legacy-main", aggregateRows("legacy-main"));
    const identity = fakeFactory("identity", aggregateRows("identity"));
    const plugin = fakeFactory("plugin", aggregateRows("plugin"));
    const report = await runOrganizationReconciliationDevelopSourcePreflight({
      legacyConnectionFactory: legacy.factory,
      identityConnectionFactory: identity.factory,
      pluginConnectionFactory: plugin.factory,
      buildRevision: "a".repeat(40),
      now: () => new Date("2026-08-10T08:00:00.000Z")
    });

    expect(report).toMatchObject({
      environment: "xrteeth-develop",
      mode: "read-only",
      checkedAt: "2026-08-10T08:00:00.000Z",
      buildRevision: "a".repeat(40),
      passed: true,
      productionReady: false,
      failures: []
    });
    expect(report.components.map((component) => component.datasetProbeCount)).toEqual([7, 13, 1]);
    expect(report.components.every((component) => component.schemaShapePassed)).toBe(true);
    expect(JSON.stringify(report)).not.toContain("identity_user_id");
    expect(JSON.stringify(report)).not.toContain("legacy_user_id");
    expect([...legacy.sql, ...identity.sql, ...plugin.sql].every((sql) =>
      /^(SELECT|SET TRANSACTION|START TRANSACTION|COMMIT|ROLLBACK)/.test(sql))).toBe(true);
  });

  it("fails closed on incomplete candidate coverage without leaking rows", async () => {
    const identityAggregates = aggregateRows("identity").map((row) =>
      row.metric === "identity_membership_snapshot_count" ? { ...row, metric_value: "1" } : row
    );
    const report = await runOrganizationReconciliationDevelopSourcePreflight({
      legacyConnectionFactory: fakeFactory("legacy-main", aggregateRows("legacy-main")).factory,
      identityConnectionFactory: fakeFactory("identity", identityAggregates).factory,
      pluginConnectionFactory: fakeFactory("plugin", aggregateRows("plugin")).factory,
      buildRevision: "b".repeat(40),
      now: () => new Date("2026-08-10T08:00:00.000Z")
    });
    expect(report.passed).toBe(false);
    expect(report.failures).toContain("identity-membership-snapshots-complete");
    expect(report.productionReady).toBe(false);
  });

  it("requires the exact Develop-only CLI target before any connection attempt", async () => {
    const stdout: string[] = [];
    const stderr: string[] = [];
    expect(await runOrganizationReconciliationDevelopPreflightCli([], {}, {
      stdout: (text) => stdout.push(text),
      stderr: (text) => stderr.push(text)
    })).toBe(2);
    expect(stdout).toEqual([]);
    expect(stderr.join("")).toContain("--environment=xrteeth-develop");

    stdout.length = 0;
    stderr.length = 0;
    expect(await runOrganizationReconciliationDevelopPreflightCli(["--help"], {}, {
      stdout: (text) => stdout.push(text),
      stderr: (text) => stderr.push(text)
    })).toBe(0);
    expect(stdout.join("")).toContain("performs no DDL or");
    expect(stderr).toEqual([]);
  });
});

type Component = "legacy-main" | "identity" | "plugin";

function fakeFactory(component: Component, aggregates: readonly Record<string, unknown>[]) {
  const sql: string[] = [];
  const factory: MysqlRepeatableReadSnapshotConnectionFactory = async () => ({
    async query(statement, parameters = []) {
      sql.push(statement);
      if (statement.startsWith("SELECT DATABASE()")) {
        return [[{
          database_name: component === "identity" ? "xrugc_identity_dev" :
            component === "plugin" ? "bujiaban_plugin" : "bujiaban",
          server_hostname: "develop-db",
          server_port: 3306,
          server_version: "8.0-test"
        }], []];
      }
      if (statement.includes("INFORMATION_SCHEMA.COLUMNS")) return [schemaRows(component), []];
      if (statement.includes(" AS metric")) return [aggregates, []];
      if (statement === ORGANIZATION_RECONCILIATION_MYSQL_STATEMENTS["identity-iam-policy-version-page/v1"]) {
        expect(parameters[0]).toBe(ORGANIZATION_RECONCILIATION_DEVELOP_IAM_POLICY_CHECKSUM);
        return [[{
          checksum: ORGANIZATION_RECONCILIATION_DEVELOP_IAM_POLICY_CHECKSUM,
          source: "legacy-import-candidate",
          status: "candidate",
          role_count: 2,
          permission_count: 1,
          relation_count: 1
        }], []];
      }
      return [[], []];
    },
    release() {}
  });
  return { factory, sql };
}

function schemaRows(component: Component): Record<string, unknown>[] {
  const columns: Record<Component, Record<string, readonly string[]>> = {
    "legacy-main": {
      organization: ["id", "name", "title", "created_at", "updated_at"],
      user: ["id", "status"],
      user_organization: ["user_id", "organization_id"],
      auth_assignment: ["item_name", "user_id"],
      auth_item: ["name", "type", "description", "rule_name"],
      auth_item_child: ["parent", "child"]
    },
    identity: {
      identity_users: ["id", "legacy_user_id", "status", "source"],
      identity_organizations_candidate: [
        "legacy_organization_id", "identity_organization_id", "name", "title", "source", "candidate_status"
      ],
      identity_organization_id_map: [
        "legacy_organization_id", "identity_organization_id", "source", "mapping_status"
      ],
      identity_organization_memberships_shadow: [
        "legacy_user_id", "organization_id", "organization_role", "source", "status"
      ],
      identity_organization_memberships_candidate: [
        "legacy_user_id", "legacy_organization_id", "identity_user_id", "identity_organization_id",
        "organization_role", "source", "candidate_status", "operation_key"
      ],
      identity_organization_membership_snapshots: [
        "identity_user_id", "legacy_user_id", "operation_key", "organization_count", "source", "candidate_status"
      ],
      identity_role_assignments_shadow: ["legacy_user_id", "role_name", "source", "status"],
      identity_iam_policy_versions: [
        "checksum", "source", "status", "role_count", "permission_count", "relation_count"
      ],
      identity_iam_roles: ["policy_checksum", "role_name", "description", "source", "status"],
      identity_iam_permissions: ["policy_checksum", "permission_name", "description", "source", "status"],
      identity_iam_item_relations: [
        "policy_checksum", "parent_name", "parent_type", "child_name", "child_type", "source", "status"
      ],
      identity_iam_subject_assignments: [
        "identity_user_id", "legacy_user_id", "item_name", "item_type", "policy_checksum", "source", "status"
      ]
    },
    plugin: { plugins: ["id", "enabled", "access_scope", "organization_name"] }
  };
  return Object.entries(columns[component]).flatMap(([table, names]) => names.map((column, index) => ({
    table_name: table,
    column_name: column,
    data_type: column.endsWith("_id") || column.endsWith("_count") ? "bigint" : "varchar",
    column_type: column.endsWith("_id") || column.endsWith("_count") ? "bigint" : "varchar(255)",
    is_nullable: "NO",
    collation_name: column.endsWith("_id") || column.endsWith("_count") ? "" : "utf8mb4_unicode_ci",
    ordinal_position: index + 1
  })));
}

function aggregateRows(component: Component): Record<string, unknown>[] {
  const values: Record<Component, Record<string, number>> = {
    "legacy-main": {
      legacy_organization_count: 2,
      legacy_subject_count: 2,
      legacy_active_subject_count: 2,
      legacy_membership_count: 1,
      legacy_rbac_item_count: 3,
      legacy_named_rule_count: 0,
      legacy_rbac_edge_count: 1,
      legacy_role_assignment_count: 2,
      legacy_rbac_assignment_count: 3
    },
    identity: {
      identity_subject_count: 2,
      identity_subject_collision_count: 0,
      identity_organization_candidate_count: 2,
      identity_organization_id_map_count: 2,
      identity_membership_candidate_count: 1,
      identity_membership_snapshot_count: 2,
      identity_membership_snapshot_organization_sum: 1,
      identity_membership_shadow_count: 1,
      identity_role_shadow_count: 2,
      identity_iam_policy_version_count: 1,
      identity_iam_declared_role_count: 2,
      identity_iam_declared_permission_count: 1,
      identity_iam_declared_relation_count: 1,
      identity_iam_role_count: 2,
      identity_iam_permission_count: 1,
      identity_iam_relation_count: 1,
      identity_iam_subject_assignment_count: 2
    },
    plugin: {
      plugin_count: 1,
      plugin_enabled_count: 1,
      plugin_invalid_scope_count: 0,
      plugin_empty_organization_name_count: 0
    }
  };
  return Object.entries(values[component]).map(([metric, metricValue]) => ({
    metric,
    metric_value: String(metricValue)
  }));
}
