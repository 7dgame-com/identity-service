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
  runOrganizationReconciliationDevelopPreflightCli,
  validateDevelopDatabaseConfiguration
} from "../../../scripts/iam-organization-reconciliation-develop-preflight.js";
import type { IdentityConfig } from "../src/config.js";

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
      contract: "iam-organization-reconciliation-xrteeth-develop-source-preflight/v2",
      environment: "xrteeth-develop",
      mode: "read-only",
      checkedAt: "2026-08-10T08:00:00.000Z",
      buildRevision: "a".repeat(40),
      passed: true,
      productionReady: false,
      failures: []
    });
    expect(report.subjectUniverseComparison).toEqual({
      legacySubjectCount: 2,
      identitySelectedSubjectCount: 2,
      missingInIdentityCount: 0,
      extraInIdentityCount: 0
    });
    expect(report.legacyRbacScope).toEqual({
      targetCount: 11,
      presentTargetCount: 11,
      namedRuleIntersectionCount: 0
    });
    expect(report.membershipSnapshotComparison).toEqual({
      legacySubjectCount: 2,
      snapshotSubjectCount: 2,
      missingLegacySnapshotCount: 0,
      extraSnapshotCount: 0
    });
    expect(report.components.map((component) => component.datasetProbeCount)).toEqual([7, 13, 1]);
    expect(report.components.every((component) => component.schemaShapePassed)).toBe(true);
    expect(JSON.stringify(report)).not.toContain("identity_user_id");
    expect(JSON.stringify(report)).not.toContain("legacy_user_id");
    expect([...legacy.sql, ...identity.sql, ...plugin.sql].every((sql) =>
      /^(SELECT|SET TRANSACTION|START TRANSACTION|COMMIT|ROLLBACK)/.test(sql))).toBe(true);
  });

  it("fails closed on incomplete candidate coverage without leaking rows", async () => {
    const report = await runOrganizationReconciliationDevelopSourcePreflight({
      legacyConnectionFactory: fakeFactory("legacy-main", aggregateRows("legacy-main")).factory,
      identityConnectionFactory: fakeFactory("identity", aggregateRows("identity"), {
        membershipSnapshotSubjectIds: [1]
      }).factory,
      pluginConnectionFactory: fakeFactory("plugin", aggregateRows("plugin")).factory,
      buildRevision: "b".repeat(40),
      now: () => new Date("2026-08-10T08:00:00.000Z")
    });
    expect(report.passed).toBe(false);
    expect(report.failures).toContain("identity-legacy-membership-snapshots-complete");
    expect(report.membershipSnapshotComparison.missingLegacySnapshotCount).toBe(1);
    expect(report.productionReady).toBe(false);
  });

  it("proves every Legacy subject is represented while reporting Identity-only subjects separately", async () => {
    const report = await runOrganizationReconciliationDevelopSourcePreflight({
      legacyConnectionFactory: fakeFactory("legacy-main", aggregateRows("legacy-main"), {
        subjectIds: [1, 2]
      }).factory,
      identityConnectionFactory: fakeFactory("identity", aggregateRows("identity"), {
        subjectIds: [1, 2, 3]
      }).factory,
      pluginConnectionFactory: fakeFactory("plugin", aggregateRows("plugin")).factory,
      buildRevision: "c".repeat(40),
      now: () => new Date("2026-08-10T08:00:00.000Z")
    });
    expect(report.failures).not.toContain("identity-legacy-subjects-complete");
    expect(report.subjectUniverseComparison).toEqual({
      legacySubjectCount: 2,
      identitySelectedSubjectCount: 3,
      missingInIdentityCount: 0,
      extraInIdentityCount: 1
    });

    const missing = await runOrganizationReconciliationDevelopSourcePreflight({
      legacyConnectionFactory: fakeFactory("legacy-main", aggregateRows("legacy-main"), {
        subjectIds: [1, 2]
      }).factory,
      identityConnectionFactory: fakeFactory("identity", aggregateRows("identity"), {
        subjectIds: [1, 3]
      }).factory,
      pluginConnectionFactory: fakeFactory("plugin", aggregateRows("plugin")).factory,
      buildRevision: "d".repeat(40),
      now: () => new Date("2026-08-10T08:00:00.000Z")
    });
    expect(missing.failures).toContain("identity-legacy-subjects-complete");
    expect(missing.subjectUniverseComparison.missingInIdentityCount).toBe(1);
  });

  it("limits named-rule rejection to the compiled reconciliation capability closure", async () => {
    const unrelated = await runOrganizationReconciliationDevelopSourcePreflight({
      legacyConnectionFactory: fakeFactory("legacy-main", aggregateRows("legacy-main"), {
        additionalRbacItems: [{ name: "unrelated", type: 2, rule_name: "legacy-rule" }]
      }).factory,
      identityConnectionFactory: fakeFactory("identity", aggregateRows("identity")).factory,
      pluginConnectionFactory: fakeFactory("plugin", aggregateRows("plugin")).factory,
      buildRevision: "e".repeat(40),
      now: () => new Date("2026-08-10T08:00:00.000Z")
    });
    expect(unrelated.failures).not.toContain("legacy-reconciliation-scope-rule-free");

    const intersecting = await runOrganizationReconciliationDevelopSourcePreflight({
      legacyConnectionFactory: fakeFactory("legacy-main", aggregateRows("legacy-main"), {
        additionalRbacItems: [{ name: "legacy-rule-parent", type: 1, rule_name: "legacy-rule" }],
        rbacEdges: [{ parent: "legacy-rule-parent", child: "organization.list" }]
      }).factory,
      identityConnectionFactory: fakeFactory("identity", aggregateRows("identity")).factory,
      pluginConnectionFactory: fakeFactory("plugin", aggregateRows("plugin")).factory,
      buildRevision: "f".repeat(40),
      now: () => new Date("2026-08-10T08:00:00.000Z")
    });
    expect(intersecting.failures).toContain("legacy-reconciliation-scope-rule-free");
    expect(intersecting.legacyRbacScope.namedRuleIntersectionCount).toBe(1);
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

  it("requires a dedicated plugin read-only database identity instead of reusing Legacy credentials", () => {
    const config = {
      legacyDb: { host: "legacy-db", port: 3306, name: "bujiaban", user: "legacy-reader", password: "legacy" },
      identityDb: { host: "identity-db", port: 3306, name: "xrugc_identity_dev", user: "identity-reader", password: "identity" }
    } as unknown as IdentityConfig;
    expect(() => validateDevelopDatabaseConfiguration(config, {
      PLUGIN_DB_HOST: "plugin-db",
      PLUGIN_DB_NAME: "bujiaban_plugin",
      PLUGIN_DB_USER: "legacy-reader",
      PLUGIN_DB_PASSWORD: "plugin"
    })).toThrow(/dedicated/);
    expect(validateDevelopDatabaseConfiguration(config, {
      PLUGIN_DB_HOST: "plugin-db",
      PLUGIN_DB_PORT: "3306",
      PLUGIN_DB_NAME: "bujiaban_plugin",
      PLUGIN_DB_USER: "plugin-readonly",
      PLUGIN_DB_PASSWORD: "plugin"
    })).toEqual({
      host: "plugin-db",
      port: 3306,
      name: "bujiaban_plugin",
      user: "plugin-readonly",
      password: "plugin"
    });
  });
});

type Component = "legacy-main" | "identity" | "plugin";

function fakeFactory(
  component: Component,
  aggregates: readonly Record<string, unknown>[],
  options: {
    readonly subjectIds?: readonly number[];
    readonly membershipSnapshotSubjectIds?: readonly number[];
    readonly additionalRbacItems?: readonly Record<string, unknown>[];
    readonly rbacEdges?: readonly Record<string, unknown>[];
  } = {}
) {
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
      if (statement === "SELECT id AS subject_id FROM `user` ORDER BY id ASC" ||
        statement.startsWith("SELECT legacy_user_id AS subject_id FROM identity_users")) {
        return [(options.subjectIds ?? [1, 2]).map((subjectId) => ({ subject_id: subjectId })), []];
      }
      if (statement.startsWith("SELECT legacy_user_id AS subject_id FROM identity_organization_membership_snapshots")) {
        return [(options.membershipSnapshotSubjectIds ?? [1, 2]).map((subjectId) => ({ subject_id: subjectId })), []];
      }
      if (statement.startsWith("SELECT name, type, rule_name FROM auth_item")) {
        return [[...capabilityItems(), ...(options.additionalRbacItems ?? [])], []];
      }
      if (statement.startsWith("SELECT parent, child FROM auth_item_child")) {
        return [[...(options.rbacEdges ?? [])], []];
      }
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

function capabilityItems(): Record<string, unknown>[] {
  return [
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
  ].map((name) => ({ name, type: 2, rule_name: null }));
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
