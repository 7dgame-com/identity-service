import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import {
  ORGANIZATION_RECONCILIATION_DEVELOP_PHYSICAL_CATALOG,
  ORGANIZATION_RECONCILIATION_DEVELOP_PHYSICAL_CATALOG_PINNED_SHA256,
  ORGANIZATION_RECONCILIATION_DEVELOP_PHYSICAL_CATALOG_SHA256,
  ORGANIZATION_RECONCILIATION_DEVELOP_PHYSICAL_PROBE_READY,
  runOrganizationReconciliationDevelopPhysicalProbe
} from "../src/iam-organization-reconciliation-develop-physical-probe.js";
import type {
  OrganizationReconciliationMysqlRawComponentId
} from "../src/iam-organization-reconciliation/mysql-source-adapters/raw-source-snapshots.js";
import type {
  MysqlRepeatableReadSnapshotConnectionFactory
} from "../src/iam-organization-reconciliation/mysql-repeatable-read-snapshot.js";
import {
  resolveOrganizationReconciliationDevelopPhysicalProbeConfiguration,
  runOrganizationReconciliationDevelopPhysicalProbeCli
} from "../../../scripts/iam-organization-reconciliation-develop-physical-probe.js";
import type { IdentityConfig } from "../src/config.js";

const USERS = Object.freeze({
  "legacy-main": "iam-org-legacy-ro",
  identity: "iam-org-identity-ro",
  plugin: "iam-org-plugin-ro"
});

const DATABASES = Object.freeze({
  "legacy-main": "bujiaban_development",
  identity: "xrugc_identity_dev",
  plugin: "bujiaban_development_plugin"
});

describe("xrteeth Develop compiled physical probe", () => {
  it("pins the exact compiled 7/13/1 statement-to-dataset and 6/12/1 physical closure without a thirteenth Identity table", async () => {
    expect(ORGANIZATION_RECONCILIATION_DEVELOP_PHYSICAL_PROBE_READY).toBe(false);
    expect(ORGANIZATION_RECONCILIATION_DEVELOP_PHYSICAL_CATALOG_SHA256)
      .toBe("3d4243a7a894203bd5371d5f9ebd41e45d54e2daba8a631f0e4793b58cce68b3");
    expect(ORGANIZATION_RECONCILIATION_DEVELOP_PHYSICAL_CATALOG_PINNED_SHA256)
      .toBe(ORGANIZATION_RECONCILIATION_DEVELOP_PHYSICAL_CATALOG_SHA256);
    expect(ORGANIZATION_RECONCILIATION_DEVELOP_PHYSICAL_CATALOG).toMatchObject({
      environment: "xrteeth-develop",
      datasetCount: 21,
      uniquePhysicalTableCount: 19,
      derivedDatasetCount: 1
    });
    expect(ORGANIZATION_RECONCILIATION_DEVELOP_PHYSICAL_CATALOG.components
      .map((component) => Object.keys(component.datasets).length)).toEqual([7, 13, 1]);
    expect(ORGANIZATION_RECONCILIATION_DEVELOP_PHYSICAL_CATALOG.components
      .map((component) => Object.keys(component.tables).length)).toEqual([6, 12, 1]);
    expect(ORGANIZATION_RECONCILIATION_DEVELOP_PHYSICAL_CATALOG.derivedDatasets)
      .toEqual({
        "identity-iam-subject-assignment-snapshot": {
          relation: "left-join",
          tables: ["identity_users", "identity_iam_subject_assignments"],
          requiresDedicatedPhysicalTable: false
        }
      });
    const identity = componentRequirement("identity");
    expect(Object.keys(identity.tables)).not.toContain("identity_iam_subject_assignment_snapshots");
    expect(identity.tables.identity_iam_subject_assignments?.columns).toContain("id");
    expect(new Set(ORGANIZATION_RECONCILIATION_DEVELOP_PHYSICAL_CATALOG.components.flatMap((component) =>
      Object.values(component.datasets).map((dataset) => dataset.statementId))).size).toBe(21);
    expect(componentRequirement("legacy-main").datasets["legacy-membership"]?.deterministicUniqueKeys)
      .toContainEqual({
        tableName: "user_organization",
        columns: ["user_id", "organization_id"],
        purpose: "cursor-uniqueness"
      });
    expect(componentRequirement("legacy-main").datasets["legacy-rbac-assignment"]?.deterministicUniqueKeys)
      .toContainEqual({
        tableName: "auth_assignment",
        columns: ["item_name", "user_id"],
        purpose: "cursor-uniqueness"
      });

    const packageJson = JSON.parse(await readFile(new URL("../../../package.json", import.meta.url), "utf8")) as {
      scripts: Record<string, string>;
    };
    expect(packageJson.scripts["iam:organization-reconciliation:develop-physical-probe"])
      .toBe("tsx scripts/iam-organization-reconciliation-develop-physical-probe.ts");
    expect(packageJson.scripts["iam:organization-reconciliation:develop-physical-probe:dist"])
      .toBe("node dist/scripts/iam-organization-reconciliation-develop-physical-probe.js");
  });

  it("runs two fixed read-only metadata passes per source and emits only sanitized counts, booleans and digests", async () => {
    const secrets = ["legacy-host-secret", "identity-host-secret", "plugin-host-secret", "super-secret-password"];
    const legacy = fakeFactory("legacy-main");
    const identity = fakeFactory("identity");
    const plugin = fakeFactory("plugin");
    const report = await runOrganizationReconciliationDevelopPhysicalProbe({
      legacyConnectionFactory: legacy.factory,
      identityConnectionFactory: identity.factory,
      pluginConnectionFactory: plugin.factory,
      expectedDatabaseUsers: USERS,
      buildRevision: "a".repeat(40)
    });

    expect(report).toMatchObject({
      contract: "iam-organization-reconciliation-xrteeth-develop-physical-probe/v1",
      environment: "xrteeth-develop",
      mode: "read-only",
      assuranceScope: "compiled-21-dataset-physical-metadata-and-deterministic-cursor-keys-only",
      optimizerOrderPerformanceClaimed: false,
      currentTransactionVariableIntrospectionClaimed: false,
      componentCount: 3,
      datasetCount: 21,
      physicalTableCount: 19,
      derivedDatasetCount: 1,
      completedProbePassCount: 6,
      failedIds: [],
      passed: true,
      productionReady: false
    });
    expect(report.components.map((component) => component.datasetCount)).toEqual([7, 13, 1]);
    expect(report.components.map((component) => component.physicalTableCount)).toEqual([6, 12, 1]);
    expect([legacy.connectionCount, identity.connectionCount, plugin.connectionCount]).toEqual([2, 2, 2]);
    expect(report.sourceCatalogSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(report.statementCatalogSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(report.physicalCatalogSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(report.buildRevisionSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(report.components.every((component) => component.aBAligned)).toBe(true);
    expect(report.components.every((component) => component.databaseBindingPassed)).toBe(true);
    expect(report.components.every((component) => component.grantPassed)).toBe(true);
    expect(report.components.every((component) => component.snapshotProtocolPassed)).toBe(true);
    expect(report.components.every((component) => component.tableShapePassed)).toBe(true);
    expect(report.components.every((component) => component.columnShapePassed)).toBe(true);
    expect(report.components.every((component) => component.deterministicUniqueKeysPassed)).toBe(true);
    expect(report.components.every((component) => component.collationPassed)).toBe(true);
    expect(report.components.every((component) => component.binaryOrderWitnessPassed)).toBe(true);
    for (const component of report.components) {
      for (const key of [
        "sourceIdentitySha256", "grantScopeSha256", "physicalSchemaSha256", "physicalIndexSha256",
        "snapshotProtocolSha256", "binaryOrderWitnessSha256"
      ] as const) expect(component[key]).toMatch(/^[a-f0-9]{64}$/);
    }
    const serialized = JSON.stringify(report);
    for (const secret of [...secrets, ...Object.values(USERS), ...Object.values(DATABASES)]) {
      expect(serialized).not.toContain(secret);
    }
    expect(serialized).not.toContain("GRANT SELECT");
    expect(serialized).not.toContain("identity_user_id");
    for (const sql of [...legacy.sql, ...identity.sql, ...plugin.sql]) {
      expect(sql).toMatch(/^(?:SELECT|SHOW GRANTS|SET SESSION TRANSACTION|START TRANSACTION|ROLLBACK)/);
      expect(sql).not.toMatch(/^(?:INSERT|UPDATE|DELETE|REPLACE|ALTER|CREATE|DROP|TRUNCATE|GRANT|REVOKE)/);
    }
    const allSql = [...legacy.sql, ...identity.sql, ...plugin.sql];
    expect(allSql.filter((sql) => sql.includes("FROM INFORMATION_SCHEMA.TABLES"))
      .every((sql) => sql.endsWith("LIMIT 65"))).toBe(true);
    expect(allSql.filter((sql) => sql.includes("FROM INFORMATION_SCHEMA.COLUMNS"))
      .every((sql) => sql.endsWith("LIMIT 513"))).toBe(true);
    expect(allSql.filter((sql) => sql.includes("FROM INFORMATION_SCHEMA.STATISTICS"))
      .every((sql) => sql.endsWith("LIMIT 513"))).toBe(true);
  });

  it("fails closed on writable, global, role-indirect, grant-option and incomplete grants", async () => {
    const validPluginGrants = [
      "GRANT USAGE ON *.* TO `iam-org-plugin-ro`@`%`",
      "GRANT SELECT, SHOW VIEW ON `bujiaban_development_plugin`.* TO `iam-org-plugin-ro`@`%`"
    ];
    const invalidGrants = [
      [...validPluginGrants, "GRANT SELECT, UPDATE ON `bujiaban_development_plugin`.* TO `iam-org-plugin-ro`@`%`"],
      [...validPluginGrants, "GRANT SELECT ON *.* TO `iam-org-plugin-ro`@`%`"],
      [...validPluginGrants, "GRANT `reader-role`@`%` TO `iam-org-plugin-ro`@`%`"],
      [...validPluginGrants, "GRANT SELECT ON `bujiaban_development_plugin`.`other` TO `iam-org-plugin-ro`@`%`"],
      [...validPluginGrants, "GRANT CREATE ON `bujiaban_development_plugin`.* TO `iam-org-plugin-ro`@`%`"],
      [...validPluginGrants, "GRANT SELECT ON `bujiaban_development_plugin`.* TO `iam-org-plugin-ro`@`%` WITH GRANT OPTION"],
      [...validPluginGrants, "GRANT SELECT ON `bujiaban_development_plugin`.* TO `different-user`@`%`"],
      [...validPluginGrants, "GRANT SELECT ON `bujiaban_development_plugin`.* TO `iam-org-plugin-ro`@`%`; GRANT UPDATE ON *.* TO `x`@`%`"]
    ];
    for (const grants of invalidGrants) {
      const report = await runProbe({ plugin: { grants } });
      expect(report.passed).toBe(false);
      expect(report.components.find((component) => component.componentId === "plugin")?.grantPassed).toBe(false);
      expect(report.failedIds).toContain("plugin:a:grant-bound");
      expect(report.failedIds).toContain("plugin:b:grant-bound");
      for (const grant of grants) expect(JSON.stringify(report)).not.toContain(grant);
    }
  });

  it("binds DATABASE(), CURRENT_USER() and every SHOW GRANTS principal to the exact component account", async () => {
    const wrongDatabase = await runProbe({ plugin: { databaseName: "bujiaban_plugin" } });
    expect(wrongDatabase.failedIds).toContain("plugin:a:database-binding");
    expect(wrongDatabase.components.find((component) => component.componentId === "plugin")?.databaseBindingPassed)
      .toBe(false);
    const wrongUser = await runProbe({ plugin: { currentUser: "another-readonly" } });
    expect(wrongUser.failedIds).toContain("plugin:a:database-binding");
    expect(wrongUser.failedIds).toContain("plugin:a:grant-bound");
    const mismatchedAccountHost = await runProbe({
      plugin: {
        grants: [
          "GRANT USAGE ON *.* TO `iam-org-plugin-ro`@`localhost`",
          "GRANT SELECT, SHOW VIEW ON `bujiaban_development_plugin`.* TO `iam-org-plugin-ro`@`localhost`"
        ]
      }
    });
    expect(mismatchedAccountHost.failedIds).toContain("plugin:a:grant-bound");
  });

  it("rejects missing table, column, exact deterministic key, invalid collation and noncanonical metadata order", async () => {
    const cases: Array<{
      options: FakeOptions;
      failure: string;
      field?: "tableShapePassed" | "columnShapePassed" | "deterministicUniqueKeysPassed" | "collationPassed";
    }> = [
      { options: { missingTable: "plugins" }, failure: "plugin:a:table-shape", field: "tableShapePassed" },
      { options: { missingColumn: "organization_name" }, failure: "plugin:a:column-shape", field: "columnShapePassed" },
      {
        options: { missingUniqueKeyColumn: "id" },
        failure: "plugin:a:deterministic-unique-keys",
        field: "deterministicUniqueKeysPassed"
      },
      { options: { invalidCollation: true }, failure: "plugin:a:collation", field: "collationPassed" },
      { options: { reverseColumns: true }, failure: "plugin:a:probe-unavailable" }
    ];
    for (const candidate of cases) {
      const report = await runProbe({ plugin: candidate.options });
      expect(report.passed).toBe(false);
      expect(report.failedIds).toContain(candidate.failure);
      const plugin = report.components.find((component) => component.componentId === "plugin");
      if (candidate.field !== undefined) expect(plugin?.[candidate.field]).toBe(false);
    }
  });

  it("requires exact full visible unique BTREE key sequences instead of accepting a leading column", async () => {
    const cases = [
      { componentId: "legacy-main" as const, tableName: "user_organization", mutation: "truncate" as const },
      { componentId: "legacy-main" as const, tableName: "auth_assignment", mutation: "reverse" as const },
      { componentId: "identity" as const, tableName: "identity_iam_roles", mutation: "non-unique" as const },
      { componentId: "identity" as const, tableName: "identity_iam_permissions", mutation: "prefix" as const },
      { componentId: "identity" as const, tableName: "identity_iam_item_relations", mutation: "hash" as const },
      { componentId: "plugin" as const, tableName: "plugins", mutation: "invisible" as const }
    ];
    for (const candidate of cases) {
      const report = await runProbe({
        [candidate.componentId]: {
          mutateUniqueKeyTable: candidate.tableName,
          uniqueKeyMutation: candidate.mutation
        }
      });
      expect(report.passed).toBe(false);
      expect(report.failedIds).toContain(`${candidate.componentId}:a:deterministic-unique-keys`);
      expect(report.failedIds).toContain(`${candidate.componentId}:b:deterministic-unique-keys`);
      expect(report.components.find((component) => component.componentId === candidate.componentId)
        ?.deterministicUniqueKeysPassed).toBe(false);
    }
  });

  it("binds A/B evidence and rejects a shape-preserving metadata splice", async () => {
    const report = await runProbe({
      identity: { mutatePassBColumnType: true }
    });
    const identity = report.components.find((component) => component.componentId === "identity");
    expect(report.passed).toBe(false);
    expect(report.failedIds).toContain("identity:a-b-alignment");
    expect(identity).toMatchObject({
      completedProbePassCount: 2,
      tableShapePassed: true,
      columnShapePassed: true,
      deterministicUniqueKeysPassed: true,
      aBAligned: false,
      physicalSchemaSha256: null
    });
  });

  it("enforces bounded metadata and never returns raw thrown errors", async () => {
    const secret = "do-not-leak-this-host-or-password";
    const oversized = await runProbe({ plugin: { extraColumnCount: 513 } });
    expect(oversized.passed).toBe(false);
    expect(oversized.failedIds).toContain("plugin:a:probe-unavailable");
    expect(oversized.components.find((component) => component.componentId === "plugin"))
      .toMatchObject({ completedProbePassCount: 0, observedColumnCount: 0 });
    const oversizedIndexes = await runProbe({ plugin: { extraIndexCount: 513 } });
    expect(oversizedIndexes.failedIds).toContain("plugin:a:probe-unavailable");
    const oversizedGrants = await runProbe({
      plugin: {
        grants: Array.from({ length: 33 }, () =>
          "GRANT SELECT, SHOW VIEW ON `bujiaban_development_plugin`.* TO `iam-org-plugin-ro`@`%`")
      }
    });
    expect(oversizedGrants.failedIds).toContain("plugin:a:probe-unavailable");

    const throwingFactory: MysqlRepeatableReadSnapshotConnectionFactory = async () => {
      throw new Error(secret);
    };
    const report = await runOrganizationReconciliationDevelopPhysicalProbe({
      legacyConnectionFactory: fakeFactory("legacy-main").factory,
      identityConnectionFactory: fakeFactory("identity").factory,
      pluginConnectionFactory: throwingFactory,
      expectedDatabaseUsers: USERS,
      buildRevision: "a".repeat(40)
    });
    expect(report.failedIds).toContain("plugin:a:probe-unavailable");
    expect(JSON.stringify(report)).not.toContain(secret);

    let accessorReads = 0;
    const accessor = await runProbe({
      plugin: {
        accessorRow: "table",
        onAccessorRead: () => { accessorReads += 1; }
      }
    });
    expect(accessor.passed).toBe(false);
    expect(accessor.failedIds).toContain("plugin:a:probe-unavailable");
    expect(accessorReads).toBe(0);
    const grantAccessor = await runProbe({
      plugin: {
        accessorRow: "grant",
        onAccessorRead: () => { accessorReads += 1; }
      }
    });
    expect(grantAccessor.passed).toBe(false);
    expect(grantAccessor.failedIds).toContain("plugin:a:probe-unavailable");
    expect(accessorReads).toBe(0);
  });

  it("requires the exact REPEATABLE READ session protocol and a MySQL-vs-Node UTF-8 binary ordering witness", async () => {
    const wrongIsolation = await runProbe({ identity: { sessionIsolation: "READ-COMMITTED" } });
    expect(wrongIsolation.failedIds).toContain("identity:a:snapshot-protocol");
    expect(wrongIsolation.components.find((component) => component.componentId === "identity")?.snapshotProtocolPassed)
      .toBe(false);
    const badWitness = await runProbe({ identity: { reverseBinaryWitness: true } });
    expect(badWitness.failedIds).toContain("identity:a:utf8-binary-order-witness");
    expect(badWitness.components.find((component) => component.componentId === "identity")?.binaryOrderWitnessPassed)
      .toBe(false);
    const utf16Order = ["\uE000", "\u{10000}"].sort();
    const utf8Order = ["\uE000", "\u{10000}"].sort((left, right) =>
      Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8")));
    expect(utf16Order).toEqual(["\u{10000}", "\uE000"]);
    expect(utf8Order).toEqual(["\uE000", "\u{10000}"]);
  });

  it("accepts the MySQL UTF-8 family names observed across the three isolated Develop schemas", async () => {
    const report = await runProbe({
      "legacy-main": { characterSet: "utf8mb3", tableCollation: "utf8mb3_unicode_ci" },
      identity: { characterSet: "utf8mb4", tableCollation: "utf8mb4_unicode_ci" },
      plugin: { characterSet: "utf8mb4", tableCollation: "utf8mb4_0900_ai_ci" }
    });
    expect(report.passed).toBe(true);
    expect(report.components.every((component) => component.collationPassed)).toBe(true);
  });

  it("validates three distinct Develop-only credentials without reusing service identities", () => {
    const config = baseConfig();
    const env = baseEnv();
    expect(resolveOrganizationReconciliationDevelopPhysicalProbeConfiguration(config, env)).toEqual({
      "legacy-main": {
        host: "shared-develop-db",
        port: 3306,
        name: "bujiaban_development",
        user: USERS["legacy-main"],
        password: "legacy-probe-secret"
      },
      identity: {
        host: "shared-develop-db",
        port: 3306,
        name: "xrugc_identity_dev",
        user: USERS.identity,
        password: "identity-probe-secret"
      },
      plugin: {
        host: "shared-develop-db",
        port: 3306,
        name: "bujiaban_development_plugin",
        user: USERS.plugin,
        password: "plugin-probe-secret"
      }
    });
    expect(() => resolveOrganizationReconciliationDevelopPhysicalProbeConfiguration(config, {
      ...env,
      PLUGIN_DB_USER: USERS.identity
    })).toThrow("invalid-physical-probe-configuration");
    expect(() => resolveOrganizationReconciliationDevelopPhysicalProbeConfiguration(config, {
      ...env,
      IDENTITY_IAM_ORG_RECONCILIATION_LEGACY_DB_USER: "legacy-service"
    })).toThrow("invalid-physical-probe-configuration");
    expect(() => resolveOrganizationReconciliationDevelopPhysicalProbeConfiguration(config, {
      ...env,
      IDENTITY_IAM_ORG_RECONCILIATION_LEGACY_DB_USER: "identity-service"
    })).toThrow("invalid-physical-probe-configuration");
    expect(() => resolveOrganizationReconciliationDevelopPhysicalProbeConfiguration(config, {
      ...env,
      PLUGIN_DB_USER: "identity-service"
    })).toThrow("invalid-physical-probe-configuration");
    expect(() => resolveOrganizationReconciliationDevelopPhysicalProbeConfiguration(config, {
      ...env,
      IDENTITY_IAM_ORG_RECONCILIATION_IDENTITY_DB_USER: "plugin-service"
    })).toThrow("invalid-physical-probe-configuration");
    expect(() => resolveOrganizationReconciliationDevelopPhysicalProbeConfiguration(config, {
      ...env,
      IDENTITY_IAM_ORG_RECONCILIATION_PLUGIN_SERVICE_DB_USER: undefined
    })).toThrow("plugin-service-user-missing");
    expect(() => resolveOrganizationReconciliationDevelopPhysicalProbeConfiguration(config, {
      ...env,
      PLUGIN_DB_NAME: "bujiaban_plugin"
    })).toThrow("invalid-physical-probe-configuration");
  });

  it("exposes a fixed Develop-only CLI and writes exactly one sanitized JSON line", async () => {
    const stdout: string[] = [];
    const stderr: string[] = [];
    const secretValues = [
      "shared-develop-db", "legacy-probe-secret", "identity-probe-secret", "plugin-probe-secret",
      "plugin-service", ...Object.values(USERS), ...Object.values(DATABASES)
    ];
    const code = await runOrganizationReconciliationDevelopPhysicalProbeCli(
      ["--environment=xrteeth-develop"],
      baseEnv(),
      { stdout: (text) => stdout.push(text), stderr: (text) => stderr.push(text) },
      {
        connectionFactory: (configuration) => {
          const componentId = (Object.entries(DATABASES)
            .find(([, database]) => database === configuration.name)?.[0] ?? "invalid") as OrganizationReconciliationMysqlRawComponentId;
          return fakeFactory(componentId, { currentUser: configuration.user }).factory;
        }
      }
    );
    expect(code).toBe(0);
    expect(stderr).toEqual([]);
    expect(stdout).toHaveLength(1);
    expect(stdout[0]?.match(/\n/g)).toHaveLength(1);
    const report = JSON.parse(stdout[0] as string) as Record<string, unknown>;
    expect(report).toMatchObject({ passed: true, productionReady: false, physicalTableCount: 19 });
    for (const secret of secretValues) expect(stdout[0]).not.toContain(secret);

    stdout.length = 0;
    expect(await runOrganizationReconciliationDevelopPhysicalProbeCli(
      ["--environment=production"],
      baseEnv(),
      { stdout: (text) => stdout.push(text), stderr: (text) => stderr.push(text) }
    )).toBe(2);
    expect(stdout).toEqual([]);
    expect(stderr.at(-1)).toBe("Invalid arguments. Use --environment=xrteeth-develop.\n");

    stderr.length = 0;
    expect(await runOrganizationReconciliationDevelopPhysicalProbeCli(
      ["--environment=xrteeth-develop"],
      { ...baseEnv(), IDENTITY_IAM_ORG_RECONCILIATION_PLUGIN_SERVICE_DB_USER: undefined },
      { stdout: (text) => stdout.push(text), stderr: (text) => stderr.push(text) }
    )).toBe(2);
    expect(stdout).toEqual([]);
    expect(stderr).toHaveLength(1);
    expect(JSON.parse(stderr[0] as string)).toMatchObject({
      environment: "xrteeth-develop",
      mode: "read-only",
      passed: false,
      failure: "plugin-service-user-missing"
    });
  });
});

type FakeOptions = {
  readonly grants?: readonly string[];
  readonly currentUser?: string;
  readonly databaseName?: string;
  readonly missingTable?: string;
  readonly missingColumn?: string;
  readonly missingUniqueKeyColumn?: string;
  readonly mutateUniqueKeyTable?: string;
  readonly uniqueKeyMutation?: "truncate" | "reverse" | "non-unique" | "prefix" | "hash" | "invisible";
  readonly invalidCollation?: boolean;
  readonly reverseColumns?: boolean;
  readonly mutatePassBColumnType?: boolean;
  readonly extraColumnCount?: number;
  readonly extraIndexCount?: number;
  readonly sessionIsolation?: string;
  readonly reverseBinaryWitness?: boolean;
  readonly accessorRow?: "table" | "grant";
  readonly onAccessorRead?: () => void;
  readonly characterSet?: "utf8" | "utf8mb3" | "utf8mb4";
  readonly tableCollation?: string;
};

async function runProbe(options: Partial<Record<OrganizationReconciliationMysqlRawComponentId, FakeOptions>>) {
  return runOrganizationReconciliationDevelopPhysicalProbe({
    legacyConnectionFactory: fakeFactory("legacy-main", options["legacy-main"]).factory,
    identityConnectionFactory: fakeFactory("identity", options.identity).factory,
    pluginConnectionFactory: fakeFactory("plugin", options.plugin).factory,
    expectedDatabaseUsers: USERS,
    buildRevision: "a".repeat(40)
  });
}

function fakeFactory(componentId: OrganizationReconciliationMysqlRawComponentId, options: FakeOptions = {}) {
  const sql: string[] = [];
  let connectionCount = 0;
  const factory: MysqlRepeatableReadSnapshotConnectionFactory = async () => {
    const pass = connectionCount;
    connectionCount += 1;
    return Object.freeze({
      async query(statement: string) {
        sql.push(statement);
        if (statement === "SHOW GRANTS FOR CURRENT_USER()") {
          if (options.accessorRow === "grant") {
            const row: Record<string, unknown> = {};
            Object.defineProperty(row, "Grants_for_current_user", {
              enumerable: true,
              get() {
                options.onAccessorRead?.();
                return "raw-secret-must-not-be-read";
              }
            });
            return [[row], []] as const;
          }
          const grants = options.grants ?? [
            `GRANT USAGE ON *.* TO \`${options.currentUser ?? USERS[componentId]}\`@\`%\``,
            `GRANT SELECT, SHOW VIEW ON \`${DATABASES[componentId]}\`.* TO \`${options.currentUser ?? USERS[componentId]}\`@\`%\``
          ];
          return [grants.map((grant) => ({ Grants_for_current_user: grant })), []] as const;
        }
        if (statement === "SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ" ||
          statement === "START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY" || statement === "ROLLBACK") {
          return [[], []] as const;
        }
        if (statement.startsWith("SELECT DATABASE()")) {
          return [[{
            database_name: options.databaseName ?? DATABASES[componentId],
            current_user: `${options.currentUser ?? USERS[componentId]}@%`
          }], []] as const;
        }
        if (statement.startsWith("SELECT @@SESSION.transaction_isolation")) {
          return [[{
            session_transaction_isolation: options.sessionIsolation ?? "REPEATABLE-READ"
          }], []] as const;
        }
        if (statement.includes("FROM INFORMATION_SCHEMA.TABLES")) {
          if (options.accessorRow === "table") {
            const row: Record<string, unknown> = {
              table_type: "BASE TABLE",
              engine: "InnoDB",
              table_collation: "utf8mb4_unicode_ci"
            };
            Object.defineProperty(row, "table_name", {
              enumerable: true,
              get() {
                options.onAccessorRead?.();
                return "plugins";
              }
            });
            return [[row], []] as const;
          }
          return [tableRows(componentId, options), []] as const;
        }
        if (statement.includes("FROM INFORMATION_SCHEMA.COLUMNS")) {
          const rows = columnRows(componentId, options, pass);
          return [options.reverseColumns ? [...rows].reverse() : rows, []] as const;
        }
        if (statement.includes("FROM INFORMATION_SCHEMA.STATISTICS")) return [indexRows(componentId, options), []] as const;
        if (statement.includes("AS binary_order_witness ORDER BY CAST(witness_value AS BINARY)")) {
          const values = ["41", "61", "C3A9", "E4B8AD", "EE8080", "F0908080"];
          if (options.reverseBinaryWitness) values.reverse();
          return [values.map((value_hex) => ({ value_hex })), []] as const;
        }
        throw new Error("unexpected-query");
      },
      async release() {
        return undefined;
      }
    });
  };
  return {
    factory,
    sql,
    get connectionCount() {
      return connectionCount;
    }
  };
}

function tableRows(componentId: OrganizationReconciliationMysqlRawComponentId, options: FakeOptions) {
  return Object.keys(componentRequirement(componentId).tables)
    .filter((tableName) => tableName !== options.missingTable)
    .sort(binaryCompare)
    .map((tableName) => ({
      table_name: tableName,
      table_type: "BASE TABLE",
      engine: "InnoDB",
      table_collation: options.invalidCollation
        ? "latin1_swedish_ci"
        : options.tableCollation ?? "utf8mb4_unicode_ci"
    }));
}

function columnRows(
  componentId: OrganizationReconciliationMysqlRawComponentId,
  options: FakeOptions,
  pass: number
) {
  const output: Array<Record<string, unknown>> = [];
  for (const [tableName, requirement] of Object.entries(componentRequirement(componentId).tables).sort(([left], [right]) => binaryCompare(left, right))) {
    if (tableName === options.missingTable) continue;
    let ordinal = 0;
    for (const columnName of requirement.columns) {
      ordinal += 1;
      if (columnName === options.missingColumn) continue;
      output.push({
        table_name: tableName,
        column_name: columnName,
        data_type: "varchar",
        column_type: options.mutatePassBColumnType && pass === 1 && ordinal === 1 ? "varchar(65)" : "varchar(64)",
        is_nullable: "NO",
        character_set_name: options.characterSet ?? "utf8mb4",
        collation_name: options.tableCollation ?? "utf8mb4_unicode_ci",
        ordinal_position: ordinal
      });
    }
  }
  const targetTable = Object.keys(componentRequirement(componentId).tables).sort(binaryCompare)[0] as string;
  const baseOrdinal = output.filter((row) => row.table_name === targetTable).length;
  for (let index = 0; index < (options.extraColumnCount ?? 0); index += 1) {
    output.splice(baseOrdinal + index, 0, {
      table_name: targetTable,
      column_name: `extra_${String(index).padStart(4, "0")}`,
      data_type: "varchar",
      column_type: "varchar(64)",
      is_nullable: "YES",
      character_set_name: options.characterSet ?? "utf8mb4",
      collation_name: options.tableCollation ?? "utf8mb4_unicode_ci",
      ordinal_position: baseOrdinal + index + 1
    });
  }
  return output;
}

function indexRows(componentId: OrganizationReconciliationMysqlRawComponentId, options: FakeOptions) {
  const rows: Array<Record<string, unknown>> = [];
  const keys = new Map<string, { readonly tableName: string; readonly columns: readonly string[] }>();
  for (const datasetRequirement of Object.values(componentRequirement(componentId).datasets)) {
    for (const requirement of datasetRequirement.deterministicUniqueKeys) {
      keys.set(`${requirement.tableName}\u001f${requirement.columns.join("\u001f")}`, requirement);
    }
  }
  let keyNumber = 0;
  for (const requirement of [...keys.values()].sort((left, right) => {
    const table = binaryCompare(left.tableName, right.tableName);
    return table !== 0 ? table : binaryCompare(left.columns.join("\u001f"), right.columns.join("\u001f"));
  })) {
    const tableName = requirement.tableName;
    if (tableName === options.missingTable) continue;
    keyNumber += 1;
    let columns = [...requirement.columns].filter((columnName) => columnName !== options.missingUniqueKeyColumn);
    if (tableName === options.mutateUniqueKeyTable && options.uniqueKeyMutation === "truncate") {
      columns = columns.slice(0, 1);
    }
    if (tableName === options.mutateUniqueKeyTable && options.uniqueKeyMutation === "reverse") columns.reverse();
    for (const [index, columnName] of columns.entries()) {
      rows.push({
        table_name: tableName,
        index_name: `idx_probe_${String(keyNumber).padStart(3, "0")}`,
        non_unique: tableName === options.mutateUniqueKeyTable && options.uniqueKeyMutation === "non-unique" ? 1 : 0,
        seq_in_index: index + 1,
        column_name: columnName,
        index_collation: "A",
        sub_part: tableName === options.mutateUniqueKeyTable && options.uniqueKeyMutation === "prefix" ? 8 : 0,
        index_type: tableName === options.mutateUniqueKeyTable && options.uniqueKeyMutation === "hash" ? "HASH" : "BTREE",
        is_visible: tableName === options.mutateUniqueKeyTable && options.uniqueKeyMutation === "invisible" ? "NO" : "YES"
      });
    }
  }
  const extraTable = Object.keys(componentRequirement(componentId).tables).sort(binaryCompare)[0] as string;
  const extraColumn = componentRequirement(componentId).tables[extraTable]?.columns[0] as string;
  for (let index = 0; index < (options.extraIndexCount ?? 0); index += 1) {
    rows.push({
      table_name: extraTable,
      index_name: `zz_extra_${String(index).padStart(4, "0")}`,
      non_unique: 1,
      seq_in_index: 1,
      column_name: extraColumn,
      index_collation: "A",
      sub_part: 0,
      index_type: "BTREE",
      is_visible: "YES"
    });
  }
  return rows.sort((left, right) => {
    const table = binaryCompare(String(left.table_name), String(right.table_name));
    if (table !== 0) return table;
    const index = binaryCompare(String(left.index_name), String(right.index_name));
    return index !== 0 ? index : Number(left.seq_in_index) - Number(right.seq_in_index);
  });
}

function componentRequirement(componentId: OrganizationReconciliationMysqlRawComponentId) {
  const component = ORGANIZATION_RECONCILIATION_DEVELOP_PHYSICAL_CATALOG.components
    .find((candidate) => candidate.componentId === componentId);
  if (component === undefined) throw new Error("missing-test-component");
  return component as unknown as {
    readonly tables: Readonly<Record<string, {
      readonly columns: readonly string[];
    }>>;
    readonly datasets: Readonly<Record<string, {
      readonly statementId: string;
      readonly deterministicUniqueKeys: readonly {
        readonly tableName: string;
        readonly columns: readonly string[];
        readonly purpose: "cursor-uniqueness" | "join-cardinality";
      }[];
    }>>;
  };
}

function binaryCompare(left: string, right: string): number {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function baseConfig(): IdentityConfig {
  return {
    legacyDb: {
      host: "shared-develop-db",
      port: 3306,
      name: "bujiaban_development",
      user: "legacy-service",
      password: "legacy-service-secret"
    },
    identityDb: {
      host: "shared-develop-db",
      port: 3306,
      name: "xrugc_identity_dev",
      user: "identity-service",
      password: "identity-service-secret"
    }
  } as IdentityConfig;
}

function baseEnv(): NodeJS.ProcessEnv {
  return {
    LEGACY_DB_HOST: "shared-develop-db",
    LEGACY_DB_PORT: "3306",
    LEGACY_DB_NAME: "bujiaban_development",
    LEGACY_DB_USER: "legacy-service",
    LEGACY_DB_PASSWORD: "legacy-service-secret",
    IDENTITY_DB_HOST: "shared-develop-db",
    IDENTITY_DB_PORT: "3306",
    IDENTITY_DB_NAME: "xrugc_identity_dev",
    IDENTITY_DB_USER: "identity-service",
    IDENTITY_DB_PASSWORD: "identity-service-secret",
    IDENTITY_IAM_ORG_RECONCILIATION_LEGACY_DB_USER: USERS["legacy-main"],
    IDENTITY_IAM_ORG_RECONCILIATION_LEGACY_DB_PASSWORD: "legacy-probe-secret",
    IDENTITY_IAM_ORG_RECONCILIATION_IDENTITY_DB_USER: USERS.identity,
    IDENTITY_IAM_ORG_RECONCILIATION_IDENTITY_DB_PASSWORD: "identity-probe-secret",
    IDENTITY_IAM_ORG_RECONCILIATION_PLUGIN_SERVICE_DB_USER: "plugin-service",
    PLUGIN_DB_HOST: "shared-develop-db",
    PLUGIN_DB_PORT: "3306",
    PLUGIN_DB_NAME: "bujiaban_development_plugin",
    PLUGIN_DB_USER: USERS.plugin,
    PLUGIN_DB_PASSWORD: "plugin-probe-secret",
    IDENTITY_BUILD_REVISION: "a".repeat(40)
  };
}
