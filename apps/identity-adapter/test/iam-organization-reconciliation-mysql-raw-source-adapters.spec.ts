import { describe, expect, it, vi } from "vitest";
import {
  ORGANIZATION_RECONCILIATION_PAGINATION_MODE,
  ORGANIZATION_RECONCILIATION_SNAPSHOT_MODE
} from "../src/iam-organization-reconciliation-collector.js";
import {
  ORGANIZATION_RECONCILIATION_MYSQL_RAW_ADAPTER_CONTRACT,
  ORGANIZATION_RECONCILIATION_MYSQL_RAW_SOURCE_ADAPTERS_READY,
  openIdentityMysqlRawSnapshot,
  openLegacyMainMysqlRawSnapshot,
  openPluginRegistryMysqlRawSnapshot,
  organizationReconciliationMysqlRawAdapterReadiness,
  type OpenOrganizationReconciliationMysqlRawSnapshotOptions
} from "../src/iam-organization-reconciliation/mysql-source-adapters/raw-source-snapshots.js";
import {
  ORGANIZATION_RECONCILIATION_DEVELOP_IAM_POLICY_CHECKSUM,
  ORGANIZATION_RECONCILIATION_MYSQL_STATEMENTS,
  ORGANIZATION_RECONCILIATION_MYSQL_STATEMENT_CATALOG_SHA256,
  type MysqlRepeatableReadSnapshotConnection,
  type OrganizationReconciliationMysqlStatementId
} from "../src/iam-organization-reconciliation/mysql-repeatable-read-snapshot.js";

const SET_REPEATABLE_READ = "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ";
const START_READ_ONLY_SNAPSHOT = "START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY";

describe("organization reconciliation source-specific MySQL raw adapters", () => {
  it("stays deliberately unwired and enumerates unresolved owner/schema blockers", () => {
    expect(ORGANIZATION_RECONCILIATION_MYSQL_RAW_SOURCE_ADAPTERS_READY).toBe(false);
    expect(organizationReconciliationMysqlRawAdapterReadiness()).toEqual({
      ready: false,
      blockers: [
        "runtime-source-adapter-wiring-disabled",
        "compiled-owner-dataset-catalog-not-registered",
        "trusted-physical-source-binding-not-registered",
        "identity-dataset-source-status-selectors-not-owner-approved",
        "identity-shadow-versus-candidate-read-model-not-owner-approved",
        "plugin-registry-schema-version-not-owner-approved",
        "plugin-static-overlay-precedence-not-owner-approved",
        "mysql-collation-and-ordering-not-owner-approved"
      ]
    });
  });

  it("opens only through injected dependencies and keeps component and opaque source IDs distinct", async () => {
    const fake = fakeConnection();

    const snapshot = await openLegacyMainMysqlRawSnapshot({
      expectedSourceId: "legacy-main-db",
      connectionFactory: async () => fake.connection
    });

    expect(snapshot.metadata).toEqual({
      contract: ORGANIZATION_RECONCILIATION_MYSQL_RAW_ADAPTER_CONTRACT,
      componentId: "legacy-main",
      sourceId: "legacy-main-db",
      snapshotMode: ORGANIZATION_RECONCILIATION_SNAPSHOT_MODE,
      paginationMode: ORGANIZATION_RECONCILIATION_PAGINATION_MODE,
      statementCatalogSha256: ORGANIZATION_RECONCILIATION_MYSQL_STATEMENT_CATALOG_SHA256
    });

    // Exhaustion is a later lineage-layer requirement. Closing an otherwise
    // unused primitive is allowed and remains on this injected transaction.
    await snapshot.close("completed");
    expect(fake.queries.map(([sql]) => sql)).toEqual([
      SET_REPEATABLE_READ,
      START_READ_ONLY_SNAPSHOT,
      "COMMIT"
    ]);
    expect(fake.release).toHaveBeenCalledTimes(1);
  });

  it("reads all Legacy main datasets through fixed statement IDs and strict normalized rows", async () => {
    const directoryRow = {
      id: 3,
      name: "north-campus",
      title: "North Campus",
      created_at: 1_700_000_000,
      updated_at: 1_700_000_100
    };
    const fake = fakeConnection({
      "legacy-organization-directory-page/v3": [[directoryRow]],
      "legacy-subject-universe-page/v3": [[{ id: 9, status: 10 }]],
      "legacy-membership-page/v3": [[{ user_id: 9, organization_id: 3 }]],
      "legacy-role-assignment-page/v3": [[{ user_id: "9", item_name: "manager" }]],
      "legacy-rbac-edge-page/v1": [[{ parent: "manager", child: "organization.update" }]]
    });
    const snapshot = await openLegacyMainMysqlRawSnapshot(optionsFor(fake, "legacy-main-db"));

    const directory = await snapshot.readOrganizationDirectoryPage({ requestCursor: null, pageSize: 10 });
    const subjects = await snapshot.readSubjectUniversePage({ requestCursor: null, pageSize: 10 });
    const memberships = await snapshot.readMembershipPage({ requestCursor: null, pageSize: 10 });
    const roles = await snapshot.readRoleAssignmentPage({ requestCursor: null, pageSize: 10 });
    const edges = await snapshot.readRbacEdgePage({ requestCursor: null, pageSize: 10 });
    directoryRow.title = "mutated-after-read";

    expect(directory.records).toEqual([{
      legacyOrganizationId: "3",
      name: "north-campus",
      title: "North Campus",
      createdAt: 1_700_000_000,
      updatedAt: 1_700_000_100
    }]);
    expect(directory.records[0]).not.toBe(directoryRow);
    expect(Object.isFrozen(directory)).toBe(true);
    expect(Object.isFrozen(directory.records)).toBe(true);
    expect(Object.isFrozen(directory.records[0])).toBe(true);
    expect(subjects.records).toEqual([{ legacyUserId: "9", status: 10 }]);
    expect(memberships.records).toEqual([{ legacyUserId: "9", legacyOrganizationId: "3" }]);
    expect(roles.records).toEqual([{ legacyUserId: "9", roleName: "manager" }]);
    expect(edges.records).toEqual([{ parentName: "manager", childName: "organization.update" }]);
    expect([directory, subjects, memberships, roles, edges].every((page) => page.nextCursor === null)).toBe(true);

    expect(dataQueries(fake)).toEqual([
      [sql("legacy-organization-directory-page/v3"), [0, 10]],
      [sql("legacy-subject-universe-page/v3"), [0, 10]],
      [sql("legacy-membership-page/v3"), [0, 0, 0, 10]],
      [sql("legacy-role-assignment-page/v3"), [0, 0, "", 10]],
      [sql("legacy-rbac-edge-page/v1"), ["", "", "", 10]]
    ]);
    await snapshot.close("completed");
    expect(fake.queries.at(-1)?.[0]).toBe("COMMIT");
  });

  it("reads candidate, mapping, shadow, candidate-membership, and role-shadow Identity datasets", async () => {
    const fake = fakeConnection({
      "identity-organization-candidate-page/v3": [[{
        legacy_organization_id: 4,
        identity_organization_id: "legacy:4",
        name: "south-campus",
        title: "South Campus",
        source: "legacy",
        candidate_status: "candidate"
      }]],
      "identity-organization-id-map-page/v3": [[{
        legacy_organization_id: 4,
        identity_organization_id: "legacy:4",
        source: "legacy",
        mapping_status: "active"
      }]],
      "identity-membership-shadow-page/v3": [[{
        legacy_user_id: 12,
        organization_id: 4,
        organization_role: null,
        source: "legacy-shadow",
        status: "shadow"
      }]],
      "identity-membership-candidate-page/v3": [[{
        legacy_user_id: 12,
        legacy_organization_id: 4,
        identity_user_id: "legacy:12",
        identity_organization_id: "legacy:4",
        organization_role: "member",
        source: "legacy",
        candidate_status: "candidate",
        operation_key: "operation-12"
      }]],
      "identity-role-shadow-page/v3": [[{
        legacy_user_id: 12,
        role_name: "manager",
        source: "legacy-shadow",
        status: "shadow"
      }]]
    });
    const snapshot = await openIdentityMysqlRawSnapshot(optionsFor(fake, "identity-candidate-db"));

    const organizations = await snapshot.readOrganizationCandidatePage({ requestCursor: null, pageSize: 20 });
    const mappings = await snapshot.readOrganizationIdMapPage({ requestCursor: null, pageSize: 20 });
    const shadowMemberships = await snapshot.readMembershipShadowPage({ requestCursor: null, pageSize: 20 });
    const candidateMemberships = await snapshot.readMembershipCandidatePage({ requestCursor: null, pageSize: 20 });
    const shadowRoles = await snapshot.readRoleShadowPage({ requestCursor: null, pageSize: 20 });

    expect(organizations.records[0]).toEqual({
      legacyOrganizationId: "4",
      identityOrganizationId: "legacy:4",
      name: "south-campus",
      title: "South Campus",
      source: "legacy",
      candidateStatus: "candidate"
    });
    expect(mappings.records[0]).toEqual({
      legacyOrganizationId: "4",
      identityOrganizationId: "legacy:4",
      source: "legacy",
      mappingStatus: "active"
    });
    expect(shadowMemberships.records[0]).toEqual({
      legacyUserId: "12",
      legacyOrganizationId: "4",
      organizationRole: null,
      source: "legacy-shadow",
      status: "shadow"
    });
    expect(candidateMemberships.records[0]).toEqual({
      legacyUserId: "12",
      legacyOrganizationId: "4",
      identityUserId: "legacy:12",
      identityOrganizationId: "legacy:4",
      organizationRole: "member",
      source: "legacy",
      candidateStatus: "candidate",
      operationKey: "operation-12"
    });
    expect(shadowRoles.records[0]).toEqual({
      legacyUserId: "12", roleName: "manager", source: "legacy-shadow", status: "shadow"
    });
    expect(dataQueries(fake).map(([statement]) => statement)).toEqual([
      sql("identity-organization-candidate-page/v3"),
      sql("identity-organization-id-map-page/v3"),
      sql("identity-membership-shadow-page/v3"),
      sql("identity-membership-candidate-page/v3"),
      sql("identity-role-shadow-page/v3")
    ]);
    await snapshot.close("completed");
  });

  it("reads all Develop-pinned IAM and explicit completeness datasets without DDL", async () => {
    const checksum = ORGANIZATION_RECONCILIATION_DEVELOP_IAM_POLICY_CHECKSUM;
    const fake = fakeConnection({
      "identity-membership-candidate-snapshot-page/v1": [[{
        identity_user_id: "legacy:12", legacy_user_id: 12, operation_key: "operation-12",
        organization_count: 1, source: "legacy", candidate_status: "candidate"
      }]],
      "identity-iam-policy-version-page/v1": [[{
        checksum, source: "legacy-import-candidate", status: "candidate",
        role_count: "1", permission_count: 1n, relation_count: 1
      }]],
      "identity-iam-role-page/v1": [[{
        policy_checksum: checksum, role_name: "root", description: null,
        source: "legacy-import-candidate", status: "candidate"
      }]],
      "identity-iam-permission-page/v1": [[{
        policy_checksum: checksum, permission_name: "organization.update", description: "Update organization",
        source: "legacy-import-candidate", status: "candidate"
      }]],
      "identity-iam-item-relation-page/v1": [[{
        policy_checksum: checksum, parent_name: "root", parent_type: "role",
        child_name: "organization.update", child_type: "permission",
        source: "legacy-import-candidate", status: "candidate"
      }]],
      "identity-iam-subject-assignment-page/v1": [[{
        identity_user_id: "legacy:12", legacy_user_id: 12, item_name: "root", item_type: "role",
        policy_checksum: checksum, source: "legacy-import-candidate", status: "candidate"
      }]],
      "identity-iam-subject-assignment-snapshot-page/v1": [[{
        identity_user_id: "legacy:12", legacy_user_id: 12, policy_checksum: checksum,
        snapshot_key: checksum, assignment_count: "1",
        source: "legacy-import-candidate", status: "candidate"
      }]]
    });
    const snapshot = await openIdentityMysqlRawSnapshot(optionsFor(fake, "identity-candidate-db"));

    const membershipSnapshot = await snapshot.readMembershipCandidateSnapshotPage({ requestCursor: null, pageSize: 20 });
    const policy = await snapshot.readIamPolicyVersionPage({ requestCursor: null, pageSize: 20 });
    const roles = await snapshot.readIamRolePage({ requestCursor: null, pageSize: 20 });
    const permissions = await snapshot.readIamPermissionPage({ requestCursor: null, pageSize: 20 });
    const relations = await snapshot.readIamItemRelationPage({ requestCursor: null, pageSize: 20 });
    const assignments = await snapshot.readIamSubjectAssignmentPage({ requestCursor: null, pageSize: 20 });
    const assignmentSnapshots = await snapshot.readIamSubjectAssignmentSnapshotPage({ requestCursor: null, pageSize: 20 });

    expect(membershipSnapshot.records).toEqual([{
      identityUserId: "legacy:12", legacyUserId: "12", operationKey: "operation-12",
      organizationCount: 1, source: "legacy", candidateStatus: "candidate"
    }]);
    expect(policy.records).toEqual([{
      policyChecksum: checksum, source: "legacy-import-candidate", status: "candidate",
      roleCount: 1, permissionCount: 1, relationCount: 1
    }]);
    expect(roles.records[0]).toMatchObject({ policyChecksum: checksum, itemName: "root" });
    expect(permissions.records[0]).toMatchObject({ itemName: "organization.update" });
    expect(relations.records[0]).toMatchObject({ parentName: "root", childName: "organization.update" });
    expect(assignments.records[0]).toMatchObject({ identityUserId: "legacy:12", itemName: "root" });
    expect(assignmentSnapshots.records[0]).toMatchObject({
      identityUserId: "legacy:12", snapshotKey: checksum, assignmentCount: 1
    });
    expect(dataQueries(fake).map(([, parameters]) => parameters)).toEqual([
      [0, 0, "", 20],
      [checksum, "", 20],
      [checksum, "", 20],
      [checksum, "", 20],
      [checksum, "", "", "", 20],
      [checksum, 0, 0, "", 0, "", "", 20],
      [checksum, checksum, checksum, 0, 0, "", 20]
    ]);
    await snapshot.close("completed");
  });

  it("reads rule-free Legacy RBAC items and direct role-or-permission assignments", async () => {
    const fake = fakeConnection({
      "legacy-rbac-item-page/v1": [[{
        name: "organization.update", type: 2, description: null, rule_name: null
      }]],
      "legacy-rbac-assignment-page/v1": [[{
        user_id: 12, item_name: "organization.update", type: 2
      }]]
    });
    const snapshot = await openLegacyMainMysqlRawSnapshot(optionsFor(fake, "legacy-main-db"));
    const items = await snapshot.readRbacItemPage({ requestCursor: null, pageSize: 20 });
    const assignments = await snapshot.readRbacAssignmentPage({ requestCursor: null, pageSize: 20 });
    expect(items.records).toEqual([{
      itemName: "organization.update", itemType: "permission", description: null, ruleName: null
    }]);
    expect(assignments.records).toEqual([{
      legacyUserId: "12", itemName: "organization.update", itemType: "permission"
    }]);
    expect(dataQueries(fake)).toEqual([
      [sql("legacy-rbac-item-page/v1"), ["", 20]],
      [sql("legacy-rbac-assignment-page/v1"), [0, 0, "", 20]]
    ]);
    await snapshot.close("completed");

    const namedRule = fakeConnection({
      "legacy-rbac-item-page/v1": [[{
        name: "organization.update", type: 2, description: null, rule_name: "UnsafeRule"
      }]]
    });
    const namedRuleSnapshot = await openLegacyMainMysqlRawSnapshot(optionsFor(namedRule, "legacy-main-db"));
    await expect(namedRuleSnapshot.readRbacItemPage({ requestCursor: null, pageSize: 20 }))
      .rejects.toThrow("Reading the Legacy main MySQL reconciliation snapshot page failed");
    await namedRuleSnapshot.close("failed");
    expect(namedRule.queries.at(-1)?.[0]).toBe("ROLLBACK");
  });

  it("reads the plugin registry through its only fixed statement and exact owner-facing fields", async () => {
    const fake = fakeConnection({
      "plugin-registry-page/v3": [[{
        id: "system-admin",
        enabled: 1,
        access_scope: "admin-only",
        organization_name: "north-campus"
      }]]
    });
    const snapshot = await openPluginRegistryMysqlRawSnapshot(optionsFor(fake, "plugin-registry-db"));

    const page = await snapshot.readPluginRegistryPage({ requestCursor: null, pageSize: 100 });

    expect(page.componentId).toBe("plugin");
    expect(page.sourceId).toBe("plugin-registry-db");
    expect(page.records).toEqual([{
      pluginId: "system-admin",
      enabled: true,
      accessScope: "admin-only",
      organizationName: "north-campus"
    }]);
    expect(dataQueries(fake)).toEqual([[sql("plugin-registry-page/v3"), ["", 100]]]);
    await snapshot.close("completed");
  });

  it("binds an opaque keyset cursor to one Identity candidate-membership chain and permits a terminal empty page", async () => {
    const fake = fakeConnection({
      "identity-membership-candidate-page/v3": [
        [{
          legacy_user_id: 2,
          legacy_organization_id: 7,
          identity_user_id: "legacy:2",
          identity_organization_id: "legacy:7",
          organization_role: "member",
          source: "legacy", candidate_status: "candidate", operation_key: "operation-2"
        }],
        [{
          legacy_user_id: 2,
          legacy_organization_id: 7,
          identity_user_id: "legacy:2",
          identity_organization_id: "legacy:8",
          organization_role: "member",
          source: "legacy", candidate_status: "candidate", operation_key: "operation-2"
        }],
        []
      ]
    });
    const snapshot = await openIdentityMysqlRawSnapshot(optionsFor(fake, "identity-candidate-db"));

    const first = await snapshot.readMembershipCandidatePage({ requestCursor: null, pageSize: 1 });
    const second = await snapshot.readMembershipCandidatePage({ requestCursor: first.nextCursor, pageSize: 1 });
    const terminal = await snapshot.readMembershipCandidatePage({ requestCursor: second.nextCursor, pageSize: 1 });

    expect(first.nextCursor).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(second.nextCursor).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(second.nextCursor).not.toBe(first.nextCursor);
    expect(second.recordOffset).toBe(1);
    expect(terminal).toMatchObject({ recordOffset: 2, records: [], nextCursor: null });
    expect(dataQueries(fake).map(([, parameters]) => parameters)).toEqual([
      [0, 0, "", "", "", 1],
      ["2", "7", "legacy:2", "legacy:7", "operation-2", 1],
      ["2", "7", "legacy:2", "legacy:8", "operation-2", 1]
    ]);
    await snapshot.close("completed");
  });

  it("paginates Legacy RBAC edges by UTF-8 byte tuples and reaches an explicit terminal page", async () => {
    const bytewiseFirst = "\uE000";
    const bytewiseSecond = "\u{10000}";
    // JS UTF-16 orders the supplementary character first; UTF-8 bytes order it second.
    expect(bytewiseSecond < bytewiseFirst).toBe(true);
    const fake = fakeConnection({
      "legacy-rbac-edge-page/v1": [[
        { parent: bytewiseFirst, child: "child-z" },
        { parent: bytewiseSecond, child: "child-a" }
      ], []]
    });
    const snapshot = await openLegacyMainMysqlRawSnapshot(optionsFor(fake, "legacy-main-db"));

    const first = await snapshot.readRbacEdgePage({ requestCursor: null, pageSize: 2 });
    const terminal = await snapshot.readRbacEdgePage({ requestCursor: first.nextCursor, pageSize: 2 });

    expect(first.records).toEqual([
      { parentName: bytewiseFirst, childName: "child-z" },
      { parentName: bytewiseSecond, childName: "child-a" }
    ]);
    expect(first.nextCursor).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(terminal).toMatchObject({ recordOffset: 2, records: [], nextCursor: null });
    expect(dataQueries(fake)).toEqual([
      [sql("legacy-rbac-edge-page/v1"), ["", "", "", 2]],
      [sql("legacy-rbac-edge-page/v1"), [bytewiseSecond, bytewiseSecond, "child-a", 2]]
    ]);
    await snapshot.close("completed");
    expect(fake.queries.at(-1)?.[0]).toBe("COMMIT");
  });

  it("fails closed on malformed or non-byte-ordered Legacy RBAC edges", async () => {
    let getterInvoked = false;
    const accessor = Object.defineProperty({ child: "child" }, "parent", {
      enumerable: true,
      get: () => { getterInvoked = true; return "parent"; }
    });
    const symbolic = { parent: "parent", child: "child", [Symbol("hidden")]: true };
    const extra = { parent: "parent", child: "child", rule: "hidden" };
    const customPrototype = Object.assign(Object.create({ inherited: true }), {
      parent: "parent", child: "child"
    });
    const malformedRows: readonly unknown[] = [
      accessor,
      symbolic,
      extra,
      customPrototype,
      new Proxy({ parent: "parent", child: "child" }, {}),
      { parent: "", child: "child" },
      { parent: "parent", child: " child" },
      { parent: "parent", child: "e\u0301" },
      { parent: "p".repeat(65), child: "child" }
    ];
    for (const row of malformedRows) {
      const fake = fakeConnection({ "legacy-rbac-edge-page/v1": [[row]] });
      const snapshot = await openLegacyMainMysqlRawSnapshot(optionsFor(fake, "legacy-main-db"));
      await expect(snapshot.readRbacEdgePage({ requestCursor: null, pageSize: 10 }))
        .rejects.toThrow("Reading the Legacy main MySQL reconciliation snapshot page failed");
      await snapshot.close("failed");
      expect(fake.queries.at(-1)?.[0]).toBe("ROLLBACK");
    }
    expect(getterInvoked).toBe(false);

    const reversed = fakeConnection({
      "legacy-rbac-edge-page/v1": [[
        { parent: "\u{10000}", child: "child" },
        { parent: "\uE000", child: "child" }
      ]]
    });
    const snapshot = await openLegacyMainMysqlRawSnapshot(optionsFor(reversed, "legacy-main-db"));
    await expect(snapshot.readRbacEdgePage({ requestCursor: null, pageSize: 10 }))
      .rejects.toThrow("Reading the Legacy main MySQL reconciliation snapshot page failed");
    await expect(snapshot.close("completed"))
      .rejects.toThrow("Closing the Legacy main MySQL reconciliation snapshot failed");
    expect(reversed.queries.at(-1)?.[0]).toBe("ROLLBACK");
  });

  it("poisons a forged Legacy RBAC edge cursor before SQL", async () => {
    const fake = fakeConnection();
    const snapshot = await openLegacyMainMysqlRawSnapshot(optionsFor(fake, "legacy-main-db"));

    await expect(snapshot.readRbacEdgePage({ requestCursor: "forged-cursor", pageSize: 10 }))
      .rejects.toThrow("Reading the Legacy main MySQL reconciliation snapshot page failed");
    expect(dataQueries(fake)).toEqual([]);
    await expect(snapshot.close("completed"))
      .rejects.toThrow("Closing the Legacy main MySQL reconciliation snapshot failed");
    expect(fake.queries.at(-1)?.[0]).toBe("ROLLBACK");
  });

  it("poisons an invalid cursor chain before SQL and makes a completed close fail after rollback", async () => {
    const fake = fakeConnection();
    const snapshot = await openLegacyMainMysqlRawSnapshot(optionsFor(fake, "legacy-main-db"));

    const failure = await snapshot.readMembershipPage({ requestCursor: "forged-cursor", pageSize: 10 })
      .catch((error: unknown) => error);
    const closeFailure = await snapshot.close("completed").catch((error: unknown) => error);

    expect(failure).toEqual(new Error("Reading the Legacy main MySQL reconciliation snapshot page failed."));
    expect(closeFailure).toEqual(new Error("Closing the Legacy main MySQL reconciliation snapshot failed."));
    expect(dataQueries(fake)).toEqual([]);
    expect(fake.queries.at(-1)?.[0]).toBe("ROLLBACK");
    expect(fake.release).toHaveBeenCalledTimes(1);
  });

  it("redacts connection-factory and driver secrets and rolls every uncertain snapshot back", async () => {
    const bindingFake = fakeConnection();
    const bindingFailure = await openIdentityMysqlRawSnapshot({
      expectedSourceId: "identity-candidate-db",
      async connectionFactory() {
        throw new Error("mysql://private-user:private-binding-secret@identity-db");
      }
    }).catch((error: unknown) => error);
    expect(bindingFailure).toEqual(new Error("Opening the Identity MySQL reconciliation snapshot failed."));
    expect(JSON.stringify(bindingFailure)).not.toContain("private-binding-secret");
    expect(bindingFake.queries).toEqual([]);

    const queryFake = fakeConnection({}, {
      failSql: sql("legacy-subject-universe-page/v3"),
      secret: "private-driver-secret"
    });
    const snapshot = await openLegacyMainMysqlRawSnapshot(optionsFor(queryFake, "legacy-main-db"));
    const readFailure = await snapshot.readSubjectUniversePage({ requestCursor: null, pageSize: 10 })
      .catch((error: unknown) => error);
    const closeFailure = await snapshot.close("completed").catch((error: unknown) => error);
    expect(readFailure).toEqual(new Error("Reading the Legacy main MySQL reconciliation snapshot page failed."));
    expect(JSON.stringify(readFailure)).not.toContain("private-driver-secret");
    expect(closeFailure).toEqual(new Error("Closing the Legacy main MySQL reconciliation snapshot failed."));
    expect(queryFake.queries.at(-1)?.[0]).toBe("ROLLBACK");
  });

  it("captures open dependencies without invoking getters and rejects extra wiring fields before opening", async () => {
    const sourceIdGetter = vi.fn(() => "legacy-main-db");
    const connectionFactory = vi.fn(async () => fakeConnection().connection);
    const getterOptions = Object.defineProperty({
      connectionFactory
    }, "expectedSourceId", {
      enumerable: true,
      get: sourceIdGetter
    });

    const getterFailure = await openLegacyMainMysqlRawSnapshot(getterOptions as never)
      .catch((error: unknown) => error);
    expect(getterFailure).toEqual(new Error("Opening the Legacy main MySQL reconciliation snapshot failed."));
    expect(sourceIdGetter).not.toHaveBeenCalled();
    expect(connectionFactory).not.toHaveBeenCalled();

    const extraFieldFailure = await openLegacyMainMysqlRawSnapshot({
      expectedSourceId: "legacy-main-db",
      connectionFactory,
      unexpectedDatabase: "must-not-be-read"
    } as never).catch((error: unknown) => error);
    expect(extraFieldFailure).toEqual(new Error("Opening the Legacy main MySQL reconciliation snapshot failed."));
    expect(connectionFactory).not.toHaveBeenCalled();
  });

  it("rejects getters, symbols, custom prototypes, unknown fields, and non-canonical ordering", async () => {
    const getter = vi.fn(() => 1);
    const getterRow = {
      get id() { return getter(); },
      name: "north-campus",
      title: "North Campus",
      created_at: 1,
      updated_at: 1
    };
    const symbolRow = {
      id: 1,
      name: "north-campus",
      title: "North Campus",
      created_at: 1,
      updated_at: 1,
      [Symbol("hidden")]: "secret"
    };
    const prototypeRow = Object.assign(Object.create({ inherited: true }), {
      id: 1,
      name: "north-campus",
      title: "North Campus",
      created_at: 1,
      updated_at: 1
    });
    const unknownFieldRow = {
      id: 1,
      name: "north-campus",
      title: "North Campus",
      created_at: 1,
      updated_at: 1,
      password: "must-not-be-accepted"
    };

    for (const row of [getterRow, symbolRow, prototypeRow, unknownFieldRow]) {
      const fake = fakeConnection({ "legacy-organization-directory-page/v3": [[row]] });
      const snapshot = await openLegacyMainMysqlRawSnapshot(optionsFor(fake, "legacy-main-db"));
      const failure = await snapshot.readOrganizationDirectoryPage({ requestCursor: null, pageSize: 10 })
        .catch((error: unknown) => error);
      expect(failure).toEqual(new Error("Reading the Legacy main MySQL reconciliation snapshot page failed."));
      await snapshot.close("failed");
    }
    expect(getter).not.toHaveBeenCalled();

    const unorderedFake = fakeConnection({
      "legacy-subject-universe-page/v3": [[{ id: 2, status: 10 }, { id: 1, status: 10 }]]
    });
    const unordered = await openLegacyMainMysqlRawSnapshot(optionsFor(unorderedFake, "legacy-main-db"));
    const orderFailure = await unordered.readSubjectUniversePage({ requestCursor: null, pageSize: 10 })
      .catch((error: unknown) => error);
    expect(orderFailure).toEqual(new Error("Reading the Legacy main MySQL reconciliation snapshot page failed."));
    const closeFailure = await unordered.close("completed").catch((error: unknown) => error);
    expect(closeFailure).toEqual(new Error("Closing the Legacy main MySQL reconciliation snapshot failed."));
    expect(unorderedFake.queries.at(-1)?.[0]).toBe("ROLLBACK");
  });

  it("rejects lifecycle/status selector drift instead of treating unapproved Identity rows as reconciled", async () => {
    const fake = fakeConnection({
      "identity-organization-candidate-page/v3": [[{
        legacy_organization_id: 4,
        identity_organization_id: "legacy:4",
        name: "south-campus",
        title: "South Campus",
        source: "legacy",
        candidate_status: "active"
      }]]
    });
    const snapshot = await openIdentityMysqlRawSnapshot(optionsFor(fake, "identity-candidate-db"));

    const failure = await snapshot.readOrganizationCandidatePage({ requestCursor: null, pageSize: 10 })
      .catch((error: unknown) => error);
    expect(failure).toEqual(new Error("Reading the Identity MySQL reconciliation snapshot page failed."));
    const closeFailure = await snapshot.close("completed").catch((error: unknown) => error);
    expect(closeFailure).toEqual(new Error("Closing the Identity MySQL reconciliation snapshot failed."));
    expect(fake.queries.at(-1)?.[0]).toBe("ROLLBACK");
  });

  it("accepts valid composite-key ordering across numeric digit and string length transitions", async () => {
    const legacyFake = fakeConnection({
      "legacy-membership-page/v3": [[
        { user_id: 99_999, organization_id: 1 },
        { user_id: 100_000, organization_id: 1 }
      ]]
    });
    const legacy = await openLegacyMainMysqlRawSnapshot(optionsFor(legacyFake, "legacy-main-db"));
    const memberships = await legacy.readMembershipPage({ requestCursor: null, pageSize: 10 });
    expect(memberships.records.map((record) => record.legacyUserId)).toEqual(["99999", "100000"]);
    await legacy.close("completed");

    const identityFake = fakeConnection({
      "identity-membership-candidate-page/v3": [[
        {
          legacy_user_id: 1,
          legacy_organization_id: 1,
          identity_user_id: "aa",
          identity_organization_id: "legacy:1",
          organization_role: "member",
          source: "legacy", candidate_status: "candidate", operation_key: "operation-1"
        },
        {
          legacy_user_id: 1,
          legacy_organization_id: 1,
          identity_user_id: "z",
          identity_organization_id: "legacy:1",
          organization_role: "member",
          source: "legacy", candidate_status: "candidate", operation_key: "operation-1"
        }
      ]]
    });
    const identity = await openIdentityMysqlRawSnapshot(optionsFor(identityFake, "identity-candidate-db"));
    const candidates = await identity.readMembershipCandidatePage({ requestCursor: null, pageSize: 10 });
    expect(candidates.records.map((record) => record.identityUserId)).toEqual(["aa", "z"]);
    await identity.close("completed");
  });

  it("makes close idempotent, waits for accepted reads, and rejects reads after close starts", async () => {
    const fake = fakeConnection({ "plugin-registry-page/v3": [[]] });
    const snapshot = await openPluginRegistryMysqlRawSnapshot(optionsFor(fake, "plugin-registry-db"));

    const read = snapshot.readPluginRegistryPage({ requestCursor: null, pageSize: 10 });
    const firstClose = snapshot.close("completed");
    const duplicateClose = snapshot.close("failed");
    const lateRead = await snapshot.readPluginRegistryPage({ requestCursor: null, pageSize: 10 })
      .catch((error: unknown) => error);
    await Promise.all([read, firstClose, duplicateClose]);

    expect(lateRead).toEqual(new Error("The plugin registry MySQL reconciliation snapshot is closed."));
    expect(fake.queries.at(-1)?.[0]).toBe("COMMIT");
    expect(fake.release).toHaveBeenCalledTimes(1);
  });
});

function optionsFor(
  fake: ReturnType<typeof fakeConnection>,
  expectedSourceId: string
): OpenOrganizationReconciliationMysqlRawSnapshotOptions {
  return {
    expectedSourceId,
    connectionFactory: async () => fake.connection
  };
}

function sql(statementId: OrganizationReconciliationMysqlStatementId): string {
  return ORGANIZATION_RECONCILIATION_MYSQL_STATEMENTS[statementId];
}

function dataQueries(
  fake: ReturnType<typeof fakeConnection>
): Array<readonly [string, readonly unknown[] | undefined]> {
  const reviewed = new Set<string>(Object.values(ORGANIZATION_RECONCILIATION_MYSQL_STATEMENTS));
  return fake.queries.filter(([candidate]) => reviewed.has(candidate));
}

function fakeConnection(
  responsePages: Partial<Record<OrganizationReconciliationMysqlStatementId, readonly unknown[][]>> = {},
  failure: { readonly failSql?: string; readonly secret?: string; readonly failRelease?: boolean } = {}
): {
  readonly connection: MysqlRepeatableReadSnapshotConnection;
  readonly queries: Array<readonly [string, readonly unknown[] | undefined]>;
  readonly release: ReturnType<typeof vi.fn>;
} {
  const queries: Array<readonly [string, readonly unknown[] | undefined]> = [];
  const queues = new Map<string, unknown[][]>();
  for (const [statementId, pages] of Object.entries(responsePages)) {
    queues.set(sql(statementId as OrganizationReconciliationMysqlStatementId), [...pages]);
  }
  const release = vi.fn(() => {
    if (failure.failRelease) throw new Error(failure.secret ?? "private-release-secret");
  });
  const connection: MysqlRepeatableReadSnapshotConnection = {
    async query(statement, parameters) {
      queries.push([statement, parameters]);
      if (statement === failure.failSql) throw new Error(failure.secret ?? "private-query-secret");
      const rows = queues.get(statement)?.shift() ?? [];
      return [rows, []];
    },
    release
  };
  return { connection, queries, release };
}
