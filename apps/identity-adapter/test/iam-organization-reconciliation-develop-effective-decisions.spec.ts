import { describe, expect, it, vi } from "vitest";
import {
  ORGANIZATION_OWNER_DEVELOP_APPROVED_REGISTRY_CANDIDATE,
  ORGANIZATION_OWNER_DEVELOP_DECISION_CATALOGS
} from "../src/iam-organization-owner-semantic-registry.js";
import {
  collectOrganizationReconciliationDatasetLineage,
  type OrganizationReconciliationDatasetComponentBinding,
  type OrganizationReconciliationDatasetPage,
  type OrganizationReconciliationDatasetSourceAdapter
} from "../src/iam-organization-reconciliation-dataset-lineage.js";
import {
  ORGANIZATION_RECONCILIATION_DEVELOP_EFFECTIVE_DECISION_BLOCKERS,
  ORGANIZATION_RECONCILIATION_DEVELOP_EFFECTIVE_DECISIONS_READY,
  projectDevelopIdentityEffectiveDecisions,
  projectDevelopLegacyEffectiveDecisions
} from "../src/iam-organization-reconciliation-develop-effective-decisions.js";
import {
  createDevelopProjectionSnapshotViews
} from "../src/iam-organization-reconciliation-develop-projection-views.js";
import {
  ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG
} from "../src/iam-organization-reconciliation-develop-source-catalog.js";
import {
  ORGANIZATION_RECONCILIATION_PAGINATION_MODE,
  ORGANIZATION_RECONCILIATION_SNAPSHOT_MODE,
  type OrganizationReconciliationSourceSnapshot
} from "../src/iam-organization-reconciliation-collector.js";
import {
  createOrganizationReconciliationComponentDatasetInventory,
  createOrganizationReconciliationContentSnapshotId,
  createOrganizationReconciliationContentSourceVersion,
  type OrganizationReconciliationDatasetInventoryPageInput,
  type OrganizationReconciliationInventoryJsonValue
} from "../src/iam-organization-reconciliation-dataset-inventory.js";
import type { OrganizationReconciliationPhysicalSource } from
  "../src/iam-organization-reconciliation-component-manifest.js";
import {
  ORGANIZATION_RECONCILIATION_DEVELOP_IAM_POLICY_CHECKSUM
} from "../src/iam-organization-reconciliation/mysql-repeatable-read-snapshot.js";

type Scalar = string | number | boolean | null;
type JsonRecord = Record<string, Scalar>;
type RecordsByComponent = Record<OrganizationReconciliationPhysicalSource, Record<string, JsonRecord[]>>;
type Mutable<T> = { -readonly [K in keyof T]: T[K] };

interface Fixture {
  readonly componentId: OrganizationReconciliationPhysicalSource;
  readonly snapshot: Mutable<OrganizationReconciliationSourceSnapshot>;
  readonly binding: OrganizationReconciliationDatasetComponentBinding;
  readonly adapter: OrganizationReconciliationDatasetSourceAdapter<unknown>;
}

const BASE_TIME = Date.parse("2026-08-11T00:00:00.000Z");
const CHECKSUM = ORGANIZATION_RECONCILIATION_DEVELOP_IAM_POLICY_CHECKSUM;
const EXACT_CAPABILITY_EXECUTION_AUTHORIZED =
  (ORGANIZATION_OWNER_DEVELOP_DECISION_CATALOGS.capabilityCatalog as unknown as {
    executionState?: unknown;
  }).executionState === "owner-bound-context-decision-execution";
const CAMPUS_CONTEXT_EXECUTION_AUTHORIZED =
  (ORGANIZATION_OWNER_DEVELOP_DECISION_CATALOGS.campusPublicContext as unknown as {
    executionState?: unknown;
  }).executionState === "owner-bound-campus-context-decision-execution";

describe("xrteeth Develop effective-decision readiness", () => {
  it("authorizes only exact Develop read-only context decisions and keeps production unready", () => {
    expect(ORGANIZATION_OWNER_DEVELOP_DECISION_CATALOGS.capabilityCatalog.entries).toHaveLength(20);
    expect(EXACT_CAPABILITY_EXECUTION_AUTHORIZED).toBe(true);
    expect(CAMPUS_CONTEXT_EXECUTION_AUTHORIZED).toBe(true);
    expect(ORGANIZATION_RECONCILIATION_DEVELOP_EFFECTIVE_DECISIONS_READY).toBe(false);
    expect(ORGANIZATION_RECONCILIATION_DEVELOP_EFFECTIVE_DECISION_BLOCKERS).toEqual([
      "effective-decision-production-pipeline-not-registered"
    ]);
  });
});

describe(
  "xrteeth Develop independent effective-decision evaluators",
() => {
  it("projects both physical graphs over the complete subject x (organization + 2) x approved-capability universe", async () => {
    const views = createDevelopProjectionSnapshotViews(await collect(createFixtures()));
    const registrySha256 = ORGANIZATION_OWNER_DEVELOP_APPROVED_REGISTRY_CANDIDATE.registrySha256;
    const legacy = projectDevelopLegacyEffectiveDecisions(views.legacy, registrySha256);
    const identity = projectDevelopIdentityEffectiveDecisions(views.identity, registrySha256);
    const entries = capabilityEntries();

    expect(entries).toHaveLength(20);
    expect(legacy.effectiveDecisions).toHaveLength(3 * (1 + 2) * 20);
    expect(identity.effectiveDecisions).toEqual(legacy.effectiveDecisions);
    expect(identity.effectiveDecisions).not.toBe(legacy.effectiveDecisions);
    expect(identity.effectiveDecisions[0]).not.toBe(legacy.effectiveDecisions[0]);
    expect(Object.isFrozen(identity.effectiveDecisions)).toBe(true);
    expect(Object.isFrozen(identity.effectiveDecisions[0])).toBe(true);
    expect(identity).toMatchObject({
      side: "identity",
      evaluator: "identity-exact-pinned-candidate-rule-free-graph",
      policyChecksum: CHECKSUM,
      productionReady: false,
      blockers: ["effective-decision-production-pipeline-not-registered"]
    });
    expect(legacy).toMatchObject({
      side: "legacy",
      evaluator: "legacy-live-yii-rule-free-graph",
      policyChecksum: "legacy-snapshot-bound",
      productionReady: false
    });
    expect(new Set(identity.effectiveDecisions.map((row) => `${row.contextKind}\u0000${row.contextRef}`)))
      .toEqual(new Set([
        "organization\u0000legacy-org:7",
        "platform-global\u0000org:platform-global",
        "public\u0000org:public"
      ]));

    expect(decision(identity.effectiveDecisions, "legacy-user:1", capability("manage-global-tools"))).toBe("allow");
    expect(decision(identity.effectiveDecisions, "legacy-user:2", capability("manage-global-tools"))).toBe("deny");
    expect(decision(identity.effectiveDecisions, "legacy-user:2", capability("view-dashboard"))).toBe("allow");
    expect(decision(identity.effectiveDecisions, "legacy-user:2", capabilityForPermission("organization.list"))).toBe("deny");
    expect(decision(identity.effectiveDecisions, "legacy-user:2", capabilityForPermission("user-management.list-users"))).toBe("deny");
    expect(decision(identity.effectiveDecisions, "legacy-user:1", capabilityForPermission("user-management.list-users"))).toBe("deny");

    expect(decisionAt(
      identity.effectiveDecisions,
      "legacy-user:1",
      "platform-global",
      capability("manage-student-accounts")
    )).toBe("deny");
    expect(decisionAt(
      identity.effectiveDecisions,
      "legacy-user:2",
      "platform-global",
      capabilityForPermission("organization.list")
    )).toBe("allow");
    expect(decisionAt(
      identity.effectiveDecisions,
      "legacy-user:2",
      "platform-global",
      capabilityForPermission("organization.create")
    )).toBe("deny");
    expect(decisionAt(
      identity.effectiveDecisions,
      "legacy-user:1",
      "platform-global",
      capabilityForPermission("user-management.list-users")
    )).toBe("allow");
    expect(decisionAt(
      identity.effectiveDecisions,
      "legacy-user:2",
      "platform-global",
      capabilityForPermission("user-management.list-users")
    )).toBe("deny");

    for (const publicCapability of ["manage-student-accounts", "view-students"] as const) {
      expect(decisionAt(
        identity.effectiveDecisions,
        "legacy-user:1",
        "public",
        capability(publicCapability)
      )).toBe("allow");
      expect(decisionAt(
        identity.effectiveDecisions,
        "legacy-user:2",
        "public",
        capability(publicCapability)
      )).toBe("deny");
    }
    expect(decisionAt(
      identity.effectiveDecisions,
      "legacy-user:1",
      "public",
      capability("view-dashboard")
    )).toBe("deny");
    expect(identity.effectiveDecisions
      .filter((row) => row.subjectRef === "legacy-user:3")
      .every((row) => row.decision === "deny")).toBe(true);
  });

  it("keeps Legacy and Identity public/global truth independent without A+B union fallback", async () => {
    const views = createDevelopProjectionSnapshotViews(await collect(createFixtures((records) => {
      const identityRoot = records.identity["identity-iam-subject-assignment"]!
        .find((row) => row.legacyUserId === "1");
      if (!identityRoot) throw new Error("missing Identity root fixture");
      identityRoot.itemName = "user";
    })));
    const registrySha256 = ORGANIZATION_OWNER_DEVELOP_APPROVED_REGISTRY_CANDIDATE.registrySha256;
    const legacy = projectDevelopLegacyEffectiveDecisions(views.legacy, registrySha256);
    const identity = projectDevelopIdentityEffectiveDecisions(views.identity, registrySha256);

    expect(decisionAt(
      legacy.effectiveDecisions,
      "legacy-user:1",
      "public",
      capability("view-students")
    )).toBe("allow");
    expect(decisionAt(
      identity.effectiveDecisions,
      "legacy-user:1",
      "public",
      capability("view-students")
    )).toBe("deny");
    expect(decisionAt(
      legacy.effectiveDecisions,
      "legacy-user:1",
      "platform-global",
      capabilityForPermission("organization.list")
    )).toBe("allow");
    expect(decisionAt(
      identity.effectiveDecisions,
      "legacy-user:1",
      "platform-global",
      capabilityForPermission("organization.list")
    )).toBe("deny");
  });

  it("rejects a registry digest other than the exact approved Develop candidate", async () => {
    const views = createDevelopProjectionSnapshotViews(await collect(createFixtures()));
    expect(() => projectDevelopLegacyEffectiveDecisions(views.legacy, "0".repeat(64)))
      .toThrow("approved Develop semantic registry candidate");
    expect(() => projectDevelopIdentityEffectiveDecisions(views.identity, "0".repeat(64)))
      .toThrow("approved Develop semantic registry candidate");
  });

  it.each([
    {
      name: "named rules",
      mutate: (records: RecordsByComponent) => {
        records["legacy-main"]["legacy-rbac-item"]!.find((row) => row.itemName === "root")!.ruleName = "unsafe-rule";
      },
      error: "named Legacy Yii RBAC rule"
    },
    {
      name: "unknown edge items",
      mutate: (records: RecordsByComponent) => {
        records["legacy-main"]["legacy-rbac-edge"]![0]!.childName = "missing-permission";
      },
      error: "unknown item"
    },
    {
      name: "cycles",
      mutate: (records: RecordsByComponent) => {
        records["legacy-main"]["legacy-rbac-edge"]!.push(
          { parentName: "root", childName: "admin" },
          { parentName: "admin", childName: "root" }
        );
      },
      error: "contains a cycle"
    },
    {
      name: "missing approved graph items",
      mutate: (records: RecordsByComponent) => removeLegacyPermission(records, "organization.update"),
      error: "missing an owner-approved permission"
    },
    {
      name: "unknown assignments",
      mutate: (records: RecordsByComponent) => {
        records["legacy-main"]["legacy-rbac-assignment"]![0]!.itemName = "unknown-role";
      },
      error: "unknown or mistyped item"
    },
    {
      name: "unknown owner-scoped roles",
      mutate: (records: RecordsByComponent) => {
        records["legacy-main"]["legacy-rbac-item"]!.push({
          itemName: "rogue-role", itemType: "role", description: null, ruleName: null
        });
      },
      error: "unknown owner-scoped role"
    }
  ])("fails the Legacy graph closed for $name", async ({ mutate, error }) => {
    const views = createDevelopProjectionSnapshotViews(await collect(createFixtures(mutate)));
    expect(() => projectDevelopLegacyEffectiveDecisions(
      views.legacy,
      ORGANIZATION_OWNER_DEVELOP_APPROVED_REGISTRY_CANDIDATE.registrySha256
    )).toThrow(error);
  });

  it.each([
    {
      name: "policy counts",
      mutate: (records: RecordsByComponent) => {
        policyVersion(records).roleCount = Number(policyVersion(records).roleCount) + 1;
      },
      error: "role or permission count"
    },
    {
      name: "missing explicit-zero assignment snapshots",
      mutate: (records: RecordsByComponent) => {
        records.identity["identity-iam-subject-assignment-snapshot"] =
          records.identity["identity-iam-subject-assignment-snapshot"]!
            .filter((row) => row.legacyUserId !== "3");
      },
      error: "explicit zero rows are required"
    },
    {
      name: "assignment snapshot count mismatches",
      mutate: (records: RecordsByComponent) => {
        records.identity["identity-iam-subject-assignment-snapshot"]!
          .find((row) => row.legacyUserId === "2")!.assignmentCount = 9;
      },
      error: "assignment count"
    },
    {
      name: "cross-dataset subject identity conflicts",
      mutate: (records: RecordsByComponent) => {
        records.identity["identity-iam-subject-assignment-snapshot"]!
          .find((row) => row.legacyUserId === "1")!.identityUserId = "identity:conflict";
      },
      error: "exact candidate subject identity"
    },
    {
      name: "unknown relations",
      mutate: (records: RecordsByComponent) => {
        records.identity["identity-iam-item-relation"]![0]!.childName = "missing-permission";
      },
      error: "unknown or mistyped item"
    },
    {
      name: "cycles",
      mutate: (records: RecordsByComponent) => addIdentityCycle(records),
      error: "contains a cycle"
    },
    {
      name: "missing approved graph items",
      mutate: (records: RecordsByComponent) => removeIdentityPermission(records, "organization.update"),
      error: "missing an owner-approved permission"
    },
    {
      name: "unknown assignments",
      mutate: (records: RecordsByComponent) => {
        records.identity["identity-iam-subject-assignment"]![0]!.itemName = "unknown-role";
      },
      error: "unknown or mistyped item"
    },
    {
      name: "rule-bearing row shapes",
      mutate: (records: RecordsByComponent) => {
        records.identity["identity-iam-role"]![0]!.ruleName = "unsafe-rule";
      },
      error: "invalid shape"
    },
    {
      name: "unpinned policy checksums",
      mutate: (records: RecordsByComponent) => {
        records.identity["identity-iam-permission"]![0]!.policyChecksum = "0".repeat(64);
      },
      error: "exact pinned Identity IAM candidate policy"
    },
    {
      name: "unknown owner-scoped roles",
      mutate: (records: RecordsByComponent) => {
        records.identity["identity-iam-role"]!.push(policyItem("rogue-role"));
        policyVersion(records).roleCount = records.identity["identity-iam-role"]!.length;
      },
      error: "unknown owner-scoped role"
    }
  ])("fails the Identity graph closed for $name", async ({ mutate, error }) => {
    const views = createDevelopProjectionSnapshotViews(await collect(createFixtures(mutate)));
    expect(() => projectDevelopIdentityEffectiveDecisions(
      views.identity,
      ORGANIZATION_OWNER_DEVELOP_APPROVED_REGISTRY_CANDIDATE.registrySha256
    )).toThrow(error);
  });

  it("requires exact Identity membership counts and explicit zero rows before evaluating roles", async () => {
    const missingZero = createDevelopProjectionSnapshotViews(await collect(createFixtures((records) => {
      records.identity["identity-membership-candidate-snapshot"] =
        records.identity["identity-membership-candidate-snapshot"]!.filter((row) => row.legacyUserId !== "3");
    })));
    expect(() => projectDevelopIdentityEffectiveDecisions(
      missingZero.identity,
      ORGANIZATION_OWNER_DEVELOP_APPROVED_REGISTRY_CANDIDATE.registrySha256
    )).toThrow("explicit zero rows are required");

    const badCount = createDevelopProjectionSnapshotViews(await collect(createFixtures((records) => {
      records.identity["identity-membership-candidate-snapshot"]!
        .find((row) => row.legacyUserId === "2")!.organizationCount = 2;
    })));
    expect(() => projectDevelopIdentityEffectiveDecisions(
      badCount.identity,
      ORGANIZATION_OWNER_DEVELOP_APPROVED_REGISTRY_CANDIDATE.registrySha256
    )).toThrow("membership count");
  });
});

function createFixtures(mutate?: (records: RecordsByComponent) => void): Fixture[] {
  const recordsByComponent = baseRecords();
  mutate?.(recordsByComponent);
  return ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG.components.map((component, index) => {
    const sourceId = component.expectedSourceId;
    const pageRecords = new Map<string, JsonRecord[]>();
    for (const dataset of component.datasetCatalog.datasets) {
      pageRecords.set(dataset.datasetId, recordsByComponent[component.componentId][dataset.datasetId] ?? []);
    }
    const commitmentKey = Buffer.alloc(32, index + 1);
    const inventory = createOrganizationReconciliationComponentDatasetInventory({
      componentId: component.componentId,
      sourceId,
      catalogSha256: component.declaredCatalogSha256,
      datasets: [...pageRecords].map(([datasetId, records]) => ({
        datasetId,
        pages: [{ requestCursor: null, nextCursor: null, recordOffset: 0, records }]
      })),
      commitmentKey
    });
    const snapshot: Mutable<OrganizationReconciliationSourceSnapshot> = {
      sourceId,
      sourceVersion: createOrganizationReconciliationContentSourceVersion(sourceId, inventory),
      snapshotId: createOrganizationReconciliationContentSnapshotId(sourceId, inventory),
      recordCount: inventory.recordCount,
      subjectUniverseCount: component.componentId === "plugin" ? 0 : 3,
      subjectUniverseHash: component.componentId === "plugin" ? "" : "4".repeat(64),
      snapshotMode: ORGANIZATION_RECONCILIATION_SNAPSHOT_MODE,
      paginationMode: ORGANIZATION_RECONCILIATION_PAGINATION_MODE,
      datasetInventory: inventory
    };
    const delivered = new Set<string>();
    const adapter = {
      sourceId,
      openSnapshot: vi.fn(async () => snapshot),
      readSnapshotPage: vi.fn(async (request: Readonly<{
        snapshot: OrganizationReconciliationSourceSnapshot;
        datasetId: string;
        requestCursor: string | null;
      }>) => {
        if (request.snapshot !== snapshot || request.requestCursor !== null || delivered.has(request.datasetId)) {
          throw new Error("invalid fixture cursor");
        }
        delivered.add(request.datasetId);
        const records = pageRecords.get(request.datasetId);
        if (!records) throw new Error("unknown fixture dataset");
        return datasetPage(snapshot, request.datasetId, records);
      }),
      verifySnapshotDatasetReplay: vi.fn((request: Readonly<{
        snapshot: OrganizationReconciliationSourceSnapshot;
        datasetId: string;
        pages: readonly OrganizationReconciliationDatasetInventoryPageInput[];
      }>) => {
        const observed = createOrganizationReconciliationComponentDatasetInventory({
          componentId: component.componentId,
          sourceId,
          catalogSha256: component.declaredCatalogSha256,
          datasets: [{ datasetId: request.datasetId, pages: request.pages }],
          commitmentKey
        }).datasets[0];
        const expected = inventory.datasets.find((dataset) => dataset.datasetId === request.datasetId);
        if (request.snapshot !== snapshot || !observed || !expected ||
            observed.lineageSha256 !== expected.lineageSha256) {
          throw new Error("fixture replay mismatch");
        }
      }),
      closeSnapshot: vi.fn(async () => undefined)
    } satisfies OrganizationReconciliationDatasetSourceAdapter<unknown>;
    return {
      componentId: component.componentId,
      snapshot,
      adapter,
      binding: {
        componentId: component.componentId,
        expectedSourceId: sourceId,
        schemaSha256: String(index + 7).repeat(64),
        catalogSha256: component.declaredCatalogSha256,
        buildSha256: ["a", "b", "c"][index]!.repeat(64),
        adapter,
        datasetCatalog: component.datasetCatalog
      }
    };
  });
}

function baseRecords(): RecordsByComponent {
  const entries = capabilityEntries();
  const permissions = [...new Set(entries.flatMap((entry) => stringArray(entry.permissionItems)))].sort();
  const roles = [...new Set([
    ...entries.flatMap((entry) => {
      const roleCatalog = entry.roles as Record<string, unknown>;
      return [...stringArray(roleCatalog.global), ...stringArray(roleCatalog.organization)];
    }),
    ...approvedRoleNames()
  ])].sort();
  const legacyItems: JsonRecord[] = [
    ...roles.map((itemName) => ({ itemName, itemType: "role", description: null, ruleName: null })),
    ...permissions.map((itemName) => ({ itemName, itemType: "permission", description: null, ruleName: null }))
  ];
  const legacyEdges = permissions.map((permission) => ({ parentName: "root", childName: permission }));
  const identityRoles = roles.map((itemName) => policyItem(itemName));
  const identityPermissions = permissions.map((itemName) => policyItem(itemName));
  const identityRelations = permissions.map((permission) => ({
    policyChecksum: CHECKSUM,
    parentName: "root",
    parentType: "role",
    childName: permission,
    childType: "permission",
    source: "legacy-import-candidate",
    status: "candidate"
  }));

  return {
    "legacy-main": {
      "legacy-organization-directory": [{
        legacyOrganizationId: "7", name: "north", title: "North", createdAt: 1, updatedAt: 2
      }],
      "legacy-subject-universe": [
        { legacyUserId: "1", status: 10 },
        { legacyUserId: "2", status: 10 },
        { legacyUserId: "3", status: 0 }
      ],
      "legacy-membership": [{ legacyUserId: "2", legacyOrganizationId: "7" }],
      "legacy-role-assignment": [
        { legacyUserId: "1", roleName: "user" },
        { legacyUserId: "2", roleName: "root" }
      ],
      "legacy-rbac-item": legacyItems,
      "legacy-rbac-edge": legacyEdges,
      "legacy-rbac-assignment": [
        { legacyUserId: "1", itemName: "root", itemType: "role" },
        { legacyUserId: "2", itemName: "admin", itemType: "role" },
        { legacyUserId: "2", itemName: "organization.list", itemType: "permission" }
      ]
    },
    identity: {
      "identity-subject-universe": [
        { legacyUserId: "1", status: "active", source: "legacy-shadow" },
        { legacyUserId: "2", status: "active", source: "legacy-shadow" },
        { legacyUserId: "3", status: "inactive", source: "legacy-shadow" }
      ],
      "identity-organization-candidate": [{
        legacyOrganizationId: "7", identityOrganizationId: "legacy:7", name: "north", title: "North",
        source: "legacy", candidateStatus: "candidate"
      }],
      "identity-organization-id-map": [{
        legacyOrganizationId: "7", identityOrganizationId: "legacy:7", source: "legacy", mappingStatus: "active"
      }],
      "identity-membership-shadow": [],
      "identity-membership-candidate": [{
        legacyUserId: "2", legacyOrganizationId: "7", identityUserId: "identity:2",
        identityOrganizationId: "legacy:7", organizationRole: "member", source: "legacy",
        candidateStatus: "candidate", operationKey: "op-2"
      }],
      "identity-membership-candidate-snapshot": [
        membershipSnapshot("1", 0), membershipSnapshot("2", 1), membershipSnapshot("3", 0)
      ],
      // Deliberately contradicts the exact IAM graph: the evaluator must not use this fallback.
      "identity-role-shadow": [
        { legacyUserId: "1", roleName: "user", source: "legacy-shadow", status: "shadow" },
        { legacyUserId: "2", roleName: "root", source: "legacy-shadow", status: "shadow" }
      ],
      "identity-iam-policy-version": [{
        policyChecksum: CHECKSUM,
        source: "legacy-import-candidate",
        status: "candidate",
        roleCount: identityRoles.length,
        permissionCount: identityPermissions.length,
        relationCount: identityRelations.length
      }],
      "identity-iam-role": identityRoles,
      "identity-iam-permission": identityPermissions,
      "identity-iam-item-relation": identityRelations,
      "identity-iam-subject-assignment": [
        identityAssignment("1", "root", "role"),
        identityAssignment("2", "admin", "role"),
        identityAssignment("2", "organization.list", "permission")
      ],
      "identity-iam-subject-assignment-snapshot": [
        assignmentSnapshot("1", 1), assignmentSnapshot("2", 2), assignmentSnapshot("3", 0)
      ]
    },
    plugin: { "plugin-registry": [] }
  };
}

function capabilityEntries(): readonly Record<string, unknown>[] {
  const catalog = ORGANIZATION_OWNER_DEVELOP_DECISION_CATALOGS.capabilityCatalog as unknown;
  const entries = (catalog as { entries?: unknown }).entries;
  if (!Array.isArray(entries)) throw new Error("fixture requires exact approved capability entries");
  return entries as readonly Record<string, unknown>[];
}

function approvedRoleNames(): string[] {
  const catalog = ORGANIZATION_OWNER_DEVELOP_DECISION_CATALOGS.roleScopes as unknown as Record<string, unknown>;
  return [...stringArray(catalog.globalOnly), ...stringArray(catalog.memberOrganization)];
}

function capability(capabilityId: string): Readonly<{ resourceRef: string; capabilityRef: string }> {
  const entry = capabilityEntries().find((candidate) => candidate.capabilityId === capabilityId);
  if (!entry) throw new Error(`missing capability fixture ${capabilityId}`);
  return { resourceRef: String(entry.resourceId), capabilityRef: String(entry.capabilityId) };
}

function capabilityForPermission(permission: string): Readonly<{ resourceRef: string; capabilityRef: string }> {
  const entry = capabilityEntries().find((candidate) => stringArray(candidate.permissionItems).includes(permission));
  if (!entry) throw new Error(`missing permission fixture ${permission}`);
  return { resourceRef: String(entry.resourceId), capabilityRef: String(entry.capabilityId) };
}

function decision(
  rows: readonly Readonly<{
    subjectRef: string;
    contextKind: string;
    contextRef: string;
    resourceRef: string;
    capabilityRef: string;
    decision: string;
  }>[],
  subjectRef: string,
  capabilityValue: Readonly<{ resourceRef: string; capabilityRef: string }>
): string | undefined {
  return rows.find((row) => row.subjectRef === subjectRef && row.contextKind === "organization" &&
    row.contextRef === "legacy-org:7" &&
    row.resourceRef === capabilityValue.resourceRef && row.capabilityRef === capabilityValue.capabilityRef)?.decision;
}

function decisionAt(
  rows: readonly Readonly<{
    subjectRef: string;
    contextKind: string;
    contextRef: string;
    resourceRef: string;
    capabilityRef: string;
    decision: string;
  }>[],
  subjectRef: string,
  contextKind: "platform-global" | "public",
  capabilityValue: Readonly<{ resourceRef: string; capabilityRef: string }>
): string | undefined {
  const contextRef = contextKind === "platform-global" ? "org:platform-global" : "org:public";
  return rows.find((row) => row.subjectRef === subjectRef && row.contextKind === contextKind &&
    row.contextRef === contextRef && row.resourceRef === capabilityValue.resourceRef &&
    row.capabilityRef === capabilityValue.capabilityRef)?.decision;
}

function policyItem(itemName: string): JsonRecord {
  return {
    policyChecksum: CHECKSUM,
    itemName,
    description: null,
    source: "legacy-import-candidate",
    status: "candidate"
  };
}

function identityAssignment(legacyUserId: string, itemName: string, itemType: "role" | "permission"): JsonRecord {
  return {
    identityUserId: `identity:${legacyUserId}`,
    legacyUserId,
    itemName,
    itemType,
    policyChecksum: CHECKSUM,
    source: "legacy-import-candidate",
    status: "candidate"
  };
}

function assignmentSnapshot(legacyUserId: string, assignmentCount: number): JsonRecord {
  return {
    identityUserId: `identity:${legacyUserId}`,
    legacyUserId,
    policyChecksum: CHECKSUM,
    snapshotKey: CHECKSUM,
    assignmentCount,
    source: "legacy-import-candidate",
    status: "candidate"
  };
}

function membershipSnapshot(legacyUserId: string, organizationCount: number): JsonRecord {
  return {
    identityUserId: `identity:${legacyUserId}`,
    legacyUserId,
    operationKey: `op-${legacyUserId}`,
    organizationCount,
    source: "legacy",
    candidateStatus: "candidate"
  };
}

function policyVersion(records: RecordsByComponent): JsonRecord {
  return records.identity["identity-iam-policy-version"]![0]!;
}

function removeLegacyPermission(records: RecordsByComponent, permission: string): void {
  records["legacy-main"]["legacy-rbac-item"] = records["legacy-main"]["legacy-rbac-item"]!
    .filter((row) => row.itemName !== permission);
  records["legacy-main"]["legacy-rbac-edge"] = records["legacy-main"]["legacy-rbac-edge"]!
    .filter((row) => row.childName !== permission && row.parentName !== permission);
}

function removeIdentityPermission(records: RecordsByComponent, permission: string): void {
  records.identity["identity-iam-permission"] = records.identity["identity-iam-permission"]!
    .filter((row) => row.itemName !== permission);
  records.identity["identity-iam-item-relation"] = records.identity["identity-iam-item-relation"]!
    .filter((row) => row.childName !== permission && row.parentName !== permission);
  policyVersion(records).permissionCount = records.identity["identity-iam-permission"]!.length;
  policyVersion(records).relationCount = records.identity["identity-iam-item-relation"]!.length;
}

function addIdentityCycle(records: RecordsByComponent): void {
  records.identity["identity-iam-item-relation"]!.push(
    identityRelation("root", "role", "admin", "role"),
    identityRelation("admin", "role", "root", "role")
  );
  policyVersion(records).relationCount = records.identity["identity-iam-item-relation"]!.length;
}

function identityRelation(
  parentName: string,
  parentType: "role" | "permission",
  childName: string,
  childType: "role" | "permission"
): JsonRecord {
  return {
    policyChecksum: CHECKSUM,
    parentName,
    parentType,
    childName,
    childType,
    source: "legacy-import-candidate",
    status: "candidate"
  };
}

function stringArray(value: unknown): string[] {
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== "string")) {
    throw new Error("invalid fixture catalog array");
  }
  return value as string[];
}

function datasetPage(
  snapshot: OrganizationReconciliationSourceSnapshot,
  datasetId: string,
  records: readonly OrganizationReconciliationInventoryJsonValue[]
): OrganizationReconciliationDatasetPage<OrganizationReconciliationInventoryJsonValue> {
  return {
    sourceId: snapshot.sourceId,
    sourceVersion: snapshot.sourceVersion,
    snapshotId: snapshot.snapshotId,
    snapshotRecordCount: snapshot.recordCount,
    subjectUniverseCount: snapshot.subjectUniverseCount,
    subjectUniverseHash: snapshot.subjectUniverseHash,
    datasetId,
    datasetRecordCount: records.length,
    requestCursor: null,
    nextCursor: null,
    recordOffset: 0,
    records
  };
}

function collect(fixtures: readonly Fixture[]) {
  let clockTick = 0;
  return collectOrganizationReconciliationDatasetLineage({
    components: fixtures.map((fixture) => fixture.binding),
    maxWindowMilliseconds: 1_000,
    clock: { now: vi.fn(() => new Date(BASE_TIME + clockTick++ * 10)) }
  });
}
