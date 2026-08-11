import { describe, expect, it, vi } from "vitest";
import {
  ORGANIZATION_OWNER_DEVELOP_APPROVED_REGISTRY_CANDIDATE
} from "../src/iam-organization-owner-semantic-registry.js";
import {
  collectOrganizationReconciliationDatasetLineage,
  type OrganizationReconciliationDatasetComponentBinding,
  type OrganizationReconciliationDatasetPage,
  type OrganizationReconciliationDatasetSourceAdapter
} from "../src/iam-organization-reconciliation-dataset-lineage.js";
import {
  ORGANIZATION_RECONCILIATION_DEVELOP_PLUGIN_CAMPUS_SURFACES_READY,
  projectDevelopIdentityPluginCampusSurfaces,
  projectDevelopLegacyPluginCampusSurfaces,
  type DevelopPluginCampusSurfaces
} from "../src/iam-organization-reconciliation-develop-plugin-campus-surfaces.js";
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
import {
  ORGANIZATION_RECONCILIATION_DEVELOP_IAM_POLICY_CHECKSUM
} from "../src/iam-organization-reconciliation/mysql-repeatable-read-snapshot.js";
import type {
  OrganizationReconciliationPhysicalSource
} from "../src/iam-organization-reconciliation-component-manifest.js";

type JsonRecord = Readonly<Record<string, string | number | boolean | null>>;
type Mutable<T> = { -readonly [K in keyof T]: T[K] };

interface Fixture {
  readonly componentId: OrganizationReconciliationPhysicalSource;
  readonly snapshot: Mutable<OrganizationReconciliationSourceSnapshot>;
  readonly binding: OrganizationReconciliationDatasetComponentBinding;
  readonly adapter: OrganizationReconciliationDatasetSourceAdapter<unknown> & {
    readonly closeSnapshot: ReturnType<typeof vi.fn>;
  };
}

interface FixtureOptions {
  readonly systemAdminScope?: "root-only" | "admin-only";
  readonly omitIdentityAssignmentSnapshotForUser4?: boolean;
  readonly identityUser1GlobalRole?: "root" | "user";
  readonly legacyGraphCycle?: boolean;
  readonly identityGraphCycle?: boolean;
}

const BASE_TIME = Date.parse("2026-08-11T01:00:00.000Z");
const POLICY_SHA = ORGANIZATION_RECONCILIATION_DEVELOP_IAM_POLICY_CHECKSUM;

describe("xrteeth Develop plugin and campus candidate projections", () => {
  it("projects independent plugin surfaces and every subject-by-plugin allow/deny row", async () => {
    const views = createDevelopProjectionSnapshotViews(await collect(createFixtures()));
    const legacy = projectDevelopLegacyPluginCampusSurfaces(views.legacy);
    const identity = projectDevelopIdentityPluginCampusSurfaces(views.identity);

    expect(legacy.pluginBindings).toEqual(identity.pluginBindings);
    expect(legacy.pluginVisibility).toEqual(identity.pluginVisibility);
    expect(legacy.pluginBindings).not.toBe(identity.pluginBindings);
    expect(legacy.pluginVisibility).not.toBe(identity.pluginVisibility);
    expect(legacy.semanticRegistrySha256)
      .toBe(ORGANIZATION_OWNER_DEVELOP_APPROVED_REGISTRY_CANDIDATE.registrySha256);
    expect(legacy.pluginBindings).toEqual([
      binding("campus", "legacy-org:7", true),
      binding("disabled-tool", "org:public", false),
      binding("public-tool", "org:public", true),
      binding("system-admin", "org:public", true),
      binding("user-management", "org:public", true)
    ]);
    expect(legacy.pluginVisibility).toHaveLength(20);
    expect(new Set(legacy.pluginVisibility.map((row) =>
      `${row.subjectRef}\u0000${row.pluginRef}\u0000${row.organizationRef}`
    ))).toHaveLength(20);

    expect(pluginDecision(legacy, "legacy-user:1", "plugin:system-admin")).toBe("allow");
    expect(pluginDecision(legacy, "legacy-user:1", "plugin:campus")).toBe("allow");
    expect(pluginDecision(legacy, "legacy-user:2", "plugin:campus")).toBe("allow");
    expect(pluginDecision(legacy, "legacy-user:2", "plugin:system-admin")).toBe("deny");
    expect(pluginDecision(legacy, "legacy-user:3", "plugin:campus")).toBe("deny");
    expect(pluginDecision(legacy, "legacy-user:3", "plugin:public-tool")).toBe("allow");
    expect(legacy.pluginVisibility.filter((row) => row.pluginRef === "plugin:disabled-tool"))
      .toHaveLength(4);
    expect(legacy.pluginVisibility.filter((row) => row.pluginRef === "plugin:disabled-tool"))
      .toSatisfy((rows: typeof legacy.pluginVisibility) => rows.every((row) => row.decision === "deny"));
    expect(legacy.pluginVisibility.filter((row) => row.subjectRef === "legacy-user:4"))
      .toHaveLength(5);
    expect(legacy.pluginVisibility.filter((row) => row.subjectRef === "legacy-user:4"))
      .toSatisfy((rows: typeof legacy.pluginVisibility) => rows.every((row) => row.decision === "deny"));
    expect(Object.isFrozen(legacy.pluginBindings)).toBe(true);
    expect(Object.isFrozen(legacy.pluginVisibility[0])).toBe(true);
  });

  it("blocks authorization drift instead of silently applying the static built-in override", async () => {
    const views = createDevelopProjectionSnapshotViews(await collect(createFixtures({
      systemAdminScope: "admin-only"
    })));

    expect(() => projectDevelopLegacyPluginCampusSurfaces(views.legacy))
      .toThrow(/P1 plugin authorization drift/);
    expect(() => projectDevelopIdentityPluginCampusSurfaces(views.identity))
      .toThrow(/P1 plugin authorization drift/);
  });

  it("requires complete exact-policy Identity assignment snapshots", async () => {
    const views = createDevelopProjectionSnapshotViews(await collect(createFixtures({
      omitIdentityAssignmentSnapshotForUser4: true
    })));

    expect(() => projectDevelopIdentityPluginCampusSurfaces(views.identity))
      .toThrow(/assignment snapshot universe is incomplete/);
  });

  it("evaluates Legacy and Identity authorization inputs independently", async () => {
    const views = createDevelopProjectionSnapshotViews(await collect(createFixtures({
      identityUser1GlobalRole: "user"
    })));
    const legacy = projectDevelopLegacyPluginCampusSurfaces(views.legacy);
    const identity = projectDevelopIdentityPluginCampusSurfaces(views.identity);

    expect(pluginDecision(legacy, "legacy-user:1", "plugin:system-admin")).toBe("allow");
    expect(pluginDecision(identity, "legacy-user:1", "plugin:system-admin")).toBe("deny");
    expect(campusDecision(legacy, "legacy-user:1", "legacy-org:7")).toBe("allow");
    expect(campusDecision(identity, "legacy-user:1", "legacy-org:7")).toBe("deny");
    expect(campusDecision(legacy, "legacy-user:1", "org:public")).toBe("allow");
    expect(campusDecision(identity, "legacy-user:1", "org:public")).toBe("deny");
    expect(legacy.pluginVisibility).not.toEqual(identity.pluginVisibility);
    expect(legacy.campusContexts).not.toEqual(identity.campusContexts);
  });

  it("rejects malformed Legacy and Identity rule-free policy graphs", async () => {
    const legacyCycleViews = createDevelopProjectionSnapshotViews(await collect(createFixtures({
      legacyGraphCycle: true
    })));
    expect(() => projectDevelopLegacyPluginCampusSurfaces(legacyCycleViews.legacy))
      .toThrow(/cycle/);

    const identityCycleViews = createDevelopProjectionSnapshotViews(await collect(createFixtures({
      identityGraphCycle: true
    })));
    expect(() => projectDevelopIdentityPluginCampusSurfaces(identityCycleViews.identity))
      .toThrow(/cycle/);
  });

  it("rejects getter-bearing clones and proxies before invoking attacker code", async () => {
    const views = createDevelopProjectionSnapshotViews(await collect(createFixtures()));
    let getterCalls = 0;
    const getterClone = { ...views.legacy };
    Object.defineProperty(getterClone, "datasets", {
      enumerable: true,
      get: () => {
        getterCalls += 1;
        return views.legacy.datasets;
      }
    });
    expect(() => projectDevelopLegacyPluginCampusSurfaces(
      getterClone as unknown as typeof views.legacy
    )).toThrow(/forged or cloned/);
    expect(getterCalls).toBe(0);

    let proxyGetCalls = 0;
    const proxy = new Proxy(views.identity, {
      get: (target, property, receiver) => {
        proxyGetCalls += 1;
        return Reflect.get(target, property, receiver);
      }
    });
    expect(() => projectDevelopIdentityPluginCampusSurfaces(proxy))
      .toThrow(/forged or cloned/);
    expect(proxyGetCalls).toBe(0);
  });

  it("projects complete campus summary truth over the structural S x (O + 2) universe", async () => {
    const views = createDevelopProjectionSnapshotViews(await collect(createFixtures()));
    const legacy = projectDevelopLegacyPluginCampusSurfaces(views.legacy);
    const identity = projectDevelopIdentityPluginCampusSurfaces(views.identity);

    expect(ORGANIZATION_RECONCILIATION_DEVELOP_PLUGIN_CAMPUS_SURFACES_READY).toBe(false);
    expect(legacy.campusContexts).toEqual(identity.campusContexts);
    expect(legacy.campusContexts).toHaveLength(16);
    expect(campusDecision(legacy, "legacy-user:1", "legacy-org:7")).toBe("allow");
    expect(campusDecision(legacy, "legacy-user:1", "legacy-org:8")).toBe("allow");
    expect(campusDecision(legacy, "legacy-user:2", "legacy-org:7")).toBe("allow");
    expect(campusDecision(legacy, "legacy-user:2", "legacy-org:8")).toBe("deny");
    expect(campusDecision(legacy, "legacy-user:3", "legacy-org:7")).toBe("deny");
    expect(campusDecision(legacy, "legacy-user:1", "org:platform-global")).toBe("deny");
    expect(campusDecision(legacy, "legacy-user:1", "org:public")).toBe("allow");
    expect(campusDecision(legacy, "legacy-user:2", "org:public")).toBe("deny");
    expect(campusDecision(legacy, "legacy-user:4", "org:public")).toBe("deny");
    expect(legacy.campusContextCoverage).toEqual({
      ownerApprovedContextKinds: ["organization", "platform-global", "public"],
      projectedContextKinds: ["organization", "platform-global", "public"],
      blockedDecisionKinds: [],
      structuralUniverseComplete: true,
      summaryTruthComplete: true,
      validatorCompatibleForFullUniverse: true
    });
    expect(legacy.blockers).toEqual(expect.arrayContaining([
      "static-plugin-artifact-deployment-digest-not-attested",
      "operation-evidence-projector-not-production-registered",
      "runtime-pipeline-not-registered"
    ]));
    expect(legacy.blockers).not.toContain("campus-public-context-execution-not-authorized");
    expect(legacy.blockers)
      .not.toContain("independent-effective-context-decision-execution-not-authorized");
  });
});

function binding(pluginId: string, organizationRef: string, active: boolean) {
  const pluginRef = `plugin:${pluginId}`;
  return { pluginRef, bindingRef: `${pluginRef}:${organizationRef}`, organizationRef, active };
}

function pluginDecision(
  result: DevelopPluginCampusSurfaces,
  subjectRef: string,
  pluginRef: string
): string | undefined {
  return result.pluginVisibility.find((row) =>
    row.subjectRef === subjectRef && row.pluginRef === pluginRef
  )?.decision;
}

function campusDecision(
  result: DevelopPluginCampusSurfaces,
  subjectRef: string,
  contextRef: string
): string | undefined {
  return result.campusContexts.find((row) =>
    row.subjectRef === subjectRef && row.contextRef === contextRef
  )?.decision;
}

function createFixtures(options: FixtureOptions = {}): Fixture[] {
  const systemAdminScope = options.systemAdminScope ?? "root-only";
  const recordsByComponent: Record<OrganizationReconciliationPhysicalSource, Record<string, JsonRecord[]>> = {
    "legacy-main": {
      "legacy-organization-directory": [
        { legacyOrganizationId: "7", name: "north", title: "North", createdAt: 1, updatedAt: 2 },
        { legacyOrganizationId: "8", name: "south", title: "South", createdAt: 1, updatedAt: 2 }
      ],
      "legacy-subject-universe": [
        { legacyUserId: "1", status: 10 },
        { legacyUserId: "2", status: 10 },
        { legacyUserId: "3", status: 10 },
        { legacyUserId: "4", status: 0 }
      ],
      "legacy-membership": [{ legacyUserId: "2", legacyOrganizationId: "7" }],
      "legacy-role-assignment": [
        { legacyUserId: "1", roleName: "root" },
        { legacyUserId: "2", roleName: "manager" },
        { legacyUserId: "3", roleName: "user" },
        { legacyUserId: "4", roleName: "user" }
      ],
      "legacy-rbac-item": [
        { itemName: "manager", itemType: "role", description: null, ruleName: null },
        { itemName: "root", itemType: "role", description: null, ruleName: null },
        { itemName: "user", itemType: "role", description: null, ruleName: null }
      ],
      "legacy-rbac-assignment": [
        { legacyUserId: "1", itemName: "root", itemType: "role" },
        { legacyUserId: "2", itemName: "manager", itemType: "role" },
        { legacyUserId: "3", itemName: "user", itemType: "role" },
        { legacyUserId: "4", itemName: "user", itemType: "role" }
      ],
      "legacy-rbac-edge": options.legacyGraphCycle
        ? [{ parentName: "root", childName: "root" }]
        : []
    },
    identity: {
      "identity-subject-universe": [
        identitySubject("1", "active"),
        identitySubject("2", "active"),
        identitySubject("3", "active"),
        identitySubject("4", "inactive")
      ],
      "identity-organization-candidate": [
        identityOrganization("7", "north", "North"),
        identityOrganization("8", "south", "South")
      ],
      "identity-organization-id-map": [identityMap("7"), identityMap("8")],
      "identity-membership-candidate": [{
        legacyUserId: "2", legacyOrganizationId: "7", identityUserId: "legacy:2",
        identityOrganizationId: "legacy:7", organizationRole: "member", source: "legacy",
        candidateStatus: "candidate", operationKey: "membership-2"
      }],
      "identity-membership-candidate-snapshot": [
        membershipSnapshot("1", 0),
        membershipSnapshot("2", 1),
        membershipSnapshot("3", 0),
        membershipSnapshot("4", 0)
      ],
      "identity-role-shadow": [
        roleShadow("1", "root"),
        roleShadow("2", "manager"),
        roleShadow("3", "user"),
        roleShadow("4", "user")
      ],
      "identity-iam-policy-version": [{
        policyChecksum: POLICY_SHA, source: "legacy-import-candidate", status: "candidate",
        roleCount: 4, permissionCount: 0, relationCount: options.identityGraphCycle ? 1 : 0
      }],
      "identity-iam-role": ["admin", "manager", "root", "user"].map((itemName) => ({
        policyChecksum: POLICY_SHA, itemName, description: null,
        source: "legacy-import-candidate", status: "candidate"
      })),
      "identity-iam-subject-assignment": [
        identityAssignment("1", options.identityUser1GlobalRole ?? "root"),
        identityAssignment("2", "manager"),
        identityAssignment("3", "user"),
        identityAssignment("4", "user")
      ],
      "identity-iam-subject-assignment-snapshot": ["1", "2", "3", ...options.omitIdentityAssignmentSnapshotForUser4 ? [] : ["4"]]
        .map(identityAssignmentSnapshot),
      "identity-iam-item-relation": options.identityGraphCycle
        ? [{
            policyChecksum: POLICY_SHA,
            parentName: "root",
            parentType: "role",
            childName: "root",
            childType: "role",
            source: "legacy-import-candidate",
            status: "candidate"
          }]
        : []
    },
    plugin: {
      "plugin-registry": [
        { pluginId: "campus", enabled: true, accessScope: "manager-only", organizationName: "north" },
        { pluginId: "disabled-tool", enabled: false, accessScope: "root-only", organizationName: null },
        { pluginId: "public-tool", enabled: true, accessScope: "auth-only", organizationName: null },
        { pluginId: "system-admin", enabled: true, accessScope: systemAdminScope, organizationName: null }
      ]
    }
  };

  return ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG.components.map((component, index) => {
    const sourceId = component.expectedSourceId;
    const pageRecords = new Map<string, JsonRecord[]>();
    for (const dataset of component.datasetCatalog.datasets) {
      pageRecords.set(dataset.datasetId, recordsByComponent[component.componentId][dataset.datasetId] ?? []);
    }
    const commitmentKey = Buffer.alloc(32, index + 11);
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
      subjectUniverseCount: component.componentId === "plugin" ? 0 : 4,
      subjectUniverseHash: component.componentId === "plugin" ? "" : "5".repeat(64),
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
        pageSize: number;
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
        if (request.snapshot !== snapshot) throw new Error("wrong fixture snapshot");
        const observed = createOrganizationReconciliationComponentDatasetInventory({
          componentId: component.componentId,
          sourceId,
          catalogSha256: component.declaredCatalogSha256,
          datasets: [{ datasetId: request.datasetId, pages: request.pages }],
          commitmentKey
        }).datasets[0];
        const expected = inventory.datasets.find((dataset) => dataset.datasetId === request.datasetId);
        if (!observed || !expected || observed.lineageSha256 !== expected.lineageSha256) {
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
        schemaSha256: String(index + 3).repeat(64),
        catalogSha256: component.declaredCatalogSha256,
        buildSha256: ["d", "e", "f"][index]!.repeat(64),
        adapter,
        datasetCatalog: component.datasetCatalog
      }
    };
  });
}

function identitySubject(legacyUserId: string, status: "active" | "inactive"): JsonRecord {
  return { legacyUserId, status, source: "legacy-shadow" };
}

function identityOrganization(legacyOrganizationId: string, name: string, title: string): JsonRecord {
  return {
    legacyOrganizationId,
    identityOrganizationId: `legacy:${legacyOrganizationId}`,
    name,
    title,
    source: "legacy",
    candidateStatus: "candidate"
  };
}

function identityMap(legacyOrganizationId: string): JsonRecord {
  return {
    legacyOrganizationId,
    identityOrganizationId: `legacy:${legacyOrganizationId}`,
    source: "legacy",
    mappingStatus: "active"
  };
}

function membershipSnapshot(legacyUserId: string, organizationCount: number): JsonRecord {
  return {
    identityUserId: `legacy:${legacyUserId}`,
    legacyUserId,
    operationKey: `membership-${legacyUserId}`,
    organizationCount,
    source: "legacy",
    candidateStatus: "candidate"
  };
}

function roleShadow(legacyUserId: string, roleName: string): JsonRecord {
  return { legacyUserId, roleName, source: "legacy-shadow", status: "shadow" };
}

function identityAssignment(legacyUserId: string, itemName: string): JsonRecord {
  return {
    identityUserId: `legacy:${legacyUserId}`,
    legacyUserId,
    itemName,
    itemType: "role",
    policyChecksum: POLICY_SHA,
    source: "legacy-import-candidate",
    status: "candidate"
  };
}

function identityAssignmentSnapshot(legacyUserId: string): JsonRecord {
  return {
    identityUserId: `legacy:${legacyUserId}`,
    legacyUserId,
    policyChecksum: POLICY_SHA,
    snapshotKey: POLICY_SHA,
    assignmentCount: 1,
    source: "legacy-import-candidate",
    status: "candidate"
  };
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
