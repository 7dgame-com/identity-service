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
  projectDevelopIdentityBasicSurfaces,
  projectDevelopLegacyBasicSurfaces
} from "../src/iam-organization-reconciliation-develop-basic-surfaces.js";
import {
  createDevelopProjectionSnapshotViews,
  assertIdentityDevelopProjectionSnapshotView,
  assertLegacyDevelopProjectionSnapshotView
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

const BASE_TIME = Date.parse("2026-08-11T00:00:00.000Z");
const REGISTRY_SHA = ORGANIZATION_OWNER_DEVELOP_APPROVED_REGISTRY_CANDIDATE.registrySha256;

describe("xrteeth Develop basic organization projections", () => {
  it("consumes all 21 dataset artifacts and projects the first four surfaces independently", async () => {
    const fixtures = createFixtures();
    const run = await collect(fixtures);
    const views = createDevelopProjectionSnapshotViews(run);
    const legacy = projectDevelopLegacyBasicSurfaces(views.legacy, REGISTRY_SHA);
    const identity = projectDevelopIdentityBasicSurfaces(views.identity, REGISTRY_SHA);

    expect(run.artifacts).toHaveLength(21);
    expect(legacy.organizationDirectory).toEqual(identity.organizationDirectory);
    expect(legacy.organizationMappings).toEqual(identity.organizationMappings);
    expect(legacy.memberships).toEqual(identity.memberships);
    expect(legacy.organizationScopedRoles).toEqual(identity.organizationScopedRoles);
    expect(legacy.blockers).toEqual([
      "plugin-surfaces-not-ready",
      "operation-evidence-projector-not-production-registered",
      "runtime-pipeline-not-registered"
    ]);
    expect(identity.blockers).toEqual(legacy.blockers);
    expect(legacy).toMatchObject({
      semanticRegistrySha256: REGISTRY_SHA,
      organizationDirectory: [{ legacyOrganizationId: "7", name: "north", title: "North", active: true }],
      organizationMappings: [{
        legacyOrganizationId: "7",
        identityOrganizationId: "legacy:7",
        active: true
      }],
      memberships: [{ subjectRef: "legacy-user:1", legacyOrganizationId: "7", active: true }],
      organizationScopedRoles: [{
        subjectRef: "legacy-user:1",
        legacyOrganizationId: "7",
        roleRef: "admin",
        active: true
      }]
    });
    expect(views.legacy.datasets["plugin-registry"]).not.toBe(views.identity.datasets["plugin-registry"]);
    expect(legacy.organizationDirectory).not.toBe(identity.organizationDirectory);
    expect(Object.isFrozen(legacy.organizationDirectory)).toBe(true);
    expect(Object.isFrozen(identity.organizationDirectory[0])).toBe(true);
    for (const fixture of fixtures) {
      expect(fixture.adapter.closeSnapshot).toHaveBeenCalledOnce();
      expect(fixture.adapter.closeSnapshot).toHaveBeenCalledWith(fixture.snapshot, "completed");
    }
  });

  it("rejects forged views, a wrong registry digest, and artifact replay", async () => {
    const run = await collect(createFixtures());
    const views = createDevelopProjectionSnapshotViews(run);

    expect(() => assertLegacyDevelopProjectionSnapshotView({ ...views.legacy }))
      .toThrow("forged or cloned");
    expect(() => assertIdentityDevelopProjectionSnapshotView({ ...views.identity }))
      .toThrow("forged or cloned");
    expect(() => projectDevelopLegacyBasicSurfaces(views.legacy, "0".repeat(64)))
      .toThrow("approved Develop semantic registry candidate");
    expect(() => createDevelopProjectionSnapshotViews(run)).toThrow("replayed");
  });

  it("requires an explicit membership snapshot for every Identity subject, including empty membership", async () => {
    const fixtures = createFixtures({ omitEmptyIdentityMembershipSnapshot: true });
    const views = createDevelopProjectionSnapshotViews(await collect(fixtures));

    expect(() => projectDevelopIdentityBasicSurfaces(views.identity, REGISTRY_SHA))
      .toThrow("membership snapshot universe is incomplete");
  });
});

function createFixtures(
  options: Readonly<{ omitEmptyIdentityMembershipSnapshot?: boolean }> = {}
): Fixture[] {
  const recordsByComponent: Record<OrganizationReconciliationPhysicalSource, Record<string, JsonRecord[]>> = {
    "legacy-main": {
      "legacy-organization-directory": [{
        legacyOrganizationId: "7", name: "north", title: "North", createdAt: 1, updatedAt: 2
      }],
      "legacy-subject-universe": [
        { legacyUserId: "1", status: 10 },
        { legacyUserId: "2", status: 0 }
      ],
      "legacy-membership": [{ legacyUserId: "1", legacyOrganizationId: "7" }],
      "legacy-role-assignment": [
        { legacyUserId: "1", roleName: "admin" },
        { legacyUserId: "2", roleName: "user" }
      ]
    },
    identity: {
      "identity-subject-universe": [
        { legacyUserId: "1", status: "active", source: "legacy-shadow" },
        { legacyUserId: "2", status: "inactive", source: "legacy-shadow" }
      ],
      "identity-organization-candidate": [{
        legacyOrganizationId: "7", identityOrganizationId: "legacy:7", name: "north", title: "North",
        source: "legacy", candidateStatus: "candidate"
      }],
      "identity-organization-id-map": [{
        legacyOrganizationId: "7", identityOrganizationId: "legacy:7", source: "legacy", mappingStatus: "active"
      }],
      "identity-membership-candidate": [{
        legacyUserId: "1", legacyOrganizationId: "7", identityUserId: "legacy:1",
        identityOrganizationId: "legacy:7", organizationRole: "member", source: "legacy",
        candidateStatus: "candidate", operationKey: "op-1"
      }],
      "identity-membership-candidate-snapshot": [
        {
          identityUserId: "legacy:1", legacyUserId: "1", operationKey: "op-1", organizationCount: 1,
          source: "legacy", candidateStatus: "candidate"
        },
        ...options.omitEmptyIdentityMembershipSnapshot ? [] : [{
          identityUserId: "legacy:2", legacyUserId: "2", operationKey: "op-2", organizationCount: 0,
          source: "legacy", candidateStatus: "candidate"
        }]
      ],
      "identity-role-shadow": [
        { legacyUserId: "1", roleName: "admin", source: "legacy-shadow", status: "shadow" },
        { legacyUserId: "2", roleName: "user", source: "legacy-shadow", status: "shadow" }
      ]
    },
    plugin: {
      "plugin-registry": [{
        pluginId: "system-admin", enabled: true, accessScope: "root-only", organizationName: null
      }]
    }
  };

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
      subjectUniverseCount: component.componentId === "plugin" ? 0 : 2,
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
        schemaSha256: String(index + 7).repeat(64),
        catalogSha256: component.declaredCatalogSha256,
        buildSha256: ["a", "b", "c"][index]!.repeat(64),
        adapter,
        datasetCatalog: component.datasetCatalog
      }
    };
  });
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
