import { describe, expect, it, vi } from "vitest";
import {
  ORGANIZATION_RECONCILIATION_DATASET_CATALOG_TRUST,
  ORGANIZATION_RECONCILIATION_DATASET_LINEAGE_CONTRACT,
  ORGANIZATION_RECONCILIATION_DATASET_LINEAGE_PRODUCTION_READY,
  assertOrganizationReconciliationDatasetArtifactBelongsToRun,
  collectOrganizationReconciliationDatasetLineage,
  consumeOrganizationReconciliationDatasetArtifact,
  organizationReconciliationDatasetLineageReadiness,
  type OrganizationReconciliationDatasetCatalog,
  type OrganizationReconciliationDatasetComponentBinding,
  type OrganizationReconciliationDatasetLineageRun,
  type OrganizationReconciliationDatasetPage,
  type OrganizationReconciliationDatasetSourceAdapter
} from "../src/iam-organization-reconciliation-dataset-lineage.js";
import {
  ORGANIZATION_RECONCILIATION_PAGINATION_MODE,
  ORGANIZATION_RECONCILIATION_SNAPSHOT_MODE,
  type OrganizationReconciliationSourceSnapshot
} from "../src/iam-organization-reconciliation-collector.js";
import type { OrganizationReconciliationPhysicalSource } from
  "../src/iam-organization-reconciliation-component-manifest.js";

interface RawRecord { readonly id: string }
type Mutable<T> = { -readonly [K in keyof T]: T[K] };

interface Fixture {
  readonly id: OrganizationReconciliationPhysicalSource;
  readonly snapshot: Mutable<OrganizationReconciliationSourceSnapshot>;
  readonly adapter: Mutable<OrganizationReconciliationDatasetSourceAdapter<unknown>> & {
    openSnapshot: ReturnType<typeof vi.fn>;
    readSnapshotPage: ReturnType<typeof vi.fn>;
    closeSnapshot: ReturnType<typeof vi.fn>;
  };
  readonly binding: OrganizationReconciliationDatasetComponentBinding;
  readonly pages: Map<string, Array<OrganizationReconciliationDatasetPage<RawRecord>>>;
}

const BASE_TIME = Date.parse("2026-08-09T00:00:00.000Z");

describe("organization reconciliation dataset page lineage", () => {
  it("collects multiple independent dataset cursor chains and keeps readiness false", async () => {
    const fixtures = fixturesFor([]);
    const run = await collect(fixtures);

    expect(ORGANIZATION_RECONCILIATION_DATASET_LINEAGE_PRODUCTION_READY).toBe(false);
    expect(organizationReconciliationDatasetLineageReadiness()).toEqual({
      ready: false,
      blockers: [
        "real-dataset-adapters-not-registered",
        "compiled-owner-catalog-not-registered",
        "trusted-physical-source-binding-not-registered",
        "transaction-owned-dataset-counts-not-implemented",
        "dataset-unique-order-contract-not-registered",
        "operation-evidence-projector-not-implemented"
      ]
    });
    expect(run).toMatchObject({
      contract: ORGANIZATION_RECONCILIATION_DATASET_LINEAGE_CONTRACT,
      catalogTrust: "caller-structured-untrusted",
      crossDatabaseAtomic: false,
      readiness: { ready: false }
    });
    expect(run.artifacts.map(({ componentId, datasetId, recordCount }) =>
      [componentId, datasetId, recordCount])).toEqual([
      ["legacy-main", "directory", 2],
      ["legacy-main", "membership", 1],
      ["identity", "directory", 1],
      ["identity", "membership", 1],
      ["plugin", "registry", 1]
    ]);
    expect(run.artifacts[0]!.pages).toHaveLength(2);
    expect(run.artifacts[0]!.pages[0]).toMatchObject({
      requestCursor: null,
      nextCursor: "directory-cursor-1",
      recordOffset: 0,
      recordCount: 1
    });
    expect(run.artifacts[0]!.pages[0]!.recordsSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(run.artifacts[0]!.lineageSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(run.artifacts[0]!.pages[0]!.structuralCatalogSha256).not.toBe(
      run.artifacts[0]!.pages[0]!.declaredCatalogSha256
    );
    expect(run.coordinatorManifest.evidenceSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(Object.isFrozen(run.artifacts[0]!.records)).toBe(true);
    expect(assertOrganizationReconciliationDatasetArtifactBelongsToRun(run, run.artifacts[0]!))
      .toBe(run.artifacts[0]);
    for (const fixture of fixtures) {
      expect(fixture.adapter.closeSnapshot).toHaveBeenCalledTimes(1);
      expect(fixture.adapter.closeSnapshot).toHaveBeenCalledWith(fixture.snapshot, "completed");
      for (const [request] of fixture.adapter.readSnapshotPage.mock.calls) {
        expect(request.snapshot).toBe(fixture.snapshot);
      }
    }
    expect(fixtures[0]!.adapter.readSnapshotPage.mock.calls.map(([request]) => request.datasetId))
      .toEqual(["directory", "directory", "membership"]);
  });

  it("rejects cloned, look-alike, and cross-run artifacts", async () => {
    const runA = await collect(fixturesFor([]));
    const runB = await collect(fixturesFor([]));
    const artifactA = runA.artifacts[0]!;
    expect(() => assertOrganizationReconciliationDatasetArtifactBelongsToRun(
      runA,
      { ...artifactA }
    )).toThrow("forged or belongs to another run");
    expect(() => assertOrganizationReconciliationDatasetArtifactBelongsToRun(runB, artifactA))
      .toThrow("forged or belongs to another run");
    expect(() => assertOrganizationReconciliationDatasetArtifactBelongsToRun(
      { ...runA } as OrganizationReconciliationDatasetLineageRun,
      artifactA
    )).toThrow("forged or belongs to another run");
    expect(consumeOrganizationReconciliationDatasetArtifact(runA, artifactA)).toBe(artifactA);
    expect(() => consumeOrganizationReconciliationDatasetArtifact(runA, artifactA))
      .toThrow("artifact was replayed");
  });

  it("rejects unknown options and component fields before opening a snapshot", async () => {
    const callback = vi.fn();
    const optionFixtures = fixturesFor([]);
    await expect(collect(optionFixtures, { operation: callback })).rejects.toThrow("unknown fields");
    expect(callback).not.toHaveBeenCalled();
    expect(optionFixtures.every(({ adapter }) => adapter.openSnapshot.mock.calls.length === 0)).toBe(true);

    const componentFixtures = fixturesFor([]);
    (componentFixtures[0]!.binding as unknown as Record<string, unknown>).untrustedOwner = true;
    await expect(collect(componentFixtures)).rejects.toThrow("unknown fields");
    expect(componentFixtures.every(({ adapter }) => adapter.openSnapshot.mock.calls.length === 0)).toBe(true);
  });

  it.each([
    ["page", "maxPages", 6_000],
    ["record", "maxRecords", 6_000_000]
  ] as const)("rejects an aggregate %s budget before opening a snapshot", async (_label, field, value) => {
    const fixtures = fixturesFor([]);
    const datasets = fixtures[0]!.binding.datasetCatalog.datasets as unknown as Array<Record<string, unknown>>;
    datasets[0] = { ...datasets[0]!, [field]: value };
    datasets[1] = { ...datasets[1]!, [field]: value };

    await expect(collect(fixtures)).rejects.toThrow("exceeds its aggregate budget");
    expect(fixtures.every(({ adapter }) => adapter.openSnapshot.mock.calls.length === 0)).toBe(true);
  });

  it.each([
    ["cross-snapshot", (fixtures: Fixture[]) => {
      firstPage(fixtures, "legacy-main", "directory").snapshotId = "other-snapshot";
    }],
    ["cross-component", (fixtures: Fixture[]) => {
      firstPage(fixtures, "legacy-main", "directory").sourceId = "identity-db";
    }],
    ["self-reported page digest", (fixtures: Fixture[]) => {
      const page = firstPage(fixtures, "legacy-main", "directory") as unknown as Record<string, unknown>;
      page.recordsSha256 = "f".repeat(64);
    }],
    ["dataset count drift", (fixtures: Fixture[]) => {
      const pages = fixtures[0]!.pages.get("directory")!;
      pages[1] = { ...pages[1]!, datasetRecordCount: 3 };
    }]
  ])("fails closed on a %s page", async (_label, mutate) => {
    const fixtures = fixturesFor([]);
    mutate(fixtures);
    await expect(collect(fixtures)).rejects.toThrow("coordinated snapshot operation failed");
    assertClosedOnce(fixtures, "failed");
  });

  it("rejects a missing terminal page and a repeated cursor", async () => {
    for (const mode of ["missing", "repeated"] as const) {
      const fixtures = fixturesFor([]);
      const pages = fixtures[0]!.pages.get("directory")!;
      if (mode === "missing") {
        pages.splice(0, pages.length, { ...pages[0]!, nextCursor: null });
      } else {
        pages[1] = { ...pages[1]!, nextCursor: "directory-cursor-1" };
      }
      await expect(collect(fixtures)).rejects.toThrow("coordinated snapshot operation failed");
      assertClosedOnce(fixtures, "failed");
    }
  });

  it("rejects a non-null first request cursor for another dataset", async () => {
    const fixtures = fixturesFor([]);
    const membership = firstPage(fixtures, "legacy-main", "membership");
    membership.requestCursor = "directory-cursor-1";
    await expect(collect(fixtures)).rejects.toThrow("coordinated snapshot operation failed");
    assertClosedOnce(fixtures, "failed");
  });

  it("keeps dataset counts separate from aggregate component raw count", async () => {
    const fixtures = fixturesFor([]);
    const legacy = fixtures[0]!;
    legacy.snapshot.recordCount += 1;
    for (const pages of legacy.pages.values()) {
      for (let index = 0; index < pages.length; index += 1) {
        pages[index] = { ...pages[index]!, snapshotRecordCount: legacy.snapshot.recordCount };
      }
    }
    await expect(collect(fixtures)).rejects.toThrow("coordinated snapshot operation failed");
    assertClosedOnce(fixtures, "failed");
  });

  it("rejects read-method TOCTOU before accepting a page", async () => {
    const fixtures = fixturesFor([]);
    const legacy = fixtures[0]!;
    legacy.adapter.openSnapshot.mockImplementationOnce(async () => {
      legacy.adapter.readSnapshotPage = vi.fn(async () => firstPage(fixtures, "legacy-main", "directory"));
      return legacy.snapshot;
    });
    await expect(collect(fixtures)).rejects.toThrow("coordinated snapshot operation failed");
    assertClosedOnce(fixtures, "failed");
  });

  it("redacts read failures, closes in reverse exactly once, and rejects any close failure", async () => {
    const readEvents: string[] = [];
    const readFixtures = fixturesFor(readEvents);
    readFixtures[0]!.adapter.readSnapshotPage.mockRejectedValueOnce(new Error("private-read-token"));
    const readFailure = await collect(readFixtures).catch((error: unknown) => error);
    expect(readFailure).toEqual(new Error("The coordinated snapshot operation failed."));
    expect(JSON.stringify(readFailure)).not.toContain("private-read-token");
    assertClosedOnce(readFixtures, "failed");
    expect(readEvents.slice(-3)).toEqual([
      "close:plugin:failed", "close:identity:failed", "close:legacy-main:failed"
    ]);

    const closeEvents: string[] = [];
    const closeFixtures = fixturesFor(closeEvents);
    closeFixtures[2]!.adapter.closeSnapshot.mockImplementationOnce(async (
      _snapshot: OrganizationReconciliationSourceSnapshot,
      outcome: "completed" | "failed"
    ) => {
      closeEvents.push(`close:plugin:${outcome}`);
      throw new Error("private-close-token");
    });
    const closeFailure = await collect(closeFixtures).catch((error: unknown) => error);
    expect(closeFailure).toEqual(new Error(
      "Closing or finalizing coordinated source snapshots failed; composite evidence was rejected."
    ));
    expect(JSON.stringify(closeFailure)).not.toContain("private-close-token");
    assertClosedOnce(closeFixtures, "completed");
    expect(closeEvents.slice(-3)).toEqual([
      "close:plugin:completed", "close:identity:completed", "close:legacy-main:completed"
    ]);
  });

  it("rejects record getters and snapshots mutable page records before hashing", async () => {
    const getterFixtures = fixturesFor([]);
    const page = firstPage(getterFixtures, "legacy-main", "directory") as unknown as Record<string, unknown>;
    Object.defineProperty(page, "records", {
      enumerable: true,
      get: () => [{ id: "private-getter-record" }]
    });
    const failure = await collect(getterFixtures).catch((error: unknown) => error);
    expect(failure).toEqual(new Error("The coordinated snapshot operation failed."));
    expect(JSON.stringify(failure)).not.toContain("private-getter-record");
    assertClosedOnce(getterFixtures, "failed");

    const mutationFixtures = fixturesFor([]);
    const mutable = firstPage(mutationFixtures, "legacy-main", "directory").records[0] as Mutable<RawRecord>;
    const run = await collect(mutationFixtures);
    mutable.id = "mutated-after-read";
    expect(run.artifacts[0]!.records[0]).toEqual({ id: "legacy-main-directory-1" });
    expect(run.artifacts[0]!.recordsSha256).toMatch(/^[a-f0-9]{64}$/);
  });
});

function fixturesFor(events: string[]): Fixture[] {
  const definitions: readonly [OrganizationReconciliationPhysicalSource, readonly [string, number][]][] = [
    ["legacy-main", [["membership", 1], ["directory", 2]]],
    ["identity", [["membership", 1], ["directory", 1]]],
    ["plugin", [["registry", 1]]]
  ];
  return definitions.map(([id, datasets], componentIndex) => {
    const sourceId = `${id}-db`;
    const snapshot: Mutable<OrganizationReconciliationSourceSnapshot> = {
      sourceId,
      sourceVersion: `${id}-version-1`,
      snapshotId: `${id}-snapshot-1`,
      recordCount: datasets.reduce((sum, [, count]) => sum + count, 0),
      subjectUniverseCount: id === "plugin" ? 0 : 1,
      subjectUniverseHash: id === "plugin" ? "" : "1".repeat(64),
      snapshotMode: ORGANIZATION_RECONCILIATION_SNAPSHOT_MODE,
      paginationMode: ORGANIZATION_RECONCILIATION_PAGINATION_MODE
    };
    const pages = new Map<string, Array<OrganizationReconciliationDatasetPage<RawRecord>>>();
    for (const [datasetId, count] of datasets) {
      const records = Array.from({ length: count }, (_, index) => ({ id: `${id}-${datasetId}-${index + 1}` }));
      pages.set(datasetId, count === 2
        ? [
            datasetPage(snapshot, datasetId, count, [records[0]!], null, `${datasetId}-cursor-1`, 0),
            datasetPage(snapshot, datasetId, count, [records[1]!], `${datasetId}-cursor-1`, null, 1)
          ]
        : [datasetPage(snapshot, datasetId, count, records, null, null, 0)]);
    }
    const adapter = {
      sourceId,
      openSnapshot: vi.fn(async () => {
        events.push(`open:${id}`);
        return snapshot;
      }),
      readSnapshotPage: vi.fn(async (request: { datasetId: string }) => {
        events.push(`read:${id}:${request.datasetId}`);
        return pages.get(request.datasetId)!.shift()!;
      }),
      closeSnapshot: vi.fn(async (_snapshot: OrganizationReconciliationSourceSnapshot, outcome: "completed" | "failed") => {
        events.push(`close:${id}:${outcome}`);
      })
    } as Fixture["adapter"];
    const datasetCatalog: OrganizationReconciliationDatasetCatalog = {
      contract: ORGANIZATION_RECONCILIATION_DATASET_LINEAGE_CONTRACT,
      trust: ORGANIZATION_RECONCILIATION_DATASET_CATALOG_TRUST,
      datasets: datasets.map(([datasetId]) => ({ datasetId, pageSize: 10, maxPages: 10, maxRecords: 100 }))
    };
    return {
      id,
      snapshot,
      adapter,
      pages,
      binding: {
        componentId: id,
        expectedSourceId: sourceId,
        schemaSha256: String(componentIndex + 4).repeat(64),
        catalogSha256: String(componentIndex + 7).repeat(64),
        buildSha256: ["a", "b", "c"][componentIndex]!.repeat(64),
        adapter,
        datasetCatalog
      }
    };
  });
}

function datasetPage(
  snapshot: OrganizationReconciliationSourceSnapshot,
  datasetId: string,
  datasetRecordCount: number,
  records: readonly RawRecord[],
  requestCursor: string | null,
  nextCursor: string | null,
  recordOffset: number
): OrganizationReconciliationDatasetPage<RawRecord> {
  return {
    sourceId: snapshot.sourceId,
    sourceVersion: snapshot.sourceVersion,
    snapshotId: snapshot.snapshotId,
    snapshotRecordCount: snapshot.recordCount,
    subjectUniverseCount: snapshot.subjectUniverseCount,
    subjectUniverseHash: snapshot.subjectUniverseHash,
    datasetId,
    datasetRecordCount,
    requestCursor,
    nextCursor,
    recordOffset,
    records
  };
}

function collect(fixtures: Fixture[], extra: Record<string, unknown> = {}) {
  return collectOrganizationReconciliationDatasetLineage({
    components: fixtures.map(({ binding }) => binding),
    maxWindowMilliseconds: 1_000,
    clock: clockAt(0, 10, 20, 30, 40, 50),
    ...extra
  });
}

function firstPage(
  fixtures: Fixture[],
  componentId: OrganizationReconciliationPhysicalSource,
  datasetId: string
): Mutable<OrganizationReconciliationDatasetPage<RawRecord>> {
  return fixtures.find(({ id }) => id === componentId)!.pages.get(datasetId)![0]!;
}

function clockAt(...offsets: number[]) {
  let index = 0;
  return {
    now: vi.fn(() => {
      if (index >= offsets.length) throw new Error("test clock exhausted");
      return new Date(BASE_TIME + offsets[index++]!);
    })
  };
}

function assertClosedOnce(fixtures: Fixture[], outcome: "completed" | "failed") {
  for (const fixture of fixtures) {
    expect(fixture.adapter.closeSnapshot).toHaveBeenCalledTimes(1);
    expect(fixture.adapter.closeSnapshot).toHaveBeenCalledWith(fixture.snapshot, outcome);
  }
}
