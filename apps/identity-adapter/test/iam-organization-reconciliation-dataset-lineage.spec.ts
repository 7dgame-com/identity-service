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
import {
  createOrganizationReconciliationComponentDatasetInventory,
  createOrganizationReconciliationContentSnapshotId,
  createOrganizationReconciliationContentSourceVersion,
  type OrganizationReconciliationDatasetInventoryPageInput,
  type OrganizationReconciliationInventoryJsonValue
} from
  "../src/iam-organization-reconciliation-dataset-inventory.js";
import { openOrganizationReconciliationTransactionDatasetSpool } from
  "../src/iam-organization-reconciliation-transaction-dataset-spool.js";

interface RawRecord { readonly id: string }
type Mutable<T> = { -readonly [K in keyof T]: T[K] };

interface Fixture {
  readonly id: OrganizationReconciliationPhysicalSource;
  readonly snapshot: Mutable<OrganizationReconciliationSourceSnapshot>;
  readonly adapter: Mutable<OrganizationReconciliationDatasetSourceAdapter<unknown>> & {
    openSnapshot: ReturnType<typeof vi.fn>;
    readSnapshotPage: ReturnType<typeof vi.fn>;
    verifySnapshotDatasetReplay: ReturnType<typeof vi.fn>;
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
        "transaction-owned-inventory-bridge-not-production-registered",
        "dataset-unique-order-contract-not-registered",
        "bounded-streaming-projector-not-implemented",
        "operation-evidence-projector-not-implemented",
        "factory-created-transaction-adapter-capability-not-registered",
        "compiled-reconciliation-pipeline-not-registered"
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
    expect(run.artifacts[0]!.pages[0]!.recordsCommitment).toMatch(/^[a-f0-9]{64}$/);
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

  it("rejects a short page before a nonterminal cursor", async () => {
    const fixtures = fixturesFor([]);
    const pages = fixtures[0]!.pages.get("directory")!;
    pages[0] = { ...pages[0]!, records: [] };
    await expect(collect(fixtures)).rejects.toThrow("coordinated snapshot operation failed");
    assertClosedOnce(fixtures, "failed");
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
    await expect(collect(fixtures)).rejects.toThrow("record count does not match its dataset inventory");
    expect(legacy.adapter.closeSnapshot).toHaveBeenCalledTimes(1);
    expect(legacy.adapter.closeSnapshot).toHaveBeenCalledWith(legacy.snapshot, "failed");
    expect(fixtures[1]!.adapter.closeSnapshot).not.toHaveBeenCalled();
    expect(fixtures[2]!.adapter.closeSnapshot).not.toHaveBeenCalled();
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

  it("captures snapshot metadata once and rejects raw-handle mutation during a read", async () => {
    const fixtures = fixturesFor([]);
    const legacy = fixtures[0]!;
    const originalRead = legacy.adapter.readSnapshotPage;
    legacy.adapter.readSnapshotPage = vi.fn(async (request: {
      snapshot: OrganizationReconciliationSourceSnapshot;
      datasetId: string;
      requestCursor: string | null;
      pageSize: number;
    }) => {
      legacy.snapshot.sourceVersion = "mutated-after-open";
      const page = await originalRead(request);
      return { ...page, sourceVersion: "mutated-after-open" };
    });
    await expect(collect(fixtures)).rejects.toThrow(/operation failed|finalizing/);
    expect(legacy.adapter.closeSnapshot).toHaveBeenCalledWith(legacy.snapshot, "failed");
  });

  it("rejects snapshot metadata accessors without invoking them and closes the raw handle", async () => {
    const fixtures = fixturesFor([]);
    const legacy = fixtures[0]!;
    let invoked = false;
    Object.defineProperty(legacy.snapshot, "sourceVersion", {
      enumerable: true,
      get: () => { invoked = true; return "private-accessor"; }
    });
    await expect(collect(fixtures)).rejects.toThrow("Opening a coordinated authoritative source snapshot failed");
    expect(invoked).toBe(false);
    expect(legacy.adapter.closeSnapshot).toHaveBeenCalledWith(legacy.snapshot, "failed");
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

  it("preserves exact spool replay identities privately while publishing only canonical clones", async () => {
    const system = await spoolBackedLegacyFixtures();
    try {
      const run = await collect(system.fixtures);
      const artifact = run.artifacts.find((candidate) =>
        candidate.componentId === "legacy-main" && candidate.datasetId === "directory")!;
      const [verificationRequest] = system.legacy.adapter.verifySnapshotDatasetReplay.mock.calls[0]!;

      expect(system.replayRecords).toHaveLength(2);
      expect(verificationRequest.pages[0].records).toBe(system.replayRecords[0]);
      expect(verificationRequest.pages[1].records).toBe(system.replayRecords[1]);
      expect(artifact.records).toEqual([
        { id: "legacy-main-directory-spool-1" },
        { id: "legacy-main-directory-spool-2" }
      ]);
      expect(artifact.records).not.toBe(system.replayRecords[0]);
      expect(artifact.records[0]).not.toBe(system.replayRecords[0]![0]);
      expect(artifact.records[1]).not.toBe(system.replayRecords[1]![0]);
      expect(Object.isFrozen(artifact.records[0])).toBe(true);
      expect(await system.spool.close("completed")).toBe("completed");
    } finally {
      await system.spool.close("failed").catch(() => undefined);
    }
  });

  it.each(["clone", "page-a-b", "component-a-b", "proxy"] as const)(
    "rejects %s replacement of an exact spool replay records identity",
    async (mode) => {
      const system = await spoolBackedLegacyFixtures(({ records, pageIndex, fixtures, replayRecords }) => {
        if (mode === "clone" && pageIndex === 0) return Object.freeze([...records]);
        if (mode === "page-a-b" && pageIndex === 1) return replayRecords[0]!;
        if (mode === "component-a-b" && pageIndex === 0) {
          return firstPage(fixtures, "identity", "directory").records as unknown as
            readonly OrganizationReconciliationInventoryJsonValue[];
        }
        if (mode === "proxy" && pageIndex === 0) return new Proxy(records, {});
        return records;
      });
      try {
        const failure = await collect(system.fixtures).catch((error: unknown) => error);
        expect(failure).toEqual(new Error("The coordinated snapshot operation failed."));
        expect(system.legacy.adapter.verifySnapshotDatasetReplay).toHaveBeenCalledTimes(
          mode === "proxy" ? 0 : 1
        );
        assertClosedOnce(system.fixtures, "failed");
      } finally {
        await system.spool.close("failed").catch(() => undefined);
      }
    }
  );

  it.each(["hidden", "symbol", "custom-prototype", "index-accessor"] as const)(
    "rejects a %s records array before replay verification",
    async (mode) => {
      const fixtures = fixturesFor([]);
      const page = firstPage(fixtures, "legacy-main", "directory");
      const records = page.records as RawRecord[];
      let getterInvoked = false;
      if (mode === "hidden") Object.defineProperty(records, "hidden", { value: true });
      if (mode === "symbol") (records as unknown as Record<symbol, unknown>)[Symbol("hidden")] = true;
      if (mode === "custom-prototype") Object.setPrototypeOf(records, { attacker: true });
      if (mode === "index-accessor") {
        Object.defineProperty(records, "0", {
          enumerable: true,
          get: () => {
            getterInvoked = true;
            return { id: "private-index-getter" };
          }
        });
      }

      const failure = await collect(fixtures).catch((error: unknown) => error);
      expect(failure).toEqual(new Error("The coordinated snapshot operation failed."));
      expect(getterInvoked).toBe(false);
      expect(fixtures[0]!.adapter.verifySnapshotDatasetReplay).not.toHaveBeenCalled();
      assertClosedOnce(fixtures, "failed");
    }
  );

  it("rejects record getters and snapshots mutable page records before hashing", async () => {
    const getterFixtures = fixturesFor([]);
    const page = firstPage(getterFixtures, "legacy-main", "directory") as unknown as Record<string, unknown>;
    let getterInvoked = false;
    Object.defineProperty(page, "records", {
      enumerable: true,
      get: () => {
        getterInvoked = true;
        return [{ id: "private-getter-record" }];
      }
    });
    const failure = await collect(getterFixtures).catch((error: unknown) => error);
    expect(failure).toEqual(new Error("The coordinated snapshot operation failed."));
    expect(getterInvoked).toBe(false);
    expect(JSON.stringify(failure)).not.toContain("private-getter-record");
    assertClosedOnce(getterFixtures, "failed");

    const mutationFixtures = fixturesFor([]);
    const mutable = firstPage(mutationFixtures, "legacy-main", "directory").records[0] as Mutable<RawRecord>;
    const run = await collect(mutationFixtures);
    mutable.id = "mutated-after-read";
    expect(run.artifacts[0]!.records[0]).toEqual({ id: "legacy-main-directory-1" });
    expect(run.artifacts[0]!.recordsCommitment).toMatch(/^[a-f0-9]{64}$/);
  });
});

interface SpoolReplayTransformContext {
  readonly records: readonly OrganizationReconciliationInventoryJsonValue[];
  readonly pageIndex: number;
  readonly fixtures: Fixture[];
  readonly replayRecords: readonly (readonly OrganizationReconciliationInventoryJsonValue[])[];
}

async function spoolBackedLegacyFixtures(
  transform?: (context: SpoolReplayTransformContext) => readonly OrganizationReconciliationInventoryJsonValue[]
) {
  const fixtures = fixturesFor([]);
  const legacy = fixtures[0]!;
  const datasetCatalog: OrganizationReconciliationDatasetCatalog = {
    contract: ORGANIZATION_RECONCILIATION_DATASET_LINEAGE_CONTRACT,
    trust: ORGANIZATION_RECONCILIATION_DATASET_CATALOG_TRUST,
    datasets: [{ datasetId: "directory", pageSize: 1, maxPages: 2, maxRecords: 2 }]
  };
  const spool = await openOrganizationReconciliationTransactionDatasetSpool({
    componentId: "legacy-main",
    sourceId: legacy.snapshot.sourceId,
    catalogSha256: legacy.binding.catalogSha256,
    datasetCatalog,
    commitmentKey: Buffer.alloc(32, 9),
    subjectUniverse: null
  });
  try {
    await spool.appendPage({
      datasetId: "directory",
      requestCursor: null,
      nextCursor: "directory-cursor-1",
      recordOffset: 0,
      records: [{ id: "legacy-main-directory-spool-1" }]
    });
    await spool.appendPage({
      datasetId: "directory",
      requestCursor: "directory-cursor-1",
      nextCursor: null,
      recordOffset: 1,
      records: [{ id: "legacy-main-directory-spool-2" }]
    });
    const inventory = await spool.seal();
    legacy.snapshot.recordCount = 2;
    legacy.snapshot.datasetInventory = inventory;
    legacy.snapshot.sourceVersion = createOrganizationReconciliationContentSourceVersion(
      legacy.snapshot.sourceId,
      inventory
    );
    legacy.snapshot.snapshotId = createOrganizationReconciliationContentSnapshotId(
      legacy.snapshot.sourceId,
      inventory
    );
    (legacy.binding as Mutable<OrganizationReconciliationDatasetComponentBinding>).datasetCatalog = datasetCatalog;

    const replayRecords: Array<readonly OrganizationReconciliationInventoryJsonValue[]> = [];
    legacy.adapter.readSnapshotPage = vi.fn(async (
      request: Parameters<OrganizationReconciliationDatasetSourceAdapter<unknown>["readSnapshotPage"]>[0]
    ) => {
      const page = await spool.readPage({
        datasetId: request.datasetId,
        requestCursor: request.requestCursor,
        pageSize: request.pageSize
      });
      const pageIndex = replayRecords.length;
      replayRecords.push(page.records);
      const records = transform?.({ records: page.records, pageIndex, fixtures, replayRecords }) ?? page.records;
      return {
        sourceId: legacy.snapshot.sourceId,
        sourceVersion: legacy.snapshot.sourceVersion,
        snapshotId: legacy.snapshot.snapshotId,
        snapshotRecordCount: legacy.snapshot.recordCount,
        subjectUniverseCount: legacy.snapshot.subjectUniverseCount,
        subjectUniverseHash: legacy.snapshot.subjectUniverseHash,
        datasetId: page.datasetId,
        datasetRecordCount: page.datasetRecordCount,
        requestCursor: page.requestCursor,
        nextCursor: page.nextCursor,
        recordOffset: page.recordOffset,
        records
      } satisfies OrganizationReconciliationDatasetPage<OrganizationReconciliationInventoryJsonValue>;
    });
    legacy.adapter.verifySnapshotDatasetReplay = vi.fn((
      request: Parameters<
        OrganizationReconciliationDatasetSourceAdapter<unknown>["verifySnapshotDatasetReplay"]
      >[0]
    ) => {
      spool.verifyDatasetReplay({
        datasetId: request.datasetId,
        pages: request.pages as readonly OrganizationReconciliationDatasetInventoryPageInput[]
      });
    });
    legacy.adapter.closeSnapshot = vi.fn(async (
      _snapshot: OrganizationReconciliationSourceSnapshot,
      outcome: "completed" | "failed"
    ) => {
      await spool.close(outcome);
    });
    return { fixtures, legacy, spool, replayRecords };
  } catch (error) {
    await spool.close("failed").catch(() => undefined);
    throw error;
  }
}

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
    const catalogSha256 = String(componentIndex + 7).repeat(64);
    const commitmentKey = Buffer.alloc(32, componentIndex + 1);
    snapshot.datasetInventory = createOrganizationReconciliationComponentDatasetInventory({
      componentId: id,
      sourceId,
      catalogSha256,
      datasets: [...pages.entries()].map(([datasetId, datasetPages]) => ({
        datasetId,
        pages: datasetPages.map((page) => ({
          requestCursor: page.requestCursor,
          nextCursor: page.nextCursor,
          recordOffset: page.recordOffset,
          records: page.records as unknown as readonly import("../src/iam-organization-reconciliation-dataset-inventory.js").OrganizationReconciliationInventoryJsonValue[]
        }))
      })),
      commitmentKey
    });
    snapshot.sourceVersion = createOrganizationReconciliationContentSourceVersion(sourceId, snapshot.datasetInventory);
    snapshot.snapshotId = createOrganizationReconciliationContentSnapshotId(sourceId, snapshot.datasetInventory);
    for (const datasetPages of pages.values()) {
      for (const page of datasetPages) {
        (page as Mutable<typeof page>).sourceVersion = snapshot.sourceVersion;
        (page as Mutable<typeof page>).snapshotId = snapshot.snapshotId;
      }
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
      verifySnapshotDatasetReplay: vi.fn((request: {
        snapshot: OrganizationReconciliationSourceSnapshot;
        datasetId: string;
        pages: readonly import("../src/iam-organization-reconciliation-dataset-inventory.js").OrganizationReconciliationDatasetInventoryPageInput[];
      }) => {
        if (request.snapshot !== snapshot) throw new Error("wrong snapshot");
        const observed = createOrganizationReconciliationComponentDatasetInventory({
          componentId: id,
          sourceId,
          catalogSha256,
          datasets: [{ datasetId: request.datasetId, pages: request.pages }],
          commitmentKey
        }).datasets[0]!;
        const expected = snapshot.datasetInventory!.datasets.find((dataset) => dataset.datasetId === request.datasetId);
        if (!expected || observed.lineageSha256 !== expected.lineageSha256) throw new Error("mismatch");
      }),
      closeSnapshot: vi.fn(async (_snapshot: OrganizationReconciliationSourceSnapshot, outcome: "completed" | "failed") => {
        events.push(`close:${id}:${outcome}`);
      })
    } as Fixture["adapter"];
    const datasetCatalog: OrganizationReconciliationDatasetCatalog = {
      contract: ORGANIZATION_RECONCILIATION_DATASET_LINEAGE_CONTRACT,
      trust: ORGANIZATION_RECONCILIATION_DATASET_CATALOG_TRUST,
      datasets: datasets.map(([datasetId]) => ({ datasetId, pageSize: 1, maxPages: 10, maxRecords: 100 }))
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
        catalogSha256,
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
