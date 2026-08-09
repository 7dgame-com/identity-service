import { describe, expect, it, vi } from "vitest";
import {
  collectOrganizationReconciliationSource,
  ORGANIZATION_RECONCILIATION_PAGINATION_MODE,
  ORGANIZATION_RECONCILIATION_SNAPSHOT_MODE,
  type OrganizationReconciliationSourceAdapter,
  type OrganizationReconciliationSourcePage,
  type OrganizationReconciliationSourceSnapshot
} from "../src/iam-organization-reconciliation-collector.js";

interface RawRecord {
  readonly id: unknown;
  readonly value: unknown;
}

interface RecordModel {
  readonly id: number;
  readonly value: string;
}

describe("organization reconciliation source collector", () => {
  it("collects one immutable, complete, ordered cursor chain", async () => {
    const adapter = adapterFor([
      page(null, "cursor-2", 0, [{ id: 1, value: "one" }, { id: 2, value: "two" }], 3),
      page("cursor-2", null, 2, [{ id: 3, value: "three" }], 3)
    ], 3);

    const result = await collect(adapter);

    expect(adapter.openSnapshot).toHaveBeenCalledTimes(1);
    expect(adapter.closeSnapshot).toHaveBeenCalledTimes(1);
    expect(adapter.closeSnapshot).toHaveBeenCalledWith(snapshot(3), "completed");
    expect(adapter.readSnapshotPage).toHaveBeenCalledTimes(2);
    expect(adapter.readSnapshotPage).toHaveBeenNthCalledWith(1, {
      snapshot: snapshot(3), requestCursor: null, pageSize: 2
    });
    expect(adapter.readSnapshotPage).toHaveBeenNthCalledWith(2, {
      snapshot: snapshot(3), requestCursor: "cursor-2", pageSize: 2
    });
    expect(result.source).toEqual(snapshot(3));
    expect(result.collectorBuildRevision).toBe(COLLECTOR_BUILD_REVISION);
    expect(result.page).toMatchObject({
      sourceVersion: SOURCE_VERSION,
      nextCursor: null,
      records: [{ id: 1, value: "one" }, { id: 2, value: "two" }, { id: 3, value: "three" }],
      collection: {
        snapshotId: SNAPSHOT_ID,
        pageCount: 2,
        recordCount: 3,
        pages: [
          { pageNumber: 1, requestCursor: null, nextCursor: "cursor-2", recordOffset: 0, recordCount: 2 },
          { pageNumber: 2, requestCursor: "cursor-2", nextCursor: null, recordOffset: 2, recordCount: 1 }
        ]
      }
    });
  });

  it("supports a proven empty full-range snapshot with one terminal page", async () => {
    const result = await collect(adapterFor([page(null, null, 0, [], 0)], 0));
    expect(result.page.records).toEqual([]);
    expect(result.page.collection).toMatchObject({ pageCount: 1, recordCount: 0 });
  });

  it.each([
    ["source version", { sourceVersion: "changed-version" }],
    ["snapshot ID", { snapshotId: "changed-snapshot" }],
    ["snapshot count", { snapshotRecordCount: 4 }],
    ["subject universe count", { subjectUniverseCount: 2 }],
    ["subject universe hash", { subjectUniverseHash: "b".repeat(64) }],
    ["request cursor", { requestCursor: "wrong-cursor" }],
    ["record offset", { recordOffset: 1 }]
  ] as const)("fails closed when a page changes %s", async (_label, override) => {
    const changed = { ...page(null, null, 0, [{ id: 1, value: "one" }], 1), ...override };
    await expect(collect(adapterFor([changed], 1))).rejects.toThrow();
  });

  it.each([
    ["missing source version", { sourceVersion: "" }],
    ["missing snapshot ID", { snapshotId: "" }],
    ["empty subject universe", { subjectUniverseCount: 0 }],
    ["invalid subject universe hash", { subjectUniverseHash: "short" }],
    ["non-immutable snapshot", { snapshotMode: "best-effort" }],
    ["non-snapshot pagination", { paginationMode: "offset" }]
  ] as const)("rejects an opened snapshot with %s", async (_label, override) => {
    const adapter = adapterFor([page(null, null, 0, [], 0)], 0);
    adapter.openSnapshot.mockResolvedValue({ ...snapshot(0), ...override } as OrganizationReconciliationSourceSnapshot);
    await expect(collect(adapter)).rejects.toThrow();
    expect(adapter.readSnapshotPage).not.toHaveBeenCalled();
  });

  it("rejects truncated, repeated, empty-continuation, duplicate, and out-of-order chains", async () => {
    await expect(collect(adapterFor([page(null, null, 0, [{ id: 1, value: "one" }], 2)], 2)))
      .rejects.toThrow("terminal source record count");

    await expect(collect(adapterFor([
      page(null, "repeat", 0, [{ id: 1, value: "one" }], 2),
      page("repeat", "repeat", 1, [{ id: 2, value: "two" }], 2)
    ], 2))).rejects.toThrow("repeats a continuation cursor");

    await expect(collect(adapterFor([
      page(null, "next", 0, [], 1),
      page("next", null, 0, [{ id: 1, value: "one" }], 1)
    ], 1))).rejects.toThrow("non-terminal source page cannot be empty");

    await expect(collect(adapterFor([
      page(null, "next", 0, [{ id: 1, value: "one" }], 2),
      page("next", null, 1, [{ id: 1, value: "duplicate" }], 2)
    ], 2))).rejects.toThrow("duplicate record key");

    await expect(collect(adapterFor([
      page(null, null, 0, [{ id: 2, value: "two" }, { id: 1, value: "one" }], 2)
    ], 2))).rejects.toThrow("strict canonical order");
  });

  it("uses a strict record decoder and does not expose a raw source failure", async () => {
    await expect(collect(adapterFor([
      page(null, null, 0, [{ id: "not-an-integer", value: "private-value" }], 1)
    ], 1))).rejects.toThrow("Source record normalization failed at page 1, record 1.");

    const adapter = adapterFor([page(null, null, 0, [], 0)], 0);
    adapter.readSnapshotPage.mockRejectedValue(new Error("raw-private-source-token"));
    const failure = await collect(adapter).catch((error: unknown) => error);
    expect(failure).toEqual(new Error("Reading authoritative source page 1 failed."));
    expect(JSON.stringify(failure)).not.toContain("raw-private-source-token");
    expect(adapter.closeSnapshot).toHaveBeenCalledTimes(1);
    expect(adapter.closeSnapshot).toHaveBeenCalledWith(snapshot(0), "failed");
  });

  it("redacts decoder key failures and always closes an opened snapshot exactly once", async () => {
    const adapter = adapterFor([page(null, null, 0, [{ id: 1, value: "one" }], 1)], 1);
    const failure = await collect(adapter, {
      decoder: {
        ...strictDecoder,
        uniqueKey() {
          throw new Error("private-subject-ref");
        }
      }
    }).catch((error: unknown) => error);
    expect(failure).toEqual(new Error("Source record normalization failed at page 1, record 1."));
    expect(JSON.stringify(failure)).not.toContain("private-subject-ref");
    expect(adapter.closeSnapshot).toHaveBeenCalledTimes(1);
    expect(adapter.closeSnapshot).toHaveBeenCalledWith(snapshot(1), "failed");
  });

  it("does not close when open fails and rejects evidence when close fails", async () => {
    const openFailure = adapterFor([page(null, null, 0, [], 0)], 0);
    openFailure.openSnapshot.mockRejectedValue(new Error("private-open-token"));
    await expect(collect(openFailure)).rejects.toThrow("Opening the authoritative source snapshot failed.");
    expect(openFailure.closeSnapshot).not.toHaveBeenCalled();

    const closeFailure = adapterFor([page(null, null, 0, [], 0)], 0);
    closeFailure.closeSnapshot.mockRejectedValue(new Error("private-close-token"));
    const failure = await collect(closeFailure).catch((error: unknown) => error);
    expect(failure).toEqual(new Error("Closing the authoritative source snapshot failed; collection evidence was rejected."));
    expect(JSON.stringify(failure)).not.toContain("private-close-token");
    expect(closeFailure.closeSnapshot).toHaveBeenCalledTimes(1);
    expect(closeFailure.closeSnapshot).toHaveBeenCalledWith(snapshot(0), "completed");
  });

  it("closes exactly once after page-binding, decode, and canonical-order failures", async () => {
    const cases = [
      adapterFor([{ ...page(null, null, 0, [], 0), snapshotId: "changed-snapshot" }], 0),
      adapterFor([page(null, null, 0, [{ id: "invalid", value: "private" }], 1)], 1),
      adapterFor([page(null, null, 0, [{ id: 2, value: "two" }, { id: 1, value: "one" }], 2)], 2)
    ];
    for (const adapter of cases) {
      await expect(collect(adapter)).rejects.toThrow();
      expect(adapter.closeSnapshot).toHaveBeenCalledTimes(1);
      expect(adapter.closeSnapshot).toHaveBeenCalledWith(expect.any(Object), "failed");
    }
  });

  it("enforces page, record, and source binding bounds before claiming completeness", async () => {
    const wrongSource = adapterFor([page(null, null, 0, [], 0)], 0);
    await expect(collect(wrongSource, { expectedSourceId: "another-source" })).rejects.toThrow("unexpected source");
    expect(wrongSource.openSnapshot).not.toHaveBeenCalled();

    const tooManyPages = adapterFor([
      page(null, "next", 0, [{ id: 1, value: "one" }], 2),
      page("next", null, 1, [{ id: 2, value: "two" }], 2)
    ], 2);
    await expect(collect(tooManyPages, { maxPages: 1 })).rejects.toThrow("page bound");

    const tooManyRecords = adapterFor([page(null, null, 0, [], 2)], 2);
    await expect(collect(tooManyRecords, { maxRecords: 1 })).rejects.toThrow("record count");
    expect(tooManyRecords.readSnapshotPage).not.toHaveBeenCalled();

    const invalidNonce = adapterFor([page(null, null, 0, [], 0)], 0);
    await expect(collectOrganizationReconciliationSource({
      expectedSourceId: SOURCE_ID,
      evidenceNonce: "short",
      pageSize: 2,
      maxPages: 10,
      maxRecords: 100,
      adapter: invalidNonce,
      decoder: strictDecoder
    }, REVIEWED_BUILD_REVISION_PROVIDER)).rejects.toThrow("evidence nonce");
    expect(invalidNonce.openSnapshot).not.toHaveBeenCalled();

    const invalidBuildProvider = adapterFor([page(null, null, 0, [], 0)], 0);
    await expect(collectOrganizationReconciliationSource({
      expectedSourceId: SOURCE_ID,
      evidenceNonce: EVIDENCE_NONCE,
      pageSize: 2,
      maxPages: 10,
      maxRecords: 100,
      adapter: invalidBuildProvider,
      decoder: strictDecoder
    }, { getBuildRevision: () => "caller-supplied-short" })).rejects.toThrow(
      "reviewed collector artifact build revision"
    );
    expect(invalidBuildProvider.openSnapshot).not.toHaveBeenCalled();
  });
});

const SOURCE_ID = "legacy-main-db";
const COLLECTOR_BUILD_REVISION = "a".repeat(40);
const SOURCE_VERSION = "legacy-binlog-position-100";
const SNAPSHOT_ID = "legacy-snapshot-100";
const SUBJECT_UNIVERSE_HASH = "c".repeat(64);
const EVIDENCE_NONCE = "d4".repeat(32);
const REVIEWED_BUILD_REVISION_PROVIDER = Object.freeze({
  getBuildRevision: () => COLLECTOR_BUILD_REVISION
});

function snapshot(recordCount: number): OrganizationReconciliationSourceSnapshot {
  return {
    sourceId: SOURCE_ID,
    sourceVersion: SOURCE_VERSION,
    snapshotId: SNAPSHOT_ID,
    recordCount,
    subjectUniverseCount: 3,
    subjectUniverseHash: SUBJECT_UNIVERSE_HASH,
    snapshotMode: ORGANIZATION_RECONCILIATION_SNAPSHOT_MODE,
    paginationMode: ORGANIZATION_RECONCILIATION_PAGINATION_MODE
  };
}

function page(
  requestCursor: string | null,
  nextCursor: string | null,
  recordOffset: number,
  records: readonly RawRecord[],
  snapshotRecordCount: number
): OrganizationReconciliationSourcePage<RawRecord> {
  return {
    sourceId: SOURCE_ID,
    sourceVersion: SOURCE_VERSION,
    snapshotId: SNAPSHOT_ID,
    snapshotRecordCount,
    subjectUniverseCount: 3,
    subjectUniverseHash: SUBJECT_UNIVERSE_HASH,
    requestCursor,
    nextCursor,
    recordOffset,
    records
  };
}

function adapterFor(pages: readonly OrganizationReconciliationSourcePage<RawRecord>[], recordCount: number) {
  let pageIndex = 0;
  return {
    sourceId: SOURCE_ID,
    openSnapshot: vi.fn(async () => snapshot(recordCount)),
    readSnapshotPage: vi.fn(async () => pages[pageIndex++]!),
    closeSnapshot: vi.fn(async () => undefined)
  } satisfies OrganizationReconciliationSourceAdapter<RawRecord>;
}

function collect(
  adapter: ReturnType<typeof adapterFor>,
  overrides: Partial<{
    expectedSourceId: string;
    pageSize: number;
    maxPages: number;
    maxRecords: number;
    decoder: typeof strictDecoder;
  }> = {}
) {
  return collectOrganizationReconciliationSource({
    expectedSourceId: overrides.expectedSourceId ?? SOURCE_ID,
    evidenceNonce: EVIDENCE_NONCE,
    pageSize: overrides.pageSize ?? 2,
    maxPages: overrides.maxPages ?? 10,
    maxRecords: overrides.maxRecords ?? 100,
    adapter,
    decoder: overrides.decoder ?? strictDecoder
  }, REVIEWED_BUILD_REVISION_PROVIDER);
}

const strictDecoder = {
  decode(raw: RawRecord): RecordModel {
    if (!raw || typeof raw !== "object" || !Number.isSafeInteger(raw.id) || typeof raw.value !== "string") {
      throw new Error("invalid raw record");
    }
    return { id: raw.id as number, value: raw.value };
  },
  uniqueKey(record: RecordModel) {
    return String(record.id).padStart(12, "0");
  },
  orderKey(record: RecordModel) {
    return String(record.id).padStart(12, "0");
  }
};
