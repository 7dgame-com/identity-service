import { describe, expect, it, vi } from "vitest";
import { createHmac } from "node:crypto";
import { readdir, realpath } from "node:fs/promises";
import { tmpdir } from "node:os";
import {
  createOrganizationReconciliationComponentDatasetInventory,
  createOrganizationReconciliationIncrementalDatasetInventoryBuilder,
  ORGANIZATION_RECONCILIATION_INCREMENTAL_DATASET_INVENTORY_BUILDER_CONTRACT,
  type OrganizationReconciliationDatasetInventoryPageInput,
  type OrganizationReconciliationIncrementalDatasetInventoryBuilder,
  type OrganizationReconciliationInventoryJsonValue
} from "../src/iam-organization-reconciliation-dataset-inventory.js";
import {
  openOrganizationReconciliationTransactionDatasetSpool,
  ORGANIZATION_RECONCILIATION_TRANSACTION_DATASET_SPOOL_IMPLEMENTED,
  ORGANIZATION_RECONCILIATION_TRANSACTION_DATASET_SPOOL_READY,
  organizationReconciliationTransactionDatasetSpoolReadiness,
  type OrganizationReconciliationTransactionDatasetSpool
} from "../src/iam-organization-reconciliation-transaction-dataset-spool.js";
import {
  ORGANIZATION_RECONCILIATION_DATASET_CATALOG_TRUST,
  ORGANIZATION_RECONCILIATION_DATASET_LINEAGE_CONTRACT,
  type OrganizationReconciliationDatasetCatalog
} from "../src/iam-organization-reconciliation-dataset-lineage.js";
import {
  createOrganizationReconciliationEvidenceHash,
  createOrganizationReconciliationStringArrayEvidenceHashBuilder,
  ORGANIZATION_RECONCILIATION_STRING_ARRAY_EVIDENCE_HASH_BUILDER_CONTRACT
} from "../src/iam-organization-reconciliation-validator.js";

const DIGEST_A = "a".repeat(64);
const NONCE = "0123456789abcdef0123456789abcdef";

describe("incremental string-array evidence HMAC", () => {
  it("is byte-equivalent for empty, escaped, Unicode, and deliberately unsorted arrays", () => {
    const cases = [
      [],
      ["quote\"", "slash\\", "line\nfeed"],
      ["中文", "é", "e\u0301", "😀"],
      ["legacy-user:2", "legacy-user:10", "legacy-user:1"]
    ] as const;
    for (const values of cases) {
      const builder = createOrganizationReconciliationStringArrayEvidenceHashBuilder(NONCE);
      for (const value of values) builder.append(value);
      const expected = createHmac("sha256", NONCE)
        .update("iam-organization-reconciliation:v4\u001f")
        .update(`[${values.map((value) => JSON.stringify(value)).join(",")}]`)
        .digest("hex");
      expect(builder.seal()).toBe(expected);
      expect(createOrganizationReconciliationEvidenceHash(NONCE, values)).toBe(expected);

      const callerNonce = Buffer.from(NONCE, "utf8");
      const bufferBuilder = createOrganizationReconciliationStringArrayEvidenceHashBuilder(callerNonce);
      callerNonce.fill(0);
      for (const value of values) bufferBuilder.append(value);
      expect(bufferBuilder.seal()).toBe(expected);
    }
    const arbitraryObjectExpected = createHmac("sha256", NONCE)
      .update("iam-organization-reconciliation:v4\u001f")
      .update('{"values":["b","a"]}')
      .digest("hex");
    expect(createOrganizationReconciliationEvidenceHash(NONCE, { values: ["b", "a"] }))
      .toBe(arbitraryObjectExpected);
  });

  it("is one-shot, factory-branded, cross-instance safe, poisonable, and trust-neutral", () => {
    const make = () => createOrganizationReconciliationStringArrayEvidenceHashBuilder(NONCE);
    const first = make();
    const second = make();
    expect(first.contract).toBe(ORGANIZATION_RECONCILIATION_STRING_ARRAY_EVIDENCE_HASH_BUILDER_CONTRACT);
    expect(JSON.stringify(first)).not.toContain(NONCE);
    expect(JSON.stringify(first)).not.toContain("trust");
    expect(() => first.append.call(second, "value")).toThrow("lifecycle");
    expect(() => first.append.call({ ...first }, "value")).toThrow("lifecycle");
    expect(() => first.append.call(new Proxy(first, {}), "value")).toThrow("lifecycle");
    const fill = vi.spyOn(Buffer.prototype, "fill");
    first.append("value");
    expect(first.seal()).toMatch(/^[a-f0-9]{64}$/);
    expect(fill).toHaveBeenCalled();
    fill.mockRestore();
    expect(() => first.seal()).toThrow("lifecycle");

    const poisoned = make();
    expect(() => poisoned.append(1 as never)).toThrow("Appending");
    try { poisoned.append("unreachable"); } catch (error) {
      expect(String(error)).not.toContain(NONCE);
    }
    expect(() => poisoned.seal()).toThrow("lifecycle");
    const aborted = make();
    aborted.abort();
    expect(() => aborted.abort()).toThrow("lifecycle");
  });

  it("preserves the legacy single-read behavior for accessor, Proxy, and mid-scan mutation arrays", () => {
    const expected = (values: readonly string[]) => createHmac("sha256", NONCE)
      .update("iam-organization-reconciliation:v4\u001f")
      .update(`[${values.map((value) => JSON.stringify(value)).join(",")}]`)
      .digest("hex");

    let getterReads = 0;
    const accessor = ["placeholder"];
    Object.defineProperty(accessor, "0", {
      enumerable: true,
      configurable: true,
      get: () => { getterReads += 1; return "getter-value"; }
    });
    expect(createOrganizationReconciliationEvidenceHash(NONCE, accessor)).toBe(expected(["getter-value"]));
    expect(getterReads).toBe(1);

    let proxyIndexReads = 0;
    const proxy = new Proxy(["proxy-value"], {
      get(target, property, receiver) {
        if (property === "0") proxyIndexReads += 1;
        return Reflect.get(target, property, receiver);
      }
    });
    expect(createOrganizationReconciliationEvidenceHash(NONCE, proxy)).toBe(expected(["proxy-value"]));
    expect(proxyIndexReads).toBe(1);

    let mutationReads = 0;
    const mutating = ["first", "before"];
    Object.defineProperty(mutating, "0", {
      enumerable: true,
      configurable: true,
      get: () => {
        mutationReads += 1;
        mutating[1] = "after";
        return "first";
      }
    });
    expect(createOrganizationReconciliationEvidenceHash(NONCE, mutating)).toBe(expected(["first", "after"]));
    expect(mutationReads).toBe(1);
  });
});

describe("incremental transaction dataset inventory builder", () => {
  it("is byte-equivalent to the v2 batch creator for empty and multi-page datasets", () => {
    const datasets = [
      {
        datasetId: "records",
        pages: [
          page(null, "cursor-2", 0, [
            JSON.parse('{"id":1,"__proto__":null}'),
            { id: 2, nested: [null, true, "value"] }
          ]),
          page("cursor-2", null, 2, [
            JSON.parse('{"constructor":"literal","id":3}'),
            { id: 4, negativeZero: -0 }
          ])
        ]
      },
      {
        datasetId: "empty",
        pages: [page(null, null, 0, [])]
      }
    ] as const;
    const key = Buffer.alloc(32, 0x5a);
    const batch = createOrganizationReconciliationComponentDatasetInventory({
      componentId: "legacy-main",
      sourceId: "legacy-db",
      catalogSha256: DIGEST_A,
      datasets,
      commitmentKey: key
    });
    const builder = createOrganizationReconciliationIncrementalDatasetInventoryBuilder({
      componentId: "legacy-main",
      sourceId: "legacy-db",
      catalogSha256: DIGEST_A,
      commitmentKey: key
    });
    appendDataset(builder, datasets[0]);
    appendDataset(builder, datasets[1]);
    const streamed = builder.seal();

    expect(JSON.stringify(streamed)).toBe(JSON.stringify(batch));
    expect(streamed).toEqual(batch);
    expect(streamed.datasets[0]).toMatchObject({ datasetId: "empty", recordCount: 0, pageCount: 1 });
    expect(streamed.datasets[1]).toMatchObject({ datasetId: "records", recordCount: 4, pageCount: 2 });
  });

  it("binds records order, cursor nullability, and every prototype-looking JSON key", () => {
    const inventoryFor = (records: readonly never[]) => {
      const builder = createOrganizationReconciliationIncrementalDatasetInventoryBuilder({
        componentId: "identity",
        sourceId: "identity-db",
        catalogSha256: DIGEST_A,
        commitmentKey: Buffer.alloc(32, 0x7b)
      });
      builder.appendPage({
        datasetId: "records",
        datasetRecordCount: records.length,
        datasetPageCount: 1,
        pageNumber: 1,
        requestCursor: null,
        nextCursor: null,
        recordOffset: 0,
        records
      });
      return builder.seal();
    };
    const records = [
      JSON.parse('{"id":1,"__proto__":null}'),
      JSON.parse('{"id":1,"__proto__":"value"}'),
      JSON.parse('{"id":1,"constructor":"value"}'),
      JSON.parse('{"id":1,"prototype":"value"}')
    ] as never[];
    expect(inventoryFor(records).datasets[0]!.recordsCommitment)
      .not.toBe(inventoryFor([...records].reverse()).datasets[0]!.recordsCommitment);

    const cursorBuilder = createOrganizationReconciliationIncrementalDatasetInventoryBuilder({
      componentId: "plugin",
      sourceId: "plugin-db",
      catalogSha256: DIGEST_A,
      commitmentKey: Buffer.alloc(32, 0x7b)
    });
    cursorBuilder.appendPage({
      datasetId: "plugin-registry", datasetRecordCount: 0, datasetPageCount: 2, pageNumber: 1,
      requestCursor: null, nextCursor: "cursor-2", recordOffset: 0, records: []
    });
    expect(() => cursorBuilder.appendPage({
      datasetId: "plugin-registry", datasetRecordCount: 0, datasetPageCount: 2, pageNumber: 2,
      requestCursor: null, nextCursor: null, recordOffset: 0, records: []
    })).toThrow("discontinuous");
    expect(() => cursorBuilder.seal()).toThrow("lifecycle");
  });

  it("enforces exact one-shot lifecycle, private brands, cross-instance rejection, and key cleanup", () => {
    const make = () => createOrganizationReconciliationIncrementalDatasetInventoryBuilder({
      componentId: "plugin", sourceId: "plugin-db", catalogSha256: DIGEST_A,
      commitmentKey: Buffer.alloc(32, 0x6c)
    });
    const first = make();
    const second = make();
    const fill = vi.spyOn(Buffer.prototype, "fill");
    expect(() => first.appendPage.call(second, {
      datasetId: "plugin-registry", datasetRecordCount: 0, datasetPageCount: 1, pageNumber: 1,
      requestCursor: null, nextCursor: null, recordOffset: 0, records: []
    })).toThrow("lifecycle");
    expect(() => first.appendPage.call({ ...first }, {
      datasetId: "plugin-registry", datasetRecordCount: 0, datasetPageCount: 1, pageNumber: 1,
      requestCursor: null, nextCursor: null, recordOffset: 0, records: []
    })).toThrow("invalid");
    expect(() => first.appendPage.call(new Proxy(first, {}), {
      datasetId: "plugin-registry", datasetRecordCount: 0, datasetPageCount: 1, pageNumber: 1,
      requestCursor: null, nextCursor: null, recordOffset: 0, records: []
    })).toThrow("invalid");
    first.appendPage({
      datasetId: "plugin-registry", datasetRecordCount: 0, datasetPageCount: 1, pageNumber: 1,
      requestCursor: null, nextCursor: null, recordOffset: 0, records: []
    });
    expect(first.contract).toBe(ORGANIZATION_RECONCILIATION_INCREMENTAL_DATASET_INVENTORY_BUILDER_CONTRACT);
    expect(first.seal()).toMatchObject({ componentId: "plugin", recordCount: 0 });
    expect(fill).toHaveBeenCalled();
    fill.mockRestore();
    expect(() => first.seal()).toThrow("lifecycle");
    expect(JSON.stringify(first)).not.toContain("6c6c");

    let getterInvoked = false;
    const poisoned = make();
    const records: unknown[] = [];
    Object.defineProperty(records, "0", {
      enumerable: true,
      get: () => { getterInvoked = true; return { id: 1 }; }
    });
    Object.defineProperty(records, "length", { value: 1 });
    expect(() => poisoned.appendPage({
      datasetId: "plugin-registry", datasetRecordCount: 1, datasetPageCount: 1, pageNumber: 1,
      requestCursor: null, nextCursor: null, recordOffset: 0, records: records as never
    })).toThrow("accessor");
    expect(getterInvoked).toBe(false);
    expect(() => poisoned.seal()).toThrow("lifecycle");

    const aborted = make();
    aborted.abort();
    expect(() => aborted.abort()).toThrow("lifecycle");
  });

  it("poisons boundary violations without evaluating proxy content", () => {
    const builder = createOrganizationReconciliationIncrementalDatasetInventoryBuilder({
      componentId: "plugin", sourceId: "plugin-db", catalogSha256: DIGEST_A,
      commitmentKey: Buffer.alloc(32, 0x11)
    });
    let trapInvoked = false;
    const proxyRecord = new Proxy({ id: 1 }, {
      ownKeys: () => { trapInvoked = true; return ["id"]; }
    });
    expect(() => builder.appendPage({
      datasetId: "plugin-registry", datasetRecordCount: 1, datasetPageCount: 10_001,
      pageNumber: 1, requestCursor: null, nextCursor: null, recordOffset: 0,
      records: [proxyRecord] as never
    })).toThrow("page count");
    expect(trapInvoked).toBe(false);
    expect(() => builder.appendPage({
      datasetId: "plugin-registry", datasetRecordCount: 0, datasetPageCount: 1,
      pageNumber: 1, requestCursor: null, nextCursor: null, recordOffset: 0, records: []
    })).toThrow("lifecycle");
  });
});

describe("bounded transaction dataset spool", () => {
  it("uses an unlinked bounded file, matches v2 inventory, and replays one branded page at a time", async () => {
    expect(ORGANIZATION_RECONCILIATION_TRANSACTION_DATASET_SPOOL_READY).toBe(false);
    expect(ORGANIZATION_RECONCILIATION_TRANSACTION_DATASET_SPOOL_IMPLEMENTED).toBe(true);
    expect(organizationReconciliationTransactionDatasetSpoolReadiness()).toEqual({
      ready: false,
      blockers: [
        "named-temp-artifact-create-unlink-crash-window-not-eliminated",
        "spool-at-rest-encryption-not-proven",
        "cross-process-disk-quota-not-enforced",
        "secure-spool-runtime-platform-review-not-complete",
        "subject-universe-projection-factory-not-production-registered",
        "runtime-source-adapter-wiring-disabled"
      ]
    });
    const before = await namedSpoolArtifacts();
    const key = Buffer.alloc(32, 0x44);
    const catalog = testCatalog();
    const spool = await openOrganizationReconciliationTransactionDatasetSpool({
      componentId: "legacy-main", sourceId: "legacy-db", catalogSha256: DIGEST_A,
      datasetCatalog: catalog, commitmentKey: key, subjectUniverse: null
    });
    key.fill(0);
    expect(await namedSpoolArtifacts()).toEqual(before);
    expect(JSON.stringify(spool)).not.toContain("dataset-pages");
    expect(JSON.stringify(spool)).not.toContain("4444");
    await spool.appendPage({
      datasetId: "a", requestCursor: null, nextCursor: "a-2", recordOffset: 0,
      records: [{ id: 1 }, { id: 2 }]
    });
    await spool.appendPage({
      datasetId: "a", requestCursor: "a-2", nextCursor: null, recordOffset: 2,
      records: [{ id: 3 }]
    });
    await spool.appendPage({ datasetId: "b", requestCursor: null, nextCursor: null, recordOffset: 0, records: [] });
    const inventory = await spool.seal();
    const batch = createOrganizationReconciliationComponentDatasetInventory({
      componentId: "legacy-main", sourceId: "legacy-db", catalogSha256: DIGEST_A,
      datasets: [
        { datasetId: "a", pages: [page(null, "a-2", 0, [{ id: 1 }, { id: 2 }]), page("a-2", null, 2, [{ id: 3 }])] },
        { datasetId: "b", pages: [page(null, null, 0, [])] }
      ],
      commitmentKey: Buffer.alloc(32, 0x44)
    });
    expect(inventory).toEqual(batch);

    const a1 = await spool.readPage({ datasetId: "a", requestCursor: null, pageSize: 2 });
    const a2 = await spool.readPage({ datasetId: "a", requestCursor: "a-2", pageSize: 2 });
    expect(Object.isFrozen(a1.records)).toBe(true);
    spool.verifyDatasetReplay({ datasetId: "a", pages: [
      page(a1.requestCursor, a1.nextCursor, a1.recordOffset, a1.records),
      page(a2.requestCursor, a2.nextCursor, a2.recordOffset, a2.records)
    ] });
    const b = await spool.readPage({ datasetId: "b", requestCursor: null, pageSize: 2 });
    spool.verifyDatasetReplay({ datasetId: "b", pages: [
      page(b.requestCursor, b.nextCursor, b.recordOffset, b.records)
    ] });
    await expect(spool.close("completed")).resolves.toBe("completed");
    expect(await namedSpoolArtifacts()).toEqual(before);
  });

  it("rejects partial, oversized, replayed, cloned, and cross-session pages fail-closed", async () => {
    const partial = await makeSpool(0x31);
    await partial.appendPage({ datasetId: "a", requestCursor: null, nextCursor: null, recordOffset: 0, records: [] });
    await expect(partial.seal()).rejects.toThrow("Sealing");
    await expect(partial.close("failed")).resolves.toBe("failed");

    const oversized = await makeSpool(0x32);
    await expect(oversized.appendPage({
      datasetId: "a", requestCursor: null, nextCursor: null, recordOffset: 0,
      records: [{ value: "x".repeat(65_537) }]
    })).rejects.toThrow("Appending");
    await expect(oversized.close("failed")).resolves.toBe("failed");

    const longKey = await makeSpool(0x35);
    let getterInvoked = false;
    const longKeyRecord = Object.create(null) as Record<string, unknown>;
    Object.defineProperty(longKeyRecord, "k".repeat(257), {
      enumerable: true,
      get: () => { getterInvoked = true; return "secret"; }
    });
    await expect(longKey.appendPage({
      datasetId: "a", requestCursor: null, nextCursor: null, recordOffset: 0,
      records: [longKeyRecord as never]
    })).rejects.toThrow("Appending");
    expect(getterInvoked).toBe(false);
    await expect(longKey.close("failed")).resolves.toBe("failed");

    const first = await sealedSinglePageSpool(0x33);
    const second = await sealedSinglePageSpool(0x34);
    const firstPage = await first.readPage({ datasetId: "a", requestCursor: null, pageSize: 2 });
    const secondPage = await second.readPage({ datasetId: "a", requestCursor: null, pageSize: 2 });
    expect(() => first.verifyDatasetReplay({ datasetId: "a", pages: [
      page(null, null, 0, structuredClone(firstPage.records))
    ] })).toThrow("Verifying");
    await expect(first.close("completed")).rejects.toThrow("not consumed");
    await expect(first.close("completed")).rejects.toThrow("not consumed");
    expect(() => second.verifyDatasetReplay({ datasetId: "a", pages: [
      page(null, null, 0, firstPage.records)
    ] })).toThrow("Verifying");
    await expect(second.close("failed")).resolves.toBe("failed");
    expect(secondPage.records).toEqual([]);
  });

  it("merges canonical subject refs in the existing UTF-16 order and emits byte-equivalent structural evidence", async () => {
    const spool = await makeSubjectSpool();
    expect(JSON.stringify(spool)).not.toContain(NONCE);
    await appendSubjectRawPage(spool, null, "next", 0, [2, 10], [
      "legacy-user:2", "legacy-user:10"
    ]);
    await appendSubjectRawPage(spool, "next", null, 2, [1], ["legacy-user:1"]);
    await spool.seal();
    const result = spool.subjectUniverse();
    const expectedRefs = ["legacy-user:2", "legacy-user:10", "legacy-user:1"].sort();
    expect(expectedRefs).toEqual(["legacy-user:1", "legacy-user:10", "legacy-user:2"]);
    expect(result).toEqual({
      count: 3,
      hash: createOrganizationReconciliationEvidenceHash(NONCE, expectedRefs)
    });
    expect(Object.isFrozen(result)).toBe(true);
    expect(JSON.stringify(result)).not.toContain("trust");
    await expect(spool.close("failed")).resolves.toBe("failed");
  });

  it("keeps generic same-count A/B projections structural-only instead of inventing source trust", async () => {
    const first = await makeSubjectSpool({ pageSize: 1, maxPages: 1, maxRecords: 1 });
    const second = await makeSubjectSpool({ pageSize: 1, maxPages: 1, maxRecords: 1 });
    await appendSubjectRawPage(first, null, null, 0, [999], ["legacy-user:1"]);
    await appendSubjectRawPage(second, null, null, 0, [999], ["legacy-user:2"]);
    await first.seal();
    await second.seal();
    expect(first.subjectUniverse()).toMatchObject({ count: 1 });
    expect(second.subjectUniverse()).toMatchObject({ count: 1 });
    expect(first.subjectUniverse().hash).not.toBe(second.subjectUniverse().hash);
    expect(Object.keys(first.subjectUniverse()).sort()).toEqual(["count", "hash"]);
    await Promise.all([first.close("failed"), second.close("failed")]);
  });

  it("rejects missing, empty, malformed, accessor, duplicate, and unbounded subject projections", async () => {
    const missing = await makeSubjectSpool({ pageSize: 1, maxPages: 1, maxRecords: 1 });
    await missing.appendPage({
      datasetId: "legacy-subject-universe", requestCursor: null, nextCursor: null,
      recordOffset: 0, records: [{ legacyUserId: 1 }]
    });
    await expect(missing.seal()).rejects.toThrow("Sealing");
    await expect(missing.close("failed")).resolves.toBe("failed");

    const empty = await makeSubjectSpool({ pageSize: 1, maxPages: 1, maxRecords: 0 });
    await appendSubjectRawPage(empty, null, null, 0, [], []);
    await expect(empty.seal()).rejects.toThrow("Sealing");
    await expect(empty.close("failed")).resolves.toBe("failed");

    const malformed = await makeSubjectSpool({ pageSize: 1, maxPages: 1, maxRecords: 1 });
    await malformed.appendPage({
      datasetId: "legacy-subject-universe", requestCursor: null, nextCursor: null,
      recordOffset: 0, records: [{ legacyUserId: 1 }]
    });
    await expect(malformed.appendSubjectUniversePage({
      datasetId: "legacy-subject-universe", recordOffset: 0, subjectRefs: ["legacy-user:01"]
    })).rejects.toThrow("Appending bounded");
    await expect(malformed.close("failed")).resolves.toBe("failed");

    const accessor = await makeSubjectSpool({ pageSize: 1, maxPages: 1, maxRecords: 1 });
    await accessor.appendPage({
      datasetId: "legacy-subject-universe", requestCursor: null, nextCursor: null,
      recordOffset: 0, records: [{ legacyUserId: 1 }]
    });
    let getterInvoked = false;
    const refs: string[] = [];
    Object.defineProperty(refs, "0", {
      enumerable: true, configurable: true, get: () => { getterInvoked = true; return "legacy-user:1"; }
    });
    Object.defineProperty(refs, "length", { value: 1 });
    await expect(accessor.appendSubjectUniversePage({
      datasetId: "legacy-subject-universe", recordOffset: 0, subjectRefs: refs
    })).rejects.toThrow("Appending bounded");
    expect(getterInvoked).toBe(false);
    await expect(accessor.close("failed")).resolves.toBe("failed");

    const duplicate = await makeSubjectSpool();
    await appendSubjectRawPage(duplicate, null, "next", 0, [1, 2], ["legacy-user:1", "legacy-user:2"]);
    await appendSubjectRawPage(duplicate, "next", null, 2, [2], ["legacy-user:2"]);
    await expect(duplicate.seal()).rejects.toThrow("Sealing");
    await expect(duplicate.close("failed")).resolves.toBe("failed");

    const unbounded = await makeSubjectSpool({ pageSize: 40, maxPages: 1, maxRecords: 40 });
    const ids = Array.from({ length: 33 }, (_, index) => index + 1);
    const oversizedRefs = ids.map((id) => `legacy-user:${"9".repeat(65_500)}${String(id).padStart(2, "0")}`);
    await unbounded.appendPage({
      datasetId: "legacy-subject-universe", requestCursor: null, nextCursor: null,
      recordOffset: 0, records: ids.map((legacyUserId) => ({ legacyUserId }))
    });
    await expect(unbounded.appendSubjectUniversePage({
      datasetId: "legacy-subject-universe", recordOffset: 0, subjectRefs: oversizedRefs
    })).rejects.toThrow("Appending bounded");
    await expect(unbounded.close("failed")).resolves.toBe("failed");
  });

  it("rejects cross-component subject bindings and exposes no sidecar result when disabled", async () => {
    await expect(openOrganizationReconciliationTransactionDatasetSpool({
      componentId: "legacy-main", sourceId: "legacy-db", catalogSha256: DIGEST_A,
      datasetCatalog: subjectCatalog("identity-subject-universe", 1, 1, 1),
      commitmentKey: Buffer.alloc(32, 0x71),
      subjectUniverse: { datasetId: "identity-subject-universe", evidenceNonce: NONCE }
    })).rejects.toThrow("component-bound");

    const disabled = await sealedSinglePageSpool(0x72);
    expect(() => disabled.subjectUniverse()).toThrow("unavailable");
    await expect(disabled.close("failed")).resolves.toBe("failed");
  });

  it("enforces the process-global active spool bound and releases it on every close", async () => {
    const spools = await Promise.all([makeSpool(0x51), makeSpool(0x52), makeSpool(0x53)]);
    await expect(makeSpool(0x54)).rejects.toThrow("budget");
    await Promise.all(spools.map((spool) => spool.close("failed")));
    const after = await makeSpool(0x55);
    await expect(after.close("failed")).resolves.toBe("failed");
  });

  it("claims async operations before I/O and waits for the unique close before releasing capacity", async () => {
    const writeStarted = deferred();
    const releaseWrite = deferred();
    const syncStarted = deferred();
    const releaseSync = deferred();
    const readStarted = deferred();
    const releaseRead = deferred();
    const closeStarted = deferred();
    const releaseClose = deferred();
    const opened: OrganizationReconciliationTransactionDatasetSpool[] = [];
    let gateRead = false;
    vi.resetModules();
    vi.doMock("node:fs/promises", async () => {
      const actual = await vi.importActual<typeof import("node:fs/promises")>("node:fs/promises");
      let handleCount = 0;
      let writeBlocked = false;
      let readBlocked = false;
      return {
        ...actual,
        open: async (...args: Parameters<typeof actual.open>) => {
          const handle = await actual.open(...args);
          handleCount += 1;
          if (handleCount !== 1) return handle;
          const originalWrite = handle.write.bind(handle);
          const originalRead = handle.read.bind(handle);
          const originalSync = handle.sync.bind(handle);
          const originalClose = handle.close.bind(handle);
          Object.defineProperties(handle, {
            write: {
              configurable: true,
              value: async (...values: Parameters<typeof handle.write>) => {
                if (!writeBlocked) {
                  writeBlocked = true;
                  writeStarted.resolve();
                  await releaseWrite.promise;
                }
                return originalWrite(...values);
              }
            },
            read: {
              configurable: true,
              value: async (...values: Parameters<typeof handle.read>) => {
                if (gateRead && !readBlocked) {
                  readBlocked = true;
                  readStarted.resolve();
                  await releaseRead.promise;
                }
                return originalRead(...values);
              }
            },
            sync: {
              configurable: true,
              value: async () => {
                syncStarted.resolve();
                await releaseSync.promise;
                return originalSync();
              }
            },
            close: {
              configurable: true,
              value: async () => {
                closeStarted.resolve();
                await releaseClose.promise;
                return originalClose();
              }
            }
          });
          return handle;
        }
      };
    });
    try {
      const module = await import("../src/iam-organization-reconciliation-transaction-dataset-spool.js");
      const openBounded = async () => {
        const spool = await module.openOrganizationReconciliationTransactionDatasetSpool({
          componentId: "legacy-main", sourceId: "legacy-db", catalogSha256: DIGEST_A,
          datasetCatalog: testCatalog(), commitmentKey: Buffer.alloc(32, 0x74), subjectUniverse: null
        });
        opened.push(spool);
        return spool;
      };
      const target = await openBounded();
      const firstAppend = target.appendPage({
        datasetId: "a", requestCursor: null, nextCursor: null, recordOffset: 0, records: []
      });
      await writeStarted.promise;
      await expect(target.appendPage({
        datasetId: "a", requestCursor: null, nextCursor: null, recordOffset: 0, records: []
      })).rejects.toThrow("lifecycle");
      releaseWrite.resolve();
      await firstAppend;
      await target.appendPage({
        datasetId: "b", requestCursor: null, nextCursor: null, recordOffset: 0, records: []
      });

      const firstSeal = target.seal();
      await syncStarted.promise;
      await expect(target.seal()).rejects.toThrow("lifecycle");
      releaseSync.resolve();
      await firstSeal;

      gateRead = true;
      const firstRead = target.readPage({ datasetId: "a", requestCursor: null, pageSize: 2 });
      await readStarted.promise;
      await expect(target.readPage({ datasetId: "a", requestCursor: null, pageSize: 2 }))
        .rejects.toThrow("lifecycle");
      let closeSettled = false;
      const targetClose = target.close("failed").then((value) => {
        closeSettled = true;
        return value;
      });
      await Promise.resolve();
      expect(closeSettled).toBe(false);
      releaseRead.resolve();
      await firstRead;
      await closeStarted.promise;
      expect(closeSettled).toBe(false);

      const second = await openBounded();
      const third = await openBounded();
      await expect(openBounded()).rejects.toThrow("budget");
      expect(closeSettled).toBe(false);
      releaseClose.resolve();
      await expect(targetClose).resolves.toBe("failed");
      const replacement = await openBounded();
      await Promise.all([second.close("failed"), third.close("failed"), replacement.close("failed")]);
    } finally {
      releaseWrite.resolve();
      releaseSync.resolve();
      releaseRead.resolve();
      releaseClose.resolve();
      await Promise.all(opened.map((spool) => spool.close("failed").catch(() => "failed" as const)));
      vi.doUnmock("node:fs/promises");
      vi.resetModules();
    }
  });

  it("fails closed on zero-write, truncated-read, cleanup failure, and path TOCTOU", async () => {
    for (const fault of ["write", "read", "close", "toctou", "directory-mode", "file-mode"] as const) {
      await exerciseFileFault(fault);
    }
  });
});

function deferred(): { readonly promise: Promise<void>; resolve(): void } {
  let resolve!: () => void;
  const promise = new Promise<void>((accepted) => { resolve = accepted; });
  return Object.freeze({ promise, resolve });
}

function page(
  requestCursor: string | null,
  nextCursor: string | null,
  recordOffset: number,
  records: readonly OrganizationReconciliationInventoryJsonValue[]
): OrganizationReconciliationDatasetInventoryPageInput {
  return { requestCursor, nextCursor, recordOffset, records };
}

function appendDataset(
  builder: OrganizationReconciliationIncrementalDatasetInventoryBuilder,
  dataset: { readonly datasetId: string; readonly pages: readonly OrganizationReconciliationDatasetInventoryPageInput[] }
): void {
  const datasetRecordCount = dataset.pages.reduce((sum, candidate) => sum + candidate.records.length, 0);
  for (let index = 0; index < dataset.pages.length; index += 1) {
    const candidate = dataset.pages[index]!;
    builder.appendPage({
      datasetId: dataset.datasetId,
      datasetRecordCount,
      datasetPageCount: dataset.pages.length,
      pageNumber: index + 1,
      requestCursor: candidate.requestCursor,
      nextCursor: candidate.nextCursor,
      recordOffset: candidate.recordOffset,
      records: candidate.records
    });
  }
}

function testCatalog(): OrganizationReconciliationDatasetCatalog {
  return Object.freeze({
    contract: ORGANIZATION_RECONCILIATION_DATASET_LINEAGE_CONTRACT,
    trust: ORGANIZATION_RECONCILIATION_DATASET_CATALOG_TRUST,
    datasets: Object.freeze([
      Object.freeze({ datasetId: "a", pageSize: 2, maxPages: 2, maxRecords: 3 }),
      Object.freeze({ datasetId: "b", pageSize: 2, maxPages: 1, maxRecords: 0 })
    ])
  });
}

function subjectCatalog(
  datasetId = "legacy-subject-universe",
  pageSize = 2,
  maxPages = 2,
  maxRecords = 3
): OrganizationReconciliationDatasetCatalog {
  return Object.freeze({
    contract: ORGANIZATION_RECONCILIATION_DATASET_LINEAGE_CONTRACT,
    trust: ORGANIZATION_RECONCILIATION_DATASET_CATALOG_TRUST,
    datasets: Object.freeze([
      Object.freeze({ datasetId, pageSize, maxPages, maxRecords })
    ])
  });
}

function makeSubjectSpool(bounds: {
  readonly pageSize: number;
  readonly maxPages: number;
  readonly maxRecords: number;
} = { pageSize: 2, maxPages: 2, maxRecords: 3 }): Promise<OrganizationReconciliationTransactionDatasetSpool> {
  return openOrganizationReconciliationTransactionDatasetSpool({
    componentId: "legacy-main",
    sourceId: "legacy-db",
    catalogSha256: DIGEST_A,
    datasetCatalog: subjectCatalog(
      "legacy-subject-universe", bounds.pageSize, bounds.maxPages, bounds.maxRecords
    ),
    commitmentKey: Buffer.alloc(32, 0x73),
    subjectUniverse: { datasetId: "legacy-subject-universe", evidenceNonce: NONCE }
  });
}

async function appendSubjectRawPage(
  spool: OrganizationReconciliationTransactionDatasetSpool,
  requestCursor: string | null,
  nextCursor: string | null,
  recordOffset: number,
  legacyUserIds: readonly number[],
  subjectRefs: readonly string[]
): Promise<void> {
  await spool.appendPage({
    datasetId: "legacy-subject-universe",
    requestCursor,
    nextCursor,
    recordOffset,
    records: legacyUserIds.map((legacyUserId) => ({ legacyUserId }))
  });
  await spool.appendSubjectUniversePage({
    datasetId: "legacy-subject-universe",
    recordOffset,
    subjectRefs
  });
}

function makeSpool(keyByte: number): Promise<OrganizationReconciliationTransactionDatasetSpool> {
  return openOrganizationReconciliationTransactionDatasetSpool({
    componentId: "legacy-main", sourceId: "legacy-db", catalogSha256: DIGEST_A,
    datasetCatalog: testCatalog(), commitmentKey: Buffer.alloc(32, keyByte), subjectUniverse: null
  });
}

async function sealedSinglePageSpool(keyByte: number): Promise<OrganizationReconciliationTransactionDatasetSpool> {
  const spool = await makeSpool(keyByte);
  await spool.appendPage({ datasetId: "a", requestCursor: null, nextCursor: null, recordOffset: 0, records: [] });
  await spool.appendPage({ datasetId: "b", requestCursor: null, nextCursor: null, recordOffset: 0, records: [] });
  await spool.seal();
  return spool;
}

async function namedSpoolArtifacts(): Promise<readonly string[]> {
  const root = await realpath(tmpdir());
  const prefix = `iam-organization-reconciliation-spool-${process.pid}-`;
  return (await readdir(root)).filter((name) => name.startsWith(prefix)).sort();
}

async function exerciseFileFault(
  fault: "write" | "read" | "close" | "toctou" | "directory-mode" | "file-mode"
): Promise<void> {
  const before = await namedSpoolArtifacts();
  vi.resetModules();
  vi.doMock("node:fs/promises", async () => {
    const actual = await vi.importActual<typeof import("node:fs/promises")>("node:fs/promises");
    let lstatCount = 0;
    let closeInjected = false;
    return {
      ...actual,
      lstat: async (...args: Parameters<typeof actual.lstat>) => {
        const stat = await (actual.lstat as (...values: typeof args) => ReturnType<typeof actual.lstat>)(...args);
        lstatCount += 1;
        const override = fault === "toctou" && lstatCount === 2 ? "ino" :
          fault === "directory-mode" && lstatCount === 1 ? "directory-mode" :
          fault === "file-mode" && lstatCount === 3 ? "file-mode" : null;
        if (override === null) return stat;
        return new Proxy(stat, {
          get(target, property) {
            if (property === "ino" && override === "ino") {
              return typeof target.ino === "bigint" ? target.ino + 1n : target.ino + 1;
            }
            if (property === "mode" && override === "directory-mode") return 0o040710;
            if (property === "mode" && override === "file-mode") return 0o100640;
            const value = Reflect.get(target, property, target);
            return typeof value === "function" ? value.bind(target) : value;
          }
        });
      },
      open: async (...args: Parameters<typeof actual.open>) => {
        const handle = await actual.open(...args);
        if (fault === "write") {
          Object.defineProperty(handle, "write", {
            value: async () => ({ bytesWritten: 0, buffer: Buffer.alloc(0) }), configurable: true
          });
        }
        if (fault === "read") {
          Object.defineProperty(handle, "read", {
            value: async () => ({ bytesRead: 0, buffer: Buffer.alloc(0) }), configurable: true
          });
        }
        if (fault === "close") {
          const close = handle.close.bind(handle);
          Object.defineProperty(handle, "close", {
            value: async () => {
              await close();
              if (!closeInjected) {
                closeInjected = true;
                throw new Error("injected close failure");
              }
            },
            configurable: true
          });
        }
        return handle;
      }
    };
  });
  try {
    const module = await import("../src/iam-organization-reconciliation-transaction-dataset-spool.js");
    const openFaulted = () => module.openOrganizationReconciliationTransactionDatasetSpool({
      componentId: "legacy-main", sourceId: "legacy-db", catalogSha256: DIGEST_A,
      datasetCatalog: testCatalog(), commitmentKey: Buffer.alloc(32, 0x61), subjectUniverse: null
    });
    if (fault === "toctou" || fault === "directory-mode" || fault === "file-mode") {
      await expect(openFaulted()).rejects.toThrow("Opening");
      const replacement = await openFaulted();
      await expect(replacement.close("failed")).resolves.toBe("failed");
    } else {
      const spool = await openFaulted();
      if (fault === "write") {
        await expect(spool.appendPage({
          datasetId: "a", requestCursor: null, nextCursor: null, recordOffset: 0, records: []
        })).rejects.toThrow("Appending");
      } else if (fault === "read") {
        await spool.appendPage({ datasetId: "a", requestCursor: null, nextCursor: null, recordOffset: 0, records: [] });
        await spool.appendPage({ datasetId: "b", requestCursor: null, nextCursor: null, recordOffset: 0, records: [] });
        await expect(spool.seal()).rejects.toThrow("Sealing");
      } else {
        await expect(spool.close("failed")).rejects.toThrow("Closing");
      }
      await spool.close("failed").catch(() => undefined);
      const replacement = await openFaulted();
      await replacement.close("failed").catch(() => undefined);
    }
    expect(await namedSpoolArtifacts()).toEqual(before);
  } finally {
    vi.doUnmock("node:fs/promises");
    vi.resetModules();
  }
}
