import { describe, expect, it, vi } from "vitest";
import {
  createOrganizationReconciliationComponentDatasetInventory,
  validateOrganizationReconciliationComponentDatasetInventory
} from "../src/iam-organization-reconciliation-dataset-inventory.js";
import {
  collectOrganizationReconciliationDatasetLineage,
  ORGANIZATION_RECONCILIATION_DATASET_CATALOG_TRUST,
  ORGANIZATION_RECONCILIATION_DATASET_LINEAGE_CONTRACT,
  type OrganizationReconciliationDatasetCatalog
} from "../src/iam-organization-reconciliation-dataset-lineage.js";
import {
  createOrganizationReconciliationMysqlTransactionDatasetAdapter,
  ORGANIZATION_RECONCILIATION_MYSQL_TRANSACTION_DATASET_ADAPTER_READY,
  organizationReconciliationMysqlTransactionDatasetAdapterReadiness
} from "../src/iam-organization-reconciliation/mysql-source-adapters/transaction-dataset-adapter.js";
import {
  ORGANIZATION_RECONCILIATION_MYSQL_STATEMENTS,
  type MysqlRepeatableReadSnapshotConnection,
  type OrganizationReconciliationMysqlStatementId
} from "../src/iam-organization-reconciliation/mysql-repeatable-read-snapshot.js";

const DIGEST_A = "a".repeat(64);
const DIGEST_B = "b".repeat(64);
const DIGEST_C = "c".repeat(64);
const NONCE = "0123456789abcdef0123456789abcdef";

describe("transaction-owned organization reconciliation dataset adapter", () => {
  it("canonicalizes and rejects tampered per-page inventory lineage", () => {
    const commitmentKey = Buffer.alloc(32, 0xab);
    const inventory = createOrganizationReconciliationComponentDatasetInventory({
      componentId: "legacy-main",
      sourceId: "legacy-db",
      catalogSha256: DIGEST_A,
      datasets: [{
        datasetId: "subjects",
        pages: [
        { requestCursor: null, nextCursor: "cursor-2", recordOffset: 0, records: [{ id: "1" }] },
        { requestCursor: "cursor-2", nextCursor: null, recordOffset: 1, records: [{ id: "2" }] }
        ]
      }],
      commitmentKey
    });
    expect(validateOrganizationReconciliationComponentDatasetInventory(inventory)).toEqual(inventory);
    expect(inventory).toMatchObject({ recordCount: 2, datasets: [{ pageCount: 2, recordCount: 2 }] });

    const tampered = structuredClone(inventory);
    (tampered.datasets[0]!.pages[1]! as { requestCursorCommitment: string | null }).requestCursorCommitment = DIGEST_B;
    expect(() => validateOrganizationReconciliationComponentDatasetInventory(tampered))
      .toThrow("discontinuous");

    const commitmentFor = (record: unknown, keyByte = 0xab) =>
      createOrganizationReconciliationComponentDatasetInventory({
        componentId: "legacy-main", sourceId: "legacy-db", catalogSha256: DIGEST_A,
        datasets: [{ datasetId: "subjects", pages: [{
          requestCursor: null, nextCursor: null, recordOffset: 0, records: [record] as never
        }] }],
        commitmentKey: Buffer.alloc(32, keyByte)
      });
    const protoCommitments = [
      { id: 1 },
      JSON.parse('{"id":1,"__proto__":null}'),
      JSON.parse('{"id":1,"__proto__":"x"}'),
      JSON.parse('{"id":1,"__proto__":7}'),
      JSON.parse('{"id":1,"constructor":"x"}'),
      JSON.parse('{"id":1,"prototype":"x"}')
    ].map((record) => commitmentFor(record).datasets[0]!.recordsCommitment);
    expect(new Set(protoCommitments).size).toBe(protoCommitments.length);
    expect(commitmentFor(null).datasets[0]!.recordsCommitment)
      .not.toBe(commitmentFor("null").datasets[0]!.recordsCommitment);
    expect(commitmentFor({ id: 1 }, 0xac).datasets[0]!.recordsCommitment)
      .not.toBe(commitmentFor({ id: 1 }, 0xab).datasets[0]!.recordsCommitment);
    const callerKey = Buffer.alloc(32, 0xcd);
    const captured = createOrganizationReconciliationComponentDatasetInventory({
      componentId: "legacy-main", sourceId: "legacy-db", catalogSha256: DIGEST_A,
      datasets: [{ datasetId: "subjects", pages: [{
        requestCursor: null, nextCursor: null, recordOffset: 0, records: [{ id: 1 }]
      }] }],
      commitmentKey: callerKey
    });
    const serialized = JSON.stringify(captured);
    callerKey.fill(0);
    expect(JSON.stringify(captured)).toBe(serialized);
    expect(serialized).not.toContain("commitmentKey");

    expect(() => createOrganizationReconciliationComponentDatasetInventory({
      componentId: "legacy-main", sourceId: "legacy-db", catalogSha256: DIGEST_A,
      datasets: [
        { datasetId: "a", pages: Array(5_001).fill({}) },
        { datasetId: "b", pages: Array(5_001).fill({}) }
      ] as never,
      commitmentKey: Buffer.alloc(32, 1)
    })).toThrow("aggregate page bound");
    expect(() => createOrganizationReconciliationComponentDatasetInventory({
      componentId: "legacy-main", sourceId: "legacy-db", catalogSha256: DIGEST_A,
      datasets: [{ datasetId: "mémbership", pages: [] }] as never,
      commitmentKey: Buffer.alloc(32, 1)
    })).toThrow("dataset ID");
    let recordGetterInvoked = false;
    const getterRecords: unknown[] = [];
    Object.defineProperty(getterRecords, "0", {
      enumerable: true,
      get: () => { recordGetterInvoked = true; return { id: 1 }; }
    });
    Object.defineProperty(getterRecords, "length", { value: 1 });
    expect(() => createOrganizationReconciliationComponentDatasetInventory({
      componentId: "legacy-main", sourceId: "legacy-db", catalogSha256: DIGEST_A,
      datasets: [{ datasetId: "subjects", pages: [{
        requestCursor: null, nextCursor: null, recordOffset: 0, records: getterRecords as never
      }] }],
      commitmentKey: Buffer.alloc(32, 1)
    })).toThrow("accessor");
    expect(recordGetterInvoked).toBe(false);
  });

  it("pre-scans all three fixed raw sources inside their transactions and replays them into lineage", async () => {
    expect(ORGANIZATION_RECONCILIATION_MYSQL_TRANSACTION_DATASET_ADAPTER_READY).toBe(false);
    expect(organizationReconciliationMysqlTransactionDatasetAdapterReadiness()).toEqual({
      ready: false,
      blockers: [
        "compiled-owner-dataset-catalog-not-registered",
        "trusted-physical-source-binding-not-registered",
        "identity-source-status-semantics-not-owner-approved",
        "identity-shadow-versus-candidate-read-model-not-owner-approved",
        "plugin-registry-and-static-overlay-contract-not-owner-approved",
        "mysql-collation-and-unique-order-contract-not-owner-approved",
        "bounded-transaction-spool-not-production-ready",
        "operation-evidence-projector-not-production-registered",
        "bounded-streaming-projector-not-implemented",
        "compiled-reconciliation-pipeline-not-registered",
        "runtime-source-adapter-wiring-disabled"
      ]
    });
    const legacy = fakeConnection(legacyRows());
    const identity = fakeConnection(identityRows());
    const plugin = fakeConnection(pluginRows());
    const legacyCatalog = catalog([
      "legacy-membership", "legacy-organization-directory", "legacy-role-assignment", "legacy-subject-universe"
    ]);
    const identityCatalog = catalog([
      "identity-membership-candidate", "identity-membership-shadow", "identity-organization-candidate",
      "identity-organization-id-map", "identity-role-shadow", "identity-subject-universe"
    ]);
    const pluginCatalog = catalog(["plugin-registry"]);
    const adapters = [
      createOrganizationReconciliationMysqlTransactionDatasetAdapter({
        componentId: "legacy-main", expectedSourceId: "legacy-db", connectionFactory: legacy.factory,
        evidenceNonce: NONCE, catalogSha256: DIGEST_A, datasetCatalog: legacyCatalog
      }),
      createOrganizationReconciliationMysqlTransactionDatasetAdapter({
        componentId: "identity", expectedSourceId: "identity-db", connectionFactory: identity.factory,
        evidenceNonce: NONCE, catalogSha256: DIGEST_B, datasetCatalog: identityCatalog
      }),
      createOrganizationReconciliationMysqlTransactionDatasetAdapter({
        componentId: "plugin", expectedSourceId: "plugin-db", connectionFactory: plugin.factory,
        evidenceNonce: NONCE, catalogSha256: DIGEST_C, datasetCatalog: pluginCatalog
      })
    ] as const;
    let tick = 0;
    const run = await collectOrganizationReconciliationDatasetLineage({
      components: [
        binding("legacy-main", "legacy-db", DIGEST_A, legacyCatalog, adapters[0]),
        binding("identity", "identity-db", DIGEST_B, identityCatalog, adapters[1]),
        binding("plugin", "plugin-db", DIGEST_C, pluginCatalog, adapters[2])
      ],
      maxWindowMilliseconds: 1_000,
      clock: { now: () => new Date(Date.UTC(2026, 7, 9, 8, 0, 0, tick++)) }
    });

    expect(run.artifacts).toHaveLength(11);
    expect(run.artifacts.map((artifact) => artifact.datasetId)).toEqual([
      "legacy-membership", "legacy-organization-directory", "legacy-role-assignment", "legacy-subject-universe",
      "identity-membership-candidate", "identity-membership-shadow", "identity-organization-candidate",
      "identity-organization-id-map", "identity-role-shadow", "identity-subject-universe", "plugin-registry"
    ]);
    expect(run.coordinatorManifest.components.map((component) => component.recordCount)).toEqual([4, 6, 1]);
    for (const fake of [legacy, identity, plugin]) {
      expect(fake.sql.at(-1)).toBe("COMMIT");
      expect(fake.release).toHaveBeenCalledTimes(1);
    }
  });

  it("derives repeatable public versions from content, rejects caller metadata, and rolls back incomplete replay", async () => {
    const first = fakeConnection(legacyRows());
    const second = fakeConnection(legacyRows());
    const third = fakeConnection(legacyRows());
    const legacyCatalog = catalog([
      "legacy-membership", "legacy-organization-directory", "legacy-role-assignment", "legacy-subject-universe"
    ]);
    const create = (fake: ReturnType<typeof fakeConnection>) =>
      createOrganizationReconciliationMysqlTransactionDatasetAdapter({
        componentId: "legacy-main", expectedSourceId: "legacy-db", connectionFactory: fake.factory,
        evidenceNonce: NONCE, catalogSha256: DIGEST_A, datasetCatalog: legacyCatalog
      });
    const firstAdapter = create(first);
    const firstSnapshot = await firstAdapter.openSnapshot();
    expect(firstSnapshot.sourceVersion).toMatch(/^[a-f0-9]{64}$/);
    expect(firstSnapshot.snapshotId).toMatch(/^[a-f0-9]{64}$/);
    expect(firstSnapshot.datasetInventory).toMatchObject({ recordCount: 4, catalogSha256: DIGEST_A });
    const partialClose = firstAdapter.closeSnapshot(firstSnapshot, "completed");
    await expect(partialClose)
      .rejects.toThrow("not consumed completely");
    expect(first.sql.at(-1)).toBe("ROLLBACK");

    const secondAdapter = create(second);
    const secondSnapshot = await secondAdapter.openSnapshot();
    expect(secondSnapshot.sourceVersion).not.toBe(firstSnapshot.sourceVersion);
    expect(secondSnapshot.snapshotId).not.toBe(firstSnapshot.snapshotId);
    const failedClose = secondAdapter.closeSnapshot(secondSnapshot, "failed");
    await failedClose;

    const thirdAdapter = create(third);
    const thirdSnapshot = await thirdAdapter.openSnapshot();
    const invalidClose = thirdAdapter.closeSnapshot(thirdSnapshot, "invalid" as never);
    await expect(invalidClose)
      .rejects.toThrow("close outcome is invalid");
    expect(third.sql.at(-1)).toBe("ROLLBACK");

    const connectionFactory = vi.fn(async () => fakeConnection(legacyRows()).connection);
    expect(() => createOrganizationReconciliationMysqlTransactionDatasetAdapter({
      componentId: "legacy-main", expectedSourceId: "legacy-db", connectionFactory,
      evidenceNonce: NONCE, catalogSha256: DIGEST_A, datasetCatalog: legacyCatalog,
      sourceVersion: "caller-forged"
    } as never)).toThrow("unknown fields");
    expect(connectionFactory).not.toHaveBeenCalled();

    const unboundedCatalog: OrganizationReconciliationDatasetCatalog = {
      ...catalog([
        "legacy-membership", "legacy-organization-directory", "legacy-role-assignment", "legacy-subject-universe"
      ]),
      datasets: catalog([
        "legacy-membership", "legacy-organization-directory", "legacy-role-assignment", "legacy-subject-universe"
      ]).datasets.map((dataset) => ({ ...dataset, maxPages: 3_000 }))
    };
    expect(() => createOrganizationReconciliationMysqlTransactionDatasetAdapter({
      componentId: "legacy-main", expectedSourceId: "legacy-db", connectionFactory,
      evidenceNonce: NONCE, catalogSha256: DIGEST_A, datasetCatalog: unboundedCatalog
    })).toThrow("aggregate component bound");
    expect(connectionFactory).not.toHaveBeenCalled();
  });

  it("claims opening synchronously and releases the claim after an open failure", async () => {
    const first = fakeConnection(legacyRows());
    let releaseConnection!: () => void;
    const connectionGate = new Promise<void>((resolve) => { releaseConnection = resolve; });
    const delayedFactory = vi.fn(async () => {
      await connectionGate;
      return first.connection;
    });
    const legacyCatalog = catalog([
      "legacy-membership", "legacy-organization-directory", "legacy-role-assignment", "legacy-subject-universe"
    ]);
    const adapter = createOrganizationReconciliationMysqlTransactionDatasetAdapter({
      componentId: "legacy-main", expectedSourceId: "legacy-db", connectionFactory: delayedFactory,
      evidenceNonce: NONCE, catalogSha256: DIGEST_A, datasetCatalog: legacyCatalog
    });

    const firstOpen = adapter.openSnapshot();
    expect(delayedFactory).toHaveBeenCalledTimes(1);
    await expect(adapter.openSnapshot()).rejects.toThrow("already open");
    expect(delayedFactory).toHaveBeenCalledTimes(1);
    releaseConnection();
    const snapshot = await firstOpen;
    await adapter.closeSnapshot(snapshot, "failed");

    const recovered = fakeConnection(legacyRows());
    const recoveringFactory = vi.fn()
      .mockRejectedValueOnce(new Error("connection failed"))
      .mockResolvedValueOnce(recovered.connection);
    const recoveringAdapter = createOrganizationReconciliationMysqlTransactionDatasetAdapter({
      componentId: "legacy-main", expectedSourceId: "legacy-db", connectionFactory: recoveringFactory,
      evidenceNonce: NONCE, catalogSha256: DIGEST_A, datasetCatalog: legacyCatalog
    });
    await expect(recoveringAdapter.openSnapshot()).rejects.toThrow("inventory failed");
    const recoveredSnapshot = await recoveringAdapter.openSnapshot();
    await recoveringAdapter.closeSnapshot(recoveredSnapshot, "failed");
    expect(recoveringFactory).toHaveBeenCalledTimes(2);
  });

  it("clears the factory key on scan failure and still surfaces raw-close failures", async () => {
    const legacyCatalog = catalog([
      "legacy-membership", "legacy-organization-directory", "legacy-role-assignment", "legacy-subject-universe"
    ]);
    const invalidRows = legacyRows();
    invalidRows["legacy-membership-page/v1"] = [[{ user_id: 0, organization_id: 1 }]];
    const scanFake = fakeConnection(invalidRows);
    const scanAdapter = createOrganizationReconciliationMysqlTransactionDatasetAdapter({
      componentId: "legacy-main", expectedSourceId: "legacy-db", connectionFactory: scanFake.factory,
      evidenceNonce: NONCE, catalogSha256: DIGEST_A, datasetCatalog: legacyCatalog
    });
    const scanFill = vi.spyOn(Buffer.prototype, "fill");
    await expect(scanAdapter.openSnapshot()).rejects.toThrow("inventory failed");
    expect(scanFill).toHaveBeenCalled();
    scanFill.mockRestore();

    const closeFake = fakeConnection(legacyRows());
    const originalQuery = closeFake.connection.query.bind(closeFake.connection);
    closeFake.connection.query = async (statement, parameters) => {
      if (statement === "ROLLBACK") throw new Error("raw close failed");
      return originalQuery(statement, parameters);
    };
    const closeAdapter = createOrganizationReconciliationMysqlTransactionDatasetAdapter({
      componentId: "legacy-main", expectedSourceId: "legacy-db", connectionFactory: closeFake.factory,
      evidenceNonce: NONCE, catalogSha256: DIGEST_A, datasetCatalog: legacyCatalog
    });
    const snapshot = await closeAdapter.openSnapshot();
    const closePromise = closeAdapter.closeSnapshot(snapshot, "failed");
    await expect(closePromise).rejects.toThrow("Closing the materialized transaction snapshot failed");
  });

  it("poisons every active snapshot on verifier misuse without retaining an adapter run key", async () => {
    const legacyCatalog = catalog([
      "legacy-membership", "legacy-organization-directory", "legacy-role-assignment", "legacy-subject-universe"
    ]);
    for (const mode of [
      "before-exhaust", "wrong-snapshot", "unknown-dataset", "tampered-record", "tampered-cursor", "twice"
    ] as const) {
      const fake = fakeConnection(legacyRows());
      const adapter = createOrganizationReconciliationMysqlTransactionDatasetAdapter({
        componentId: "legacy-main", expectedSourceId: "legacy-db", connectionFactory: fake.factory,
        evidenceNonce: NONCE, catalogSha256: DIGEST_A, datasetCatalog: legacyCatalog
      });
      const snapshot = await adapter.openSnapshot();
      const spec = legacyCatalog.datasets[0]!;
      const pages = mode === "before-exhaust" ? [] : await exhaustDataset(adapter, snapshot, spec);
      if (mode === "twice") {
        adapter.verifySnapshotDatasetReplay({ snapshot, datasetId: spec.datasetId, pages });
      }
      const candidatePages = structuredClone(pages);
      if (mode === "tampered-record") {
        const record = { ...(candidatePages[0]!.records[0] as Record<string, unknown>) };
        Object.defineProperty(record, "__proto__", { value: null, enumerable: true });
        (candidatePages[0] as unknown as { records: unknown[] }).records = [record];
      }
      if (mode === "tampered-cursor") {
        (candidatePages[0] as { requestCursor: string | null }).requestCursor = "forged-cursor";
      }
      expect(() => adapter.verifySnapshotDatasetReplay({
        snapshot: mode === "wrong-snapshot" ? { ...snapshot } : snapshot,
        datasetId: mode === "unknown-dataset" ? "unknown-dataset" : spec.datasetId,
        pages: candidatePages
      })).toThrow("transaction-owned commitment");
      await expect(adapter.readSnapshotPage({
        snapshot, datasetId: legacyCatalog.datasets[1]!.datasetId, requestCursor: null,
        pageSize: legacyCatalog.datasets[1]!.pageSize
      })).rejects.toThrow("poisoned");
      expect(() => adapter.verifySnapshotDatasetReplay({ snapshot, datasetId: spec.datasetId, pages }))
        .toThrow("transaction-owned commitment");
      await expect(adapter.closeSnapshot(snapshot, "completed")).rejects.toThrow("not consumed completely");
      expect(fake.sql.at(-1)).toBe("ROLLBACK");
    }
  });

  it("rolls back when one fixed dataset is omitted from the verified full set", async () => {
    const fake = fakeConnection(legacyRows());
    const legacyCatalog = catalog([
      "legacy-membership", "legacy-organization-directory", "legacy-role-assignment", "legacy-subject-universe"
    ]);
    const adapter = createOrganizationReconciliationMysqlTransactionDatasetAdapter({
      componentId: "legacy-main", expectedSourceId: "legacy-db", connectionFactory: fake.factory,
      evidenceNonce: NONCE, catalogSha256: DIGEST_A, datasetCatalog: legacyCatalog
    });
    const snapshot = await adapter.openSnapshot();
    for (const spec of legacyCatalog.datasets.slice(0, -1)) {
      const pages = await exhaustDataset(adapter, snapshot, spec);
      adapter.verifySnapshotDatasetReplay({ snapshot, datasetId: spec.datasetId, pages });
    }
    await expect(adapter.closeSnapshot(snapshot, "completed")).rejects.toThrow("not consumed completely");
    expect(fake.sql.at(-1)).toBe("ROLLBACK");
  });

  it("waits for spool cleanup before raw commit and rolls back when spool cleanup fails", async () => {
    await exerciseSpoolCloseOrdering("success");
    await exerciseSpoolCloseOrdering("failure");
  });

  it("rejects descriptor-unsafe or non-ASCII catalogs before calling the connection factory", () => {
    const required = [
      "legacy-membership", "legacy-organization-directory", "legacy-role-assignment", "legacy-subject-universe"
    ];
    let getterInvoked = false;
    const getterCatalog = catalog(required) as unknown as Record<string, unknown>;
    Object.defineProperty(getterCatalog, "datasets", {
      enumerable: true,
      get: () => { getterInvoked = true; return []; }
    });
    const sparse = catalog(required);
    delete (sparse.datasets as unknown as unknown[])[1];
    const symbolic = catalog(required);
    (symbolic.datasets as unknown as Record<symbol, unknown>)[Symbol("hidden")] = true;
    const hidden = catalog(required);
    Object.defineProperty(hidden.datasets, "hidden", { value: true });
    const customPrototype = Object.setPrototypeOf({ ...catalog(required) }, { attacker: true });
    const unknownEntry = catalog(required);
    (unknownEntry.datasets[0] as unknown as Record<string, unknown>).owner = "caller";
    const nonAscii = catalog(required);
    (nonAscii.datasets[0] as unknown as { datasetId: string }).datasetId = "legacy-mémbership";
    for (const datasetCatalog of [getterCatalog, sparse, symbolic, hidden, customPrototype, unknownEntry, nonAscii]) {
      const connectionFactory = vi.fn(async () => fakeConnection(legacyRows()).connection);
      expect(() => createOrganizationReconciliationMysqlTransactionDatasetAdapter({
        componentId: "legacy-main", expectedSourceId: "legacy-db", connectionFactory,
        evidenceNonce: NONCE, catalogSha256: DIGEST_A, datasetCatalog: datasetCatalog as never
      })).toThrow();
      expect(connectionFactory).not.toHaveBeenCalled();
    }
    expect(getterInvoked).toBe(false);
  });
});

async function exerciseSpoolCloseOrdering(mode: "success" | "failure"): Promise<void> {
  const closeStarted = deferred();
  const releaseClose = deferred();
  vi.resetModules();
  vi.doMock("node:fs/promises", async () => {
    const actual = await vi.importActual<typeof import("node:fs/promises")>("node:fs/promises");
    return {
      ...actual,
      open: async (...args: Parameters<typeof actual.open>) => {
        const handle = await actual.open(...args);
        const close = handle.close.bind(handle);
        Object.defineProperty(handle, "close", {
          configurable: true,
          value: async () => {
            closeStarted.resolve();
            await releaseClose.promise;
            await close();
            if (mode === "failure") throw new Error("injected spool close failure");
          }
        });
        return handle;
      }
    };
  });
  try {
    const module = await import(
      "../src/iam-organization-reconciliation/mysql-source-adapters/transaction-dataset-adapter.js"
    );
    const fake = fakeConnection(legacyRows());
    const legacyCatalog = catalog([
      "legacy-membership", "legacy-organization-directory", "legacy-role-assignment", "legacy-subject-universe"
    ]);
    const adapter = module.createOrganizationReconciliationMysqlTransactionDatasetAdapter({
      componentId: "legacy-main", expectedSourceId: "legacy-db", connectionFactory: fake.factory,
      evidenceNonce: NONCE, catalogSha256: DIGEST_A, datasetCatalog: legacyCatalog
    });
    const snapshot = await adapter.openSnapshot();
    for (const spec of legacyCatalog.datasets) {
      const pages = await exhaustDataset(adapter, snapshot, spec);
      adapter.verifySnapshotDatasetReplay({ snapshot, datasetId: spec.datasetId, pages });
    }
    const closePromise = adapter.closeSnapshot(snapshot, "completed");
    await closeStarted.promise;
    expect(fake.sql).not.toContain("COMMIT");
    expect(fake.sql).not.toContain("ROLLBACK");
    releaseClose.resolve();
    if (mode === "success") {
      await expect(closePromise).resolves.toBeUndefined();
      expect(fake.sql.at(-1)).toBe("COMMIT");
    } else {
      await expect(closePromise).rejects.toThrow("Closing the materialized transaction snapshot failed");
      expect(fake.sql.at(-1)).toBe("ROLLBACK");
    }
  } finally {
    releaseClose.resolve();
    vi.doUnmock("node:fs/promises");
    vi.resetModules();
  }
}

function deferred(): { readonly promise: Promise<void>; resolve(): void } {
  let resolve!: () => void;
  const promise = new Promise<void>((accepted) => { resolve = accepted; });
  return Object.freeze({ promise, resolve });
}

async function exhaustDataset(
  adapter: ReturnType<typeof createOrganizationReconciliationMysqlTransactionDatasetAdapter>,
  snapshot: Awaited<ReturnType<ReturnType<
    typeof createOrganizationReconciliationMysqlTransactionDatasetAdapter
  >["openSnapshot"]>>,
  spec: { readonly datasetId: string; readonly pageSize: number }
) {
  const pages: Array<{
    requestCursor: string | null;
    nextCursor: string | null;
    recordOffset: number;
    records: readonly import("../src/iam-organization-reconciliation-dataset-inventory.js").OrganizationReconciliationInventoryJsonValue[];
  }> = [];
  let requestCursor: string | null = null;
  while (true) {
    const page = await adapter.readSnapshotPage({
      snapshot, datasetId: spec.datasetId, requestCursor, pageSize: spec.pageSize
    });
    pages.push({
      requestCursor: page.requestCursor,
      nextCursor: page.nextCursor,
      recordOffset: page.recordOffset,
      records: page.records
    });
    if (page.nextCursor === null) return pages;
    requestCursor = page.nextCursor;
  }
}

function binding(
  componentId: "legacy-main" | "identity" | "plugin",
  expectedSourceId: string,
  catalogSha256: string,
  datasetCatalog: OrganizationReconciliationDatasetCatalog,
  adapter: ReturnType<typeof createOrganizationReconciliationMysqlTransactionDatasetAdapter>
) {
  return {
    componentId,
    expectedSourceId,
    schemaSha256: DIGEST_A,
    catalogSha256,
    buildSha256: DIGEST_B,
    adapter,
    datasetCatalog
  } as const;
}

function catalog(datasetIds: readonly string[]): OrganizationReconciliationDatasetCatalog {
  return {
    contract: ORGANIZATION_RECONCILIATION_DATASET_LINEAGE_CONTRACT,
    trust: ORGANIZATION_RECONCILIATION_DATASET_CATALOG_TRUST,
    datasets: datasetIds.map((datasetId) => ({ datasetId, pageSize: 10, maxPages: 4, maxRecords: 100 }))
  };
}

function legacyRows(): Partial<Record<OrganizationReconciliationMysqlStatementId, readonly unknown[][]>> {
  return {
    "legacy-membership-page/v1": [[{ user_id: 1, organization_id: 1 }]],
    "legacy-organization-directory-page/v1": [[{
      id: 1, name: "root", title: "Root", created_at: 1, updated_at: 1
    }]],
    "legacy-role-assignment-page/v1": [[{ user_id: 1, item_name: "root" }]],
    "legacy-subject-universe-page/v1": [[{ id: 1, status: 10 }]]
  };
}

function identityRows(): Partial<Record<OrganizationReconciliationMysqlStatementId, readonly unknown[][]>> {
  return {
    "identity-membership-candidate-page/v1": [[{
      legacy_user_id: 1, legacy_organization_id: 1, identity_user_id: "legacy:1",
      identity_organization_id: "legacy:1", organization_role: "member", candidate_status: "candidate"
    }]],
    "identity-membership-shadow-page/v1": [[{
      legacy_user_id: 1, organization_id: 1, organization_role: "member", status: "shadow"
    }]],
    "identity-organization-candidate-page/v1": [[{
      legacy_organization_id: 1, identity_organization_id: "legacy:1", name: "root", title: "Root",
      candidate_status: "candidate"
    }]],
    "identity-organization-id-map-page/v1": [[{
      legacy_organization_id: 1, identity_organization_id: "legacy:1", mapping_status: "active"
    }]],
    "identity-role-shadow-page/v1": [[{ legacy_user_id: 1, role_name: "root", status: "shadow" }]],
    "identity-subject-universe-page/v1": [[{ legacy_user_id: 1, status: "active", source: "legacy-shadow" }]]
  };
}

function pluginRows(): Partial<Record<OrganizationReconciliationMysqlStatementId, readonly unknown[][]>> {
  return {
    "plugin-registry-page/v1": [[{
      id: "system-admin", enabled: 1, access_scope: "root-only", organization_name: null
    }]]
  };
}

function fakeConnection(
  responsePages: Partial<Record<OrganizationReconciliationMysqlStatementId, readonly unknown[][]>>
) {
  const sql: string[] = [];
  const release = vi.fn();
  const queues = new Map<string, unknown[][]>(Object.entries(responsePages).map(([statementId, pages]) => [
    ORGANIZATION_RECONCILIATION_MYSQL_STATEMENTS[statementId as OrganizationReconciliationMysqlStatementId],
    [...pages!]
  ]));
  const connection: MysqlRepeatableReadSnapshotConnection = {
    async query(statement) {
      sql.push(statement);
      return [queues.get(statement)?.shift() ?? [], []];
    },
    release
  };
  return { connection, factory: async () => connection, sql, release };
}
