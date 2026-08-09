import { describe, expect, it, vi, type Mock } from "vitest";
import {
  ORGANIZATION_RECONCILIATION_DATASET_CATALOG_TRUST,
  ORGANIZATION_RECONCILIATION_DATASET_LINEAGE_CONTRACT,
  ORGANIZATION_RECONCILIATION_DATASET_LINEAGE_PRODUCTION_READY,
  type OrganizationReconciliationDatasetCatalog,
  type OrganizationReconciliationDatasetComponentBinding
} from "../src/iam-organization-reconciliation-dataset-lineage.js";
import {
  ORGANIZATION_RECONCILIATION_TRANSACTION_DATASET_LINEAGE_FACTORY_PROVENANCE_CONTRACT,
  assertOrganizationReconciliationTransactionDatasetLineageFactoryProvenance,
  collectOrganizationReconciliationFactoryBoundTransactionDatasetLineage
} from
  "../src/iam-organization-reconciliation-transaction-dataset-lineage-capability.js";
import {
  ORGANIZATION_RECONCILIATION_COMPILED_PIPELINE_REGISTRATION_READY,
  ORGANIZATION_RECONCILIATION_RAW_SOURCE_CAPABILITY_READY,
  ORGANIZATION_RECONCILIATION_TRANSACTION_ADAPTER_FACTORY_CAPABILITY_IMPLEMENTED,
  ORGANIZATION_RECONCILIATION_TRANSACTION_ADAPTER_FACTORY_CAPABILITY_READY
} from "../src/iam-organization-reconciliation-runtime-readiness.js";
import { ORGANIZATION_RECONCILIATION_REAL_SOURCE_ADAPTERS_READY } from
  "../src/iam-organization-reconciliation-validator.js";
import {
  ORGANIZATION_RECONCILIATION_MYSQL_TRANSACTION_DATASET_ADAPTER_CONTRACT,
  ORGANIZATION_RECONCILIATION_MYSQL_TRANSACTION_DATASET_ADAPTER_FACTORY_PROVENANCE_CONTRACT,
  ORGANIZATION_RECONCILIATION_MYSQL_TRANSACTION_DATASET_ADAPTER_READY,
  assertOrganizationReconciliationMysqlTransactionDatasetAdapterFactoryProvenance,
  createOrganizationReconciliationMysqlTransactionDatasetAdapter
} from
  "../src/iam-organization-reconciliation/mysql-source-adapters/transaction-dataset-adapter.js";
import {
  ORGANIZATION_RECONCILIATION_MYSQL_STATEMENTS,
  ORGANIZATION_RECONCILIATION_MYSQL_STATEMENT_CATALOG_SHA256,
  type MysqlRepeatableReadSnapshotConnection,
  type MysqlRepeatableReadSnapshotConnectionFactory,
  type OrganizationReconciliationMysqlStatementId
} from "../src/iam-organization-reconciliation/mysql-repeatable-read-snapshot.js";

const DIGEST_A = "a".repeat(64);
const DIGEST_B = "b".repeat(64);
const DIGEST_C = "c".repeat(64);
const DIGEST_D = "d".repeat(64);
const NONCE = "0123456789abcdef0123456789abcdef";
const LEGACY_DATASET_IDS = [
  "legacy-membership",
  "legacy-organization-directory",
  "legacy-rbac-edge",
  "legacy-role-assignment",
  "legacy-subject-universe"
] as const;

describe("transaction dataset lineage factory provenance capability", () => {
  it("keeps implementation distinct from every production readiness gate and runtime input", () => {
    const originalArgv = [...process.argv];
    const originalReady = process.env.IDENTITY_IAM_RECONCILIATION_READY;
    try {
      process.argv.push("--identity-iam-reconciliation-ready=true");
      process.env.IDENTITY_IAM_RECONCILIATION_READY = "true";
      expect(ORGANIZATION_RECONCILIATION_TRANSACTION_ADAPTER_FACTORY_CAPABILITY_IMPLEMENTED)
        .toBe(true);
      expect(ORGANIZATION_RECONCILIATION_TRANSACTION_ADAPTER_FACTORY_CAPABILITY_READY)
        .toBe(false);
      expect(ORGANIZATION_RECONCILIATION_RAW_SOURCE_CAPABILITY_READY).toBe(false);
      expect(ORGANIZATION_RECONCILIATION_COMPILED_PIPELINE_REGISTRATION_READY).toBe(false);
      expect(ORGANIZATION_RECONCILIATION_DATASET_LINEAGE_PRODUCTION_READY).toBe(false);
      expect(ORGANIZATION_RECONCILIATION_MYSQL_TRANSACTION_DATASET_ADAPTER_READY).toBe(false);
      expect(ORGANIZATION_RECONCILIATION_REAL_SOURCE_ADAPTERS_READY).toBe(false);
      expect(() => assertOrganizationReconciliationTransactionDatasetLineageFactoryProvenance({
        ready: true,
        contract: ORGANIZATION_RECONCILIATION_TRANSACTION_DATASET_LINEAGE_FACTORY_PROVENANCE_CONTRACT
      })).toThrow("no transaction factory provenance");
    } finally {
      process.argv.splice(0, process.argv.length, ...originalArgv);
      if (originalReady === undefined) delete process.env.IDENTITY_IAM_RECONCILIATION_READY;
      else process.env.IDENTITY_IAM_RECONCILIATION_READY = originalReady;
    }
  });

  it("brands only the exact factory object and binds exact declarations without leaking dependencies", () => {
    const fakeA = fakeConnection(legacyRows());
    const fakeB = fakeConnection(legacyRows());
    const catalogA = catalogFor("legacy-main");
    const catalogB = catalogFor("legacy-main");
    const adapterA = createOrganizationReconciliationMysqlTransactionDatasetAdapter({
      componentId: "legacy-main",
      expectedSourceId: "legacy-db-a",
      connectionFactory: fakeA.factory,
      evidenceNonce: NONCE,
      catalogSha256: DIGEST_A,
      datasetCatalog: catalogA
    });
    const adapterB = createOrganizationReconciliationMysqlTransactionDatasetAdapter({
      componentId: "legacy-main",
      expectedSourceId: "legacy-db-b",
      connectionFactory: fakeB.factory,
      evidenceNonce: "fedcba9876543210fedcba9876543210",
      catalogSha256: DIGEST_B,
      datasetCatalog: catalogB
    });
    const bindingA = factoryBinding("legacy-main", "legacy-db-a", DIGEST_A, catalogA);
    const bindingB = factoryBinding("legacy-main", "legacy-db-b", DIGEST_B, catalogB);
    const provenance =
      assertOrganizationReconciliationMysqlTransactionDatasetAdapterFactoryProvenance(
        adapterA,
        bindingA
      );

    expect(provenance).toMatchObject({
      contract: ORGANIZATION_RECONCILIATION_MYSQL_TRANSACTION_DATASET_ADAPTER_FACTORY_PROVENANCE_CONTRACT,
      adapterContract: ORGANIZATION_RECONCILIATION_MYSQL_TRANSACTION_DATASET_ADAPTER_CONTRACT,
      trust: "factory-origin-only",
      physicalSourceTrust: "unattested",
      ownerCatalogTrust: "caller-structured-untrusted",
      componentId: "legacy-main",
      expectedSourceId: "legacy-db-a",
      declaredCatalogSha256: DIGEST_A,
      statementCatalogSha256: ORGANIZATION_RECONCILIATION_MYSQL_STATEMENT_CATALOG_SHA256
    });
    expect(provenance.datasetIds).toEqual([
      "legacy-membership",
      "legacy-organization-directory",
      "legacy-rbac-edge",
      "legacy-role-assignment",
      "legacy-subject-universe"
    ]);
    expect(provenance.structuralCatalogSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(Object.isFrozen(provenance)).toBe(true);
    expect(Object.isFrozen(provenance.datasetCatalog.datasets)).toBe(true);
    const serialized = JSON.stringify(provenance);
    expect(serialized).not.toContain(NONCE);
    expect(serialized).not.toContain("fedcba9876543210fedcba9876543210");
    expect(serialized).not.toContain("connectionFactory");
    expect(fakeA.factory).not.toHaveBeenCalled();
    expect(fakeB.factory).not.toHaveBeenCalled();

    const lookalike = {
      sourceId: adapterA.sourceId,
      openSnapshot: adapterA.openSnapshot,
      readSnapshotPage: adapterA.readSnapshotPage,
      verifySnapshotDatasetReplay: adapterA.verifySnapshotDatasetReplay,
      closeSnapshot: adapterA.closeSnapshot
    };
    const serializedAdapter = JSON.parse(JSON.stringify(adapterA));
    for (const candidate of [
      { ...adapterA },
      new Proxy(adapterA, {}),
      lookalike,
      serializedAdapter
    ]) {
      expect(() => assertOrganizationReconciliationMysqlTransactionDatasetAdapterFactoryProvenance(
        candidate,
        bindingA
      )).toThrow("no factory provenance");
    }
    expect(() => assertOrganizationReconciliationMysqlTransactionDatasetAdapterFactoryProvenance(
      adapterA,
      bindingB
    )).toThrow("does not match its factory binding");
    expect(() => assertOrganizationReconciliationMysqlTransactionDatasetAdapterFactoryProvenance(
      adapterA,
      factoryBinding("identity", "legacy-db-a", DIGEST_A, catalogFor("identity"))
    )).toThrow("does not match its factory binding");
    expect(fakeA.factory).not.toHaveBeenCalled();
    expect(fakeB.factory).not.toHaveBeenCalled();

    expect(assertOrganizationReconciliationMysqlTransactionDatasetAdapterFactoryProvenance(
      adapterB,
      bindingB
    ).expectedSourceId).toBe("legacy-db-b");
  });

  it("rejects catalog drift, A/B metadata, accessors, symbols, and proxies before source I/O", () => {
    const fake = fakeConnection(legacyRows());
    const datasetCatalog = catalogFor("legacy-main");
    const adapter = createOrganizationReconciliationMysqlTransactionDatasetAdapter({
      componentId: "legacy-main",
      expectedSourceId: "legacy-db",
      connectionFactory: fake.factory,
      evidenceNonce: NONCE,
      catalogSha256: DIGEST_A,
      datasetCatalog
    });
    const base = factoryBinding("legacy-main", "legacy-db", DIGEST_A, datasetCatalog);

    (datasetCatalog.datasets[0] as { pageSize: number }).pageSize = 11;
    expect(() => assertOrganizationReconciliationMysqlTransactionDatasetAdapterFactoryProvenance(
      adapter,
      base
    )).toThrow("does not match its factory binding");

    let getterInvoked = false;
    const accessor = factoryBinding("legacy-main", "legacy-db", DIGEST_A, catalogFor("legacy-main")) as
      unknown as Record<string, unknown>;
    Object.defineProperty(accessor, "datasetCatalog", {
      enumerable: true,
      get: () => {
        getterInvoked = true;
        return catalogFor("legacy-main");
      }
    });
    const symbolic = factoryBinding("legacy-main", "legacy-db", DIGEST_A, catalogFor("legacy-main")) as
      unknown as Record<symbol, unknown>;
    symbolic[Symbol("hidden")] = true;
    for (const binding of [accessor, symbolic, new Proxy(base, {})]) {
      expect(() => assertOrganizationReconciliationMysqlTransactionDatasetAdapterFactoryProvenance(
        adapter,
        binding
      )).toThrow();
    }
    expect(getterInvoked).toBe(false);
    expect(fake.factory).not.toHaveBeenCalled();
  });

  it("validates all wrapper brands and descriptors before any connection factory is invoked", async () => {
    const cases: readonly [string, (system: FactorySystem) => void][] = [
      ["spread adapter", (system) => {
        mutableBinding(system.bindings[0]!).adapter = { ...system.bindings[0]!.adapter };
      }],
      ["proxy adapter", (system) => {
        mutableBinding(system.bindings[0]!).adapter = new Proxy(system.bindings[0]!.adapter, {});
      }],
      ["look-alike adapter", (system) => {
        const adapter = system.bindings[0]!.adapter;
        mutableBinding(system.bindings[0]!).adapter = {
          sourceId: adapter.sourceId,
          openSnapshot: adapter.openSnapshot,
          readSnapshotPage: adapter.readSnapshotPage,
          verifySnapshotDatasetReplay: adapter.verifySnapshotDatasetReplay,
          closeSnapshot: adapter.closeSnapshot
        };
      }],
      ["JSON adapter", (system) => {
        mutableBinding(system.bindings[0]!).adapter = JSON.parse(JSON.stringify(system.bindings[0]!.adapter));
      }],
      ["A/B source", (system) => {
        mutableBinding(system.bindings[0]!).expectedSourceId = "identity-db";
      }],
      ["A/B catalog digest", (system) => {
        mutableBinding(system.bindings[0]!).catalogSha256 = DIGEST_B;
      }],
      ["cross component", (system) => {
        mutableBinding(system.bindings[0]!).componentId = "identity";
        mutableBinding(system.bindings[0]!).datasetCatalog = catalogFor("identity");
      }],
      ["catalog metadata drift", (system) => {
        (system.bindings[0]!.datasetCatalog.datasets[0] as { maxRecords: number }).maxRecords = 99;
      }]
    ];
    for (const [label, mutate] of cases) {
      const system = createFactorySystem();
      mutate(system);
      await expect(collectFactoryRun(system)).rejects.toThrow();
      expect(system.fakes.every((fake) => fake.factory.mock.calls.length === 0), label).toBe(true);
    }

    const accessorSystem = createFactorySystem();
    let getterInvoked = false;
    Object.defineProperty(accessorSystem.bindings[2], "catalogSha256", {
      enumerable: true,
      get: () => {
        getterInvoked = true;
        return DIGEST_C;
      }
    });
    await expect(collectFactoryRun(accessorSystem)).rejects.toThrow("accessor");
    expect(getterInvoked).toBe(false);
    expect(accessorSystem.fakes.every((fake) => fake.factory.mock.calls.length === 0)).toBe(true);

    const proxySystem = createFactorySystem();
    await expect(collectOrganizationReconciliationFactoryBoundTransactionDatasetLineage(
      new Proxy(factoryRunOptions(proxySystem), {})
    )).rejects.toThrow("invalid");
    expect(proxySystem.fakes.every((fake) => fake.factory.mock.calls.length === 0)).toBe(true);
  });

  it("emits a non-transferable run brand that attests factory origin only", async () => {
    const system = createFactorySystem();
    const run = await collectFactoryRun(system);
    const provenance =
      assertOrganizationReconciliationTransactionDatasetLineageFactoryProvenance(run);

    expect(run.artifacts).toHaveLength(12);
    expect(provenance).toEqual({
      contract: ORGANIZATION_RECONCILIATION_TRANSACTION_DATASET_LINEAGE_FACTORY_PROVENANCE_CONTRACT,
      trust: "factory-origin-only",
      physicalSourceTrust: "unattested",
      ownerCatalogTrust: ORGANIZATION_RECONCILIATION_DATASET_CATALOG_TRUST,
      factoryCapabilityImplemented: true,
      productionReady: false,
      components: [
        componentExpectation("legacy-main", "legacy-db", DIGEST_A, DIGEST_A, DIGEST_D),
        componentExpectation("identity", "identity-db", DIGEST_B, DIGEST_A, DIGEST_D),
        componentExpectation("plugin", "plugin-db", DIGEST_C, DIGEST_A, DIGEST_D)
      ]
    });
    for (const fake of system.fakes) {
      expect(fake.factory).toHaveBeenCalledTimes(1);
      expect(fake.sql.at(-1)).toBe("COMMIT");
      expect(fake.release).toHaveBeenCalledTimes(1);
    }
    const serialized = JSON.stringify(provenance);
    expect(serialized).not.toContain(NONCE);
    expect(serialized).not.toContain("connectionFactory");
    expect(serialized).not.toContain("commitmentKey");

    const cloned = { ...run };
    const serializedRun = JSON.parse(JSON.stringify(run));
    const proxy = new Proxy(run, {});
    const spliced = { ...run, coordinatorManifest: { ...run.coordinatorManifest } };
    for (const candidate of [cloned, serializedRun, proxy, spliced]) {
      expect(() => assertOrganizationReconciliationTransactionDatasetLineageFactoryProvenance(candidate))
        .toThrow("no transaction factory provenance");
    }
    expect(assertOrganizationReconciliationTransactionDatasetLineageFactoryProvenance(run))
      .toBe(provenance);
  });
});

type ComponentId = "legacy-main" | "identity" | "plugin";

interface FakeConnection {
  readonly factory: Mock<MysqlRepeatableReadSnapshotConnectionFactory>;
  readonly sql: string[];
  readonly release: ReturnType<typeof vi.fn>;
}

interface FactorySystem {
  readonly fakes: readonly [FakeConnection, FakeConnection, FakeConnection];
  readonly bindings: OrganizationReconciliationDatasetComponentBinding[];
}

function createFactorySystem(): FactorySystem {
  const fakes = [
    fakeConnection(legacyRows()),
    fakeConnection(identityRows()),
    fakeConnection(pluginRows())
  ] as const;
  const definitions = [
    ["legacy-main", "legacy-db", DIGEST_A, catalogFor("legacy-main"), fakes[0]],
    ["identity", "identity-db", DIGEST_B, catalogFor("identity"), fakes[1]],
    ["plugin", "plugin-db", DIGEST_C, catalogFor("plugin"), fakes[2]]
  ] as const;
  const bindings = definitions.map(([componentId, sourceId, catalogSha256, datasetCatalog, fake]) => {
    const adapter = createOrganizationReconciliationMysqlTransactionDatasetAdapter({
      componentId,
      expectedSourceId: sourceId,
      connectionFactory: fake.factory,
      evidenceNonce: NONCE,
      catalogSha256,
      datasetCatalog
    });
    return {
      componentId,
      expectedSourceId: sourceId,
      schemaSha256: DIGEST_A,
      catalogSha256,
      buildSha256: DIGEST_D,
      adapter,
      datasetCatalog
    } satisfies OrganizationReconciliationDatasetComponentBinding;
  });
  return { fakes, bindings };
}

function collectFactoryRun(system: FactorySystem) {
  return collectOrganizationReconciliationFactoryBoundTransactionDatasetLineage(
    factoryRunOptions(system)
  );
}

function factoryRunOptions(system: FactorySystem) {
  let tick = 0;
  return {
    components: system.bindings,
    maxWindowMilliseconds: 1_000,
    clock: { now: () => new Date(Date.UTC(2026, 7, 9, 10, 0, 0, tick++)) }
  };
}

function mutableBinding(binding: OrganizationReconciliationDatasetComponentBinding): Record<string, unknown> {
  return binding as unknown as Record<string, unknown>;
}

function factoryBinding(
  componentId: ComponentId,
  expectedSourceId: string,
  catalogSha256: string,
  datasetCatalog: OrganizationReconciliationDatasetCatalog
) {
  return { componentId, expectedSourceId, catalogSha256, datasetCatalog };
}

function catalogFor(componentId: ComponentId): OrganizationReconciliationDatasetCatalog {
  const datasetIds = componentId === "legacy-main"
    ? LEGACY_DATASET_IDS
    : componentId === "identity"
      ? [
          "identity-membership-candidate",
          "identity-membership-shadow",
          "identity-organization-candidate",
          "identity-organization-id-map",
          "identity-role-shadow",
          "identity-subject-universe"
        ]
      : ["plugin-registry"];
  return {
    contract: ORGANIZATION_RECONCILIATION_DATASET_LINEAGE_CONTRACT,
    trust: ORGANIZATION_RECONCILIATION_DATASET_CATALOG_TRUST,
    datasets: datasetIds.map((datasetId) => ({
      datasetId,
      pageSize: 10,
      maxPages: 4,
      maxRecords: 100
    }))
  };
}

function componentExpectation(
  componentId: ComponentId,
  expectedSourceId: string,
  catalogSha256: string,
  schemaSha256: string,
  buildSha256: string
) {
  return {
    componentId,
    expectedSourceId,
    declaredSchemaSha256: schemaSha256,
    declaredCatalogSha256: catalogSha256,
    declaredBuildSha256: buildSha256,
    structuralCatalogSha256: expect.stringMatching(/^[a-f0-9]{64}$/),
    datasetIds: catalogFor(componentId).datasets.map((dataset) => dataset.datasetId),
    adapterContract: ORGANIZATION_RECONCILIATION_MYSQL_TRANSACTION_DATASET_ADAPTER_CONTRACT,
    adapterFactoryProvenanceContract:
      ORGANIZATION_RECONCILIATION_MYSQL_TRANSACTION_DATASET_ADAPTER_FACTORY_PROVENANCE_CONTRACT,
    statementCatalogSha256: ORGANIZATION_RECONCILIATION_MYSQL_STATEMENT_CATALOG_SHA256
  };
}

function legacyRows(): Partial<Record<OrganizationReconciliationMysqlStatementId, readonly unknown[][]>> {
  return {
    "legacy-membership-page/v1": [[{ user_id: 1, organization_id: 1 }]],
    "legacy-organization-directory-page/v1": [[{
      id: 1,
      name: "root",
      title: "Root",
      created_at: 1,
      updated_at: 1
    }]],
    "legacy-rbac-edge-page/v1": [[{ parent: "root", child: "organization.update" }]],
    "legacy-role-assignment-page/v1": [[{ user_id: 1, item_name: "root" }]],
    "legacy-subject-universe-page/v1": [[{ id: 1, status: 10 }]]
  };
}

function identityRows(): Partial<Record<OrganizationReconciliationMysqlStatementId, readonly unknown[][]>> {
  return {
    "identity-membership-candidate-page/v1": [[{
      legacy_user_id: 1,
      legacy_organization_id: 1,
      identity_user_id: "legacy:1",
      identity_organization_id: "legacy:1",
      organization_role: "member",
      candidate_status: "candidate"
    }]],
    "identity-membership-shadow-page/v1": [[{
      legacy_user_id: 1,
      organization_id: 1,
      organization_role: "member",
      status: "shadow"
    }]],
    "identity-organization-candidate-page/v1": [[{
      legacy_organization_id: 1,
      identity_organization_id: "legacy:1",
      name: "root",
      title: "Root",
      candidate_status: "candidate"
    }]],
    "identity-organization-id-map-page/v1": [[{
      legacy_organization_id: 1,
      identity_organization_id: "legacy:1",
      mapping_status: "active"
    }]],
    "identity-role-shadow-page/v1": [[{
      legacy_user_id: 1,
      role_name: "root",
      status: "shadow"
    }]],
    "identity-subject-universe-page/v1": [[{
      legacy_user_id: 1,
      status: "active",
      source: "legacy-shadow"
    }]]
  };
}

function pluginRows(): Partial<Record<OrganizationReconciliationMysqlStatementId, readonly unknown[][]>> {
  return {
    "plugin-registry-page/v1": [[{
      id: "system-admin",
      enabled: 1,
      access_scope: "root-only",
      organization_name: null
    }]]
  };
}

function fakeConnection(
  responsePages: Partial<Record<OrganizationReconciliationMysqlStatementId, readonly unknown[][]>>
): FakeConnection {
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
  return {
    factory: vi.fn<MysqlRepeatableReadSnapshotConnectionFactory>(async () => connection),
    sql,
    release
  };
}
