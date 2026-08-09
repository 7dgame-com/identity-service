import { createHash, randomBytes } from "node:crypto";
import { isProxy } from "node:util/types";
import {
  ORGANIZATION_RECONCILIATION_PAGINATION_MODE,
  ORGANIZATION_RECONCILIATION_SNAPSHOT_MODE,
  type OrganizationReconciliationSourceSnapshot
} from "../../iam-organization-reconciliation-collector.js";
import {
  ORGANIZATION_RECONCILIATION_DATASET_CATALOG_TRUST,
  ORGANIZATION_RECONCILIATION_DATASET_LINEAGE_CONTRACT,
  type OrganizationReconciliationDatasetCatalog,
  type OrganizationReconciliationDatasetPage,
  type OrganizationReconciliationDatasetPageRequest,
  type OrganizationReconciliationDatasetReplayVerificationRequest,
  type OrganizationReconciliationDatasetSourceAdapter,
  type OrganizationReconciliationDatasetSpec
} from "../../iam-organization-reconciliation-dataset-lineage.js";
import {
  createOrganizationReconciliationContentSnapshotId,
  createOrganizationReconciliationContentSourceVersion,
  type OrganizationReconciliationInventoryJsonValue
} from "../../iam-organization-reconciliation-dataset-inventory.js";
import {
  openOrganizationReconciliationTransactionDatasetSpool,
  type OrganizationReconciliationTransactionDatasetSpool
} from "../../iam-organization-reconciliation-transaction-dataset-spool.js";
import { subjectRefForLegacyUserId } from "../../iam-organization-reconciliation-refs.js";
import {
  ORGANIZATION_RECONCILIATION_MYSQL_STATEMENT_CATALOG_SHA256,
  type MysqlRepeatableReadSnapshotConnectionFactory
} from "../mysql-repeatable-read-snapshot.js";
import {
  openIdentityMysqlRawSnapshot,
  openLegacyMainMysqlRawSnapshot,
  openPluginRegistryMysqlRawSnapshot,
  type IdentityMysqlRawSnapshot,
  type LegacyMainMysqlRawSnapshot,
  type OrganizationReconciliationMysqlRawComponentId,
  type OrganizationReconciliationMysqlRawPage,
  type OrganizationReconciliationMysqlRawSurface,
  type PluginRegistryMysqlRawSnapshot
} from "./raw-source-snapshots.js";

export const ORGANIZATION_RECONCILIATION_MYSQL_TRANSACTION_DATASET_ADAPTER_CONTRACT =
  "iam-organization-reconciliation-mysql-transaction-dataset-adapter/v1" as const;
export const ORGANIZATION_RECONCILIATION_MYSQL_TRANSACTION_DATASET_ADAPTER_FACTORY_PROVENANCE_CONTRACT =
  "iam-organization-reconciliation-mysql-transaction-dataset-adapter-factory-provenance/v1" as const;
/** Owner catalogs and reviewed physical runtime bindings remain deliberately absent. */
export const ORGANIZATION_RECONCILIATION_MYSQL_TRANSACTION_DATASET_ADAPTER_READY = false as const;

/**
 * Runtime proof of one deliberately narrow fact: the exact adapter object was
 * created by this hardened factory with the captured declarations below. It
 * does not authenticate the physical database or approve the declared catalog.
 */
export interface OrganizationReconciliationMysqlTransactionDatasetAdapterFactoryProvenance {
  readonly contract:
    typeof ORGANIZATION_RECONCILIATION_MYSQL_TRANSACTION_DATASET_ADAPTER_FACTORY_PROVENANCE_CONTRACT;
  readonly adapterContract:
    typeof ORGANIZATION_RECONCILIATION_MYSQL_TRANSACTION_DATASET_ADAPTER_CONTRACT;
  readonly trust: "factory-origin-only";
  readonly physicalSourceTrust: "unattested";
  readonly ownerCatalogTrust: typeof ORGANIZATION_RECONCILIATION_DATASET_CATALOG_TRUST;
  readonly componentId: OrganizationReconciliationMysqlRawComponentId;
  readonly expectedSourceId: string;
  readonly declaredCatalogSha256: string;
  readonly structuralCatalogSha256: string;
  readonly datasetIds: readonly string[];
  readonly datasetCatalog: OrganizationReconciliationDatasetCatalog;
  readonly statementCatalogSha256: string;
}

export interface OrganizationReconciliationMysqlTransactionDatasetAdapterFactoryBinding {
  readonly componentId: OrganizationReconciliationMysqlRawComponentId;
  readonly expectedSourceId: string;
  readonly catalogSha256: string;
  readonly datasetCatalog: OrganizationReconciliationDatasetCatalog;
}

export interface OrganizationReconciliationMysqlTransactionDatasetAdapterReadiness {
  readonly ready: false;
  readonly blockers: readonly [
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
  ];
}

export function organizationReconciliationMysqlTransactionDatasetAdapterReadiness():
OrganizationReconciliationMysqlTransactionDatasetAdapterReadiness {
  return Object.freeze({
    ready: ORGANIZATION_RECONCILIATION_MYSQL_TRANSACTION_DATASET_ADAPTER_READY,
    blockers: Object.freeze([
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
    ] as const)
  });
}

export interface CreateOrganizationReconciliationMysqlTransactionDatasetAdapterOptions {
  readonly componentId: OrganizationReconciliationMysqlRawComponentId;
  readonly expectedSourceId: string;
  readonly connectionFactory: MysqlRepeatableReadSnapshotConnectionFactory;
  readonly evidenceNonce: string;
  readonly catalogSha256: string;
  readonly datasetCatalog: OrganizationReconciliationDatasetCatalog;
}

type RawSnapshot = LegacyMainMysqlRawSnapshot | IdentityMysqlRawSnapshot | PluginRegistryMysqlRawSnapshot;
type RawPage = OrganizationReconciliationMysqlRawPage<OrganizationReconciliationMysqlRawSurface, unknown>;

interface ActiveSnapshot {
  readonly publicSnapshot: Readonly<OrganizationReconciliationSourceSnapshot>;
  readonly rawSnapshot: RawSnapshot;
  readonly spool: OrganizationReconciliationTransactionDatasetSpool;
  readonly datasetCount: number;
  verifiedDatasetCount: number;
  poisoned: boolean;
  closing: boolean;
  closePromise: Promise<void> | null;
}

interface FactoryProvenanceBrand {
  readonly provenance: OrganizationReconciliationMysqlTransactionDatasetAdapterFactoryProvenance;
  readonly adapterValues: Readonly<{
    sourceId: string;
    openSnapshot: OrganizationReconciliationDatasetSourceAdapter<OrganizationReconciliationInventoryJsonValue>["openSnapshot"];
    readSnapshotPage: OrganizationReconciliationDatasetSourceAdapter<OrganizationReconciliationInventoryJsonValue>["readSnapshotPage"];
    verifySnapshotDatasetReplay:
      OrganizationReconciliationDatasetSourceAdapter<OrganizationReconciliationInventoryJsonValue>["verifySnapshotDatasetReplay"];
    closeSnapshot: OrganizationReconciliationDatasetSourceAdapter<OrganizationReconciliationInventoryJsonValue>["closeSnapshot"];
  }>;
  readonly canonicalCatalogJson: string;
}

const COMPONENT_DATASETS: Readonly<Record<OrganizationReconciliationMysqlRawComponentId, readonly string[]>> =
  Object.freeze({
    "legacy-main": Object.freeze([
      "legacy-membership",
      "legacy-organization-directory",
      "legacy-role-assignment",
      "legacy-subject-universe"
    ]),
    identity: Object.freeze([
      "identity-membership-candidate",
      "identity-membership-shadow",
      "identity-organization-candidate",
      "identity-organization-id-map",
      "identity-role-shadow",
      "identity-subject-universe"
    ]),
    plugin: Object.freeze(["plugin-registry"])
  });
const MAX_COMPONENT_PAGES = 10_000;
const MAX_COMPONENT_RECORDS = 10_000_000;
const STRUCTURAL_CATALOG_HASH_DOMAIN = Buffer.from(
  "iam-organization-reconciliation:mysql-transaction-dataset-structural-catalog:v1\u001f",
  "utf8"
);
const factoryProvenanceBrands = new WeakMap<object, FactoryProvenanceBrand>();

export function createOrganizationReconciliationMysqlTransactionDatasetAdapter(
  candidate: CreateOrganizationReconciliationMysqlTransactionDatasetAdapterOptions
): OrganizationReconciliationDatasetSourceAdapter<OrganizationReconciliationInventoryJsonValue> {
  const options = validateOptions(candidate);
  let active: ActiveSnapshot | null = null;
  let opening = false;

  const adapter: OrganizationReconciliationDatasetSourceAdapter<OrganizationReconciliationInventoryJsonValue> = {
    sourceId: options.expectedSourceId,
    async openSnapshot() {
      if (active !== null || opening) throw new Error("A materialized transaction snapshot is already open.");
      opening = true;
      let rawSnapshot: RawSnapshot | null = null;
      let commitmentKey: Buffer | null = null;
      let spool: OrganizationReconciliationTransactionDatasetSpool | null = null;
      try {
        rawSnapshot = await openRawSnapshot(options);
        commitmentKey = randomBytes(32);
        spool = await openOrganizationReconciliationTransactionDatasetSpool({
          componentId: options.componentId,
          sourceId: options.expectedSourceId,
          catalogSha256: options.catalogSha256,
          datasetCatalog: options.datasetCatalog,
          commitmentKey,
          subjectUniverse: options.componentId === "plugin" ? null : {
            datasetId: options.componentId === "legacy-main" ?
              "legacy-subject-universe" : "identity-subject-universe",
            evidenceNonce: options.evidenceNonce
          }
        });
        // The spool owns a private copy after open; this factory retains no run key.
        commitmentKey.fill(0);
        commitmentKey = null;
        for (const spec of options.datasets) {
          await spoolRawDataset(rawSnapshot, spec, spool, options.componentId);
        }
        const inventory = await spool.seal();
        const subjectUniverse = options.componentId === "plugin" ?
          Object.freeze({ count: 0, hash: "" }) : spool.subjectUniverse();
        const publicSnapshot = Object.freeze({
          sourceId: options.expectedSourceId,
          sourceVersion: createOrganizationReconciliationContentSourceVersion(options.expectedSourceId, inventory),
          snapshotId: createOrganizationReconciliationContentSnapshotId(options.expectedSourceId, inventory),
          recordCount: inventory.recordCount,
          subjectUniverseCount: subjectUniverse.count,
          subjectUniverseHash: subjectUniverse.hash,
          snapshotMode: ORGANIZATION_RECONCILIATION_SNAPSHOT_MODE,
          paginationMode: ORGANIZATION_RECONCILIATION_PAGINATION_MODE,
          datasetInventory: inventory
        });
        active = {
          publicSnapshot,
          rawSnapshot,
          spool,
          datasetCount: options.datasets.length,
          verifiedDatasetCount: 0,
          poisoned: false,
          closing: false,
          closePromise: null
        };
        rawSnapshot = null;
        spool = null;
        return publicSnapshot;
      } catch {
        // Best-effort overwrite only; JavaScript runtimes do not guarantee strong memory erasure.
        commitmentKey?.fill(0);
        await spool?.close("failed").catch(() => undefined);
        await rawSnapshot?.close("failed").catch(() => undefined);
        throw new Error("Materializing the transaction-owned dataset inventory failed.");
      } finally {
        opening = false;
      }
    },
    async readSnapshotPage(candidateRequest: OrganizationReconciliationDatasetPageRequest) {
      const state = active;
      if (!state || state.closing || state.poisoned) {
        throw new Error("The materialized transaction snapshot is not open or has been poisoned.");
      }
      const request = validateReadRequest(candidateRequest);
      if (request.snapshot !== state.publicSnapshot) {
        throw new Error("The materialized dataset request uses an unexpected snapshot handle.");
      }
      try {
        const page = await state.spool.readPage({
          datasetId: request.datasetId,
          requestCursor: request.requestCursor,
          pageSize: request.pageSize
        });
        const snapshot = state.publicSnapshot;
        return Object.freeze({
          sourceId: snapshot.sourceId,
          sourceVersion: snapshot.sourceVersion,
          snapshotId: snapshot.snapshotId,
          snapshotRecordCount: snapshot.recordCount,
          subjectUniverseCount: snapshot.subjectUniverseCount,
          subjectUniverseHash: snapshot.subjectUniverseHash,
          datasetId: page.datasetId,
          datasetRecordCount: page.datasetRecordCount,
          requestCursor: page.requestCursor,
          nextCursor: page.nextCursor,
          recordOffset: page.recordOffset,
          records: page.records
        } satisfies OrganizationReconciliationDatasetPage<OrganizationReconciliationInventoryJsonValue>);
      } catch {
        state.poisoned = true;
        throw new Error("Reading the bounded transaction dataset page failed.");
      }
    },
    verifySnapshotDatasetReplay(
      candidateRequest: OrganizationReconciliationDatasetReplayVerificationRequest<
        OrganizationReconciliationInventoryJsonValue
      >
    ) {
      const state = active;
      if (!state || state.closing) throw new Error("The materialized transaction snapshot is not open.");
      try {
        if (state.poisoned) throw new Error("poisoned");
        const request = exact(candidateRequest, ["snapshot", "datasetId", "pages"]);
        if (request.snapshot !== state.publicSnapshot) throw new Error("unexpected snapshot");
        const datasetId = requireDatasetId(request.datasetId);
        state.spool.verifyDatasetReplay({
          datasetId,
          pages: request.pages as OrganizationReconciliationDatasetReplayVerificationRequest<
            OrganizationReconciliationInventoryJsonValue
          >["pages"]
        });
        state.verifiedDatasetCount += 1;
      } catch {
        poisonActiveSnapshot(state);
        throw new Error("The materialized replay does not match its transaction-owned commitment.");
      }
    },
    closeSnapshot(snapshot: OrganizationReconciliationSourceSnapshot, outcome: "completed" | "failed") {
      const state = active;
      if (!state || snapshot !== state.publicSnapshot) {
        return Promise.reject(new Error("Closing an unexpected materialized transaction snapshot failed."));
      }
      if (state.closePromise) return state.closePromise;
      state.closing = true;
      state.closePromise = (async () => {
        const validOutcome = outcome === "completed" || outcome === "failed";
        const fullyReplayed = state.verifiedDatasetCount === state.datasetCount && !state.poisoned;
        const requestedCommit = validOutcome && outcome === "completed" && fullyReplayed;
        let spoolCommitted = false;
        let spoolCloseFailed = false;
        try {
          const spoolOutcome = await state.spool.close(requestedCommit ? "completed" : "failed");
          spoolCommitted = spoolOutcome === "completed";
        } catch {
          spoolCloseFailed = true;
        }
        // Raw COMMIT is attempted only after the spool has closed successfully
        // and proved complete. Every spool failure still reaches raw ROLLBACK.
        const rawOutcome = requestedCommit && spoolCommitted && !spoolCloseFailed ? "completed" : "failed";
        let rawCloseFailed = false;
        try {
          await state.rawSnapshot.close(rawOutcome);
        } catch {
          rawCloseFailed = true;
        } finally {
          active = null;
        }
        if (spoolCloseFailed || rawCloseFailed) {
          throw new Error("Closing the materialized transaction snapshot failed.");
        }
        if (!validOutcome) {
          throw new Error("The materialized transaction snapshot close outcome is invalid.");
        }
        if (outcome === "completed" && (!fullyReplayed || !spoolCommitted)) {
          throw new Error("The materialized transaction snapshot was not consumed completely.");
        }
      })();
      return state.closePromise;
    }
  };
  const frozenAdapter = Object.freeze(adapter);
  const provenance = Object.freeze({
    contract:
      ORGANIZATION_RECONCILIATION_MYSQL_TRANSACTION_DATASET_ADAPTER_FACTORY_PROVENANCE_CONTRACT,
    adapterContract: ORGANIZATION_RECONCILIATION_MYSQL_TRANSACTION_DATASET_ADAPTER_CONTRACT,
    trust: "factory-origin-only" as const,
    physicalSourceTrust: "unattested" as const,
    ownerCatalogTrust: ORGANIZATION_RECONCILIATION_DATASET_CATALOG_TRUST,
    componentId: options.componentId,
    expectedSourceId: options.expectedSourceId,
    declaredCatalogSha256: options.catalogSha256,
    structuralCatalogSha256: options.structuralCatalogSha256,
    datasetIds: Object.freeze(options.datasets.map((dataset) => dataset.datasetId)),
    datasetCatalog: options.datasetCatalog,
    statementCatalogSha256: ORGANIZATION_RECONCILIATION_MYSQL_STATEMENT_CATALOG_SHA256
  } satisfies OrganizationReconciliationMysqlTransactionDatasetAdapterFactoryProvenance);
  factoryProvenanceBrands.set(frozenAdapter, Object.freeze({
    provenance,
    adapterValues: Object.freeze({
      sourceId: frozenAdapter.sourceId,
      openSnapshot: frozenAdapter.openSnapshot,
      readSnapshotPage: frozenAdapter.readSnapshotPage,
      verifySnapshotDatasetReplay: frozenAdapter.verifySnapshotDatasetReplay,
      closeSnapshot: frozenAdapter.closeSnapshot
    }),
    canonicalCatalogJson: JSON.stringify(options.datasetCatalog)
  }));
  return frozenAdapter;
}

/**
 * Validates the exact factory-created object and its exact captured binding.
 * The returned metadata is descriptive only; cloning it never transfers the
 * private runtime brand held by this module.
 */
export function assertOrganizationReconciliationMysqlTransactionDatasetAdapterFactoryProvenance(
  candidateAdapter: unknown,
  candidateBinding: unknown
): OrganizationReconciliationMysqlTransactionDatasetAdapterFactoryProvenance {
  if (
    candidateAdapter === null ||
    typeof candidateAdapter !== "object" ||
    isProxy(candidateAdapter)
  ) {
    throw new Error("The transaction dataset adapter has no factory provenance.");
  }
  const brand = factoryProvenanceBrands.get(candidateAdapter);
  if (!brand) {
    throw new Error("The transaction dataset adapter has no factory provenance.");
  }
  const adapterValues = exact(candidateAdapter, [
    "sourceId",
    "openSnapshot",
    "readSnapshotPage",
    "verifySnapshotDatasetReplay",
    "closeSnapshot"
  ]);
  if (
    !Object.isFrozen(candidateAdapter) ||
    adapterValues.sourceId !== brand.adapterValues.sourceId ||
    adapterValues.openSnapshot !== brand.adapterValues.openSnapshot ||
    adapterValues.readSnapshotPage !== brand.adapterValues.readSnapshotPage ||
    adapterValues.verifySnapshotDatasetReplay !== brand.adapterValues.verifySnapshotDatasetReplay ||
    adapterValues.closeSnapshot !== brand.adapterValues.closeSnapshot
  ) {
    throw new Error("The transaction dataset adapter factory provenance changed.");
  }

  const binding = exact(candidateBinding, [
    "componentId", "expectedSourceId", "catalogSha256", "datasetCatalog"
  ]);
  const componentId = requireComponentId(binding.componentId);
  const expectedSourceId = requireMetadata(binding.expectedSourceId, "source ID");
  const declaredCatalogSha256 = requireSha256(binding.catalogSha256, "catalog digest");
  const datasetCatalog = captureDatasetCatalog(componentId, binding.datasetCatalog);
  const structuralCatalogSha256 = createStructuralCatalogSha256(datasetCatalog);
  if (
    componentId !== brand.provenance.componentId ||
    expectedSourceId !== brand.provenance.expectedSourceId ||
    declaredCatalogSha256 !== brand.provenance.declaredCatalogSha256 ||
    structuralCatalogSha256 !== brand.provenance.structuralCatalogSha256 ||
    JSON.stringify(datasetCatalog) !== brand.canonicalCatalogJson ||
    brand.provenance.statementCatalogSha256 !==
      ORGANIZATION_RECONCILIATION_MYSQL_STATEMENT_CATALOG_SHA256
  ) {
    throw new Error("The transaction dataset adapter does not match its factory binding.");
  }
  return brand.provenance;
}

interface ValidatedOptions {
  readonly componentId: OrganizationReconciliationMysqlRawComponentId;
  readonly expectedSourceId: string;
  readonly connectionFactory: MysqlRepeatableReadSnapshotConnectionFactory;
  readonly evidenceNonce: string;
  readonly catalogSha256: string;
  readonly structuralCatalogSha256: string;
  readonly datasetCatalog: OrganizationReconciliationDatasetCatalog;
  readonly datasets: readonly OrganizationReconciliationDatasetSpec[];
}

function validateOptions(candidate: unknown): ValidatedOptions {
  const options = exact(candidate, [
    "componentId", "expectedSourceId", "connectionFactory", "evidenceNonce", "catalogSha256", "datasetCatalog"
  ]);
  if (options.componentId !== "legacy-main" && options.componentId !== "identity" && options.componentId !== "plugin") {
    throw new Error("A materialized dataset component ID is invalid.");
  }
  if (typeof options.connectionFactory !== "function") throw new Error("A reviewed connection factory is required.");
  const expectedSourceId = requireMetadata(options.expectedSourceId, "source ID");
  if (typeof options.evidenceNonce !== "string" || !/^[a-f0-9]{32,128}$/i.test(options.evidenceNonce)) {
    throw new Error("A high-entropy evidence nonce is required.");
  }
  const catalogSha256 = requireSha256(options.catalogSha256, "catalog digest");
  const datasetCatalog = captureDatasetCatalog(options.componentId, options.datasetCatalog);
  const datasets = datasetCatalog.datasets;
  return Object.freeze({
    componentId: options.componentId,
    expectedSourceId,
    connectionFactory: options.connectionFactory as MysqlRepeatableReadSnapshotConnectionFactory,
    evidenceNonce: options.evidenceNonce,
    catalogSha256,
    structuralCatalogSha256: createStructuralCatalogSha256(datasetCatalog),
    datasetCatalog,
    datasets
  });
}

function captureDatasetCatalog(
  componentId: OrganizationReconciliationMysqlRawComponentId,
  candidate: unknown
): OrganizationReconciliationDatasetCatalog {
  const catalog = exact(candidate, ["contract", "trust", "datasets"]);
  if (catalog.contract !== ORGANIZATION_RECONCILIATION_DATASET_LINEAGE_CONTRACT ||
    catalog.trust !== ORGANIZATION_RECONCILIATION_DATASET_CATALOG_TRUST) {
    throw new Error("The structural dataset catalog is invalid.");
  }
  const capturedDatasets = safeArray(catalog.datasets, "structural dataset catalog", 1, 64);
  const datasets = capturedDatasets.map((value) => {
    const spec = exact(value, ["datasetId", "pageSize", "maxPages", "maxRecords"]);
    return Object.freeze({
      datasetId: requireDatasetId(spec.datasetId),
      pageSize: requireBound(spec.pageSize, 1, 5_000, "page size"),
      maxPages: requireBound(spec.maxPages, 1, 10_000, "page count"),
      maxRecords: requireBound(spec.maxRecords, 0, 10_000_000, "record count")
    });
  }).sort((left, right) => left.datasetId < right.datasetId ? -1 : left.datasetId > right.datasetId ? 1 : 0);
  const requiredDatasets = COMPONENT_DATASETS[componentId];
  if (datasets.map((dataset) => dataset.datasetId).join("\u001f") !== requiredDatasets.join("\u001f")) {
    throw new Error("The structural dataset catalog does not cover the fixed component datasets.");
  }
  if (datasets.reduce((sum, dataset) => sum + dataset.maxPages, 0) > MAX_COMPONENT_PAGES ||
    datasets.reduce((sum, dataset) => sum + dataset.maxRecords, 0) > MAX_COMPONENT_RECORDS) {
    throw new Error("The structural dataset catalog exceeds its aggregate component bound.");
  }
  return Object.freeze({
    contract: ORGANIZATION_RECONCILIATION_DATASET_LINEAGE_CONTRACT,
    trust: ORGANIZATION_RECONCILIATION_DATASET_CATALOG_TRUST,
    datasets: Object.freeze(datasets)
  });
}

function createStructuralCatalogSha256(catalog: OrganizationReconciliationDatasetCatalog): string {
  return createHash("sha256")
    .update(STRUCTURAL_CATALOG_HASH_DOMAIN)
    .update(JSON.stringify(catalog), "utf8")
    .digest("hex");
}

async function openRawSnapshot(options: ValidatedOptions): Promise<RawSnapshot> {
  const dependencies = {
    expectedSourceId: options.expectedSourceId,
    connectionFactory: options.connectionFactory
  };
  switch (options.componentId) {
    case "legacy-main": return openLegacyMainMysqlRawSnapshot(dependencies);
    case "identity": return openIdentityMysqlRawSnapshot(dependencies);
    case "plugin": return openPluginRegistryMysqlRawSnapshot(dependencies);
  }
}

async function spoolRawDataset(
  rawSnapshot: RawSnapshot,
  spec: OrganizationReconciliationDatasetSpec,
  spool: OrganizationReconciliationTransactionDatasetSpool,
  componentId: OrganizationReconciliationMysqlRawComponentId
): Promise<void> {
  let requestCursor: string | null = null;
  let recordCount = 0;
  let pageCount = 0;
  while (true) {
    if (pageCount >= spec.maxPages) throw new Error("A raw dataset exceeded its page bound.");
    const rawPage = await readRawPage(rawSnapshot, spec.datasetId, requestCursor, spec.pageSize);
    if (rawPage.requestCursor !== requestCursor || rawPage.recordOffset !== recordCount ||
      rawPage.records.length > spec.pageSize || rawPage.surface !== spec.datasetId) {
      throw new Error("A raw dataset page is not contiguous.");
    }
    const records = rawPage.records as unknown as readonly OrganizationReconciliationInventoryJsonValue[];
    await spool.appendPage({
      datasetId: spec.datasetId,
      requestCursor: rawPage.requestCursor,
      nextCursor: rawPage.nextCursor,
      recordOffset: rawPage.recordOffset,
      records
    });
    if (isSubjectUniverseDataset(componentId, spec.datasetId)) {
      await spool.appendSubjectUniversePage({
        datasetId: spec.datasetId,
        recordOffset: rawPage.recordOffset,
        subjectRefs: projectSubjectRefsFromRawPage(componentId, rawPage.records)
      });
    }
    pageCount += 1;
    recordCount += records.length;
    if (rawPage.nextCursor === null) break;
    requestCursor = rawPage.nextCursor;
  }
}

function isSubjectUniverseDataset(
  componentId: OrganizationReconciliationMysqlRawComponentId,
  datasetId: string
): boolean {
  return (componentId === "legacy-main" && datasetId === "legacy-subject-universe") ||
    (componentId === "identity" && datasetId === "identity-subject-universe");
}

function projectSubjectRefsFromRawPage(
  componentId: OrganizationReconciliationMysqlRawComponentId,
  candidateRecords: unknown
): readonly string[] {
  if (componentId === "plugin") throw new Error("The plugin component has no subject-universe projection.");
  const records = safeArray(candidateRecords, "subject-universe raw page", 0, 5_000);
  return Object.freeze(records.map((candidate) => {
    const row = exact(candidate, componentId === "legacy-main" ?
      ["legacyUserId", "status"] : ["legacyUserId", "status", "source"]);
    return subjectRefForLegacyUserId(row.legacyUserId as string);
  }));
}

function readRawPage(
  snapshot: RawSnapshot,
  datasetId: string,
  requestCursor: string | null,
  pageSize: number
): Promise<RawPage> {
  const request = { requestCursor, pageSize };
  if (snapshot.metadata.componentId === "legacy-main") {
    const legacy = snapshot as LegacyMainMysqlRawSnapshot;
    switch (datasetId) {
      case "legacy-membership": return legacy.readMembershipPage(request) as Promise<RawPage>;
      case "legacy-organization-directory": return legacy.readOrganizationDirectoryPage(request) as Promise<RawPage>;
      case "legacy-role-assignment": return legacy.readRoleAssignmentPage(request) as Promise<RawPage>;
      case "legacy-subject-universe": return legacy.readSubjectUniversePage(request) as Promise<RawPage>;
    }
  } else if (snapshot.metadata.componentId === "identity") {
    const identity = snapshot as IdentityMysqlRawSnapshot;
    switch (datasetId) {
      case "identity-membership-candidate": return identity.readMembershipCandidatePage(request) as Promise<RawPage>;
      case "identity-membership-shadow": return identity.readMembershipShadowPage(request) as Promise<RawPage>;
      case "identity-organization-candidate": return identity.readOrganizationCandidatePage(request) as Promise<RawPage>;
      case "identity-organization-id-map": return identity.readOrganizationIdMapPage(request) as Promise<RawPage>;
      case "identity-role-shadow": return identity.readRoleShadowPage(request) as Promise<RawPage>;
      case "identity-subject-universe": return identity.readSubjectUniversePage(request) as Promise<RawPage>;
    }
  } else if (datasetId === "plugin-registry") {
    return (snapshot as PluginRegistryMysqlRawSnapshot).readPluginRegistryPage(request) as Promise<RawPage>;
  }
  return Promise.reject(new Error("The fixed raw dataset is unavailable."));
}

function validateReadRequest(candidate: unknown): OrganizationReconciliationDatasetPageRequest {
  const request = exact(candidate, ["snapshot", "datasetId", "requestCursor", "pageSize"]);
  if (request.requestCursor !== null && (typeof request.requestCursor !== "string" || request.requestCursor.length < 1)) {
    throw new Error("A materialized dataset cursor is invalid.");
  }
  return {
    snapshot: request.snapshot as OrganizationReconciliationSourceSnapshot,
    datasetId: requireDatasetId(request.datasetId),
    requestCursor: request.requestCursor as string | null,
    pageSize: requireBound(request.pageSize, 1, 5_000, "page size")
  };
}

function poisonActiveSnapshot(state: ActiveSnapshot): void {
  state.poisoned = true;
}

function safeArray(candidate: unknown, label: string, minimum: number, maximum: number): readonly unknown[] {
  if (!Array.isArray(candidate) || isProxy(candidate) || Object.getPrototypeOf(candidate) !== Array.prototype ||
    Object.getOwnPropertySymbols(candidate).length > 0) {
    throw new Error(`The ${label} is invalid.`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(candidate);
  const lengthDescriptor = descriptors["length"] as PropertyDescriptor | undefined;
  if (!lengthDescriptor || !("value" in lengthDescriptor) || typeof lengthDescriptor.value !== "number" ||
    !Number.isSafeInteger(lengthDescriptor.value) || lengthDescriptor.value < minimum ||
    lengthDescriptor.value > maximum) {
    throw new Error(`The ${label} is sparse or unbounded.`);
  }
  const length = lengthDescriptor.value;
  if (Object.keys(descriptors).length !== length + 1) {
    throw new Error(`The ${label} has sparse, hidden, or extra fields.`);
  }
  const values: unknown[] = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) {
      throw new Error(`The ${label} contains an accessor or sparse entry.`);
    }
    values.push(descriptor.value);
  }
  return Object.freeze(values);
}

function exact(candidate: unknown, keys: readonly string[]): Record<string, unknown> {
  if (!candidate || typeof candidate !== "object" || Array.isArray(candidate) ||
    isProxy(candidate) ||
    (Object.getPrototypeOf(candidate) !== Object.prototype && Object.getPrototypeOf(candidate) !== null) ||
    Object.getOwnPropertySymbols(candidate).length > 0) throw new Error("Materialized dataset configuration is invalid.");
  const descriptors = Object.getOwnPropertyDescriptors(candidate);
  if (Object.keys(descriptors).sort().join("\u001f") !== [...keys].sort().join("\u001f")) {
    throw new Error("Materialized dataset configuration has missing or unknown fields.");
  }
  const output: Record<string, unknown> = {};
  for (const key of keys) {
    const descriptor = descriptors[key]!;
    if (!descriptor.enumerable || !("value" in descriptor)) throw new Error("Materialized dataset configuration has an accessor.");
    output[key] = descriptor.value;
  }
  return output;
}

function requireMetadata(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length < 1 || value.length > 1_024 || value.trim() !== value ||
    value.normalize("NFC") !== value || /[\u0000-\u001f\u007f]/u.test(value)) throw new Error(`The ${label} is invalid.`);
  return value;
}

function requireComponentId(value: unknown): OrganizationReconciliationMysqlRawComponentId {
  if (value !== "legacy-main" && value !== "identity" && value !== "plugin") {
    throw new Error("A materialized dataset component ID is invalid.");
  }
  return value;
}

function requireDatasetId(value: unknown): string {
  if (typeof value !== "string" || !/^[a-z0-9][a-z0-9-]{0,127}$/.test(value)) {
    throw new Error("The dataset ID is invalid.");
  }
  return value;
}

function requireSha256(value: unknown, label: string): string {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) throw new Error(`The ${label} is invalid.`);
  return value;
}

function requireBound(value: unknown, minimum: number, maximum: number, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    throw new Error(`The ${label} is invalid.`);
  }
  return value as number;
}
