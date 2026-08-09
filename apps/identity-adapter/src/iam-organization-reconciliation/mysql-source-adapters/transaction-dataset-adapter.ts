import { randomBytes } from "node:crypto";
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
  createOrganizationReconciliationComponentDatasetInventory,
  createOrganizationReconciliationContentSnapshotId,
  createOrganizationReconciliationContentSourceVersion,
  type OrganizationReconciliationInventoryJsonValue
} from "../../iam-organization-reconciliation-dataset-inventory.js";
import {
  createOrganizationReconciliationEvidenceHash
} from "../../iam-organization-reconciliation-validator.js";
import { subjectRefForLegacyUserId } from "../../iam-organization-reconciliation-refs.js";
import type { MysqlRepeatableReadSnapshotConnectionFactory } from "../mysql-repeatable-read-snapshot.js";
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
/** Owner catalogs and reviewed physical runtime bindings remain deliberately absent. */
export const ORGANIZATION_RECONCILIATION_MYSQL_TRANSACTION_DATASET_ADAPTER_READY = false as const;

export interface OrganizationReconciliationMysqlTransactionDatasetAdapterReadiness {
  readonly ready: false;
  readonly blockers: readonly [
    "compiled-owner-dataset-catalog-not-registered",
    "trusted-physical-source-binding-not-registered",
    "identity-source-status-semantics-not-owner-approved",
    "identity-shadow-versus-candidate-read-model-not-owner-approved",
    "plugin-registry-and-static-overlay-contract-not-owner-approved",
    "mysql-collation-and-unique-order-contract-not-owner-approved",
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

interface CachedPage {
  readonly requestCursor: string | null;
  readonly nextCursor: string | null;
  readonly recordOffset: number;
  readonly records: readonly OrganizationReconciliationInventoryJsonValue[];
}

interface CachedDataset {
  readonly spec: OrganizationReconciliationDatasetSpec;
  readonly pages: readonly CachedPage[];
  readonly recordCount: number;
  readonly byteCount: number;
  expectedCursor: string | null;
  replayPageIndex: number;
  exhausted: boolean;
  verified: boolean;
}

interface ActiveSnapshot {
  readonly publicSnapshot: Readonly<OrganizationReconciliationSourceSnapshot>;
  readonly rawSnapshot: RawSnapshot;
  readonly datasets: ReadonlyMap<string, CachedDataset>;
  readonly commitmentKey: Buffer;
  poisoned: boolean;
  closing: boolean;
  closePromise: Promise<void> | null;
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
const MAX_COMPONENT_CACHED_BYTES = 64 * 1024 * 1024;
const MAX_COMPONENT_PAGES = 10_000;
const MAX_COMPONENT_RECORDS = 10_000_000;

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
      try {
        rawSnapshot = await openRawSnapshot(options);
        commitmentKey = randomBytes(32);
        const datasets = new Map<string, CachedDataset>();
        let componentByteCount = 0;
        for (const spec of options.datasets) {
          const cached = await scanDataset(
            rawSnapshot,
            spec,
            MAX_COMPONENT_CACHED_BYTES - componentByteCount
          );
          componentByteCount += cached.byteCount;
          if (componentByteCount > MAX_COMPONENT_CACHED_BYTES) {
            throw new Error("The materialized component exceeds its cache byte bound.");
          }
          datasets.set(spec.datasetId, cached);
        }
        const inventory = createOrganizationReconciliationComponentDatasetInventory({
          componentId: options.componentId,
          sourceId: options.expectedSourceId,
          catalogSha256: options.catalogSha256,
          datasets: [...datasets.entries()].map(([datasetId, dataset]) => ({ datasetId, pages: dataset.pages })),
          commitmentKey
        });
        const subjectUniverse = createSubjectUniverse(
          options.componentId,
          datasets,
          options.evidenceNonce
        );
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
          publicSnapshot, rawSnapshot, datasets, commitmentKey, poisoned: false, closing: false, closePromise: null
        };
        return publicSnapshot;
      } catch {
        // Best-effort overwrite only; JavaScript runtimes do not guarantee strong memory erasure.
        commitmentKey?.fill(0);
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
      const dataset = state.datasets.get(request.datasetId);
      if (!dataset || request.pageSize !== dataset.spec.pageSize || dataset.exhausted ||
        request.requestCursor !== dataset.expectedCursor) {
        throw new Error("The materialized dataset cursor chain is invalid.");
      }
      const page = dataset.pages[dataset.replayPageIndex];
      if (!page || page.requestCursor !== request.requestCursor) {
        throw new Error("The materialized dataset page is unavailable.");
      }
      dataset.replayPageIndex += 1;
      dataset.expectedCursor = page.nextCursor;
      dataset.exhausted = page.nextCursor === null;
      const snapshot = state.publicSnapshot;
      return Object.freeze({
        sourceId: snapshot.sourceId,
        sourceVersion: snapshot.sourceVersion,
        snapshotId: snapshot.snapshotId,
        snapshotRecordCount: snapshot.recordCount,
        subjectUniverseCount: snapshot.subjectUniverseCount,
        subjectUniverseHash: snapshot.subjectUniverseHash,
        datasetId: request.datasetId,
        datasetRecordCount: dataset.recordCount,
        requestCursor: page.requestCursor,
        nextCursor: page.nextCursor,
        recordOffset: page.recordOffset,
        records: page.records
      } satisfies OrganizationReconciliationDatasetPage<OrganizationReconciliationInventoryJsonValue>);
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
        const dataset = state.datasets.get(datasetId);
        if (!dataset || dataset.verified || !dataset.exhausted || dataset.replayPageIndex !== dataset.pages.length) {
          throw new Error("not consumable");
        }
        const observed = createOrganizationReconciliationComponentDatasetInventory({
          componentId: options.componentId,
          sourceId: options.expectedSourceId,
          catalogSha256: options.catalogSha256,
          datasets: [{
          datasetId,
          pages: request.pages as OrganizationReconciliationDatasetReplayVerificationRequest<
            OrganizationReconciliationInventoryJsonValue
          >["pages"]
          }],
          commitmentKey: state.commitmentKey
        }).datasets[0]!;
        const expected = state.publicSnapshot.datasetInventory!.datasets.find((entry) => entry.datasetId === datasetId);
        if (!expected || observed.lineageSha256 !== expected.lineageSha256) {
          throw new Error("commitment mismatch");
        }
        dataset.verified = true;
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
        // This full-set gate is what prevents a partial dataset replay from committing.
        const fullyReplayed = [...state.datasets.values()].every((dataset) =>
          dataset.exhausted && dataset.replayPageIndex === dataset.pages.length && dataset.verified
        ) && !state.poisoned;
        const acceptedOutcome = validOutcome && outcome === "completed" && fullyReplayed ? "completed" : "failed";
        // Best-effort overwrite before the first close await; strong erasure is not guaranteed by JavaScript.
        state.commitmentKey.fill(0);
        try {
          await state.rawSnapshot.close(acceptedOutcome);
        } catch {
          throw new Error("Closing the materialized transaction snapshot failed.");
        } finally {
          active = null;
        }
        if (!validOutcome) {
          throw new Error("The materialized transaction snapshot close outcome is invalid.");
        }
        if (outcome === "completed" && !fullyReplayed) {
          throw new Error("The materialized transaction snapshot was not consumed completely.");
        }
      })();
      return state.closePromise;
    }
  };
  return Object.freeze(adapter);
}

interface ValidatedOptions {
  readonly componentId: OrganizationReconciliationMysqlRawComponentId;
  readonly expectedSourceId: string;
  readonly connectionFactory: MysqlRepeatableReadSnapshotConnectionFactory;
  readonly evidenceNonce: string;
  readonly catalogSha256: string;
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
  const catalog = exact(options.datasetCatalog, ["contract", "trust", "datasets"]);
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
  const requiredDatasets = COMPONENT_DATASETS[options.componentId];
  if (datasets.map((dataset) => dataset.datasetId).join("\u001f") !== requiredDatasets.join("\u001f")) {
    throw new Error("The structural dataset catalog does not cover the fixed component datasets.");
  }
  if (datasets.reduce((sum, dataset) => sum + dataset.maxPages, 0) > MAX_COMPONENT_PAGES ||
    datasets.reduce((sum, dataset) => sum + dataset.maxRecords, 0) > MAX_COMPONENT_RECORDS) {
    throw new Error("The structural dataset catalog exceeds its aggregate component bound.");
  }
  return Object.freeze({
    componentId: options.componentId,
    expectedSourceId,
    connectionFactory: options.connectionFactory as MysqlRepeatableReadSnapshotConnectionFactory,
    evidenceNonce: options.evidenceNonce,
    catalogSha256,
    datasets: Object.freeze(datasets)
  });
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

async function scanDataset(
  rawSnapshot: RawSnapshot,
  spec: OrganizationReconciliationDatasetSpec,
  remainingSerializedByteBudget: number
): Promise<CachedDataset> {
  const pages: CachedPage[] = [];
  let requestCursor: string | null = null;
  let recordCount = 0;
  let byteCount = 0;
  const observedCursors = new Set<string>();
  while (true) {
    if (pages.length >= spec.maxPages) throw new Error("A raw dataset exceeded its page bound.");
    const rawPage = await readRawPage(rawSnapshot, spec.datasetId, requestCursor, spec.pageSize);
    if (rawPage.requestCursor !== requestCursor || rawPage.recordOffset !== recordCount ||
      rawPage.records.length > spec.pageSize || rawPage.surface !== spec.datasetId) {
      throw new Error("A raw dataset page is not contiguous.");
    }
    const records = rawPage.records as unknown as readonly OrganizationReconciliationInventoryJsonValue[];
    const serialized = JSON.stringify(records);
    byteCount += Buffer.byteLength(serialized, "utf8");
    // Serialized bytes are bounded here; this is not a JavaScript heap bound.
    if (byteCount > remainingSerializedByteBudget) {
      throw new Error("A raw dataset exceeded its remaining component serialized-byte budget.");
    }
    recordCount += records.length;
    if (recordCount > spec.maxRecords) throw new Error("A raw dataset exceeded its record bound.");
    pages.push(Object.freeze({
      requestCursor: rawPage.requestCursor,
      nextCursor: rawPage.nextCursor,
      recordOffset: rawPage.recordOffset,
      records
    }));
    if (rawPage.nextCursor === null) break;
    if (records.length < spec.pageSize) {
      throw new Error("A raw dataset page is short before its terminal cursor.");
    }
    if (observedCursors.has(rawPage.nextCursor)) {
      throw new Error("A raw dataset cursor chain repeated or made no progress.");
    }
    observedCursors.add(rawPage.nextCursor);
    requestCursor = rawPage.nextCursor;
  }
  return {
    spec,
    pages: Object.freeze(pages),
    recordCount,
    byteCount,
    expectedCursor: null,
    replayPageIndex: 0,
    exhausted: false,
    verified: false
  };
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

function createSubjectUniverse(
  componentId: OrganizationReconciliationMysqlRawComponentId,
  datasets: ReadonlyMap<string, CachedDataset>,
  evidenceNonce: string
): { readonly count: number; readonly hash: string } {
  if (componentId === "plugin") return { count: 0, hash: "" };
  const datasetId = componentId === "legacy-main" ? "legacy-subject-universe" : "identity-subject-universe";
  const dataset = datasets.get(datasetId);
  if (!dataset) throw new Error("The complete subject universe dataset is missing.");
  const subjectRefs = dataset.pages.flatMap((page) => page.records.map((record) => {
    if (!record || typeof record !== "object" || Array.isArray(record)) {
      throw new Error("A subject universe row is invalid.");
    }
    return subjectRefForLegacyUserId((record as { legacyUserId?: string }).legacyUserId!);
  }));
  const unique = new Set(subjectRefs);
  if (unique.size !== subjectRefs.length || subjectRefs.length < 1) {
    throw new Error("The complete subject universe is empty or duplicate.");
  }
  const sorted = [...subjectRefs].sort();
  return {
    count: sorted.length,
    hash: createOrganizationReconciliationEvidenceHash(evidenceNonce, sorted)
  };
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
  // Best-effort overwrite only; JavaScript runtimes do not guarantee strong memory erasure.
  state.commitmentKey.fill(0);
}

function safeArray(candidate: unknown, label: string, minimum: number, maximum: number): readonly unknown[] {
  if (!Array.isArray(candidate) || Object.getPrototypeOf(candidate) !== Array.prototype ||
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
  const expectedNames = new Set(["length", ...Array.from({ length }, (_, index) => String(index))]);
  if (Object.keys(descriptors).length !== expectedNames.size ||
    Object.keys(descriptors).some((name) => !expectedNames.has(name))) {
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
