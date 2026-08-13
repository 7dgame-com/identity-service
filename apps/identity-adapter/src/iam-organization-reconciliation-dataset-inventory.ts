import { createHash, createHmac } from "node:crypto";
import { isProxy } from "node:util/types";

export const ORGANIZATION_RECONCILIATION_DATASET_INVENTORY_CONTRACT =
  "iam-organization-reconciliation-dataset-inventory/v2" as const;
export const ORGANIZATION_RECONCILIATION_RECORD_COMMITMENT_SCHEME =
  "hmac-sha256-run-secret/v1" as const;
export const ORGANIZATION_RECONCILIATION_INCREMENTAL_DATASET_INVENTORY_BUILDER_CONTRACT =
  "iam-organization-reconciliation-incremental-dataset-inventory-builder/v1" as const;

export type OrganizationReconciliationInventoryJsonValue =
  | null | boolean | number | string
  | readonly OrganizationReconciliationInventoryJsonValue[]
  | { readonly [key: string]: OrganizationReconciliationInventoryJsonValue };

export interface OrganizationReconciliationDatasetInventoryPage {
  readonly pageNumber: number;
  readonly requestCursorCommitment: string | null;
  readonly nextCursorCommitment: string | null;
  readonly recordOffset: number;
  readonly recordCount: number;
  /** Run-specific HMAC commitment, never a stable raw-record digest. */
  readonly recordsCommitment: string;
}

export interface OrganizationReconciliationDatasetInventoryEntry {
  readonly datasetId: string;
  readonly recordCount: number;
  /** Run-specific HMAC commitment, never a stable raw-record digest. */
  readonly recordsCommitment: string;
  readonly pageCount: number;
  readonly pages: readonly OrganizationReconciliationDatasetInventoryPage[];
  readonly lineageSha256: string;
}

export interface OrganizationReconciliationComponentDatasetInventory {
  readonly contract: typeof ORGANIZATION_RECONCILIATION_DATASET_INVENTORY_CONTRACT;
  readonly recordCommitmentScheme: typeof ORGANIZATION_RECONCILIATION_RECORD_COMMITMENT_SCHEME;
  readonly componentId: string;
  readonly sourceId: string;
  readonly catalogSha256: string;
  readonly recordCount: number;
  readonly datasets: readonly OrganizationReconciliationDatasetInventoryEntry[];
  readonly inventorySha256: string;
}

export interface OrganizationReconciliationDatasetInventoryPageInput {
  readonly requestCursor: string | null;
  readonly nextCursor: string | null;
  readonly recordOffset: number;
  readonly records: readonly OrganizationReconciliationInventoryJsonValue[];
}

export interface OrganizationReconciliationDatasetInventoryInput {
  readonly datasetId: string;
  readonly pages: readonly OrganizationReconciliationDatasetInventoryPageInput[];
}

export interface CreateOrganizationReconciliationComponentDatasetInventoryOptions {
  readonly componentId: string;
  readonly sourceId: string;
  readonly catalogSha256: string;
  readonly datasets: readonly OrganizationReconciliationDatasetInventoryInput[];
  readonly commitmentKey: Buffer;
}

export interface CreateOrganizationReconciliationIncrementalDatasetInventoryBuilderOptions {
  readonly componentId: string;
  readonly sourceId: string;
  readonly catalogSha256: string;
  readonly commitmentKey: Buffer;
}

export interface OrganizationReconciliationIncrementalDatasetInventoryPageInput {
  readonly datasetId: string;
  readonly datasetRecordCount: number;
  readonly datasetPageCount: number;
  readonly pageNumber: number;
  readonly requestCursor: string | null;
  readonly nextCursor: string | null;
  readonly recordOffset: number;
  readonly records: readonly OrganizationReconciliationInventoryJsonValue[];
}

export interface OrganizationReconciliationIncrementalDatasetInventoryAppendResult {
  readonly page: OrganizationReconciliationDatasetInventoryPage;
  readonly completedDataset?: OrganizationReconciliationDatasetInventoryEntry;
}

/**
 * Opaque one-shot structural commitment builder. Its brand proves only that
 * this module computed the v2 tuples; it says nothing about source trust.
 */
export interface OrganizationReconciliationIncrementalDatasetInventoryBuilder {
  readonly contract:
    typeof ORGANIZATION_RECONCILIATION_INCREMENTAL_DATASET_INVENTORY_BUILDER_CONTRACT;
  appendPage(
    this: OrganizationReconciliationIncrementalDatasetInventoryBuilder,
    page: OrganizationReconciliationIncrementalDatasetInventoryPageInput
  ): OrganizationReconciliationIncrementalDatasetInventoryAppendResult;
  seal(
    this: OrganizationReconciliationIncrementalDatasetInventoryBuilder
  ): OrganizationReconciliationComponentDatasetInventory;
  abort(this: OrganizationReconciliationIncrementalDatasetInventoryBuilder): void;
}

/**
 * Transport-only one-page codec. It creates no commitment and conveys no
 * source trust. The caller owns the returned Buffer and must fill(0) it in a
 * finally block after the write attempt.
 */
export function encodeOrganizationReconciliationInventoryPageRecords(
  candidate: unknown,
  maximumRecords: number,
  maximumBytes: number
): Buffer {
  const captured = captureInventoryPageRecords(candidate, maximumRecords, maximumBytes);
  return Buffer.from(captured.serialized, "utf8");
}

/** Decodes only the exact canonical bytes accepted by the transport-only encoder above. */
export function decodeOrganizationReconciliationInventoryPageRecords(
  candidate: Buffer,
  maximumRecords: number,
  maximumBytes: number
): readonly OrganizationReconciliationInventoryJsonValue[] {
  if (!Buffer.isBuffer(candidate) || candidate.byteLength < 2 || candidate.byteLength > maximumBytes) {
    throw new DatasetInventoryFailure("The page record transport frame is invalid.");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(candidate.toString("utf8"));
  } catch {
    throw new DatasetInventoryFailure("The page record transport frame is invalid.");
  }
  const captured = captureInventoryPageRecords(parsed, maximumRecords, maximumBytes);
  const canonical = Buffer.from(captured.serialized, "utf8");
  try {
    if (!candidate.equals(canonical)) {
      throw new DatasetInventoryFailure("The page record transport frame is not canonical.");
    }
  } finally {
    canonical.fill(0);
  }
  return captured.records;
}

const CURSOR_DOMAIN = Buffer.from("iam-organization-reconciliation:inventory-cursor:v2\u001f", "utf8");
const PAGE_RECORDS_DOMAIN = Buffer.from("iam-organization-reconciliation:inventory-page-records:v2\u001f", "utf8");
const DATASET_RECORDS_DOMAIN = Buffer.from("iam-organization-reconciliation:inventory-dataset-records:v2\u001f", "utf8");
const LINEAGE_DOMAIN = Buffer.from("iam-organization-reconciliation:inventory-dataset-lineage:v2\u001f", "utf8");
const INVENTORY_DOMAIN = Buffer.from("iam-organization-reconciliation:component-inventory:v2\u001f", "utf8");
const MAX_COMPONENT_PAGES = 10_000;
const MAX_JSON_DEPTH = 64;
const MAX_JSON_NODES = 100_000;
const MAX_JSON_STRING_BYTES = 65_536;
const MAX_JSON_OBJECT_KEY_BYTES = 256;
const MAX_INCREMENTAL_PAGE_RECORDS = 5_000;
const MAX_INCREMENTAL_PAGE_CANONICAL_BYTES = 2 * 1024 * 1024;
const MAX_INCREMENTAL_COMPONENT_CANONICAL_BYTES = 64 * 1024 * 1024;
const MAX_INCREMENTAL_PAGE_JSON_NODES = 90_000;
const MAX_INCREMENTAL_COMPONENT_JSON_NODES = 1_000_000;

interface DatasetCommitmentWriter {
  readonly hmac: ReturnType<typeof createHmac>;
  firstRecord: boolean;
}

interface IncrementalDatasetState {
  readonly datasetId: string;
  readonly expectedRecordCount: number;
  readonly expectedPageCount: number;
  readonly pages: OrganizationReconciliationDatasetInventoryPage[];
  readonly recordsCommitment: DatasetCommitmentWriter;
  expectedRequestCursor: string | null;
  recordCount: number;
  nextPageNumber: number;
}

interface IncrementalBuilderState {
  phase: "appending" | "sealed" | "poisoned";
  readonly componentId: string;
  readonly sourceId: string;
  readonly catalogSha256: string;
  readonly commitmentKey: Buffer;
  readonly datasets: OrganizationReconciliationDatasetInventoryEntry[];
  readonly datasetIds: Set<string>;
  activeDataset: IncrementalDatasetState | null;
  totalPageCount: number;
  totalRecordCount: number;
  totalCanonicalBytes: number;
  totalCanonicalNodes: number;
  methods: {
    readonly appendPage: OrganizationReconciliationIncrementalDatasetInventoryBuilder["appendPage"];
    readonly seal: OrganizationReconciliationIncrementalDatasetInventoryBuilder["seal"];
    readonly abort: OrganizationReconciliationIncrementalDatasetInventoryBuilder["abort"];
  } | null;
}

const incrementalBuilderBrands = new WeakMap<object, IncrementalBuilderState>();

function captureInventoryPageRecords(
  candidate: unknown,
  maximumRecords: number,
  maximumBytes: number
): {
  readonly records: readonly OrganizationReconciliationInventoryJsonValue[];
  readonly serialized: string;
  readonly byteCount: number;
  readonly nodeCount: number;
} {
  const recordBound = requirePositiveCount(maximumRecords, MAX_INCREMENTAL_PAGE_RECORDS, "page record bound");
  const byteBound = requirePositiveCount(maximumBytes, MAX_INCREMENTAL_PAGE_CANONICAL_BYTES, "page byte bound");
  const rawRecords = safeArray(candidate, "page records", 0, recordBound);
  const jsonState = { nodes: 0 };
  const records = Object.freeze(rawRecords.map((record) =>
    canonicalize(record, new Set<object>(), jsonState, 0)
  ));
  if (jsonState.nodes > MAX_INCREMENTAL_PAGE_JSON_NODES) {
    throw new DatasetInventoryFailure("The page record transport frame exceeds its structural bound.");
  }
  const byteCount = canonicalJsonByteLength(records, byteBound);
  const serialized = canonicalJson(records);
  if (Buffer.byteLength(serialized, "utf8") !== byteCount) {
    throw new DatasetInventoryFailure("The page record transport frame is not canonical.");
  }
  return Object.freeze({ records, serialized, byteCount, nodeCount: jsonState.nodes });
}

export function createOrganizationReconciliationIncrementalDatasetInventoryBuilder(
  candidate: CreateOrganizationReconciliationIncrementalDatasetInventoryBuilderOptions
): OrganizationReconciliationIncrementalDatasetInventoryBuilder {
  const options = exact(candidate, ["componentId", "sourceId", "catalogSha256", "commitmentKey"]);
  const state: IncrementalBuilderState = {
    phase: "appending",
    componentId: requireDatasetId(options.componentId),
    sourceId: requireMetadata(options.sourceId, "source ID"),
    catalogSha256: requireSha256(options.catalogSha256, "dataset catalog digest"),
    commitmentKey: captureCommitmentKey(options.commitmentKey),
    datasets: [],
    datasetIds: new Set<string>(),
    activeDataset: null,
    totalPageCount: 0,
    totalRecordCount: 0,
    totalCanonicalBytes: 0,
    totalCanonicalNodes: 0,
    methods: null
  };

  const appendPage: OrganizationReconciliationIncrementalDatasetInventoryBuilder["appendPage"] =
    function (this: OrganizationReconciliationIncrementalDatasetInventoryBuilder, candidatePage) {
      const accepted = requireIncrementalBuilder(this, appendPage, "appendPage");
      try {
        return appendIncrementalPage(accepted, candidatePage);
      } catch (error) {
        poisonIncrementalBuilder(accepted);
        if (error instanceof DatasetInventoryFailure) throw error;
        throw new DatasetInventoryFailure("Appending incremental inventory content failed.");
      }
    };
  const seal: OrganizationReconciliationIncrementalDatasetInventoryBuilder["seal"] =
    function (this: OrganizationReconciliationIncrementalDatasetInventoryBuilder) {
      const accepted = requireIncrementalBuilder(this, seal, "seal");
      try {
        if (accepted.activeDataset !== null || accepted.datasets.length < 1) {
          throw new DatasetInventoryFailure("The incremental component inventory is incomplete.");
        }
        const datasets = Object.freeze([...accepted.datasets].sort(compareDatasetId));
        const body = Object.freeze({
          contract: ORGANIZATION_RECONCILIATION_DATASET_INVENTORY_CONTRACT,
          recordCommitmentScheme: ORGANIZATION_RECONCILIATION_RECORD_COMMITMENT_SCHEME,
          componentId: accepted.componentId,
          sourceId: accepted.sourceId,
          catalogSha256: accepted.catalogSha256,
          recordCount: accepted.totalRecordCount,
          datasets
        });
        const inventory = Object.freeze({
          ...body,
          inventorySha256: hash(INVENTORY_DOMAIN, body)
        });
        accepted.phase = "sealed";
        return inventory;
      } catch (error) {
        accepted.phase = "poisoned";
        accepted.activeDataset = null;
        if (error instanceof DatasetInventoryFailure) throw error;
        throw new DatasetInventoryFailure("Sealing incremental inventory content failed.");
      } finally {
        // Best-effort overwrite only; JavaScript/OpenSSL do not promise strong erasure.
        accepted.commitmentKey.fill(0);
      }
    };
  const abort: OrganizationReconciliationIncrementalDatasetInventoryBuilder["abort"] =
    function (this: OrganizationReconciliationIncrementalDatasetInventoryBuilder) {
      const accepted = requireIncrementalBuilder(this, abort, "abort");
      poisonIncrementalBuilder(accepted);
    };

  const builder = Object.freeze({
    contract: ORGANIZATION_RECONCILIATION_INCREMENTAL_DATASET_INVENTORY_BUILDER_CONTRACT,
    appendPage,
    seal,
    abort
  });
  state.methods = Object.freeze({ appendPage, seal, abort });
  incrementalBuilderBrands.set(builder, state);
  return builder;
}

function appendIncrementalPage(
  state: IncrementalBuilderState,
  candidate: OrganizationReconciliationIncrementalDatasetInventoryPageInput
): OrganizationReconciliationIncrementalDatasetInventoryAppendResult {
  const input = exact(candidate, [
    "datasetId", "datasetRecordCount", "datasetPageCount", "pageNumber", "requestCursor",
    "nextCursor", "recordOffset", "records"
  ]);
  const datasetId = requireDatasetId(input.datasetId);
  const datasetRecordCount = requireCount(input.datasetRecordCount, "dataset record count");
  const datasetPageCount = requirePositiveCount(input.datasetPageCount, MAX_COMPONENT_PAGES, "dataset page count");
  const pageNumber = requirePositiveCount(input.pageNumber, datasetPageCount, "dataset page number");
  const recordOffset = requireCount(input.recordOffset, "dataset record offset");
  const requestCursor = input.requestCursor === null ? null : requireCursor(input.requestCursor, "request cursor");
  const nextCursor = input.nextCursor === null ? null : requireCursor(input.nextCursor, "next cursor");
  const capturedRecords = captureInventoryPageRecords(
    input.records,
    MAX_INCREMENTAL_PAGE_RECORDS,
    MAX_INCREMENTAL_PAGE_CANONICAL_BYTES
  );
  const canonicalRecords = capturedRecords.records;
  const canonicalRecordBytes = capturedRecords.byteCount;
  if (
    state.totalCanonicalNodes + capturedRecords.nodeCount > MAX_INCREMENTAL_COMPONENT_JSON_NODES ||
    state.totalCanonicalBytes + canonicalRecordBytes > MAX_INCREMENTAL_COMPONENT_CANONICAL_BYTES
  ) {
    throw new DatasetInventoryFailure("The incremental canonical content exceeds its approved bound.");
  }

  let dataset = state.activeDataset;
  if (dataset === null) {
    if (state.datasetIds.has(datasetId)) {
      throw new DatasetInventoryFailure("The incremental component inventory is duplicate.");
    }
    if (state.datasets.length >= 64) {
      throw new DatasetInventoryFailure("The incremental component inventory exceeds its dataset bound.");
    }
    dataset = {
      datasetId,
      expectedRecordCount: datasetRecordCount,
      expectedPageCount: datasetPageCount,
      pages: [],
      recordsCommitment: startDatasetRecordsCommitment(
        state.commitmentKey,
        state.componentId,
        state.sourceId,
        state.catalogSha256,
        datasetId,
        datasetRecordCount
      ),
      expectedRequestCursor: null,
      recordCount: 0,
      nextPageNumber: 1
    };
    state.datasetIds.add(datasetId);
    state.activeDataset = dataset;
  }
  if (
    dataset.datasetId !== datasetId ||
    dataset.expectedRecordCount !== datasetRecordCount ||
    dataset.expectedPageCount !== datasetPageCount ||
    dataset.nextPageNumber !== pageNumber ||
    dataset.expectedRequestCursor !== requestCursor ||
    dataset.recordCount !== recordOffset
  ) {
    throw new DatasetInventoryFailure("The incremental dataset page lineage is discontinuous.");
  }
  const terminal = pageNumber === datasetPageCount;
  if ((terminal && nextCursor !== null) || (!terminal && nextCursor === null)) {
    throw new DatasetInventoryFailure("The incremental dataset page lineage is not terminal.");
  }
  if (dataset.recordCount + canonicalRecords.length > dataset.expectedRecordCount ||
    state.totalPageCount + 1 > MAX_COMPONENT_PAGES ||
    state.totalRecordCount + canonicalRecords.length > 10_000_000) {
    throw new DatasetInventoryFailure("The incremental component inventory exceeds its approved bound.");
  }

  const page = Object.freeze({
    pageNumber,
    requestCursorCommitment: commitCursor(
      state.commitmentKey, state.componentId, state.sourceId, state.catalogSha256, datasetId, requestCursor
    ),
    nextCursorCommitment: commitCursor(
      state.commitmentKey, state.componentId, state.sourceId, state.catalogSha256, datasetId, nextCursor
    ),
    recordOffset,
    recordCount: canonicalRecords.length,
    recordsCommitment: commitment(state.commitmentKey, PAGE_RECORDS_DOMAIN, {
      contract: ORGANIZATION_RECONCILIATION_DATASET_INVENTORY_CONTRACT,
      componentId: state.componentId,
      sourceId: state.sourceId,
      catalogSha256: state.catalogSha256,
      datasetId,
      pageNumber,
      requestCursor,
      nextCursor,
      recordOffset,
      recordCount: canonicalRecords.length,
      records: canonicalRecords
    })
  });
  for (const record of canonicalRecords) {
    appendDatasetCommitmentRecord(dataset.recordsCommitment, record);
  }
  dataset.pages.push(page);
  dataset.recordCount += canonicalRecords.length;
  dataset.nextPageNumber += 1;
  dataset.expectedRequestCursor = nextCursor;
  state.totalPageCount += 1;
  state.totalRecordCount += canonicalRecords.length;
  state.totalCanonicalBytes += canonicalRecordBytes;
  state.totalCanonicalNodes += capturedRecords.nodeCount;

  if (!terminal) return Object.freeze({ page });
  if (dataset.recordCount !== dataset.expectedRecordCount || dataset.pages.length !== dataset.expectedPageCount) {
    throw new DatasetInventoryFailure("The incremental dataset count is incomplete.");
  }
  const body = Object.freeze({
    datasetId,
    recordCount: dataset.recordCount,
    recordsCommitment: finishDatasetRecordsCommitment(dataset.recordsCommitment, state.sourceId),
    pageCount: dataset.pages.length,
    pages: Object.freeze([...dataset.pages])
  });
  const completedDataset = Object.freeze({ ...body, lineageSha256: hash(LINEAGE_DOMAIN, body) });
  state.datasets.push(completedDataset);
  state.activeDataset = null;
  return Object.freeze({ page, completedDataset });
}

function requireIncrementalBuilder(
  candidate: unknown,
  method: Function,
  operation: keyof NonNullable<IncrementalBuilderState["methods"]>
): IncrementalBuilderState {
  if (!candidate || typeof candidate !== "object" || isProxy(candidate) || !Object.isFrozen(candidate)) {
    throw new DatasetInventoryFailure("The incremental inventory builder is invalid.");
  }
  const state = incrementalBuilderBrands.get(candidate);
  if (!state || state.phase !== "appending" || state.methods?.[operation] !== method) {
    throw new DatasetInventoryFailure("The incremental inventory builder lifecycle is invalid.");
  }
  return state;
}

function poisonIncrementalBuilder(state: IncrementalBuilderState): void {
  state.phase = "poisoned";
  state.activeDataset = null;
  // Best-effort overwrite only; JavaScript/OpenSSL do not promise strong erasure.
  state.commitmentKey.fill(0);
}

export function createOrganizationReconciliationComponentDatasetInventory(
  candidate: CreateOrganizationReconciliationComponentDatasetInventoryOptions
): OrganizationReconciliationComponentDatasetInventory {
  const options = exact(candidate, ["componentId", "sourceId", "catalogSha256", "datasets", "commitmentKey"]);
  const componentId = requireDatasetId(options.componentId);
  const sourceId = requireMetadata(options.sourceId, "source ID");
  const catalogSha256 = requireSha256(options.catalogSha256, "dataset catalog digest");
  const capturedInputs = safeArray(options.datasets, "component datasets", 1, 64);
  const bounded = capturedInputs.map((candidateDataset) => {
    const input = exact(candidateDataset, ["datasetId", "pages"]);
    return Object.freeze({
      datasetId: requireDatasetId(input.datasetId),
      pages: safeArray(input.pages, "dataset pages", 1, MAX_COMPONENT_PAGES)
    });
  });
  if (bounded.reduce((sum, input) => sum + input.pages.length, 0) > MAX_COMPONENT_PAGES) {
    throw new DatasetInventoryFailure("The component dataset inventory exceeds its aggregate page bound.");
  }
  const captured = bounded.map(({ datasetId, pages: candidatePages }) => {
    let recordOffset = 0;
    const pages = candidatePages.map((candidatePage) => {
      const page = exact(candidatePage, ["requestCursor", "nextCursor", "recordOffset", "records"]);
      const records = safeArray(page.records, "page records", 0, 10_000_000);
      if (page.recordOffset !== recordOffset) {
        throw new DatasetInventoryFailure("A dataset page lineage is discontinuous.");
      }
      recordOffset += records.length;
      return Object.freeze({
        requestCursor: page.requestCursor,
        nextCursor: page.nextCursor,
        recordOffset: page.recordOffset as number,
        records
      });
    });
    return Object.freeze({
      datasetId,
      recordCount: recordOffset,
      pages: Object.freeze(pages)
    });
  });
  const builder = createOrganizationReconciliationIncrementalDatasetInventoryBuilder({
    componentId,
    sourceId,
    catalogSha256,
    commitmentKey: options.commitmentKey as Buffer
  });
  try {
    for (const dataset of captured) {
      for (let index = 0; index < dataset.pages.length; index += 1) {
        const page = dataset.pages[index]!;
        builder.appendPage({
          datasetId: dataset.datasetId,
          datasetRecordCount: dataset.recordCount,
          datasetPageCount: dataset.pages.length,
          pageNumber: index + 1,
          requestCursor: page.requestCursor as string | null,
          nextCursor: page.nextCursor as string | null,
          recordOffset: page.recordOffset,
          records: page.records as readonly OrganizationReconciliationInventoryJsonValue[]
        });
      }
    }
    return builder.seal();
  } catch (error) {
    try { builder.abort(); } catch { /* builder already poisoned */ }
    throw error;
  }
}

export function validateOrganizationReconciliationComponentDatasetInventory(
  candidate: unknown
): OrganizationReconciliationComponentDatasetInventory {
  const inventory = exact(candidate, [
    "contract", "recordCommitmentScheme", "componentId", "sourceId", "catalogSha256", "recordCount",
    "datasets", "inventorySha256"
  ]);
  if (inventory.contract !== ORGANIZATION_RECONCILIATION_DATASET_INVENTORY_CONTRACT ||
    inventory.recordCommitmentScheme !== ORGANIZATION_RECONCILIATION_RECORD_COMMITMENT_SCHEME) {
    throw new DatasetInventoryFailure("The component dataset inventory contract is invalid.");
  }
  const componentId = requireDatasetId(inventory.componentId);
  const sourceId = requireMetadata(inventory.sourceId, "source ID");
  const catalogSha256 = requireSha256(inventory.catalogSha256, "dataset catalog digest");
  const candidateDatasets = safeArray(inventory.datasets, "component datasets", 1, 64);
  const capturedDatasets = candidateDatasets.map((candidateDataset) => {
    const dataset = exact(candidateDataset, [
      "datasetId", "recordCount", "recordsCommitment", "pageCount", "pages", "lineageSha256"
    ]);
    const pages = safeArray(dataset.pages, "dataset pages", 1, MAX_COMPONENT_PAGES);
    return Object.freeze({ dataset, pages });
  });
  const capturedDatasetOrder = Object.freeze(capturedDatasets.map(({ dataset }) => dataset.datasetId));
  if (capturedDatasets.reduce((sum, value) => sum + value.pages.length, 0) > MAX_COMPONENT_PAGES) {
    throw new DatasetInventoryFailure("The component dataset inventory exceeds its aggregate page bound.");
  }
  const ids = new Set<string>();
  const datasets = capturedDatasets.map(({ dataset, pages: candidatePages }) => {
    const datasetId = requireDatasetId(dataset.datasetId);
    if (ids.has(datasetId)) throw new DatasetInventoryFailure("The component dataset inventory is duplicate.");
    ids.add(datasetId);
    const recordCount = requireCount(dataset.recordCount, "dataset record count");
    const pageCount = requireCount(dataset.pageCount, "dataset page count");
    if (pageCount !== candidatePages.length) {
      throw new DatasetInventoryFailure("A dataset page lineage count is invalid.");
    }
    let offset = 0;
    let previousNext: string | null = null;
    const pages = candidatePages.map((candidatePage, index) => {
      const page = exact(candidatePage, [
        "pageNumber", "requestCursorCommitment", "nextCursorCommitment", "recordOffset", "recordCount",
        "recordsCommitment"
      ]);
      const requestCursorCommitment = requireNullableSha256(page.requestCursorCommitment, "request cursor commitment");
      const nextCursorCommitment = requireNullableSha256(page.nextCursorCommitment, "next cursor commitment");
      const pageRecordCount = requireCount(page.recordCount, "page record count");
      if (page.pageNumber !== index + 1 || page.recordOffset !== offset ||
        requestCursorCommitment !== previousNext ||
        (index === candidatePages.length - 1 ? nextCursorCommitment !== null : nextCursorCommitment === null)) {
        throw new DatasetInventoryFailure("A dataset page lineage is discontinuous.");
      }
      offset += pageRecordCount;
      previousNext = nextCursorCommitment;
      return Object.freeze({
        pageNumber: index + 1,
        requestCursorCommitment,
        nextCursorCommitment,
        recordOffset: page.recordOffset as number,
        recordCount: pageRecordCount,
        recordsCommitment: requireSha256(page.recordsCommitment, "page records commitment")
      });
    });
    if (offset !== recordCount) throw new DatasetInventoryFailure("A dataset page lineage record count is invalid.");
    const body = Object.freeze({
      datasetId,
      recordCount,
      recordsCommitment: requireSha256(dataset.recordsCommitment, "dataset records commitment"),
      pageCount,
      pages: Object.freeze(pages)
    });
    const lineageSha256 = requireSha256(dataset.lineageSha256, "dataset lineage digest");
    if (lineageSha256 !== hash(LINEAGE_DOMAIN, body)) {
      throw new DatasetInventoryFailure("A dataset lineage digest does not match its canonical content.");
    }
    return Object.freeze({ ...body, lineageSha256 });
  }).sort(compareDatasetId);
  if (datasets.some((dataset, index) => dataset.datasetId !==
    capturedDatasetOrder[index])) {
    throw new DatasetInventoryFailure("The component dataset inventory is not canonically ordered.");
  }
  const recordCount = requireCount(inventory.recordCount, "component record count");
  if (datasets.reduce((sum, dataset) => sum + dataset.recordCount, 0) !== recordCount) {
    throw new DatasetInventoryFailure("The component dataset inventory aggregate count is invalid.");
  }
  const body = Object.freeze({
    contract: ORGANIZATION_RECONCILIATION_DATASET_INVENTORY_CONTRACT,
    recordCommitmentScheme: ORGANIZATION_RECONCILIATION_RECORD_COMMITMENT_SCHEME,
    componentId,
    sourceId,
    catalogSha256,
    recordCount,
    datasets: Object.freeze(datasets)
  });
  const inventorySha256 = requireSha256(inventory.inventorySha256, "component inventory digest");
  if (inventorySha256 !== hash(INVENTORY_DOMAIN, body)) {
    throw new DatasetInventoryFailure("The component inventory digest does not match its canonical content.");
  }
  return Object.freeze({ ...body, inventorySha256 });
}

export function createOrganizationReconciliationContentSourceVersion(
  sourceId: string,
  inventory: OrganizationReconciliationComponentDatasetInventory
): string {
  const canonical = validateOrganizationReconciliationComponentDatasetInventory(inventory);
  const acceptedSourceId = requireMetadata(sourceId, "source ID");
  if (canonical.sourceId !== acceptedSourceId) {
    throw new DatasetInventoryFailure("The inventory source binding is invalid.");
  }
  return hash(Buffer.from("iam-organization-reconciliation:content-source-version:v2\u001f", "utf8"), {
    sourceId: acceptedSourceId,
    componentId: canonical.componentId,
    catalogSha256: canonical.catalogSha256,
    recordCommitmentScheme: canonical.recordCommitmentScheme,
    recordCount: canonical.recordCount,
    datasets: canonical.datasets.map((dataset) => ({
      datasetId: dataset.datasetId,
      recordCount: dataset.recordCount,
      recordsCommitment: dataset.recordsCommitment
    }))
  });
}

export function createOrganizationReconciliationContentSnapshotId(
  sourceId: string,
  inventory: OrganizationReconciliationComponentDatasetInventory
): string {
  const canonical = validateOrganizationReconciliationComponentDatasetInventory(inventory);
  const acceptedSourceId = requireMetadata(sourceId, "source ID");
  if (canonical.sourceId !== acceptedSourceId) {
    throw new DatasetInventoryFailure("The inventory source binding is invalid.");
  }
  return hash(Buffer.from("iam-organization-reconciliation:content-snapshot-id:v2\u001f", "utf8"), {
    sourceId: acceptedSourceId, inventory: canonical
  });
}

function captureCommitmentKey(candidate: unknown): Buffer {
  if (!Buffer.isBuffer(candidate) || candidate.byteLength !== 32) {
    throw new DatasetInventoryFailure("A 32-byte run commitment key is required.");
  }
  return Buffer.from(candidate);
}

function commitment(key: Buffer, domain: Buffer, value: unknown): string {
  return createHmac("sha256", key).update(domain).update(canonicalJson(canonicalize(value)), "utf8").digest("hex");
}

/** Single canonical tuple emitter shared by batch and incremental inventory creation. */
function startDatasetRecordsCommitment(
  key: Buffer,
  componentId: string,
  sourceId: string,
  catalogSha256: string,
  datasetId: string,
  recordCount: number
): DatasetCommitmentWriter {
  const hmac = createHmac("sha256", key).update(DATASET_RECORDS_DOMAIN);
  hmac.update(
    `{"catalogSha256":${canonicalJson(catalogSha256)},` +
    `"componentId":${canonicalJson(componentId)},` +
    `"contract":${canonicalJson(ORGANIZATION_RECONCILIATION_DATASET_INVENTORY_CONTRACT)},` +
    `"datasetId":${canonicalJson(datasetId)},` +
    `"recordCount":${canonicalJson(recordCount)},"records":[`,
    "utf8"
  );
  return { hmac, firstRecord: true };
}

function appendDatasetCommitmentRecord(
  writer: DatasetCommitmentWriter,
  record: OrganizationReconciliationInventoryJsonValue
): void {
  if (!writer.firstRecord) writer.hmac.update(",", "utf8");
  writer.hmac.update(canonicalJson(record), "utf8");
  writer.firstRecord = false;
}

function finishDatasetRecordsCommitment(writer: DatasetCommitmentWriter, sourceId: string): string {
  return writer.hmac
    .update(`],"sourceId":${canonicalJson(sourceId)}}`, "utf8")
    .digest("hex");
}

function commitCursor(
  key: Buffer,
  componentId: string,
  sourceId: string,
  catalogSha256: string,
  datasetId: string,
  cursor: unknown
): string | null {
  if (cursor === null) return null;
  if (!validCursor(cursor)) throw new DatasetInventoryFailure("A dataset cursor is invalid.");
  return commitment(key, CURSOR_DOMAIN, {
    contract: ORGANIZATION_RECONCILIATION_DATASET_INVENTORY_CONTRACT,
    componentId,
    sourceId,
    catalogSha256,
    datasetId,
    cursor
  });
}

function hash(domain: Buffer, value: unknown): string {
  return createHash("sha256").update(domain).update(canonicalJson(canonicalize(value)), "utf8").digest("hex");
}

function canonicalize(
  value: unknown,
  active = new Set<object>(),
  state = { nodes: 0 },
  depth = 0
): OrganizationReconciliationInventoryJsonValue {
  state.nodes += 1;
  if (state.nodes > MAX_JSON_NODES || depth > MAX_JSON_DEPTH) {
    throw new DatasetInventoryFailure("Inventory content exceeds its canonical JSON complexity bound.");
  }
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "string") {
    if (Buffer.byteLength(value, "utf8") > MAX_JSON_STRING_BYTES) {
      throw new DatasetInventoryFailure("Inventory content exceeds its canonical JSON string bound.");
    }
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new DatasetInventoryFailure("Inventory content is not canonical JSON.");
    return Object.is(value, -0) ? 0 : value;
  }
  if (typeof value !== "object" || active.has(value)) {
    throw new DatasetInventoryFailure("Inventory content is not canonical JSON.");
  }
  if (isProxy(value)) {
    throw new DatasetInventoryFailure("Inventory content is not canonical JSON.");
  }
  active.add(value);
  try {
    if (Array.isArray(value)) {
      return Object.freeze(safeArray(value, "JSON array", 0, MAX_JSON_NODES).map((entry) =>
        canonicalize(entry, active, state, depth + 1)
      ));
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new DatasetInventoryFailure("Inventory content is not a plain object.");
    }
    const descriptors = Object.getOwnPropertyDescriptors(value);
    if (Object.getOwnPropertySymbols(value).length > 0) throw new DatasetInventoryFailure("Inventory content has symbols.");
    const output = Object.create(null) as Record<string, OrganizationReconciliationInventoryJsonValue>;
    for (const key of Object.keys(descriptors).sort()) {
      const descriptor = descriptors[key]!;
      if (Buffer.byteLength(key, "utf8") > MAX_JSON_OBJECT_KEY_BYTES ||
        !descriptor.enumerable || !("value" in descriptor) || descriptor.value === undefined) {
        throw new DatasetInventoryFailure("Inventory content has an accessor or hidden value.");
      }
      output[key] = canonicalize(descriptor.value, active, state, depth + 1);
    }
    return Object.freeze(output);
  } finally {
    active.delete(value);
  }
}

function safeArray(candidate: unknown, label: string, minimum: number, maximum: number): readonly unknown[] {
  if (!Array.isArray(candidate) || isProxy(candidate) || Object.getPrototypeOf(candidate) !== Array.prototype ||
    Object.getOwnPropertySymbols(candidate).length > 0) {
    throw new DatasetInventoryFailure(`The ${label} is invalid.`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(candidate);
  const lengthDescriptor = descriptors["length"] as PropertyDescriptor | undefined;
  if (!lengthDescriptor || !("value" in lengthDescriptor) || typeof lengthDescriptor.value !== "number" ||
    !Number.isSafeInteger(lengthDescriptor.value) || lengthDescriptor.value < minimum ||
    lengthDescriptor.value > maximum) {
    throw new DatasetInventoryFailure(`The ${label} is empty, sparse, or unbounded.`);
  }
  const length = lengthDescriptor.value as number;
  const expectedNames = new Set(["length", ...Array.from({ length }, (_, index) => String(index))]);
  if (Object.keys(descriptors).length !== expectedNames.size ||
    Object.keys(descriptors).some((name) => !expectedNames.has(name))) {
    throw new DatasetInventoryFailure(`The ${label} has sparse, hidden, or extra fields.`);
  }
  const output: unknown[] = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) {
      throw new DatasetInventoryFailure(`The ${label} contains an accessor or sparse entry.`);
    }
    output.push(descriptor.value);
  }
  return Object.freeze(output);
}

function canonicalJson(value: OrganizationReconciliationInventoryJsonValue): string {
  if (value === null) return "null";
  if (typeof value === "string") return JSON.stringify(value)!;
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") return JSON.stringify(value)!;
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const record = value as Readonly<Record<string, OrganizationReconciliationInventoryJsonValue>>;
  return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key]!)}`).join(",")}}`;
}

function canonicalJsonByteLength(
  value: OrganizationReconciliationInventoryJsonValue,
  maximum: number,
  observed = 0
): number {
  let total = observed;
  const add = (bytes: number): void => {
    total += bytes;
    if (total > maximum) throw new DatasetInventoryFailure("The page record transport frame exceeds its byte bound.");
  };
  if (value === null) add(4);
  else if (typeof value === "boolean") add(value ? 4 : 5);
  else if (typeof value === "number") add(Buffer.byteLength(JSON.stringify(value)!, "utf8"));
  else if (typeof value === "string") add(Buffer.byteLength(JSON.stringify(value)!, "utf8"));
  else if (Array.isArray(value)) {
    add(2 + Math.max(0, value.length - 1));
    for (const entry of value) total = canonicalJsonByteLength(entry, maximum, total);
  } else {
    const record = value as Readonly<Record<string, OrganizationReconciliationInventoryJsonValue>>;
    const keys = Object.keys(record).sort();
    add(2 + Math.max(0, keys.length - 1));
    for (const key of keys) {
      add(Buffer.byteLength(JSON.stringify(key)!, "utf8") + 1);
      total = canonicalJsonByteLength(record[key]!, maximum, total);
    }
  }
  return total;
}

function exact(candidate: unknown, keys: readonly string[]): Record<string, unknown> {
  if (!candidate || typeof candidate !== "object" || Array.isArray(candidate) ||
    isProxy(candidate) ||
    (Object.getPrototypeOf(candidate) !== Object.prototype && Object.getPrototypeOf(candidate) !== null) ||
    Object.getOwnPropertySymbols(candidate).length > 0) throw new DatasetInventoryFailure("Inventory content is invalid.");
  const descriptors = Object.getOwnPropertyDescriptors(candidate);
  if (Object.keys(descriptors).sort().join("\u001f") !== [...keys].sort().join("\u001f")) {
    throw new DatasetInventoryFailure("Inventory content has missing or unknown fields.");
  }
  const output: Record<string, unknown> = {};
  for (const key of keys) {
    const descriptor = descriptors[key]!;
    if (!descriptor.enumerable || !("value" in descriptor)) throw new DatasetInventoryFailure("Inventory content has an accessor.");
    output[key] = descriptor.value;
  }
  return output;
}

/** Strict structural capture only; it conveys no source or catalog trust. */
export const captureOrganizationReconciliationInventoryExactObject = exact;
/** Strict structural capture only; it conveys no source or catalog trust. */
export const captureOrganizationReconciliationInventoryBoundedArray = safeArray;

function requireDatasetId(value: unknown): string {
  if (typeof value !== "string" || !/^[a-z0-9][a-z0-9-]{0,127}$/.test(value)) {
    throw new DatasetInventoryFailure("The dataset ID is invalid.");
  }
  return value;
}

function compareDatasetId(left: { readonly datasetId: string }, right: { readonly datasetId: string }): number {
  return left.datasetId < right.datasetId ? -1 : left.datasetId > right.datasetId ? 1 : 0;
}

function requireMetadata(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length < 1 || value.length > 1_024 || value.trim() !== value ||
    value.normalize("NFC") !== value || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new DatasetInventoryFailure(`The ${label} is invalid.`);
  }
  return value;
}

function requireSha256(value: unknown, label: string): string {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) {
    throw new DatasetInventoryFailure(`The ${label} must be a full SHA-256 digest.`);
  }
  return value;
}

function requireNullableSha256(value: unknown, label: string): string | null {
  return value === null ? null : requireSha256(value, label);
}

function requireCount(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0 || (value as number) > 10_000_000) {
    throw new DatasetInventoryFailure(`The ${label} is invalid.`);
  }
  return value as number;
}

function requirePositiveCount(value: unknown, maximum: number, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1 || (value as number) > maximum) {
    throw new DatasetInventoryFailure(`The ${label} is invalid.`);
  }
  return value as number;
}

function requireCursor(value: unknown, label: string): string {
  if (!validCursor(value)) throw new DatasetInventoryFailure(`The ${label} is invalid.`);
  return value;
}

function validCursor(value: unknown): value is string {
  return typeof value === "string" && value.length >= 1 && value.length <= 2_048 && value.trim() === value;
}

class DatasetInventoryFailure extends Error {}
