import { createHash, createHmac } from "node:crypto";

export const ORGANIZATION_RECONCILIATION_DATASET_INVENTORY_CONTRACT =
  "iam-organization-reconciliation-dataset-inventory/v2" as const;
export const ORGANIZATION_RECONCILIATION_RECORD_COMMITMENT_SCHEME =
  "hmac-sha256-run-secret/v1" as const;

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

const CURSOR_DOMAIN = Buffer.from("iam-organization-reconciliation:inventory-cursor:v2\u001f", "utf8");
const PAGE_RECORDS_DOMAIN = Buffer.from("iam-organization-reconciliation:inventory-page-records:v2\u001f", "utf8");
const DATASET_RECORDS_DOMAIN = Buffer.from("iam-organization-reconciliation:inventory-dataset-records:v2\u001f", "utf8");
const LINEAGE_DOMAIN = Buffer.from("iam-organization-reconciliation:inventory-dataset-lineage:v2\u001f", "utf8");
const INVENTORY_DOMAIN = Buffer.from("iam-organization-reconciliation:component-inventory:v2\u001f", "utf8");
const MAX_COMPONENT_PAGES = 10_000;
const MAX_JSON_DEPTH = 64;
const MAX_JSON_NODES = 100_000;

export function createOrganizationReconciliationComponentDatasetInventory(
  candidate: CreateOrganizationReconciliationComponentDatasetInventoryOptions
): OrganizationReconciliationComponentDatasetInventory {
  const options = exact(candidate, ["componentId", "sourceId", "catalogSha256", "datasets", "commitmentKey"]);
  const componentId = requireDatasetId(options.componentId);
  const sourceId = requireMetadata(options.sourceId, "source ID");
  const catalogSha256 = requireSha256(options.catalogSha256, "dataset catalog digest");
  const commitmentKey = captureCommitmentKey(options.commitmentKey);
  try {
  const capturedInputs = safeArray(options.datasets, "component datasets", 1, 64);
  const captured = capturedInputs.map((candidate) => {
    const input = exact(candidate, ["datasetId", "pages"]);
    return Object.freeze({
      datasetId: requireDatasetId(input.datasetId),
      pages: safeArray(input.pages, "dataset pages", 1, MAX_COMPONENT_PAGES)
    });
  });
  if (captured.reduce((sum, input) => sum + input.pages.length, 0) > MAX_COMPONENT_PAGES) {
    throw new DatasetInventoryFailure("The component dataset inventory exceeds its aggregate page bound.");
  }
  const ids = new Set<string>();
  const jsonState = { nodes: 0 };
  const datasets = captured.map((input) => {
    if (ids.has(input.datasetId)) throw new DatasetInventoryFailure("The component dataset inventory is duplicate.");
    ids.add(input.datasetId);
    const records: OrganizationReconciliationInventoryJsonValue[] = [];
    const pages: OrganizationReconciliationDatasetInventoryPage[] = [];
    let expectedRequestCursor: string | null = null;
    for (let index = 0; index < input.pages.length; index += 1) {
      const candidatePage = exact(input.pages[index], ["requestCursor", "nextCursor", "recordOffset", "records"]);
      const rawRecords = safeArray(candidatePage.records, "page records", 0, 10_000_000);
      if (candidatePage.requestCursor !== expectedRequestCursor || candidatePage.recordOffset !== records.length) {
        throw new DatasetInventoryFailure("A dataset page lineage is discontinuous.");
      }
      const isLast = index === input.pages.length - 1;
      if ((isLast && candidatePage.nextCursor !== null) || (!isLast && !validCursor(candidatePage.nextCursor))) {
        throw new DatasetInventoryFailure("A dataset page lineage is not terminal.");
      }
      const canonicalRecords = Object.freeze(rawRecords.map((record) =>
        canonicalize(record, new Set<object>(), jsonState, 0)
      ));
      pages.push(Object.freeze({
        pageNumber: index + 1,
        requestCursorCommitment: commitCursor(
          commitmentKey, componentId, sourceId, catalogSha256, input.datasetId, candidatePage.requestCursor
        ),
        nextCursorCommitment: commitCursor(
          commitmentKey, componentId, sourceId, catalogSha256, input.datasetId, candidatePage.nextCursor
        ),
        recordOffset: records.length,
        recordCount: canonicalRecords.length,
        recordsCommitment: commitment(commitmentKey, PAGE_RECORDS_DOMAIN, {
          contract: ORGANIZATION_RECONCILIATION_DATASET_INVENTORY_CONTRACT,
          componentId,
          sourceId,
          catalogSha256,
          datasetId: input.datasetId,
          pageNumber: index + 1,
          requestCursor: candidatePage.requestCursor,
          nextCursor: candidatePage.nextCursor,
          recordOffset: records.length,
          recordCount: canonicalRecords.length,
          records: canonicalRecords
        })
      }));
      records.push(...canonicalRecords);
      expectedRequestCursor = candidatePage.nextCursor as string | null;
    }
    const body = Object.freeze({
      datasetId: input.datasetId,
      recordCount: records.length,
      recordsCommitment: commitment(commitmentKey, DATASET_RECORDS_DOMAIN, {
        contract: ORGANIZATION_RECONCILIATION_DATASET_INVENTORY_CONTRACT,
        componentId,
        sourceId,
        catalogSha256,
        datasetId: input.datasetId,
        recordCount: records.length,
        records
      }),
      pageCount: pages.length,
      pages: Object.freeze(pages)
    });
    return Object.freeze({ ...body, lineageSha256: hash(LINEAGE_DOMAIN, body) });
  }).sort(compareDatasetId);
  const recordCount = datasets.reduce((sum, dataset) => sum + dataset.recordCount, 0);
  if (!Number.isSafeInteger(recordCount) || recordCount > 10_000_000) {
    throw new DatasetInventoryFailure("The component dataset inventory exceeds its record bound.");
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
  return Object.freeze({ ...body, inventorySha256: hash(INVENTORY_DOMAIN, body) });
  } finally {
    // Best-effort overwrite of the creator-owned copy; strong erasure is not guaranteed by JavaScript.
    commitmentKey.fill(0);
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
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new DatasetInventoryFailure("Inventory content is not canonical JSON.");
    return Object.is(value, -0) ? 0 : value;
  }
  if (typeof value !== "object" || active.has(value)) {
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
      if (!descriptor.enumerable || !("value" in descriptor) || descriptor.value === undefined) {
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
  if (!Array.isArray(candidate) || Object.getPrototypeOf(candidate) !== Array.prototype ||
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

function exact(candidate: unknown, keys: readonly string[]): Record<string, unknown> {
  if (!candidate || typeof candidate !== "object" || Array.isArray(candidate) ||
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

function validCursor(value: unknown): value is string {
  return typeof value === "string" && value.length >= 1 && value.length <= 2_048 && value.trim() === value;
}

class DatasetInventoryFailure extends Error {}
