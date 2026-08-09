import {
  createOrganizationReconciliationCollectedSnapshot,
  type ReconciliationPage
} from "./iam-organization-reconciliation-validator.js";
import {
  validateOrganizationReconciliationComponentDatasetInventory,
  type OrganizationReconciliationComponentDatasetInventory
} from "./iam-organization-reconciliation-dataset-inventory.js";

export const ORGANIZATION_RECONCILIATION_SNAPSHOT_MODE = "immutable-snapshot" as const;
export const ORGANIZATION_RECONCILIATION_PAGINATION_MODE = "snapshot-bound-opaque-cursor" as const;

/**
 * Public, non-secret evidence returned when a source opens one immutable
 * full-range snapshot. Any source-specific token stays inside the adapter.
 */
export interface OrganizationReconciliationSourceSnapshot {
  readonly sourceId: string;
  readonly sourceVersion: string;
  readonly snapshotId: string;
  readonly recordCount: number;
  /** Full subject universe, including subjects with no organization membership. */
  readonly subjectUniverseCount: number;
  /** HMAC-SHA256 evidence hash of the sorted, complete subject reference set. */
  readonly subjectUniverseHash: string;
  readonly snapshotMode: typeof ORGANIZATION_RECONCILIATION_SNAPSHOT_MODE;
  readonly paginationMode: typeof ORGANIZATION_RECONCILIATION_PAGINATION_MODE;
  /** Present only for transaction-materialized multi-dataset adapters. */
  readonly datasetInventory?: OrganizationReconciliationComponentDatasetInventory;
}

export interface OrganizationReconciliationSourcePage<TRawRecord> {
  readonly sourceId: string;
  readonly sourceVersion: string;
  readonly snapshotId: string;
  readonly snapshotRecordCount: number;
  readonly subjectUniverseCount: number;
  readonly subjectUniverseHash: string;
  readonly requestCursor: string | null;
  readonly nextCursor: string | null;
  readonly recordOffset: number;
  readonly records: readonly TRawRecord[];
}

export interface OrganizationReconciliationSourcePageRequest {
  readonly snapshot: OrganizationReconciliationSourceSnapshot;
  readonly requestCursor: string | null;
  readonly pageSize: number;
}

/**
 * A source-specific implementation must acquire a real immutable snapshot and
 * read it through source-owned cursors. In-memory/manual JSON sources do not
 * satisfy the production trust policy merely by implementing this interface.
 */
export interface OrganizationReconciliationSourceAdapter<TRawRecord> {
  readonly sourceId: string;
  openSnapshot(): Promise<OrganizationReconciliationSourceSnapshot>;
  readSnapshotPage(
    request: OrganizationReconciliationSourcePageRequest
  ): Promise<OrganizationReconciliationSourcePage<TRawRecord>>;
  /** Releases the private transaction/token retained by the adapter. */
  closeSnapshot(
    snapshot: OrganizationReconciliationSourceSnapshot,
    outcome: "completed" | "failed"
  ): Promise<void>;
}

/**
 * Trusted process dependency supplied by the reviewed collector artifact. It
 * is deliberately separate from caller options, source adapters, and evidence.
 */
export interface OrganizationReconciliationCollectorBuildRevisionProvider {
  getBuildRevision(): string;
}

export interface OrganizationReconciliationRecordDecoder<TRawRecord, TRecord> {
  /** Must reject unknown/missing fields rather than silently defaulting them. */
  decode(rawRecord: TRawRecord, context: { readonly pageNumber: number; readonly recordIndex: number }): TRecord;
  /** Stable canonical key used to reject overlap between cursor pages. */
  uniqueKey(record: TRecord): string;
  /** Stable source ordering key; values must be strictly increasing. */
  orderKey(record: TRecord): string;
}

export interface CollectOrganizationReconciliationSourceOptions<TRawRecord, TRecord> {
  readonly expectedSourceId: string;
  readonly evidenceNonce: string;
  readonly pageSize: number;
  readonly maxPages: number;
  readonly maxRecords: number;
  readonly adapter: OrganizationReconciliationSourceAdapter<TRawRecord>;
  readonly decoder: OrganizationReconciliationRecordDecoder<TRawRecord, TRecord>;
}

export interface CollectedOrganizationReconciliationSource<TRecord> {
  /** Obtained only from the injected reviewed artifact provider. */
  readonly collectorBuildRevision: string;
  readonly source: OrganizationReconciliationSourceSnapshot;
  readonly page: ReconciliationPage<TRecord>;
}

interface CapturedOrganizationReconciliationSourceSnapshot {
  readonly rawMetadata: Readonly<Record<string, unknown>>;
  readonly publicSnapshot: Readonly<OrganizationReconciliationSourceSnapshot>;
}

/**
 * Collects exactly one source-owned immutable snapshot. The function has no
 * transport or database assumptions: concrete adapters own those details, but
 * cannot change version/snapshot/count/offset/order while collection is in
 * progress without making the collection fail closed.
 */
export async function collectOrganizationReconciliationSource<TRawRecord, TRecord>(
  options: CollectOrganizationReconciliationSourceOptions<TRawRecord, TRecord>,
  buildRevisionProvider: OrganizationReconciliationCollectorBuildRevisionProvider
): Promise<CollectedOrganizationReconciliationSource<TRecord>> {
  validateCollectionLimits(options);
  requireEvidenceNonce(options.evidenceNonce);
  const collectorBuildRevision = trustedBuildRevision(buildRevisionProvider);
  const adapterSourceId = requireOpaqueMetadata(options.adapter.sourceId, "adapter source ID");
  const expectedSourceId = requireOpaqueMetadata(options.expectedSourceId, "expected source ID");
  if (adapterSourceId !== expectedSourceId) throw new Error("The collector adapter is bound to an unexpected source.");

  let rawSnapshot: OrganizationReconciliationSourceSnapshot;
  try {
    rawSnapshot = await options.adapter.openSnapshot();
  } catch {
    throw new Error("Opening the authoritative source snapshot failed.");
  }
  let outcome: "completed" | "failed" = "failed";
  let capturedSnapshot: CapturedOrganizationReconciliationSourceSnapshot | null = null;
  try {
    capturedSnapshot = captureSnapshot(rawSnapshot, expectedSourceId, options.maxRecords);
    try {
      Object.freeze(rawSnapshot);
    } catch {
      throw new Error("The authoritative source snapshot handle could not be made immutable.");
    }
    const snapshot = capturedSnapshot.publicSnapshot;

    const records: TRecord[] = [];
    const collectedPages: Array<{
      requestCursor: string | null;
      nextCursor: string | null;
      records: readonly TRecord[];
    }> = [];
    const uniqueKeys = new Set<string>();
    const observedCursors = new Set<string>();
    let previousOrderKey: string | null = null;
    let requestCursor: string | null = null;

    while (true) {
      if (collectedPages.length >= options.maxPages) {
        throw new Error("The source cursor chain exceeded the approved page bound.");
      }

      const pageNumber = collectedPages.length + 1;
      let rawPage: OrganizationReconciliationSourcePage<TRawRecord>;
      assertRawSnapshotMetadataUnchanged(rawSnapshot, capturedSnapshot, expectedSourceId, options.maxRecords);
      try {
        rawPage = await options.adapter.readSnapshotPage({
          snapshot: rawSnapshot,
          requestCursor,
          pageSize: options.pageSize
        });
      } catch {
        throw new Error(`Reading authoritative source page ${pageNumber} failed.`);
      }
      assertRawSnapshotMetadataUnchanged(rawSnapshot, capturedSnapshot, expectedSourceId, options.maxRecords);

      validatePageBinding(rawPage, snapshot, requestCursor, records.length, options.pageSize);
      if (records.length + rawPage.records.length > options.maxRecords) {
        throw new Error("The source record count exceeded the approved collection bound.");
      }

      const decodedPage: TRecord[] = [];
      for (let recordIndex = 0; recordIndex < rawPage.records.length; recordIndex += 1) {
        let decoded: TRecord;
        let uniqueKey: string;
        let orderKey: string;
        try {
          decoded = options.decoder.decode(rawPage.records[recordIndex]!, { pageNumber, recordIndex });
          uniqueKey = requireCanonicalKey(options.decoder.uniqueKey(decoded), "record unique key");
          orderKey = requireCanonicalKey(options.decoder.orderKey(decoded), "record order key");
        } catch {
          throw new Error(`Source record normalization failed at page ${pageNumber}, record ${recordIndex + 1}.`);
        }
        if (uniqueKeys.has(uniqueKey)) throw new Error("The source cursor chain contains a duplicate record key.");
        if (previousOrderKey !== null && orderKey <= previousOrderKey) {
          throw new Error("The source cursor chain is not in strict canonical order.");
        }
        uniqueKeys.add(uniqueKey);
        previousOrderKey = orderKey;
        decodedPage.push(decoded);
      }

      records.push(...decodedPage);
      collectedPages.push({
        requestCursor: rawPage.requestCursor,
        nextCursor: rawPage.nextCursor,
        records: decodedPage
      });

      if (rawPage.nextCursor === null) break;
      const nextCursor = requireCursor(rawPage.nextCursor);
      if (rawPage.records.length === 0) throw new Error("A non-terminal source page cannot be empty.");
      if (observedCursors.has(nextCursor)) throw new Error("The source cursor chain repeats a continuation cursor.");
      observedCursors.add(nextCursor);
      requestCursor = nextCursor;
    }

    assertRawSnapshotMetadataUnchanged(rawSnapshot, capturedSnapshot, expectedSourceId, options.maxRecords);
    if (records.length !== snapshot.recordCount) {
      throw new Error("The terminal source record count does not match the opened snapshot.");
    }

    const result = {
      collectorBuildRevision,
      source: snapshot,
      page: createOrganizationReconciliationCollectedSnapshot(
        options.evidenceNonce,
        snapshot.sourceVersion,
        snapshot.snapshotId,
        collectedPages
      )
    };
    assertRawSnapshotMetadataUnchanged(rawSnapshot, capturedSnapshot, expectedSourceId, options.maxRecords);
    outcome = "completed";
    return result;
  } finally {
    let metadataDrifted = false;
    if (capturedSnapshot !== null) {
      try {
        assertRawSnapshotMetadataUnchanged(rawSnapshot, capturedSnapshot, expectedSourceId, options.maxRecords);
      } catch {
        metadataDrifted = true;
        outcome = "failed";
      }
    }
    let closeFailed = false;
    try {
      await options.adapter.closeSnapshot(rawSnapshot, outcome);
    } catch {
      closeFailed = true;
    }
    if (capturedSnapshot !== null) {
      try {
        assertRawSnapshotMetadataUnchanged(rawSnapshot, capturedSnapshot, expectedSourceId, options.maxRecords);
      } catch {
        metadataDrifted = true;
      }
    }
    if (closeFailed) {
      throw new Error("Closing the authoritative source snapshot failed; collection evidence was rejected.");
    }
    if (metadataDrifted) {
      throw new Error("The authoritative source snapshot metadata changed; collection evidence was rejected.");
    }
  }
}

function validateCollectionLimits(options: {
  readonly pageSize: number;
  readonly maxPages: number;
  readonly maxRecords: number;
}): void {
  if (!Number.isSafeInteger(options.pageSize) || options.pageSize < 1 || options.pageSize > 5_000) {
    throw new Error("The collector page size is outside the approved bound.");
  }
  if (!Number.isSafeInteger(options.maxPages) || options.maxPages < 1 || options.maxPages > 10_000) {
    throw new Error("The collector page bound is invalid.");
  }
  if (!Number.isSafeInteger(options.maxRecords) || options.maxRecords < 0 || options.maxRecords > 10_000_000) {
    throw new Error("The collector record bound is invalid.");
  }
}

function captureSnapshot(
  candidate: unknown,
  expectedSourceId: string,
  maxRecords: number
): CapturedOrganizationReconciliationSourceSnapshot {
  const rawMetadata = captureSnapshotOwnData(candidate);
  const sourceId = requireOpaqueMetadata(rawMetadata.sourceId as string, "snapshot source ID");
  if (sourceId !== expectedSourceId) {
    throw new Error("The opened snapshot belongs to an unexpected source.");
  }
  const sourceVersion = requireOpaqueMetadata(rawMetadata.sourceVersion as string, "snapshot source version");
  const snapshotId = requireOpaqueMetadata(rawMetadata.snapshotId as string, "snapshot ID");
  const recordCount = rawMetadata.recordCount;
  if (
    !Number.isSafeInteger(recordCount) ||
    (recordCount as number) < 0 ||
    (recordCount as number) > maxRecords
  ) {
    throw new Error("The authoritative snapshot record count is invalid or exceeds the approved bound.");
  }
  const subjectUniverseCount = rawMetadata.subjectUniverseCount;
  if (!Number.isSafeInteger(subjectUniverseCount) || (subjectUniverseCount as number) < 1) {
    throw new Error("The authoritative subject universe count is invalid.");
  }
  const subjectUniverseHash = requireSha256(rawMetadata.subjectUniverseHash as string, "subject universe hash");
  if (rawMetadata.snapshotMode !== ORGANIZATION_RECONCILIATION_SNAPSHOT_MODE) {
    throw new Error("The source does not provide an immutable snapshot.");
  }
  if (rawMetadata.paginationMode !== ORGANIZATION_RECONCILIATION_PAGINATION_MODE) {
    throw new Error("The source does not provide snapshot-bound opaque cursors.");
  }
  let datasetInventory: OrganizationReconciliationComponentDatasetInventory | undefined;
  if (Object.prototype.hasOwnProperty.call(rawMetadata, "datasetInventory")) {
    datasetInventory = validateOrganizationReconciliationComponentDatasetInventory(rawMetadata.datasetInventory);
  }
  const publicSnapshot = Object.freeze({
    sourceId,
    sourceVersion,
    snapshotId,
    recordCount: recordCount as number,
    subjectUniverseCount: subjectUniverseCount as number,
    subjectUniverseHash,
    snapshotMode: ORGANIZATION_RECONCILIATION_SNAPSHOT_MODE,
    paginationMode: ORGANIZATION_RECONCILIATION_PAGINATION_MODE,
    ...(datasetInventory === undefined ? {} : { datasetInventory })
  });
  return Object.freeze({ rawMetadata, publicSnapshot });
}

function captureSnapshotOwnData(candidate: unknown): Readonly<Record<string, unknown>> {
  if (!candidate || typeof candidate !== "object" || Array.isArray(candidate) ||
    (Object.getPrototypeOf(candidate) !== Object.prototype && Object.getPrototypeOf(candidate) !== null) ||
    Object.getOwnPropertySymbols(candidate).length > 0) {
    throw new Error("The authoritative snapshot metadata is invalid.");
  }
  const descriptors = Object.getOwnPropertyDescriptors(candidate);
  const requiredKeys = [
    "sourceId", "sourceVersion", "snapshotId", "recordCount", "subjectUniverseCount",
    "subjectUniverseHash", "snapshotMode", "paginationMode"
  ];
  const hasDatasetInventory = Object.prototype.hasOwnProperty.call(descriptors, "datasetInventory");
  const expectedKeys = hasDatasetInventory ? [...requiredKeys, "datasetInventory"] : requiredKeys;
  if (Object.keys(descriptors).sort().join("\u001f") !== [...expectedKeys].sort().join("\u001f")) {
    throw new Error("The authoritative snapshot metadata has missing or unknown fields.");
  }
  const output = Object.create(null) as Record<string, unknown>;
  for (const key of expectedKeys) {
    const descriptor = descriptors[key]!;
    if (!descriptor.enumerable || !("value" in descriptor)) {
      throw new Error("The authoritative snapshot metadata contains an accessor or hidden field.");
    }
    output[key] = descriptor.value;
  }
  return Object.freeze(output);
}

function assertRawSnapshotMetadataUnchanged(
  rawSnapshot: OrganizationReconciliationSourceSnapshot,
  captured: CapturedOrganizationReconciliationSourceSnapshot,
  expectedSourceId: string,
  maxRecords: number
): void {
  let observed: CapturedOrganizationReconciliationSourceSnapshot;
  try {
    observed = captureSnapshot(rawSnapshot, expectedSourceId, maxRecords);
  } catch {
    throw new Error("The authoritative source snapshot metadata changed during collection.");
  }
  const originalKeys = Object.keys(captured.rawMetadata).sort();
  const observedKeys = Object.keys(observed.rawMetadata).sort();
  if (originalKeys.length !== observedKeys.length ||
    originalKeys.some((key, index) => key !== observedKeys[index] ||
      !Object.is(captured.rawMetadata[key], observed.rawMetadata[key])) ||
    captured.publicSnapshot.datasetInventory?.inventorySha256 !==
      observed.publicSnapshot.datasetInventory?.inventorySha256) {
    throw new Error("The authoritative source snapshot metadata changed during collection.");
  }
}

function validatePageBinding<TRawRecord>(
  page: OrganizationReconciliationSourcePage<TRawRecord>,
  snapshot: OrganizationReconciliationSourceSnapshot,
  requestCursor: string | null,
  recordOffset: number,
  pageSize: number
): void {
  if (
    page.sourceId !== snapshot.sourceId ||
    page.sourceVersion !== snapshot.sourceVersion ||
    page.snapshotId !== snapshot.snapshotId ||
    page.snapshotRecordCount !== snapshot.recordCount ||
    page.subjectUniverseCount !== snapshot.subjectUniverseCount ||
    page.subjectUniverseHash !== snapshot.subjectUniverseHash
  ) {
    throw new Error("The source changed version, snapshot, or count during collection.");
  }
  if (page.requestCursor !== requestCursor) throw new Error("The source did not echo the requested cursor.");
  if (!Number.isSafeInteger(page.recordOffset) || page.recordOffset !== recordOffset) {
    throw new Error("The source page offset does not continue the full-range snapshot.");
  }
  if (!Array.isArray(page.records) || page.records.length > pageSize) {
    throw new Error("The source page exceeds the requested page size.");
  }
  if (page.nextCursor !== null) requireCursor(page.nextCursor);
}

function requireBuildRevision(value: string): string {
  if (typeof value !== "string" || !/^[a-f0-9]{40}$/.test(value)) {
    throw new Error("The collector build revision must be an exact full 40-character revision.");
  }
  return value;
}

function trustedBuildRevision(
  provider: OrganizationReconciliationCollectorBuildRevisionProvider
): string {
  try {
    return requireBuildRevision(provider.getBuildRevision());
  } catch {
    throw new Error("The reviewed collector artifact build revision is unavailable or invalid.");
  }
}

function requireEvidenceNonce(value: string): string {
  if (typeof value !== "string" || !/^[a-f0-9]{32,128}$/i.test(value)) {
    throw new Error("A high-entropy evidence nonce is required before opening a source snapshot.");
  }
  return value;
}

function requireSha256(value: string, label: string): string {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) {
    throw new Error(`The ${label} must be a full SHA-256 digest.`);
  }
  return value;
}

function requireOpaqueMetadata(value: string, label: string): string {
  if (typeof value !== "string" || value.length < 1 || value.length > 1_024 || value.trim() !== value) {
    throw new Error(`The ${label} is invalid.`);
  }
  return value;
}

function requireCursor(value: string): string {
  if (typeof value !== "string" || value.length < 1 || value.length > 2_048 || value.trim() !== value) {
    throw new Error("The source returned an invalid continuation cursor.");
  }
  return value;
}

function requireCanonicalKey(value: string, label: string): string {
  if (typeof value !== "string" || value.length < 1 || value.length > 2_048 || value.trim() !== value) {
    throw new Error(`The ${label} is invalid.`);
  }
  return value;
}
