import { createHash } from "node:crypto";
import { constants } from "node:fs";
import {
  chmod,
  lstat,
  mkdtemp,
  open,
  realpath,
  rmdir,
  unlink,
  type FileHandle
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";
import { isProxy } from "node:util/types";
import {
  createOrganizationReconciliationIncrementalDatasetInventoryBuilder,
  captureOrganizationReconciliationInventoryBoundedArray as strictArray,
  captureOrganizationReconciliationInventoryExactObject as strictObject,
  decodeOrganizationReconciliationInventoryPageRecords,
  encodeOrganizationReconciliationInventoryPageRecords,
  type OrganizationReconciliationComponentDatasetInventory,
  type OrganizationReconciliationDatasetInventoryPageInput,
  type OrganizationReconciliationIncrementalDatasetInventoryBuilder,
  type OrganizationReconciliationInventoryJsonValue
} from "./iam-organization-reconciliation-dataset-inventory.js";
import {
  ORGANIZATION_RECONCILIATION_DATASET_CATALOG_TRUST,
  ORGANIZATION_RECONCILIATION_DATASET_LINEAGE_CONTRACT,
  type OrganizationReconciliationDatasetCatalog,
  type OrganizationReconciliationDatasetSpec
} from "./iam-organization-reconciliation-dataset-lineage.js";
import { isCanonicalLegacyUserSubjectRef } from "./iam-organization-reconciliation-refs.js";
import { createOrganizationReconciliationStringArrayEvidenceHashBuilder } from
  "./iam-organization-reconciliation-validator.js";
import {
  ORGANIZATION_RECONCILIATION_TRANSACTION_DATASET_SPOOL_READY
} from "./iam-organization-reconciliation-runtime-readiness.js";

export {
  ORGANIZATION_RECONCILIATION_TRANSACTION_DATASET_SPOOL_IMPLEMENTED,
  ORGANIZATION_RECONCILIATION_TRANSACTION_DATASET_SPOOL_READY
} from "./iam-organization-reconciliation-runtime-readiness.js";

export const ORGANIZATION_RECONCILIATION_TRANSACTION_DATASET_SPOOL_CONTRACT =
  "iam-organization-reconciliation-transaction-dataset-bounded-spool/v1" as const;

export interface OrganizationReconciliationTransactionDatasetSpoolReadiness {
  readonly ready: false;
  readonly blockers: readonly [
    "named-temp-artifact-create-unlink-crash-window-not-eliminated",
    "spool-at-rest-encryption-not-proven",
    "cross-process-disk-quota-not-enforced",
    "secure-spool-runtime-platform-review-not-complete",
    "subject-universe-projection-factory-not-production-registered",
    "runtime-source-adapter-wiring-disabled"
  ];
}

export function organizationReconciliationTransactionDatasetSpoolReadiness():
OrganizationReconciliationTransactionDatasetSpoolReadiness {
  return Object.freeze({
    ready: ORGANIZATION_RECONCILIATION_TRANSACTION_DATASET_SPOOL_READY,
    blockers: Object.freeze([
      "named-temp-artifact-create-unlink-crash-window-not-eliminated",
      "spool-at-rest-encryption-not-proven",
      "cross-process-disk-quota-not-enforced",
      "secure-spool-runtime-platform-review-not-complete",
      "subject-universe-projection-factory-not-production-registered",
      "runtime-source-adapter-wiring-disabled"
    ] as const)
  });
}

export interface OpenOrganizationReconciliationTransactionDatasetSpoolOptions {
  readonly componentId: string;
  readonly sourceId: string;
  readonly catalogSha256: string;
  readonly datasetCatalog: OrganizationReconciliationDatasetCatalog;
  readonly commitmentKey: Buffer;
  readonly subjectUniverse: null | {
    readonly datasetId: string;
    readonly evidenceNonce: string;
  };
}

export interface OrganizationReconciliationTransactionSubjectUniverse {
  /**
   * Structural commitment over canonical caller-supplied references bound to
   * this spool's subject-dataset page counts and offsets. This does not prove
   * that the references were correctly derived from the raw records. A
   * hardened factory-owned caller may bind that derivation, but the current
   * integration is not production-registered and does not attest the source.
   */
  readonly count: number;
  readonly hash: string;
}

export interface OrganizationReconciliationTransactionDatasetSpoolAppendPageInput {
  readonly datasetId: string;
  readonly requestCursor: string | null;
  readonly nextCursor: string | null;
  readonly recordOffset: number;
  readonly records: readonly OrganizationReconciliationInventoryJsonValue[];
}

export interface OrganizationReconciliationTransactionDatasetSpoolReadPageRequest {
  readonly datasetId: string;
  readonly requestCursor: string | null;
  readonly pageSize: number;
}

export interface OrganizationReconciliationTransactionDatasetSpoolReadPage {
  readonly datasetId: string;
  readonly datasetRecordCount: number;
  readonly requestCursor: string | null;
  readonly nextCursor: string | null;
  readonly recordOffset: number;
  readonly records: readonly OrganizationReconciliationInventoryJsonValue[];
}

export interface OrganizationReconciliationTransactionDatasetSpoolReplayVerificationRequest {
  readonly datasetId: string;
  readonly pages: readonly OrganizationReconciliationDatasetInventoryPageInput[];
}

export interface OrganizationReconciliationTransactionDatasetSpool {
  readonly contract: typeof ORGANIZATION_RECONCILIATION_TRANSACTION_DATASET_SPOOL_CONTRACT;
  appendPage(
    this: OrganizationReconciliationTransactionDatasetSpool,
    page: OrganizationReconciliationTransactionDatasetSpoolAppendPageInput
  ): Promise<void>;
  appendSubjectUniversePage(
    this: OrganizationReconciliationTransactionDatasetSpool,
    page: { readonly datasetId: string; readonly recordOffset: number; readonly subjectRefs: readonly string[] }
  ): Promise<void>;
  seal(
    this: OrganizationReconciliationTransactionDatasetSpool
  ): Promise<OrganizationReconciliationComponentDatasetInventory>;
  readPage(
    this: OrganizationReconciliationTransactionDatasetSpool,
    request: OrganizationReconciliationTransactionDatasetSpoolReadPageRequest
  ): Promise<OrganizationReconciliationTransactionDatasetSpoolReadPage>;
  verifyDatasetReplay(
    this: OrganizationReconciliationTransactionDatasetSpool,
    request: OrganizationReconciliationTransactionDatasetSpoolReplayVerificationRequest
  ): void;
  /** Returns structural evidence only; it is not a source-trust capability. */
  subjectUniverse(
    this: OrganizationReconciliationTransactionDatasetSpool
  ): OrganizationReconciliationTransactionSubjectUniverse;
  close(
    this: OrganizationReconciliationTransactionDatasetSpool,
    outcome: "completed" | "failed"
  ): Promise<"completed" | "failed">;
}

interface FrameMetadata {
  readonly payloadOffset: number;
  readonly payloadLength: number;
  readonly requestCursor: string | null;
  readonly nextCursor: string | null;
  readonly recordOffset: number;
  readonly recordCount: number;
}

interface DatasetState {
  readonly spec: OrganizationReconciliationDatasetSpec;
  readonly frames: FrameMetadata[];
  readonly cursorDigests: Set<string>;
  expectedRequestCursor: string | null;
  recordCount: number;
  terminal: boolean;
}

interface SpoolMethods {
  readonly appendPage: OrganizationReconciliationTransactionDatasetSpool["appendPage"];
  readonly appendSubjectUniversePage:
    OrganizationReconciliationTransactionDatasetSpool["appendSubjectUniversePage"];
  readonly seal: OrganizationReconciliationTransactionDatasetSpool["seal"];
  readonly readPage: OrganizationReconciliationTransactionDatasetSpool["readPage"];
  readonly verifyDatasetReplay: OrganizationReconciliationTransactionDatasetSpool["verifyDatasetReplay"];
  readonly subjectUniverse: OrganizationReconciliationTransactionDatasetSpool["subjectUniverse"];
  readonly close: OrganizationReconciliationTransactionDatasetSpool["close"];
}

interface SubjectRun {
  readonly start: number;
  readonly end: number;
  readonly count: number;
}

interface SubjectRunReader {
  readonly runIndex: number;
  readonly end: number;
  position: number;
  remaining: number;
  value: string;
}

interface SubjectUniverseState {
  readonly datasetId: string;
  readonly evidenceNonce: Buffer;
  readonly runs: SubjectRun[];
  pendingFrameIndex: number | null;
  result: OrganizationReconciliationTransactionSubjectUniverse | null;
}

interface CapturedSubjectUniverseOptions {
  readonly datasetId: string;
  readonly evidenceNonce: Buffer;
}

interface ActiveSpoolOperation {
  readonly operation: keyof SpoolMethods;
  readonly done: Promise<void>;
  finish(): void;
}

interface SpoolState {
  phase: "appending" | "appending-page" | "appending-subjects" | "sealing" |
    "sealed" | "reading" | "closing" | "closed" | "poisoned";
  readonly componentId: string;
  readonly sourceId: string;
  readonly catalogSha256: string;
  readonly commitmentKey: Buffer;
  readonly datasets: readonly DatasetState[];
  file: FileHandle | null;
  filePosition: number;
  reservedBytes: number;
  appendDatasetIndex: number;
  inventory: OrganizationReconciliationComponentDatasetInventory | null;
  verifier: OrganizationReconciliationIncrementalDatasetInventoryBuilder | null;
  replayDatasetIndex: number;
  replayPageIndex: number;
  replayExpectedCursor: string | null;
  replayAwaitingVerification: boolean;
  closePromise: Promise<"completed" | "failed"> | null;
  cleanupFailed: boolean;
  poisoned: boolean;
  activeReservation: boolean;
  methods: SpoolMethods | null;
  readonly subjectUniverse: SubjectUniverseState | null;
  activeOperation: ActiveSpoolOperation | null;
  disposePromise: Promise<void> | null;
}

interface ReplayPageBrand {
  readonly state: SpoolState;
  readonly datasetIndex: number;
  readonly pageIndex: number;
}

const MAX_PAGE_SPOOL_BYTES = 2 * 1024 * 1024;
const MAX_COMPONENT_SPOOL_BYTES = 64 * 1024 * 1024;
const MAX_GLOBAL_ACTIVE_SPOOL_BYTES = 192 * 1024 * 1024;
const MAX_ACTIVE_SPOOLS = 3;
const MAX_COMPONENT_PAGES = 10_000;
const MAX_COMPONENT_RECORDS = 10_000_000;
const FRAME_HEADER_BYTES = 4;
const MAX_SUBJECT_REF_BYTES = 65_536;
const TEMP_PREFIX = `iam-organization-reconciliation-spool-${process.pid}-`;
const TEMP_FILE_NAME = "dataset-pages.spool";

let activeSpoolBytes = 0;
let activeSpoolCount = 0;
const spoolBrands = new WeakMap<object, SpoolState>();
const replayPageBrands = new WeakMap<object, ReplayPageBrand>();

export async function openOrganizationReconciliationTransactionDatasetSpool(
  candidate: OpenOrganizationReconciliationTransactionDatasetSpoolOptions
): Promise<OrganizationReconciliationTransactionDatasetSpool> {
  const options = captureOptions(candidate);
  if (activeSpoolCount >= MAX_ACTIVE_SPOOLS) {
    options.commitmentKey.fill(0);
    options.subjectUniverse?.evidenceNonce.fill(0);
    throw new TransactionDatasetSpoolFailure("The process transaction spool budget is exhausted.");
  }
  activeSpoolCount += 1;
  let file: FileHandle | null = null;
  try {
    file = await openSecureAnonymousSpoolFile();
    const state: SpoolState = {
      phase: "appending",
      componentId: options.componentId,
      sourceId: options.sourceId,
      catalogSha256: options.catalogSha256,
      commitmentKey: options.commitmentKey,
      datasets: options.datasets.map((spec) => ({
        spec,
        frames: [],
        cursorDigests: new Set<string>(),
        expectedRequestCursor: null,
        recordCount: 0,
        terminal: false
      })),
      file,
      filePosition: 0,
      reservedBytes: 0,
      appendDatasetIndex: 0,
      inventory: null,
      verifier: null,
      replayDatasetIndex: 0,
      replayPageIndex: 0,
      replayExpectedCursor: null,
      replayAwaitingVerification: false,
      closePromise: null,
      cleanupFailed: false,
      poisoned: false,
      activeReservation: true,
      methods: null,
      subjectUniverse: options.subjectUniverse === null ? null : {
        datasetId: options.subjectUniverse.datasetId,
        evidenceNonce: options.subjectUniverse.evidenceNonce,
        runs: [],
        pendingFrameIndex: null,
        result: null
      },
      activeOperation: null,
      disposePromise: null
    };

    const appendPage: OrganizationReconciliationTransactionDatasetSpool["appendPage"] =
      async function (this: OrganizationReconciliationTransactionDatasetSpool, page) {
        const accepted = requireSpool(this, appendPage, "appendPage", ["appending"]);
        const operation = claimSpoolOperation(accepted, "appendPage");
        accepted.phase = "appending-page";
        try {
          await appendSpoolPage(accepted, page);
          accepted.phase = "appending";
        } catch {
          await poisonAndDispose(accepted);
          throw new TransactionDatasetSpoolFailure("Appending a bounded transaction spool page failed.");
        } finally {
          releaseSpoolOperation(accepted, operation);
        }
      };
    const appendSubjectUniversePage:
    OrganizationReconciliationTransactionDatasetSpool["appendSubjectUniversePage"] =
      async function (this: OrganizationReconciliationTransactionDatasetSpool, page) {
        const accepted = requireSpool(
          this, appendSubjectUniversePage, "appendSubjectUniversePage", ["appending"]
        );
        const operation = claimSpoolOperation(accepted, "appendSubjectUniversePage");
        accepted.phase = "appending-subjects";
        try {
          await appendSpoolSubjectUniversePage(accepted, page);
          accepted.phase = "appending";
        } catch {
          await poisonAndDispose(accepted);
          throw new TransactionDatasetSpoolFailure("Appending bounded subject-universe evidence failed.");
        } finally {
          releaseSpoolOperation(accepted, operation);
        }
      };
    const seal: OrganizationReconciliationTransactionDatasetSpool["seal"] =
      async function (this: OrganizationReconciliationTransactionDatasetSpool) {
        const accepted = requireSpool(this, seal, "seal", ["appending"]);
        const operation = claimSpoolOperation(accepted, "seal");
        accepted.phase = "sealing";
        try {
          return await sealSpool(accepted);
        } catch {
          await poisonAndDispose(accepted);
          throw new TransactionDatasetSpoolFailure("Sealing the bounded transaction spool failed.");
        } finally {
          releaseSpoolOperation(accepted, operation);
        }
      };
    const readPage: OrganizationReconciliationTransactionDatasetSpool["readPage"] =
      async function (this: OrganizationReconciliationTransactionDatasetSpool, request) {
        const accepted = requireSpool(this, readPage, "readPage", ["sealed"]);
        const operation = claimSpoolOperation(accepted, "readPage");
        accepted.phase = "reading";
        try {
          const page = await readSpoolPage(accepted, request);
          accepted.phase = "sealed";
          return page;
        } catch {
          await poisonAndDispose(accepted);
          throw new TransactionDatasetSpoolFailure("Reading a bounded transaction spool page failed.");
        } finally {
          releaseSpoolOperation(accepted, operation);
        }
      };
    const verifyDatasetReplay: OrganizationReconciliationTransactionDatasetSpool["verifyDatasetReplay"] =
      function (this: OrganizationReconciliationTransactionDatasetSpool, request) {
        const accepted = requireSpool(this, verifyDatasetReplay, "verifyDatasetReplay", ["sealed"]);
        try {
          verifySpoolDatasetReplay(accepted, request);
        } catch {
          poisonUntilClose(accepted);
          throw new TransactionDatasetSpoolFailure("Verifying bounded transaction spool replay failed.");
        }
      };
    const subjectUniverse: OrganizationReconciliationTransactionDatasetSpool["subjectUniverse"] =
      function (this: OrganizationReconciliationTransactionDatasetSpool) {
        const accepted = requireSpool(this, subjectUniverse, "subjectUniverse", ["sealed"]);
        const result = accepted.subjectUniverse?.result;
        if (result === null || result === undefined) {
          throw new TransactionDatasetSpoolFailure("Bounded subject-universe evidence is unavailable.");
        }
        return result;
      };
    const close: OrganizationReconciliationTransactionDatasetSpool["close"] =
      function (this: OrganizationReconciliationTransactionDatasetSpool, outcome) {
        const accepted = requireSpoolBrand(this, close, "close");
        if (accepted.closePromise !== null) return accepted.closePromise;
        const pendingOperation = accepted.activeOperation?.done ?? Promise.resolve();
        accepted.closePromise = pendingOperation.then(async () => {
          const operation = claimSpoolOperation(accepted, "close");
          try {
            return await closeSpool(accepted, outcome);
          } finally {
            releaseSpoolOperation(accepted, operation);
          }
        });
        return accepted.closePromise;
      };
    const spool = Object.freeze({
      contract: ORGANIZATION_RECONCILIATION_TRANSACTION_DATASET_SPOOL_CONTRACT,
      appendPage,
      appendSubjectUniversePage,
      seal,
      readPage,
      verifyDatasetReplay,
      subjectUniverse,
      close
    });
    state.methods = Object.freeze({
      appendPage, appendSubjectUniversePage, seal, readPage, verifyDatasetReplay, subjectUniverse, close
    });
    spoolBrands.set(spool, state);
    return spool;
  } catch {
    options.commitmentKey.fill(0);
    options.subjectUniverse?.evidenceNonce.fill(0);
    if (file !== null) await file.close().catch(() => undefined);
    activeSpoolCount -= 1;
    throw new TransactionDatasetSpoolFailure("Opening the bounded transaction spool failed.");
  }
}

async function appendSpoolPage(
  state: SpoolState,
  candidate: OrganizationReconciliationTransactionDatasetSpoolAppendPageInput
): Promise<void> {
  if (state.subjectUniverse !== null && state.subjectUniverse.pendingFrameIndex !== null) {
    throw new TransactionDatasetSpoolFailure("subject-universe page evidence is pending");
  }
  const input = strictObject(candidate, ["datasetId", "requestCursor", "nextCursor", "recordOffset", "records"]);
  const dataset = state.datasets[state.appendDatasetIndex];
  if (!dataset || dataset.terminal || input.datasetId !== dataset.spec.datasetId) {
    throw new TransactionDatasetSpoolFailure("invalid dataset order");
  }
  const requestCursor = nullableCursor(input.requestCursor);
  const nextCursor = nullableCursor(input.nextCursor);
  const recordOffset = boundedInteger(input.recordOffset, 0, dataset.spec.maxRecords, "record offset");
  const records = strictArray(input.records, "page records", 0, dataset.spec.pageSize);
  if (requestCursor !== dataset.expectedRequestCursor || recordOffset !== dataset.recordCount ||
    dataset.frames.length >= dataset.spec.maxPages ||
    dataset.recordCount + records.length > dataset.spec.maxRecords) {
    throw new TransactionDatasetSpoolFailure("invalid page lineage");
  }
  if (nextCursor !== null && records.length !== dataset.spec.pageSize) {
    throw new TransactionDatasetSpoolFailure("short non-terminal page");
  }
  if (nextCursor !== null) {
    const digest = cursorDigest(nextCursor);
    if (dataset.cursorDigests.has(digest)) throw new TransactionDatasetSpoolFailure("repeated cursor");
    dataset.cursorDigests.add(digest);
  }
  const payloadBuffer = encodeOrganizationReconciliationInventoryPageRecords(
    records, dataset.spec.pageSize, MAX_PAGE_SPOOL_BYTES
  );
  const frameBytes = FRAME_HEADER_BYTES + payloadBuffer.byteLength;
  reserveBytes(state, frameBytes);
  const header = Buffer.allocUnsafe(FRAME_HEADER_BYTES);
  header.writeUInt32BE(payloadBuffer.byteLength, 0);
  const file = requireFile(state);
  const frameStart = state.filePosition;
  try {
    await writeFully(file, header, frameStart);
    await writeFully(file, payloadBuffer, frameStart + FRAME_HEADER_BYTES);
  } catch {
    throw new TransactionDatasetSpoolFailure("spool write failed");
  } finally {
    header.fill(0);
    payloadBuffer.fill(0);
  }
  dataset.frames.push(Object.freeze({
    payloadOffset: frameStart + FRAME_HEADER_BYTES,
    payloadLength: payloadBuffer.byteLength,
    requestCursor,
    nextCursor,
    recordOffset,
    recordCount: records.length
  }));
  if (state.subjectUniverse?.datasetId === dataset.spec.datasetId) {
    state.subjectUniverse.pendingFrameIndex = dataset.frames.length - 1;
  }
  state.filePosition += frameBytes;
  dataset.recordCount += records.length;
  dataset.expectedRequestCursor = nextCursor;
  if (nextCursor === null) {
    dataset.terminal = true;
    state.appendDatasetIndex += 1;
  }
}

async function appendSpoolSubjectUniversePage(
  state: SpoolState,
  candidate: {
    readonly datasetId: string;
    readonly recordOffset: number;
    readonly subjectRefs: readonly string[];
  }
): Promise<void> {
  const input = strictObject(candidate, ["datasetId", "recordOffset", "subjectRefs"]);
  const subjectUniverse = state.subjectUniverse;
  if (subjectUniverse === null || input.datasetId !== subjectUniverse.datasetId ||
    subjectUniverse.pendingFrameIndex === null) {
    throw new TransactionDatasetSpoolFailure("invalid subject-universe page order");
  }
  const dataset = state.datasets.find((value) => value.spec.datasetId === subjectUniverse.datasetId);
  const frame = dataset?.frames[subjectUniverse.pendingFrameIndex];
  if (!dataset || !frame ||
    boundedInteger(input.recordOffset, 0, dataset.spec.maxRecords, "record offset") !== frame.recordOffset) {
    throw new TransactionDatasetSpoolFailure("subject-universe page lineage mismatch");
  }
  const captured = strictArray(input.subjectRefs, "subject references", 0, dataset.spec.pageSize);
  if (captured.length !== frame.recordCount) {
    throw new TransactionDatasetSpoolFailure("subject-universe page count mismatch");
  }
  const sorted = captured.map((value) => {
    if (typeof value !== "string" || value.length > MAX_SUBJECT_REF_BYTES ||
      !isCanonicalLegacyUserSubjectRef(value)) {
      throw new TransactionDatasetSpoolFailure("invalid canonical subject reference");
    }
    return value;
  }).sort(compareCanonicalSubjectRef);
  let runBytes = 0;
  for (let index = 0; index < sorted.length; index += 1) {
    if (index > 0 && sorted[index - 1] === sorted[index]) {
      throw new TransactionDatasetSpoolFailure("duplicate subject reference within page");
    }
    const valueBytes = Buffer.byteLength(sorted[index]!, "utf8");
    if (valueBytes < 1 || valueBytes > MAX_SUBJECT_REF_BYTES ||
      runBytes + FRAME_HEADER_BYTES + valueBytes > MAX_PAGE_SPOOL_BYTES) {
      throw new TransactionDatasetSpoolFailure("subject-universe page exceeds its byte bound");
    }
    runBytes += FRAME_HEADER_BYTES + valueBytes;
  }
  if (runBytes > 0) reserveBytes(state, runBytes);
  const file = requireFile(state);
  const start = state.filePosition;
  let position = start;
  try {
    for (const value of sorted) {
      const payload = Buffer.from(value, "utf8");
      const header = Buffer.allocUnsafe(FRAME_HEADER_BYTES);
      header.writeUInt32BE(payload.byteLength, 0);
      try {
        await writeFully(file, header, position);
        await writeFully(file, payload, position + FRAME_HEADER_BYTES);
      } finally {
        header.fill(0);
        payload.fill(0);
      }
      position += FRAME_HEADER_BYTES + Buffer.byteLength(value, "utf8");
    }
  } catch {
    throw new TransactionDatasetSpoolFailure("subject-universe spool write failed");
  }
  if (position !== start + runBytes) {
    throw new TransactionDatasetSpoolFailure("subject-universe spool length drift");
  }
  subjectUniverse.runs.push(Object.freeze({ start, end: position, count: sorted.length }));
  state.filePosition = position;
  subjectUniverse.pendingFrameIndex = null;
}

async function mergeSubjectUniverse(
  state: SpoolState,
  file: FileHandle
): Promise<OrganizationReconciliationTransactionSubjectUniverse> {
  const subjectUniverse = state.subjectUniverse;
  if (subjectUniverse === null) throw new TransactionDatasetSpoolFailure("subject-universe state unavailable");
  const dataset = state.datasets.find((value) => value.spec.datasetId === subjectUniverse.datasetId);
  if (!dataset || subjectUniverse.pendingFrameIndex !== null ||
    subjectUniverse.runs.length !== dataset.frames.length || dataset.recordCount < 1 ||
    subjectUniverse.runs.reduce((sum, run) => sum + run.count, 0) !== dataset.recordCount) {
    throw new TransactionDatasetSpoolFailure("incomplete subject-universe sidecar");
  }
  let builder: ReturnType<typeof createOrganizationReconciliationStringArrayEvidenceHashBuilder> | null = null;
  try {
    builder = createOrganizationReconciliationStringArrayEvidenceHashBuilder(
      subjectUniverse.evidenceNonce
    );
    const heap: SubjectRunReader[] = [];
    for (let index = 0; index < subjectUniverse.runs.length; index += 1) {
      const run = subjectUniverse.runs[index]!;
      const reader: SubjectRunReader = {
        runIndex: index,
        end: run.end,
        position: run.start,
        remaining: run.count,
        value: ""
      };
      if (await advanceSubjectRun(file, reader)) heapPushSubjectReader(heap, reader);
    }
    let previous: string | null = null;
    let count = 0;
    while (heap.length > 0) {
      const reader = heapPopSubjectReader(heap)!;
      const value = reader.value;
      if (previous !== null && compareCanonicalSubjectRef(previous, value) >= 0) {
        throw new TransactionDatasetSpoolFailure("subject-universe merge is duplicate or unordered");
      }
      builder.append(value);
      previous = value;
      count += 1;
      if (count > dataset.recordCount) {
        throw new TransactionDatasetSpoolFailure("subject-universe merge count exceeded");
      }
      if (await advanceSubjectRun(file, reader)) heapPushSubjectReader(heap, reader);
    }
    if (count !== dataset.recordCount) {
      throw new TransactionDatasetSpoolFailure("subject-universe merge count mismatch");
    }
    const hash = builder.seal();
    builder = null;
    return Object.freeze({ count, hash });
  } catch (error) {
    if (builder !== null) {
      try { builder.abort(); } catch { /* builder already sealed or poisoned */ }
    }
    throw error;
  } finally {
    subjectUniverse.evidenceNonce.fill(0);
  }
}

async function advanceSubjectRun(file: FileHandle, reader: SubjectRunReader): Promise<boolean> {
  if (reader.remaining === 0) {
    if (reader.position !== reader.end) throw new TransactionDatasetSpoolFailure("subject run has trailing bytes");
    reader.value = "";
    return false;
  }
  const header = Buffer.alloc(FRAME_HEADER_BYTES);
  let payload: Buffer | null = null;
  let roundTrip: Buffer | null = null;
  try {
    if (reader.position + FRAME_HEADER_BYTES > reader.end) {
      throw new TransactionDatasetSpoolFailure("truncated subject run header");
    }
    await readFully(file, header, reader.position);
    const length = header.readUInt32BE(0);
    if (length < 1 || length > MAX_SUBJECT_REF_BYTES ||
      reader.position + FRAME_HEADER_BYTES + length > reader.end) {
      throw new TransactionDatasetSpoolFailure("invalid subject run frame");
    }
    payload = Buffer.alloc(length);
    await readFully(file, payload, reader.position + FRAME_HEADER_BYTES);
    const value = payload.toString("utf8");
    roundTrip = Buffer.from(value, "utf8");
    if (!roundTrip.equals(payload) || !isCanonicalLegacyUserSubjectRef(value)) {
      throw new TransactionDatasetSpoolFailure("invalid subject run value");
    }
    reader.position += FRAME_HEADER_BYTES + length;
    reader.remaining -= 1;
    if (reader.remaining === 0 && reader.position !== reader.end) {
      throw new TransactionDatasetSpoolFailure("subject run length mismatch");
    }
    reader.value = value;
    return true;
  } finally {
    header.fill(0);
    payload?.fill(0);
    roundTrip?.fill(0);
  }
}

function compareCanonicalSubjectRef(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function compareSubjectRunReader(left: SubjectRunReader, right: SubjectRunReader): number {
  return compareCanonicalSubjectRef(left.value, right.value) || left.runIndex - right.runIndex;
}

function heapPushSubjectReader(heap: SubjectRunReader[], value: SubjectRunReader): void {
  heap.push(value);
  let index = heap.length - 1;
  while (index > 0) {
    const parent = Math.floor((index - 1) / 2);
    if (compareSubjectRunReader(heap[parent]!, heap[index]!) <= 0) break;
    [heap[parent], heap[index]] = [heap[index]!, heap[parent]!];
    index = parent;
  }
}

function heapPopSubjectReader(heap: SubjectRunReader[]): SubjectRunReader | undefined {
  const first = heap[0];
  const last = heap.pop();
  if (first === undefined || last === undefined || heap.length === 0) return first;
  heap[0] = last;
  let index = 0;
  while (true) {
    const left = index * 2 + 1;
    const right = left + 1;
    if (left >= heap.length) break;
    const smallest = right < heap.length && compareSubjectRunReader(heap[right]!, heap[left]!) < 0 ? right : left;
    if (compareSubjectRunReader(heap[index]!, heap[smallest]!) <= 0) break;
    [heap[index], heap[smallest]] = [heap[smallest]!, heap[index]!];
    index = smallest;
  }
  return first;
}

async function sealSpool(state: SpoolState): Promise<OrganizationReconciliationComponentDatasetInventory> {
  if (state.appendDatasetIndex !== state.datasets.length || state.datasets.some((dataset) =>
    !dataset.terminal || dataset.frames.length < 1
  ) || (state.subjectUniverse !== null && state.subjectUniverse.pendingFrameIndex !== null)) {
    throw new TransactionDatasetSpoolFailure("partial spool");
  }
  const file = requireFile(state);
  await file.sync();
  const subjectUniverse = state.subjectUniverse === null ? null : await mergeSubjectUniverse(state, file);
  const builder = createOrganizationReconciliationIncrementalDatasetInventoryBuilder({
    componentId: state.componentId,
    sourceId: state.sourceId,
    catalogSha256: state.catalogSha256,
    commitmentKey: state.commitmentKey
  });
  try {
    for (const dataset of state.datasets) {
      for (let index = 0; index < dataset.frames.length; index += 1) {
        const frame = dataset.frames[index]!;
        const records = await readFrameRecords(file, frame);
        builder.appendPage({
          datasetId: dataset.spec.datasetId,
          datasetRecordCount: dataset.recordCount,
          datasetPageCount: dataset.frames.length,
          pageNumber: index + 1,
          requestCursor: frame.requestCursor,
          nextCursor: frame.nextCursor,
          recordOffset: frame.recordOffset,
          records
        });
      }
    }
    const inventory = builder.seal();
    const verifier = createOrganizationReconciliationIncrementalDatasetInventoryBuilder({
      componentId: state.componentId,
      sourceId: state.sourceId,
      catalogSha256: state.catalogSha256,
      commitmentKey: state.commitmentKey
    });
    state.commitmentKey.fill(0);
    state.inventory = inventory;
    state.verifier = verifier;
    if (state.subjectUniverse !== null) state.subjectUniverse.result = subjectUniverse;
    state.phase = "sealed";
    return inventory;
  } catch (error) {
    try { builder.abort(); } catch { /* builder already sealed or poisoned */ }
    throw error;
  }
}

async function readSpoolPage(
  state: SpoolState,
  candidate: OrganizationReconciliationTransactionDatasetSpoolReadPageRequest
): Promise<OrganizationReconciliationTransactionDatasetSpoolReadPage> {
  if (state.replayAwaitingVerification) throw new TransactionDatasetSpoolFailure("dataset replay not verified");
  const request = strictObject(candidate, ["datasetId", "requestCursor", "pageSize"]);
  const dataset = state.datasets[state.replayDatasetIndex];
  if (!dataset || request.datasetId !== dataset.spec.datasetId ||
    nullableCursor(request.requestCursor) !== state.replayExpectedCursor ||
    request.pageSize !== dataset.spec.pageSize) {
    throw new TransactionDatasetSpoolFailure("invalid replay request");
  }
  const frame = dataset.frames[state.replayPageIndex];
  if (!frame || frame.requestCursor !== state.replayExpectedCursor) {
    throw new TransactionDatasetSpoolFailure("unavailable replay frame");
  }
  const records = await readFrameRecords(requireFile(state), frame);
  const pageIndex = state.replayPageIndex;
  const verifier = state.verifier;
  const inventory = state.inventory;
  if (!verifier || !inventory) throw new TransactionDatasetSpoolFailure("replay verifier unavailable");
  const result = verifier.appendPage({
    datasetId: dataset.spec.datasetId,
    datasetRecordCount: dataset.recordCount,
    datasetPageCount: dataset.frames.length,
    pageNumber: pageIndex + 1,
    requestCursor: frame.requestCursor,
    nextCursor: frame.nextCursor,
    recordOffset: frame.recordOffset,
    records
  });
  if (JSON.stringify(result.page) !== JSON.stringify(inventory.datasets[state.replayDatasetIndex]!.pages[pageIndex]) ||
    (result.completedDataset && JSON.stringify(result.completedDataset) !==
      JSON.stringify(inventory.datasets[state.replayDatasetIndex]))) {
    throw new TransactionDatasetSpoolFailure("replay commitment mismatch");
  }
  replayPageBrands.set(records, Object.freeze({ state, datasetIndex: state.replayDatasetIndex, pageIndex }));
  state.replayPageIndex += 1;
  state.replayExpectedCursor = frame.nextCursor;
  if (frame.nextCursor === null) {
    if (!result.completedDataset) throw new TransactionDatasetSpoolFailure("incomplete replay commitment");
    state.replayAwaitingVerification = true;
    if (state.replayDatasetIndex === state.datasets.length - 1) {
      const replayInventory = verifier.seal();
      state.verifier = null;
      if (JSON.stringify(replayInventory) !== JSON.stringify(inventory)) {
        throw new TransactionDatasetSpoolFailure("inventory commitment mismatch");
      }
    }
  }
  return Object.freeze({
    datasetId: dataset.spec.datasetId,
    datasetRecordCount: dataset.recordCount,
    requestCursor: frame.requestCursor,
    nextCursor: frame.nextCursor,
    recordOffset: frame.recordOffset,
    records
  });
}

function verifySpoolDatasetReplay(
  state: SpoolState,
  candidate: OrganizationReconciliationTransactionDatasetSpoolReplayVerificationRequest
): void {
  const request = strictObject(candidate, ["datasetId", "pages"]);
  const datasetIndex = state.replayDatasetIndex;
  const dataset = state.datasets[datasetIndex];
  const inventory = state.inventory;
  if (!dataset || !inventory || request.datasetId !== dataset.spec.datasetId ||
    !state.replayAwaitingVerification || state.replayPageIndex !== dataset.frames.length) {
    throw new TransactionDatasetSpoolFailure("invalid replay verification");
  }
  const pages = strictArray(request.pages, "replay pages", dataset.frames.length, dataset.frames.length);
  for (let index = 0; index < pages.length; index += 1) {
    const input = strictObject(pages[index], ["requestCursor", "nextCursor", "recordOffset", "records"]);
    const frame = dataset.frames[index]!;
    if (input.requestCursor !== frame.requestCursor || input.nextCursor !== frame.nextCursor ||
      input.recordOffset !== frame.recordOffset || !Array.isArray(input.records) ||
      replayPageBrands.get(input.records)?.state !== state ||
      replayPageBrands.get(input.records)?.datasetIndex !== datasetIndex ||
      replayPageBrands.get(input.records)?.pageIndex !== index) {
      throw new TransactionDatasetSpoolFailure("unbranded replay page");
    }
  }
  state.replayDatasetIndex += 1;
  state.replayPageIndex = 0;
  state.replayExpectedCursor = null;
  state.replayAwaitingVerification = false;
}

async function closeSpool(state: SpoolState, outcome: "completed" | "failed"): Promise<"completed" | "failed"> {
  state.phase = "closing";
  const validOutcome = outcome === "completed" || outcome === "failed";
  const complete = state.inventory !== null && state.replayDatasetIndex === state.datasets.length &&
    state.verifier === null && !state.replayAwaitingVerification && !state.cleanupFailed && !state.poisoned &&
    (state.subjectUniverse === null || state.subjectUniverse.result !== null);
  const acceptedOutcome = validOutcome && outcome === "completed" && complete ? "completed" : "failed";
  await disposeState(state, false);
  if (!validOutcome) throw new TransactionDatasetSpoolFailure("The transaction spool close outcome is invalid.");
  if (outcome === "completed" && !complete) {
    throw new TransactionDatasetSpoolFailure("The transaction spool was not consumed completely.");
  }
  if (state.cleanupFailed) throw new TransactionDatasetSpoolFailure("Closing the transaction spool failed.");
  return acceptedOutcome;
}

async function poisonAndDispose(state: SpoolState): Promise<void> {
  state.poisoned = true;
  state.phase = "poisoned";
  await disposeState(state, true);
}

function poisonUntilClose(state: SpoolState): void {
  state.poisoned = true;
  state.phase = "poisoned";
  if (state.verifier !== null) {
    try { state.verifier.abort(); } catch { /* already sealed or poisoned */ }
    state.verifier = null;
  }
  state.commitmentKey.fill(0);
  state.subjectUniverse?.evidenceNonce.fill(0);
}

async function disposeState(state: SpoolState, poisoned: boolean): Promise<void> {
  if (poisoned) state.poisoned = true;
  if (state.disposePromise === null) state.disposePromise = disposeStateOnce(state);
  await state.disposePromise;
  state.phase = state.poisoned ? "poisoned" : "closed";
}

async function disposeStateOnce(state: SpoolState): Promise<void> {
  try {
    if (state.verifier !== null) {
      try { state.verifier.abort(); } catch { /* already sealed or poisoned */ }
      state.verifier = null;
    }
    state.commitmentKey.fill(0);
    state.subjectUniverse?.evidenceNonce.fill(0);
    const file = state.file;
    state.file = null;
    if (file !== null) {
      try {
        await file.close();
      } catch {
        state.cleanupFailed = true;
      }
    }
  } finally {
    if (state.reservedBytes > 0) {
      activeSpoolBytes -= state.reservedBytes;
      state.reservedBytes = 0;
    }
    if (state.activeReservation) {
      activeSpoolCount -= 1;
      state.activeReservation = false;
    }
  }
}

function reserveBytes(state: SpoolState, bytes: number): void {
  if (!Number.isSafeInteger(bytes) || bytes < FRAME_HEADER_BYTES ||
    state.reservedBytes + bytes > MAX_COMPONENT_SPOOL_BYTES ||
    activeSpoolBytes + bytes > MAX_GLOBAL_ACTIVE_SPOOL_BYTES) {
    throw new TransactionDatasetSpoolFailure("spool byte budget exhausted");
  }
  state.reservedBytes += bytes;
  activeSpoolBytes += bytes;
}

async function openSecureAnonymousSpoolFile(): Promise<FileHandle> {
  let directoryPath: string | null = null;
  let filePath: string | null = null;
  let file: FileHandle | null = null;
  try {
    const canonicalTempRoot = await realpath(tmpdir());
    if (!isAbsolute(canonicalTempRoot)) throw new TransactionDatasetSpoolFailure("invalid temp root");
    directoryPath = await mkdtemp(join(canonicalTempRoot, TEMP_PREFIX));
    await chmod(directoryPath, 0o700);
    const directoryBefore = await lstat(directoryPath);
    assertPrivateDirectory(directoryBefore);
    filePath = join(directoryPath, TEMP_FILE_NAME);
    const noFollow = constants.O_NOFOLLOW ?? 0;
    const closeOnExec = (constants as unknown as Record<string, number>).O_CLOEXEC ?? 0;
    file = await open(
      filePath,
      constants.O_CREAT | constants.O_EXCL | constants.O_RDWR | noFollow | closeOnExec,
      0o600
    );
    await file.chmod(0o600);
    const [directoryAfter, pathStat, fileStat] = await Promise.all([
      lstat(directoryPath),
      lstat(filePath),
      file.stat()
    ]);
    assertSameDirectory(directoryBefore, directoryAfter);
    assertPrivateRegularFile(pathStat, fileStat);
    await unlink(filePath);
    filePath = null;
    const unlinkedStat = await file.stat();
    if (unlinkedStat.nlink !== 0) throw new TransactionDatasetSpoolFailure("spool unlink failed");
    await rmdir(directoryPath);
    directoryPath = null;
    return file;
  } catch {
    if (file !== null) await file.close().catch(() => undefined);
    if (filePath !== null) await unlink(filePath).catch(() => undefined);
    if (directoryPath !== null) await rmdir(directoryPath).catch(() => undefined);
    throw new TransactionDatasetSpoolFailure("Secure transaction spool initialization failed.");
  }
}

function assertPrivateDirectory(stat: Awaited<ReturnType<typeof lstat>>): void {
  if (!stat.isDirectory() || stat.isSymbolicLink() || (Number(stat.mode) & 0o777) !== 0o700 ||
    (typeof process.getuid === "function" && stat.uid !== process.getuid())) {
    throw new TransactionDatasetSpoolFailure("invalid private spool directory");
  }
}

function assertSameDirectory(
  before: Awaited<ReturnType<typeof lstat>>,
  after: Awaited<ReturnType<typeof lstat>>
): void {
  assertPrivateDirectory(after);
  if (before.dev !== after.dev || before.ino !== after.ino) {
    throw new TransactionDatasetSpoolFailure("spool directory changed");
  }
}

function assertPrivateRegularFile(
  pathStat: Awaited<ReturnType<typeof lstat>>,
  fileStat: Awaited<ReturnType<FileHandle["stat"]>>
): void {
  if (!pathStat.isFile() || pathStat.isSymbolicLink() || !fileStat.isFile() ||
    pathStat.dev !== fileStat.dev || pathStat.ino !== fileStat.ino || fileStat.nlink !== 1 ||
    (Number(pathStat.mode) & 0o777) !== 0o600 || (Number(fileStat.mode) & 0o777) !== 0o600 ||
    (typeof process.getuid === "function" && fileStat.uid !== process.getuid())) {
    throw new TransactionDatasetSpoolFailure("invalid private spool file");
  }
}

async function writeFully(file: FileHandle, buffer: Buffer, position: number): Promise<void> {
  let offset = 0;
  while (offset < buffer.byteLength) {
    const result = await file.write(buffer, offset, buffer.byteLength - offset, position + offset);
    if (!Number.isSafeInteger(result.bytesWritten) || result.bytesWritten < 1 ||
      result.bytesWritten > buffer.byteLength - offset) {
      throw new TransactionDatasetSpoolFailure("short spool write");
    }
    offset += result.bytesWritten;
  }
}

async function readFrameRecords(
  file: FileHandle,
  frame: FrameMetadata
): Promise<readonly OrganizationReconciliationInventoryJsonValue[]> {
  const header = Buffer.alloc(FRAME_HEADER_BYTES);
  const payload = Buffer.alloc(frame.payloadLength);
  try {
    await readFully(file, header, frame.payloadOffset - FRAME_HEADER_BYTES);
    if (header.readUInt32BE(0) !== frame.payloadLength) throw new TransactionDatasetSpoolFailure("frame drift");
    await readFully(file, payload, frame.payloadOffset);
    const records = decodeOrganizationReconciliationInventoryPageRecords(
      payload, 5_000, MAX_PAGE_SPOOL_BYTES
    );
    if (records.length !== frame.recordCount) {
      throw new TransactionDatasetSpoolFailure("frame content drift");
    }
    return records;
  } catch {
    throw new TransactionDatasetSpoolFailure("spool frame read failed");
  } finally {
    header.fill(0);
    payload.fill(0);
  }
}

async function readFully(file: FileHandle, buffer: Buffer, position: number): Promise<void> {
  let offset = 0;
  while (offset < buffer.byteLength) {
    const result = await file.read(buffer, offset, buffer.byteLength - offset, position + offset);
    if (!Number.isSafeInteger(result.bytesRead) || result.bytesRead < 1 ||
      result.bytesRead > buffer.byteLength - offset) {
      throw new TransactionDatasetSpoolFailure("short spool read");
    }
    offset += result.bytesRead;
  }
}

function captureOptions(candidate: unknown): {
  readonly componentId: string;
  readonly sourceId: string;
  readonly catalogSha256: string;
  readonly commitmentKey: Buffer;
  readonly datasets: readonly OrganizationReconciliationDatasetSpec[];
  readonly subjectUniverse: CapturedSubjectUniverseOptions | null;
} {
  const options = strictObject(candidate, [
    "componentId", "sourceId", "catalogSha256", "datasetCatalog", "commitmentKey", "subjectUniverse"
  ]);
  const componentId = datasetId(options.componentId);
  const sourceId = metadata(options.sourceId, "source ID");
  const catalogSha256 = sha256(options.catalogSha256, "catalog digest");
  if (!Buffer.isBuffer(options.commitmentKey) || options.commitmentKey.byteLength !== 32) {
    throw new TransactionDatasetSpoolFailure("A commitment key is required.");
  }
  const commitmentKey = Buffer.from(options.commitmentKey);
  let subjectUniverse: CapturedSubjectUniverseOptions | null = null;
  try {
    const catalog = strictObject(options.datasetCatalog, ["contract", "trust", "datasets"]);
    if (catalog.contract !== ORGANIZATION_RECONCILIATION_DATASET_LINEAGE_CONTRACT ||
      catalog.trust !== ORGANIZATION_RECONCILIATION_DATASET_CATALOG_TRUST) {
      throw new TransactionDatasetSpoolFailure("invalid structural catalog");
    }
    const ids = new Set<string>();
    const datasets = strictArray(catalog.datasets, "dataset catalog", 1, 64).map((candidateDataset) => {
      const spec = strictObject(candidateDataset, ["datasetId", "pageSize", "maxPages", "maxRecords"]);
      const accepted = Object.freeze({
        datasetId: datasetId(spec.datasetId),
        pageSize: boundedInteger(spec.pageSize, 1, 5_000, "page size"),
        maxPages: boundedInteger(spec.maxPages, 1, MAX_COMPONENT_PAGES, "page count"),
        maxRecords: boundedInteger(spec.maxRecords, 0, MAX_COMPONENT_RECORDS, "record count")
      });
      if (ids.has(accepted.datasetId)) throw new TransactionDatasetSpoolFailure("duplicate dataset");
      ids.add(accepted.datasetId);
      return accepted;
    }).sort((left, right) => left.datasetId < right.datasetId ? -1 : left.datasetId > right.datasetId ? 1 : 0);
    if (datasets.reduce((sum, spec) => sum + spec.maxPages, 0) > MAX_COMPONENT_PAGES ||
      datasets.reduce((sum, spec) => sum + spec.maxRecords, 0) > MAX_COMPONENT_RECORDS) {
      throw new TransactionDatasetSpoolFailure("aggregate catalog bound");
    }
    if (options.subjectUniverse !== null) {
      const expectedDatasetId = componentId === "legacy-main" ? "legacy-subject-universe" :
        componentId === "identity" ? "identity-subject-universe" : null;
      const candidateSubjectUniverse = strictObject(options.subjectUniverse, ["datasetId", "evidenceNonce"]);
      if (expectedDatasetId === null || candidateSubjectUniverse.datasetId !== expectedDatasetId ||
        !ids.has(expectedDatasetId) || typeof candidateSubjectUniverse.evidenceNonce !== "string" ||
        !/^[a-f0-9]{32,128}$/i.test(candidateSubjectUniverse.evidenceNonce)) {
        throw new TransactionDatasetSpoolFailure("invalid component-bound subject-universe sidecar");
      }
      subjectUniverse = Object.freeze({
        datasetId: expectedDatasetId,
        evidenceNonce: Buffer.from(candidateSubjectUniverse.evidenceNonce, "utf8")
      });
    }
    return Object.freeze({
      componentId,
      sourceId,
      catalogSha256,
      commitmentKey,
      datasets: Object.freeze(datasets),
      subjectUniverse
    });
  } catch (error) {
    commitmentKey.fill(0);
    subjectUniverse?.evidenceNonce.fill(0);
    throw error;
  }
}

function requireSpool(
  candidate: unknown,
  method: Function,
  operation: keyof SpoolMethods,
  phases: readonly SpoolState["phase"][]
): SpoolState {
  const state = requireSpoolBrand(candidate, method, operation);
  if (state.closePromise !== null || !phases.includes(state.phase)) {
    throw new TransactionDatasetSpoolFailure("invalid spool lifecycle");
  }
  return state;
}

function claimSpoolOperation(state: SpoolState, operation: keyof SpoolMethods): ActiveSpoolOperation {
  if (state.activeOperation !== null) {
    throw new TransactionDatasetSpoolFailure("another spool operation is active");
  }
  let finish!: () => void;
  const done = new Promise<void>((resolve) => { finish = resolve; });
  const claim = Object.freeze({ operation, done, finish });
  state.activeOperation = claim;
  return claim;
}

function releaseSpoolOperation(state: SpoolState, claim: ActiveSpoolOperation): void {
  if (state.activeOperation !== claim) {
    state.poisoned = true;
    state.phase = "poisoned";
    return;
  }
  state.activeOperation = null;
  claim.finish();
}

function requireSpoolBrand(
  candidate: unknown,
  method: Function,
  operation: keyof SpoolMethods
): SpoolState {
  if (!candidate || typeof candidate !== "object" || isProxy(candidate) || !Object.isFrozen(candidate)) {
    throw new TransactionDatasetSpoolFailure("invalid spool handle");
  }
  const state = spoolBrands.get(candidate);
  if (!state || state.methods?.[operation] !== method) {
    throw new TransactionDatasetSpoolFailure("invalid spool brand");
  }
  return state;
}

function requireFile(state: SpoolState): FileHandle {
  if (state.file === null) throw new TransactionDatasetSpoolFailure("spool file unavailable");
  return state.file;
}

function datasetId(value: unknown): string {
  if (typeof value !== "string" || !/^[a-z0-9][a-z0-9-]{0,127}$/.test(value)) {
    throw new TransactionDatasetSpoolFailure("invalid dataset ID");
  }
  return value;
}

function metadata(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length < 1 || value.length > 1_024 || value.trim() !== value ||
    value.normalize("NFC") !== value || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new TransactionDatasetSpoolFailure(`invalid ${label}`);
  }
  return value;
}

function sha256(value: unknown, label: string): string {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) {
    throw new TransactionDatasetSpoolFailure(`invalid ${label}`);
  }
  return value;
}

function nullableCursor(value: unknown): string | null {
  if (value === null) return null;
  if (typeof value !== "string" || value.length < 1 || value.length > 2_048 || value.trim() !== value) {
    throw new TransactionDatasetSpoolFailure("invalid cursor");
  }
  return value;
}

function boundedInteger(value: unknown, minimum: number, maximum: number, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    throw new TransactionDatasetSpoolFailure(`invalid ${label}`);
  }
  return value as number;
}

function cursorDigest(cursor: string): string {
  return createHash("sha256")
    .update("iam-organization-reconciliation:spool-cursor:v1\u001f", "utf8")
    .update(cursor, "utf8")
    .digest("hex");
}

class TransactionDatasetSpoolFailure extends Error {}
