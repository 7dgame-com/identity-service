import { createHash } from "node:crypto";
import {
  coordinateOrganizationReconciliationSnapshots,
  type CoordinateOrganizationReconciliationSnapshotsOptions,
  type OrganizationReconciliationComponentBinding
} from "./iam-organization-reconciliation-coordinator.js";
import {
  canonicalizeOrganizationReconciliationEvidenceValue,
  type OrganizationReconciliationCompositeManifest,
  type OrganizationReconciliationEvidenceJsonValue,
  type OrganizationReconciliationPhysicalSource
} from "./iam-organization-reconciliation-component-manifest.js";
import type {
  OrganizationReconciliationSourceAdapter,
  OrganizationReconciliationSourceSnapshot
} from "./iam-organization-reconciliation-collector.js";

export const ORGANIZATION_RECONCILIATION_DATASET_LINEAGE_CONTRACT =
  "iam-organization-reconciliation-snapshot-dataset-lineage/v1" as const;
export const ORGANIZATION_RECONCILIATION_DATASET_CATALOG_TRUST =
  "caller-structured-untrusted" as const;
/** No runtime adapter, owner-approved dataset catalog, or projector is registered. */
export const ORGANIZATION_RECONCILIATION_DATASET_LINEAGE_PRODUCTION_READY = false as const;

export interface OrganizationReconciliationDatasetSpec {
  readonly datasetId: string;
  readonly pageSize: number;
  readonly maxPages: number;
  readonly maxRecords: number;
}

/** Structural routing only. Its digest is not an owner-approved catalog pin. */
export interface OrganizationReconciliationDatasetCatalog {
  readonly contract: typeof ORGANIZATION_RECONCILIATION_DATASET_LINEAGE_CONTRACT;
  readonly trust: typeof ORGANIZATION_RECONCILIATION_DATASET_CATALOG_TRUST;
  readonly datasets: readonly OrganizationReconciliationDatasetSpec[];
}

export interface OrganizationReconciliationDatasetPageRequest {
  readonly snapshot: OrganizationReconciliationSourceSnapshot;
  readonly datasetId: string;
  readonly requestCursor: string | null;
  readonly pageSize: number;
}

export interface OrganizationReconciliationDatasetPage<TRawRecord> {
  readonly sourceId: string;
  readonly sourceVersion: string;
  readonly snapshotId: string;
  /** Aggregate raw rows across every declared dataset in this component. */
  readonly snapshotRecordCount: number;
  readonly subjectUniverseCount: number;
  readonly subjectUniverseHash: string;
  readonly datasetId: string;
  /** Raw rows in this dataset only, repeated identically on every page. */
  readonly datasetRecordCount: number;
  readonly requestCursor: string | null;
  readonly nextCursor: string | null;
  /** Dataset-local raw offset. */
  readonly recordOffset: number;
  readonly records: readonly TRawRecord[];
}

/**
 * Future bridge contract only. Existing raw MySQL adapters do not yet emit the
 * transaction-owned `datasetRecordCount` required here and are not wired in.
 */
export interface OrganizationReconciliationDatasetSourceAdapter<TRawRecord>
  extends Pick<OrganizationReconciliationSourceAdapter<TRawRecord>, "sourceId" | "openSnapshot" | "closeSnapshot"> {
  readSnapshotPage(
    request: OrganizationReconciliationDatasetPageRequest
  ): Promise<OrganizationReconciliationDatasetPage<TRawRecord>>;
}

export interface OrganizationReconciliationDatasetComponentBinding
  extends Omit<OrganizationReconciliationComponentBinding, "adapter"> {
  readonly adapter: OrganizationReconciliationDatasetSourceAdapter<unknown>;
  readonly datasetCatalog: OrganizationReconciliationDatasetCatalog;
}

export interface OrganizationReconciliationDatasetPageLineage {
  readonly pageNumber: number;
  readonly sourceId: string;
  readonly sourceVersion: string;
  readonly snapshotId: string;
  readonly datasetId: string;
  readonly requestCursor: string | null;
  readonly nextCursor: string | null;
  readonly recordOffset: number;
  readonly recordCount: number;
  readonly recordsSha256: string;
  /** Caller-declared component catalog digest; not verified as an owner pin here. */
  readonly declaredCatalogSha256: string;
  /** Process-generated digest of the explicitly untrusted structural catalog. */
  readonly structuralCatalogSha256: string;
}

export interface OrganizationReconciliationDatasetLineageArtifact {
  readonly componentId: OrganizationReconciliationPhysicalSource;
  readonly sourceVersion: string;
  readonly snapshotId: string;
  readonly datasetId: string;
  readonly recordCount: number;
  readonly recordsSha256: string;
  readonly records: readonly OrganizationReconciliationEvidenceJsonValue[];
  readonly pages: readonly OrganizationReconciliationDatasetPageLineage[];
  readonly lineageSha256: string;
}

export interface OrganizationReconciliationDatasetLineageReadiness {
  readonly ready: false;
  readonly blockers: readonly [
    "real-dataset-adapters-not-registered",
    "compiled-owner-catalog-not-registered",
    "trusted-physical-source-binding-not-registered",
    "transaction-owned-dataset-counts-not-implemented",
    "dataset-unique-order-contract-not-registered",
    "operation-evidence-projector-not-implemented"
  ];
}

export interface OrganizationReconciliationDatasetLineageRun {
  readonly contract: typeof ORGANIZATION_RECONCILIATION_DATASET_LINEAGE_CONTRACT;
  readonly catalogTrust: typeof ORGANIZATION_RECONCILIATION_DATASET_CATALOG_TRUST;
  readonly crossDatabaseAtomic: false;
  readonly readiness: OrganizationReconciliationDatasetLineageReadiness;
  readonly artifacts: readonly OrganizationReconciliationDatasetLineageArtifact[];
  readonly coordinatorManifest: OrganizationReconciliationCompositeManifest;
}

export interface CollectOrganizationReconciliationDatasetLineageOptions
  extends Omit<CoordinateOrganizationReconciliationSnapshotsOptions, "components"> {
  readonly components: readonly OrganizationReconciliationDatasetComponentBinding[];
}

interface PreparedComponent {
  readonly componentId: OrganizationReconciliationPhysicalSource;
  readonly binding: OrganizationReconciliationComponentBinding;
  readonly originalAdapter: OrganizationReconciliationDatasetSourceAdapter<unknown>;
  readonly sourceId: string;
  readonly readSnapshotPage: OrganizationReconciliationDatasetSourceAdapter<unknown>["readSnapshotPage"];
  readonly declaredCatalogSha256: string;
  readonly structuralCatalogSha256: string;
  readonly datasets: readonly OrganizationReconciliationDatasetSpec[];
  readonly snapshotHandle: { value?: OrganizationReconciliationSourceSnapshot };
}

interface RunBrand {
  readonly artifacts: readonly OrganizationReconciliationDatasetLineageArtifact[];
  readonly manifest: OrganizationReconciliationCompositeManifest;
  readonly consumed: WeakSet<object>;
}

const runBrands = new WeakMap<object, RunBrand>();
const artifactBrands = new WeakMap<object, { readonly run: OrganizationReconciliationDatasetLineageRun }>();
const PAGE_HASH_DOMAIN = Buffer.from("iam-organization-reconciliation:raw-dataset-page:v1\u001f", "utf8");
const RECORDS_HASH_DOMAIN = Buffer.from("iam-organization-reconciliation:raw-dataset-records:v1\u001f", "utf8");
const LINEAGE_HASH_DOMAIN = Buffer.from("iam-organization-reconciliation:dataset-lineage:v1\u001f", "utf8");
const CATALOG_HASH_DOMAIN = Buffer.from("iam-organization-reconciliation:untrusted-dataset-catalog:v1\u001f", "utf8");
const MAX_TOTAL_DATASET_PAGES = 10_000;
const MAX_TOTAL_DATASET_RECORDS = 10_000_000;

export function organizationReconciliationDatasetLineageReadiness(): OrganizationReconciliationDatasetLineageReadiness {
  return Object.freeze({
    ready: ORGANIZATION_RECONCILIATION_DATASET_LINEAGE_PRODUCTION_READY,
    blockers: Object.freeze([
      "real-dataset-adapters-not-registered",
      "compiled-owner-catalog-not-registered",
      "trusted-physical-source-binding-not-registered",
      "transaction-owned-dataset-counts-not-implemented",
      "dataset-unique-order-contract-not-registered",
      "operation-evidence-projector-not-implemented"
    ] as const)
  });
}

/**
 * Opens all three immutable component snapshots, reads every declared raw
 * dataset through its own cursor chain, and closes snapshots in the existing
 * coordinator lifecycle. There is no caller callback and no evidence projector.
 */
export async function collectOrganizationReconciliationDatasetLineage(
  options: CollectOrganizationReconciliationDatasetLineageOptions
): Promise<OrganizationReconciliationDatasetLineageRun> {
  const strictOptions = exactObject(
    options,
    ["components", "maxWindowMilliseconds", "clock"],
    "dataset lineage options"
  );
  const prepared = prepareComponents(
    strictOptions.components as readonly OrganizationReconciliationDatasetComponentBinding[]
  );
  const originalClock = strictOptions.clock;
  const capturedNow = requireFunction(originalClock, "now") as CoordinateOrganizationReconciliationSnapshotsOptions["clock"]["now"];
  const result = await coordinateOrganizationReconciliationSnapshots({
    components: prepared.ordered.map((component) => component.binding),
    maxWindowMilliseconds: strictOptions.maxWindowMilliseconds as number,
    clock: Object.freeze({ now: () => capturedNow.call(originalClock) })
  }, async (context) => {
    const artifacts: OrganizationReconciliationDatasetLineageArtifact[] = [];
    for (const coordinated of context.components) {
      const component = prepared.byId.get(coordinated.componentId)!;
      let componentRawCount = 0;
      for (const dataset of component.datasets) {
        const artifact = await collectDataset(component, coordinated.source, dataset);
        componentRawCount += artifact.recordCount;
        artifacts.push(artifact);
      }
      if (componentRawCount !== coordinated.source.recordCount) {
        throw new DatasetLineageFailure("Dataset raw counts do not cover the opened component snapshot.");
      }
    }
    return {
      contract: ORGANIZATION_RECONCILIATION_DATASET_LINEAGE_CONTRACT,
      catalogTrust: ORGANIZATION_RECONCILIATION_DATASET_CATALOG_TRUST,
      crossDatabaseAtomic: false as const,
      readiness: organizationReconciliationDatasetLineageReadiness(),
      artifacts
    } as unknown as OrganizationReconciliationEvidenceJsonValue;
  });

  const value = result.value as unknown as Omit<OrganizationReconciliationDatasetLineageRun, "coordinatorManifest">;
  const run = Object.freeze({ ...value, coordinatorManifest: result.manifest });
  runBrands.set(run, {
    artifacts: run.artifacts,
    manifest: run.coordinatorManifest,
    consumed: new WeakSet<object>()
  });
  for (const artifact of run.artifacts) artifactBrands.set(artifact, { run });
  return run;
}

/** Rejects clones, look-alikes, and artifacts from another collection run. */
export function assertOrganizationReconciliationDatasetArtifactBelongsToRun(
  run: OrganizationReconciliationDatasetLineageRun,
  artifact: OrganizationReconciliationDatasetLineageArtifact
): OrganizationReconciliationDatasetLineageArtifact {
  const runBrand = run && typeof run === "object" ? runBrands.get(run) : undefined;
  const artifactBrand = artifact && typeof artifact === "object" ? artifactBrands.get(artifact) : undefined;
  if (
    !runBrand || artifactBrand?.run !== run ||
    run.artifacts !== runBrand.artifacts || run.coordinatorManifest !== runBrand.manifest ||
    !run.artifacts.includes(artifact)
  ) {
    throw new DatasetLineageFailure("The dataset lineage artifact is forged or belongs to another run.");
  }
  return artifact;
}

/** Future projectors must consume each branded artifact at most once. */
export function consumeOrganizationReconciliationDatasetArtifact(
  run: OrganizationReconciliationDatasetLineageRun,
  artifact: OrganizationReconciliationDatasetLineageArtifact
): OrganizationReconciliationDatasetLineageArtifact {
  const accepted = assertOrganizationReconciliationDatasetArtifactBelongsToRun(run, artifact);
  const brand = runBrands.get(run)!;
  if (brand.consumed.has(artifact)) {
    throw new DatasetLineageFailure("The dataset lineage artifact was replayed.");
  }
  brand.consumed.add(artifact);
  return accepted;
}

function prepareComponents(candidates: readonly OrganizationReconciliationDatasetComponentBinding[]): {
  readonly ordered: readonly PreparedComponent[];
  readonly byId: ReadonlyMap<OrganizationReconciliationPhysicalSource, PreparedComponent>;
} {
  if (!Array.isArray(candidates)) throw new DatasetLineageFailure("The dataset component set is invalid.");
  const byId = new Map<OrganizationReconciliationPhysicalSource, PreparedComponent>();
  for (const candidate of candidates) {
    const strictCandidate = exactObject(candidate, [
      "componentId", "expectedSourceId", "schemaSha256", "catalogSha256", "buildSha256",
      "adapter", "datasetCatalog"
    ], "dataset component binding");
    const componentId = strictCandidate.componentId;
    if (!isPhysicalSource(componentId) || byId.has(componentId)) {
      throw new DatasetLineageFailure("The dataset component set is duplicate or invalid.");
    }
    const adapter = strictCandidate.adapter as OrganizationReconciliationDatasetSourceAdapter<unknown>;
    const sourceId = requireMetadata(readData(adapter, "sourceId"), "adapter source ID");
    const expectedSourceId = requireMetadata(strictCandidate.expectedSourceId, "expected source ID");
    if (sourceId !== expectedSourceId) throw new DatasetLineageFailure("A dataset adapter is bound to an unexpected source.");
    const openSnapshot = requireFunction(adapter, "openSnapshot") as OrganizationReconciliationDatasetSourceAdapter<unknown>["openSnapshot"];
    const readSnapshotPage = requireFunction(adapter, "readSnapshotPage") as OrganizationReconciliationDatasetSourceAdapter<unknown>["readSnapshotPage"];
    const closeSnapshot = requireFunction(adapter, "closeSnapshot") as OrganizationReconciliationDatasetSourceAdapter<unknown>["closeSnapshot"];
    const catalog = canonicalCatalog(strictCandidate.datasetCatalog);
    const declaredCatalogSha256 = requireSha256(strictCandidate.catalogSha256, "declared catalog digest");
    const snapshotHandle: { value?: OrganizationReconciliationSourceSnapshot } = {};
    const facade: OrganizationReconciliationComponentBinding["adapter"] = Object.freeze({
      sourceId,
      openSnapshot: async () => {
        const snapshot = await openSnapshot.call(adapter);
        snapshotHandle.value = snapshot;
        return snapshot;
      },
      closeSnapshot: (snapshot: OrganizationReconciliationSourceSnapshot, outcome: "completed" | "failed") => {
        if (snapshotHandle.value !== snapshot) {
          throw new DatasetLineageFailure("The coordinator attempted to close an unexpected snapshot handle.");
        }
        return closeSnapshot.call(adapter, snapshot, outcome);
      }
    });
    const binding = Object.freeze({
      componentId,
      expectedSourceId,
      schemaSha256: requireSha256(strictCandidate.schemaSha256, "schema digest"),
      catalogSha256: declaredCatalogSha256,
      buildSha256: requireSha256(strictCandidate.buildSha256, "build digest"),
      adapter: facade
    });
    byId.set(componentId, Object.freeze({
      componentId,
      binding,
      originalAdapter: adapter,
      sourceId,
      readSnapshotPage,
      declaredCatalogSha256,
      structuralCatalogSha256: sha256(CATALOG_HASH_DOMAIN, catalog),
      datasets: catalog.datasets,
      snapshotHandle
    }));
  }
  if (byId.size !== 3) throw new DatasetLineageFailure("Every physical dataset component is required.");
  return {
    ordered: Object.freeze([byId.get("legacy-main")!, byId.get("identity")!, byId.get("plugin")!]),
    byId
  };
}

function canonicalCatalog(candidate: unknown): OrganizationReconciliationDatasetCatalog {
  const canonical = canonicalizeOrganizationReconciliationEvidenceValue(candidate);
  const catalog = exactObject(canonical, ["contract", "trust", "datasets"], "dataset catalog");
  if (
    catalog.contract !== ORGANIZATION_RECONCILIATION_DATASET_LINEAGE_CONTRACT ||
    catalog.trust !== ORGANIZATION_RECONCILIATION_DATASET_CATALOG_TRUST ||
    !Array.isArray(catalog.datasets) || catalog.datasets.length < 1 || catalog.datasets.length > 64
  ) throw new DatasetLineageFailure("The structural dataset catalog is invalid.");
  const ids = new Set<string>();
  const datasets = catalog.datasets.map((value) => {
    const entry = exactObject(value, ["datasetId", "pageSize", "maxPages", "maxRecords"], "dataset entry");
    const datasetId = requireMetadata(entry.datasetId, "dataset ID");
    if (ids.has(datasetId)) throw new DatasetLineageFailure("The structural dataset catalog has a duplicate dataset.");
    ids.add(datasetId);
    return Object.freeze({
      datasetId,
      pageSize: requireLimit(entry.pageSize, 1, 5_000, "dataset page size"),
      maxPages: requireLimit(entry.maxPages, 1, 10_000, "dataset page count"),
      maxRecords: requireLimit(entry.maxRecords, 0, 10_000_000, "dataset record count")
    });
  }).sort((left, right) => left.datasetId.localeCompare(right.datasetId));
  const aggregatePages = datasets.reduce((sum, dataset) => sum + dataset.maxPages, 0);
  const aggregateRecords = datasets.reduce((sum, dataset) => sum + dataset.maxRecords, 0);
  if (
    aggregatePages > MAX_TOTAL_DATASET_PAGES ||
    aggregateRecords > MAX_TOTAL_DATASET_RECORDS
  ) {
    throw new DatasetLineageFailure("The structural dataset catalog exceeds its aggregate budget.");
  }
  return Object.freeze({
    contract: ORGANIZATION_RECONCILIATION_DATASET_LINEAGE_CONTRACT,
    trust: ORGANIZATION_RECONCILIATION_DATASET_CATALOG_TRUST,
    datasets: Object.freeze(datasets)
  });
}

async function collectDataset(
  component: PreparedComponent,
  snapshot: Readonly<OrganizationReconciliationSourceSnapshot>,
  dataset: OrganizationReconciliationDatasetSpec
): Promise<OrganizationReconciliationDatasetLineageArtifact> {
  const records: OrganizationReconciliationEvidenceJsonValue[] = [];
  const pages: OrganizationReconciliationDatasetPageLineage[] = [];
  const cursors = new Set<string>();
  let requestCursor: string | null = null;
  let expectedDatasetCount: number | undefined;
  const snapshotHandle = component.snapshotHandle.value;
  if (!snapshotHandle) throw new DatasetLineageFailure("The coordinator-owned snapshot handle is unavailable.");
  while (true) {
    if (pages.length >= dataset.maxPages) throw new DatasetLineageFailure("A dataset cursor chain exceeded its page bound.");
    assertReadStable(component);
    let candidate: unknown;
    try {
      candidate = await component.readSnapshotPage.call(component.originalAdapter, {
        snapshot: snapshotHandle,
        datasetId: dataset.datasetId,
        requestCursor,
        pageSize: dataset.pageSize
      });
    } catch {
      throw new DatasetLineageFailure("Reading an authoritative dataset page failed.");
    }
    assertReadStable(component);
    const page = canonicalPage(candidate);
    validatePage(page, snapshot, dataset, requestCursor, records.length, expectedDatasetCount);
    expectedDatasetCount ??= page.datasetRecordCount;
    if (records.length + page.records.length > dataset.maxRecords) {
      throw new DatasetLineageFailure("A dataset exceeded its raw record bound.");
    }
    const pageRecordsHash = sha256(PAGE_HASH_DOMAIN, page.records);
    pages.push(Object.freeze({
      pageNumber: pages.length + 1,
      sourceId: page.sourceId,
      sourceVersion: page.sourceVersion,
      snapshotId: page.snapshotId,
      datasetId: page.datasetId,
      requestCursor: page.requestCursor,
      nextCursor: page.nextCursor,
      recordOffset: page.recordOffset,
      recordCount: page.records.length,
      recordsSha256: pageRecordsHash,
      declaredCatalogSha256: component.declaredCatalogSha256,
      structuralCatalogSha256: component.structuralCatalogSha256
    }));
    records.push(...page.records);
    if (page.nextCursor === null) break;
    const nextCursor = requireCursor(page.nextCursor);
    if (page.records.length === 0 || cursors.has(nextCursor)) {
      throw new DatasetLineageFailure("A dataset cursor chain is empty or repeated before termination.");
    }
    cursors.add(nextCursor);
    requestCursor = nextCursor;
  }
  if (expectedDatasetCount === undefined || records.length !== expectedDatasetCount) {
    throw new DatasetLineageFailure("A dataset cursor chain is incomplete.");
  }
  const artifactBody = Object.freeze({
    componentId: component.componentId,
    sourceVersion: snapshot.sourceVersion,
    snapshotId: snapshot.snapshotId,
    datasetId: dataset.datasetId,
    recordCount: records.length,
    recordsSha256: sha256(RECORDS_HASH_DOMAIN, records),
    records: Object.freeze(records),
    pages: Object.freeze(pages)
  });
  return Object.freeze({ ...artifactBody, lineageSha256: sha256(LINEAGE_HASH_DOMAIN, artifactBody) });
}

function canonicalPage(candidate: unknown): OrganizationReconciliationDatasetPage<OrganizationReconciliationEvidenceJsonValue> {
  const canonical = canonicalizeOrganizationReconciliationEvidenceValue(candidate);
  exactObject(canonical, [
    "sourceId", "sourceVersion", "snapshotId", "snapshotRecordCount", "subjectUniverseCount",
    "subjectUniverseHash", "datasetId", "datasetRecordCount", "requestCursor", "nextCursor",
    "recordOffset", "records"
  ], "dataset page");
  return canonical as unknown as OrganizationReconciliationDatasetPage<OrganizationReconciliationEvidenceJsonValue>;
}

function validatePage(
  page: OrganizationReconciliationDatasetPage<OrganizationReconciliationEvidenceJsonValue>,
  snapshot: Readonly<OrganizationReconciliationSourceSnapshot>,
  dataset: OrganizationReconciliationDatasetSpec,
  requestCursor: string | null,
  recordOffset: number,
  expectedDatasetCount: number | undefined
): void {
  if (
    page.sourceId !== snapshot.sourceId || page.sourceVersion !== snapshot.sourceVersion ||
    page.snapshotId !== snapshot.snapshotId || page.snapshotRecordCount !== snapshot.recordCount ||
    page.subjectUniverseCount !== snapshot.subjectUniverseCount ||
    page.subjectUniverseHash !== snapshot.subjectUniverseHash || page.datasetId !== dataset.datasetId
  ) throw new DatasetLineageFailure("A dataset page is not bound to its opened snapshot and dataset.");
  if (
    !Number.isSafeInteger(page.datasetRecordCount) || page.datasetRecordCount < 0 ||
    page.datasetRecordCount > dataset.maxRecords ||
    (expectedDatasetCount !== undefined && page.datasetRecordCount !== expectedDatasetCount)
  ) throw new DatasetLineageFailure("A dataset changed its raw count during collection.");
  if (page.requestCursor !== requestCursor) throw new DatasetLineageFailure("A dataset page did not echo its cursor.");
  if (!Number.isSafeInteger(page.recordOffset) || page.recordOffset !== recordOffset) {
    throw new DatasetLineageFailure("A dataset page does not continue its raw offset.");
  }
  if (!Array.isArray(page.records) || page.records.length > dataset.pageSize) {
    throw new DatasetLineageFailure("A dataset page exceeds its page size.");
  }
  if (page.nextCursor !== null) requireCursor(page.nextCursor);
}

function assertReadStable(component: PreparedComponent): void {
  if (
    readData(component.originalAdapter, "sourceId") !== component.sourceId ||
    requireFunction(component.originalAdapter, "readSnapshotPage") !== component.readSnapshotPage
  ) throw new DatasetLineageFailure("A dataset adapter changed during collection.");
}

function exactObject(candidate: unknown, keys: readonly string[], label: string): Record<string, unknown> {
  if (!candidate || typeof candidate !== "object" || Array.isArray(candidate) ||
    (Object.getPrototypeOf(candidate) !== Object.prototype && Object.getPrototypeOf(candidate) !== null) ||
    Object.getOwnPropertySymbols(candidate).length > 0) throw new DatasetLineageFailure(`The ${label} is invalid.`);
  const descriptors = Object.getOwnPropertyDescriptors(candidate);
  if (Object.keys(descriptors).sort().join("\u001f") !== [...keys].sort().join("\u001f")) {
    throw new DatasetLineageFailure(`The ${label} has missing or unknown fields.`);
  }
  const output: Record<string, unknown> = {};
  for (const key of keys) {
    const descriptor = descriptors[key]!;
    if (!("value" in descriptor) || !descriptor.enumerable) {
      throw new DatasetLineageFailure(`The ${label} contains an accessor or hidden field.`);
    }
    output[key] = descriptor.value;
  }
  return output;
}

function readData(candidate: unknown, key: string): unknown {
  if (!candidate || (typeof candidate !== "object" && typeof candidate !== "function")) {
    throw new DatasetLineageFailure("Dataset lineage configuration is invalid.");
  }
  const descriptor = Object.getOwnPropertyDescriptor(candidate, key);
  if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
    throw new DatasetLineageFailure("Dataset lineage configuration contains an accessor or hidden field.");
  }
  return descriptor.value;
}

function requireFunction(candidate: unknown, key: string): (...args: never[]) => unknown {
  const value = readData(candidate, key);
  if (typeof value !== "function") throw new DatasetLineageFailure("A dataset adapter method is invalid.");
  return value as (...args: never[]) => unknown;
}

function sha256(domain: Buffer, candidate: unknown): string {
  const canonical = canonicalizeOrganizationReconciliationEvidenceValue(candidate);
  return createHash("sha256").update(domain).update(canonicalJson(canonical), "utf8").digest("hex");
}

function canonicalJson(value: OrganizationReconciliationEvidenceJsonValue): string {
  if (value === null) return "null";
  if (typeof value === "string") return JSON.stringify(value)!;
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") return JSON.stringify(value)!;
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const record = value as Readonly<Record<string, OrganizationReconciliationEvidenceJsonValue>>;
  return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key]!)}`).join(",")}}`;
}

function requireMetadata(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length < 1 || value.length > 1_024 || value.trim() !== value ||
    value.normalize("NFC") !== value || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new DatasetLineageFailure(`The ${label} is invalid.`);
  }
  return value;
}

function requireSha256(value: unknown, label: string): string {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) {
    throw new DatasetLineageFailure(`The ${label} must be a full SHA-256 digest.`);
  }
  return value;
}

function requireLimit(value: unknown, minimum: number, maximum: number, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    throw new DatasetLineageFailure(`The ${label} is outside its approved bound.`);
  }
  return value as number;
}

function requireCursor(value: unknown): string {
  if (typeof value !== "string" || value.length < 1 || value.length > 2_048 || value.trim() !== value) {
    throw new DatasetLineageFailure("A dataset continuation cursor is invalid.");
  }
  return value;
}

function isPhysicalSource(value: unknown): value is OrganizationReconciliationPhysicalSource {
  return value === "legacy-main" || value === "identity" || value === "plugin";
}

class DatasetLineageFailure extends Error {}
