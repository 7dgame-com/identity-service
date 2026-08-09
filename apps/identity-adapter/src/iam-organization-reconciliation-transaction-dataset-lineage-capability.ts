import { isProxy } from "node:util/types";
import {
  ORGANIZATION_RECONCILIATION_DATASET_CATALOG_TRUST,
  collectOrganizationReconciliationDatasetLineage,
  type CollectOrganizationReconciliationDatasetLineageOptions,
  type OrganizationReconciliationDatasetComponentBinding,
  type OrganizationReconciliationDatasetLineageRun,
  type OrganizationReconciliationDatasetSourceAdapter
} from "./iam-organization-reconciliation-dataset-lineage.js";
import type { OrganizationReconciliationPhysicalSource } from
  "./iam-organization-reconciliation-component-manifest.js";
import {
  ORGANIZATION_RECONCILIATION_TRANSACTION_ADAPTER_FACTORY_CAPABILITY_IMPLEMENTED
} from "./iam-organization-reconciliation-runtime-readiness.js";
import {
  assertOrganizationReconciliationMysqlTransactionDatasetAdapterFactoryProvenance,
  type OrganizationReconciliationMysqlTransactionDatasetAdapterFactoryProvenance
} from
  "./iam-organization-reconciliation/mysql-source-adapters/transaction-dataset-adapter.js";

export const ORGANIZATION_RECONCILIATION_TRANSACTION_DATASET_LINEAGE_FACTORY_PROVENANCE_CONTRACT =
  "iam-organization-reconciliation-transaction-dataset-lineage-factory-provenance/v1" as const;

export interface OrganizationReconciliationTransactionDatasetLineageFactoryProvenanceComponent {
  readonly componentId: OrganizationReconciliationPhysicalSource;
  readonly expectedSourceId: string;
  readonly declaredSchemaSha256: string;
  readonly declaredCatalogSha256: string;
  readonly declaredBuildSha256: string;
  readonly structuralCatalogSha256: string;
  readonly datasetIds: readonly string[];
  readonly adapterContract: string;
  readonly adapterFactoryProvenanceContract: string;
  readonly statementCatalogSha256: string;
}

/**
 * Side-channel metadata for an exact branded run. It proves only that every
 * adapter came from the hardened transaction factory with matching captured
 * declarations. It does not authenticate a database, approve a catalog, or
 * make the run production-ready.
 */
export interface OrganizationReconciliationTransactionDatasetLineageFactoryProvenance {
  readonly contract:
    typeof ORGANIZATION_RECONCILIATION_TRANSACTION_DATASET_LINEAGE_FACTORY_PROVENANCE_CONTRACT;
  readonly trust: "factory-origin-only";
  readonly physicalSourceTrust: "unattested";
  readonly ownerCatalogTrust: typeof ORGANIZATION_RECONCILIATION_DATASET_CATALOG_TRUST;
  readonly factoryCapabilityImplemented: true;
  readonly productionReady: false;
  readonly components: readonly OrganizationReconciliationTransactionDatasetLineageFactoryProvenanceComponent[];
}

interface CapturedComponent {
  readonly binding: OrganizationReconciliationDatasetComponentBinding;
  readonly provenance: OrganizationReconciliationTransactionDatasetLineageFactoryProvenanceComponent;
}

interface RunBrand {
  readonly run: OrganizationReconciliationDatasetLineageRun;
  readonly artifacts: OrganizationReconciliationDatasetLineageRun["artifacts"];
  readonly manifest: OrganizationReconciliationDatasetLineageRun["coordinatorManifest"];
  readonly provenance: OrganizationReconciliationTransactionDatasetLineageFactoryProvenance;
}

const runBrands = new WeakMap<object, RunBrand>();
const REQUIRED_COMPONENTS = Object.freeze([
  "legacy-main",
  "identity",
  "plugin"
] as const satisfies readonly OrganizationReconciliationPhysicalSource[]);

/**
 * Strict factory-bound wrapper. Every descriptor and private factory brand is
 * validated for all three components before the generic lineage collector can
 * open a snapshot or invoke a connection factory.
 */
export async function collectOrganizationReconciliationFactoryBoundTransactionDatasetLineage(
  candidateOptions: CollectOrganizationReconciliationDatasetLineageOptions
): Promise<OrganizationReconciliationDatasetLineageRun> {
  const options = exactObject(
    candidateOptions,
    ["components", "maxWindowMilliseconds", "clock"],
    "factory-bound lineage options"
  );
  const componentCandidates = exactArray(
    options.components,
    REQUIRED_COMPONENTS.length,
    REQUIRED_COMPONENTS.length,
    "factory-bound component set"
  );
  const byComponent = new Map<OrganizationReconciliationPhysicalSource, CapturedComponent>();

  // Complete this loop before invoking the collector. A failure in the last
  // component therefore still guarantees zero source opens for every component.
  for (const candidate of componentCandidates) {
    const component = captureComponent(candidate);
    if (byComponent.has(component.binding.componentId)) {
      throw new Error("The factory-bound component set contains a duplicate component.");
    }
    byComponent.set(component.binding.componentId, component);
  }
  if (byComponent.size !== REQUIRED_COMPONENTS.length ||
    REQUIRED_COMPONENTS.some((componentId) => !byComponent.has(componentId))) {
    throw new Error("The factory-bound component set is incomplete.");
  }

  const clock = exactObject(options.clock, ["now"], "factory-bound coordinator clock");
  if (typeof clock.now !== "function") {
    throw new Error("The factory-bound coordinator clock is invalid.");
  }
  const capturedNow = clock.now as () => Date;
  const maxWindowMilliseconds = requireBound(
    options.maxWindowMilliseconds,
    1,
    3_600_000,
    "factory-bound snapshot window"
  );
  const ordered = REQUIRED_COMPONENTS.map((componentId) => byComponent.get(componentId)!);
  const provenance = Object.freeze({
    contract: ORGANIZATION_RECONCILIATION_TRANSACTION_DATASET_LINEAGE_FACTORY_PROVENANCE_CONTRACT,
    trust: "factory-origin-only" as const,
    physicalSourceTrust: "unattested" as const,
    ownerCatalogTrust: ORGANIZATION_RECONCILIATION_DATASET_CATALOG_TRUST,
    factoryCapabilityImplemented:
      ORGANIZATION_RECONCILIATION_TRANSACTION_ADAPTER_FACTORY_CAPABILITY_IMPLEMENTED,
    productionReady: false as const,
    components: Object.freeze(ordered.map((component) => component.provenance))
  } satisfies OrganizationReconciliationTransactionDatasetLineageFactoryProvenance);
  const run = await collectOrganizationReconciliationDatasetLineage(Object.freeze({
    components: Object.freeze(ordered.map((component) => component.binding)),
    maxWindowMilliseconds,
    clock: Object.freeze({ now: () => capturedNow.call(undefined) })
  }));
  runBrands.set(run, Object.freeze({
    run,
    artifacts: run.artifacts,
    manifest: run.coordinatorManifest,
    provenance
  }));
  return run;
}

/** Rejects cloned, serialized, cross-run, and A/B-spliced run objects. */
export function assertOrganizationReconciliationTransactionDatasetLineageFactoryProvenance(
  candidateRun: unknown
): OrganizationReconciliationTransactionDatasetLineageFactoryProvenance {
  if (
    candidateRun === null ||
    typeof candidateRun !== "object" ||
    isProxy(candidateRun)
  ) {
    throw new Error("The dataset lineage run has no transaction factory provenance.");
  }
  const brand = runBrands.get(candidateRun);
  const run = candidateRun as OrganizationReconciliationDatasetLineageRun;
  if (
    !brand ||
    brand.run !== candidateRun ||
    run.artifacts !== brand.artifacts ||
    run.coordinatorManifest !== brand.manifest
  ) {
    throw new Error("The dataset lineage run has no transaction factory provenance.");
  }
  return brand.provenance;
}

function captureComponent(candidate: unknown): CapturedComponent {
  const component = exactObject(candidate, [
    "componentId",
    "expectedSourceId",
    "schemaSha256",
    "catalogSha256",
    "buildSha256",
    "adapter",
    "datasetCatalog"
  ], "factory-bound component binding");
  const componentId = requireComponentId(component.componentId);
  const factoryProvenance =
    assertOrganizationReconciliationMysqlTransactionDatasetAdapterFactoryProvenance(
      component.adapter,
      Object.freeze({
        componentId,
        expectedSourceId: component.expectedSourceId,
        catalogSha256: component.catalogSha256,
        datasetCatalog: component.datasetCatalog
      })
    );
  const schemaSha256 = requireSha256(component.schemaSha256, "declared schema digest");
  const buildSha256 = requireSha256(component.buildSha256, "declared build digest");
  const adapter = component.adapter as OrganizationReconciliationDatasetSourceAdapter<unknown>;
  const binding = Object.freeze({
    componentId,
    expectedSourceId: factoryProvenance.expectedSourceId,
    schemaSha256,
    catalogSha256: factoryProvenance.declaredCatalogSha256,
    buildSha256,
    adapter,
    datasetCatalog: factoryProvenance.datasetCatalog
  } satisfies OrganizationReconciliationDatasetComponentBinding);
  return Object.freeze({
    binding,
    provenance: componentProvenance(factoryProvenance, schemaSha256, buildSha256)
  });
}

function componentProvenance(
  factory: OrganizationReconciliationMysqlTransactionDatasetAdapterFactoryProvenance,
  schemaSha256: string,
  buildSha256: string
): OrganizationReconciliationTransactionDatasetLineageFactoryProvenanceComponent {
  return Object.freeze({
    componentId: factory.componentId,
    expectedSourceId: factory.expectedSourceId,
    declaredSchemaSha256: schemaSha256,
    declaredCatalogSha256: factory.declaredCatalogSha256,
    declaredBuildSha256: buildSha256,
    structuralCatalogSha256: factory.structuralCatalogSha256,
    datasetIds: factory.datasetIds,
    adapterContract: factory.adapterContract,
    adapterFactoryProvenanceContract: factory.contract,
    statementCatalogSha256: factory.statementCatalogSha256
  });
}

function exactObject(candidate: unknown, expectedKeys: readonly string[], label: string): Record<string, unknown> {
  if (
    candidate === null ||
    typeof candidate !== "object" ||
    Array.isArray(candidate) ||
    isProxy(candidate) ||
    (Object.getPrototypeOf(candidate) !== Object.prototype && Object.getPrototypeOf(candidate) !== null) ||
    Object.getOwnPropertySymbols(candidate).length > 0
  ) {
    throw new Error(`The ${label} is invalid.`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(candidate);
  if (Object.keys(descriptors).sort().join("\u001f") !== [...expectedKeys].sort().join("\u001f")) {
    throw new Error(`The ${label} has missing or unknown fields.`);
  }
  const captured: Record<string, unknown> = Object.create(null);
  for (const key of expectedKeys) {
    const descriptor = descriptors[key]!;
    if (!descriptor.enumerable || !("value" in descriptor)) {
      throw new Error(`The ${label} contains an accessor or hidden field.`);
    }
    captured[key] = descriptor.value;
  }
  return Object.freeze(captured);
}

function exactArray(
  candidate: unknown,
  minimum: number,
  maximum: number,
  label: string
): readonly unknown[] {
  if (
    !Array.isArray(candidate) ||
    isProxy(candidate) ||
    Object.getPrototypeOf(candidate) !== Array.prototype ||
    Object.getOwnPropertySymbols(candidate).length > 0
  ) {
    throw new Error(`The ${label} is invalid.`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(candidate);
  const lengthDescriptor = descriptors["length"] as PropertyDescriptor | undefined;
  if (
    !lengthDescriptor ||
    !("value" in lengthDescriptor) ||
    !Number.isSafeInteger(lengthDescriptor.value) ||
    lengthDescriptor.value < minimum ||
    lengthDescriptor.value > maximum
  ) {
    throw new Error(`The ${label} is sparse or unbounded.`);
  }
  const length = lengthDescriptor.value as number;
  const expectedNames = new Set(["length", ...Array.from({ length }, (_, index) => String(index))]);
  if (
    Object.keys(descriptors).length !== expectedNames.size ||
    Object.keys(descriptors).some((key) => !expectedNames.has(key))
  ) {
    throw new Error(`The ${label} has sparse, hidden, or unknown fields.`);
  }
  const captured: unknown[] = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) {
      throw new Error(`The ${label} contains an accessor or sparse entry.`);
    }
    captured.push(descriptor.value);
  }
  return Object.freeze(captured);
}

function requireComponentId(value: unknown): OrganizationReconciliationPhysicalSource {
  if (value !== "legacy-main" && value !== "identity" && value !== "plugin") {
    throw new Error("The factory-bound component ID is invalid.");
  }
  return value;
}

function requireSha256(value: unknown, label: string): string {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) {
    throw new Error(`The ${label} is invalid.`);
  }
  return value;
}

function requireBound(value: unknown, minimum: number, maximum: number, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    throw new Error(`The ${label} is invalid.`);
  }
  return value as number;
}
