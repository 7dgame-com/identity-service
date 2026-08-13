import {
  canonicalizeOrganizationReconciliationEvidenceValue,
  type OrganizationReconciliationEvidenceJsonValue
} from "./iam-organization-reconciliation-component-manifest.js";
import {
  assertOrganizationReconciliationDatasetArtifactBelongsToRun,
  consumeOrganizationReconciliationDatasetArtifact,
  type OrganizationReconciliationDatasetLineageArtifact,
  type OrganizationReconciliationDatasetLineageRun
} from "./iam-organization-reconciliation-dataset-lineage.js";
import {
  ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG
} from "./iam-organization-reconciliation-develop-source-catalog.js";

export const ORGANIZATION_RECONCILIATION_DEVELOP_PROJECTION_VIEW_CONTRACT =
  "iam-organization-reconciliation-xrteeth-develop-projection-view/v2" as const;

type DevelopProjectionSide = "legacy" | "identity";

interface DevelopProjectionSnapshotViewBase {
  readonly contract: typeof ORGANIZATION_RECONCILIATION_DEVELOP_PROJECTION_VIEW_CONTRACT;
  readonly side: DevelopProjectionSide;
  readonly lineageManifestSha256: string;
  readonly sourceVersion: string;
  readonly snapshotId: string;
  readonly pluginSourceVersion: string;
  readonly pluginSnapshotId: string;
  readonly datasets: Readonly<Record<string, readonly OrganizationReconciliationEvidenceJsonValue[]>>;
}

declare const LEGACY_DEVELOP_VIEW_BRAND: unique symbol;
declare const IDENTITY_DEVELOP_VIEW_BRAND: unique symbol;

export interface LegacyDevelopProjectionSnapshotView extends DevelopProjectionSnapshotViewBase {
  readonly side: "legacy";
  readonly [LEGACY_DEVELOP_VIEW_BRAND]: true;
}

export interface IdentityDevelopProjectionSnapshotView extends DevelopProjectionSnapshotViewBase {
  readonly side: "identity";
  readonly [IDENTITY_DEVELOP_VIEW_BRAND]: true;
}

export interface DevelopProjectionSnapshotViews {
  readonly legacy: LegacyDevelopProjectionSnapshotView;
  readonly identity: IdentityDevelopProjectionSnapshotView;
}

const legacyViewBrands = new WeakSet<object>();
const identityViewBrands = new WeakSet<object>();

export class DevelopProjectionViewError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DevelopProjectionViewError";
  }
}

/**
 * Consumes every branded artifact exactly once and produces two detached
 * object graphs. Shared plugin rows are canonicalized independently so the
 * two evaluators cannot communicate through mutable object identity.
 */
export function createDevelopProjectionSnapshotViews(
  run: OrganizationReconciliationDatasetLineageRun
): DevelopProjectionSnapshotViews {
  if (!run || typeof run !== "object" || !Array.isArray(run.artifacts)) {
    throw new DevelopProjectionViewError("The dataset lineage run is invalid.");
  }
  const expectedByComponent = new Map(
    ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG.components.map((component) => [
      component.componentId,
      component.datasetCatalog.datasets.map((dataset) => dataset.datasetId)
    ])
  );
  const artifacts = new Map<string, OrganizationReconciliationDatasetLineageArtifact>();
  for (const artifact of run.artifacts) {
    const accepted = assertOrganizationReconciliationDatasetArtifactBelongsToRun(run, artifact);
    const key = `${accepted.componentId}\u0000${accepted.datasetId}`;
    if (artifacts.has(key)) throw new DevelopProjectionViewError("The dataset lineage run has a duplicate artifact.");
    const expected = expectedByComponent.get(accepted.componentId);
    if (!expected?.includes(accepted.datasetId)) {
      throw new DevelopProjectionViewError("The dataset lineage run has an unexpected artifact.");
    }
    artifacts.set(key, consumeOrganizationReconciliationDatasetArtifact(run, accepted));
  }
  const expectedCount = [...expectedByComponent.values()].reduce((sum, ids) => sum + ids.length, 0);
  if (artifacts.size !== expectedCount) {
    throw new DevelopProjectionViewError("The dataset lineage run does not cover the compiled dataset catalog.");
  }
  for (const [componentId, datasetIds] of expectedByComponent) {
    for (const datasetId of datasetIds) {
      if (!artifacts.has(`${componentId}\u0000${datasetId}`)) {
        throw new DevelopProjectionViewError("The dataset lineage run is missing a compiled artifact.");
      }
    }
  }

  const lineageManifestSha256 = run.coordinatorManifest.manifestSha256;
  if (!/^[a-f0-9]{64}$/.test(lineageManifestSha256)) {
    throw new DevelopProjectionViewError("The dataset lineage manifest digest is invalid.");
  }
  const legacy = createView("legacy", "legacy-main", artifacts, lineageManifestSha256) as LegacyDevelopProjectionSnapshotView;
  const identity = createView("identity", "identity", artifacts, lineageManifestSha256) as IdentityDevelopProjectionSnapshotView;
  legacyViewBrands.add(legacy);
  identityViewBrands.add(identity);
  return Object.freeze({ legacy, identity });
}

export function assertLegacyDevelopProjectionSnapshotView(
  candidate: unknown
): asserts candidate is LegacyDevelopProjectionSnapshotView {
  if (!candidate || typeof candidate !== "object" || !legacyViewBrands.has(candidate)) {
    throw new DevelopProjectionViewError("The Legacy Develop projection view is forged or cloned.");
  }
}

export function assertIdentityDevelopProjectionSnapshotView(
  candidate: unknown
): asserts candidate is IdentityDevelopProjectionSnapshotView {
  if (!candidate || typeof candidate !== "object" || !identityViewBrands.has(candidate)) {
    throw new DevelopProjectionViewError("The Identity Develop projection view is forged or cloned.");
  }
}

function createView(
  side: DevelopProjectionSide,
  componentId: "legacy-main" | "identity",
  artifacts: ReadonlyMap<string, OrganizationReconciliationDatasetLineageArtifact>,
  lineageManifestSha256: string
): LegacyDevelopProjectionSnapshotView | IdentityDevelopProjectionSnapshotView {
  const component = ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_CATALOG.components
    .find((candidate) => candidate.componentId === componentId)!;
  const componentArtifacts = component.datasetCatalog.datasets.map((dataset) =>
    artifacts.get(`${componentId}\u0000${dataset.datasetId}`)!
  );
  const pluginArtifact = artifacts.get("plugin\u0000plugin-registry")!;
  const sourceVersion = requireSame(componentArtifacts.map((artifact) => artifact.sourceVersion), "source version");
  const snapshotId = requireSame(componentArtifacts.map((artifact) => artifact.snapshotId), "snapshot ID");
  const datasetObject: Record<string, readonly OrganizationReconciliationEvidenceJsonValue[]> = {};
  for (const artifact of [...componentArtifacts, pluginArtifact]) {
    datasetObject[artifact.datasetId] = artifact.records;
  }
  const canonical = canonicalizeOrganizationReconciliationEvidenceValue({
    contract: ORGANIZATION_RECONCILIATION_DEVELOP_PROJECTION_VIEW_CONTRACT,
    side,
    lineageManifestSha256,
    sourceVersion,
    snapshotId,
    pluginSourceVersion: pluginArtifact.sourceVersion,
    pluginSnapshotId: pluginArtifact.snapshotId,
    datasets: datasetObject
  });
  return canonical as unknown as LegacyDevelopProjectionSnapshotView | IdentityDevelopProjectionSnapshotView;
}

function requireSame(values: readonly string[], label: string): string {
  if (values.length < 1 || values.some((value) => value !== values[0])) {
    throw new DevelopProjectionViewError(`The component ${label} is inconsistent.`);
  }
  return values[0]!;
}
