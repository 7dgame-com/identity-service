import {
  type OrganizationReconciliationSourceAdapter,
  type OrganizationReconciliationSourceSnapshot
} from "./iam-organization-reconciliation-collector.js";
import {
  canonicalizeOrganizationReconciliationEvidenceValue,
  createOrganizationReconciliationCompositeManifestSha256,
  createOrganizationReconciliationOperationEvidenceSha256,
  ORGANIZATION_RECONCILIATION_COMPOSITE_CONSISTENCY_MODEL,
  ORGANIZATION_RECONCILIATION_COMPOSITE_MANIFEST_CONTRACT,
  ORGANIZATION_RECONCILIATION_OPERATION_EVIDENCE_CONTRACT,
  ORGANIZATION_RECONCILIATION_PAGINATION_MODE,
  ORGANIZATION_RECONCILIATION_REQUIRED_PHYSICAL_SOURCES,
  ORGANIZATION_RECONCILIATION_SNAPSHOT_MODE,
  validateOrganizationReconciliationCompositeManifestEvidenceBinding,
  type OrganizationReconciliationCompositeManifest,
  type OrganizationReconciliationCompositeManifestUnsigned,
  type OrganizationReconciliationEvidenceJsonValue,
  type OrganizationReconciliationPhysicalSource
} from "./iam-organization-reconciliation-component-manifest.js";
import type {
  OrganizationReconciliationInput
} from "./iam-organization-reconciliation-validator.js";

export * from "./iam-organization-reconciliation-component-manifest.js";

export interface OrganizationReconciliationCoordinatorClock {
  /** Must be supplied by the reviewed runtime, not evidence or source data. */
  now(): Date;
}

export interface OrganizationReconciliationComponentBinding {
  /** One component is required for each independently snapshotted physical source. */
  readonly componentId: OrganizationReconciliationPhysicalSource;
  readonly expectedSourceId: string;
  readonly schemaSha256: string;
  readonly catalogSha256: string;
  readonly buildSha256: string;
  readonly adapter: Pick<
    OrganizationReconciliationSourceAdapter<unknown>,
    "sourceId" | "openSnapshot" | "closeSnapshot"
  >;
}

export interface OrganizationReconciliationCoordinatedComponent {
  readonly componentId: OrganizationReconciliationPhysicalSource;
  readonly source: Readonly<OrganizationReconciliationSourceSnapshot>;
  readonly subjectUniverseScope: "complete" | "not-applicable";
  readonly schemaSha256: string;
  readonly catalogSha256: string;
  readonly buildSha256: string;
  readonly openedAt: string;
}

export interface OrganizationReconciliationCoordinatorContext {
  readonly consistencyModel: typeof ORGANIZATION_RECONCILIATION_COMPOSITE_CONSISTENCY_MODEL;
  /** These snapshots are independent. This value can never be promoted by caller input. */
  readonly crossDatabaseAtomic: false;
  readonly components: readonly OrganizationReconciliationCoordinatedComponent[];
}

export interface CoordinateOrganizationReconciliationSnapshotsOptions {
  readonly components: readonly OrganizationReconciliationComponentBinding[];
  readonly maxWindowMilliseconds: number;
  readonly clock: OrganizationReconciliationCoordinatorClock;
}

export interface CoordinatedOrganizationReconciliationResult<
  T extends OrganizationReconciliationEvidenceJsonValue
> {
  readonly value: T;
  readonly manifest: OrganizationReconciliationCompositeManifest;
}

/**
 * The only supported projection from a coordinated result into validator/CLI
 * input. It revalidates the manifest-to-body digest, rejects a nested caller
 * manifest, and freezes one exact final input. This binds content and lifecycle;
 * it deliberately does not claim page lineage for the still-unimplemented
 * production source adapters.
 */
export function assembleCoordinatedOrganizationReconciliationInput(
  result: CoordinatedOrganizationReconciliationResult<OrganizationReconciliationEvidenceJsonValue>
): OrganizationReconciliationInput {
  try {
    const evidence = canonicalizeOrganizationReconciliationEvidenceValue(result?.value);
    if (evidence === null || typeof evidence !== "object" || Array.isArray(evidence)) {
      throw new Error("invalid evidence body");
    }
    if (Object.prototype.hasOwnProperty.call(evidence, "componentManifest")) {
      throw new Error("nested manifest");
    }
    const manifest = validateOrganizationReconciliationCompositeManifestEvidenceBinding(
      result?.manifest,
      evidence
    );
    return canonicalizeOrganizationReconciliationEvidenceValue({
      ...evidence,
      componentManifest: manifest
    }) as unknown as OrganizationReconciliationInput;
  } catch {
    throw new CoordinatorFailure(
      "Assembling coordinated organization reconciliation evidence failed."
    );
  }
}

interface ValidatedBinding {
  readonly componentId: OrganizationReconciliationPhysicalSource;
  readonly expectedSourceId: string;
  readonly schemaSha256: string;
  readonly catalogSha256: string;
  readonly buildSha256: string;
  readonly adapter: OrganizationReconciliationComponentBinding["adapter"];
  readonly originalBinding: OrganizationReconciliationComponentBinding;
}

interface OpenedComponent {
  readonly binding: ValidatedBinding;
  readonly rawSnapshot: OrganizationReconciliationSourceSnapshot;
  snapshot?: Readonly<OrganizationReconciliationSourceSnapshot>;
  readonly openedAt: string;
  readonly openedAtMilliseconds: number;
  closeAttempted: boolean;
  closedAt?: string;
  closedAtMilliseconds?: number;
}

/**
 * Opens the three physical sources in a deterministic order, runs one bounded
 * operation, and closes every successfully opened snapshot exactly once.
 *
 * The resulting manifest proves a bounded set of independent immutable
 * snapshots. It deliberately cannot claim a transaction spanning databases.
 * This lifecycle primitive does not make real source adapters production-ready.
 */
export async function coordinateOrganizationReconciliationSnapshots<
  T extends OrganizationReconciliationEvidenceJsonValue
>(
  options: CoordinateOrganizationReconciliationSnapshotsOptions,
  operation: (context: OrganizationReconciliationCoordinatorContext) => Promise<T>
): Promise<CoordinatedOrganizationReconciliationResult<T>> {
  const bindings = validateBindings(options.components);
  const maxWindowMilliseconds = requireWindowBound(options.maxWindowMilliseconds);
  if (!options.clock || typeof options.clock.now !== "function") {
    throw new CoordinatorFailure("A reviewed coordinator clock is required.");
  }
  if (typeof operation !== "function") {
    throw new CoordinatorFailure("A coordinated snapshot operation is required.");
  }

  const opened: OpenedComponent[] = [];
  let lastObservedTime = Number.NEGATIVE_INFINITY;
  let canonicalValue: T | undefined;
  let evidenceSha256: string | undefined;
  let failure: CoordinatorFailure | undefined;

  const observeTime = (): { iso: string; milliseconds: number } => {
    let candidate: Date;
    try {
      candidate = options.clock.now();
    } catch {
      throw new CoordinatorFailure("The coordinator clock failed.");
    }
    if (!(candidate instanceof Date) || !Number.isFinite(candidate.getTime())) {
      throw new CoordinatorFailure("The coordinator clock returned an invalid timestamp.");
    }
    const milliseconds = candidate.getTime();
    if (milliseconds < lastObservedTime) {
      throw new CoordinatorFailure("The coordinator clock moved backwards.");
    }
    lastObservedTime = milliseconds;
    return { iso: new Date(milliseconds).toISOString(), milliseconds };
  };

  try {
    for (const binding of bindings) {
      const openedTime = observeTime();
      if (
        opened.length > 0 &&
        openedTime.milliseconds - opened[0]!.openedAtMilliseconds > maxWindowMilliseconds
      ) {
        throw new CoordinatorFailure("The composite snapshot window exceeded its approved bound while opening.");
      }

      let rawSnapshot: OrganizationReconciliationSourceSnapshot;
      try {
        rawSnapshot = await binding.adapter.openSnapshot();
      } catch {
        throw new CoordinatorFailure("Opening a coordinated authoritative source snapshot failed.");
      }

      const openedComponent: OpenedComponent = {
        binding,
        rawSnapshot,
        openedAt: openedTime.iso,
        openedAtMilliseconds: openedTime.milliseconds,
        closeAttempted: false
      };
      opened.push(openedComponent);
      openedComponent.snapshot = Object.freeze(copyAndValidateSnapshot(rawSnapshot, binding));
    }

    assertNoComponentDrift(opened);
    assertCompatibleSubjectUniverses(opened);
    let operationValue: T;
    try {
      operationValue = await operation(createOperationContext(opened));
    } catch {
      throw new CoordinatorFailure("The coordinated snapshot operation failed.");
    }

    assertNoComponentDrift(opened);
    try {
      canonicalValue = canonicalizeOrganizationReconciliationEvidenceValue(operationValue) as T;
      evidenceSha256 = createOrganizationReconciliationOperationEvidenceSha256(canonicalValue);
    } catch {
      throw new CoordinatorFailure(
        "The coordinated snapshot operation must return canonical JSON-safe evidence."
      );
    }
  } catch (error) {
    failure = asCoordinatorFailure(error);
  }

  const closeOutcome: "completed" | "failed" = failure ? "failed" : "completed";
  let closeFailure = false;
  for (const component of [...opened].reverse()) {
    component.closeAttempted = true;
    try {
      await component.binding.adapter.closeSnapshot(component.rawSnapshot, closeOutcome);
    } catch {
      closeFailure = true;
    }
    try {
      const closedTime = observeTime();
      component.closedAt = closedTime.iso;
      component.closedAtMilliseconds = closedTime.milliseconds;
    } catch {
      closeFailure = true;
    }
  }

  if (!closeFailure) {
    try {
      assertEveryOpenedComponentClosedExactlyOnce(opened);
      if (!failure) {
        assertNoComponentDrift(opened);
        assertBoundedWindow(opened, maxWindowMilliseconds);
      }
    } catch {
      closeFailure = true;
    }
  }

  if (closeFailure) {
    throw new CoordinatorFailure(
      "Closing or finalizing coordinated source snapshots failed; composite evidence was rejected."
    );
  }
  if (failure) throw failure;
  if (evidenceSha256 === undefined) {
    throw new CoordinatorFailure("The coordinated snapshot operation evidence digest is unavailable.");
  }

  const unsignedManifest = createUnsignedManifest(opened, maxWindowMilliseconds, evidenceSha256);
  return {
    value: canonicalValue as T,
    manifest: Object.freeze({
      ...unsignedManifest,
      manifestSha256: createOrganizationReconciliationCompositeManifestSha256(unsignedManifest)
    })
  };
}

function validateBindings(
  candidates: readonly OrganizationReconciliationComponentBinding[]
): readonly ValidatedBinding[] {
  if (!Array.isArray(candidates)) {
    throw new CoordinatorFailure("The coordinated component set is invalid.");
  }
  const byComponent = new Map<OrganizationReconciliationPhysicalSource, ValidatedBinding>();
  const sourceIds = new Set<string>();
  for (const candidate of candidates) {
    if (!candidate || !isRequiredPhysicalSource(candidate.componentId)) {
      throw new CoordinatorFailure("The coordinated component set contains an unknown component.");
    }
    if (byComponent.has(candidate.componentId)) {
      throw new CoordinatorFailure("The coordinated component set contains a duplicate component.");
    }
    const expectedSourceId = requireOpaqueMetadata(candidate.expectedSourceId, "expected source ID");
    if (sourceIds.has(expectedSourceId)) {
      throw new CoordinatorFailure("Each coordinated physical source must have a distinct source ID.");
    }
    if (!candidate.adapter || typeof candidate.adapter.openSnapshot !== "function" ||
      typeof candidate.adapter.closeSnapshot !== "function") {
      throw new CoordinatorFailure("A coordinated component adapter is invalid.");
    }
    const adapterSourceId = requireOpaqueMetadata(candidate.adapter.sourceId, "adapter source ID");
    if (adapterSourceId !== expectedSourceId) {
      throw new CoordinatorFailure("A coordinated component adapter is bound to an unexpected source.");
    }
    sourceIds.add(expectedSourceId);
    byComponent.set(candidate.componentId, Object.freeze({
      componentId: candidate.componentId,
      expectedSourceId,
      schemaSha256: requireSha256(candidate.schemaSha256, "schema digest"),
      catalogSha256: requireSha256(candidate.catalogSha256, "catalog digest"),
      buildSha256: requireSha256(candidate.buildSha256, "build digest"),
      adapter: candidate.adapter,
      originalBinding: candidate
    }));
  }

  if (byComponent.size !== ORGANIZATION_RECONCILIATION_REQUIRED_PHYSICAL_SOURCES.length) {
    throw new CoordinatorFailure("The coordinated component set is missing a required physical source.");
  }
  return Object.freeze(
    ORGANIZATION_RECONCILIATION_REQUIRED_PHYSICAL_SOURCES.map((componentId) => byComponent.get(componentId)!)
  );
}

function copyAndValidateSnapshot(
  snapshot: OrganizationReconciliationSourceSnapshot,
  binding: ValidatedBinding
): OrganizationReconciliationSourceSnapshot {
  if (!snapshot || typeof snapshot !== "object") {
    throw new CoordinatorFailure("A coordinated source returned invalid snapshot metadata.");
  }
  const copy = {
    sourceId: requireOpaqueMetadata(snapshot.sourceId, "snapshot source ID"),
    sourceVersion: requireOpaqueMetadata(snapshot.sourceVersion, "snapshot source version"),
    snapshotId: requireOpaqueMetadata(snapshot.snapshotId, "snapshot ID"),
    recordCount: requireNonNegativeSafeInteger(snapshot.recordCount, "snapshot record count"),
    subjectUniverseCount: requireNonNegativeSafeInteger(
      snapshot.subjectUniverseCount,
      "snapshot subject universe count"
    ),
    subjectUniverseHash: snapshot.subjectUniverseHash,
    snapshotMode: snapshot.snapshotMode,
    paginationMode: snapshot.paginationMode
  };
  if (copy.sourceId !== binding.expectedSourceId) {
    throw new CoordinatorFailure("A coordinated snapshot belongs to an unexpected source.");
  }
  if (copy.snapshotMode !== ORGANIZATION_RECONCILIATION_SNAPSHOT_MODE) {
    throw new CoordinatorFailure("A coordinated source does not provide an immutable snapshot.");
  }
  if (copy.paginationMode !== ORGANIZATION_RECONCILIATION_PAGINATION_MODE) {
    throw new CoordinatorFailure("A coordinated source does not provide snapshot-bound cursors.");
  }
  if (binding.componentId === "plugin") {
    if (copy.subjectUniverseCount !== 0 || copy.subjectUniverseHash !== "") {
      throw new CoordinatorFailure(
        "The plugin snapshot subject universe must be explicitly not applicable."
      );
    }
  } else {
    requirePositiveSafeInteger(copy.subjectUniverseCount, "snapshot subject universe count");
    requireSha256(copy.subjectUniverseHash, "subject universe digest");
  }
  return copy;
}

function createOperationContext(opened: readonly OpenedComponent[]): OrganizationReconciliationCoordinatorContext {
  return Object.freeze({
    consistencyModel: ORGANIZATION_RECONCILIATION_COMPOSITE_CONSISTENCY_MODEL,
    crossDatabaseAtomic: false as const,
    components: Object.freeze(opened.map((component) => Object.freeze({
      componentId: component.binding.componentId,
      source: component.snapshot!,
      subjectUniverseScope: component.binding.componentId === "plugin" ? "not-applicable" : "complete",
      schemaSha256: component.binding.schemaSha256,
      catalogSha256: component.binding.catalogSha256,
      buildSha256: component.binding.buildSha256,
      openedAt: component.openedAt
    })))
  });
}

function assertCompatibleSubjectUniverses(opened: readonly OpenedComponent[]): void {
  const legacy = opened.find((component) => component.binding.componentId === "legacy-main")?.snapshot;
  const identity = opened.find((component) => component.binding.componentId === "identity")?.snapshot;
  const plugin = opened.find((component) => component.binding.componentId === "plugin")?.snapshot;
  if (!legacy || !identity || !plugin) {
    throw new CoordinatorFailure("The coordinated subject universe component set is incomplete.");
  }
  if (
    legacy.subjectUniverseCount !== identity.subjectUniverseCount ||
    legacy.subjectUniverseHash !== identity.subjectUniverseHash
  ) {
    throw new CoordinatorFailure("Legacy and Identity snapshot subject universes do not match.");
  }
  if (plugin.subjectUniverseCount !== 0 || plugin.subjectUniverseHash !== "") {
    throw new CoordinatorFailure("The plugin snapshot subject universe is not applicable.");
  }
}

function assertNoComponentDrift(opened: readonly OpenedComponent[]): void {
  for (const component of opened) {
    const currentBinding = validateOneBinding(component.binding.originalBinding);
    if (
      currentBinding.componentId !== component.binding.componentId ||
      currentBinding.expectedSourceId !== component.binding.expectedSourceId ||
      currentBinding.schemaSha256 !== component.binding.schemaSha256 ||
      currentBinding.catalogSha256 !== component.binding.catalogSha256 ||
      currentBinding.buildSha256 !== component.binding.buildSha256 ||
      currentBinding.adapter !== component.binding.adapter ||
      canonicalJson(copyAndValidateSnapshot(component.rawSnapshot, component.binding)) !==
        canonicalJson(component.snapshot!)
    ) {
      throw new CoordinatorFailure("A coordinated component changed metadata during the snapshot window.");
    }
  }
}

function validateOneBinding(candidate: OrganizationReconciliationComponentBinding): ValidatedBinding {
  if (!candidate) {
    throw new CoordinatorFailure("A coordinated component changed identity during the snapshot window.");
  }
  const componentId = candidate.componentId;
  const adapter = candidate.adapter;
  if (!isRequiredPhysicalSource(componentId)) {
    throw new CoordinatorFailure("A coordinated component changed identity during the snapshot window.");
  }
  const expectedSourceId = requireOpaqueMetadata(candidate.expectedSourceId, "expected source ID");
  if (!adapter || typeof adapter.openSnapshot !== "function" || typeof adapter.closeSnapshot !== "function") {
    throw new CoordinatorFailure("A coordinated component changed source binding during the snapshot window.");
  }
  const adapterSourceId = requireOpaqueMetadata(adapter.sourceId, "adapter source ID");
  if (adapterSourceId !== expectedSourceId) {
    throw new CoordinatorFailure("A coordinated component changed source binding during the snapshot window.");
  }
  return {
    componentId,
    expectedSourceId,
    schemaSha256: requireSha256(candidate.schemaSha256, "schema digest"),
    catalogSha256: requireSha256(candidate.catalogSha256, "catalog digest"),
    buildSha256: requireSha256(candidate.buildSha256, "build digest"),
    adapter,
    originalBinding: candidate
  };
}

function assertEveryOpenedComponentClosedExactlyOnce(opened: readonly OpenedComponent[]): void {
  if (opened.some((component) => !component.closeAttempted || component.closedAt === undefined)) {
    throw new CoordinatorFailure("A coordinated snapshot did not complete its close lifecycle.");
  }
}

function assertBoundedWindow(opened: readonly OpenedComponent[], maxWindowMilliseconds: number): void {
  if (opened.length !== ORGANIZATION_RECONCILIATION_REQUIRED_PHYSICAL_SOURCES.length) {
    throw new CoordinatorFailure("The composite manifest is missing a coordinated component.");
  }
  const windowStartedAt = opened[0]!.openedAtMilliseconds;
  const windowEndedAt = Math.max(...opened.map((component) => component.closedAtMilliseconds!));
  if (
    opened.some((component) =>
      component.closedAtMilliseconds === undefined ||
      component.closedAtMilliseconds < component.openedAtMilliseconds ||
      component.closedAtMilliseconds - component.openedAtMilliseconds > maxWindowMilliseconds
    ) ||
    windowEndedAt - windowStartedAt > maxWindowMilliseconds
  ) {
    throw new CoordinatorFailure("The composite snapshot window exceeded its approved bound.");
  }
}

function createUnsignedManifest(
  opened: readonly OpenedComponent[],
  maxWindowMilliseconds: number,
  evidenceSha256: string
): OrganizationReconciliationCompositeManifestUnsigned {
  const components = Object.freeze(opened.map((component) => Object.freeze({
    componentId: component.binding.componentId,
    sourceId: component.snapshot!.sourceId,
    sourceVersion: component.snapshot!.sourceVersion,
    snapshotId: component.snapshot!.snapshotId,
    recordCount: component.snapshot!.recordCount,
    subjectUniverseScope: component.binding.componentId === "plugin" ? "not-applicable" : "complete",
    subjectUniverse: Object.freeze({
      count: component.snapshot!.subjectUniverseCount,
      sha256: component.snapshot!.subjectUniverseHash
    }),
    snapshotMode: component.snapshot!.snapshotMode,
    paginationMode: component.snapshot!.paginationMode,
    schemaSha256: component.binding.schemaSha256,
    catalogSha256: component.binding.catalogSha256,
    buildSha256: component.binding.buildSha256,
    openedAt: component.openedAt,
    closedAt: component.closedAt!
  })));
  return Object.freeze({
    contract: ORGANIZATION_RECONCILIATION_COMPOSITE_MANIFEST_CONTRACT,
    consistencyModel: ORGANIZATION_RECONCILIATION_COMPOSITE_CONSISTENCY_MODEL,
    crossDatabaseAtomic: false as const,
    windowStartedAt: opened[0]!.openedAt,
    windowEndedAt: new Date(
      Math.max(...opened.map((component) => component.closedAtMilliseconds!))
    ).toISOString(),
    maxWindowMilliseconds,
    evidenceContract: ORGANIZATION_RECONCILIATION_OPERATION_EVIDENCE_CONTRACT,
    evidenceSha256,
    components
  });
}

function isRequiredPhysicalSource(value: unknown): value is OrganizationReconciliationPhysicalSource {
  return typeof value === "string" &&
    ORGANIZATION_RECONCILIATION_REQUIRED_PHYSICAL_SOURCES.includes(
      value as OrganizationReconciliationPhysicalSource
    );
}

function requireWindowBound(value: number): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > 3_600_000) {
    throw new CoordinatorFailure("The composite snapshot window bound is invalid.");
  }
  return value;
}

function requireNonNegativeSafeInteger(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new CoordinatorFailure(`The ${label} is invalid.`);
  }
  return value;
}

function requirePositiveSafeInteger(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new CoordinatorFailure(`The ${label} is invalid.`);
  }
  return value;
}

function requireSha256(value: string, label: string): string {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) {
    throw new CoordinatorFailure(`The ${label} must be a full SHA-256 digest.`);
  }
  return value;
}

function requireOpaqueMetadata(value: string, label: string): string {
  if (typeof value !== "string" || value.length < 1 || value.length > 1_024 || value.trim() !== value) {
    throw new CoordinatorFailure(`The ${label} is invalid.`);
  }
  return value;
}

function asCoordinatorFailure(error: unknown): CoordinatorFailure {
  return error instanceof CoordinatorFailure
    ? error
    : new CoordinatorFailure("Coordinating authoritative source snapshots failed.");
}

function canonicalJson(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "string") return JSON.stringify(value)!;
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new CoordinatorFailure("Manifest metadata is not canonical JSON.");
    return JSON.stringify(value)!;
  }
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record).sort();
    if (keys.some((key) => record[key] === undefined)) {
      throw new CoordinatorFailure("Manifest metadata is not canonical JSON.");
    }
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(",")}}`;
  }
  throw new CoordinatorFailure("Manifest metadata is not canonical JSON.");
}

class CoordinatorFailure extends Error {}
