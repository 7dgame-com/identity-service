import { createHash, timingSafeEqual } from "node:crypto";

export const ORGANIZATION_RECONCILIATION_COMPOSITE_MANIFEST_CONTRACT =
  "iam-organization-reconciliation-composite-manifest/v2" as const;
export const ORGANIZATION_RECONCILIATION_COMPOSITE_CONSISTENCY_MODEL =
  "independent-immutable-snapshots-bounded-window" as const;
export const ORGANIZATION_RECONCILIATION_OPERATION_EVIDENCE_CONTRACT =
  "iam-organization-reconciliation-operation-evidence/v2" as const;
export const ORGANIZATION_RECONCILIATION_SNAPSHOT_MODE = "immutable-snapshot" as const;
export const ORGANIZATION_RECONCILIATION_PAGINATION_MODE =
  "snapshot-bound-opaque-cursor" as const;

export const ORGANIZATION_RECONCILIATION_REQUIRED_PHYSICAL_SOURCES = [
  "legacy-main",
  "identity",
  "plugin"
] as const;

export type OrganizationReconciliationPhysicalSource =
  (typeof ORGANIZATION_RECONCILIATION_REQUIRED_PHYSICAL_SOURCES)[number];
export type OrganizationReconciliationSubjectUniverseScope = "complete" | "not-applicable";
export type OrganizationReconciliationEvidenceJsonValue =
  | null
  | boolean
  | number
  | string
  | readonly OrganizationReconciliationEvidenceJsonValue[]
  | { readonly [key: string]: OrganizationReconciliationEvidenceJsonValue };

export interface OrganizationReconciliationComponentManifest {
  readonly componentId: OrganizationReconciliationPhysicalSource;
  readonly sourceId: string;
  readonly sourceVersion: string;
  readonly snapshotId: string;
  readonly recordCount: number;
  readonly subjectUniverseScope: OrganizationReconciliationSubjectUniverseScope;
  readonly subjectUniverse: {
    readonly count: number;
    readonly sha256: string;
  };
  readonly snapshotMode: typeof ORGANIZATION_RECONCILIATION_SNAPSHOT_MODE;
  readonly paginationMode: typeof ORGANIZATION_RECONCILIATION_PAGINATION_MODE;
  readonly schemaSha256: string;
  readonly catalogSha256: string;
  readonly buildSha256: string;
  readonly openedAt: string;
  readonly closedAt: string;
}

export interface OrganizationReconciliationCompositeManifestUnsigned {
  readonly contract: typeof ORGANIZATION_RECONCILIATION_COMPOSITE_MANIFEST_CONTRACT;
  readonly consistencyModel: typeof ORGANIZATION_RECONCILIATION_COMPOSITE_CONSISTENCY_MODEL;
  readonly crossDatabaseAtomic: false;
  readonly windowStartedAt: string;
  readonly windowEndedAt: string;
  readonly maxWindowMilliseconds: number;
  readonly evidenceContract: typeof ORGANIZATION_RECONCILIATION_OPERATION_EVIDENCE_CONTRACT;
  readonly evidenceSha256: string;
  readonly components: readonly OrganizationReconciliationComponentManifest[];
}

export interface OrganizationReconciliationCompositeManifest
  extends OrganizationReconciliationCompositeManifestUnsigned {
  readonly manifestSha256: string;
}

const MANIFEST_HASH_DOMAIN = Buffer.from(
  "iam-organization-reconciliation:composite-manifest:v2\u001f",
  "utf8"
);
const OPERATION_EVIDENCE_HASH_DOMAIN = Buffer.from(
  "iam-organization-reconciliation:operation-evidence:v2\u001f",
  "utf8"
);

/**
 * Strictly validates and canonicalizes the unsigned manifest. Component input
 * order cannot affect the returned representation or its digest.
 */
export function validateOrganizationReconciliationCompositeManifestUnsigned(
  candidate: unknown
): OrganizationReconciliationCompositeManifestUnsigned {
  const canonicalCandidate = canonicalizeOrganizationReconciliationEvidenceValue(candidate);
  requireExactKeys(canonicalCandidate, [
    "contract",
    "consistencyModel",
    "crossDatabaseAtomic",
    "windowStartedAt",
    "windowEndedAt",
    "maxWindowMilliseconds",
    "evidenceContract",
    "evidenceSha256",
    "components"
  ], "composite manifest");
  const manifest = canonicalCandidate as Record<string, unknown>;
  if (manifest.contract !== ORGANIZATION_RECONCILIATION_COMPOSITE_MANIFEST_CONTRACT ||
    manifest.consistencyModel !== ORGANIZATION_RECONCILIATION_COMPOSITE_CONSISTENCY_MODEL ||
    manifest.crossDatabaseAtomic !== false) {
    throw new OrganizationReconciliationComponentManifestError(
      "The composite manifest cannot claim cross-database atomic consistency."
    );
  }
  const maxWindowMilliseconds = requireWindowBound(manifest.maxWindowMilliseconds);
  if (manifest.evidenceContract !== ORGANIZATION_RECONCILIATION_OPERATION_EVIDENCE_CONTRACT) {
    throw new OrganizationReconciliationComponentManifestError(
      "The composite manifest operation evidence contract is invalid."
    );
  }
  const evidenceSha256 = requireSha256(manifest.evidenceSha256, "operation evidence digest");
  const windowStartedAt = requireCanonicalTimestamp(manifest.windowStartedAt, "manifest window start");
  const windowEndedAt = requireCanonicalTimestamp(manifest.windowEndedAt, "manifest window end");
  const windowStart = Date.parse(windowStartedAt);
  const windowEnd = Date.parse(windowEndedAt);
  if (windowEnd < windowStart || windowEnd - windowStart > maxWindowMilliseconds) {
    throw new OrganizationReconciliationComponentManifestError(
      "The composite manifest window is invalid or unbounded."
    );
  }
  if (!Array.isArray(manifest.components)) {
    throw new OrganizationReconciliationComponentManifestError(
      "The composite manifest component set is invalid."
    );
  }

  const byComponent = new Map<
    OrganizationReconciliationPhysicalSource,
    OrganizationReconciliationComponentManifest
  >();
  const sourceIds = new Set<string>();
  for (const candidateComponent of manifest.components) {
    requireExactKeys(candidateComponent, [
      "componentId",
      "sourceId",
      "sourceVersion",
      "snapshotId",
      "recordCount",
      "subjectUniverseScope",
      "subjectUniverse",
      "snapshotMode",
      "paginationMode",
      "schemaSha256",
      "catalogSha256",
      "buildSha256",
      "openedAt",
      "closedAt"
    ], "component manifest");
    const component = candidateComponent as Record<string, unknown>;
    if (!isRequiredPhysicalSource(component.componentId)) {
      throw new OrganizationReconciliationComponentManifestError(
        "The composite manifest contains an unknown component."
      );
    }
    if (byComponent.has(component.componentId)) {
      throw new OrganizationReconciliationComponentManifestError(
        "The composite manifest contains a duplicate component."
      );
    }
    const sourceId = requireOpaqueMetadata(component.sourceId, "component source ID");
    if (sourceIds.has(sourceId)) {
      throw new OrganizationReconciliationComponentManifestError(
        "The composite manifest contains a duplicate physical source."
      );
    }
    sourceIds.add(sourceId);
    if (component.snapshotMode !== ORGANIZATION_RECONCILIATION_SNAPSHOT_MODE ||
      component.paginationMode !== ORGANIZATION_RECONCILIATION_PAGINATION_MODE) {
      throw new OrganizationReconciliationComponentManifestError(
        "A composite manifest component is not an immutable snapshot."
      );
    }
    requireExactKeys(component.subjectUniverse, ["count", "sha256"], "subject universe");
    const subjectUniverse = component.subjectUniverse as Record<string, unknown>;
    const subjectUniverseScope = requireSubjectUniverse(
      component.componentId,
      component.subjectUniverseScope,
      subjectUniverse
    );
    const openedAt = requireCanonicalTimestamp(component.openedAt, "component window start");
    const closedAt = requireCanonicalTimestamp(component.closedAt, "component window end");
    const openedTime = Date.parse(openedAt);
    const closedTime = Date.parse(closedAt);
    if (
      openedTime < windowStart ||
      closedTime > windowEnd ||
      closedTime < openedTime ||
      closedTime - openedTime > maxWindowMilliseconds
    ) {
      throw new OrganizationReconciliationComponentManifestError(
        "A composite manifest component window is invalid or unbounded."
      );
    }
    byComponent.set(component.componentId, Object.freeze({
      componentId: component.componentId,
      sourceId,
      sourceVersion: requireOpaqueMetadata(component.sourceVersion, "component source version"),
      snapshotId: requireOpaqueMetadata(component.snapshotId, "component snapshot ID"),
      recordCount: requireNonNegativeSafeInteger(component.recordCount, "component record count"),
      subjectUniverseScope: subjectUniverseScope.scope,
      subjectUniverse: subjectUniverseScope.subjectUniverse,
      snapshotMode: ORGANIZATION_RECONCILIATION_SNAPSHOT_MODE,
      paginationMode: ORGANIZATION_RECONCILIATION_PAGINATION_MODE,
      schemaSha256: requireSha256(component.schemaSha256, "component schema digest"),
      catalogSha256: requireSha256(component.catalogSha256, "component catalog digest"),
      buildSha256: requireSha256(component.buildSha256, "component build digest"),
      openedAt,
      closedAt
    }));
  }
  if (byComponent.size !== ORGANIZATION_RECONCILIATION_REQUIRED_PHYSICAL_SOURCES.length) {
    throw new OrganizationReconciliationComponentManifestError(
      "The composite manifest is missing a required component."
    );
  }

  const components = Object.freeze(
    ORGANIZATION_RECONCILIATION_REQUIRED_PHYSICAL_SOURCES.map((componentId) => byComponent.get(componentId)!)
  );
  const openedTimes = components.map((component) => Date.parse(component.openedAt));
  const closedTimes = components.map((component) => Date.parse(component.closedAt));
  if (
    openedTimes.some((openedAt, index) => index > 0 && openedAt < openedTimes[index - 1]!) ||
    closedTimes.some((closedAt, index) => index > 0 && closedAt > closedTimes[index - 1]!)
  ) {
    throw new OrganizationReconciliationComponentManifestError(
      "The composite manifest component lifecycle order is invalid."
    );
  }
  if (Math.max(...openedTimes) > Math.min(...closedTimes)) {
    throw new OrganizationReconciliationComponentManifestError(
      "The composite manifest components do not share one immutable snapshot interval."
    );
  }
  const legacyUniverse = components[0]!.subjectUniverse;
  const identityUniverse = components[1]!.subjectUniverse;
  if (
    legacyUniverse.count !== identityUniverse.count ||
    legacyUniverse.sha256 !== identityUniverse.sha256
  ) {
    throw new OrganizationReconciliationComponentManifestError(
      "Legacy and Identity component subject universes do not match."
    );
  }
  if (Math.min(...openedTimes) !== windowStart || Math.max(...closedTimes) !== windowEnd) {
    throw new OrganizationReconciliationComponentManifestError(
      "The composite manifest window does not bind every component."
    );
  }
  return Object.freeze({
    contract: ORGANIZATION_RECONCILIATION_COMPOSITE_MANIFEST_CONTRACT,
    consistencyModel: ORGANIZATION_RECONCILIATION_COMPOSITE_CONSISTENCY_MODEL,
    crossDatabaseAtomic: false as const,
    windowStartedAt,
    windowEndedAt,
    maxWindowMilliseconds,
    evidenceContract: ORGANIZATION_RECONCILIATION_OPERATION_EVIDENCE_CONTRACT,
    evidenceSha256,
    components
  });
}

/** Canonical, domain-separated digest of a strictly validated unsigned manifest. */
export function createOrganizationReconciliationCompositeManifestSha256(
  manifest: OrganizationReconciliationCompositeManifestUnsigned
): string {
  const canonicalManifest = validateOrganizationReconciliationCompositeManifestUnsigned(manifest);
  return createHash("sha256")
    .update(MANIFEST_HASH_DOMAIN)
    .update(canonicalJson(canonicalManifest), "utf8")
    .digest("hex");
}

/**
 * Copies an operation result into deeply frozen canonical JSON. Accessors,
 * sparse arrays, symbols, cycles, non-finite numbers, and class instances are
 * rejected so a caller cannot self-report a digest over different records.
 */
export function canonicalizeOrganizationReconciliationEvidenceValue(
  candidate: unknown
): OrganizationReconciliationEvidenceJsonValue {
  try {
    return canonicalizeEvidenceValue(candidate, new Set<object>(), { nodes: 0 }, 0);
  } catch (error) {
    if (error instanceof OrganizationReconciliationComponentManifestError) throw error;
    throw new OrganizationReconciliationComponentManifestError(
      "The operation evidence value is not canonical JSON."
    );
  }
}

/** Coordinator-owned digest over the exact canonical operation return value. */
export function createOrganizationReconciliationOperationEvidenceSha256(
  candidate: unknown
): string {
  const canonicalValue = canonicalizeOrganizationReconciliationEvidenceValue(candidate);
  const serialized = canonicalJson(canonicalValue);
  if (Buffer.byteLength(serialized, "utf8") > 64 * 1024 * 1024) {
    throw new OrganizationReconciliationComponentManifestError(
      "The operation evidence value exceeds the approved canonical JSON bound."
    );
  }
  return createHash("sha256")
    .update(OPERATION_EVIDENCE_HASH_DOMAIN)
    .update(serialized, "utf8")
    .digest("hex");
}

/** Strictly validates both the manifest body and its canonical manifest digest. */
export function validateOrganizationReconciliationCompositeManifest(
  candidate: unknown
): OrganizationReconciliationCompositeManifest {
  const canonicalCandidate = canonicalizeOrganizationReconciliationEvidenceValue(candidate);
  requireExactKeys(canonicalCandidate, [
    "contract",
    "consistencyModel",
    "crossDatabaseAtomic",
    "windowStartedAt",
    "windowEndedAt",
    "maxWindowMilliseconds",
    "evidenceContract",
    "evidenceSha256",
    "components",
    "manifestSha256"
  ], "signed composite manifest");
  const manifest = canonicalCandidate as Record<string, unknown>;
  const unsigned = validateOrganizationReconciliationCompositeManifestUnsigned({
    contract: manifest.contract,
    consistencyModel: manifest.consistencyModel,
    crossDatabaseAtomic: manifest.crossDatabaseAtomic,
    windowStartedAt: manifest.windowStartedAt,
    windowEndedAt: manifest.windowEndedAt,
    maxWindowMilliseconds: manifest.maxWindowMilliseconds,
    evidenceContract: manifest.evidenceContract,
    evidenceSha256: manifest.evidenceSha256,
    components: manifest.components
  });
  const manifestSha256 = requireSha256(manifest.manifestSha256, "composite manifest digest");
  const expectedSha256 = createOrganizationReconciliationCompositeManifestSha256(unsigned);
  if (!safeDigestEqual(manifestSha256, expectedSha256)) {
    throw new OrganizationReconciliationComponentManifestError(
      "The composite manifest digest does not match its canonical content."
    );
  }
  return Object.freeze({ ...unsigned, manifestSha256 });
}

/** Rejects pairing snapshot manifest A with operation evidence B. */
export function validateOrganizationReconciliationCompositeManifestEvidenceBinding(
  candidateManifest: unknown,
  candidateEvidence: unknown
): OrganizationReconciliationCompositeManifest {
  const manifest = validateOrganizationReconciliationCompositeManifest(candidateManifest);
  const evidenceSha256 = createOrganizationReconciliationOperationEvidenceSha256(candidateEvidence);
  if (!safeDigestEqual(manifest.evidenceSha256, evidenceSha256)) {
    throw new OrganizationReconciliationComponentManifestError(
      "The operation evidence does not match the composite manifest binding."
    );
  }
  return manifest;
}

function canonicalizeEvidenceValue(
  value: unknown,
  activeObjects: Set<object>,
  state: { nodes: number },
  depth: number
): OrganizationReconciliationEvidenceJsonValue {
  state.nodes += 1;
  if (state.nodes > 1_000_000 || depth > 64) {
    throw new OrganizationReconciliationComponentManifestError(
      "The operation evidence value exceeds the approved structural bound."
    );
  }
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new OrganizationReconciliationComponentManifestError(
        "The operation evidence value contains a non-finite number."
      );
    }
    return Object.is(value, -0) ? 0 : value;
  }
  if (typeof value !== "object") {
    throw new OrganizationReconciliationComponentManifestError(
      "The operation evidence value is not canonical JSON."
    );
  }
  if (activeObjects.has(value)) {
    throw new OrganizationReconciliationComponentManifestError(
      "The operation evidence value contains a cycle."
    );
  }
  activeObjects.add(value);
  try {
    if (Array.isArray(value)) {
      const ownKeys = Reflect.ownKeys(value);
      if (
        ownKeys.some((key) => typeof key !== "string") ||
        ownKeys.length !== value.length + 1 ||
        !ownKeys.includes("length")
      ) {
        throw new OrganizationReconciliationComponentManifestError(
          "The operation evidence value contains a non-canonical array."
        );
      }
      const normalized: OrganizationReconciliationEvidenceJsonValue[] = [];
      for (let index = 0; index < value.length; index += 1) {
        const key = String(index);
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
          throw new OrganizationReconciliationComponentManifestError(
            "The operation evidence value contains a sparse or accessor array."
          );
        }
        normalized.push(canonicalizeEvidenceValue(descriptor.value, activeObjects, state, depth + 1));
      }
      return Object.freeze(normalized);
    }

    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new OrganizationReconciliationComponentManifestError(
        "The operation evidence value contains a non-JSON object."
      );
    }
    const keys = Reflect.ownKeys(value);
    if (keys.some((key) => typeof key !== "string")) {
      throw new OrganizationReconciliationComponentManifestError(
        "The operation evidence value contains a symbol key."
      );
    }
    const normalized: Record<string, OrganizationReconciliationEvidenceJsonValue> = Object.create(null);
    for (const key of (keys as string[]).sort()) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
        throw new OrganizationReconciliationComponentManifestError(
          "The operation evidence value contains an accessor or hidden field."
        );
      }
      normalized[key] = canonicalizeEvidenceValue(descriptor.value, activeObjects, state, depth + 1);
    }
    return Object.freeze(normalized);
  } finally {
    activeObjects.delete(value);
  }
}

function safeDigestEqual(left: string, right: string): boolean {
  const leftBytes = Buffer.from(left, "hex");
  const rightBytes = Buffer.from(right, "hex");
  return leftBytes.length === rightBytes.length && timingSafeEqual(leftBytes, rightBytes);
}

function isRequiredPhysicalSource(value: unknown): value is OrganizationReconciliationPhysicalSource {
  return typeof value === "string" &&
    ORGANIZATION_RECONCILIATION_REQUIRED_PHYSICAL_SOURCES.includes(
      value as OrganizationReconciliationPhysicalSource
    );
}

function requireSubjectUniverse(
  componentId: OrganizationReconciliationPhysicalSource,
  candidateScope: unknown,
  candidateUniverse: Record<string, unknown>
): {
  readonly scope: OrganizationReconciliationSubjectUniverseScope;
  readonly subjectUniverse: Readonly<{ count: number; sha256: string }>;
} {
  if (componentId === "plugin") {
    if (
      candidateScope !== "not-applicable" ||
      candidateUniverse.count !== 0 ||
      candidateUniverse.sha256 !== ""
    ) {
      throw new OrganizationReconciliationComponentManifestError(
        "The plugin component subject universe must be explicitly not applicable."
      );
    }
    return {
      scope: "not-applicable",
      subjectUniverse: Object.freeze({ count: 0, sha256: "" })
    };
  }
  if (candidateScope !== "complete") {
    throw new OrganizationReconciliationComponentManifestError(
      "Legacy and Identity components require a complete subject universe."
    );
  }
  return {
    scope: "complete",
    subjectUniverse: Object.freeze({
      count: requirePositiveSafeInteger(
        candidateUniverse.count,
        "component subject universe count"
      ),
      sha256: requireSha256(
        candidateUniverse.sha256,
        "component subject universe digest"
      )
    })
  };
}

function requireWindowBound(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1 || (value as number) > 3_600_000) {
    throw new OrganizationReconciliationComponentManifestError(
      "The composite snapshot window bound is invalid."
    );
  }
  return value as number;
}

function requireNonNegativeSafeInteger(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new OrganizationReconciliationComponentManifestError(`The ${label} is invalid.`);
  }
  return value as number;
}

function requirePositiveSafeInteger(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) {
    throw new OrganizationReconciliationComponentManifestError(`The ${label} is invalid.`);
  }
  return value as number;
}

function requireSha256(value: unknown, label: string): string {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) {
    throw new OrganizationReconciliationComponentManifestError(
      `The ${label} must be a full SHA-256 digest.`
    );
  }
  return value;
}

function requireOpaqueMetadata(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length < 1 || value.length > 1_024 || value.trim() !== value) {
    throw new OrganizationReconciliationComponentManifestError(`The ${label} is invalid.`);
  }
  return value;
}

function requireCanonicalTimestamp(value: unknown, label: string): string {
  const timestamp = typeof value === "string" ? Date.parse(value) : Number.NaN;
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== value) {
    throw new OrganizationReconciliationComponentManifestError(
      `The ${label} is not a canonical timestamp.`
    );
  }
  return value as string;
}

function requireExactKeys(value: unknown, expectedKeys: readonly string[], label: string): void {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new OrganizationReconciliationComponentManifestError(`The ${label} is invalid.`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new OrganizationReconciliationComponentManifestError(`The ${label} is invalid.`);
  }
  const ownKeys = Reflect.ownKeys(value);
  if (ownKeys.some((key) => typeof key !== "string")) {
    throw new OrganizationReconciliationComponentManifestError(`The ${label} is invalid.`);
  }
  const actualKeys = (ownKeys as string[]).sort();
  const canonicalExpectedKeys = [...expectedKeys].sort();
  if (canonicalJson(actualKeys) !== canonicalJson(canonicalExpectedKeys)) {
    throw new OrganizationReconciliationComponentManifestError(
      `The ${label} has missing or unknown fields.`
    );
  }
  for (const key of actualKeys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
      throw new OrganizationReconciliationComponentManifestError(`The ${label} is invalid.`);
    }
  }
}

function canonicalJson(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "string") return JSON.stringify(value)!;
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new OrganizationReconciliationComponentManifestError(
        "Manifest metadata is not canonical JSON."
      );
    }
    return JSON.stringify(value)!;
  }
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record).sort();
    if (keys.some((key) => record[key] === undefined)) {
      throw new OrganizationReconciliationComponentManifestError(
        "Manifest metadata is not canonical JSON."
      );
    }
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(",")}}`;
  }
  throw new OrganizationReconciliationComponentManifestError(
    "Manifest metadata is not canonical JSON."
  );
}

export class OrganizationReconciliationComponentManifestError extends Error {}
