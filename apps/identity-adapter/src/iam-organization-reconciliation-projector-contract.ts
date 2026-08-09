import {
  canonicalizeOrganizationReconciliationEvidenceValue,
  type OrganizationReconciliationEvidenceJsonValue
} from "./iam-organization-reconciliation-component-manifest.js";
import type {
  CampusContextRecord,
  EffectiveOrganizationDecisionRecord,
  OrganizationDirectoryRecord,
  OrganizationMappingRecord,
  OrganizationMembershipRecord,
  OrganizationScopedRoleRecord,
  PluginBindingRecord,
  PluginVisibilityRecord
} from "./iam-organization-reconciliation-validator.js";

export const LEGACY_ORGANIZATION_SURFACE_PROJECTOR_CONTRACT =
  "iam-organization-legacy-surface-projector/v1" as const;
export const IDENTITY_ORGANIZATION_SURFACE_PROJECTOR_CONTRACT =
  "iam-organization-identity-surface-projector/v1" as const;
export const ORGANIZATION_SURFACE_PROJECTORS_READY = false as const;

export interface OrganizationSurfaceProjectionRecords {
  readonly organizationDirectory: readonly OrganizationDirectoryRecord[];
  readonly organizationMappings: readonly OrganizationMappingRecord[];
  readonly memberships: readonly OrganizationMembershipRecord[];
  readonly organizationScopedRoles: readonly OrganizationScopedRoleRecord[];
  readonly pluginBindings: readonly PluginBindingRecord[];
  readonly pluginVisibility: readonly PluginVisibilityRecord[];
  readonly campusContexts: readonly CampusContextRecord[];
  readonly effectiveDecisions: readonly EffectiveOrganizationDecisionRecord[];
}

export interface OrganizationSurfaceProjectionDraft {
  readonly surfaces: OrganizationSurfaceProjectionRecords;
}

interface OrganizationSurfaceProjectionBase {
  readonly evaluatorId: string;
  readonly evaluatorBuildSha256: string;
  readonly semanticRegistrySha256: string;
  readonly surfaces: OrganizationSurfaceProjectionRecords;
}

declare const LEGACY_PROJECTION_BRAND: unique symbol;
declare const IDENTITY_PROJECTION_BRAND: unique symbol;

export interface LegacyOrganizationSurfaceProjection extends OrganizationSurfaceProjectionBase {
  readonly side: "legacy";
  readonly contract: typeof LEGACY_ORGANIZATION_SURFACE_PROJECTOR_CONTRACT;
  readonly [LEGACY_PROJECTION_BRAND]: true;
}

export interface IdentityOrganizationSurfaceProjection extends OrganizationSurfaceProjectionBase {
  readonly side: "identity";
  readonly contract: typeof IDENTITY_ORGANIZATION_SURFACE_PROJECTOR_CONTRACT;
  readonly [IDENTITY_PROJECTION_BRAND]: true;
}

export interface LegacyOrganizationSurfaceProjector<TSnapshotView> {
  readonly side: "legacy";
  readonly contract: typeof LEGACY_ORGANIZATION_SURFACE_PROJECTOR_CONTRACT;
  readonly evaluatorId: string;
  readonly evaluatorBuildSha256: string;
  project(input: Readonly<{
    snapshotView: TSnapshotView;
    semanticRegistrySha256: string;
  }>): Promise<OrganizationSurfaceProjectionDraft> | OrganizationSurfaceProjectionDraft;
}

export interface IdentityOrganizationSurfaceProjector<TSnapshotView> {
  readonly side: "identity";
  readonly contract: typeof IDENTITY_ORGANIZATION_SURFACE_PROJECTOR_CONTRACT;
  readonly evaluatorId: string;
  readonly evaluatorBuildSha256: string;
  project(input: Readonly<{
    snapshotView: TSnapshotView;
    semanticRegistrySha256: string;
  }>): Promise<OrganizationSurfaceProjectionDraft> | OrganizationSurfaceProjectionDraft;
}

export interface OrganizationSurfaceProjectorReadiness {
  readonly ready: false;
  readonly blockers: readonly [
    "compiled-owner-semantic-registry-empty",
    "compiled-owner-semantic-registry-selection-not-implemented",
    "legacy-projector-not-registered",
    "identity-projector-not-registered",
    "independent-projector-artifact-provenance-not-attested"
  ];
}

interface CapturedOrganizationSurfaceProjector<TSnapshotView> {
  readonly origin: object;
  readonly receiver: Readonly<{
    side: "legacy" | "identity";
    contract:
      | typeof LEGACY_ORGANIZATION_SURFACE_PROJECTOR_CONTRACT
      | typeof IDENTITY_ORGANIZATION_SURFACE_PROJECTOR_CONTRACT;
    evaluatorId: string;
    evaluatorBuildSha256: string;
  }>;
  readonly side: "legacy" | "identity";
  readonly contract:
    | typeof LEGACY_ORGANIZATION_SURFACE_PROJECTOR_CONTRACT
    | typeof IDENTITY_ORGANIZATION_SURFACE_PROJECTOR_CONTRACT;
  readonly evaluatorId: string;
  readonly evaluatorBuildSha256: string;
  readonly project: (
    input: Readonly<{
      snapshotView: TSnapshotView;
      semanticRegistrySha256: string;
    }>
  ) => Promise<OrganizationSurfaceProjectionDraft> | OrganizationSurfaceProjectionDraft;
}

const legacyProjectionBrand = new WeakSet<object>();
const identityProjectionBrand = new WeakSet<object>();
const projectionOrigins = new WeakMap<object, object>();

export class OrganizationSurfaceProjectorContractError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "OrganizationSurfaceProjectorContractError";
  }
}

export function organizationSurfaceProjectorReadiness(): OrganizationSurfaceProjectorReadiness {
  return Object.freeze({
    ready: ORGANIZATION_SURFACE_PROJECTORS_READY,
    blockers: Object.freeze([
      "compiled-owner-semantic-registry-empty",
      "compiled-owner-semantic-registry-selection-not-implemented",
      "legacy-projector-not-registered",
      "identity-projector-not-registered",
      "independent-projector-artifact-provenance-not-attested"
    ] as const)
  });
}

/**
 * Executes and brands only the Legacy projector contract. The draft is
 * canonicalized into a detached frozen graph, so an implementation cannot
 * retain mutable aliases into coordinator evidence.
 */
export async function executeLegacyOrganizationSurfaceProjector<TSnapshotView>(
  projector: LegacyOrganizationSurfaceProjector<TSnapshotView>,
  snapshotView: TSnapshotView,
  semanticRegistrySha256: string
): Promise<LegacyOrganizationSurfaceProjection> {
  const canonicalRegistrySha256 = requireSha256(semanticRegistrySha256, "semantic registry");
  const captured = captureProjector(
    projector,
    "legacy",
    LEGACY_ORGANIZATION_SURFACE_PROJECTOR_CONTRACT
  );
  const draft = await captured.project.call(captured.receiver, Object.freeze({
    snapshotView,
    semanticRegistrySha256: canonicalRegistrySha256
  }));
  const projection = createProjection(
    captured,
    draft,
    "legacy",
    LEGACY_ORGANIZATION_SURFACE_PROJECTOR_CONTRACT,
    canonicalRegistrySha256
  ) as LegacyOrganizationSurfaceProjection;
  legacyProjectionBrand.add(projection);
  projectionOrigins.set(projection, captured.origin);
  return projection;
}

/** Identity output receives a disjoint runtime brand and detached object graph. */
export async function executeIdentityOrganizationSurfaceProjector<TSnapshotView>(
  projector: IdentityOrganizationSurfaceProjector<TSnapshotView>,
  snapshotView: TSnapshotView,
  semanticRegistrySha256: string
): Promise<IdentityOrganizationSurfaceProjection> {
  const canonicalRegistrySha256 = requireSha256(semanticRegistrySha256, "semantic registry");
  const captured = captureProjector(
    projector,
    "identity",
    IDENTITY_ORGANIZATION_SURFACE_PROJECTOR_CONTRACT
  );
  const draft = await captured.project.call(captured.receiver, Object.freeze({
    snapshotView,
    semanticRegistrySha256: canonicalRegistrySha256
  }));
  const projection = createProjection(
    captured,
    draft,
    "identity",
    IDENTITY_ORGANIZATION_SURFACE_PROJECTOR_CONTRACT,
    canonicalRegistrySha256
  ) as IdentityOrganizationSurfaceProjection;
  identityProjectionBrand.add(projection);
  projectionOrigins.set(projection, captured.origin);
  return projection;
}

export function isLegacyOrganizationSurfaceProjection(
  candidate: unknown
): candidate is LegacyOrganizationSurfaceProjection {
  return typeof candidate === "object" && candidate !== null && legacyProjectionBrand.has(candidate);
}

export function isIdentityOrganizationSurfaceProjection(
  candidate: unknown
): candidate is IdentityOrganizationSurfaceProjection {
  return typeof candidate === "object" && candidate !== null && identityProjectionBrand.has(candidate);
}

/**
 * Enforces side brands, metadata-disjoint projector wrappers, and disjoint
 * result graphs. It does not attest independent evaluator artifacts or prove
 * that two wrappers do not share one callable/closure; readiness remains false
 * until that provenance is implemented.
 */
export function assertIndependentOrganizationSurfaceProjections(
  legacy: LegacyOrganizationSurfaceProjection,
  identity: IdentityOrganizationSurfaceProjection
): void {
  if (!isLegacyOrganizationSurfaceProjection(legacy) || !isIdentityOrganizationSurfaceProjection(identity)) {
    throw new OrganizationSurfaceProjectorContractError("A surface projection has no trusted side brand.");
  }
  const legacyOrigin = projectionOrigins.get(legacy);
  const identityOrigin = projectionOrigins.get(identity);
  if (
    legacyOrigin === undefined ||
    identityOrigin === undefined ||
    legacyOrigin === identityOrigin ||
    legacy.evaluatorId === identity.evaluatorId ||
    legacy.evaluatorBuildSha256 === identity.evaluatorBuildSha256
  ) {
    throw new OrganizationSurfaceProjectorContractError(
      "Legacy and Identity projector wrappers must have disjoint origins and metadata."
    );
  }
  if (legacy.semanticRegistrySha256 !== identity.semanticRegistrySha256) {
    throw new OrganizationSurfaceProjectorContractError(
      "Legacy and Identity projections do not bind the same semantic registry."
    );
  }
  assertNoSharedObjectIdentity(legacy.surfaces, identity.surfaces);
}

function createProjection(
  projector: Readonly<{ evaluatorId: string; evaluatorBuildSha256: string }>,
  candidateDraft: unknown,
  side: "legacy" | "identity",
  contract:
    | typeof LEGACY_ORGANIZATION_SURFACE_PROJECTOR_CONTRACT
    | typeof IDENTITY_ORGANIZATION_SURFACE_PROJECTOR_CONTRACT,
  semanticRegistrySha256: string
): object {
  const canonicalDraft = canonicalizeOrganizationReconciliationEvidenceValue(candidateDraft);
  requireExactKeys(canonicalDraft, ["surfaces"], "surface projection draft");
  const draft = canonicalDraft as Record<string, OrganizationReconciliationEvidenceJsonValue>;
  requireExactKeys(draft.surfaces, [
    "organizationDirectory",
    "organizationMappings",
    "memberships",
    "organizationScopedRoles",
    "pluginBindings",
    "pluginVisibility",
    "campusContexts",
    "effectiveDecisions"
  ], "surface projection records");
  const surfaces = draft.surfaces as Record<string, OrganizationReconciliationEvidenceJsonValue>;
  for (const [surface, records] of Object.entries(surfaces)) {
    if (!Array.isArray(records)) {
      throw new OrganizationSurfaceProjectorContractError(
        `The ${surface} projection must be an array.`
      );
    }
  }
  return Object.freeze({
    side,
    contract,
    evaluatorId: requireEvaluatorId(projector.evaluatorId),
    evaluatorBuildSha256: requireSha256(projector.evaluatorBuildSha256, "evaluator build"),
    semanticRegistrySha256: requireSha256(semanticRegistrySha256, "semantic registry"),
    surfaces: draft.surfaces
  });
}

/**
 * Captures all projector fields exactly once from own enumerable data
 * descriptors. Accessors, symbols, hidden/unknown fields, and custom
 * prototypes are rejected without invoking caller code. Async execution uses
 * only this frozen capture and binds `this` to a frozen minimal metadata
 * receiver rather than the mutable caller object, preventing metadata TOCTOU.
 */
function captureProjector<TSnapshotView>(
  candidate: LegacyOrganizationSurfaceProjector<TSnapshotView> | IdentityOrganizationSurfaceProjector<TSnapshotView>,
  side: "legacy" | "identity",
  contract:
    | typeof LEGACY_ORGANIZATION_SURFACE_PROJECTOR_CONTRACT
    | typeof IDENTITY_ORGANIZATION_SURFACE_PROJECTOR_CONTRACT
): CapturedOrganizationSurfaceProjector<TSnapshotView> {
  if (
    typeof candidate !== "object" ||
    candidate === null ||
    Array.isArray(candidate) ||
    Object.getPrototypeOf(candidate) !== Object.prototype
  ) {
    throw new OrganizationSurfaceProjectorContractError("The surface projector object is invalid.");
  }
  const expectedKeys = ["side", "contract", "evaluatorId", "evaluatorBuildSha256", "project"];
  const ownKeys = Reflect.ownKeys(candidate);
  if (
    ownKeys.some((key) => typeof key !== "string") ||
    JSON.stringify((ownKeys as string[]).sort()) !== JSON.stringify([...expectedKeys].sort())
  ) {
    throw new OrganizationSurfaceProjectorContractError(
      "The surface projector has hidden, symbolic, missing, or unknown fields."
    );
  }
  const descriptors = Object.getOwnPropertyDescriptors(candidate);
  const capturedValues: Record<string, unknown> = {};
  for (const key of expectedKeys) {
    const descriptor = descriptors[key];
    if (descriptor === undefined || !("value" in descriptor) || descriptor.enumerable !== true) {
      throw new OrganizationSurfaceProjectorContractError(
        "The surface projector must use enumerable data descriptors."
      );
    }
    capturedValues[key] = descriptor.value;
  }
  if (capturedValues.side !== side || capturedValues.contract !== contract) {
    throw new OrganizationSurfaceProjectorContractError("The surface projector side contract is invalid.");
  }
  if (typeof capturedValues.evaluatorId !== "string") {
    throw new OrganizationSurfaceProjectorContractError("The evaluator ID is invalid.");
  }
  if (typeof capturedValues.evaluatorBuildSha256 !== "string") {
    throw new OrganizationSurfaceProjectorContractError("The evaluator build digest is invalid.");
  }
  if (typeof capturedValues.project !== "function") {
    throw new OrganizationSurfaceProjectorContractError("The surface projector callable is invalid.");
  }
  const evaluatorId = requireEvaluatorId(capturedValues.evaluatorId);
  const evaluatorBuildSha256 = requireSha256(capturedValues.evaluatorBuildSha256, "evaluator build");
  const receiver = Object.freeze({ side, contract, evaluatorId, evaluatorBuildSha256 });
  return Object.freeze({
    origin: candidate,
    receiver,
    side,
    contract,
    evaluatorId,
    evaluatorBuildSha256,
    project: capturedValues.project as CapturedOrganizationSurfaceProjector<TSnapshotView>["project"]
  });
}

function assertNoSharedObjectIdentity(left: object, right: object): void {
  const leftObjects = collectObjectIdentities(left);
  for (const object of collectObjectIdentities(right)) {
    if (leftObjects.has(object)) {
      throw new OrganizationSurfaceProjectorContractError(
        "Legacy and Identity projections share decision object identity."
      );
    }
  }
}

function collectObjectIdentities(root: object): Set<object> {
  const objects = new Set<object>();
  const queue: object[] = [root];
  for (let offset = 0; offset < queue.length; offset += 1) {
    const current = queue[offset]!;
    if (objects.has(current)) continue;
    objects.add(current);
    for (const value of Array.isArray(current) ? current : Object.values(current)) {
      if (typeof value === "object" && value !== null) queue.push(value);
    }
  }
  return objects;
}

function requireEvaluatorId(value: string): string {
  if (!/^[a-z0-9][a-z0-9./:-]{0,127}$/.test(value) || value.includes("..")) {
    throw new OrganizationSurfaceProjectorContractError("The evaluator ID is invalid.");
  }
  return value;
}

function requireSha256(value: string, label: string): string {
  if (!/^[a-f0-9]{64}$/.test(value)) {
    throw new OrganizationSurfaceProjectorContractError(`The ${label} digest is invalid.`);
  }
  return value;
}

function requireExactKeys(
  value: OrganizationReconciliationEvidenceJsonValue,
  expectedKeys: readonly string[],
  label: string
): void {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new OrganizationSurfaceProjectorContractError(`The ${label} is invalid.`);
  }
  if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...expectedKeys].sort())) {
    throw new OrganizationSurfaceProjectorContractError(`The ${label} has missing or unknown fields.`);
  }
}
