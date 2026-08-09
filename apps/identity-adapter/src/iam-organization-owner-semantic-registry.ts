import { createHash } from "node:crypto";
import {
  canonicalizeOrganizationReconciliationEvidenceValue,
  type OrganizationReconciliationEvidenceJsonValue
} from "./iam-organization-reconciliation-component-manifest.js";

export const ORGANIZATION_OWNER_SEMANTIC_REGISTRY_CONTRACT =
  "iam-organization-owner-semantic-registry/v1" as const;

export const ORGANIZATION_OWNER_SEMANTIC_PRIMITIVES = Object.freeze({
  deterministicMappingContract: "legacy-organization-id-mapping/legacy-prefix-v1",
  legacySubjectLifecycleContract: "legacy-subject-lifecycle/status-10-active-v1",
  pluginBindingContract: "plugin-binding/sql-null-public-strict-v1",
  pluginAccessScopeContract: "plugin-access-scope/role-level-v1",
  yiiRbacContract: "yii-rbac/rule-free-closure-v1"
} as const);

export const ORGANIZATION_OWNER_DECISION_CONTRACTS = Object.freeze({
  identityShadowCandidateSelectors:
    "identity-organization-shadow-candidate-selectors-owner-decision/v1",
  roleScopes: "organization-role-scope-owner-decision/v1",
  pluginOverlay: "plugin-overlay-owner-decision/v1",
  campusPublicContext: "campus-public-context-owner-decision/v1",
  capabilityCatalog: "organization-capability-catalog-owner-decision/v1"
} as const);

export type OrganizationOwnerDecisionName = keyof typeof ORGANIZATION_OWNER_DECISION_CONTRACTS;

export interface OrganizationOwnerSemanticDecisionPin {
  readonly decisionContract: (typeof ORGANIZATION_OWNER_DECISION_CONTRACTS)[OrganizationOwnerDecisionName];
  readonly approvalSha256: string;
  readonly catalogSha256: string;
}

export interface OrganizationOwnerSemanticRegistryInput {
  readonly contract: typeof ORGANIZATION_OWNER_SEMANTIC_REGISTRY_CONTRACT;
  readonly registryId: string;
  readonly registryRevisionSha256: string;
  readonly primitives: typeof ORGANIZATION_OWNER_SEMANTIC_PRIMITIVES;
  readonly ownerDecisions: Readonly<{
    identityShadowCandidateSelectors: OrganizationOwnerSemanticDecisionPin | null;
    roleScopes: OrganizationOwnerSemanticDecisionPin | null;
    pluginOverlay: OrganizationOwnerSemanticDecisionPin | null;
    campusPublicContext: OrganizationOwnerSemanticDecisionPin | null;
    capabilityCatalog: OrganizationOwnerSemanticDecisionPin | null;
  }>;
}

export interface CanonicalOrganizationOwnerSemanticRegistry
  extends OrganizationOwnerSemanticRegistryInput {
  readonly registrySha256: string;
}

export type OrganizationOwnerSemanticRegistryBlocker =
  | "compiled-owner-semantic-registry-empty"
  | "identity-shadow-candidate-selectors-owner-decision-missing"
  | "role-scope-owner-decision-missing"
  | "plugin-overlay-owner-decision-missing"
  | "campus-public-context-owner-decision-missing"
  | "capability-catalog-owner-decision-missing";

export interface OrganizationOwnerSemanticRegistryReadiness {
  readonly ready: false;
  readonly compiledRegistryCount: 0;
  readonly blockers: readonly OrganizationOwnerSemanticRegistryBlocker[];
}

const REGISTRY_DIGEST_DOMAIN = Buffer.from(
  "iam-organization:owner-semantic-registry:v1\u001f",
  "utf8"
);

/**
 * Deliberately empty production registry. This table may only be populated by
 * a reviewed source change. No argv, environment, JSON file, request body, or
 * evidence envelope is consulted by production lookup/readiness.
 */
const COMPILED_OWNER_SEMANTIC_REGISTRY: readonly CanonicalOrganizationOwnerSemanticRegistry[] =
  Object.freeze([]);

const REQUIRED_PRIMITIVE_KEYS = Object.freeze(Object.keys(ORGANIZATION_OWNER_SEMANTIC_PRIMITIVES).sort());
const REQUIRED_DECISION_KEYS = Object.freeze(Object.keys(ORGANIZATION_OWNER_DECISION_CONTRACTS).sort());

export class OrganizationOwnerSemanticRegistryError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "OrganizationOwnerSemanticRegistryError";
  }
}

/**
 * Strictly validates an owner-semantic registry candidate and returns a
 * detached, deeply frozen canonical copy. Validation does not provision the
 * candidate into the compiled production registry.
 */
export function canonicalizeOrganizationOwnerSemanticRegistry(
  candidate: unknown
): CanonicalOrganizationOwnerSemanticRegistry {
  const canonical = canonicalizeOrganizationReconciliationEvidenceValue(candidate);
  requireExactKeys(canonical, [
    "contract",
    "registryId",
    "registryRevisionSha256",
    "primitives",
    "ownerDecisions"
  ], "owner semantic registry");
  const registry = canonical as Record<string, OrganizationReconciliationEvidenceJsonValue>;
  if (registry.contract !== ORGANIZATION_OWNER_SEMANTIC_REGISTRY_CONTRACT) {
    throw new OrganizationOwnerSemanticRegistryError("The owner semantic registry contract is invalid.");
  }
  const registryId = requireRegistryId(registry.registryId);
  const registryRevisionSha256 = requireSha256(
    registry.registryRevisionSha256,
    "registry revision"
  );
  const primitives = validatePrimitives(registry.primitives);
  const ownerDecisions = validateOwnerDecisions(registry.ownerDecisions);
  const unsigned = Object.freeze({
    contract: ORGANIZATION_OWNER_SEMANTIC_REGISTRY_CONTRACT,
    registryId,
    registryRevisionSha256,
    primitives,
    ownerDecisions
  });
  return Object.freeze({
    ...unsigned,
    registrySha256: createRegistryDigest(unsigned)
  });
}

/** Returns missing owner decisions for a validated candidate; it never confers production trust. */
export function organizationOwnerSemanticRegistryCandidateBlockers(
  registry: CanonicalOrganizationOwnerSemanticRegistry
): readonly OrganizationOwnerSemanticRegistryBlocker[] {
  const blockers: OrganizationOwnerSemanticRegistryBlocker[] = [];
  if (registry.ownerDecisions.identityShadowCandidateSelectors === null) {
    blockers.push("identity-shadow-candidate-selectors-owner-decision-missing");
  }
  if (registry.ownerDecisions.roleScopes === null) {
    blockers.push("role-scope-owner-decision-missing");
  }
  if (registry.ownerDecisions.pluginOverlay === null) {
    blockers.push("plugin-overlay-owner-decision-missing");
  }
  if (registry.ownerDecisions.campusPublicContext === null) {
    blockers.push("campus-public-context-owner-decision-missing");
  }
  if (registry.ownerDecisions.capabilityCatalog === null) {
    blockers.push("capability-catalog-owner-decision-missing");
  }
  return Object.freeze(blockers);
}

export function organizationOwnerSemanticRegistryReadiness(): OrganizationOwnerSemanticRegistryReadiness {
  return Object.freeze({
    ready: false,
    compiledRegistryCount: 0,
    blockers: Object.freeze([
      "compiled-owner-semantic-registry-empty",
      "identity-shadow-candidate-selectors-owner-decision-missing",
      "role-scope-owner-decision-missing",
      "plugin-overlay-owner-decision-missing",
      "campus-public-context-owner-decision-missing",
      "capability-catalog-owner-decision-missing"
    ] as const)
  });
}

/** Production lookup can only return values compiled into this module. */
export function findCompiledOrganizationOwnerSemanticRegistry(
  registrySha256: string
): CanonicalOrganizationOwnerSemanticRegistry | undefined {
  if (!/^[a-f0-9]{64}$/.test(registrySha256)) return undefined;
  return COMPILED_OWNER_SEMANTIC_REGISTRY.find(
    (registry) => registry.registrySha256 === registrySha256
  );
}

function validatePrimitives(
  candidate: OrganizationReconciliationEvidenceJsonValue
): typeof ORGANIZATION_OWNER_SEMANTIC_PRIMITIVES {
  requireExactKeys(candidate, REQUIRED_PRIMITIVE_KEYS, "owner semantic primitives");
  const primitives = candidate as Record<string, OrganizationReconciliationEvidenceJsonValue>;
  for (const [name, expected] of Object.entries(ORGANIZATION_OWNER_SEMANTIC_PRIMITIVES)) {
    if (primitives[name] !== expected) {
      throw new OrganizationOwnerSemanticRegistryError(
        `The proven semantic primitive ${name} cannot be overridden.`
      );
    }
  }
  return ORGANIZATION_OWNER_SEMANTIC_PRIMITIVES;
}

function validateOwnerDecisions(
  candidate: OrganizationReconciliationEvidenceJsonValue
): OrganizationOwnerSemanticRegistryInput["ownerDecisions"] {
  requireExactKeys(candidate, REQUIRED_DECISION_KEYS, "owner semantic decisions");
  const decisions = candidate as Record<string, OrganizationReconciliationEvidenceJsonValue>;
  return Object.freeze({
    identityShadowCandidateSelectors: validateDecisionPin(
      "identityShadowCandidateSelectors",
      decisions.identityShadowCandidateSelectors
    ),
    roleScopes: validateDecisionPin("roleScopes", decisions.roleScopes),
    pluginOverlay: validateDecisionPin("pluginOverlay", decisions.pluginOverlay),
    campusPublicContext: validateDecisionPin("campusPublicContext", decisions.campusPublicContext),
    capabilityCatalog: validateDecisionPin("capabilityCatalog", decisions.capabilityCatalog)
  });
}

function validateDecisionPin(
  name: OrganizationOwnerDecisionName,
  candidate: OrganizationReconciliationEvidenceJsonValue
): OrganizationOwnerSemanticDecisionPin | null {
  if (candidate === null) return null;
  requireExactKeys(candidate, ["decisionContract", "approvalSha256", "catalogSha256"], `${name} decision pin`);
  const pin = candidate as Record<string, OrganizationReconciliationEvidenceJsonValue>;
  if (pin.decisionContract !== ORGANIZATION_OWNER_DECISION_CONTRACTS[name]) {
    throw new OrganizationOwnerSemanticRegistryError(`The ${name} decision contract is invalid.`);
  }
  return Object.freeze({
    decisionContract: ORGANIZATION_OWNER_DECISION_CONTRACTS[name],
    approvalSha256: requireSha256(pin.approvalSha256, `${name} approval`),
    catalogSha256: requireSha256(pin.catalogSha256, `${name} catalog`)
  });
}

function createRegistryDigest(input: OrganizationOwnerSemanticRegistryInput): string {
  return createHash("sha256")
    .update(REGISTRY_DIGEST_DOMAIN)
    .update(JSON.stringify(input), "utf8")
    .digest("hex");
}

function requireRegistryId(value: OrganizationReconciliationEvidenceJsonValue): string {
  if (
    typeof value !== "string" ||
    !/^[a-z0-9][a-z0-9./:-]{0,127}$/.test(value) ||
    value.includes("..")
  ) {
    throw new OrganizationOwnerSemanticRegistryError("The owner semantic registry ID is invalid.");
  }
  return value;
}

function requireSha256(
  value: OrganizationReconciliationEvidenceJsonValue,
  label: string
): string {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) {
    throw new OrganizationOwnerSemanticRegistryError(`The ${label} must be a full SHA-256 digest.`);
  }
  return value;
}

function requireExactKeys(
  value: OrganizationReconciliationEvidenceJsonValue,
  expectedKeys: readonly string[],
  label: string
): void {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new OrganizationOwnerSemanticRegistryError(`The ${label} is invalid.`);
  }
  const actualKeys = Object.keys(value).sort();
  if (JSON.stringify(actualKeys) !== JSON.stringify([...expectedKeys].sort())) {
    throw new OrganizationOwnerSemanticRegistryError(
      `The ${label} has missing or unknown fields.`
    );
  }
}
