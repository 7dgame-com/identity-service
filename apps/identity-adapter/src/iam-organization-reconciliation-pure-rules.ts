import {
  canonicalizeOrganizationReconciliationEvidenceValue,
  type OrganizationReconciliationEvidenceJsonValue
} from "./iam-organization-reconciliation-component-manifest.js";
import {
  ORGANIZATION_RECONCILIATION_PUBLIC_CONTEXT_REF,
  canonicalLegacyOrganizationId,
  canonicalReconciliationToken,
  pluginRefForId
} from "./iam-organization-reconciliation-refs.js";

export const ORGANIZATION_RECONCILIATION_PROVEN_RULES_CONTRACT =
  "iam-organization-reconciliation-proven-rules/v1" as const;
export const LEGACY_ACTIVE_SUBJECT_STATUS = 10 as const;

export type StrictPluginAccessScope =
  | "auth-only"
  | "manager-only"
  | "admin-only"
  | "root-only";

export const STRICT_PLUGIN_ACCESS_SCOPE_LEVELS = Object.freeze({
  "auth-only": 1,
  "manager-only": 2,
  "admin-only": 3,
  "root-only": 4
} as const satisfies Readonly<Record<StrictPluginAccessScope, number>>);

export interface LegacySubjectLifecycleDecision {
  readonly legacyStatus: number;
  readonly active: boolean;
  readonly identityStatus: "active" | "inactive";
}

export type StrictPluginOrganizationBinding =
  | Readonly<{
      kind: "public";
      organizationName: null;
      organizationRef: typeof ORGANIZATION_RECONCILIATION_PUBLIC_CONTEXT_REF;
    }>
  | Readonly<{
      kind: "organization-name";
      organizationName: string;
    }>;

export interface RuleFreeYiiRbacItemInput {
  readonly name: string;
  readonly type: "role" | "permission";
  /** Only SQL NULL is accepted; every named Yii rule remains unsupported. */
  readonly ruleName: null;
}

export interface RuleFreeYiiRbacRelationInput {
  readonly parent: string;
  readonly child: string;
}

export interface RuleFreeYiiRbacGraphInput {
  /** Complete auth_rule name universe. Rule-free evaluation requires this to be empty. */
  readonly rules: readonly string[];
  readonly items: readonly RuleFreeYiiRbacItemInput[];
  readonly relations: readonly RuleFreeYiiRbacRelationInput[];
}

export interface RuleFreeYiiRbacClosure {
  readonly directAssignments: readonly string[];
  readonly roles: readonly string[];
  readonly permissions: readonly string[];
  readonly visitedItems: readonly string[];
}

export type OrganizationReconciliationProvenRuleErrorCode =
  | "invalid-input"
  | "unsupported-yii-rule"
  | "duplicate-rbac-item"
  | "duplicate-rbac-relation"
  | "missing-rbac-item"
  | "rbac-cycle"
  | "duplicate-rbac-assignment";

export class OrganizationReconciliationProvenRuleError extends Error {
  constructor(
    readonly code: OrganizationReconciliationProvenRuleErrorCode,
    message: string
  ) {
    super(message);
    this.name = "OrganizationReconciliationProvenRuleError";
  }
}

/** Existing Identity candidate compatibility contract: Legacy organization N -> `legacy:N`. */
export function identityOrganizationIdForCanonicalLegacyId(
  legacyOrganizationId: string | number
): string {
  return `legacy:${canonicalLegacyOrganizationId(legacyOrganizationId)}`;
}

/** Mirrors the existing importer exactly: only numeric Legacy status 10 is active. */
export function legacySubjectLifecycleFromStatus(status: unknown): LegacySubjectLifecycleDecision {
  if (!Number.isSafeInteger(status)) {
    throw ruleError("invalid-input", "The Legacy subject status must be a safe integer.");
  }
  const legacyStatus = status as number;
  const active = legacyStatus === LEGACY_ACTIVE_SUBJECT_STATUS;
  return Object.freeze({
    legacyStatus,
    active,
    identityStatus: active ? "active" : "inactive"
  });
}

/** Strict system-admin plugin ID validation; no trimming, coercion, or namespace input. */
export function canonicalSystemAdminPluginId(pluginId: unknown): string {
  if (typeof pluginId !== "string") {
    throw ruleError("invalid-input", "The plugin ID must be a string.");
  }
  try {
    const pluginRef = pluginRefForId(pluginId);
    return pluginRef.slice("plugin:".length);
  } catch (error) {
    throw ruleError("invalid-input", error instanceof Error ? error.message : "The plugin ID is invalid.");
  }
}

/** Rejects invalid access scopes rather than applying a caller-controlled fallback. */
export function requireStrictPluginAccessScope(value: unknown): StrictPluginAccessScope {
  if (
    value !== "auth-only" &&
    value !== "manager-only" &&
    value !== "admin-only" &&
    value !== "root-only"
  ) {
    throw ruleError("invalid-input", "The plugin access scope is invalid.");
  }
  return value;
}

/**
 * Models the current plugin registry contract: SQL NULL alone is public. Empty,
 * padded, non-NFC, control-bearing, and overlength names fail closed.
 */
export function classifyStrictPluginOrganizationBinding(
  organizationName: unknown
): StrictPluginOrganizationBinding {
  if (organizationName === null) {
    return Object.freeze({
      kind: "public",
      organizationName: null,
      organizationRef: ORGANIZATION_RECONCILIATION_PUBLIC_CONTEXT_REF
    });
  }
  if (
    typeof organizationName !== "string" ||
    organizationName.length > 128
  ) {
    throw ruleError("invalid-input", "The plugin organization binding is invalid.");
  }
  try {
    return Object.freeze({
      kind: "organization-name",
      organizationName: canonicalReconciliationToken(
        organizationName,
        "plugin organization name"
      )
    });
  } catch (error) {
    throw ruleError(
      "invalid-input",
      error instanceof Error ? error.message : "The plugin organization binding is invalid."
    );
  }
}

/** Current host access-scope rule over the recognized platform role levels. */
export function pluginAccessScopeAllows(
  accessScope: unknown,
  candidateInput: unknown
): boolean {
  const scope = requireStrictPluginAccessScope(accessScope);
  let canonicalInput: OrganizationReconciliationEvidenceJsonValue;
  try {
    canonicalInput = canonicalizeOrganizationReconciliationEvidenceValue(candidateInput);
  } catch (error) {
    throw ruleError("invalid-input", error instanceof Error ? error.message : "The plugin access subject is invalid.");
  }
  requireExactKeys(canonicalInput, ["authenticated", "roles"], "plugin access subject");
  const input = canonicalInput as Record<string, OrganizationReconciliationEvidenceJsonValue>;
  if (typeof input.authenticated !== "boolean" || !Array.isArray(input.roles)) {
    throw ruleError("invalid-input", "The plugin access subject is invalid.");
  }
  if (!input.authenticated) return false;
  let highestLevel = 0;
  for (const role of input.roles) {
    if (typeof role !== "string") {
      throw ruleError("invalid-input", "A plugin access role is invalid.");
    }
    highestLevel = Math.max(highestLevel, platformRoleLevel(role));
  }
  return highestLevel >= STRICT_PLUGIN_ACCESS_SCOPE_LEVELS[scope];
}

/**
 * Computes Yii RBAC reachability only for a complete, rule-free graph. Named
 * rules, cycles, missing items, duplicate identities, and unknown assignments
 * are rejected instead of being approximated.
 */
export function calculateRuleFreeYiiRbacClosure(
  candidateGraph: unknown,
  candidateAssignments: unknown
): RuleFreeYiiRbacClosure {
  let canonicalGraph: OrganizationReconciliationEvidenceJsonValue;
  let canonicalAssignments: OrganizationReconciliationEvidenceJsonValue;
  try {
    canonicalGraph = canonicalizeOrganizationReconciliationEvidenceValue(candidateGraph);
    canonicalAssignments = canonicalizeOrganizationReconciliationEvidenceValue(candidateAssignments);
  } catch (error) {
    throw ruleError("invalid-input", error instanceof Error ? error.message : "The Yii RBAC input is invalid.");
  }
  requireExactKeys(canonicalGraph, ["rules", "items", "relations"], "Yii RBAC graph");
  const graph = canonicalGraph as Record<string, OrganizationReconciliationEvidenceJsonValue>;
  if (
    !Array.isArray(graph.rules) ||
    !Array.isArray(graph.items) ||
    !Array.isArray(graph.relations) ||
    !Array.isArray(canonicalAssignments)
  ) {
    throw ruleError("invalid-input", "The Yii RBAC graph and assignments must be arrays.");
  }
  if (graph.rules.length > 0) {
    throw ruleError("unsupported-yii-rule", "The Yii RBAC graph contains unsupported auth_rule rows.");
  }
  if (graph.items.length > 100_000 || graph.relations.length > 500_000 || canonicalAssignments.length > 100_000) {
    throw ruleError("invalid-input", "The Yii RBAC input exceeds the reviewed structural bound.");
  }

  const itemByName = new Map<string, RuleFreeYiiRbacItemInput>();
  for (const candidateItem of graph.items) {
    requireExactKeys(candidateItem, ["name", "type", "ruleName"], "Yii RBAC item");
    const item = candidateItem as Record<string, OrganizationReconciliationEvidenceJsonValue>;
    const name = requireRbacName(item.name, "Yii RBAC item name");
    if (item.type !== "role" && item.type !== "permission") {
      throw ruleError("invalid-input", "A Yii RBAC item type is invalid.");
    }
    if (item.ruleName !== null) {
      throw ruleError("unsupported-yii-rule", "Named Yii RBAC rules are not supported by the pure closure.");
    }
    if (itemByName.has(name)) {
      throw ruleError("duplicate-rbac-item", "The Yii RBAC graph contains a duplicate item.");
    }
    itemByName.set(name, Object.freeze({ name, type: item.type, ruleName: null }));
  }

  const childrenByParent = new Map<string, string[]>();
  const indegree = new Map<string, number>([...itemByName.keys()].map((name) => [name, 0]));
  const relationKeys = new Set<string>();
  for (const candidateRelation of graph.relations) {
    requireExactKeys(candidateRelation, ["parent", "child"], "Yii RBAC relation");
    const relation = candidateRelation as Record<string, OrganizationReconciliationEvidenceJsonValue>;
    const parent = requireRbacName(relation.parent, "Yii RBAC relation parent");
    const child = requireRbacName(relation.child, "Yii RBAC relation child");
    if (!itemByName.has(parent) || !itemByName.has(child)) {
      throw ruleError("missing-rbac-item", "A Yii RBAC relation references a missing item.");
    }
    const relationKey = `${parent}\u0000${child}`;
    if (relationKeys.has(relationKey)) {
      throw ruleError("duplicate-rbac-relation", "The Yii RBAC graph contains a duplicate relation.");
    }
    relationKeys.add(relationKey);
    const children = childrenByParent.get(parent) ?? [];
    children.push(child);
    childrenByParent.set(parent, children);
    indegree.set(child, (indegree.get(child) ?? 0) + 1);
  }
  assertAcyclic(itemByName, childrenByParent, indegree);

  const directAssignments: string[] = [];
  const assignmentSet = new Set<string>();
  for (const candidateAssignment of canonicalAssignments) {
    const assignment = requireRbacName(candidateAssignment, "Yii RBAC assignment");
    if (!itemByName.has(assignment)) {
      throw ruleError("missing-rbac-item", "A Yii RBAC assignment references a missing item.");
    }
    if (assignmentSet.has(assignment)) {
      throw ruleError("duplicate-rbac-assignment", "The Yii RBAC input contains a duplicate assignment.");
    }
    assignmentSet.add(assignment);
    directAssignments.push(assignment);
  }

  const visited = new Set<string>();
  const queue = [...directAssignments].sort();
  for (let offset = 0; offset < queue.length; offset += 1) {
    const current = queue[offset]!;
    if (visited.has(current)) continue;
    visited.add(current);
    const children = [...(childrenByParent.get(current) ?? [])].sort();
    for (const child of children) {
      if (!visited.has(child)) queue.push(child);
    }
  }
  const visitedItems = [...visited].sort();
  return Object.freeze({
    directAssignments: Object.freeze([...directAssignments].sort()),
    roles: Object.freeze(visitedItems.filter((name) => itemByName.get(name)!.type === "role")),
    permissions: Object.freeze(visitedItems.filter((name) => itemByName.get(name)!.type === "permission")),
    visitedItems: Object.freeze(visitedItems)
  });
}

function assertAcyclic(
  itemByName: ReadonlyMap<string, RuleFreeYiiRbacItemInput>,
  childrenByParent: ReadonlyMap<string, readonly string[]>,
  candidateIndegree: ReadonlyMap<string, number>
): void {
  const indegree = new Map(candidateIndegree);
  const queue = [...itemByName.keys()].filter((name) => indegree.get(name) === 0).sort();
  let visited = 0;
  for (let offset = 0; offset < queue.length; offset += 1) {
    const current = queue[offset]!;
    visited += 1;
    for (const child of childrenByParent.get(current) ?? []) {
      const next = (indegree.get(child) ?? 0) - 1;
      indegree.set(child, next);
      if (next === 0) queue.push(child);
    }
  }
  if (visited !== itemByName.size) {
    throw ruleError("rbac-cycle", "The Yii RBAC graph contains a cycle.");
  }
}

function platformRoleLevel(role: string): number {
  if (role === "root") return 4;
  if (role === "admin") return 3;
  if (role === "manager") return 2;
  if (role === "user") return 1;
  return 0;
}

function requireRbacName(
  value: OrganizationReconciliationEvidenceJsonValue,
  label: string
): string {
  if (typeof value !== "string") {
    throw ruleError("invalid-input", `The ${label} is invalid.`);
  }
  try {
    return canonicalReconciliationToken(value, label);
  } catch (error) {
    throw ruleError("invalid-input", error instanceof Error ? error.message : `The ${label} is invalid.`);
  }
}

function requireExactKeys(
  value: OrganizationReconciliationEvidenceJsonValue,
  expectedKeys: readonly string[],
  label: string
): void {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw ruleError("invalid-input", `The ${label} is invalid.`);
  }
  if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...expectedKeys].sort())) {
    throw ruleError("invalid-input", `The ${label} has missing or unknown fields.`);
  }
}

function ruleError(
  code: OrganizationReconciliationProvenRuleErrorCode,
  message: string
): OrganizationReconciliationProvenRuleError {
  return new OrganizationReconciliationProvenRuleError(code, message);
}
