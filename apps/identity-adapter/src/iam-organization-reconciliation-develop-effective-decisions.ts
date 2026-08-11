import {
  canonicalizeOrganizationReconciliationEvidenceValue,
  type OrganizationReconciliationEvidenceJsonValue
} from "./iam-organization-reconciliation-component-manifest.js";
import {
  ORGANIZATION_OWNER_DEVELOP_APPROVED_REGISTRY_CANDIDATE,
  ORGANIZATION_OWNER_DEVELOP_DECISION_CATALOGS
} from "./iam-organization-owner-semantic-registry.js";
import {
  assertIdentityDevelopProjectionSnapshotView,
  assertLegacyDevelopProjectionSnapshotView,
  type IdentityDevelopProjectionSnapshotView,
  type LegacyDevelopProjectionSnapshotView
} from "./iam-organization-reconciliation-develop-projection-views.js";
import {
  identityOrganizationIdForCanonicalLegacyId
} from "./iam-organization-reconciliation-pure-rules.js";
import {
  ORGANIZATION_RECONCILIATION_PLATFORM_GLOBAL_CONTEXT_REF,
  ORGANIZATION_RECONCILIATION_PUBLIC_CONTEXT_REF,
  canonicalLegacyOrganizationId,
  canonicalReconciliationToken,
  organizationRefForLegacyId,
  subjectRefForLegacyUserId
} from "./iam-organization-reconciliation-refs.js";
import {
  ORGANIZATION_RECONCILIATION_DEVELOP_IAM_POLICY_CHECKSUM
} from "./iam-organization-reconciliation/mysql-repeatable-read-snapshot.js";
import type { EffectiveOrganizationDecisionRecord } from
  "./iam-organization-reconciliation-validator.js";

export const ORGANIZATION_RECONCILIATION_DEVELOP_EFFECTIVE_DECISIONS_CONTRACT =
  "iam-organization-reconciliation-xrteeth-develop-effective-decisions/v2" as const;
export const ORGANIZATION_RECONCILIATION_DEVELOP_EFFECTIVE_DECISIONS_IMPLEMENTED = true as const;
/**
 * Deliberately false. Develop read-only context decisions are owner-authorized,
 * but no production effective-decision pipeline is registered.
 */
export const ORGANIZATION_RECONCILIATION_DEVELOP_EFFECTIVE_DECISIONS_READY = false as const;

export const ORGANIZATION_RECONCILIATION_DEVELOP_EFFECTIVE_DECISION_BLOCKERS = Object.freeze([
  "effective-decision-production-pipeline-not-registered"
] as const);

type EffectiveDecisionBlocker =
  (typeof ORGANIZATION_RECONCILIATION_DEVELOP_EFFECTIVE_DECISION_BLOCKERS)[number];
type ItemType = "role" | "permission";
type CapabilityDecisionRule =
  | "fixed-deny"
  | "verified-root-active-org"
  | "verified-root-or-active-member"
  | "plus-explicit-public-root"
  | "live-yii-rule-free-permission"
  | "verified-root-and-live-yii-permission";

interface ApprovedCapabilityEntry {
  readonly surface: "campus" | "legacy-organization-api" | "user-management";
  readonly capabilityRef: string;
  readonly resourceRef: string;
  readonly permissionItems: readonly string[];
  readonly globalRoles: readonly string[];
  readonly organizationRoles: readonly string[];
  readonly scopes: readonly ("organization" | "platform-global" | "public")[];
  readonly decisionRule: CapabilityDecisionRule;
}

interface SubjectState {
  readonly legacyUserId: string;
  readonly subjectRef: string;
  readonly active: boolean;
}

interface OrganizationState {
  readonly legacyOrganizationId: string;
  readonly organizationRef: string;
}

interface RuleFreeGraph {
  readonly itemTypes: ReadonlyMap<string, ItemType>;
  readonly effectiveItemsBySubject: ReadonlyMap<string, ReadonlySet<string>>;
}

interface IdentityMembershipState {
  readonly membershipKeys: ReadonlySet<string>;
  readonly identityUserIdBySubject: ReadonlyMap<string, string>;
}

export interface DevelopEffectiveDecisionProjection {
  readonly contract: typeof ORGANIZATION_RECONCILIATION_DEVELOP_EFFECTIVE_DECISIONS_CONTRACT;
  readonly side: "legacy" | "identity";
  readonly semanticRegistrySha256: string;
  readonly evaluator:
    | "legacy-live-yii-rule-free-graph"
    | "identity-exact-pinned-candidate-rule-free-graph";
  readonly sourceVersion: string;
  readonly snapshotId: string;
  readonly policyChecksum: "legacy-snapshot-bound" | typeof ORGANIZATION_RECONCILIATION_DEVELOP_IAM_POLICY_CHECKSUM;
  readonly effectiveDecisions: readonly EffectiveOrganizationDecisionRecord[];
  readonly blockers: readonly EffectiveDecisionBlocker[];
  readonly productionReady: false;
}

export class DevelopEffectiveDecisionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DevelopEffectiveDecisionError";
  }
}

/**
 * Builds the Legacy decision universe only from the Legacy repeatable-read
 * Yii RBAC item/edge/assignment graph. No Identity row or precomputed graph is
 * accepted or consulted.
 */
export function projectDevelopLegacyEffectiveDecisions(
  view: LegacyDevelopProjectionSnapshotView,
  semanticRegistrySha256: string
): DevelopEffectiveDecisionProjection {
  assertLegacyDevelopProjectionSnapshotView(view);
  requireApprovedRegistry(semanticRegistrySha256);
  const capabilities = readApprovedCapabilityCatalog();
  const approvedRoles = readApprovedRoleCatalog();
  const subjects = readLegacySubjects(view);
  const organizations = readLegacyOrganizations(view);
  const memberships = readLegacyMemberships(view, subjects, organizations);
  const graph = buildLegacyRuleFreeGraph(view, subjects, capabilities, approvedRoles);
  const rows: EffectiveOrganizationDecisionRecord[] = [];

  for (const subject of subjects.values()) {
    const effectiveItems = graph.effectiveItemsBySubject.get(subject.legacyUserId)!;
    for (const organization of organizations.values()) {
      const isMember = memberships.has(membershipKey(subject.legacyUserId, organization.legacyOrganizationId));
      for (const capability of capabilities) {
        rows.push(Object.freeze({
          subjectRef: subject.subjectRef,
          contextKind: "organization",
          contextRef: organization.organizationRef,
          resourceRef: capability.resourceRef,
          capabilityRef: capability.capabilityRef,
          decision: subject.active && evaluateCapability(
            capability,
            effectiveItems,
            isMember,
            "organization"
          ) ? "allow" : "deny"
        }));
      }
    }
    for (const capability of capabilities) {
      rows.push(
        Object.freeze({
          subjectRef: subject.subjectRef,
          contextKind: "platform-global" as const,
          contextRef: ORGANIZATION_RECONCILIATION_PLATFORM_GLOBAL_CONTEXT_REF,
          resourceRef: capability.resourceRef,
          capabilityRef: capability.capabilityRef,
          decision: subject.active && evaluateCapability(
            capability,
            effectiveItems,
            false,
            "platform-global"
          ) ? "allow" as const : "deny" as const
        }),
        Object.freeze({
          subjectRef: subject.subjectRef,
          contextKind: "public" as const,
          contextRef: ORGANIZATION_RECONCILIATION_PUBLIC_CONTEXT_REF,
          resourceRef: capability.resourceRef,
          capabilityRef: capability.capabilityRef,
          decision: subject.active && evaluateCapability(
            capability,
            effectiveItems,
            false,
            "public"
          ) ? "allow" as const : "deny" as const
        })
      );
    }
  }

  return canonicalResult({
    side: "legacy",
    semanticRegistrySha256,
    evaluator: "legacy-live-yii-rule-free-graph",
    sourceVersion: view.sourceVersion,
    snapshotId: view.snapshotId,
    policyChecksum: "legacy-snapshot-bound",
    effectiveDecisions: sortDecisionRows(rows)
  });
}

/**
 * Builds the Identity decision universe only from the exact pinned candidate
 * policy/version graph and its explicit subject-assignment snapshots. The
 * identity-role-shadow dataset is intentionally never read, so it cannot act
 * as a union, fill, or fallback authority.
 */
export function projectDevelopIdentityEffectiveDecisions(
  view: IdentityDevelopProjectionSnapshotView,
  semanticRegistrySha256: string
): DevelopEffectiveDecisionProjection {
  assertIdentityDevelopProjectionSnapshotView(view);
  requireApprovedRegistry(semanticRegistrySha256);
  const capabilities = readApprovedCapabilityCatalog();
  const approvedRoles = readApprovedRoleCatalog();
  const subjects = readIdentitySubjects(view);
  const organizations = readIdentityOrganizations(view);
  const identityUserIdBySubject = readIdentityAssignmentSnapshotUserIds(view, subjects);
  const graph = buildIdentityRuleFreeGraph(
    view,
    subjects,
    capabilities,
    approvedRoles,
    identityUserIdBySubject
  );
  const protectedRootIds = new Set(
    [...graph.effectiveItemsBySubject]
      .filter(([, effectiveItems]) => effectiveItems.has("root"))
      .map(([legacyUserId]) => legacyUserId)
  );
  const memberships = readIdentityMemberships(
    view,
    subjects,
    organizations,
    protectedRootIds,
    identityUserIdBySubject
  );
  const rows: EffectiveOrganizationDecisionRecord[] = [];

  for (const subject of subjects.values()) {
    const effectiveItems = graph.effectiveItemsBySubject.get(subject.legacyUserId)!;
    for (const organization of organizations.values()) {
      const isMember = memberships.membershipKeys.has(
        membershipKey(subject.legacyUserId, organization.legacyOrganizationId)
      );
      for (const capability of capabilities) {
        rows.push(Object.freeze({
          subjectRef: subject.subjectRef,
          contextKind: "organization",
          contextRef: organization.organizationRef,
          resourceRef: capability.resourceRef,
          capabilityRef: capability.capabilityRef,
          decision: subject.active && evaluateCapability(
            capability,
            effectiveItems,
            isMember,
            "organization"
          ) ? "allow" : "deny"
        }));
      }
    }
    for (const capability of capabilities) {
      rows.push(
        Object.freeze({
          subjectRef: subject.subjectRef,
          contextKind: "platform-global" as const,
          contextRef: ORGANIZATION_RECONCILIATION_PLATFORM_GLOBAL_CONTEXT_REF,
          resourceRef: capability.resourceRef,
          capabilityRef: capability.capabilityRef,
          decision: subject.active && evaluateCapability(
            capability,
            effectiveItems,
            false,
            "platform-global"
          ) ? "allow" as const : "deny" as const
        }),
        Object.freeze({
          subjectRef: subject.subjectRef,
          contextKind: "public" as const,
          contextRef: ORGANIZATION_RECONCILIATION_PUBLIC_CONTEXT_REF,
          resourceRef: capability.resourceRef,
          capabilityRef: capability.capabilityRef,
          decision: subject.active && evaluateCapability(
            capability,
            effectiveItems,
            false,
            "public"
          ) ? "allow" as const : "deny" as const
        })
      );
    }
  }

  return canonicalResult({
    side: "identity",
    semanticRegistrySha256,
    evaluator: "identity-exact-pinned-candidate-rule-free-graph",
    sourceVersion: view.sourceVersion,
    snapshotId: view.snapshotId,
    policyChecksum: ORGANIZATION_RECONCILIATION_DEVELOP_IAM_POLICY_CHECKSUM,
    effectiveDecisions: sortDecisionRows(rows)
  });
}

function buildLegacyRuleFreeGraph(
  view: LegacyDevelopProjectionSnapshotView,
  subjects: ReadonlyMap<string, SubjectState>,
  capabilities: readonly ApprovedCapabilityEntry[],
  approvedRoles: ReadonlySet<string>
): RuleFreeGraph {
  const items = new Map<string, ItemType>();
  const namedRuleItems = new Set<string>();
  for (const candidate of datasetRows(view, "legacy-rbac-item")) {
    const row = exactRecord(candidate, ["itemName", "itemType", "description", "ruleName"], "Legacy RBAC item");
    const itemName = canonicalText(row.itemName, "Legacy RBAC item name");
    const itemType = itemTypeValue(row.itemType, "Legacy RBAC item type");
    if (row.description !== null) canonicalText(row.description, "Legacy RBAC item description", 65_535);
    if (row.ruleName !== null) {
      canonicalText(row.ruleName, "Legacy Yii RBAC rule name", 64);
      namedRuleItems.add(itemName);
    }
    if (items.has(itemName)) fail("The Legacy Yii RBAC item graph contains a duplicate item.");
    items.set(itemName, itemType);
  }
  requireCatalogItems(items, capabilities, approvedRoles, "Legacy");

  const children = new Map<string, Set<string>>();
  const parents = new Map<string, Set<string>>();
  const edgeKeys = new Set<string>();
  for (const candidate of datasetRows(view, "legacy-rbac-edge")) {
    const row = exactRecord(candidate, ["parentName", "childName"], "Legacy RBAC edge");
    const parent = canonicalText(row.parentName, "Legacy RBAC edge parent");
    const child = canonicalText(row.childName, "Legacy RBAC edge child");
    const parentType = items.get(parent);
    const childType = items.get(child);
    if (!parentType || !childType) fail("A Legacy Yii RBAC edge references an unknown item.");
    if (parentType === "permission" && childType === "role") {
      fail("A Legacy Yii RBAC permission cannot contain a role.");
    }
    const key = graphEdgeKey(parent, child);
    if (edgeKeys.has(key)) fail("The Legacy Yii RBAC graph contains a duplicate edge.");
    edgeKeys.add(key);
    const values = children.get(parent) ?? new Set<string>();
    values.add(child);
    children.set(parent, values);
    const parentValues = parents.get(child) ?? new Set<string>();
    parentValues.add(parent);
    parents.set(child, parentValues);
  }
  assertAcyclic(items.keys(), children, "Legacy Yii RBAC");
  assertApprovedLegacyScopeHasNoNamedRules(
    namedRuleItems,
    parents,
    capabilities,
    approvedRoles
  );

  const assignmentsBySubject = new Map<string, Set<string>>();
  const assignmentKeys = new Set<string>();
  for (const candidate of datasetRows(view, "legacy-rbac-assignment")) {
    const row = exactRecord(candidate, ["legacyUserId", "itemName", "itemType"], "Legacy RBAC assignment");
    const legacyUserId = positiveId(row.legacyUserId, "Legacy RBAC assignment subject");
    if (!subjects.has(legacyUserId)) fail("A Legacy Yii RBAC assignment references an unknown subject.");
    const itemName = canonicalText(row.itemName, "Legacy RBAC assignment item");
    const itemType = itemTypeValue(row.itemType, "Legacy RBAC assignment item type");
    if (items.get(itemName) !== itemType) fail("A Legacy Yii RBAC assignment references an unknown or mistyped item.");
    const key = assignmentKey(legacyUserId, itemName);
    if (assignmentKeys.has(key)) fail("The Legacy Yii RBAC graph contains a duplicate assignment.");
    assignmentKeys.add(key);
    const values = assignmentsBySubject.get(legacyUserId) ?? new Set<string>();
    values.add(itemName);
    assignmentsBySubject.set(legacyUserId, values);
  }

  const effectiveItemsBySubject = new Map<string, ReadonlySet<string>>();
  for (const legacyUserId of subjects.keys()) {
    const effective = new Set<string>();
    const pending = [...(assignmentsBySubject.get(legacyUserId) ?? [])];
    while (pending.length > 0) {
      const item = pending.pop()!;
      if (effective.has(item)) continue;
      effective.add(item);
      for (const child of children.get(item) ?? []) pending.push(child);
    }
    effectiveItemsBySubject.set(legacyUserId, effective);
  }
  return Object.freeze({ itemTypes: items, effectiveItemsBySubject });
}

function assertApprovedLegacyScopeHasNoNamedRules(
  namedRuleItems: ReadonlySet<string>,
  parents: ReadonlyMap<string, ReadonlySet<string>>,
  capabilities: readonly ApprovedCapabilityEntry[],
  approvedRoles: ReadonlySet<string>
): void {
  const targets = new Set<string>(approvedRoles);
  for (const capability of capabilities) {
    for (const permission of capability.permissionItems) targets.add(permission);
  }
  const visited = new Set<string>();
  const pending = [...targets];
  while (pending.length > 0) {
    const item = pending.pop()!;
    if (visited.has(item)) continue;
    visited.add(item);
    if (namedRuleItems.has(item)) {
      fail("A named Legacy Yii RBAC rule intersects the owner-approved capability scope.");
    }
    for (const parent of parents.get(item) ?? []) pending.push(parent);
  }
}

function buildIdentityRuleFreeGraph(
  view: IdentityDevelopProjectionSnapshotView,
  subjects: ReadonlyMap<string, SubjectState>,
  capabilities: readonly ApprovedCapabilityEntry[],
  approvedRoles: ReadonlySet<string>,
  identityUserIdBySubject: ReadonlyMap<string, string>
): RuleFreeGraph {
  const policyRows = datasetRows(view, "identity-iam-policy-version");
  if (policyRows.length !== 1) fail("The exact Identity IAM policy version is missing or duplicate.");
  const policy = exactRecord(policyRows[0], [
    "policyChecksum", "source", "status", "roleCount", "permissionCount", "relationCount"
  ], "Identity IAM policy version");
  requirePinnedPolicyRow(policy, "Identity IAM policy version");
  const expectedRoleCount = nonNegativeInteger(policy.roleCount, "Identity IAM role count");
  const expectedPermissionCount = nonNegativeInteger(policy.permissionCount, "Identity IAM permission count");
  const expectedRelationCount = nonNegativeInteger(policy.relationCount, "Identity IAM relation count");

  const items = new Map<string, ItemType>();
  const roleRows = datasetRows(view, "identity-iam-role");
  for (const candidate of roleRows) {
    const row = exactRecord(candidate, ["policyChecksum", "itemName", "description", "source", "status"], "Identity IAM role");
    requirePinnedPolicyRow(row, "Identity IAM role");
    const itemName = canonicalText(row.itemName, "Identity IAM role name");
    if (row.description !== null) canonicalText(row.description, "Identity IAM role description", 65_535);
    if (items.has(itemName)) fail("The Identity IAM policy contains a duplicate or cross-typed item.");
    items.set(itemName, "role");
  }
  const permissionRows = datasetRows(view, "identity-iam-permission");
  for (const candidate of permissionRows) {
    const row = exactRecord(candidate, ["policyChecksum", "itemName", "description", "source", "status"], "Identity IAM permission");
    requirePinnedPolicyRow(row, "Identity IAM permission");
    const itemName = canonicalText(row.itemName, "Identity IAM permission name");
    if (row.description !== null) canonicalText(row.description, "Identity IAM permission description", 65_535);
    if (items.has(itemName)) fail("The Identity IAM policy contains a duplicate or cross-typed item.");
    items.set(itemName, "permission");
  }
  if (roleRows.length !== expectedRoleCount || permissionRows.length !== expectedPermissionCount) {
    fail("The Identity IAM policy role or permission count does not match its pinned version.");
  }
  requireCatalogItems(items, capabilities, approvedRoles, "Identity");

  const children = new Map<string, Set<string>>();
  const relationRows = datasetRows(view, "identity-iam-item-relation");
  const relationKeys = new Set<string>();
  for (const candidate of relationRows) {
    const row = exactRecord(candidate, [
      "policyChecksum", "parentName", "parentType", "childName", "childType", "source", "status"
    ], "Identity IAM relation");
    requirePinnedPolicyRow(row, "Identity IAM relation");
    const parent = canonicalText(row.parentName, "Identity IAM relation parent");
    const child = canonicalText(row.childName, "Identity IAM relation child");
    const parentType = itemTypeValue(row.parentType, "Identity IAM relation parent type");
    const childType = itemTypeValue(row.childType, "Identity IAM relation child type");
    if (items.get(parent) !== parentType || items.get(child) !== childType) {
      fail("An Identity IAM relation references an unknown or mistyped item.");
    }
    if (parentType === "permission" && childType === "role") {
      fail("An Identity IAM permission cannot contain a role.");
    }
    const key = graphEdgeKey(parent, child);
    if (relationKeys.has(key)) fail("The Identity IAM policy contains a duplicate relation.");
    relationKeys.add(key);
    const values = children.get(parent) ?? new Set<string>();
    values.add(child);
    children.set(parent, values);
  }
  if (relationRows.length !== expectedRelationCount) {
    fail("The Identity IAM policy relation count does not match its pinned version.");
  }
  assertAcyclic(items.keys(), children, "Identity IAM");

  const snapshotsBySubject = new Map<string, Readonly<{ identityUserId: string; assignmentCount: number }>>();
  const identityUserIds = new Set<string>();
  for (const candidate of datasetRows(view, "identity-iam-subject-assignment-snapshot")) {
    const row = exactRecord(candidate, [
      "identityUserId", "legacyUserId", "policyChecksum", "snapshotKey", "assignmentCount", "source", "status"
    ], "Identity IAM assignment snapshot");
    requirePinnedPolicyRow(row, "Identity IAM assignment snapshot");
    if (row.snapshotKey !== ORGANIZATION_RECONCILIATION_DEVELOP_IAM_POLICY_CHECKSUM) {
      fail("The Identity IAM assignment snapshot is not bound to the exact policy checksum.");
    }
    const identityUserId = canonicalText(row.identityUserId, "Identity IAM assignment snapshot identity user ID");
    const legacyUserId = positiveId(row.legacyUserId, "Identity IAM assignment snapshot subject");
    if (!subjects.has(legacyUserId)) fail("An Identity IAM assignment snapshot references an unknown subject.");
    if (identityUserIdBySubject.get(legacyUserId) !== identityUserId) {
      fail("An Identity IAM assignment snapshot conflicts with the exact candidate subject identity.");
    }
    if (snapshotsBySubject.has(legacyUserId) || identityUserIds.has(identityUserId)) {
      fail("The Identity IAM assignment snapshot contains a duplicate subject identity.");
    }
    identityUserIds.add(identityUserId);
    snapshotsBySubject.set(legacyUserId, Object.freeze({
      identityUserId,
      assignmentCount: nonNegativeInteger(row.assignmentCount, "Identity IAM assignment snapshot count")
    }));
  }
  if (snapshotsBySubject.size !== subjects.size) {
    fail("The Identity IAM assignment snapshot universe is incomplete; explicit zero rows are required.");
  }

  const assignmentsBySubject = new Map<string, Set<string>>();
  const assignmentKeys = new Set<string>();
  for (const candidate of datasetRows(view, "identity-iam-subject-assignment")) {
    const row = exactRecord(candidate, [
      "identityUserId", "legacyUserId", "itemName", "itemType", "policyChecksum", "source", "status"
    ], "Identity IAM subject assignment");
    requirePinnedPolicyRow(row, "Identity IAM subject assignment");
    const legacyUserId = positiveId(row.legacyUserId, "Identity IAM assignment subject");
    const snapshot = snapshotsBySubject.get(legacyUserId);
    if (!snapshot) fail("An Identity IAM assignment references a subject outside the explicit snapshot universe.");
    const identityUserId = canonicalText(row.identityUserId, "Identity IAM assignment identity user ID");
    if (identityUserId !== snapshot.identityUserId) {
      fail("An Identity IAM assignment conflicts with the exact candidate subject identity.");
    }
    const itemName = canonicalText(row.itemName, "Identity IAM assignment item");
    const itemType = itemTypeValue(row.itemType, "Identity IAM assignment item type");
    if (items.get(itemName) !== itemType) {
      fail("An Identity IAM assignment references an unknown or mistyped item.");
    }
    const key = assignmentKey(legacyUserId, itemName);
    if (assignmentKeys.has(key)) fail("The Identity IAM policy contains a duplicate subject assignment.");
    assignmentKeys.add(key);
    const values = assignmentsBySubject.get(legacyUserId) ?? new Set<string>();
    values.add(itemName);
    assignmentsBySubject.set(legacyUserId, values);
  }
  for (const [legacyUserId, snapshot] of snapshotsBySubject) {
    if ((assignmentsBySubject.get(legacyUserId)?.size ?? 0) !== snapshot.assignmentCount) {
      fail("The Identity IAM subject assignment count does not match its explicit snapshot.");
    }
  }

  const effectiveItemsBySubject = new Map<string, ReadonlySet<string>>();
  for (const legacyUserId of subjects.keys()) {
    const effective = new Set<string>();
    const pending = [...(assignmentsBySubject.get(legacyUserId) ?? [])];
    while (pending.length > 0) {
      const item = pending.pop()!;
      if (effective.has(item)) continue;
      effective.add(item);
      for (const child of children.get(item) ?? []) pending.push(child);
    }
    effectiveItemsBySubject.set(legacyUserId, effective);
  }
  return Object.freeze({ itemTypes: items, effectiveItemsBySubject });
}

function readLegacySubjects(
  view: LegacyDevelopProjectionSnapshotView
): ReadonlyMap<string, SubjectState> {
  const subjects = new Map<string, SubjectState>();
  for (const candidate of datasetRows(view, "legacy-subject-universe")) {
    const row = exactRecord(candidate, ["legacyUserId", "status"], "Legacy subject");
    const legacyUserId = positiveId(row.legacyUserId, "Legacy subject ID");
    const status = nonNegativeInteger(row.status, "Legacy subject status");
    if (subjects.has(legacyUserId)) fail("The Legacy subject universe contains a duplicate subject.");
    subjects.set(legacyUserId, Object.freeze({
      legacyUserId,
      subjectRef: subjectRefForLegacyUserId(legacyUserId),
      active: status === 10
    }));
  }
  if (subjects.size === 0) fail("The Legacy subject universe is empty.");
  return subjects;
}

function readIdentitySubjects(
  view: IdentityDevelopProjectionSnapshotView
): ReadonlyMap<string, SubjectState> {
  const subjects = new Map<string, SubjectState>();
  for (const candidate of datasetRows(view, "identity-subject-universe")) {
    const row = exactRecord(candidate, ["legacyUserId", "status", "source"], "Identity subject");
    if (row.source !== "legacy-shadow" || (row.status !== "active" && row.status !== "inactive")) {
      fail("An Identity subject is outside the exact approved selector.");
    }
    const legacyUserId = positiveId(row.legacyUserId, "Identity subject ID");
    if (subjects.has(legacyUserId)) fail("The Identity subject universe contains a duplicate subject.");
    subjects.set(legacyUserId, Object.freeze({
      legacyUserId,
      subjectRef: subjectRefForLegacyUserId(legacyUserId),
      active: row.status === "active"
    }));
  }
  if (subjects.size === 0) fail("The Identity subject universe is empty.");
  return subjects;
}

function readLegacyOrganizations(
  view: LegacyDevelopProjectionSnapshotView
): ReadonlyMap<string, OrganizationState> {
  const organizations = new Map<string, OrganizationState>();
  for (const candidate of datasetRows(view, "legacy-organization-directory")) {
    const row = exactRecord(candidate, [
      "legacyOrganizationId", "name", "title", "createdAt", "updatedAt"
    ], "Legacy organization");
    const legacyOrganizationId = positiveId(row.legacyOrganizationId, "Legacy organization ID");
    canonicalText(row.name, "Legacy organization name", 64);
    canonicalText(row.title, "Legacy organization title", 255);
    nonNegativeInteger(row.createdAt, "Legacy organization created timestamp");
    nonNegativeInteger(row.updatedAt, "Legacy organization updated timestamp");
    if (organizations.has(legacyOrganizationId)) fail("The Legacy organization directory contains a duplicate ID.");
    organizations.set(legacyOrganizationId, Object.freeze({
      legacyOrganizationId,
      organizationRef: organizationRefForLegacyId(legacyOrganizationId)
    }));
  }
  if (organizations.size === 0) fail("The Legacy organization directory is empty.");
  return organizations;
}

function readIdentityOrganizations(
  view: IdentityDevelopProjectionSnapshotView
): ReadonlyMap<string, OrganizationState> {
  const mappings = new Map<string, string>();
  const identityIds = new Set<string>();
  for (const candidate of datasetRows(view, "identity-organization-id-map")) {
    const row = exactRecord(candidate, [
      "legacyOrganizationId", "identityOrganizationId", "source", "mappingStatus"
    ], "Identity organization mapping");
    if (row.source !== "legacy" || row.mappingStatus !== "active") {
      fail("An Identity organization mapping is outside the exact approved selector.");
    }
    const legacyOrganizationId = positiveId(row.legacyOrganizationId, "Identity organization mapping Legacy ID");
    const identityOrganizationId = canonicalText(row.identityOrganizationId, "Identity organization mapping ID");
    if (identityOrganizationId !== identityOrganizationIdForCanonicalLegacyId(legacyOrganizationId)) {
      fail("An Identity organization mapping violates the deterministic Legacy mapping contract.");
    }
    if (mappings.has(legacyOrganizationId) || identityIds.has(identityOrganizationId)) {
      fail("The Identity organization mapping contains a duplicate ID.");
    }
    mappings.set(legacyOrganizationId, identityOrganizationId);
    identityIds.add(identityOrganizationId);
  }

  const organizations = new Map<string, OrganizationState>();
  for (const candidate of datasetRows(view, "identity-organization-candidate")) {
    const row = exactRecord(candidate, [
      "legacyOrganizationId", "identityOrganizationId", "name", "title", "source", "candidateStatus"
    ], "Identity organization candidate");
    if (row.source !== "legacy" || row.candidateStatus !== "candidate") {
      fail("An Identity organization is outside the exact approved candidate selector.");
    }
    const legacyOrganizationId = positiveId(row.legacyOrganizationId, "Identity organization Legacy ID");
    const identityOrganizationId = canonicalText(row.identityOrganizationId, "Identity organization ID");
    canonicalText(row.name, "Identity organization name", 64);
    canonicalText(row.title, "Identity organization title", 255);
    if (mappings.get(legacyOrganizationId) !== identityOrganizationId) {
      fail("An Identity organization candidate is missing its exact active mapping.");
    }
    if (organizations.has(legacyOrganizationId)) fail("The Identity organization candidates contain a duplicate ID.");
    organizations.set(legacyOrganizationId, Object.freeze({
      legacyOrganizationId,
      organizationRef: organizationRefForLegacyId(legacyOrganizationId)
    }));
  }
  if (organizations.size === 0 || organizations.size !== mappings.size) {
    fail("The Identity organization candidate and mapping universes are incomplete.");
  }
  return organizations;
}

function readLegacyMemberships(
  view: LegacyDevelopProjectionSnapshotView,
  subjects: ReadonlyMap<string, SubjectState>,
  organizations: ReadonlyMap<string, OrganizationState>
): ReadonlySet<string> {
  const memberships = new Set<string>();
  for (const candidate of datasetRows(view, "legacy-membership")) {
    const row = exactRecord(candidate, ["legacyUserId", "legacyOrganizationId"], "Legacy membership");
    const legacyUserId = positiveId(row.legacyUserId, "Legacy membership subject");
    const legacyOrganizationId = positiveId(row.legacyOrganizationId, "Legacy membership organization");
    if (!subjects.has(legacyUserId) || !organizations.has(legacyOrganizationId)) {
      fail("A Legacy membership references an unknown subject or organization.");
    }
    const key = membershipKey(legacyUserId, legacyOrganizationId);
    if (memberships.has(key)) fail("The Legacy membership dataset contains a duplicate row.");
    memberships.add(key);
  }
  return memberships;
}

function readIdentityAssignmentSnapshotUserIds(
  view: IdentityDevelopProjectionSnapshotView,
  subjects: ReadonlyMap<string, SubjectState>
): ReadonlyMap<string, string> {
  const identityUserIdBySubject = new Map<string, string>();
  const identityUserIds = new Set<string>();
  for (const candidate of datasetRows(view, "identity-iam-subject-assignment-snapshot")) {
    const row = exactRecord(candidate, [
      "identityUserId", "legacyUserId", "policyChecksum", "snapshotKey", "assignmentCount", "source", "status"
    ], "Identity IAM assignment snapshot identity");
    requirePinnedPolicyRow(row, "Identity IAM assignment snapshot identity");
    if (row.snapshotKey !== ORGANIZATION_RECONCILIATION_DEVELOP_IAM_POLICY_CHECKSUM) {
      fail("The Identity IAM assignment snapshot identity is not bound to the exact policy checksum.");
    }
    const legacyUserId = positiveId(row.legacyUserId, "Identity IAM assignment snapshot identity subject");
    const identityUserId = canonicalText(
      row.identityUserId,
      "Identity IAM assignment snapshot identity user ID"
    );
    if (!subjects.has(legacyUserId)) {
      fail("An Identity IAM assignment snapshot identity references an unknown subject.");
    }
    if (identityUserIdBySubject.has(legacyUserId) || identityUserIds.has(identityUserId)) {
      fail("The Identity IAM assignment snapshot identity contains a duplicate subject identity.");
    }
    nonNegativeInteger(row.assignmentCount, "Identity IAM assignment snapshot identity count");
    identityUserIds.add(identityUserId);
    identityUserIdBySubject.set(legacyUserId, identityUserId);
  }
  if (identityUserIdBySubject.size !== subjects.size) {
    fail("The Identity IAM assignment snapshot identity universe is incomplete; explicit zero rows are required.");
  }
  return identityUserIdBySubject;
}

function readIdentityMemberships(
  view: IdentityDevelopProjectionSnapshotView,
  subjects: ReadonlyMap<string, SubjectState>,
  organizations: ReadonlyMap<string, OrganizationState>,
  protectedRootIds: ReadonlySet<string>,
  identityUserIdBySubject: ReadonlyMap<string, string>
): IdentityMembershipState {
  const snapshots = new Map<string, Readonly<{
    identityUserId: string;
    operationKey: string;
    organizationCount: number;
  }>>();
  const identityUserIds = new Set<string>();
  for (const candidate of datasetRows(view, "identity-membership-candidate-snapshot")) {
    const row = exactRecord(candidate, [
      "identityUserId", "legacyUserId", "operationKey", "organizationCount", "source", "candidateStatus"
    ], "Identity membership snapshot");
    if (row.source !== "legacy" || row.candidateStatus !== "candidate") {
      fail("An Identity membership snapshot is outside the exact approved selector.");
    }
    const legacyUserId = positiveId(row.legacyUserId, "Identity membership snapshot subject");
    const identityUserId = canonicalText(row.identityUserId, "Identity membership snapshot identity user ID");
    if (!subjects.has(legacyUserId)) fail("An Identity membership snapshot references an unknown subject.");
    if (snapshots.has(legacyUserId) || identityUserIds.has(identityUserId)) {
      fail("The Identity membership snapshot contains a duplicate subject identity.");
    }
    identityUserIds.add(identityUserId);
    snapshots.set(legacyUserId, Object.freeze({
      identityUserId,
      operationKey: canonicalText(row.operationKey, "Identity membership snapshot operation key"),
      organizationCount: nonNegativeInteger(row.organizationCount, "Identity membership snapshot count")
    }));
  }
  const expectedSnapshotIds = new Set(
    [...subjects.keys()].filter((legacyUserId) => !protectedRootIds.has(legacyUserId))
  );
  if (
    snapshots.size !== expectedSnapshotIds.size ||
    [...snapshots.keys()].some((legacyUserId) => !expectedSnapshotIds.has(legacyUserId))
  ) {
    fail("The Identity membership snapshot universe is incomplete; explicit zero rows are required.");
  }
  for (const [legacyUserId, snapshot] of snapshots) {
    if (identityUserIdBySubject.get(legacyUserId) !== snapshot.identityUserId) {
      fail("An Identity membership snapshot conflicts with the exact candidate subject identity.");
    }
  }

  const memberships = new Set<string>();
  const countBySubject = new Map<string, number>();
  for (const candidate of datasetRows(view, "identity-membership-candidate")) {
    const row = exactRecord(candidate, [
      "legacyUserId", "legacyOrganizationId", "identityUserId", "identityOrganizationId",
      "organizationRole", "source", "candidateStatus", "operationKey"
    ], "Identity membership candidate");
    if (row.organizationRole !== "member" || row.source !== "legacy" || row.candidateStatus !== "candidate") {
      fail("An Identity membership is outside the exact approved candidate selector.");
    }
    const legacyUserId = positiveId(row.legacyUserId, "Identity membership subject");
    const legacyOrganizationId = positiveId(row.legacyOrganizationId, "Identity membership organization");
    const snapshot = snapshots.get(legacyUserId);
    if (!snapshot || !organizations.has(legacyOrganizationId)) {
      fail("An Identity membership references an unknown subject or organization.");
    }
    if (
      row.identityUserId !== snapshot.identityUserId ||
      row.operationKey !== snapshot.operationKey ||
      row.identityOrganizationId !== identityOrganizationIdForCanonicalLegacyId(legacyOrganizationId)
    ) {
      fail("An Identity membership conflicts with its exact candidate snapshot or mapping.");
    }
    const key = membershipKey(legacyUserId, legacyOrganizationId);
    if (memberships.has(key)) fail("The Identity membership candidate contains a duplicate row.");
    memberships.add(key);
    countBySubject.set(legacyUserId, (countBySubject.get(legacyUserId) ?? 0) + 1);
  }
  for (const [legacyUserId, snapshot] of snapshots) {
    if ((countBySubject.get(legacyUserId) ?? 0) !== snapshot.organizationCount) {
      fail("The Identity membership count does not match its explicit snapshot.");
    }
  }
  if ([...protectedRootIds].some((legacyUserId) => countBySubject.has(legacyUserId))) {
    fail("A protected Identity root cannot enter the membership candidate surface.");
  }
  return Object.freeze({
    membershipKeys: memberships,
    identityUserIdBySubject: new Map(
      [...snapshots].map(([legacyUserId, snapshot]) => [legacyUserId, snapshot.identityUserId])
    )
  });
}

function evaluateCapability(
  capability: ApprovedCapabilityEntry,
  effectiveItems: ReadonlySet<string>,
  isMember: boolean,
  contextKind: "organization" | "platform-global" | "public"
): boolean {
  if (!capability.scopes.includes(contextKind)) return false;
  const hasVerifiedRoot = capability.globalRoles.some((role) => effectiveItems.has(role));
  const hasLivePermission = capability.permissionItems.length > 0 &&
    capability.permissionItems.every((permission) => effectiveItems.has(permission));

  switch (contextKind) {
    case "organization":
      switch (capability.decisionRule) {
        case "verified-root-active-org": return hasVerifiedRoot;
        case "verified-root-or-active-member":
        case "plus-explicit-public-root":
          return hasVerifiedRoot ||
            (isMember && capability.organizationRoles.some((role) => effectiveItems.has(role)));
        default: return false;
      }
    case "platform-global":
      if (capability.surface === "legacy-organization-api" &&
        capability.decisionRule === "live-yii-rule-free-permission") {
        return hasLivePermission;
      }
      if (capability.surface === "user-management" &&
        capability.decisionRule === "verified-root-and-live-yii-permission") {
        return hasVerifiedRoot && hasLivePermission;
      }
      return false;
    case "public":
      return capability.surface === "campus" &&
        capability.decisionRule === "plus-explicit-public-root" &&
        (capability.capabilityRef === "manage-student-accounts" ||
          capability.capabilityRef === "view-students") &&
        hasVerifiedRoot;
  }
}

function readApprovedCapabilityCatalog(): readonly ApprovedCapabilityEntry[] {
  if (ORGANIZATION_OWNER_DEVELOP_DECISION_CATALOGS.campusPublicContext.executionState !==
    "owner-bound-campus-context-decision-execution") {
    fail("The approved Develop campus context-decision execution is not authorized.");
  }
  const catalog = ORGANIZATION_OWNER_DEVELOP_DECISION_CATALOGS.capabilityCatalog as unknown;
  if (catalog === null || typeof catalog !== "object" || !Array.isArray((catalog as { entries?: unknown }).entries)) {
    fail("The approved Develop capability catalog has no exact entry registry.");
  }
  if (
    (catalog as { executionState?: unknown }).executionState !==
      "owner-bound-context-decision-execution"
  ) {
    fail("The approved Develop capability context-decision execution is not authorized.");
  }
  const entries: ApprovedCapabilityEntry[] = [];
  const keys = new Set<string>();
  for (const candidate of (catalog as { entries: readonly unknown[] }).entries) {
    if (candidate === null || typeof candidate !== "object" || Array.isArray(candidate)) {
      fail("The approved Develop capability catalog contains an invalid entry.");
    }
    const row = candidate as Record<string, unknown>;
    const surface = row.surface;
    if (surface !== "campus" && surface !== "legacy-organization-api" && surface !== "user-management") {
      fail("The approved Develop capability catalog contains an unknown surface.");
    }
    const capabilityRef = canonicalText(row.capabilityId, "approved capability ID");
    const resourceRef = canonicalText(row.resourceId, "approved capability resource ID");
    const permissionItems = canonicalStringArray(row.permissionItems, "approved capability permission item");
    const roles = row.roles;
    if (roles === null || typeof roles !== "object" || Array.isArray(roles)) {
      fail("The approved Develop capability catalog contains invalid roles.");
    }
    const globalRoles = canonicalStringArray((roles as Record<string, unknown>).global, "approved global role");
    const organizationRoles = canonicalStringArray(
      (roles as Record<string, unknown>).organization,
      "approved organization role"
    );
    const scopes = scopeArray(row.scope);
    const decisionRule = capabilityDecisionRule(row.decisionRule);
    const key = `${resourceRef}\u0000${capabilityRef}`;
    if (keys.has(key)) fail("The approved Develop capability catalog contains a duplicate decision key.");
    keys.add(key);
    entries.push(Object.freeze({
      surface,
      capabilityRef,
      resourceRef,
      permissionItems,
      globalRoles,
      organizationRoles,
      scopes,
      decisionRule
    }));
  }
  if (entries.length !== 20) fail("The approved Develop capability catalog must contain exactly 20 entries.");
  return Object.freeze(entries);
}

function requireCatalogItems(
  items: ReadonlyMap<string, ItemType>,
  capabilities: readonly ApprovedCapabilityEntry[],
  approvedRoles: ReadonlySet<string>,
  side: "Legacy" | "Identity"
): void {
  for (const [itemName, itemType] of items) {
    if (itemType === "role" && !approvedRoles.has(itemName)) {
      fail(`The ${side} rule-free graph contains an unknown owner-scoped role.`);
    }
  }
  for (const role of approvedRoles) {
    if (items.get(role) !== "role") fail(`The ${side} rule-free graph is missing an owner-approved role.`);
  }
  for (const capability of capabilities) {
    for (const role of [...capability.globalRoles, ...capability.organizationRoles]) {
      if (items.get(role) !== "role") fail(`The ${side} rule-free graph is missing an owner-approved role.`);
    }
    for (const permission of capability.permissionItems) {
      if (items.get(permission) !== "permission") {
        fail(`The ${side} rule-free graph is missing an owner-approved permission.`);
      }
    }
  }
}

function readApprovedRoleCatalog(): ReadonlySet<string> {
  const catalog = ORGANIZATION_OWNER_DEVELOP_DECISION_CATALOGS.roleScopes as unknown;
  if (catalog === null || typeof catalog !== "object" || Array.isArray(catalog)) {
    fail("The approved Develop organization-role scope catalog is invalid.");
  }
  const record = catalog as Record<string, unknown>;
  const roles = [
    ...canonicalStringArray(record.globalOnly, "approved global-only role"),
    ...canonicalStringArray(record.memberOrganization, "approved member-organization role")
  ];
  if (roles.length !== 4 || new Set(roles).size !== roles.length) {
    fail("The approved Develop organization-role scope catalog must contain four distinct roles.");
  }
  return new Set(roles);
}

function assertAcyclic(
  itemNames: Iterable<string>,
  children: ReadonlyMap<string, ReadonlySet<string>>,
  label: string
): void {
  const names = [...itemNames];
  const inDegree = new Map(names.map((item) => [item, 0]));
  for (const values of children.values()) {
    for (const child of values) inDegree.set(child, (inDegree.get(child) ?? 0) + 1);
  }
  const ready = names.filter((item) => inDegree.get(item) === 0);
  let visitedCount = 0;
  while (ready.length > 0) {
    const item = ready.pop()!;
    visitedCount += 1;
    for (const child of children.get(item) ?? []) {
      const remaining = inDegree.get(child)! - 1;
      inDegree.set(child, remaining);
      if (remaining === 0) ready.push(child);
    }
  }
  if (visitedCount !== names.length) fail(`The ${label} graph contains a cycle.`);
}

function canonicalResult(input: Readonly<{
  side: "legacy" | "identity";
  semanticRegistrySha256: string;
  evaluator: DevelopEffectiveDecisionProjection["evaluator"];
  sourceVersion: string;
  snapshotId: string;
  policyChecksum: DevelopEffectiveDecisionProjection["policyChecksum"];
  effectiveDecisions: readonly EffectiveOrganizationDecisionRecord[];
}>): DevelopEffectiveDecisionProjection {
  return canonicalizeOrganizationReconciliationEvidenceValue({
    contract: ORGANIZATION_RECONCILIATION_DEVELOP_EFFECTIVE_DECISIONS_CONTRACT,
    ...input,
    blockers: ORGANIZATION_RECONCILIATION_DEVELOP_EFFECTIVE_DECISION_BLOCKERS,
    productionReady: ORGANIZATION_RECONCILIATION_DEVELOP_EFFECTIVE_DECISIONS_READY
  }) as unknown as DevelopEffectiveDecisionProjection;
}

function sortDecisionRows(
  rows: readonly EffectiveOrganizationDecisionRecord[]
): readonly EffectiveOrganizationDecisionRecord[] {
  return [...rows].sort((left, right) => {
    const a = decisionKey(left);
    const b = decisionKey(right);
    return a < b ? -1 : a > b ? 1 : 0;
  });
}

function decisionKey(row: EffectiveOrganizationDecisionRecord): string {
  return [
    row.subjectRef,
    row.contextKind,
    row.contextRef,
    row.resourceRef,
    row.capabilityRef
  ].join("\u0000");
}

function requireApprovedRegistry(value: string): void {
  if (value !== ORGANIZATION_OWNER_DEVELOP_APPROVED_REGISTRY_CANDIDATE.registrySha256) {
    fail("The effective-decision evaluator is not bound to the approved Develop semantic registry candidate.");
  }
}

function requirePinnedPolicyRow(row: Readonly<Record<string, unknown>>, label: string): void {
  if (
    row.policyChecksum !== ORGANIZATION_RECONCILIATION_DEVELOP_IAM_POLICY_CHECKSUM ||
    row.source !== "legacy-import-candidate" ||
    row.status !== "candidate"
  ) {
    fail(`The ${label} is outside the exact pinned Identity IAM candidate policy.`);
  }
}

function datasetRows(
  view: LegacyDevelopProjectionSnapshotView | IdentityDevelopProjectionSnapshotView,
  datasetId: string
): readonly OrganizationReconciliationEvidenceJsonValue[] {
  const rows = view.datasets[datasetId];
  if (!Array.isArray(rows)) fail(`The compiled effective-decision dataset ${datasetId} is missing.`);
  return rows;
}

function exactRecord(
  candidate: unknown,
  expectedKeys: readonly string[],
  label: string
): Readonly<Record<string, unknown>> {
  if (candidate === null || typeof candidate !== "object" || Array.isArray(candidate)) {
    fail(`The ${label} row is invalid.`);
  }
  const keys = Object.keys(candidate).sort();
  const expected = [...expectedKeys].sort();
  if (JSON.stringify(keys) !== JSON.stringify(expected)) fail(`The ${label} row has an invalid shape.`);
  return candidate as Readonly<Record<string, unknown>>;
}

function positiveId(value: unknown, label: string): string {
  try {
    if (typeof value !== "string" && typeof value !== "number") throw new Error("invalid");
    return canonicalLegacyOrganizationId(value);
  } catch {
    fail(`The ${label} is not a canonical positive ID.`);
  }
}

function nonNegativeInteger(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    fail(`The ${label} is not a non-negative safe integer.`);
  }
  return value;
}

function canonicalText(value: unknown, label: string, maxLength = 256): string {
  if (typeof value !== "string" || value.length > maxLength) fail(`The ${label} is not canonical.`);
  try {
    return canonicalReconciliationToken(value, label);
  } catch {
    fail(`The ${label} is not canonical.`);
  }
}

function itemTypeValue(value: unknown, label: string): ItemType {
  if (value !== "role" && value !== "permission") fail(`The ${label} is unknown.`);
  return value;
}

function canonicalStringArray(value: unknown, label: string): readonly string[] {
  if (!Array.isArray(value)) fail(`The ${label} catalog is invalid.`);
  const result = value.map((entry) => canonicalText(entry, label));
  if (new Set(result).size !== result.length) fail(`The ${label} catalog contains a duplicate.`);
  return Object.freeze(result);
}

function scopeArray(value: unknown): readonly ("organization" | "platform-global" | "public")[] {
  if (!Array.isArray(value)) fail("The approved capability scope catalog is invalid.");
  const result = value.map((scope) => {
    if (scope !== "organization" && scope !== "platform-global" && scope !== "public") {
      fail("The approved capability catalog contains an unknown context scope.");
    }
    return scope;
  });
  if (new Set(result).size !== result.length) fail("The approved capability scope catalog contains a duplicate.");
  return Object.freeze(result);
}

function capabilityDecisionRule(value: unknown): CapabilityDecisionRule {
  switch (value) {
    case "fixed-deny":
    case "verified-root-active-org":
    case "verified-root-or-active-member":
    case "plus-explicit-public-root":
    case "live-yii-rule-free-permission":
    case "verified-root-and-live-yii-permission":
      return value;
    default:
      fail("The approved capability catalog contains an unknown or unresolved decision rule.");
  }
}

function membershipKey(legacyUserId: string, legacyOrganizationId: string): string {
  return `${legacyUserId}\u0000${legacyOrganizationId}`;
}

function graphEdgeKey(parent: string, child: string): string {
  return `${parent}\u0000${child}`;
}

function assignmentKey(legacyUserId: string, itemName: string): string {
  return `${legacyUserId}\u0000${itemName}`;
}

function fail(message: string): never {
  throw new DevelopEffectiveDecisionError(message);
}
