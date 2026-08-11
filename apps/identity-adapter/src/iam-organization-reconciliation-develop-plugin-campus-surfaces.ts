import {
  ORGANIZATION_OWNER_DEVELOP_APPROVED_REGISTRY_CANDIDATE,
  ORGANIZATION_OWNER_DEVELOP_DECISION_CATALOGS
} from "./iam-organization-owner-semantic-registry.js";
import {
  projectDevelopIdentityBasicSurfaces,
  projectDevelopLegacyBasicSurfaces,
  type DevelopBasicSurfaces
} from "./iam-organization-reconciliation-develop-basic-surfaces.js";
import {
  assertIdentityDevelopProjectionSnapshotView,
  assertLegacyDevelopProjectionSnapshotView,
  type IdentityDevelopProjectionSnapshotView,
  type LegacyDevelopProjectionSnapshotView
} from "./iam-organization-reconciliation-develop-projection-views.js";
import {
  calculateRuleFreeYiiRbacClosure,
  classifyStrictPluginOrganizationBinding,
  legacySubjectLifecycleFromStatus,
  pluginAccessScopeAllows,
  requireStrictPluginAccessScope,
  type StrictPluginAccessScope
} from "./iam-organization-reconciliation-pure-rules.js";
import {
  ORGANIZATION_RECONCILIATION_PLATFORM_GLOBAL_CONTEXT_REF,
  ORGANIZATION_RECONCILIATION_PUBLIC_CONTEXT_REF,
  organizationRefForLegacyId,
  pluginRefForId,
  subjectRefForLegacyUserId
} from "./iam-organization-reconciliation-refs.js";
import {
  ORGANIZATION_RECONCILIATION_DEVELOP_IAM_POLICY_CHECKSUM
} from "./iam-organization-reconciliation/mysql-repeatable-read-snapshot.js";
import type {
  IdentityIamItemRelationMysqlRawRecord,
  IdentityIamNamedItemMysqlRawRecord,
  IdentityIamPolicyVersionMysqlRawRecord,
  IdentityIamSubjectAssignmentMysqlRawRecord,
  IdentityIamSubjectAssignmentSnapshotMysqlRawRecord,
  IdentitySubjectUniverseMysqlRawRecord,
  LegacyRbacAssignmentMysqlRawRecord,
  LegacyRbacEdgeMysqlRawRecord,
  LegacyRbacItemMysqlRawRecord,
  LegacySubjectUniverseMysqlRawRecord,
  PluginRegistryMysqlRawRecord
} from "./iam-organization-reconciliation/mysql-source-adapters/raw-source-snapshots.js";
import type {
  CampusContextRecord,
  OrganizationDirectoryRecord,
  PluginBindingRecord,
  PluginVisibilityRecord
} from "./iam-organization-reconciliation-validator.js";

export const ORGANIZATION_RECONCILIATION_DEVELOP_PLUGIN_CAMPUS_SURFACES_CONTRACT =
  "iam-organization-reconciliation-xrteeth-develop-plugin-campus-surfaces/v2" as const;
export const ORGANIZATION_RECONCILIATION_DEVELOP_PLUGIN_CAMPUS_SURFACES_IMPLEMENTED = true as const;
export const ORGANIZATION_RECONCILIATION_DEVELOP_PLUGIN_CAMPUS_SURFACES_READY = false as const;

export const ORGANIZATION_RECONCILIATION_DEVELOP_PLUGIN_CAMPUS_BLOCKERS = Object.freeze([
  "static-plugin-artifact-deployment-digest-not-attested",
  "operation-evidence-projector-not-production-registered",
  "runtime-pipeline-not-registered"
] as const);

type DevelopPluginCampusSide = "legacy" | "identity";
type DevelopPluginCampusBlocker =
  (typeof ORGANIZATION_RECONCILIATION_DEVELOP_PLUGIN_CAMPUS_BLOCKERS)[number];

export interface DevelopCampusContextCoverage {
  readonly ownerApprovedContextKinds: readonly ["organization", "platform-global", "public"];
  readonly projectedContextKinds: readonly ["organization", "platform-global", "public"];
  readonly blockedDecisionKinds: readonly [];
  readonly structuralUniverseComplete: true;
  readonly summaryTruthComplete: true;
  readonly validatorCompatibleForFullUniverse: true;
}

export interface DevelopPluginCampusSurfaces {
  readonly contract: typeof ORGANIZATION_RECONCILIATION_DEVELOP_PLUGIN_CAMPUS_SURFACES_CONTRACT;
  readonly side: DevelopPluginCampusSide;
  readonly semanticRegistrySha256: string;
  readonly pluginBindings: readonly PluginBindingRecord[];
  readonly pluginVisibility: readonly PluginVisibilityRecord[];
  /** Complete S x (O + 2) summary truth from the exact campus capability rules. */
  readonly campusContexts: readonly CampusContextRecord[];
  readonly campusContextCoverage: DevelopCampusContextCoverage;
  readonly blockers: readonly DevelopPluginCampusBlocker[];
}

interface SubjectProjectionState {
  readonly subjectRef: string;
  readonly active: boolean;
  readonly globalRoles: ReadonlySet<"root" | "user">;
  readonly effectiveRoles: ReadonlySet<"root" | "user" | "admin" | "manager">;
  readonly verifiedRoot: boolean;
}

interface EffectivePlugin {
  readonly pluginId: string;
  readonly pluginRef: string;
  readonly enabled: boolean;
  readonly accessScope: StrictPluginAccessScope;
  readonly organizationName: string | null;
}

interface OrganizationProjectionState {
  readonly ordered: readonly OrganizationDirectoryRecord[];
  readonly byName: ReadonlyMap<string, OrganizationDirectoryRecord>;
}

const CAMPUS_CONTEXT_COVERAGE = Object.freeze({
  ownerApprovedContextKinds: approvedCampusContextKinds(),
  projectedContextKinds: Object.freeze(["organization", "platform-global", "public"] as const),
  blockedDecisionKinds: Object.freeze([] as const),
  structuralUniverseComplete: true,
  summaryTruthComplete: true,
  validatorCompatibleForFullUniverse: true
} satisfies DevelopCampusContextCoverage);

function approvedCampusContextKinds(): readonly ["organization", "platform-global", "public"] {
  const campusCatalog = ORGANIZATION_OWNER_DEVELOP_DECISION_CATALOGS.campusPublicContext;
  if (campusCatalog.executionState !== "owner-bound-campus-context-decision-execution") {
    throw new Error("The approved Develop campus context-decision execution is not authorized.");
  }
  const contextKinds = campusCatalog.contextClassifier.contextKinds;
  if (
    contextKinds.length !== 3 ||
    contextKinds[0] !== "organization" ||
    contextKinds[1] !== "platform-global" ||
    contextKinds[2] !== "public"
  ) {
    throw new Error("The approved Develop campus context-kind catalog is invalid.");
  }
  return Object.freeze([contextKinds[0], contextKinds[1], contextKinds[2]]);
}

export function projectDevelopLegacyPluginCampusSurfaces(
  view: LegacyDevelopProjectionSnapshotView
): DevelopPluginCampusSurfaces {
  assertLegacyDevelopProjectionSnapshotView(view);
  const basic = projectDevelopLegacyBasicSurfaces(
    view,
    ORGANIZATION_OWNER_DEVELOP_APPROVED_REGISTRY_CANDIDATE.registrySha256
  );
  const subjects = legacySubjectState(view);
  bindLegacyGlobalRoles(view, subjects);
  return projectSurfaces("legacy", view, basic, subjects);
}

export function projectDevelopIdentityPluginCampusSurfaces(
  view: IdentityDevelopProjectionSnapshotView
): DevelopPluginCampusSurfaces {
  assertIdentityDevelopProjectionSnapshotView(view);
  const basic = projectDevelopIdentityBasicSurfaces(
    view,
    ORGANIZATION_OWNER_DEVELOP_APPROVED_REGISTRY_CANDIDATE.registrySha256
  );
  const subjects = identitySubjectState(view);
  bindIdentityGlobalRoles(view, subjects);
  return projectSurfaces("identity", view, basic, subjects);
}

function projectSurfaces(
  side: DevelopPluginCampusSide,
  view: LegacyDevelopProjectionSnapshotView | IdentityDevelopProjectionSnapshotView,
  basic: DevelopBasicSurfaces,
  subjectsByRef: Map<string, MutableSubjectProjectionState>
): DevelopPluginCampusSurfaces {
  const organizations = organizationState(basic.organizationDirectory);
  validateBasicSurfaceReferences(basic, subjectsByRef, organizations);
  const plugins = overlayApprovedStaticBuiltIns(rows<PluginRegistryMysqlRawRecord>(view, "plugin-registry"));
  const bindings = projectPluginBindings(plugins, organizations);
  const visibility = projectPluginVisibility(plugins, bindings, basic, subjectsByRef);
  const campusContexts = projectOrganizationCampusContexts(basic, subjectsByRef, organizations);
  return Object.freeze({
    contract: ORGANIZATION_RECONCILIATION_DEVELOP_PLUGIN_CAMPUS_SURFACES_CONTRACT,
    side,
    semanticRegistrySha256: ORGANIZATION_OWNER_DEVELOP_APPROVED_REGISTRY_CANDIDATE.registrySha256,
    pluginBindings: bindings,
    pluginVisibility: visibility,
    campusContexts,
    campusContextCoverage: CAMPUS_CONTEXT_COVERAGE,
    blockers: ORGANIZATION_RECONCILIATION_DEVELOP_PLUGIN_CAMPUS_BLOCKERS
  });
}

interface MutableSubjectProjectionState {
  readonly subjectRef: string;
  readonly active: boolean;
  readonly globalRoles: Set<"root" | "user">;
  readonly effectiveRoles: Set<"root" | "user" | "admin" | "manager">;
  verifiedRoot: boolean;
}

function legacySubjectState(
  view: LegacyDevelopProjectionSnapshotView
): Map<string, MutableSubjectProjectionState> {
  return subjectState(rows<LegacySubjectUniverseMysqlRawRecord>(view, "legacy-subject-universe").map((row) => ({
    subjectRef: subjectRefForLegacyUserId(row.legacyUserId),
    active: legacySubjectLifecycleFromStatus(row.status).active
  })));
}

function identitySubjectState(
  view: IdentityDevelopProjectionSnapshotView
): Map<string, MutableSubjectProjectionState> {
  return subjectState(rows<IdentitySubjectUniverseMysqlRawRecord>(view, "identity-subject-universe").map((row) => {
    if (row.status !== "active" && row.status !== "inactive") {
      throw new Error("An Identity subject has an invalid lifecycle state.");
    }
    if (row.source !== "legacy-shadow") {
      throw new Error("An Identity subject is outside the approved candidate selector.");
    }
    return {
      subjectRef: subjectRefForLegacyUserId(row.legacyUserId),
      active: row.status === "active"
    };
  }));
}

function subjectState(
  inputs: readonly Readonly<{ subjectRef: string; active: boolean }>[]
): Map<string, MutableSubjectProjectionState> {
  const result = new Map<string, MutableSubjectProjectionState>();
  for (const input of inputs) {
    if (result.has(input.subjectRef)) throw new Error("The subject universe contains a duplicate subject.");
    result.set(input.subjectRef, {
      ...input,
      globalRoles: new Set(),
      effectiveRoles: new Set(),
      verifiedRoot: false
    });
  }
  return result;
}

function bindLegacyGlobalRoles(
  view: LegacyDevelopProjectionSnapshotView,
  subjectsByRef: Map<string, MutableSubjectProjectionState>
): void {
  const itemTypes = new Map<string, "role" | "permission">();
  const items = rows<LegacyRbacItemMysqlRawRecord>(view, "legacy-rbac-item");
  for (const item of items) {
    if (item.ruleName !== null) throw new Error("A named Legacy Yii RBAC rule is unsupported.");
    if (itemTypes.has(item.itemName)) throw new Error("The Legacy RBAC item catalog is duplicate.");
    itemTypes.set(item.itemName, item.itemType);
  }
  const ruleFreeGraph = {
    rules: [],
    items: items.map((item) => ({
      name: item.itemName,
      type: item.itemType,
      ruleName: item.ruleName
    })),
    relations: rows<LegacyRbacEdgeMysqlRawRecord>(view, "legacy-rbac-edge")
      .map((relation) => ({ parent: relation.parentName, child: relation.childName }))
  } as const;
  calculateRuleFreeYiiRbacClosure(ruleFreeGraph, []);
  const assignmentKeys = new Set<string>();
  const assignmentsBySubject = new Map<string, string[]>();
  for (const assignment of rows<LegacyRbacAssignmentMysqlRawRecord>(view, "legacy-rbac-assignment")) {
    const subjectRef = subjectRefForLegacyUserId(assignment.legacyUserId);
    const subject = subjectsByRef.get(subjectRef);
    if (!subject) throw new Error("A Legacy RBAC assignment references an unknown subject.");
    const key = `${assignment.legacyUserId}\u0000${assignment.itemType}\u0000${assignment.itemName}`;
    if (assignmentKeys.has(key)) throw new Error("The Legacy RBAC assignment dataset is duplicate.");
    assignmentKeys.add(key);
    if (itemTypes.get(assignment.itemName) !== assignment.itemType) {
      throw new Error("A Legacy RBAC assignment does not match the compiled item catalog.");
    }
    bindApprovedGlobalRole(subject, assignment.itemName, assignment.itemType);
    const subjectAssignments = assignmentsBySubject.get(subjectRef) ?? [];
    subjectAssignments.push(assignment.itemName);
    assignmentsBySubject.set(subjectRef, subjectAssignments);
  }
  for (const subject of subjectsByRef.values()) {
    bindEffectiveRoles(subject, calculateRuleFreeYiiRbacClosure(
      ruleFreeGraph,
      assignmentsBySubject.get(subject.subjectRef) ?? []
    ).roles);
  }
}

function bindIdentityGlobalRoles(
  view: IdentityDevelopProjectionSnapshotView,
  subjectsByRef: Map<string, MutableSubjectProjectionState>
): void {
  const roles = validateIdentityNamedItems(
    rows<IdentityIamNamedItemMysqlRawRecord>(view, "identity-iam-role"),
    "role"
  );
  const permissions = validateIdentityNamedItems(
    rows<IdentityIamNamedItemMysqlRawRecord>(view, "identity-iam-permission"),
    "permission"
  );
  validateIdentityPolicyVersion(view, roles.size, permissions.size);
  const assignments = rows<IdentityIamSubjectAssignmentMysqlRawRecord>(
    view,
    "identity-iam-subject-assignment"
  );
  const assignmentsBySubject = new Map<string, IdentityIamSubjectAssignmentMysqlRawRecord[]>();
  const assignmentKeys = new Set<string>();
  for (const assignment of assignments) {
    requireIdentityCandidateRow(assignment);
    const subjectRef = subjectRefForLegacyUserId(assignment.legacyUserId);
    const subject = subjectsByRef.get(subjectRef);
    if (!subject) throw new Error("An Identity IAM assignment references an unknown subject.");
    const catalog = assignment.itemType === "role" ? roles : permissions;
    if (!catalog.has(assignment.itemName)) {
      throw new Error("An Identity IAM assignment does not match the exact candidate policy graph.");
    }
    const key = `${subjectRef}\u0000${assignment.itemType}\u0000${assignment.itemName}`;
    if (assignmentKeys.has(key)) throw new Error("The Identity IAM assignment dataset is duplicate.");
    assignmentKeys.add(key);
    const list = assignmentsBySubject.get(subjectRef) ?? [];
    list.push(assignment);
    assignmentsBySubject.set(subjectRef, list);
    bindApprovedGlobalRole(subject, assignment.itemName, assignment.itemType);
  }
  validateIdentityAssignmentSnapshots(view, subjectsByRef, assignmentsBySubject);
  const relations = rows<IdentityIamItemRelationMysqlRawRecord>(view, "identity-iam-item-relation");
  const ruleFreeGraph = {
    rules: [],
    items: [
      ...[...roles].map((name) => ({ name, type: "role" as const, ruleName: null })),
      ...[...permissions].map((name) => ({ name, type: "permission" as const, ruleName: null }))
    ],
    relations: relations.map((relation) => ({
      parent: relation.parentName,
      child: relation.childName
    }))
  } as const;
  for (const subject of subjectsByRef.values()) {
    bindEffectiveRoles(subject, calculateRuleFreeYiiRbacClosure(
      ruleFreeGraph,
      (assignmentsBySubject.get(subject.subjectRef) ?? []).map((assignment) => assignment.itemName)
    ).roles);
  }
}

function bindEffectiveRoles(
  subject: MutableSubjectProjectionState,
  roles: readonly string[]
): void {
  for (const role of roles) {
    if (role === "root" || role === "user" || role === "admin" || role === "manager") {
      subject.effectiveRoles.add(role);
    }
  }
  subject.verifiedRoot = subject.effectiveRoles.has("root");
}

function bindApprovedGlobalRole(
  subject: MutableSubjectProjectionState,
  itemName: string,
  itemType: "role" | "permission"
): void {
  if (itemType !== "role") return;
  if (itemName === "root" || itemName === "user") {
    subject.globalRoles.add(itemName);
    return;
  }
  if (itemName === "admin" || itemName === "manager") return;
  throw new Error("An unknown role cannot enter the approved Develop plugin projection.");
}

function validateIdentityNamedItems(
  values: readonly IdentityIamNamedItemMysqlRawRecord[],
  itemType: "role" | "permission"
): Set<string> {
  const result = new Set<string>();
  for (const value of values) {
    requireIdentityCandidateRow(value);
    if (result.has(value.itemName)) throw new Error(`The Identity IAM ${itemType} catalog is duplicate.`);
    result.add(value.itemName);
  }
  return result;
}

function validateIdentityPolicyVersion(
  view: IdentityDevelopProjectionSnapshotView,
  roleCount: number,
  permissionCount: number
): void {
  const versions = rows<IdentityIamPolicyVersionMysqlRawRecord>(view, "identity-iam-policy-version");
  const relations = rows<IdentityIamItemRelationMysqlRawRecord>(view, "identity-iam-item-relation");
  if (versions.length !== 1) throw new Error("The exact Identity IAM policy version is missing or duplicate.");
  const version = versions[0]!;
  requireIdentityCandidateRow(version);
  const itemTypes = new Map<string, "role" | "permission">();
  for (const role of rows<IdentityIamNamedItemMysqlRawRecord>(view, "identity-iam-role")) {
    if (itemTypes.has(role.itemName)) {
      throw new Error("The exact Identity IAM policy graph contains a duplicate item name.");
    }
    itemTypes.set(role.itemName, "role");
  }
  for (const permission of rows<IdentityIamNamedItemMysqlRawRecord>(view, "identity-iam-permission")) {
    if (itemTypes.has(permission.itemName)) {
      throw new Error("The exact Identity IAM policy graph contains a duplicate item name.");
    }
    itemTypes.set(permission.itemName, "permission");
  }
  for (const relation of relations) {
    requireIdentityCandidateRow(relation);
    if (
      itemTypes.get(relation.parentName) !== relation.parentType ||
      itemTypes.get(relation.childName) !== relation.childType
    ) {
      throw new Error("An Identity IAM relation does not match the exact candidate item catalog.");
    }
  }
  if (
    version.roleCount !== roleCount ||
    version.permissionCount !== permissionCount ||
    version.relationCount !== relations.length
  ) {
    throw new Error("The exact Identity IAM policy catalog counts do not match the policy version.");
  }
  calculateRuleFreeYiiRbacClosure({
    rules: [],
    items: [...itemTypes].map(([name, type]) => ({ name, type, ruleName: null })),
    relations: relations.map((relation) => ({
      parent: relation.parentName,
      child: relation.childName
    }))
  }, []);
}

function validateIdentityAssignmentSnapshots(
  view: IdentityDevelopProjectionSnapshotView,
  subjectsByRef: ReadonlyMap<string, MutableSubjectProjectionState>,
  assignmentsBySubject: ReadonlyMap<string, readonly IdentityIamSubjectAssignmentMysqlRawRecord[]>
): void {
  const snapshots = rows<IdentityIamSubjectAssignmentSnapshotMysqlRawRecord>(
    view,
    "identity-iam-subject-assignment-snapshot"
  );
  const snapshotBySubject = new Map<string, IdentityIamSubjectAssignmentSnapshotMysqlRawRecord>();
  for (const snapshot of snapshots) {
    requireIdentityCandidateRow(snapshot);
    if (snapshot.snapshotKey !== ORGANIZATION_RECONCILIATION_DEVELOP_IAM_POLICY_CHECKSUM) {
      throw new Error("An Identity IAM assignment snapshot has the wrong exact policy key.");
    }
    const subjectRef = subjectRefForLegacyUserId(snapshot.legacyUserId);
    if (!subjectsByRef.has(subjectRef) || snapshotBySubject.has(subjectRef)) {
      throw new Error("The Identity IAM assignment snapshot universe is invalid.");
    }
    snapshotBySubject.set(subjectRef, snapshot);
  }
  if (snapshotBySubject.size !== subjectsByRef.size) {
    throw new Error("The Identity IAM assignment snapshot universe is incomplete.");
  }
  for (const subjectRef of subjectsByRef.keys()) {
    const snapshot = snapshotBySubject.get(subjectRef)!;
    const assignments = assignmentsBySubject.get(subjectRef) ?? [];
    if (
      snapshot.assignmentCount !== assignments.length ||
      assignments.some((assignment) => assignment.identityUserId !== snapshot.identityUserId)
    ) {
      throw new Error("An Identity IAM assignment snapshot count or subject binding is invalid.");
    }
  }
}

function requireIdentityCandidateRow(value: Readonly<{
  policyChecksum: string;
  source: string;
  status: string;
}>): void {
  if (
    value.policyChecksum !== ORGANIZATION_RECONCILIATION_DEVELOP_IAM_POLICY_CHECKSUM ||
    value.source !== "legacy-import-candidate" ||
    value.status !== "candidate"
  ) {
    throw new Error("An Identity IAM row is outside the approved exact candidate policy selector.");
  }
}

function overlayApprovedStaticBuiltIns(
  databaseRows: readonly PluginRegistryMysqlRawRecord[]
): readonly EffectivePlugin[] {
  const plugins = new Map<string, EffectivePlugin>();
  for (const row of databaseRows) {
    const plugin = validatePlugin(row);
    if (plugins.has(plugin.pluginRef)) throw new Error("The plugin database baseline contains a duplicate ID.");
    plugins.set(plugin.pluginRef, plugin);
  }
  for (const staticPlugin of ORGANIZATION_OWNER_DEVELOP_DECISION_CATALOGS.pluginOverlay.staticBuiltIns) {
    const candidate = validatePlugin({
      pluginId: staticPlugin.id,
      enabled: staticPlugin.enabled,
      accessScope: staticPlugin.accessScope,
      organizationName: staticPlugin.organizationName
    });
    const database = plugins.get(candidate.pluginRef);
    if (database && !samePluginAuthorization(database, candidate)) {
      throw new Error(
        `P1 plugin authorization drift blocks the approved static overlay for ${candidate.pluginRef}.`
      );
    }
    plugins.set(candidate.pluginRef, candidate);
  }
  return Object.freeze([...plugins.values()].sort((left, right) => compare(left.pluginRef, right.pluginRef)));
}

function validatePlugin(row: PluginRegistryMysqlRawRecord): EffectivePlugin {
  if (typeof row.enabled !== "boolean") throw new Error("A plugin has an invalid enabled state.");
  const pluginRef = pluginRefForId(row.pluginId);
  const accessScope = requireStrictPluginAccessScope(row.accessScope);
  const binding = classifyStrictPluginOrganizationBinding(row.organizationName);
  if (binding.kind === "organization-name" && !/^[a-z0-9][a-z0-9-]*$/.test(binding.organizationName)) {
    throw new Error("A plugin organization binding is not a canonical lowercase slug.");
  }
  return Object.freeze({
    pluginId: row.pluginId,
    pluginRef,
    enabled: row.enabled,
    accessScope,
    organizationName: binding.organizationName
  });
}

function samePluginAuthorization(left: EffectivePlugin, right: EffectivePlugin): boolean {
  return left.enabled === right.enabled &&
    left.accessScope === right.accessScope &&
    left.organizationName === right.organizationName;
}

function projectPluginBindings(
  plugins: readonly EffectivePlugin[],
  organizations: OrganizationProjectionState
): readonly PluginBindingRecord[] {
  return canonicalSort(plugins.map((plugin) => {
    const organizationRef = resolvePluginOrganizationRef(plugin.organizationName, organizations);
    return {
      pluginRef: plugin.pluginRef,
      bindingRef: `${plugin.pluginRef}:${organizationRef}`,
      organizationRef,
      active: plugin.enabled
    };
  }), (record) => record.pluginRef);
}

function projectPluginVisibility(
  plugins: readonly EffectivePlugin[],
  bindings: readonly PluginBindingRecord[],
  basic: DevelopBasicSurfaces,
  subjectsByRef: ReadonlyMap<string, MutableSubjectProjectionState>
): readonly PluginVisibilityRecord[] {
  const bindingByPlugin = new Map(bindings.map((binding) => [binding.pluginRef, binding]));
  const memberships = new Set(basic.memberships
    .filter((membership) => membership.active)
    .map((membership) => `${membership.subjectRef}\u0000${organizationRefForLegacyId(membership.legacyOrganizationId)}`));
  const scopedRoles = scopedRolesBySubjectAndOrganization(basic);
  const records: PluginVisibilityRecord[] = [];
  for (const subject of orderedSubjects(subjectsByRef)) {
    for (const plugin of plugins) {
      const binding = bindingByPlugin.get(plugin.pluginRef);
      if (!binding) throw new Error("An effective plugin is missing its binding row.");
      const scopedKey = `${subject.subjectRef}\u0000${binding.organizationRef}`;
      const roles = new Set<string>(subject.globalRoles);
      if (binding.organizationRef !== ORGANIZATION_RECONCILIATION_PUBLIC_CONTEXT_REF) {
        for (const role of scopedRoles.get(scopedKey) ?? []) roles.add(role);
      }
      const organizationAllowed =
        binding.organizationRef === ORGANIZATION_RECONCILIATION_PUBLIC_CONTEXT_REF ||
        roles.has("root") ||
        memberships.has(scopedKey);
      const scopeAllowed = pluginAccessScopeAllows(plugin.accessScope, {
        authenticated: subject.active,
        roles: [...roles].sort()
      });
      records.push({
        subjectRef: subject.subjectRef,
        pluginRef: plugin.pluginRef,
        organizationRef: binding.organizationRef,
        decision: plugin.enabled && subject.active && organizationAllowed && scopeAllowed ? "allow" : "deny"
      });
    }
  }
  if (records.length !== subjectsByRef.size * plugins.length) {
    throw new Error("The plugin visibility projector did not cover the full subject-by-plugin universe.");
  }
  return canonicalSort(records, (record) =>
    `${record.subjectRef}\u0000${record.pluginRef}\u0000${record.organizationRef}`
  );
}

function projectOrganizationCampusContexts(
  basic: DevelopBasicSurfaces,
  subjectsByRef: ReadonlyMap<string, MutableSubjectProjectionState>,
  organizations: OrganizationProjectionState
): readonly CampusContextRecord[] {
  const activeMemberships = new Set(basic.memberships
    .filter((membership) => membership.active)
    .map((membership) =>
      `${membership.subjectRef}\u0000${organizationRefForLegacyId(membership.legacyOrganizationId)}`
    ));
  const records: CampusContextRecord[] = [];
  for (const subject of orderedSubjects(subjectsByRef)) {
    for (const organization of organizations.ordered) {
      const organizationRef = organizationRefForLegacyId(organization.legacyOrganizationId);
      const hasActiveMembership = activeMemberships.has(`${subject.subjectRef}\u0000${organizationRef}`);
      records.push({
        subjectRef: subject.subjectRef,
        contextKind: "organization",
        contextRef: organizationRef,
        decision:
          subject.active && organization.active &&
          (subject.verifiedRoot ||
            (hasActiveMembership &&
              (subject.effectiveRoles.has("admin") || subject.effectiveRoles.has("manager"))))
            ? "allow"
            : "deny"
      });
    }
    records.push(
      {
        subjectRef: subject.subjectRef,
        contextKind: "platform-global",
        contextRef: ORGANIZATION_RECONCILIATION_PLATFORM_GLOBAL_CONTEXT_REF,
        decision: "deny"
      },
      {
        subjectRef: subject.subjectRef,
        contextKind: "public",
        contextRef: ORGANIZATION_RECONCILIATION_PUBLIC_CONTEXT_REF,
        decision: subject.active && subject.verifiedRoot ? "allow" : "deny"
      }
    );
  }
  if (records.length !== subjectsByRef.size * (organizations.ordered.length + 2)) {
    throw new Error("The campus projector did not cover the full S x (O + 2) structural universe.");
  }
  return canonicalSort(records, (record) =>
    `${record.subjectRef}\u0000${record.contextKind}\u0000${record.contextRef}`
  );
}

function scopedRolesBySubjectAndOrganization(
  basic: DevelopBasicSurfaces
): Map<string, Set<string>> {
  const result = new Map<string, Set<string>>();
  for (const role of basic.organizationScopedRoles) {
    if (!role.active) continue;
    if (role.roleRef !== "admin" && role.roleRef !== "manager") {
      throw new Error("A non-member-scoped role entered the Develop organization role surface.");
    }
    const key = `${role.subjectRef}\u0000${organizationRefForLegacyId(role.legacyOrganizationId)}`;
    const roles = result.get(key) ?? new Set<string>();
    if (roles.has(role.roleRef)) throw new Error("The Develop organization role surface is duplicate.");
    roles.add(role.roleRef);
    result.set(key, roles);
  }
  return result;
}

function organizationState(
  organizations: readonly OrganizationDirectoryRecord[]
): OrganizationProjectionState {
  const byName = new Map<string, OrganizationDirectoryRecord>();
  const ids = new Set<string>();
  const ordered = [...organizations].sort((left, right) =>
    compare(
      organizationRefForLegacyId(left.legacyOrganizationId),
      organizationRefForLegacyId(right.legacyOrganizationId)
    )
  );
  for (const organization of ordered) {
    const organizationRef = organizationRefForLegacyId(organization.legacyOrganizationId);
    if (!organization.active) throw new Error("The Develop organization directory contains an inactive row.");
    if (!/^[a-z0-9][a-z0-9-]*$/.test(organization.name)) {
      throw new Error("An organization name is not a canonical lowercase slug.");
    }
    if (ids.has(organizationRef) || byName.has(organization.name)) {
      throw new Error("The Develop organization directory is duplicate or name-ambiguous.");
    }
    ids.add(organizationRef);
    byName.set(organization.name, organization);
  }
  return { ordered: Object.freeze(ordered), byName };
}

function validateBasicSurfaceReferences(
  basic: DevelopBasicSurfaces,
  subjectsByRef: ReadonlyMap<string, MutableSubjectProjectionState>,
  organizations: OrganizationProjectionState
): void {
  const organizationRefs = new Set(organizations.ordered
    .map((organization) => organizationRefForLegacyId(organization.legacyOrganizationId)));
  const memberships = new Set<string>();
  for (const membership of basic.memberships) {
    const organizationRef = organizationRefForLegacyId(membership.legacyOrganizationId);
    const key = `${membership.subjectRef}\u0000${organizationRef}`;
    if (!membership.active || !subjectsByRef.has(membership.subjectRef) || !organizationRefs.has(organizationRef)) {
      throw new Error("The Develop membership surface contains an invalid reference.");
    }
    if (memberships.has(key)) throw new Error("The Develop membership surface is duplicate.");
    memberships.add(key);
  }
  for (const role of basic.organizationScopedRoles) {
    const key = `${role.subjectRef}\u0000${organizationRefForLegacyId(role.legacyOrganizationId)}`;
    if (!memberships.has(key)) {
      throw new Error("A Develop organization role exists without an active membership.");
    }
  }
}

function resolvePluginOrganizationRef(
  organizationName: string | null,
  organizations: OrganizationProjectionState
): string {
  if (organizationName === null) return ORGANIZATION_RECONCILIATION_PUBLIC_CONTEXT_REF;
  const organization = organizations.byName.get(organizationName);
  if (!organization) throw new Error("A plugin organization binding is unresolved or ambiguous.");
  return organizationRefForLegacyId(organization.legacyOrganizationId);
}

function orderedSubjects(
  subjectsByRef: ReadonlyMap<string, MutableSubjectProjectionState>
): readonly SubjectProjectionState[] {
  return [...subjectsByRef.values()].sort((left, right) => compare(left.subjectRef, right.subjectRef));
}

function rows<T>(
  view: LegacyDevelopProjectionSnapshotView | IdentityDevelopProjectionSnapshotView,
  datasetId: string
): readonly T[] {
  const value = view.datasets[datasetId];
  if (!Array.isArray(value)) throw new Error(`The compiled dataset ${datasetId} is missing.`);
  return value as unknown as readonly T[];
}

function canonicalSort<T>(values: readonly T[], keyFor: (value: T) => string): readonly T[] {
  const result = [...values].sort((left, right) => compare(keyFor(left), keyFor(right)));
  for (let index = 1; index < result.length; index += 1) {
    if (keyFor(result[index - 1]!) === keyFor(result[index]!)) {
      throw new Error("A Develop plugin/campus surface contains a duplicate canonical key.");
    }
  }
  return Object.freeze(result.map((value) => Object.freeze({ ...value })));
}

function compare(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
