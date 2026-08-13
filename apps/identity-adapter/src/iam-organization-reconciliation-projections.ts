import { createHash } from "node:crypto";
import {
  canonicalizeOrganizationReconciliationEvidenceValue
} from "./iam-organization-reconciliation-component-manifest.js";
import type {
  CampusContextRecord,
  EffectiveOrganizationDecisionRecord,
  OrganizationDirectoryRecord,
  OrganizationMembershipRecord,
  OrganizationScopedRoleRecord,
  PluginBindingRecord,
  PluginVisibilityRecord
} from "./iam-organization-reconciliation-validator.js";
import {
  ORGANIZATION_RECONCILIATION_PLATFORM_GLOBAL_CONTEXT_REF,
  ORGANIZATION_RECONCILIATION_PUBLIC_CONTEXT_REF,
  ORGANIZATION_RECONCILIATION_PROJECTION_CATALOGS_READY,
  type AuthorizationContext,
  type AuthorizationContextKind,
  authorizationContextForLegacyOrganizationId,
  canonicalLegacyOrganizationId,
  canonicalReconciliationToken,
  isCanonicalAuthorizationContext,
  isCanonicalLegacyUserSubjectRef,
  organizationRefForLegacyId,
  pluginRefForId
} from "./iam-organization-reconciliation-refs.js";

export {
  ORGANIZATION_RECONCILIATION_PLATFORM_GLOBAL_CONTEXT_REF,
  ORGANIZATION_RECONCILIATION_PUBLIC_CONTEXT_REF,
  ORGANIZATION_RECONCILIATION_PROJECTION_CATALOGS_READY,
  organizationRefForLegacyId,
  pluginRefForId
} from "./iam-organization-reconciliation-refs.js";

export const ORGANIZATION_RECONCILIATION_PROJECTION_CONTRACT =
  "iam-organization-reconciliation-projections/v2" as const;
const ORGANIZATION_RECONCILIATION_PROJECTION_CATALOG_DIGEST_DOMAIN =
  "iam-organization-reconciliation:projection-catalog-digest:v2\u001f";

/**
 * Production catalogs are deliberately absent. Supplying data to the pure
 * functions below does not make a collector production-ready: the eventual
 * orchestrator must obtain a reviewed catalog from an immutable build-time
 * registry and bind its digest into the signed component manifest.
 */
export type OrganizationReconciliationAccessScope =
  | "auth-only"
  | "manager-only"
  | "admin-only"
  | "root-only";

export interface OrganizationReconciliationSubject {
  readonly subjectRef: string;
  readonly active: boolean;
  readonly authenticated: boolean;
}

export interface OrganizationReconciliationRoleAssignment {
  readonly subjectRef: string;
  readonly roleRef: string;
  readonly active: boolean;
}

export interface OrganizationReconciliationRolePolicy {
  readonly roleRef: string;
  /** Platform roles such as root must not be expanded across organizations. */
  readonly scope: "global" | "member-organization";
}

export interface OrganizationReconciliationPlugin {
  readonly pluginId: string;
  readonly enabled: boolean;
  readonly accessScope: OrganizationReconciliationAccessScope;
  /** SQL NULL means public. An empty string is invalid and never means public. */
  readonly organizationName: string | null;
}

export interface OrganizationReconciliationCampusCatalogEntry {
  readonly contextKind: AuthorizationContextKind;
  readonly contextRef: string;
}

export interface OrganizationReconciliationCapabilityRule {
  readonly resourceRef: string;
  readonly capabilityRef: string;
  readonly minimumRole: "user" | "manager" | "admin" | "root";
  readonly membershipRequired: boolean;
  readonly rootMayBypassMembership: boolean;
}

export interface OrganizationReconciliationProjectionInput {
  readonly subjects: readonly OrganizationReconciliationSubject[];
  readonly organizations: readonly OrganizationDirectoryRecord[];
  readonly memberships: readonly OrganizationMembershipRecord[];
  readonly roleAssignments: readonly OrganizationReconciliationRoleAssignment[];
}

export interface OrganizationReconciliationProjectionReadiness {
  readonly ready: false;
  readonly blockers: readonly [
    "compiled-projection-catalog-missing",
    "identity-directory-read-model-incomplete",
    "identity-mapping-read-model-incomplete",
    "campus-catalog-not-owner-approved",
    "campus-platform-global-public-summary-not-owner-approved",
    "effective-capability-catalog-not-owner-approved",
    "exact-capability-context-execution-not-authorized",
    "projection-binding-not-integrated"
  ];
}

const ROLE_LEVELS: Readonly<Record<string, number>> = Object.freeze({
  root: 4,
  admin: 3,
  manager: 2,
  user: 1
});

const ACCESS_SCOPE_LEVELS: Readonly<Record<OrganizationReconciliationAccessScope, number>> =
  Object.freeze({
    "root-only": 4,
    "admin-only": 3,
    "manager-only": 2,
    "auth-only": 1
  });

export function organizationReconciliationProjectionReadiness(): OrganizationReconciliationProjectionReadiness {
  return {
    ready: ORGANIZATION_RECONCILIATION_PROJECTION_CATALOGS_READY,
    blockers: [
      "compiled-projection-catalog-missing",
      "identity-directory-read-model-incomplete",
      "identity-mapping-read-model-incomplete",
      "campus-catalog-not-owner-approved",
      "campus-platform-global-public-summary-not-owner-approved",
      "effective-capability-catalog-not-owner-approved",
      "exact-capability-context-execution-not-authorized",
      "projection-binding-not-integrated"
    ]
  };
}

export function projectOrganizationScopedRoles(
  input: OrganizationReconciliationProjectionInput,
  rolePolicies: readonly OrganizationReconciliationRolePolicy[]
): OrganizationScopedRoleRecord[] {
  const state = validateProjectionInput(input);
  const policyByRole = uniqueIndex(rolePolicies, (policy) => {
    if (policy.scope !== "global" && policy.scope !== "member-organization") {
      throw new Error("A role policy has an unsupported scope.");
    }
    const roleRef = canonicalReconciliationToken(policy.roleRef, "role policy ref");
    if (roleRef === "root" && policy.scope !== "global") {
      throw new Error("The protected root role must remain platform-global.");
    }
    return roleRef;
  });
  const projected: OrganizationScopedRoleRecord[] = [];

  for (const assignment of input.roleAssignments) {
    if (!assignment.active) continue;
    const subjectRef = canonicalSubjectRef(assignment.subjectRef);
    if (!state.subjects.has(subjectRef)) throw new Error("A role assignment references an unknown subject.");
    const roleRef = canonicalReconciliationToken(assignment.roleRef, "role assignment ref");
    const policy = policyByRole.get(roleRef);
    if (!policy) throw new Error("A role assignment has no reviewed organization-scope policy.");
    if (policy.scope === "global") continue;

    for (const organizationId of state.membershipsBySubject.get(subjectRef) ?? []) {
      projected.push({
        subjectRef,
        legacyOrganizationId: organizationId,
        roleRef,
        active: true
      });
    }
  }

  return sortAndRejectDuplicateRecords(projected, (record) =>
    [record.subjectRef, canonicalLegacyOrganizationId(record.legacyOrganizationId), record.roleRef].join("\u0000")
  );
}

export function projectPluginBindings(
  organizations: readonly OrganizationDirectoryRecord[],
  plugins: readonly OrganizationReconciliationPlugin[]
): PluginBindingRecord[] {
  const organizationState = validateOrganizations(organizations);
  const pluginIndex = uniqueIndex(plugins, validatePlugin);
  const records: PluginBindingRecord[] = [];

  for (const [pluginRef, plugin] of pluginIndex) {
    const organizationRef = resolvePluginOrganizationRef(plugin.organizationName, organizationState);
    records.push({
      pluginRef,
      bindingRef: `${pluginRef}:${organizationRef}`,
      organizationRef,
      active: plugin.enabled
    });
  }

  return sortAndRejectDuplicateRecords(records, (record) => record.pluginRef);
}

export function projectPluginVisibility(
  input: OrganizationReconciliationProjectionInput,
  plugins: readonly OrganizationReconciliationPlugin[]
): PluginVisibilityRecord[] {
  const state = validateProjectionInput(input);
  const pluginIndex = uniqueIndex(plugins, validatePlugin);
  const records: PluginVisibilityRecord[] = [];

  for (const [subjectRef, subject] of state.subjects) {
    const roleLevel = highestRoleLevel(state.rolesBySubject.get(subjectRef));
    const isRoot = (state.rolesBySubject.get(subjectRef) ?? new Set()).has("root");
    for (const [pluginRef, plugin] of pluginIndex) {
      const organizationRef = resolvePluginOrganizationRef(plugin.organizationName, state.organizations);
      const organizationAllowed =
        organizationRef === ORGANIZATION_RECONCILIATION_PUBLIC_CONTEXT_REF ||
        isRoot ||
        state.organizationRefsBySubject.get(subjectRef)?.has(organizationRef) === true;
      const scopeAllowed =
        subject.active &&
        subject.authenticated &&
        roleLevel >= ACCESS_SCOPE_LEVELS[plugin.accessScope];
      records.push({
        subjectRef,
        pluginRef,
        organizationRef,
        decision: plugin.enabled && organizationAllowed && scopeAllowed ? "allow" : "deny"
      });
    }
  }

  return sortAndRejectDuplicateRecords(records, (record) =>
    [record.subjectRef, record.pluginRef, record.organizationRef].join("\u0000")
  );
}

export function projectCampusContexts(
  input: OrganizationReconciliationProjectionInput,
  catalog: readonly OrganizationReconciliationCampusCatalogEntry[]
): CampusContextRecord[] {
  const state = validateProjectionInput(input);
  const campusIndex = uniqueIndex(catalog, (entry) => {
    if (!isCanonicalAuthorizationContext(entry.contextKind, entry.contextRef)) {
      throw new Error("A campus catalog entry has an invalid authorization context.");
    }
    return authorizationContextKey(entry.contextKind, entry.contextRef);
  });
  const contexts = canonicalAuthorizationContextsForOrganizations(state.organizations);
  if (
    campusIndex.size !== contexts.length ||
    contexts.some((context) => !campusIndex.has(authorizationContextKey(context.contextKind, context.contextRef)))
  ) {
    throw new Error("The campus catalog does not cover the exact organization/platform-global/public universe.");
  }
  const records: CampusContextRecord[] = [];

  for (const context of contexts) {
    const organization = context.contextKind === "organization"
      ? organizationForContextRef(state.organizations, context.contextRef)
      : undefined;
    for (const [subjectRef, subject] of state.subjects) {
      const roles = state.rolesBySubject.get(subjectRef) ?? new Set<string>();
      const organizationAllowed = organization !== undefined && (
        roles.has("root") ||
        ((roles.has("admin") || roles.has("manager")) &&
          state.organizationRefsBySubject.get(subjectRef)?.has(context.contextRef) === true)
      );
      records.push({
        subjectRef,
        contextKind: context.contextKind,
        contextRef: context.contextRef,
        // The two reserved contexts are deliberately conservative until their
        // owner-approved summary rules are compiled and pinned.
        decision: subject.active && subject.authenticated && organization?.active === true && organizationAllowed
          ? "allow"
          : "deny"
      });
    }
  }

  return sortAndRejectDuplicateRecords(records, (record) =>
    [record.subjectRef, record.contextKind, record.contextRef].join("\u0000")
  );
}

export function projectEffectiveDecisions(
  input: OrganizationReconciliationProjectionInput,
  rules: readonly OrganizationReconciliationCapabilityRule[]
): EffectiveOrganizationDecisionRecord[] {
  const state = validateProjectionInput(input);
  const ruleIndex = uniqueIndex(rules, (rule) => {
    if (!(rule.minimumRole in ROLE_LEVELS)) throw new Error("A capability rule has an invalid minimum role.");
    if (typeof rule.membershipRequired !== "boolean" || typeof rule.rootMayBypassMembership !== "boolean") {
      throw new Error("A capability rule has invalid membership semantics.");
    }
    return [canonicalReconciliationToken(rule.resourceRef, "resource ref"), canonicalReconciliationToken(rule.capabilityRef, "capability ref")].join("\u0000");
  });
  const records: EffectiveOrganizationDecisionRecord[] = [];

  for (const [subjectRef, subject] of state.subjects) {
    const roles = state.rolesBySubject.get(subjectRef) ?? new Set<string>();
    const roleLevel = highestRoleLevel(roles);
    for (const context of canonicalAuthorizationContextsForOrganizations(state.organizations)) {
      const organization = context.contextKind === "organization"
        ? organizationForContextRef(state.organizations, context.contextRef)
        : undefined;
      const isMember = state.organizationRefsBySubject.get(subjectRef)?.has(context.contextRef) === true;
      for (const rule of ruleIndex.values()) {
        const membershipAllowed =
          !rule.membershipRequired ||
          isMember ||
          (rule.rootMayBypassMembership && roles.has("root"));
        records.push({
          subjectRef,
          contextKind: context.contextKind,
          contextRef: context.contextRef,
          resourceRef: rule.resourceRef,
          capabilityRef: rule.capabilityRef,
          decision:
            subject.active &&
            subject.authenticated &&
            organization?.active === true &&
            membershipAllowed &&
            roleLevel >= ROLE_LEVELS[rule.minimumRole]!
              ? "allow"
              : "deny"
        });
      }
    }
  }

  return sortAndRejectDuplicateRecords(records, (record) =>
    [
      record.subjectRef,
      record.contextKind,
      record.contextRef,
      record.resourceRef,
      record.capabilityRef
    ].join("\u0000")
  );
}

export function organizationReconciliationProjectionCatalogDigest(value: unknown): string {
  const canonicalCatalog = canonicalizeOrganizationReconciliationProjectionCatalog(value);
  return createHash("sha256")
    .update(ORGANIZATION_RECONCILIATION_PROJECTION_CATALOG_DIGEST_DOMAIN, "utf8")
    .update(ORGANIZATION_RECONCILIATION_PROJECTION_CONTRACT, "utf8")
    .update("\u001f", "utf8")
    .update(stableSerialize(canonicalCatalog), "utf8")
    .digest("hex");
}

/**
 * Copies an owner-reviewed catalog into one immutable canonical JSON value.
 * Future registry call sites must project from this returned copy and bind the
 * digest of the same copy, never hash one mutable object and later read another.
 */
export function canonicalizeOrganizationReconciliationProjectionCatalog<T>(
  value: T
): Readonly<T> {
  return canonicalizeOrganizationReconciliationEvidenceValue(value) as Readonly<T>;
}

interface OrganizationState {
  readonly ordered: readonly OrganizationDirectoryRecord[];
  readonly byId: ReadonlyMap<string, OrganizationDirectoryRecord>;
  readonly byRef: ReadonlyMap<string, OrganizationDirectoryRecord>;
  readonly activeByExactName: ReadonlyMap<string, OrganizationDirectoryRecord>;
}

interface ProjectionState {
  readonly subjects: ReadonlyMap<string, OrganizationReconciliationSubject>;
  readonly organizations: OrganizationState;
  readonly membershipsBySubject: ReadonlyMap<string, readonly (string | number)[]>;
  readonly organizationRefsBySubject: ReadonlyMap<string, ReadonlySet<string>>;
  readonly rolesBySubject: ReadonlyMap<string, ReadonlySet<string>>;
}

function validateProjectionInput(input: OrganizationReconciliationProjectionInput): ProjectionState {
  const subjects = uniqueIndex(input.subjects, (subject) => {
    if (typeof subject.active !== "boolean" || typeof subject.authenticated !== "boolean") {
      throw new Error("A subject has an invalid lifecycle state.");
    }
    return canonicalSubjectRef(subject.subjectRef);
  });
  const organizations = validateOrganizations(input.organizations);
  const membershipsBySubject = new Map<string, Array<string | number>>();
  const organizationRefsBySubject = new Map<string, Set<string>>();
  const membershipKeys = new Set<string>();

  for (const membership of input.memberships) {
    if (typeof membership.active !== "boolean") throw new Error("A membership has an invalid lifecycle state.");
    if (!membership.active) continue;
    const subjectRef = canonicalSubjectRef(membership.subjectRef);
    if (!subjects.has(subjectRef)) throw new Error("A membership references an unknown subject.");
    const organizationId = canonicalLegacyOrganizationId(membership.legacyOrganizationId);
    const organization = organizations.byId.get(organizationId);
    if (!organization || !organization.active) throw new Error("A membership references an inactive or unknown organization.");
    const key = `${subjectRef}\u0000${organizationId}`;
    if (membershipKeys.has(key)) throw new Error("The projection input contains a duplicate active membership.");
    membershipKeys.add(key);
    const ids = membershipsBySubject.get(subjectRef) ?? [];
    ids.push(membership.legacyOrganizationId);
    membershipsBySubject.set(subjectRef, ids);
    const refs = organizationRefsBySubject.get(subjectRef) ?? new Set<string>();
    refs.add(organizationRefForLegacyId(membership.legacyOrganizationId));
    organizationRefsBySubject.set(subjectRef, refs);
  }

  const rolesBySubject = new Map<string, Set<string>>();
  const roleKeys = new Set<string>();
  for (const assignment of input.roleAssignments) {
    if (typeof assignment.active !== "boolean") throw new Error("A role assignment has an invalid lifecycle state.");
    if (!assignment.active) continue;
    const subjectRef = canonicalSubjectRef(assignment.subjectRef);
    if (!subjects.has(subjectRef)) throw new Error("A role assignment references an unknown subject.");
    const roleRef = canonicalReconciliationToken(assignment.roleRef, "role assignment ref");
    const key = `${subjectRef}\u0000${roleRef}`;
    if (roleKeys.has(key)) throw new Error("The projection input contains a duplicate active role assignment.");
    roleKeys.add(key);
    const roles = rolesBySubject.get(subjectRef) ?? new Set<string>();
    roles.add(roleRef);
    rolesBySubject.set(subjectRef, roles);
  }

  return { subjects, organizations, membershipsBySubject, organizationRefsBySubject, rolesBySubject };
}

function validateOrganizations(organizations: readonly OrganizationDirectoryRecord[]): OrganizationState {
  const byId = new Map<string, OrganizationDirectoryRecord>();
  const byRef = new Map<string, OrganizationDirectoryRecord>();
  const activeByExactName = new Map<string, OrganizationDirectoryRecord>();
  const ordered = [...organizations].sort((left, right) =>
    canonicalLegacyOrganizationId(left.legacyOrganizationId).localeCompare(canonicalLegacyOrganizationId(right.legacyOrganizationId))
  );
  for (const organization of ordered) {
    if (typeof organization.active !== "boolean") throw new Error("An organization has an invalid lifecycle state.");
    const id = canonicalLegacyOrganizationId(organization.legacyOrganizationId);
    const name = canonicalReconciliationToken(organization.name, "organization name");
    if (byId.has(id)) throw new Error("The organization directory contains a duplicate Legacy ID.");
    byId.set(id, organization);
    byRef.set(organizationRefForLegacyId(id), organization);
    if (organization.active) {
      if (activeByExactName.has(name)) throw new Error("The active organization directory contains an ambiguous name.");
      activeByExactName.set(name, organization);
    }
  }
  return { ordered, byId, byRef, activeByExactName };
}

function canonicalAuthorizationContextsForOrganizations(
  organizations: OrganizationState
): readonly Readonly<AuthorizationContext>[] {
  return Object.freeze([
    ...organizations.ordered.map((organization) =>
      authorizationContextForLegacyOrganizationId(organization.legacyOrganizationId)
    ),
    Object.freeze({
      contextKind: "platform-global" as const,
      contextRef: ORGANIZATION_RECONCILIATION_PLATFORM_GLOBAL_CONTEXT_REF
    }),
    Object.freeze({
      contextKind: "public" as const,
      contextRef: ORGANIZATION_RECONCILIATION_PUBLIC_CONTEXT_REF
    })
  ]);
}

function organizationForContextRef(
  organizations: OrganizationState,
  contextRef: string
): OrganizationDirectoryRecord {
  const organization = organizations.byRef.get(contextRef);
  if (!organization) throw new Error("An organization authorization context is unresolved.");
  return organization;
}

function authorizationContextKey(
  contextKind: AuthorizationContextKind,
  contextRef: string
): string {
  return `${contextKind}\u0000${contextRef}`;
}

function resolvePluginOrganizationRef(
  organizationName: string | null,
  organizations: OrganizationState
): string {
  if (organizationName === null) return ORGANIZATION_RECONCILIATION_PUBLIC_CONTEXT_REF;
  const exactName = canonicalReconciliationToken(organizationName, "plugin organization name");
  const organization = organizations.activeByExactName.get(exactName);
  if (!organization) throw new Error("A plugin organization binding is unresolved or inactive.");
  return organizationRefForLegacyId(organization.legacyOrganizationId);
}

function validatePlugin(plugin: OrganizationReconciliationPlugin): string {
  if (typeof plugin.enabled !== "boolean") throw new Error("A plugin has an invalid enabled state.");
  if (!(plugin.accessScope in ACCESS_SCOPE_LEVELS)) throw new Error("A plugin has an invalid access scope.");
  if (plugin.organizationName !== null && typeof plugin.organizationName !== "string") {
    throw new Error("A plugin has an invalid organization binding.");
  }
  return pluginRefForId(plugin.pluginId);
}

function highestRoleLevel(roles: ReadonlySet<string> | undefined): number {
  let level = 0;
  for (const role of roles ?? []) level = Math.max(level, ROLE_LEVELS[role] ?? 0);
  return level;
}

function canonicalSubjectRef(value: string): string {
  if (!isCanonicalLegacyUserSubjectRef(value)) {
    throw new Error("A projection subject ref is not a canonical Legacy user ref.");
  }
  return value;
}

function uniqueIndex<T>(records: readonly T[], keyFor: (record: T) => string): Map<string, T> {
  const index = new Map<string, T>();
  for (const record of records) {
    const key = keyFor(record);
    if (index.has(key)) throw new Error("The projection input contains a duplicate canonical key.");
    index.set(key, record);
  }
  return index;
}

function sortAndRejectDuplicateRecords<T>(records: T[], keyFor: (record: T) => string): T[] {
  records.sort((left, right) => keyFor(left).localeCompare(keyFor(right)));
  let previous: string | null = null;
  for (const record of records) {
    const key = keyFor(record);
    if (key === previous) throw new Error("The projection produced a duplicate canonical key.");
    previous = key;
  }
  return records;
}

function stableSerialize(value: unknown): string {
  if (value === null || typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("The projection catalog contains a non-finite number.");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(stableSerialize).join(",")}]`;
  if (typeof value !== "object" || value === undefined) {
    throw new Error("The projection catalog contains an unsupported value.");
  }
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stableSerialize(record[key])}`)
    .join(",")}}`;
}
