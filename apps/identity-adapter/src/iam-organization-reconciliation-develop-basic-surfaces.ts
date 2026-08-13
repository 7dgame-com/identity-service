import {
  ORGANIZATION_OWNER_DEVELOP_APPROVED_REGISTRY_CANDIDATE
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
  subjectRefForLegacyUserId
} from "./iam-organization-reconciliation-refs.js";
import type {
  IdentityOrganizationCandidateMysqlRawRecord,
  IdentityOrganizationIdMapMysqlRawRecord,
  IdentityOrganizationMembershipCandidateMysqlRawRecord,
  IdentityOrganizationMembershipCandidateSnapshotMysqlRawRecord,
  IdentityRoleAssignmentShadowMysqlRawRecord,
  IdentitySubjectUniverseMysqlRawRecord,
  LegacyOrganizationDirectoryMysqlRawRecord,
  LegacyOrganizationMembershipMysqlRawRecord,
  LegacyRoleAssignmentMysqlRawRecord
} from "./iam-organization-reconciliation/mysql-source-adapters/raw-source-snapshots.js";
import type {
  OrganizationDirectoryRecord,
  OrganizationMappingRecord,
  OrganizationMembershipRecord,
  OrganizationScopedRoleRecord
} from "./iam-organization-reconciliation-validator.js";

export const ORGANIZATION_RECONCILIATION_DEVELOP_BASIC_SURFACES_CONTRACT =
  "iam-organization-reconciliation-xrteeth-develop-basic-surfaces/v1" as const;
export const ORGANIZATION_RECONCILIATION_DEVELOP_BASIC_SURFACES_IMPLEMENTED = true as const;
export const ORGANIZATION_RECONCILIATION_DEVELOP_BASIC_SURFACES_READY = false as const;

export interface DevelopBasicSurfaces {
  readonly contract: typeof ORGANIZATION_RECONCILIATION_DEVELOP_BASIC_SURFACES_CONTRACT;
  readonly semanticRegistrySha256: string;
  readonly organizationDirectory: readonly OrganizationDirectoryRecord[];
  readonly organizationMappings: readonly OrganizationMappingRecord[];
  readonly memberships: readonly OrganizationMembershipRecord[];
  readonly organizationScopedRoles: readonly OrganizationScopedRoleRecord[];
  readonly blockers: readonly [
    "plugin-surfaces-not-ready",
    "operation-evidence-projector-not-production-registered",
    "runtime-pipeline-not-registered"
  ];
}

export function projectDevelopLegacyBasicSurfaces(
  view: LegacyDevelopProjectionSnapshotView,
  semanticRegistrySha256: string
): DevelopBasicSurfaces {
  assertLegacyDevelopProjectionSnapshotView(view);
  requireRegistry(semanticRegistrySha256);
  const organizations = rows<LegacyOrganizationDirectoryMysqlRawRecord>(view, "legacy-organization-directory");
  const memberships = rows<LegacyOrganizationMembershipMysqlRawRecord>(view, "legacy-membership");
  const roles = rows<LegacyRoleAssignmentMysqlRawRecord>(view, "legacy-role-assignment");
  return result(
    organizations.map((row) => ({
      legacyOrganizationId: row.legacyOrganizationId,
      name: row.name,
      title: row.title,
      active: true
    })),
    organizations.map((row) => ({
      legacyOrganizationId: row.legacyOrganizationId,
      identityOrganizationId: identityOrganizationIdForCanonicalLegacyId(row.legacyOrganizationId),
      active: true
    })),
    memberships.map((row) => ({
      subjectRef: subjectRefForLegacyUserId(row.legacyUserId),
      legacyOrganizationId: row.legacyOrganizationId,
      active: true
    })),
    projectScopedRoles(
      memberships,
      roles.map((row) => ({ legacyUserId: row.legacyUserId, roleName: row.roleName }))
    ),
    semanticRegistrySha256
  );
}

export function projectDevelopIdentityBasicSurfaces(
  view: IdentityDevelopProjectionSnapshotView,
  semanticRegistrySha256: string
): DevelopBasicSurfaces {
  assertIdentityDevelopProjectionSnapshotView(view);
  requireRegistry(semanticRegistrySha256);
  const subjects = rows<IdentitySubjectUniverseMysqlRawRecord>(view, "identity-subject-universe");
  const organizations = rows<IdentityOrganizationCandidateMysqlRawRecord>(view, "identity-organization-candidate");
  const mappings = rows<IdentityOrganizationIdMapMysqlRawRecord>(view, "identity-organization-id-map");
  const memberships = rows<IdentityOrganizationMembershipCandidateMysqlRawRecord>(view, "identity-membership-candidate");
  const roles = rows<IdentityRoleAssignmentShadowMysqlRawRecord>(view, "identity-role-shadow");
  validateMembershipSnapshots(
    subjects,
    memberships,
    rows<IdentityOrganizationMembershipCandidateSnapshotMysqlRawRecord>(
      view,
      "identity-membership-candidate-snapshot"
    ),
    roles
  );
  return result(
    organizations.map((row) => ({
      legacyOrganizationId: row.legacyOrganizationId,
      name: row.name,
      title: row.title,
      active: true
    })),
    mappings.map((row) => ({
      legacyOrganizationId: row.legacyOrganizationId,
      identityOrganizationId: row.identityOrganizationId,
      active: true
    })),
    memberships.map((row) => ({
      subjectRef: subjectRefForLegacyUserId(row.legacyUserId),
      legacyOrganizationId: row.legacyOrganizationId,
      active: true
    })),
    projectScopedRoles(
      memberships,
      roles.map((row) => ({ legacyUserId: row.legacyUserId, roleName: row.roleName }))
    ),
    semanticRegistrySha256
  );
}

function result(
  directory: readonly OrganizationDirectoryRecord[],
  mappings: readonly OrganizationMappingRecord[],
  memberships: readonly OrganizationMembershipRecord[],
  roles: readonly OrganizationScopedRoleRecord[],
  semanticRegistrySha256: string
): DevelopBasicSurfaces {
  return Object.freeze({
    contract: ORGANIZATION_RECONCILIATION_DEVELOP_BASIC_SURFACES_CONTRACT,
    semanticRegistrySha256,
    organizationDirectory: canonicalSort(directory, organizationIdKey),
    organizationMappings: canonicalSort(mappings, organizationIdKey),
    memberships: canonicalSort(memberships, membershipKey),
    organizationScopedRoles: canonicalSort(roles, scopedRoleKey),
    blockers: Object.freeze([
      "plugin-surfaces-not-ready",
      "operation-evidence-projector-not-production-registered",
      "runtime-pipeline-not-registered"
    ] as const)
  });
}

function projectScopedRoles(
  memberships: readonly Readonly<{ legacyUserId: string; legacyOrganizationId: string }>[],
  assignments: readonly Readonly<{ legacyUserId: string; roleName: string }>[]
): OrganizationScopedRoleRecord[] {
  const organizationsBySubject = new Map<string, string[]>();
  for (const membership of memberships) {
    const values = organizationsBySubject.get(membership.legacyUserId) ?? [];
    if (values.includes(membership.legacyOrganizationId)) throw new Error("A membership is duplicate.");
    values.push(membership.legacyOrganizationId);
    organizationsBySubject.set(membership.legacyUserId, values);
  }
  const seenAssignments = new Set<string>();
  const records: OrganizationScopedRoleRecord[] = [];
  for (const assignment of assignments) {
    if (!["root", "user", "admin", "manager"].includes(assignment.roleName)) {
      throw new Error("An unknown role cannot enter the approved organization-role projection.");
    }
    const assignmentKey = `${assignment.legacyUserId}\u0000${assignment.roleName}`;
    if (seenAssignments.has(assignmentKey)) throw new Error("A role assignment is duplicate.");
    seenAssignments.add(assignmentKey);
    if (assignment.roleName === "root" || assignment.roleName === "user") continue;
    for (const legacyOrganizationId of organizationsBySubject.get(assignment.legacyUserId) ?? []) {
      records.push(Object.freeze({
        subjectRef: subjectRefForLegacyUserId(assignment.legacyUserId),
        legacyOrganizationId,
        roleRef: assignment.roleName,
        active: true
      }));
    }
  }
  return records;
}

function validateMembershipSnapshots(
  subjects: readonly IdentitySubjectUniverseMysqlRawRecord[],
  memberships: readonly IdentityOrganizationMembershipCandidateMysqlRawRecord[],
  snapshots: readonly IdentityOrganizationMembershipCandidateSnapshotMysqlRawRecord[],
  roles: readonly IdentityRoleAssignmentShadowMysqlRawRecord[]
): void {
  const subjectIds = new Set(subjects.map((subject) => subject.legacyUserId));
  if (subjectIds.size !== subjects.length) throw new Error("The Identity subject universe is duplicate.");
  const snapshotBySubject = uniqueMap(snapshots, (snapshot) => snapshot.legacyUserId);
  const membershipsBySubject = group(memberships, (membership) => membership.legacyUserId);
  const protectedRootIds = new Set(
    roles.filter((role) => role.roleName === "root").map((role) => role.legacyUserId)
  );
  if ([...protectedRootIds].some((legacyUserId) => !subjectIds.has(legacyUserId))) {
    throw new Error("A protected Identity root is outside the approved subject universe.");
  }
  const expectedSnapshotIds = new Set(
    [...subjectIds].filter((legacyUserId) => !protectedRootIds.has(legacyUserId))
  );
  if (
    snapshotBySubject.size !== expectedSnapshotIds.size ||
    [...snapshotBySubject.keys()].some((legacyUserId) => !expectedSnapshotIds.has(legacyUserId))
  ) {
    throw new Error("The Identity membership snapshot universe is incomplete.");
  }
  if ([...protectedRootIds].some((legacyUserId) => (membershipsBySubject.get(legacyUserId) ?? []).length !== 0)) {
    throw new Error("A protected Identity root cannot enter the membership candidate surface.");
  }
  for (const legacyUserId of expectedSnapshotIds) {
    const snapshot = snapshotBySubject.get(legacyUserId);
    const values = membershipsBySubject.get(legacyUserId) ?? [];
    if (!snapshot || snapshot.organizationCount !== values.length ||
        values.some((membership) => membership.operationKey !== snapshot.operationKey)) {
      throw new Error("The Identity membership snapshot count or operation key is invalid.");
    }
  }
  if ([...membershipsBySubject.keys()].some((legacyUserId) => !subjectIds.has(legacyUserId))) {
    throw new Error("An Identity membership references a subject outside the approved universe.");
  }
}

function rows<T>(
  view: LegacyDevelopProjectionSnapshotView | IdentityDevelopProjectionSnapshotView,
  datasetId: string
): readonly T[] {
  const value = view.datasets[datasetId];
  if (!Array.isArray(value)) throw new Error(`The compiled dataset ${datasetId} is missing.`);
  return value as unknown as readonly T[];
}

function requireRegistry(value: string): void {
  if (value !== ORGANIZATION_OWNER_DEVELOP_APPROVED_REGISTRY_CANDIDATE.registrySha256) {
    throw new Error("The basic projector is not bound to the approved Develop semantic registry candidate.");
  }
}

function uniqueMap<T>(values: readonly T[], keyFor: (value: T) => string): Map<string, T> {
  const result = new Map<string, T>();
  for (const value of values) {
    const key = keyFor(value);
    if (result.has(key)) throw new Error("A compiled projection dataset contains a duplicate key.");
    result.set(key, value);
  }
  return result;
}

function group<T>(values: readonly T[], keyFor: (value: T) => string): Map<string, T[]> {
  const result = new Map<string, T[]>();
  for (const value of values) {
    const key = keyFor(value);
    const list = result.get(key) ?? [];
    list.push(value);
    result.set(key, list);
  }
  return result;
}

function canonicalSort<T>(values: readonly T[], keyFor: (value: T) => string): readonly T[] {
  const result = [...values].sort((left, right) => {
    const a = keyFor(left);
    const b = keyFor(right);
    return a < b ? -1 : a > b ? 1 : 0;
  });
  for (let index = 1; index < result.length; index += 1) {
    if (keyFor(result[index - 1]!) === keyFor(result[index]!)) {
      throw new Error("A projected basic surface contains a duplicate key.");
    }
  }
  return Object.freeze(result.map((value) => Object.freeze({ ...value })));
}

const organizationIdKey = (row: { readonly legacyOrganizationId: string | number }): string =>
  String(row.legacyOrganizationId).padStart(20, "0");
const membershipKey = (row: OrganizationMembershipRecord): string =>
  `${row.subjectRef}\u0000${String(row.legacyOrganizationId).padStart(20, "0")}`;
const scopedRoleKey = (row: OrganizationScopedRoleRecord): string =>
  `${membershipKey(row)}\u0000${row.roleRef}`;
