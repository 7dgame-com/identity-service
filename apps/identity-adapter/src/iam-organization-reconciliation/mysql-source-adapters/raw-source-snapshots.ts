import { createHash, randomBytes } from "node:crypto";
import { isProxy } from "node:util/types";
import {
  ORGANIZATION_RECONCILIATION_PAGINATION_MODE,
  ORGANIZATION_RECONCILIATION_SNAPSHOT_MODE
} from "../../iam-organization-reconciliation-collector.js";
import {
  ORGANIZATION_RECONCILIATION_MYSQL_STATEMENT_CATALOG_SHA256,
  openMysqlRepeatableReadSnapshot,
  type MysqlRepeatableReadSnapshotConnectionFactory,
  type MysqlRepeatableReadSnapshotOutcome,
  type MysqlRepeatableReadSnapshotSession,
  type MysqlSnapshotParameter,
  type OrganizationReconciliationMysqlStatementId
} from "../mysql-repeatable-read-snapshot.js";

export const ORGANIZATION_RECONCILIATION_MYSQL_RAW_ADAPTER_CONTRACT =
  "iam-organization-reconciliation-mysql-raw-source-adapters/v1" as const;

/**
 * Deliberate fail-closed gate. These primitives have no default connection,
 * environment lookup, or production binding. The missing contracts enumerated
 * by organizationReconciliationMysqlRawAdapterReadiness must be closed first.
 */
export const ORGANIZATION_RECONCILIATION_MYSQL_RAW_SOURCE_ADAPTERS_READY = false as const;

export const ORGANIZATION_RECONCILIATION_MYSQL_RAW_COMPONENT_IDS = Object.freeze({
  legacyMain: "legacy-main",
  identity: "identity",
  plugin: "plugin"
} as const);

export interface OrganizationReconciliationMysqlRawAdapterReadiness {
  readonly ready: false;
  readonly blockers: readonly [
    "runtime-source-adapter-wiring-disabled",
    "compiled-owner-dataset-catalog-not-registered",
    "trusted-physical-source-binding-not-registered",
    "identity-dataset-source-status-selectors-not-owner-approved",
    "identity-shadow-versus-candidate-read-model-not-owner-approved",
    "plugin-registry-schema-version-not-owner-approved",
    "plugin-static-overlay-precedence-not-owner-approved",
    "mysql-collation-and-ordering-not-owner-approved"
  ];
}

export function organizationReconciliationMysqlRawAdapterReadiness():
OrganizationReconciliationMysqlRawAdapterReadiness {
  return Object.freeze({
    ready: ORGANIZATION_RECONCILIATION_MYSQL_RAW_SOURCE_ADAPTERS_READY,
    blockers: Object.freeze([
      "runtime-source-adapter-wiring-disabled",
      "compiled-owner-dataset-catalog-not-registered",
      "trusted-physical-source-binding-not-registered",
      "identity-dataset-source-status-selectors-not-owner-approved",
      "identity-shadow-versus-candidate-read-model-not-owner-approved",
      "plugin-registry-schema-version-not-owner-approved",
      "plugin-static-overlay-precedence-not-owner-approved",
      "mysql-collation-and-ordering-not-owner-approved"
    ] as const)
  });
}

export type OrganizationReconciliationMysqlRawComponentId =
  (typeof ORGANIZATION_RECONCILIATION_MYSQL_RAW_COMPONENT_IDS)[keyof typeof ORGANIZATION_RECONCILIATION_MYSQL_RAW_COMPONENT_IDS];

export type OrganizationReconciliationMysqlRawSurface =
  | "legacy-organization-directory"
  | "legacy-subject-universe"
  | "legacy-membership"
  | "legacy-role-assignment"
  | "legacy-rbac-edge"
  | "identity-subject-universe"
  | "identity-organization-candidate"
  | "identity-organization-id-map"
  | "identity-membership-shadow"
  | "identity-membership-candidate"
  | "identity-role-shadow"
  | "plugin-registry";

export interface OpenOrganizationReconciliationMysqlRawSnapshotOptions {
  /** Opaque physical source ID expected by the coordinator wiring. */
  readonly expectedSourceId: string;
  readonly connectionFactory: MysqlRepeatableReadSnapshotConnectionFactory;
}

export interface OrganizationReconciliationMysqlRawSnapshotMetadata {
  readonly contract: typeof ORGANIZATION_RECONCILIATION_MYSQL_RAW_ADAPTER_CONTRACT;
  readonly componentId: OrganizationReconciliationMysqlRawComponentId;
  readonly sourceId: string;
  readonly snapshotMode: typeof ORGANIZATION_RECONCILIATION_SNAPSHOT_MODE;
  readonly paginationMode: typeof ORGANIZATION_RECONCILIATION_PAGINATION_MODE;
  readonly statementCatalogSha256: string;
}

export interface OrganizationReconciliationMysqlRawPageRequest {
  readonly requestCursor: string | null;
  readonly pageSize: number;
}

export interface OrganizationReconciliationMysqlRawPage<
  TSurface extends OrganizationReconciliationMysqlRawSurface,
  TRecord
> extends OrganizationReconciliationMysqlRawSnapshotMetadata {
  readonly surface: TSurface;
  readonly statementId: OrganizationReconciliationMysqlStatementId;
  readonly requestCursor: string | null;
  readonly nextCursor: string | null;
  readonly recordOffset: number;
  readonly records: readonly Readonly<TRecord>[];
}

export interface LegacyOrganizationDirectoryMysqlRawRecord {
  readonly legacyOrganizationId: string;
  readonly name: string;
  readonly title: string;
  readonly createdAt: number;
  readonly updatedAt: number;
}

export interface LegacySubjectUniverseMysqlRawRecord {
  readonly legacyUserId: string;
  readonly status: number;
}

export interface LegacyOrganizationMembershipMysqlRawRecord {
  readonly legacyUserId: string;
  readonly legacyOrganizationId: string;
}

export interface LegacyRoleAssignmentMysqlRawRecord {
  readonly legacyUserId: string;
  readonly roleName: string;
}

export interface LegacyRbacEdgeMysqlRawRecord {
  readonly parentName: string;
  readonly childName: string;
}

export interface IdentityOrganizationCandidateMysqlRawRecord {
  readonly legacyOrganizationId: string;
  readonly identityOrganizationId: string;
  readonly name: string;
  readonly title: string;
  readonly candidateStatus: "candidate";
}

export interface IdentitySubjectUniverseMysqlRawRecord {
  readonly legacyUserId: string;
  readonly status: string;
  readonly source: string;
}

export interface IdentityOrganizationIdMapMysqlRawRecord {
  readonly legacyOrganizationId: string;
  readonly identityOrganizationId: string;
  readonly mappingStatus: "active";
}

export interface IdentityOrganizationMembershipShadowMysqlRawRecord {
  readonly legacyUserId: string;
  readonly legacyOrganizationId: string;
  readonly organizationRole: string | null;
  readonly status: "shadow";
}

export interface IdentityOrganizationMembershipCandidateMysqlRawRecord {
  readonly legacyUserId: string;
  readonly legacyOrganizationId: string;
  readonly identityUserId: string;
  readonly identityOrganizationId: string;
  readonly organizationRole: "member";
  readonly candidateStatus: "candidate";
}

export interface IdentityRoleAssignmentShadowMysqlRawRecord {
  readonly legacyUserId: string;
  readonly roleName: string;
  readonly status: "shadow";
}

export type OrganizationReconciliationPluginAccessScope =
  | "auth-only"
  | "manager-only"
  | "admin-only"
  | "root-only";

export interface PluginRegistryMysqlRawRecord {
  readonly pluginId: string;
  readonly enabled: boolean;
  readonly accessScope: OrganizationReconciliationPluginAccessScope;
  readonly organizationName: string | null;
}

interface OrganizationReconciliationMysqlRawSnapshotBase {
  readonly metadata: OrganizationReconciliationMysqlRawSnapshotMetadata;
  close(outcome: MysqlRepeatableReadSnapshotOutcome): Promise<void>;
}

export interface LegacyMainMysqlRawSnapshot
  extends OrganizationReconciliationMysqlRawSnapshotBase {
  readOrganizationDirectoryPage(
    request: OrganizationReconciliationMysqlRawPageRequest
  ): Promise<OrganizationReconciliationMysqlRawPage<
    "legacy-organization-directory",
    LegacyOrganizationDirectoryMysqlRawRecord
  >>;
  readSubjectUniversePage(
    request: OrganizationReconciliationMysqlRawPageRequest
  ): Promise<OrganizationReconciliationMysqlRawPage<
    "legacy-subject-universe",
    LegacySubjectUniverseMysqlRawRecord
  >>;
  readMembershipPage(
    request: OrganizationReconciliationMysqlRawPageRequest
  ): Promise<OrganizationReconciliationMysqlRawPage<
    "legacy-membership",
    LegacyOrganizationMembershipMysqlRawRecord
  >>;
  readRoleAssignmentPage(
    request: OrganizationReconciliationMysqlRawPageRequest
  ): Promise<OrganizationReconciliationMysqlRawPage<
    "legacy-role-assignment",
    LegacyRoleAssignmentMysqlRawRecord
  >>;
  readRbacEdgePage(
    request: OrganizationReconciliationMysqlRawPageRequest
  ): Promise<OrganizationReconciliationMysqlRawPage<
    "legacy-rbac-edge",
    LegacyRbacEdgeMysqlRawRecord
  >>;
}

export interface IdentityMysqlRawSnapshot
  extends OrganizationReconciliationMysqlRawSnapshotBase {
  readSubjectUniversePage(
    request: OrganizationReconciliationMysqlRawPageRequest
  ): Promise<OrganizationReconciliationMysqlRawPage<
    "identity-subject-universe",
    IdentitySubjectUniverseMysqlRawRecord
  >>;
  readOrganizationCandidatePage(
    request: OrganizationReconciliationMysqlRawPageRequest
  ): Promise<OrganizationReconciliationMysqlRawPage<
    "identity-organization-candidate",
    IdentityOrganizationCandidateMysqlRawRecord
  >>;
  readOrganizationIdMapPage(
    request: OrganizationReconciliationMysqlRawPageRequest
  ): Promise<OrganizationReconciliationMysqlRawPage<
    "identity-organization-id-map",
    IdentityOrganizationIdMapMysqlRawRecord
  >>;
  readMembershipShadowPage(
    request: OrganizationReconciliationMysqlRawPageRequest
  ): Promise<OrganizationReconciliationMysqlRawPage<
    "identity-membership-shadow",
    IdentityOrganizationMembershipShadowMysqlRawRecord
  >>;
  readMembershipCandidatePage(
    request: OrganizationReconciliationMysqlRawPageRequest
  ): Promise<OrganizationReconciliationMysqlRawPage<
    "identity-membership-candidate",
    IdentityOrganizationMembershipCandidateMysqlRawRecord
  >>;
  readRoleShadowPage(
    request: OrganizationReconciliationMysqlRawPageRequest
  ): Promise<OrganizationReconciliationMysqlRawPage<
    "identity-role-shadow",
    IdentityRoleAssignmentShadowMysqlRawRecord
  >>;
}

export interface PluginRegistryMysqlRawSnapshot
  extends OrganizationReconciliationMysqlRawSnapshotBase {
  readPluginRegistryPage(
    request: OrganizationReconciliationMysqlRawPageRequest
  ): Promise<OrganizationReconciliationMysqlRawPage<
    "plugin-registry",
    PluginRegistryMysqlRawRecord
  >>;
}

type AnyRawRecord =
  | LegacyOrganizationDirectoryMysqlRawRecord
  | LegacySubjectUniverseMysqlRawRecord
  | LegacyOrganizationMembershipMysqlRawRecord
  | LegacyRoleAssignmentMysqlRawRecord
  | LegacyRbacEdgeMysqlRawRecord
  | IdentitySubjectUniverseMysqlRawRecord
  | IdentityOrganizationCandidateMysqlRawRecord
  | IdentityOrganizationIdMapMysqlRawRecord
  | IdentityOrganizationMembershipShadowMysqlRawRecord
  | IdentityOrganizationMembershipCandidateMysqlRawRecord
  | IdentityRoleAssignmentShadowMysqlRawRecord
  | PluginRegistryMysqlRawRecord;

interface SurfaceDefinition<
  TSurface extends OrganizationReconciliationMysqlRawSurface,
  TRecord extends AnyRawRecord
> {
  readonly surface: TSurface;
  readonly statementId: OrganizationReconciliationMysqlStatementId;
  readonly initialCursorValues: readonly MysqlSnapshotParameter[];
  decode(candidate: unknown): Readonly<TRecord>;
  cursorValues(record: Readonly<TRecord>): readonly MysqlSnapshotParameter[];
  queryParameters(
    cursorValues: readonly MysqlSnapshotParameter[],
    pageSize: number
  ): readonly MysqlSnapshotParameter[];
  orderKey(record: Readonly<TRecord>): string;
}

interface SurfaceState {
  readonly surface: OrganizationReconciliationMysqlRawSurface;
  started: boolean;
  exhausted: boolean;
  expectedCursor: string | null;
  recordOffset: number;
  pageSize: number | null;
  cursorValues: readonly MysqlSnapshotParameter[];
  lastOrderKey: string | null;
}

interface ValidatedOpenDependencies {
  readonly sourceId: string;
  readonly connectionFactory: MysqlRepeatableReadSnapshotConnectionFactory;
}

const LEGACY_DIRECTORY = defineSurface({
  surface: "legacy-organization-directory",
  statementId: "legacy-organization-directory-page/v1",
  initialCursorValues: [0],
  decode: decodeLegacyOrganizationDirectory,
  cursorValues: (record) => [record.legacyOrganizationId],
  queryParameters: singleKeyParameters,
  orderKey: (record) => numericOrderKey(record.legacyOrganizationId)
});

const LEGACY_SUBJECTS = defineSurface({
  surface: "legacy-subject-universe",
  statementId: "legacy-subject-universe-page/v1",
  initialCursorValues: [0],
  decode: decodeLegacySubjectUniverse,
  cursorValues: (record) => [record.legacyUserId],
  queryParameters: singleKeyParameters,
  orderKey: (record) => numericOrderKey(record.legacyUserId)
});

const LEGACY_MEMBERSHIPS = defineSurface({
  surface: "legacy-membership",
  statementId: "legacy-membership-page/v1",
  initialCursorValues: [0, 0],
  decode: decodeLegacyMembership,
  cursorValues: (record) => [record.legacyUserId, record.legacyOrganizationId],
  queryParameters: twoPartNumericParameters,
  orderKey: (record) => tupleOrderKey(
    numericOrderKey(record.legacyUserId),
    numericOrderKey(record.legacyOrganizationId)
  )
});

const LEGACY_ROLES = defineSurface({
  surface: "legacy-role-assignment",
  statementId: "legacy-role-assignment-page/v1",
  initialCursorValues: [0, ""],
  decode: decodeLegacyRoleAssignment,
  cursorValues: (record) => [record.legacyUserId, record.roleName],
  queryParameters: twoPartStringParameters,
  orderKey: (record) => tupleOrderKey(numericOrderKey(record.legacyUserId), record.roleName)
});

const LEGACY_RBAC_EDGES = defineSurface({
  surface: "legacy-rbac-edge",
  statementId: "legacy-rbac-edge-page/v1",
  initialCursorValues: ["", ""],
  decode: decodeLegacyRbacEdge,
  cursorValues: (record) => [record.parentName, record.childName],
  queryParameters: twoPartStringParameters,
  orderKey: (record) => tupleOrderKey(
    utf8ByteOrderKey(record.parentName),
    utf8ByteOrderKey(record.childName)
  )
});

const IDENTITY_SUBJECTS = defineSurface({
  surface: "identity-subject-universe",
  statementId: "identity-subject-universe-page/v1",
  initialCursorValues: [0],
  decode: decodeIdentitySubjectUniverse,
  cursorValues: (record) => [record.legacyUserId],
  queryParameters: singleKeyParameters,
  orderKey: (record) => numericOrderKey(record.legacyUserId)
});

const IDENTITY_ORGANIZATIONS = defineSurface({
  surface: "identity-organization-candidate",
  statementId: "identity-organization-candidate-page/v1",
  initialCursorValues: [0],
  decode: decodeIdentityOrganizationCandidate,
  cursorValues: (record) => [record.legacyOrganizationId],
  queryParameters: singleKeyParameters,
  orderKey: (record) => numericOrderKey(record.legacyOrganizationId)
});

const IDENTITY_ORGANIZATION_MAP = defineSurface({
  surface: "identity-organization-id-map",
  statementId: "identity-organization-id-map-page/v1",
  initialCursorValues: [0],
  decode: decodeIdentityOrganizationIdMap,
  cursorValues: (record) => [record.legacyOrganizationId],
  queryParameters: singleKeyParameters,
  orderKey: (record) => numericOrderKey(record.legacyOrganizationId)
});

const IDENTITY_MEMBERSHIP_SHADOW = defineSurface({
  surface: "identity-membership-shadow",
  statementId: "identity-membership-shadow-page/v1",
  initialCursorValues: [0, 0],
  decode: decodeIdentityMembershipShadow,
  cursorValues: (record) => [record.legacyUserId, record.legacyOrganizationId],
  queryParameters: twoPartNumericParameters,
  orderKey: (record) => tupleOrderKey(
    numericOrderKey(record.legacyUserId),
    numericOrderKey(record.legacyOrganizationId)
  )
});

const IDENTITY_MEMBERSHIP_CANDIDATE = defineSurface({
  surface: "identity-membership-candidate",
  statementId: "identity-membership-candidate-page/v1",
  initialCursorValues: [0, 0, "", ""],
  decode: decodeIdentityMembershipCandidate,
  cursorValues: (record) => [
    record.legacyUserId,
    record.legacyOrganizationId,
    record.identityUserId,
    record.identityOrganizationId
  ],
  queryParameters: fourPartCandidateMembershipParameters,
  orderKey: (record) => tupleOrderKey(
    numericOrderKey(record.legacyUserId),
    numericOrderKey(record.legacyOrganizationId),
    record.identityUserId,
    record.identityOrganizationId
  )
});

const IDENTITY_ROLE_SHADOW = defineSurface({
  surface: "identity-role-shadow",
  statementId: "identity-role-shadow-page/v1",
  initialCursorValues: [0, ""],
  decode: decodeIdentityRoleShadow,
  cursorValues: (record) => [record.legacyUserId, record.roleName],
  queryParameters: twoPartStringParameters,
  orderKey: (record) => tupleOrderKey(numericOrderKey(record.legacyUserId), record.roleName)
});

const PLUGIN_REGISTRY = defineSurface({
  surface: "plugin-registry",
  statementId: "plugin-registry-page/v1",
  initialCursorValues: [""],
  decode: decodePluginRegistry,
  cursorValues: (record) => [record.pluginId],
  queryParameters: singleKeyParameters,
  orderKey: (record) => record.pluginId
});

export async function openLegacyMainMysqlRawSnapshot(
  options: OpenOrganizationReconciliationMysqlRawSnapshotOptions
): Promise<LegacyMainMysqlRawSnapshot> {
  const core = await openRawSnapshot(ORGANIZATION_RECONCILIATION_MYSQL_RAW_COMPONENT_IDS.legacyMain, options);
  return Object.freeze({
    metadata: core.metadata,
    readOrganizationDirectoryPage: (request: OrganizationReconciliationMysqlRawPageRequest) =>
      core.read(LEGACY_DIRECTORY, request),
    readSubjectUniversePage: (request: OrganizationReconciliationMysqlRawPageRequest) =>
      core.read(LEGACY_SUBJECTS, request),
    readMembershipPage: (request: OrganizationReconciliationMysqlRawPageRequest) =>
      core.read(LEGACY_MEMBERSHIPS, request),
    readRoleAssignmentPage: (request: OrganizationReconciliationMysqlRawPageRequest) =>
      core.read(LEGACY_ROLES, request),
    readRbacEdgePage: (request: OrganizationReconciliationMysqlRawPageRequest) =>
      core.read(LEGACY_RBAC_EDGES, request),
    close: (outcome: MysqlRepeatableReadSnapshotOutcome) => core.close(outcome)
  });
}

export async function openIdentityMysqlRawSnapshot(
  options: OpenOrganizationReconciliationMysqlRawSnapshotOptions
): Promise<IdentityMysqlRawSnapshot> {
  const core = await openRawSnapshot(ORGANIZATION_RECONCILIATION_MYSQL_RAW_COMPONENT_IDS.identity, options);
  return Object.freeze({
    metadata: core.metadata,
    readSubjectUniversePage: (request: OrganizationReconciliationMysqlRawPageRequest) =>
      core.read(IDENTITY_SUBJECTS, request),
    readOrganizationCandidatePage: (request: OrganizationReconciliationMysqlRawPageRequest) =>
      core.read(IDENTITY_ORGANIZATIONS, request),
    readOrganizationIdMapPage: (request: OrganizationReconciliationMysqlRawPageRequest) =>
      core.read(IDENTITY_ORGANIZATION_MAP, request),
    readMembershipShadowPage: (request: OrganizationReconciliationMysqlRawPageRequest) =>
      core.read(IDENTITY_MEMBERSHIP_SHADOW, request),
    readMembershipCandidatePage: (request: OrganizationReconciliationMysqlRawPageRequest) =>
      core.read(IDENTITY_MEMBERSHIP_CANDIDATE, request),
    readRoleShadowPage: (request: OrganizationReconciliationMysqlRawPageRequest) =>
      core.read(IDENTITY_ROLE_SHADOW, request),
    close: (outcome: MysqlRepeatableReadSnapshotOutcome) => core.close(outcome)
  });
}

export async function openPluginRegistryMysqlRawSnapshot(
  options: OpenOrganizationReconciliationMysqlRawSnapshotOptions
): Promise<PluginRegistryMysqlRawSnapshot> {
  const core = await openRawSnapshot(ORGANIZATION_RECONCILIATION_MYSQL_RAW_COMPONENT_IDS.plugin, options);
  return Object.freeze({
    metadata: core.metadata,
    readPluginRegistryPage: (request: OrganizationReconciliationMysqlRawPageRequest) =>
      core.read(PLUGIN_REGISTRY, request),
    close: (outcome: MysqlRepeatableReadSnapshotOutcome) => core.close(outcome)
  });
}

class MysqlRawSnapshotCore {
  readonly metadata: OrganizationReconciliationMysqlRawSnapshotMetadata;
  private readonly states = new Map<OrganizationReconciliationMysqlRawSurface, SurfaceState>();
  private operationTail: Promise<void> = Promise.resolve();
  private poisoned = false;
  private closing = false;
  private closePromise: Promise<void> | null = null;

  constructor(
    private readonly session: MysqlRepeatableReadSnapshotSession,
    metadata: OrganizationReconciliationMysqlRawSnapshotMetadata,
    private readonly transactionHandleId: string
  ) {
    this.metadata = Object.freeze({ ...metadata });
  }

  read<TSurface extends OrganizationReconciliationMysqlRawSurface, TRecord extends AnyRawRecord>(
    definition: SurfaceDefinition<TSurface, TRecord>,
    request: OrganizationReconciliationMysqlRawPageRequest
  ): Promise<OrganizationReconciliationMysqlRawPage<TSurface, TRecord>> {
    if (this.closing) return Promise.reject(new Error(closedFailure(this.metadata.componentId)));
    const operation = this.operationTail.then(() => this.readNow(definition, request));
    this.operationTail = operation.then(() => undefined, () => undefined);
    return operation.catch(() => {
      this.poisoned = true;
      throw new Error(readFailure(this.metadata.componentId));
    });
  }

  close(outcome: MysqlRepeatableReadSnapshotOutcome): Promise<void> {
    if (this.closePromise !== null) return this.closePromise;
    this.closing = true;
    this.closePromise = this.finishClose(outcome);
    return this.closePromise;
  }

  private async readNow<
    TSurface extends OrganizationReconciliationMysqlRawSurface,
    TRecord extends AnyRawRecord
  >(
    definition: SurfaceDefinition<TSurface, TRecord>,
    request: OrganizationReconciliationMysqlRawPageRequest
  ): Promise<OrganizationReconciliationMysqlRawPage<TSurface, TRecord>> {
    if (this.poisoned) throw new Error("poisoned source");
    const validatedRequest = validatePageRequest(request);
    const state = this.getState(definition);
    if (state.exhausted) throw new Error("surface exhausted");
    if (validatedRequest.requestCursor !== state.expectedCursor) {
      throw new Error("cursor chain mismatch");
    }
    if (state.pageSize !== null && validatedRequest.pageSize !== state.pageSize) {
      throw new Error("page size changed");
    }

    const parameters = definition.queryParameters(state.cursorValues, validatedRequest.pageSize);
    const candidateRows = await this.session.query<unknown>(definition.statementId, parameters);
    if (!Array.isArray(candidateRows) || candidateRows.length > validatedRequest.pageSize) {
      throw new Error("invalid row set");
    }

    const records: Array<Readonly<TRecord>> = [];
    let lastOrderKey = state.lastOrderKey;
    for (const candidate of candidateRows) {
      const record = definition.decode(candidate);
      const orderKey = definition.orderKey(record);
      if (lastOrderKey !== null && orderKey <= lastOrderKey) {
        throw new Error("non-canonical source order");
      }
      lastOrderKey = orderKey;
      records.push(record);
    }

    const nextOffset = state.recordOffset + records.length;
    if (!Number.isSafeInteger(nextOffset) || nextOffset > 10_000_000) {
      throw new Error("source bound exceeded");
    }
    const hasContinuation = records.length === validatedRequest.pageSize;
    const nextCursorValues = records.length > 0
      ? definition.cursorValues(records.at(-1)!)
      : state.cursorValues;
    const nextCursor = hasContinuation
      ? createOpaqueCursor(this.metadata, this.transactionHandleId, definition.surface, nextOffset, nextCursorValues)
      : null;

    const page = Object.freeze({
      ...this.metadata,
      surface: definition.surface,
      statementId: definition.statementId,
      requestCursor: validatedRequest.requestCursor,
      nextCursor,
      recordOffset: state.recordOffset,
      records: Object.freeze(records)
    });

    state.started = true;
    state.exhausted = nextCursor === null;
    state.expectedCursor = nextCursor;
    state.recordOffset = nextOffset;
    state.pageSize ??= validatedRequest.pageSize;
    state.cursorValues = Object.freeze([...nextCursorValues]);
    state.lastOrderKey = lastOrderKey;
    return page;
  }

  private getState<TSurface extends OrganizationReconciliationMysqlRawSurface, TRecord extends AnyRawRecord>(
    definition: SurfaceDefinition<TSurface, TRecord>
  ): SurfaceState {
    const existing = this.states.get(definition.surface);
    if (existing) return existing;
    const created: SurfaceState = {
      surface: definition.surface,
      started: false,
      exhausted: false,
      expectedCursor: null,
      recordOffset: 0,
      pageSize: null,
      cursorValues: Object.freeze([...definition.initialCursorValues]),
      lastOrderKey: null
    };
    this.states.set(definition.surface, created);
    return created;
  }

  private async finishClose(outcome: MysqlRepeatableReadSnapshotOutcome): Promise<void> {
    let failed = outcome !== "completed" && outcome !== "failed";
    try {
      await this.operationTail;
      const underlyingOutcome = outcome === "completed" && !this.poisoned ? "completed" : "failed";
      await this.session.close(underlyingOutcome);
      if (outcome === "completed" && this.poisoned) failed = true;
    } catch {
      failed = true;
    }
    if (failed) throw new Error(closeFailure(this.metadata.componentId));
  }
}

async function openRawSnapshot(
  componentId: OrganizationReconciliationMysqlRawComponentId,
  options: OpenOrganizationReconciliationMysqlRawSnapshotOptions
): Promise<MysqlRawSnapshotCore> {
  let session: MysqlRepeatableReadSnapshotSession | null = null;
  try {
    const dependencies = validateOpenDependencies(options);
    session = await openMysqlRepeatableReadSnapshot(dependencies.connectionFactory);
    return new MysqlRawSnapshotCore(session, {
      contract: ORGANIZATION_RECONCILIATION_MYSQL_RAW_ADAPTER_CONTRACT,
      componentId,
      sourceId: dependencies.sourceId,
      snapshotMode: ORGANIZATION_RECONCILIATION_SNAPSHOT_MODE,
      paginationMode: ORGANIZATION_RECONCILIATION_PAGINATION_MODE,
      statementCatalogSha256: ORGANIZATION_RECONCILIATION_MYSQL_STATEMENT_CATALOG_SHA256
    }, randomBytes(32).toString("hex"));
  } catch {
    if (session !== null) await session.close("failed").catch(() => undefined);
    throw new Error(openFailure(componentId));
  }
}

function validateOpenDependencies(candidate: unknown): ValidatedOpenDependencies {
  const options = exactRecord(candidate, ["expectedSourceId", "connectionFactory"]);
  if (typeof options.connectionFactory !== "function") {
    throw new Error("invalid dependencies");
  }
  return Object.freeze({
    sourceId: canonicalMetadata(options.expectedSourceId),
    connectionFactory: options.connectionFactory as MysqlRepeatableReadSnapshotConnectionFactory
  });
}

function validatePageRequest(candidate: unknown): OrganizationReconciliationMysqlRawPageRequest {
  const request = exactRecord(candidate, ["requestCursor", "pageSize"]);
  const requestCursor = request.requestCursor;
  if (requestCursor !== null) canonicalCursor(requestCursor);
  if (typeof request.pageSize !== "number" || !Number.isSafeInteger(request.pageSize) ||
    request.pageSize < 1 || request.pageSize > 5_000) {
    throw new Error("invalid page size");
  }
  return { requestCursor: requestCursor as string | null, pageSize: request.pageSize };
}

function createOpaqueCursor(
  metadata: OrganizationReconciliationMysqlRawSnapshotMetadata,
  transactionHandleId: string,
  surface: OrganizationReconciliationMysqlRawSurface,
  offset: number,
  cursorValues: readonly MysqlSnapshotParameter[]
): string {
  return createHash("sha256")
    .update("iam-organization-reconciliation:mysql-raw-cursor:v1\u001f", "utf8")
    .update(JSON.stringify({
      contract: metadata.contract,
      sourceId: metadata.sourceId,
      transactionHandleId,
      statementCatalogSha256: metadata.statementCatalogSha256,
      surface,
      offset,
      cursorValues: cursorValues.map((value) => typeof value === "bigint" ? value.toString(10) : value)
    }), "utf8")
    .digest("base64url");
}

function defineSurface<
  TSurface extends OrganizationReconciliationMysqlRawSurface,
  TRecord extends AnyRawRecord
>(definition: SurfaceDefinition<TSurface, TRecord>): SurfaceDefinition<TSurface, TRecord> {
  return Object.freeze({
    ...definition,
    initialCursorValues: Object.freeze([...definition.initialCursorValues])
  });
}

function singleKeyParameters(
  cursor: readonly MysqlSnapshotParameter[],
  pageSize: number
): readonly MysqlSnapshotParameter[] {
  requireCursorTuple(cursor, 1);
  return [cursor[0]!, pageSize];
}

function twoPartNumericParameters(
  cursor: readonly MysqlSnapshotParameter[],
  pageSize: number
): readonly MysqlSnapshotParameter[] {
  requireCursorTuple(cursor, 2);
  return [cursor[0]!, cursor[0]!, cursor[1]!, pageSize];
}

function twoPartStringParameters(
  cursor: readonly MysqlSnapshotParameter[],
  pageSize: number
): readonly MysqlSnapshotParameter[] {
  requireCursorTuple(cursor, 2);
  return [cursor[0]!, cursor[0]!, cursor[1]!, pageSize];
}

function fourPartCandidateMembershipParameters(
  cursor: readonly MysqlSnapshotParameter[],
  pageSize: number
): readonly MysqlSnapshotParameter[] {
  requireCursorTuple(cursor, 4);
  const [legacyUserId, legacyOrganizationId, identityUserId, identityOrganizationId] = cursor;
  return [
    legacyUserId!, legacyUserId!, legacyOrganizationId!,
    legacyUserId!, legacyOrganizationId!, identityUserId!,
    legacyUserId!, legacyOrganizationId!, identityUserId!, identityOrganizationId!,
    pageSize
  ];
}

function requireCursorTuple(cursor: readonly MysqlSnapshotParameter[], length: number): void {
  if (!Array.isArray(cursor) || cursor.length !== length) throw new Error("invalid private cursor");
}

function decodeLegacyOrganizationDirectory(candidate: unknown): Readonly<LegacyOrganizationDirectoryMysqlRawRecord> {
  const row = exactRecord(candidate, ["id", "name", "title", "created_at", "updated_at"]);
  return Object.freeze({
    legacyOrganizationId: positiveId(row.id),
    name: organizationName(row.name),
    title: canonicalText(row.title, 255),
    createdAt: nonNegativeSafeInteger(row.created_at),
    updatedAt: nonNegativeSafeInteger(row.updated_at)
  });
}

function decodeLegacySubjectUniverse(candidate: unknown): Readonly<LegacySubjectUniverseMysqlRawRecord> {
  const row = exactRecord(candidate, ["id", "status"]);
  return Object.freeze({
    legacyUserId: positiveId(row.id),
    status: nonNegativeSafeInteger(row.status)
  });
}

function decodeLegacyMembership(candidate: unknown): Readonly<LegacyOrganizationMembershipMysqlRawRecord> {
  const row = exactRecord(candidate, ["user_id", "organization_id"]);
  return Object.freeze({
    legacyUserId: positiveId(row.user_id),
    legacyOrganizationId: positiveId(row.organization_id)
  });
}

function decodeLegacyRoleAssignment(candidate: unknown): Readonly<LegacyRoleAssignmentMysqlRawRecord> {
  const row = exactRecord(candidate, ["user_id", "item_name"]);
  return Object.freeze({
    legacyUserId: positiveId(row.user_id),
    roleName: canonicalText(row.item_name, 128)
  });
}

function decodeLegacyRbacEdge(candidate: unknown): Readonly<LegacyRbacEdgeMysqlRawRecord> {
  if (candidate !== null && typeof candidate === "object" && isProxy(candidate)) {
    throw new Error("invalid row proxy");
  }
  const row = exactRecord(candidate, ["parent", "child"]);
  return Object.freeze({
    parentName: canonicalText(row.parent, 64),
    childName: canonicalText(row.child, 64)
  });
}

function decodeIdentitySubjectUniverse(candidate: unknown): Readonly<IdentitySubjectUniverseMysqlRawRecord> {
  const row = exactRecord(candidate, ["legacy_user_id", "status", "source"]);
  return Object.freeze({
    legacyUserId: positiveId(row.legacy_user_id),
    status: canonicalText(row.status, 32),
    source: canonicalText(row.source, 64)
  });
}

function decodeIdentityOrganizationCandidate(candidate: unknown): Readonly<IdentityOrganizationCandidateMysqlRawRecord> {
  const row = exactRecord(candidate, [
    "legacy_organization_id", "identity_organization_id", "name", "title", "candidate_status"
  ]);
  return Object.freeze({
    legacyOrganizationId: positiveId(row.legacy_organization_id),
    identityOrganizationId: canonicalText(row.identity_organization_id, 128),
    name: organizationName(row.name),
    title: canonicalText(row.title, 255),
    candidateStatus: exactLiteral(row.candidate_status, "candidate")
  });
}

function decodeIdentityOrganizationIdMap(candidate: unknown): Readonly<IdentityOrganizationIdMapMysqlRawRecord> {
  const row = exactRecord(candidate, [
    "legacy_organization_id", "identity_organization_id", "mapping_status"
  ]);
  return Object.freeze({
    legacyOrganizationId: positiveId(row.legacy_organization_id),
    identityOrganizationId: canonicalText(row.identity_organization_id, 128),
    mappingStatus: exactLiteral(row.mapping_status, "active")
  });
}

function decodeIdentityMembershipShadow(candidate: unknown): Readonly<IdentityOrganizationMembershipShadowMysqlRawRecord> {
  const row = exactRecord(candidate, [
    "legacy_user_id", "organization_id", "organization_role", "status"
  ]);
  return Object.freeze({
    legacyUserId: positiveId(row.legacy_user_id),
    legacyOrganizationId: positiveId(row.organization_id),
    organizationRole: nullableCanonicalText(row.organization_role, 128),
    status: exactLiteral(row.status, "shadow")
  });
}

function decodeIdentityMembershipCandidate(candidate: unknown): Readonly<IdentityOrganizationMembershipCandidateMysqlRawRecord> {
  const row = exactRecord(candidate, [
    "legacy_user_id", "legacy_organization_id", "identity_user_id", "identity_organization_id",
    "organization_role", "candidate_status"
  ]);
  return Object.freeze({
    legacyUserId: positiveId(row.legacy_user_id),
    legacyOrganizationId: positiveId(row.legacy_organization_id),
    identityUserId: canonicalText(row.identity_user_id, 128),
    identityOrganizationId: canonicalText(row.identity_organization_id, 128),
    organizationRole: exactLiteral(row.organization_role, "member"),
    candidateStatus: exactLiteral(row.candidate_status, "candidate")
  });
}

function decodeIdentityRoleShadow(candidate: unknown): Readonly<IdentityRoleAssignmentShadowMysqlRawRecord> {
  const row = exactRecord(candidate, ["legacy_user_id", "role_name", "status"]);
  return Object.freeze({
    legacyUserId: positiveId(row.legacy_user_id),
    roleName: canonicalText(row.role_name, 128),
    status: exactLiteral(row.status, "shadow")
  });
}

function decodePluginRegistry(candidate: unknown): Readonly<PluginRegistryMysqlRawRecord> {
  const row = exactRecord(candidate, ["id", "enabled", "access_scope", "organization_name"]);
  const pluginId = canonicalText(row.id, 64);
  if (!/^[A-Za-z0-9-]{1,64}$/.test(pluginId)) throw new Error("invalid plugin ID");
  const accessScope = row.access_scope;
  if (accessScope !== "auth-only" && accessScope !== "manager-only" &&
    accessScope !== "admin-only" && accessScope !== "root-only") {
    throw new Error("invalid plugin access scope");
  }
  return Object.freeze({
    pluginId,
    enabled: mysqlBoolean(row.enabled),
    accessScope,
    organizationName: row.organization_name === null ? null : organizationName(row.organization_name)
  });
}

function exactRecord(candidate: unknown, expectedKeys: readonly string[]): Record<string, unknown> {
  if (candidate === null || typeof candidate !== "object" || Array.isArray(candidate)) {
    throw new Error("invalid row");
  }
  const prototype = Object.getPrototypeOf(candidate);
  if (prototype !== Object.prototype && prototype !== null) throw new Error("invalid row prototype");
  const descriptors = Object.getOwnPropertyDescriptors(candidate);
  const ownKeys = Reflect.ownKeys(descriptors);
  if (ownKeys.some((key) => typeof key !== "string") || ownKeys.length !== expectedKeys.length) {
    throw new Error("invalid row keys");
  }
  const expected = new Set(expectedKeys);
  const output: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const key of ownKeys as string[]) {
    if (!expected.has(key)) throw new Error("invalid row keys");
    const descriptor = descriptors[key];
    if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) {
      throw new Error("invalid row property");
    }
    output[key] = descriptor.value;
  }
  return output;
}

function positiveId(value: unknown): string {
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 1) throw new Error("invalid positive ID");
    return String(value);
  }
  if (typeof value === "bigint") {
    if (value < 1n) throw new Error("invalid positive ID");
    return value.toString(10);
  }
  if (typeof value === "string" && /^[1-9]\d{0,127}$/.test(value)) return value;
  throw new Error("invalid positive ID");
}

function nonNegativeSafeInteger(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new Error("invalid non-negative integer");
  }
  return value;
}

function canonicalText(value: unknown, maxLength: number): string {
  if (typeof value !== "string" || value.length < 1 || value.length > maxLength ||
    value.trim() !== value || value.normalize("NFC") !== value ||
    /[\u0000-\u001f\u007f-\u009f]/u.test(value)) {
    throw new Error("invalid canonical text");
  }
  return value;
}

function nullableCanonicalText(value: unknown, maxLength: number): string | null {
  return value === null ? null : canonicalText(value, maxLength);
}

function organizationName(value: unknown): string {
  const name = canonicalText(value, 64);
  if (!/^[a-z0-9][a-z0-9-]*$/.test(name)) throw new Error("invalid organization name");
  return name;
}

function canonicalMetadata(value: unknown): string {
  return canonicalText(value, 256);
}

function canonicalCursor(value: unknown): string {
  return canonicalText(value, 2_048);
}

function exactLiteral<TLiteral extends string>(value: unknown, literal: TLiteral): TLiteral {
  if (value !== literal) throw new Error("unexpected row lifecycle state");
  return literal;
}

function mysqlBoolean(value: unknown): boolean {
  if (value === true || value === 1) return true;
  if (value === false || value === 0) return false;
  throw new Error("invalid MySQL boolean");
}

function numericOrderKey(value: string): string {
  return `${value.length.toString(10).padStart(3, "0")}:${value}`;
}

function utf8ByteOrderKey(value: string): string {
  // Lower-case hexadecimal is an order-preserving ASCII encoding of UTF-8
  // bytes, including prefix ordering, so the generic string state machine can
  // verify MySQL CAST(... AS BINARY) order without using JS UTF-16 ordering.
  return Buffer.from(value, "utf8").toString("hex");
}

function tupleOrderKey(...values: readonly string[]): string {
  // Every decoder rejects control characters, so NUL is an unambiguous tuple
  // separator and preserves each component's lexical order (including prefix
  // and 9-to-10 length transitions).
  return values.join("\u0000");
}

function sourceLabel(componentId: OrganizationReconciliationMysqlRawComponentId): string {
  switch (componentId) {
    case "legacy-main": return "Legacy main";
    case "identity": return "Identity";
    case "plugin": return "plugin registry";
  }
}

function openFailure(componentId: OrganizationReconciliationMysqlRawComponentId): string {
  return `Opening the ${sourceLabel(componentId)} MySQL reconciliation snapshot failed.`;
}

function readFailure(componentId: OrganizationReconciliationMysqlRawComponentId): string {
  return `Reading the ${sourceLabel(componentId)} MySQL reconciliation snapshot page failed.`;
}

function closeFailure(componentId: OrganizationReconciliationMysqlRawComponentId): string {
  return `Closing the ${sourceLabel(componentId)} MySQL reconciliation snapshot failed.`;
}

function closedFailure(componentId: OrganizationReconciliationMysqlRawComponentId): string {
  return `The ${sourceLabel(componentId)} MySQL reconciliation snapshot is closed.`;
}
