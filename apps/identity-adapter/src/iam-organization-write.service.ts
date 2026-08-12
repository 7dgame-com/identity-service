import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { isProxy } from "node:util/types";
import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Injectable,
  Logger,
  NotFoundException,
  ServiceUnavailableException,
  UnauthorizedException
} from "@nestjs/common";
import { loadConfig } from "./config.js";
import {
  IamOrganizationWriteEvidence,
  organizationWriteCorrelationId,
  organizationWriteFingerprint
} from "./iam-organization-write-evidence.js";
import {
  IamOrganizationWriteRepository,
  ORGANIZATION_CANDIDATE_MATERIALIZATION_PENDING_LEASE_MS,
  type OrganizationCandidateSnapshot,
  type OrganizationWriteOperationRecord,
  organizationCandidateMaterializationOperationKey,
  organizationCandidateSnapshotFingerprint,
  organizationWriteOperationKey,
  organizationWriteRequestFingerprint
} from "./iam-organization-write.repository.js";
import {
  identityNativeOrganizationWriteTargetDecision,
  identityNativeOrganizationWriteTargetScope
} from "./iam-organization-write-target-control.js";
import { IamRepository, type IdentityUserRow } from "./iam.repository.js";
import { JwtIssuerService, VerifiedAccessToken } from "./jwt-issuer.service.js";
import {
  LegacyIdentityReader,
  LegacyOrganization,
  LegacyUserReadModel,
  type LegacyOrganizationCandidateSourceUser
} from "./legacy-identity.reader.js";
import { PluginUserWriteRequest, PluginUserWriteService } from "./plugin-user-write.service.js";
import { ORGANIZATION_RECONCILIATION_DEVELOP_LEGACY_DATABASE } from
  "./iam-organization-reconciliation-develop-source-catalog.js";

export interface IamOrganizationWriteProxyResponse {
  status: number;
  body: unknown;
  mode: "legacy-proxy" | "dual-write" | "identity-native";
  evidence: IamOrganizationWriteEvidence;
}

export const ORGANIZATION_CANDIDATE_BATCH_MATERIALIZATION_CONTRACT =
  "iam-organization-candidate-batch-materialization/xrteeth-develop/v1" as const;

interface OrganizationCandidateBatchSubjectPlan {
  readonly source: LegacyOrganizationCandidateSourceUser;
  readonly legacyUser: LegacyUserReadModel;
  readonly snapshotFingerprint: string;
  readonly protected: boolean;
  readonly alignment: OrganizationAlignment;
  readonly unresolvedOperationCount: number;
  readonly disposition: "aligned" | "materialize" | "protected" | "blocked";
}

interface OrganizationCandidateBatchPlan {
  readonly planToken: string;
  readonly subjects: readonly OrganizationCandidateBatchSubjectPlan[];
  readonly legacySubjectCount: number;
  readonly ordinarySubjectCount: number;
  readonly protectedSubjectCount: number;
  readonly ordinaryAlignedCount: number;
  readonly ordinaryMissingCount: number;
  readonly ordinaryBlockedCount: number;
  readonly inactiveOrdinaryCount: number;
  readonly protectedAlignedCount: number;
  readonly protectedMissingCount: number;
  readonly blockers: readonly string[];
}

@Injectable()
export class IamOrganizationWriteService {
  private readonly config = loadConfig();
  private readonly logger = new Logger(IamOrganizationWriteService.name);

  constructor(
    private readonly pluginUserWrite: PluginUserWriteService,
    private readonly repository: IamOrganizationWriteRepository,
    private readonly legacy: LegacyIdentityReader,
    private readonly jwtIssuer: JwtIssuerService,
    private readonly iamRepository?: IamRepository
  ) {}

  async readiness() {
    const { iam } = this.config;
    const materializationSchema = await this.candidateMaterializationSchemaState();
    const rollout = organizationRolloutReadiness(iam);
    const pluginUserOwner = this.pluginUserWrite.readiness();
    const legacyOwnerExecutable =
      pluginUserOwner.mode === "legacy-proxy" ||
      (pluginUserOwner.mode === "dual-write" && pluginUserOwner.dualWriteSupported === true);
    const legacyProxyGate = {
      executable:
        iam.organizationWriteMode === "legacy-proxy" &&
        iam.organizationWriteRouteIntegrationEnabled &&
        legacyOwnerExecutable &&
        rollout.selectionConfigured,
      missingCapabilities: [
        ...(!iam.organizationWriteRouteIntegrationEnabled ? ["route-integration"] : []),
        ...(!legacyOwnerExecutable ? ["plugin-user-legacy-write-owner"] : []),
        ...(!rollout.selectionConfigured ? ["scoped-rollout-selector"] : [])
      ]
    };
    const dualWriteGate = {
      executable:
        iam.organizationWriteMode === "dual-write" &&
        iam.organizationWriteRouteIntegrationEnabled &&
        iam.organizationWriteDualWriteExecutionEnabled &&
        legacyOwnerExecutable &&
        this.repository.isConfigured() &&
        rollout.selectionConfigured,
      missingCapabilities: [
        ...(!iam.organizationWriteRouteIntegrationEnabled ? ["route-integration"] : []),
        ...(!iam.organizationWriteDualWriteExecutionEnabled ? ["dual-write-execution-flag"] : []),
        ...(!legacyOwnerExecutable ? ["plugin-user-legacy-write-owner"] : []),
        ...(!this.repository.isConfigured() ? ["identity-organization-candidate-repository"] : []),
        ...(!rollout.selectionConfigured ? ["scoped-rollout-selector"] : [])
      ]
    };
    const identityNativeTargetScope = identityNativeOrganizationWriteTargetScope(iam);
    const livePermissionReaderConfigured = typeof this.legacy.isConfigured === "function" && this.legacy.isConfigured();
    const identityNativeGate = {
      executable:
        iam.organizationWriteMode === "identity-native" &&
        iam.organizationWriteRouteIntegrationEnabled &&
        iam.organizationWriteIdentityNativeExecutionEnabled &&
        this.repository.isConfigured() &&
        this.iamRepository?.isConfigured() === true &&
        livePermissionReaderConfigured &&
        materializationSchema.ready &&
        identityNativeTargetScope.configured,
      missingCapabilities: uniqueStrings([
        ...(!iam.organizationWriteRouteIntegrationEnabled ? ["route-integration"] : []),
        ...(!iam.organizationWriteIdentityNativeExecutionEnabled ? ["identity-native-execution-flag"] : []),
        ...(!this.repository.isConfigured() ? ["identity-organization-candidate-repository"] : []),
        ...(this.iamRepository?.isConfigured() !== true ? ["identity-user-repository"] : []),
        ...(!livePermissionReaderConfigured ? ["live-yii-permission-reader"] : []),
        ...(materializationSchema.blocker ? [materializationSchema.blocker] : []),
        ...identityNativeTargetScope.missingCapabilities
      ])
    };
    const candidateMaterializationPreviewBlockers = uniqueStrings([
      ...(iam.organizationWriteCandidateMaterializationTargetLegacyUserId <= 0 ? ["target-not-configured"] : []),
      ...(!this.repository.isConfigured() ? ["identity-organization-candidate-repository"] : []),
      ...(materializationSchema.blocker ? [materializationSchema.blocker] : [])
    ]);
    const candidateMaterializationApplyBlockers = uniqueStrings([
      ...candidateMaterializationPreviewBlockers,
      ...(!iam.organizationWriteCandidateMaterializationEnabled ? ["candidate-materialization-disabled"] : []),
      ...this.candidateMaterializationPostureBlockedReasons()
    ]);
    const candidateBatchConfigurationBlockers = this.candidateBatchConfigurationBlockedReasons();
    const candidateBatchPreviewBlockers = uniqueStrings([
      ...candidateBatchConfigurationBlockers,
      ...(!this.repository.isConfigured() ? ["identity-organization-candidate-repository"] : []),
      ...(materializationSchema.blocker ? [materializationSchema.blocker] : [])
    ]);
    const candidateBatchApplyBlockers = uniqueStrings([
      ...candidateBatchPreviewBlockers,
      ...(!iam.organizationWriteCandidateBatchMaterializationEnabled
        ? ["candidate-batch-materialization-disabled"]
        : []),
      ...this.candidateMaterializationPostureBlockedReasons(),
      ...(iam.organizationWriteCandidateMaterializationEnabled
        ? ["single-subject-candidate-materialization-must-be-disabled"]
        : []),
      ...(iam.organizationWriteCandidateMaterializationTargetLegacyUserId !== 0
        ? ["single-subject-candidate-target-must-be-zero"]
        : [])
    ]);
    return {
      enabled: iam.organizationWriteMode !== "disabled",
      mode: iam.organizationWriteMode,
      routeIntegrationEnabled: iam.organizationWriteRouteIntegrationEnabled,
      route: "/v1/plugin-user/update-user",
      scope: "membership-replace",
      sourceOfTruth: iam.organizationWriteMode === "identity-native"
        ? "identity-candidate-selected-legacy-unselected"
        : "legacy",
      legacyOrganizationIdContract: "stable-external-key",
      updateSemantics: { absent: "preserve", emptyArray: "replace-empty", values: "positive-integer-dedupe-sort" },
      repositoryConfigured: this.repository.isConfigured(),
      pluginUserOwner: {
        mode: pluginUserOwner.mode,
        legacyProxyConfigured: pluginUserOwner.legacyProxyConfigured,
        executable: legacyOwnerExecutable
      },
      legacyProxyGate,
      dualWriteExecutionEnabled: iam.organizationWriteDualWriteExecutionEnabled,
      dualWriteGate,
      identityNativeExecutionEnabled: iam.organizationWriteIdentityNativeExecutionEnabled,
      identityNativeGate,
      identityNativeTargetScope,
      candidateMaterialization: {
        enabled: iam.organizationWriteCandidateMaterializationEnabled,
        targetConfigured: iam.organizationWriteCandidateMaterializationTargetLegacyUserId > 0,
        schemaReady: materializationSchema.ready,
        canPreview: candidateMaterializationPreviewBlockers.length === 0,
        canApply: candidateMaterializationApplyBlockers.length === 0,
        blockers: candidateMaterializationApplyBlockers,
        previewEndpoint: "/internal/iam/organization-write/subjects/:legacyUserId/materialization-preview",
        endpoint: "/internal/iam/organization-write/subjects/:legacyUserId/materialize-candidate",
        requiresInternalToken: true,
        requiresExpectedSnapshotFingerprint: true,
        requiresIdempotencyKey: true,
        sourceOfTruth: "legacy",
        mutatesLegacy: false,
        writeScope: "identity-candidate-only"
      },
      candidateBatchMaterialization: {
        contract: ORGANIZATION_CANDIDATE_BATCH_MATERIALIZATION_CONTRACT,
        enabled: iam.organizationWriteCandidateBatchMaterializationEnabled,
        environment: iam.organizationWriteCandidateBatchMaterializationEnvironment,
        planHmacKeyConfigured: candidateBatchPlanHmacKeyConfigured(iam),
        expectedLegacySubjectCount: iam.organizationWriteCandidateBatchExpectedLegacySubjectCount,
        expectedProtectedSubjectCount: iam.organizationWriteCandidateBatchExpectedProtectedSubjectCount,
        canPreview: candidateBatchPreviewBlockers.length === 0,
        canApply: candidateBatchApplyBlockers.length === 0,
        blockers: candidateBatchApplyBlockers,
        previewEndpoint: "/internal/iam/organization-write/candidate-batch-materialization/preview",
        endpoint: "/internal/iam/organization-write/candidate-batch-materialization/apply",
        requiresInternalToken: true,
        requiresExpectedBuildRevision: true,
        requiresPlanHmac: true,
        requiresIdempotencyKey: true,
        sourceOfTruth: "legacy",
        mutatesLegacy: false,
        protectedSubjectsWritten: false,
        writeScope: "identity-candidate-only"
      },
      recoveryDrill: {
        enabled: iam.organizationWriteRecoveryDrillEnabled,
        targetConfigured: iam.organizationWriteRecoveryDrillTargetLegacyUserId > 0,
        endpoint: "/internal/iam/organization-write/recovery-drill/prepare",
        recoveryEndpoint: "/internal/iam/organization-write/operations/:operationKey/retry-identity-candidate",
        requiresInternalToken: true,
        mutatesLegacy: false,
        writeScope: "identity-candidate-and-ledger"
      },
      identityNativeSupported: identityNativeGate.executable,
      rollout,
      redactionPolicy: "metadata-only-no-request-or-token-payloads",
      blockedReasons:
        iam.organizationWriteMode === "identity-native"
          ? identityNativeGate.missingCapabilities
          : iam.organizationWriteMode === "legacy-proxy" && !legacyProxyGate.executable
            ? legacyProxyGate.missingCapabilities
          : iam.organizationWriteMode === "dual-write" && !dualWriteGate.executable
            ? dualWriteGate.missingCapabilities
            : []
    };
  }

  async proxyMembershipUpdate(request: PluginUserWriteRequest): Promise<IamOrganizationWriteProxyResponse | null> {
    const { iam } = this.config;
    if (!iam.organizationWriteRouteIntegrationEnabled || iam.organizationWriteMode === "disabled") return null;
    if (iam.organizationWriteMode === "identity-native" && identityNativeOrganizationFieldMalformed(request.body)) {
      throw new BadRequestException({
        code: "IAM_ORGANIZATION_WRITE_INPUT_INVALID",
        message: "organization_ids must be an own data property containing positive integer identifiers."
      });
    }
    const parsed = parseMembershipReplace(request.body);
    if (!parsed.selected) return null;

    const claims = this.claims(request.headers.authorization);
    const nativeTargetDecision = identityNativeOrganizationWriteTargetDecision(iam, parsed.legacyUserId);
    const decision = iam.organizationWriteMode === "identity-native"
      ? {
          selected: nativeTargetDecision.owned,
          decision: nativeTargetDecision.owned
            ? `selected:${nativeTargetDecision.selectorKind}`
            : `not-selected:${nativeTargetDecision.reason}`,
          selectorKind: nativeTargetDecision.selectorKind
        }
      : organizationRolloutDecision(iam, parsed.legacyUserId, claims);
    const evidence: IamOrganizationWriteEvidence = {
      correlationId: organizationWriteCorrelationId(request.headers),
      decision: decision.decision,
      actorFingerprint: organizationWriteFingerprint(claims ? `legacy:${claims.uid}` : null),
      targetFingerprint: organizationWriteFingerprint(`legacy:${parsed.legacyUserId}`),
      matchedSelectorKind: decision.selectorKind
    };

    if (!decision.selected) return null;
    if (iam.organizationWriteMode === "legacy-proxy") {
      const upstream = await this.pluginUserWrite.proxy(request, "/v1/plugin-user/update-user");
      const readbackEvidence = await this.legacyProxyReadbackEvidence(upstream.status, parsed, evidence);
      this.logDecision(readbackEvidence, parsed.legacyUserId, parsed.organizationIds.length);
      return { ...upstream, mode: "legacy-proxy", evidence: readbackEvidence };
    }
    if (iam.organizationWriteMode === "identity-native") {
      const readiness = await this.readiness();
      if (!readiness.identityNativeGate.executable) {
        throw new ServiceUnavailableException({
          code: "IAM_ORGANIZATION_WRITE_IDENTITY_NATIVE_NOT_READY",
          message: "Organization identity-native execution gates are not satisfied.",
          missingCapabilities: readiness.identityNativeGate.missingCapabilities
        });
      }
      const idempotencyKey = clientIdempotencyKey(request.headers);
      if (!idempotencyKey) {
        throw new BadRequestException({
          code: "IAM_ORGANIZATION_WRITE_IDEMPOTENCY_KEY_REQUIRED",
          message: "A client Idempotency-Key is required for selected organization identity-native write."
        });
      }
      return this.identityNativeWrite(request, parsed, idempotencyKey, evidence);
    }
    if (iam.organizationWriteMode !== "dual-write") {
      throw new NotFoundException({
        code: "IAM_ORGANIZATION_WRITE_UNSUPPORTED_MODE",
        message: "Organization identity-native write is not authorized."
      });
    }
    if (!iam.organizationWriteDualWriteExecutionEnabled || !this.repository.isConfigured()) {
      throw new ServiceUnavailableException({
        code: "IAM_ORGANIZATION_WRITE_DUAL_WRITE_NOT_READY",
        message: "Organization dual-write execution gates are not satisfied.",
        missingCapabilities: (await this.readiness()).dualWriteGate.missingCapabilities
      });
    }

    const idempotencyKey = clientIdempotencyKey(request.headers);
    if (!idempotencyKey) {
      throw new BadRequestException({
        code: "IAM_ORGANIZATION_WRITE_IDEMPOTENCY_KEY_REQUIRED",
        message: "A client Idempotency-Key is required for selected organization dual-write."
      });
    }
    return this.dualWrite(request, parsed, idempotencyKey, evidence);
  }

  async previewMembershipRollout(legacyUserId: number) {
    const { iam } = this.config;
    const readiness = await this.readiness();
    const decision = organizationRolloutDecision(iam, legacyUserId, null);
    const modeGateExecutable = iam.organizationWriteMode === "legacy-proxy"
      ? readiness.legacyProxyGate.executable
      : iam.organizationWriteMode === "dual-write"
        ? readiness.dualWriteGate.executable
        : false;
    return {
      mutation: false,
      mode: iam.organizationWriteMode,
      route: "/v1/plugin-user/update-user",
      scope: "membership-replace",
      targetFingerprint: organizationWriteFingerprint(`legacy:${legacyUserId}`),
      selected: decision.selected,
      executable: decision.selected && modeGateExecutable,
      decision: decision.decision,
      matchedSelectorKind: decision.selectorKind,
      sourceOfTruth: iam.organizationWriteMode === "identity-native"
        ? "identity-candidate-selected-legacy-unselected"
        : "legacy",
      identityNativeSupported: readiness.identityNativeGate.executable,
      blockedReasons: decision.selected ? readiness.blockedReasons : ["target-not-selected"]
    };
  }

  async operationLedgerSummary(input: { sinceMinutes?: number }) {
    const sinceMinutes = normalizeNumber(input.sinceMinutes, 60, 1, 1440);
    if (!this.repository.isConfigured()) return { configured: false, schemaReady: false, sinceMinutes, operations: [] };
    const schema = await this.candidateMaterializationSchemaState();
    return schema.ready
      ? { configured: true, schemaReady: true, sinceMinutes, operations: await this.repository.summarizeRecent(sinceMinutes) }
      : { configured: true, schemaReady: false, sinceMinutes, operations: [] };
  }

  async operationLedgerRecent(input: { sinceMinutes?: number; limit?: number }) {
    const sinceMinutes = normalizeNumber(input.sinceMinutes, 60, 1, 1440);
    const limit = normalizeNumber(input.limit, 50, 1, 200);
    if (!this.repository.isConfigured()) return { configured: false, schemaReady: false, sinceMinutes, limit, operations: [] };
    const schema = await this.candidateMaterializationSchemaState();
    return schema.ready
      ? { configured: true, schemaReady: true, sinceMinutes, limit, operations: await this.repository.listRecentSafe(sinceMinutes, limit) }
      : { configured: true, schemaReady: false, sinceMinutes, limit, operations: [] };
  }

  async subjectAlignment(legacyUserId: number) {
    this.requireRepository();
    await this.assertCandidateMaterializationSchemaReady();
    const [legacyUser, candidate] = await Promise.all([
      this.legacy.getUserById(legacyUserId),
      this.repository.candidateForLegacyUser(legacyUserId)
    ]);
    return organizationAlignment(legacyUserId, legacyUser, candidate);
  }

  async subjectCandidate(legacyUserId: number) {
    this.requireRepository();
    await this.assertCandidateMaterializationSchemaReady();
    const candidate = await this.repository.candidateForLegacyUser(legacyUserId);
    if (!candidate) {
      throw new NotFoundException({
        code: "IAM_ORGANIZATION_WRITE_IDENTITY_CANDIDATE_MISSING",
        message: "The Identity organization candidate snapshot is missing."
      });
    }
    const organizations = normalizeOrganizations(candidate.organizations);
    return {
      mutation: false,
      sourceOfTruth: "identity-candidate" as const,
      targetFingerprint: organizationWriteFingerprint(`legacy:${legacyUserId}`),
      organizationIds: organizations.map(({ id }) => id),
      organizationCount: organizations.length,
      snapshotFingerprint: organizationCandidateSnapshotFingerprint(legacyUserId, organizations)
    };
  }

  async previewCandidateMaterialization(legacyUserId: number) {
    const { iam } = this.config;
    if (
      iam.organizationWriteCandidateMaterializationTargetLegacyUserId <= 0 ||
      iam.organizationWriteCandidateMaterializationTargetLegacyUserId !== legacyUserId
    ) {
      throw new ConflictException({
        code: "IAM_ORGANIZATION_CANDIDATE_MATERIALIZATION_TARGET_MISMATCH",
        message: "Organization candidate materialization preview is not enabled for the requested subject."
      });
    }
    this.requireRepository();
    const schema = await this.candidateMaterializationSchemaState();
    if (!schema.ready) {
      return candidateMaterializationBlockedPreview(legacyUserId, schema.blocker ?? "schema-not-ready");
    }
    const [legacyUser, candidate] = await Promise.all([
      this.legacy.getUserById(legacyUserId),
      this.repository.candidateForLegacyUser(legacyUserId)
    ]);
    const alignment = organizationAlignment(legacyUserId, legacyUser, candidate);
    const unresolvedCount = legacyUser
      ? await this.repository.countUnresolvedForLegacyUser(legacyUserId)
      : 0;
    const blockedReasons = [
      ...(!iam.organizationWriteCandidateMaterializationEnabled ? ["candidate-materialization-disabled"] : []),
      ...(iam.organizationWriteCandidateMaterializationTargetLegacyUserId !== legacyUserId ? ["target-not-selected"] : []),
      ...this.candidateMaterializationPostureBlockedReasons(),
      ...(!legacyUser ? ["legacy-user-not-found"] : []),
      ...(legacyUser && legacyUser.status !== 10 ? ["inactive-subject"] : []),
      ...(legacyUser && isProtectedOrganizationSubject(legacyUser) ? ["protected-subject"] : []),
      ...(alignment.reason !== "identity-candidate-snapshot-missing" ? ["candidate-snapshot-not-missing"] : []),
      ...(alignment.P0 !== 0 || alignment.P2 !== 0 ? ["alignment-not-materializable"] : []),
      ...(unresolvedCount !== 0 ? ["unresolved-organization-operation"] : [])
    ];
    return {
      mutation: false,
      executable: blockedReasons.length === 0,
      targetFingerprint: organizationWriteFingerprint(`legacy:${legacyUserId}`),
      expectedSnapshotFingerprint: alignment.legacySnapshotFingerprint,
      organizationCount: alignment.organizationCount,
      alignment: alignmentSummary(alignment),
      unresolvedOperationCount: unresolvedCount,
      sourceOfTruth: "legacy",
      legacyWritePerformed: false,
      identityCandidateWritePerformed: false,
      blockedReasons
    };
  }

  async materializeCandidate(input: {
    legacyUserId: number;
    expectedSnapshotFingerprint?: string;
    idempotencyKey?: string;
  }) {
    const { iam } = this.config;
    if (!iam.organizationWriteCandidateMaterializationEnabled) {
      throw new NotFoundException({
        code: "IAM_ORGANIZATION_CANDIDATE_MATERIALIZATION_DISABLED",
        message: "Organization candidate materialization is disabled."
      });
    }
    if (iam.organizationWriteCandidateMaterializationTargetLegacyUserId !== input.legacyUserId) {
      throw new ConflictException({
        code: "IAM_ORGANIZATION_CANDIDATE_MATERIALIZATION_TARGET_MISMATCH",
        message: "Organization candidate materialization is not enabled for the requested subject."
      });
    }
    this.assertCandidateMaterializationPosture();
    this.requireRepository();

    const expectedSnapshotFingerprint = candidateSnapshotFingerprintInput(input.expectedSnapshotFingerprint);
    const idempotencyKey = candidateMaterializationIdempotencyKey(input.idempotencyKey);
    const lock = await this.repository.withCandidateMaterializationSubjectLock(input.legacyUserId, async () => {
      await this.assertCandidateMaterializationSchemaReady();
      return this.materializeCandidateWhileLocked({
        legacyUserId: input.legacyUserId,
        expectedSnapshotFingerprint,
        idempotencyKey
      });
    });
    if (!lock.acquired) {
      throw new ConflictException({
        code: "IAM_ORGANIZATION_CANDIDATE_MATERIALIZATION_SUBJECT_BUSY",
        message: "Another organization materialization operation is active for the selected subject."
      });
    }
    return lock.value;
  }

  async previewCandidateBatchMaterialization() {
    this.requireRepository();
    await this.assertCandidateMaterializationSchemaReady();
    this.assertCandidateBatchConfiguration();
    const plan = await this.createCandidateBatchPlan();
    return candidateBatchPublicPlan(plan, {
      applyEnabled: this.config.iam.organizationWriteCandidateBatchMaterializationEnabled,
      postureBlockers: this.candidateMaterializationPostureBlockedReasons()
    });
  }

  async materializeCandidateBatch(input: { planToken?: string; idempotencyKey?: string }) {
    const { iam } = this.config;
    if (!iam.organizationWriteCandidateBatchMaterializationEnabled) {
      throw new NotFoundException({
        code: "IAM_ORGANIZATION_CANDIDATE_BATCH_MATERIALIZATION_DISABLED",
        message: "Organization candidate batch materialization is disabled."
      });
    }
    this.assertCandidateBatchConfiguration();
    this.assertCandidateMaterializationPosture();
    if (iam.organizationWriteCandidateMaterializationEnabled ||
      iam.organizationWriteCandidateMaterializationTargetLegacyUserId !== 0) {
      throw new ConflictException({
        code: "IAM_ORGANIZATION_CANDIDATE_BATCH_SINGLE_SUBJECT_GATE_ACTIVE",
        message: "The single-subject candidate materialization gate must be fully restored before batch apply."
      });
    }
    this.requireRepository();
    const planToken = candidateBatchPlanTokenInput(input.planToken);
    const idempotencyKey = candidateMaterializationIdempotencyKey(input.idempotencyKey);
    const batchLock = await this.repository.withCandidateMaterializationBatchLock(async () => {
      await this.assertCandidateMaterializationSchemaReady();
      const plan = await this.createCandidateBatchPlan();
      if (!constantTimeHexEqual(plan.planToken, planToken)) {
        throw new ConflictException({
          code: "IAM_ORGANIZATION_CANDIDATE_BATCH_PLAN_CHANGED",
          message: "The reviewed Legacy batch plan no longer matches the current source snapshot."
        });
      }
      if (plan.blockers.length > 0 || plan.ordinaryBlockedCount > 0) {
        throw new ConflictException({
          code: "IAM_ORGANIZATION_CANDIDATE_BATCH_PLAN_BLOCKED",
          message: "The current candidate batch plan contains a fail-closed blocker.",
          blockedReasons: [...plan.blockers]
        });
      }

      let appliedCount = 0;
      let replayedCount = 0;
      let skippedAlignedCount = 0;
      for (const subject of plan.subjects) {
        if (subject.disposition === "protected") continue;
        if (subject.disposition === "aligned") {
          skippedAlignedCount += 1;
          continue;
        }
        if (subject.disposition !== "materialize") {
          throw new ConflictException({
            code: "IAM_ORGANIZATION_CANDIDATE_BATCH_PLAN_BLOCKED",
            message: "The current candidate batch plan contains a non-materializable ordinary subject."
          });
        }
        const subjectIdempotencyKey = candidateBatchSubjectIdempotencyKey({
          planToken,
          idempotencyKey,
          legacyUserId: subject.source.id,
          key: this.requireCandidateBatchPlanHmacKey()
        });
        const locked = await this.repository.withCandidateMaterializationSubjectLock(subject.source.id, async () =>
          this.materializeCandidateWhileLocked({
            legacyUserId: subject.source.id,
            expectedSnapshotFingerprint: subject.snapshotFingerprint,
            idempotencyKey: subjectIdempotencyKey
          })
        );
        if (!locked.acquired) {
          throw new ConflictException({
            code: "IAM_ORGANIZATION_CANDIDATE_MATERIALIZATION_SUBJECT_BUSY",
            message: "Another organization materialization operation is active for a batch subject."
          });
        }
        if (locked.value.idempotentReplay === true) replayedCount += 1;
        else appliedCount += 1;
      }
      const finalPlan = await this.createCandidateBatchPlan();
      if (!constantTimeHexEqual(finalPlan.planToken, planToken) ||
        finalPlan.blockers.length > 0 ||
        finalPlan.ordinaryMissingCount > 0 ||
        finalPlan.ordinaryBlockedCount > 0) {
        throw new ConflictException({
          code: "IAM_ORGANIZATION_CANDIDATE_BATCH_POSTCHECK_FAILED",
          message: "The full Legacy source or Identity candidate set changed before the batch postcheck completed.",
          blockedReasons: [...finalPlan.blockers]
        });
      }
      this.logger.log(JSON.stringify({
        event: "identity.iam.organization_candidate.batch_materialized",
        planTokenDigest: shortDigest(planToken),
        legacySubjectCount: plan.legacySubjectCount,
        protectedSkippedCount: plan.protectedSubjectCount,
        appliedCount,
        replayedCount,
        skippedAlignedCount
      }));
      return {
        contract: ORGANIZATION_CANDIDATE_BATCH_MATERIALIZATION_CONTRACT,
        mutation: appliedCount > 0,
        completed: true,
        planTokenDigest: shortDigest(planToken),
        legacySubjectCount: plan.legacySubjectCount,
        ordinarySubjectCount: plan.ordinarySubjectCount,
        protectedSkippedCount: plan.protectedSubjectCount,
        appliedCount,
        replayedCount,
        skippedAlignedCount,
        sourceOfTruth: "legacy" as const,
        legacyWritePerformed: false,
        protectedSubjectWritePerformed: false,
        writeScope: "identity-candidate-only" as const
      };
    });
    if (!batchLock.acquired) {
      throw new ConflictException({
        code: "IAM_ORGANIZATION_CANDIDATE_BATCH_BUSY",
        message: "Another organization candidate batch operation is active."
      });
    }
    return batchLock.value;
  }

  private async createCandidateBatchPlan(): Promise<OrganizationCandidateBatchPlan> {
    const snapshot = await this.legacy.readOrganizationCandidateSourceSnapshot();
    const users = [...snapshot.users];
    if (users.length === 0 || users.length > 5000) {
      throw new ServiceUnavailableException({
        code: "IAM_ORGANIZATION_CANDIDATE_BATCH_SOURCE_INVALID",
        message: "The Legacy candidate batch source universe is empty or exceeds the reviewed bound."
      });
    }
    let previousId = 0;
    const subjects: OrganizationCandidateBatchSubjectPlan[] = [];
    for (const source of users) {
      if (!Number.isSafeInteger(source.id) || source.id <= previousId) {
        throw new ServiceUnavailableException({
          code: "IAM_ORGANIZATION_CANDIDATE_BATCH_SOURCE_ORDER_INVALID",
          message: "The Legacy candidate batch source universe is not strictly ordered."
        });
      }
      previousId = source.id;
      const legacyUser = candidateBatchLegacyUser(source);
      const snapshotFingerprint = organizationCandidateSnapshotFingerprint(
        source.id,
        normalizeOrganizations(legacyUser.organizations)
      );
      const [candidate, unresolvedOperationCount] = await Promise.all([
        this.repository.candidateForLegacyUser(source.id),
        this.repository.countUnresolvedForLegacyUser(source.id)
      ]);
      const alignment = organizationAlignment(source.id, legacyUser, candidate);
      const protectedSubject = isProtectedOrganizationSubject(legacyUser);
      const disposition = protectedSubject
        ? "protected"
        : source.status !== 10
          ? "blocked"
          : alignment.aligned && alignment.P0 === 0 && alignment.P1 === 0 && alignment.P2 === 0 &&
              unresolvedOperationCount === 0
            ? "aligned"
            : alignment.reason === "identity-candidate-snapshot-missing" &&
                alignment.P0 === 0 && alignment.P2 === 0 && unresolvedOperationCount === 0
              ? "materialize"
              : "blocked";
      subjects.push(Object.freeze({
        source,
        legacyUser,
        snapshotFingerprint,
        protected: protectedSubject,
        alignment,
        unresolvedOperationCount,
        disposition
      }));
    }

    const protectedSubjects = subjects.filter((subject) => subject.protected);
    const ordinarySubjects = subjects.filter((subject) => !subject.protected);
    const key = this.requireCandidateBatchPlanHmacKey();
    let planToken: string;
    try {
      planToken = createHmac("sha256", key)
        .update("iam-organization-candidate-batch-plan:xrteeth-develop:v1\u001f", "utf8")
        .update(JSON.stringify(subjects.map((subject) => ({
          legacyUserId: subject.source.id,
          status: subject.source.status,
          protected: subject.protected,
          snapshotFingerprint: subject.snapshotFingerprint
        }))), "utf8")
        .digest("hex");
    } finally {
      key.fill(0);
    }
    const blockers = uniqueStrings([
      ...(subjects.length !== this.config.iam.organizationWriteCandidateBatchExpectedLegacySubjectCount
        ? ["legacy-subject-count-mismatch"]
        : []),
      ...(protectedSubjects.length !== this.config.iam.organizationWriteCandidateBatchExpectedProtectedSubjectCount
        ? ["protected-subject-count-mismatch"]
        : []),
      ...(subjects.some((subject) => subject.unresolvedOperationCount > 0)
        ? ["unresolved-candidate-materialization-operation"]
        : []),
      ...(ordinarySubjects.some((subject) => subject.disposition === "blocked")
        ? ["ordinary-subject-not-materializable"]
        : [])
    ]);
    return Object.freeze({
      planToken,
      subjects: Object.freeze(subjects),
      legacySubjectCount: subjects.length,
      ordinarySubjectCount: ordinarySubjects.length,
      protectedSubjectCount: protectedSubjects.length,
      ordinaryAlignedCount: ordinarySubjects.filter((subject) => subject.disposition === "aligned").length,
      ordinaryMissingCount: ordinarySubjects.filter((subject) => subject.disposition === "materialize").length,
      ordinaryBlockedCount: ordinarySubjects.filter((subject) => subject.disposition === "blocked").length,
      inactiveOrdinaryCount: ordinarySubjects.filter((subject) => subject.source.status !== 10).length,
      protectedAlignedCount: protectedSubjects.filter((subject) => subject.alignment.aligned).length,
      protectedMissingCount: protectedSubjects.filter((subject) => !subject.alignment.aligned).length,
      blockers: Object.freeze(blockers)
    });
  }

  private async materializeCandidateWhileLocked(input: {
    legacyUserId: number;
    expectedSnapshotFingerprint: string;
    idempotencyKey: string;
  }) {
    const legacyUser = this.requireCandidateMaterializationInitialSubject(
      await this.legacy.getUserById(input.legacyUserId)
    );
    const organizations = normalizeOrganizations(legacyUser.organizations);
    const actualSnapshotFingerprint = organizationCandidateSnapshotFingerprint(input.legacyUserId, organizations);
    if (actualSnapshotFingerprint !== input.expectedSnapshotFingerprint) {
      throw new ConflictException({
        code: "IAM_ORGANIZATION_CANDIDATE_MATERIALIZATION_SNAPSHOT_CHANGED",
        message: "The current Legacy organization snapshot does not match the reviewed fingerprint."
      });
    }

    const operationKey = organizationCandidateMaterializationOperationKey(input.legacyUserId, input.idempotencyKey);
    const [candidate, existing] = await Promise.all([
      this.repository.candidateForLegacyUser(input.legacyUserId),
      this.repository.find(operationKey)
    ]);
    const before = organizationAlignment(input.legacyUserId, legacyUser, candidate);
    if (existing && (existing.mode !== "candidate-materialization" || existing.legacyUserId !== input.legacyUserId)) {
      throw new ConflictException({
        code: "IDEMPOTENCY_KEY_REUSED_WITH_DIFFERENT_REQUEST",
        message: "The candidate materialization idempotency key belongs to a different operation."
      });
    }
    if (existing) assertCandidateMaterializationLedgerState(existing);
    const compensationRecovery = existing?.status === "failed" &&
      (existing.compensationStatus === "required" || existing.compensationStatus === "failed");
    const existingFingerprintMatches = existing?.requestFingerprint === actualSnapshotFingerprint;
    const pendingOperation = existing?.status === "pending";
    const stalePending = pendingOperation && existing
      ? candidateMaterializationPendingLeaseStale(existing.requestedAt)
      : false;
    const stalePendingSnapshotRecovery = stalePending && !existingFingerprintMatches;
    if (existing && !existingFingerprintMatches && !compensationRecovery && !stalePendingSnapshotRecovery) {
      if (pendingOperation) {
        throw new ConflictException({
          code: "IAM_ORGANIZATION_CANDIDATE_MATERIALIZATION_OPERATION_IN_PROGRESS",
          message: "Another worker owns the candidate materialization lease."
        });
      }
      throw new ConflictException({
        code: "IDEMPOTENCY_KEY_REUSED_WITH_DIFFERENT_REQUEST",
        message: "The candidate materialization idempotency key was already used for a different request."
      });
    }

    if (existing?.status === "completed") {
      const after = await this.candidateMaterializationFreshPostcheck(
        input.legacyUserId,
        input.expectedSnapshotFingerprint
      );
      return candidateMaterializationResult({
        operationKey,
        before,
        after,
        organizationCount: organizations.length,
        replay: true
      });
    }
    const recovering = existing?.status === "failed" || pendingOperation;
    if (
      before.P0 !== 0 ||
      (!recovering && (before.reason !== "identity-candidate-snapshot-missing" || before.P2 !== 0)) ||
      (!recovering && before.aligned)
    ) {
      throw new ConflictException({
        code: "IAM_ORGANIZATION_CANDIDATE_MATERIALIZATION_NOT_APPLICABLE",
        message: "Only a missing snapshot or this operation's recoverable candidate state can be materialized."
      });
    }

    const unresolvedCount = await this.repository.countUnresolvedForLegacyUser(input.legacyUserId, operationKey);
    if (unresolvedCount !== 0) {
      throw new ConflictException({
        code: "IAM_ORGANIZATION_CANDIDATE_MATERIALIZATION_UNRESOLVED_OPERATION",
        message: "An unresolved organization operation blocks candidate materialization."
      });
    }

    const metadata = {
      targetFingerprint: organizationWriteFingerprint(`legacy:${input.legacyUserId}`),
      snapshotFingerprint: shortDigest(actualSnapshotFingerprint),
      organizationCount: organizations.length,
      source: "current-legacy-read",
      legacyWritePerformed: false,
      ...(compensationRecovery ? {
        recovery: "current-reviewed-legacy-snapshot",
        recoveryPreviousSnapshotFingerprintDigest: shortDigest(existing.requestFingerprint),
        recoverySnapshotFingerprintDigest: shortDigest(actualSnapshotFingerprint)
      } : stalePendingSnapshotRecovery && existing ? {
        recovery: "stale-pending-current-reviewed-legacy-snapshot",
        recoveryPreviousSnapshotFingerprintDigest: shortDigest(existing.requestFingerprint),
        recoverySnapshotFingerprintDigest: shortDigest(actualSnapshotFingerprint)
      } : existing ? { recovery: "same-idempotency-key-retry" } : {})
    };
    const claimToken = randomBytes(32).toString("hex");
    let claimed = false;
    if (existing?.status === "failed") {
      claimed = (await this.repository.resumeCandidateMaterialization(
        operationKey,
        existing.requestFingerprint,
        actualSnapshotFingerprint,
        claimToken,
        metadata
      )).claimed;
    } else if (pendingOperation && existing) {
      claimed = (await this.repository.reclaimStaleCandidateMaterialization({
        operationKey,
        expectedRequestFingerprint: existing.requestFingerprint,
        requestFingerprint: actualSnapshotFingerprint,
        claimToken,
        staleBefore: candidateMaterializationLeaseCutoff(),
        metadata
      })).claimed;
    } else {
      const begun = await this.repository.beginCandidateMaterialization({
        operationKey,
        idempotencyKeyDigest: createHash("sha256").update(input.idempotencyKey).digest("hex"),
        requestFingerprint: actualSnapshotFingerprint,
        legacyUserId: input.legacyUserId,
        claimToken,
        metadata
      });
      claimed = !begun.duplicate;
    }
    if (!claimed) {
      return this.candidateMaterializationClaimRaceResult({
        operationKey,
        legacyUserId: input.legacyUserId,
        expectedSnapshotFingerprint: actualSnapshotFingerprint,
        before,
        organizationCount: organizations.length
      });
    }

    let candidateWriteAttempted = false;
    let candidateWriteCompleted = false;
    try {
      candidateWriteAttempted = true;
      await this.repository.replaceCandidate({
        operationKey,
        legacyUserId: input.legacyUserId,
        organizations,
        materializationClaim: {
          claimToken,
          leaseValidAfter: candidateMaterializationLeaseCutoff()
        }
      });
      candidateWriteCompleted = true;
      const after = await this.candidateMaterializationFreshPostcheck(
        input.legacyUserId,
        input.expectedSnapshotFingerprint
      );
      const completed = await this.repository.finalizeCandidateMaterialization({
        operationKey,
        status: "completed",
        legacyStatus: "read-only",
        identityStatus: compensationRecovery ? "candidate-recovered-from-current-legacy" : "candidate-materialized",
        compensationStatus: compensationRecovery ? "completed" : "none",
        claimToken,
        leaseValidAfter: candidateMaterializationLeaseCutoff(),
        metadata
      });
      if (!completed.updated) throw candidateMaterializationLedgerCasFailure();
      this.logger.log(JSON.stringify({
        event: "identity.iam.organization_candidate.materialized",
        targetFingerprint: metadata.targetFingerprint,
        snapshotFingerprint: metadata.snapshotFingerprint,
        organizationCount: organizations.length,
        operationKeyDigest: shortDigest(operationKey)
      }));
      return candidateMaterializationResult({
        operationKey,
        before,
        after,
        organizationCount: organizations.length,
        replay: false
      });
    } catch (error) {
      let failed;
      try {
        failed = await this.repository.finalizeCandidateMaterialization({
          operationKey,
          status: "failed",
          legacyStatus: "read-only",
          identityStatus: candidateWriteCompleted
            ? "candidate-postcheck-failed"
            : candidateWriteAttempted
              ? "candidate-write-outcome-unknown"
              : "candidate-materialization-failed",
          compensationStatus: candidateWriteAttempted ? "required" : "none",
          claimToken,
          leaseValidAfter: candidateMaterializationLeaseCutoff(),
          errorCode: errorName(error),
          metadata
        });
      } catch {
        throw candidateMaterializationLedgerCasFailure();
      }
      if (!failed.updated) throw candidateMaterializationLedgerCasFailure();
      throw error;
    }
  }

  private async candidateMaterializationClaimRaceResult(input: {
    operationKey: string;
    legacyUserId: number;
    expectedSnapshotFingerprint: string;
    before: OrganizationAlignment;
    organizationCount: number;
  }) {
    const raced = await this.repository.find(input.operationKey);
    if (
      raced?.mode === "candidate-materialization" &&
      raced.status === "completed" &&
      raced.requestFingerprint === input.expectedSnapshotFingerprint
    ) {
      const after = await this.candidateMaterializationFreshPostcheck(
        input.legacyUserId,
        input.expectedSnapshotFingerprint
      );
      return candidateMaterializationResult({
        operationKey: input.operationKey,
        before: input.before,
        after,
        organizationCount: input.organizationCount,
        replay: true
      });
    }
    if (raced && raced.requestFingerprint !== input.expectedSnapshotFingerprint) {
      throw new ConflictException({
        code: "IDEMPOTENCY_KEY_REUSED_WITH_DIFFERENT_REQUEST",
        message: "The candidate materialization idempotency key is already reserved for another snapshot."
      });
    }
    throw new ConflictException({
      code: "IAM_ORGANIZATION_CANDIDATE_MATERIALIZATION_OPERATION_IN_PROGRESS",
      message: "Another worker owns the candidate materialization lease."
    });
  }

  async retryIdentityCandidate(operationKey: string) {
    this.requireRepository();
    const operation = await this.repository.find(operationKey);
    if (!operation) throw new NotFoundException({ code: "IAM_ORGANIZATION_WRITE_OPERATION_NOT_FOUND" });
    if (operation.mode !== "dual-write") {
      throw new ConflictException({
        code: "IAM_ORGANIZATION_WRITE_RECOVERY_NOT_APPLICABLE",
        message: "Candidate materialization recovery must use its guarded single-subject endpoint."
      });
    }
    if (operation.compensationStatus !== "required") {
      throw new ConflictException({ code: "IAM_ORGANIZATION_WRITE_RECOVERY_NOT_REQUIRED" });
    }
    const legacyUser = await this.legacy.getUserById(operation.legacyUserId);
    if (!legacyUser) throw new NotFoundException({ code: "IAM_ORGANIZATION_WRITE_LEGACY_USER_NOT_FOUND" });
    try {
      await this.repository.replaceCandidate({
        operationKey,
        legacyUserId: operation.legacyUserId,
        organizations: normalizeOrganizations(legacyUser.organizations)
      });
      await this.repository.update({
        operationKey,
        status: "completed",
        identityStatus: "candidate-recovered-from-current-legacy",
        compensationStatus: "completed",
        metadata: { recovery: "current-legacy-read", organizationCount: legacyUser.organizations.length }
      });
      return { operationKeyDigest: shortDigest(operationKey), recovered: true, source: "current-legacy-read" };
    } catch (error) {
      await this.repository.update({
        operationKey,
        status: "failed",
        identityStatus: "candidate-recovery-failed",
        compensationStatus: "failed",
        errorCode: errorName(error),
        metadata: { recovery: "current-legacy-read", organizationCount: legacyUser.organizations.length }
      });
      throw error;
    }
  }

  async prepareRecoveryDrill() {
    const { iam } = this.config;
    if (!iam.organizationWriteRecoveryDrillEnabled) {
      throw new NotFoundException({
        code: "IAM_ORGANIZATION_WRITE_RECOVERY_DRILL_DISABLED",
        message: "Organization-write recovery drill is disabled."
      });
    }
    if (iam.organizationWriteMode !== "dual-write" || !iam.organizationWriteDualWriteExecutionEnabled) {
      throw new ConflictException({
        code: "IAM_ORGANIZATION_WRITE_RECOVERY_DRILL_REQUIRES_DUAL_WRITE",
        message: "Organization-write recovery drill requires an explicitly enabled dual-write window."
      });
    }

    const targetLegacyUserId = iam.organizationWriteRecoveryDrillTargetLegacyUserId;
    if (!Number.isInteger(targetLegacyUserId) || targetLegacyUserId <= 0) {
      throw new ConflictException({
        code: "IAM_ORGANIZATION_WRITE_RECOVERY_DRILL_TARGET_REQUIRED",
        message: "Organization-write recovery drill requires one configured dedicated target."
      });
    }
    const readiness = await this.readiness();
    const decision = organizationRolloutDecision(iam, targetLegacyUserId, null);
    if (!readiness.dualWriteGate.executable || !decision.selected) {
      throw new ConflictException({
        code: "IAM_ORGANIZATION_WRITE_RECOVERY_DRILL_GATE_BLOCKED",
        message: "Organization-write recovery drill is blocked by the exact-target dual-write gate.",
        missingCapabilities: [
          ...readiness.dualWriteGate.missingCapabilities,
          ...(!decision.selected ? ["dedicated-target-not-selected"] : [])
        ]
      });
    }

    const legacyUser = await this.legacy.getUserById(targetLegacyUserId);
    const organizations = legacyUser ? normalizeOrganizations(legacyUser.organizations) : [];
    const exactUserRole = legacyUser?.roles.length === 1 && legacyUser.roles[0]?.trim().toLowerCase() === "user";
    if (!legacyUser || legacyUser.status !== 10 || isProtectedOrganizationSubject(legacyUser)) {
      throw new ConflictException({
        code: "IAM_ORGANIZATION_WRITE_RECOVERY_DRILL_TARGET_PROTECTED",
        message: "Missing, inactive, or protected targets cannot be used for an organization-write recovery drill."
      });
    }
    if (!exactUserRole || !sameIds(organizations.map(({ id }) => id), [1])) {
      throw new ConflictException({
        code: "IAM_ORGANIZATION_WRITE_RECOVERY_DRILL_TARGET_NOT_BASELINE",
        message: "Organization-write recovery drill target must have the exact user/[1] Legacy baseline."
      });
    }

    const idempotencyKey = `organization-recovery-drill:v1:legacy:${targetLegacyUserId}:baseline:1`;
    const operationKey = organizationWriteOperationKey(targetLegacyUserId, idempotencyKey);
    const requestFingerprint = organizationWriteRequestFingerprint(targetLegacyUserId, [1]);
    const metadata = {
      decision: decision.decision,
      targetFingerprint: organizationWriteFingerprint(`legacy:${targetLegacyUserId}`),
      selectorKind: decision.selectorKind,
      organizationCount: 1,
      drill: {
        kind: "identity-candidate-recovery",
        noLegacyMutation: true,
        exactLegacyBaseline: [1]
      }
    };
    const begun = await this.repository.begin({
      operationKey,
      idempotencyKeyDigest: createHash("sha256").update(idempotencyKey).digest("hex"),
      requestFingerprint,
      legacyUserId: targetLegacyUserId,
      metadata
    });
    if (begun.duplicate) {
      const existing = await this.repository.find(operationKey);
      if (!existing) {
        throw new ConflictException({
          code: "IAM_ORGANIZATION_WRITE_RECOVERY_DRILL_DUPLICATE",
          message: "Organization-write recovery drill operation already exists but cannot be read."
        });
      }
      if (
        existing.mode !== "dual-write" ||
        existing.legacyUserId !== targetLegacyUserId ||
        existing.requestFingerprint !== requestFingerprint
      ) {
        throw new ConflictException({
          code: "IAM_ORGANIZATION_WRITE_RECOVERY_DRILL_CONFLICT",
          message: "Existing organization-write recovery drill does not match the exact reviewed request."
        });
      }
      if (existing.status === "pending" && existing.compensationStatus === "none") {
        await this.repository.update({
          operationKey,
          status: "legacy_completed",
          legacyStatus: "drill:no-mutation",
          identityStatus: "drill:recovery-required",
          compensationStatus: "required",
          errorCode: "IAM_ORGANIZATION_WRITE_RECOVERY_DRILL",
          metadata
        });
        return {
          operationKey,
          operationKeyDigest: shortDigest(operationKey),
          targetFingerprint: organizationWriteFingerprint(`legacy:${targetLegacyUserId}`),
          status: "legacy_completed",
          compensationStatus: "required",
          noLegacyMutation: true,
          duplicate: true,
          resumedPrepare: true,
          nextAction: "retry-identity-candidate"
        };
      }
      const retryable = existing.status === "legacy_completed" && existing.compensationStatus === "required";
      const completed = existing.status === "completed" && existing.compensationStatus === "completed";
      if (!retryable && !completed) {
        throw new ConflictException({
          code: "IAM_ORGANIZATION_WRITE_RECOVERY_DRILL_STATE_INVALID",
          message: "Existing organization-write recovery drill state is not retryable or complete."
        });
      }
      return {
        operationKey,
        operationKeyDigest: shortDigest(operationKey),
        targetFingerprint: organizationWriteFingerprint(`legacy:${targetLegacyUserId}`),
        status: existing.status,
        compensationStatus: existing.compensationStatus,
        noLegacyMutation: true,
        duplicate: true,
        resumedPrepare: false,
        nextAction: completed ? "none" : "retry-identity-candidate"
      };
    }

    await this.repository.update({
      operationKey,
      status: "legacy_completed",
      legacyStatus: "drill:no-mutation",
      identityStatus: "drill:recovery-required",
      compensationStatus: "required",
      errorCode: "IAM_ORGANIZATION_WRITE_RECOVERY_DRILL",
      metadata
    });
    return {
      operationKey,
      operationKeyDigest: shortDigest(operationKey),
      targetFingerprint: organizationWriteFingerprint(`legacy:${targetLegacyUserId}`),
      status: "legacy_completed",
      compensationStatus: "required",
      noLegacyMutation: true,
      duplicate: false,
      resumedPrepare: false,
      nextAction: "retry-identity-candidate"
    };
  }

  private async dualWrite(
    request: PluginUserWriteRequest,
    parsed: SelectedMembershipReplace,
    idempotencyKey: string,
    evidence: IamOrganizationWriteEvidence
  ): Promise<IamOrganizationWriteProxyResponse> {
    const before = await this.legacy.getUserById(parsed.legacyUserId);
    if (!before) {
      throw new ServiceUnavailableException({
        code: "IAM_ORGANIZATION_WRITE_LEGACY_PREFLIGHT_UNAVAILABLE",
        message: "The selected target could not be verified from Legacy before mutation."
      });
    }
    if (isProtectedOrganizationSubject(before)) {
      throw new ConflictException({
        code: "IAM_ORGANIZATION_WRITE_PROTECTED_SUBJECT",
        message: "Organization membership writes are not allowed for a protected root subject."
      });
    }
    const operationKey = organizationWriteOperationKey(parsed.legacyUserId, idempotencyKey);
    const requestFingerprint = organizationWriteRequestFingerprint(parsed.legacyUserId, parsed.organizationIds);
    const metadata = {
      correlationId: evidence.correlationId,
      decision: evidence.decision,
      actorFingerprint: evidence.actorFingerprint,
      targetFingerprint: evidence.targetFingerprint,
      selectorKind: evidence.matchedSelectorKind,
      organizationCount: parsed.organizationIds.length
    };
    const begin = await this.repository.begin({
      operationKey,
      idempotencyKeyDigest: createHash("sha256").update(idempotencyKey).digest("hex"),
      requestFingerprint,
      legacyUserId: parsed.legacyUserId,
      metadata
    });
    if (begin.duplicate) {
      const existing = await this.repository.find(operationKey);
      if (!existing || existing.requestFingerprint !== requestFingerprint) {
        throw new ConflictException({
          code: "IDEMPOTENCY_KEY_REUSED_WITH_DIFFERENT_REQUEST",
          message: "The idempotency key was already used for a different organization membership request."
        });
      }
    }

    let upstream;
    try {
      upstream = await this.pluginUserWrite.proxy(request, "/v1/plugin-user/update-user");
    } catch (error) {
      if (!begin.duplicate) {
        await this.repository.update({
          operationKey,
          status: "failed",
          legacyStatus: "unavailable",
          identityStatus: "skipped",
          compensationStatus: "none",
          errorCode: errorName(error),
          metadata
        });
      }
      throw error;
    }
    if (upstream.status < 200 || upstream.status >= 300) {
      await this.repository.update({
        operationKey,
        status: "failed",
        legacyStatus: String(upstream.status),
        identityStatus: "skipped",
        compensationStatus: "none",
        errorCode: "LegacyRejected",
        metadata
      });
      return { ...upstream, evidence: { ...evidence, identityStatus: "skipped" } };
    }
    await this.repository.update({
      operationKey,
      status: "legacy_completed",
      legacyStatus: String(upstream.status),
      identityStatus: "pending",
      compensationStatus: "none",
      metadata
    });

    try {
      const legacyUser = await this.legacy.getUserById(parsed.legacyUserId);
      if (!legacyUser) throw new Error("LegacyUserReadbackMissing");
      const organizations = normalizeOrganizations(legacyUser.organizations);
      if (!sameIds(organizations.map(({ id }) => id), parsed.organizationIds)) {
        throw new Error("LegacyOrganizationReadbackMismatch");
      }
      await this.repository.replaceCandidate({ operationKey, legacyUserId: parsed.legacyUserId, organizations });
      await this.repository.update({
        operationKey,
        status: "completed",
        legacyStatus: String(upstream.status),
        identityStatus: "candidate-completed",
        compensationStatus: "none",
        metadata
      });
      const completedEvidence = { ...evidence, identityStatus: "candidate-completed" };
      this.logDecision(completedEvidence, parsed.legacyUserId, organizations.length);
      return { ...upstream, mode: "dual-write", evidence: completedEvidence };
    } catch (error) {
      await this.repository.update({
        operationKey,
        status: "legacy_completed",
        legacyStatus: String(upstream.status),
        identityStatus: "candidate-failed",
        compensationStatus: "required",
        errorCode: errorName(error),
        metadata
      });
      const partialEvidence = { ...evidence, identityStatus: "candidate-failed" };
      this.logger.error(JSON.stringify({
        event: "identity.iam.organization_write.partial",
        operationKeyDigest: shortDigest(operationKey),
        correlationId: evidence.correlationId,
        targetFingerprint: evidence.targetFingerprint,
        organizationCount: parsed.organizationIds.length,
        errorCode: errorName(error)
      }));
      return { ...upstream, mode: "dual-write", evidence: partialEvidence };
    }
  }

  private async identityNativeWrite(
    request: PluginUserWriteRequest,
    parsed: SelectedMembershipReplace,
    idempotencyKey: string,
    evidence: IamOrganizationWriteEvidence
  ): Promise<IamOrganizationWriteProxyResponse> {
    assertIdentityNativeMembershipOnlyBody(request.body);
    const claims = this.requireIdentityNativeClaims(request.headers.authorization);
    await this.assertIdentityNativeOperator(claims);
    const iamRepository = this.iamRepository;
    if (!iamRepository?.isConfigured() || !this.repository.isConfigured()) {
      throw new ServiceUnavailableException({
        code: "IAM_ORGANIZATION_WRITE_IDENTITY_NATIVE_NOT_READY",
        message: "Identity-native organization repositories are unavailable."
      });
    }

    const operationKey = organizationWriteOperationKey(parsed.legacyUserId, idempotencyKey);
    const requestFingerprint = organizationWriteRequestFingerprint(parsed.legacyUserId, parsed.organizationIds);
    const metadata = {
      correlationId: evidence.correlationId,
      decision: evidence.decision,
      actorFingerprint: evidence.actorFingerprint,
      targetFingerprint: evidence.targetFingerprint,
      selectorKind: evidence.matchedSelectorKind,
      organizationCount: parsed.organizationIds.length,
      owner: "identity",
      legacyWritePerformed: false
    };
    const lock = await this.repository.withCandidateMaterializationSubjectLock(parsed.legacyUserId, async () => {
      const [target, roleShadow, before, requestedOrganizations] = await Promise.all([
        iamRepository.getIdentityUserByLegacyId(parsed.legacyUserId),
        iamRepository.listRoleAssignmentsShadow(parsed.legacyUserId),
        this.repository.candidateForLegacyUser(parsed.legacyUserId),
        this.repository.candidateOrganizationsByLegacyIds(parsed.organizationIds)
      ]);
      if (!target || target.legacyUserId !== parsed.legacyUserId || target.source !== "legacy-shadow") {
        throw new NotFoundException({
          code: "IAM_ORGANIZATION_WRITE_IDENTITY_TARGET_NOT_FOUND",
          message: "The selected target is not present in the Identity user model."
        });
      }
      if (target.status !== "active") {
        throw new ConflictException({
          code: "IAM_ORGANIZATION_WRITE_INACTIVE_SUBJECT",
          message: "Organization membership can only be changed for an active Identity subject."
        });
      }
      if (
        target.username?.trim().toLowerCase() === "root" ||
        roleShadow.some((role) => role.roleName.trim().toLowerCase() === "root")
      ) {
        throw new ConflictException({
          code: "IAM_ORGANIZATION_WRITE_PROTECTED_SUBJECT",
          message: "Organization membership writes are not allowed for a protected root subject."
        });
      }
      if (!before) {
        throw new ConflictException({
          code: "IAM_ORGANIZATION_WRITE_IDENTITY_CANDIDATE_MISSING",
          message: "Identity-native organization write requires an existing candidate snapshot."
        });
      }
      if (!sameIds(requestedOrganizations.map(({ id }) => id), parsed.organizationIds)) {
        throw new BadRequestException({
          code: "IAM_ORGANIZATION_WRITE_UNKNOWN_ORGANIZATION",
          message: "One or more organization identifiers are not present in the Identity organization catalog."
        });
      }
      const begin = await this.repository.begin({
        operationKey,
        idempotencyKeyDigest: createHash("sha256").update(idempotencyKey).digest("hex"),
        requestFingerprint,
        legacyUserId: parsed.legacyUserId,
        mode: "identity-native",
        metadata
      });
      if (begin.duplicate) {
        const existing = await this.repository.find(operationKey);
        if (
          !existing ||
          existing.mode !== "identity-native" ||
          existing.requestFingerprint !== requestFingerprint
        ) {
          throw new ConflictException({
            code: "IDEMPOTENCY_KEY_REUSED_WITH_DIFFERENT_REQUEST",
            message: "The idempotency key was already used for a different organization membership request."
          });
        }
        if (existing.status !== "completed" || existing.compensationStatus !== "none") {
          throw new ConflictException({
            code: "IAM_ORGANIZATION_WRITE_REPLAY_UNAVAILABLE",
            message: "The recorded Identity-native operation is not safely replayable."
          });
        }
        const current = await this.repository.candidateForLegacyUser(parsed.legacyUserId);
        if (!current || !sameIds(current.organizations.map(({ id }) => id), parsed.organizationIds)) {
          throw new ConflictException({
            code: "IAM_ORGANIZATION_WRITE_REPLAY_STATE_CHANGED",
            message: "The target membership changed after the completed idempotent operation."
          });
        }
        return identityNativeOrganizationResponse(target, current.organizations, evidence);
      }

      let candidateWriteAttempted = false;
      let candidateWriteCompleted = false;
      try {
        candidateWriteAttempted = true;
        await this.repository.replaceCandidate({
          operationKey,
          legacyUserId: parsed.legacyUserId,
          organizations: normalizeOrganizations(requestedOrganizations)
        });
        candidateWriteCompleted = true;
        const after = await this.repository.candidateForLegacyUser(parsed.legacyUserId);
        if (!after || !sameIds(after.organizations.map(({ id }) => id), parsed.organizationIds)) {
          throw new Error("IdentityOrganizationPostcheckMismatch");
        }
        await this.repository.update({
          operationKey,
          status: "completed",
          legacyStatus: "not-called",
          identityStatus: "completed",
          compensationStatus: "none",
          metadata
        });
        return identityNativeOrganizationResponse(target, after.organizations, evidence);
      } catch (error) {
        let compensationStatus: "none" | "completed" | "required" = "none";
        let identityStatus = "failed";
        let restoreRequired = candidateWriteCompleted;
        if (candidateWriteAttempted && !candidateWriteCompleted) {
          try {
            const observed = await this.repository.candidateForLegacyUser(parsed.legacyUserId);
            restoreRequired = Boolean(
              observed && sameIds(observed.organizations.map(({ id }) => id), parsed.organizationIds)
            );
          } catch {
            restoreRequired = true;
          }
        }
        if (restoreRequired) {
          try {
            await this.repository.replaceCandidate({
              operationKey,
              legacyUserId: parsed.legacyUserId,
              organizations: normalizeOrganizations(before.organizations)
            });
            compensationStatus = "completed";
            identityStatus = "failed-restored-before-snapshot";
          } catch {
            compensationStatus = "required";
            identityStatus = "failed-restore-required";
          }
        }
        await this.repository.update({
          operationKey,
          status: "failed",
          legacyStatus: "not-called",
          identityStatus,
          compensationStatus,
          errorCode: errorName(error),
          metadata
        });
        throw error;
      }
    });
    if (!lock.acquired) {
      throw new ConflictException({
        code: "IAM_ORGANIZATION_WRITE_SUBJECT_BUSY",
        message: "Another organization membership operation is active for the selected subject."
      });
    }
    const completedEvidence = { ...evidence, identityStatus: "completed" };
    this.logDecision(completedEvidence, parsed.legacyUserId, parsed.organizationIds.length);
    return { ...lock.value, evidence: completedEvidence };
  }

  private requireIdentityNativeClaims(
    authorization: string | string[] | undefined
  ): VerifiedAccessToken {
    const claims = this.claims(authorization);
    if (!claims) {
      throw new UnauthorizedException({
        code: "IAM_ORGANIZATION_WRITE_OPERATOR_TOKEN_INVALID",
        message: "A valid Identity operator token is required."
      });
    }
    return claims;
  }

  private async assertIdentityNativeOperator(claims: VerifiedAccessToken): Promise<void> {
    let permissions;
    try {
      permissions = await this.legacy.listUserPermissions(claims.uid);
    } catch {
      throw new ServiceUnavailableException({
        code: "IAM_ORGANIZATION_WRITE_OPERATOR_AUTHORIZATION_UNAVAILABLE",
        message: "The reviewed live Yii permission decision is unavailable."
      });
    }
    const verifiedRoot = claims.roles.some((role) => role.trim().toLowerCase() === "root");
    const livePermission = permissions.some((permission) => permission.name === "user-management.update-user");
    if (!verifiedRoot || !livePermission) {
      throw new ForbiddenException({
        code: "IAM_ORGANIZATION_WRITE_OPERATOR_FORBIDDEN",
        message: "The operator does not satisfy the reviewed root and live-permission decision."
      });
    }
  }

  private claims(authorization: string | string[] | undefined): VerifiedAccessToken | null {
    const raw = firstHeader(authorization);
    const match = raw?.match(/^Bearer\s+(.+)$/i);
    if (!match?.[1]) return null;
    try { return this.jwtIssuer.verifyAccessToken(match[1]); } catch { return null; }
  }

  private async legacyProxyReadbackEvidence(
    upstreamStatus: number,
    parsed: SelectedMembershipReplace,
    evidence: IamOrganizationWriteEvidence
  ): Promise<IamOrganizationWriteEvidence> {
    if (upstreamStatus < 200 || upstreamStatus >= 300) return { ...evidence, identityStatus: "skipped" };
    try {
      const legacyUser = await this.legacy.getUserById(parsed.legacyUserId);
      if (!legacyUser) return { ...evidence, identityStatus: "legacy-readback-unavailable" };
      return {
        ...evidence,
        identityStatus: sameIds(legacyUser.organizations.map(({ id }) => id), parsed.organizationIds)
          ? "legacy-readback-aligned"
          : "legacy-readback-mismatch"
      };
    } catch {
      return { ...evidence, identityStatus: "legacy-readback-unavailable" };
    }
  }

  private requireRepository(): void {
    if (!this.repository.isConfigured()) {
      throw new ServiceUnavailableException({ code: "IAM_ORGANIZATION_WRITE_REPOSITORY_NOT_CONFIGURED" });
    }
  }

  private assertCandidateMaterializationPosture(): void {
    const blockedReasons = this.candidateMaterializationPostureBlockedReasons();
    if (blockedReasons.length > 0) {
      throw new ConflictException({
        code: "IAM_ORGANIZATION_CANDIDATE_MATERIALIZATION_UNSAFE_POSTURE",
        message: "Candidate materialization requires a default-off, Legacy-authoritative IAM posture.",
        blockedReasons
      });
    }
  }

  private candidateBatchConfigurationBlockedReasons(): string[] {
    const { iam, identityDb, legacyDb } = this.config;
    return [
      ...(iam.organizationWriteCandidateBatchMaterializationEnvironment !== "xrteeth-develop"
        ? ["candidate-batch-environment-not-xrteeth-develop"]
        : []),
      ...(identityDb.name !== "xrugc_identity_dev" ? ["candidate-batch-identity-database-mismatch"] : []),
      ...(legacyDb.name !== ORGANIZATION_RECONCILIATION_DEVELOP_LEGACY_DATABASE
        ? ["candidate-batch-legacy-database-mismatch"]
        : []),
      ...(!candidateBatchPlanHmacKeyConfigured(iam) ? ["candidate-batch-plan-hmac-key-not-configured"] : []),
      ...(iam.organizationWriteCandidateBatchExpectedLegacySubjectCount <= 0
        ? ["candidate-batch-expected-legacy-subject-count-not-configured"]
        : []),
      ...(iam.organizationWriteCandidateBatchExpectedProtectedSubjectCount <= 0 ||
        iam.organizationWriteCandidateBatchExpectedProtectedSubjectCount >=
          iam.organizationWriteCandidateBatchExpectedLegacySubjectCount
        ? ["candidate-batch-expected-protected-subject-count-not-configured"]
        : [])
    ];
  }

  private assertCandidateBatchConfiguration(): void {
    const blockedReasons = this.candidateBatchConfigurationBlockedReasons();
    if (blockedReasons.length > 0) {
      throw new ServiceUnavailableException({
        code: "IAM_ORGANIZATION_CANDIDATE_BATCH_CONFIGURATION_NOT_READY",
        message: "The xrteeth Develop candidate batch configuration is not complete.",
        blockedReasons
      });
    }
  }

  private requireCandidateBatchPlanHmacKey(): Buffer {
    const key = this.config.iam.organizationWriteCandidateBatchMaterializationPlanHmacKey?.trim().toLowerCase() ?? "";
    if (!/^[a-f0-9]{64}$/.test(key)) {
      throw new ServiceUnavailableException({
        code: "IAM_ORGANIZATION_CANDIDATE_BATCH_PLAN_KEY_NOT_CONFIGURED",
        message: "The candidate batch plan HMAC key is not configured."
      });
    }
    return Buffer.from(key, "hex");
  }

  private candidateMaterializationPostureBlockedReasons(): string[] {
    const { iam } = this.config;
    return [
      ...(!iam.enabled ? ["iam-enabled-required"] : []),
      ...(iam.mode !== "readonly" ? ["iam-readonly-required"] : []),
      ...(!iam.fallbackEnabled ? ["iam-fallback-must-remain-enabled"] : []),
      ...(iam.reconciliationEnabled ? ["iam-reconciliation-must-be-disabled"] : []),
      ...(iam.rolePermissionMaterializationEnabled ? ["role-permission-materialization-must-be-disabled"] : []),
      ...(iam.permissionModelImportEnabled ? ["permission-model-import-must-be-disabled"] : []),
      ...(iam.organizationWriteMode !== "disabled" ? ["organization-write-disabled-required"] : []),
      ...(iam.organizationWriteRouteIntegrationEnabled ? ["organization-route-integration-must-be-disabled"] : []),
      ...(iam.organizationWriteDualWriteExecutionEnabled ? ["organization-dual-write-must-be-disabled"] : []),
      ...(iam.organizationWriteIdentityNativeExecutionEnabled ? ["organization-identity-native-must-be-disabled"] : []),
      ...(iam.organizationWriteRolloutMode !== "off" ? ["organization-rollout-must-be-off"] : []),
      ...(iam.organizationWriteRolloutAllowlist.trim() !== "" ? ["organization-rollout-allowlist-must-be-empty"] : []),
      ...(iam.organizationWriteRolloutPercentage !== 0 ? ["organization-rollout-percentage-must-be-zero"] : []),
      ...(iam.organizationWriteRecoveryDrillEnabled ? ["organization-recovery-drill-must-be-disabled"] : []),
      ...(iam.organizationWriteRecoveryDrillTargetLegacyUserId !== 0 ? ["organization-recovery-drill-target-must-be-zero"] : []),
      ...(iam.roleWriteMode !== "disabled" ? ["role-write-disabled-required"] : []),
      ...(iam.roleWriteDualWriteExecutionEnabled ? ["role-dual-write-must-be-disabled"] : []),
      ...(iam.roleWriteIdentityNativeExecutionEnabled ? ["role-identity-native-must-be-disabled"] : []),
      ...(iam.roleWriteIdentityNativeTargetMode !== "single-target" ? ["role-native-target-mode-must-be-single-target"] : []),
      ...(iam.roleWriteRolloutMode !== "off" ? ["role-rollout-must-be-off"] : []),
      ...(iam.roleWriteRolloutAllowlist.trim() !== "" ? ["role-rollout-allowlist-must-be-empty"] : []),
      ...(iam.roleWriteRolloutPercentage !== 0 ? ["role-rollout-percentage-must-be-zero"] : []),
      ...(Boolean(iam.roleWritePolicyChecksum) ? ["role-policy-checksum-must-be-empty"] : []),
      ...(iam.roleWriteCandidateRestoreEnabled ? ["role-candidate-restore-must-be-disabled"] : []),
      ...(iam.roleWriteCandidateRestoreTargetLegacyUserId !== 0 ? ["role-candidate-restore-target-must-be-zero"] : []),
      ...(iam.roleWriteRecoveryDrillEnabled ? ["role-recovery-drill-must-be-disabled"] : []),
      ...(iam.roleWriteRecoveryDrillTargetLegacyUserId !== 0 ? ["role-recovery-drill-target-must-be-zero"] : []),
      ...(iam.roleWriteIdentityNativeTargetLegacyUserId !== 0 ? ["role-native-target-must-be-zero"] : []),
      ...(iam.roleWriteIdentityNativeTargetAllowlist.trim() !== "" ? ["role-native-target-allowlist-must-be-empty"] : []),
      ...(iam.authzReadMode !== "legacy" ? ["authz-read-must-remain-legacy"] : []),
      ...(iam.authzRolloutMode !== "off" ? ["authz-rollout-must-be-off"] : []),
      ...(iam.authzRolloutAllowlist.trim() !== "" ? ["authz-rollout-allowlist-must-be-empty"] : []),
      ...(iam.authzRetainedLegacyAllowlist.trim() !== "" ? ["authz-retained-allowlist-must-be-empty"] : []),
      ...(iam.authzRolloutPercentage !== 0 ? ["authz-rollout-percentage-must-be-zero"] : []),
      ...(!iam.authzFallbackEnabled ? ["authz-fallback-must-remain-enabled"] : [])
    ];
  }

  private async candidateMaterializationSchemaState(): Promise<{ ready: boolean; blocker: string | null }> {
    if (!this.repository.isConfigured()) return { ready: false, blocker: "identity-organization-candidate-repository" };
    try {
      const readiness = await this.repository.materializationSchemaReadiness();
      return readiness.ready
        ? { ready: true, blocker: null }
        : { ready: false, blocker: "schema-not-ready" };
    } catch {
      return { ready: false, blocker: "schema-readiness-unavailable" };
    }
  }

  private async assertCandidateMaterializationSchemaReady(): Promise<void> {
    const schema = await this.candidateMaterializationSchemaState();
    if (!schema.ready) {
      throw new ServiceUnavailableException({
        code: "IAM_ORGANIZATION_CANDIDATE_MATERIALIZATION_SCHEMA_NOT_READY",
        message: "Organization candidate materialization requires the existing read-only verified schema.",
        blocker: schema.blocker
      });
    }
  }

  private requireCandidateMaterializationInitialSubject(legacyUser: LegacyUserReadModel | null): LegacyUserReadModel {
    if (!legacyUser) {
      throw new NotFoundException({
        code: "IAM_ORGANIZATION_CANDIDATE_MATERIALIZATION_LEGACY_USER_NOT_FOUND",
        message: "The materialization target was not found in Legacy."
      });
    }
    if (legacyUser.status !== 10) {
      throw new ConflictException({
        code: "IAM_ORGANIZATION_CANDIDATE_MATERIALIZATION_INACTIVE_SUBJECT",
        message: "Organization candidate materialization requires an active dedicated subject."
      });
    }
    if (isProtectedOrganizationSubject(legacyUser)) {
      throw new ConflictException({
        code: "IAM_ORGANIZATION_CANDIDATE_MATERIALIZATION_PROTECTED_SUBJECT",
        message: "Organization candidate materialization is not allowed for a protected root subject."
      });
    }
    return legacyUser;
  }

  private async candidateMaterializationFreshPostcheck(
    legacyUserId: number,
    expectedSnapshotFingerprint: string
  ): Promise<OrganizationAlignment> {
    const legacyUser = await this.legacy.getUserById(legacyUserId);
    if (!legacyUser) {
      throw new ServiceUnavailableException({
        code: "IAM_ORGANIZATION_CANDIDATE_MATERIALIZATION_POSTCHECK_LEGACY_USER_MISSING",
        message: "The Legacy subject disappeared after the candidate write."
      });
    }
    if (legacyUser.status !== 10) {
      throw new ServiceUnavailableException({
        code: "IAM_ORGANIZATION_CANDIDATE_MATERIALIZATION_POSTCHECK_INACTIVE_SUBJECT",
        message: "The Legacy subject became inactive during candidate materialization."
      });
    }
    if (isProtectedOrganizationSubject(legacyUser)) {
      throw new ServiceUnavailableException({
        code: "IAM_ORGANIZATION_CANDIDATE_MATERIALIZATION_POSTCHECK_PROTECTED_SUBJECT",
        message: "The Legacy subject became protected during candidate materialization."
      });
    }
    const freshOrganizations = normalizeOrganizations(legacyUser.organizations);
    const freshSnapshotFingerprint = organizationCandidateSnapshotFingerprint(legacyUserId, freshOrganizations);
    if (freshSnapshotFingerprint !== expectedSnapshotFingerprint) {
      throw new ServiceUnavailableException({
        code: "IAM_ORGANIZATION_CANDIDATE_MATERIALIZATION_POSTCHECK_SNAPSHOT_CHANGED",
        message: "The Legacy organization snapshot changed during candidate materialization."
      });
    }
    const candidate = await this.repository.candidateForLegacyUser(legacyUserId);
    const alignment = organizationAlignment(legacyUserId, legacyUser, candidate);
    if (!alignment.aligned || alignment.P0 !== 0 || alignment.P1 !== 0 || alignment.P2 !== 0 || alignment.mismatch !== 0) {
      throw new ServiceUnavailableException({
        code: "IAM_ORGANIZATION_CANDIDATE_MATERIALIZATION_POSTCHECK_FAILED",
        message: "Candidate materialization completed but the alignment postcheck did not pass."
      });
    }
    return alignment;
  }

  private logDecision(evidence: IamOrganizationWriteEvidence, legacyUserId: number, organizationCount: number): void {
    this.logger.log(JSON.stringify({
      event: "identity.iam.organization_write.decision",
      decision: evidence.decision,
      correlationId: evidence.correlationId,
      actorFingerprint: evidence.actorFingerprint,
      targetFingerprint: organizationWriteFingerprint(`legacy:${legacyUserId}`),
      selectorKind: evidence.matchedSelectorKind,
      organizationCount,
      identityStatus: evidence.identityStatus ?? null
    }));
  }
}

interface SelectedMembershipReplace { selected: true; legacyUserId: number; organizationIds: number[]; }

interface OrganizationAlignment {
  legacyUserId: number;
  aligned: boolean;
  mismatch: number;
  P0: number;
  P1: number;
  P2: number;
  reason?: string;
  sourceOfTruth: "legacy";
  legacySnapshotFingerprint: string | null;
  organizationCount: number;
  membershipMismatch?: number[];
  metadataMismatch?: number[];
}

function candidateMaterializationLeaseCutoff(now = Date.now()): Date {
  return new Date(now - ORGANIZATION_CANDIDATE_MATERIALIZATION_PENDING_LEASE_MS);
}

function candidateMaterializationPendingLeaseStale(requestedAt: string | null, now = Date.now()): boolean {
  const requestedAtMs = Date.parse(requestedAt ?? "");
  return Number.isFinite(requestedAtMs) && requestedAtMs <= candidateMaterializationLeaseCutoff(now).getTime();
}

function candidateMaterializationLedgerCasFailure(): ServiceUnavailableException {
  return new ServiceUnavailableException({
    code: "IAM_ORGANIZATION_CANDIDATE_MATERIALIZATION_LEDGER_CAS_FAILED",
    message: "The candidate materialization ledger lease or expected pending state was lost."
  });
}

function assertCandidateMaterializationLedgerState(operation: OrganizationWriteOperationRecord): void {
  const valid =
    (operation.status === "completed" && ["none", "completed"].includes(operation.compensationStatus)) ||
    (operation.status === "pending" && operation.compensationStatus === "none") ||
    (operation.status === "failed" && ["none", "required", "failed"].includes(operation.compensationStatus));
  if (!valid) {
    throw new ServiceUnavailableException({
      code: "IAM_ORGANIZATION_CANDIDATE_MATERIALIZATION_LEDGER_STATE_INVALID",
      message: "The candidate materialization ledger contains an invalid mode-specific state combination."
    });
  }
}

function candidateMaterializationBlockedPreview(legacyUserId: number, blocker: string) {
  return {
    mutation: false,
    executable: false,
    schemaReady: false,
    targetFingerprint: organizationWriteFingerprint(`legacy:${legacyUserId}`),
    expectedSnapshotFingerprint: null,
    organizationCount: null,
    alignment: null,
    unresolvedOperationCount: null,
    sourceOfTruth: "legacy",
    legacyWritePerformed: false,
    identityCandidateWritePerformed: false,
    blockedReasons: [blocker]
  };
}

function uniqueStrings(values: string[]): string[] {
  return [...new Set(values)];
}

function candidateBatchPlanHmacKeyConfigured(
  iam: ReturnType<typeof loadConfig>["iam"]
): boolean {
  return /^[a-f0-9]{64}$/.test(
    iam.organizationWriteCandidateBatchMaterializationPlanHmacKey?.trim().toLowerCase() ?? ""
  );
}

function candidateBatchLegacyUser(source: LegacyOrganizationCandidateSourceUser): LegacyUserReadModel {
  return {
    id: source.id,
    username: source.username,
    email: null,
    status: source.status,
    nickname: null,
    emailVerifiedAt: null,
    createdAt: null,
    updatedAt: null,
    userInfo: {},
    roles: [...source.roles],
    organizations: source.organizations.map((organization) => ({ ...organization })),
    source: "legacy"
  };
}

function candidateBatchPublicPlan(
  plan: OrganizationCandidateBatchPlan,
  input: { applyEnabled: boolean; postureBlockers: string[] }
) {
  const blockedReasons = uniqueStrings([
    ...plan.blockers,
    ...input.postureBlockers
  ]);
  return {
    contract: ORGANIZATION_CANDIDATE_BATCH_MATERIALIZATION_CONTRACT,
    mutation: false,
    executable: blockedReasons.length === 0,
    applyEnabled: input.applyEnabled,
    planToken: plan.planToken,
    legacySubjectCount: plan.legacySubjectCount,
    ordinarySubjectCount: plan.ordinarySubjectCount,
    protectedSubjectCount: plan.protectedSubjectCount,
    ordinaryAlignedCount: plan.ordinaryAlignedCount,
    ordinaryMissingCount: plan.ordinaryMissingCount,
    ordinaryBlockedCount: plan.ordinaryBlockedCount,
    inactiveOrdinaryCount: plan.inactiveOrdinaryCount,
    protectedAlignedCount: plan.protectedAlignedCount,
    protectedMissingCount: plan.protectedMissingCount,
    sourceOfTruth: "legacy" as const,
    legacyWritePerformed: false,
    identityCandidateWritePerformed: false,
    protectedSubjectWritePerformed: false,
    blockedReasons
  };
}

function candidateBatchPlanTokenInput(value: string | undefined): string {
  const normalized = value?.trim().toLowerCase() ?? "";
  if (!/^[a-f0-9]{64}$/.test(normalized)) {
    throw new BadRequestException({
      code: "IAM_ORGANIZATION_CANDIDATE_BATCH_PLAN_TOKEN_REQUIRED",
      message: "A reviewed 64-character candidate batch plan token is required."
    });
  }
  return normalized;
}

function constantTimeHexEqual(left: string, right: string): boolean {
  if (!/^[a-f0-9]{64}$/.test(left) || !/^[a-f0-9]{64}$/.test(right)) return false;
  return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

function candidateBatchSubjectIdempotencyKey(input: {
  planToken: string;
  idempotencyKey: string;
  legacyUserId: number;
  key: Buffer;
}): string {
  try {
    return createHmac("sha256", input.key)
      .update("iam-organization-candidate-batch-subject-idempotency:v1\u001f", "utf8")
      .update(input.planToken, "utf8")
      .update("\u001f", "utf8")
      .update(input.idempotencyKey, "utf8")
      .update("\u001f", "utf8")
      .update(String(input.legacyUserId), "utf8")
      .digest("hex");
  } finally {
    input.key.fill(0);
  }
}

function parseMembershipReplace(body: unknown): SelectedMembershipReplace | { selected: false } {
  if (!body || typeof body !== "object" || Array.isArray(body) || isProxy(body)) return { selected: false };
  const descriptors = Object.getOwnPropertyDescriptors(body);
  const idDescriptor = descriptors.id;
  const organizationDescriptor = descriptors.organization_ids;
  if (!organizationDescriptor || !("value" in organizationDescriptor) || !idDescriptor || !("value" in idDescriptor)) {
    return { selected: false };
  }
  const legacyUserId = Number(idDescriptor.value);
  if (!Number.isSafeInteger(legacyUserId) || legacyUserId <= 0 || !Array.isArray(organizationDescriptor.value)) return { selected: false };
  const ids = organizationDescriptor.value.map(Number);
  if (ids.some((id) => !Number.isSafeInteger(id) || id <= 0)) return { selected: false };
  return { selected: true, legacyUserId, organizationIds: [...new Set(ids)].sort((a, b) => a - b) };
}

function identityNativeOrganizationFieldMalformed(body: unknown): boolean {
  if (!body || typeof body !== "object" || Array.isArray(body)) return false;
  if (isProxy(body)) return true;
  const descriptors = Object.getOwnPropertyDescriptors(body);
  const descriptor = descriptors.organization_ids;
  if (!descriptor) return false;
  if (!("value" in descriptor) || !Array.isArray(descriptor.value)) return true;
  return descriptor.value.some((value) => typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0);
}

function assertIdentityNativeMembershipOnlyBody(body: unknown): void {
  if (!body || typeof body !== "object" || Array.isArray(body) || isProxy(body)) {
    throw new BadRequestException({ code: "IAM_ORGANIZATION_WRITE_INPUT_INVALID" });
  }
  const descriptors = Object.getOwnPropertyDescriptors(body);
  if (Object.values(descriptors).some((descriptor) => !("value" in descriptor))) {
    throw new BadRequestException({ code: "IAM_ORGANIZATION_WRITE_INPUT_INVALID" });
  }
  const unsupportedFields = Object.keys(descriptors).filter((key) => key !== "id" && key !== "organization_ids");
  if (unsupportedFields.length > 0) {
    throw new ConflictException({
      code: "IAM_ORGANIZATION_WRITE_MIXED_UPDATE_UNSUPPORTED",
      message: "The first Identity-native window accepts an organization-only membership replacement.",
      unsupportedFields: unsupportedFields.sort()
    });
  }
}

function identityNativeOrganizationResponse(
  target: IdentityUserRow,
  organizations: LegacyOrganization[],
  evidence: IamOrganizationWriteEvidence
): IamOrganizationWriteProxyResponse {
  const metadata = target.metadata && typeof target.metadata === "object" && !Array.isArray(target.metadata)
    ? target.metadata as Record<string, unknown>
    : {};
  return {
    status: 200,
    mode: "identity-native",
    evidence,
    body: {
      code: 0,
      data: {
        id: target.legacyUserId,
        username: target.username,
        email: target.email,
        status: target.status === "active" ? 10 : 0,
        nickname: typeof metadata.legacyNickname === "string" ? metadata.legacyNickname : null,
        created_at: finiteNumber(metadata.legacyCreatedAt),
        updated_at: finiteNumber(metadata.legacyUpdatedAt),
        organizations: normalizeOrganizations(organizations)
      }
    }
  };
}

function finiteNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function organizationRolloutReadiness(iam: ReturnType<typeof loadConfig>["iam"]) {
  const allowlist = splitCsv(iam.organizationWriteRolloutAllowlist);
  const selectionConfigured =
    iam.organizationWriteRolloutMode === "full" ||
    (iam.organizationWriteRolloutMode === "allowlist" && allowlist.length > 0) ||
    (iam.organizationWriteRolloutMode === "percentage" && iam.organizationWriteRolloutPercentage > 0);
  return { mode: iam.organizationWriteRolloutMode, allowlistCount: allowlist.length, percentage: iam.organizationWriteRolloutPercentage, selectionConfigured };
}

function organizationRolloutDecision(
  iam: ReturnType<typeof loadConfig>["iam"],
  legacyUserId: number,
  claims: VerifiedAccessToken | null
): { selected: boolean; decision: string; selectorKind: string | null } {
  if (iam.organizationWriteRolloutMode === "full") return { selected: true, decision: "selected:full", selectorKind: "full" };
  const tokens = new Set([`legacy:${legacyUserId}`, `uid:${legacyUserId}`, ...(claims ? [`actor:${claims.uid}`] : [])].map(normalizeSelector));
  if (iam.organizationWriteRolloutMode === "allowlist") {
    const match = splitCsv(iam.organizationWriteRolloutAllowlist).map(normalizeSelector).find((item) => tokens.has(item));
    return match
      ? { selected: true, decision: "selected:allowlist", selectorKind: match.split(":", 1)[0] ?? "allowlist" }
      : { selected: false, decision: "not-selected:allowlist", selectorKind: null };
  }
  if (iam.organizationWriteRolloutMode === "percentage") {
    const bucket = Number.parseInt(createHash("sha256").update(`legacy:${legacyUserId}`).digest("hex").slice(0, 8), 16) % 100;
    return bucket < iam.organizationWriteRolloutPercentage
      ? { selected: true, decision: "selected:percentage", selectorKind: "percentage" }
      : { selected: false, decision: "not-selected:percentage", selectorKind: "percentage" };
  }
  return { selected: false, decision: "not-selected:off", selectorKind: null };
}

function compareOrganizations(legacy: LegacyOrganization[], candidate: LegacyOrganization[]) {
  const legacyMap = new Map(legacy.map((item) => [item.id, item]));
  const candidateMap = new Map(candidate.map((item) => [item.id, item]));
  const membershipMismatch = [...new Set([...legacyMap.keys(), ...candidateMap.keys()])].filter((id) => !legacyMap.has(id) || !candidateMap.has(id));
  const metadataMismatch = [...legacyMap.keys()].filter((id) => {
    const left = legacyMap.get(id); const right = candidateMap.get(id);
    return Boolean(right && (left?.name !== right.name || left?.title !== right.title));
  });
  const P1 = membershipMismatch.length;
  const P2 = metadataMismatch.length;
  return { mismatch: P1 + P2, P0: 0, P1, P2, membershipMismatch, metadataMismatch };
}

function normalizeOrganizations(value: LegacyOrganization[]): LegacyOrganization[] {
  return [...value].sort((a, b) => a.id - b.id).map((item) => ({ ...item }));
}

function organizationAlignment(
  legacyUserId: number,
  legacyUser: LegacyUserReadModel | null,
  candidate: OrganizationCandidateSnapshot | null
): OrganizationAlignment {
  if (!legacyUser) {
    return {
      legacyUserId,
      aligned: false,
      mismatch: 1,
      P0: 1,
      P1: 0,
      P2: 0,
      reason: "legacy-user-not-found",
      sourceOfTruth: "legacy",
      legacySnapshotFingerprint: null,
      organizationCount: 0
    };
  }
  const organizations = normalizeOrganizations(legacyUser.organizations);
  const legacySnapshotFingerprint = organizationCandidateSnapshotFingerprint(legacyUserId, organizations);
  if (!candidate) {
    return {
      legacyUserId,
      aligned: false,
      mismatch: Math.max(1, organizations.length),
      P0: 0,
      P1: Math.max(1, organizations.length),
      P2: 0,
      reason: "identity-candidate-snapshot-missing",
      sourceOfTruth: "legacy",
      legacySnapshotFingerprint,
      organizationCount: organizations.length
    };
  }
  const comparison = compareOrganizations(organizations, candidate.organizations);
  return {
    legacyUserId,
    aligned: comparison.mismatch === 0,
    ...comparison,
    sourceOfTruth: "legacy",
    legacySnapshotFingerprint,
    organizationCount: organizations.length
  };
}

function candidateSnapshotFingerprintInput(value: string | undefined): string {
  const normalized = value?.trim().toLowerCase() ?? "";
  if (!/^[a-f0-9]{64}$/.test(normalized)) {
    throw new BadRequestException({
      code: "IAM_ORGANIZATION_CANDIDATE_MATERIALIZATION_FINGERPRINT_REQUIRED",
      message: "A reviewed 64-character Legacy snapshot fingerprint is required."
    });
  }
  return normalized;
}

function candidateMaterializationIdempotencyKey(value: string | undefined): string {
  const normalized = value?.trim() ?? "";
  if (!normalized || normalized.length > 180) {
    throw new BadRequestException({
      code: "IAM_ORGANIZATION_CANDIDATE_MATERIALIZATION_IDEMPOTENCY_KEY_REQUIRED",
      message: "A 1-180 character Idempotency-Key is required."
    });
  }
  return normalized;
}

function candidateMaterializationResult(input: {
  operationKey: string;
  before: OrganizationAlignment;
  after: OrganizationAlignment;
  organizationCount: number;
  replay: boolean;
}) {
  return {
    materialized: !input.replay,
    idempotentReplay: input.replay,
    operationKeyDigest: shortDigest(input.operationKey),
    subjectFingerprint: organizationWriteFingerprint(`legacy:${input.before.legacyUserId}`),
    snapshotFingerprint: input.before.legacySnapshotFingerprint
      ? shortDigest(input.before.legacySnapshotFingerprint)
      : null,
    organizationCount: input.organizationCount,
    before: alignmentSummary(input.before),
    after: alignmentSummary(input.after),
    safety: {
      legacyWritePerformed: false,
      identityCandidateWritePerformed: !input.replay,
      historicalMutationReplayed: false,
      legacyRemainsAuthoritative: true,
      authzInputChanged: false,
      writeScope: "identity-candidate-only"
    }
  };
}

function alignmentSummary(value: OrganizationAlignment) {
  return {
    aligned: value.aligned,
    mismatch: value.mismatch,
    P0: value.P0,
    P1: value.P1,
    P2: value.P2,
    reason: value.reason ?? null,
    organizationCount: value.organizationCount
  };
}

function isProtectedOrganizationSubject(user: LegacyUserReadModel): boolean {
  return user.username?.trim().toLowerCase() === "root" ||
    user.roles.some((role) => role.trim().toLowerCase() === "root");
}
function sameIds(left: number[], right: number[]): boolean { return left.length === right.length && [...left].sort((a, b) => a - b).every((id, index) => id === [...right].sort((a, b) => a - b)[index]); }
function clientIdempotencyKey(headers: PluginUserWriteRequest["headers"]): string | null {
  const primary = firstHeader(headers["idempotency-key"])?.trim() ?? null;
  const alias = firstHeader(headers["x-idempotency-key"])?.trim() ?? null;
  if (primary && alias && primary !== alias) {
    throw new BadRequestException({
      code: "IDEMPOTENCY_KEY_CONFLICT",
      message: "Conflicting idempotency headers were provided."
    });
  }
  const normalized = primary || alias || "";
  if (!normalized) return null;
  if (normalized.length > 180) {
    throw new BadRequestException({
      code: "IDEMPOTENCY_KEY_INVALID",
      message: "The idempotency key must contain between 1 and 180 characters."
    });
  }
  return normalized;
}
function splitCsv(value: string): string[] { return value.split(",").map((item) => item.trim()).filter(Boolean); }
function normalizeSelector(value: string): string { return value.trim().toLowerCase().replace(/^subject:/, "uid:"); }
function firstHeader(value: string | string[] | undefined): string | null { return Array.isArray(value) ? value[0] ?? null : value ?? null; }
function normalizeNumber(value: number | undefined, fallback: number, min: number, max: number): number { return Math.max(min, Math.min(max, Number.isFinite(value) ? Math.trunc(value as number) : fallback)); }
function shortDigest(value: string): string { return createHash("sha256").update(value).digest("hex").slice(0, 16); }
function errorName(error: unknown): string { return error instanceof Error ? error.name || "Error" : "UnknownError"; }
