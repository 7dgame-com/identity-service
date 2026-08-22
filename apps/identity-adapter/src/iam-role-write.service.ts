import { createHash, randomUUID } from "node:crypto";
import { ConflictException, Injectable, Logger, NotFoundException, ServiceUnavailableException, UnauthorizedException } from "@nestjs/common";
import { loadConfig } from "./config.js";
import {
  type IamRoleWriteEvidence,
  normalizeRoleWriteSelector,
  roleWriteActorFingerprint,
  roleWriteActorTokens,
  roleWriteCorrelationId,
  roleWriteSelectorKind
} from "./iam-role-write-evidence.js";
import { IamRepository } from "./iam.repository.js";
import {
  identityNativeRoleWriteTargetDecision,
  identityNativeRoleWriteTargetScope,
  type IdentityNativeRoleWriteTargetDecision
} from "./iam-role-write-target-control.js";
import { createIamPermissionPolicySnapshot } from "./iam-permission-model.js";
import { JwtIssuerService, type VerifiedAccessToken } from "./jwt-issuer.service.js";
import { LegacyIdentityReader } from "./legacy-identity.reader.js";
import {
  type PluginUserWriteOperationRecord,
  PluginUserWriteOperationRepository,
  pluginUserWriteCompensationMetadata,
  pluginUserWriteOperationKey,
  pluginUserWriteReplayResponseFromOperation,
  pluginUserWriteRequestFingerprint,
  pluginUserWriteResponseReplayMetadata,
  redactPluginUserWriteMetadata
} from "./plugin-user-write-operation.repository.js";
import { PluginUserWriteService } from "./plugin-user-write.service.js";

export interface IamRoleWriteRequest {
  method: string;
  originalUrl?: string;
  headers: Record<string, string | string[] | undefined>;
  body?: unknown;
}

export interface IamRoleWriteProxyResponse {
  status: number;
  body: unknown;
  mode: "legacy-proxy" | "dual-write" | "identity-native";
  evidence?: IamRoleWriteEvidence;
}

type RoleWriteContract = "plugin-user-change-role" | "people-auth";
type RoleWriteRoute = "change-role" | "people-auth";

const ROLE_WRITE_MODES = ["disabled", "legacy-proxy", "dual-write", "identity-native"] as const;
const ROLE_WRITE_ROUTES: RoleWriteRoute[] = ["change-role", "people-auth"];
const ROLE_LEVELS: Record<string, number> = { user: 1, manager: 2, admin: 3, root: 4 };
const VALID_IDENTITY_NATIVE_ROLES = new Set(Object.keys(ROLE_LEVELS));
const REQUIRED_BEFORE_DUAL_WRITE = [
  "legacy-proxy-contract-compatibility",
  "candidate-policy-checksum",
  "operation-ledger",
  "idempotency-keys",
  "legacy-first-execution",
  "identity-assignment-recovery",
  "root-protection",
  "allowlist-or-percentage-rollout"
] as const;

@Injectable()
export class IamRoleWriteService {
  private readonly config = loadConfig();
  private readonly logger = new Logger(IamRoleWriteService.name);

  constructor(
    private readonly operations: PluginUserWriteOperationRepository,
    private readonly iamRepository: IamRepository,
    private readonly legacyReader: LegacyIdentityReader,
    private readonly jwtIssuer: JwtIssuerService,
    private readonly pluginUserWrite: PluginUserWriteService
  ) {}

  async readiness() {
    const { iam } = this.config;
    const rollout = roleWriteRolloutReadiness(iam);
    const identityNativeTargetScope = identityNativeRoleWriteTargetScope(iam);
    const dualWriteGate = await this.dualWriteGate(rollout);
    const identityNativeGate = await this.identityNativeGate(rollout);
    const modeBlocked =
      (iam.roleWriteMode === "identity-native" && !identityNativeGate.executable) ||
      (iam.roleWriteMode === "dual-write" && !dualWriteGate.executable);

    return {
      enabled: iam.roleWriteMode !== "disabled",
      mode: iam.roleWriteMode,
      sourceOfTruth:
        iam.roleWriteMode === "identity-native" && identityNativeGate.executable
          ? "identity-candidate-for-selected-role-writes"
          : iam.roleWriteMode === "dual-write" && dualWriteGate.executable
            ? "legacy-with-identity-candidate"
            : "legacy",
      routes: ROLE_WRITE_ROUTES,
      legacyProxyConfigured: Boolean(iam.roleWriteLegacyApiBaseUrl),
      timeoutMs: iam.roleWriteTimeoutMs,
      operationLedgerConfigured: this.operations.isConfigured(),
      identityRepositoryConfigured: this.iamRepository.isConfigured(),
      legacyReaderConfigured: this.legacyReader.isConfigured(),
      policyChecksumConfigured: Boolean(iam.roleWritePolicyChecksum),
      dualWriteExecutionEnabled: iam.roleWriteDualWriteExecutionEnabled,
      identityNativeExecutionEnabled: iam.roleWriteIdentityNativeExecutionEnabled,
      identityNativeTargetConfigured: identityNativeTargetScope.configured,
      identityNativeTargetScope,
      identityNativeUnownedTargetBehavior: "legacy-proxy",
      identityNativeOwnedTargetUnselectedBehavior: "fail-closed",
      rollout,
      rootProtection: {
        legacyOwnerEnforced: true,
        identityCandidateGuardEnabled: true,
        roleRootNeverMaterialized: true
      },
      allowedExecutableModes: [...ROLE_WRITE_MODES],
      responseShapePreservedInLegacyProxy: true,
      recoveryEndpoint: "/internal/iam/role-write/operations/:operationKey/retry-identity-shadow",
      subjectAlignment: {
        endpoint: "/internal/iam/role-write/subjects/:legacyUserId/alignment?checksum=:policyChecksum",
        readOnly: true,
        requiresInternalToken: true,
        requiresExplicitChecksum: true,
        operationHistoryScope: "all"
      },
      candidateRestore: {
        enabled: iam.roleWriteCandidateRestoreEnabled,
        targetConfigured: iam.roleWriteCandidateRestoreTargetLegacyUserId > 0,
        endpoint: "/internal/iam/role-write/subjects/:legacyUserId/restore-candidate",
        requiresInternalToken: true,
        requiresExplicitChecksum: true,
        sourceOfTruth: "legacy",
        mutatesLegacy: false,
        writeScope: "identity-candidate-only"
      },
      recoveryDrill: {
        enabled: iam.roleWriteRecoveryDrillEnabled,
        targetConfigured: iam.roleWriteRecoveryDrillTargetLegacyUserId > 0,
        endpoint: "/internal/iam/role-write/recovery-drill/prepare",
        mutatesLegacy: false,
        requiresInternalToken: true
      },
      dualWriteGate,
      identityNativeGate,
      blockedReasons: modeBlocked
        ? iam.roleWriteMode === "identity-native"
          ? identityNativeGate.missingCapabilities
          : dualWriteGate.missingCapabilities
        : [],
      requiredBeforeDualWrite: [...REQUIRED_BEFORE_DUAL_WRITE]
    };
  }

  async operationLedgerSummary(input: { sinceMinutes?: number }) {
    const sinceMinutes = normalizeSinceMinutes(input.sinceMinutes);
    if (!this.operations.isConfigured()) {
      return { configured: false, sinceMinutes, routes: [] };
    }
    const routes = await this.operations.summarizeRecent({ sinceMinutes });
    return { configured: true, sinceMinutes, routes: routes.filter((row) => ROLE_WRITE_ROUTES.includes(row.route as RoleWriteRoute)) };
  }

  async operationLedgerRecent(input: { sinceMinutes?: number; limit?: number }) {
    const sinceMinutes = normalizeSinceMinutes(input.sinceMinutes);
    const limit = normalizeRecentLimit(input.limit);
    if (!this.operations.isConfigured()) {
      return { configured: false, sinceMinutes, limit, operations: [] };
    }
    const operations = await this.operations.listRecentSafe({ sinceMinutes, limit: Math.min(200, limit * 3) });
    return {
      configured: true,
      sinceMinutes,
      limit,
      operations: operations.filter((operation) => ROLE_WRITE_ROUTES.includes(operation.route as RoleWriteRoute)).slice(0, limit)
    };
  }

  async operationLedgerBaseline(legacyUserId: number) {
    if (!this.operations.isConfigured()) {
      return {
        configured: false,
        readOnly: true,
        writePerformed: false,
        global: { total: 0, completed: 0, unresolved: 0 },
        target: { total: 0, completed: 0, unresolved: 0 },
        uniqueCompletedTargetCount: 0,
        targetUnique: false
      };
    }
    const summary = await this.operations.summarizeBaselineForLegacyUser(legacyUserId);
    if (!summary) {
      return {
        configured: true,
        readOnly: true,
        writePerformed: false,
        global: { total: 0, completed: 0, unresolved: 0 },
        target: { total: 0, completed: 0, unresolved: 0 },
        uniqueCompletedTargetCount: 0,
        targetUnique: false
      };
    }
    return {
      configured: true,
      readOnly: true,
      writePerformed: false,
      ...summary,
      targetUnique: summary.target.total > 0 && summary.uniqueCompletedTargetCount === 1
    };
  }

  /**
   * Explains why a configured role-write candidate is (or is not) executable without
   * disclosing a policy checksum or mutating Legacy, Identity, or the operation ledger.
   */
  async policyDiagnostics(policyChecksumOverride?: string) {
    const { iam } = this.config;
    const configuredChecksum = policyChecksumOverride ?? iam.roleWritePolicyChecksum;
    const sources = {
      legacyReaderConfigured: this.legacyReader.isConfigured(),
      identityRepositoryConfigured: this.iamRepository.isConfigured()
    };

    if (!sources.legacyReaderConfigured || !sources.identityRepositoryConfigured) {
      return {
        readOnly: true,
        legacyRemainsAuthoritative: true,
        writes: { legacy: false, identityCandidate: false, operationLedger: false },
        sources,
        configuredPolicy: {
          checksumConfigured: Boolean(configuredChecksum),
          matchesCurrentLegacyPolicy: false,
          candidateLookup: "not_checked" as const
        },
        currentLegacyPolicy: {
          previewAvailable: false,
          candidateLookup: "not_checked" as const,
          roleCount: 0,
          permissionCount: 0,
          relationCount: 0
        },
        blockedReasons: [
          ...(!sources.legacyReaderConfigured ? ["legacy-reader"] : []),
          ...(!sources.identityRepositoryConfigured ? ["identity-repository"] : [])
        ]
      };
    }

    const currentLegacyPolicy = createIamPermissionPolicySnapshot(await this.legacyReader.readRbacPolicySnapshot());
    const currentLookup = await this.policyCandidateLookup(currentLegacyPolicy.checksum);
    const configuredMatchesCurrentLegacyPolicy = Boolean(configuredChecksum) && configuredChecksum === currentLegacyPolicy.checksum;
    const configuredLookup = configuredMatchesCurrentLegacyPolicy
      ? currentLookup
      : await this.policyCandidateLookup(configuredChecksum);

    return {
      readOnly: true,
      legacyRemainsAuthoritative: true,
      writes: { legacy: false, identityCandidate: false, operationLedger: false },
      sources,
      configuredPolicy: {
        checksumConfigured: Boolean(configuredChecksum),
        matchesCurrentLegacyPolicy: configuredMatchesCurrentLegacyPolicy,
        candidateLookup: configuredLookup
      },
      currentLegacyPolicy: {
        previewAvailable: true,
        candidateLookup: currentLookup,
        roleCount: currentLegacyPolicy.roles.length,
        permissionCount: currentLegacyPolicy.permissions.length,
        relationCount: currentLegacyPolicy.relations.length
      },
      blockedReasons: policyDiagnosticsBlockedReasons({
        configuredChecksumPresent: Boolean(configuredChecksum),
        configuredMatchesCurrentLegacyPolicy,
        configuredLookup,
        currentLookup
      })
    };
  }

  async subjectAlignment(input: { legacyUserId: number; policyChecksum: string }) {
    if (!this.legacyReader.isConfigured()) {
      throw new ServiceUnavailableException({
        code: "LEGACY_IAM_SOURCE_NOT_CONFIGURED",
        message: "Legacy IAM source is not configured for role-write subject alignment."
      });
    }
    if (!this.iamRepository.isConfigured() || !this.operations.isConfigured()) {
      throw new ServiceUnavailableException({
        code: "IAM_ROLE_WRITE_ALIGNMENT_NOT_CONFIGURED",
        message: "Identity candidate and operation ledger are required for role-write subject alignment."
      });
    }

    const legacyUser = await this.legacyReader.getUserById(input.legacyUserId);
    if (!legacyUser) {
      throw new NotFoundException({
        code: "IAM_ROLE_WRITE_ALIGNMENT_SUBJECT_NOT_FOUND",
        message: "The requested Legacy subject was not found."
      });
    }
    const policy = await this.iamRepository.getPermissionPolicyCandidate(input.policyChecksum);
    if (!policy) {
      throw new NotFoundException({
        code: "IAM_ROLE_WRITE_ALIGNMENT_POLICY_NOT_FOUND",
        message: "The requested Identity permission candidate was not found."
      });
    }

    const identityUserId = `legacy:${input.legacyUserId}`;
    const [legacyRows, candidateRows, operationSummary] = await Promise.all([
      this.legacyReader.listUserRbacAssignments(input.legacyUserId),
      this.iamRepository.listSubjectAssignments(identityUserId, input.policyChecksum),
      this.operations.summarizeForLegacyUser(input.legacyUserId)
    ]);
    if (!operationSummary) {
      throw new ServiceUnavailableException({
        code: "IAM_ROLE_WRITE_LEDGER_NOT_AVAILABLE",
        message: "Role-write operation ledger is not available for subject alignment."
      });
    }
    const legacyAssignments = normalizeAssignmentKeys(legacyRows);
    const candidateAssignments = normalizeAssignmentKeys(candidateRows);
    const policyAssignments = normalizeAssignmentKeys([
      ...policy.roles.map((role) => ({ name: role.name, type: "role" as const })),
      ...policy.permissions.map((permission) => ({ name: permission.name, type: "permission" as const }))
    ]);
    const missingInCandidate = legacyAssignments.filter((assignment) => !candidateAssignments.includes(assignment));
    const extraInCandidate = candidateAssignments.filter((assignment) => !legacyAssignments.includes(assignment));
    const legacyOutsidePolicy = legacyAssignments.filter((assignment) => !policyAssignments.includes(assignment));
    const candidateOutsidePolicy = candidateAssignments.filter((assignment) => !policyAssignments.includes(assignment));
    const rootInLegacy = legacyAssignments.includes("role:root");
    const rootInCandidate = candidateAssignments.includes("role:root");
    const unresolvedOperationCount = operationSummary
      .filter((row) => row.status !== "completed" || !["none", "completed"].includes(row.compensationStatus))
      .reduce((total, row) => total + row.total, 0);
    const assignmentAligned = missingInCandidate.length === 0 && extraInCandidate.length === 0;
    const blockedReasons = [
      ...(!assignmentAligned ? ["candidate-assignment-mismatch"] : []),
      ...(legacyOutsidePolicy.length > 0 ? ["legacy-assignment-outside-policy"] : []),
      ...(candidateOutsidePolicy.length > 0 ? ["candidate-assignment-outside-policy"] : []),
      ...(rootInLegacy || rootInCandidate ? ["root-subject-protected"] : []),
      ...(unresolvedOperationCount > 0 ? ["unresolved-role-write-operation"] : [])
    ];

    return {
      legacyUserId: input.legacyUserId,
      subjectFingerprint: shortDigest(identityUserId),
      policyChecksum: input.policyChecksum,
      assignments: {
        legacy: legacyAssignments,
        candidate: candidateAssignments,
        missingInCandidate,
        extraInCandidate,
        legacyOutsidePolicy,
        candidateOutsidePolicy,
        aligned: assignmentAligned
      },
      operations: {
        summary: operationSummary,
        unresolvedCount: unresolvedOperationCount
      },
      rootProtection: {
        legacyRoot: rootInLegacy,
        candidateRoot: rootInCandidate,
        protected: rootInLegacy || rootInCandidate
      },
      safetyGate: {
        passed: blockedReasons.length === 0,
        canRequestRuntime: blockedReasons.length === 0,
        requiresCandidateRestore:
          !assignmentAligned &&
          legacyOutsidePolicy.length === 0 &&
          !rootInLegacy &&
          !rootInCandidate,
        blockedReasons
      },
      safety: {
        readOnly: true,
        writePerformed: false,
        legacyRemainsAuthoritative: true,
        permissionUnionApplied: false
      }
    };
  }

  async proxyPluginUser(request: IamRoleWriteRequest): Promise<IamRoleWriteProxyResponse> {
    if (this.config.iam.roleWriteMode === "disabled") {
      this.assertRequiredDualWriteAvailable(request, "role_write_disabled");
      return this.pluginUserWrite.proxy(request, "/v1/plugin-user/change-role");
    }
    return this.proxy(request, "plugin-user-change-role");
  }

  async proxyPeopleAuth(request: IamRoleWriteRequest): Promise<IamRoleWriteProxyResponse> {
    return this.proxy(request, "people-auth");
  }

  async previewPluginUserRollout(request: IamRoleWriteRequest, targetLegacyUserId?: number) {
    const claims = this.requireClaims(request.headers.authorization);
    const correlationId = roleWriteCorrelationId(request.headers);
    const decision = this.config.iam.roleWriteMode === "dual-write" || this.config.iam.roleWriteMode === "identity-native"
      ? this.dualWriteRolloutDecision(request, "plugin-user-change-role", correlationId, claims)
      : this.inactiveRolloutDecision(request, "plugin-user-change-role", correlationId, claims);
    const rollout = roleWriteRolloutReadiness(this.config.iam);
    const dualWriteGate = this.config.iam.roleWriteMode === "dual-write"
      ? await this.dualWriteGate(rollout)
      : {
          executable: false,
          missingCapabilities: ["role-write-mode-not-dual-write"]
        };
    const identityNativeGate = this.config.iam.roleWriteMode === "identity-native"
      ? await this.identityNativeGate(rollout)
      : { executable: false, missingCapabilities: ["role-write-mode-not-identity-native"] };
    const evidence = evidenceFromDecision(decision);
    const targetScope = identityNativeRoleWriteTargetScope(this.config.iam);
    const targetDecision = targetLegacyUserId
      ? await this.identityNativeTargetDecision(targetLegacyUserId)
      : null;
    const effectiveSelected =
      this.config.iam.roleWriteMode === "identity-native"
        ? decision.selected && targetDecision?.owned === true
        : decision.selected;
    const effectiveWriteOwner = this.config.iam.roleWriteMode !== "identity-native" || targetDecision?.owned === false
      ? "legacy"
      : targetDecision?.owned === true && identityNativeGate.executable && decision.selected
        ? "identity"
        : "blocked";

    this.logRolloutDecision(decision, true);
    return {
      writePerformed: false,
      sourceOfTruth:
        effectiveWriteOwner === "identity"
          ? "identity-candidate"
          : effectiveWriteOwner === "legacy"
            ? "legacy"
            : "unavailable",
      roleWriteMode: this.config.iam.roleWriteMode,
      rolloutMode: decision.mode,
      selected: decision.selected,
      effectiveSelected,
      effectiveWriteOwner,
      targetProvided: targetLegacyUserId !== undefined,
      targetOwned: targetDecision?.owned ?? null,
      targetReason: targetDecision?.reason ?? "target_not_provided",
      identityNativeTargetScope: targetScope,
      reason: decision.reason,
      dualWriteExecutable: dualWriteGate.executable,
      identityNativeExecutable: identityNativeGate.executable,
      missingCapabilities:
        this.config.iam.roleWriteMode === "identity-native"
          ? identityNativeGate.missingCapabilities
          : dualWriteGate.missingCapabilities,
      ...evidence
    };
  }

  async retryIdentityShadow(operationKey: string) {
    if (!operationKey.startsWith("plugin-user-write:v1:")) {
      throw new NotFoundException({ code: "IAM_ROLE_WRITE_OPERATION_NOT_FOUND", message: "Role-write operation was not found." });
    }
    if (!this.operations.isConfigured()) {
      throw new ServiceUnavailableException({ code: "IAM_ROLE_WRITE_LEDGER_NOT_CONFIGURED", message: "Role-write ledger is not configured." });
    }
    const operation = await this.operations.findByOperationKey(operationKey);
    if (!operation || !ROLE_WRITE_ROUTES.includes(operation.route as RoleWriteRoute)) {
      throw new NotFoundException({ code: "IAM_ROLE_WRITE_OPERATION_NOT_FOUND", message: "Role-write operation was not found." });
    }
    if (operation.status === "completed") {
      return { operationKeyDigest: shortDigest(operation.operationKey), recovered: false, status: "already-completed" };
    }
    if (operation.status !== "legacy_completed" || !operation.legacyUserId) {
      throw new ServiceUnavailableException({
        code: "IAM_ROLE_WRITE_RECOVERY_NOT_APPLICABLE",
        message: "Role-write operation has no recoverable legacy-first state."
      });
    }

    const policyChecksum = stringValue(operation.metadata.policyChecksum) ?? this.config.iam.roleWritePolicyChecksum;
    try {
      const result = await this.syncIdentityAssignments({
        legacyUserId: operation.legacyUserId,
        requestedRole: stringValue(operation.metadata.requestedRole),
        policyChecksum
      });
      await this.operations.update({
        operationKey: operation.operationKey,
        status: "completed",
        legacyStatus: operation.legacyStatus,
        identityStatus: "recovered",
        compensationStatus: "completed",
        metadata: {
          ...operation.metadata,
          recovery: { action: "resync-current-legacy-assignments", assignmentCount: result.assignmentCount }
        }
      });
      return { operationKeyDigest: shortDigest(operation.operationKey), recovered: true, assignmentCount: result.assignmentCount };
    } catch (error) {
      await this.operations.update({
        operationKey: operation.operationKey,
        status: "legacy_completed",
        legacyStatus: operation.legacyStatus,
        identityStatus: "recovery-failed",
        compensationStatus: "required",
        errorCode: errorCode(error),
        metadata: operation.metadata
      });
      throw error;
    }
  }

  async restoreCandidateAssignments(input: { legacyUserId: number; policyChecksum: string }) {
    const { iam } = this.config;
    if (!iam.roleWriteCandidateRestoreEnabled) {
      throw new NotFoundException({
        code: "IAM_ROLE_WRITE_CANDIDATE_RESTORE_DISABLED",
        message: "IAM role-write candidate restore is disabled."
      });
    }
    if (iam.roleWriteCandidateRestoreTargetLegacyUserId !== input.legacyUserId) {
      throw new ConflictException({
        code: "IAM_ROLE_WRITE_CANDIDATE_RESTORE_TARGET_MISMATCH",
        message: "IAM role-write candidate restore is not enabled for the requested subject."
      });
    }
    const postureBlocked =
      iam.mode !== "readonly" ||
      iam.roleWriteMode !== "disabled" ||
      iam.roleWriteDualWriteExecutionEnabled ||
      iam.roleWriteIdentityNativeExecutionEnabled ||
      iam.roleWriteIdentityNativeTargetMode !== "single-target" ||
      iam.roleWriteIdentityNativeTargetLegacyUserId !== 0 ||
      iam.roleWriteIdentityNativeTargetAllowlist.trim() !== "" ||
      iam.roleWriteRolloutMode !== "off" ||
      iam.roleWriteRolloutAllowlist.trim() !== "" ||
      iam.roleWriteRolloutPercentage !== 0 ||
      Boolean(iam.roleWritePolicyChecksum) ||
      iam.roleWriteRecoveryDrillEnabled ||
      iam.authzReadMode !== "legacy" ||
      iam.authzRolloutMode !== "off" ||
      iam.authzRolloutAllowlist.trim() !== "" ||
      iam.authzRetainedLegacyAllowlist.trim() !== "" ||
      iam.authzRolloutPercentage !== 0 ||
      !iam.authzFallbackEnabled;
    if (postureBlocked) {
      throw new ConflictException({
        code: "IAM_ROLE_WRITE_CANDIDATE_RESTORE_UNSAFE_POSTURE",
        message: "Candidate restore requires IAM readonly, Legacy-authoritative AuthZ, and all role-write rollout controls disabled."
      });
    }

    const before = await this.subjectAlignment(input);
    const recoverable =
      before.safetyGate.requiresCandidateRestore &&
      before.safetyGate.blockedReasons.length === 1 &&
      before.safetyGate.blockedReasons[0] === "candidate-assignment-mismatch" &&
      before.assignments.legacyOutsidePolicy.length === 0 &&
      before.assignments.candidateOutsidePolicy.length === 0 &&
      before.operations.unresolvedCount === 0 &&
      !before.rootProtection.protected;
    if (!recoverable) {
      throw new ConflictException({
        code: "IAM_ROLE_WRITE_CANDIDATE_RESTORE_NOT_APPLICABLE",
        message: "Subject alignment does not permit a candidate-only restore."
      });
    }

    const assignmentCount = await this.iamRepository.replaceSubjectAssignments({
      identityUserId: `legacy:${input.legacyUserId}`,
      legacyUserId: input.legacyUserId,
      policyChecksum: input.policyChecksum,
      assignments: before.assignments.legacy.map(assignmentRowFromKey),
      source: "role-write-candidate-restore"
    });
    const after = await this.subjectAlignment(input);
    if (!after.safetyGate.passed) {
      throw new ServiceUnavailableException({
        code: "IAM_ROLE_WRITE_CANDIDATE_RESTORE_POSTCHECK_FAILED",
        message: "Candidate restore completed but the post-restore alignment gate did not pass."
      });
    }

    this.logger.log(
      JSON.stringify({
        event: "iam-role-write-candidate-restored",
        subjectFingerprint: before.subjectFingerprint,
        policyChecksumFingerprint: shortDigest(input.policyChecksum),
        assignmentCount
      })
    );
    return {
      restored: true,
      subjectFingerprint: before.subjectFingerprint,
      policyChecksumFingerprint: shortDigest(input.policyChecksum),
      assignmentCount,
      before: alignmentSummary(before),
      after: alignmentSummary(after),
      safety: {
        legacyWritePerformed: false,
        identityCandidateWritePerformed: true,
        historicalMutationReplayed: false,
        legacyRemainsAuthoritative: true,
        permissionUnionApplied: false,
        writeScope: "identity-candidate-only"
      }
    };
  }

  async prepareRecoveryDrill() {
    const { iam } = this.config;
    if (!iam.roleWriteRecoveryDrillEnabled) {
      throw new NotFoundException({
        code: "IAM_ROLE_WRITE_RECOVERY_DRILL_DISABLED",
        message: "Role-write recovery drill is disabled."
      });
    }
    if (iam.roleWriteMode !== "dual-write" || !iam.roleWriteDualWriteExecutionEnabled) {
      throw new ConflictException({
        code: "IAM_ROLE_WRITE_RECOVERY_DRILL_REQUIRES_DUAL_WRITE",
        message: "Role-write recovery drill requires an explicitly enabled dual-write window."
      });
    }

    const targetLegacyUserId = iam.roleWriteRecoveryDrillTargetLegacyUserId;
    if (!Number.isInteger(targetLegacyUserId) || targetLegacyUserId <= 0) {
      throw new ConflictException({
        code: "IAM_ROLE_WRITE_RECOVERY_DRILL_TARGET_REQUIRED",
        message: "Role-write recovery drill requires one configured dedicated target."
      });
    }

    const rollout = roleWriteRolloutReadiness(iam);
    const gate = await this.dualWriteGate(rollout);
    if (!gate.executable) {
      throw new ConflictException({
        code: "IAM_ROLE_WRITE_RECOVERY_DRILL_GATE_BLOCKED",
        message: "Role-write recovery drill is blocked by the dual-write readiness gate.",
        missingCapabilities: gate.missingCapabilities
      });
    }

    const user = await this.legacyReader.getUserById(targetLegacyUserId);
    const assignments = await this.legacyReader.listUserRbacAssignments(targetLegacyUserId);
    const roleAssignments = assignments.filter((assignment) => assignment.type === "role").map((assignment) => assignment.name);
    if (!user || user.roles.includes("root") || roleAssignments.includes("root")) {
      throw new ConflictException({
        code: "IAM_ROLE_WRITE_RECOVERY_DRILL_TARGET_PROTECTED",
        message: "Root or missing targets cannot be used for a role-write recovery drill."
      });
    }
    if (user.roles.length !== 1 || user.roles[0] !== "user" || roleAssignments.length !== 1 || roleAssignments[0] !== "user") {
      throw new ConflictException({
        code: "IAM_ROLE_WRITE_RECOVERY_DRILL_TARGET_NOT_BASELINE_USER",
        message: "Role-write recovery drill target must have the exact user baseline in Legacy."
      });
    }

    const targetSubject = `legacy:${targetLegacyUserId}`;
    const actorSubject = "internal:role-write-recovery-drill";
    const requestFingerprint = pluginUserWriteRequestFingerprint("change-role", {
      drill: "identity-assignment-recovery",
      targetSubject,
      policyChecksum: iam.roleWritePolicyChecksum,
      version: 1
    });
    const operationKey = pluginUserWriteOperationKey({
      route: "change-role",
      actorSubject,
      targetSubject,
      requestFingerprint
    });
    const metadata = {
      phase: "identity",
      policyChecksum: iam.roleWritePolicyChecksum,
      requestedRole: "user",
      drill: {
        kind: "identity-assignment-recovery",
        noLegacyMutation: true,
        exactLegacyBaseline: "user"
      }
    };
    const begun = await this.operations.begin({
      operationKey,
      idempotencyKey: `recovery-drill:${requestFingerprint}`,
      route: "change-role",
      mode: "dual-write",
      actorSubject,
      targetSubject,
      legacyUserId: targetLegacyUserId,
      identityUserId: targetSubject,
      metadata
    });
    if (begun.duplicate) {
      const existing = await this.operations.findByOperationKey(operationKey);
      if (!existing) {
        throw new ConflictException({
          code: "IAM_ROLE_WRITE_RECOVERY_DRILL_DUPLICATE",
          message: "Role-write recovery drill operation already exists but cannot be read."
        });
      }
      return {
        operationKey,
        operationKeyDigest: shortDigest(operationKey),
        targetFingerprint: shortDigest(targetSubject),
        status: existing.status,
        compensationStatus: existing.compensationStatus,
        noLegacyMutation: true,
        duplicate: true,
        nextAction: existing.status === "completed" ? "none" : "retry-identity-shadow"
      };
    }

    await this.operations.update({
      operationKey,
      status: "legacy_completed",
      legacyStatus: "drill:no-mutation",
      identityStatus: "drill:recovery-required",
      compensationStatus: "required",
      errorCode: "IAM_ROLE_WRITE_RECOVERY_DRILL",
      metadata
    });

    return {
      operationKey,
      operationKeyDigest: shortDigest(operationKey),
      targetFingerprint: shortDigest(targetSubject),
      status: "legacy_completed",
      compensationStatus: "required",
      noLegacyMutation: true,
      duplicate: false,
      nextAction: "retry-identity-shadow"
    };
  }

  private async proxy(request: IamRoleWriteRequest, contract: RoleWriteContract): Promise<IamRoleWriteProxyResponse> {
    const { iam } = this.config;
    const correlationId = roleWriteCorrelationId(request.headers);
    const claims = this.claimsFromAuthorization(request.headers.authorization);
    if (iam.roleWriteMode === "disabled") {
      this.assertRequiredDualWriteAvailable(request, "role_write_disabled");
      throw new NotFoundException({ code: "IAM_ROLE_WRITE_DISABLED", message: "IAM role write migration is disabled." });
    }
    if (iam.roleWriteMode === "legacy-proxy") {
      this.assertRequiredDualWriteAvailable(request, "legacy_proxy_mode");
      const decision = this.inactiveRolloutDecision(request, contract, correlationId, claims, "legacy_proxy_mode");
      this.logRolloutDecision(decision);
      return this.legacyProxy(request, contract, evidenceFromDecision(decision));
    }
    if (iam.roleWriteMode !== "dual-write" && iam.roleWriteMode !== "identity-native") {
      throw new NotFoundException({
        code: "IAM_ROLE_WRITE_UNSUPPORTED_MODE",
        message: `IAM role write mode ${iam.roleWriteMode} is not executable.`
      });
    }

    const unsupportedScopeField = unsupportedRoleWriteScopeField(request.body);
    if (unsupportedScopeField) {
      if (iam.roleWriteMode === "identity-native") {
        throw new ConflictException({
          code: "IAM_ROLE_WRITE_SCOPED_ASSIGNMENT_UNSUPPORTED",
          message: "Organization, campus, and scoped assignments remain outside the global Identity role-write owner.",
          scopeField: unsupportedScopeField
        });
      }
      this.assertRequiredDualWriteAvailable(request, "unsupported_scope_legacy_only");
      const decision: RoleWriteRolloutDecision = {
        selected: false,
        mode: iam.roleWriteRolloutMode,
        route: routeForContract(contract),
        subjectId: claims ? `legacy:${claims.uid}` : null,
        reason: "unsupported_scope_legacy_only",
        scopeField: unsupportedScopeField,
        correlationId,
        actorFingerprint: roleWriteActorFingerprint(claims),
        matchedSelectorKind: null
      };
      this.logRolloutDecision(decision);
      return this.legacyProxy(request, contract, evidenceFromDecision(decision));
    }

    const rollout = roleWriteRolloutReadiness(iam);
    const gate = iam.roleWriteMode === "identity-native"
      ? await this.identityNativeGate(rollout)
      : await this.dualWriteGate(rollout);
    if (!gate.executable) {
      throw new NotFoundException({
        code: "IAM_ROLE_WRITE_UNSUPPORTED_MODE",
        message: `IAM role write ${iam.roleWriteMode} mode is not executable yet.`,
        missingCapabilities: gate.missingCapabilities
      });
    }

    const targetLegacyUserId = positiveInteger(asRecord(request.body).id);
    if (!targetLegacyUserId) {
      throw new ConflictException({
        code: "IAM_ROLE_WRITE_TARGET_REQUIRED",
        message: "A target user and role are required."
      });
    }
    const targetDecision = await this.identityNativeTargetDecision(targetLegacyUserId);
    const actorDecision = this.dualWriteRolloutDecision(request, contract, correlationId, claims);
    if (iam.roleWriteMode === "identity-native" && targetDecision.reason === "legacy_root_retained") {
      throw new ConflictException({
        code: "IAM_ROLE_WRITE_ROOT_PROTECTED",
        message: "Root subjects remain Legacy-owned and cannot be changed by role-write."
      });
    }
    if (iam.roleWriteMode === "identity-native" && !targetDecision.owned) {
      const legacyDecision: RoleWriteRolloutDecision = {
        ...actorDecision,
        selected: false,
        reason: "identity_native_target_not_owned",
        matchedSelectorKind: null
      };
      this.logRolloutDecision(legacyDecision);
      this.assertRequiredDualWriteAvailable(request, legacyDecision.reason);
      return this.legacyProxy(request, contract, evidenceFromDecision(legacyDecision));
    }

    this.logRolloutDecision(actorDecision);
    const evidence = evidenceFromDecision(actorDecision);
    if (!actorDecision.selected && iam.roleWriteMode === "identity-native") {
      throw new ConflictException({
        code: "IAM_ROLE_WRITE_IDENTITY_NATIVE_OPERATOR_NOT_SELECTED",
        message: "The target is owned by Identity, but this operator is outside the active role-write rollout."
      });
    }
    if (!actorDecision.selected) {
      this.assertRequiredDualWriteAvailable(request, actorDecision.reason);
    }
    if (actorDecision.selected && iam.roleWriteMode === "dual-write" && iam.roleWriteRolloutMode === "canary" && !requiresDualWrite(request.headers)) {
      throw new ConflictException({
        code: "IAM_ROLE_WRITE_DUAL_WRITE_REQUIRED",
        message: "A selected canary role-write requires the guarded dual-write handoff.",
        reason: "canary_guard_required"
      });
    }
    if (!actorDecision.selected) {
      return this.legacyProxy(request, contract, evidence);
    }
    return iam.roleWriteMode === "identity-native"
      ? this.identityNativeWrite(request, contract, evidence)
      : this.dualWrite(request, contract, evidence);
  }

  private async identityNativeTargetDecision(
    legacyUserId: number
  ): Promise<IdentityNativeRoleWriteTargetDecision> {
    const decision = identityNativeRoleWriteTargetDecision(this.config.iam, legacyUserId);
    if (!decision.owned) {
      return decision;
    }

    const checksum = this.config.iam.roleWritePolicyChecksum;
    const candidateAssignments =
      this.iamRepository.isConfigured() && /^[a-f0-9]{64}$/.test(checksum ?? "")
        ? this.iamRepository.listSubjectAssignments(`legacy:${legacyUserId}`, checksum!)
        : Promise.resolve([]);
    const [legacyUser, legacyAssignments, identityAssignments] = await Promise.all([
      this.legacyReader.getUserById(legacyUserId),
      this.legacyReader.listUserRbacAssignments(legacyUserId),
      candidateAssignments
    ]);
    const rootProtected =
      legacyUser?.roles.includes("root") === true ||
      legacyAssignments.some((assignment) => assignment.type === "role" && assignment.name === "root") ||
      identityAssignments.some((assignment) => assignment.itemType === "role" && assignment.itemName === "root");

    return rootProtected
      ? { owned: false, mode: decision.mode, reason: "legacy_root_retained" }
      : decision;
  }

  private async identityNativeWrite(
    request: IamRoleWriteRequest,
    contract: RoleWriteContract,
    evidence: IamRoleWriteEvidence
  ): Promise<IamRoleWriteProxyResponse> {
    const plan = this.planOperation(request, contract, evidence);
    const claims = this.requireClaims(request.headers.authorization);
    const explicitIdempotency = clientIdempotencyKey(request.headers);
    if (!explicitIdempotency) {
      throw new ConflictException({
        code: "IAM_ROLE_WRITE_IDEMPOTENCY_REQUIRED",
        message: "Identity-native role writes require an explicit idempotency key."
      });
    }
    if (!plan.legacyUserId || !plan.requestedRole) {
      throw new ConflictException({ code: "IAM_ROLE_WRITE_TARGET_REQUIRED", message: "A target user and role are required." });
    }
    const targetDecision = await this.identityNativeTargetDecision(plan.legacyUserId);
    if (!targetDecision.owned) {
      throw new ConflictException({
        code: "IAM_ROLE_WRITE_IDENTITY_NATIVE_TARGET_MISMATCH",
        message: "Identity-native role-write is restricted to configured owner targets."
      });
    }
    if (!VALID_IDENTITY_NATIVE_ROLES.has(plan.requestedRole) || plan.requestedRole === "root") {
      throw new ConflictException({ code: "IAM_ROLE_WRITE_ROOT_PROTECTED", message: "Root cannot be assigned by role-write." });
    }
    const scopeField = unsupportedRoleWriteScopeField(request.body);
    if (scopeField) {
      throw new ConflictException({
        code: "IAM_ROLE_WRITE_SCOPED_ASSIGNMENT_UNSUPPORTED",
        message: "Organization, campus, and scoped assignments are not handled by the global role-write owner.",
        scopeField
      });
    }

    const policyChecksum = validatedPolicyChecksum(this.config.iam.roleWritePolicyChecksum);
    const [policy, target, currentAssignments] = await Promise.all([
      this.iamRepository.getPermissionPolicyCandidate(policyChecksum),
      this.legacyReader.getUserById(plan.legacyUserId),
      this.iamRepository.listSubjectAssignments(`legacy:${plan.legacyUserId}`, policyChecksum)
    ]);
    if (!policy) {
      throw new ServiceUnavailableException({ code: "IAM_ROLE_WRITE_POLICY_NOT_FOUND", message: "Configured IAM role policy candidate is unavailable." });
    }
    if (!target) {
      throw new NotFoundException({ code: "IAM_ROLE_WRITE_TARGET_NOT_FOUND", message: "Role-write target was not found." });
    }
    const currentRoles = currentAssignments.filter((item) => item.itemType === "role").map((item) => item.itemName);
    if (currentAssignments.length === 0) {
      throw new ConflictException({
        code: "IAM_ROLE_WRITE_IDENTITY_NATIVE_CANDIDATE_MISSING",
        message: "Identity-native role-write requires a materialized candidate assignment for the owned target."
      });
    }
    if (target.roles.includes("root") || currentRoles.includes("root")) {
      throw new ConflictException({ code: "IAM_ROLE_WRITE_ROOT_PROTECTED", message: "Root subjects cannot be changed." });
    }
    assertRoleHierarchy(claims.roles, currentRoles, plan.requestedRole, contract);
    const policyRoles = new Set(policy.roles.map((role) => role.name));
    const nextRoles = assignedRolesFor(plan.requestedRole);
    if (nextRoles.some((role) => !policyRoles.has(role))) {
      throw new ServiceUnavailableException({
        code: "IAM_ROLE_WRITE_ROLE_OUTSIDE_POLICY",
        message: "Requested role is unavailable in the configured Identity policy candidate."
      });
    }
    const directPermissions = currentAssignments
      .filter((item) => item.itemType === "permission")
      .map((item) => ({ itemName: item.itemName, itemType: "permission" as const }));
    const assignments = [
      ...nextRoles.map((itemName) => ({ itemName, itemType: "role" as const })),
      ...directPermissions
    ];

    const nativeMetadata = {
      ...plan.metadata,
      owner: "identity",
      ownerTargetMode: targetDecision.mode,
      ownerTargetReason: targetDecision.reason,
      legacyWritePerformed: false
    };
    const begun = await this.operations.begin({
      operationKey: plan.operationKey,
      idempotencyKey: explicitIdempotency,
      route: plan.route,
      mode: "identity-native",
      actorSubject: plan.actorSubject,
      targetSubject: plan.targetSubject,
      legacyUserId: plan.legacyUserId,
      identityUserId: `legacy:${plan.legacyUserId}`,
      metadata: nativeMetadata
    });
    if (begun.duplicate) {
      const existing = await this.operations.findByOperationKey(plan.operationKey);
      const replay = existing ? pluginUserWriteReplayResponseFromOperation(existing) : null;
      if (replay) return { ...replay, mode: "identity-native", evidence };
      throw new ServiceUnavailableException({
        code: "IAM_ROLE_WRITE_REPLAY_UNAVAILABLE",
        message: "Role-write operation is already recorded but has no completed replay response."
      });
    }

    try {
      await this.iamRepository.replaceSubjectAssignments({
        identityUserId: `legacy:${plan.legacyUserId}`,
        legacyUserId: plan.legacyUserId,
        policyChecksum,
        assignments,
        source: "role-write-identity-native"
      });
      const body = identityNativeCompatibilityResponse(contract, target, nextRoles);
      const responseReplay = pluginUserWriteResponseReplayMetadata({ status: 200, body });
      await this.operations.update({
        operationKey: plan.operationKey,
        status: "completed",
        legacyStatus: "not-called",
        identityStatus: "completed",
        compensationStatus: "none",
        metadata: { ...nativeMetadata, ...responseReplay }
      });
      return { status: 200, body, mode: "identity-native", evidence };
    } catch (error) {
      await this.operations.update({
        operationKey: plan.operationKey,
        status: "failed",
        legacyStatus: "not-called",
        identityStatus: "failed",
        compensationStatus: "none",
        errorCode: errorCode(error),
        metadata: nativeMetadata
      });
      throw error;
    }
  }

  private assertRequiredDualWriteAvailable(request: IamRoleWriteRequest, reason: string): void {
    if (!requiresDualWrite(request.headers)) {
      return;
    }
    throw new ConflictException({
      code: "IAM_ROLE_WRITE_DUAL_WRITE_REQUIRED",
      message: "The guarded role-write request requires an active selected dual-write route.",
      reason
    });
  }

  private async dualWrite(
    request: IamRoleWriteRequest,
    contract: RoleWriteContract,
    evidence: IamRoleWriteEvidence
  ): Promise<IamRoleWriteProxyResponse> {
    const plan = this.planOperation(request, contract, evidence);
    const begun = await this.operations.begin({
      operationKey: plan.operationKey,
      idempotencyKey: plan.idempotencyKey,
      route: plan.route,
      mode: "dual-write",
      actorSubject: plan.actorSubject,
      targetSubject: plan.targetSubject,
      legacyUserId: plan.legacyUserId,
      identityUserId: plan.legacyUserId ? `legacy:${plan.legacyUserId}` : null,
      metadata: plan.metadata
    });

    if (begun.duplicate) {
      const existing = await this.operations.findByOperationKey(plan.operationKey);
      const replay = existing ? pluginUserWriteReplayResponseFromOperation(existing) : null;
      if (replay) {
        return { ...replay, mode: "dual-write", evidence };
      }
      throw new ServiceUnavailableException({
        code: "IAM_ROLE_WRITE_REPLAY_UNAVAILABLE",
        message: "Role-write operation is already recorded but has no completed replay response."
      });
    }

    let legacyResponse: IamRoleWriteProxyResponse;
    try {
      legacyResponse = await this.legacyProxy(request, contract, evidence);
    } catch (error) {
      await this.operations.update({
        operationKey: plan.operationKey,
        status: "failed",
        legacyStatus: "unavailable",
        identityStatus: "skipped",
        compensationStatus: "none",
        errorCode: errorCode(error),
        metadata: { ...plan.metadata, phase: "legacy" }
      });
      throw error;
    }

    const responseReplay = pluginUserWriteResponseReplayMetadata({ status: legacyResponse.status, body: legacyResponse.body });
    if (legacyResponse.status < 200 || legacyResponse.status >= 300) {
      await this.operations.update({
        operationKey: plan.operationKey,
        status: "failed",
        legacyStatus: String(legacyResponse.status),
        identityStatus: "skipped",
        compensationStatus: "none",
        errorCode: "LegacyRejected",
        metadata: { ...plan.metadata, ...responseReplay }
      });
      return { ...legacyResponse, mode: "dual-write", evidence };
    }

    try {
      const result = await this.syncIdentityAssignments({
        legacyUserId: plan.legacyUserId,
        requestedRole: plan.requestedRole,
        policyChecksum: this.config.iam.roleWritePolicyChecksum
      });
      await this.operations.update({
        operationKey: plan.operationKey,
        status: "completed",
        legacyStatus: String(legacyResponse.status),
        identityStatus: "completed",
        compensationStatus: "none",
        metadata: { ...plan.metadata, ...responseReplay, identityShadow: result }
      });
    } catch (error) {
      await this.operations.update({
        operationKey: plan.operationKey,
        status: "legacy_completed",
        legacyStatus: String(legacyResponse.status),
        identityStatus: identityStatusForError(error),
        compensationStatus: "required",
        errorCode: errorCode(error),
        metadata: {
          ...plan.metadata,
          ...responseReplay,
          ...pluginUserWriteCompensationMetadata({
            phase: "identity",
            reason: "identity-role-assignment-sync-failed",
            errorCode: errorCode(error),
            legacyStatus: legacyResponse.status,
            identityStatus: "failed",
            detail: { route: plan.route, legacyUserId: plan.legacyUserId }
          })
        }
      });
    }

    return { ...legacyResponse, mode: "dual-write", evidence };
  }

  private async syncIdentityAssignments(input: {
    legacyUserId: number | null;
    requestedRole: string | null;
    policyChecksum: string | undefined | null;
  }): Promise<{ assignmentCount: number; policyChecksum: string }> {
    if (!input.legacyUserId) {
      throw new RoleWriteSyncError("IAM_ROLE_WRITE_TARGET_REQUIRED", "Role-write target is required before syncing Identity assignments.");
    }
    if (input.requestedRole === "root") {
      throw new RoleWriteSyncError("IAM_ROLE_WRITE_ROOT_PROTECTED", "Root role is never materialized by the Identity candidate path.");
    }
    if (!this.legacyReader.isConfigured()) {
      throw new RoleWriteSyncError("IAM_ROLE_WRITE_LEGACY_READER_NOT_CONFIGURED", "Legacy role reader is not configured.");
    }
    if (!this.iamRepository.isConfigured()) {
      throw new RoleWriteSyncError("IAM_ROLE_WRITE_IDENTITY_REPOSITORY_NOT_CONFIGURED", "Identity role repository is not configured.");
    }
    const policyChecksum = validatedPolicyChecksum(input.policyChecksum);
    const policy = await this.iamRepository.getPermissionPolicyCandidate(policyChecksum);
    if (!policy) {
      throw new RoleWriteSyncError("IAM_ROLE_WRITE_POLICY_NOT_FOUND", "Configured IAM role policy candidate is unavailable.");
    }
    const user = await this.legacyReader.getUserById(input.legacyUserId);
    if (!user) {
      throw new RoleWriteSyncError("IAM_ROLE_WRITE_TARGET_NOT_FOUND", "Legacy role-write target is unavailable.");
    }
    if (user.roles.includes("root")) {
      throw new RoleWriteSyncError("IAM_ROLE_WRITE_ROOT_PROTECTED", "Root subject is never materialized by the Identity candidate path.");
    }
    const assignments = await this.legacyReader.listUserRbacAssignments(input.legacyUserId);
    if (assignments.some((assignment) => assignment.name === "root")) {
      throw new RoleWriteSyncError("IAM_ROLE_WRITE_ROOT_PROTECTED", "Root assignment is never materialized by the Identity candidate path.");
    }
    const assignmentCount = await this.iamRepository.replaceSubjectAssignments({
      identityUserId: `legacy:${input.legacyUserId}`,
      legacyUserId: input.legacyUserId,
      policyChecksum: policy.checksum,
      assignments: assignments.map((assignment) => ({ itemName: assignment.name, itemType: assignment.type })),
      source: "role-write-dual-write"
    });
    return { assignmentCount, policyChecksum: policy.checksum };
  }

  private async legacyProxy(
    request: IamRoleWriteRequest,
    contract: RoleWriteContract,
    evidence?: IamRoleWriteEvidence
  ): Promise<IamRoleWriteProxyResponse> {
    const upstream = await this.callLegacy(request, contract, evidence);
    return { status: upstream.status, body: await parseUpstreamBody(upstream), mode: "legacy-proxy", evidence };
  }

  private async callLegacy(
    request: IamRoleWriteRequest,
    contract: RoleWriteContract,
    evidence?: IamRoleWriteEvidence
  ): Promise<Response> {
    const baseUrl = this.config.iam.roleWriteLegacyApiBaseUrl;
    if (!baseUrl) {
      throw new ServiceUnavailableException({
        code: "IAM_ROLE_WRITE_LEGACY_API_NOT_CONFIGURED",
        message: "Legacy role-write API base URL is not configured."
      });
    }
    const path = contract === "people-auth" ? "/v1/people/auth" : "/v1/plugin-user/change-role";
    const url = new URL(path, `${baseUrl.replace(/\/+$/, "")}/`);
    const query = queryStringFromOriginalUrl(request.originalUrl);
    if (query) {
      url.search = query;
    }
    const headers = new Headers({ Accept: "application/json", "Content-Type": "application/json", "X-Identity-IAM-Role-Write-Proxy": "1" });
    copyHeader(request.headers, headers, "authorization", "Authorization");
    copyHeader(request.headers, headers, "x-forwarded-for", "X-Forwarded-For");
    copyHeader(request.headers, headers, "user-agent", "User-Agent");
    if (evidence) {
      headers.set("X-Identity-IAM-Role-Write-Correlation", evidence.correlationId);
    } else {
      copyHeader(request.headers, headers, "x-identity-iam-role-write-correlation", "X-Identity-IAM-Role-Write-Correlation");
    }
    try {
      return await fetch(url, {
        method: request.method.toUpperCase(),
        headers,
        body: JSON.stringify(request.body ?? {}),
        signal: AbortSignal.timeout(this.config.iam.roleWriteTimeoutMs)
      });
    } catch (error) {
      throw new ServiceUnavailableException({
        code: "IAM_ROLE_WRITE_LEGACY_API_UNAVAILABLE",
        message: "Legacy role-write API is unavailable.",
        detail: error instanceof Error ? error.message : String(error)
      });
    }
  }

  private planOperation(request: IamRoleWriteRequest, contract: RoleWriteContract, evidence: IamRoleWriteEvidence) {
    const route: RoleWriteRoute = contract === "people-auth" ? "people-auth" : "change-role";
    const body = asRecord(request.body);
    const claims = this.claimsFromAuthorization(request.headers.authorization);
    const legacyUserId = positiveInteger(body.id);
    const requestedRole = stringValue(contract === "people-auth" ? body.auth : body.role);
    const actorSubject = claims ? `legacy:${claims.uid}` : firstHeader(request.headers.authorization) ? "authorization:present" : null;
    const targetSubject = legacyUserId ? `legacy:${legacyUserId}` : null;
    const explicitIdempotency = clientIdempotencyKey(request.headers);
    const requestFingerprint = pluginUserWriteRequestFingerprint(route, body);
    const operationKey = pluginUserWriteOperationKey({
      route,
      actorSubject,
      targetSubject,
      requestFingerprint: `${requestFingerprint}:${explicitIdempotency ? `idempotency:${shortDigest(explicitIdempotency)}` : `request:${randomUUID()}`}`
    });
    return {
      route,
      operationKey,
      idempotencyKey: operationKey,
      actorSubject,
      targetSubject,
      legacyUserId,
      requestedRole,
      metadata: {
        route,
        method: request.method.toUpperCase(),
        targetSubject,
        requestedRole,
        policyChecksum: this.config.iam.roleWritePolicyChecksum ?? null,
        correlationId: evidence.correlationId,
        rolloutDecision: evidence.decision,
        actorFingerprint: evidence.actorFingerprint,
        matchedSelectorKind: evidence.matchedSelectorKind,
        idempotencySource: explicitIdempotency ? "client-header" : "per-request",
        redactedBody: redactPluginUserWriteMetadata(body)
      }
    };
  }

  private dualWriteRolloutDecision(
    request: IamRoleWriteRequest,
    contract: RoleWriteContract,
    correlationId: string,
    verifiedClaims?: VerifiedAccessToken | null
  ): RoleWriteRolloutDecision {
    const { iam } = this.config;
    const claims = verifiedClaims === undefined ? this.claimsFromAuthorization(request.headers.authorization) : verifiedClaims;
    const subjectId = claims ? `legacy:${claims.uid}` : null;
    const base = {
      route: routeForContract(contract),
      subjectId,
      correlationId,
      actorFingerprint: roleWriteActorFingerprint(claims)
    };
    if (iam.roleWriteRolloutMode === "full") {
      return { ...base, selected: true, mode: "full", reason: "full_rollout", matchedSelectorKind: "full" };
    }
    if (iam.roleWriteRolloutMode === "off") {
      return { ...base, selected: false, mode: "off", reason: "rollout_off", matchedSelectorKind: null };
    }
    if (iam.roleWriteRolloutMode === "canary") {
      const tokens = roleWriteActorTokens(claims);
      const matchedToken = splitCsv(iam.roleWriteRolloutAllowlist).map(normalizeRoleWriteSelector).find((item) => tokens.has(item));
      return {
        ...base,
        selected: Boolean(matchedToken),
        mode: "canary",
        reason: matchedToken ? "canary_actor_selected" : "canary_actor_not_selected",
        matchedSelectorKind: roleWriteSelectorKind(matchedToken)
      };
    }
    const percentage = safeRolloutPercentage(iam.roleWriteRolloutPercentage);
    const bucket = subjectId ? rolloutBucket(subjectId) : null;
    const selected = percentage > 0 && bucket !== null && (percentage >= 100 || bucket < percentage);
    return {
      ...base,
      selected,
      mode: "percentage",
      reason: selected ? "percentage_bucket_selected" : "percentage_bucket_not_selected",
      bucket,
      percentage,
      matchedSelectorKind: selected ? "percentage" : null
    };
  }

  private inactiveRolloutDecision(
    request: IamRoleWriteRequest,
    contract: RoleWriteContract,
    correlationId: string,
    verifiedClaims?: VerifiedAccessToken | null,
    reason = "role_write_disabled"
  ): RoleWriteRolloutDecision {
    const claims = verifiedClaims === undefined ? this.claimsFromAuthorization(request.headers.authorization) : verifiedClaims;
    return {
      selected: false,
      mode: "off",
      route: routeForContract(contract),
      subjectId: claims ? `legacy:${claims.uid}` : null,
      reason,
      correlationId,
      actorFingerprint: roleWriteActorFingerprint(claims),
      matchedSelectorKind: null
    };
  }

  private logRolloutDecision(decision: RoleWriteRolloutDecision, preview = false): void {
    this.logger.log(JSON.stringify({
      event: "identity.iam.role_write.rollout",
      preview,
      correlationId: decision.correlationId,
      mode: decision.mode,
      selected: decision.selected,
      reason: decision.reason,
      route: decision.route,
      actorFingerprint: decision.actorFingerprint,
      matchedSelectorKind: decision.matchedSelectorKind,
      bucket: decision.bucket ?? null,
      percentage: decision.percentage ?? null,
      scopeField: decision.scopeField ?? null,
      unselectedBehavior: "legacy-proxy"
    }));
  }

  private claimsFromAuthorization(authorization: string | string[] | undefined): VerifiedAccessToken | null {
    const token = bearerToken(firstHeader(authorization));
    if (!token) {
      return null;
    }
    try {
      return this.jwtIssuer.verifyAccessToken(token);
    } catch {
      return null;
    }
  }

  private requireClaims(authorization: string | string[] | undefined): VerifiedAccessToken {
    const claims = this.claimsFromAuthorization(authorization);
    if (!claims) {
      throw new UnauthorizedException({
        code: "IAM_ROLE_WRITE_OPERATOR_TOKEN_INVALID",
        message: "A valid Identity operator token is required for role-write rollout preview."
      });
    }
    return claims;
  }

  private async dualWriteGate(rollout: RoleWriteRolloutReadiness) {
    const { iam } = this.config;
    const missingCapabilities: string[] = [];
    if (!iam.roleWriteDualWriteExecutionEnabled) missingCapabilities.push("operator-dual-write-execution-flag");
    if (!iam.roleWriteLegacyApiBaseUrl) missingCapabilities.push("legacy-proxy-base-url");
    if (!this.operations.isConfigured()) missingCapabilities.push("operation-ledger");
    if (!this.iamRepository.isConfigured()) missingCapabilities.push("identity-repository");
    if (!this.legacyReader.isConfigured()) missingCapabilities.push("legacy-reader");
    if (!iam.roleWritePolicyChecksum) {
      missingCapabilities.push("candidate-policy-checksum");
    } else if (!(await this.iamRepository.getPermissionPolicyCandidate(iam.roleWritePolicyChecksum))) {
      missingCapabilities.push("candidate-policy-not-found");
    }
    if (!rollout.selectionConfigured) missingCapabilities.push("single-target-rollout-selector");
    return {
      executable: missingCapabilities.length === 0,
      sourceOfTruthUntilCloseout: "legacy",
      identityNativeSupported: false,
      recoveryMode: "resync-current-legacy-assignments",
      supportedRoutes: missingCapabilities.length === 0 ? [...ROLE_WRITE_ROUTES] : [],
      blockedRoutes: missingCapabilities.length === 0 ? [] : [...ROLE_WRITE_ROUTES],
      missingCapabilities
    };
  }

  private async identityNativeGate(rollout: RoleWriteRolloutReadiness) {
    const { iam } = this.config;
    const missingCapabilities: string[] = [];
    const targetScope = identityNativeRoleWriteTargetScope(iam);
    if (!iam.roleWriteIdentityNativeExecutionEnabled) missingCapabilities.push("operator-identity-native-execution-flag");
    missingCapabilities.push(...targetScope.missingCapabilities);
    if (!this.operations.isConfigured()) missingCapabilities.push("operation-ledger");
    if (!this.iamRepository.isConfigured()) missingCapabilities.push("identity-repository");
    if (!this.legacyReader.isConfigured()) missingCapabilities.push("legacy-read-model");
    if (!iam.roleWritePolicyChecksum) {
      missingCapabilities.push("candidate-policy-checksum");
    } else if (!(await this.iamRepository.getPermissionPolicyCandidate(iam.roleWritePolicyChecksum))) {
      missingCapabilities.push("candidate-policy-not-found");
    }
    if (!rollout.selectionConfigured) missingCapabilities.push("single-target-rollout-selector");
    return {
      executable: missingCapabilities.length === 0,
      sourceOfTruthForSelectedWrites: "identity-candidate",
      legacyWritePerformed: false,
      targetConfigured: targetScope.configured,
      targetScope,
      supportedRoutes: missingCapabilities.length === 0 ? [...ROLE_WRITE_ROUTES] : [],
      blockedRoutes: missingCapabilities.length === 0 ? [] : [...ROLE_WRITE_ROUTES],
      missingCapabilities
    };
  }

  private async policyCandidateLookup(checksum: string | undefined): Promise<PolicyCandidateLookup> {
    if (!checksum) {
      return "not_configured";
    }

    try {
      return (await this.iamRepository.getPermissionPolicyCandidate(checksum)) ? "available" : "not_found";
    } catch (error) {
      return error instanceof Error && error.message === "IAM permission candidate checksum does not match stored policy data"
        ? "materialization_checksum_mismatch"
        : "repository_error";
    }
  }
}

class RoleWriteSyncError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = "RoleWriteSyncError";
  }
}

interface RoleWriteRolloutReadiness {
  mode: "off" | "canary" | "percentage" | "full";
  allowlistCount: number;
  percentage: number;
  selectionConfigured: boolean;
  unselectedBehavior: "legacy-proxy";
}

type PolicyCandidateLookup =
  | "not_checked"
  | "not_configured"
  | "available"
  | "not_found"
  | "materialization_checksum_mismatch"
  | "repository_error";

function policyDiagnosticsBlockedReasons(input: {
  configuredChecksumPresent: boolean;
  configuredMatchesCurrentLegacyPolicy: boolean;
  configuredLookup: PolicyCandidateLookup;
  currentLookup: PolicyCandidateLookup;
}): string[] {
  const blockedReasons: string[] = [];
  if (!input.configuredChecksumPresent) {
    blockedReasons.push("candidate-policy-checksum-not-configured");
  } else if (!input.configuredMatchesCurrentLegacyPolicy) {
    blockedReasons.push("configured-checksum-does-not-match-current-legacy-policy");
  }
  if (input.configuredLookup !== "available") {
    blockedReasons.push(`configured-candidate-${input.configuredLookup}`);
  }
  if (input.currentLookup !== "available") {
    blockedReasons.push(`current-legacy-candidate-${input.currentLookup}`);
  }
  return blockedReasons;
}

interface RoleWriteRolloutDecision {
  selected: boolean;
  mode: "off" | "canary" | "percentage" | "full";
  route: RoleWriteRoute;
  subjectId: string | null;
  reason: string;
  correlationId: string;
  actorFingerprint: string | null;
  matchedSelectorKind: string | null;
  bucket?: number | null;
  percentage?: number;
  scopeField?: string | null;
}

function evidenceFromDecision(decision: RoleWriteRolloutDecision): IamRoleWriteEvidence {
  return {
    correlationId: decision.correlationId,
    decision: decision.reason,
    route: decision.route,
    actorFingerprint: decision.actorFingerprint,
    matchedSelectorKind: decision.matchedSelectorKind
  };
}

function unsupportedRoleWriteScopeField(body: unknown): string | null {
  const record = asRecord(body);
  const scopeFields = [
    "organization_id",
    "organizationId",
    "organization_ids",
    "organizationIds",
    "campus_id",
    "campusId",
    "scope",
    "scope_id",
    "scopeId",
    "scope_type",
    "scopeType"
  ];

  return scopeFields.find((field) => hasScopedValue(record[field])) ?? null;
}

function hasScopedValue(value: unknown): boolean {
  if (value === null || value === undefined) {
    return false;
  }
  if (typeof value === "string") {
    return value.trim().length > 0;
  }
  if (Array.isArray(value)) {
    return value.length > 0;
  }
  return true;
}

function roleWriteRolloutReadiness(iam: ReturnType<typeof loadConfig>["iam"]): RoleWriteRolloutReadiness {
  const allowlistCount = splitCsv(iam.roleWriteRolloutAllowlist).length;
  const percentage = safeRolloutPercentage(iam.roleWriteRolloutPercentage);
  return {
    mode: iam.roleWriteRolloutMode,
    allowlistCount,
    percentage,
    selectionConfigured:
      iam.roleWriteRolloutMode === "full" ||
      (iam.roleWriteRolloutMode === "canary" && allowlistCount > 0) ||
      (iam.roleWriteRolloutMode === "percentage" && percentage > 0),
    unselectedBehavior: "legacy-proxy"
  };
}

function routeForContract(contract: RoleWriteContract): RoleWriteRoute {
  return contract === "people-auth" ? "people-auth" : "change-role";
}

function validatedPolicyChecksum(value: string | null | undefined): string {
  if (!value || !/^[a-f0-9]{64}$/.test(value)) {
    throw new RoleWriteSyncError("IAM_ROLE_WRITE_POLICY_CHECKSUM_REQUIRED", "A 64-character IAM role policy checksum is required.");
  }
  return value;
}

function identityStatusForError(error: unknown): string {
  return error instanceof RoleWriteSyncError ? `skipped:${error.code}` : "failed";
}

function errorCode(error: unknown): string {
  return error instanceof RoleWriteSyncError ? error.code : error instanceof Error ? error.name : "IamRoleWriteError";
}

function normalizeSinceMinutes(value: number | undefined): number {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? Math.max(1, Math.min(1440, Math.trunc(numeric))) : 60;
}

function normalizeRecentLimit(value: number | undefined): number {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? Math.max(1, Math.min(200, Math.trunc(numeric))) : 50;
}

function normalizeAssignmentKeys(
  assignments: Array<
    | { name: string; type: "role" | "permission" }
    | { itemName: string; itemType: "role" | "permission" }
  >
): string[] {
  return [...new Set(assignments.map((assignment) => (
    "name" in assignment
      ? `${assignment.type}:${assignment.name}`
      : `${assignment.itemType}:${assignment.itemName}`
  )))].sort();
}

function alignmentSummary(alignment: {
  assignments: {
    legacy: string[];
    candidate: string[];
    missingInCandidate: string[];
    extraInCandidate: string[];
  };
  operations: { unresolvedCount: number };
  rootProtection: { protected: boolean };
  safetyGate: {
    passed: boolean;
    canRequestRuntime: boolean;
    requiresCandidateRestore: boolean;
    blockedReasons: string[];
  };
}) {
  return {
    assignmentCounts: {
      legacy: alignment.assignments.legacy.length,
      candidate: alignment.assignments.candidate.length,
      missingInCandidate: alignment.assignments.missingInCandidate.length,
      extraInCandidate: alignment.assignments.extraInCandidate.length
    },
    unresolvedOperationCount: alignment.operations.unresolvedCount,
    rootProtected: alignment.rootProtection.protected,
    safetyGate: alignment.safetyGate
  };
}

function assignmentRowFromKey(key: string): { itemName: string; itemType: "role" | "permission" } {
  const separator = key.indexOf(":");
  const itemType = key.slice(0, separator);
  const itemName = key.slice(separator + 1);
  if ((itemType !== "role" && itemType !== "permission") || !itemName) {
    throw new Error("Invalid normalized IAM assignment key.");
  }
  return { itemName, itemType };
}

function assignedRolesFor(requestedRole: string): string[] {
  return requestedRole === "user" ? ["user"] : ["user", requestedRole];
}

function assertRoleHierarchy(
  operatorRoles: string[],
  targetRoles: string[],
  requestedRole: string,
  contract: RoleWriteContract
): void {
  const operatorLevel = roleLevel(operatorRoles);
  const targetLevel = roleLevel(targetRoles);
  const requestedLevel = ROLE_LEVELS[requestedRole] ?? 0;
  if (operatorLevel === 0) {
    throw new UnauthorizedException({ code: "IAM_ROLE_WRITE_OPERATOR_ROLE_REQUIRED", message: "A recognized operator role is required." });
  }
  if (operatorLevel < ROLE_LEVELS.manager) {
    throw new UnauthorizedException({
      code: "IAM_ROLE_WRITE_OPERATOR_ELEVATION_REQUIRED",
      message: "Role-write requires a manager, admin, or root operator."
    });
  }
  if (targetLevel === 0) {
    throw new ConflictException({
      code: "IAM_ROLE_WRITE_TARGET_ASSIGNMENT_REQUIRED",
      message: "The Identity candidate target must have a known role assignment before role-write."
    });
  }
  if (targetLevel > operatorLevel) {
    throw new ConflictException({ code: "IAM_ROLE_WRITE_TARGET_ABOVE_OPERATOR", message: "The target role is above the operator role." });
  }
  if (requestedLevel > operatorLevel) {
    throw new ConflictException({ code: "IAM_ROLE_WRITE_GRANT_ABOVE_OPERATOR", message: "The requested role is above the operator role." });
  }
  if (contract === "people-auth" && operatorLevel === ROLE_LEVELS.admin && requestedRole === "admin") {
    throw new ConflictException({ code: "IAM_ROLE_WRITE_PEOPLE_AUTH_ADMIN_GUARD", message: "The legacy people/auth contract forbids admin self-level grants." });
  }
}

function roleLevel(roles: string[]): number {
  return roles.reduce((level, role) => Math.max(level, ROLE_LEVELS[role] ?? 0), 0);
}

function identityNativeCompatibilityResponse(
  contract: RoleWriteContract,
  target: {
    id: number;
    username: string | null;
    email: string | null;
    status: number;
    createdAt: number | null;
    updatedAt: number | null;
  },
  roles: string[]
): unknown {
  if (contract === "people-auth") {
    return {
      ...Object.fromEntries(roles.map((role) => [role, role])),
      success: true
    };
  }
  return {
    code: 0,
    data: {
      id: target.id,
      username: target.username,
      email: target.email,
      status: target.status,
      created_at: target.createdAt,
      updated_at: target.updatedAt,
      roles
    }
  };
}

function safeRolloutPercentage(value: number): number {
  return Math.max(0, Math.min(100, Math.trunc(Number.isFinite(value) ? value : 0)));
}

function rolloutBucket(subject: string): number {
  return Number.parseInt(createHash("sha256").update(subject).digest("hex").slice(0, 8), 16) % 100;
}

function splitCsv(value: string): string[] {
  return value.split(",").map((item) => item.trim()).filter(Boolean);
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

function positiveInteger(value: unknown): number | null {
  const numeric = Number(value);
  return Number.isInteger(numeric) && numeric > 0 ? numeric : null;
}

function stringValue(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function firstHeader(value: string | string[] | undefined): string | null {
  return Array.isArray(value) ? value[0] ?? null : value ?? null;
}

function requiresDualWrite(headers: IamRoleWriteRequest["headers"]): boolean {
  const value = firstHeader(headers["x-identity-iam-role-write-require-dual-write"]);
  return value === "1" || value?.toLowerCase() === "true";
}

function copyHeader(
  source: IamRoleWriteRequest["headers"],
  target: Headers,
  sourceName: string,
  targetName: string
): void {
  const value = firstHeader(source[sourceName]);
  if (value) target.set(targetName, value);
}

function bearerToken(authorization: string | null): string | null {
  const [scheme, token] = authorization?.split(/\s+/, 2) ?? [];
  return scheme?.toLowerCase() === "bearer" && token ? token : null;
}

function clientIdempotencyKey(headers: IamRoleWriteRequest["headers"]): string | null {
  const value = firstHeader(headers["idempotency-key"]) ?? firstHeader(headers["x-idempotency-key"]);
  return value?.trim().slice(0, 180) || null;
}

function queryStringFromOriginalUrl(originalUrl: string | undefined): string {
  if (!originalUrl?.includes("?")) return "";
  return originalUrl.slice(originalUrl.indexOf("?"));
}

async function parseUpstreamBody(response: Response): Promise<unknown> {
  const text = await response.text();
  if (!text) return null;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return text;
  }
}

function shortDigest(value: string): string {
  return createHash("sha256").update(value).digest("hex").slice(0, 16);
}
