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
  mode: "legacy-proxy" | "dual-write";
  evidence?: IamRoleWriteEvidence;
}

type RoleWriteContract = "plugin-user-change-role" | "people-auth";
type RoleWriteRoute = "change-role" | "people-auth";

const ROLE_WRITE_MODES = ["disabled", "legacy-proxy", "dual-write"] as const;
const ROLE_WRITE_ROUTES: RoleWriteRoute[] = ["change-role", "people-auth"];
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
    const dualWriteGate = await this.dualWriteGate(rollout);
    const modeBlocked = iam.roleWriteMode === "identity-native" || (iam.roleWriteMode === "dual-write" && !dualWriteGate.executable);

    return {
      enabled: iam.roleWriteMode !== "disabled",
      mode: iam.roleWriteMode,
      sourceOfTruth: iam.roleWriteMode === "dual-write" && dualWriteGate.executable ? "legacy-with-identity-candidate" : "legacy",
      routes: ROLE_WRITE_ROUTES,
      legacyProxyConfigured: Boolean(iam.roleWriteLegacyApiBaseUrl),
      timeoutMs: iam.roleWriteTimeoutMs,
      operationLedgerConfigured: this.operations.isConfigured(),
      identityRepositoryConfigured: this.iamRepository.isConfigured(),
      legacyReaderConfigured: this.legacyReader.isConfigured(),
      policyChecksumConfigured: Boolean(iam.roleWritePolicyChecksum),
      dualWriteExecutionEnabled: iam.roleWriteDualWriteExecutionEnabled,
      rollout,
      rootProtection: {
        legacyOwnerEnforced: true,
        identityCandidateGuardEnabled: true,
        roleRootNeverMaterialized: true
      },
      allowedExecutableModes: [...ROLE_WRITE_MODES],
      responseShapePreservedInLegacyProxy: true,
      recoveryEndpoint: "/internal/iam/role-write/operations/:operationKey/retry-identity-shadow",
      dualWriteGate,
      blockedReasons: modeBlocked ? dualWriteGate.missingCapabilities : [],
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

  async previewPluginUserRollout(request: IamRoleWriteRequest) {
    const claims = this.requireClaims(request.headers.authorization);
    const correlationId = roleWriteCorrelationId(request.headers);
    const decision = this.config.iam.roleWriteMode === "dual-write"
      ? this.dualWriteRolloutDecision(request, "plugin-user-change-role", correlationId, claims)
      : this.inactiveRolloutDecision(request, "plugin-user-change-role", correlationId, claims);
    const rollout = roleWriteRolloutReadiness(this.config.iam);
    const dualWriteGate = this.config.iam.roleWriteMode === "dual-write"
      ? await this.dualWriteGate(rollout)
      : {
          executable: false,
          missingCapabilities: ["role-write-mode-not-dual-write"]
        };
    const evidence = evidenceFromDecision(decision);

    this.logRolloutDecision(decision, true);
    return {
      writePerformed: false,
      sourceOfTruth: "legacy",
      roleWriteMode: this.config.iam.roleWriteMode,
      rolloutMode: decision.mode,
      selected: decision.selected,
      reason: decision.reason,
      dualWriteExecutable: dualWriteGate.executable,
      missingCapabilities: dualWriteGate.missingCapabilities,
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
    if (iam.roleWriteMode !== "dual-write") {
      throw new NotFoundException({
        code: "IAM_ROLE_WRITE_UNSUPPORTED_MODE",
        message: `IAM role write mode ${iam.roleWriteMode} is not executable yet.`
      });
    }

    const unsupportedScopeField = unsupportedRoleWriteScopeField(request.body);
    if (unsupportedScopeField) {
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
    const gate = await this.dualWriteGate(rollout);
    if (!gate.executable) {
      throw new NotFoundException({
        code: "IAM_ROLE_WRITE_UNSUPPORTED_MODE",
        message: "IAM role write dual-write mode is not executable yet.",
        missingCapabilities: gate.missingCapabilities
      });
    }

    const decision = this.dualWriteRolloutDecision(request, contract, correlationId, claims);
    this.logRolloutDecision(decision);
    const evidence = evidenceFromDecision(decision);
    if (!decision.selected) {
      this.assertRequiredDualWriteAvailable(request, decision.reason);
    }
    return decision.selected ? this.dualWrite(request, contract, evidence) : this.legacyProxy(request, contract, evidence);
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
