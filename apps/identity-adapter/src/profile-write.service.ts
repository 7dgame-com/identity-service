import { createHash } from "node:crypto";
import { HttpException, Injectable, Logger, NotFoundException, ServiceUnavailableException } from "@nestjs/common";
import { loadConfig } from "./config.js";
import { IamRepository } from "./iam.repository.js";
import { JwtIssuerService, VerifiedAccessToken } from "./jwt-issuer.service.js";
import { LegacyIdentityReader, LegacyUserReadModel } from "./legacy-identity.reader.js";
import {
  ProfileWriteOperationRepository,
  profileWriteCompensationMetadata,
  profileWriteOperationKey,
  profileWriteReplayResponseFromOperation,
  profileWriteRequestFingerprint,
  profileWriteResponseReplayMetadata,
  redactProfileWriteMetadata
} from "./profile-write-operation.repository.js";

export interface ProfileWriteProxyResponse {
  status: number;
  body: unknown;
  mode: "legacy-proxy" | "dual-write";
}

export interface ProfileWriteRequest {
  method: string;
  originalUrl?: string;
  headers: Record<string, string | string[] | undefined>;
  body?: unknown;
}

const PROFILE_WRITE_EXECUTABLE_MODES = ["disabled", "legacy-proxy", "dual-write"] as const;
const PROFILE_WRITE_ROUTES = ["v1/user/update"] as const;
const REQUIRED_BEFORE_DUAL_WRITE = [
  "operation-ledger",
  "idempotency-keys",
  "identity-profile-shadow-write",
  "compensation-records",
  "secret-redaction-gate",
  "develop-rollback-drill",
  "userinfo-and-plugin-read-regression"
] as const;
const REQUIRED_BEFORE_IDENTITY_NATIVE = [
  "clean-dual-write-production-evidence",
  "profile-field-owner-closeout",
  "avatar-owner-closeout",
  "legacy-proxy-rollback-window",
  "identity-native-canary-runbook"
] as const;

@Injectable()
export class ProfileWriteService {
  private readonly config = loadConfig();
  private readonly logger = new Logger(ProfileWriteService.name);

  constructor(
    private readonly operations: ProfileWriteOperationRepository,
    private readonly iamRepository: IamRepository,
    private readonly jwtIssuer: JwtIssuerService,
    private readonly legacyReader: LegacyIdentityReader
  ) {}

  readiness() {
    const { iam } = this.config;
    const legacyProxyConfigured = Boolean(iam.profileWriteLegacyApiBaseUrl);
    const operationLedgerConfigured = this.operations.isConfigured();
    const identityRepositoryConfigured = this.iamRepository.isConfigured();
    const rollout = profileWriteRolloutReadiness(iam);
    const dualWriteGate = dualWriteGateForReadiness({
      legacyProxyConfigured,
      operationLedgerConfigured,
      identityRepositoryConfigured,
      executionFlagEnabled: iam.profileWriteDualWriteExecutionEnabled,
      rollout
    });
    const unsupportedModeBlocked =
      (iam.profileWriteMode === "dual-write" && !dualWriteGate.executable) || iam.profileWriteMode === "identity-native";

    return {
      enabled: iam.profileWriteMode !== "disabled",
      mode: iam.profileWriteMode,
      legacyProxyConfigured,
      timeoutMs: iam.profileWriteTimeoutMs,
      operationLedgerConfigured,
      identityRepositoryConfigured,
      dualWriteExecutionEnabled: iam.profileWriteDualWriteExecutionEnabled,
      idempotencyKeyFormat: "profile-write:v1:<subject-id>:v1/user/update:<sha256-48>",
      sourceOfTruth: sourceOfTruthForMode(iam.profileWriteMode, dualWriteGate.executable),
      routes: [...PROFILE_WRITE_ROUTES],
      rollout,
      allowedExecutableModes: [...PROFILE_WRITE_EXECUTABLE_MODES],
      unsupportedModesBlocked: iam.profileWriteMode === "identity-native" ? ["identity-native"] : unsupportedModeBlocked ? ["dual-write"] : [],
      blockedReasons: unsupportedModeBlocked ? blockedReasonsForMode(iam.profileWriteMode) : [],
      dualWriteSupported: dualWriteGate.executable,
      identityNativeSupported: false,
      dualWriteGate,
      identityNativeGate: identityNativeGateForReadiness({
        dualWriteSupported: dualWriteGate.executable && dualWriteGate.productionCanaryReady,
        identityRepositoryConfigured
      }),
      responseShapePreserved: true,
      redactionPolicy: "metadata-only-no-secret-payloads",
      compensationRecordsRequired: true,
      reconciliation: {
        dryRunSupported: true,
        endpoint: "/internal/profile-write/reconciliation/dry-run",
        comparedFields: ["nickname", "info"],
        rawProfileValuesRedacted: true
      },
      requiredBeforeDualWrite: [...REQUIRED_BEFORE_DUAL_WRITE],
      requiredBeforeIdentityNative: [...REQUIRED_BEFORE_IDENTITY_NATIVE]
    };
  }

  async operationLedgerSummary(input: { sinceMinutes?: number }) {
    const sinceMinutes = normalizeSinceMinutes(input.sinceMinutes);
    if (!this.operations.isConfigured()) {
      return {
        configured: false,
        sinceMinutes,
        routes: []
      };
    }

    return {
      configured: true,
      sinceMinutes,
      routes: await this.operations.summarizeRecent({ sinceMinutes })
    };
  }

  async operationLedgerRecent(input: { sinceMinutes?: number; limit?: number }) {
    const sinceMinutes = normalizeSinceMinutes(input.sinceMinutes);
    const limit = normalizeRecentLimit(input.limit);
    if (!this.operations.isConfigured()) {
      return {
        configured: false,
        sinceMinutes,
        limit,
        operations: []
      };
    }

    return {
      configured: true,
      sinceMinutes,
      limit,
      operations: await this.operations.listRecentSafe({ sinceMinutes, limit })
    };
  }

  async reconciliationDryRun(rawInput: unknown) {
    const input = parseProfileReconciliationInput(rawInput);
    if (!this.legacyReader.isConfigured()) {
      throw new ServiceUnavailableException({
        code: "PROFILE_RECONCILIATION_LEGACY_SOURCE_NOT_CONFIGURED",
        message: "Legacy profile source is not configured."
      });
    }
    if (!this.iamRepository.isConfigured()) {
      throw new ServiceUnavailableException({
        code: "PROFILE_RECONCILIATION_IDENTITY_DB_NOT_CONFIGURED",
        message: "Identity database is not configured."
      });
    }

    const users = await this.loadReconciliationUsers(input);
    const items: ProfileReconciliationItem[] = [];
    for (const user of users) {
      const identity = await this.iamRepository.getIdentityUserByLegacyId(user.id);
      const identityUserId = identity?.id ?? `legacy:${user.id}`;
      if (!identity) {
        items.push(
          profileReconciliationItem("p1", user, identityUserId, "identityUser", user.id, null, {
            message: "Identity profile shadow user is missing for legacy user."
          })
        );
        continue;
      }

      if (identity.legacyUserId !== user.id) {
        items.push(
          profileReconciliationItem("p0", user, identity.id, "legacyUserId", user.id, identity.legacyUserId, {
            message: "Identity profile shadow maps to a different legacy user id."
          })
        );
      }

      const profile = identityProfileMetadata(identity.metadata);
      if (!profile) {
        items.push(
          profileReconciliationItem("p2", user, identity.id, "profile", "expected", "missing", {
            message: "Identity profile shadow metadata is missing for this user.",
            metadata: {
              owner: "profile-write-dual-write",
              waiverAllowedBeforeCanary: false
            }
          })
        );
        continue;
      }

      if (!sameCanonical(profile.nickname ?? null, user.nickname ?? null)) {
        items.push(
          profileReconciliationItem("p2", user, identity.id, "profile.nickname", user.nickname, profile.nickname ?? null, {
            message: "Legacy nickname and identity profile shadow nickname differ."
          })
        );
      }

      if (!sameCanonical(profile.info ?? null, normalizeEmptyObject(user.userInfo))) {
        items.push(
          profileReconciliationItem("p2", user, identity.id, "profile.info", normalizeEmptyObject(user.userInfo), profile.info ?? null, {
            message: "Legacy user_info.info and identity profile shadow info differ."
          })
        );
      }
    }

    return {
      dryRun: true,
      writeSideEffects: "none",
      comparedFields: ["nickname", "info"],
      avatar: {
        compared: false,
        reason: "avatar_id is not materialized by the current legacy profile reader; P7 waiver applies until a reversible avatar asset exists."
      },
      sampleCount: users.length,
      severity: summarizeProfileReconciliationItems(items),
      items,
      safetyGate: {
        passed: items.every((item) => item.severity !== "p0" && item.severity !== "p1"),
        p0BlocksDualWriteCloseout: true,
        p1BlocksDualWriteCloseout: true,
        p2RequiresOwnerReview: true
      },
      nextRecommendedAction: nextProfileReconciliationAction(items)
    };
  }

  async reconciliationBackfillShadow(rawInput: unknown) {
    const input = parseProfileBackfillInput(rawInput);
    if (!this.legacyReader.isConfigured()) {
      throw new ServiceUnavailableException({
        code: "PROFILE_RECONCILIATION_LEGACY_SOURCE_NOT_CONFIGURED",
        message: "Legacy profile source is not configured."
      });
    }
    if (!this.iamRepository.isConfigured()) {
      throw new ServiceUnavailableException({
        code: "PROFILE_RECONCILIATION_IDENTITY_DB_NOT_CONFIGURED",
        message: "Identity database is not configured."
      });
    }

    const users = await this.loadReconciliationUsers(input);
    const plans: ProfileBackfillPlan[] = [];
    for (const user of users) {
      const identity = await this.iamRepository.getIdentityUserByLegacyId(user.id);
      const profile = identity ? identityProfileMetadata(identity.metadata) : null;
      const identityUserId = identity?.id ?? `legacy:${user.id}`;
      const metadata = profileShadowMetadataFromLegacyUser(user, "profile-write-reconciliation-backfill");
      const needsWrite =
        !identity ||
        !profile ||
        !sameCanonical(profile.nickname ?? null, metadata.profile.nickname ?? null) ||
        !sameCanonical(profile.info ?? null, metadata.profile.info ?? null);

      plans.push({
        legacyUserId: user.id,
        identityUserId,
        username: user.username,
        status: identityStatusFromLegacyUser(user),
        reason: !identity ? "missing-identity-user" : !profile ? "missing-profile-shadow" : needsWrite ? "profile-shadow-diff" : "already-aligned",
        needsWrite,
        metadata
      });
    }

    const writePlans = plans.filter((plan) => plan.needsWrite);
    const applyShadow = input.applyShadow && input.confirmApplyShadow;
    if (applyShadow) {
      for (const plan of writePlans) {
        await this.iamRepository.upsertIdentityUserProfileShadow({
          identityUserId: plan.identityUserId,
          legacyUserId: plan.legacyUserId,
          username: plan.username,
          status: plan.status,
          metadata: plan.metadata
        });
      }
    }

    return {
      dryRun: !applyShadow,
      applyShadow,
      writeSideEffects: applyShadow ? "identity-profile-shadow" : "none",
      sampleCount: users.length,
      plannedWriteCount: writePlans.length,
      shadowWriteCount: applyShadow ? writePlans.length : 0,
      reasonCounts: countProfileBackfillReasons(plans),
      cursor: {
        afterLegacyUserId: input.afterLegacyUserId ?? 0,
        limit: input.limit ?? 50,
        nextAfterLegacyUserId: users.length > 0 ? users[users.length - 1]!.id : input.afterLegacyUserId ?? 0
      },
      evidence: {
        rawProfileValuesRedacted: true,
        plannedLegacyUserIds: writePlans.map((plan) => plan.legacyUserId).slice(0, 100)
      },
      safetyGate: {
        readyForApply: writePlans.length > 0,
        requiresExplicitConfirmApplyShadow: true,
        p0BlocksDualWriteCloseout: true,
        p1BlocksDualWriteCloseout: true
      },
      nextRecommendedAction: applyShadow
        ? "rerun_profile_reconciliation_dry_run"
        : writePlans.length > 0
          ? "rerun_with_applyShadow_and_confirmApplyShadow"
          : "rerun_profile_reconciliation_dry_run"
    };
  }

  async proxy(request: ProfileWriteRequest, path: string): Promise<ProfileWriteProxyResponse> {
    const { iam } = this.config;

    if (iam.profileWriteMode === "disabled") {
      throw new NotFoundException({
        code: "PROFILE_WRITE_DISABLED",
        message: "Profile write migration is disabled."
      });
    }

    if (iam.profileWriteMode === "legacy-proxy") {
      return this.legacyProxy(request, path, "legacy-proxy");
    }

    if (iam.profileWriteMode === "dual-write") {
      const dualWriteGate = dualWriteGateForReadiness({
        legacyProxyConfigured: Boolean(iam.profileWriteLegacyApiBaseUrl),
        operationLedgerConfigured: this.operations.isConfigured(),
        identityRepositoryConfigured: this.iamRepository.isConfigured(),
        executionFlagEnabled: iam.profileWriteDualWriteExecutionEnabled,
        rollout: profileWriteRolloutReadiness(iam)
      });
      if (!dualWriteGate.executable) {
        throw new NotFoundException({
          code: "PROFILE_WRITE_UNSUPPORTED_MODE",
          message: "Profile write dual-write mode is not executable yet.",
          missingCapabilities: dualWriteGate.missingCapabilities
        });
      }

      const rolloutDecision = this.dualWriteRolloutDecision(request);
      this.logRolloutDecision(rolloutDecision);
      if (!rolloutDecision.selected) {
        return this.legacyProxy(request, path, "legacy-proxy");
      }

      return this.dualWrite(request, path, rolloutDecision.claims);
    }

    throw new NotFoundException({
      code: "PROFILE_WRITE_UNSUPPORTED_MODE",
      message: `Profile write mode ${iam.profileWriteMode} is not executable yet.`
    });
  }

  private async loadReconciliationUsers(input: ProfileReconciliationInput): Promise<LegacyUserReadModel[]> {
    if (input.legacyUserIds?.length) {
      const users = await Promise.all(input.legacyUserIds.map((id) => this.legacyReader.getUserById(id)));
      return users.filter((user): user is LegacyUserReadModel => user !== null);
    }

    return this.legacyReader.listUsers({
      afterId: input.afterLegacyUserId ?? 0,
      limit: input.limit ?? 50
    });
  }

  private dualWriteRolloutDecision(request: ProfileWriteRequest): ProfileWriteRolloutDecision {
    const { iam } = this.config;
    const claims = this.claimsFromAuthorization(request.headers.authorization);
    const tokens = profileWriteRolloutTokens(claims);
    const allowlist = splitCsv(iam.profileWriteRolloutAllowlist).map(normalizeRolloutToken).filter(Boolean);

    if (iam.profileWriteRolloutMode === "full") {
      return {
        selected: true,
        mode: "full",
        subjectId: claims ? `legacy:${claims.uid}` : null,
        reason: "full_rollout",
        claims
      };
    }

    if (iam.profileWriteRolloutMode === "canary") {
      const matchedToken = allowlist.find((item) => tokens.has(item));
      return {
        selected: Boolean(matchedToken),
        mode: "canary",
        subjectId: claims ? `legacy:${claims.uid}` : null,
        reason: matchedToken ? "canary_subject_selected" : "canary_subject_not_selected",
        matchedToken: matchedToken ?? null,
        claims
      };
    }

    if (iam.profileWriteRolloutMode === "off") {
      return {
        selected: false,
        mode: "off",
        subjectId: claims ? `legacy:${claims.uid}` : null,
        reason: "rollout_off",
        claims
      };
    }

    const percentage = safeRolloutPercentage(iam.profileWriteRolloutPercentage);
    const bucketSubject = claims ? `legacy:${claims.uid}` : null;
    const bucket = bucketSubject ? rolloutBucket(bucketSubject) : null;
    const selected = percentage >= 100 || (percentage > 0 && bucket !== null && bucket < percentage);
    return {
      selected,
      mode: "percentage",
      subjectId: bucketSubject,
      reason: selected ? "percentage_bucket_selected" : "percentage_bucket_not_selected",
      bucket,
      percentage,
      claims
    };
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

  private logRolloutDecision(decision: ProfileWriteRolloutDecision): void {
    this.logger.log(
      JSON.stringify({
        event: "identity.profile.write.rollout",
        mode: decision.mode,
        selected: decision.selected,
        reason: decision.reason,
        subjectId: decision.subjectId,
        matchedToken: decision.matchedToken ?? null,
        bucket: decision.bucket ?? null,
        percentage: decision.percentage ?? null,
        unselectedBehavior: decision.selected ? "dual-write" : "legacy-proxy"
      })
    );
  }

  private async legacyProxy(
    request: ProfileWriteRequest,
    path: string,
    mode: "legacy-proxy" | "dual-write"
  ): Promise<ProfileWriteProxyResponse> {
    const { iam } = this.config;
    if (!iam.profileWriteLegacyApiBaseUrl) {
      throw new ServiceUnavailableException({
        code: "PROFILE_WRITE_LEGACY_API_NOT_CONFIGURED",
        message: "Legacy profile API base URL is not configured."
      });
    }

    const url = new URL(path, `${iam.profileWriteLegacyApiBaseUrl.replace(/\/+$/, "")}/`);
    const query = queryStringFromOriginalUrl(request.originalUrl);
    if (query) {
      url.search = query;
    }

    const headers = new Headers({
      Accept: "application/json",
      "X-Identity-Profile-Write-Proxy": "1"
    });
    const authorization = firstHeader(request.headers.authorization);
    const forwardedFor = firstHeader(request.headers["x-forwarded-for"]);
    const userAgent = firstHeader(request.headers["user-agent"]);
    if (authorization) {
      headers.set("Authorization", authorization);
    }
    if (forwardedFor) {
      headers.set("X-Forwarded-For", forwardedFor);
    }
    if (userAgent) {
      headers.set("User-Agent", userAgent);
    }

    const method = request.method.toUpperCase();
    const init: RequestInit = {
      method,
      headers,
      signal: AbortSignal.timeout(iam.profileWriteTimeoutMs)
    };
    if (!["GET", "HEAD"].includes(method)) {
      headers.set("Content-Type", "application/json");
      init.body = JSON.stringify(request.body ?? {});
    }

    let upstream: Response;
    try {
      upstream = await fetch(url, init);
    } catch (error) {
      throw new ServiceUnavailableException({
        code: "PROFILE_WRITE_LEGACY_API_UNAVAILABLE",
        message: "Legacy profile API is unavailable.",
        detail: error instanceof Error ? error.message : String(error)
      });
    }

    const body = await parseUpstreamBody(upstream);
    if (upstream.status >= 400) {
      throw new HttpException(toHttpExceptionBody(body), upstream.status);
    }

    return {
      status: upstream.status,
      body,
      mode
    };
  }

  private async dualWrite(
    request: ProfileWriteRequest,
    path: string,
    claims: VerifiedAccessToken | null
  ): Promise<ProfileWriteProxyResponse> {
    const plan = planProfileWriteOperation(request, claims);
    const begin = await this.operations.begin({
      operationKey: plan.operationKey,
      idempotencyKey: plan.operationKey,
      route: "update-profile",
      mode: "dual-write",
      subjectId: plan.subjectId,
      legacyUserId: plan.legacyUserId,
      identityUserId: plan.identityUserId,
      metadata: plan.metadata
    });

    if (begin.duplicate) {
      const existing = await this.operations.findByOperationKey(plan.operationKey);
      const replay = existing ? profileWriteReplayResponseFromOperation(existing) : null;
      if (replay) {
        return {
          ...replay,
          mode: "dual-write"
        };
      }

      throw new ServiceUnavailableException({
        code: "PROFILE_WRITE_REPLAY_UNAVAILABLE",
        message: "Profile write operation is already recorded but has no completed replay response."
      });
    }

    let legacyResponse: ProfileWriteProxyResponse;
    try {
      legacyResponse = await this.legacyProxy(request, path, "dual-write");
    } catch (error) {
      await this.operations.update({
        operationKey: plan.operationKey,
        status: "failed",
        legacyStatus: "unavailable",
        identityStatus: "skipped",
        compensationStatus: "none",
        errorCode: error instanceof Error ? error.name : "ProfileWriteLegacyError",
        metadata: {
          phase: "legacy",
          route: "update-profile"
        }
      });
      throw error;
    }

    const responseReplay = profileWriteResponseReplayMetadata({
      status: legacyResponse.status,
      body: legacyResponse.body
    });

    try {
      if (!plan.legacyUserId || !plan.identityUserId) {
        await this.operations.update({
          operationKey: plan.operationKey,
          status: "legacy_completed",
          legacyStatus: String(legacyResponse.status),
          identityStatus: "skipped:missing-authenticated-subject",
          compensationStatus: "required",
          errorCode: "ProfileWriteSubjectMissing",
          metadata: {
            ...responseReplay,
            ...profileWriteCompensationMetadata({
              phase: "identity",
              reason: "missing-authenticated-subject",
              errorCode: "ProfileWriteSubjectMissing",
              legacyStatus: legacyResponse.status,
              identityStatus: "skipped",
              detail: plan.metadata
            })
          }
        });
        return legacyResponse;
      }

      await this.iamRepository.upsertIdentityUserProfileShadow({
        identityUserId: plan.identityUserId,
        legacyUserId: plan.legacyUserId,
        username: plan.username,
        metadata: {
          source: "profile-write-dual-write",
          legacyUserId: plan.legacyUserId,
          profile: plan.profileMetadata
        }
      });

      await this.operations.update({
        operationKey: plan.operationKey,
        status: "completed",
        legacyStatus: String(legacyResponse.status),
        identityStatus: "completed",
        compensationStatus: "none",
        metadata: {
          ...responseReplay,
          identityShadow: {
            writeCount: 1,
            fields: Object.keys(plan.profileMetadata)
          }
        }
      });
      return legacyResponse;
    } catch (error) {
      await this.operations.update({
        operationKey: plan.operationKey,
        status: "legacy_completed",
        legacyStatus: String(legacyResponse.status),
        identityStatus: "failed",
        compensationStatus: "required",
        errorCode: error instanceof Error ? error.name : "ProfileWriteIdentityError",
        metadata: {
          ...responseReplay,
          ...profileWriteCompensationMetadata({
            phase: "identity",
            reason: "identity-profile-shadow-write-failed",
            errorCode: error instanceof Error ? error.name : "ProfileWriteIdentityError",
            legacyStatus: legacyResponse.status,
            identityStatus: "failed",
            detail: plan.metadata
          })
        }
      });
      return legacyResponse;
    }
  }
}

function planProfileWriteOperation(request: ProfileWriteRequest, claims: VerifiedAccessToken | null) {
  const legacyUserId = claims?.uid ?? null;
  const identityUserId = legacyUserId ? `legacy:${legacyUserId}` : null;
  const subjectId = identityUserId;
  const profileMetadata = profileMetadataFromBody(request.body);
  const requestFingerprint = profileWriteRequestFingerprint(profileMetadata);
  const operationKey = profileWriteOperationKey({
    route: "update-profile",
    subjectId,
    requestFingerprint
  });

  return {
    operationKey,
    subjectId,
    legacyUserId,
    identityUserId,
    username: claims?.username ?? null,
    profileMetadata,
    metadata: {
      route: "update-profile",
      method: request.method.toUpperCase(),
      subjectId,
      redactedBody: redactProfileWriteMetadata(request.body ?? {})
    }
  };
}

function profileMetadataFromBody(body: unknown): Record<string, unknown> {
  const record = body && typeof body === "object" && !Array.isArray(body) ? (body as Record<string, unknown>) : {};
  const output: Record<string, unknown> = {};

  for (const field of ["nickname", "info", "avatar_id", "avatarId", "gender", "birthday", "company", "industry", "position", "location"]) {
    if (field in record) {
      output[field] = redactProfileWriteMetadata({ [field]: record[field] })[field];
    }
  }

  return output;
}

function normalizeSinceMinutes(value: number | undefined): number {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) {
    return 60;
  }

  return Math.max(1, Math.min(1440, Math.trunc(numeric)));
}

function normalizeRecentLimit(value: number | undefined): number {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) {
    return 50;
  }

  return Math.max(1, Math.min(200, Math.trunc(numeric)));
}

function dualWriteGateForReadiness(input: {
  legacyProxyConfigured: boolean;
  operationLedgerConfigured: boolean;
  identityRepositoryConfigured: boolean;
  executionFlagEnabled: boolean;
  rollout: ProfileWriteRolloutReadiness;
}) {
  const missingCapabilities: string[] = [];
  if (!input.executionFlagEnabled) {
    missingCapabilities.unshift("operator-dual-write-execution-flag");
  }
  if (!input.legacyProxyConfigured) {
    missingCapabilities.unshift("legacy-proxy-base-url");
  }
  if (!input.operationLedgerConfigured) {
    missingCapabilities.unshift("operation-ledger");
  }
  if (!input.identityRepositoryConfigured) {
    missingCapabilities.unshift("identity-repository");
  }
  const executable = missingCapabilities.length === 0;

  return {
    executable,
    productionCanaryReady: executable && input.rollout.selectionConfigured,
    sourceOfTruthUntilCloseout: "legacy",
    supportedRoutes: executable ? [...PROFILE_WRITE_ROUTES] : [],
    blockedRoutes: executable ? [] : [...PROFILE_WRITE_ROUTES],
    fieldOwners: {
      nickname: "dual-write-candidate",
      info: "dual-write-candidate",
      avatar_id: "dual-write-candidate-after-avatar-waiver-closeout",
      email: "account-lifecycle-owner",
      phone: "retained-legacy-owner",
      status: "account-lifecycle-owner"
    },
    configured: {
      legacyProxy: input.legacyProxyConfigured,
      operationLedger: input.operationLedgerConfigured,
      identityRepository: input.identityRepositoryConfigured,
      executionFlag: input.executionFlagEnabled,
      rollout: input.rollout.selectionConfigured
    },
    runtimeCapabilities: ["idempotent-response-replay", "identity-profile-shadow-write", "compensation-records"],
    productionCanaryBlockers: input.rollout.selectionConfigured ? [] : ["single-target-rollout-selector"],
    missingCapabilities
  };
}

function identityNativeGateForReadiness(input: { dualWriteSupported: boolean; identityRepositoryConfigured: boolean }) {
  const missingCapabilities: string[] = [];
  if (!input.dualWriteSupported) {
    missingCapabilities.push("dual-write-production-closeout");
  }
  if (!input.identityRepositoryConfigured) {
    missingCapabilities.push("identity-repository");
  }
  missingCapabilities.push("identity-native-canary-runbook");

  return {
    executable: false,
    supportedRoutes: [],
    retainedLegacyRoutes: ["email", "phone", "status"],
    configured: {
      dualWriteSupported: input.dualWriteSupported,
      identityRepository: input.identityRepositoryConfigured
    },
    missingCapabilities
  };
}

interface ProfileWriteRolloutReadiness {
  mode: "off" | "canary" | "percentage" | "full";
  allowlistConfigured: boolean;
  allowlistCount: number;
  percentage: number;
  selectionConfigured: boolean;
  unselectedBehavior: "legacy-proxy";
}

interface ProfileWriteRolloutDecision {
  selected: boolean;
  mode: "off" | "canary" | "percentage" | "full";
  subjectId: string | null;
  reason: string;
  matchedToken?: string | null;
  bucket?: number | null;
  percentage?: number | null;
  claims: VerifiedAccessToken | null;
}

interface ProfileReconciliationInput {
  legacyUserIds?: number[];
  afterLegacyUserId?: number;
  limit?: number;
}

interface ProfileBackfillInput extends ProfileReconciliationInput {
  applyShadow: boolean;
  confirmApplyShadow: boolean;
}

interface ProfileBackfillPlan {
  legacyUserId: number;
  identityUserId: string;
  username: string | null;
  status: string;
  reason: "missing-identity-user" | "missing-profile-shadow" | "profile-shadow-diff" | "already-aligned";
  needsWrite: boolean;
  metadata: {
    source: string;
    legacyUserId: number;
    profile: {
      nickname: string | null;
      info: unknown;
    };
  };
}

interface ProfileReconciliationItem {
  severity: "p0" | "p1" | "p2" | "info";
  legacySubjectType: "legacy_user";
  legacySubjectId: string;
  identitySubjectType: "identity_user";
  identitySubjectId: string;
  fieldPath: string;
  legacyValueHash: string | null;
  identityValueHash: string | null;
  message: string;
  metadata: Record<string, unknown>;
}

function profileWriteRolloutReadiness(iam: ReturnType<typeof loadConfig>["iam"]): ProfileWriteRolloutReadiness {
  const allowlistCount = splitCsv(iam.profileWriteRolloutAllowlist).length;
  const percentage = safeRolloutPercentage(iam.profileWriteRolloutPercentage);
  const selectionConfigured =
    iam.profileWriteRolloutMode === "full" ||
    (iam.profileWriteRolloutMode === "canary" && allowlistCount > 0) ||
    (iam.profileWriteRolloutMode === "percentage" && percentage > 0);

  return {
    mode: iam.profileWriteRolloutMode,
    allowlistConfigured: allowlistCount > 0,
    allowlistCount,
    percentage,
    selectionConfigured,
    unselectedBehavior: "legacy-proxy"
  };
}

function parseProfileReconciliationInput(rawInput: unknown): ProfileReconciliationInput {
  const object = rawInput && typeof rawInput === "object" && !Array.isArray(rawInput) ? (rawInput as Record<string, unknown>) : {};
  const legacyUserIds = Array.isArray(object.legacyUserIds)
    ? object.legacyUserIds.map((value) => Number(value)).filter((value) => Number.isInteger(value) && value > 0).slice(0, 100)
    : undefined;
  const afterLegacyUserId = positiveIntegerOrUndefined(object.afterLegacyUserId);
  const limit = Math.max(1, Math.min(500, positiveIntegerOrUndefined(object.limit) ?? 50));

  return {
    legacyUserIds: legacyUserIds && legacyUserIds.length > 0 ? legacyUserIds : undefined,
    afterLegacyUserId,
    limit
  };
}

function parseProfileBackfillInput(rawInput: unknown): ProfileBackfillInput {
  const object = rawInput && typeof rawInput === "object" && !Array.isArray(rawInput) ? (rawInput as Record<string, unknown>) : {};
  const base = parseProfileReconciliationInput(rawInput);
  return {
    ...base,
    applyShadow: object.applyShadow === true,
    confirmApplyShadow: object.confirmApplyShadow === true
  };
}

function profileShadowMetadataFromLegacyUser(
  user: LegacyUserReadModel,
  source: "profile-write-dual-write" | "profile-write-reconciliation-backfill"
): ProfileBackfillPlan["metadata"] {
  return {
    source,
    legacyUserId: user.id,
    profile: {
      nickname: user.nickname ?? null,
      info: normalizeEmptyObject(user.userInfo)
    }
  };
}

function identityStatusFromLegacyUser(user: LegacyUserReadModel): string {
  return user.status === 10 ? "active" : "inactive";
}

function countProfileBackfillReasons(plans: ProfileBackfillPlan[]): Record<ProfileBackfillPlan["reason"], number> {
  return {
    "missing-identity-user": plans.filter((plan) => plan.reason === "missing-identity-user").length,
    "missing-profile-shadow": plans.filter((plan) => plan.reason === "missing-profile-shadow").length,
    "profile-shadow-diff": plans.filter((plan) => plan.reason === "profile-shadow-diff").length,
    "already-aligned": plans.filter((plan) => plan.reason === "already-aligned").length
  };
}

function profileReconciliationItem(
  severity: ProfileReconciliationItem["severity"],
  legacyUser: LegacyUserReadModel,
  identityUserId: string,
  fieldPath: string,
  legacyValue: unknown,
  identityValue: unknown,
  input: { message: string; metadata?: Record<string, unknown> }
): ProfileReconciliationItem {
  return {
    severity,
    legacySubjectType: "legacy_user",
    legacySubjectId: String(legacyUser.id),
    identitySubjectType: "identity_user",
    identitySubjectId: identityUserId,
    fieldPath,
    legacyValueHash: hashValue(legacyValue),
    identityValueHash: hashValue(identityValue),
    message: input.message,
    metadata: input.metadata ?? {}
  };
}

function identityProfileMetadata(metadata: unknown): Record<string, unknown> | null {
  const record = metadata && typeof metadata === "object" && !Array.isArray(metadata) ? (metadata as Record<string, unknown>) : {};
  const profile = record.profile;
  if (profile && typeof profile === "object" && !Array.isArray(profile)) {
    return profile as Record<string, unknown>;
  }

  return null;
}

function summarizeProfileReconciliationItems(items: ProfileReconciliationItem[]) {
  return {
    p0: items.filter((item) => item.severity === "p0").length,
    p1: items.filter((item) => item.severity === "p1").length,
    p2: items.filter((item) => item.severity === "p2").length,
    info: items.filter((item) => item.severity === "info").length
  };
}

function nextProfileReconciliationAction(items: ProfileReconciliationItem[]): string {
  const summary = summarizeProfileReconciliationItems(items);
  if (summary.p0 > 0 || summary.p1 > 0) {
    return "fix_p0_p1_before_dual_write_closeout";
  }
  if (summary.p2 > 0) {
    return "review_profile_owner_or_record_waiver";
  }
  return "ready_for_develop_dual_write_closeout_if_runtime_smoke_passes";
}

function sameCanonical(left: unknown, right: unknown): boolean {
  return stableStringify(left) === stableStringify(right);
}

function normalizeEmptyObject(value: unknown): unknown {
  if (value && typeof value === "object" && !Array.isArray(value) && Object.keys(value as Record<string, unknown>).length === 0) {
    return null;
  }

  return value ?? null;
}

function hashValue(value: unknown): string | null {
  if (value === null || value === undefined) {
    return null;
  }

  return createHash("sha256").update(stableStringify(value)).digest("hex").slice(0, 16);
}

function stableStringify(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(",")}]`;
  }

  if (!value || typeof value !== "object") {
    return JSON.stringify(value);
  }

  const entries = Object.entries(value as Record<string, unknown>).sort(([left], [right]) => left.localeCompare(right));
  return `{${entries.map(([key, child]) => `${JSON.stringify(key)}:${stableStringify(child)}`).join(",")}}`;
}

function positiveIntegerOrUndefined(value: unknown): number | undefined {
  const numeric = Number(value);
  return Number.isInteger(numeric) && numeric > 0 ? numeric : undefined;
}

function blockedReasonsForMode(mode: string): string[] {
  if (mode === "dual-write") {
    return ["profile-write-dual-write-gate-not-ready"];
  }

  if (mode === "identity-native") {
    return ["profile-write-identity-native-requires-separate-canary"];
  }

  return [];
}

function sourceOfTruthForMode(mode: string, dualWriteExecutable: boolean): string {
  if (mode === "legacy-proxy") {
    return "legacy";
  }
  if (mode === "dual-write") {
    return dualWriteExecutable ? "legacy-during-dual-write" : "unsupported";
  }
  if (mode === "identity-native") {
    return "unsupported";
  }
  return "none";
}

function profileWriteRolloutTokens(claims: VerifiedAccessToken | null): Set<string> {
  const tokens = new Set<string>();
  if (!claims) {
    return tokens;
  }

  tokens.add(normalizeRolloutToken(`legacy:${claims.uid}`));
  tokens.add(normalizeRolloutToken(`legacy-user:${claims.uid}`));
  if (claims.username) {
    tokens.add(normalizeRolloutToken(`username:${claims.username}`));
  }

  return tokens;
}

function normalizeRolloutToken(value: string | null | undefined): string {
  return (value ?? "").trim().toLowerCase();
}

function splitCsv(value: string | undefined): string[] {
  return (value ?? "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function safeRolloutPercentage(value: number | undefined): number {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) {
    return 0;
  }

  return Math.max(0, Math.min(100, Math.trunc(numeric)));
}

function rolloutBucket(subject: string): number {
  const digest = createHash("sha256").update(subject).digest("hex");
  return Number.parseInt(digest.slice(0, 8), 16) % 100;
}

function bearerToken(authorization: string | null): string | null {
  const match = authorization?.match(/^Bearer\s+(.+)$/i);
  return match?.[1] ?? null;
}

function firstHeader(value: string | string[] | undefined): string | null {
  if (Array.isArray(value)) {
    return value[0] ?? null;
  }

  return value ?? null;
}

function queryStringFromOriginalUrl(originalUrl: string | undefined): string {
  const queryStart = originalUrl?.indexOf("?") ?? -1;
  return queryStart >= 0 ? originalUrl!.slice(queryStart + 1) : "";
}

async function parseUpstreamBody(response: Response): Promise<unknown> {
  const text = await response.text();
  if (!text) {
    return null;
  }

  const contentType = response.headers.get("content-type") ?? "";
  if (contentType.includes("application/json")) {
    try {
      return JSON.parse(text);
    } catch {
      return { message: text };
    }
  }

  try {
    return JSON.parse(text);
  } catch {
    return { message: text };
  }
}

function toHttpExceptionBody(body: unknown): string | Record<string, unknown> {
  if (body && typeof body === "object") {
    return body as Record<string, unknown>;
  }

  return { message: String(body ?? "Profile write upstream request failed.") };
}
