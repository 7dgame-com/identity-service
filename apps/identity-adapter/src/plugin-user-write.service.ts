import { createHash } from "node:crypto";
import { Injectable, Logger, NotFoundException, ServiceUnavailableException } from "@nestjs/common";
import { loadConfig } from "./config.js";
import { IamRepository } from "./iam.repository.js";
import { JwtIssuerService, VerifiedAccessToken } from "./jwt-issuer.service.js";
import { planPluginUserIdentityShadow } from "./plugin-user-write-identity-shadow.js";
import { PluginUserWriteOperationRepository } from "./plugin-user-write-operation.repository.js";
import {
  PluginUserWriteOperationRecord,
  pluginUserWriteCompensationMetadata,
  pluginUserWriteReplayResponseFromOperation,
  pluginUserWriteResponseReplayMetadata
} from "./plugin-user-write-operation.repository.js";
import { planShadowOperation, PluginUserWriteShadowService } from "./plugin-user-write-shadow.service.js";

export interface PluginUserWriteProxyResponse {
  status: number;
  body: unknown;
  mode: "legacy-proxy" | "dual-write";
}

const PLUGIN_USER_WRITE_EXECUTABLE_MODES = ["disabled", "legacy-proxy", "dual-write"] as const;
const PLUGIN_USER_WRITE_ROUTES = [
  "create-user",
  "update-user",
  "delete-user",
  "change-role",
  "batch-create-users"
] as const;
const REQUIRED_BEFORE_DUAL_WRITE = [
  "operation-ledger",
  "idempotency-keys",
  "compensation-records",
  "secret-redaction-gate",
  "develop-rollback-drill",
  "ordinary-user-negative-regression"
] as const;
const REQUIRED_BEFORE_IDENTITY_NATIVE = [
  "clean-dual-write-production-evidence",
  "profile-owner-closed-or-retained",
  "role-permission-owner-closed-or-retained",
  "organization-owner-closed-or-retained",
  "legacy-proxy-rollback-window"
] as const;
const DUAL_WRITE_EXECUTION_BLOCKERS: string[] = [];
const DUAL_WRITE_RUNTIME_CAPABILITIES = ["idempotent-response-replay", "identity-write-executor", "compensation-runner"] as const;
const IDENTITY_NATIVE_EXECUTION_BLOCKERS = [
  "production-dual-write-observation-closeout",
  "profile-owner-closeout",
  "role-permission-owner-closeout",
  "organization-owner-closeout",
  "identity-native-canary-runbook"
] as const;

@Injectable()
export class PluginUserWriteService {
  private readonly config = loadConfig();
  private readonly logger = new Logger(PluginUserWriteService.name);

  constructor(
    private readonly operations: PluginUserWriteOperationRepository,
    private readonly shadow: PluginUserWriteShadowService,
    private readonly iamRepository: IamRepository,
    private readonly jwtIssuer: JwtIssuerService
  ) {}

  readiness() {
    const { iam } = this.config;
    const unsupportedModeBlocked = iam.pluginUserWriteMode === "dual-write" || iam.pluginUserWriteMode === "identity-native";
    const legacyProxyConfigured = Boolean(iam.pluginUserWriteLegacyApiBaseUrl);
    const operationLedgerConfigured = this.operations.isConfigured();
    const identityRepositoryConfigured = this.iamRepository.isConfigured();
    const rollout = pluginUserWriteRolloutReadiness(iam);
    const dualWriteGate = dualWriteGateForReadiness({
      legacyProxyConfigured,
      operationLedgerConfigured,
      identityRepositoryConfigured,
      executionFlagEnabled: iam.pluginUserWriteDualWriteExecutionEnabled,
      rollout
    });
    const identityNativeGate = identityNativeGateForReadiness({
      dualWriteSupported: dualWriteGate.executable && dualWriteGate.productionCanaryReady,
      identityRepositoryConfigured
    });
    const blockedReasons =
      iam.pluginUserWriteMode === "dual-write" && dualWriteGate.executable ? [] : blockedReasonsForMode(iam.pluginUserWriteMode);

    return {
      enabled: iam.pluginUserWriteMode !== "disabled",
      mode: iam.pluginUserWriteMode,
      legacyProxyConfigured,
      timeoutMs: iam.pluginUserWriteTimeoutMs,
      operationLedgerConfigured,
      identityRepositoryConfigured,
      dualWriteExecutionEnabled: iam.pluginUserWriteDualWriteExecutionEnabled,
      operationLedgerSchemaAutoEnsure: false,
      idempotencyKeyFormat: "plugin-user-write:v1:<route>:<sha256-48>",
      redactionPolicy: "metadata-only-no-secret-payloads",
      compensationRecordsRequired: true,
      shadow: this.shadow.readiness(),
      rollout,
      allowedExecutableModes: [...PLUGIN_USER_WRITE_EXECUTABLE_MODES],
      unsupportedModeBlocked: unsupportedModeBlocked && !dualWriteGate.executable,
      blockedReasons,
      dualWriteSupported: dualWriteGate.executable,
      identityNativeSupported: false,
      dualWriteGate,
      identityNativeGate,
      nextRequiredSpec: "identity-plugin-user-native-write",
      sourceOfTruth: sourceOfTruthForMode(iam.pluginUserWriteMode, dualWriteGate.executable),
      routes: [...PLUGIN_USER_WRITE_ROUTES],
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

  async proxy(request: PluginUserWriteRequest, path: string): Promise<PluginUserWriteProxyResponse> {
    const { iam } = this.config;

    if (iam.pluginUserWriteMode === "disabled") {
      throw new NotFoundException({
        code: "PLUGIN_USER_WRITE_DISABLED",
        message: "Plugin user write migration is disabled."
      });
    }

    if (iam.pluginUserWriteMode === "legacy-proxy") {
      return this.legacyProxy(request, path, true);
    }

    if (iam.pluginUserWriteMode === "dual-write") {
      const dualWriteGate = dualWriteGateForReadiness({
        legacyProxyConfigured: Boolean(iam.pluginUserWriteLegacyApiBaseUrl),
        operationLedgerConfigured: this.operations.isConfigured(),
        identityRepositoryConfigured: this.iamRepository.isConfigured(),
        executionFlagEnabled: iam.pluginUserWriteDualWriteExecutionEnabled,
        rollout: pluginUserWriteRolloutReadiness(iam)
      });
      if (!dualWriteGate.executable) {
        throw new NotFoundException({
          code: "PLUGIN_USER_WRITE_UNSUPPORTED_MODE",
          message: "Plugin user write dual-write mode is not executable yet.",
          missingCapabilities: dualWriteGate.missingCapabilities
        });
      }

      const rolloutDecision = this.dualWriteRolloutDecision(request, path);
      if (!rolloutDecision.selected) {
        this.logRolloutDecision(rolloutDecision);
        return this.legacyProxy(request, path, true);
      }

      this.logRolloutDecision(rolloutDecision);
      return this.dualWrite(request, path);
    }

    throw new NotFoundException({
      code: "PLUGIN_USER_WRITE_UNSUPPORTED_MODE",
      message: `Plugin user write mode ${iam.pluginUserWriteMode} is not executable yet.`
    });
  }

  private dualWriteRolloutDecision(request: PluginUserWriteRequest, path: string): PluginUserWriteRolloutDecision {
    const { iam } = this.config;
    const plan = planShadowOperation({
      method: request.method,
      path,
      headers: request.headers,
      body: request.body,
      legacyStatus: 0
    });
    const claims = this.claimsFromAuthorization(request.headers.authorization);
    const actorTokens = pluginUserWriteActorTokens(plan.actorSubject, claims);
    const targetTokens = pluginUserWriteTargetTokens(plan.targetSubject);
    const tokens = new Set([...actorTokens, ...targetTokens].map(normalizeRolloutToken).filter(Boolean));
    const allowlist = splitCsv(iam.pluginUserWriteRolloutAllowlist).map(normalizeRolloutToken).filter(Boolean);

    if (iam.pluginUserWriteRolloutMode === "full") {
      return {
        selected: true,
        mode: "full",
        route: plan.route,
        actorSubject: plan.actorSubject,
        targetSubject: plan.targetSubject,
        reason: "full_rollout"
      };
    }

    if (iam.pluginUserWriteRolloutMode === "canary") {
      const matchedToken = allowlist.find((item) => tokens.has(item));
      return {
        selected: Boolean(matchedToken),
        mode: "canary",
        route: plan.route,
        actorSubject: plan.actorSubject,
        targetSubject: plan.targetSubject,
        reason: matchedToken ? "canary_subject_selected" : "canary_subject_not_selected",
        matchedToken: matchedToken ?? null
      };
    }

    const percentage = safeRolloutPercentage(iam.pluginUserWriteRolloutPercentage);
    const bucketSubject = rolloutBucketSubject(claims, plan.actorSubject, plan.targetSubject);
    const bucket = bucketSubject ? rolloutBucket(bucketSubject) : null;
    const selected = percentage >= 100 || (percentage > 0 && bucket !== null && bucket < percentage);
    return {
      selected,
      mode: "percentage",
      route: plan.route,
      actorSubject: plan.actorSubject,
      targetSubject: plan.targetSubject,
      reason: selected ? "percentage_bucket_selected" : "percentage_bucket_not_selected",
      bucket,
      percentage
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

  private logRolloutDecision(decision: PluginUserWriteRolloutDecision): void {
    this.logger.log(
      JSON.stringify({
        event: "identity.plugin_user.write.rollout",
        mode: decision.mode,
        selected: decision.selected,
        reason: decision.reason,
        route: decision.route,
        actorSubject: decision.actorSubject,
        targetSubject: decision.targetSubject,
        matchedToken: decision.matchedToken ?? null,
        bucket: decision.bucket ?? null,
        percentage: decision.percentage ?? null,
        unselectedBehavior: decision.selected ? "dual-write" : "legacy-proxy"
      })
    );
  }

  private async legacyProxy(request: PluginUserWriteRequest, path: string, observeShadow: boolean): Promise<PluginUserWriteProxyResponse> {
    const upstream = await this.callLegacy(request, path);
    const body = await parseUpstreamBody(upstream);

    if (observeShadow) {
      await this.shadow.observe({
        method: request.method,
        path,
        headers: request.headers,
        body: request.body,
        legacyStatus: upstream.status
      });
    }

    return {
      status: upstream.status,
      body,
      mode: "legacy-proxy"
    };
  }

  private async dualWrite(request: PluginUserWriteRequest, path: string): Promise<PluginUserWriteProxyResponse> {
    const plan = planShadowOperation({
      method: request.method,
      path,
      headers: request.headers,
      body: request.body,
      legacyStatus: 0
    });
    const begin = await this.operations.begin({
      operationKey: plan.operationKey,
      idempotencyKey: plan.operationKey,
      route: plan.route,
      mode: "dual-write",
      actorSubject: plan.actorSubject,
      targetSubject: plan.targetSubject,
      legacyUserId: plan.legacyUserId,
      metadata: {
        route: plan.route,
        method: request.method.toUpperCase(),
        targetSubject: plan.targetSubject,
        redactedBody: plan.metadata.redactedBody
      }
    });

    let legacyResponse: PluginUserWriteProxyResponse | null = null;
    if (begin.duplicate) {
      const existing = await this.operations.findByOperationKey(plan.operationKey);
      const replay = existing ? pluginUserWriteReplayResponseFromOperation(existing) : null;
      if (replay) {
        return {
          ...replay,
          mode: "dual-write"
        };
      }

      legacyResponse = deleteReplayFromIncompleteOperation(existing, plan);
      if (!legacyResponse) {
        throw new ServiceUnavailableException({
          code: "PLUGIN_USER_WRITE_REPLAY_UNAVAILABLE",
          message: "Plugin user write operation is already recorded but has no completed replay response."
        });
      }
    }

    if (!legacyResponse) {
      try {
        legacyResponse = await this.legacyProxy(request, path, false);
      } catch (error) {
        await this.operations.update({
          operationKey: plan.operationKey,
          status: "failed",
          legacyStatus: "unavailable",
          identityStatus: "skipped",
          compensationStatus: "none",
          errorCode: error instanceof Error ? error.name : "PluginUserWriteLegacyError",
          metadata: {
            phase: "legacy",
            route: plan.route
          }
        });
        throw error;
      }
    }

    const responseReplay = pluginUserWriteResponseReplayMetadata({
      status: legacyResponse.status,
      body: legacyResponse.body
    });
    if (legacyResponse.status < 200 || legacyResponse.status >= 300) {
      await this.operations.update({
        operationKey: plan.operationKey,
        status: "failed",
        legacyStatus: String(legacyResponse.status),
        identityStatus: "skipped",
        compensationStatus: "none",
        errorCode: "LegacyRejected",
        metadata: responseReplay
      });
      return {
        ...legacyResponse,
        mode: "dual-write"
      };
    }

    try {
      const identityPlan = planPluginUserIdentityShadow({
        route: plan.route,
        requestBody: request.body,
        legacyStatus: legacyResponse.status,
        legacyBody: legacyResponse.body
      });
      if (identityPlan.writes.length === 0 && identityPlan.skippedReason !== "role-permission-owner-retained") {
        await this.operations.update({
          operationKey: plan.operationKey,
          status: "legacy_completed",
          legacyStatus: String(legacyResponse.status),
          identityStatus: `skipped:${identityPlan.skippedReason ?? "identity-shadow-plan-empty"}`,
          compensationStatus: "required",
          errorCode: "IdentityShadowPlanSkipped",
          metadata: {
            ...responseReplay,
            ...pluginUserWriteCompensationMetadata({
              phase: "identity",
              reason: identityPlan.skippedReason ?? "identity-shadow-plan-empty",
              errorCode: "IdentityShadowPlanSkipped",
              legacyStatus: legacyResponse.status,
              identityStatus: "skipped",
              detail: {
                route: plan.route,
                targetSubject: plan.targetSubject,
                requestBody: request.body
              }
            })
          }
        });
        return {
          ...legacyResponse,
          mode: "dual-write"
        };
      }

      for (const write of identityPlan.writes) {
        await this.iamRepository.upsertIdentityUserShadow(write);
        await this.iamRepository.upsertPluginSubjectMap({
          identityUserId: write.identityUserId,
          legacyUserId: write.legacyUserId,
          status: write.status === "inactive" ? "inactive" : "active",
          metadata: {
            source: "plugin-user-dual-write",
            route: plan.route
          }
        });
      }

      await this.operations.update({
        operationKey: plan.operationKey,
        status: "completed",
        legacyStatus: String(legacyResponse.status),
        identityStatus: identityPlan.skippedReason ? `skipped:${identityPlan.skippedReason}` : "completed",
        compensationStatus: "none",
        metadata: {
          ...responseReplay,
          identityShadow: {
            writeCount: identityPlan.writes.length,
            skippedReason: identityPlan.skippedReason ?? null
          }
        }
      });
      return {
        ...legacyResponse,
        mode: "dual-write"
      };
    } catch (error) {
      await this.operations.update({
        operationKey: plan.operationKey,
        status: "legacy_completed",
        legacyStatus: String(legacyResponse.status),
        identityStatus: "failed",
        compensationStatus: "required",
        errorCode: error instanceof Error ? error.name : "PluginUserWriteIdentityError",
        metadata: {
          ...responseReplay,
          ...pluginUserWriteCompensationMetadata({
            phase: "identity",
            reason: "identity-shadow-write-failed",
            errorCode: error instanceof Error ? error.name : "PluginUserWriteIdentityError",
            legacyStatus: legacyResponse.status,
            identityStatus: "failed",
            detail: {
              route: plan.route,
              targetSubject: plan.targetSubject,
              requestBody: request.body
            }
          })
        }
      });
      return {
        ...legacyResponse,
        mode: "dual-write"
      };
    }
  }

  private async callLegacy(request: PluginUserWriteRequest, path: string): Promise<Response> {
    const { iam } = this.config;
    if (!iam.pluginUserWriteLegacyApiBaseUrl) {
      throw new ServiceUnavailableException({
        code: "PLUGIN_USER_WRITE_LEGACY_API_NOT_CONFIGURED",
        message: "Legacy plugin-user API base URL is not configured."
      });
    }

    const url = new URL(path, `${iam.pluginUserWriteLegacyApiBaseUrl.replace(/\/+$/, "")}/`);
    const query = queryStringFromOriginalUrl(request.originalUrl);
    if (query) {
      url.search = query;
    }

    const headers = new Headers({
      Accept: "application/json",
      "X-Identity-Plugin-User-Write-Proxy": "1"
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

    const init: RequestInit = {
      method: request.method.toUpperCase(),
      headers,
      signal: AbortSignal.timeout(iam.pluginUserWriteTimeoutMs)
    };
    headers.set("Content-Type", "application/json");
    init.body = JSON.stringify(request.body ?? {});

    let upstream: Response;
    try {
      return await fetch(url, init);
    } catch (error) {
      throw new ServiceUnavailableException({
        code: "PLUGIN_USER_WRITE_LEGACY_API_UNAVAILABLE",
        message: "Legacy plugin-user API is unavailable.",
        detail: error instanceof Error ? error.message : String(error)
      });
    }
  }
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
  rollout: PluginUserWriteRolloutReadiness;
}) {
  const missingCapabilities: string[] = [...DUAL_WRITE_EXECUTION_BLOCKERS];
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
    supportedRoutes: executable ? [...PLUGIN_USER_WRITE_ROUTES] : [],
    blockedRoutes: executable ? [] : [...PLUGIN_USER_WRITE_ROUTES],
    routeOwners: {
      "create-user": "dual-write-candidate",
      "update-user": "dual-write-candidate",
      "delete-user": "dual-write-candidate",
      "batch-create-users": "dual-write-candidate",
      "change-role": "legacy-proxy-until-role-permission-closeout"
    },
    configured: {
      legacyProxy: input.legacyProxyConfigured,
      operationLedger: input.operationLedgerConfigured,
      identityRepository: input.identityRepositoryConfigured,
      executionFlag: input.executionFlagEnabled,
      rollout: input.rollout.selectionConfigured
    },
    runtimeCapabilities: [...DUAL_WRITE_RUNTIME_CAPABILITIES],
    productionCanaryBlockers: input.rollout.selectionConfigured ? [] : ["single-target-rollout-selector"],
    missingCapabilities
  };
}

interface PluginUserWriteRolloutReadiness {
  mode: "canary" | "percentage" | "full";
  allowlistConfigured: boolean;
  allowlistCount: number;
  percentage: number;
  selectionConfigured: boolean;
  unselectedBehavior: "legacy-proxy";
}

interface PluginUserWriteRolloutDecision {
  selected: boolean;
  mode: "canary" | "percentage" | "full";
  route: string;
  actorSubject: string | null;
  targetSubject: string | null;
  reason: string;
  matchedToken?: string | null;
  bucket?: number | null;
  percentage?: number;
}

function pluginUserWriteRolloutReadiness(iam: ReturnType<typeof loadConfig>["iam"]): PluginUserWriteRolloutReadiness {
  const allowlistCount = splitCsv(iam.pluginUserWriteRolloutAllowlist).length;
  const percentage = safeRolloutPercentage(iam.pluginUserWriteRolloutPercentage);
  const selectionConfigured =
    iam.pluginUserWriteRolloutMode === "full" ||
    (iam.pluginUserWriteRolloutMode === "canary" && allowlistCount > 0) ||
    (iam.pluginUserWriteRolloutMode === "percentage" && percentage > 0);

  return {
    mode: iam.pluginUserWriteRolloutMode,
    allowlistConfigured: allowlistCount > 0,
    allowlistCount,
    percentage,
    selectionConfigured,
    unselectedBehavior: "legacy-proxy"
  };
}

function identityNativeGateForReadiness(input: { dualWriteSupported: boolean; identityRepositoryConfigured: boolean }) {
  const missingCapabilities: string[] = [...IDENTITY_NATIVE_EXECUTION_BLOCKERS];
  if (!input.dualWriteSupported) {
    missingCapabilities.unshift("dual-write-execution");
  }
  if (!input.identityRepositoryConfigured) {
    missingCapabilities.unshift("identity-repository");
  }

  return {
    executable: false,
    supportedRoutes: [],
    blockedRoutes: [...PLUGIN_USER_WRITE_ROUTES],
    retainedLegacyRoutes: ["change-role"],
    configured: {
      dualWriteSupported: input.dualWriteSupported,
      identityRepository: input.identityRepositoryConfigured
    },
    missingCapabilities
  };
}

function blockedReasonsForMode(mode: string): string[] {
  if (mode === "dual-write") {
    return [
      "identity-plugin-user-native-write closeout is required before dual-write execution.",
      "Operation ledger, idempotency keys, compensation records, redaction gates, and rollback drills are not configured."
    ];
  }

  if (mode === "identity-native") {
    return [
      "identity-native plugin-user writes require clean dual-write evidence first.",
      "Profile, role, permission, organization, and rollback ownership gates must be closed or explicitly retained."
    ];
  }

  return [];
}

function sourceOfTruthForMode(mode: string, dualWriteExecutable = false): string {
  if (mode === "legacy-proxy") {
    return "legacy";
  }

  if (mode === "dual-write") {
    return dualWriteExecutable ? "legacy-during-dual-write" : "unsupported";
  }

  if (mode === "disabled") {
    return "legacy-unproxied";
  }

  return "unsupported";
}

function pluginUserWriteActorTokens(actorSubject: string | null, claims: VerifiedAccessToken | null): string[] {
  const tokens = new Set<string>();
  if (actorSubject) {
    tokens.add(actorSubject);
  }
  if (claims) {
    tokens.add(String(claims.uid));
    tokens.add(`uid:${claims.uid}`);
    tokens.add(`subject:${claims.uid}`);
    tokens.add(`legacy-user:${claims.uid}`);
    if (claims.username) {
      tokens.add(claims.username);
      tokens.add(`username:${claims.username}`);
    }
  }

  return [...tokens];
}

function pluginUserWriteTargetTokens(targetSubject: string | null): string[] {
  if (!targetSubject) {
    return [];
  }

  return [targetSubject, `target:${targetSubject}`];
}

function normalizeRolloutToken(value: string | null | undefined): string {
  return value?.trim().toLowerCase() ?? "";
}

function splitCsv(value: string | undefined): string[] {
  return (value ?? "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function safeRolloutPercentage(value: number | undefined): number {
  const numeric = Number(value ?? 0);
  if (!Number.isFinite(numeric)) {
    return 0;
  }

  return Math.max(0, Math.min(100, numeric));
}

function rolloutBucketSubject(
  claims: VerifiedAccessToken | null,
  actorSubject: string | null,
  targetSubject: string | null
): string | null {
  if (claims) {
    return `uid:${claims.uid}`;
  }

  return actorSubject ?? targetSubject;
}

function rolloutBucket(subject: string): number {
  const hash = createHash("sha256").update(subject).digest("hex").slice(0, 8);
  return Number.parseInt(hash, 16) % 100;
}

function bearerToken(authorization: string | null): string | null {
  const [scheme, token] = authorization?.split(/\s+/, 2) ?? [];
  return scheme?.toLowerCase() === "bearer" && token ? token : null;
}

export interface PluginUserWriteRequest {
  method: string;
  originalUrl?: string;
  headers: Record<string, string | string[] | undefined>;
  body?: unknown;
}

function firstHeader(value: string | string[] | undefined): string | null {
  if (Array.isArray(value)) {
    return value[0] ?? null;
  }

  return value ?? null;
}

function deleteReplayFromIncompleteOperation(
  operation: PluginUserWriteOperationRecord | null,
  plan: ReturnType<typeof planShadowOperation>
): PluginUserWriteProxyResponse | null {
  if (
    !operation ||
    !["pending", "legacy_completed", "identity_completed"].includes(operation.status) ||
    operation.mode !== "dual-write" ||
    operation.route !== "delete-user" ||
    plan.route !== "delete-user" ||
    operation.actorSubject !== plan.actorSubject ||
    operation.targetSubject !== plan.targetSubject ||
    operation.legacyUserId !== plan.legacyUserId ||
    plan.legacyUserId === null
  ) {
    return null;
  }

  const metadata = recordValue(operation.metadata);
  const responseReplay = recordValue(metadata.responseReplay);
  const responseReplayStatus = Number(responseReplay.httpStatus);
  if (
    Number.isInteger(responseReplayStatus) &&
    responseReplayStatus >= 200 &&
    responseReplayStatus < 300 &&
    "body" in responseReplay
  ) {
    return {
      status: responseReplayStatus,
      body: responseReplay.body,
      mode: "dual-write"
    };
  }

  const method = typeof metadata.method === "string" ? metadata.method.toUpperCase() : null;
  const legacyStatus = Number(metadata.legacyStatus);
  if (
    metadata.route !== plan.route ||
    method !== plan.metadata.method ||
    !Number.isInteger(legacyStatus) ||
    legacyStatus < 200 ||
    legacyStatus >= 300
  ) {
    return null;
  }

  return {
    status: legacyStatus,
    body: {
      code: 0,
      data: {
        id: plan.legacyUserId
      },
      message: "ok"
    },
    mode: "dual-write"
  };
}

function recordValue(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

function queryStringFromOriginalUrl(originalUrl: string | undefined): string {
  const index = originalUrl?.indexOf("?") ?? -1;
  return index >= 0 && originalUrl ? originalUrl.slice(index + 1) : "";
}

async function parseUpstreamBody(response: Response): Promise<unknown> {
  const text = await response.text();
  if (text.trim() === "") {
    return {};
  }

  try {
    return JSON.parse(text);
  } catch {
    return {
      message: text
    };
  }
}
