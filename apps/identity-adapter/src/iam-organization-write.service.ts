import { createHash } from "node:crypto";
import {
  BadRequestException,
  ConflictException,
  Injectable,
  Logger,
  NotFoundException,
  ServiceUnavailableException
} from "@nestjs/common";
import { loadConfig } from "./config.js";
import {
  IamOrganizationWriteEvidence,
  organizationWriteCorrelationId,
  organizationWriteFingerprint
} from "./iam-organization-write-evidence.js";
import {
  IamOrganizationWriteRepository,
  organizationWriteOperationKey,
  organizationWriteRequestFingerprint
} from "./iam-organization-write.repository.js";
import { JwtIssuerService, VerifiedAccessToken } from "./jwt-issuer.service.js";
import { LegacyIdentityReader, LegacyOrganization } from "./legacy-identity.reader.js";
import { PluginUserWriteRequest, PluginUserWriteService } from "./plugin-user-write.service.js";

export interface IamOrganizationWriteProxyResponse {
  status: number;
  body: unknown;
  mode: "legacy-proxy" | "dual-write";
  evidence: IamOrganizationWriteEvidence;
}

@Injectable()
export class IamOrganizationWriteService {
  private readonly config = loadConfig();
  private readonly logger = new Logger(IamOrganizationWriteService.name);

  constructor(
    private readonly pluginUserWrite: PluginUserWriteService,
    private readonly repository: IamOrganizationWriteRepository,
    private readonly legacy: LegacyIdentityReader,
    private readonly jwtIssuer: JwtIssuerService
  ) {}

  readiness() {
    const { iam } = this.config;
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
    return {
      enabled: iam.organizationWriteMode !== "disabled",
      mode: iam.organizationWriteMode,
      routeIntegrationEnabled: iam.organizationWriteRouteIntegrationEnabled,
      route: "/v1/plugin-user/update-user",
      scope: "membership-replace",
      sourceOfTruth: "legacy",
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
      identityNativeSupported: false,
      rollout,
      redactionPolicy: "metadata-only-no-request-or-token-payloads",
      blockedReasons:
        iam.organizationWriteMode === "identity-native"
          ? ["identity-native-not-authorized", "legacy-owner-retained"]
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
    const parsed = parseMembershipReplace(request.body);
    if (!parsed.selected) return null;

    const claims = this.claims(request.headers.authorization);
    const decision = organizationRolloutDecision(iam, parsed.legacyUserId, claims);
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
        missingCapabilities: this.readiness().dualWriteGate.missingCapabilities
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

  previewMembershipRollout(legacyUserId: number) {
    const { iam } = this.config;
    const readiness = this.readiness();
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
      sourceOfTruth: "legacy",
      identityNativeSupported: false,
      blockedReasons: decision.selected ? readiness.blockedReasons : ["target-not-selected"]
    };
  }

  async operationLedgerSummary(input: { sinceMinutes?: number }) {
    const sinceMinutes = normalizeNumber(input.sinceMinutes, 60, 1, 1440);
    return this.repository.isConfigured()
      ? { configured: true, sinceMinutes, operations: await this.repository.summarizeRecent(sinceMinutes) }
      : { configured: false, sinceMinutes, operations: [] };
  }

  async operationLedgerRecent(input: { sinceMinutes?: number; limit?: number }) {
    const sinceMinutes = normalizeNumber(input.sinceMinutes, 60, 1, 1440);
    const limit = normalizeNumber(input.limit, 50, 1, 200);
    return this.repository.isConfigured()
      ? { configured: true, sinceMinutes, limit, operations: await this.repository.listRecentSafe(sinceMinutes, limit) }
      : { configured: false, sinceMinutes, limit, operations: [] };
  }

  async subjectAlignment(legacyUserId: number) {
    this.requireRepository();
    const [legacyUser, candidate] = await Promise.all([
      this.legacy.getUserById(legacyUserId),
      this.repository.candidateForLegacyUser(legacyUserId)
    ]);
    if (!legacyUser) {
      return { legacyUserId, aligned: false, mismatch: 1, P0: 1, P1: 0, P2: 0, reason: "legacy-user-not-found" };
    }
    if (!candidate) {
      return {
        legacyUserId,
        aligned: false,
        mismatch: Math.max(1, legacyUser.organizations.length),
        P0: 0,
        P1: Math.max(1, legacyUser.organizations.length),
        P2: 0,
        reason: "identity-candidate-snapshot-missing",
        sourceOfTruth: "legacy"
      };
    }
    const comparison = compareOrganizations(legacyUser.organizations, candidate.organizations);
    return { legacyUserId, aligned: comparison.mismatch === 0, ...comparison, sourceOfTruth: "legacy" };
  }

  async retryIdentityCandidate(operationKey: string) {
    this.requireRepository();
    const operation = await this.repository.find(operationKey);
    if (!operation) throw new NotFoundException({ code: "IAM_ORGANIZATION_WRITE_OPERATION_NOT_FOUND" });
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
    if (before.username?.trim().toLowerCase() === "root" || before.roles.some((role) => role.trim().toLowerCase() === "root")) {
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

function parseMembershipReplace(body: unknown): SelectedMembershipReplace | { selected: false } {
  if (!body || typeof body !== "object" || Array.isArray(body)) return { selected: false };
  const record = body as Record<string, unknown>;
  if (!Object.prototype.hasOwnProperty.call(record, "organization_ids")) return { selected: false };
  const legacyUserId = Number(record.id);
  if (!Number.isSafeInteger(legacyUserId) || legacyUserId <= 0 || !Array.isArray(record.organization_ids)) return { selected: false };
  const ids = record.organization_ids.map(Number);
  if (ids.some((id) => !Number.isSafeInteger(id) || id <= 0)) return { selected: false };
  return { selected: true, legacyUserId, organizationIds: [...new Set(ids)].sort((a, b) => a - b) };
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
  return [...value].sort((a, b) => a.id - b.id).map((item) => ({ ...item, name: item.name.toLowerCase() }));
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
