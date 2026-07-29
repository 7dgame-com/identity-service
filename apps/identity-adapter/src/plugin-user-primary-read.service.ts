import { createHash } from "node:crypto";
import { Injectable, Logger, ServiceUnavailableException } from "@nestjs/common";
import { loadConfig } from "./config.js";
import { identityNativeRoleWriteTargetDecision } from "./iam-role-write-target-control.js";
import { IdentityOrganizationShadowRow, IdentityUserRow, IamRepository } from "./iam.repository.js";
import { VerifiedAccessToken } from "./jwt-issuer.service.js";
import {
  LegacyIdentityReader,
  LegacyManagedUserListInput,
  LegacyManagedUserListResult,
  LegacyOrganization,
  LegacyUserReadModel
} from "./legacy-identity.reader.js";

export type PluginUserReadSource = "legacy" | "identity-db" | "legacy-fallback";
type FallbackControlMode = "off" | "canary" | "percentage";

export interface PluginUserReadResult<T> {
  data: T;
  source: PluginUserReadSource;
  fallbackReason?: string;
}

@Injectable()
export class PluginUserPrimaryReadService {
  private readonly config = loadConfig();
  private readonly logger = new Logger(PluginUserPrimaryReadService.name);

  constructor(
    private readonly repository: IamRepository,
    private readonly legacyReader: LegacyIdentityReader
  ) {}

  async getUserById(id: number, claims: VerifiedAccessToken): Promise<PluginUserReadResult<LegacyUserReadModel | null>> {
    const decision = this.readDecision(claims);

    if (decision === "legacy") {
      this.logDecision("detail", claims, "legacy", false, false, false);
      return { data: await this.withAuthoritativeRoles(await this.legacyReader.getUserById(id)), source: "legacy" };
    }

    if (decision === "shadow-compare") {
      const legacy = await this.legacyReader.getUserById(id);
      const identity = await this.safeIdentityUserById(id);
      this.logComparison("detail", claims, compareUsers(legacy, identity.data), identity.fallbackReason);
      return { data: await this.withAuthoritativeRoles(legacy), source: "legacy" };
    }

    const identity = await this.safeIdentityUserById(id);
    if (!identity.fallbackReason) {
      this.logDecision("detail", claims, "identity-db", false, false, false);
      return { data: identity.data, source: "identity-db" };
    }

    return this.fallback("detail", claims, identity.fallbackReason, async () =>
      this.withAuthoritativeRoles(await this.legacyReader.getUserById(id))
    );
  }

  async listUsers(
    input: LegacyManagedUserListInput,
    claims: VerifiedAccessToken
  ): Promise<PluginUserReadResult<LegacyManagedUserListResult>> {
    const decision = this.readDecision(claims);

    if (decision === "legacy") {
      this.logDecision("list", claims, "legacy", false, false, false);
      return { data: await this.withAuthoritativeListRoles(await this.legacyReader.listManagedUsers(input)), source: "legacy" };
    }

    if (decision === "shadow-compare") {
      const [legacy, identity] = await Promise.all([
        this.legacyReader.listManagedUsers(input),
        this.safeIdentityUserList(input)
      ]);
      this.logComparison("list", claims, compareLists(legacy, identity.data), identity.fallbackReason);
      return { data: await this.withAuthoritativeListRoles(legacy), source: "legacy" };
    }

    const identity = await this.safeIdentityUserList(input);
    if (!identity.fallbackReason) {
      this.logDecision("list", claims, "identity-db", false, false, false);
      return { data: identity.data, source: "identity-db" };
    }

    return this.fallback("list", claims, identity.fallbackReason, async () =>
      this.withAuthoritativeListRoles(await this.legacyReader.listManagedUsers(input))
    );
  }

  private readDecision(claims: VerifiedAccessToken): "legacy" | "shadow-compare" | "primary" {
    if (
      this.config.iam.pluginUserWriteMode === "legacy-proxy"
      && this.config.iam.roleWriteMode !== "identity-native"
    ) {
      return "legacy";
    }

    const primary = this.config.pluginUserPrimaryRead;
    if (!primary.enabled || primary.mode === "disabled") {
      return "legacy";
    }
    if (primary.mode === "shadow-compare") {
      return "shadow-compare";
    }
    if (primary.mode === "allowlist") {
      return this.isAllowlisted(claims) ? "primary" : "legacy";
    }
    if (primary.mode === "percentage") {
      return this.isInPercentageWindow(claims, primary.percentage) ? "primary" : "legacy";
    }

    return "primary";
  }

  private async safeIdentityUserById(id: number): Promise<{ data: LegacyUserReadModel | null; fallbackReason?: string }> {
    try {
      if (!this.repository.isConfigured()) {
        return { data: null, fallbackReason: "identity_repository_not_configured" };
      }
      const user = await this.identityUserById(id);
      return user ? { data: user } : { data: null, fallbackReason: "identity_user_missing" };
    } catch (error) {
      return { data: null, fallbackReason: error instanceof Error ? error.message : "identity_read_failed" };
    }
  }

  private async safeIdentityUserList(
    input: LegacyManagedUserListInput
  ): Promise<{ data: LegacyManagedUserListResult; fallbackReason?: string }> {
    try {
      if (!this.repository.isConfigured()) {
        return { data: emptyList(input), fallbackReason: "identity_repository_not_configured" };
      }
      const result = await this.identityUserList(input);
      if (!input.search && input.status === undefined && result.total === 0) {
        return { data: result, fallbackReason: "identity_user_read_model_empty" };
      }
      return { data: result };
    } catch (error) {
      return { data: emptyList(input), fallbackReason: error instanceof Error ? error.message : "identity_read_failed" };
    }
  }

  private async identityUserById(id: number): Promise<LegacyUserReadModel | null> {
    const identity = await this.repository.getIdentityUserByLegacyId(id);
    if (!identity || identity.legacyUserId === null) {
      return null;
    }

    return this.toManagedUser(identity);
  }

  private async identityUserList(input: LegacyManagedUserListInput): Promise<LegacyManagedUserListResult> {
    const result = await this.repository.listManagedUsers(input);
    const users = await Promise.all(result.users.map((user) => this.toManagedUser(user)));

    return {
      users,
      page: result.page,
      pageSize: result.pageSize,
      total: result.total,
      totalPages: result.totalPages
    };
  }

  private async toManagedUser(identity: IdentityUserRow): Promise<LegacyUserReadModel> {
    const legacyUserId = identity.legacyUserId;
    if (legacyUserId === null) {
      throw new Error("identity_user_missing_legacy_user_id");
    }

    const metadata = recordMetadata(identity.metadata);
    const [roleNames, organizations] = await Promise.all([
      this.managedRoleNames(legacyUserId),
      this.repository.listOrganizationMembershipsShadow(legacyUserId)
    ]);

    return {
      id: legacyUserId,
      username: identity.username,
      email: identity.email,
      status: legacyStatus(identity.status),
      nickname: stringOrNull(metadata.legacyNickname),
      emailVerifiedAt: numberOrNull(metadata.legacyEmailVerifiedAt),
      createdAt: numberOrNull(metadata.legacyCreatedAt) ?? secondsFromIso(identity.createdAt),
      updatedAt: numberOrNull(metadata.legacyUpdatedAt) ?? secondsFromIso(identity.updatedAt),
      userInfo: metadata.legacyUserInfo ?? null,
      roles: roleNames,
      organizations: organizations.map(toLegacyOrganization),
      source: "legacy"
    };
  }

  private async withAuthoritativeRoles(user: LegacyUserReadModel | null): Promise<LegacyUserReadModel | null> {
    if (!user) return null;
    return {
      ...user,
      roles: await this.managedRoleNames(user.id, user.roles)
    };
  }

  private async withAuthoritativeListRoles(result: LegacyManagedUserListResult): Promise<LegacyManagedUserListResult> {
    return {
      ...result,
      users: await Promise.all(result.users.map(async (user) => (await this.withAuthoritativeRoles(user))!))
    };
  }

  private async managedRoleNames(legacyUserId: number, observedRoleNames?: string[]): Promise<string[]> {
    const roleWrite = this.config.iam;
    const currentRoleNames = observedRoleNames ?? (await this.repository.listRoleAssignmentsShadow(legacyUserId)).map((role) => role.roleName);
    if (currentRoleNames.includes("root")) {
      return currentRoleNames;
    }
    const ownsTarget = roleWrite.roleWriteMode === "identity-native"
      && roleWrite.roleWriteIdentityNativeExecutionEnabled
      && identityNativeRoleWriteTargetDecision(roleWrite, legacyUserId).owned;

    if (!ownsTarget) {
      return currentRoleNames;
    }

    const policyChecksum = (roleWrite.roleWritePolicyChecksum ?? "").trim().toLowerCase();
    if (!/^[a-f0-9]{64}$/.test(policyChecksum)) {
      throw new Error("identity_native_role_read_policy_checksum_missing");
    }

    const assignments = await this.repository.listSubjectAssignments(
      `legacy:${legacyUserId}`,
      policyChecksum
    );
    const roles = assignments
      .filter((assignment) => assignment.itemType === "role")
      .map((assignment) => assignment.itemName);
    if (roles.length === 0) {
      throw new Error("identity_native_role_read_assignment_missing");
    }
    return roles;
  }

  private async fallback<T>(
    scope: "detail" | "list",
    claims: VerifiedAccessToken,
    reason: string,
    loadLegacy: () => Promise<T>
  ): Promise<PluginUserReadResult<T>> {
    if (!this.config.pluginUserPrimaryRead.fallbackEnabled) {
      this.logFallbackBlocked(scope, claims, reason, "global-disabled", "fallback_master_disabled");
      throw new ServiceUnavailableException({
        code: "PLUGIN_USER_PRIMARY_READ_UNAVAILABLE",
        message: "Plugin user primary read failed and fallback is disabled.",
        reason
      });
    }

    const fallbackDecision = this.fallbackControlDecision(claims);
    if (fallbackDecision.disableFallback) {
      this.logFallbackBlocked(scope, claims, reason, fallbackDecision.mode, fallbackDecision.reason);
      throw new ServiceUnavailableException({
        code: "PLUGIN_USER_PRIMARY_READ_UNAVAILABLE",
        message: "Plugin user primary read failed and fallback is disabled for this rollout subject.",
        reason,
        fallbackControlMode: fallbackDecision.mode,
        fallbackControlReason: fallbackDecision.reason
      });
    }

    this.logRead(scope, claims, "legacy-fallback", reason, fallbackDecision.mode, fallbackDecision.reason);
    return {
      data: await loadLegacy(),
      source: "legacy-fallback",
      fallbackReason: reason
    };
  }

  private isAllowlisted(claims: VerifiedAccessToken): boolean {
    const allowlist = splitCsv(this.config.pluginUserPrimaryRead.allowlist);
    if (allowlist.length === 0) {
      return false;
    }

    const subjects = subjectTokens(claims);
    return allowlist.some((item) => subjects.has(item));
  }

  private fallbackControlDecision(claims: VerifiedAccessToken): {
    disableFallback: boolean;
    mode: FallbackControlMode;
    reason: string;
  } {
    const control = this.config.pluginUserFallbackControl;
    if (!control.enabled || control.disableMode === "off") {
      return { disableFallback: false, mode: "off", reason: "control_off" };
    }

    if (control.disableMode === "canary") {
      const allowlist = splitCsv(control.disableAllowlist);
      const subjects = subjectTokens(claims);
      const matched = allowlist.some((item) => subjects.has(item));
      return {
        disableFallback: matched,
        mode: "canary",
        reason: matched ? "canary_subject_selected" : "canary_subject_not_selected"
      };
    }

    const selected = this.isInPercentageWindow(claims, control.disablePercentage);
    return {
      disableFallback: selected,
      mode: "percentage",
      reason: selected ? "percentage_bucket_selected" : "percentage_bucket_not_selected"
    };
  }

  private isInPercentageWindow(claims: VerifiedAccessToken, percentage: number | undefined): boolean {
    const safePercentage = Math.max(0, Math.min(100, Number(percentage ?? 0)));
    if (safePercentage <= 0) {
      return false;
    }
    if (safePercentage >= 100) {
      return true;
    }

    const hash = createHash("sha256").update(String(claims.uid)).digest("hex").slice(0, 8);
    const bucket = Number.parseInt(hash, 16) % 100;
    return bucket < safePercentage;
  }

  private logComparison(
    scope: "detail" | "list",
    claims: VerifiedAccessToken,
    comparison: { mismatchSeverity: "none" | "p1" | "p2"; mismatchCount: number },
    fallbackReason?: string
  ): void {
    this.logger.log(
      JSON.stringify({
        event: "identity.plugin_user.primary_read.shadow_compare",
        scope: `plugin-user.users.${scope}`,
        readMode: this.config.pluginUserPrimaryRead.mode,
        source: "legacy",
        fallbackReason: fallbackReason ?? null,
        mismatchSeverity: comparison.mismatchSeverity,
        mismatchCount: comparison.mismatchCount,
        subjectId: `uid:${claims.uid}`
      })
    );
  }

  private logRead(
    scope: "detail" | "list",
    claims: VerifiedAccessToken,
    source: PluginUserReadSource,
    fallbackReason?: string,
    fallbackControlMode: FallbackControlMode = "off",
    fallbackControlReason = "control_off"
  ): void {
    this.logger.warn(
      JSON.stringify({
        event: "identity.plugin_user.primary_read.fallback",
        scope: `plugin-user.users.${scope}`,
        readMode: this.config.pluginUserPrimaryRead.mode,
        source,
        fallbackAttempted: true,
        fallbackUsed: true,
        fallbackBlocked: false,
        fallbackControlMode,
        fallbackControlReason,
        fallbackReason: fallbackReason ?? null,
        subjectId: `uid:${claims.uid}`
      })
    );
  }

  private logDecision(
    scope: "detail" | "list",
    claims: VerifiedAccessToken,
    source: PluginUserReadSource,
    fallbackAttempted: boolean,
    fallbackUsed: boolean,
    fallbackBlocked: boolean,
    fallbackControlMode: FallbackControlMode = "off",
    fallbackControlReason = "control_off",
    fallbackReason?: string
  ): void {
    if (!this.config.pluginUserFallbackControl.observeMetricsEnabled) {
      return;
    }

    this.logger.log(
      JSON.stringify({
        event: "identity.plugin_user.primary_read.decision",
        scope: `plugin-user.users.${scope}`,
        readMode: this.config.pluginUserPrimaryRead.mode,
        source,
        fallbackAttempted,
        fallbackUsed,
        fallbackBlocked,
        fallbackControlMode,
        fallbackControlReason,
        fallbackReason: fallbackReason ?? null,
        subjectId: `uid:${claims.uid}`
      })
    );
  }

  private logFallbackBlocked(
    scope: "detail" | "list",
    claims: VerifiedAccessToken,
    fallbackReason: string,
    fallbackControlMode: FallbackControlMode | "global-disabled",
    fallbackControlReason: string
  ): void {
    if (!this.config.pluginUserFallbackControl.observeMetricsEnabled) {
      return;
    }

    this.logger.warn(
      JSON.stringify({
        event: "identity.plugin_user.primary_read.fallback_blocked",
        scope: `plugin-user.users.${scope}`,
        readMode: this.config.pluginUserPrimaryRead.mode,
        source: "identity-db",
        fallbackAttempted: true,
        fallbackUsed: false,
        fallbackBlocked: true,
        fallbackControlMode,
        fallbackControlReason,
        fallbackReason,
        subjectId: `uid:${claims.uid}`
      })
    );
  }
}

function subjectTokens(claims: VerifiedAccessToken): Set<string> {
  return new Set([
    String(claims.uid),
    `uid:${claims.uid}`,
    `subject:${claims.uid}`,
    claims.username ?? "",
    claims.username ? `username:${claims.username}` : ""
  ]);
}

function emptyList(input: LegacyManagedUserListInput): LegacyManagedUserListResult {
  return {
    users: [],
    page: input.page,
    pageSize: input.pageSize,
    total: 0,
    totalPages: 0
  };
}

function compareUsers(legacy: LegacyUserReadModel | null, identity: LegacyUserReadModel | null) {
  if (!legacy && !identity) {
    return { mismatchSeverity: "none" as const, mismatchCount: 0 };
  }
  if (!legacy || !identity) {
    return { mismatchSeverity: "p1" as const, mismatchCount: 1 };
  }
  if (legacy.id !== identity.id || legacy.status !== identity.status) {
    return { mismatchSeverity: "p1" as const, mismatchCount: 1 };
  }

  const mismatchCount = stableJson(serializeComparableUser(legacy)) === stableJson(serializeComparableUser(identity)) ? 0 : 1;
  return { mismatchSeverity: mismatchCount > 0 ? ("p2" as const) : ("none" as const), mismatchCount };
}

function compareLists(legacy: LegacyManagedUserListResult, identity: LegacyManagedUserListResult) {
  const legacyIds = legacy.users.map((user) => user.id);
  const identityIds = identity.users.map((user) => user.id);
  if (legacy.total !== identity.total || stableJson(legacyIds) !== stableJson(identityIds)) {
    return { mismatchSeverity: "p1" as const, mismatchCount: 1 };
  }

  const mismatchCount = legacy.users.filter((user, index) => {
    const identityUser = identity.users[index];
    return stableJson(serializeComparableUser(user)) !== stableJson(serializeComparableUser(identityUser));
  }).length;
  return { mismatchSeverity: mismatchCount > 0 ? ("p2" as const) : ("none" as const), mismatchCount };
}

function serializeComparableUser(user: LegacyUserReadModel | undefined) {
  if (!user) {
    return null;
  }

  return {
    id: user.id,
    username: user.username,
    email: user.email,
    status: user.status,
    nickname: user.nickname,
    roles: [...user.roles].sort((a, b) => a.localeCompare(b)),
    organizations: user.organizations.map((organization) => ({
      id: organization.id,
      name: organization.name,
      title: organization.title
    }))
  };
}

function toLegacyOrganization(organization: IdentityOrganizationShadowRow): LegacyOrganization {
  const metadata = recordMetadata(organization.metadata);
  return {
    id: organization.organizationId,
    name: stringOrNull(metadata.legacyName) ?? String(organization.organizationId),
    title: stringOrNull(metadata.legacyTitle) ?? String(organization.organizationId),
    createdAt: numberOrNull(metadata.legacyCreatedAt),
    updatedAt: numberOrNull(metadata.legacyUpdatedAt)
  };
}

function legacyStatus(status: string): number {
  return status === "active" ? 10 : 0;
}

function secondsFromIso(value: string | null): number | null {
  if (!value) {
    return null;
  }

  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) ? Math.floor(milliseconds / 1000) : null;
}

function numberOrNull(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }
  if (typeof value === "string" && value.trim() !== "") {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
  }

  return null;
}

function stringOrNull(value: unknown): string | null {
  return typeof value === "string" && value.trim() !== "" ? value : null;
}

function recordMetadata(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

function splitCsv(value: string): string[] {
  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map(stableJson).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, entry]) => `${JSON.stringify(key)}:${stableJson(entry)}`)
      .join(",")}}`;
  }

  return JSON.stringify(value);
}
