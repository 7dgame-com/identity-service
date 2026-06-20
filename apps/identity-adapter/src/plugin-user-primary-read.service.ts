import { createHash } from "node:crypto";
import { Injectable, Logger, ServiceUnavailableException } from "@nestjs/common";
import { loadConfig } from "./config.js";
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
      return { data: await this.legacyReader.getUserById(id), source: "legacy" };
    }

    if (decision === "shadow-compare") {
      const legacy = await this.legacyReader.getUserById(id);
      const identity = await this.safeIdentityUserById(id);
      this.logComparison("detail", claims, compareUsers(legacy, identity.data), identity.fallbackReason);
      return { data: legacy, source: "legacy" };
    }

    const identity = await this.safeIdentityUserById(id);
    if (!identity.fallbackReason) {
      return { data: identity.data, source: "identity-db" };
    }

    return this.fallback("detail", claims, identity.fallbackReason, () => this.legacyReader.getUserById(id));
  }

  async listUsers(
    input: LegacyManagedUserListInput,
    claims: VerifiedAccessToken
  ): Promise<PluginUserReadResult<LegacyManagedUserListResult>> {
    const decision = this.readDecision(claims);

    if (decision === "legacy") {
      return { data: await this.legacyReader.listManagedUsers(input), source: "legacy" };
    }

    if (decision === "shadow-compare") {
      const [legacy, identity] = await Promise.all([
        this.legacyReader.listManagedUsers(input),
        this.safeIdentityUserList(input)
      ]);
      this.logComparison("list", claims, compareLists(legacy, identity.data), identity.fallbackReason);
      return { data: legacy, source: "legacy" };
    }

    const identity = await this.safeIdentityUserList(input);
    if (!identity.fallbackReason) {
      return { data: identity.data, source: "identity-db" };
    }

    return this.fallback("list", claims, identity.fallbackReason, () => this.legacyReader.listManagedUsers(input));
  }

  private readDecision(claims: VerifiedAccessToken): "legacy" | "shadow-compare" | "primary" {
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
    const [roles, organizations] = await Promise.all([
      this.repository.listRoleAssignmentsShadow(legacyUserId),
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
      roles: roles.map((role) => role.roleName),
      organizations: organizations.map(toLegacyOrganization),
      source: "legacy"
    };
  }

  private async fallback<T>(
    scope: "detail" | "list",
    claims: VerifiedAccessToken,
    reason: string,
    loadLegacy: () => Promise<T>
  ): Promise<PluginUserReadResult<T>> {
    if (!this.config.pluginUserPrimaryRead.fallbackEnabled) {
      throw new ServiceUnavailableException({
        code: "PLUGIN_USER_PRIMARY_READ_UNAVAILABLE",
        message: "Plugin user primary read failed and fallback is disabled.",
        reason
      });
    }

    this.logRead(scope, claims, "legacy-fallback", reason);
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

    const subjects = new Set([
      String(claims.uid),
      `uid:${claims.uid}`,
      claims.username ?? "",
      claims.username ? `username:${claims.username}` : ""
    ]);
    return allowlist.some((item) => subjects.has(item));
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

  private logRead(scope: "detail" | "list", claims: VerifiedAccessToken, source: PluginUserReadSource, fallbackReason?: string): void {
    this.logger.warn(
      JSON.stringify({
        event: "identity.plugin_user.primary_read.fallback",
        scope: `plugin-user.users.${scope}`,
        readMode: this.config.pluginUserPrimaryRead.mode,
        source,
        fallbackReason: fallbackReason ?? null,
        subjectId: `uid:${claims.uid}`
      })
    );
  }
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
