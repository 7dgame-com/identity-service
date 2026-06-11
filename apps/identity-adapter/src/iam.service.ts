import { createHash, randomUUID } from "node:crypto";
import {
  BadRequestException,
  Injectable,
  NotFoundException,
  OnApplicationBootstrap,
  ServiceUnavailableException,
  UnauthorizedException
} from "@nestjs/common";
import { z } from "zod";
import { loadConfig } from "./config.js";
import { IamReconciliationItemInput, IamRepository } from "./iam.repository.js";
import { JwtIssuerService, VerifiedAccessToken } from "./jwt-issuer.service.js";
import { LegacyIdentityReader, LegacyUserReadModel } from "./legacy-identity.reader.js";
import { sanitizeMetadata } from "./login-audit.service.js";

type IamViewScope = "user" | "role" | "permission" | "organization" | "plugin";
type IamReconciliationScope = IamViewScope;

const reconciliationScopes = ["user", "role", "permission", "organization", "plugin"] as const;
const reconciliationSchema = z.object({
  dryRun: z.boolean().optional(),
  runKey: z.string().min(8).max(160).optional(),
  scopes: z.array(z.enum(reconciliationScopes)).min(1).optional(),
  legacyUserIds: z.array(z.number().int().positive()).min(1).max(100).optional(),
  afterLegacyUserId: z.number().int().min(0).optional(),
  limit: z.number().int().min(1).max(5000).optional(),
  applyShadow: z.boolean().optional()
});

type IamReconciliationInput = z.infer<typeof reconciliationSchema>;

@Injectable()
export class IamService implements OnApplicationBootstrap {
  private readonly config = loadConfig();

  constructor(
    private readonly repository: IamRepository,
    private readonly legacyReader: LegacyIdentityReader,
    private readonly jwtIssuer: JwtIssuerService
  ) {}

  async onApplicationBootstrap() {
    if (this.config.iam.schemaAutoEnsureEnabled) {
      await this.ensureSchema();
    }
  }

  async readiness() {
    const { iam } = this.config;

    return {
      enabled: iam.enabled,
      mode: iam.mode,
      fallbackEnabled: iam.fallbackEnabled,
      schemaAutoEnsureEnabled: iam.schemaAutoEnsureEnabled,
      reconciliationEnabled: iam.reconciliationEnabled,
      reconciliationBatchSize: iam.reconciliationBatchSize,
      identityRepositoryConfigured: this.repository.isConfigured(),
      legacyReaderConfigured: this.legacyReader.isConfigured(),
      identityDatabase: await this.repository.health(),
      diagnostics: await this.repository.diagnostics(),
      views: {
        user: iam.userViewEnabled,
        role: iam.roleViewEnabled,
        permission: iam.permissionViewEnabled,
        organization: iam.organizationViewEnabled,
        plugin: iam.pluginViewEnabled
      },
      writes: {
        profile: iam.profileWriteMode,
        role: iam.roleWriteMode,
        organization: iam.organizationWriteMode,
        pluginUser: iam.pluginUserWriteMode
      },
      reconciliationSafetyGate: {
        p0BlocksCutover: true,
        p1BlocksCutover: true,
        requiredBeforeIdentityPrimary: true,
        supportedScopes: reconciliationScopes
      }
    };
  }

  async ensureSchema() {
    if (!this.repository.isConfigured()) {
      throw new ServiceUnavailableException({
        code: "IDENTITY_DB_NOT_CONFIGURED",
        message: "Identity database is not configured for IAM schema bootstrap."
      });
    }

    await this.repository.ensureSchema();

    return {
      identityDatabase: await this.repository.health(),
      diagnostics: await this.repository.diagnostics(),
      nonUserFacing: true
    };
  }

  async userView(legacyUserId: number) {
    this.assertViewEnabled("user");
    const legacyUser = await this.requireLegacyUser(legacyUserId);
    const identity = await this.repository.getIdentityUserByLegacyId(legacyUserId);
    const identityUserId = identity?.id ?? `legacy:${legacyUserId}`;
    const subjects = identity ? await this.repository.listSubjectMaps(identity.id) : [];

    return {
      identityUserId,
      legacyUserId,
      keycloakSubject: identity?.keycloakSubject ?? null,
      username: legacyUser.username,
      email: legacyUser.email,
      status: normalizeLegacyStatus(legacyUser.status),
      profile: {
        nickname: legacyUser.nickname,
        emailVerifiedAt: legacyUser.emailVerifiedAt,
        createdAt: legacyUser.createdAt,
        updatedAt: legacyUser.updatedAt,
        userInfo: legacyUser.userInfo
      },
      subjects: subjects.length > 0 ? subjects : derivedLegacySubject(identityUserId, legacyUserId),
      source: {
        profile: "legacy",
        identityMap: identity ? "identity-db" : "derived"
      }
    };
  }

  async rolesView(legacyUserId: number) {
    this.assertViewEnabled("role");
    const legacyUser = await this.requireLegacyUser(legacyUserId);
    const shadow = await this.repository.listRoleAssignmentsShadow(legacyUserId);

    return {
      legacyUserId,
      identityUserId: shadow.find((row) => row.identityUserId)?.identityUserId ?? `legacy:${legacyUserId}`,
      roles: legacyUser.roles.map((name) => ({
        name,
        source: "legacy-yii-rbac"
      })),
      shadow,
      source: {
        roles: "legacy",
        shadow: this.repository.isConfigured() ? "identity-db" : "not_configured"
      }
    };
  }

  async permissionsView(legacyUserId: number) {
    this.assertViewEnabled("permission");
    await this.requireLegacyUser(legacyUserId);
    const permissions = await this.legacyReader.listUserPermissions(legacyUserId);

    return {
      legacyUserId,
      identityUserId: `legacy:${legacyUserId}`,
      permissions: permissions.map((permission) => ({
        name: permission.name,
        description: permission.description,
        source: permission.source === "direct" ? "legacy-yii-rbac-direct" : "legacy-yii-rbac-role-child"
      })),
      source: {
        permissions: "legacy"
      }
    };
  }

  async organizationsView(legacyUserId: number) {
    this.assertViewEnabled("organization");
    const legacyUser = await this.requireLegacyUser(legacyUserId);
    const shadow = await this.repository.listOrganizationMembershipsShadow(legacyUserId);

    return {
      legacyUserId,
      identityUserId: shadow.find((row) => row.identityUserId)?.identityUserId ?? `legacy:${legacyUserId}`,
      organizations: legacyUser.organizations.map((organization) => ({
        ...organization,
        source: "legacy"
      })),
      shadow,
      source: {
        organizations: "legacy",
        shadow: this.repository.isConfigured() ? "identity-db" : "not_configured"
      }
    };
  }

  async pluginVerifyToken(token: string | null | undefined) {
    this.assertViewEnabled("plugin");
    const claims = this.verifyToken(token);
    const user = await this.requireLegacyUser(claims.uid);

    return {
      valid: true,
      user: pluginUserShape(user, claims),
      source: {
        token: "identity-jwt",
        profile: "legacy"
      }
    };
  }

  async pluginMe(token: string | null | undefined) {
    const verified = await this.pluginVerifyToken(token);
    return verified.user;
  }

  async reconcile(rawInput: unknown) {
    const input = this.parseReconciliationInput(rawInput);
    const dryRun = input.dryRun ?? true;
    const applyShadow = input.applyShadow ?? !dryRun;
    if (!this.repository.isConfigured()) {
      throw new ServiceUnavailableException({
        code: "IDENTITY_DB_NOT_CONFIGURED",
        message: "Identity database is not configured for IAM reconciliation."
      });
    }
    if (!this.legacyReader.isConfigured()) {
      throw new ServiceUnavailableException({
        code: "LEGACY_IAM_SOURCE_NOT_CONFIGURED",
        message: "Legacy IAM source is not configured for IAM reconciliation."
      });
    }
    if (!dryRun && !this.config.iam.reconciliationEnabled) {
      throw new NotFoundException({
        code: "IDENTITY_IAM_RECONCILIATION_DISABLED",
        message: "Identity IAM shadow reconciliation is disabled."
      });
    }

    const scopes = input.scopes ?? [...reconciliationScopes];
    const limit = input.limit ?? this.config.iam.reconciliationBatchSize;
    const runKey = input.runKey ?? `iam-reconciliation:${randomUUID()}`;
    const users = await this.loadReconciliationUsers(input, limit);
    const mode = dryRun ? "dry-run" : "shadow";
    const runScope = scopes.join(",");

    if (!dryRun) {
      await this.repository.createReconciliationRun({
        runKey,
        scope: runScope,
        mode,
        metadata: this.runMetadata({ dryRun, applyShadow, scopes, limit, userCount: users.length })
      });
    }

    let shadowWriteCount = 0;
    if (!dryRun && applyShadow) {
      shadowWriteCount = await this.applyShadow(users, scopes);
    }

    const items = await this.collectReconciliationItems(runKey, users, scopes);
    const summary = summarizeItems(items);
    const mismatchCount = items.filter((item) => item.severity !== "info").length;

    if (!dryRun) {
      try {
        await this.repository.insertReconciliationItems(items);
        await this.repository.finishReconciliationRun({
          runKey,
          status: "succeeded",
          sampleCount: users.length,
          mismatchCount,
          p0Count: summary.p0,
          p1Count: summary.p1,
          metadata: this.runMetadata({
            dryRun,
            applyShadow,
            scopes,
            limit,
            shadowWriteCount,
            safetyGatePassed: summary.p0 === 0 && summary.p1 === 0
          })
        });
      } catch (error) {
        await this.repository.finishReconciliationRun({
          runKey,
          status: "failed",
          sampleCount: users.length,
          mismatchCount,
          p0Count: summary.p0,
          p1Count: summary.p1,
          metadata: this.runMetadata({
            dryRun,
            applyShadow,
            scopes,
            limit,
            shadowWriteCount,
            error: error instanceof Error ? error.message : "unknown error"
          })
        });
        throw error;
      }
    }

    return {
      runKey,
      mode,
      dryRun,
      applyShadow: !dryRun && applyShadow,
      reconciliationEnabled: this.config.iam.reconciliationEnabled,
      scopes,
      summary: {
        sampledUsers: users.length,
        mismatchCount,
        p0Count: summary.p0,
        p1Count: summary.p1,
        p2Count: summary.p2,
        infoCount: summary.info,
        shadowWriteCount
      },
      safetyGate: {
        passed: summary.p0 === 0 && summary.p1 === 0,
        p0BlocksCutover: true,
        p1BlocksCutover: true
      },
      items: dryRun ? redactItemsForResponse(items) : undefined,
      nonUserFacing: true
    };
  }

  async reconciliationReport(runKey: string) {
    this.assertConfiguredForReport();
    const run = await this.repository.getReconciliationRun(runKey);
    if (!run) {
      throw new NotFoundException({
        code: "IAM_RECONCILIATION_RUN_NOT_FOUND",
        message: "IAM reconciliation run was not found."
      });
    }

    const items = await this.repository.listReconciliationItems(runKey);
    const summary = summarizeItems(items);
    return {
      run,
      summary: {
        mismatchCount: items.filter((item) => item.severity !== "info").length,
        p0Count: summary.p0,
        p1Count: summary.p1,
        p2Count: summary.p2,
        infoCount: summary.info
      },
      safetyGate: {
        passed: summary.p0 === 0 && summary.p1 === 0,
        p0BlocksCutover: true,
        p1BlocksCutover: true
      },
      items: redactItemsForResponse(items)
    };
  }

  private assertViewEnabled(scope: IamViewScope): void {
    const { iam } = this.config;
    if (!iam.enabled || iam.mode === "disabled") {
      throw new NotFoundException({
        code: "IDENTITY_IAM_DISABLED",
        message: "Identity IAM readonly view is disabled."
      });
    }

    const enabledByScope: Record<IamViewScope, boolean> = {
      user: iam.userViewEnabled,
      role: iam.roleViewEnabled,
      permission: iam.permissionViewEnabled,
      organization: iam.organizationViewEnabled,
      plugin: iam.pluginViewEnabled
    };

    if (!enabledByScope[scope]) {
      throw new NotFoundException({
        code: "IDENTITY_IAM_VIEW_DISABLED",
        message: `Identity IAM ${scope} view is disabled.`
      });
    }
  }

  private async requireLegacyUser(legacyUserId: number): Promise<LegacyUserReadModel> {
    if (!this.legacyReader.isConfigured() && !this.config.iam.fallbackEnabled) {
      throw new ServiceUnavailableException({
        code: "LEGACY_IAM_SOURCE_NOT_CONFIGURED",
        message: "Legacy IAM source is not configured and fallback is disabled."
      });
    }

    const user = await this.legacyReader.getUserById(legacyUserId);
    if (!user) {
      throw new NotFoundException({
        code: "IAM_USER_NOT_FOUND",
        message: "IAM user was not found in the current legacy source."
      });
    }

    return user;
  }

  private parseReconciliationInput(rawInput: unknown): IamReconciliationInput {
    const parsed = reconciliationSchema.safeParse(rawInput ?? {});
    if (!parsed.success) {
      throw new BadRequestException({
        code: "INVALID_IAM_RECONCILIATION_PAYLOAD",
        message: "IAM reconciliation payload is invalid.",
        details: parsed.error.flatten()
      });
    }

    return parsed.data;
  }

  private async loadReconciliationUsers(input: IamReconciliationInput, limit: number): Promise<LegacyUserReadModel[]> {
    if (input.legacyUserIds?.length) {
      const users = await Promise.all(input.legacyUserIds.map((id) => this.requireLegacyUser(id)));
      return users;
    }

    return this.legacyReader.listUsers({
      afterId: input.afterLegacyUserId ?? 0,
      limit
    });
  }

  private async applyShadow(users: LegacyUserReadModel[], scopes: IamReconciliationScope[]): Promise<number> {
    let writes = 0;
    for (const user of users) {
      const identityUserId = identityUserIdForLegacy(user.id);

      if (scopes.some((scope) => ["user", "role", "organization", "plugin"].includes(scope))) {
        await this.repository.upsertIdentityUserShadow({
          identityUserId,
          legacyUserId: user.id,
          username: user.username,
          email: user.email,
          status: normalizeLegacyStatus(user.status),
          metadata: sanitizeMetadata({
            source: "iam-reconciliation",
            legacyCreatedAt: user.createdAt,
            legacyUpdatedAt: user.updatedAt
          })
        });
        writes += 1;
      }

      if (scopes.includes("role")) {
        writes += await this.repository.replaceRoleAssignmentsShadow(
          user.id,
          user.roles.map((roleName) => ({
            identityUserId,
            legacyUserId: user.id,
            roleName,
            source: "legacy-shadow"
          }))
        );
      }

      if (scopes.includes("organization")) {
        writes += await this.repository.replaceOrganizationMembershipsShadow(
          user.id,
          user.organizations.map((organization) => ({
            identityUserId,
            legacyUserId: user.id,
            organizationId: organization.id,
            organizationRole: "member",
            source: "legacy-shadow"
          }))
        );
      }

      if (scopes.includes("plugin")) {
        await this.repository.upsertPluginSubjectMap({
          identityUserId,
          legacyUserId: user.id,
          metadata: sanitizeMetadata({
            source: "iam-reconciliation",
            pluginIdentity: "legacy-compatible"
          })
        });
        writes += 1;
      }
    }

    return writes;
  }

  private async collectReconciliationItems(
    runKey: string,
    users: LegacyUserReadModel[],
    scopes: IamReconciliationScope[]
  ): Promise<IamReconciliationItemInput[]> {
    const items: IamReconciliationItemInput[] = [];
    for (const user of users) {
      const identity = await this.repository.getIdentityUserByLegacyId(user.id);
      const identityUserId = identity?.id ?? identityUserIdForLegacy(user.id);

      if (scopes.includes("user")) {
        items.push(...this.compareUser(runKey, user, identity));
      }
      if (scopes.includes("role")) {
        const shadowRoles = await this.repository.listRoleAssignmentsShadow(user.id);
        items.push(
          ...this.compareSet(runKey, "role", user, identityUserId, {
            fieldPath: "roles",
            legacyValues: user.roles,
            identityValues: shadowRoles.map((role) => role.roleName),
            severity: "p1",
            message: "Legacy roles and identity shadow roles differ."
          })
        );
      }
      if (scopes.includes("permission")) {
        const permissions = await this.legacyReader.listUserPermissions(user.id);
        items.push(
          this.item(runKey, "permission", "info", user, identityUserId, "permissions", permissions.map((permission) => permission.name), null, {
            message: "Permissions are still derived from legacy Yii RBAC in phase 6 readonly mode.",
            metadata: {
              source: "legacy-yii-rbac",
              permissionCount: permissions.length,
              identityPermissionShadow: "not_materialized"
            }
          })
        );
      }
      if (scopes.includes("organization")) {
        const shadowOrganizations = await this.repository.listOrganizationMembershipsShadow(user.id);
        items.push(
          ...this.compareSet(runKey, "organization", user, identityUserId, {
            fieldPath: "organizations",
            legacyValues: user.organizations.map((organization) => String(organization.id)),
            identityValues: shadowOrganizations.map((organization) => String(organization.organizationId)),
            severity: "p1",
            message: "Legacy organizations and identity shadow organizations differ."
          })
        );
      }
      if (scopes.includes("plugin")) {
        const subjectMaps = await this.repository.listSubjectMaps(identity?.id ?? identityUserId);
        const expectedSubject = `legacy:${user.id}`;
        const hasPluginSubject = subjectMaps.some(
          (subject) => subject.subjectType === "plugin_user" && subject.subjectId === expectedSubject && subject.status === "active"
        );
        if (!hasPluginSubject) {
          items.push(
            this.item(runKey, "plugin", "p2", user, identityUserId, "plugin.subjectMap", expectedSubject, null, {
              message: "Plugin identity subject map is missing from identity shadow data.",
              metadata: { expectedSubjectType: "plugin_user" }
            })
          );
        }
      }
    }

    return items;
  }

  private compareUser(
    runKey: string,
    legacyUser: LegacyUserReadModel,
    identity: Awaited<ReturnType<IamRepository["getIdentityUserByLegacyId"]>>
  ): IamReconciliationItemInput[] {
    const identityUserId = identity?.id ?? identityUserIdForLegacy(legacyUser.id);
    if (!identity) {
      return [
        this.item(runKey, "user", "p1", legacyUser, identityUserId, "identityUser", legacyUser.id, null, {
          message: "Identity shadow user is missing for legacy user.",
          metadata: { expectedIdentityUserId: identityUserId }
        })
      ];
    }

    const items: IamReconciliationItemInput[] = [];
    if (identity.legacyUserId !== legacyUser.id) {
      items.push(
        this.item(runKey, "user", "p0", legacyUser, identity.id, "legacyUserId", legacyUser.id, identity.legacyUserId, {
          message: "Identity user maps to a different legacy user id."
        })
      );
    }
    if ((identity.username ?? null) !== (legacyUser.username ?? null)) {
      items.push(
        this.item(runKey, "user", "p2", legacyUser, identity.id, "username", legacyUser.username, identity.username, {
          message: "Legacy username and identity shadow username differ."
        })
      );
    }
    if ((identity.email ?? null) !== (legacyUser.email ?? null)) {
      items.push(
        this.item(runKey, "user", "p2", legacyUser, identity.id, "email", legacyUser.email, identity.email, {
          message: "Legacy email and identity shadow email differ."
        })
      );
    }
    const legacyStatus = normalizeLegacyStatus(legacyUser.status);
    if (identity.status !== legacyStatus) {
      items.push(
        this.item(runKey, "user", "p1", legacyUser, identity.id, "status", legacyStatus, identity.status, {
          message: "Legacy account status and identity shadow status differ."
        })
      );
    }

    return items;
  }

  private compareSet(
    runKey: string,
    scope: IamReconciliationScope,
    user: LegacyUserReadModel,
    identityUserId: string,
    input: {
      fieldPath: string;
      legacyValues: string[];
      identityValues: string[];
      severity: "p1" | "p2";
      message: string;
    }
  ): IamReconciliationItemInput[] {
    const legacy = normalizeSet(input.legacyValues);
    const identity = normalizeSet(input.identityValues);
    if (JSON.stringify(legacy) === JSON.stringify(identity)) {
      return [];
    }

    return [
      this.item(runKey, scope, input.severity, user, identityUserId, input.fieldPath, legacy, identity, {
        message: input.message,
        metadata: {
          legacyCount: legacy.length,
          identityCount: identity.length
        }
      })
    ];
  }

  private item(
    runKey: string,
    scope: IamReconciliationScope,
    severity: "p0" | "p1" | "p2" | "info",
    user: LegacyUserReadModel,
    identityUserId: string | null,
    fieldPath: string,
    legacyValue: unknown,
    identityValue: unknown,
    input: { message: string; metadata?: Record<string, unknown> }
  ): IamReconciliationItemInput {
    return {
      runKey,
      scope,
      severity,
      legacySubjectType: "legacy_user",
      legacySubjectId: String(user.id),
      identitySubjectType: identityUserId ? "identity_user" : null,
      identitySubjectId: identityUserId,
      fieldPath,
      legacyValueHash: hashValue(legacyValue),
      identityValueHash: hashValue(identityValue),
      message: input.message,
      metadata: sanitizeMetadata({
        legacyUserId: user.id,
        ...input.metadata
      })
    };
  }

  private assertConfiguredForReport(): void {
    if (!this.repository.isConfigured()) {
      throw new ServiceUnavailableException({
        code: "IDENTITY_DB_NOT_CONFIGURED",
        message: "Identity database is not configured for IAM reconciliation."
      });
    }
  }

  private runMetadata(input: Record<string, unknown>): Record<string, unknown> {
    return sanitizeMetadata({
      phase: "6",
      nonUserFacing: true,
      ...input
    });
  }

  private verifyToken(token: string | null | undefined): VerifiedAccessToken {
    if (!token) {
      throw new UnauthorizedException({
        code: "AUTHORIZATION_REQUIRED",
        message: "Bearer token is required for plugin IAM view."
      });
    }

    try {
      return this.jwtIssuer.verifyAccessToken(token);
    } catch {
      throw new UnauthorizedException({
        code: "TOKEN_INVALID",
        message: "Identity token is invalid."
      });
    }
  }
}

function normalizeLegacyStatus(status: number): "active" | "inactive" {
  return status === 10 ? "active" : "inactive";
}

function derivedLegacySubject(identityUserId: string, legacyUserId: number) {
  return [
    {
      identityUserId,
      subjectType: "legacy_user",
      subjectId: String(legacyUserId),
      source: "legacy-derived",
      status: "active",
      metadata: null,
      createdAt: null,
      updatedAt: null
    }
  ];
}

function pluginUserShape(user: LegacyUserReadModel, claims: VerifiedAccessToken) {
  return {
    id: user.id,
    uid: user.id,
    identityUserId: `legacy:${user.id}`,
    username: user.username ?? claims.username,
    email: user.email,
    nickname: user.nickname,
    roles: user.roles.length > 0 ? user.roles : claims.roles,
    organizations: user.organizations,
    sessionId: claims.sessionId
  };
}

function identityUserIdForLegacy(legacyUserId: number): string {
  return `legacy:${legacyUserId}`;
}

function normalizeSet(values: string[]): string[] {
  return [...new Set(values.map((value) => value.trim()).filter(Boolean))].sort((a, b) => a.localeCompare(b));
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

function hashValue(value: unknown): string | null {
  if (value === null || value === undefined) {
    return null;
  }

  return createHash("sha256").update(stableJson(value)).digest("hex");
}

function summarizeItems(items: Array<{ severity: string }>) {
  return {
    p0: items.filter((item) => item.severity === "p0").length,
    p1: items.filter((item) => item.severity === "p1").length,
    p2: items.filter((item) => item.severity === "p2").length,
    info: items.filter((item) => item.severity === "info").length
  };
}

function redactItemsForResponse(items: Array<IamReconciliationItemInput & { createdAt?: string | null }>) {
  return items.map((item) => ({
    runKey: item.runKey,
    scope: item.scope,
    severity: item.severity,
    legacySubjectType: item.legacySubjectType,
    legacySubjectId: item.legacySubjectId,
    identitySubjectType: item.identitySubjectType,
    identitySubjectId: item.identitySubjectId,
    fieldPath: item.fieldPath,
    legacyValueHash: item.legacyValueHash,
    identityValueHash: item.identityValueHash,
    message: item.message,
    metadata: item.metadata,
    createdAt: item.createdAt ?? null
  }));
}
