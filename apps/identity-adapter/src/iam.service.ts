import { Injectable, NotFoundException, ServiceUnavailableException, UnauthorizedException } from "@nestjs/common";
import { loadConfig } from "./config.js";
import { IamRepository } from "./iam.repository.js";
import { JwtIssuerService, VerifiedAccessToken } from "./jwt-issuer.service.js";
import { LegacyIdentityReader, LegacyUserReadModel } from "./legacy-identity.reader.js";

type IamViewScope = "user" | "role" | "permission" | "organization" | "plugin";

@Injectable()
export class IamService {
  private readonly config = loadConfig();

  constructor(
    private readonly repository: IamRepository,
    private readonly legacyReader: LegacyIdentityReader,
    private readonly jwtIssuer: JwtIssuerService
  ) {}

  async readiness() {
    const { iam } = this.config;

    return {
      enabled: iam.enabled,
      mode: iam.mode,
      fallbackEnabled: iam.fallbackEnabled,
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
      }
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
