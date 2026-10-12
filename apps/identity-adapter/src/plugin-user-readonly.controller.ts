import { NativeIdentityService } from "./native-identity.service.js";
import { Controller, Optional, Get, Headers, HttpException, HttpStatus, Param, Query, Res, ServiceUnavailableException } from "@nestjs/common";
import { loadConfig } from "./config.js";
import { JwtIssuerService, VerifiedAccessToken } from "./jwt-issuer.service.js";
import { IamRepository, type IdentityOrganizationShadowRow } from "./iam.repository.js";
import { LegacyIdentityReader, LegacyUserReadModel, type LegacyAuditMember } from "./legacy-identity.reader.js";
import { LoginAuditService } from "./login-audit.service.js";
import { PluginUserPrimaryReadService, PluginUserReadSource } from "./plugin-user-primary-read.service.js";
import { auditPrimaryRole, parseOrganizationLoginQuery } from "./organization-login-events.js";

const ELEVATED_ROLES = new Set(["root", "admin", "manager"]);
type AuditActor = Pick<VerifiedAccessToken, "uid" | "roles">;

interface HeaderResponse {
  setHeader(name: string, value: string): void;
}

@Controller()
export class PluginUserReadonlyController {
  private readonly config = loadConfig();

  constructor(
    private readonly legacyReader: LegacyIdentityReader,
    private readonly jwtIssuer: JwtIssuerService,
    private readonly primaryRead: PluginUserPrimaryReadService,
    private readonly loginAudit: LoginAuditService,
    private readonly iamRepository: IamRepository,
    @Optional() private readonly native?: NativeIdentityService
  ) {}

  @Get("v1/plugin-user/users")
  async users(
    @Query() query: Record<string, unknown>,
    @Res({ passthrough: true }) response: HeaderResponse,
    @Headers("authorization") authorization?: string
  ) {
    if (this.config.dataSource === "identity") {
      response.setHeader("X-Identity-User-Source", "identity-db");
      return this.requireNative().managedUsers({headers:{authorization}},query);
    }
    this.assertEnabled();
    const claims = this.currentUser(authorization);
    const id = positiveInt(query.id);

    if (id !== null) {
      await this.assertCan(claims, "user-management.view-user");
      const result = await this.primaryRead.getUserById(id, claims);
      this.setSourceHeader(response, result.source);
      const user = result.data;
      if (!user) {
        throw new HttpException(
          {
            code: 4004,
            message: "用户不存在"
          },
          HttpStatus.NOT_FOUND
        );
      }

      return {
        code: 0,
        data: serializeManagedUser(user)
      };
    }

    await this.assertCan(claims, "user-management.list-users");
    const page = positiveInt(query.page) ?? 1;
    const pageSize = positiveInt(query.pageSize) ?? 20;
    const status = query.status === undefined || query.status === "" ? undefined : Number(query.status);
    const result = await this.primaryRead.listUsers({
      page,
      pageSize,
      search: typeof query.search === "string" ? query.search : undefined,
      status: Number.isInteger(status) ? status : undefined,
      sort: typeof query.sort === "string" ? query.sort : undefined,
      order: query.order === "asc" ? "asc" : "desc"
    }, claims);
    this.setSourceHeader(response, result.source);

    return {
      data: result.data.users.map(serializeManagedUser),
      pagination: {
        page: result.data.page,
        pageSize: result.data.pageSize,
        total: result.data.total,
        totalPages: result.data.totalPages
      }
    };
  }

  @Get("v1/plugin-user/users/:legacyUserId/login-audit")
  async userLoginAudit(
    @Headers("authorization") authorization: string | undefined,
    @Param("legacyUserId") legacyUserId: string,
    @Query() query: Record<string, unknown>
  ) {
    if (this.config.dataSource === "identity") {
      const native = this.requireNative();
      const actor = await native.actor({headers:{authorization}});
      const parsedId = positiveInt(legacyUserId);
      if (parsedId === null) throw new HttpException({code:"INVALID_USER_ID",message:"User id must be a positive integer."},HttpStatus.BAD_REQUEST);
      if (!actor.roles.some(role=>ELEVATED_ROLES.has(role))) await native.requirePermission(actor,"user-management.view-user");
      this.assertLoginAuditEnabled();
      const scope = this.resolveAuditOrganizationScope(actor,query);
      const target = await native.subject(parsedId);
      if (scope !== null && (!belongsToOrganization(target,scope) || (!actor.roles.includes("root") && !belongsToOrganization(actor,scope)))) throw this.organizationScopeDenied();
      return {code:0,data:await this.loginAudit.getUserAudit(parsedId, actor.roles.includes("root") ? "full" : "masked")};
    }
    this.assertEnabled();
    const claims = this.currentUser(authorization);
    const parsedId = positiveInt(legacyUserId);
    if (parsedId === null) {
      throw new HttpException(
        {
          code: "INVALID_USER_ID",
          message: "User id must be a positive integer."
        },
        HttpStatus.BAD_REQUEST
      );
    }

    await this.assertCan(claims, "user-management.view-user");
    this.assertLoginAuditEnabled();
    const organizationId = this.resolveAuditOrganizationScope(claims, query);

    const result = await this.primaryRead.getUserById(parsedId, claims);
    if (!result.data) {
      throw new HttpException(
        {
          code: 4004,
          message: "用户不存在"
        },
        HttpStatus.NOT_FOUND
      );
    }

    await this.assertOrganizationScopedAuditAccess(claims, result.data.id, organizationId);

    return {
      code: 0,
      data: await this.loginAudit.getUserAudit(parsedId, claims.roles.includes("root") ? "full" : "masked")
    };
  }

  @Get("v1/plugin-user/organizations/:organizationId/login-usage-invoice")
  async organizationLoginUsageInvoice(
    @Headers("authorization") authorization: string | undefined,
    @Param("organizationId") organizationId: string,
    @Query() query: Record<string, unknown>
  ) {
    const claims = await this.auditActor(authorization);
    const parsedOrganizationId = strictPositiveInt(organizationId);
    if (parsedOrganizationId === null) {
      throw new HttpException(
        {
          code: "INVALID_ORGANIZATION_ID",
          message: "Organization id must be a positive integer."
        },
        HttpStatus.BAD_REQUEST
      );
    }

    await this.assertCan(claims, "user-management.view-user");
    this.assertLoginAuditEnabled();
    const organization = await this.assertOrganizationInvoiceAccess(claims, parsedOrganizationId);
    const users = await this.legacyReader.listUsersByOrganization(parsedOrganizationId);
    const from = parseInvoiceDate(query.from, "from");
    const to = parseInvoiceDate(query.to, "to");
    if (from && to && from > to) {
      throw new HttpException(
        { code: "INVALID_LOGIN_USAGE_INVOICE_RANGE", message: "from must be before or equal to to." },
        HttpStatus.BAD_REQUEST
      );
    }
    const invoice = await this.loginAudit.createUsageInvoice({
      accounts: users.map((user) => ({ legacyUserId: user.id, username: user.username })),
      from,
      to
    });

    return {
      code: 0,
      data: {
        organization,
        ...invoice
      }
    };
  }

  @Get("v1/plugin-user/login-events")
  async organizationLoginEvents(
    @Headers("authorization") authorization: string | undefined,
    @Query() query: Record<string, unknown>
  ) {
    const claims = await this.auditActor(authorization);
    if (!claims.roles.some((role) => ELEVATED_ROLES.has(role))) throw this.organizationScopeDenied();
    this.assertLoginAuditEnabled();
    const organizationId = this.resolveAuditOrganizationScope(claims, query);
    if (organizationId === null) {
      throw new HttpException({ code: "ORGANIZATION_SCOPE_REQUIRED", message: "请选择具体组织后查看登录流水" }, HttpStatus.FORBIDDEN);
    }
    const filters = parseOrganizationLoginQuery(query);
    if (!claims.roles.includes("root")) {
      await this.assertOrganizationScopedAuditAccess(claims, claims.uid, organizationId);
    }

    let members: LegacyAuditMember[];
    try {
      members = await this.legacyReader.listOrganizationAuditMembers(organizationId);
      if (this.config.dataSource !== "identity") {
        if (!this.iamRepository.isConfigured()) throw this.organizationScopeDenied();
        const shadow = await this.iamRepository.listOrganizationMembershipsShadowForUsers(members.map((member) => member.id));
        const byUser = new Map<number, IdentityOrganizationShadowRow[]>();
        for (const membership of shadow) {
          if (membership.legacyUserId === null) throw this.organizationScopeDenied();
          const memberships = byUser.get(membership.legacyUserId) ?? [];
          memberships.push(membership);
          byUser.set(membership.legacyUserId, memberships);
        }
        for (const member of members) {
          if (!member.organizations.some((organization) => organization.id === organizationId)
            || !sameOrganizationMemberships(member, byUser.get(member.id) ?? [])) {
            throw this.organizationScopeDenied();
          }
        }
      }
    } catch {
      throw new HttpException({ code: "ORGANIZATION_SCOPE_DENIED", message: "无法确认当前组织成员范围，请稍后重试" }, HttpStatus.FORBIDDEN);
    }

    members = await this.primaryRead.withAuditMemberRoles(members);
    const search = filters.search?.toLocaleLowerCase();
    const selected = members.filter((member) =>
      (!filters.role || auditPrimaryRole(member.roles) === filters.role)
      && (!search || [member.username, member.nickname].some((value) => value?.toLocaleLowerCase().includes(search)))
    );
    const selectedById = new Map(selected.map((member) => [member.id, member]));
    const result = await this.loginAudit.listOrganizationEvents({
      userIds: selected.map((member) => member.id), startAt: filters.start_at, endAt: filters.end_at,
      page: filters.page, pageSize: filters.pageSize
    });
    return {
      code: 0,
      data: result.events.map((event) => {
        const member = selectedById.get(event.userId)!;
        return { ...event, username: member.username, nickname: member.nickname, primaryRole: auditPrimaryRole(member.roles) };
      }),
      pagination: { page: filters.page, pageSize: filters.pageSize, total: result.total, totalPages: Math.ceil(result.total / filters.pageSize) }
    };
  }

  private async assertOrganizationScopedAuditAccess(
    claims: AuditActor,
    targetUserId: number,
    organizationId: number | null
  ): Promise<void> {
    if (organizationId === null) return;

    const authoritativeTarget = await this.readAuthoritativeUser(targetUserId);
    if (!authoritativeTarget || !belongsToOrganization(authoritativeTarget, organizationId)) {
      throw this.organizationScopeDenied();
    }
    await this.assertShadowMembershipMatches(authoritativeTarget);

    if (claims.roles.includes("root")) {
      return;
    }

    const actorUser = claims.uid === authoritativeTarget.id
      ? authoritativeTarget
      : await this.readAuthoritativeUser(claims.uid);
    if (!actorUser || !belongsToOrganization(actorUser, organizationId)) {
      throw this.organizationScopeDenied();
    }
    await this.assertShadowMembershipMatches(actorUser);
  }

  private async assertOrganizationInvoiceAccess(
    claims: AuditActor,
    organizationId: number
  ): Promise<{ id: number; name: string; title: string }> {
    const organization = (await this.legacyReader.listOrganizations()).find((item) => item.id === organizationId);
    if (!organization) {
      throw new HttpException(
        {
          code: "ORGANIZATION_NOT_FOUND",
          message: "Organization does not exist."
        },
        HttpStatus.NOT_FOUND
      );
    }

    if (!claims.roles.includes("root")) {
      const actorUser = await this.readAuthoritativeUser(claims.uid);
      if (!actorUser || !belongsToOrganization(actorUser, organizationId)) {
        throw this.organizationScopeDenied();
      }
      await this.assertShadowMembershipMatches(actorUser);
    }

    return { id: organization.id, name: organization.name, title: organization.title };
  }

  private resolveAuditOrganizationScope(
    claims: Pick<VerifiedAccessToken,"roles">,
    query: Record<string, unknown>
  ): number | null {
    const organizationId = query.organization_id;
    const parsedOrganizationId = organizationId === undefined ? null : strictPositiveInt(organizationId);
    if (hasMalformedOrganizationScope(query) || (organizationId !== undefined && parsedOrganizationId === null)) {
      throw new HttpException(
        {
          code: "INVALID_ORGANIZATION_ID",
          message: "Organization id must be a positive integer."
        },
        HttpStatus.BAD_REQUEST
      );
    }

    if (organizationId === undefined) {
      if (claims.roles.includes("root")) {
        return null;
      }

      throw new HttpException(
        {
          code: "ORGANIZATION_SCOPE_REQUIRED",
          message: "Organization scope is required for non-root login audit access."
        },
        HttpStatus.FORBIDDEN
      );
    }

    return parsedOrganizationId!;
  }

  private async readAuthoritativeUser(userId: number): Promise<LegacyUserReadModel | null> {
    try {
      return await this.legacyReader.getUserById(userId);
    } catch {
      throw this.organizationScopeDenied();
    }
  }

  private async assertShadowMembershipMatches(user: LegacyUserReadModel): Promise<void> {
    // Native memberships and roles are read directly from the private account
    // schema. Staged shadow rows stop being an authority after activation.
    if (this.config.dataSource === "identity") return;
    if (!this.iamRepository.isConfigured()) {
      throw this.organizationScopeDenied();
    }

    try {
      const shadowMemberships = await this.iamRepository.listOrganizationMembershipsShadow(user.id);
      if (!sameOrganizationMemberships(user, shadowMemberships)) {
        throw this.organizationScopeDenied();
      }
    } catch (error) {
      if (error instanceof HttpException) throw error;
      throw this.organizationScopeDenied();
    }
  }

  private organizationScopeDenied(): HttpException {
    return new HttpException(
      {
        code: "ORGANIZATION_SCOPE_DENIED",
        message: "该账号不属于当前组织"
      },
      HttpStatus.FORBIDDEN
    );
  }

  private assertEnabled(): void {
    if (!this.config.pluginUserReadonly.enabled) {
      throw new HttpException(
        {
          code: "PLUGIN_USER_READONLY_DISABLED",
          message: "Plugin user readonly compatibility endpoint is disabled."
        },
        HttpStatus.NOT_FOUND
      );
    }
  }

  private assertLoginAuditEnabled(): void {
    if (!this.config.loginAudit.enabled) {
      throw new HttpException(
        {
          code: "LOGIN_AUDIT_DISABLED",
          message: "Login audit is disabled."
        },
        HttpStatus.NOT_FOUND
      );
    }
  }

  private currentUser(authorization?: string): VerifiedAccessToken {
    const token = bearerToken(authorization);
    if (!token) {
      throw new HttpException(
        {
          code: 2001,
          message: "用户未登录"
        },
        HttpStatus.UNAUTHORIZED
      );
    }

    try {
      return this.jwtIssuer.verifyAccessToken(token);
    } catch {
      throw new HttpException(
        {
          code: 2001,
          message: "用户未登录"
        },
        HttpStatus.UNAUTHORIZED
      );
    }
  }

  private requireNative(): NativeIdentityService {
    if (!this.native?.enabled) {
      throw new ServiceUnavailableException({ code: "IDENTITY_NATIVE_UNAVAILABLE", message: "Identity account authority is unavailable." });
    }
    return this.native;
  }

  private async auditActor(authorization?: string): Promise<AuditActor> {
    if (this.config.dataSource === "identity") {
      const actor = await this.requireNative().actor({ headers: { authorization } });
      return { uid: actor.id, roles: actor.roles };
    }
    this.assertEnabled();
    return this.currentUser(authorization);
  }

  private async assertCan(claims: AuditActor, permission: string): Promise<void> {
    if (claims.roles.some((role) => ELEVATED_ROLES.has(role))) {
      return;
    }

    const permissions = await this.legacyReader.listUserPermissions(claims.uid);
    if (permissions.some((item) => item.name === permission)) {
      return;
    }

    throw new HttpException(
      {
        code: 2003,
        message: "没有权限执行此操作"
      },
      HttpStatus.FORBIDDEN
    );
  }

  private setSourceHeader(response: HeaderResponse, source: PluginUserReadSource): void {
    if (this.config.pluginUserPrimaryRead.observeHeader) {
      response.setHeader("X-Identity-User-Source", source);
    }
  }
}

function belongsToOrganization(user: LegacyUserReadModel, organizationId: number): boolean {
  return user.organizations.some((organization) => Number(organization.id) === organizationId);
}

function serializeManagedUser(user: LegacyUserReadModel) {
  return {
    id: user.id,
    username: user.username,
    nickname: user.nickname ?? user.username,
    email: user.email,
    status: user.status,
    created_at: user.createdAt,
    updated_at: user.updatedAt,
    roles: user.roles,
    organizations: user.organizations
  };
}

function positiveInt(value: unknown): number | null {
  const parsed = Number(Array.isArray(value) ? value[0] : value);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    return null;
  }
  return parsed;
}

function strictPositiveInt(value: unknown): number | null {
  if (typeof value === "number") {
    return Number.isSafeInteger(value) && value > 0 ? value : null;
  }
  if (typeof value !== "string" || !/^[1-9]\d*$/.test(value)) {
    return null;
  }

  const parsed = Number(value);
  return Number.isSafeInteger(parsed) ? parsed : null;
}

function hasMalformedOrganizationScope(query: Record<string, unknown>): boolean {
  return Object.keys(query).some((key) => key.startsWith("organization_id["));
}

function parseInvoiceDate(value: unknown, field: string): Date | undefined {
  if (value === undefined || value === "") return undefined;
  if (typeof value !== "string") {
    throw new HttpException(
      { code: "INVALID_LOGIN_USAGE_INVOICE_DATE", message: `${field} must be an ISO-8601 date.` },
      HttpStatus.BAD_REQUEST
    );
  }

  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    throw new HttpException(
      { code: "INVALID_LOGIN_USAGE_INVOICE_DATE", message: `${field} must be an ISO-8601 date.` },
      HttpStatus.BAD_REQUEST
    );
  }
  return parsed;
}

function sameOrganizationMemberships(
  legacyUser: Pick<LegacyUserReadModel, "id" | "organizations">,
  shadowMemberships: IdentityOrganizationShadowRow[]
): boolean {
  const legacyOrganizationIds = new Set(legacyUser.organizations.map((organization) => organization.id));
  const shadowOrganizationIds = new Set<number>();

  for (const membership of shadowMemberships) {
    if (
      (membership.legacyUserId !== null && membership.legacyUserId !== legacyUser.id)
      || !Number.isSafeInteger(membership.organizationId)
      || membership.organizationId <= 0
    ) {
      return false;
    }
    shadowOrganizationIds.add(membership.organizationId);
  }

  if (legacyOrganizationIds.size !== shadowOrganizationIds.size) {
    return false;
  }

  return [...legacyOrganizationIds].every((organizationId) => shadowOrganizationIds.has(organizationId));
}

function bearerToken(authorization?: string): string | null {
  const match = authorization?.match(/^Bearer\s+(.+)$/i);
  return match?.[1] ?? null;
}
