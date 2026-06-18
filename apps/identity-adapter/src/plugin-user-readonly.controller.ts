import { Controller, Get, Headers, HttpException, HttpStatus, Query } from "@nestjs/common";
import { loadConfig } from "./config.js";
import { JwtIssuerService, VerifiedAccessToken } from "./jwt-issuer.service.js";
import { LegacyIdentityReader, LegacyUserReadModel } from "./legacy-identity.reader.js";

const ELEVATED_ROLES = new Set(["root", "admin", "manager"]);

@Controller()
export class PluginUserReadonlyController {
  private readonly config = loadConfig();

  constructor(
    private readonly legacyReader: LegacyIdentityReader,
    private readonly jwtIssuer: JwtIssuerService
  ) {}

  @Get("v1/plugin-user/users")
  async users(@Query() query: Record<string, unknown>, @Headers("authorization") authorization?: string) {
    this.assertEnabled();
    const claims = this.currentUser(authorization);
    const id = positiveInt(query.id);

    if (id !== null) {
      await this.assertCan(claims, "user-management.view-user");
      const user = await this.legacyReader.getUserById(id);
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
    const result = await this.legacyReader.listManagedUsers({
      page,
      pageSize,
      search: typeof query.search === "string" ? query.search : undefined,
      status: Number.isInteger(status) ? status : undefined,
      sort: typeof query.sort === "string" ? query.sort : undefined,
      order: query.order === "asc" ? "asc" : "desc"
    });

    return {
      data: result.users.map(serializeManagedUser),
      pagination: {
        page: result.page,
        pageSize: result.pageSize,
        total: result.total,
        totalPages: result.totalPages
      }
    };
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

  private async assertCan(claims: VerifiedAccessToken, permission: string): Promise<void> {
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

function bearerToken(authorization?: string): string | null {
  const match = authorization?.match(/^Bearer\s+(.+)$/i);
  return match?.[1] ?? null;
}
