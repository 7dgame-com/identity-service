import { createHmac, timingSafeEqual } from "node:crypto";
import {
  BadRequestException,
  Injectable,
  Logger,
  NotFoundException,
  ServiceUnavailableException,
  UnauthorizedException
} from "@nestjs/common";
import { loadConfig } from "./config.js";
import {
  PluginUserTemporaryAuthorizationGrantState,
  PluginUserTemporaryAuthorizationRepository
} from "./plugin-user-temporary-authorization.repository.js";

export interface PluginUserTemporaryAuthorizationGrantResult {
  granted: true;
  legacyUserId: number;
  runKey: string;
  routes: string[];
  role: "admin" | "manager" | null;
  expiresAt: string;
  grantToken: string;
  createdRouteAssignments: number;
  createdRouteItems: number;
  createdRoleAssignments: number;
}

export interface PluginUserTemporaryAuthorizationRevokeResult {
  revoked: true;
  legacyUserId: number;
  runKey: string;
  routes: string[];
  role: "admin" | "manager" | null;
  expired: boolean;
  removedRouteAssignments: number;
  removedRouteItems: number;
  removedRoleAssignments: number;
}

interface GrantPayload {
  version: 1;
  capability: "plugin-user-temporary-authorization";
  state: PluginUserTemporaryAuthorizationGrantState;
}

const PLUGIN_USER_WRITE_ROUTE_PATTERN = "/v1/plugin-user/*";
const PLUGIN_USER_WRITE_ROUTE_GRANTS = [
  "/v1/plugin-user/create-user",
  "/v1/plugin-user/update-user",
  "/v1/plugin-user/delete-user",
  "/v1/plugin-user/change-role",
  "/v1/plugin-user/batch-create-users"
] as const;
const DEFAULT_ROUTES = [PLUGIN_USER_WRITE_ROUTE_PATTERN];
const ALLOWED_ROLES = new Set(["admin", "manager"]);
const MAX_REASON_LENGTH = 160;

@Injectable()
export class PluginUserTemporaryAuthorizationService {
  private readonly config = loadConfig();
  private readonly logger = new Logger(PluginUserTemporaryAuthorizationService.name);

  constructor(private readonly repository: PluginUserTemporaryAuthorizationRepository) {}

  readiness() {
    const settings = this.config.pluginUserTemporaryAuthorization;
    const configuredAllowedRoutes = this.configuredAllowedRoutes();
    const allowedRoutes = this.allowedRoutes();
    return {
      enabled: settings.enabled,
      repositoryConfigured: this.repository.isConfigured(),
      internalTokenConfigured: Boolean(settings.internalToken),
      grantTokenSigningConfigured: Boolean(this.signingSecret()),
      advancedRouteAppIds: this.advancedRouteAppIds(),
      allowedRoutePatterns: configuredAllowedRoutes,
      allowedRoutes,
      maxTtlSeconds: this.maxTtlSeconds(),
      defaultRoutes: this.defaultRoutes(),
      supportedRoles: [...ALLOWED_ROLES],
      safety: {
        defaultClosed: true,
        internalTokenRequired: true,
        signedGrantTokenRequiredForRevoke: true,
        revokesOnlyNewAssignments: true,
        deletePrivilegePreflight: true,
        unsafeWildcardsRejected: true
      }
    };
  }

  assertMutatingAccess(token: string | undefined): void {
    const settings = this.config.pluginUserTemporaryAuthorization;
    if (!settings.enabled) {
      throw new NotFoundException({
        code: "PLUGIN_USER_TEMP_AUTH_DISABLED",
        message: "Plugin user temporary authorization is disabled."
      });
    }
    if (!settings.internalToken) {
      throw new ServiceUnavailableException({
        code: "PLUGIN_USER_TEMP_AUTH_TOKEN_NOT_CONFIGURED",
        message: "Internal API token is required before temporary authorization can be used."
      });
    }
    if (token !== settings.internalToken) {
      throw new UnauthorizedException({
        code: "INTERNAL_TOKEN_INVALID",
        message: "Internal service token is invalid."
      });
    }
  }

  async grant(body: unknown): Promise<PluginUserTemporaryAuthorizationGrantResult> {
    if (!this.repository.isConfigured()) {
      throw new ServiceUnavailableException({
        code: "PLUGIN_USER_TEMP_AUTH_REPOSITORY_NOT_CONFIGURED",
        message: "Legacy write database is not configured."
      });
    }

    const input = this.parseGrantBody(body);
    const grantedAt = new Date();
    const expiresAt = new Date(grantedAt.getTime() + input.ttlSeconds * 1000);

    try {
      const state = await this.repository.grant({
        legacyUserId: input.legacyUserId,
        routes: input.routes,
        role: input.role,
        runKey: input.runKey,
        grantedAt: grantedAt.toISOString(),
        expiresAt: expiresAt.toISOString()
      });
      const grantToken = this.signGrantState(state);
      this.logger.warn(
        `plugin-user temporary authorization granted runKey=${input.runKey} legacyUserId=${input.legacyUserId} routes=${input.routes.length} role=${input.role ?? "none"}`
      );

      return {
        granted: true,
        legacyUserId: state.legacyUserId,
        runKey: state.runKey,
        routes: state.routes.map((route) => route.route),
        role: state.role?.role ?? null,
        expiresAt: state.expiresAt,
        grantToken,
        createdRouteAssignments: state.routes.filter((route) => !route.assignmentExisted).length,
        createdRouteItems: state.routes.filter((route) => !route.itemExisted).length,
        createdRoleAssignments: state.role && !state.role.assignmentExisted ? 1 : 0
      };
    } catch (error) {
      this.logger.error(
        `plugin-user temporary authorization grant failed runKey=${input.runKey} legacyUserId=${input.legacyUserId}`,
        error instanceof Error ? error.stack : undefined
      );
      throw new ServiceUnavailableException({
        code: "PLUGIN_USER_TEMP_AUTH_GRANT_FAILED",
        message: "Temporary authorization grant failed; no manual SQL residue should be assumed safe."
      });
    }
  }

  async revoke(body: unknown): Promise<PluginUserTemporaryAuthorizationRevokeResult> {
    if (!this.repository.isConfigured()) {
      throw new ServiceUnavailableException({
        code: "PLUGIN_USER_TEMP_AUTH_REPOSITORY_NOT_CONFIGURED",
        message: "Legacy write database is not configured."
      });
    }

    const state = this.parseRevokeBody(body);
    try {
      const result = await this.repository.revoke(state);
      this.logger.warn(
        `plugin-user temporary authorization revoked runKey=${state.runKey} legacyUserId=${state.legacyUserId} routes=${state.routes.length} role=${state.role?.role ?? "none"}`
      );

      return {
        revoked: true,
        legacyUserId: state.legacyUserId,
        runKey: state.runKey,
        routes: state.routes.map((route) => route.route),
        role: state.role?.role ?? null,
        expired: Date.parse(state.expiresAt) < Date.now(),
        ...result
      };
    } catch (error) {
      this.logger.error(
        `plugin-user temporary authorization revoke failed runKey=${state.runKey} legacyUserId=${state.legacyUserId}`,
        error instanceof Error ? error.stack : undefined
      );
      throw new ServiceUnavailableException({
        code: "PLUGIN_USER_TEMP_AUTH_REVOKE_FAILED",
        message: "Temporary authorization revoke failed; stop the rollout and inspect the grant token state."
      });
    }
  }

  private parseGrantBody(body: unknown): {
    legacyUserId: number;
    routes: string[];
    role: "admin" | "manager" | null;
    runKey: string;
    ttlSeconds: number;
  } {
    const object = objectBody(body);
    const legacyUserId = positiveInteger(object.legacyUserId, "legacyUserId");
    const runKey = parseRunKey(object.runKey);
    const routes = this.parseRoutes(object.routes);
    const role = parseRole(object.role);
    const ttlSeconds = parseTtlSeconds(object.ttlSeconds, this.maxTtlSeconds());
    parseReason(object.reason);

    if (routes.length === 0 && !role) {
      throw new BadRequestException({
        code: "PLUGIN_USER_TEMP_AUTH_EMPTY_SCOPE",
        message: "At least one route or role is required."
      });
    }

    return {
      legacyUserId,
      routes,
      role,
      runKey,
      ttlSeconds
    };
  }

  private parseRevokeBody(body: unknown): PluginUserTemporaryAuthorizationGrantState {
    const object = objectBody(body);
    const grantToken = typeof object.grantToken === "string" ? object.grantToken.trim() : "";
    if (!grantToken) {
      throw new BadRequestException({
        code: "PLUGIN_USER_TEMP_AUTH_GRANT_TOKEN_REQUIRED",
        message: "grantToken is required."
      });
    }

    const payload = this.verifyGrantToken(grantToken);
    return payload.state;
  }

  private parseRoutes(value: unknown): string[] {
    const rawRoutes = routeInputValues(value);
    const configuredAllowed = new Set(this.configuredAllowedRoutes());
    const allowed = new Set(this.allowedRoutes());
    const routes = [
      ...new Set(
        rawRoutes
          .map((route) => (typeof route === "string" ? route.trim() : ""))
          .filter(Boolean)
          .flatMap((route) => this.expandRouteGrant(route, configuredAllowed, allowed))
      )
    ];

    return routes;
  }

  private signGrantState(state: PluginUserTemporaryAuthorizationGrantState): string {
    const payload: GrantPayload = {
      version: 1,
      capability: "plugin-user-temporary-authorization",
      state
    };
    const encoded = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
    return `${encoded}.${this.signature(encoded)}`;
  }

  private verifyGrantToken(token: string): GrantPayload {
    const [encoded, signature, extra] = token.split(".");
    if (!encoded || !signature || extra !== undefined) {
      throw new BadRequestException({
        code: "PLUGIN_USER_TEMP_AUTH_GRANT_TOKEN_INVALID",
        message: "grantToken is invalid."
      });
    }

    const expected = this.signature(encoded);
    if (!safeEqual(signature, expected)) {
      throw new BadRequestException({
        code: "PLUGIN_USER_TEMP_AUTH_GRANT_TOKEN_INVALID",
        message: "grantToken signature is invalid."
      });
    }

    let parsed: Partial<GrantPayload>;
    try {
      parsed = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8")) as Partial<GrantPayload>;
    } catch {
      throw new BadRequestException({
        code: "PLUGIN_USER_TEMP_AUTH_GRANT_TOKEN_INVALID",
        message: "grantToken payload is invalid."
      });
    }
    if (
      parsed.version !== 1 ||
      parsed.capability !== "plugin-user-temporary-authorization" ||
      !isGrantState(parsed.state)
    ) {
      throw new BadRequestException({
        code: "PLUGIN_USER_TEMP_AUTH_GRANT_TOKEN_INVALID",
        message: "grantToken payload is invalid."
      });
    }

    return parsed as GrantPayload;
  }

  private signature(encodedPayload: string): string {
    const secret = this.signingSecret();
    if (!secret) {
      throw new ServiceUnavailableException({
        code: "PLUGIN_USER_TEMP_AUTH_SIGNING_SECRET_NOT_CONFIGURED",
        message: "Temporary authorization grant token signing is not configured."
      });
    }
    return createHmac("sha256", secret).update(encodedPayload).digest("base64url");
  }

  private signingSecret(): string | undefined {
    return this.config.pluginUserTemporaryAuthorization.signingSecret ?? this.config.pluginUserTemporaryAuthorization.internalToken;
  }

  private allowedRoutes(): string[] {
    return [
      ...new Set(
        this.configuredAllowedRoutes().flatMap((route) =>
          route === PLUGIN_USER_WRITE_ROUTE_PATTERN
            ? pluginUserWriteRouteGrants(this.advancedRouteAppIds())
            : [route]
        )
      )
    ];
  }

  private configuredAllowedRoutes(): string[] {
    return splitCsv(this.config.pluginUserTemporaryAuthorization.allowedRoutes).filter((route) => !isUnsafeWildcard(route));
  }

  private defaultRoutes(): string[] {
    const configuredAllowed = new Set(this.configuredAllowedRoutes());
    const allowed = new Set(this.allowedRoutes());
    return [
      ...new Set(
        DEFAULT_ROUTES.flatMap((route) => this.expandRouteGrant(route, configuredAllowed, allowed, { allowEmpty: true }))
      )
    ];
  }

  private expandRouteGrant(
    route: string,
    configuredAllowed: Set<string>,
    allowed: Set<string>,
    options: { allowEmpty?: boolean } = {}
  ): string[] {
    if (isUnsafeWildcard(route)) {
      throwTemporaryAuthorizationRouteNotAllowed();
    }

    if (route === PLUGIN_USER_WRITE_ROUTE_PATTERN && configuredAllowed.has(route)) {
      return pluginUserWriteRouteGrants(this.advancedRouteAppIds());
    }

    if (allowed.has(route)) {
      return [route];
    }

    if (options.allowEmpty) {
      return [];
    }

    throwTemporaryAuthorizationRouteNotAllowed();
  }

  private maxTtlSeconds(): number {
    const configured = Number(this.config.pluginUserTemporaryAuthorization.maxTtlSeconds);
    return Number.isFinite(configured) && configured > 0 ? Math.min(Math.trunc(configured), 86400) : 1800;
  }

  private advancedRouteAppIds(): string[] {
    return [
      ...new Set(
        splitCsv(this.config.pluginUserTemporaryAuthorization.advancedAppIds)
          .map((appId) => appId.replace(/^@+/, "").trim())
          .filter((appId) => /^[a-zA-Z0-9_-]+$/.test(appId))
      )
    ];
  }
}

function pluginUserWriteRouteGrants(advancedAppIds: string[]): string[] {
  return [
    ...PLUGIN_USER_WRITE_ROUTE_GRANTS,
    ...advancedAppIds.flatMap((appId) => PLUGIN_USER_WRITE_ROUTE_GRANTS.map((route) => `@${appId}${route}`))
  ];
}

function objectBody(body: unknown): Record<string, unknown> {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new BadRequestException({
      code: "PLUGIN_USER_TEMP_AUTH_INVALID_BODY",
      message: "Request body must be an object."
    });
  }
  return body as Record<string, unknown>;
}

function routeInputValues(value: unknown): unknown[] {
  if (value === undefined) {
    return DEFAULT_ROUTES;
  }
  if (Array.isArray(value)) {
    return value;
  }
  if (typeof value === "string") {
    return value.split(",");
  }
  return [];
}

function positiveInteger(value: unknown, field: string): number {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new BadRequestException({
      code: "PLUGIN_USER_TEMP_AUTH_INVALID_LEGACY_USER_ID",
      message: `${field} must be a positive integer.`
    });
  }
  return parsed;
}

function parseRunKey(value: unknown): string {
  const runKey = typeof value === "string" ? value.trim() : "";
  if (!/^[a-zA-Z0-9._:-]{8,120}$/.test(runKey)) {
    throw new BadRequestException({
      code: "PLUGIN_USER_TEMP_AUTH_INVALID_RUN_KEY",
      message: "runKey must be 8-120 characters of letters, numbers, dot, underscore, colon, or dash."
    });
  }
  return runKey;
}

function parseRole(value: unknown): "admin" | "manager" | null {
  if (value === undefined || value === null || value === "") {
    return null;
  }
  if (typeof value !== "string" || !ALLOWED_ROLES.has(value)) {
    throw new BadRequestException({
      code: "PLUGIN_USER_TEMP_AUTH_ROLE_NOT_ALLOWED",
      message: "Temporary authorization role is not allowlisted."
    });
  }
  return value as "admin" | "manager";
}

function parseTtlSeconds(value: unknown, maxTtlSeconds: number): number {
  const parsed = value === undefined ? maxTtlSeconds : Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0 || parsed > maxTtlSeconds) {
    throw new BadRequestException({
      code: "PLUGIN_USER_TEMP_AUTH_INVALID_TTL",
      message: `ttlSeconds must be a positive integer no greater than ${maxTtlSeconds}.`
    });
  }
  return parsed;
}

function parseReason(value: unknown): string | null {
  if (value === undefined || value === null || value === "") {
    return null;
  }
  if (typeof value !== "string" || value.length > MAX_REASON_LENGTH) {
    throw new BadRequestException({
      code: "PLUGIN_USER_TEMP_AUTH_INVALID_REASON",
      message: `reason must be a string no longer than ${MAX_REASON_LENGTH} characters.`
    });
  }
  return value;
}

function splitCsv(value: string): string[] {
  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function isUnsafeWildcard(route: string): boolean {
  return route === "*" || route === "/*" || route === "/*/*";
}

function throwTemporaryAuthorizationRouteNotAllowed(): never {
  throw new BadRequestException({
    code: "PLUGIN_USER_TEMP_AUTH_ROUTE_NOT_ALLOWED",
    message: "Temporary authorization route is not allowlisted."
  });
}

function safeEqual(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}

function isGrantState(value: unknown): value is PluginUserTemporaryAuthorizationGrantState {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const state = value as Partial<PluginUserTemporaryAuthorizationGrantState>;
  return (
    Number.isInteger(state.legacyUserId) &&
    typeof state.runKey === "string" &&
    typeof state.grantedAt === "string" &&
    typeof state.expiresAt === "string" &&
    Array.isArray(state.routes) &&
    state.routes.every(
      (route) =>
        route &&
        typeof route === "object" &&
        typeof route.route === "string" &&
        typeof route.itemExisted === "boolean" &&
        typeof route.assignmentExisted === "boolean"
    ) &&
    (state.role === null ||
      (Boolean(state.role) &&
        typeof state.role === "object" &&
        (state.role.role === "admin" || state.role.role === "manager") &&
        typeof state.role.assignmentExisted === "boolean"))
  );
}
