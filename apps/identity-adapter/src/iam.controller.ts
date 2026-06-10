import { Body, Controller, Get, Headers, HttpException, HttpStatus, NotFoundException, Param, Post } from "@nestjs/common";
import { loadConfig } from "./config.js";
import { IamService } from "./iam.service.js";

@Controller("internal/iam")
export class IamController {
  private readonly config = loadConfig();

  constructor(private readonly iam: IamService) {}

  @Get("readiness")
  async readiness() {
    return {
      status: "ok",
      service: "identity-adapter",
      capability: "iam",
      data: await this.iam.readiness()
    };
  }

  @Get("users/:legacyUserId")
  async user(@Headers("x-identity-internal-token") token: string | undefined, @Param("legacyUserId") legacyUserId: string) {
    this.assertEnabledAndAuthorized(token);
    return {
      data: await this.iam.userView(parseLegacyUserId(legacyUserId))
    };
  }

  @Get("users/:legacyUserId/roles")
  async roles(@Headers("x-identity-internal-token") token: string | undefined, @Param("legacyUserId") legacyUserId: string) {
    this.assertEnabledAndAuthorized(token);
    return {
      data: await this.iam.rolesView(parseLegacyUserId(legacyUserId))
    };
  }

  @Get("users/:legacyUserId/permissions")
  async permissions(@Headers("x-identity-internal-token") token: string | undefined, @Param("legacyUserId") legacyUserId: string) {
    this.assertEnabledAndAuthorized(token);
    return {
      data: await this.iam.permissionsView(parseLegacyUserId(legacyUserId))
    };
  }

  @Get("users/:legacyUserId/organizations")
  async organizations(@Headers("x-identity-internal-token") token: string | undefined, @Param("legacyUserId") legacyUserId: string) {
    this.assertEnabledAndAuthorized(token);
    return {
      data: await this.iam.organizationsView(parseLegacyUserId(legacyUserId))
    };
  }

  @Post("plugin/verify-token")
  async pluginVerifyToken(@Headers("x-identity-internal-token") token: string | undefined, @Body() body: unknown) {
    this.assertEnabledAndAuthorized(token);
    return {
      data: await this.iam.pluginVerifyToken(tokenFromBody(body))
    };
  }

  @Get("plugin/me")
  async pluginMe(
    @Headers("x-identity-internal-token") token: string | undefined,
    @Headers("authorization") authorization: string | undefined
  ) {
    this.assertEnabledAndAuthorized(token);
    return {
      data: await this.iam.pluginMe(bearerToken(authorization))
    };
  }

  @Post("reconciliation/run")
  async reconciliationRun(@Headers("x-identity-internal-token") token: string | undefined, @Body() body: unknown) {
    this.assertEnabledAndAuthorized(token);
    return {
      data: await this.iam.reconcile(body)
    };
  }

  @Get("reconciliation/runs/:runKey")
  async reconciliationReport(@Headers("x-identity-internal-token") token: string | undefined, @Param("runKey") runKey: string) {
    this.assertEnabledAndAuthorized(token);
    return {
      data: await this.iam.reconciliationReport(runKey)
    };
  }

  private assertEnabledAndAuthorized(token: string | undefined): void {
    if (!this.config.iam.enabled || this.config.iam.mode === "disabled") {
      throw new NotFoundException({
        code: "IDENTITY_IAM_DISABLED",
        message: "Identity IAM readonly view is disabled."
      });
    }
    if (!this.config.iam.internalToken) {
      throw new HttpException(
        {
          code: "IAM_INTERNAL_TOKEN_NOT_CONFIGURED",
          message: "Internal API token is required before using IAM data views."
        },
        HttpStatus.SERVICE_UNAVAILABLE
      );
    }
    if (token !== this.config.iam.internalToken) {
      throw new HttpException(
        {
          code: "INTERNAL_TOKEN_INVALID",
          message: "Internal service token is invalid."
        },
        HttpStatus.UNAUTHORIZED
      );
    }
  }
}

function parseLegacyUserId(value: string): number {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new HttpException(
      {
        code: "INVALID_LEGACY_USER_ID",
        message: "Legacy user id must be a positive integer."
      },
      HttpStatus.BAD_REQUEST
    );
  }
  return parsed;
}

function tokenFromBody(body: unknown): string | null {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return null;
  }

  const token = (body as Record<string, unknown>).token;
  return typeof token === "string" && token.trim() ? token.trim() : null;
}

function bearerToken(authorization: string | undefined): string | null {
  if (!authorization?.startsWith("Bearer ")) {
    return null;
  }

  return authorization.slice("Bearer ".length).trim();
}
