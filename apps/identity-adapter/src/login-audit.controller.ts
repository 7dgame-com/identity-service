import {
  Body,
  Controller,
  Get,
  Headers,
  HttpCode,
  HttpException,
  HttpStatus,
  Inject,
  NotFoundException,
  Param,
  Post
} from "@nestjs/common";
import { loadConfig } from "./config.js";
import { LoginAuditService } from "./login-audit.service.js";

@Controller("internal")
export class LoginAuditController {
  private readonly config = loadConfig();

  constructor(@Inject(LoginAuditService) private readonly loginAudit: LoginAuditService) {}

  @Post("login-events")
  @HttpCode(202)
  async record(@Headers("x-identity-internal-token") token: string | undefined, @Body() body: unknown) {
    this.assertEnabledAndAuthorized(token);
    return this.loginAudit.record(body);
  }

  @Get("login-audit/users/:legacyUserId")
  async userAudit(@Headers("x-identity-internal-token") token: string | undefined, @Param("legacyUserId") legacyUserId: string) {
    this.assertEnabledAndAuthorized(token);

    const parsedId = Number(legacyUserId);
    if (!Number.isInteger(parsedId) || parsedId <= 0) {
      throw new HttpException(
        {
          code: "INVALID_USER_ID",
          message: "User id must be a positive integer."
        },
        HttpStatus.BAD_REQUEST
      );
    }

    return {
      data: await this.loginAudit.getUserAudit(parsedId)
    };
  }

  private assertEnabledAndAuthorized(token: string | undefined): void {
    if (!this.config.loginAudit.enabled) {
      throw new NotFoundException({
        code: "LOGIN_AUDIT_DISABLED",
        message: "Login audit is disabled."
      });
    }
    if (!this.config.loginAudit.internalToken) {
      throw new HttpException(
        {
          code: "LOGIN_AUDIT_TOKEN_NOT_CONFIGURED",
          message: "Internal API token is required before enabling login audit."
        },
        HttpStatus.SERVICE_UNAVAILABLE
      );
    }
    if (token !== this.config.loginAudit.internalToken) {
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
