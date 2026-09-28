import { Body, Controller, Get, Headers, HttpException, HttpStatus, Post } from "@nestjs/common";
import { loadConfig } from "./config.js";
import { TokenIssuanceService } from "./token-issuance.service.js";
import { IdentitySessionRepository } from "./identity-session.repository.js";
import { LegacyIdentityReader } from "./legacy-identity.reader.js";

@Controller("internal/auth")
export class InternalAuthController {
  private readonly config = loadConfig();

  constructor(private readonly tokenIssuance: TokenIssuanceService, private readonly sessions: IdentitySessionRepository, private readonly legacyReader: LegacyIdentityReader) {}

  @Get("device-sn/readiness")
  async deviceSnReadiness(@Headers("x-identity-internal-token") token: string | undefined) {
    this.assertInternalToken(token);
    const [sessionSchema, legacySchema] = await Promise.all([this.sessions.deviceSnReadiness(), this.legacyReader.deviceSnReadiness()]);
    return { ready: this.config.tokenIssuance.enabled && sessionSchema && legacySchema, sessionSchema, legacySchema };
  }

  @Post("issue-user-token")
  issueUserToken(
    @Headers("x-identity-internal-token") token: string | undefined,
    @Body() body: unknown,
    @Headers("x-forwarded-for") forwardedFor?: string,
    @Headers("user-agent") userAgent?: string
  ) {
    this.assertInternalToken(token);

    return this.tokenIssuance.issueLegacyUserToken(body, {
      ip: firstForwardedIp(forwardedFor),
      userAgent: userAgent ?? null
    });
  }

  private assertInternalToken(token: string | undefined): void {
    const configuredToken = this.config.tokenIssuance.internalToken;
    if (!configuredToken) {
      throw new HttpException(
        {
          code: "INTERNAL_TOKEN_NOT_CONFIGURED",
          message: "Internal API token is required before issuing user tokens."
        },
        HttpStatus.SERVICE_UNAVAILABLE
      );
    }
    if (token !== configuredToken) {
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

function firstForwardedIp(value: string | undefined): string | null {
  return value?.split(",")[0]?.trim() || null;
}
