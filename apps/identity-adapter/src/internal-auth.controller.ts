import { BadRequestException, Body, Controller, Get, Headers, HttpException, HttpStatus, Post, Query, Req } from "@nestjs/common";
import { timingSafeEqual } from "node:crypto";
import { clientIpFromRequest } from "./auth.controller.js";
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
    return { ready: this.config.tokenIssuance.enabled && sessionSchema && legacySchema, sessionSchema, legacySchema,
      deviceSource: this.config.dataSource === "identity" ? "device-sn-db" : "legacy-db",
      accountSource: this.config.dataSource };
  }

  @Post("issue-user-token")
  issueUserToken(
    @Headers("x-identity-internal-token") token: string | undefined,
    @Body() body: unknown,
    @Req() request: { ip?: string; socket?: { remoteAddress?: string | null } },
    @Headers("user-agent") userAgent?: string
  ) {
    this.assertInternalToken(token);

    return this.tokenIssuance.issueLegacyUserToken(body, {
      ip: clientIpFromRequest(request),
      userAgent: userAgent ?? null
    });
  }

  @Get("device-sn/accounts")
  deviceSnAccounts(@Headers("x-identity-internal-token") token: string | undefined,
    @Query("q") q: unknown, @Query("page") page: unknown, @Query("pageSize") pageSize: unknown) {
    this.assertInternalToken(token);
    const positive = (value: unknown, fallback: number, max: number) => {
      if (value === undefined) return fallback;
      if (typeof value !== "string" || !/^[1-9][0-9]*$/.test(value) || !Number.isSafeInteger(Number(value)) || Number(value) > max) throw new BadRequestException("Invalid account pagination.");
      return Number(value);
    };
    if (q !== undefined && (typeof q !== "string" || q.length > 200)) throw new BadRequestException("Invalid account search.");
    return this.legacyReader.listDeviceSnAccounts((q ?? "") as string, positive(page, 1, 1000000), positive(pageSize, 20, 100));
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
    if (!token || Buffer.byteLength(token) !== Buffer.byteLength(configuredToken)
      || !timingSafeEqual(Buffer.from(token), Buffer.from(configuredToken))) {
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
