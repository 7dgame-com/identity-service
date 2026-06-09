import { Body, Controller, Headers, Post } from "@nestjs/common";
import { TokenIssuanceService } from "./token-issuance.service.js";

@Controller("v1/auth")
export class AuthController {
  constructor(private readonly tokenIssuance: TokenIssuanceService) {}

  @Post("login")
  login(
    @Body() body: unknown,
    @Headers("x-forwarded-for") forwardedFor?: string,
    @Headers("user-agent") userAgent?: string
  ) {
    return this.tokenIssuance.login(body, {
      ip: firstForwardedIp(forwardedFor),
      userAgent: userAgent ?? null
    });
  }

  @Post("refresh")
  refresh(
    @Body() body: unknown,
    @Headers("x-forwarded-for") forwardedFor?: string,
    @Headers("user-agent") userAgent?: string
  ) {
    return this.tokenIssuance.refresh(body, {
      ip: firstForwardedIp(forwardedFor),
      userAgent: userAgent ?? null
    });
  }

  @Post("logout")
  logout(@Body() body: unknown) {
    return this.tokenIssuance.logout(body);
  }
}

function firstForwardedIp(value: string | undefined): string | null {
  return value?.split(",")[0]?.trim() || null;
}
