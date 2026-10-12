import { Body, Controller, Headers, Optional, Post } from "@nestjs/common";
import { TokenIssuanceService } from "./token-issuance.service.js";
import { NativeQrcodeService } from "./native-qrcode.service.js";
import { loadConfig } from "./config.js";

@Controller("v1/auth")
export class AuthController {
  constructor(private readonly tokenIssuance: TokenIssuanceService, @Optional() private readonly qrcode?: NativeQrcodeService) {}

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
    @Headers("user-agent") userAgent?: string,
    @Headers("idempotency-key") idempotencyKey?: string
  ) {
    const candidate = (body as {refreshToken?:unknown})?.refreshToken;
    if (loadConfig().dataSource === "identity" && typeof candidate === "string"
      && (candidate.startsWith("web_") || /[?&]web_/.test(candidate))) {
      if (!this.qrcode) throw new Error("Native QR service is not available");
      return this.qrcode.redeemLoginCode(candidate, {idempotencyKey,ip:firstForwardedIp(forwardedFor),userAgent:userAgent??null});
    }
    return this.tokenIssuance.refresh(body, {
      idempotencyKey,
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
