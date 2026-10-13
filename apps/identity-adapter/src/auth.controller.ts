import { refreshHeaderContext } from "./refresh-request-context.js";
import { Body, Controller, Headers, Optional, Post, Req } from "@nestjs/common";
import { TokenIssuanceService } from "./token-issuance.service.js";
import { NativeQrcodeService, normalizeLoginCode } from "./native-qrcode.service.js";
import { loadConfig } from "./config.js";

interface ClientIpRequest { rawHeaders?:string[]; ip?: string; socket?: { remoteAddress?: string | null }; }

@Controller("v1/auth")
export class AuthController {
  constructor(private readonly tokenIssuance: TokenIssuanceService, @Optional() private readonly qrcode?: NativeQrcodeService) {}

  @Post("login")
  login(
    @Body() body: unknown,
    @Req() request: ClientIpRequest,
    @Headers("user-agent") userAgent?: string
  ) {
    return this.tokenIssuance.login(body, {
      ip: clientIpFromRequest(request),
      userAgent: userAgent ?? null
    });
  }

  @Post("refresh")
  async refresh(
    @Body() body: unknown,
    @Req() request: ClientIpRequest,
    @Headers("user-agent") userAgent?: string,
    @Headers("idempotency-key") idempotencyKey?: string
  ) {
    const requestContext=refreshHeaderContext(idempotencyKey,request);
    const candidate = (body as {refreshToken?:unknown})?.refreshToken;
    if (loadConfig().dataSource === "identity" && typeof candidate === "string"
      && (candidate.startsWith("web_") || /[?&]web_/.test(candidate))) {
      const normalized = normalizeLoginCode(candidate);
      const knownRaw = await this.tokenIssuance.hasRefreshCredential(candidate);
      if (knownRaw || (normalized !== candidate && normalized && await this.tokenIssuance.hasRefreshCredential(normalized))) {
        return this.tokenIssuance.publicRefresh({ refreshToken: knownRaw ? candidate : normalized }, {
          idempotencyKey, ...requestContext, ip: clientIpFromRequest(request), userAgent: userAgent ?? null });
      }
      if (!this.qrcode) throw new Error("Native QR service is not available");
      return this.qrcode.redeemLoginCode(candidate, {idempotencyKey,...requestContext,ip:clientIpFromRequest(request),userAgent:userAgent??null});
    }
    return this.tokenIssuance.publicRefresh(body, {
      idempotencyKey,
      ...requestContext,
      ip: clientIpFromRequest(request),
      userAgent: userAgent ?? null
    });
  }

  @Post("logout")
  logout(@Body() body: unknown) {
    return this.tokenIssuance.logout(body);
  }
}

export function clientIpFromRequest(request: ClientIpRequest): string | null {
  const candidate = request.ip ?? request.socket?.remoteAddress;
  if (!candidate?.trim()) return null;
  const normalized = candidate.trim();
  return normalized.startsWith("::ffff:") ? normalized.slice(7) : normalized;
}
