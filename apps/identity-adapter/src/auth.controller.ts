import { Body, Controller, Headers, Post, Req } from "@nestjs/common";
import { TokenIssuanceService } from "./token-issuance.service.js";

interface ClientIpRequest {
  ip?: string;
  socket?: { remoteAddress?: string | null };
}

@Controller("v1/auth")
export class AuthController {
  constructor(private readonly tokenIssuance: TokenIssuanceService) {}

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
  refresh(
    @Body() body: unknown,
    @Req() request: ClientIpRequest,
    @Headers("user-agent") userAgent?: string
  ) {
    return this.tokenIssuance.refresh(body, {
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
  const candidate = request.ip ?? request.socket?.remoteAddress ?? null;
  if (!candidate) return null;

  const normalized = candidate.trim();
  if (!normalized) return null;
  return normalized.startsWith("::ffff:") ? normalized.slice("::ffff:".length) : normalized;
}
