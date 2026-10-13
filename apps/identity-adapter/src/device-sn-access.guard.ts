import { CanActivate, ExecutionContext, Injectable, Optional, UnauthorizedException } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { denyDeviceSnCredentialDerivation } from "./device-sn-source.js";
import { JwtIssuerService } from "./jwt-issuer.service.js";
import { LegacyIdentityReader } from "./legacy-identity.reader.js";
import { loadConfig } from "./config.js";
import { activationProbe } from "./identity-activation.guard.js";

/** Applies to every HTTP surface, including legacy-proxy account endpoints. */
@Injectable()
export class DeviceSnAccessGuard implements CanActivate {
  private readonly explicit = loadConfig().activationMode === "explicit";
  constructor(private readonly jwtIssuer: JwtIssuerService, private readonly legacyReader: LegacyIdentityReader,
    @Optional() private readonly reflector?: Reflector) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    if (this.explicit && this.reflector?.getAllAndOverride<boolean>(activationProbe, [context.getHandler(), context.getClass()])) return true;
    const request = context.switchToHttp().getRequest<{
      headers: Record<string, string | undefined>; path?: string; url?: string; method: string; body?: Record<string, unknown>;
    }>();
    // Express routes are case-insensitive by default; the credential boundary must match them.
    const path = (request.path ?? request.url ?? "").split("?")[0].replace(/\/+$/, "").toLowerCase();
    const tokens = [request.headers.authorization?.match(/^Bearer\s+(.+)$/i)?.[1]];
    if (["/internal/iam/plugin/verify-token", "/internal/auth/verify-access-token"].includes(path) && typeof request.body?.token === "string") tokens.push(request.body.token);
    if (path === "/internal/legacy-admin" && typeof request.body?.accessToken === "string") tokens.push(request.body.accessToken);
    for (const token of tokens) {
      if (!token || !hasDeviceSource(token)) continue;
      let claims;
      try { claims = this.jwtIssuer.verifyAccessToken(token); }
      catch { throw new UnauthorizedException({ code: "DEVICE_SN_SOURCE_INVALID", message: "Device access token is invalid." }); }
      if (!claims.deviceSnId || claims.authMethod !== "device_sn") {
        throw new UnauthorizedException({ code: "DEVICE_SN_SOURCE_INVALID", message: "Device access token source is incomplete." });
      }
      // Disabled SN access may finish its <=3h lifetime; account elevation/deletion is immediate.
      await this.legacyReader.assertDeviceSnAuthorized(claims.deviceSnId, claims.uid, false);
      if (path === "/authorize" || path === "/token" || path === "/v1/tools/user-linked" ||
        (request.method !== "GET" && /^\/v1\/(?:password|email)(?:\/|$)/.test(path)) ||
        (request.method !== "GET" && /^\/v1\/(?:person|people)(?:\/|$)/.test(path)) ||
        ["/v1/auth/register", "/v1/wechat/register", "/v1/wechat/binding", "/v1/plugin-user/register", "/v1/plugin-user/register-send-code",
          "/v1/plugin-user/create-user", "/v1/plugin-user/update-user", "/v1/plugin-user/batch-create-users", "/v1/plugin-user/change-role",
          "/v1/plugin-campus/users/password", "/internal/apple/create", "/internal/apple/link", "/internal/legacy-admin"].includes(path)) {
        denyDeviceSnCredentialDerivation();
      }
    }
    return true;
  }
}

function hasDeviceSource(token: string): boolean {
  try {
    const payload = JSON.parse(Buffer.from(token.split(".")[1] ?? "", "base64url").toString("utf8"));
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) return false;
    // This only selects additional validation. Authorization always uses verified claims above.
    return "auth_method" in payload || "device_sn_id" in payload;
  } catch { return false; }
}
