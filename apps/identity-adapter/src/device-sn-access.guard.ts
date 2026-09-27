import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from "@nestjs/common";
import { denyDeviceSnCredentialDerivation } from "./device-sn-source.js";
import { JwtIssuerService } from "./jwt-issuer.service.js";
import { LegacyIdentityReader } from "./legacy-identity.reader.js";

/** Applies to every HTTP surface, including legacy-proxy account endpoints. */
@Injectable()
export class DeviceSnAccessGuard implements CanActivate {
  constructor(private readonly jwtIssuer: JwtIssuerService, private readonly legacyReader: LegacyIdentityReader) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<{
      headers: Record<string, string | undefined>; path?: string; url?: string; method: string; body?: Record<string, unknown>;
    }>();
    // Express routes are case-insensitive by default; the credential boundary must match them.
    const path = (request.path ?? request.url ?? "").split("?")[0].replace(/\/+$/, "").toLowerCase();
    const tokens = [request.headers.authorization?.match(/^Bearer\s+(.+)$/i)?.[1]];
    if (path === "/internal/iam/plugin/verify-token" && typeof request.body?.token === "string") tokens.push(request.body.token);
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
      if (path === "/authorize" || path === "/token" ||
        (request.method !== "GET" && /^\/v1\/(?:password|email)(?:\/|$)/.test(path)) ||
        ["/v1/auth/register", "/v1/wechat/register", "/v1/plugin-user/register", "/v1/plugin-user/register-send-code"].includes(path)) {
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
