import { Body, Controller, Get, Headers, HttpCode, HttpException, HttpStatus, Post, Query, Res } from "@nestjs/common";
import { JwtIssuerService } from "./jwt-issuer.service.js";
import { OidcService } from "./oidc.service.js";

interface MinimalHttpResponse {
  redirect(status: number, url: string): void;
  status(status: number): { json(body: unknown): void };
}

@Controller()
export class OidcController {
  constructor(
    private readonly oidc: OidcService,
    private readonly jwtIssuer: JwtIssuerService
  ) {}

  @Get(".well-known/openid-configuration")
  discovery() {
    return this.oidc.discovery();
  }

  @Get("internal/oidc/readiness")
  readiness(@Headers("x-identity-internal-token") token: string | undefined) {
    this.oidc.assertInternalToken(token);
    return {
      status: "ok",
      service: "identity-adapter",
      capability: "oidc",
      data: this.oidc.readiness()
    };
  }

  @Get("authorize")
  async authorize(
    @Query() query: Record<string, unknown>,
    @Headers("authorization") authorization: string | undefined,
    @Res() response: MinimalHttpResponse
  ) {
    const result = await this.oidc.authorize(query, authorization);
    if (result.responseMode === "json") {
      response.status(200).json({
        code: result.code,
        state: result.state,
        redirect_uri: result.redirectUri
      });
      return;
    }

    response.redirect(302, result.redirectUrl);
  }

  @Post("token")
  @HttpCode(200)
  token(@Body() body: unknown, @Headers("authorization") authorization?: string) {
    return this.oidc.token(body, authorization);
  }

  @Get("logout")
  async logoutGet(@Query() query: Record<string, unknown>, @Res() response: MinimalHttpResponse) {
    const result = await this.oidc.logout(query);
    if (result.redirectUrl) {
      response.redirect(302, result.redirectUrl);
      return;
    }

    response.status(200).json({ success: true, message: "logout" });
  }

  @Post("logout")
  @HttpCode(200)
  async logoutPost(@Body() body: unknown) {
    const result = await this.oidc.logout(body);
    return {
      success: true,
      message: "logout",
      redirectUrl: result.redirectUrl
    };
  }

  @Get("userinfo")
  userinfo(@Headers("authorization") authorization?: string) {
    const token = bearerToken(authorization);
    if (!token) {
      throw new HttpException(
        {
          code: "AUTHORIZATION_REQUIRED",
          message: "Bearer token is required for userinfo."
        },
        HttpStatus.UNAUTHORIZED
      );
    }

    try {
      const claims = this.jwtIssuer.verifyAccessToken(token);
      return {
        sub: String(claims.uid),
        uid: claims.uid,
        preferred_username: claims.username,
        roles: claims.roles
      };
    } catch {
      throw new HttpException(
        {
          code: "INVALID_ACCESS_TOKEN",
          message: "Bearer token is invalid for userinfo."
        },
        HttpStatus.UNAUTHORIZED
      );
    }
  }
}

function bearerToken(value: string | undefined): string | null {
  if (!value?.startsWith("Bearer ")) {
    return null;
  }
  return value.slice("Bearer ".length).trim() || null;
}
