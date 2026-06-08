import { Controller, Get, Headers, HttpException, HttpStatus, Inject, Param } from "@nestjs/common";
import { loadConfig } from "./config.js";
import { JwtIssuerService } from "./jwt-issuer.service.js";
import { LegacyIdentityReader } from "./legacy-identity.reader.js";

@Controller()
export class IdentityController {
  private readonly config = loadConfig();

  constructor(
    @Inject(LegacyIdentityReader) private readonly legacyReader: LegacyIdentityReader,
    @Inject(JwtIssuerService) private readonly jwtIssuer: JwtIssuerService
  ) {}

  @Get("jwks.json")
  jwks() {
    const generated = this.jwtIssuer.jwks();
    if (generated.keys.length > 0) {
      return generated;
    }

    try {
      const parsed = JSON.parse(this.config.jwksPublicKeysJson);
      if (Array.isArray(parsed.keys)) {
        return parsed;
      }
    } catch {
      // Fall through to the safe empty JWKS.
    }

    return { keys: [] };
  }

  @Get("userinfo")
  userinfo(@Headers("authorization") authorization?: string) {
    if (!authorization?.startsWith("Bearer ")) {
      throw new HttpException(
        {
          code: "AUTHORIZATION_REQUIRED",
          message: "Bearer token is required for userinfo."
        },
        HttpStatus.UNAUTHORIZED
      );
    }

    throw new HttpException(
      {
        code: "TOKEN_INTROSPECTION_NOT_ACTIVE",
        message: "Stage 3 is readonly. Legacy token introspection is enabled in a later phase."
      },
      HttpStatus.NOT_IMPLEMENTED
    );
  }

  @Get("admin/users/:id")
  async user(@Param("id") id: string) {
    const parsedId = Number(id);
    if (!Number.isInteger(parsedId) || parsedId <= 0) {
      throw new HttpException(
        {
          code: "INVALID_USER_ID",
          message: "User id must be a positive integer."
        },
        HttpStatus.BAD_REQUEST
      );
    }

    const user = await this.legacyReader.getUserById(parsedId);
    if (!user) {
      throw new HttpException(
        {
          code: "USER_NOT_FOUND",
          message: "Legacy user was not found."
        },
        HttpStatus.NOT_FOUND
      );
    }

    return {
      data: user,
      diagnostics: await this.legacyReader.diagnostics()
    };
  }

  @Get("admin/roles")
  async roles() {
    return {
      data: await this.legacyReader.listRoles(),
      diagnostics: await this.legacyReader.diagnostics()
    };
  }

  @Get("admin/organizations")
  async organizations() {
    return {
      data: await this.legacyReader.listOrganizations(),
      diagnostics: await this.legacyReader.diagnostics()
    };
  }
}
