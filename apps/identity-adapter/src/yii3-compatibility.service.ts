import { BadRequestException, Injectable, NotFoundException, UnauthorizedException } from "@nestjs/common";
import { createHash } from "node:crypto";
import { z } from "zod";
import { NativeIdentityService } from "./native-identity.service.js";
import { NativeQrcodeRepository } from "./native-qrcode.repository.js";
import { NativeQrcodeService, normalizeLoginCode } from "./native-qrcode.service.js";
import { IdentitySessionRepository } from "./identity-session.repository.js";
import { TokenIssuanceService, type AuthTokenResponse, type RequestContext } from "./token-issuance.service.js";
import { validateFrontendDomain } from "./login-code-context.js";

const loginSchema=z.object({key:z.string().min(1).max(4096),operation:z.enum(["redeem","context"])}).strict();
const refreshSchema=z.object({refreshToken:z.string().min(1).max(4096),allowLoginCode:z.boolean()}).strict();

@Injectable()
export class Yii3CompatibilityService {
  constructor(private readonly native:NativeIdentityService,private readonly repository:NativeQrcodeRepository,
    private readonly codes:NativeQrcodeService,private readonly sessions:IdentitySessionRepository,private readonly tokens:TokenIssuanceService){}

  async loginCode(input:unknown,context:RequestContext={}) {
    this.assertEnabled();
    const parsed=loginSchema.safeParse(input);if(!parsed.success)throw new BadRequestException("Invalid login code request.");
    const key=normalizeLoginCode(parsed.data.key);
    if(key.startsWith("dsn_"))throw new UnauthorizedException("Login code is invalid or expired.");
    const stored=key?await this.repository.loginCode(createHash("sha256").update(key).digest("hex")):null;
    if(!stored||stored.expiresAt<=Math.floor(Date.now()/1000))throw new UnauthorizedException("Login code is invalid or expired.");
    const domain=frontendDomain(stored.context?.frontend_domain);
    if(parsed.data.operation==="context")return {frontendDomain:domain};
    const result=await this.codes.redeemLoginCode(key,context);
    return {...await this.response(result),frontendDomain:domain};
  }

  async refresh(input:unknown,context:RequestContext={}) {
    this.assertEnabled();
    const parsed=refreshSchema.safeParse(input);if(!parsed.success)throw new BadRequestException("Invalid refresh request.");
    const raw=parsed.data.refreshToken.trim();
    const credential=parsed.data.allowLoginCode?(normalizeLoginCode(raw)||raw):raw;
    // Check the raw form as well: wrapping a known revoked refresh must not hide
    // its credential type. Stored refresh rows retain that classification.
    const knownRaw=await this.sessions.hasRefreshToken(raw);
    const known=knownRaw||(credential!==raw&&await this.sessions.hasRefreshToken(credential));
    if(known)return this.response(await this.tokens.refresh({refreshToken:knownRaw?raw:credential},context));
    if(!parsed.data.allowLoginCode||credential.startsWith("dsn_"))throw new UnauthorizedException("Refresh token is invalid.");
    const response=await this.loginCode({key:credential,operation:"redeem"},context);
    if(!("authTokens" in response))throw new UnauthorizedException("Refresh token is invalid.");
    return response;
  }

  private assertEnabled(){if(!this.native.enabled)throw new NotFoundException();}
  private async response(result:AuthTokenResponse){
    const subject=await this.native.verify(result.token.accessToken);
    return {authTokens:result.token,subject:"authContext" in subject?{...subject,...subject.authContext}:subject};
  }
}

/** Match y1's stored host contract; metadata never supplies a JWT audience. */
function frontendDomain(value:unknown):string|null {
  if(value===undefined||value===null)return null;
  const domain=validateFrontendDomain(value);if(domain)return domain;
  throw new UnauthorizedException("Login code context is invalid.");
}
