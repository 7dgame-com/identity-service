import { BadRequestException, Injectable, NotFoundException, Optional, UnauthorizedException } from "@nestjs/common";
import { createHash } from "node:crypto";
import { z } from "zod";
import { NativeIdentityService } from "./native-identity.service.js";
import { NativeQrcodeRepository } from "./native-qrcode.repository.js";
import { NativeQrcodeService, normalizeLoginCode } from "./native-qrcode.service.js";
import { IdentitySessionRepository } from "./identity-session.repository.js";
import { TokenIssuanceService, type AuthTokenResponse, type RequestContext } from "./token-issuance.service.js";
import { validateFrontendDomain } from "./login-code-context.js";
import { LegacyRefreshGraphRepository } from "./legacy-refresh-graph.repository.js";
import { LegacyRefreshCredentialRepository } from "./legacy-refresh-credential.repository.js";

const loginSchema=z.object({key:z.string().min(1).max(4096),operation:z.enum(["redeem","context"])}).strict();
const refreshSchema=z.object({refreshToken:z.string().min(1).max(4096),allowLoginCode:z.boolean(),consumer:z.enum(["server","a1"]).optional(),sourceEndpoint:z.enum(["/v1/auth/refresh","/v1/common/report","/v2/auth/refresh-token"]).optional()}).strict();

@Injectable()
export class Yii3CompatibilityService {
  constructor(private readonly native:NativeIdentityService,private readonly repository:NativeQrcodeRepository,
    private readonly codes:NativeQrcodeService,private readonly sessions:IdentitySessionRepository,private readonly tokens:TokenIssuanceService,
    @Optional() private readonly legacyCredentials?:LegacyRefreshCredentialRepository,
    @Optional() private readonly legacyGraph?:LegacyRefreshGraphRepository){}

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
    if(parsed.data.sourceEndpoint && (parsed.data.consumer==="a1" ? parsed.data.sourceEndpoint==="/v2/auth/refresh-token" : parsed.data.consumer!==undefined || parsed.data.sourceEndpoint==="/v1/common/report"))throw new BadRequestException("Invalid trusted consumer response endpoint.");
    if(parsed.data.consumer==="a1"&&parsed.data.allowLoginCode)throw new BadRequestException("A1 refresh cannot redeem login codes.");
    const raw=parsed.data.refreshToken.trim();
    const credential=parsed.data.allowLoginCode?(normalizeLoginCode(raw)||raw):raw;
    // Check the raw form as well: wrapping a known revoked refresh must not hide
    // its credential type. Stored refresh rows retain that classification.
    const knownRaw=await this.sessions.hasRefreshToken(raw)||!!(this.legacyCredentials&&await this.legacyCredentials.hasCredential(raw))||!!(this.legacyGraph&&await this.legacyGraph.hasCredential(raw));
    const known=knownRaw||(credential!==raw&&(await this.sessions.hasRefreshToken(credential)||!!(this.legacyCredentials&&await this.legacyCredentials.hasCredential(credential))||!!(this.legacyGraph&&await this.legacyGraph.hasCredential(credential))));
    if(known){
      const refreshToken=knownRaw?raw:credential, protocol=await this.legacyGraph?.protocol(refreshToken);
      if(parsed.data.consumer==="a1")return this.response(await (parsed.data.sourceEndpoint
        ?this.tokens.refresh({refreshToken},context,"a1",parsed.data.sourceEndpoint==="/v1/common/report"?"/v1/common/report":"/v1/auth/refresh")
        :this.tokens.refresh({refreshToken},context,"a1")));
      return this.response(await (protocol==="yii3" ? this.tokens.refresh({refreshToken},context,parsed.data.consumer??"yii3") : this.tokens.refresh({refreshToken},context)));
    }
    if(!parsed.data.allowLoginCode||credential.startsWith("dsn_"))throw new UnauthorizedException("Refresh token is invalid.");
    const response=await this.loginCode({key:credential,operation:"redeem"},context);
    if(!("authTokens" in response))throw new UnauthorizedException("Refresh token is invalid.");
    return response;
  }

  private assertEnabled(){if(!this.native.enabled)throw new NotFoundException();}
  private async response(result:AuthTokenResponse){
    const subject=await this.native.verify(result.token.accessToken);
    return {...(result.legacyResponse?{legacyResponse:result.legacyResponse}:{}),authTokens:result.token,subject:"authContext" in subject?{...subject,...subject.authContext}:subject};
  }
}

/** Match y1's stored host contract; metadata never supplies a JWT audience. */
function frontendDomain(value:unknown):string|null {
  if(value===undefined||value===null)return null;
  const domain=validateFrontendDomain(value);if(domain)return domain;
  throw new UnauthorizedException("Login code context is invalid.");
}
