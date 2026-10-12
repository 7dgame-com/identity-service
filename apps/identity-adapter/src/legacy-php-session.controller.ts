import { Body, Controller, Headers, Post, UnauthorizedException } from "@nestjs/common";
import { timingSafeEqual } from "node:crypto";
import { NativeIdentityService } from "./native-identity.service.js";
import { TokenIssuanceService } from "./token-issuance.service.js";

@Controller("internal/legacy-php-session")
export class LegacyPhpSessionController {
  constructor(private readonly native:NativeIdentityService,private readonly tokens:TokenIssuanceService){}
  @Post("exchange") exchange(@Headers("x-identity-internal-token") key:string|undefined,@Body() body:unknown){
    const expected=this.native.config.tokenIssuance.internalToken;
    if(!this.native.enabled||!expected||!key||Buffer.byteLength(key)!==Buffer.byteLength(expected)||!timingSafeEqual(Buffer.from(key),Buffer.from(expected)))throw new UnauthorizedException();
    return this.tokens.exchangeLegacyPhpSession(body);
  }
}
