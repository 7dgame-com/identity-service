import { Body, Controller, Headers, HttpCode, Inject, Post, UnauthorizedException } from "@nestjs/common";
import { timingSafeEqual } from "node:crypto";
import { AppleIdentityService } from "./apple-identity.service.js";

@Controller("internal/apple")
export class AppleIdentityController {
  constructor(@Inject(AppleIdentityService) private readonly apple:AppleIdentityService) {}
  @Post("resolve") @HttpCode(200) resolve(@Headers("x-identity-internal-token") token:string|undefined,@Body() body:unknown) {this.authorize(token);return this.apple.resolve(body);}
  @Post("create") @HttpCode(200) create(@Headers("x-identity-internal-token") token:string|undefined,@Body() body:unknown) {this.authorize(token);return this.apple.complete("create",body);}
  @Post("link") @HttpCode(200) link(@Headers("x-identity-internal-token") token:string|undefined,@Body() body:unknown) {this.authorize(token);return this.apple.complete("link",body);}
  private authorize(token?:string) {
    const expected=this.apple.config.tokenIssuance.internalToken;
    if(!expected||!token)throw new UnauthorizedException();
    const a=Buffer.from(expected),b=Buffer.from(token);if(a.length!==b.length||!timingSafeEqual(a,b))throw new UnauthorizedException();
  }
}
