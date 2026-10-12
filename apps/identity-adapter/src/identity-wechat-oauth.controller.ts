import { Body, Controller, Get, Headers, HttpCode, Inject, Param, Post, Query, UnauthorizedException } from "@nestjs/common";
import { timingSafeEqual } from "node:crypto";
import { IdentityWechatOAuthService } from "./identity-wechat-oauth.service.js";

@Controller("internal/wechat-oauth")
export class IdentityWechatOAuthController {
  constructor(@Inject(IdentityWechatOAuthService) private readonly oauth:IdentityWechatOAuthService) {}
  @Get("metadata") metadata(@Headers("x-identity-internal-token") token?:string) { this.authorize(token);return this.oauth.metadata(); }
  @Post("resolve") @HttpCode(200) resolve(@Headers("x-identity-internal-token") token:string|undefined,@Body() body:unknown) { this.authorize(token);return this.oauth.resolve(body); }
  @Post("code") @HttpCode(200) code(@Headers("x-identity-internal-token") token:string|undefined,@Body() body:unknown) { this.authorize(token);return this.oauth.createCode(body); }
  @Post("token") @HttpCode(200) exchange(@Headers("x-identity-internal-token") token:string|undefined,@Body() body:unknown) { this.authorize(token);return this.oauth.token(body); }
  @Post("revoke") @HttpCode(200) revoke(@Headers("x-identity-internal-token") token:string|undefined,@Body() body:unknown) { this.authorize(token);return this.oauth.revoke(body); }
  @Post("userinfo") @HttpCode(200) userinfo(@Headers("x-identity-internal-token") token:string|undefined,@Headers("authorization") authorization?:string) { this.authorize(token);return this.oauth.userinfo(authorization); }
  @Post("user") @HttpCode(200) user(@Headers("x-identity-internal-token") token:string|undefined,@Body() body:{userId?:unknown}) { this.authorize(token);const id=Number(body?.userId);if(!Number.isSafeInteger(id)||id<1)throw new UnauthorizedException();return this.oauth.user(id); }
  @Get("users/:userId/identity") identity(@Headers("x-identity-internal-token") token:string|undefined,@Param("userId") userId:string,@Query("providerAppId") providerAppId?:string) {
    this.authorize(token);return this.oauth.paymentIdentity(userId,providerAppId);
  }
  private authorize(token?:string) { const expected=this.oauth.config.tokenIssuance.internalToken;if(!expected||!token)throw new UnauthorizedException();const a=Buffer.from(expected),b=Buffer.from(token);if(a.length!==b.length||!timingSafeEqual(a,b))throw new UnauthorizedException(); }
}
