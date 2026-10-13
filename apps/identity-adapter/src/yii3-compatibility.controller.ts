import { refreshHeaderContext } from "./refresh-request-context.js";
import { Body, Controller, Headers, Post, Req, UnauthorizedException } from "@nestjs/common";
import { timingSafeEqual } from "node:crypto";
import { clientIpFromRequest } from "./auth.controller.js";
import { loadConfig } from "./config.js";
import { Yii3CompatibilityService } from "./yii3-compatibility.service.js";

@Controller("internal/yii3")
export class Yii3CompatibilityController {
  private readonly config=loadConfig();
  constructor(private readonly service:Yii3CompatibilityService){}
  @Post("login-code") loginCode(@Headers("x-identity-internal-token") key:string|undefined,@Body() body:unknown,
    @Req() request:{rawHeaders?:string[];ip?:string;socket?:{remoteAddress?:string|null}},@Headers("user-agent") userAgent?:string){
    this.authorize(key);return this.service.loginCode(body,{ip:clientIpFromRequest(request),userAgent});
  }
  @Post("refresh") refresh(@Headers("x-identity-internal-token") key:string|undefined,@Body() body:unknown,
    @Req() request:{rawHeaders?:string[];ip?:string;socket?:{remoteAddress?:string|null}},@Headers("user-agent") userAgent?:string,
    @Headers("idempotency-key") idempotencyKey?:string){
    this.authorize(key);return this.service.refresh(body,{ip:clientIpFromRequest(request),userAgent,idempotencyKey,...refreshHeaderContext(idempotencyKey,request)});
  }
  private authorize(key:string|undefined){
    const expected=this.config.tokenIssuance.internalToken;
    if(this.config.dataSource!=="identity"||!expected||Buffer.byteLength(expected)<32||!key||Buffer.byteLength(key)!==Buffer.byteLength(expected)
      ||!timingSafeEqual(Buffer.from(key),Buffer.from(expected)))throw new UnauthorizedException();
  }
}
