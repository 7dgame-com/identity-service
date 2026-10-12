import { Body, Controller, Headers, Post, UnauthorizedException } from "@nestjs/common";
import { timingSafeEqual } from "node:crypto";
import { LegacyEmailLinkService } from "./legacy-email-link.service.js";

@Controller("internal/legacy-email-link")
export class LegacyEmailLinkController {
  constructor(private readonly links:LegacyEmailLinkService){}
  @Post("validate-reset") validate(@Headers("x-identity-internal-token") key:string|undefined,@Body() body:unknown){this.internal(key);return this.links.validateReset(body);}
  @Post("reset") reset(@Headers("x-identity-internal-token") key:string|undefined,@Headers("idempotency-key") requestKey:string|undefined,@Body() body:unknown){this.internal(key);return this.links.reset(body,requestKey);}
  @Post("verify") verify(@Headers("x-identity-internal-token") key:string|undefined,@Headers("idempotency-key") requestKey:string|undefined,@Body() body:unknown){this.internal(key);return this.links.verify(body,requestKey);}
  @Post("request-reset") requestReset(@Headers("x-identity-internal-token") key:string|undefined,@Body() body:unknown){this.internal(key);return this.links.requestLink("reset",body);}
  @Post("resend-verification") resend(@Headers("x-identity-internal-token") key:string|undefined,@Body() body:unknown){this.internal(key);return this.links.requestLink("verify",body);}
  @Post("signup") signup(@Headers("x-identity-internal-token") key:string|undefined,@Headers("idempotency-key") requestKey:string|undefined,@Body() body:unknown){this.internal(key);return this.links.signup(body,requestKey);}
  private internal(key:string|undefined){const expected=this.links.config.tokenIssuance.internalToken;if(this.links.config.dataSource!=="identity"||!expected||!key||Buffer.byteLength(key)!==Buffer.byteLength(expected)||!timingSafeEqual(Buffer.from(key),Buffer.from(expected)))throw new UnauthorizedException();}
}
