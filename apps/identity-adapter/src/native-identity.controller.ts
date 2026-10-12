import { Body, Controller, Get, Headers, NotFoundException, Param, Post, Query, Req, UnauthorizedException } from "@nestjs/common";
import { timingSafeEqual } from "node:crypto";
import { NativeIdentityService, NativeRequest } from "./native-identity.service.js";

@Controller()
export class NativeIdentityController {
  constructor(private readonly native: NativeIdentityService) {}
  @Get("v1/user/info") info(@Req() request: NativeRequest) { this.enabled(); return this.native.currentInfo(request); }
  @Get("v1/plugin/verify-token") plugin(@Req() request: NativeRequest) { this.enabled(); return this.native.verifyPlugin(request); }
  @Get("v1/plugin-user/me") async me(@Req() request: NativeRequest) {
    this.enabled(); const user=await this.native.actor(request);
    return {id:user.id,username:user.username,nickname:user.nickname??user.username,email:user.email,status:user.status,roles:user.roles};
  }
  @Get("v1/organization/list") organizations(@Req() request:NativeRequest,@Query() query:Record<string,unknown>) { this.enabled(); return this.native.organization(request,"list",query); }
  @Post("v1/organization/create") createOrganization(@Req() request:NativeRequest) {this.enabled();return this.native.organization(request,"create");}
  @Post("v1/organization/update") updateOrganization(@Req() request:NativeRequest) {this.enabled();return this.native.organization(request,"update");}
  @Post("v1/organization/bind-user") bind(@Req() request:NativeRequest) {this.enabled();return this.native.organization(request,"bind-user");}
  @Post("v1/organization/unbind-user") unbind(@Req() request:NativeRequest) {this.enabled();return this.native.organization(request,"unbind-user");}
  @Post("v1/plugin-campus/users/password") campusPassword(@Req() request:NativeRequest) {this.enabled();return this.native.campusPassword(request);}
  @Post("internal/auth/verify-access-token") async verify(@Headers("x-identity-internal-token") key:string|undefined,@Body() body:{token?:unknown}) {
    this.internal(key); if(typeof body?.token!=="string") throw new UnauthorizedException();
    const subject=await this.native.verify(body.token);
    return {success:true,data:"authContext" in subject?{...subject,...subject.authContext}:subject};
  }
  @Get("internal/identity/subjects/:id") async subject(@Headers("x-identity-internal-token") key:string|undefined,@Param("id") id:string) {
    this.internal(key);return {success:true,data:await this.native.subject(validId(id))};
  }
  @Get("internal/identity/organizations/:id/members") async members(@Headers("x-identity-internal-token") key:string|undefined,@Param("id") id:string) {
    this.internal(key);return {success:true,data:await this.native.organizationMembers(validId(id))};
  }
  @Post("internal/identity/authorize") async authorize(@Headers("x-identity-internal-token") key:string|undefined,@Body() body:{legacyUserId?:unknown;permission?:unknown}) {
    this.internal(key); if(typeof body?.permission!=="string" || body.permission.length>256) throw new UnauthorizedException();
    return {success:true,data:{allowed:await this.native.allowed(validId(body.legacyUserId),body.permission)}};
  }
  @Get("internal/identity/events") async events(@Headers("x-identity-internal-token") key:string|undefined,@Query("afterId") after:string|undefined,@Query("limit") limit:string|undefined) {
    this.internal(key);const cursor=Number(after??0); if(!Number.isSafeInteger(cursor)||cursor<0)throw new UnauthorizedException();
    const size=Number(limit??100);if(!Number.isInteger(size)||size<1||size>500)throw new UnauthorizedException();
    return {data:await this.native.events(cursor,size)};
  }
  private enabled(){if(!this.native.enabled)throw new NotFoundException();}
  private internal(key:string|undefined){
    this.enabled();const expected=this.native.config.iam.internalToken;
    if(!expected||!key||Buffer.byteLength(expected)!==Buffer.byteLength(key)||!timingSafeEqual(Buffer.from(expected),Buffer.from(key)))throw new UnauthorizedException();
  }
}
function validId(value:unknown){const id=Number(value);if(!Number.isSafeInteger(id)||id<=0)throw new UnauthorizedException();return id;}
