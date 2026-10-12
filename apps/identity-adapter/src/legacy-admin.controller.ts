import { BadRequestException, Body, Controller, Headers, Post, Req, UnauthorizedException } from "@nestjs/common";
import { timingSafeEqual } from "node:crypto";
import { NativeRequest } from "./native-identity.service.js";
import { LegacyAdminService } from "./legacy-admin.service.js";

@Controller("internal/legacy-admin")
export class LegacyAdminController {
  constructor(private readonly admin:LegacyAdminService){}
  @Post() async rpc(@Headers("x-identity-internal-token") key:string|undefined,@Body() body:{operation?:unknown;payload?:unknown;accessToken?:unknown;permissionName?:unknown}){
    this.internal(key);const payload=body?.payload&&typeof body.payload==="object"?body.payload as Record<string,unknown>:{};
    const request:NativeRequest={headers:{authorization:typeof body?.accessToken==="string"?`Bearer ${body.accessToken}`:undefined,"idempotency-key":typeof payload.idempotencyKey==="string"?payload.idempotencyKey:undefined,"x-identity-admin-route":typeof body?.permissionName==="string"?body.permissionName:undefined},body:payload};
    switch(body?.operation){
      case "invitation-list":return this.admin.invitations(request);
      case "invitation-create":request.body={...payload,role:payload.auth_item_name??payload.role};return this.admin.createInvitation(request);
      case "invitation-quota":return this.admin.quota();
      case "trial-create":return this.admin.trial({claimId:String(payload.businessInfoId??payload.claimId??"")});
      case "rbac-snapshot":return this.admin.snapshot(request);
      case "rbac-mutate":return this.admin.mutateRbac({...request,body:normalizeMutation(payload)});
      case "user-list":case "user-view":case "user-create":case "user-delete":case "user-activate":return this.admin.users(request,body.operation);
      default:throw new BadRequestException("Unknown administration operation");
    }
  }
  @Post("policy") policy(@Headers("x-identity-internal-token") key:string|undefined){this.internal(key);return this.admin.policy();}
  @Post("invitation-list") list(@Headers("x-identity-internal-token") key:string|undefined,@Req() request:NativeRequest){this.internal(key);return this.admin.invitations(request);}
  @Post("invitation-create") create(@Headers("x-identity-internal-token") key:string|undefined,@Req() request:NativeRequest){this.internal(key);return this.admin.createInvitation(request);}
  @Post("invitation-quota") quota(@Headers("x-identity-internal-token") key:string|undefined){this.internal(key);return this.admin.quota();}
  @Post("trial-create") trial(@Headers("x-identity-internal-token") key:string|undefined,@Body() body:unknown){this.internal(key);return this.admin.trial(body);}
  @Post("rbac-snapshot") snapshot(@Headers("x-identity-internal-token") key:string|undefined,@Req() request:NativeRequest){this.internal(key);return this.admin.snapshot(request);}
  @Post("rbac-mutate") mutate(@Headers("x-identity-internal-token") key:string|undefined,@Req() request:NativeRequest){this.internal(key);return this.admin.mutateRbac(request);}
  private internal(key:string|undefined){const expected=this.admin.config.tokenIssuance.internalToken;if(this.admin.config.dataSource!=="identity"||!key||!expected||Buffer.byteLength(key)!==Buffer.byteLength(expected)||!timingSafeEqual(Buffer.from(key),Buffer.from(expected)))throw new UnauthorizedException();}
}
function normalizeMutation(payload:Record<string,unknown>){const actions:Record<string,string>={"add-item":"item-put","update-item":"item-put","remove-item":"item-remove","add-rule":"rule-put","update-rule":"rule-put","remove-rule":"rule-remove","add-child":"edge-add","remove-child":"edge-remove","remove-children":"edges-remove",assign:"assign",revoke:"revoke","revoke-all":"revoke-all"};const nested=(payload.item??payload.rule) as Record<string,unknown>|undefined;return {...payload,...nested,operation:actions[String(payload.action)]??payload.operation,name:nested?.name??payload.name??payload.role_name,oldName:payload.oldName??payload.old_name,userId:payload.userId??(payload.user_id===undefined?undefined:Number(payload.user_id)),data:nested?.dataBase64??nested?.data??payload.dataBase64??payload.data};}

@Controller("internal/identity/policy-graph")
export class LegacyPolicyController {
  constructor(private readonly admin:LegacyAdminService){}
  @Post() async policy(@Headers("x-identity-internal-token") key:string|undefined){const expected=this.admin.config.iam.internalToken;if(this.admin.config.dataSource!=="identity"||!key||!expected||Buffer.byteLength(key)!==Buffer.byteLength(expected)||!timingSafeEqual(Buffer.from(key),Buffer.from(expected)))throw new UnauthorizedException();return {data:await this.admin.policy()};}
}
