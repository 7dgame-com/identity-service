import { AdmissionWriter } from "./identity-admission.js";
import { createCipheriv,createDecipheriv,createHash,createHmac,randomBytes } from "node:crypto";
import { BadRequestException,ConflictException,HttpException,Injectable,OnModuleDestroy,ServiceUnavailableException,UnauthorizedException } from "@nestjs/common";
import mysql,{type Pool,type PoolConnection,type RowDataPacket} from "mysql2/promise";
import { z } from "zod";
import { loadConfig } from "./config.js";
import { AccountRegistrationRepository,NativeRegistrationError } from "./account-registration.repository.js";
import { IdentitySessionRepository,hashRefreshToken } from "./identity-session.repository.js";
import { JwtIssuerService } from "./jwt-issuer.service.js";
import { verifyLegacyPassword } from "./legacy-password.js";
import { validatePasswordPolicy } from "./password-policy.js";
import { loadLegacyWechatSignupTrust } from "./legacy-wechat-signup-manifest.js";
import { legacyRefreshAccountFingerprint } from "./legacy-refresh-credential-manifest.js";
import { enqueueSubjectEvent } from "./subject-events.js";
import type { LegacyUserReadModel } from "./legacy-identity.reader.js";
import type { AuthTokenResponse,RequestContext } from "./token-issuance.service.js";

const inputSchema=z.object({token:z.string().min(1).max(255),username:z.string().trim().min(1).max(255),password:z.string().min(1).max(1024),email:z.string().trim().email().nullable().optional()});
export interface LegacyWechatSignupResult extends AuthTokenResponse {uid:number;}
/** A signup bearer is neither a login code nor a refresh credential. Known tombstones keep their type. */
@Injectable()
export class LegacyWechatSignupRepository implements OnModuleDestroy {
  private readonly config=loadConfig();private readonly pool:Pool|null;
  constructor(private readonly accounts:AccountRegistrationRepository,private readonly sessions:IdentitySessionRepository,private readonly jwt:JwtIssuerService){
    const db=this.config.identityDb;this.pool=this.config.dataSource==="identity"&&db.host&&db.user?mysql.createPool({host:db.host,port:db.port,database:db.name,user:db.user,password:db.password,timezone:"Z",connectionLimit:5}):null;
  }
  async onModuleDestroy(){await this.pool?.end();}
  async hasCredential(raw:string):Promise<boolean>{
    if(this.config.dataSource!=="identity")return false;
    await this.sessions.ensureSchema();return !!await this.lookup(hash(raw));
  }
  async pending(raw:string):Promise<void>{
    const row=await this.lookup(hash(raw));let trust;try{trust=loadLegacyWechatSignupTrust();}catch{throw unavailable();}
    if(!row||!trust||row.manifest_hash!==trust.manifestSha256||row.provider_app_id!==trust.providerAppId||row.consumed_at||row.revoked_at||row.source_revoked_at||
      (row.expires_at&&new Date(row.expires_at).getTime()<=Date.now()))throw invalid();
    await this.assertNoOtherCredential(this.db(),hash(raw));
    const [owners]=await this.db().execute<RowDataPacket[]>("SELECT user_id FROM identity_wechat_identities WHERE provider=? AND provider_app_id=? AND open_id=?",[row.provider,row.provider_app_id,row.open_id]);
    if(!owners[0]||owners[0].user_id!=null)throw invalid();
  }
  @AdmissionWriter()
  async redeem(action:"register"|"bind",payload:unknown,context:RequestContext={}):Promise<LegacyWechatSignupResult>{
    const parsed=inputSchema.safeParse(payload);if(!parsed.success)throw new BadRequestException("Invalid WeChat registration payload.");
    const input=parsed.data,credentialHash=hash(input.token),candidate=await this.lookup(credentialHash);
    if(!candidate)throw invalid();
    let trust;try{trust=loadLegacyWechatSignupTrust();}catch{throw unavailable();}
    if(!trust||trust.manifestSha256!==candidate.manifest_hash||trust.providerAppId!==candidate.provider_app_id)throw invalid();
    if(action==="register"){
      const errors=validatePasswordPolicy(input.password,{username:input.username,email:input.email});
      if(errors.length)throw new BadRequestException({password:errors,message:errors[0]});
    }
    if(!this.config.tokenIssuance.enabled)throw unavailable();
    const key=replayKey();this.jwt.assertSigningReady();await this.sessions.ensureSchema();
    const requestHash=createHmac("sha256",key).update(JSON.stringify(["legacy-wechat-signup-v1",action,credentialHash,input.username,input.password,
      action==="register"?input.email?.toLowerCase()??null:null,context.idempotencyKey??null])).digest("hex");
    const connection=await this.db().getConnection();
    try{
      await connection.query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED");await connection.beginTransaction();
      // Match current provider registration: provider -> compatibility identity -> existing user -> credential.
      const [bindings]=await connection.execute<RowDataPacket[]>(`SELECT provider,provider_app_id,open_id,user_id FROM identity_wechat_identities
        WHERE provider=? AND provider_app_id=? AND open_id=? FOR UPDATE`,[candidate.provider,candidate.provider_app_id,candidate.open_id]);
      const binding=bindings[0];
      if(!binding||binding.provider!==candidate.provider||binding.provider_app_id!==candidate.provider_app_id||binding.open_id!==candidate.open_id)throw invalid();
      const [compatRows]=await connection.execute<RowDataPacket[]>("SELECT id,openid,user_id FROM wechat WHERE id=? FOR UPDATE",[candidate.source_record_id]);
      const compat=compatRows[0];if(!compat||compat.openid!==candidate.open_id)throw invalid();
      // The provider lock serializes first redemption and makes a newly committed owner visible here.
      const current=await this.lookup(credentialHash,connection);if(!current)throw invalid();
      let user:RowDataPacket|undefined;
      if(current.consumed_user_id!=null){
        const [users]=await connection.execute<RowDataPacket[]>("SELECT * FROM user WHERE id=? FOR UPDATE",[current.consumed_user_id]);user=users[0];
      }else if(action==="bind"){
        const [users]=await connection.execute<RowDataPacket[]>("SELECT * FROM user WHERE username=? FOR UPDATE",[input.username]);user=users[0];
        if(!user||Number(user.status)!==10||user.deleted_at!=null||typeof user.password_hash!=="string"||!await verifyLegacyPassword(input.password,user.password_hash))throw invalid();
      }
      const [rows]=await connection.execute<RowDataPacket[]>("SELECT * FROM identity_legacy_wechat_signup_credentials WHERE credential_hash=? FOR UPDATE",[credentialHash]);
      const row=rows[0];
      if(!row||row.manifest_hash!==trust.manifestSha256||row.provider_app_id!==trust.providerAppId||row.provider!==candidate.provider||row.open_id!==candidate.open_id||
        row.revoked_at||row.source_revoked_at||(row.expires_at&&new Date(row.expires_at).getTime()<=Date.now()))throw invalid();
      await this.assertNoOtherCredential(connection,credentialHash);
      if(row.consumed_at){
        if(!user||Number(user.status)!==10||user.deleted_at!=null||row.consumed_action!==action||row.request_hash!==requestHash||
          row.account_fingerprint!==legacyRefreshAccountFingerprint(user.password_hash??null,user.auth_key??null)||
          Number(binding.user_id)!==Number(user.id)||Number(compat.user_id)!==Number(user.id)||!row.encrypted_response||!row.replay_expires_at||new Date(row.replay_expires_at).getTime()<=Date.now()||
          !row.session_id||!row.successor_hash||!await this.sessions.canReplayInTransaction(connection,Number(user.id),row.session_id,row.successor_hash))throw invalid();
        const result=decrypt(row.encrypted_response,key,aad(row,requestHash));
        if(result.uid!==Number(user.id)||hashRefreshToken(result.token.refreshToken)!==row.successor_hash)throw invalid();
        await connection.commit();return result;
      }
      if(row.consumed_user_id||row.session_id||row.successor_hash||row.encrypted_response||row.request_hash||binding.user_id!=null||compat.user_id!=null)throw invalid();
      if(action==="register"){
        const created=await this.accounts.createUserInTransaction(connection,input);
        const [users]=await connection.execute<RowDataPacket[]>("SELECT * FROM user WHERE id=? FOR UPDATE",[created.id]);user=users[0];
      }
      if(!user)throw invalid();const userId=Number(user.id);
      const [other]=await connection.execute<RowDataPacket[]>(`SELECT open_id FROM identity_wechat_identities
        WHERE provider=? AND provider_app_id=? AND user_id=?`,[row.provider,row.provider_app_id,userId]);
      if(other.some(entry=>entry.open_id!==row.open_id))throw new ConflictException("用户已经存在该微信应用的其他绑定");
      await connection.execute("UPDATE identity_wechat_identities SET user_id=?,signup_token_hash=NULL WHERE provider=? AND provider_app_id=? AND open_id=?",[userId,row.provider,row.provider_app_id,row.open_id]);
      await connection.execute("UPDATE wechat SET user_id=?,updated_at=UTC_TIMESTAMP(3) WHERE id=?",[userId,row.source_record_id]);
      await connection.execute("UPDATE user SET wx_openid=COALESCE(NULLIF(wx_openid,''),?),updated_at=? WHERE id=?",[row.open_id,Math.floor(Date.now()/1000),userId]);
      await enqueueSubjectEvent(connection,userId);
      const [roles]=await connection.execute<RowDataPacket[]>(`SELECT aa.item_name FROM auth_assignment aa JOIN auth_item ai ON ai.name=aa.item_name
        WHERE aa.user_id=? AND ai.type=1 ORDER BY aa.item_name`,[String(userId)]);
      const model:LegacyUserReadModel={id:userId,username:user.username??null,email:user.email??null,status:10,nickname:user.nickname??null,
        emailVerifiedAt:user.email_verified_at==null?null:Number(user.email_verified_at),createdAt:user.created_at==null?null:Number(user.created_at),updatedAt:user.updated_at==null?null:Number(user.updated_at),
        roles:roles.map(role=>String(role.item_name)),organizations:[],userInfo:null,source:"identity-db"};
      const sessionId=randomBytes(24).toString("base64url"),access=this.jwt.issue(model,sessionId);
      const session=await this.sessions.issueInTransaction(connection,{legacyUserId:userId,username:model.username,sessionId,
        expectedPasswordHash:user.password_hash,expiresAt:new Date(Date.now()+this.config.tokenIssuance.refreshTokenTtlSeconds*1000),ipAddressHash:hashMaybe(context.ip),userAgentHash:hashMaybe(context.userAgent)});
      const result:LegacyWechatSignupResult={success:true,message:"register",uid:userId,token:{token:access.accessToken,accessToken:access.accessToken,refreshToken:session.refreshToken,expires:access.expiresAt.toISOString(),tokenType:"Bearer"}};
      const replayRow={...row,consumed_user_id:userId,consumed_action:action,session_id:sessionId,successor_hash:session.refreshTokenHash};
      await connection.execute(`UPDATE identity_legacy_wechat_signup_credentials SET consumed_at=UTC_TIMESTAMP(3),consumed_user_id=?,consumed_action=?,account_fingerprint=?,session_id=?,successor_hash=?,request_hash=?,
        encrypted_response=?,replay_expires_at=DATE_ADD(UTC_TIMESTAMP(3),INTERVAL 30 SECOND) WHERE credential_hash=?`,[userId,action,legacyRefreshAccountFingerprint(user.password_hash??null,user.auth_key??null),sessionId,session.refreshTokenHash,requestHash,encrypt(result,key,aad(replayRow,requestHash)),credentialHash]);
      await connection.commit();return result;
    }catch(error){await connection.rollback();if(error instanceof NativeRegistrationError)throw new HttpException(error.body,error.status);throw error;}finally{connection.release();}
  }
  @AdmissionWriter()
  async revoke(raw:string):Promise<boolean>{
    const credentialHash=hash(raw);await this.sessions.ensureSchema();if(!await this.lookup(credentialHash))return false;
    const connection=await this.db().getConnection();
    try{
      await connection.query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED");await connection.beginTransaction();
      const original=await this.lookup(credentialHash,connection);
      // Serialize even an ownerless logout against the same provider first-redemption lock.
      await connection.execute("SELECT open_id FROM identity_wechat_identities WHERE provider=? AND provider_app_id=? AND open_id=? FOR UPDATE",[original!.provider,original!.provider_app_id,original!.open_id]);
      const current=await this.lookup(credentialHash,connection);
      if(current?.consumed_user_id!=null)await connection.execute("SELECT id FROM user WHERE id=? FOR UPDATE",[current.consumed_user_id]);
      const [rows]=await connection.execute<RowDataPacket[]>("SELECT session_id FROM identity_legacy_wechat_signup_credentials WHERE credential_hash=? FOR UPDATE",[credentialHash]);
      await connection.execute("UPDATE identity_legacy_wechat_signup_credentials SET revoked_at=COALESCE(revoked_at,UTC_TIMESTAMP(3)),encrypted_response=NULL,replay_expires_at=NULL WHERE credential_hash=?",[credentialHash]);
      if(rows[0]?.session_id)await connection.execute("UPDATE identity_refresh_sessions SET revoked_at=COALESCE(revoked_at,UTC_TIMESTAMP(3)),replaced_by_hash=NULL WHERE session_id=?",[rows[0].session_id]);
      await connection.commit();return true;
    }catch(error){await connection.rollback();throw error;}finally{connection.release();}
  }
  private async assertNoOtherCredential(connection:PoolConnection|Pool,digest:string){
    for(const [table,column] of [["identity_refresh_sessions","refresh_token_hash"],["identity_legacy_refresh_credentials","credential_hash"],["identity_login_codes","code_hash"],["identity_wechat_scenes","scene_hash"]]){
      const [known]=await connection.execute<RowDataPacket[]>(`SELECT ${column} FROM ${table} WHERE ${column}=?`,[digest]);if(known.length)throw invalid();
    }
  }
  private async lookup(digest:string,connection?:PoolConnection){const [rows]=await (connection??this.db()).execute<RowDataPacket[]>("SELECT * FROM identity_legacy_wechat_signup_credentials WHERE credential_hash=?",[digest]);return rows[0]??null;}
  private db(){if(!this.pool)throw unavailable();return this.pool;}
}
function invalid(){return new UnauthorizedException("微信注册凭据或账号密码无效");}
function unavailable(){return new ServiceUnavailableException("Legacy WeChat signup is not configured.");}
function hash(raw:string){if(typeof raw!=="string"||!raw||raw.length>4096)throw invalid();return createHash("sha256").update(raw).digest("hex");}
function hashMaybe(raw?:string|null){return raw?hash(raw):null;}
function replayKey(){const raw=process.env.IDENTITY_REFRESH_REPLAY_KEY??"",key=Buffer.from(raw,"base64url");if(key.length!==32||(key.toString("base64url")!==raw&&key.toString("base64")!==raw))throw unavailable();return key;}
function aad(row:Record<string,unknown>,requestHash:string){return Buffer.from(JSON.stringify(["legacy-wechat-signup-v1",row.credential_hash,row.manifest_hash,row.consumed_user_id,row.consumed_action,row.session_id,row.successor_hash,requestHash]));}
function encrypt(result:LegacyWechatSignupResult,key:Buffer,associated:Buffer){const iv=randomBytes(12),cipher=createCipheriv("aes-256-gcm",key,iv);cipher.setAAD(associated);const body=Buffer.concat([cipher.update(JSON.stringify(result)),cipher.final()]);return Buffer.concat([iv,cipher.getAuthTag(),body]).toString("base64url");}
function decrypt(value:string,key:Buffer,associated:Buffer):LegacyWechatSignupResult{try{const raw=Buffer.from(value,"base64url");if(raw.length<29||raw.toString("base64url")!==value)throw invalid();const decipher=createDecipheriv("aes-256-gcm",key,raw.subarray(0,12));decipher.setAAD(associated);decipher.setAuthTag(raw.subarray(12,28));const result=JSON.parse(Buffer.concat([decipher.update(raw.subarray(28)),decipher.final()]).toString());if(result?.success!==true||result.message!=="register"||typeof result.token?.refreshToken!=="string")throw invalid();return result;}catch{throw invalid();}}
