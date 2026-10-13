import { assertNativeUserAllocation } from "./identity-allocator-manifest.js";
import { createHash, randomBytes } from "node:crypto";
import { BadRequestException, ConflictException, Inject, Injectable, OnModuleDestroy, ServiceUnavailableException, UnauthorizedException } from "@nestjs/common";
import mysql, { Pool, PoolConnection, ResultSetHeader, RowDataPacket } from "mysql2/promise";
import { z } from "zod";
import { loadConfig } from "./config.js";
import { LegacyIdentityReader } from "./legacy-identity.reader.js";
import { TokenIssuanceService } from "./token-issuance.service.js";
import { JwtIssuerService } from "./jwt-issuer.service.js";
import { credentialOperationDigest } from "./account-lifecycle-operation.repository.js";
import { hashLegacyPassword, verifyLegacyPassword } from "./legacy-password.js";
import { validatePasswordPolicy } from "./password-policy.js";
import { enqueueSubjectEvent } from "./subject-events.js";

const profileSchema=z.object({providerAppId:z.string().min(1).max(191),subject:z.string().min(1).max(255),email:z.string().email().max(255).nullable().optional(),
  firstName:z.string().max(255).nullable().optional(),lastName:z.string().max(255).nullable().optional(),privateEmail:z.boolean().nullable().optional(),emailVerified:z.boolean().default(false)});
const completionSchema=z.object({apple_id:z.string().min(1).max(255),token:z.string().min(32).max(256),providerAppId:z.string().min(1).max(191).optional(),
  username:z.string().trim().min(1).max(255),password:z.string().min(1).max(1024)});

/** This API accepts only provider proofs already verified by the trusted PHP bridge. */
@Injectable()
export class AppleIdentityService implements OnModuleDestroy {
  readonly config=loadConfig();
  private readonly pool:Pool|null;
  private readonly clients=new Set((process.env.IDENTITY_APPLE_CLIENT_IDS??"").split(",").map(value=>value.trim()).filter(Boolean));
  private readonly challengeTtl=Number(process.env.IDENTITY_APPLE_CHALLENGE_TTL_SECONDS??300);
  constructor(@Inject(LegacyIdentityReader) private readonly reader:LegacyIdentityReader,@Inject(TokenIssuanceService) private readonly tokens:TokenIssuanceService,
    @Inject(JwtIssuerService) private readonly jwt:JwtIssuerService) {
    const db=this.config.identityDb;
    this.pool=this.config.dataSource==="identity"&&db.host&&db.user?mysql.createPool({host:db.host,port:db.port,database:db.name,user:db.user,password:db.password,timezone:"Z",connectionLimit:5}):null;
    if(!Number.isInteger(this.challengeTtl)||this.challengeTtl<30||this.challengeTtl>600)throw new Error("Apple challenge TTL must be between 30 and 600 seconds");
  }
  async onModuleDestroy(){await this.pool?.end();}
  async resolve(payload:unknown) {
    const profile=parse(profileSchema,payload);this.app(profile.providerAppId);this.jwt.assertSigningReady();
    const connection=await this.db().getConnection();let identity:RowDataPacket,challenge:string|null=null;
    try {
      await connection.beginTransaction();
      await connection.execute(`INSERT INTO identity_apple_identities(provider_app_id,subject,email,email_verified,first_name,last_name,private_email)
        VALUES(?,?,?,?,?,?,?) ON DUPLICATE KEY UPDATE email=COALESCE(VALUES(email),email),
        email_verified=IF(VALUES(email) IS NULL,email_verified,VALUES(email_verified)),first_name=COALESCE(VALUES(first_name),first_name),
        last_name=COALESCE(VALUES(last_name),last_name),private_email=COALESCE(VALUES(private_email),private_email)`,
        [profile.providerAppId,profile.subject,profile.email?.trim().toLowerCase()??null,profile.emailVerified?1:0,profile.firstName??null,profile.lastName??null,profile.privateEmail==null?null:Number(profile.privateEmail)]);
      identity=await this.identity(connection,profile.providerAppId,profile.subject);
      if(identity.user_id!=null)await this.activeUser(connection,Number(identity.user_id));
      else {
        challenge=randomBytes(32).toString("base64url");
        await connection.execute("INSERT INTO identity_apple_challenges(token_hash,provider_app_id,subject,expires_at)VALUES(?,?,?,?)",
          [digest(challenge),profile.providerAppId,profile.subject,new Date(Date.now()+this.challengeTtl*1000)]);
      }
      await connection.commit();
    }catch(error){await connection.rollback();throw error;}finally{connection.release();}
    return this.response(identity!,challenge);
  }

  async complete(mode:"create"|"link",payload:unknown) {
    const input=parse(completionSchema,payload);this.jwt.assertSigningReady();
    const connection=await this.db().getConnection();let identity:RowDataPacket,expectedPasswordHash:string;
    try {
      await connection.beginTransaction();
      const [challenges]=await connection.execute<RowDataPacket[]>("SELECT * FROM identity_apple_challenges WHERE token_hash=? FOR UPDATE",[digest(input.token)]);
      const challenge=challenges[0];
      if(!challenge||new Date(challenge.expires_at).getTime()<=Date.now()||challenge.subject!==input.apple_id||(input.providerAppId&&input.providerAppId!==challenge.provider_app_id))throw invalidChallenge();
      this.app(String(challenge.provider_app_id));
      identity=await this.identity(connection,String(challenge.provider_app_id),input.apple_id);
      const operationHash=credentialOperationDigest(["apple",mode,String(challenge.provider_app_id),input.apple_id,input.username.toLowerCase(),input.password]);
      if(challenge.consumed_at) {
        if(challenge.operation_hash!==operationHash||identity.user_id==null||Number(identity.user_id)!==Number(challenge.user_id))throw new ConflictException("Apple challenge was already consumed");
        const user=await this.activeUser(connection,Number(challenge.user_id));
        if(!await verifyLegacyPassword(input.password,user.password_hash))throw new ConflictException("Account credentials changed after Apple registration");
        expectedPasswordHash=String(user.password_hash);
      }else {
        if(identity.user_id!=null)throw new ConflictException("Apple identity is already bound to another account");
        let userId:number;
        if(mode==="link") {
          const [users]=await connection.execute<RowDataPacket[]>("SELECT id,password_hash,status,deleted_at FROM user WHERE username=? FOR UPDATE",[input.username]);
          const user=users[0];
          if(!user||Number(user.status)!==10||user.deleted_at!=null||!await verifyLegacyPassword(input.password,user.password_hash))throw new UnauthorizedException("Username or password is invalid");
          userId=Number(user.id);expectedPasswordHash=String(user.password_hash);
        }else {
          const email=Number(identity.email_verified)===1?identity.email:null;
          const errors=validatePasswordPolicy(input.password,{username:input.username,email});if(errors.length)throw new BadRequestException({code:"PASSWORD_POLICY",message:errors.join("；")});
          expectedPasswordHash=await hashLegacyPassword(input.password);const now=Math.floor(Date.now()/1000);
          const nickname=Array.from([identity.first_name,identity.last_name].filter(Boolean).join(" ")).slice(0,255).join("")||null;
          const [created]=await connection.execute<ResultSetHeader>(`INSERT INTO user(username,nickname,email,email_verified_at,password_hash,auth_key,status,created_at,updated_at)
            VALUES(?,?,?,?,?,?,10,?,?)`,[input.username,nickname,email,email?now:null,expectedPasswordHash,randomBytes(24).toString("base64url"),now,now]);
          userId=assertNativeUserAllocation(created.insertId);
          await connection.execute("INSERT INTO user_info(user_id)VALUES(?)",[userId]);
          await connection.execute("INSERT INTO auth_assignment(item_name,user_id,created_at)VALUES('user',?,?)",[String(userId),now]);
        }
        await connection.execute("UPDATE identity_apple_identities SET user_id=? WHERE provider_app_id=? AND subject=?",[userId,challenge.provider_app_id,input.apple_id]);
        await connection.execute("UPDATE identity_apple_challenges SET consumed_at=UTC_TIMESTAMP(3),operation_hash=?,user_id=? WHERE token_hash=?",[operationHash,userId,digest(input.token)]);
        await enqueueSubjectEvent(connection,userId);identity.user_id=userId;
      }
      await connection.commit();
    }catch(error){await connection.rollback();if((error as {code?:string}).code==="ER_DUP_ENTRY")throw new ConflictException("Username or email is already bound; link the existing account with its password");throw error;}
    finally{connection.release();}
    return this.response(identity!,null,expectedPasswordHash!);
  }
  private async response(identity:RowDataPacket,challenge:string|null,expectedPasswordHash?:string) {
    const userId=identity.user_id==null?null:Number(identity.user_id);
    let user:Record<string,unknown>|null=null;
    if(userId!==null) {
      const account=await this.reader.getUserById(userId);if(!account||account.status!==10)throw new UnauthorizedException("Account is disabled");
      const issued=await this.tokens.issueRegisteredUser(account,{},expectedPasswordHash);
      user={id:account.id,username:account.username,nickname:account.nickname,email:account.email,roles:account.roles,organizations:account.organizations,
        auth:issued.token.accessToken,auth_tokens:{access_token:issued.token.accessToken,refresh_token:issued.token.refreshToken,expires_at:issued.token.expires,token_type:issued.token.tokenType}};
    }
    return {apple_id:String(identity.subject),providerAppId:String(identity.provider_app_id),email:identity.email??null,first_name:identity.first_name??null,last_name:identity.last_name??null,
      private_email:identity.private_email==null?null:Boolean(identity.private_email),token:challenge,user_id:userId,user};
  }
  private async identity(connection:PoolConnection,appId:string,subject:string) {
    const [rows]=await connection.execute<RowDataPacket[]>("SELECT * FROM identity_apple_identities WHERE provider_app_id=? AND subject=? FOR UPDATE",[appId,subject]);
    if(!rows[0])throw invalidChallenge();return rows[0];
  }
  private async activeUser(connection:PoolConnection,userId:number) {
    const [rows]=await connection.execute<RowDataPacket[]>("SELECT id,password_hash,status,deleted_at FROM user WHERE id=? FOR UPDATE",[userId]);
    if(!rows[0]||Number(rows[0].status)!==10||rows[0].deleted_at!=null)throw new UnauthorizedException("Account is disabled");return rows[0];
  }
  private app(id:string){this.db();if(!this.clients.size)throw new ServiceUnavailableException({code:"APPLE_CLIENTS_NOT_CONFIGURED",message:"Apple client audiences must be explicitly configured"});if(!this.clients.has(id))throw new UnauthorizedException("Apple audience is not allowed");}
  private db(){if(!this.pool)throw new ServiceUnavailableException("Independent Identity database is required");return this.pool;}
}
function parse<S extends z.ZodTypeAny>(schema:S,value:unknown):z.output<S>{const result=schema.safeParse(value);if(!result.success)throw new BadRequestException("Invalid Apple request");return result.data;}
function digest(value:string){return createHash("sha256").update(value).digest("hex");}
function invalidChallenge(){return new UnauthorizedException("Apple challenge is invalid or expired");}
