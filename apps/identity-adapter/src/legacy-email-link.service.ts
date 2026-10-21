import { AdmissionWriter } from "./identity-admission.js";
import { assertNativeUserAllocation } from "./identity-allocator-manifest.js";
import { BadRequestException, ConflictException, Inject, Injectable, OnModuleDestroy, ServiceUnavailableException } from "@nestjs/common";
import { createHash, createHmac, randomBytes,createCipheriv,createDecipheriv } from "node:crypto";
import mysql, { Pool, PoolConnection, RowDataPacket, ResultSetHeader } from "mysql2/promise";
import { z } from "zod";
import { loadConfig } from "./config.js";
import { hashLegacyPassword } from "./legacy-password.js";
import { validatePasswordPolicy } from "./password-policy.js";
import { enqueueSubjectEvent } from "./subject-events.js";
import { TokenIssuanceService,type AuthTokenResponse } from "./token-issuance.service.js";
import { IdentitySessionRepository } from "./identity-session.repository.js";
import { revokeLegacyRefreshCredentialsInTransaction } from "./legacy-refresh-credential-revocation.js";

const tokenSchema=z.string().min(16).max(255);
type LinkResult={userId:number;username:string;email:string|null;status:number};

/** Continues already sent Yii email links using only the private account store. */
@Injectable()
export class LegacyEmailLinkService implements OnModuleDestroy {
  readonly config=loadConfig();
  private readonly pool:Pool|null;
  constructor(@Inject(TokenIssuanceService) private readonly tokens:TokenIssuanceService,@Inject(IdentitySessionRepository) private readonly sessions:IdentitySessionRepository){const db=this.config.identityDb;this.pool=this.config.dataSource==="identity"&&db.host&&db.user?mysql.createPool({host:db.host,port:db.port,database:db.name,user:db.user,password:db.password,timezone:"Z",connectionLimit:5}):null;}
  async onModuleDestroy(){await this.pool?.end();}
  private db(){if(!this.pool)throw new ServiceUnavailableException("Independent account storage is required");return this.pool;}
  private resetValid(token:string){
    const suffix=token.match(/_(\d+)$/),issued=suffix?Number(suffix[1]):NaN,now=Math.floor(Date.now()/1000);
    const ttl=Number(process.env.IDENTITY_LEGACY_RESET_TOKEN_TTL_SECONDS??3600);
    if(!Number.isSafeInteger(ttl)||ttl<1||ttl>31_536_000)throw new ServiceUnavailableException("Legacy reset expiry must match the source deployment");
    if(!Number.isSafeInteger(issued)||issued>now||issued+ttl<now)throw invalidLink();
  }
  async validateReset(payload:unknown):Promise<LinkResult>{
    const {token}=parse(z.object({token:tokenSchema}),payload);this.resetValid(token);
    const [rows]=await this.db().execute<RowDataPacket[]>("SELECT id,username,email,status FROM user WHERE BINARY password_reset_token=BINARY ? AND status=10 AND deleted_at IS NULL LIMIT 2",[token]);
    if(rows.length!==1)throw invalidLink();return result(rows[0]);
  }
  async reset(payload:unknown,idempotencyKey?:string):Promise<LinkResult>{
    const {token,password}=parse(z.object({token:tokenSchema,password:z.string()}),payload);
    const operation=this.operation("reset",token,idempotencyKey),fingerprint=this.fingerprint([token,password]);
    // Hash outside the write lock. Every proof and current account condition is rechecked below.
    const errors=validatePasswordPolicy(password,{});if(errors.length)throw new BadRequestException({errors});
    const passwordHash=await hashLegacyPassword(password);
    return this.transaction(async connection=>{
      const cached=await this.claim(connection,operation,fingerprint);
      if(cached){
        const [users]=await connection.execute<RowDataPacket[]>("SELECT id,username,email,status,password_hash FROM user WHERE id=? AND status=10 AND deleted_at IS NULL FOR UPDATE",[cached.userId]);
        if(!users[0]||this.fingerprint(users[0].password_hash)!==cached.credentialFingerprint)throw new ConflictException("Account changed after this reset request");
        return result(users[0]);
      }
      this.resetValid(token);
      const user=await this.proofUser(connection,"password_reset_token",token,10);
      const scopedErrors=validatePasswordPolicy(password,{username:user.username,email:user.email});if(scopedErrors.length)throw new BadRequestException({errors:scopedErrors});
      await connection.execute("UPDATE user SET password_hash=?,password_reset_token=NULL,updated_at=? WHERE id=?",[passwordHash,Math.floor(Date.now()/1000),user.id]);
      await revokeLegacyRefreshCredentialsInTransaction(connection,Number(user.id));
      await connection.execute("UPDATE identity_refresh_sessions SET revoked_at=COALESCE(revoked_at,UTC_TIMESTAMP(3)) WHERE legacy_user_id=?",[user.id]);
      await connection.execute("INSERT INTO identity_user_revocations(user_id,revoked_before) VALUES (?,UTC_TIMESTAMP(3)) ON DUPLICATE KEY UPDATE revoked_before=UTC_TIMESTAMP(3)",[user.id]);
      await enqueueSubjectEvent(connection,Number(user.id));
      await this.complete(connection,operation,{...result(user),credentialFingerprint:this.fingerprint(passwordHash)});
      return result(user);
    });
  }
  async verify(payload:unknown,idempotencyKey?:string):Promise<LinkResult&{authTokens?:AuthTokenResponse["token"]}>{
    const {token}=parse(z.object({token:tokenSchema}),payload);
    const operation=this.operation("verify",token,idempotencyKey),fingerprint=this.fingerprint([token]);
    const key=this.replayKey();await this.tokens.assertTransactionIssuanceReady();
    return this.transaction(async connection=>{
      const cached=await this.claim(connection,operation,fingerprint);
      if(cached){
        const [users]=await connection.execute<RowDataPacket[]>("SELECT id,username,email,status,password_hash,email_verified_at FROM user WHERE id=? AND status=10 AND deleted_at IS NULL FOR UPDATE",[cached.userId]);
        if(!users[0])throw invalidLink();const user=users[0],replay=cached.authReplay;
        if(replay&&Date.now()<Number(replay.retryUntil)&&cached.credentialFingerprint===this.fingerprint(user.password_hash)
          &&cached.emailFingerprint===this.fingerprint([user.email,user.email_verified_at])
          &&await this.sessions.canReplayInTransaction(connection,Number(user.id),String(replay.sessionId),String(replay.refreshTokenHash))){
          try{return {...result(user),authTokens:this.decryptAuth(replay.encryptedAuth,key,operation)};}catch{/* Key rotation or damaged ciphertext cannot grant a new login. */}
        }
        // The proof remains an idempotent verification result, never a permanent login credential.
        await this.complete(connection,operation,{...result(user),credentialFingerprint:cached.credentialFingerprint,emailFingerprint:cached.emailFingerprint});
        return result(user);
      }
      const user=await this.proofUser(connection,"verification_token",token,9),now=Math.floor(Date.now()/1000);
      const [invitations]=await connection.execute<RowDataPacket[]>("SELECT id,used,auth_item_name FROM invitation WHERE recipient_id=? ORDER BY id FOR UPDATE",[user.id]);
      if(invitations.length>1)throw new ConflictException("Multiple emailed invitations require reconciliation");
      const invitation=invitations[0],role=invitation?.auth_item_name||"guest";
      const [roles]=await connection.execute<RowDataPacket[]>("SELECT name FROM auth_item WHERE name=?",[role]);if(!roles.length)throw new ConflictException("The historical invitation role is not present");
      await connection.execute("INSERT IGNORE INTO auth_assignment(item_name,user_id,created_at) VALUES (?,?,?)",[role,String(user.id),now]);
      if(invitation)await connection.execute("UPDATE invitation SET used=1 WHERE id=?",[invitation.id]);
      await connection.execute("UPDATE user SET status=10,email_verified_at=?,verification_token=NULL,updated_at=? WHERE id=?",[now,now,user.id]);
      const issued=await this.tokens.issueInTransaction(connection,Number(user.id));
      const [credentials]=await connection.execute<RowDataPacket[]>("SELECT password_hash,email,email_verified_at FROM user WHERE id=?",[user.id]);
      await enqueueSubjectEvent(connection,Number(user.id));const response={...result(user),status:10};
      await this.complete(connection,operation,{...response,credentialFingerprint:this.fingerprint(credentials[0].password_hash),
        emailFingerprint:this.fingerprint([credentials[0].email,credentials[0].email_verified_at]),authReplay:{retryUntil:Date.now()+30000,sessionId:issued.sessionId,
          refreshTokenHash:issued.refreshTokenHash,encryptedAuth:this.encryptAuth(issued.token,key,operation)}});
      return {...response,authTokens:issued.token};
    });
  }
  /** Internal DTO only: the existing PHP mailer keeps the original templates and link URLs. */
  async requestLink(kind:"reset"|"verify",payload:unknown){
    const {email}=parse(z.object({email:z.string().trim().email().max(255)}),payload);
    return this.transaction(async connection=>{
      const [users]=await connection.execute<RowDataPacket[]>("SELECT id,username,email,status,password_reset_token,verification_token FROM user WHERE email=? AND status=? AND deleted_at IS NULL FOR UPDATE",[email,kind==="reset"?10:9]);
      if(users.length!==1)throw invalidLink();const user=users[0];
      const now=Math.floor(Date.now()/1000);
      await connection.execute("INSERT IGNORE INTO identity_legacy_link_email_limits(email,kind,last_sent_at) VALUES (?,?,0)",[email,kind]);
      const [limits]=await connection.execute<RowDataPacket[]>("SELECT last_sent_at FROM identity_legacy_link_email_limits WHERE email=? AND kind=? FOR UPDATE",[email,kind]);
      if(now-Number(limits[0].last_sent_at)<60)throw new BadRequestException("Please wait before requesting another email");
      let token=kind==="reset"?user.password_reset_token:user.verification_token;
      let reusable=typeof token==="string"&&token.length>=16;
      if(kind==="reset"&&reusable){try{this.resetValid(token);}catch(error){if(error instanceof ServiceUnavailableException)throw error;reusable=false;}}
      if(!reusable){token=`${randomBytes(32).toString("base64url")}_${now}`;await connection.execute(`UPDATE user SET ${kind==="reset"?"password_reset_token":"verification_token"}=? WHERE id=?`,[token,user.id]);}
      await connection.execute("UPDATE identity_legacy_link_email_limits SET last_sent_at=? WHERE email=? AND kind=?",[now,email,kind]);
      return {...result(user),token:String(token)};
    });
  }
  async signup(payload:unknown,idempotencyKey?:string){
    const input=parse(z.object({username:z.string().trim().min(2).max(255),email:z.string().trim().email().max(255),password:z.string(),invitation:z.string().min(1).max(255)}),payload);
    const errors=validatePasswordPolicy(input.password,input);if(errors.length)throw new BadRequestException({errors});
    const operation=this.operation("signup",input.invitation,idempotencyKey),fingerprint=this.fingerprint(input),passwordHash=await hashLegacyPassword(input.password);
    return this.transaction(async connection=>{
      const cached=await this.claim(connection,operation,fingerprint);
      if(cached){const [users]=await connection.execute<RowDataPacket[]>("SELECT id,username,email,status,password_hash,verification_token FROM user WHERE id=? AND deleted_at IS NULL FOR UPDATE",[cached.userId]);if(!users[0]||![9,10].includes(Number(users[0].status))||this.fingerprint(users[0].password_hash)!==cached.credentialFingerprint)throw new ConflictException("Account changed after this signup request");return {...result(users[0]),token:users[0].verification_token??null};}
      const [invitations]=await connection.execute<RowDataPacket[]>("SELECT id,recipient_id,used FROM invitation WHERE BINARY code=BINARY ? FOR UPDATE",[input.invitation]);
      if(invitations.length!==1||invitations[0].recipient_id!=null||Number(invitations[0].used)===1)throw new BadRequestException("Invitation is invalid or already claimed");
      const now=Math.floor(Date.now()/1000),token=`${randomBytes(32).toString("base64url")}_${now}`;
      let id:number;
      try{const [inserted]=await connection.execute<ResultSetHeader>("INSERT INTO user(username,email,password_hash,auth_key,status,verification_token,created_at,updated_at) VALUES (?,?,?,?,9,?,?,?)",[input.username,input.email,passwordHash,randomBytes(24).toString("base64url"),token,now,now]);id=assertNativeUserAllocation(inserted.insertId);}
      catch(error){if((error as {code?:string}).code==="ER_DUP_ENTRY")throw new ConflictException("Username or email already exists");throw error;}
      await connection.execute("INSERT INTO user_info(user_id) VALUES (?)",[id]);
      await connection.execute("UPDATE invitation SET recipient_id=? WHERE id=?",[id,invitations[0].id]);
      await enqueueSubjectEvent(connection,id);
      const response={userId:id,username:input.username,email:input.email,status:9};await this.complete(connection,operation,{...response,credentialFingerprint:this.fingerprint(passwordHash)});
      return {...response,token};
    });
  }
  private async proofUser(connection:PoolConnection,column:"password_reset_token"|"verification_token",token:string,status:number){
    // Locate without locking a table scan, then recheck the exact proof under the account's primary-key lock.
    const [candidates]=await connection.execute<RowDataPacket[]>(`SELECT id FROM user WHERE BINARY ${column}=BINARY ? AND status=? AND deleted_at IS NULL LIMIT 2`,[token,status]);
    if(candidates.length!==1)throw invalidLink();
    const [users]=await connection.execute<RowDataPacket[]>(`SELECT * FROM user WHERE id=? AND BINARY ${column}=BINARY ? AND status=? AND deleted_at IS NULL FOR UPDATE`,[candidates[0].id,token,status]);
    if(users.length!==1)throw invalidLink();return users[0];
  }
  @AdmissionWriter()
  private async transaction<T>(work:(connection:PoolConnection)=>Promise<T>):Promise<T>{const connection=await this.db().getConnection();try{await connection.beginTransaction();const response=await work(connection);await connection.commit();return response;}catch(error){await connection.rollback();throw error;}finally{connection.release();}}
  private fingerprint(value:unknown){const key=process.env.IDENTITY_REFRESH_REPLAY_KEY;if(!key)throw new ServiceUnavailableException("Identity request fingerprint key is required");return createHmac("sha256",key).update(JSON.stringify(value)).digest("hex");}
  private operation(kind:string,token:string,key?:string){if(key&&key.length>200)throw new BadRequestException("Idempotency-Key too long");return createHash("sha256").update(`legacy-email:${kind}:${this.fingerprint(token)}:${key??"implicit"}`).digest("hex");}
  private async claim(connection:PoolConnection,operation:string,fingerprint:string){await connection.execute("INSERT INTO identity_native_operations(operation_key,request_hash) VALUES (?,?) ON DUPLICATE KEY UPDATE operation_key=VALUES(operation_key)",[operation,fingerprint]);const [rows]=await connection.execute<RowDataPacket[]>("SELECT request_hash,response FROM identity_native_operations WHERE operation_key=? FOR UPDATE",[operation]);if(rows[0].request_hash!==fingerprint)throw new ConflictException("Idempotency-Key was used for another link request");return rows[0].response==null?null:typeof rows[0].response==="string"?JSON.parse(rows[0].response):rows[0].response;}
  private async complete(connection:PoolConnection,operation:string,response:LinkResult&{credentialFingerprint?:string;emailFingerprint?:string;authReplay?:{retryUntil:number;sessionId:string;refreshTokenHash:string;encryptedAuth:string}}){await connection.execute("UPDATE identity_native_operations SET response=? WHERE operation_key=?",[JSON.stringify(response),operation]);}
  private replayKey(){const raw=process.env.IDENTITY_REFRESH_REPLAY_KEY,key=raw?Buffer.from(raw,"base64url"):null;if(!key||key.length!==32)throw new ServiceUnavailableException("Verification retry encryption key is required");return key;}
  private encryptAuth(value:AuthTokenResponse["token"],key:Buffer,operation:string){const iv=randomBytes(12),cipher=createCipheriv("aes-256-gcm",key,iv);cipher.setAAD(Buffer.from(`legacy-email-verify:${operation}`));const bytes=Buffer.concat([cipher.update(JSON.stringify(value),"utf8"),cipher.final()]);return Buffer.concat([iv,cipher.getAuthTag(),bytes]).toString("base64url");}
  private decryptAuth(value:string,key:Buffer,operation:string):AuthTokenResponse["token"]{const bytes=Buffer.from(value,"base64url"),decipher=createDecipheriv("aes-256-gcm",key,bytes.subarray(0,12));decipher.setAAD(Buffer.from(`legacy-email-verify:${operation}`));decipher.setAuthTag(bytes.subarray(12,28));return JSON.parse(Buffer.concat([decipher.update(bytes.subarray(28)),decipher.final()]).toString("utf8"));}
}
function invalidLink(){return new BadRequestException("The email link is invalid, expired or already used");}
function result(row:RowDataPacket):LinkResult{return {userId:Number(row.id),username:String(row.username),email:row.email==null?null:String(row.email),status:Number(row.status)};}
function parse<S extends z.ZodTypeAny>(schema:S,value:unknown):z.infer<S>{const parsed=schema.safeParse(value);if(!parsed.success)throw invalidLink();return parsed.data;}
