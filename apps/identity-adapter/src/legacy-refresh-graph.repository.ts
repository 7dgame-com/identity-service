import { Injectable, OnModuleDestroy, OnApplicationBootstrap, ServiceUnavailableException, UnauthorizedException } from "@nestjs/common";
import mysql, { type Pool, type PoolConnection, type RowDataPacket } from "mysql2/promise";
import { refreshRequestHash } from "./refresh-request-context.js";
import { loadConfig } from "./config.js";
import { IdentitySessionRepository } from "./identity-session.repository.js";
import { JwtIssuerService } from "./jwt-issuer.service.js";
import { LegacyIdentityReader, type LegacyUserReadModel } from "./legacy-identity.reader.js";
import { legacyRefreshAccountFingerprint } from "./legacy-refresh-credential-manifest.js";
import { assertGraphSchema } from "./legacy-refresh-graph-import.js";
import { graphCredentialSchema, graphHash, graphTokens, graphReplayKey, type GraphBody, type GraphConsumer, type GraphCredential, type GraphProtocol, type GraphReplay } from "./legacy-refresh-graph-manifest.js";
import { decryptGraphBody, encryptGraphBody, graphBodyAad, graphEncryptionKey, verifyGraphResponse } from "./legacy-refresh-graph-crypto.js";
import type { AuthTokenResponse, RequestContext } from "./token-issuance.service.js";
import { hasRefreshGraphSchema, revokeRefreshGraphFamily } from "./legacy-refresh-graph-revocation.js";
const invalid = () => new UnauthorizedException("Refresh token is invalid.");
const value = <T>(v: unknown): T => (typeof v === "string" ? JSON.parse(v) : v) as T;
const ms = (v: unknown): number | null => v == null ? null : new Date(v as Date | string).getTime();
export type GraphEndpoint = "y1-refresh-pair" | "/v1/auth/refresh" | "/v1/common/report";
export interface LegacyFullResponse { version: "legacy-refresh-response-v1"; consumer: GraphConsumer; endpoint: GraphEndpoint; body: GraphBody; }
/** Optional migration protocol. Presence preserves classification even while disabled. */
@Injectable()
export class LegacyRefreshGraphRepository implements OnModuleDestroy, OnApplicationBootstrap {
  private readonly config = loadConfig(); private readonly pool: Pool | null;
  readonly enabled: boolean;
  constructor(private readonly sessions: IdentitySessionRepository, private readonly jwt: JwtIssuerService, private readonly reader: LegacyIdentityReader) {
    const flag=process.env.IDENTITY_LEGACY_REFRESH_GRAPH_ENABLED;
    if(flag!==undefined && !["true","false"].includes(flag))throw new Error("IDENTITY_LEGACY_REFRESH_GRAPH_ENABLED must be true or false.");
    this.enabled=flag==="true";
    const d=this.config.identityDb;this.pool=this.config.dataSource==="identity"&&d.host&&d.user?mysql.createPool({host:d.host,port:d.port,user:d.user,password:d.password,database:d.name,timezone:"Z",connectionLimit:5}):null;
    if(this.enabled&&this.config.dataSource!=="identity")throw new Error("Legacy graph requires private Identity authority.");
  }
  async onModuleDestroy(){await this.pool?.end();}
  async onApplicationBootstrap(){if(!this.enabled)return;graphEncryptionKey();const c=await this.db().getConnection();try{await assertGraphSchema(c);}finally{c.release();}}
  private db(){if(!this.pool)throw new ServiceUnavailableException("Private legacy graph storage is unavailable.");return this.pool;}
  async hasCredential(raw:string):Promise<boolean>{
    if(!this.pool)return false;const c=await this.pool.getConnection();try{
      if(!await hasRefreshGraphSchema(c))return false;
      const [rows]=await c.execute<RowDataPacket[]>("SELECT credential_hash FROM identity_legacy_refresh_graph_credentials WHERE credential_hash=?",[graphHash(raw)]);return rows.length>0;
    }finally{c.release();}
  }
  async protocol(raw:string):Promise<GraphProtocol|null>{
    if(!await this.hasCredential(raw))return null;
    const [rows]=await this.db().execute<RowDataPacket[]>(`SELECT f.protocol FROM identity_legacy_refresh_graph_credentials c JOIN identity_legacy_refresh_graph_families f ON f.family_key=c.family_key WHERE c.credential_hash=?`,[graphHash(raw)]);return rows[0]?.protocol??null;
  }
  async redeem(raw:string,context:RequestContext={},consumer:GraphConsumer="server",endpoint:GraphEndpoint="/v1/auth/refresh"):Promise<AuthTokenResponse>{
    if(!this.enabled)throw new ServiceUnavailableException("Annotated legacy graph redemption is disabled.");
    const hash=graphHash(raw),key=graphEncryptionKey(),c=await this.db().getConnection();
    try{
      const [owners]=await c.execute<RowDataPacket[]>("SELECT legacy_user_id FROM identity_legacy_refresh_graph_credentials WHERE credential_hash=?",[hash]);if(!owners[0])throw invalid();
      const uid=Number(owners[0].legacy_user_id);await c.beginTransaction();
      const [users]=await c.execute<RowDataPacket[]>("SELECT * FROM user WHERE id=? FOR UPDATE",[uid]);
      const [creds]=await c.execute<RowDataPacket[]>("SELECT * FROM identity_legacy_refresh_graph_credentials WHERE credential_hash=? FOR UPDATE",[hash]);const row=creds[0];if(!row)throw invalid();
      const [families]=await c.execute<RowDataPacket[]>("SELECT * FROM identity_legacy_refresh_graph_families WHERE family_key=? FOR UPDATE",[row.family_key]);const family=families[0];
      const credential=graphCredentialSchema.parse(value(row.source_json));await this.assertCurrent(c,users[0],family,credential);
      const protocol:GraphProtocol=family.protocol;
      if(protocol==="yii3"?(consumer!=="yii3"||endpoint!=="y1-refresh-pair"):(consumer==="yii3"||endpoint==="y1-refresh-pair"||consumer==="server"&&endpoint!=="/v1/auth/refresh"))throw invalid();
      if(protocol==="ar"&&(consumer==="a1"?!credential.a1Compatible:!credential.serverCompatible))throw invalid();
      const now=Date.now();if(credential.expiresAtMs!==null&&credential.expiresAtMs<=now)throw invalid();
      // A1's predecessor remains reusable. A PHP consume invalidates its A1 cache too.
      if(row.revoked_at||row.state==="revoked"||(consumer==="a1"&&row.state!=="active"))throw invalid();
      if(consumer==="a1"&&row.origin==="source"&&!credential.sourceRecordPresent)throw invalid();
      const requestHash=refreshRequestHash(context);
      const [replays]=await c.execute<RowDataPacket[]>(`SELECT * FROM identity_legacy_refresh_graph_replays WHERE predecessor_hash=? ORDER BY replay_key FOR UPDATE`,[hash]);
      for(const saved of replays){
        const meta=value<Omit<GraphReplay,"response">>(saved.source_json);
        if(meta.consumer!==consumer||meta.endpoint!==endpoint||meta.expiresAtMs<=now)continue;
        const same=meta.requestHash===requestHash&&(protocol!=="yii3"||requestHash!==null);
        if(!same&&(protocol!=="yii3"||now-meta.createdAtMs>5000))continue;
        const [successors]=await c.execute<RowDataPacket[]>("SELECT * FROM identity_legacy_refresh_graph_credentials WHERE credential_hash=? FOR SHARE",[meta.successorHash]);const successor=successors[0];
        if(!successor||(successor.origin==="source"&&!value<GraphCredential>(successor.source_json).sourceRecordPresent)||successor.family_key!==family.family_key||successor.state!=="active"||successor.revoked_at)throw invalid();
        const s=graphCredentialSchema.parse(value(successor.source_json));if(s.expiresAtMs!==null&&s.expiresAtMs<=now)throw invalid();
        if(protocol==="yii3"&&family.current_hash!==meta.successorHash)throw invalid();
        if(consumer==="server"&&(row.state!=="consumed"||row.successor_hash!==meta.successorHash))throw invalid();
        const body=decryptGraphBody(saved.encrypted_response,key,graphBodyAad(protocol,meta));
        if(graphHash(JSON.stringify(body))!==saved.response_sha256||graphHash(graphTokens(body).refreshToken)!==meta.successorHash)throw invalid();
        const claims=saved.origin==="source"?verifyGraphResponse({...meta,response:body}):this.nativeClaims(graphTokens(body).accessToken,uid,family.native_session_id);
        await c.commit();return this.result(body,meta,Number(claims.exp));
      }
      if(row.state!=="active"||protocol==="yii3"&&family.current_hash!==hash)throw invalid();
      if(row.origin==="source"&&!credential.sourceRecordPresent)throw invalid();
      this.jwt.assertSigningReady();
      const [roles]=await c.execute<RowDataPacket[]>(`SELECT aa.item_name AS name FROM auth_assignment aa JOIN auth_item ai ON ai.name=aa.item_name WHERE aa.user_id=? AND ai.type=1 ORDER BY aa.item_name`,[String(uid)]);
      const u=users[0],model:LegacyUserReadModel={id:uid,username:u.username??null,email:u.email??null,status:10,nickname:u.nickname??null,emailVerifiedAt:u.email_verified_at==null?null:Number(u.email_verified_at),createdAt:u.created_at==null?null:Number(u.created_at),updatedAt:u.updated_at==null?null:Number(u.updated_at),roles:roles.map(r=>String(r.name)),organizations:[],userInfo:null,source:"identity-db"};
      const source="auth_method" in credential.authContext?{authMethod:"device_sn" as const,deviceSnId:credential.authContext.device_sn_id}:{};
      const access=this.jwt.issue(model,family.native_session_id,source);
      // A1 keeps its permanent reusable credential; the finite backing row is
      // only an access/revocation anchor, never the graph credential's lifetime.
      const session=await this.sessions.issueInTransaction(c,{legacyUserId:uid,username:model.username,sessionId:family.native_session_id,expiresAt:new Date(now+this.config.tokenIssuance.refreshTokenTtlSeconds*1000),expectedPasswordHash:u.password_hash??undefined,...source});
      const next:GraphCredential={...credential,credentialHash:session.refreshTokenHash,issuedAtMs:protocol==="yii3"?now:null,expiresAtMs:consumer==="a1"?null:session.expiresAt.getTime(),state:"active",successorHash:null,rotatedAtMs:null,revokedAtMs:null,keyEncoding:"plain",a1Compatible:protocol==="ar",serverCompatible:protocol==="ar",sourceRecordId:null,sourceRecordPresent:true,sourceRecordSha256:graphHash(JSON.stringify(["native",session.refreshTokenHash]))};
      await c.execute(`INSERT INTO identity_legacy_refresh_graph_credentials(credential_hash,family_key,legacy_user_id,origin,source_json,source_sha256,state) VALUES (?,?,?,'native',?,?,'active')`,[next.credentialHash,family.family_key,uid,JSON.stringify(next),graphHash(JSON.stringify(next))]);
      if(consumer!=="a1")await c.execute("UPDATE identity_legacy_refresh_graph_credentials SET state=?,successor_hash=?,consumed_consumer=? WHERE credential_hash=?",[protocol==="yii3"?"rotated":"consumed",next.credentialHash,consumer,hash]);
      if(protocol==="yii3")await c.execute("UPDATE identity_legacy_refresh_graph_families SET current_hash=? WHERE family_key=?",[next.credentialHash,family.family_key]);
      const displayExpiry=new Intl.DateTimeFormat("sv-SE",{timeZone:"Asia/Shanghai",year:"numeric",month:"2-digit",day:"2-digit",hour:"2-digit",minute:"2-digit",second:"2-digit",hourCycle:"h23"}).format(access.expiresAt);
      const token={accessToken:access.accessToken,expires:displayExpiry,refreshToken:session.refreshToken};
      const body:GraphBody=consumer==="yii3"?{token,nickname:u.nickname??"",user:{id:uid,username:u.username??"",nickname:u.nickname??"",fixture:false}}:consumer==="server"?{success:true,message:"refresh",token}:endpoint==="/v1/common/report"?{success:true,message:"report success",user:{nickname:u.nickname??null,token},data:{watermark:false}}:{success:true,message:"refresh",nickname:u.nickname??null,token};
      const deadline=Math.min(now+(requestHash?30000:5000),credential.expiresAtMs??Infinity,next.expiresAtMs??Infinity);
      const meta:Omit<GraphReplay,"response">={predecessorHash:hash,successorHash:next.credentialHash,userId:uid,familyId:credential.familyId,accountFingerprint:credential.accountFingerprint,accountEpoch:credential.accountEpoch,userEpoch:credential.userEpoch,sourceEncryptedResponse:null,consumer,endpoint,issuer:this.config.jwt.issuer??null,requestHash,createdAtMs:now,expiresAtMs:deadline};
      const replayKey=graphHash(JSON.stringify([graphReplayKey(protocol,meta),now,next.credentialHash]));
      // Expired cache for a reusable predecessor may be replaced after its old
      // exact deadline. A live cache was already returned above under the lock.
      await c.execute(`INSERT INTO identity_legacy_refresh_graph_replays(replay_key,predecessor_hash,successor_hash,family_key,legacy_user_id,source_json,origin,response_sha256,access_token_hash,encrypted_response) VALUES (?,?,?,?,?,?,'native',?,?,?)`,[replayKey,hash,next.credentialHash,family.family_key,uid,JSON.stringify(meta),graphHash(JSON.stringify(body)),graphHash(token.accessToken),encryptGraphBody(body,key,graphBodyAad(protocol,meta))]);
      await c.commit();return this.result(body,meta,Math.floor(access.expiresAt.getTime()/1000));
    }catch(error){await c.rollback();throw error;}finally{c.release();}
  }
  private nativeClaims(token:string,uid:number,sid:string){const verified=this.jwt.verifyAccessToken(token);if(verified.uid!==uid||verified.sessionId!==sid)throw invalid();return JSON.parse(Buffer.from(token.split(".")[1],"base64url").toString()) as Record<string,unknown>;}
  private result(body:GraphBody,meta:Omit<GraphReplay,"response">,exp:number):AuthTokenResponse{
    const t=graphTokens(body);return {success:true,message:"refresh",token:{...t,token:t.accessToken,expires:new Date(exp*1000).toISOString(),tokenType:"Bearer"},legacyResponse:{version:"legacy-refresh-response-v1",consumer:meta.consumer,endpoint:meta.endpoint,body}};
  }
  private async assertCurrent(c:PoolConnection,user:RowDataPacket|undefined,f:RowDataPacket|undefined,credential:GraphCredential,requireEnabled=true){
    if(!user||!f||Number(user.id)!==credential.userId||Number(f.legacy_user_id)!==credential.userId||Number(user.status)!==10||user.deleted_at!=null||f.revoked_at)throw invalid();
    const account=value<{accountFingerprint:string;accountEpoch:string;status:number}>(f.account_snapshot_json);
    if(account.status!==10||account.accountEpoch!==credential.accountEpoch||account.accountFingerprint!==credential.accountFingerprint||legacyRefreshAccountFingerprint(user.password_hash??null,user.auth_key??null)!==account.accountFingerprint)throw invalid();
    const [cutoffs]=await c.execute<RowDataPacket[]>("SELECT revoked_before FROM identity_user_revocations WHERE user_id=? FOR SHARE",[credential.userId]);if(ms(cutoffs[0]?.revoked_before)!==(f.target_cutoff_ms==null?null:Number(f.target_cutoff_ms)))throw invalid();
    if("auth_method" in credential.authContext)await this.reader.assertDeviceSnAuthorized(credential.authContext.device_sn_id,credential.userId,requireEnabled);
  }
  async revoke(raw:string):Promise<boolean>{
    const hash=graphHash(raw),c=await this.db().getConnection();try{
      const [owners]=await c.execute<RowDataPacket[]>("SELECT legacy_user_id FROM identity_legacy_refresh_graph_credentials WHERE credential_hash=?",[hash]);if(!owners[0])return false;
      await c.beginTransaction();await c.execute("SELECT id FROM user WHERE id=? FOR UPDATE",[owners[0].legacy_user_id]);
      const [rows]=await c.execute<RowDataPacket[]>("SELECT family_key FROM identity_legacy_refresh_graph_credentials WHERE credential_hash=? FOR UPDATE",[hash]);if(!rows[0])throw invalid();
      await revokeRefreshGraphFamily(c,String(rows[0].family_key));await c.commit();return true;
    }catch(error){await c.rollback();throw error;}finally{c.release();}
  }
  async isAccessRevoked(raw:string,uid:number,connection?:PoolConnection):Promise<boolean>{
    if(!this.pool)return false;const c=connection??await this.pool.getConnection();try{
      if(!await hasRefreshGraphSchema(c))return false;
      const [rows]=await c.execute<RowDataPacket[]>(`SELECT f.*,c.source_json AS credential_json FROM identity_legacy_refresh_graph_replays r JOIN identity_legacy_refresh_graph_families f ON f.family_key=r.family_key JOIN identity_legacy_refresh_graph_credentials c ON c.credential_hash=r.successor_hash WHERE r.access_token_hash=? AND f.legacy_user_id=?${connection?" FOR SHARE":""}`,[graphHash(raw),uid]);
      for(const f of rows){if(!this.enabled)return true;const [users]=await c.execute<RowDataPacket[]>(`SELECT * FROM user WHERE id=?${connection?" FOR SHARE":""}`,[uid]);try{await this.assertCurrent(c,users[0],f,graphCredentialSchema.parse(value(f.credential_json)),false);}catch{return true;}}
      return false;
    }finally{if(!connection)c.release();}
  }
}
