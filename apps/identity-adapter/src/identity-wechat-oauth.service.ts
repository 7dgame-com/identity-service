import { AdmissionWriter } from "./identity-admission.js";
import { assertNativeUserAllocation } from "./identity-allocator-manifest.js";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { BadRequestException, ConflictException, Inject, Injectable, OnModuleDestroy, ServiceUnavailableException, UnauthorizedException } from "@nestjs/common";
import mysql, { Pool, RowDataPacket, ResultSetHeader } from "mysql2/promise";
import { z } from "zod";
import { loadConfig } from "./config.js";
import { LegacyIdentityReader, LegacyUserReadModel } from "./legacy-identity.reader.js";
import { IdentitySessionRepository } from "./identity-session.repository.js";
import { JwtIssuerService } from "./jwt-issuer.service.js";
import { enqueueSubjectEvent } from "./subject-events.js";
import { NativeIdentityService } from "./native-identity.service.js";
import { verifyImportedAuthAccessToken } from "./auth-imported-token-verifier.js";
import { verifyLegacyPassword } from "./legacy-password.js";

const profileSchema = z.object({
  provider: z.enum(["wechat_official_account", "wechat_website", "wechat_mini_program"]),
  providerAppId: z.string().min(1).max(191), openId: z.string().min(1).max(191),
  unionId: z.string().min(1).max(191).optional(), nickname: z.string().max(255).optional(),
  avatarUrl: z.string().max(4096).optional(), raw: z.record(z.unknown()).optional()
});
export type IdentityWechatProfile = z.infer<typeof profileSchema>;
const clientSchema = z.object({ clientId: z.string().min(1).max(128), redirectUris: z.array(z.string().url()).min(1),
  scopes: z.array(z.string()).default(["openid", "profile"]), publicClient: z.boolean().default(true), clientSecret: z.string().optional() });
type BridgeClient = z.infer<typeof clientSchema>;
const codeSchema = z.object({ codeHash: z.string().regex(/^[a-zA-Z0-9_-]{43}$/), clientId: z.string(), userId: z.coerce.number().int().positive(),
  redirectUri: z.string().url(), codeChallenge: z.string().min(43).max(128).optional(), codeChallengeMethod: z.enum(["plain", "S256"]).optional(),
  scopes: z.array(z.string()).min(1), expiresAt: z.string().datetime(), createdAt: z.string().datetime() });

@Injectable()
export class IdentityWechatOAuthService implements OnModuleDestroy {
  readonly config = loadConfig();
  private readonly pool: Pool | null;
  private readonly clients: BridgeClient[];
  constructor(@Inject(LegacyIdentityReader) private readonly reader: LegacyIdentityReader,
    @Inject(IdentitySessionRepository) private readonly sessions: IdentitySessionRepository,
    @Inject(JwtIssuerService) private readonly jwt: JwtIssuerService,
    @Inject(NativeIdentityService) private readonly native: NativeIdentityService) {
    const db = this.config.identityDb;
    this.pool = this.config.dataSource === "identity" && db.host && db.user
      ? mysql.createPool({host:db.host,port:db.port,database:db.name,user:db.user,password:db.password,timezone:"Z",connectionLimit:5}) : null;
    const configured: unknown = JSON.parse(this.config.wechatOauth.clientsJson);
    this.clients = z.array(clientSchema).parse(Array.isArray(configured) && configured.length ? configured : defaultClients());
  }
  async onModuleDestroy() { await this.pool?.end(); }
  metadata() { this.enabled(); return {issuer:this.config.jwt.issuer,...this.jwt.jwks()}; }

  /** Provider proof was checked by auth-service. Never match a user by email or display name. */
  @AdmissionWriter()
  async resolveWechat(payload: IdentityWechatProfile, createAccount = false): Promise<{userId:number|null;signupToken:string|null}> {
    const profile = parse(profileSchema,payload); const connection = await this.db().getConnection();
    try {
      await connection.beginTransaction();
      await connection.execute(`INSERT INTO identity_wechat_identities (provider,provider_app_id,open_id,union_id,profile_json)
        VALUES (?,?,?,?,?) ON DUPLICATE KEY UPDATE open_id=VALUES(open_id)`,
        [profile.provider,profile.providerAppId,profile.openId,profile.unionId??null,JSON.stringify({...profile.raw,nickname:profile.nickname,avatarUrl:profile.avatarUrl})]);
      const [bindings] = await connection.execute<RowDataPacket[]>(`SELECT provider,provider_app_id,open_id,user_id,union_id FROM identity_wechat_identities
        WHERE provider=? AND provider_app_id=? AND open_id=? FOR UPDATE`,[profile.provider,profile.providerAppId,profile.openId]);
      const binding = bindings[0];
      if(!binding || binding.provider!==profile.provider || binding.provider_app_id!==profile.providerAppId || binding.open_id!==profile.openId) throw new ConflictException("Provider identity requires a binary-collation schema migration");
      if (binding.union_id && profile.unionId && binding.union_id !== profile.unionId) throw new BadRequestException("Provider identity changed union ID");
      await connection.execute(`INSERT INTO wechat (openid,unionid,token,created_at,updated_at) VALUES (?,?,?,UTC_TIMESTAMP(3),UTC_TIMESTAMP(3))
        ON DUPLICATE KEY UPDATE id=LAST_INSERT_ID(id)`,[profile.openId,null,randomBytes(32).toString("base64url")]);
      const [rows] = await connection.execute<RowDataPacket[]>("SELECT id,openid,unionid,user_id,token FROM wechat WHERE BINARY openid=BINARY ? OR (? IS NOT NULL AND BINARY unionid=BINARY ?) ORDER BY id FOR UPDATE",
        [profile.openId,profile.unionId??null,profile.unionId??null]);
      const exactWechat=rows.find((row)=>row.openid===profile.openId);
      if(!exactWechat)throw new BadRequestException("Provider registration identity is missing");
      // A global compatibility openid cannot establish ownership in a new app.
      // Only the exact binding or a provider-verified union ID can carry it over.
      const unionRows=profile.unionId?rows.filter((row)=>row.unionid===profile.unionId):[];
      let unionBindings:RowDataPacket[]=[];
      if(profile.unionId) [unionBindings]=await connection.execute<RowDataPacket[]>("SELECT user_id FROM identity_wechat_identities WHERE BINARY union_id=BINARY ?",[profile.unionId]);
      const unionCandidates=[...unionRows,...unionBindings];
      if(binding.user_id==null && exactWechat.user_id!=null && !unionCandidates.some((row)=>row.user_id!=null && Number(row.user_id)===Number(exactWechat.user_id))) {
        throw new ConflictException("An exact app binding is required for this legacy WeChat account");
      }
      const ids = new Set<number>((binding.user_id!=null?[binding.user_id]:unionCandidates.map((row)=>row.user_id)).filter((id)=>id!=null).map(Number));
      if (ids.size > 1) throw new BadRequestException("Provider bindings conflict; explicit reconciliation is required");
      let userId = ids.size ? [...ids][0] : null;
      if (userId === null && createAccount) {
        const now = Math.floor(Date.now()/1000);
        const username = `wx_${createHash("sha256").update(`${profile.provider}:${profile.providerAppId}:${profile.openId}`).digest("hex").slice(0,40)}`;
        const [created] = await connection.execute<ResultSetHeader>(`INSERT INTO user (username,nickname,auth_key,status,created_at,updated_at)
          VALUES (?,?,?,10,?,?)`,[username,profile.nickname??null,randomBytes(24).toString("base64url"),now,now]);
        userId = assertNativeUserAllocation(created.insertId);
        await connection.execute("INSERT INTO user_info (user_id,info) VALUES (?,?)",[userId,JSON.stringify({wechatAvatarUrl:profile.avatarUrl??null})]);
        await connection.execute("INSERT INTO auth_assignment (item_name,user_id,created_at) VALUES ('user',?,?)",[String(userId),now]);
        await enqueueSubjectEvent(connection,userId);
      }
      if (userId !== null) {
        const [users] = await connection.execute<RowDataPacket[]>("SELECT status,deleted_at FROM user WHERE id=? FOR UPDATE",[userId]);
        if (Number(users[0]?.status)!==10 || users[0].deleted_at) throw new UnauthorizedException({error:"invalid_grant"});
        if(exactWechat.user_id==null || Number(exactWechat.user_id)===userId)
          await connection.execute("UPDATE wechat SET user_id=?,updated_at=UTC_TIMESTAMP(3) WHERE id=?",[userId,exactWechat.id]);
      }
      if(profile.unionId && !exactWechat.unionid && !unionRows.length) await connection.execute("UPDATE wechat SET unionid=? WHERE id=?",[profile.unionId,exactWechat.id]);
      await connection.execute(`UPDATE identity_wechat_identities SET user_id=?,union_id=COALESCE(union_id,?),profile_json=?,signup_token_hash=?
        WHERE provider=? AND provider_app_id=? AND open_id=?`,
        [userId,profile.unionId??null,JSON.stringify({...profile.raw,nickname:profile.nickname,avatarUrl:profile.avatarUrl}),userId===null?createHash("sha256").update(String(exactWechat.token)).digest("hex"):null,profile.provider,profile.providerAppId,profile.openId]);
      await connection.commit();
      return {userId,signupToken:userId===null?String(exactWechat.token):null};
    } catch(error) { await connection.rollback(); throw error; } finally { connection.release(); }
  }

  async resolve(payload: unknown) {
    const {profile} = parse(z.object({profile:profileSchema}),payload);
    const resolved = await this.resolveWechat(profile,true); const user = await this.user(resolved.userId!);
    return {user,identity:{id:`${profile.provider}:${profile.providerAppId}:${profile.openId}`,userId:user.id,...profile},isNewIdentity:false};
  }

  /** A confirmed, unexpired scan and the account password are both required. */
  @AdmissionWriter()
  async bindExisting(payload: unknown): Promise<{ user: LegacyUserReadModel; expectedPasswordHash: string }> {
    const body = parse(
      z.object({
        token: z.string().min(1).max(255),
        username: z.string().min(1).max(255),
        password: z.string().min(1).max(1024)
      }),
      payload
    );
    const pool = this.db();
    const tokenHash = createHash("sha256").update(body.token).digest("hex");
    const sceneSql = `SELECT scene_hash,expires_at,provider_app_id,open_id,user_id,profile_json
      FROM identity_wechat_scenes WHERE (scene_hash=? OR signup_token_hash=?) AND expires_at>? ORDER BY scene_hash LIMIT 101`;
    const [candidates] = await pool.execute<RowDataPacket[]>(sceneSql, [
      tokenHash,
      tokenHash,
      Math.floor(Date.now() / 1000)
    ]);
    const scope = bindingScope(candidates);
    const credential = await this.reader.getUserCredentialByUsername(body.username);
    if (
      !credential?.passwordHash ||
      credential.status !== 10 ||
      !(await verifyLegacyPassword(body.password, credential.passwordHash))
    )
      throw bindingUnauthorized();
    // Fail before committing a binding when this process cannot issue the resulting session.
    if (!this.config.tokenIssuance.enabled || !this.sessions.isConfigured())
      throw new ServiceUnavailableException("Token issuance is not configured");
    this.jwt.assertSigningReady();
    const connection = await pool.getConnection();
    try {
      await connection.query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED");
      await connection.beginTransaction();
      // Match resolver/registration lock order: exact provider, legacy compatibility row, user, scene.
      await connection.execute(
        `INSERT INTO identity_wechat_identities (provider,provider_app_id,open_id,profile_json)
        VALUES ('wechat_official_account',?,?,?) ON DUPLICATE KEY UPDATE open_id=open_id`,
        [scope.appId, scope.openId, JSON.stringify(scope.profile)]
      );
      const [bindings] = await connection.execute<RowDataPacket[]>(
        `SELECT user_id,provider_app_id,open_id FROM identity_wechat_identities
        WHERE provider='wechat_official_account' AND provider_app_id=? AND open_id=? FOR UPDATE`,
        [scope.appId, scope.openId]
      );
      const binding = bindings[0];
      if (!binding || binding.provider_app_id !== scope.appId || binding.open_id !== scope.openId)
        throw bindingUnauthorized();
      await connection.execute(
        `INSERT INTO wechat (openid,token,created_at,updated_at) VALUES (?,?,UTC_TIMESTAMP(3),UTC_TIMESTAMP(3))
        ON DUPLICATE KEY UPDATE id=LAST_INSERT_ID(id)`,
        [scope.openId, randomBytes(32).toString("base64url")]
      );
      const [wechatRows] = await connection.execute<RowDataPacket[]>(
        "SELECT id,openid,user_id FROM wechat WHERE openid=? FOR UPDATE",
        [scope.openId]
      );
      const wechat = wechatRows[0];
      if (!wechat || wechat.openid !== scope.openId) throw bindingUnauthorized();
      const [users] = await connection.execute<RowDataPacket[]>(
        "SELECT id,status,password_hash,wx_openid,deleted_at FROM user WHERE id=? FOR UPDATE",
        [credential.id]
      );
      const user = users[0];
      if (!user || Number(user.status) !== 10 || user.deleted_at || user.password_hash !== credential.passwordHash)
        throw bindingUnauthorized();
      // The locked user serializes assignments. A current, nonlocking read avoids
      // deadlocking another pending provider row that is waiting for this user.
      const [otherBindings] = await connection.execute<RowDataPacket[]>(
        `SELECT open_id FROM identity_wechat_identities
        WHERE provider='wechat_official_account' AND provider_app_id=? AND user_id=?`,
        [scope.appId, credential.id]
      );
      if (otherBindings.some((entry) => entry.open_id !== scope.openId))
        throw new ConflictException("用户已经存在该微信应用的其他绑定");
      const [scenes] = await connection.execute<RowDataPacket[]>(`${sceneSql} FOR UPDATE`, [
        tokenHash,
        tokenHash,
        Math.floor(Date.now() / 1000)
      ]);
      const current = bindingScope(scenes);
      if (current.appId !== scope.appId || current.openId !== scope.openId) throw bindingUnauthorized();
      if (
        [binding.user_id, ...scenes.map((scene) => scene.user_id)].some(
          (id) => id != null && Number(id) !== credential.id
        )
      )
        throw new ConflictException("微信账号或用户已经存在其他绑定");
      const changed = binding.user_id == null || wechat.user_id == null || !user.wx_openid;
      if (changed) {
        await connection.execute(
          `UPDATE identity_wechat_identities SET user_id=?,signup_token_hash=NULL
          WHERE provider='wechat_official_account' AND provider_app_id=? AND open_id=?`,
          [credential.id, scope.appId, scope.openId]
        );
        if(wechat.user_id==null || Number(wechat.user_id)===credential.id)
          await connection.execute("UPDATE wechat SET user_id=?,updated_at=UTC_TIMESTAMP(3) WHERE id=?", [credential.id,wechat.id]);
        await connection.execute("UPDATE user SET wx_openid=COALESCE(NULLIF(wx_openid,''),?),updated_at=? WHERE id=?", [
          scope.openId,
          Math.floor(Date.now() / 1000),
          credential.id
        ]);
        await enqueueSubjectEvent(connection, credential.id);
      }
      // Keep the existing challenge digest and expiry for safe same-account retries.
      for (const scene of scenes)
        if (scene.user_id == null)
          await connection.execute("UPDATE identity_wechat_scenes SET user_id=? WHERE scene_hash=?", [
            credential.id,
            scene.scene_hash
          ]);
      await connection.commit();
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
    return { user: await this.requireUser(credential.id), expectedPasswordHash: credential.passwordHash };
  }

  @AdmissionWriter()
  async createCode(payload: unknown) {
    const code = parse(codeSchema,payload); const client = this.client(code.clientId);
    if (!client.redirectUris.includes(code.redirectUri) || !code.scopes.every((scope)=>client.scopes.includes(scope))) throw invalidGrant();
    await this.requireUser(code.userId);
    const expiresAt = new Date(code.expiresAt);
    if (expiresAt.getTime()<=Date.now() || expiresAt.getTime()>Date.now()+this.config.wechatOauth.authorizationCodeTtlSeconds*1000+5000) throw invalidGrant();
    await this.db().execute(`INSERT INTO identity_wechat_oauth_codes (code_hash,client_id,user_id,redirect_uri,code_challenge,code_challenge_method,scopes_json,expires_at,created_at)
      VALUES (?,?,?,?,?,?,?,?,?)`,[code.codeHash,code.clientId,code.userId,code.redirectUri,code.codeChallenge??null,code.codeChallengeMethod??null,JSON.stringify(code.scopes),expiresAt,new Date(code.createdAt)]);
    return {success:true};
  }

  @AdmissionWriter()
  async token(payload: unknown) {
    const body = parse(z.record(z.unknown()),payload); const client = this.client(String(body.client_id??""));
    if (!client.publicClient && !secretEqual(client.clientSecret,body.client_secret)) throw new UnauthorizedException({error:"invalid_client"});
    if (body.grant_type === "refresh_token") return this.refresh(client,body);
    if (body.grant_type !== "authorization_code") throw new BadRequestException({error:"unsupported_grant_type"});
    if (typeof body.code!=="string" || typeof body.redirect_uri!=="string") throw invalidGrant();
    const connection = await this.db().getConnection();
    try {
      await connection.beginTransaction();
      const [rows] = await connection.execute<RowDataPacket[]>("SELECT * FROM identity_wechat_oauth_codes WHERE code_hash=? FOR UPDATE",[digest(body.code)]);
      const code = rows[0];
      if (!code || code.consumed_at || new Date(code.expires_at).getTime()<=Date.now() || code.client_id!==client.clientId || code.redirect_uri!==body.redirect_uri) throw invalidGrant();
      if (code.code_challenge && (typeof body.code_verifier!=="string" || !secretEqual(String(code.code_challenge),code.code_challenge_method==="S256"?digest(body.code_verifier):body.code_verifier))) throw invalidGrant();
      const user = await this.requireUser(Number(code.user_id)); const scopes = stringArray(code.scopes_json);
      if (!scopes.every((scope)=>client.scopes.includes(scope))) throw invalidGrant();
      this.jwt.assertSigningReady();
      const session = await this.sessions.issue({legacyUserId:user.id,username:user.username,sessionId:randomBytes(24).toString("base64url"),
        expiresAt:new Date(Date.now()+this.config.wechatOauth.refreshTokenTtlSeconds*1000)});
      await connection.execute("INSERT INTO identity_oauth_session_bindings (session_id,client_id,scopes_json) VALUES (?,?,?)",[session.sessionId,client.clientId,JSON.stringify(scopes)]);
      await connection.execute("UPDATE identity_wechat_oauth_codes SET consumed_at=UTC_TIMESTAMP(3) WHERE code_hash=?",[code.code_hash]);
      await connection.commit();
      return this.tokens(user,client,scopes,session.sessionId,session.refreshToken);
    } catch(error) { await connection.rollback(); throw error; } finally { connection.release(); }
  }

  @AdmissionWriter()
  private async refresh(client: BridgeClient, body: Record<string,unknown>) {
    if (typeof body.refresh_token!=="string" || body.refresh_token.length>4096) throw invalidGrant();
    let current; try { current = await this.sessions.findRefreshCandidate(body.refresh_token); } catch { throw invalidGrant(); }
    const binding = await this.binding(current.sessionId);
    if (!binding || binding.clientId!==client.clientId) throw invalidGrant();
    const scopes = binding.scopes;
    if (!scopes.every((scope)=>client.scopes.includes(scope))) throw invalidGrant();
    const user = await this.requireUser(current.legacyUserId);
    this.jwt.assertSigningReady();
    let next;
    try { next = await this.sessions.rotate(body.refresh_token,{legacyUserId:user.id,username:user.username,sessionId:current.sessionId,
      expiresAt:new Date(Date.now()+this.config.wechatOauth.refreshTokenTtlSeconds*1000)},typeof body.idempotency_key==="string"?body.idempotency_key:undefined); }
    catch { throw invalidGrant(); }
    return this.tokens(user,client,scopes,next.sessionId,next.refreshToken);
  }
  @AdmissionWriter()
  async revoke(payload: unknown) {
    const body = parse(z.object({token:z.string().max(4096)}),payload); await this.sessions.revoke(body.token); return {success:true};
  }
  async userinfo(authorization?: string) {
    if (!authorization?.startsWith("Bearer ")) throw new UnauthorizedException({error:"invalid_token"});
    const token = authorization.slice(7);
    let payload:Record<string,unknown>;
    try { payload=JSON.parse(Buffer.from(token.split(".")[1],"base64url").toString()); } catch { throw new UnauthorizedException({error:"invalid_token"}); }
    if(typeof payload.session_id!=="string") return this.importedUserinfo(token);
    const binding=await this.binding(payload.session_id);
    if (!binding || payload.aud!==binding.clientId || payload.scope!==binding.scopes.join(" ")) throw new UnauthorizedException({error:"invalid_token"});
    this.client(binding.clientId);
    const user=await this.native.verify(token,{audience:binding.clientId}); const detail=await this.user(user.id);
    return {sub:String(user.id),unionid:detail.primaryUnionId,name:detail.displayName,picture:detail.avatarUrl};
  }
  private async importedUserinfo(token:string) {
    let claims;try {claims=verifyImportedAuthAccessToken(token);}catch{throw new UnauthorizedException({error:"invalid_token"});}
    const client=this.client(claims.audience);if(!claims.scopes.every((scope)=>client.scopes.includes(scope)))throw new UnauthorizedException({error:"invalid_token"});
    const [maps]=await this.db().execute<RowDataPacket[]>("SELECT user_id,status FROM identity_auth_subject_maps WHERE auth_user_id=?",[claims.subject]);
    if(!maps[0] || maps[0].status!=="active" || await this.sessions.isAccessRevoked(Number(maps[0].user_id),claims.issuedAt,null,true))throw new UnauthorizedException({error:"invalid_token"});
    const user=await this.user(Number(maps[0].user_id));
    // Preserve the old sub for this bounded old credential; newly issued tokens use the canonical ID.
    return {sub:claims.subject,unionid:user.primaryUnionId,name:user.displayName,picture:user.avatarUrl};
  }
  async user(id: number) {
    const user=await this.requireUser(id); const [profiles]=await this.db().execute<RowDataPacket[]>("SELECT union_id,profile_json FROM identity_wechat_identities WHERE user_id=? ORDER BY updated_at DESC LIMIT 1",[id]);
    const raw=profiles[0]?.profile_json; const profile=typeof raw==="string"?JSON.parse(raw):raw??{};
    return {id:String(id),status:"active",displayName:user.nickname??user.username,primaryUnionId:profiles[0]?.union_id??undefined,avatarUrl:profile.headimgurl??profile.avatarUrl,
      createdAt:new Date((user.createdAt??0)*1000).toISOString(),updatedAt:new Date((user.updatedAt??0)*1000).toISOString()};
  }
  async paymentIdentity(userId:unknown,providerAppId:unknown):Promise<{providerAppId:string;openId:string;unionId:string|null}|null> {
    const input=parse(z.object({userId:z.coerce.number().int().positive().max(Number.MAX_SAFE_INTEGER),providerAppId:z.string().min(1).max(191)}),{userId,providerAppId});
    const [rows]=await this.db().execute<RowDataPacket[]>(`SELECT provider_app_id,open_id,union_id FROM identity_wechat_identities
      WHERE user_id=? AND provider='wechat_official_account' AND BINARY provider_app_id=BINARY ? ORDER BY open_id LIMIT 2`,[input.userId,input.providerAppId]);
    if(rows.length>1)throw new BadRequestException("Multiple payment provider bindings require explicit reconciliation");
    if(rows[0] && rows[0].provider_app_id!==input.providerAppId) throw new BadRequestException("Payment provider application mismatch");
    return rows[0]?{providerAppId:input.providerAppId,openId:String(rows[0].open_id),unionId:rows[0].union_id==null?null:String(rows[0].union_id)}:null;
  }
  private tokens(user:LegacyUserReadModel,client:BridgeClient,scopes:string[],sessionId:string,refreshToken:string) {
    const access=this.jwt.issue(user,sessionId,{audience:client.clientId,scopes,expiresInSeconds:this.config.wechatOauth.accessTokenTtlSeconds});
    const id=this.jwt.issueOidcIdToken({user,issuer:this.config.jwt.issuer,audience:client.clientId,authTime:new Date(),scope:scopes,expiresInSeconds:this.config.wechatOauth.accessTokenTtlSeconds});
    return {access_token:access.accessToken,token_type:"Bearer",expires_in:this.config.wechatOauth.accessTokenTtlSeconds,refresh_token:refreshToken,id_token:id.accessToken,scope:scopes.join(" ")};
  }
  private async binding(sessionId:string) { const [rows]=await this.db().execute<RowDataPacket[]>("SELECT client_id,scopes_json FROM identity_oauth_session_bindings WHERE session_id=?",[sessionId]); return rows[0]?{clientId:String(rows[0].client_id),scopes:stringArray(rows[0].scopes_json)}:null; }
  private async requireUser(id:number) { const user=await this.reader.getUserById(id);if(!user||user.status!==10)throw invalidGrant();return user; }
  private client(id:string) { const client=this.clients.find((entry)=>entry.clientId===id);if(!client)throw new UnauthorizedException({error:"invalid_client"});return client; }
  private enabled() { if(this.config.dataSource!=="identity" || !this.pool) throw new ServiceUnavailableException("Independent Identity database is required"); }
  private db() { this.enabled();return this.pool!; }
}
function parse<T extends z.ZodTypeAny>(schema:T,value:unknown):z.infer<T> { const parsed=schema.safeParse(value);if(!parsed.success)throw new BadRequestException({error:"invalid_request"});return parsed.data; }
function digest(value:string) { return createHash("sha256").update(value).digest("base64url"); }
function secretEqual(a:unknown,b:unknown) { if(typeof a!=="string"||typeof b!=="string")return false;const left=Buffer.from(a),right=Buffer.from(b);return left.length===right.length&&timingSafeEqual(left,right); }
function stringArray(value:unknown):string[] { const parsed=typeof value==="string"?JSON.parse(value):value;if(!Array.isArray(parsed)||!parsed.every((item)=>typeof item==="string"))throw invalidGrant();return parsed; }
function invalidGrant() { return new BadRequestException({error:"invalid_grant"}); }
function bindingUnauthorized() { return new UnauthorizedException("微信扫码凭据或账号密码无效"); }
function bindingScope(rows: RowDataPacket[]) {
  if (!rows.length || rows.length > 100) throw bindingUnauthorized();
  const first = rows[0];
  if (
    !first.provider_app_id ||
    !first.open_id ||
    rows.some((row) => row.provider_app_id !== first.provider_app_id || row.open_id !== first.open_id)
  )
    throw bindingUnauthorized();
  let profile: Record<string, unknown> = {};
  for (const row of rows) {
    const raw = row.profile_json;
    const candidate: Record<string, unknown> = typeof raw === "string" ? JSON.parse(raw) : (raw ?? {});
    if (
      (candidate.providerAppId != null && candidate.providerAppId !== first.provider_app_id) ||
      (candidate.openId != null && candidate.openId !== first.open_id)
    )
      throw bindingUnauthorized();
    if (row === first) profile = candidate;
  }
  return { appId: String(first.provider_app_id), openId: String(first.open_id), profile };
}
function defaultClients() { return [{clientId:"bujiaban-web",redirectUris:["https://bujiaban.com/auth/callback","http://localhost:3010/auth/callback"],scopes:["openid","profile"],publicClient:true},
  {clientId:"3dugc-web",redirectUris:["https://3dugc.com/auth/callback"],scopes:["openid","profile"],publicClient:true}]; }
