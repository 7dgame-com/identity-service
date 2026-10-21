import { AdmissionWriter } from "./identity-admission.js";
import { assertNativeUserAllocation } from "./identity-allocator-manifest.js";
import { createHash, createHmac, randomBytes } from "node:crypto";
import { BadRequestException, ConflictException, ForbiddenException, Injectable, NotFoundException, OnApplicationBootstrap, OnModuleDestroy, Optional, ServiceUnavailableException, UnauthorizedException } from "@nestjs/common";
import mysql, { Pool, PoolConnection, ResultSetHeader, RowDataPacket } from "mysql2/promise";
import { z } from "zod";
import { loadConfig } from "./config.js";
import { LegacyIdentityReader, LegacyUserReadModel } from "./legacy-identity.reader.js";
import { JwtIssuerService } from "./jwt-issuer.service.js";
import { IdentitySessionRepository } from "./identity-session.repository.js";
import { hashLegacyPassword } from "./legacy-password.js";
import { validatePasswordPolicy } from "./password-policy.js";
import { enqueueSubjectEvent } from "./subject-events.js";
import { assertAllocatorReady } from "./identity-allocator-state.js";
import { activateIdentityAuthority } from "./migration-state.js";
import { deviceSnSource } from "./device-sn-source.js";
import { revokeLegacyRefreshCredentialsInTransaction } from "./legacy-refresh-credential-revocation.js";
import { LegacyRefreshGraphRepository } from "./legacy-refresh-graph.repository.js";
import { IdentityActivationService } from "./identity-activation.service.js";

export interface NativeRequest { headers: Record<string, string | string[] | undefined>; body?: unknown; }
const positiveId = z.coerce.number().int().positive().max(Number.MAX_SAFE_INTEGER);
const roleLevels: Record<string, number> = { root: 4, admin: 3, manager: 2, user: 1 };

/** Native execution reuses the existing compatibility schema inside the private DB. */
@Injectable()
export class NativeIdentityService implements OnModuleDestroy, OnApplicationBootstrap {
  readonly config = loadConfig();
  private readonly pool: Pool | null;
  constructor(private readonly reader: LegacyIdentityReader, private readonly jwt: JwtIssuerService,
    private readonly sessions: IdentitySessionRepository, @Optional() private readonly activation?: IdentityActivationService, @Optional() private readonly legacyGraph?: LegacyRefreshGraphRepository) {
    const db = this.config.identityDb;
    this.pool = this.enabled && db.host && db.user ? mysql.createPool({ host: db.host, port: db.port,
      database: db.name, user: db.user, password: db.password, connectionLimit: 10, timezone: "Z" }) : null;
  }
  get enabled() { return this.config.dataSource === "identity"; }
  async onApplicationBootstrap() {
    if (!this.enabled) return;
    if (!this.config.tokenIssuance.enabled || Buffer.from(process.env.IDENTITY_REFRESH_REPLAY_KEY ?? "", "base64url").length !== 32
      || !this.config.iam.internalToken || this.config.iam.internalToken.length < 32) {
      throw new Error("Independent Identity requires token issuance, a 32-byte refresh replay key and an internal API token of at least 32 characters");
    }
    if (!this.config.jwt.privateKeyPem && !this.config.jwt.privateKeyFile) throw new Error("Independent Identity requires its signing key");
    this.jwt.assertSigningReady();
    if (this.config.activationMode === "explicit") await this.sessions.useExistingSchema();
    else await this.sessions.ensureSchema();
    for (const table of ["user","user_info","auth_item","auth_assignment","user_organization","identity_native_operations","identity_subject_events","identity_event_clock","identity_profile_avatars"]) {
      await this.db().query(`SELECT 1 FROM ${table} LIMIT 1`);
    }
    const [clock] = await this.db().query<RowDataPacket[]>("SELECT id FROM identity_event_clock WHERE id=1");
    if (!clock.length) throw new Error("Identity event sequence clock is not initialized");
    if (this.config.activationMode === "explicit") {
      if (!this.activation) throw new Error("Explicit activation requires the global activation coordinator");
      await this.activation.warm();
      return;
    }
    const connection=await this.db().getConnection();
    try{await connection.beginTransaction();await connection.execute("SELECT authority FROM identity_migration_control WHERE id=1 FOR UPDATE");await assertAllocatorReady(connection);await activateIdentityAuthority(connection);await connection.commit();}
    catch(error){await connection.rollback();throw error;}finally{connection.release();}
  }
  async onModuleDestroy() { await this.pool?.end(); }
  private db(): Pool { if (!this.enabled || !this.pool) throw new ServiceUnavailableException("Identity account database is unavailable"); return this.pool; }

  async subject(id: number) {
    const user = await this.reader.getUserById(id);
    if (!user) throw new NotFoundException({ code: 4004, message: "用户不存在" });
    const granted = await this.reader.listUserPermissions(id);
    const permissions = granted.map((p) => p.name);
    const directPermissions = granted.filter((p) => p.source === "direct").map((p) => p.name);
    const [avatar] = await this.db().execute<RowDataPacket[]>("SELECT a.avatar_id,u.deleted_at FROM user u LEFT JOIN identity_profile_avatars a ON a.user_id=u.id WHERE u.id = ?", [id]);
    return { ...user, permissions, directPermissions, deletedAt: avatar[0]?.deleted_at == null ? null : Number(avatar[0].deleted_at), avatarId: avatar[0]?.avatar_id == null ? null : Number(avatar[0].avatar_id) };
  }

  async verify(token: string, options?: { audience: string }) {
    let claims;
    try { claims = this.jwt.verifyAccessToken(token, options); } catch { throw new UnauthorizedException({ code: 2001, message: "请先登录" }); }
    if(!options && claims.sessionId && await this.sessions.isOAuthBound(claims.sessionId)) {
      throw new UnauthorizedException({ code: "OAUTH_CLIENT_TOKEN_REQUIRED", message: "Client access tokens must use their bound endpoint" });
    }
    const source = deviceSnSource(claims.authMethod, claims.deviceSnId);
    if (source) await this.reader.assertDeviceSnAuthorized(source.deviceSnId, claims.uid, false);
    const user = await this.subject(claims.uid);
    const payload = JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString("utf8"));
    if (user.status !== 10 || await this.legacyGraph?.isAccessRevoked(token,user.id) || await this.sessions.isAccessRevoked(user.id, Number(payload.iat), claims.sessionId, claims.importedLegacy)) {
      throw new UnauthorizedException({ code: "SESSION_REVOKED", message: "登录已失效" });
    }
    return source ? { ...user, authContext: { auth_method: source.authMethod, device_sn_id: source.deviceSnId } } : user;
  }
  async actor(request: NativeRequest) {
    const header = request.headers.authorization;
    const match = typeof header === "string" ? header.match(/^Bearer\s+(.+)$/i) : null;
    if (!match) throw new UnauthorizedException({ code: 2001, message: "请先登录" });
    return this.verify(match[1]);
  }
  async assertAccessInTransaction(token:string,userId:number,connection:PoolConnection):Promise<void> {
    let claims: ReturnType<JwtIssuerService["verifyAccessToken"]>;
    let payload: { iat: unknown };
    try {
      claims=this.jwt.verifyAccessToken(token);
      payload=JSON.parse(Buffer.from(token.split(".")[1],"base64url").toString("utf8"));
    } catch { throw new UnauthorizedException(); }
    if(claims.uid!==userId || await this.legacyGraph?.isAccessRevoked(token,userId,connection) || (claims.sessionId && await this.sessions.isOAuthBound(claims.sessionId,connection))
      || await this.sessions.isAccessRevoked(userId,Number(payload.iat),claims.sessionId,claims.importedLegacy,connection))throw new UnauthorizedException();
    const source = deviceSnSource(claims.authMethod, claims.deviceSnId);
    if (source) await this.reader.assertDeviceSnAuthorized(source.deviceSnId, userId, false);
  }
  async allowed(userId: number, permission: string) {
    const user = await this.subject(userId);
    return user.status === 10 && (user.roles.includes("root") || permissionCandidates(permission).some((name)=>user.roles.includes(name)||user.permissions.includes(name)));
  }
  async requirePermission(actor: LegacyUserReadModel, permission: string) {
    if (!(await this.allowed(actor.id, permission))) throw new ForbiddenException({ code: 2003, message: "没有权限执行此操作" });
  }
  async currentInfo(request: NativeRequest) {
    const user = await this.actor(request);
    return { success: true, message: "ok", data: { id: user.id, userData: { username: user.username, nickname: user.nickname }, userInfo: { info: user.userInfo, avatar_id: user.avatarId },
      roles: user.roles, perms: user.permissions, organizations: user.organizations, email: user.email,
      emailVerified: !!user.emailVerifiedAt, emailVerifiedAt: user.emailVerifiedAt,
      emailBind: user.email ? { email: user.email, verified: !!user.emailVerifiedAt, verifiedAt: user.emailVerifiedAt } : null } };
  }
  async verifyPlugin(request: NativeRequest) {
    const user = await this.actor(request);
    return { code: 0, message: "ok", data: { id: user.id, username: user.username, nickname: user.nickname,
      roles: user.roles, organizations: user.organizations } };
  }
  async managedUsers(request: NativeRequest, query: Record<string, unknown>) {
    const actor = await this.actor(request);
    if (query.id !== undefined && query.id !== "") {
      await this.requirePermission(actor, "user-management.view-user");
      const target=await this.subject(parse(positiveId,query.id));if(target.deletedAt)throw new NotFoundException("用户不存在");
      return { code: 0, data: serializeUser(target) };
    }
    await this.requirePermission(actor, "user-management.list-users");
    const result = await this.reader.listManagedUsers({ page: parse(z.coerce.number().int().min(1).default(1), query.page),
      pageSize: parse(z.coerce.number().int().min(1).max(100).default(20), query.pageSize),
      search: typeof query.search === "string" ? query.search : undefined,
      status: query.status === undefined || query.status === "" ? undefined : parse(z.coerce.number().int(), query.status),
      sort: typeof query.sort === "string" ? query.sort : undefined, order: query.order === "asc" ? "asc" : "desc" });
    return { code: 0, data: result.users.map(serializeUser), pagination: { page: result.page, pageSize: result.pageSize,
      total: result.total, totalPages: result.totalPages } };
  }

  async profile(request: NativeRequest) {
    const actor = await this.actor(request); const body = record(request.body);
    return this.mutate(request, actor, "profile", async (connection) => {
      if (body.nickname !== undefined) await connection.execute("UPDATE user SET nickname = ?, updated_at = ? WHERE id = ?",
        [parse(z.string().max(255).nullable(), body.nickname), nowSeconds(), actor.id]);
      if (body.info !== undefined) {
        let info = body.info;
        if (typeof info === "string") { try { info = JSON.parse(info); } catch { throw new BadRequestException("info must be valid JSON"); } }
        await connection.execute("INSERT INTO user_info (user_id,info) VALUES (?,?) ON DUPLICATE KEY UPDATE info = VALUES(info)", [actor.id, JSON.stringify(info)]);
      }
      if (body.avatar_id !== undefined) await connection.execute(
        "INSERT INTO identity_profile_avatars (user_id,avatar_id) VALUES (?,?) ON DUPLICATE KEY UPDATE avatar_id = VALUES(avatar_id)",
        [actor.id, body.avatar_id === null ? null : parse(positiveId, body.avatar_id)]);
      await this.event(connection, actor.id);
      const [profiles] = await connection.execute<RowDataPacket[]>("SELECT u.username,u.nickname,i.info,a.avatar_id FROM user u LEFT JOIN user_info i ON i.user_id=u.id LEFT JOIN identity_profile_avatars a ON a.user_id=u.id WHERE u.id=?",[actor.id]);
      const profile = profiles[0];
      return { success: true, message: "ok", data: { id: actor.id, userData: { username: profile.username, nickname: profile.nickname },
        userInfo: { info: profile.info, avatar_id: profile.avatar_id }, roles: actor.roles } };
    });
  }

  async pluginWrite(request: NativeRequest, route: string): Promise<unknown> {
    const actor = await this.actor(request); const body = record(request.body);
    const permission = route === "batch-create-users" ? "create-user" : route;
    await this.requirePermission(actor, `user-management.${permission}`);
    if (route === "batch-create-users") {
      const entries = parse(z.array(z.record(z.unknown())).min(1).max(100), body.users);
      const results: Record<string, unknown>[] = [];
      for (let index = 0; index < entries.length; index++) {
        const headers = { ...request.headers };
        const idempotency = headers["idempotency-key"];
        if (typeof idempotency === "string") headers["idempotency-key"] = `${idempotency}:${index}`;
        try {
          const role = parse(z.enum(["admin", "manager", "user"]), entries[index].role);
          if ((roleLevels[role] ?? 0) > level(actor.roles)) throw new ForbiddenException("不能分配高于自身的角色");
          const result = await this.createUser({ headers, body: { ...entries[index], organization_ids: body.organization_ids ?? body.organizationIds } }, actor, role);
          results.push({ index, username: entries[index].username, success: true, id: result.data.id });
        } catch (error) { results.push({ index, username: entries[index].username, success: false, error: safeMessage(error) }); }
      }
      const success = results.filter((r) => r.success).length;
      return { code: success ? 0 : 4003, data: { total: results.length, success, failed: results.length - success, results } };
    }
    if (route === "create-user") return this.createUser(request, actor, "user");
    const id = parse(positiveId, body.id); const target = await this.subject(id);
    return this.mutate(request, actor, route, async (connection) => {
      await this.lockTarget(connection, id);
      const currentRoles = await rolesFor(connection,id);
      if (route === "change-role") {
        const role = parse(z.enum(["admin", "manager", "user"]), body.role);
        if (currentRoles.includes("root") || level(currentRoles) > level(actor.roles) || roleLevels[role] > level(actor.roles)) throw new ForbiddenException("不能修改此角色");
        await connection.execute("DELETE FROM auth_assignment WHERE user_id = ? AND item_name IN ('root','admin','manager','user')", [String(id)]);
        await this.assignRoles(connection, id, role);
      } else if (route === "delete-user") {
        if (id === actor.id) throw new ForbiddenException({ code: 2007, message: "不能删除当前登录用户" });
        await connection.execute("UPDATE user SET status = 0, deleted_at = ?, updated_at = ? WHERE id = ?", [nowSeconds(), nowSeconds(), id]);
        await this.revokeInTransaction(connection, id);
      } else if (route === "update-user") {
        for (const field of ["nickname", "email", "status"] as const) if (body[field] !== undefined) {
          const value = field === "status" ? parse(z.coerce.number().int().refine((v) => [0, 9, 10].includes(v)), body[field])
            : field === "email" ? optionalEmail(body.email) : parse(z.string().max(255).nullable(), body.nickname);
          await connection.execute(`UPDATE user SET ${field} = ?, updated_at = ? WHERE id = ?`, [value, nowSeconds(), id]);
          if (field === "email" && value !== target.email) await connection.execute("UPDATE user SET email_verified_at = NULL WHERE id = ?", [id]);
          if (field === "status" && value !== 10) await this.revokeInTransaction(connection, id);
        }
        if (typeof body.password === "string" && body.password) {
          passwordPolicy(body.password, target.username, target.email);
          await connection.execute("UPDATE user SET password_hash = ?, updated_at = ? WHERE id = ?", [await hashLegacyPassword(body.password), nowSeconds(), id]);
          await this.revokeInTransaction(connection, id);
        }
        const organizations = organizationIds(body);
        if (organizations !== undefined) await this.replaceOrganizations(connection, id, organizations);
      } else throw new NotFoundException("Unknown user operation");
      await this.event(connection, id);
      if (route === "delete-user") return { code: 0, message: "删除成功" };
      return { code: 0, data: await this.serializeInTransaction(connection, id) };
    });
  }

  private async createUser(request: NativeRequest, actor: LegacyUserReadModel, role: string, commandRoute = `create-user:${role}`) {
    const body = record(request.body); const username = parse(z.string().trim().min(2).max(255), body.username);
    const password = parse(z.string(), body.password); const email = optionalEmail(body.email);
    passwordPolicy(password, username, email);
    const passwordHash = await hashLegacyPassword(password);
    return this.mutate(request, actor, commandRoute, async (connection) => {
      if ((roleLevels[role] ?? 0) > level(actor.roles)) throw new ForbiddenException("不能分配高于自身的角色");
      const [result] = await connection.execute<ResultSetHeader>(
        "INSERT INTO user (username,nickname,email,password_hash,auth_key,status,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)",
        [username, body.nickname == null ? null : parse(z.string().max(255), body.nickname), email, passwordHash,
          randomBytes(24).toString("base64url"), parse(z.coerce.number().int().refine((v) => [0,9,10].includes(v)).default(10), body.status), nowSeconds(), nowSeconds()]);
      const id = assertNativeUserAllocation(result.insertId);
      await connection.execute("INSERT INTO user_info (user_id) VALUES (?)", [id]);
      await this.assignRoles(connection, id, role);
      await this.replaceOrganizations(connection, id, organizationIds(body) ?? []);
      await this.event(connection, id);
      return { code: 0, data: await this.serializeInTransaction(connection, id) };
    });
  }
  private async assignRoles(connection: PoolConnection, id: number, role: string) {
    for (const name of new Set(["user", role])) await connection.execute("INSERT INTO auth_assignment (item_name,user_id,created_at) VALUES (?,?,?)", [name, String(id), nowSeconds()]);
  }
  private async replaceOrganizations(connection: PoolConnection, id: number, ids: number[]) {
    for (const org of ids) {
      const [rows] = await connection.execute<RowDataPacket[]>("SELECT id FROM organization WHERE id = ?", [org]);
      if (!rows.length) throw new BadRequestException("组织不存在");
    }
    await connection.execute("DELETE FROM user_organization WHERE user_id = ?", [id]);
    for (const org of new Set(ids)) await connection.execute("INSERT INTO user_organization (user_id,organization_id) VALUES (?,?)", [id,org]);
  }

  async organization(request: NativeRequest, route: string, query: Record<string, unknown> = {}) {
    const actor = await this.actor(request);
    await this.requirePermission(actor, `organization.${route === "unbind-user" ? "bind-user" : route}`);
    if (route === "list") {
      const organizations = await this.reader.listOrganizations();
      const rawNames = typeof query.names === "string" ? query.names.split(",") : Array.isArray(query.names) ? query.names : [];
      const names=[...new Set(rawNames.filter((name):name is string=>typeof name==="string").map(name=>name.trim().toLowerCase()).filter(Boolean))];
      return { code: 0, message: "ok", data: organizations.filter((o) => !names.length || names.includes(o.name)).map(serializeOrganization) };
    }
    const body = record(request.body);
    return this.mutate(request, actor, `organization:${route}`, async (connection) => {
      if (route === "create") {
        const name=parse(z.string().trim().toLowerCase().min(1).max(64).regex(/^[a-z0-9][a-z0-9-]*$/),body.name);
        const title=parse(z.string().trim().min(1).max(255),body.title);
        await connection.execute("INSERT IGNORE INTO identity_organization_name_locks(name) VALUES (?)",[name]);
        await connection.execute("SELECT name FROM identity_organization_name_locks WHERE name=? FOR UPDATE",[name]);
        const [existing]=await connection.execute<RowDataPacket[]>("SELECT id FROM organization WHERE name=? LIMIT 1",[name]);
        if(existing.length)throw new ConflictException("组织名称已存在");
        const [result] = await connection.execute<ResultSetHeader>("INSERT INTO organization (name,title,created_at,updated_at) VALUES (?,?,?,?)",
          [name,title,nowSeconds(),nowSeconds()]);
        return { code: 0, message: "ok", data: { id: Number(result.insertId), name, title } };
      }
      if (route === "update") {
        const id = parse(positiveId,body.id);
        const [result] = await connection.execute<ResultSetHeader>("UPDATE organization SET title = ?, updated_at = ? WHERE id = ?",[parse(z.string().trim().min(1).max(255),body.title),nowSeconds(),id]);
        if (!result.affectedRows) throw new NotFoundException("组织不存在");
        const [members] = await connection.execute<RowDataPacket[]>("SELECT user_id FROM user_organization WHERE organization_id = ?", [id]);
        for (const member of members) await this.event(connection,Number(member.user_id));
        const [rows] = await connection.execute<RowDataPacket[]>("SELECT id,name,title FROM organization WHERE id = ?", [id]);
        return { code:0,message:"ok",data: rows[0] };
      }
      const id = parse(positiveId,body.user_id); const org = parse(positiveId,body.organization_id);
      await this.lockTarget(connection,id);
      const [organizations] = await connection.execute<RowDataPacket[]>("SELECT id FROM organization WHERE id = ?",[org]);
      if (!organizations.length) throw new NotFoundException("组织不存在");
      if (route === "bind-user") await connection.execute("INSERT IGNORE INTO user_organization (user_id,organization_id) VALUES (?,?)",[id,org]);
      else if (route === "unbind-user") await connection.execute("DELETE FROM user_organization WHERE user_id = ? AND organization_id = ?",[id,org]);
      else throw new NotFoundException();
      await this.event(connection,id);
      return { code:0,message:"ok",data:{user_id:id,organization_id:org} };
    });
  }

  async person(request: NativeRequest, route: "index"|"view"|"create"|"update"|"delete"|"auth", id?: number, query: Record<string,unknown> = {}) {
    const actor = await this.actor(request);
    if (!actor.roles.some((role)=>role==="root"||role==="admin")) throw new ForbiddenException("权限不足");
    await this.requirePermission(actor,`/v1/person/${route}`);
    const body=record(request.body);
    if(route==="index") {
      const result=await this.reader.listManagedUsers({page:parse(z.coerce.number().int().min(1).default(1),query.page),pageSize:20,
        search:typeof query["PersonSearch[username]"]==="string"?query["PersonSearch[username]"] as string:undefined,
        sort:typeof query.sort==="string"?query.sort:undefined,order:"desc"});
      const avatarIds=new Map<number,number|null>();
      if(result.users.length){const [avatars]=await this.db().execute<RowDataPacket[]>(`SELECT user_id,avatar_id FROM identity_profile_avatars WHERE user_id IN (${result.users.map(()=>"?").join(",")})`,result.users.map(user=>user.id));for(const avatar of avatars)avatarIds.set(Number(avatar.user_id),avatar.avatar_id==null?null:Number(avatar.avatar_id));}
      return {body:result.users.map(user=>personUser(user,avatarIds.get(user.id)??null)),pagination:{page:result.page,pageSize:result.pageSize,total:result.total,totalPages:result.totalPages}};
    }
    if(route==="view") { const target=await this.subject(parse(positiveId,id));if(target.deletedAt)throw new NotFoundException();return {body:personUser(target,target.avatarId)}; }
    if(route==="create") {
      const created=await this.createUser(request,actor,"user","person:create");
      const user=await this.subject(created.data.id);
      const session=await this.sessions.issue({legacyUserId:user.id,username:user.username,sessionId:randomBytes(24).toString("hex"),expiresAt:new Date(Date.now()+this.config.tokenIssuance.refreshTokenTtlSeconds*1000)});
      return {body:{access_token:this.jwt.issue(user,session.sessionId).accessToken,code:20000}};
    }
    const targetId=parse(positiveId,route==="auth"?body.id:id);
    const response=await this.mutate(request,actor,`person:${route}`,async(connection)=>{
      await this.lockTarget(connection,targetId);
      const targetRoles=await rolesFor(connection,targetId);
      const root=actor.roles.includes("root");
      if(targetRoles.includes("root"))throw new BadRequestException("root用户不可修改");
      if(route==="auth") {
        const role=parse(z.enum(["admin","manager","user"]),body.auth);
        if(!root && role==="admin")throw new BadRequestException("权限不足");
        await connection.execute("DELETE FROM auth_assignment WHERE user_id=? AND item_name IN ('admin','manager','user')",[String(targetId)]);
        await this.assignRoles(connection,targetId,role);await this.event(connection,targetId);
        const [items]=await connection.execute<RowDataPacket[]>("SELECT name,type FROM auth_item WHERE type=1 OR name NOT LIKE '/%' ORDER BY name");
        const [assignments]=await connection.execute<RowDataPacket[]>("SELECT item_name FROM auth_assignment WHERE user_id=?",[String(targetId)]);
        const names=new Set(assignments.map(a=>String(a.item_name)));const available:Record<string,string>={},assigned:Record<string,string>={};
        for(const item of items)(names.has(item.name)?assigned:available)[item.name]=Number(item.type)===1?"role":"permission";
        return {available,assigned,success:role==="user"?1:2};
      }
      if(targetId===actor.id)throw new BadRequestException(route==="delete"?"不能删除自己":"不能修改自己");
      if(!root && (targetRoles.includes("admin") || (route==="update" && targetRoles.includes("manager"))))throw new BadRequestException("权限不足");
      if(route==="delete") {
        await connection.execute("UPDATE user SET status=0,deleted_at=?,updated_at=? WHERE id=?",[nowSeconds(),nowSeconds(),targetId]);
        await this.revokeInTransaction(connection,targetId);await this.event(connection,targetId);return {success:true};
      }
      if(!Object.hasOwn(body,"nickname"))throw new BadRequestException("缺乏 nickname 数据");
      const nickname=body.nickname===null?null:parse(z.string().trim().max(255),body.nickname)||null;
      await connection.execute("UPDATE user SET nickname=?,updated_at=? WHERE id=?",[nickname,nowSeconds(),targetId]);await this.event(connection,targetId);
      const user=await this.serializeInTransaction(connection,targetId);return {success:true,data:{id:targetId,username:user.username,nickname:user.nickname,organizations:user.organizations}};
    });
    return {body:response};
  }

  async campusPassword(request: NativeRequest) {
    const actor = await this.actor(request); const body = record(request.body);
    if (level(actor.roles) < 2) throw new ForbiddenException();
    const org = parse(positiveId,body.organization_id);
    if (!actor.roles.includes("root") && !actor.roles.includes("admin") && !actor.organizations.some((o) => o.id === org)) throw new ForbiddenException();
    const ids = body.user_ids === undefined ? [] : parse(z.array(positiveId).max(500),body.user_ids);
    const [members] = await this.db().execute<RowDataPacket[]>("SELECT user_id FROM user_organization WHERE organization_id = ?",[org]);
    const selected = ids.length ? ids : members.map((m) => Number(m.user_id));
    const memberIds = new Set(members.map((m) => Number(m.user_id)));
    const results = [];
    for (const id of selected) {
      const target = await this.subject(id);
      if (!memberIds.has(id) || id === actor.id || target.roles.includes("root") || (!actor.roles.includes("root") && target.roles.includes("admin"))) continue;
      const password = parse(z.string(),body.password); passwordPolicy(password,target.username,target.email);
      await this.mutate({ ...request, body: { id, password }, headers: { ...request.headers, "idempotency-key": typeof request.headers["idempotency-key"] === "string" ? `${request.headers["idempotency-key"]}:${id}` : undefined } },actor,`campus-password:${id}`,async (connection) => {
        await this.lockTarget(connection,id);
        const [member] = await connection.execute<RowDataPacket[]>("SELECT user_id FROM user_organization WHERE user_id=? AND organization_id=?",[id,org]);
        const targetRoles = await rolesFor(connection,id);
        const [actorMember] = await connection.execute<RowDataPacket[]>("SELECT user_id FROM user_organization WHERE user_id=? AND organization_id=?",[actor.id,org]);
        if (!member.length || id===actor.id || level(actor.roles)<2 || targetRoles.includes("root")
          || (!actor.roles.includes("root") && targetRoles.includes("admin"))
          || (!actor.roles.includes("root") && !actor.roles.includes("admin") && !actorMember.length)) throw new ForbiddenException();
        await connection.execute("UPDATE user SET password_hash = ?, updated_at = ? WHERE id = ?",[await hashLegacyPassword(password),nowSeconds(),id]);
        await this.revokeInTransaction(connection,id); await this.event(connection,id); return {code:0};
      });
      results.push({id,username:target.username,success:true,message:"密码已更新"});
    }
    return {code:0,message:"ok",data:{success_count:results.length,failed_count:0,skipped_count:selected.length-results.length,results}};
  }

  async events(after: number, limit: number) {
    const [rows] = await this.db().execute<RowDataPacket[]>(`SELECT id,user_id,version FROM identity_subject_events WHERE id > ? ORDER BY id LIMIT ${Math.max(1,Math.min(limit,500))}`,[after]);
    const events = [];
    for (const row of rows) events.push({id:Number(row.id),userId:Number(row.user_id),version:Number(row.id),subject:await this.subject(Number(row.user_id))});
    return { events, nextCursor: rows.length ? Number(rows[rows.length-1].id) : after };
  }
  async organizationMembers(id:number) {
    const [orgs]=await this.db().execute<RowDataPacket[]>("SELECT id,name,title FROM organization WHERE id=?",[id]);
    if(!orgs.length)throw new NotFoundException("组织不存在");
    const [users]=await this.db().execute<RowDataPacket[]>("SELECT u.id,u.username,u.nickname,u.email,u.status FROM user u JOIN user_organization m ON m.user_id=u.id WHERE m.organization_id=? AND u.deleted_at IS NULL ORDER BY u.id LIMIT 10001",[id]);
    if(users.length>10000)throw new ServiceUnavailableException("Organization member export requires pagination");
    if(!users.length)return {organization:orgs[0],subjects:[]};
    const marks=users.map(()=>"?").join(","), ids=users.map(u=>String(u.id));
    const [roles]=await this.db().execute<RowDataPacket[]>(`SELECT a.user_id,a.item_name FROM auth_assignment a JOIN auth_item i ON i.name=a.item_name WHERE i.type=1 AND a.user_id IN (${marks}) ORDER BY a.item_name`,ids);
    const [memberships]=await this.db().execute<RowDataPacket[]>(`SELECT m.user_id,o.id,o.name,o.title FROM user_organization m JOIN organization o ON o.id=m.organization_id WHERE m.user_id IN (${marks}) ORDER BY o.title,o.id`,ids);
    return {organization:orgs[0],subjects:users.map(u=>({...u,id:Number(u.id),status:Number(u.status),roles:roles.filter(r=>Number(r.user_id)===Number(u.id)).map(r=>String(r.item_name)),
      organizations:memberships.filter(m=>Number(m.user_id)===Number(u.id)).map(m=>({id:Number(m.id),name:String(m.name),title:String(m.title)}))}))};
  }
  private async lockTarget(connection: PoolConnection,id:number) {
    const [rows] = await connection.execute<RowDataPacket[]>("SELECT id FROM user WHERE id = ? AND deleted_at IS NULL FOR UPDATE",[id]);
    if (!rows.length) throw new NotFoundException("用户不存在");
  }
  private async revokeInTransaction(connection:PoolConnection,id:number) {
    await revokeLegacyRefreshCredentialsInTransaction(connection,id);
    await connection.execute("UPDATE identity_refresh_sessions SET revoked_at=COALESCE(revoked_at,UTC_TIMESTAMP(3)) WHERE legacy_user_id = ?",[id]);
    await connection.execute("INSERT INTO identity_user_revocations (user_id,revoked_before) VALUES (?,UTC_TIMESTAMP(3)) ON DUPLICATE KEY UPDATE revoked_before=UTC_TIMESTAMP(3)",[id]);
  }
  private async event(connection:PoolConnection,id:number) { await enqueueSubjectEvent(connection,id); }
  private async serializeInTransaction(connection:PoolConnection,id:number) {
    const [users] = await connection.execute<RowDataPacket[]>("SELECT id,username,nickname,email,status,created_at,updated_at FROM user WHERE id = ?",[id]);
    const [organizations] = await connection.execute<RowDataPacket[]>("SELECT o.id,o.name,o.title FROM organization o JOIN user_organization uo ON o.id=uo.organization_id WHERE uo.user_id = ? ORDER BY o.title,o.id",[id]);
    return {...users[0],id,username:users[0].username,nickname:users[0].nickname,roles:await rolesFor(connection,id),organizations};
  }
  @AdmissionWriter()
  private async mutate<T>(request:NativeRequest,actor:LegacyUserReadModel,route:string,work:(connection:PoolConnection)=>Promise<T>):Promise<T> {
    const connection = await this.db().getConnection();
    const key = typeof request.headers["idempotency-key"] === "string" ? request.headers["idempotency-key"] : randomBytes(24).toString("hex");
    if (key.length > 200) { connection.release(); throw new BadRequestException("Idempotency-Key too long"); }
    const operation = createHash("sha256").update(`${actor.id}:${route}:${key}`).digest("hex");
    const secret = process.env.IDENTITY_REFRESH_REPLAY_KEY;
    if (!secret) { connection.release(); throw new ServiceUnavailableException("Native request fingerprint key is required"); }
    const fingerprint = createHmac("sha256",secret).update(canonicalJson(request.body)).digest("hex");
    try {
      await connection.beginTransaction();
      await connection.execute("INSERT INTO identity_native_operations (operation_key,request_hash) VALUES (?,?) ON DUPLICATE KEY UPDATE operation_key=VALUES(operation_key)",[operation,fingerprint]);
      const [operations] = await connection.execute<RowDataPacket[]>("SELECT request_hash,response FROM identity_native_operations WHERE operation_key = ? FOR UPDATE",[operation]);
      if (operations[0].request_hash !== fingerprint) throw new ConflictException("Idempotency-Key was used for a different request");
      await this.lockTarget(connection,actor.id);
      const [users] = await connection.execute<RowDataPacket[]>("SELECT status FROM user WHERE id = ?",[actor.id]);
      if (Number(users[0]?.status) !== 10) throw new UnauthorizedException();
      const authorization=request.headers.authorization;
      const token=typeof authorization==="string"?authorization.replace(/^Bearer\s+/i,""):"";
      await this.assertAccessInTransaction(token,actor.id,connection);
      actor.roles = await rolesFor(connection, actor.id);
      const required = route.startsWith("create-user:") ? "user-management.create-user"
        : ["change-role","delete-user","update-user"].includes(route) ? `user-management.${route}`
        : route.startsWith("organization:") ? `organization.${route.slice(13) === "unbind-user" ? "bind-user" : route.slice(13)}` : null;
      if (route.startsWith("person:") && (level(actor.roles)<3 || !(await allowedInTransaction(connection,actor.id,actor.roles,`/v1/person/${route.slice(7)}`)))) throw new ForbiddenException();
      if (required && !(await allowedInTransaction(connection,actor.id,actor.roles,required))) throw new ForbiddenException();
      if (operations[0].response !== null) { await connection.commit(); return typeof operations[0].response === "string" ? JSON.parse(operations[0].response) : operations[0].response; }
      const response = await work(connection);
      await connection.execute("UPDATE identity_native_operations SET response = ? WHERE operation_key = ?",[JSON.stringify(response),operation]);
      await connection.commit(); return response;
    } catch (error) {
      await connection.rollback();
      if ((error as {code?:string}).code === "ER_DUP_ENTRY") throw new ConflictException({code:4002,message:"用户名或邮箱已存在"});
      throw error;
    } finally { connection.release(); }
  }
}

function parse<S extends z.ZodTypeAny>(schema:S,value:unknown):z.output<S> { const result=schema.safeParse(value); if (!result.success) throw new BadRequestException(result.error.flatten()); return result.data; }
function record(value:unknown):Record<string,unknown> { return parse(z.record(z.unknown()),value??{}); }
function optionalEmail(value:unknown):string|null { return value===undefined || value===null || value==="" ? null : parse(z.string().trim().toLowerCase().email().max(255),value); }
function passwordPolicy(password:string,username:string|null,email:string|null) { const errors=validatePasswordPolicy(password,{username,email}); if(errors.length) throw new BadRequestException({code:4001,message:errors.join("；"),errors}); }
function organizationIds(body:Record<string,unknown>):number[]|undefined { const value=body.organization_ids??body.organizationIds??(body.organization_id===undefined?undefined:[body.organization_id]); return value===undefined?undefined:parse(z.array(positiveId).max(100),value); }
function nowSeconds() { return Math.floor(Date.now()/1000); }
function level(roles:string[]) { return Math.max(0,...roles.map((role)=>roleLevels[role]??0)); }
function serializeUser(user:LegacyUserReadModel) { return {id:user.id,username:user.username,nickname:user.nickname??user.username,email:user.email,status:user.status,created_at:user.createdAt,updated_at:user.updatedAt,roles:user.roles,organizations:user.organizations.map(serializeOrganization)}; }
function serializeOrganization(org:{id:number;name:string;title:string}) { return {id:org.id,name:org.name,title:org.title}; }
async function rolesFor(connection:PoolConnection,id:number):Promise<string[]> { const [rows]=await connection.execute<RowDataPacket[]>("SELECT aa.item_name FROM auth_assignment aa JOIN auth_item ai ON ai.name=aa.item_name AND ai.type=1 WHERE aa.user_id=? ORDER BY aa.item_name",[String(id)]); return rows.map((r)=>String(r.item_name)); }
function safeMessage(error:unknown) { return error instanceof BadRequestException || error instanceof ForbiddenException || error instanceof ConflictException ? error.message : "创建用户失败"; }
function canonicalJson(value:unknown):string { if(Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`; if(value&&typeof value==="object") return `{${Object.keys(value).sort().map((key)=>`${JSON.stringify(key)}:${canonicalJson((value as Record<string,unknown>)[key])}`).join(",")}}`; return JSON.stringify(value)??"null"; }

async function allowedInTransaction(connection:PoolConnection,id:number,roles:string[],permission:string) {
  const candidates=permissionCandidates(permission);
  if (roles.includes("root") || candidates.some((name)=>roles.includes(name))) return true;
  const [rows] = await connection.execute<RowDataPacket[]>(`WITH RECURSIVE grants_tree(name) AS (
    SELECT item_name FROM auth_assignment WHERE user_id=?
    UNION DISTINCT SELECT a.child FROM auth_item_child a JOIN grants_tree g ON g.name=a.parent
  ) SELECT name FROM grants_tree WHERE name IN (${candidates.map(()=>"?").join(",")}) LIMIT 1`,[String(id),...candidates]);
  return rows.length>0;
}
function permissionCandidates(permission:string):string[] {
  if (!permission.startsWith("/")) return [permission];
  const names=[permission];let path=permission;
  while(path.includes("/")){path=path.slice(0,path.lastIndexOf("/"));names.push(`${path}/*`);}
  return [...new Set(names)];
}

function personUser(user:LegacyUserReadModel,avatarId:number|null) { return {id:user.id,username:user.username,nickname:user.nickname,email:user.email,created_at:user.createdAt,roles:user.roles,avatar:null,avatar_id:avatarId,organizations:user.organizations.map(serializeOrganization)}; }
