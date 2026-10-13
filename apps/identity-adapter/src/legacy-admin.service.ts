import { assertNativeUserAllocation } from "./identity-allocator-manifest.js";
import { BadRequestException, ConflictException, ForbiddenException, Injectable, OnModuleDestroy, ServiceUnavailableException } from "@nestjs/common";
import { createHash, createHmac, randomBytes } from "node:crypto";
import mysql, { Pool, PoolConnection, RowDataPacket, ResultSetHeader } from "mysql2/promise";
import { z } from "zod";
import { loadConfig } from "./config.js";
import { NativeIdentityService, NativeRequest } from "./native-identity.service.js";
import { enqueueSubjectEvent } from "./subject-events.js";
import { hashLegacyPassword } from "./legacy-password.js";
import { validatePasswordPolicy } from "./password-policy.js";
import { revokeLegacyRefreshCredentialsInTransaction } from "./legacy-refresh-credential-revocation.js";

/** Keeps Yii administration views while making the private DB the only writer. */
@Injectable()
export class LegacyAdminService implements OnModuleDestroy {
  readonly config=loadConfig();private readonly pool:Pool|null;
  constructor(private readonly native:NativeIdentityService){const d=this.config.identityDb;this.pool=this.config.dataSource==="identity"&&d.host&&d.user?mysql.createPool({host:d.host,port:d.port,user:d.user,password:d.password,database:d.name,timezone:"Z",connectionLimit:5}):null;}
  async onModuleDestroy(){await this.pool?.end();}
  private db(){if(!this.pool)throw new ServiceUnavailableException();return this.pool;}
  async invitations(request:NativeRequest){return this.authorized(request,false,async(c,actor,roles)=>{
    const [items]=await c.query<RowDataPacket[]>("SELECT name FROM auth_item WHERE type=1 AND name<>'root' ORDER BY name");
    const [rows]=await c.execute<RowDataPacket[]>("SELECT i.*,u.username AS recipient_username FROM invitation i LEFT JOIN user u ON u.id=i.recipient_id WHERE sender_id=? ORDER BY id DESC",[actor]);
    return {invitations:rows,roles:roles.includes("root")?items:[{name:"user"}]};
  });}
  async createInvitation(request:NativeRequest){const input=parse(z.object({role:z.string().min(1).max(128)}),request.body);return this.authorized(request,false,async(c,actor,roles)=>{
    await exactNames(c,"auth_item",[input.role]);
    if(input.role==="root"||(!roles.includes("root")&&input.role!=="user"))throw new ForbiddenException();
    const [items]=await c.execute<RowDataPacket[]>("SELECT name FROM auth_item WHERE name=? AND type=1",[input.role]);if(!items.length)throw new BadRequestException("Unknown invitation role");
    return this.once(c,request,`invite:${actor}`,input,async()=>{const created=localTimestamp();await this.dayLock(c,created.slice(0,10));return this.insertInvitation(c,actor,input.role,created);});
  });}
  async quota(){const day=localDay();const [rows]=await this.db().execute<RowDataPacket[]>("SELECT COUNT(*) AS count FROM invitation WHERE create_at>=? AND create_at<DATE_ADD(?,INTERVAL 1 DAY)",[day,day]);return {count:Number(rows[0].count),limit:10};}
  async users(request:NativeRequest,operation:string):Promise<unknown>{
    const body=parse(z.object({id:z.coerce.number().int().positive().optional(),page:z.coerce.number().int().min(1).default(1),pageSize:z.coerce.number().int().min(1).max(100).default(20),username:z.string().max(255).optional(),email:z.string().max(255).optional(),status:z.coerce.number().int().optional(),password:z.string().optional()}),request.body??{});
    if(["user-create","user-activate","user-delete"].includes(operation)){
      const passwordHash=operation==="user-create"?await hashLegacyPassword(body.password??""):null;
      if(operation==="user-create"){
        if(!body.username||!body.password)throw new BadRequestException("Username and password are required");
        const errors=validatePasswordPolicy(body.password,{username:body.username,email:body.email});if(errors.length)throw new BadRequestException({errors});
        if(body.email&&!z.string().email().safeParse(body.email).success)throw new BadRequestException("Invalid email");
      }
      return this.authorized(request,true,async(c,actor)=>{
        const permission=request.headers["x-identity-admin-route"];
        const suffix=operation==="user-create"?"signup":operation==="user-delete"?"delete":"activate";
        if(typeof permission==="string"&&permission!==`/admin/user/${suffix}`)throw new ForbiddenException();
        return this.once(c,request,`${operation}:${actor}`,body,async()=>{
          const now=Math.floor(Date.now()/1000);
          if(operation==="user-create"){
            let id:number;try{const [inserted]=await c.execute<ResultSetHeader>("INSERT INTO user(username,email,password_hash,status,created_at,updated_at) VALUES (?,?,?,10,?,?)",[body.username!,body.email??null,passwordHash,now,now]);id=assertNativeUserAllocation(inserted.insertId);}catch(error){if((error as {code?:string}).code==="ER_DUP_ENTRY")throw new ConflictException("Username or email already exists");throw error;}
            await c.execute("INSERT INTO user_info(user_id) VALUES (?)",[id]);await c.execute("INSERT INTO auth_assignment(item_name,user_id,created_at) VALUES ('user',?,?)",[String(id),now]);await enqueueSubjectEvent(c,id);
            return {id,username:body.username,email:body.email??null,nickname:null,status:10,created_at:now,updated_at:now};
          }
          if(!body.id)throw new BadRequestException("id is required");
          const [users]=await c.execute<RowDataPacket[]>("SELECT id,status FROM user WHERE id=? AND deleted_at IS NULL FOR UPDATE",[body.id]);if(!users[0])throw new BadRequestException("Unknown user");
          if(operation==="user-delete"){
            if(body.id===actor)throw new ForbiddenException("Cannot delete the current account");
            const [root]=await c.execute<RowDataPacket[]>("SELECT item_name FROM auth_assignment WHERE user_id=? AND item_name='root'",[String(body.id)]);
            if(root.length){const [actors]=await c.execute<RowDataPacket[]>("SELECT item_name FROM auth_assignment WHERE user_id=? AND item_name='root'",[String(actor)]);if(!actors.length)throw new ForbiddenException("Root accounts require a root actor");}
            await c.execute("UPDATE user SET status=0,deleted_at=?,updated_at=? WHERE id=?",[now,now,body.id]);
            await revokeLegacyRefreshCredentialsInTransaction(c,body.id);
            await c.execute("UPDATE identity_refresh_sessions SET revoked_at=COALESCE(revoked_at,UTC_TIMESTAMP(3)),replaced_by_hash=NULL WHERE legacy_user_id=?",[body.id]);await c.execute("INSERT INTO identity_user_revocations(user_id,revoked_before) VALUES (?,UTC_TIMESTAMP(3)) ON DUPLICATE KEY UPDATE revoked_before=UTC_TIMESTAMP(3)",[body.id]);
          }else await c.execute("UPDATE user SET status=10,updated_at=? WHERE id=?",[now,body.id]);
          await enqueueSubjectEvent(c,body.id);return {success:true};
        });
      });
    }
    return this.authorized(request,true,async c=>{
      const fields="id,username,nickname,email,status,created_at,updated_at";
      if(operation==="user-view"){if(!body.id)throw new BadRequestException("id is required");const [rows]=await c.execute<RowDataPacket[]>(`SELECT ${fields} FROM user WHERE id=? AND deleted_at IS NULL`,[body.id]);if(!rows[0])throw new BadRequestException("Unknown user");return rows[0];}
      const clauses=["deleted_at IS NULL"],params:(string|number)[]=[];
      for(const field of ["id","status"] as const)if(body[field]!==undefined){clauses.push(`${field}=?`);params.push(body[field]);}
      for(const field of ["username","email"] as const)if(body[field]){clauses.push(`${field} LIKE ?`);params.push(`%${body[field]}%`);}
      const where=clauses.join(" AND ");const [count]=await c.execute<RowDataPacket[]>(`SELECT COUNT(*) AS total FROM user WHERE ${where}`,params);
      const [rows]=await c.query<RowDataPacket[]>(`SELECT ${fields} FROM user WHERE ${where} ORDER BY id DESC LIMIT ? OFFSET ?`,[...params,body.pageSize,(body.page-1)*body.pageSize]);return {users:rows,total:Number(count[0].total),page:body.page,pageSize:body.pageSize};
    });
  }
  /** Only the internal PHP bridge can attest a previously validated business Info row. */
  async trial(payload:unknown){const {claimId}=parse(z.object({claimId:z.string().min(1).max(160)}),payload),key=createHash("sha256").update(`business-info:${claimId}`).digest("hex");return this.transaction(async c=>{
    await c.execute("INSERT INTO identity_legacy_trial_claims(claim_key) VALUES (?) ON DUPLICATE KEY UPDATE claim_key=VALUES(claim_key)",[key]);
    const [claims]=await c.execute<RowDataPacket[]>("SELECT invitation_id FROM identity_legacy_trial_claims WHERE claim_key=? FOR UPDATE",[key]);
    if(claims[0].invitation_id){const [rows]=await c.execute<RowDataPacket[]>("SELECT * FROM invitation WHERE id=?",[claims[0].invitation_id]);if(!rows[0])throw new ConflictException("Trial invitation requires reconciliation");return rows[0];}
    const [roots]=await c.query<RowDataPacket[]>("SELECT u.id FROM user u JOIN auth_assignment a ON a.user_id=CAST(u.id AS CHAR) AND a.item_name='root' WHERE u.status=10 AND u.deleted_at IS NULL ORDER BY u.id LIMIT 1 FOR SHARE");if(!roots[0])throw new ConflictException("No active invitation issuer");
    const created=localTimestamp(),day=await this.dayLock(c,created.slice(0,10));const [counts]=await c.execute<RowDataPacket[]>("SELECT COUNT(*) AS count FROM invitation WHERE create_at>=? AND create_at<DATE_ADD(?,INTERVAL 1 DAY)",[day,day]);if(Number(counts[0].count)>=10)throw new ConflictException("Daily invitation quota reached");
    const invitation=await this.insertInvitation(c,Number(roots[0].id),"user",created);await c.execute("UPDATE identity_legacy_trial_claims SET invitation_id=? WHERE claim_key=?",[invitation.id,key]);return invitation;
  });}
  async snapshot(request:NativeRequest){return this.authorized(request,true,c=>this.policy(c,true));}
  async policy(connection?:PoolConnection,assignments=false):Promise<Record<string,unknown>>{
    if(!connection)return this.transaction(c=>this.policy(c,assignments));
    await connection.query("SELECT id FROM identity_event_clock WHERE id=1 FOR SHARE");
    const response:Record<string,unknown>={};for(const [table,key] of [["auth_item","items"],["auth_item_child","children"],["auth_rule","rules"],...(assignments?[["auth_assignment","assignments"]]:[])] as string[][]){const [rows]=await (connection??this.db()).query<RowDataPacket[]>(`SELECT * FROM ${table} LIMIT 50001`);if(rows.length>50000)throw new ConflictException("Administration snapshot exceeds its reviewed budget");response[key]=rows.map(row=>({...row,...("data" in row?{data:row.data==null?null:Buffer.from(row.data).toString("base64"),dataBase64:row.data==null?null:Buffer.from(row.data).toString("base64")}:{} )}));}return response;
  }
  async mutateRbac(request:NativeRequest){const body=parse(z.object({operation:z.enum(["item-put","item-remove","edge-add","edge-remove","edges-remove","assign","revoke","revoke-all","rule-put","rule-remove"]),name:z.string().min(1).max(128).optional(),oldName:z.string().min(1).max(128).optional(),type:z.number().int().min(1).max(2).optional(),description:z.string().max(65535).nullable().optional(),rule_name:z.string().max(64).nullable().optional(),data:z.string().max(87384).nullable().optional(),parent:z.string().min(1).max(128).optional(),child:z.string().min(1).max(128).optional(),userId:z.number().int().positive().optional()}),request.body);
    return this.authorized(request,true,async(c,actor)=>this.once(c,request,`rbac:${actor}`,body,async()=>{
      // Serialize policy edits before inspecting or traversing the graph.
      await c.query("SELECT id FROM identity_event_clock WHERE id=1 FOR UPDATE");
      await assertCurrentAdministrator(c,request,actor);
      const route=request.headers["x-identity-admin-route"];if(typeof route==="string"&&!/^\/admin\/(role|permission|rule|route|assignment)\/(create|update|delete|assign|remove|revoke|remove-all)$/.test(route))throw new ForbiddenException();
      await exactNames(c,body.operation.startsWith("rule-")?"auth_rule":"auth_item",[body.name,body.oldName,body.parent,body.child]);
      if(body.rule_name)await exactNames(c,"auth_rule",[body.rule_name]);
      const name=body.name??"",now=Math.floor(Date.now()/1000),canonical=["root","admin","manager","user"];
      const requireName=()=>{if(!name)throw new BadRequestException("name is required");return name;};
      const affected=new Set<number>();let global=false;
      switch(body.operation){
        case "item-put": {
          requireName();if(!body.type)throw new BadRequestException("type is required");const old=body.oldName??name!;
          if(canonical.includes(old)&&(old!==name||body.type!==1))throw new ConflictException("Canonical role identity is immutable");
          if(body.rule_name){const [rules]=await c.execute<RowDataPacket[]>("SELECT name FROM auth_rule WHERE name=?",[body.rule_name]);if(!rules.length)throw new BadRequestException("Unknown rule");}
          if(old!==name){const [existing]=await c.execute<RowDataPacket[]>("SELECT name FROM auth_item WHERE name=?",[name]);if(existing.length)throw new ConflictException("Item already exists");const [found]=await c.execute<RowDataPacket[]>("SELECT name FROM auth_item WHERE name=?",[old]);if(!found.length)throw new BadRequestException("Unknown item");
            await c.execute("UPDATE auth_item SET name=? WHERE name=?",[name,old]);await c.execute("UPDATE auth_assignment SET item_name=? WHERE item_name=?",[name,old]);await c.execute("UPDATE auth_item_child SET parent=? WHERE parent=?",[name,old]);await c.execute("UPDATE auth_item_child SET child=? WHERE child=?",[name,old]);await c.execute("UPDATE invitation SET auth_item_name=? WHERE auth_item_name=?",[name,old]);}
          await c.execute("INSERT INTO auth_item(name,type,description,rule_name,data,created_at,updated_at) VALUES (?,?,?,?,?,?,?) ON DUPLICATE KEY UPDATE type=VALUES(type),description=VALUES(description),rule_name=VALUES(rule_name),data=VALUES(data),updated_at=VALUES(updated_at)",[name,body.type,body.description??null,body.rule_name??null,decode(body.data),now,now]);global=true;break;
        }
        case "item-remove":requireName();if(canonical.includes(name!))throw new ConflictException("Canonical roles cannot be deleted");await c.execute("DELETE FROM auth_assignment WHERE item_name=?",[name]);await c.execute("DELETE FROM auth_item_child WHERE parent=? OR child=?",[name,name]);await c.execute("DELETE FROM auth_item WHERE name=?",[name]);global=true;break;
        case "edges-remove":if(!body.parent)throw new BadRequestException("parent is required");await c.execute("DELETE FROM auth_item_child WHERE parent=?",[body.parent]);global=true;break;
        case "edge-add":case "edge-remove":{
          if(!body.parent||!body.child||body.parent===body.child)throw new BadRequestException("Invalid edge");
          if(body.operation==="edge-add"){
            const [items]=await c.execute<RowDataPacket[]>("SELECT name,type FROM auth_item WHERE name IN (?,?)",[body.parent,body.child]);if(items.length!==2||Number(items.find(i=>i.name===body.parent)?.type)===2&&Number(items.find(i=>i.name===body.child)?.type)===1)throw new BadRequestException("Invalid RBAC items");
            const [cycle]=await c.execute<RowDataPacket[]>("WITH RECURSIVE descendants(name) AS (SELECT child FROM auth_item_child WHERE parent=? UNION DISTINCT SELECT e.child FROM auth_item_child e JOIN descendants d ON e.parent=d.name) SELECT name FROM descendants WHERE name=? LIMIT 1",[body.child,body.parent]);if(cycle.length)throw new ConflictException("RBAC cycle");
            await c.execute("INSERT IGNORE INTO auth_item_child(parent,child) VALUES (?,?)",[body.parent,body.child]);
          }else await c.execute("DELETE FROM auth_item_child WHERE parent=? AND child=?",[body.parent,body.child]);global=true;break;
        }
        case "assign":case "revoke":case "revoke-all":{
          if(!body.userId)throw new BadRequestException("userId is required");const [users]=await c.execute<RowDataPacket[]>("SELECT id,status FROM user WHERE id=? AND deleted_at IS NULL FOR UPDATE",[body.userId]);if(!users.length)throw new BadRequestException("Unknown user");
          if(body.operation==="assign"){requireName();const [items]=await c.execute<RowDataPacket[]>("SELECT name FROM auth_item WHERE name=?",[name]);if(!items.length)throw new BadRequestException("Unknown item");await c.execute("INSERT IGNORE INTO auth_assignment(item_name,user_id,created_at) VALUES (?,?,?)",[name,String(body.userId),now]);}
          else {if(body.operation==="revoke")requireName();const removesRoot=body.operation==="revoke-all"||name==="root";if(removesRoot){const [root]=await c.execute<RowDataPacket[]>("SELECT a.user_id FROM auth_assignment a JOIN user u ON CAST(u.id AS CHAR)=a.user_id WHERE a.item_name='root' AND u.status=10 AND u.deleted_at IS NULL FOR UPDATE");if(root.some(r=>String(r.user_id)===String(body.userId))&&root.length<=1)throw new ConflictException("Cannot remove the final root");}await c.execute(body.operation==="revoke-all"?"DELETE FROM auth_assignment WHERE user_id=?":"DELETE FROM auth_assignment WHERE user_id=? AND item_name=?",body.operation==="revoke-all"?[String(body.userId)]:[String(body.userId),name]);}affected.add(body.userId);break;
        }
        case "rule-put":requireName();if(name.length>64)throw new BadRequestException();if(body.oldName&&body.oldName!==name){const [found]=await c.execute<RowDataPacket[]>("SELECT name FROM auth_rule WHERE name IN (?,?)",[body.oldName,name]);if(found.length!==1||found[0].name!==body.oldName)throw new ConflictException("Rule rename conflict");await c.execute("UPDATE auth_rule SET name=? WHERE name=?",[name,body.oldName]);await c.execute("UPDATE auth_item SET rule_name=? WHERE rule_name=?",[name,body.oldName]);}await c.execute("INSERT INTO auth_rule(name,data,created_at,updated_at) VALUES (?,?,?,?) ON DUPLICATE KEY UPDATE data=VALUES(data),updated_at=VALUES(updated_at)",[name,decode(body.data),now,now]);global=true;break;
        case "rule-remove":requireName();await c.execute("UPDATE auth_item SET rule_name=NULL WHERE rule_name=?",[name]);await c.execute("DELETE FROM auth_rule WHERE name=?",[name]);global=true;break;
      }
      if(global){const [users]=await c.query<RowDataPacket[]>("SELECT id FROM user WHERE deleted_at IS NULL LIMIT 10001");if(users.length>10000)throw new ConflictException("Policy fanout exceeds the reviewed administration budget");for(const u of users)affected.add(Number(u.id));}
      for(const id of [...affected].sort((a,b)=>a-b))await enqueueSubjectEvent(c,id);return {success:true,changed:true};
    }));
  }
  private async authorized<T>(request:NativeRequest,rootOnly:boolean,work:(c:PoolConnection,actor:number,roles:string[])=>Promise<T>){const actor=await this.native.actor(request);return this.transaction(async c=>{const [users]=await c.execute<RowDataPacket[]>("SELECT status FROM user WHERE id=? AND deleted_at IS NULL FOR UPDATE",[actor.id]);if(Number(users[0]?.status)!==10)throw new ForbiddenException();await this.native.assertAccessInTransaction(String(request.headers.authorization).replace(/^Bearer\s+/i,""),actor.id,c);const [rows]=await c.execute<RowDataPacket[]>("SELECT item_name FROM auth_assignment WHERE user_id=?",[String(actor.id)]),roles=rows.map(r=>String(r.item_name));if(!roles.includes("root")){if(rootOnly){const permission=request.headers["x-identity-admin-route"];if(typeof permission!=="string"||!/^\/admin\/[a-z-]+\/[a-z-]+$/.test(permission)||permission.length>256||!await administrationAllowed(c,actor.id,permission))throw new ForbiddenException();}else if(!roles.includes("agent"))throw new ForbiddenException();}return work(c,actor.id,roles);});}
  private async transaction<T>(work:(c:PoolConnection)=>Promise<T>):Promise<T>{for(let attempt=0;;attempt++){const c=await this.db().getConnection();try{await c.query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED");await c.beginTransaction();const value=await work(c);await c.commit();return value;}catch(error){await c.rollback();if(attempt<4&&["ER_LOCK_DEADLOCK","ER_LOCK_WAIT_TIMEOUT"].includes(String((error as {code?:string}).code))){await new Promise(resolve=>setTimeout(resolve,10*(attempt+1)));continue;}throw error;}finally{c.release();}}}
  private async dayLock(c:PoolConnection,day=localDay()){await c.execute("INSERT INTO identity_legacy_invitation_days(day) VALUES (?) ON DUPLICATE KEY UPDATE day=VALUES(day)",[day]);await c.execute("SELECT day FROM identity_legacy_invitation_days WHERE day=? FOR UPDATE",[day]);return day;}
  private async insertInvitation(c:PoolConnection,sender:number,role:string,created=localTimestamp()){const code=`${sender}_${randomBytes(24).toString("base64url")}`;const [r]=await c.execute<ResultSetHeader>("INSERT INTO invitation(code,sender_id,used,auth_item_name,create_at) VALUES (?,?,0,?,?)",[code,sender,role,created]);return {id:Number(r.insertId),code,sender_id:sender,recipient_id:null,used:0,auth_item_name:role,create_at:created};}
  private async once<T>(c:PoolConnection,request:NativeRequest,scope:string,input:unknown,work:()=>Promise<T>):Promise<T>{const key=request.headers["idempotency-key"];if(key===undefined)return work();if(typeof key!=="string"||!key||key.length>200)throw new BadRequestException("Invalid Idempotency-Key");const secret=process.env.IDENTITY_REFRESH_REPLAY_KEY;if(!secret)throw new ServiceUnavailableException();const op=createHash("sha256").update(`legacy-admin:${scope}:${key}`).digest("hex"),hash=createHmac("sha256",secret).update(JSON.stringify(input)).digest("hex");await c.execute("INSERT INTO identity_native_operations(operation_key,request_hash) VALUES (?,?) ON DUPLICATE KEY UPDATE operation_key=VALUES(operation_key)",[op,hash]);const [rows]=await c.execute<RowDataPacket[]>("SELECT request_hash,response FROM identity_native_operations WHERE operation_key=? FOR UPDATE",[op]);if(rows[0].request_hash!==hash)throw new ConflictException("Idempotency-Key conflict");if(rows[0].response!=null)return typeof rows[0].response==="string"?JSON.parse(rows[0].response):rows[0].response;const value=await work();await c.execute("UPDATE identity_native_operations SET response=? WHERE operation_key=?",[JSON.stringify(value),op]);return value;}
}
function parse<S extends z.ZodTypeAny>(schema:S,value:unknown):z.infer<S>{const r=schema.safeParse(value);if(!r.success)throw new BadRequestException("Invalid administration request");return r.data;}
function decode(value:string|null|undefined){if(value==null)return null;const b=Buffer.from(value,"base64");if(b.toString("base64")!==value)throw new BadRequestException("Invalid base64 data");return b;}
function localTimestamp(){return new Intl.DateTimeFormat("sv-SE",{timeZone:"Asia/Shanghai",year:"numeric",month:"2-digit",day:"2-digit",hour:"2-digit",minute:"2-digit",second:"2-digit",hourCycle:"h23"}).format(new Date());}
function localDay(){return localTimestamp().slice(0,10);}

async function administrationAllowed(connection:PoolConnection,userId:number,permission:string){
 const candidates=[permission];let path=permission;while(path.includes("/")){path=path.slice(0,path.lastIndexOf("/"));candidates.push(`${path}/*`);}
 const [rows]=await connection.execute<RowDataPacket[]>(`WITH RECURSIVE grants_tree(name) AS (
   SELECT item_name FROM auth_assignment WHERE user_id=? UNION DISTINCT SELECT child FROM auth_item_child e JOIN grants_tree g ON e.parent=g.name
 ) SELECT name FROM grants_tree WHERE name IN (${candidates.map(()=>"?").join(",")}) LIMIT 1`,[String(userId),...candidates]);return rows.length>0;
}

async function assertCurrentAdministrator(connection:PoolConnection,request:NativeRequest,actor:number){
 const [roots]=await connection.execute<RowDataPacket[]>("SELECT item_name FROM auth_assignment WHERE user_id=? AND item_name='root'",[String(actor)]);if(roots.length)return;
 const permission=request.headers["x-identity-admin-route"];if(typeof permission!=="string"||!/^\/admin\/[a-z-]+\/[a-z-]+$/.test(permission)||!await administrationAllowed(connection,actor,permission))throw new ForbiddenException();
}

async function exactNames(connection:PoolConnection,table:"auth_item"|"auth_rule",names:(string|undefined)[]){for(const name of names){if(name===undefined)continue;const [rows]=await connection.execute<RowDataPacket[]>(`SELECT name FROM ${table} WHERE name=?`,[name]);if(rows[0]&&rows[0].name!==name)throw new ConflictException("RBAC identifier aliases are not permitted");}}
