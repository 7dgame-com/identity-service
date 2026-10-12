import "reflect-metadata";
import {generateKeyPairSync,randomBytes,randomUUID} from "node:crypto";
import {readFile} from "node:fs/promises";
import mysql,{Connection,RowDataPacket} from "mysql2/promise";
import {afterAll,beforeAll,describe,expect,it,vi} from "vitest";
import {LegacyIdentityReader} from "../src/legacy-identity.reader.js";
import {IdentitySessionRepository} from "../src/identity-session.repository.js";
import {JwtIssuerService} from "../src/jwt-issuer.service.js";
import {TokenIssuanceService} from "../src/token-issuance.service.js";
import {NativeIdentityService} from "../src/native-identity.service.js";
import {LegacyAdminService} from "../src/legacy-admin.service.js";
import {LegacyAdminController,LegacyPolicyController} from "../src/legacy-admin.controller.js";
import {hashLegacyPassword} from "../src/legacy-password.js";
import type {LoginAuditService} from "../src/login-audit.service.js";

const options={host:process.env.IDENTITY_DB_HOST??"127.0.0.1",port:Number(process.env.IDENTITY_DB_PORT??3306),user:process.env.IDENTITY_DB_USER??"root",password:process.env.IDENTITY_DB_PASSWORD??"",multipleStatements:true,timezone:"Z"};
const name=`test_legacy_admin_${randomUUID().replaceAll("-","")}`,password="Admin-private!73",authKey=randomBytes(32).toString("hex"),iamKey=randomBytes(32).toString("hex");
let db:Connection,adminDb:Connection,reader:LegacyIdentityReader,sessions:IdentitySessionRepository,tokens:TokenIssuanceService,native:NativeIdentityService,admin:LegacyAdminService,controller:LegacyAdminController,root:string,agent:string,user:string;
function request(body:unknown,token=root,key?:string){return {headers:{authorization:`Bearer ${token}`,...(key?{"idempotency-key":key}:{})},body};}
function mutate(body:unknown){return admin.mutateRbac(request(body));}
async function waitForPolicyLockWaiters(count:number){
 for(let attempt=0;attempt<100;attempt++){
  const [rows]=await db.query<RowDataPacket[]>("SHOW PROCESSLIST");
  const waiting=rows.filter(row=>row.db===name&&String(row.Info).includes("SELECT id FROM identity_event_clock WHERE id=1 FOR UPDATE"));
  if(waiting.length>=count)return;
  await new Promise(resolve=>setTimeout(resolve,20));
 }
 throw new Error(`Expected ${count} policy writers to wait for the clock`);
}

describe.skipIf(process.env.IDENTITY_TEST_MYSQL!=="1")("legacy administration against private MySQL",()=>{
 beforeAll(async()=>{
  adminDb=await mysql.createConnection(options);await adminDb.query(`CREATE DATABASE ${name}`);db=await mysql.createConnection({...options,database:name});
  const init=await readFile(new URL("../../../deploy/mysql/init.sql",import.meta.url),"utf8");await db.query(init.slice(init.indexOf("CREATE TABLE IF NOT EXISTS `auth_login_events`")));
  for(const file of ["identity-account-schema.sql","identity-runtime-schema.sql"])await db.query(await readFile(new URL(`../../../deploy/mysql/${file}`,import.meta.url),"utf8"));
  const keys=generateKeyPairSync("ec",{namedCurve:"prime256v1"});for(const [key,value] of Object.entries({IDENTITY_DATA_SOURCE:"identity",IDENTITY_DB_HOST:options.host,IDENTITY_DB_PORT:String(options.port),IDENTITY_DB_USER:options.user,IDENTITY_DB_PASSWORD:options.password,IDENTITY_DB_NAME:name,IDENTITY_TOKEN_ISSUANCE_ENABLED:"true",IDENTITY_TOKEN_ISSUANCE_INTERNAL_API_TOKEN:authKey,IDENTITY_IAM_INTERNAL_API_TOKEN:iamKey,IDENTITY_REFRESH_REPLAY_KEY:randomBytes(32).toString("base64url"),IDENTITY_JWT_PRIVATE_KEY_PEM:keys.privateKey.export({type:"pkcs8",format:"pem"}).toString(),IDENTITY_LOGIN_AUDIT_ENABLED:"false",LEGACY_DB_HOST:"127.0.0.1",LEGACY_DB_PORT:"1",LEGACY_DB_USER:"unreachable"}))vi.stubEnv(key,value);
  reader=new LegacyIdentityReader();sessions=new IdentitySessionRepository();const jwt=new JwtIssuerService();tokens=new TokenIssuanceService(reader,sessions,jwt,{record:vi.fn()} as unknown as LoginAuditService);native=new NativeIdentityService(reader,jwt,sessions);admin=new LegacyAdminService(native);controller=new LegacyAdminController(admin);
  await native.onApplicationBootstrap();await db.query("INSERT INTO auth_item(name,type) VALUES ('agent',1)");const hash=await hashLegacyPassword(password);
  for(const [id,role] of [[1,"root"],[2,"agent"],[3,"user"]] as const){await db.execute("INSERT INTO user(id,username,password_hash,status) VALUES (?,?,?,10)",[id,`legacy-admin-${role}`,hash]);await db.execute("INSERT INTO auth_assignment(item_name,user_id) VALUES (?,?)",[role,String(id)]);}
  [root,agent,user]=await Promise.all(["root","agent","user"].map(async role=>(await tokens.login({username:`legacy-admin-${role}`,password})).token.accessToken));
 },30000);
 afterAll(async()=>{await Promise.all([reader,sessions,native,admin].filter(Boolean).map(s=>s.onModuleDestroy()));await db?.end();if(adminDb){await adminDb.query(`DROP DATABASE ${name}`);await adminDb.end();}vi.unstubAllEnvs();});
 it("preserves own invitation lists, root role selection and agent restrictions",async()=>{
  const invite=await admin.createInvitation(request({role:"manager"}));expect(invite.auth_item_name).toBe("manager");
  expect((await admin.invitations(request({}))).invitations.map(r=>r.id)).toContain(invite.id);
  expect((await admin.invitations(request({},agent))).invitations).toEqual([]);expect((await admin.invitations(request({},agent))).roles).toEqual([{name:"user"}]);
  await expect(admin.createInvitation(request({role:"manager"},agent))).rejects.toMatchObject({status:403});await expect(admin.invitations(request({},user))).rejects.toMatchObject({status:403});
 });
 it("does not duplicate invitation creation after a lost response",async()=>{
  const r=request({role:"user"},root,"invitation-once");const [a,b]=await Promise.all([admin.createInvitation(r),admin.createInvitation(r)]);expect(a.id).toBe(b.id);
  await expect(admin.createInvitation(request({role:"admin"},root,"invitation-once"))).rejects.toMatchObject({status:409});
 });
 it("enforces the daily ten quota atomically and replays a business Info claim",async()=>{
  await db.query("DELETE FROM invitation");const results=await Promise.allSettled(Array.from({length:14},(_,i)=>admin.trial({claimId:String(i+1)})));
  const successes=results.flatMap((r,i)=>r.status==="fulfilled"?[{value:r.value,claim:String(i+1)}]:[]);expect(successes).toHaveLength(10);expect(results.filter(r=>r.status==="rejected")).toHaveLength(4);
  expect((await admin.quota()).count).toBe(10);expect((await admin.trial({claimId:successes[0].claim})).code).toBe(successes[0].value.code);
  const [rows]=await db.query<RowDataPacket[]>("SELECT COUNT(*) AS count FROM invitation");expect(Number(rows[0].count)).toBe(10);
 });
 it("sources current role graphs and assignments from Identity",async()=>{
  await mutate({operation:"item-put",name:"legacy-custom",type:1});await mutate({operation:"item-put",name:"legacy.permission",type:2});await mutate({operation:"edge-add",parent:"legacy-custom",child:"legacy.permission"});await mutate({operation:"assign",name:"legacy-custom",userId:3});
  expect(await native.allowed(3,"legacy.permission")).toBe(true);await mutate({operation:"revoke",name:"legacy-custom",userId:3});expect(await native.allowed(3,"legacy.permission")).toBe(false);
  await expect(mutate({operation:"edge-add",parent:"legacy.permission",child:"legacy-custom"})).rejects.toMatchObject({status:400});
  await mutate({operation:"item-put",name:"legacy-other",type:1});await mutate({operation:"edge-add",parent:"legacy-custom",child:"legacy-other"});await expect(mutate({operation:"edge-add",parent:"legacy-other",child:"legacy-custom"})).rejects.toMatchObject({status:409});
 });
 it("retains binary PHP rule payloads and propagates rule renames",async()=>{
  const data=Buffer.from([0,255,0,31]).toString("base64");await mutate({operation:"rule-put",name:"legacy-rule",data});await mutate({operation:"item-put",name:"legacy.permission",type:2,rule_name:"legacy-rule"});await mutate({operation:"rule-put",name:"renamed-rule",oldName:"legacy-rule",data});
  const snapshot=await admin.snapshot(request({})) as {items:RowDataPacket[];rules:RowDataPacket[]};expect(snapshot.rules.find(r=>r.name==="renamed-rule")?.dataBase64).toBe(data);expect(snapshot.items.find(i=>i.name==="legacy.permission")?.rule_name).toBe("renamed-rule");
 });
 it("rejects canonical role deletion and loss of the final root",async()=>{
  await expect(mutate({operation:"item-remove",name:"root"})).rejects.toMatchObject({status:409});await expect(mutate({operation:"item-put",name:"new-root",oldName:"root",type:1})).rejects.toMatchObject({status:409});await expect(mutate({operation:"revoke-all",userId:1})).rejects.toMatchObject({status:409});
  await expect(admin.snapshot(request({},agent))).rejects.toMatchObject({status:403});
 });
 it("checks scoped server credentials and adapts the original PHP RPC envelopes",async()=>{
  await expect(controller.rpc(iamKey,{operation:"rbac-snapshot",accessToken:root})).rejects.toMatchObject({status:401});
  expect(await controller.rpc(authKey,{operation:"rbac-mutate",accessToken:root,payload:{action:"add-item",item:{name:"rpc.permission",type:2}}})).toMatchObject({success:true});
  const graph=await new LegacyPolicyController(admin).policy(iamKey);expect(graph.data.items).toEqual(expect.arrayContaining([expect.objectContaining({name:"rpc.permission"})]));expect(graph.data).not.toHaveProperty("assignments");
  await expect(new LegacyPolicyController(admin).policy(authKey)).rejects.toMatchObject({status:401});
 });
 it("refuses administration by a revoked browser session",async()=>{
  const login=await tokens.login({username:"legacy-admin-root",password});await tokens.logout({refreshToken:login.token.refreshToken});await expect(admin.createInvitation(request({role:"user"},login.token.accessToken))).rejects.toMatchObject({status:401});
 });
 it("keeps the legacy administration account fields, paging and soft deletion",async()=>{
  const payload={username:"mdm-created",email:"mdm-created@example.test",password,idempotencyKey:"mdm-create-once"};
  const first=await controller.rpc(authKey,{operation:"user-create",accessToken:root,payload}) as {id:number};
  const second=await controller.rpc(authKey,{operation:"user-create",accessToken:root,payload}) as {id:number};expect(second.id).toBe(first.id);
  const list=await controller.rpc(authKey,{operation:"user-list",accessToken:root,payload:{username:"mdm-created",page:1,pageSize:10}}) as {users:RowDataPacket[];total:number};expect(list.total).toBe(1);expect(list.users[0]).toMatchObject({id:first.id,email:payload.email,status:10});expect(list.users[0]).not.toHaveProperty("password_hash");
  const session=await tokens.login({username:payload.username,password});await controller.rpc(authKey,{operation:"user-delete",accessToken:root,payload:{id:first.id}});await expect(native.verify(session.token.accessToken)).rejects.toMatchObject({status:401});
  const [rows]=await db.execute<RowDataPacket[]>("SELECT id,status,deleted_at FROM user WHERE id=?",[first.id]);expect(rows[0].id).toBe(first.id);expect(rows[0].status).toBe(0);expect(rows[0].deleted_at).not.toBeNull();
 });
 it("activates an existing inactive account only through Identity",async()=>{
  await db.execute("INSERT INTO user(id,username,password_hash,status) VALUES (700,'mdm-inactive',?,9)",[await hashLegacyPassword(password)]);
  expect(await controller.rpc(authKey,{operation:"user-activate",accessToken:root,payload:{id:700}})).toEqual({success:true});expect((await native.subject(700)).status).toBe(10);
  await expect(controller.rpc(authKey,{operation:"user-activate",accessToken:user,payload:{id:700}})).rejects.toMatchObject({status:403});
 });
 it("rejects a cycle when different root sessions queue opposite graph edges",async()=>{
  const blocker=await mysql.createConnection({...options,database:name});let pending:Promise<PromiseSettledResult<unknown>[]>|undefined;
  await db.query("INSERT INTO user(id,username,password_hash,status) SELECT 801,'review-second-root',password_hash,10 FROM user WHERE id=1");
  await db.execute("INSERT INTO auth_assignment(item_name,user_id) VALUES ('root','801')");
  await db.query("INSERT INTO auth_item(name,type) VALUES ('review-cycle-a',1),('review-cycle-b',1)");
  const second=(await tokens.login({username:"review-second-root",password})).token.accessToken;
  try{
   await blocker.beginTransaction();await blocker.query("SELECT id FROM identity_event_clock WHERE id=1 FOR UPDATE");
   pending=Promise.allSettled([
    admin.mutateRbac(request({operation:"edge-add",parent:"review-cycle-a",child:"review-cycle-b"})),
    admin.mutateRbac(request({operation:"edge-add",parent:"review-cycle-b",child:"review-cycle-a"},second)),
   ]);
   await waitForPolicyLockWaiters(2);await blocker.commit();
   const results=await pending;expect(results.filter(result=>result.status==="fulfilled")).toHaveLength(1);
   const rejected=results.find(result=>result.status==="rejected") as PromiseRejectedResult;
   expect(rejected.reason).toMatchObject({status:409,message:"RBAC cycle"});
   const [edges]=await db.query<RowDataPacket[]>("SELECT parent,child FROM auth_item_child WHERE parent IN ('review-cycle-a','review-cycle-b')");expect(edges).toHaveLength(1);
  }finally{
   await blocker.rollback();await pending;await blocker.end();
   await db.query("DELETE FROM auth_assignment WHERE user_id='801'");
   await db.query("DELETE FROM auth_item_child WHERE parent IN ('review-cycle-a','review-cycle-b') OR child IN ('review-cycle-a','review-cycle-b')");
   await db.query("DELETE FROM auth_item WHERE name IN ('review-cycle-a','review-cycle-b')");
  }
 });
 it("honors an attested delegated route and rechecks its current grant after the policy lock",async()=>{
  const blocker=await mysql.createConnection({...options,database:name});let pending:Promise<PromiseSettledResult<unknown>[]>|undefined;
  await db.query("INSERT INTO auth_item(name,type) VALUES ('review-route-admin',1),('/admin/role/*',2)");
  await db.query("INSERT INTO auth_assignment(item_name,user_id) VALUES ('review-route-admin','3')");
  await db.query("INSERT INTO auth_item_child(parent,child) VALUES ('review-route-admin','/admin/role/*')");
  try{
   const delegated={operation:"rbac-snapshot",accessToken:user,permissionName:"/admin/role/index"};
   expect(await controller.rpc(authKey,delegated)).toHaveProperty("assignments");
   await expect(controller.rpc(iamKey,delegated)).rejects.toMatchObject({status:401});
   await expect(controller.rpc(authKey,{...delegated,permissionName:undefined})).rejects.toMatchObject({status:403});
   await expect(controller.rpc(authKey,{...delegated,permissionName:"/admin/assignment/index"})).rejects.toMatchObject({status:403});
   await blocker.beginTransaction();await blocker.query("SELECT id FROM identity_event_clock WHERE id=1 FOR UPDATE");
   pending=Promise.allSettled([controller.rpc(authKey,{operation:"rbac-mutate",accessToken:user,permissionName:"/admin/role/create",
    payload:{action:"add-item",item:{name:"review-revoked-operation",type:1}}})]);
   await waitForPolicyLockWaiters(1);
   await blocker.query("DELETE FROM auth_item_child WHERE parent='review-route-admin' AND child='/admin/role/*'");await blocker.commit();
   expect(await pending).toEqual([expect.objectContaining({status:"rejected",reason:expect.objectContaining({status:403})})]);
   const [items]=await db.query<RowDataPacket[]>("SELECT name FROM auth_item WHERE name='review-revoked-operation'");expect(items).toHaveLength(0);
   await expect(controller.rpc(authKey,delegated)).rejects.toMatchObject({status:403});
  }finally{
   await blocker.rollback();await pending;await blocker.end();
   await db.query("DELETE FROM auth_assignment WHERE item_name='review-route-admin'");
   await db.query("DELETE FROM auth_item_child WHERE parent='review-route-admin'");
   await db.query("DELETE FROM auth_item WHERE name IN ('review-route-admin','/admin/role/*','review-revoked-operation')");
  }
 });
 it.each(["ROOT","Root","Röot","root "])("rejects SQL-equivalent canonical role alias %j",async alias=>{
  await expect(mutate({operation:"revoke",name:alias,userId:1})).rejects.toMatchObject({status:409});
  await expect(mutate({operation:"item-remove",name:alias})).rejects.toMatchObject({status:409});
  await expect(mutate({operation:"item-put",name:alias,type:2})).rejects.toMatchObject({status:409});
  await expect(admin.createInvitation(request({role:alias}))).rejects.toMatchObject({status:409});
  const [roles]=await db.query<RowDataPacket[]>("SELECT i.name,i.type,a.user_id FROM auth_item i JOIN auth_assignment a ON a.item_name=i.name WHERE i.name='root' AND a.user_id='1'");
  expect(roles).toEqual([expect.objectContaining({name:"root",type:1,user_id:"1"})]);
 });
 it("keeps delegated MDM user CRUD without granting separate plugin permissions or issuing target sessions",async()=>{
  await db.query("INSERT INTO auth_item(name,type) VALUES ('review-user-admin',1),('/admin/user/*',2)");
  await db.query("INSERT INTO auth_assignment(item_name,user_id) VALUES ('review-user-admin','3')");
  await db.query("INSERT INTO auth_item_child(parent,child) VALUES ('review-user-admin','/admin/user/*')");
  try{
   expect(await native.allowed(3,"user-management.create-user")).toBe(false);
   const payload={username:"review-mdm-created",password,email:"review-mdm-created@example.test",idempotencyKey:"review-delegated-user"};
   const create={operation:"user-create",accessToken:user,permissionName:"/admin/user/signup",payload};
   await expect(controller.rpc(authKey,{...create,permissionName:"/admin/user/index"})).rejects.toMatchObject({status:403});
   const first=await controller.rpc(authKey,create) as {id:number};
   expect(await controller.rpc(authKey,create)).toMatchObject({id:first.id});
   const [createdSessions]=await db.execute<RowDataPacket[]>("SELECT COUNT(*) AS count FROM identity_refresh_sessions WHERE legacy_user_id=?",[first.id]);expect(Number(createdSessions[0].count)).toBe(0);
   const list=await controller.rpc(authKey,{operation:"user-list",accessToken:user,permissionName:"/admin/user/index",payload:{username:payload.username}}) as {users:RowDataPacket[];total:number};
   expect(list.total).toBe(1);expect(list.users[0]).toMatchObject({id:first.id,username:payload.username,status:10});expect(list.users[0]).not.toHaveProperty("password_hash");
   await db.execute("UPDATE user SET status=9 WHERE id=?",[first.id]);
   expect(await controller.rpc(authKey,{operation:"user-activate",accessToken:user,permissionName:"/admin/user/activate",payload:{id:first.id}})).toEqual({success:true});
   const session=await tokens.login({username:payload.username,password});
   await expect(controller.rpc(authKey,{operation:"user-delete",accessToken:user,permissionName:"/admin/user/activate",payload:{id:first.id}})).rejects.toMatchObject({status:403});
   await expect(controller.rpc(authKey,{operation:"user-delete",accessToken:user,permissionName:"/admin/user/delete",payload:{id:1}})).rejects.toMatchObject({status:403});
   expect(await controller.rpc(authKey,{operation:"user-delete",accessToken:user,permissionName:"/admin/user/delete",payload:{id:first.id}})).toEqual({success:true});
   await expect(native.verify(session.token.accessToken)).rejects.toMatchObject({status:401});
   const [users]=await db.execute<RowDataPacket[]>("SELECT status,deleted_at FROM user WHERE id=?",[first.id]);expect(users[0].status).toBe(0);expect(users[0].deleted_at).not.toBeNull();
  }finally{
   await db.query("DELETE FROM auth_assignment WHERE item_name='review-user-admin'");
   await db.query("DELETE FROM auth_item_child WHERE parent='review-user-admin'");
   await db.query("DELETE FROM auth_item WHERE name IN ('review-user-admin','/admin/user/*')");
  }
 });
 it("does not accept a delegated read route as permission for RBAC writes",async()=>{
  await db.query("INSERT INTO auth_item(name,type) VALUES ('/admin/role/index',2)");
  await db.query("INSERT INTO auth_assignment(item_name,user_id) VALUES ('/admin/role/index','3')");
  try{
   const base={accessToken:user,permissionName:"/admin/role/index"};
   expect(await controller.rpc(authKey,{...base,operation:"rbac-snapshot"})).toHaveProperty("items");
   await expect(controller.rpc(authKey,{...base,operation:"rbac-mutate",payload:{action:"add-item",item:{name:"review-index-write",type:1}}})).rejects.toMatchObject({status:403});
   const [items]=await db.query<RowDataPacket[]>("SELECT name FROM auth_item WHERE name='review-index-write'");expect(items).toHaveLength(0);
  }finally{
   await db.query("DELETE FROM auth_assignment WHERE item_name='/admin/role/index'");
   await db.query("DELETE FROM auth_item WHERE name IN ('/admin/role/index','review-index-write')");
  }
 });
 it("preserves an active root when two roots concurrently revoke their own assignments",async()=>{
  await db.query("INSERT INTO user(username,password_hash,status) SELECT 'review-final-root',password_hash,10 FROM user WHERE id=1");
  const [inserted]=await db.query<RowDataPacket[]>("SELECT id FROM user WHERE username='review-final-root'");const secondId=Number(inserted[0].id);
  await db.execute("INSERT INTO auth_assignment(item_name,user_id) VALUES ('root',?)",[String(secondId)]);
  const second=(await tokens.login({username:"review-final-root",password})).token.accessToken;
  try{
   const results=await Promise.allSettled([
    admin.mutateRbac(request({operation:"revoke",name:"root",userId:1})),
    admin.mutateRbac(request({operation:"revoke",name:"root",userId:secondId},second)),
   ]);
   expect(results.filter(result=>result.status==="fulfilled")).toHaveLength(1);
   const rejected=results.find(result=>result.status==="rejected") as PromiseRejectedResult;expect(rejected.reason).toMatchObject({status:409});
   const [roots]=await db.query<RowDataPacket[]>("SELECT a.user_id FROM auth_assignment a JOIN user u ON a.user_id=CAST(u.id AS CHAR) WHERE a.item_name='root' AND u.status=10 AND u.deleted_at IS NULL");expect(roots).toHaveLength(1);
  }finally{
   await db.query("INSERT IGNORE INTO auth_assignment(item_name,user_id) VALUES ('root','1')");
   await db.execute("DELETE FROM auth_assignment WHERE user_id=?",[String(secondId)]);
  }
 });
});
