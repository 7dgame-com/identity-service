import "reflect-metadata";
import { randomBytes, randomUUID, generateKeyPairSync, sign, createPrivateKey, createPublicKey, createHmac, createHash } from "node:crypto";
import { readFile, mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import mysql, { type Connection, type RowDataPacket } from "mysql2/promise";
import { beforeAll, afterAll, describe, it, expect, vi } from "vitest";
import { LegacyIdentityReader } from "../src/legacy-identity.reader.js";
import { JwtIssuerService } from "../src/jwt-issuer.service.js";
import { IdentitySessionRepository, InvalidRefreshTokenError } from "../src/identity-session.repository.js";
import { TokenIssuanceService } from "../src/token-issuance.service.js";
import { NativeIdentityService } from "../src/native-identity.service.js";
import { IamService } from "../src/iam.service.js";
import type { IamRepository } from "../src/iam.repository.js";
import type { LoginAuditService } from "../src/login-audit.service.js";
import { hashLegacyPassword } from "../src/legacy-password.js";
import { enqueueSubjectEvent } from "../src/subject-events.js";
import { IdentityWechatOAuthService } from "../src/identity-wechat-oauth.service.js";
import { readAccountBaseline } from "../src/identity-account-baseline.js";
import { LegacyEmailLinkService } from "../src/legacy-email-link.service.js";
import { LegacyEmailLinkController } from "../src/legacy-email-link.controller.js";
import { PluginUserReadonlyController } from "../src/plugin-user-readonly.controller.js";
import type { PluginUserPrimaryReadService } from "../src/plugin-user-primary-read.service.js";
import { AccountPasswordRepository } from "../src/account-password.repository.js";
import { PasswordResetChallengeRepository } from "../src/password-reset-challenge.repository.js";
import { AccountPasswordResetService } from "../src/account-password-reset.service.js";
import { AccountLifecycleOperationRepository } from "../src/account-lifecycle-operation.repository.js";
import { LegacySessionRevocationService } from "../src/legacy-session-revocation.service.js";
import { EmailDeliveryService } from "../src/email-delivery.service.js";

const opts={host:process.env.IDENTITY_DB_HOST??"127.0.0.1",port:Number(process.env.IDENTITY_DB_PORT??3306),user:process.env.IDENTITY_DB_USER??"root",password:process.env.IDENTITY_DB_PASSWORD??"",multipleStatements:true,timezone:"Z"};
const name=`test_identity_runtime_${randomUUID().replaceAll("-","")}`;
let admin:Connection, db:Connection, reader:LegacyIdentityReader, sessions:IdentitySessionRepository, jwt:JwtIssuerService, tokens:TokenIssuanceService, native:NativeIdentityService;
let rootToken:string, links:LegacyEmailLinkService;
const password="Strong-private!89";
const request=(body:unknown,key:string,token=rootToken)=>({headers:{authorization:`Bearer ${token}`,"idempotency-key":key},body});
async function pendingVerification(suffix:string){
 await db.execute("INSERT IGNORE INTO auth_item(name,type) VALUES ('guest',1)");
 const token=`verification-${randomBytes(24).toString("base64url")}`,username=`verify-${suffix}`;
 await db.execute(`INSERT INTO user(username,email,password_hash,auth_key,status,verification_token,created_at,updated_at)
  SELECT ?,?,password_hash,?,9,?,1,1 FROM user WHERE id=1`,[username,`${username}@example.test`,randomBytes(24).toString("base64url"),token]);
 const [rows]=await db.execute<RowDataPacket[]>("SELECT id FROM user WHERE username=?",[username]);return {id:Number(rows[0].id),token};
}
async function sessionCount(userId:number){const [rows]=await db.execute<RowDataPacket[]>("SELECT COUNT(*) AS total FROM identity_refresh_sessions WHERE legacy_user_id=?",[userId]);return Number(rows[0].total);}

describe.skipIf(process.env.IDENTITY_TEST_MYSQL!=="1")("private identity runtime integration",()=>{
 beforeAll(async()=>{
  admin=await mysql.createConnection(opts); await admin.query(`CREATE DATABASE ${name} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`);
  db=await mysql.createConnection({...opts,database:name});
  const base=await readFile(new URL("../../../deploy/mysql/init.sql",import.meta.url),"utf8");
  await db.query(base.slice(base.indexOf("CREATE TABLE IF NOT EXISTS `auth_login_events`")));
  for(const filename of ["identity-account-schema.sql","identity-password-reset-token-schema.sql","identity-legacy-challenge-schema.sql","identity-runtime-schema.sql","identity-wechat-oauth-schema.sql"]) await db.query(await readFile(new URL(`../../../deploy/mysql/${filename}`,import.meta.url),"utf8"));
  const {privateKey}=generateKeyPairSync("ec",{namedCurve:"P-256"});
  for(const [key,value] of Object.entries({IDENTITY_DATA_SOURCE:"identity",IDENTITY_DB_HOST:opts.host,IDENTITY_DB_PORT:String(opts.port),IDENTITY_DB_USER:opts.user,IDENTITY_DB_PASSWORD:opts.password,IDENTITY_DB_NAME:name,IDENTITY_TOKEN_ISSUANCE_ENABLED:"true",IDENTITY_REFRESH_REPLAY_KEY:randomBytes(32).toString("base64url"),IDENTITY_INTERNAL_API_TOKEN:randomBytes(32).toString("hex"),IDENTITY_JWT_PRIVATE_KEY_PEM:privateKey.export({format:"pem",type:"pkcs8"}).toString(),LEGACY_DB_HOST:"127.0.0.1",LEGACY_DB_PORT:"1",LEGACY_DB_USER:"unreachable",LEGACY_WRITE_DB_HOST:"127.0.0.1",LEGACY_WRITE_DB_PORT:"1",LEGACY_WRITE_DB_USER:"unreachable"})) vi.stubEnv(key,value);
  vi.stubEnv("IDENTITY_LOGIN_AUDIT_ENABLED","true");
  reader=new LegacyIdentityReader(); sessions=new IdentitySessionRepository(); jwt=new JwtIssuerService(); tokens=new TokenIssuanceService(reader,sessions,jwt,{record:vi.fn()} as unknown as LoginAuditService); native=new NativeIdentityService(reader,jwt,sessions);links=new LegacyEmailLinkService(tokens,sessions);
  await native.onApplicationBootstrap();
  const hash=await hashLegacyPassword(password);
  for(const [id,role] of [[1,"root"],[2,"admin"],[3,"manager"],[4,"user"]] as const){await db.execute("INSERT INTO user (id,username,password_hash,status) VALUES (?,?,?,10)",[id,`native-${role}`,hash]); await db.execute("INSERT INTO auth_assignment (item_name,user_id) VALUES (?,?)",[role,String(id)]);}
  await db.query("INSERT INTO auth_item(name,type) VALUES ('user-management.create-user',2),('user-management.change-role',2),('user-management.list-users',2),('organization.list',2),('/v1/tools/*',2)");
  await db.query("INSERT INTO auth_item_child(parent,child) VALUES ('admin','user-management.create-user'),('manager','user-management.list-users'),('user','/v1/tools/*')");
  rootToken=(await tokens.login({username:"native-root",password})).token.accessToken;
 },30000);
 afterAll(async()=>{await Promise.all([native,reader,sessions,links].filter(Boolean).map(r=>r.onModuleDestroy()));await db?.end();if(admin){await admin.query(`DROP DATABASE ${name}`);await admin.end();}vi.unstubAllEnvs();});
 it("completes login, profile, refresh and logout with both old database connections unreachable",async()=>{
  await native.profile(request({nickname:"private profile",info:{bio:"preserved"},avatar_id:700},"profile-once"));
  const info=await native.currentInfo(request(undefined,"read"));expect(info.data.userData.nickname).toBe("private profile");expect(info.data.userInfo.avatar_id).toBe(700);
  await native.profile(request({nickname:"kept avatar"},"profile-nickname-only"));expect((await native.subject(1)).avatarId).toBe(700);
  const initial=await tokens.login({username:"native-user",password}); const refreshed=await tokens.refresh({refreshToken:initial.token.refreshToken},{idempotencyKey:"flow-refresh"});
  expect((await native.verify(refreshed.token.accessToken)).id).toBe(4);
  await tokens.logout({refreshToken:refreshed.token.refreshToken});await expect(native.verify(refreshed.token.accessToken)).rejects.toMatchObject({status:401});
 });
 it("validates only active imported opaque reset tokens without consuming them",async()=>{
  const challenges=new PasswordResetChallengeRepository();
  try{
   const token=randomBytes(24).toString("base64url"),digest=createHash("sha256").update(token).digest("hex");
   await db.query("INSERT INTO user(username,email,password_hash,email_verified_at,status) SELECT 'reset-token-check','reset-token-check@example.test',password_hash,1,10 FROM user WHERE id=1");
   const [users]=await db.query<RowDataPacket[]>("SELECT id FROM user WHERE username='reset-token-check'");const id=Number(users[0].id);
   await db.execute("INSERT INTO identity_password_reset_tokens(token_hash,legacy_user_id,email,issued_at,expires_at) VALUES (?,?,?,UTC_TIMESTAMP(3),DATE_ADD(UTC_TIMESTAMP(3),INTERVAL 1 MINUTE))",[digest,id,"reset-token-check@example.test"]);
   expect(await challenges.findActiveByToken(token)).toMatchObject({tokenHash:digest,legacyUserId:id});
   expect(await challenges.findActiveByToken(token)).not.toBeNull();
   const [rows]=await db.execute<RowDataPacket[]>("SELECT consumed_at FROM identity_password_reset_tokens WHERE token_hash=?",[digest]);expect(rows[0].consumed_at).toBeNull();
   expect(await challenges.findActiveByToken(`${token}x`)).toBeNull();
   const code=await challenges.createChallenge({email:"reset-token-check@example.test",legacyUserId:id});expect(await challenges.findActiveByToken(code.challenge.challengeKey)).toBeNull();
   await db.execute("UPDATE user SET email='changed-reset@example.test' WHERE id=?",[id]);expect(await challenges.findActiveByToken(token)).toBeNull();
   await db.execute("UPDATE user SET email='reset-token-check@example.test',status=0 WHERE id=?",[id]);expect(await challenges.findActiveByToken(token)).toBeNull();
   await db.execute("UPDATE user SET status=10 WHERE id=?",[id]);
   await db.execute("UPDATE identity_password_reset_tokens SET expires_at=DATE_SUB(UTC_TIMESTAMP(3),INTERVAL 1 SECOND) WHERE token_hash=?",[digest]);expect(await challenges.findActiveByToken(token)).toBeNull();
  }finally{await challenges.onModuleDestroy();}
 });
 it("consumes an opaque reset token with the password and session revocation in one transaction",async()=>{
  vi.stubEnv("IDENTITY_ACCOUNT_PASSWORD_RESET_NATIVE_ENABLED","true");vi.stubEnv("IDENTITY_EMAIL_WEBHOOK_URL","");
  const challenges=new PasswordResetChallengeRepository(),passwords=new AccountPasswordRepository(),operations=new AccountLifecycleOperationRepository();
  const service=new AccountPasswordResetService(passwords,challenges,operations,sessions,new LegacySessionRevocationService(),new EmailDeliveryService());
  try{
   await db.query("INSERT INTO user(username,email,password_hash,email_verified_at,status) SELECT 'reset-token-change','reset-token-change@example.test',password_hash,1,10 FROM user WHERE id=1");
   const [users]=await db.query<RowDataPacket[]>("SELECT id FROM user WHERE username='reset-token-change'");const id=Number(users[0].id),token=randomBytes(24).toString("base64url"),digest=createHash("sha256").update(token).digest("hex");
   await db.execute("INSERT INTO identity_password_reset_tokens(token_hash,legacy_user_id,email,issued_at,expires_at) VALUES (?,?,?,UTC_TIMESTAMP(3),DATE_ADD(UTC_TIMESTAMP(3),INTERVAL 1 MINUTE))",[digest,id,"reset-token-change@example.test"]);
   const initial=await tokens.login({username:"reset-token-change",password});
   expect(await service.handle("/v1/password/verify-token",{token})).toEqual({status:200,body:{success:true,message:"重置令牌有效"}});
   const body={token,password:"Reset-token-new!93"};expect((await service.handle("/v1/password/reset",body)).status).toBe(200);
   await expect(native.verify(initial.token.accessToken)).rejects.toMatchObject({status:401});
   const fresh=await tokens.login({username:"reset-token-change",password:body.password});
   expect((await service.handle("/v1/password/reset",body)).status).toBe(200);expect((await native.verify(fresh.token.accessToken)).id).toBe(id);
   await expect(service.handle("/v1/password/verify-token",{token})).rejects.toMatchObject({status:400,response:{error:{code:"INVALID_TOKEN"}}});
   await expect(service.handle("/v1/password/reset",{token,password:"Changed-replay!94"})).rejects.toMatchObject({status:400,response:{error:{code:"INVALID_TOKEN"}}});
   const expired=randomBytes(24).toString("base64url"),expiredHash=createHash("sha256").update(expired).digest("hex");
   await db.execute("INSERT INTO identity_password_reset_tokens(token_hash,legacy_user_id,email,issued_at,expires_at) VALUES (?,?,?,DATE_SUB(UTC_TIMESTAMP(3),INTERVAL 1 MINUTE),DATE_SUB(UTC_TIMESTAMP(3),INTERVAL 1 SECOND))",[expiredHash,id,"reset-token-change@example.test"]);
   const credential=(await passwords.getCredentialById(id))!;
   await expect(passwords.changePassword(credential,"Rollback-expired!95",{operationKey:"expired-token-rollback",resetTokenHash:expiredHash})).rejects.toMatchObject({status:400,body:{error:{code:"INVALID_TOKEN"}}});
   expect(await passwords.verifyPassword(body.password,(await passwords.getCredentialById(id))!.passwordHash)).toBe(true);
   expect((await native.verify(fresh.token.accessToken)).id).toBe(id);
   const contested=randomBytes(24).toString("base64url"),contestedHash=createHash("sha256").update(contested).digest("hex");
   await db.execute("INSERT INTO identity_password_reset_tokens(token_hash,legacy_user_id,email,issued_at,expires_at) VALUES (?,?,?,UTC_TIMESTAMP(3),DATE_ADD(UTC_TIMESTAMP(3),INTERVAL 1 MINUTE))",[contestedHash,id,"reset-token-change@example.test"]);
   const [before]=await db.execute<RowDataPacket[]>("SELECT COUNT(*) AS count FROM identity_subject_events WHERE user_id=?",[id]);
   const competing=["Concurrent-alpha!96","Concurrent-bravo!97"],results=await Promise.allSettled(competing.map(password=>service.handle("/v1/password/reset",{token:contested,password})));
   expect(results.filter(result=>result.status==="fulfilled")).toHaveLength(1);
   const [after]=await db.execute<RowDataPacket[]>("SELECT COUNT(*) AS count FROM identity_subject_events WHERE user_id=?",[id]);expect(Number(after[0].count)-Number(before[0].count)).toBe(1);
   const winner=competing[results.findIndex(result=>result.status==="fulfilled")];
   expect(await passwords.verifyPassword(winner,(await passwords.getCredentialById(id))!.passwordHash)).toBe(true);
   expect(await challenges.findActiveByToken(contested)).toBeNull();
   await expect(native.verify(fresh.token.accessToken)).rejects.toMatchObject({status:401});
  }finally{await Promise.all([challenges,passwords,operations].map(item=>item.onModuleDestroy()));}
 });
 it("serializes concurrent refresh to one successor and replays a lost response",async()=>{
  const initial=await tokens.login({username:"native-user",password});
  const responses=await Promise.all(Array.from({length:12},()=>tokens.refresh({refreshToken:initial.token.refreshToken},{idempotencyKey:"same-refresh-request"})));
  expect(new Set(responses.map(r=>r.token.refreshToken)).size).toBe(1);
  const [rows]=await db.execute<RowDataPacket[]>("SELECT COUNT(*) AS total FROM identity_refresh_sessions WHERE session_id=?",[jwt.verifyAccessToken(initial.token.accessToken).sessionId]);expect(Number(rows[0].total)).toBe(2);
  // An old client without a request key gets the same successor during the short overlap.
  expect((await tokens.refresh({refreshToken:initial.token.refreshToken})).token.refreshToken).toBe(responses[0].token.refreshToken);
  await tokens.logout({refreshToken:initial.token.refreshToken});await expect(native.verify(responses[0].token.accessToken)).rejects.toMatchObject({status:401});
  await expect(tokens.refresh({refreshToken:initial.token.refreshToken},{idempotencyKey:"same-refresh-request"})).rejects.toMatchObject({status:401});
 });
 it("keeps SN provenance and family immutable during concurrent replay and predecessor logout",async()=>{
  const source={authMethod:"device_sn" as const,deviceSnId:42};const family=`device-family-${randomUUID()}`;
  const initial=await sessions.issue({legacyUserId:4,username:"native-user",sessionId:family,expiresAt:new Date(Date.now()+60000),...source});
  const next={legacyUserId:4,username:"native-user",sessionId:"caller-chosen-family",expiresAt:new Date(Date.now()+60000),authMethod:null,deviceSnId:null};
  const successors=await Promise.all([sessions.rotate(initial.refreshToken,next,"source-retry"),sessions.rotate(initial.refreshToken,next,"source-retry")]);
  expect(successors[0].refreshToken).toBe(successors[1].refreshToken);
  for(const successor of successors)expect(successor).toMatchObject({...source,sessionId:family,legacyUserId:4});
  const stored=await sessions.findValidSession(successors[0].refreshToken);expect(stored).toMatchObject({...source,sessionId:family});
  const [rows]=await db.execute<RowDataPacket[]>("SELECT COUNT(*) AS total FROM identity_refresh_sessions WHERE session_id=? AND revoked_at IS NULL",[family]);expect(Number(rows[0].total)).toBe(1);
  const ordinary=await sessions.issue({legacyUserId:4,username:"native-user",sessionId:`ordinary-${randomUUID()}`,expiresAt:new Date(Date.now()+60000)});
  const ordinaryNext=await sessions.rotate(ordinary.refreshToken,{...next,...source});expect(ordinaryNext.authMethod).toBeUndefined();expect(ordinaryNext.deviceSnId).toBeUndefined();
  await sessions.revoke(initial.refreshToken);await expect(sessions.findValidSession(successors[0].refreshToken)).rejects.toBeInstanceOf(InvalidRefreshTokenError);
  await expect(sessions.rotate(initial.refreshToken,next,"source-retry")).rejects.toBeInstanceOf(InvalidRefreshTokenError);
 });
 it("does not restore a session when logout races rotation",async()=>{
  for(let i=0;i<6;i++){
   const initial=await tokens.login({username:"native-user",password});
   const [refresh]=await Promise.allSettled([tokens.refresh({refreshToken:initial.token.refreshToken},{idempotencyKey:`logout-race-${i}`}),tokens.logout({refreshToken:initial.token.refreshToken})]);
   if(refresh.status==="fulfilled") await expect(native.verify(refresh.value.token.accessToken)).rejects.toMatchObject({status:401});
   await expect(tokens.refresh({refreshToken:initial.token.refreshToken},{idempotencyKey:`logout-race-${i}`})).rejects.toMatchObject({status:401});
  }
 });
 it("rejects stale password authentication but permits immediate login after revocation",async()=>{
  const old=await tokens.login({username:"native-user",password});await sessions.revokeUserSessions(4);
  const fresh=await tokens.login({username:"native-user",password});expect((await native.verify(fresh.token.accessToken)).id).toBe(4);
  await expect(native.verify(old.token.accessToken)).rejects.toMatchObject({status:401});
  await expect(sessions.issue({legacyUserId:4,username:"native-user",sessionId:randomUUID(),expiresAt:new Date(Date.now()+60000),expectedPasswordHash:"stale-hash"})).rejects.toBeInstanceOf(InvalidRefreshTokenError);
 });
 it("honors role allow and deny decisions from current assignments without Yii decisions",async()=>{
  const iam=new IamService({} as IamRepository,reader,jwt,native);
  expect(await native.allowed(1,"unlisted-permission")).toBe(true);expect(await native.allowed(2,"user-management.create-user")).toBe(true);
  expect(await native.allowed(3,"user-management.create-user")).toBe(false);expect(await native.allowed(4,"user-management.list-users")).toBe(false);
  expect(await native.allowed(4,"/v1/tools/user-linked")).toBe(true);
  expect((await iam.authzResolve({subject:{legacyUserId:3},permission:"user-management.list-users"})).outcome.decision).toBe("allow");
  const manager=(await tokens.login({username:"native-manager",password})).token.accessToken;
  await db.execute("DELETE FROM auth_assignment WHERE user_id='3'");expect((await native.verify(manager)).roles).toEqual([]);
  await expect(native.managedUsers(request(undefined,"list-manager",manager),{})).rejects.toMatchObject({status:403});
 });
 it("creates a user once, preserves its ID on disable and emits ordered projection events",async()=>{
  const create=request({username:"created-once",password},"new-account-once");
  const [a,b]=await Promise.all([native.pluginWrite(create,"create-user"),native.pluginWrite(create,"create-user")]) as [{data:{id:number}},{data:{id:number}}];expect(a.data.id).toBe(b.data.id);
  await expect(native.pluginWrite(request({username:"another-name",password},"new-account-once"),"create-user")).rejects.toMatchObject({status:409});
  const issued=await tokens.login({username:"created-once",password});await native.pluginWrite(request({id:a.data.id},"disable-created"),"delete-user");
  expect((await native.subject(a.data.id)).status).toBe(0);await expect(native.verify(issued.token.accessToken)).rejects.toMatchObject({status:401});
  const stream=await native.events(0,100);expect(stream.events.some(e=>e.userId===a.data.id&&e.subject.status===0)).toBe(true);expect(stream.nextCursor).toBeGreaterThan(0);
 });
 it("serializes outbox allocation until the preceding writer commits",async()=>{
  const first=await mysql.createConnection({...opts,database:name}), second=await mysql.createConnection({...opts,database:name});
  try {await first.beginTransaction();await second.beginTransaction();await enqueueSubjectEvent(first as never,1);
   let allocated=false;const pending=enqueueSubjectEvent(second as never,2).then(()=>{allocated=true;});
   await new Promise(resolve=>setTimeout(resolve,50));expect(allocated).toBe(false);await first.commit();await pending;await second.commit();
   const [events]=await db.query<RowDataPacket[]>("SELECT user_id FROM identity_subject_events ORDER BY id DESC LIMIT 2");expect(events.map(e=>Number(e.user_id))).toEqual([2,1]);
  } finally {await first.rollback();await second.rollback();await first.end();await second.end();}
 });
 it("keeps OAuth audience and refresh scopes out of the general account APIs",async()=>{
  const user=(await reader.getUserById(4))!;
  const session=await sessions.issue({legacyUserId:4,username:user.username,sessionId:randomUUID(),expiresAt:new Date(Date.now()+60000)});
  await db.execute("INSERT INTO identity_oauth_session_bindings(session_id,client_id,scopes_json) VALUES (?,'client-test','[\"openid\"]')",[session.sessionId]);
  const access=jwt.issue(user,session.sessionId,{audience:"client-test",scopes:["openid"]});
  await expect(native.verify(access.accessToken)).rejects.toMatchObject({status:401});
  expect((await native.verify(access.accessToken,{audience:"client-test"})).id).toBe(4);
  await expect(tokens.refresh({refreshToken:session.refreshToken})).rejects.toMatchObject({status:401});
  const idToken=jwt.issueOidcIdToken({user,issuer:native.config.jwt.issuer,audience:"client-test",authTime:new Date()});
  await expect(native.verify(idToken.accessToken,{audience:"client-test"})).rejects.toMatchObject({status:401});
 });
 it("preserves organization normalization and refuses duplicate names and deleted members",async()=>{
  const result=await native.organization(request({name:"  Campus-A  ",title:"  Campus A  "},"organization-normalize"),"create") as {data:{id:number;name:string;title:string}};
  expect(result.data).toMatchObject({name:"campus-a",title:"Campus A"});
  const found=await native.organization(request(undefined,"org-list"),"list",{names:" CAMPUS-A ,campus-a"}) as {data:unknown[]};expect(found.data).toHaveLength(1);
  await expect(native.organization(request({name:"campus-a",title:"duplicate"},"organization-duplicate"),"create")).rejects.toMatchObject({status:409});
  const [deleted]=await db.query<RowDataPacket[]>("SELECT id FROM user WHERE deleted_at IS NOT NULL LIMIT 1");
  await expect(native.organization(request({user_id:deleted[0].id,organization_id:result.data.id},"bind-deleted"),"bind-user")).rejects.toMatchObject({status:404});
  await native.organization(request({user_id:4,organization_id:result.data.id},"bind-user"),"bind-user");
  expect((await native.organizationMembers(result.data.id)).subjects.map(u=>u.id)).toEqual([4]);
  const update=request({organization_id:result.data.id,user_ids:[4],password:"Campus-updated!83"},"campus-password-once");
  await native.campusPassword(update);const login=await tokens.login({username:"native-user",password:"Campus-updated!83"});
  await native.campusPassword(update);expect((await native.verify(login.token.accessToken)).id).toBe(4);
 });
 it("preserves the stricter historical person-management role rules",async()=>{
  await db.query("INSERT INTO auth_assignment(item_name,user_id) VALUES('manager','3')");
  await db.query("INSERT INTO auth_item(name,type) VALUES('/v1/person/*',2)");await db.query("INSERT INTO auth_item_child(parent,child) VALUES('admin','/v1/person/*')");
  const admin=(await tokens.login({username:"native-admin",password})).token.accessToken;
  await expect(native.person(request({id:4,auth:"admin"},"person-admin-escalation",admin),"auth")).rejects.toMatchObject({status:400});
  await expect(native.person(request({nickname:"cannot edit manager"},"person-admin-manager",admin),"update",3)).rejects.toMatchObject({status:400});
  const created=await native.person(request({username:"person-created",password},"person-create-once"),"create") as {body:{access_token:string;code:number}};
  expect(created.body.code).toBe(20000);const id=(await native.verify(created.body.access_token)).id;
  const update=await native.person(request({nickname:" Person name "},"person-update"),"update",id) as {body:{data:{nickname:string}}};expect(update.body.data.nickname).toBe("Person name");
  await native.person(request(undefined,"person-delete"),"delete",id);
  await expect(native.person(request(undefined,"person-view-deleted"),"view",id)).rejects.toMatchObject({status:404});
 });
 it("accepts bounded old Yii access credentials including fractional times and one-element audience arrays",async()=>{
  const folder=await mkdtemp(join(tmpdir(),"identity-legacy-trust-"));
  try{
   const key=createPrivateKey(process.env.IDENTITY_JWT_PRIVATE_KEY_PEM!);await writeFile(join(folder,"legacy.pem"),createPublicKey(key).export({format:"pem",type:"spki"}));
   const now=Date.now()/1000;await writeFile(join(folder,"trust.json"),JSON.stringify([{algorithm:"ES256",publicKeyFile:join(folder,"legacy.pem"),issuer:"http://legacy.local",audience:"http://legacy.api",issuedBefore:new Date((now+1)*1000).toISOString(),acceptUntil:new Date((now+120)*1000).toISOString()}]));
   vi.stubEnv("IDENTITY_LEGACY_JWT_CONFIG_FILE",join(folder,"trust.json"));
   const old=(extra:Record<string,unknown>={})=>{const h=Buffer.from(JSON.stringify({alg:"ES256",typ:"JWT"})).toString("base64url");const p=Buffer.from(JSON.stringify({uid:2,sub:"2",session_id:"legacy-access-without-refresh",iss:"http://legacy.local",aud:["http://legacy.api"],iat:now-1.25,nbf:now-1.25,exp:now+60.5,...extra})).toString("base64url");return `${h}.${p}.${sign("sha256",Buffer.from(`${h}.${p}`),{key,dsaEncoding:"ieee-p1363"}).toString("base64url")}`;};
   expect((await native.verify(old())).id).toBe(2);
   await expect(native.verify(old({iat:now+2}))).rejects.toMatchObject({status:401});
   await expect(native.verify(old({exp:now-1}))).rejects.toMatchObject({status:401});
   await expect(native.verify(old({aud:["http://legacy.api","another-client"]}))).rejects.toMatchObject({status:401});
   await sessions.revokeUserSessions(2);await expect(native.verify(old())).rejects.toMatchObject({status:401});
  }finally{vi.stubEnv("IDENTITY_LEGACY_JWT_CONFIG_FILE","");await rm(folder,{recursive:true,force:true});}
 });
 it("accepts bounded old OAuth userinfo without requiring an invented session ID",async()=>{
  const created=await native.pluginWrite(request({username:"old-oauth-subject",password},"old-oauth-subject"),"create-user") as {data:{id:number}};
  await db.execute("INSERT INTO identity_auth_subject_maps(auth_user_id,user_id,status) VALUES('old-oauth-uuid',?,'active')",[created.data.id]);
  const folder=await mkdtemp(join(tmpdir(),"identity-old-oauth-"));const now=Math.floor(Date.now()/1000),secret=randomBytes(32).toString("hex");
  await writeFile(join(folder,"secret"),secret);await writeFile(join(folder,"trust.json"),JSON.stringify([{algorithm:"HS256",secretFile:join(folder,"secret"),issuer:"https://old-auth.test",audience:"bujiaban-web",allowedScopes:["openid","profile"],issuedBefore:new Date((now+1)*1000).toISOString(),acceptUntil:new Date((now+120)*1000).toISOString()}]));
  vi.stubEnv("IDENTITY_AUTH_LEGACY_JWT_CONFIG_FILE",join(folder,"trust.json"));
  const oauth=new IdentityWechatOAuthService(reader,sessions,jwt,native);
  try{
   const input=[{alg:"HS256",typ:"JWT"},{typ:"access",sub:"old-oauth-uuid",iss:"https://old-auth.test",aud:"bujiaban-web",scope:"openid profile",iat:now-1,exp:now+60}].map(value=>Buffer.from(JSON.stringify(value)).toString("base64url")).join(".");
   const token=`${input}.${createHmac("sha256",secret).update(input).digest("base64url")}`;
   expect(await oauth.userinfo(`Bearer ${token}`)).toMatchObject({sub:"old-oauth-uuid",name:"old-oauth-subject"});
   await expect(native.verify(token)).rejects.toMatchObject({status:401});
   await sessions.revokeUserSessions(created.data.id);await expect(oauth.userinfo(`Bearer ${token}`)).rejects.toMatchObject({status:401});
  }finally{await oauth.onModuleDestroy();vi.stubEnv("IDENTITY_AUTH_LEGACY_JWT_CONFIG_FILE","");await rm(folder,{recursive:true,force:true});}
 });
 it("inventories real identity columns and business foreign keys without exposing credentials",async()=>{
  await db.query("CREATE TABLE baseline_content(id BIGINT PRIMARY KEY,user_id BIGINT,FOREIGN KEY(user_id) REFERENCES user(id) ON DELETE CASCADE)");
  const baseline=await readAccountBaseline(db);
  expect(baseline.users.count).toBeGreaterThan(4);expect(baseline.users.credentialAlgorithms["bcrypt-2y"]).toBeGreaterThan(0);
  expect(baseline.foreignKeys).toEqual(expect.arrayContaining([expect.objectContaining({TABLE_NAME:"baseline_content",DELETE_RULE:"CASCADE"})]));
  expect(JSON.stringify(baseline)).not.toContain("Strong-private");expect(JSON.stringify(baseline)).not.toContain("native-root");
  await expect(readAccountBaseline(db,1)).rejects.toThrow("budget");
 });
 // This full journey performs seven cost-12 hashes and two password checks,
 // including competing resets and response retries on shared CI CPUs.
 it("atomically continues old reset links and does not revoke a fresh login on response retry",async()=>{
  const created=await native.pluginWrite(request({username:"legacy-reset-account",email:"legacy-reset@example.test",password},"legacy-reset-account"),"create-user") as {data:{id:number}};
  const token=`${randomBytes(24).toString("base64url")}_${Math.floor(Date.now()/1000)}`;
  await db.execute("UPDATE user SET password_reset_token=? WHERE id=?",[token,created.data.id]);
  const old=await tokens.login({username:"legacy-reset-account",password});
  expect(await links.validateReset({token})).toMatchObject({userId:created.data.id});
  const payload={token,password:"Reset-updated!74"};
  expect((await Promise.all([links.reset(payload),links.reset(payload)])).map(value=>value.userId)).toEqual([created.data.id,created.data.id]);
  await expect(native.verify(old.token.accessToken)).rejects.toMatchObject({status:401});
  const fresh=await tokens.login({username:"legacy-reset-account",password:payload.password});await links.reset(payload);expect((await native.verify(fresh.token.accessToken)).id).toBe(created.data.id);
  await expect(links.reset({...payload,password:"Another-reset!91"})).rejects.toMatchObject({status:409});
  await native.pluginWrite(request({id:created.data.id,password:"Later-updated!62"},"legacy-reset-after-change"),"update-user");
  await expect(links.reset(payload)).rejects.toMatchObject({status:409});
  await db.execute("UPDATE user SET password_reset_token=? WHERE id=?",[`expired-token-with-enough-entropy_${Math.floor(Date.now()/1000)-3601}`,created.data.id]);
  await expect(links.validateReset({token:`expired-token-with-enough-entropy_${Math.floor(Date.now()/1000)-3601}`})).rejects.toMatchObject({status:400});
  expect(()=>new LegacyEmailLinkController(links).reset("incorrect-internal-key",undefined,payload)).toThrow();
 },15_000);
 it("preserves emailed invitation signup and verification without duplicate accounts or grants",async()=>{
  await db.execute("INSERT INTO invitation(code,sender_id,used,auth_item_name) VALUES ('historical-email-invite',1,0,'manager')");
  const signup={username:"email-invited-account",email:"email-invited@example.test",password,invitation:"historical-email-invite"};
  const [first,second]=await Promise.all([links.signup(signup),links.signup(signup)]);expect(first.userId).toBe(second.userId);expect(first.token).toBe(second.token);
  await expect(tokens.login({username:signup.username,password})).rejects.toMatchObject({status:401});
  const [a,b]=await Promise.all([links.verify({token:first.token}),links.verify({token:first.token})]);expect([a.status,b.status]).toEqual([10,10]);
  const user=await native.subject(first.userId);expect(user.roles).toEqual(["manager"]);
  const [invites]=await db.query<RowDataPacket[]>("SELECT recipient_id,used FROM invitation WHERE code='historical-email-invite'");expect(invites[0]).toMatchObject({recipient_id:first.userId,used:1});
  expect((await links.signup(signup)).token).toBeNull();
  const reset=await links.requestLink("reset",{email:signup.email});expect(await links.validateReset({token:reset.token})).toMatchObject({userId:first.userId});
  await expect(links.requestLink("reset",{email:signup.email})).rejects.toMatchObject({status:400});
  await expect(links.signup({...signup,username:"a-second-invited-account"})).rejects.toMatchObject({status:409});
  await native.pluginWrite(request({id:first.userId,status:0},"disable-email-invited"),"update-user");await expect(links.verify({token:first.token})).rejects.toMatchObject({status:400});
 });
 it("bridges only valid old signed PHP credentials within the configured window and before any revocation",async()=>{
  const created=await native.pluginWrite(request({username:"legacy-php-account",password},"legacy-php-account"),"create-user") as {data:{id:number}};
  const authKey=randomBytes(24).toString("base64url");await db.execute("UPDATE user SET auth_key=? WHERE id=?",[authKey,created.data.id]);
  const payload={userId:created.data.id,authKey};vi.stubEnv("IDENTITY_LEGACY_PHP_SESSION_ACCEPT_UNTIL",new Date(Date.now()+60000).toISOString());
  const exchanged=await tokens.exchangeLegacyPhpSession(payload);expect((await native.verify(exchanged.token.accessToken)).id).toBe(created.data.id);
  await expect(tokens.exchangeLegacyPhpSession({...payload,authKey:randomBytes(24).toString("base64url")})).rejects.toMatchObject({status:401});
  await sessions.revokeUserSessions(created.data.id);await expect(tokens.exchangeLegacyPhpSession(payload)).rejects.toMatchObject({status:401});
  const fresh=await tokens.login({username:"legacy-php-account",password});expect((await native.verify(fresh.token.accessToken)).id).toBe(created.data.id);
  vi.stubEnv("IDENTITY_LEGACY_PHP_SESSION_ACCEPT_UNTIL","");await expect(tokens.exchangeLegacyPhpSession(payload)).rejects.toMatchObject({status:401});
 });
 it("consumes one emailed verification proof and replays only its encrypted original session",async()=>{
  const pending=await pendingVerification("single-session");
  const responses=await Promise.all(Array.from({length:6},()=>links.verify({token:pending.token})));
  expect(new Set(responses.map(value=>value.authTokens?.refreshToken)).size).toBe(1);expect(responses[0].authTokens).toBeDefined();
  expect(await sessionCount(pending.id)).toBe(1);expect((await native.verify(responses[0].authTokens!.accessToken)).id).toBe(pending.id);
  const [rows]=await db.query<RowDataPacket[]>("SELECT response FROM identity_native_operations WHERE JSON_UNQUOTE(JSON_EXTRACT(response,'$.userId'))=?",[String(pending.id)]);
  const serialized=JSON.stringify(rows);expect(serialized).toContain("encryptedAuth");expect(serialized).not.toContain(responses[0].authTokens!.refreshToken);expect(serialized).not.toContain(responses[0].authTokens!.accessToken);
  await expect(links.verify({token:pending.token},"different-request-key")).rejects.toMatchObject({status:400});expect(await sessionCount(pending.id)).toBe(1);
 });
 it("rolls back activation, grants and the inserted session when verification signing or commit work fails",async()=>{
  const pending=await pendingVerification("rollback");
  const ready=vi.spyOn(jwt,"assertSigningReady").mockImplementationOnce(()=>{throw new Error("signing not ready");});
  await expect(links.verify({token:pending.token})).rejects.toThrow("signing not ready");ready.mockRestore();
  const original=tokens.issueInTransaction.bind(tokens),issue=vi.spyOn(tokens,"issueInTransaction").mockImplementationOnce(async(...args)=>{await original(...args);throw new Error("failure after session insert");});
  await expect(links.verify({token:pending.token})).rejects.toThrow("failure after session insert");issue.mockRestore();
  const [rows]=await db.execute<RowDataPacket[]>("SELECT status,verification_token FROM user WHERE id=?",[pending.id]);expect(rows[0]).toMatchObject({status:9,verification_token:pending.token});
  expect(await sessionCount(pending.id)).toBe(0);expect((await native.subject(pending.id)).roles).toEqual([]);
  expect((await links.verify({token:pending.token})).authTokens).toBeDefined();expect(await sessionCount(pending.id)).toBe(1);
 });
 it.each(["logout","password","email","expiry","refresh"])("never mints a new login from consumed verification proof after %s",async(kind)=>{
  const pending=await pendingVerification(kind),first=await links.verify({token:pending.token});expect(first.authTokens).toBeDefined();
  if(kind==="logout")await tokens.logout({refreshToken:first.authTokens!.refreshToken});
  else if(kind==="password")await native.pluginWrite(request({id:pending.id,password:"Changed-verification!87"},`verify-password-${pending.id}`),"update-user");
  else if(kind==="email")await db.execute("UPDATE user SET email=?,email_verified_at=email_verified_at+1 WHERE id=?",[`changed-${pending.id}@example.test`,pending.id]);
  else if(kind==="expiry")await db.execute("UPDATE identity_native_operations SET response=JSON_SET(response,'$.authReplay.retryUntil',0) WHERE JSON_UNQUOTE(JSON_EXTRACT(response,'$.userId'))=?",[String(pending.id)]);
  else await tokens.refresh({refreshToken:first.authTokens!.refreshToken});
  const count=await sessionCount(pending.id);
  expect((await links.verify({token:pending.token})).authTokens).toBeUndefined();expect((await links.verify({token:pending.token})).authTokens).toBeUndefined();
  expect(await sessionCount(pending.id)).toBe(count);
  const [rows]=await db.execute<RowDataPacket[]>("SELECT response FROM identity_native_operations WHERE JSON_UNQUOTE(JSON_EXTRACT(response,'$.userId'))=?",[String(pending.id)]);expect(JSON.stringify(rows)).not.toContain("encryptedAuth");
 });
 it("linearizes verification retry with logout without recreating a session",async()=>{
  const pending=await pendingVerification("logout-race"),first=await links.verify({token:pending.token});
  await Promise.all([links.verify({token:pending.token}),tokens.logout({refreshToken:first.authTokens!.refreshToken})]);
  expect((await links.verify({token:pending.token})).authTokens).toBeUndefined();expect(await sessionCount(pending.id)).toBe(1);
  await expect(native.verify(first.authTokens!.accessToken)).rejects.toMatchObject({status:401});
 });
 it("rejects a legacy PHP auth key changed between subject read and session insertion",async()=>{
  const pending=await pendingVerification("php-key-race"),verified=await links.verify({token:pending.token});
  const authKey=randomBytes(24).toString("base64url");await db.execute("UPDATE user SET auth_key=? WHERE id=?",[authKey,pending.id]);
  vi.stubEnv("IDENTITY_LEGACY_PHP_SESSION_ACCEPT_UNTIL",new Date(Date.now()+60000).toISOString());
  const original=sessions.issue.bind(sessions),issue=vi.spyOn(sessions,"issue").mockImplementationOnce(async(...args)=>{await db.execute("UPDATE user SET auth_key=? WHERE id=?",[randomBytes(24).toString("base64url"),pending.id]);return original(...args);});
  await expect(tokens.exchangeLegacyPhpSession({userId:pending.id,authKey})).rejects.toMatchObject({status:401});issue.mockRestore();
  expect(await sessionCount(pending.id)).toBe(1);expect((await native.verify(verified.authTokens!.accessToken)).id).toBe(pending.id);
  vi.stubEnv("IDENTITY_LEGACY_PHP_SESSION_ACCEPT_UNTIL","");
 });
 it("authorizes login audit with live private memberships without legacy shadow prerequisites",async()=>{
  const [organizations]=await db.query<RowDataPacket[]>("SELECT id FROM organization WHERE name='campus-a'");const organizationId=Number(organizations[0].id);
  await native.organization(request({user_id:3,organization_id:organizationId},"audit-bind-manager"),"bind-user");
  const manager=(await tokens.login({username:"native-manager",password})).token.accessToken;
  const audit={getUserAudit:vi.fn().mockResolvedValue({events:[]})};
  const controller=new PluginUserReadonlyController(reader,jwt,{} as PluginUserPrimaryReadService,audit as unknown as LoginAuditService,{} as IamRepository,native);
  expect(await controller.userLoginAudit(`Bearer ${manager}`,"4",{organization_id:String(organizationId)})).toEqual({code:0,data:{events:[]}});
  await native.organization(request({user_id:3,organization_id:organizationId},"audit-unbind-manager"),"unbind-user");
  await expect(controller.userLoginAudit(`Bearer ${manager}`,"4",{organization_id:String(organizationId)})).rejects.toMatchObject({status:403});
  expect(audit.getUserAudit).toHaveBeenCalledTimes(1);
 });
});
