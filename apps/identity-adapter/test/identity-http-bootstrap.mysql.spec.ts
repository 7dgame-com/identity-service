import "reflect-metadata";
import { execFile } from "node:child_process";
import { generateKeyPairSync, randomBytes, randomUUID, createHash, createHmac } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";
import type { INestApplication } from "@nestjs/common";
import { NestFactory } from "@nestjs/core";
import mysql, { type Connection, type RowDataPacket } from "mysql2/promise";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { hashLegacyPassword } from "../src/legacy-password.js";

const enabled=process.env.IDENTITY_TEST_MYSQL==="1";
const projectRoot=fileURLToPath(new URL("../../../",import.meta.url));
const databaseName=`test_identity_http_${randomUUID().replaceAll("-","")}`;
const deviceDatabaseName=`test_identity_http_sn_${randomUUID().replaceAll("-","")}`;
const options={host:process.env.IDENTITY_DB_HOST??"127.0.0.1",port:Number(process.env.IDENTITY_DB_PORT??3306),
  user:process.env.IDENTITY_DB_USER??"root",password:process.env.IDENTITY_DB_PASSWORD??"",multipleStatements:true,timezone:"Z"};
const password="Http-bootstrap!73",internalToken=randomBytes(32).toString("hex"),authInternalToken=randomBytes(32).toString("hex");
let admin:Connection|undefined,db:Connection|undefined,app:INestApplication|undefined,buildDirectory:string|undefined,baseUrl:string;

type Json=Record<string,any>;
async function http(path:string,method="GET",body?:unknown,headers:Record<string,string>={}) {
  const response=await fetch(`${baseUrl}${path}`,{method,headers:{...(body===undefined?{}:{"content-type":"application/json"}),...headers},
    ...(body===undefined?{}:{body:JSON.stringify(body)}),signal:AbortSignal.timeout(10000)});
  const raw=await response.text();
  return {status:response.status,headers:response.headers,body:(raw?JSON.parse(raw):null) as Json};
}
async function login(username:string) {
  const response=await http("/v1/auth/login","POST",{username,password});
  expect(response.status).toBe(201);expect(response.body.success).toBe(true);
  expect(response.body.token.accessToken).toEqual(expect.any(String));return response.body.token as {accessToken:string;refreshToken:string};
}
function bearer(token:string){return {authorization:`Bearer ${token}`};}

describe.skipIf(!enabled)("compiled AppModule independent HTTP bootstrap",()=>{
  beforeAll(async()=>{
    // Vitest's TypeScript transform omits design:paramtypes. Compile with the
    // production tsconfig and import emitted JS so this verifies real Nest DI.
    buildDirectory=await mkdtemp(join(projectRoot,".identity-http-build-"));
    await promisify(execFile)(process.execPath,[join(projectRoot,"node_modules/typescript/bin/tsc"),"--outDir",buildDirectory,"--noEmitOnError","true"],
      {cwd:projectRoot,timeout:90000,maxBuffer:1024*1024});
    const controllerCode=await readFile(join(buildDirectory,"apps/identity-adapter/src/native-identity.controller.js"),"utf8");
    expect(controllerCode).toContain('__metadata("design:paramtypes"');
    admin=await mysql.createConnection(options);
    await admin.query(`CREATE DATABASE \`${databaseName}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`);
    await admin.query(`CREATE DATABASE \`${deviceDatabaseName}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
      CREATE TABLE \`${deviceDatabaseName}\`.device_sn(id INT PRIMARY KEY,user_id INT,device_uuid VARCHAR(255),enabled BOOL,activated_at DATETIME);
      INSERT INTO \`${deviceDatabaseName}\`.device_sn VALUES(9,4,'http-yii3-device',1,NOW())`);
    db=await mysql.createConnection({...options,database:databaseName});
    const init=await readFile(join(projectRoot,"deploy/mysql/init.sql"),"utf8");
    await db.query(init.slice(init.indexOf("CREATE TABLE IF NOT EXISTS `auth_login_events`")));
    for(const schema of ["identity-account-schema.sql","identity-password-reset-token-schema.sql","identity-legacy-challenge-schema.sql","identity-runtime-schema.sql","identity-wechat-oauth-schema.sql","identity-qrcode-schema.sql","identity-apple-schema.sql"])
      await db.query(await readFile(join(projectRoot,"deploy/mysql",schema),"utf8"));
    const keys=generateKeyPairSync("ec",{namedCurve:"prime256v1"});
    const environment={IDENTITY_DATA_SOURCE:"identity",IDENTITY_DB_HOST:options.host,IDENTITY_DB_PORT:String(options.port),IDENTITY_DB_USER:options.user,
      IDENTITY_DB_PASSWORD:options.password,IDENTITY_DB_NAME:databaseName,IDENTITY_TOKEN_ISSUANCE_ENABLED:"true",IDENTITY_REFRESH_REPLAY_KEY:randomBytes(32).toString("base64url"),
      IDENTITY_INTERNAL_API_TOKEN:internalToken,IDENTITY_IAM_INTERNAL_API_TOKEN:internalToken,IDENTITY_JWT_PRIVATE_KEY_PEM:keys.privateKey.export({type:"pkcs8",format:"pem"}).toString(),
      IDENTITY_TOKEN_ISSUANCE_INTERNAL_API_TOKEN:authInternalToken,
      IDENTITY_CORS_ORIGINS:"https://http-school.example.test",
      DEVICE_SN_DB_HOST:options.host,DEVICE_SN_DB_PORT:String(options.port),DEVICE_SN_DB_NAME:deviceDatabaseName,DEVICE_SN_DB_USER:options.user,DEVICE_SN_DB_PASSWORD:options.password,
      IDENTITY_JWT_PUBLIC_KEY_PEM:keys.publicKey.export({type:"spki",format:"pem"}).toString(),IDENTITY_JWT_ISSUER:"https://identity-http.test",IDENTITY_JWT_AUDIENCE:"http-private-api",
      IDENTITY_ACCOUNT_LIFECYCLE_ENABLED:"true",IDENTITY_ACCOUNT_LIFECYCLE_MODE:"native",IDENTITY_ACCOUNT_REGISTER_ENABLED:"true",IDENTITY_ACCOUNT_EMAIL_ENABLED:"true",
      IDENTITY_ACCOUNT_EMAIL_VERIFY_NATIVE_ENABLED:"true",IDENTITY_ACCOUNT_EMAIL_CHANGE_NATIVE_ENABLED:"true",IDENTITY_ACCOUNT_PASSWORD_ENABLED:"true",
      IDENTITY_EMAIL_WEBHOOK_URL:"http://127.0.0.1:1/unavailable-delivery",
      IDENTITY_ACCOUNT_PASSWORD_CHANGE_NATIVE_ENABLED:"true",IDENTITY_ACCOUNT_PASSWORD_RESET_NATIVE_ENABLED:"true",IDENTITY_ACCOUNT_INVITATION_ENABLED:"true",
      IDENTITY_ACCOUNT_INVITATION_MANAGEMENT_NATIVE_ENABLED:"true",IDENTITY_ACCOUNT_INVITATION_CHECK_NATIVE_ENABLED:"true",IDENTITY_ACCOUNT_INVITATION_RECORDS_NATIVE_ENABLED:"true",
      IDENTITY_APPLE_CLIENT_IDS:"apple.http.app",IDENTITY_LOGIN_AUDIT_ENABLED:"false",IDENTITY_IAM_ENABLED:"false",IDENTITY_OIDC_ENABLED:"false",IDENTITY_LEGACY_SESSION_REVOKE_ENABLED:"false",
      LEGACY_DB_HOST:"127.0.0.1",LEGACY_DB_PORT:"1",LEGACY_DB_USER:"unreachable",LEGACY_DB_PASSWORD:"unreachable",
      LEGACY_WRITE_DB_HOST:"127.0.0.1",LEGACY_WRITE_DB_PORT:"1",LEGACY_WRITE_DB_USER:"unreachable",LEGACY_WRITE_DB_PASSWORD:"unreachable"};
    for(const [key,value] of Object.entries(environment))vi.stubEnv(key,value);
    const hash=await hashLegacyPassword(password);
    for(const [id,role] of [[1,"root"],[2,"admin"],[3,"manager"],[4,"user"]] as const) {
      await db.execute("INSERT INTO user(id,username,password_hash,status,created_at,updated_at) VALUES (?,?,?,10,1700000000,1700000000)",[id,`http-${role}`,hash]);
      await db.execute("INSERT INTO user_info(user_id,info) VALUES (?,?)",[id,JSON.stringify({fixture:role})]);
      await db.execute("INSERT INTO auth_assignment(item_name,user_id) VALUES (?,?)",[role,String(id)]);
    }
    const {AppModule}=await import(pathToFileURL(join(buildDirectory,"apps/identity-adapter/src/app.module.js")).href);
    app=await NestFactory.create(AppModule,{logger:false,abortOnError:false});
    await app.listen(0,"127.0.0.1");baseUrl=await app.getUrl();
  },120000);
  afterAll(async()=>{
    await app?.close();await db?.end();
    if(admin){await admin.query(`DROP DATABASE IF EXISTS \`${databaseName}\`;DROP DATABASE IF EXISTS \`${deviceDatabaseName}\``);await admin.end();}
    if(buildDirectory)await rm(buildDirectory,{recursive:true,force:true});
    vi.unstubAllEnvs();
  },30000);

  it("boots all production providers against the private database and exposes authenticated user info",async()=>{
    const health=await http("/health");expect(health.status).toBe(200);
    expect(health.body).toMatchObject({mode:"independent",accountAuthority:"identity",dependencies:{identityDatabase:"configured"}});
    const [authority]=await db!.query<RowDataPacket[]>("SELECT authority FROM identity_migration_control WHERE id=1");expect(authority[0].authority).toBe("identity");
    expect((await http("/v1/user/info")).status).toBe(401);
    expect((await http("/v1/auth/login","POST",{username:"http-user",password:"incorrect"})).status).toBe(401);
    const token=await login("http-user"),info=await http("/v1/user/info","GET",undefined,bearer(token.accessToken));
    expect(info.status).toBe(200);expect(info.body).toMatchObject({success:true,data:{id:4,userData:{username:"http-user"},roles:["user"]}});
    expect((await http("/v1/email/status","GET",undefined,bearer(token.accessToken))).status).toBe(200);
  });

  it("keeps Person routes administrative and performs their CRUD through the actual HTTP router",async()=>{
    const root=await login("http-root"),user=await login("http-user"),manager=await login("http-manager");
    expect((await http("/v1/person","GET",undefined,bearer(user.accessToken))).status).toBe(403);
    expect((await http("/v1/person/4","GET",undefined,bearer(manager.accessToken))).status).toBe(403);
    const list=await http("/v1/person","GET",undefined,bearer(root.accessToken));
    expect(list.status).toBe(200);expect(list.body).toEqual(expect.arrayContaining([expect.objectContaining({id:4,username:"http-user"})]));
    expect(list.headers.get("x-pagination-total-count")).toBe("4");
    const created=await http("/v1/person","POST",{username:"http-created-person",password},{...bearer(root.accessToken),"idempotency-key":"http-create-person"});
    expect(created.status).toBe(201);expect(created.body.code).toBe(20000);
    const createdInfo=await http("/v1/user/info","GET",undefined,bearer(created.body.access_token)),id=createdInfo.body.data.id;
    expect(createdInfo.status).toBe(200);expect(id).toBeGreaterThan(4);
    const update=await http(`/v1/person/${id}`,"PUT",{nickname:"HTTP nickname"},bearer(root.accessToken));
    expect(update.status).toBe(200);expect(update.body.data.nickname).toBe("HTTP nickname");
    const role=await http("/v1/person/auth","PUT",{id,auth:"manager"},bearer(root.accessToken));
    expect(role.status).toBe(200);expect(role.body.assigned.manager).toBe("role");
    expect((await http(`/v1/person/${id}`,"DELETE",undefined,bearer(root.accessToken))).status).toBe(200);
    expect((await http(`/v1/person/${id}`,"GET",undefined,bearer(root.accessToken))).status).toBe(404);
    expect((await http("/v1/user/info","GET",undefined,bearer(created.body.access_token))).status).toBe(401);
  });

  it("requires internal authentication for subjects, verification and provider binding reads",async()=>{
    const token=await login("http-user");
    const rejectedHeaders:Record<string,string>[]=[{},{"x-identity-internal-token":"incorrect"}];
    for(const headers of rejectedHeaders) {
      expect((await http("/internal/identity/subjects/4","GET",undefined,headers)).status).toBe(401);
      expect((await http("/internal/auth/verify-access-token","POST",{token:token.accessToken},headers)).status).toBe(401);
      expect((await http("/internal/wechat-oauth/users/4/identity?providerAppId=wx-private","GET",undefined,headers)).status).toBe(401);
    }
    const headers={"x-identity-internal-token":internalToken};
    expect((await http("/internal/identity/subjects/4","GET",undefined,headers)).body.data.id).toBe(4);
    const verified=await http("/internal/auth/verify-access-token","POST",{token:token.accessToken},headers);
    expect(verified.status).toBe(201);expect(verified.body.data.id).toBe(4);
    expect((await http("/internal/wechat-oauth/users/4/identity?providerAppId=wx-private","GET",undefined,{"x-identity-internal-token":authInternalToken})).body).toBeNull();
  });

  it("routes Yii3 code context, multi-device exchange and strict refresh through the scoped internal auth key",async()=>{
    const key=randomBytes(32).toString("base64url"),now=Math.floor(Date.now()/1000),headers={"x-identity-internal-token":authInternalToken};
    await db!.execute("INSERT INTO identity_login_codes(code_hash,user_id,issued_at,expires_at,context_json) VALUES (?,4,?,?,?)",
      [createHash("sha256").update(key).digest("hex"),now,now+60,JSON.stringify({frontend_domain:"http-school.example.test"})]);
    const path="/internal/yii3/login-code",body={key,operation:"context"};
    const rejectedHeaders:Record<string,string>[]=[{},{"x-identity-internal-token":internalToken},{"x-identity-internal-token":"incorrect"}];
    for(const rejected of rejectedHeaders)expect((await http(path,"POST",body,rejected)).status).toBe(401);
    const [before]=await db!.query<RowDataPacket[]>("SELECT COUNT(*) AS n FROM identity_refresh_sessions");
    const context=await http(path,"POST",body,headers);expect(context.status).toBe(201);expect(context.body).toEqual({frontendDomain:"http-school.example.test"});
    const [after]=await db!.query<RowDataPacket[]>("SELECT COUNT(*) AS n FROM identity_refresh_sessions");expect(Number(after[0].n)).toBe(Number(before[0].n));
    const exchanges=await Promise.all([1,2].map(()=>http(path,"POST",{key:`web_${key}`,operation:"redeem"},headers)));
    for(const exchanged of exchanges){expect(exchanged.status).toBe(201);expect(exchanged.body.subject).toMatchObject({id:4,status:10});
      const claims=JSON.parse(Buffer.from(exchanged.body.authTokens.accessToken.split(".")[1],"base64url").toString());expect(claims.aud).toBe("http-private-api");}
    expect(exchanges[0].body.authTokens.refreshToken).not.toBe(exchanges[1].body.authTokens.refreshToken);
    const refreshPath="/internal/yii3/refresh",initial=exchanges[0].body.authTokens;
    expect((await http(refreshPath,"POST",{refreshToken:key,allowLoginCode:false},headers)).status).toBe(401);
    expect((await http(refreshPath,"POST",{refreshToken:key,allowLoginCode:true},headers)).status).toBe(201);
    const refreshed=await http(refreshPath,"POST",{refreshToken:initial.refreshToken,allowLoginCode:false},{...headers,"idempotency-key":"http-yii3-refresh"});
    expect(refreshed.status).toBe(201);expect(refreshed.body.authTokens.refreshToken).not.toBe(initial.refreshToken);
    expect((await http("/v1/auth/logout","POST",{refreshToken:initial.refreshToken})).status).toBe(201);
    expect((await http(refreshPath,"POST",{refreshToken:initial.refreshToken,allowLoginCode:true},headers)).status).toBe(401);
    const root=await login("http-root"),issued=await http("/v1/tools/user-linked","GET",undefined,{...bearer(root.accessToken),origin:"https://http-school.example.test"});
    expect(issued.status).toBe(200);
    expect((await http(path,"POST",{key:issued.body.key,operation:"context"},headers)).body).toEqual({frontendDomain:"http-school.example.test"});
    const untrusted=await http("/v1/tools/user-linked","GET",undefined,{...bearer(root.accessToken),origin:"https://untrusted.example.test",referer:"https://http-school.example.test/page"});
    expect(untrusted.status).toBe(200);
    expect((await http(path,"POST",{key:untrusted.body.key,operation:"context"},headers)).body).toEqual({frontendDomain:null});
  });

  it("verifies old Yii3 HS256 and current SN claims through IAM while preventing ordinary credential derivation",async()=>{
    const secret=randomBytes(32).toString("hex"),secretFile=join(buildDirectory!,"yii3-key"),trustFile=join(buildDirectory!,"yii3-trust.json"),now=Date.now()/1000;
    await writeFile(secretFile,` \n${secret}\n`,{mode:0o600});
    await writeFile(trustFile,JSON.stringify({version:1,algorithm:"HS256",secretFile,issuedBefore:new Date(Date.now()+1000).toISOString(),
      acceptUntil:new Date(Date.now()+3600000).toISOString(),maxAccessTtlSeconds:10800}),{mode:0o600});
    vi.stubEnv("IDENTITY_LEGACY_YII3_JWT_CONFIG_FILE",trustFile);
    try {
      const input=[{alg:"HS256"},{uid:4,iat:now-1.123456,exp:now+120,auth_method:"device_sn",device_sn_id:9}]
        .map(value=>Buffer.from(JSON.stringify(value)).toString("base64url")).join(".");
      const token=`${input}.${createHmac("sha256",secret).update(input).digest("base64url")}`;
      const verified=await http("/internal/auth/verify-access-token","POST",{token},{"x-identity-internal-token":internalToken});
      expect(verified.status).toBe(201);expect(verified.body.data).toMatchObject({id:4,status:10,auth_method:"device_sn",device_sn_id:9});
      expect((await http("/v1/tools/user-linked","GET",undefined,bearer(token))).status).toBe(403);
      const issued=await http("/internal/auth/issue-user-token","POST",{legacyUserId:4,auth_method:"device_sn",device_sn_id:9},{"x-identity-internal-token":authInternalToken});
      expect(issued.status).toBe(201);
      const current=await http("/internal/auth/verify-access-token","POST",{token:issued.body.token.accessToken},{"x-identity-internal-token":internalToken});
      expect(current.body.data).toMatchObject({id:4,auth_method:"device_sn",device_sn_id:9});
      expect((await http("/v1/tools/user-linked","GET",undefined,bearer(issued.body.token.accessToken))).status).toBe(403);
    } finally {vi.stubEnv("IDENTITY_LEGACY_YII3_JWT_CONFIG_FILE","");}
  });

  it("routes verified Apple proofs through the real controller with private accounts and legacy token strings",async()=>{
    const profile={providerAppId:"apple.http.app",subject:"http-apple-subject",email:"http-apple@example.test",emailVerified:true};
    expect((await http("/internal/apple/resolve","POST",profile)).status).toBe(401);
    const headers={"x-identity-internal-token":authInternalToken};
    expect((await http("/internal/apple/resolve","POST",{...profile,providerAppId:"other.app"},headers)).status).toBe(401);
    const resolved=await http("/internal/apple/resolve","POST",profile,headers);expect(resolved.status).toBe(200);expect(resolved.body.user).toBeNull();
    const request={apple_id:profile.subject,token:resolved.body.token,username:"http-apple",password};
    const created=await http("/internal/apple/create","POST",request,headers);expect(created.status).toBe(200);expect(created.body.user.auth).toEqual(expect.any(String));
    const info=await http("/v1/user/info","GET",undefined,bearer(created.body.user.auth));expect(info.status).toBe(200);expect(info.body.data.id).toBe(created.body.user_id);
    const replay=await http("/internal/apple/create","POST",request,headers);expect(replay.status).toBe(200);expect(replay.body.user_id).toBe(created.body.user_id);
  });

  it("verifies old email links with one atomic login and a bounded same-session HTTP replay",async()=>{
    await db!.execute("INSERT IGNORE INTO auth_item(name,type) VALUES ('guest',1)");
    const token=`http-email-${randomBytes(24).toString("base64url")}`;
    await db!.execute(`INSERT INTO user(username,email,password_hash,auth_key,status,verification_token,created_at,updated_at)
      SELECT 'http-legacy-email','http-legacy-email@example.test',password_hash,?,9,?,1,1 FROM user WHERE id=1`,[randomBytes(24).toString("base64url"),token]);
    const path="/internal/legacy-email-link/verify",body={token},headers={"x-identity-internal-token":authInternalToken};
    expect((await http(path,"POST",body)).status).toBe(401);
    expect((await http(path,"POST",body,{"x-identity-internal-token":internalToken})).status).toBe(401);
    const [first,replay]=await Promise.all([http(path,"POST",body,headers),http(path,"POST",body,headers)]);
    expect(first.status).toBe(201);expect(replay.status).toBe(201);expect(first.body.authTokens.refreshToken).toBe(replay.body.authTokens.refreshToken);
    const info=await http("/v1/user/info","GET",undefined,bearer(first.body.authTokens.accessToken));expect(info.status).toBe(200);expect(info.body.data.id).toBe(first.body.userId);
    await db!.execute("UPDATE identity_native_operations SET response=JSON_SET(response,'$.authReplay.retryUntil',0) WHERE JSON_UNQUOTE(JSON_EXTRACT(response,'$.userId'))=?",[String(first.body.userId)]);
    const expired=await http(path,"POST",body,headers);expect(expired.status).toBe(201);expect(expired.body.authTokens).toBeUndefined();
    const [sessions]=await db!.execute<RowDataPacket[]>("SELECT COUNT(*) AS total FROM identity_refresh_sessions WHERE legacy_user_id=?",[first.body.userId]);expect(Number(sessions[0].total)).toBe(1);
  });

  it("exchanges signed PHP session credentials only through the scoped internal auth boundary",async()=>{
    const authKey=randomBytes(24).toString("base64url");
    await db!.execute(`INSERT INTO user(username,password_hash,auth_key,status,created_at,updated_at)
      SELECT 'http-php-session',password_hash,?,10,1,1 FROM user WHERE id=1`,[authKey]);
    const [users]=await db!.execute<RowDataPacket[]>("SELECT id FROM user WHERE username='http-php-session'");
    const path="/internal/legacy-php-session/exchange",body={userId:Number(users[0].id),authKey},headers={"x-identity-internal-token":authInternalToken};
    expect((await http(path,"POST",body)).status).toBe(401);expect((await http(path,"POST",body,{"x-identity-internal-token":internalToken})).status).toBe(401);
    vi.stubEnv("IDENTITY_LEGACY_PHP_SESSION_ACCEPT_UNTIL",new Date(Date.now()+60000).toISOString());
    const issued=await http(path,"POST",body,headers);expect(issued.status).toBe(201);expect((await http("/v1/user/info","GET",undefined,bearer(issued.body.token.accessToken))).body.data.id).toBe(body.userId);
    expect((await http(path,"POST",{...body,authKey:randomBytes(24).toString("base64url")},headers)).status).toBe(401);
    vi.stubEnv("IDENTITY_LEGACY_PHP_SESSION_ACCEPT_UNTIL","");expect((await http(path,"POST",body,headers)).status).toBe(401);
  });

  it("routes legacy administration RPC and policy graphs with separate auth and IAM credentials",async()=>{
    const root=await login("http-root"),user=await login("http-user");
    const headers={"x-identity-internal-token":authInternalToken},iamHeaders={"x-identity-internal-token":internalToken};
    const rpc=(operation:string,payload:Json={},accessToken=root.accessToken)=>http("/internal/legacy-admin","POST",{operation,payload,accessToken},headers);
    const snapshot={operation:"rbac-snapshot",accessToken:root.accessToken};
    expect((await http("/internal/legacy-admin","POST",snapshot)).status).toBe(401);
    expect((await http("/internal/legacy-admin","POST",snapshot,iamHeaders)).status).toBe(401);
    expect((await rpc("user-list",{},user.accessToken)).status).toBe(403);
    expect((await http("/internal/identity/policy-graph","POST",{})).status).toBe(401);
    expect((await http("/internal/identity/policy-graph","POST",{},headers)).status).toBe(401);

    const invitation=await rpc("invitation-create",{auth_item_name:"user",idempotencyKey:"http-admin-invitation"});
    expect(invitation.status).toBe(201);expect(invitation.body).toMatchObject({sender_id:1,used:0,auth_item_name:"user"});
    const replay=await rpc("invitation-create",{auth_item_name:"user",idempotencyKey:"http-admin-invitation"});
    expect(replay.status).toBe(201);expect(replay.body.id).toBe(invitation.body.id);
    const invitations=await rpc("invitation-list");expect(invitations.status).toBe(201);
    expect(invitations.body.invitations).toEqual(expect.arrayContaining([expect.objectContaining({id:invitation.body.id})]));

    const created=await rpc("user-create",{username:"http-admin-created",email:"http-admin-created@example.test",password,idempotencyKey:"http-admin-user"});
    expect(created.status).toBe(201);expect(created.body).toMatchObject({username:"http-admin-created",email:"http-admin-created@example.test",status:10});
    expect(created.body).not.toHaveProperty("password_hash");
    const users=await rpc("user-list",{username:"http-admin-created",page:1,pageSize:10});
    expect(users.status).toBe(201);expect(users.body.total).toBe(1);
    expect(users.body.users).toEqual([expect.objectContaining({id:created.body.id,username:"http-admin-created"})]);

    const permission="http.legacy.permission";
    const added=await rpc("rbac-mutate",{action:"add-item",item:{name:permission,type:2},idempotencyKey:"http-admin-policy-item"});
    expect(added.status).toBe(201);expect(added.body).toMatchObject({success:true,changed:true});
    expect((await rpc("rbac-mutate",{action:"add-child",parent:"user",child:permission,idempotencyKey:"http-admin-policy-edge"})).status).toBe(201);
    const graph=await http("/internal/identity/policy-graph","POST",{},iamHeaders);expect(graph.status).toBe(201);
    expect(graph.body.data.items).toEqual(expect.arrayContaining([expect.objectContaining({name:permission,type:2})]));
    expect(graph.body.data.children).toEqual(expect.arrayContaining([expect.objectContaining({parent:"user",child:permission})]));
    expect(graph.body.data).not.toHaveProperty("assignments");
    const complete=await rpc("rbac-snapshot");expect(complete.status).toBe(201);
    expect(complete.body.assignments).toEqual(expect.arrayContaining([expect.objectContaining({item_name:"root",user_id:"1"})]));
  });

  it("registers, refreshes with an idempotent successor and invalidates HTTP access on logout",async()=>{
    const registration=await http("/v1/auth/register","POST",{username:"http-registered",password,email:"http-registered@example.test"});
    expect(registration.status).toBe(201);expect(registration.body.success).toBe(true);
    const initial=registration.body.token;
    expect((await http("/v1/user/info","GET",undefined,bearer(initial.accessToken))).status).toBe(200);
    const headers={"idempotency-key":"http-refresh-once"},body={refreshToken:initial.refreshToken};
    const [a,b]=await Promise.all([http("/v1/auth/refresh","POST",body,headers),http("/v1/auth/refresh","POST",body,headers)]);
    expect(a.status).toBe(201);expect(b.status).toBe(201);expect(a.body.token.refreshToken).toBe(b.body.token.refreshToken);
    expect((await http("/v1/user/info","GET",undefined,bearer(a.body.token.accessToken))).status).toBe(200);
    const logout=await http("/v1/auth/logout","POST",{refreshToken:initial.refreshToken});expect(logout.status).toBe(201);
    expect((await http("/v1/user/info","GET",undefined,bearer(a.body.token.accessToken))).status).toBe(401);
    expect((await http("/v1/auth/refresh","POST",body,headers)).status).toBe(401);
  });

  it("validates and consumes opaque legacy reset tokens through the compiled public password routes",async()=>{
    await db!.query("INSERT INTO user(username,email,password_hash,email_verified_at,status) SELECT 'http-reset-token','http-reset-token@example.test',password_hash,1,10 FROM user WHERE id=1");
    const [users]=await db!.query<RowDataPacket[]>("SELECT id FROM user WHERE username='http-reset-token'");
    const id=Number(users[0].id),token=randomBytes(24).toString("base64url"),digest=createHash("sha256").update(token).digest("hex");
    await db!.execute("INSERT INTO identity_password_reset_tokens(token_hash,legacy_user_id,email,issued_at,expires_at) VALUES (?,?,?,UTC_TIMESTAMP(3),DATE_ADD(UTC_TIMESTAMP(3),INTERVAL 1 MINUTE))",[digest,id,"http-reset-token@example.test"]);
    const initial=await login("http-reset-token"),path="/v1/password/verify-token";
    const valid=await http(path,"POST",{token});expect(valid.status).toBe(200);expect(valid.body).toEqual({success:true,message:"重置令牌有效"});
    const missing=await http(path,"POST",{token:""});expect(missing.status).toBe(400);expect(missing.body.error.code).toBe("VALIDATION_ERROR");
    const invalid=await http(path,"POST",{token:`${token}x`});expect(invalid.status).toBe(400);expect(invalid.body.error.code).toBe("INVALID_TOKEN");
    const body={token,password:"Renewed-access!94"},reset=await http("/v1/password/reset","POST",body);
    expect(reset.status).toBe(200);expect(reset.body).toMatchObject({success:true});
    expect((await http("/v1/user/info","GET",undefined,bearer(initial.accessToken))).status).toBe(401);
    const fresh=await http("/v1/auth/login","POST",{username:"http-reset-token",password:body.password});expect(fresh.status).toBe(201);
    expect((await http("/v1/password/reset","POST",body)).status).toBe(200);
    expect((await http("/v1/user/info","GET",undefined,bearer(fresh.body.token.accessToken))).status).toBe(200);
    const used=await http(path,"POST",{token});expect(used.status).toBe(400);expect(used.body.error.code).toBe("INVALID_TOKEN");
    const [rows]=await db!.execute<RowDataPacket[]>("SELECT token_hash,consumed_at FROM identity_password_reset_tokens WHERE token_hash=?",[digest]);
    expect(rows[0].token_hash).toBe(digest);expect(rows[0].consumed_at).not.toBeNull();
  });

  it("accepts real PHP A1 access tokens only under their own trust and current private roles/status/cutoff",async()=>{
    const fixture=JSON.parse(await readFile(new URL("fixtures/a1-legacy-access-token.json",import.meta.url),"utf8"));
    const secretFile=join(buildDirectory!,"synthetic-a1-key"),trustFile=join(buildDirectory!,"a1-trust.json");
    await writeFile(secretFile,Buffer.from(fixture.secretBase64,"base64"),{mode:0o600});
    const now=Date.parse("2026-10-12T00:00:01Z");
    await writeFile(trustFile,JSON.stringify({version:1,algorithm:"HS256",secretFile,issuers:["https://a1.example.test"],
      issuedBefore:new Date(now).toISOString(),acceptUntil:new Date(now+10800000).toISOString(),maxAccessTtlSeconds:10800}),{mode:0o600});
    await db!.query("INSERT INTO user(id,username,email,email_verified_at,password_hash,status) SELECT 42,'http-a1-imported','a1@example.test',1,password_hash,10 FROM user WHERE id=1; INSERT INTO user_info(user_id) VALUES(42); INSERT INTO auth_assignment(item_name,user_id) VALUES('admin','42')");
    // Freeze only the wall-clock reading to exercise the reproducible real PHP vector.
    const clock=vi.spyOn(Date,"now").mockReturnValue(now);
    vi.stubEnv("IDENTITY_LEGACY_A1_JWT_CONFIG_FILE","");
    try {
      expect((await http("/v1/user/info","GET",undefined,bearer(fixture.token))).status).toBe(401);
      vi.stubEnv("IDENTITY_LEGACY_A1_JWT_CONFIG_FILE",trustFile);
      const verified=await http("/v1/user/info","GET",undefined,bearer(fixture.token));
      expect(verified.status).toBe(200);expect(verified.body.data).toMatchObject({id:42,roles:["admin"]});
      expect((await http("/internal/auth/verify-access-token","POST",{token:fixture.stringUidToken},{"x-identity-internal-token":internalToken})).status).toBe(201);
      await db!.query("DELETE FROM auth_assignment WHERE user_id='42'; INSERT INTO auth_assignment(item_name,user_id) VALUES('user','42')");
      expect((await http("/v1/user/info","GET",undefined,bearer(fixture.token))).body.data.roles).toEqual(["user"]);
      await db!.query("UPDATE user SET status=0 WHERE id=42");
      expect((await http("/v1/user/info","GET",undefined,bearer(fixture.token))).status).toBe(401);
      await db!.query("UPDATE user SET status=10 WHERE id=42");
      expect((await http("/v1/user/info","GET",undefined,bearer(fixture.token))).status).toBe(200);
      const resetToken=randomBytes(24).toString("base64url");
      await db!.execute("INSERT INTO identity_password_reset_tokens(token_hash,legacy_user_id,email,issued_at,expires_at) VALUES (?,42,'a1@example.test',UTC_TIMESTAMP(3),DATE_ADD(UTC_TIMESTAMP(3),INTERVAL 1 MINUTE))",[createHash("sha256").update(resetToken).digest("hex")]);
      expect((await http("/v1/password/reset","POST",{token:resetToken,password:"Renewed-private!94"})).status).toBe(200);
      expect((await http("/v1/user/info","GET",undefined,bearer(fixture.token))).status).toBe(401);
      expect((await http("/internal/auth/verify-access-token","POST",{token:fixture.stringUidToken},{"x-identity-internal-token":internalToken})).status).toBe(401);
    } finally {clock.mockRestore();vi.stubEnv("IDENTITY_LEGACY_A1_JWT_CONFIG_FILE","");}
  });
});
