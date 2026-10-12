import "reflect-metadata";
import { createHash, createHmac, generateKeyPairSync, randomBytes, randomUUID } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import mysql, { type Connection, type RowDataPacket } from "mysql2/promise";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { IdentitySessionRepository } from "../src/identity-session.repository.js";
import { JwtIssuerService } from "../src/jwt-issuer.service.js";
import { LegacyIdentityReader } from "../src/legacy-identity.reader.js";
import { NativeIdentityService } from "../src/native-identity.service.js";
import { NativeQrcodeRepository } from "../src/native-qrcode.repository.js";
import { NativeQrcodeService } from "../src/native-qrcode.service.js";
import { TokenIssuanceService } from "../src/token-issuance.service.js";
import { Yii3CompatibilityService } from "../src/yii3-compatibility.service.js";
import { exportYii3RefreshSessions } from "../src/identity-yii3-session-export.js";
import { importLegacySessions, normalizeLegacySessionManifest } from "../src/legacy-session-import.js";
import type { IdentityWechatOAuthService } from "../src/identity-wechat-oauth.service.js";
import type { AccountRegistrationService } from "../src/account-registration.service.js";
import type { LoginAuditService } from "../src/login-audit.service.js";

const hash=(value:string)=>createHash("sha256").update(value).digest("hex");
const opts={host:"127.0.0.1",port:Number(process.env.IDENTITY_TEST_MYSQL_PORT??13316),
  user:process.env.IDENTITY_TEST_MYSQL_USER??"root",password:process.env.IDENTITY_TEST_MYSQL_PASSWORD??"",multipleStatements:true,timezone:"Z"};
const suffix=randomUUID().replaceAll("-", ""),name=`test_yii3_${suffix}`,business=`test_yii3_sn_${suffix}`;
const source={application:"yii3-a1",sourceRevision:"1".repeat(40),redisDatabase:1,keyPrefix:"refresh_token:",
  fixedTtlSeconds:2592000,expiryPolicy:"setex-on-create-only",namespaceWritersReviewed:true};
const makeManifest=(token:string,device=false,expiry=Date.now()+120000)=>exportYii3RefreshSessions({version:1,source,capturedAtMs:Date.now(),entries:[{
  key:`refresh_token:${token}`,value:device?{version:1,user_id:42,auth_method:"device_sn",device_sn_id:9}:"42",
  expiry:{kind:"pexpiretime",expiresAtMs:expiry,observedAtMs:Date.now()}}]}).manifest;

describe.skipIf(process.env.IDENTITY_TEST_MYSQL!=="1")("Yii3 compatibility uses private authority and source-bound sessions",()=>{
  let admin:Connection,db:Connection,devices:Connection,reader:LegacyIdentityReader,sessions:IdentitySessionRepository,native:NativeIdentityService,
    repository:NativeQrcodeRepository,codes:NativeQrcodeService,bridge:Yii3CompatibilityService,tokens:TokenIssuanceService,trustDir:string;
  const secret=randomBytes(32).toString("hex");
  const hs=(claims:Record<string,unknown>)=>{
    const input=[{alg:"HS256"},claims].map(v=>Buffer.from(JSON.stringify(v)).toString("base64url")).join(".");
    return `${input}.${createHmac("sha256",secret).update(input).digest("base64url")}`;
  };
  const sessionCount=async()=>Number((await db.query<RowDataPacket[]>("SELECT COUNT(*) AS n FROM identity_refresh_sessions"))[0][0].n);
  async function code(key=randomBytes(32).toString("base64url"),context:unknown={frontend_domain:"school.example.test"}){
    const now=Math.floor(Date.now()/1000);
    await db.execute("INSERT INTO identity_login_codes(code_hash,user_id,issued_at,expires_at,context_json) VALUES (?,42,?,?,?)",
      [hash(key),now,now+60,JSON.stringify(context)]);return key;
  }
  const importOptions={apply:true,environment:"staging",assertDeviceSnAuthorized:async(id:number,userId:number)=>reader.assertDeviceSnAuthorized(id,userId,true)};
  beforeAll(async()=>{
    if(process.env.NODE_ENV==="production")throw new Error("Disposable local fixture cannot run in production.");
    admin=await mysql.createConnection(opts);
    await admin.query(`CREATE DATABASE \`${name}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
      CREATE DATABASE \`${business}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`);
    db=await mysql.createConnection({...opts,database:name});devices=await mysql.createConnection({...opts,database:business});
    for(const schema of ["identity-account-schema.sql","identity-runtime-schema.sql","identity-wechat-oauth-schema.sql","identity-qrcode-schema.sql"])
      await db.query(await readFile(new URL(`../../../deploy/mysql/${schema}`,import.meta.url),"utf8"));
    await db.query("INSERT INTO user(id,username,status) VALUES (42,'yii3-user',10); INSERT INTO user_info(user_id) VALUES (42); INSERT INTO auth_assignment(item_name,user_id) VALUES ('user','42')");
    await devices.query("CREATE TABLE device_sn(id INT PRIMARY KEY,user_id INT,device_uuid VARCHAR(255),enabled BOOL,activated_at DATETIME); INSERT INTO device_sn VALUES(9,42,'yii3-device',1,NOW())");
    for(const [prefix,database] of [["IDENTITY_DB",name],["DEVICE_SN_DB",business]])
      for(const [key,value] of Object.entries({HOST:opts.host,PORT:String(opts.port),NAME:database,USER:opts.user,PASSWORD:opts.password}))vi.stubEnv(`${prefix}_${key}`,value);
    const keys=generateKeyPairSync("ec",{namedCurve:"prime256v1"});
    for(const [key,value] of Object.entries({IDENTITY_DATA_SOURCE:"identity",IDENTITY_TOKEN_ISSUANCE_ENABLED:"true",IDENTITY_JWT_ISSUER:"https://yii3-private.test",
      IDENTITY_JWT_AUDIENCE:"private-api",IDENTITY_JWT_PRIVATE_KEY_PEM:keys.privateKey.export({type:"pkcs8",format:"pem"}).toString(),
      IDENTITY_JWT_PUBLIC_KEY_PEM:keys.publicKey.export({type:"spki",format:"pem"}).toString(),IDENTITY_REFRESH_REPLAY_KEY:randomBytes(32).toString("base64url"),
      LEGACY_DB_HOST:"127.0.0.1",LEGACY_DB_PORT:"1",LEGACY_DB_USER:"unreachable",IDENTITY_LOGIN_AUDIT_ENABLED:"false"}))vi.stubEnv(key,value);
    trustDir=await mkdtemp(join(tmpdir(),"identity-yii3-trust-"));
    const secretFile=join(trustDir,"key"),trustFile=join(trustDir,"trust.json");
    await writeFile(secretFile,` \n${secret}\n`,{mode:0o600});
    await writeFile(trustFile,JSON.stringify({version:1,algorithm:"HS256",secretFile,issuedBefore:new Date(Date.now()+10000).toISOString(),
      acceptUntil:new Date(Date.now()+3600000).toISOString(),maxAccessTtlSeconds:10800}),{mode:0o600});
    vi.stubEnv("IDENTITY_LEGACY_YII3_JWT_CONFIG_FILE",trustFile);vi.stubEnv("IDENTITY_LEGACY_JWT_CONFIG_FILE","");
    reader=new LegacyIdentityReader();sessions=new IdentitySessionRepository();const jwt=new JwtIssuerService();
    native=new NativeIdentityService(reader,jwt,sessions);tokens=new TokenIssuanceService(reader,sessions,jwt,{record:vi.fn()} as unknown as LoginAuditService);
    repository=new NativeQrcodeRepository();codes=new NativeQrcodeService(repository,native,tokens,{} as IdentityWechatOAuthService,{} as AccountRegistrationService);
    bridge=new Yii3CompatibilityService(native,repository,codes,sessions,tokens);
    await sessions.ensureSchema();
  },30000);
  beforeEach(async()=>{
    await db.query("DELETE FROM identity_login_codes;DELETE FROM identity_refresh_replays;DELETE FROM identity_refresh_sessions;DELETE FROM identity_user_revocations;DELETE FROM auth_assignment;INSERT INTO auth_assignment(item_name,user_id) VALUES ('user','42');DELETE FROM auth_item_child;UPDATE user SET status=10,deleted_at=NULL WHERE id=42");
    await devices.query("UPDATE device_sn SET enabled=1,user_id=42,activated_at=NOW()");
  });
  afterAll(async()=>{
    await Promise.all([reader?.onModuleDestroy(),sessions?.onModuleDestroy(),native?.onModuleDestroy(),repository?.onModuleDestroy()]);
    await db?.end();await devices?.end();if(admin){await admin.query(`DROP DATABASE IF EXISTS \`${name}\`;DROP DATABASE IF EXISTS \`${business}\``);await admin.end();}
    if(trustDir)await rm(trustDir,{recursive:true,force:true});vi.unstubAllEnvs();
  });

  it("reads context without issuing and creates independent families for four uses within the original 60 seconds",async()=>{
    const key=await code();expect(await bridge.loginCode({key,operation:"context"})).toEqual({frontendDomain:"school.example.test"});
    expect(await sessionCount()).toBe(0);
    const results=await Promise.all(Array.from({length:4},()=>bridge.loginCode({key:`web_${key}`,operation:"redeem"},{idempotencyKey:"same-code"})));
    const responses=results.map(result=>{if(!("authTokens" in result))throw new Error("Missing redeemed tokens");return result;});
    expect(new Set(responses.map(r=>r.authTokens.refreshToken)).size).toBe(4);
    for(const response of responses){expect(response.subject).toMatchObject({id:42,status:10,roles:["user"]});
      const claims=JSON.parse(Buffer.from(response.authTokens.accessToken.split(".")[1],"base64url").toString());expect(claims.aud).toBe("private-api");}
    const [rows]=await db.query<RowDataPacket[]>("SELECT expires_at-issued_at AS ttl FROM identity_login_codes");expect(Number(rows[0].ttl)).toBe(60);
  });
  it("rejects expired codes, invalid context and currently disabled subjects",async()=>{
    const key=await code();await db.query("UPDATE identity_login_codes SET expires_at=1");
    await expect(bridge.loginCode({key,operation:"redeem"})).rejects.toMatchObject({status:401});
    const bad=await code(undefined,{frontend_domain:"school.example.test\n"});
    await expect(bridge.loginCode({key:bad,operation:"redeem"})).rejects.toMatchObject({status:401});
    const live=await code();await db.query("UPDATE user SET status=0 WHERE id=42");
    await expect(bridge.loginCode({key:live,operation:"redeem"})).rejects.toThrow();expect(await sessionCount()).toBe(0);
  });
  it("rotates a real refresh and never falls back from a stored revoked or expired refresh to a matching code",async()=>{
    const initial=await tokens.issueLegacyUserToken({legacyUserId:42});
    const refreshed=await bridge.refresh({refreshToken:initial.token.refreshToken,allowLoginCode:false},{idempotencyKey:"yii3-rotate"});
    expect(refreshed.authTokens.refreshToken).not.toBe(initial.token.refreshToken);
    await code(initial.token.refreshToken);await sessions.revoke(initial.token.refreshToken);
    await expect(bridge.refresh({refreshToken:`web_${initial.token.refreshToken}`,allowLoginCode:true})).rejects.toThrow();
    expect(await sessionCount()).toBe(2);
    const expired=await tokens.issueLegacyUserToken({legacyUserId:42});await code(expired.token.refreshToken);
    await db.execute("UPDATE identity_refresh_sessions SET expires_at=DATE_SUB(UTC_TIMESTAMP(3),INTERVAL 1 SECOND) WHERE refresh_token_hash=?",[hash(expired.token.refreshToken)]);
    await expect(bridge.refresh({refreshToken:expired.token.refreshToken,allowLoginCode:true})).rejects.toThrow();expect(await sessionCount()).toBe(3);
  });
  it("allows bare or wrapped code only in v1 and never downgrades an unknown dsn credential",async()=>{
    const key=await code();await expect(bridge.refresh({refreshToken:key,allowLoginCode:false})).rejects.toMatchObject({status:401});
    expect((await bridge.refresh({refreshToken:`https://front.test/?web_${key}`,allowLoginCode:true})).subject.id).toBe(42);
    const sn=`dsn_${"a".repeat(64)}`;await code(sn);
    await expect(bridge.refresh({refreshToken:sn,allowLoginCode:true})).rejects.toMatchObject({status:401});expect(await sessionCount()).toBe(1);
  });
  it("imports old ordinary and SN refreshes with exact millisecond expiry and preserves source through rotation",async()=>{
    const ordinary="a".repeat(64),device=`dsn_${"b".repeat(64)}`,expiry=Date.now()+120123;
    const sessionsManifest=[...makeManifest(ordinary,false,expiry).sessions,...makeManifest(device,true,expiry).sessions];
    const report=await importLegacySessions(db,{version:1,sessions:sessionsManifest},importOptions);expect(report).toMatchObject({imported:2,deviceSessions:1,notFinal:true});
    const [rows]=await db.query<RowDataPacket[]>("SELECT expires_at,auth_method,device_sn_id FROM identity_refresh_sessions ORDER BY auth_method");
    expect(rows.every(row=>row.expires_at.getTime()===expiry)).toBe(true);
    expect(rows.filter(row=>row.auth_method===null)).toHaveLength(1);
    const result=await bridge.refresh({refreshToken:device,allowLoginCode:false});expect(result.subject).toMatchObject({id:42,auth_method:"device_sn",device_sn_id:9});
    const next=await sessions.findValidSession(result.authTokens.refreshToken);expect(next).toMatchObject({authMethod:"device_sn",deviceSnId:9});
    await devices.query("UPDATE device_sn SET enabled=0");await expect(bridge.refresh({refreshToken:result.authTokens.refreshToken,allowLoginCode:false})).rejects.toThrow();
  });
  it("requires current private eligibility and independent enabled device source in dry-run and apply",async()=>{
    const manifest=makeManifest(`dsn_${"c".repeat(64)}`,true);
    await expect(importLegacySessions(db,manifest)).rejects.toThrow("authorization check is required");
    await devices.query("UPDATE device_sn SET enabled=0");await expect(importLegacySessions(db,manifest,importOptions)).rejects.toThrow();
    await devices.query("UPDATE device_sn SET enabled=1");await db.query("INSERT INTO auth_item_child(parent,child) VALUES ('user','manager')");
    await expect(importLegacySessions(db,manifest,importOptions)).rejects.toThrow();expect(await sessionCount()).toBe(0);
  });
  it("rejects source downgrade, tampered lifetime and existing source conflicts before issuing",async()=>{
    const manifest=makeManifest(`dsn_${"d".repeat(64)}`,true),row=manifest.sessions[0];
    for(const extra of [{yii3:undefined},{device_sn_id:undefined},{auth_method:undefined},{expires_at:new Date(Date.now()+500000).toISOString()},
      {yii3:{...(row.yii3 as object),credentialKind:"ordinary"}}])expect(()=>normalizeLegacySessionManifest({version:1,sessions:[{...row,...extra}]})).toThrow();
    await importLegacySessions(db,manifest,importOptions);
    await db.query("UPDATE identity_refresh_sessions SET auth_method=NULL,device_sn_id=NULL");
    await expect(importLegacySessions(db,manifest,importOptions)).rejects.toThrow("identity conflict");expect(await sessionCount()).toBe(1);
  });
  it("rejects deriving ordinary device login codes from verified SN access",async()=>{
    const token=hs({uid:42,iat:Date.now()/1000-5.123456,exp:Date.now()/1000+100,auth_method:"device_sn",device_sn_id:9});
    await expect(codes.issueLoginCode({headers:{authorization:`Bearer ${token}`}})).rejects.toMatchObject({status:403});expect(await sessionCount()).toBe(0);
  });
  it("accepts separately trusted PHP microsecond access while reading current private roles and revocation cutoff",async()=>{
    const now=Date.now()/1000,token=hs({uid:42,iat:now-5.123456,exp:now+100});
    expect(await native.verify(token)).toMatchObject({id:42,roles:["user"]});
    await db.query("DELETE FROM auth_assignment;INSERT INTO auth_assignment(item_name,user_id) VALUES('manager','42')");
    expect(await native.verify(token)).toMatchObject({roles:["manager"]});
    await sessions.revokeUserSessions(42);await expect(native.verify(token)).rejects.toMatchObject({status:401});
  });
  it("keeps legacy SN access grace while immediately enforcing current private account and elevated role checks",async()=>{
    const now=Date.now()/1000,token=hs({uid:42,iat:now-1.123456,exp:now+100,auth_method:"device_sn",device_sn_id:9});
    await devices.query("UPDATE device_sn SET enabled=0");expect(await native.verify(token)).toMatchObject({authContext:{auth_method:"device_sn",device_sn_id:9}});
    await db.query("INSERT INTO auth_item_child(parent,child) VALUES ('user','admin')");await expect(native.verify(token)).rejects.toMatchObject({status:401});
    await db.query("DELETE FROM auth_item_child;UPDATE user SET status=0 WHERE id=42");await expect(native.verify(token)).rejects.toMatchObject({status:401});
  });
});
