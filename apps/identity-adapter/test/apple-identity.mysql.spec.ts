import "reflect-metadata";
import { generateKeyPairSync, randomBytes, randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import mysql, {type Connection,type RowDataPacket} from "mysql2/promise";
import {afterAll,beforeAll,describe,expect,it,vi} from "vitest";
import {AppleIdentityService} from "../src/apple-identity.service.js";
import {AppleIdentityController} from "../src/apple-identity.controller.js";
import {LegacyIdentityReader} from "../src/legacy-identity.reader.js";
import {TokenIssuanceService} from "../src/token-issuance.service.js";
import {IdentitySessionRepository} from "../src/identity-session.repository.js";
import {JwtIssuerService} from "../src/jwt-issuer.service.js";
import {AccountRegistrationRepository} from "../src/account-registration.repository.js";
import {AccountPasswordRepository} from "../src/account-password.repository.js";
import {type LoginAuditService} from "../src/login-audit.service.js";
import {importLegacyAppleIdentities} from "../src/apple-identity-import.js";

const options={host:process.env.IDENTITY_DB_HOST??"127.0.0.1",port:Number(process.env.IDENTITY_DB_PORT??3306),user:process.env.IDENTITY_DB_USER??"root",password:process.env.IDENTITY_DB_PASSWORD??"",multipleStatements:true,timezone:"Z"};
const name=`test_identity_apple_${randomUUID().replaceAll("-","")}`,sourceName=`${name}_source`;
let admin:Connection,db:Connection,source:Connection,apple:AppleIdentityService,reader:LegacyIdentityReader,sessions:IdentitySessionRepository,jwt:JwtIssuerService,tokens:TokenIssuanceService;
let registration:AccountRegistrationRepository,passwords:AccountPasswordRepository;
const profile={providerAppId:"apple.app.one",subject:"apple-subject",email:"apple@example.test",emailVerified:true,firstName:"First",lastName:"Last",privateEmail:true};
const authPassword="Native-create!73";
const completion=(token:string,username="apple-created")=>({apple_id:profile.subject,token,username,password:authPassword});

describe.skipIf(process.env.IDENTITY_TEST_MYSQL!=="1")("Apple identity authority MySQL",()=>{
 beforeAll(async()=>{
  admin=await mysql.createConnection(options);await admin.query(`CREATE DATABASE ${name} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;CREATE DATABASE ${sourceName} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`);
  db=await mysql.createConnection({...options,database:name});source=await mysql.createConnection({...options,database:sourceName});
  const init=await readFile(new URL("../../../deploy/mysql/init.sql",import.meta.url),"utf8");await db.query(init.slice(init.indexOf("CREATE TABLE IF NOT EXISTS `auth_login_events`")));
  for(const schema of ["identity-account-schema.sql","identity-runtime-schema.sql","identity-apple-schema.sql"])await db.query(await readFile(new URL(`../../../deploy/mysql/${schema}`,import.meta.url),"utf8"));
  const keys=generateKeyPairSync("ec",{namedCurve:"prime256v1"});
  for(const [key,value] of Object.entries({IDENTITY_DATA_SOURCE:"identity",IDENTITY_DB_HOST:options.host,IDENTITY_DB_PORT:String(options.port),IDENTITY_DB_USER:options.user,IDENTITY_DB_PASSWORD:options.password,IDENTITY_DB_NAME:name,
    IDENTITY_TOKEN_ISSUANCE_ENABLED:"true",IDENTITY_LOGIN_AUDIT_ENABLED:"false",IDENTITY_INTERNAL_API_TOKEN:randomBytes(32).toString("hex"),IDENTITY_REFRESH_REPLAY_KEY:randomBytes(32).toString("base64url"),IDENTITY_APPLE_CLIENT_IDS:"apple.app.one,apple.app.two",
    IDENTITY_JWT_PRIVATE_KEY_PEM:keys.privateKey.export({type:"pkcs8",format:"pem"}).toString(),IDENTITY_JWT_PUBLIC_KEY_PEM:keys.publicKey.export({type:"spki",format:"pem"}).toString(),
    LEGACY_DB_HOST:"127.0.0.1",LEGACY_DB_PORT:"1",LEGACY_DB_USER:"unreachable",LEGACY_WRITE_DB_HOST:"127.0.0.1",LEGACY_WRITE_DB_PORT:"1",LEGACY_WRITE_DB_USER:"unreachable"}))vi.stubEnv(key,value);
  reader=new LegacyIdentityReader();sessions=new IdentitySessionRepository();jwt=new JwtIssuerService();tokens=new TokenIssuanceService(reader,sessions,jwt,{} as LoginAuditService);
  registration=new AccountRegistrationRepository();passwords=new AccountPasswordRepository();apple=new AppleIdentityService(reader,tokens,jwt);
 },30000);
 afterAll(async()=>{await Promise.all([apple,reader,sessions,registration,passwords].filter(Boolean).map(item=>item.onModuleDestroy()));await db?.end();await source?.end();if(admin){await admin.query(`DROP DATABASE IF EXISTS ${name};DROP DATABASE IF EXISTS ${sourceName}`);await admin.end();}vi.unstubAllEnvs();});

 it("isolates exact app audiences and rejects untrusted internal callers and expired challenges",async()=>{
  const controller=new AppleIdentityController(apple);
  expect(()=>controller.resolve(undefined,profile)).toThrow();expect(()=>controller.resolve("incorrect",profile)).toThrow();
  vi.stubEnv("IDENTITY_APPLE_CLIENT_IDS","");const disabled=new AppleIdentityService(reader,tokens,jwt);
  await expect(disabled.resolve(profile)).rejects.toMatchObject({status:503});await disabled.onModuleDestroy();vi.stubEnv("IDENTITY_APPLE_CLIENT_IDS","apple.app.one,apple.app.two");
  await expect(apple.resolve({...profile,providerAppId:"unconfigured.apple.app"})).rejects.toMatchObject({status:401});
  const resolved=await apple.resolve({...profile,subject:"expiry-subject"});expect(resolved.user_id).toBeNull();expect(resolved.token).toEqual(expect.any(String));
  await expect(apple.complete("create",{...completion(resolved.token!),apple_id:"expiry-subject",providerAppId:"apple.app.two"})).rejects.toMatchObject({status:401});
  await expect(apple.complete("create",completion(resolved.token!))).rejects.toMatchObject({status:401});
  await db.query("UPDATE identity_apple_challenges SET expires_at=DATE_SUB(UTC_TIMESTAMP(3),INTERVAL 1 SECOND)");
  await expect(apple.complete("create",{...completion(resolved.token!),apple_id:"expiry-subject"})).rejects.toMatchObject({status:401});
 });
 it("creates one canonical account atomically, returns legacy auth strings and forbids changed replay bodies",async()=>{
  const resolved=await apple.resolve(profile),request=completion(resolved.token!);
  const [first,replay]=await Promise.all([apple.complete("create",request),apple.complete("create",request)]);
  expect(first.user_id).toBe(replay.user_id);expect(Number.isSafeInteger(first.user_id)).toBe(true);expect(first.token).toBeNull();
  expect(first.user?.auth).toEqual(expect.any(String));expect(jwt.verifyAccessToken(first.user!.auth as string).uid).toBe(first.user_id);
  expect(await reader.getUserById(first.user_id!)).toMatchObject({nickname:"First Last",email:profile.email,emailVerifiedAt:expect.any(Number),roles:["user"]});
  await expect(apple.complete("create",{...request,username:"different-body"})).rejects.toMatchObject({status:409});
  await expect(apple.complete("link",request)).rejects.toMatchObject({status:409});
  const credential=(await passwords.getCredentialById(first.user_id!))!;await passwords.changePassword(credential,"Changed-private!83",{operationKey:"apple-changed-password"});
  await expect(apple.complete("create",request)).rejects.toMatchObject({status:409});
  const [rows]=await db.query<RowDataPacket[]>("SELECT token_hash,operation_hash FROM identity_apple_challenges WHERE user_id=?",[first.user_id]);
  expect(rows[0].token_hash).not.toBe(resolved.token);expect(rows[0].operation_hash).toMatch(/^[a-f0-9]{64}$/);
 });
 it("requires the existing account password and keeps provider bindings isolated between applications",async()=>{
  const existing=await registration.register({username:"apple-existing",password:"Existing-private!73",email:"existing-apple@example.test"},"apple-existing");
  const sameEmail=await apple.resolve({...profile,subject:"link-subject",email:existing.email});expect(sameEmail.user_id).toBeNull();
  const competing=await apple.resolve({...profile,subject:"link-subject",email:existing.email});
  const request={apple_id:"link-subject",token:sameEmail.token!,username:"apple-existing",password:"Existing-private!73"};
  await expect(apple.complete("link",{...request,password:"incorrect"})).rejects.toMatchObject({status:401});
  const linked=await apple.complete("link",request);expect(linked.user_id).toBe(existing.id);
  await expect(apple.complete("link",{...request,token:competing.token})).rejects.toMatchObject({status:409});
  expect((await apple.resolve({...profile,subject:"link-subject",email:existing.email})).user_id).toBe(existing.id);
  const otherApp=await apple.resolve({...profile,subject:"link-subject",providerAppId:"apple.app.two",email:existing.email});expect(otherApp.user_id).toBeNull();
  await expect(apple.complete("create",{apple_id:"link-subject",token:otherApp.token,username:"apple-email-collision",password:authPassword})).rejects.toMatchObject({status:409});
  await db.execute("UPDATE user SET status=0 WHERE id=?",[existing.id]);
  await expect(apple.resolve({...profile,subject:"link-subject",email:existing.email})).rejects.toMatchObject({status:401});
 });
 it("does not consume a challenge before signing readiness and recovers a post-commit signing failure",async()=>{
  const resolved=await apple.resolve({...profile,subject:"signing-subject",email:"apple-signing@example.test",firstName:"名".repeat(250),lastName:"字".repeat(250)});
  const request={...completion(resolved.token!,"apple-signing"),apple_id:"signing-subject"};
  const ready=vi.spyOn(jwt,"assertSigningReady").mockImplementationOnce(()=>{throw new Error("signing unavailable");});
  await expect(apple.complete("create",request)).rejects.toThrow("signing unavailable");ready.mockRestore();
  const issue=vi.spyOn(tokens,"issueRegisteredUser").mockRejectedValueOnce(new Error("signing failed after commit"));
  await expect(apple.complete("create",request)).rejects.toThrow("signing failed after commit");
  const recovered=await apple.complete("create",request);expect(recovered.user_id).toEqual(expect.any(Number));expect(recovered.user?.auth).toEqual(expect.any(String));issue.mockRestore();
  expect(Array.from(String(recovered.user!.nickname)).length).toBe(255);
  const [rows]=await db.query<RowDataPacket[]>("SELECT COUNT(*) AS count FROM user WHERE username='apple-signing'");expect(Number(rows[0].count)).toBe(1);
 });
 it("inventories old subjects without emails and requires a reviewed app manifest before import",async()=>{
  await source.query("CREATE TABLE apple_id(id INT PRIMARY KEY,apple_id VARCHAR(255),email VARCHAR(255),first_name VARCHAR(255),last_name VARCHAR(255),user_id BIGINT,token VARCHAR(255))");
  await source.execute("INSERT INTO apple_id VALUES(100,'legacy-apple-subject','old-apple@example.test','Old','Name',NULL,'old-provider-access-token')");
  const inventory=await importLegacyAppleIdentities(source,db,{importKey:"apple-old-import"});
  expect(inventory).toMatchObject({requiresReviewedAppManifest:true,subjects:[{legacyId:100,providerSubject:"legacy-apple-subject",userId:null}]});
  expect(JSON.stringify(inventory)).not.toContain("old-apple@example.test");expect(JSON.stringify(inventory)).not.toContain("old-provider-access-token");
  await expect(importLegacyAppleIdentities(source,db,{importKey:"apple-old-import",apply:true})).rejects.toThrow();
  const manifest=[{legacyId:100,providerSubject:"legacy-apple-subject",providerAppId:"apple.app.one"}];
  expect(await importLegacyAppleIdentities(source,db,{importKey:"apple-old-import",manifest,apply:true})).toMatchObject({applied:true,rowCount:1});
  expect(await importLegacyAppleIdentities(source,db,{importKey:"apple-old-import",manifest,apply:true})).toMatchObject({replay:true});
  const [rows]=await db.query<RowDataPacket[]>("SELECT provider_app_id,subject,user_id,email_verified FROM identity_apple_identities WHERE subject='legacy-apple-subject'");
  expect(rows[0]).toMatchObject({provider_app_id:"apple.app.one",user_id:null,email_verified:0});
  await db.query("UPDATE identity_migration_control SET authority='identity' WHERE id=1");
  await expect(importLegacyAppleIdentities(source,db,{importKey:"apple-after-authority",manifest,apply:true})).rejects.toThrow("already authoritative");
 });
});
