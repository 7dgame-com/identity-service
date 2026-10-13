import { finalizeAllocator, readSourceAllocatorInventory } from "../src/identity-allocator-finalizer.js";
import "reflect-metadata";
import { readFile } from "node:fs/promises";
import { createHash, generateKeyPairSync, randomBytes, randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import mysql, { type Connection, type RowDataPacket } from "mysql2/promise";
import { AccountRegistrationRepository } from "../src/account-registration.repository.js";
import { AccountPasswordRepository } from "../src/account-password.repository.js";
import { AccountEmailRepository } from "../src/account-email.repository.js";
import { LegacyIdentityReader } from "../src/legacy-identity.reader.js";
import { InvitationIdentityRepository } from "../src/invitation-identity.repository.js";
import { InvitationRecordRepository } from "../src/invitation-record.repository.js";
import { PasswordResetChallengeRepository } from "../src/password-reset-challenge.repository.js";
import { accountImportTables, importIdentityAccounts } from "../src/identity-account-import.js";
import { IdentityWechatOAuthService } from "../src/identity-wechat-oauth.service.js";
import { IdentitySessionRepository } from "../src/identity-session.repository.js";
import { JwtIssuerService } from "../src/jwt-issuer.service.js";
import { NativeIdentityService } from "../src/native-identity.service.js";
import { importReviewedYiiWechatBindings, importWechatIdentities } from "../src/identity-wechat-import.js";
import { AccountRegistrationService } from "../src/account-registration.service.js";
import { AccountLifecycleOperationRepository } from "../src/account-lifecycle-operation.repository.js";
import { TokenIssuanceService } from "../src/token-issuance.service.js";
import { EmailVerificationChallengeRepository } from "../src/email-verification-challenge.repository.js";
import { EmailChangeTokenRepository } from "../src/email-change-token.repository.js";

const enabled = process.env.IDENTITY_TEST_MYSQL === "1";
const ownedDatabases: string[] = [];
const resources: Array<{ onModuleDestroy(): Promise<void> }> = [];
let admin: Connection;
let db: Connection;
let source: Connection;
let target: Connection;
const connectionOptions = {
  host: process.env.IDENTITY_DB_HOST ?? "127.0.0.1",
  port: Number(process.env.IDENTITY_DB_PORT ?? 3306),
  user: process.env.IDENTITY_DB_USER ?? "root",
  password: process.env.IDENTITY_DB_PASSWORD ?? "",
  timezone: "Z",
  multipleStatements: true
};

async function createDatabase(businessOnly=false): Promise<{ connection: Connection; name: string }> {
  const name = `test_identity_accounts_${randomUUID().replaceAll("-", "")}`;
  ownedDatabases.push(name);
  await admin.query(`CREATE DATABASE \`${name}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`);
  const connection = await mysql.createConnection({ ...connectionOptions, database: name });
  const init = await readFile(new URL("../../../deploy/mysql/init.sql", import.meta.url), "utf8");
  await connection.query(init.slice(init.indexOf("CREATE TABLE IF NOT EXISTS `auth_login_events`")));
  await connection.query(await readFile(new URL("../../../deploy/mysql/identity-account-schema.sql", import.meta.url), "utf8"));
  await connection.query(await readFile(new URL("../../../deploy/mysql/identity-password-reset-token-schema.sql", import.meta.url), "utf8"));
  await connection.query(await readFile(new URL("../../../deploy/mysql/identity-legacy-challenge-schema.sql", import.meta.url), "utf8"));
  await connection.query(await readFile(new URL("../../../deploy/mysql/identity-runtime-schema.sql", import.meta.url), "utf8"));
  await connection.query(await readFile(new URL("../../../deploy/mysql/identity-wechat-oauth-schema.sql", import.meta.url), "utf8"));
  await connection.query(await readFile(new URL("../../../deploy/mysql/identity-qrcode-schema.sql", import.meta.url), "utf8"));
  await connection.query(`CREATE TABLE IF NOT EXISTS identity_subject_events (
    id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY, user_id BIGINT NOT NULL, version BIGINT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)`);
  for(const asset of ["identity-apple-schema.sql","identity-allocator-schema.sql"])await connection.query(await readFile(new URL("../../../deploy/mysql/"+asset,import.meta.url),"utf8"));
  if(businessOnly){const [tables]=await connection.query<RowDataPacket[]>("SHOW TABLES");for(const row of tables){const table=String(Object.values(row)[0]);if(!Object.keys(accountImportTables).includes(table))await connection.query("DROP TABLE `"+table+"`");}}
  return { connection, name };
}

function owned<T extends { onModuleDestroy(): Promise<void> }>(resource: T): T { resources.push(resource); return resource; }

describe.skipIf(!enabled)("independent identity account MySQL integration", () => {
  beforeAll(async () => {
    admin = await mysql.createConnection(connectionOptions);
    const runtime = await createDatabase();
    db = runtime.connection;
    source = (await createDatabase(true)).connection;
    target = (await createDatabase()).connection;
    vi.stubEnv("IDENTITY_DATA_SOURCE", "identity");
    vi.stubEnv("IDENTITY_INTERNAL_API_TOKEN","test-identity-internal-key-with-at-least-32-bytes");
    vi.stubEnv("IDENTITY_DB_HOST", connectionOptions.host);
    vi.stubEnv("IDENTITY_DB_PORT", String(connectionOptions.port));
    vi.stubEnv("IDENTITY_DB_USER", connectionOptions.user);
    vi.stubEnv("IDENTITY_DB_PASSWORD", connectionOptions.password);
    vi.stubEnv("IDENTITY_DB_NAME", runtime.name);
    // These addresses must never be opened in independent mode.
    vi.stubEnv("LEGACY_DB_HOST", "127.0.0.1");
    vi.stubEnv("LEGACY_DB_PORT", "1");
    vi.stubEnv("LEGACY_DB_USER", "unreachable");
    vi.stubEnv("LEGACY_WRITE_DB_HOST", "127.0.0.1");
    vi.stubEnv("LEGACY_WRITE_DB_PORT", "1");
    vi.stubEnv("LEGACY_WRITE_DB_USER", "unreachable");
  }, 30_000);

  afterAll(async () => {
    await Promise.all(resources.map((resource) => resource.onModuleDestroy()));
    await Promise.all([db, source, target].filter(Boolean).map((connection) => connection.end()));
    for (const name of ownedDatabases) await admin.query(`DROP DATABASE \`${name}\``);
    await admin?.end();
    vi.unstubAllEnvs();
  });

  it("registers once, reads private credentials, updates passwords and email without the legacy database", async () => {
    const registration = owned(new AccountRegistrationRepository());
    const reader = owned(new LegacyIdentityReader());
    const passwords = owned(new AccountPasswordRepository());
    const emails = owned(new AccountEmailRepository());
    const input = { username: "account-native", password: "Strong-native!73", email: "native@example.test" };
    const results = await Promise.all([registration.register(input, "test-register-once"), registration.register(input, "test-register-once")]);
    expect(results[0].id).toBe(results[1].id);
    const userId = results[0].id;
    expect(await reader.getUserById(userId)).toMatchObject({ source: "identity-db", username: input.username, roles: ["user"] });
    const credential = (await passwords.getCredentialById(userId))!;
    expect(await passwords.verifyPassword(input.password, credential.passwordHash)).toBe(true);
    await passwords.changePassword(credential, "Another-native!93", { operationKey: "password-native-once" });
    await expect(passwords.changePassword(credential, "Stale-native!94", { operationKey: "password-native-stale" })).rejects.toMatchObject({ status: 409 });
    expect(await passwords.findCompletedPasswordOperation("password-native-once", userId)).toMatchObject({ id: userId });
    expect(await passwords.verifyPassword("Another-native!93", (await passwords.getCredentialById(userId))!.passwordHash)).toBe(true);
    await expect(registration.register(input,"test-register-once")).rejects.toMatchObject({status:409});
    await expect(registration.register({...input,username:"different-body"},"test-register-once")).rejects.toMatchObject({status:409});
    await emails.bindVerifiedEmail(userId, "changed@example.test", 1700000000);
    expect(await reader.getUserById(userId)).toMatchObject({ email: "changed@example.test", emailVerifiedAt: 1700000000 });
    await emails.unbindEmail(userId, 1700000001);
    expect(await emails.getUserById(userId)).toMatchObject({ email: null, emailVerifiedAt: null });
    const [events] = await db.execute<RowDataPacket[]>("SELECT COUNT(*) AS count FROM identity_subject_events WHERE user_id = ?", [userId]);
    expect(Number(events[0].count)).toBe(4);
    const [columns] = await db.query<RowDataPacket[]>("SHOW COLUMNS FROM user_info");
    expect(columns.map((column) => column.Field)).toEqual(["id", "user_id", "info"]);
  });

  it("consumes one invitation quota and email code transactionally, with stable registration retries", async () => {
    const registration = owned(new AccountRegistrationRepository());
    const invitations = owned(new InvitationIdentityRepository());
    const records = owned(new InvitationRecordRepository());
    const now = Math.floor(Date.now() / 1000);
    await invitations.create({ inviteCode: "native-invite", quota: 1, remaining: 1, expiresAt: now + 300,
      creatorLegacyUserId: 1, creatorName: "manager", note: "test", legacyCreatedAt: now, source: "identity-service" });
    const code = await registration.createInvitationEmailChallenge("native-invite", "invitee@example.test");
    const input = { username: "invited-native", password: "Invited-native!73", email: "invitee@example.test", inviteCode: "native-invite", verificationCode: code };
    const [first, replay] = await Promise.all([registration.registerInvitation(input, "test-invite-once"), registration.registerInvitation(input, "test-invite-once")]);
    expect(first.id).toBe(replay.id);
    expect(first.emailVerifiedAt).not.toBeNull();
    expect((await invitations.findByCodes(["native-invite"]))[0].remaining).toBe(0);
    expect((await records.listByInviteCode("native-invite")).rows).toHaveLength(1);
    const [challenge] = await db.query<RowDataPacket[]>("SELECT consumed_at FROM invitation_email_challenges WHERE invite_code = 'native-invite'");
    expect(challenge[0].consumed_at).not.toBeNull();
    await expect(registration.createInvitationEmailChallenge("native-invite", "another@example.test")).rejects.toMatchObject({ status: 400 });
  });

  it("imports an identity-only snapshot once and preserves passwords, IDs and existing identity mappings", async () => {
    await source.execute("INSERT INTO user (id,username,password_hash,email,status,created_at) VALUES (7001,'import-user','$2y$existing-hash','import@example.test',10,1700000000)");
    await source.execute("INSERT INTO user_info (user_id,info) VALUES (7001,?)", [JSON.stringify({ displayName: "imported" })]);
    await source.query("ALTER TABLE user_info ADD COLUMN avatar_id BIGINT NULL");
    await source.execute("UPDATE user_info SET avatar_id=12345 WHERE user_id=7001");
    await source.execute("INSERT INTO auth_assignment (item_name,user_id) VALUES ('user','7001')");
    await target.execute("INSERT INTO identity_users (id,legacy_user_id,username) VALUES ('existing-subject',7001,'old-name')");
    const dry = await importIdentityAccounts(source, target, { importKey: "test-cutover" });
    expect(dry).toMatchObject({ applied: false, rowCounts: { user: 1, user_info: 1 } });
    const [empty] = await target.query<RowDataPacket[]>("SELECT COUNT(*) AS count FROM user");
    expect(Number(empty[0].count)).toBe(0);
    expect(await importIdentityAccounts(source, target, { importKey: "test-cutover", apply: true })).toMatchObject({ applied: true });
    const [copied] = await target.query<RowDataPacket[]>("SELECT id,password_hash,created_at FROM user");
    expect(copied[0]).toMatchObject({ id: 7001, password_hash: "$2y$existing-hash", created_at: 1700000000 });
    const [maps] = await target.query<RowDataPacket[]>("SELECT id FROM identity_users WHERE legacy_user_id = 7001");
    expect(maps[0].id).toBe("existing-subject");
    const [avatar] = await target.query<RowDataPacket[]>("SELECT avatar_id FROM identity_profile_avatars WHERE user_id=7001");
    expect(Number(avatar[0].avatar_id)).toBe(12345);
    await target.execute("UPDATE user SET nickname='changed-after-cutover' WHERE id=7001");
    expect(await importIdentityAccounts(source, target, { importKey: "test-cutover", apply: true })).toMatchObject({ applied: false, replay: true });
    const [unchanged] = await target.query<RowDataPacket[]>("SELECT nickname FROM user WHERE id=7001");
    expect(unchanged[0].nickname).toBe("changed-after-cutover");
    await expect(importIdentityAccounts(source, target, { importKey: "different-cutover", apply: true })).rejects.toThrow("empty target");
  });

  it("prevents distinct registrants from exceeding the same invitation quota", async () => {
    const registration = owned(new AccountRegistrationRepository());
    const invitations = owned(new InvitationIdentityRepository());
    const now = Math.floor(Date.now() / 1000);
    await invitations.create({ inviteCode: "quota-race", quota: 1, remaining: 1, expiresAt: now + 300,
      creatorLegacyUserId: 1, creatorName: "manager", note: "race", legacyCreatedAt: now, source: "identity-service" });
    const emails = ["race1@example.test", "race2@example.test"];
    const codes = await Promise.all(emails.map((email) => registration.createInvitationEmailChallenge("quota-race", email)));
    const results = await Promise.allSettled(emails.map((email, index) => registration.registerInvitation({
      username: `quota-racer-${index}`, password: "Invited-racer!73", email, inviteCode: "quota-race", verificationCode: codes[index]
    }, `quota-race-operation-${index}`)));
    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(results.filter((result) => result.status === "rejected")).toHaveLength(1);
    expect((await invitations.findByCodes(["quota-race"]))[0].remaining).toBe(0);
    const [records] = await db.query<RowDataPacket[]>("SELECT COUNT(*) AS count FROM invitation_record WHERE invite_code = 'quota-race'");
    expect(Number(records[0].count)).toBe(1);
  });

  it("consumes reset codes in the password transaction and rolls back reuse", async () => {
    const registration = owned(new AccountRegistrationRepository());
    const passwords = owned(new AccountPasswordRepository());
    const challenges = owned(new PasswordResetChallengeRepository());
    const user = await registration.register({ username: "reset-native", password: "Reset-initial!73", email: "reset@example.test" }, "reset-native-register");
    const { code, challenge } = await challenges.createChallenge({ email: "reset@example.test", legacyUserId: user.id });
    expect((await challenges.verifyCode("reset@example.test", code)).challengeKey).toBe(challenge.challengeKey);
    const credential = (await passwords.getCredentialById(user.id))!;
    await passwords.changePassword(credential, "Reset-updated!83", { operationKey: "reset-native-operation", resetChallengeKey: challenge.challengeKey });
    expect(await passwords.findCompletedPasswordOperation("reset-native-operation")).toMatchObject({ id: user.id });
    await expect(challenges.verifyCode("reset@example.test", code)).rejects.toThrow();
    const current = (await passwords.getCredentialById(user.id))!;
    await expect(passwords.changePassword(current, "Reset-reused!93", { operationKey: "reset-native-reused", resetChallengeKey: challenge.challengeKey })).rejects.toMatchObject({ status: 400 });
    expect(await passwords.verifyPassword("Reset-updated!83", (await passwords.getCredentialById(user.id))!.passwordHash)).toBe(true);
    const [revocations] = await db.execute<RowDataPacket[]>("SELECT user_id FROM identity_user_revocations WHERE user_id = ?", [user.id]);
    expect(revocations).toHaveLength(1);
  });

  it("owns WeChat OAuth accounts, binds clients and scopes, consumes codes once and rotates refresh atomically", async () => {
    const keys=generateKeyPairSync("ec",{namedCurve:"prime256v1"});
    vi.stubEnv("IDENTITY_JWT_PRIVATE_KEY_PEM",String(keys.privateKey.export({type:"pkcs8",format:"pem"})));
    vi.stubEnv("IDENTITY_JWT_PUBLIC_KEY_PEM",String(keys.publicKey.export({type:"spki",format:"pem"})));
    vi.stubEnv("IDENTITY_JWT_ISSUER","https://identity.test");vi.stubEnv("IDENTITY_JWT_AUDIENCE","primary-api");
    vi.stubEnv("IDENTITY_REFRESH_REPLAY_KEY",randomBytes(32).toString("base64url"));
    const reader=owned(new LegacyIdentityReader()),sessions=owned(new IdentitySessionRepository()),jwt=new JwtIssuerService();
    const native=owned(new NativeIdentityService(reader,jwt,sessions));
    const oauth=owned(new IdentityWechatOAuthService(reader,sessions,jwt,native));
    const profile={provider:"wechat_official_account" as const,providerAppId:"wx-integration",openId:"oauth-openid",unionId:"oauth-unionid",nickname:"OAuth native"};
    expect(await oauth.resolveWechat(profile)).toMatchObject({userId:null,signupToken:expect.any(String)});
    const [first,repeat]=await Promise.all([oauth.resolveWechat(profile,true),oauth.resolveWechat(profile,true)]);
    expect(first.userId).toBe(repeat.userId);expect(first.signupToken).toBeNull();
    expect(await oauth.paymentIdentity(first.userId,"wx-integration")).toEqual({providerAppId:"wx-integration",openId:"oauth-openid",unionId:"oauth-unionid"});
    expect(await oauth.paymentIdentity(first.userId,"another-app")).toBeNull();
    await expect(oauth.paymentIdentity(first.userId,undefined)).rejects.toThrow();
    const signup=await oauth.resolveWechat({...profile,openId:"signup-openid",unionId:"signup-unionid"});
    const registered=await owned(new AccountRegistrationRepository()).registerWechat({username:"wechat-signup-native",password:"Wechat-signup!73",wechatToken:signup.signupToken!},"wechat-signup-native-once");
    expect(await oauth.paymentIdentity(registered.id,"wx-integration")).toEqual({providerAppId:"wx-integration",openId:"signup-openid",unionId:"signup-unionid"});
    const rawCode=randomBytes(32).toString("base64url"),verifier=randomBytes(32).toString("base64url");
    await oauth.createCode({codeHash:createHash("sha256").update(rawCode).digest("base64url"),clientId:"bujiaban-web",userId:first.userId,
      redirectUri:"https://bujiaban.com/auth/callback",codeChallenge:createHash("sha256").update(verifier).digest("base64url"),codeChallengeMethod:"S256",
      scopes:["openid","profile"],createdAt:new Date().toISOString(),expiresAt:new Date(Date.now()+60000).toISOString()});
    const request={grant_type:"authorization_code",client_id:"bujiaban-web",code:rawCode,redirect_uri:"https://bujiaban.com/auth/callback",code_verifier:verifier};
    await expect(oauth.token({...request,code_verifier:"wrong"})).rejects.toThrow();
    const signingCheck=vi.spyOn(jwt,"assertSigningReady").mockImplementationOnce(()=>{throw new Error("signing key unavailable");});
    await expect(oauth.token(request)).rejects.toThrow("signing key unavailable");
    signingCheck.mockRestore();
    const exchanges=await Promise.allSettled([oauth.token(request),oauth.token(request)]);
    expect(exchanges.filter((result)=>result.status==="fulfilled")).toHaveLength(1);
    const token=(exchanges.find((result)=>result.status==="fulfilled") as PromiseFulfilledResult<Awaited<ReturnType<typeof oauth.token>>>).value;
    expect(JSON.parse(Buffer.from(token.access_token.split(".")[1],"base64url").toString())).toMatchObject({aud:"bujiaban-web",scope:"openid profile",sub:String(first.userId)});
    expect(await oauth.userinfo(`Bearer ${token.access_token}`)).toMatchObject({sub:String(first.userId),name:"OAuth native"});
    await expect(oauth.token({grant_type:"refresh_token",client_id:"3dugc-web",refresh_token:token.refresh_token})).rejects.toThrow();
    const [rotated,replayed]=await Promise.all([oauth.token({grant_type:"refresh_token",client_id:"bujiaban-web",refresh_token:token.refresh_token,idempotency_key:"same-request"}),
      oauth.token({grant_type:"refresh_token",client_id:"bujiaban-web",refresh_token:token.refresh_token,idempotency_key:"same-request"})]);
    expect(rotated.refresh_token).toBe(replayed.refresh_token);
    await oauth.revoke({token:token.refresh_token});
    await expect(oauth.userinfo(`Bearer ${rotated.access_token}`)).rejects.toThrow();
  });

  it("imports every old OAuth UUID and provider binding once, matching existing canonical users", async () => {
    const authSource=(await createDatabase(true)).connection;
    try {
    await authSource.query(`CREATE TABLE auth_users(id VARCHAR(128) PRIMARY KEY,primary_unionid VARCHAR(191),display_name VARCHAR(191),avatar_url TEXT,status VARCHAR(32),created_at DATETIME(3),updated_at DATETIME(3));
      CREATE TABLE auth_identities(id VARCHAR(128) PRIMARY KEY,user_id VARCHAR(128),provider VARCHAR(64),provider_app_id VARCHAR(191),openid VARCHAR(191),unionid VARCHAR(191),profile_json JSON)`);
    await authSource.execute("INSERT INTO auth_users VALUES('old-oauth-uuid',NULL,'OAuth imported',NULL,'active',UTC_TIMESTAMP(3),UTC_TIMESTAMP(3)),('old-orphan-uuid',NULL,'Orphan',NULL,'disabled',UTC_TIMESTAMP(3),UTC_TIMESTAMP(3))");
    await authSource.execute("INSERT INTO auth_identities VALUES('provider-old','old-oauth-uuid','wechat_official_account','wx-old','old-open',NULL,?)",[JSON.stringify({nickname:"OAuth imported"})]);
    await source.execute("INSERT INTO wechat(openid,unionid,user_id,token)VALUES('old-open','old-union',7001,'old-registration-token')");
    await target.execute("INSERT INTO wechat(openid,unionid,user_id,token)VALUES('old-open','old-union',7001,'old-registration-token')");
    expect(await importWechatIdentities(authSource,target,{importKey:"oauth-import"})).toMatchObject({applied:false,rowCounts:{auth_users:2,auth_identities:1}});
    await expect(importWechatIdentities(authSource,target,{importKey:"oauth-before-review",apply:true})).rejects.toThrow();
    const [sourceDatabase]=await source.query<RowDataPacket[]>("SELECT DATABASE() AS name");
    expect(await importReviewedYiiWechatBindings(source,target,{schema_version:1,source_database:sourceDatabase[0].name,
      review:{reference:"account-cutover-fixture",reviewed_by:"integration-review",reviewed_at:new Date().toISOString()},
      bindings:[{provider:"wechat_official_account",provider_app_id:"wx-old",open_id:"old-open",user_id:7001,evidence:"wechat",union_id:"old-union"}]},
      {importKey:"yii-reviewed-before-oauth",apply:true})).toMatchObject({applied:true,imported:1});
    const src=await readSourceAllocatorInventory(source),[dst]=await target.query<RowDataPacket[]>("SELECT DATABASE() AS name");
    const fence=await mysql.createConnection({...connectionOptions,database:dst[0].name});
    try{await finalizeAllocator({source,target,fence,review:{version:1,sourceDatabase:src.database,targetDatabase:dst[0].name,sourceServerUuid:src.serverUuid,importKey:"test-cutover",writersDrainedAt:new Date(Date.now()-1000).toISOString(),finalSyncSha256:"a".repeat(64),referenceReviewSha256:src.referenceReviewSha256},reviewSha256:"b".repeat(64),apply:true});}finally{await fence.end();}
    expect(await importWechatIdentities(authSource,target,{importKey:"oauth-import",apply:true})).toMatchObject({applied:true});
    const [maps]=await target.query<RowDataPacket[]>("SELECT auth_user_id,user_id,status FROM identity_auth_subject_maps ORDER BY auth_user_id");
    expect(maps).toHaveLength(2);expect(maps.find((row)=>row.auth_user_id==="old-oauth-uuid")).toMatchObject({user_id:7001,status:"active"});
    expect(maps.find((row)=>row.auth_user_id==="old-orphan-uuid")).toMatchObject({status:"disabled"});
    const [bindings]=await target.query<RowDataPacket[]>("SELECT provider,provider_app_id,open_id,user_id FROM identity_wechat_identities WHERE open_id='old-open'");
    expect(bindings[0]).toMatchObject({provider:"wechat_official_account",provider_app_id:"wx-old",user_id:7001});
    expect(await importWechatIdentities(authSource,target,{importKey:"oauth-import",apply:true})).toMatchObject({applied:false,replay:true});
    await target.execute("UPDATE identity_migration_control SET authority='identity' WHERE id=1");
    await expect(importWechatIdentities(authSource,target,{importKey:"oauth-after-activation",apply:true})).rejects.toThrow("already authoritative");
    }finally{await authSource.end();}
  });

  it("recovers an account committed before token signing failed without creating a duplicate", async () => {
    vi.stubEnv("IDENTITY_TOKEN_ISSUANCE_ENABLED","true");
    const registrations=owned(new AccountRegistrationRepository()),operations=owned(new AccountLifecycleOperationRepository());
    const issueRegisteredUser=vi.fn().mockRejectedValueOnce(new Error("signing key unavailable")).mockResolvedValueOnce({token:{accessToken:"recovered-access",refreshToken:"recovered-refresh"}});
    const service=new AccountRegistrationService(registrations,operations,{issueRegisteredUser} as unknown as TokenIssuanceService);
    const body={username:"register-signing-recovery",password:"Recovery-account!73",email:"signing-recovery@example.test"};
    await expect(service.register("/v1/auth/register",body)).rejects.toThrow("signing key unavailable");
    expect(await service.register("/v1/auth/register",body)).toMatchObject({status:201,body:{success:true,token:{accessToken:"recovered-access"}}});
    const [users]=await db.query<RowDataPacket[]>("SELECT id FROM user WHERE username='register-signing-recovery'");expect(users).toHaveLength(1);
    expect(issueRegisteredUser.mock.calls[0][0].id).toBe(issueRegisteredUser.mock.calls[1][0].id);
    const passwords=owned(new AccountPasswordRepository()),credential=(await passwords.getCredentialById(Number(users[0].id)))!;
    await passwords.changePassword(credential,"Recovery-changed!93",{operationKey:"registration-recovery-password-change"});
    await expect(service.register("/v1/auth/register",body)).rejects.toMatchObject({status:409});
    expect(issueRegisteredUser).toHaveBeenCalledTimes(2);
  });

  it("consumes email confirmation and change credentials only once inside account transactions", async () => {
    const registrations=owned(new AccountRegistrationRepository()),emails=owned(new AccountEmailRepository());
    const challenges=owned(new EmailVerificationChallengeRepository()),changeTokens=owned(new EmailChangeTokenRepository());
    const user=await registrations.register({username:"email-race",password:"Email-racing!73",email:"email-initial@example.test"},"email-race-register");
    await emails.bindVerifiedEmail(user.id,"email-initial@example.test",Math.floor(Date.now()/1000));
    const oldChallenge=await challenges.createChallenge({email:"email-initial@example.test",legacyUserId:user.id});
    const tokens=await Promise.allSettled([changeTokens.createToken(user.id,oldChallenge.challenge.challengeKey),changeTokens.createToken(user.id,oldChallenge.challenge.challengeKey)]);
    expect(tokens.filter((result)=>result.status==="fulfilled")).toHaveLength(1);
    const token=(tokens.find((result)=>result.status==="fulfilled") as PromiseFulfilledResult<Awaited<ReturnType<typeof changeTokens.createToken>>>).value;
    const nextEmails=["email-next-a@example.test","email-next-b@example.test"];
    const nextChallenges=await Promise.all(nextEmails.map((email)=>challenges.createChallenge({email,legacyUserId:user.id})));
    const changes=await Promise.allSettled(nextEmails.map((email,index)=>emails.bindVerifiedEmail(user.id,email,Math.floor(Date.now()/1000),{
      expectedEmail:"email-initial@example.test",challengeKey:nextChallenges[index].challenge.challengeKey,changeTokenKey:token.record.tokenKey})));
    expect(changes.filter((result)=>result.status==="fulfilled")).toHaveLength(1);
    expect(changes.filter((result)=>result.status==="rejected")).toHaveLength(1);
    const [consumed]=await db.query<RowDataPacket[]>("SELECT COUNT(*) AS count FROM email_verification_challenges WHERE legacy_user_id=? AND email IN (?,?) AND consumed_at IS NOT NULL",[user.id,...nextEmails]);
    expect(Number(consumed[0].count)).toBe(1);
  });

  it("rejects in-flight email and password requests when logout commits before their account transaction",async()=>{
    const keys=generateKeyPairSync("ec",{namedCurve:"prime256v1"});
    vi.stubEnv("IDENTITY_JWT_PRIVATE_KEY_PEM",String(keys.privateKey.export({type:"pkcs8",format:"pem"})));
    vi.stubEnv("IDENTITY_JWT_PUBLIC_KEY_PEM",String(keys.publicKey.export({type:"spki",format:"pem"})));
    vi.stubEnv("IDENTITY_JWT_AUDIENCE","primary-api");
    const registrations=owned(new AccountRegistrationRepository()),passwords=owned(new AccountPasswordRepository()),emails=owned(new AccountEmailRepository());
    const reader=owned(new LegacyIdentityReader()),sessions=owned(new IdentitySessionRepository()),jwt=new JwtIssuerService(),native=owned(new NativeIdentityService(reader,jwt,sessions));
    const user=await registrations.register({username:"logout-write-race",password:"Logout-initial!73",email:"logout-initial@example.test"},"logout-write-race");
    for(const operation of ["email","password"] as const) {
      const session=await sessions.issue({legacyUserId:user.id,username:user.username,sessionId:randomUUID(),expiresAt:new Date(Date.now()+60000)});
      const token=jwt.issue(user,session.sessionId).accessToken;await native.verify(token);
      let enter!:()=>void,release!:()=>void;
      const entered=new Promise<void>((resolve)=>{enter=resolve;}),gate=new Promise<void>((resolve)=>{release=resolve;});
      const authorize=async(connection:Parameters<NativeIdentityService["assertAccessInTransaction"]>[2])=>native.assertAccessInTransaction(token,user.id,connection);
      // Logout and account writes now share an account-first lock order. Pause
      // the already verified request before its transaction acquires that lock.
      const pending=(async()=>{enter();await gate;return operation==="email"
        ?emails.bindVerifiedEmail(user.id,"logout-forbidden@example.test",Math.floor(Date.now()/1000),{expectedEmail:user.email,authorize})
        :passwords.changePassword((await passwords.getCredentialById(user.id))!,"Logout-forbidden!83",{operationKey:"logout-forbidden-password",authorize});})();
      await entered;await sessions.revoke(session.refreshToken);release();
      await expect(pending).rejects.toMatchObject({status:401});
    }
    expect((await emails.getUserById(user.id))?.email).toBe("logout-initial@example.test");
    expect(await passwords.verifyPassword("Logout-initial!73",(await passwords.getCredentialById(user.id))!.passwordHash)).toBe(true);
  });

  it("fences invitation import once the private database is authoritative",async()=>{
    const invitations=owned(new InvitationIdentityRepository()),now=Math.floor(Date.now()/1000);
    const input={code:"migration-fenced-invite",key:"invite:migration-fenced-invite",quota:2,remaining:2,expiresAt:now+600,creatorId:1,creatorName:"root",note:null,createdAt:now,ttl:600,raw:{}};
    expect(await invitations.upsertImported([input])).toBeGreaterThan(0);
    await db.execute("UPDATE identity_migration_control SET authority='identity' WHERE id=1");
    await expect(invitations.upsertImported([{...input,remaining:1}])).rejects.toThrow("already authoritative");
    expect((await invitations.findByCodes([input.code]))[0].remaining).toBe(2);
  });
});
