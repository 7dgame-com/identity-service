import { readFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import mysql, { type Connection, type RowDataPacket } from "mysql2/promise";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { importIdentityAccounts } from "../src/identity-account-import.js";
import { syncIdentityAccounts } from "../src/identity-account-sync.js";
import { profileGroupSha256, type ProfileSelectionManifest } from "../src/identity-profile-migration.js";

const enabled = process.env.IDENTITY_TEST_MYSQL === "1";
const options = {
  host: process.env.IDENTITY_DB_HOST ?? "127.0.0.1",
  port: Number(process.env.IDENTITY_DB_PORT ?? 3306),
  user: process.env.IDENTITY_DB_USER ?? "root",
  password: process.env.IDENTITY_DB_PASSWORD ?? "",
  multipleStatements: true,
  timezone: "Z",
};
let admin: Connection, source: Connection, target: Connection;
const owned: string[] = [];
const syncOptions = { apply: true, maxChanges: 100 };

async function database(): Promise<Connection> {
  const name = `profile_${randomUUID().replaceAll("-", "")}_test`;
  owned.push(name);
  await admin.query(`CREATE DATABASE \`${name}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`);
  const connection = await mysql.createConnection({ ...options, database: name });
  const init = await readFile(new URL("../../../deploy/mysql/init.sql", import.meta.url), "utf8");
  await connection.query(init.slice(init.indexOf("CREATE TABLE IF NOT EXISTS `auth_login_events`")));
  for (const schema of ["identity-account-schema.sql", "identity-runtime-schema.sql", "identity-wechat-oauth-schema.sql"])
    await connection.query(await readFile(new URL(`../../../deploy/mysql/${schema}`, import.meta.url), "utf8"));
  return connection;
}
async function rows(sql: string): Promise<RowDataPacket[]> {
  const [result] = await target.query<RowDataPacket[]>(sql);
  return result;
}
async function count(table: string): Promise<number> {
  if (!["user", "user_info", "identity_profile_avatars", "identity_legacy_profile_rows", "identity_legacy_profile_history", "identity_account_import_runs"].includes(table))
    throw new Error("Unsupported test table");
  return Number((await rows(`SELECT COUNT(*) AS total FROM \`${table}\``))[0].total);
}
async function selection(profileId = 14): Promise<ProfileSelectionManifest> {
  const [group] = await source.query<RowDataPacket[]>("SELECT id,user_id,info,avatar_id FROM user_info WHERE user_id=7001");
  return { version: 1, selections: [{ userId: 7001, profileId, sourceRowsSha256: profileGroupSha256(group, true) }] };
}
async function importBaseline(profileId = 14): Promise<void> {
  await importIdentityAccounts(source, target, { apply: true, importKey: "profile-baseline", profileSelection: await selection(profileId) });
}
async function expectEmpty(): Promise<void> {
  for (const table of ["user", "user_info", "identity_profile_avatars", "identity_legacy_profile_rows", "identity_legacy_profile_history", "identity_account_import_runs"])
    expect(await count(table)).toBe(0);
}

describe.skipIf(!enabled)("reviewed legacy profile projection MySQL", () => {
  beforeAll(async () => {
    if (!["127.0.0.1", "localhost", "::1"].includes(options.host))
      throw new Error("Profile migration integration requires disposable local MySQL.");
    admin = await mysql.createConnection(options);
  });
  beforeEach(async () => {
    source = await database();
    target = await database();
    await source.query("ALTER TABLE user_info DROP INDEX account_profile_user, ADD COLUMN avatar_id BIGINT NULL, ADD COLUMN gold BIGINT NOT NULL DEFAULT 0, ADD COLUMN points BIGINT NOT NULL DEFAULT 0");
    await source.query(`INSERT INTO user(id,username,email,status,password_hash) VALUES
      (7001,'profile-owner','owner@example.test',10,'existing-hash'),
      (7002,'singleton','singleton@example.test',10,'existing-hash'),
      (7003,'without-profile','without@example.test',10,'existing-hash')`);
    const profiles = Array.from({ length: 7 }, (_, i) => ({ id: 11 + i, userId: 7001, info: { variant: i % 2 }, avatar: i % 3 === 0 ? null : 100 + i % 3 }));
    profiles.push({ id: 21, userId: 7002, info: { variant: 9 }, avatar: 777 });
    await source.query(`INSERT INTO user_info(id,user_id,info,avatar_id,gold,points) VALUES ${profiles.map(() => "(?,?,?,?,100,200)").join(",")}`,
      profiles.flatMap((row) => [row.id, row.userId, JSON.stringify(row.info), row.avatar]));
  }, 30_000);
  afterEach(async () => {
    await Promise.all([source?.end(), target?.end()]);
    for (const name of owned.splice(0)) {
      if (!/^profile_[a-f0-9]+_test$/.test(name)) throw new Error("Refusing cleanup outside owned test databases");
      await admin.query(`DROP DATABASE IF EXISTS \`${name}\``);
    }
  });
  afterAll(async () => { await admin?.end(); });

  it("rejects unreviewed duplicates during dry-run and apply without writing target rows", async () => {
    for (const apply of [false, true])
      await expect(importIdentityAccounts(source, target, { apply, importKey: "unreviewed" })).rejects.toMatchObject({ code: "PROFILE_SELECTION_REQUIRED" });
    await expectEmpty();
    const [sourceRows] = await source.query<RowDataPacket[]>("SELECT COUNT(*) AS total FROM user_info");
    expect(Number(sourceRows[0].total)).toBe(8);
  });

  it("imports one reviewed middle row, archives every identity profile and immediately syncs without drift", async () => {
    const manifest = await selection();
    const preview = await importIdentityAccounts(source, target, { importKey: "preview", profileSelection: manifest });
    expect(preview.profiles).toEqual({ sourceRows: 8, owners: 2, duplicateGroups: 1, archivedRows: 8 });
    await expectEmpty();
    await importBaseline();
    expect(await count("user")).toBe(3);
    expect((await rows("SELECT id,user_id,info FROM user_info ORDER BY user_id")).map((row) => ({ id: Number(row.id), userId: Number(row.user_id), info: row.info })))
      .toEqual([{ id: 14, userId: 7001, info: { variant: 1 } }, { id: 21, userId: 7002, info: { variant: 9 } }]);
    expect(await rows("SELECT user_id,avatar_id FROM identity_profile_avatars")).toEqual([{ user_id: 7002, avatar_id: 777 }]);
    const archive = await rows("SELECT id,payload_json,selected_profile_id,is_present FROM identity_legacy_profile_rows ORDER BY id");
    expect(archive).toHaveLength(8);
    expect(archive.slice(0, 7).every((row) => Number(row.selected_profile_id) === 14 && Number(row.is_present) === 1)).toBe(true);
    expect(archive[0].payload_json).toEqual({ id: 11, user_id: 7001, info: { variant: 0 }, avatar_id: null });
    const [allSourceProfiles]=await source.query<RowDataPacket[]>("SELECT id,user_id,info,avatar_id FROM user_info ORDER BY id");
    expect(archive.map(row=>row.payload_json)).toEqual(allSourceProfiles.map(row=>({...row})));
    expect(await count("identity_legacy_profile_history")).toBe(8);
    expect(await syncIdentityAccounts(source, target, syncOptions)).toMatchObject({ applied: true, changes: 0 });
    expect(await count("identity_legacy_profile_history")).toBe(8);
  });

  it("archives unselected updates and their old versions without changing canonical data", async () => {
    await importBaseline();
    await source.query("UPDATE user_info SET info=JSON_OBJECT('variant',99),avatar_id=999,gold=9999 WHERE id=11");
    expect(await syncIdentityAccounts(source, target, syncOptions)).toMatchObject({ applied: true, tableChanges: { identity_legacy_profile_rows: 1 } });
    expect((await rows("SELECT id,info FROM user_info WHERE user_id=7001"))[0]).toEqual({ id: 14, info: { variant: 1 } });
    expect(await rows("SELECT avatar_id FROM identity_profile_avatars WHERE user_id=7001")).toEqual([]);
    expect((await rows("SELECT payload_json FROM identity_legacy_profile_rows WHERE id=11"))[0].payload_json)
      .toEqual({ id: 11, user_id: 7001, info: { variant: 99 }, avatar_id: 999 });
    expect(await rows("SELECT payload_json FROM identity_legacy_profile_history WHERE id=11 ORDER BY payload_hash")).toHaveLength(2);
    expect(await syncIdentityAccounts(source, target, syncOptions)).toMatchObject({ changes: 0 });
    expect(await count("identity_legacy_profile_history")).toBe(9);
  });

  it("updates canonical info and avatar from the same pinned row", async () => {
    await importBaseline();
    await source.query("UPDATE user_info SET info=JSON_OBJECT('selected',true),avatar_id=321 WHERE id=14");
    await syncIdentityAccounts(source, target, syncOptions);
    expect((await rows("SELECT id,info FROM user_info WHERE user_id=7001"))[0]).toEqual({ id: 14, info: { selected: true } });
    expect((await rows("SELECT avatar_id FROM identity_profile_avatars WHERE user_id=7001"))[0].avatar_id).toBe(321);
    expect(await rows("SELECT payload_json FROM identity_legacy_profile_history WHERE id=14")).toHaveLength(2);
    expect(await syncIdentityAccounts(source, target, syncOptions)).toMatchObject({ changes: 0 });
  });

  it("archives a newly added unselected row while preserving the existing selection", async () => {
    await importBaseline();
    await source.query("INSERT INTO user_info(id,user_id,info,avatar_id) VALUES(99,7001,JSON_OBJECT('new',1),888)");
    await syncIdentityAccounts(source, target, syncOptions);
    expect(Number((await rows("SELECT id FROM user_info WHERE user_id=7001"))[0].id)).toBe(14);
    expect(await rows("SELECT avatar_id FROM identity_profile_avatars WHERE user_id=7001")).toEqual([]);
    expect(await count("identity_legacy_profile_rows")).toBe(9);
    expect(Number((await rows("SELECT selected_profile_id FROM identity_legacy_profile_rows WHERE id=99"))[0].selected_profile_id)).toBe(14);
    expect(await syncIdentityAccounts(source, target, syncOptions)).toMatchObject({ changes: 0 });
  });

  it("requires fresh explicit reselection after canonical deletion and keeps the deleted row archived", async () => {
    await importBaseline();
    await source.query("DELETE FROM user_info WHERE id=14");
    for (const apply of [false, true])
      await expect(syncIdentityAccounts(source, target, { ...syncOptions, apply })).rejects.toMatchObject({ code: "PROFILE_SELECTED_ROW_MISSING" });
    expect(Number((await rows("SELECT id FROM user_info WHERE user_id=7001"))[0].id)).toBe(14);
    await syncIdentityAccounts(source, target, { ...syncOptions, profileSelection: await selection(16) });
    expect(Number((await rows("SELECT id FROM user_info WHERE user_id=7001"))[0].id)).toBe(16);
    expect(Number((await rows("SELECT is_present FROM identity_legacy_profile_rows WHERE id=14"))[0].is_present)).toBe(0);
    expect(await count("identity_legacy_profile_rows")).toBe(8);
    expect(await count("identity_legacy_profile_history")).toBe(8);
    expect(await syncIdentityAccounts(source, target, syncOptions)).toMatchObject({ changes: 0 });
  });

  it("clears canonical profiles and avatars when all source rows disappear while retaining archives", async () => {
    await importBaseline();
    await source.query("DELETE FROM user_info");
    await syncIdentityAccounts(source, target, syncOptions);
    expect(await count("user_info")).toBe(0);
    expect(await count("identity_profile_avatars")).toBe(0);
    expect(await count("identity_legacy_profile_rows")).toBe(8);
    expect((await rows("SELECT is_present FROM identity_legacy_profile_rows")).every((row) => Number(row.is_present) === 0)).toBe(true);
    expect(await count("identity_legacy_profile_history")).toBe(8);
    expect(await syncIdentityAccounts(source, target, syncOptions)).toMatchObject({ changes: 0 });
  });

  it("rejects archive edits made independently of the migration baseline", async () => {
    await importBaseline();
    await target.query("UPDATE identity_legacy_profile_rows SET payload_json=JSON_SET(payload_json,'$.info.tampered',true) WHERE id=11");
    await expect(syncIdentityAccounts(source, target, syncOptions)).rejects.toThrow("diverged");
    expect(Number((await rows("SELECT id FROM user_info WHERE user_id=7001"))[0].id)).toBe(14);
    expect(await count("identity_legacy_profile_history")).toBe(8);
  });

  it("rejects stale manifest digests before import or sync writes", async () => {
    const stale = await selection();
    await source.query("UPDATE user_info SET avatar_id=989 WHERE id=11");
    await expect(importIdentityAccounts(source, target, { apply: true, importKey: "stale", profileSelection: stale })).rejects.toMatchObject({ code: "PROFILE_MANIFEST_SOURCE_CHANGED" });
    await expectEmpty();
    const current = await selection();
    await importIdentityAccounts(source, target, { apply: true, importKey: "current", profileSelection: current });
    await source.query("UPDATE user_info SET avatar_id=990 WHERE id=11");
    await expect(syncIdentityAccounts(source, target, { ...syncOptions, profileSelection: current })).rejects.toMatchObject({ code: "PROFILE_MANIFEST_SOURCE_CHANGED" });
    expect((await rows("SELECT payload_json FROM identity_legacy_profile_rows WHERE id=11"))[0].payload_json.avatar_id).toBe(989);
    expect(await count("identity_legacy_profile_history")).toBe(8);
  });

  it("detects target collation collisions during dry-run while leaving target accounts empty", async () => {
    await source.query("ALTER TABLE user MODIFY username VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL");
    await source.query("UPDATE user SET username=CASE id WHEN 7001 THEN 'Case' WHEN 7002 THEN 'case' ELSE username END");
    await expect(importIdentityAccounts(source, target, { importKey: "case-conflict", profileSelection: await selection() }))
      .rejects.toMatchObject({ code: "ACCOUNT_TARGET_UNIQUE_CONFLICT", table: "user", index: "account_username" });
    await expectEmpty();
  });

  it("allows several NULL emails because the target unique index permits NULLs", async () => {
    await source.query("UPDATE user SET email=NULL WHERE id IN (7001,7002)");
    const manifest=await selection();
    await expect(importIdentityAccounts(source,target,{importKey:"nullable-email",profileSelection:manifest})).resolves.toMatchObject({applied:false});
    await expectEmpty();
    await importIdentityAccounts(source,target,{apply:true,importKey:"nullable-email",profileSelection:manifest});
    expect(Number((await rows("SELECT COUNT(*) AS total FROM user WHERE email IS NULL"))[0].total)).toBe(2);
  });

  it("rejects repeated non-NULL empty emails in dry-run", async () => {
    await source.query("ALTER TABLE user DROP INDEX account_email");
    await source.query("UPDATE user SET email='' WHERE id IN (7001,7002)");
    await expect(importIdentityAccounts(source,target,{importKey:"empty-email",profileSelection:await selection()}))
      .rejects.toMatchObject({code:"ACCOUNT_TARGET_UNIQUE_CONFLICT",table:"user",index:"account_email"});
    await expectEmpty();
  });

  it("uses target accent and trailing-space comparisons instead of source binary equality", async () => {
    await source.query("ALTER TABLE user MODIFY username VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL");
    await source.query("UPDATE user SET username=CASE id WHEN 7001 THEN 'café' WHEN 7002 THEN 'cafe' ELSE username END");
    const manifest=await selection();
    await expect(importIdentityAccounts(source,target,{importKey:"accent",profileSelection:manifest}))
      .rejects.toMatchObject({code:"ACCOUNT_TARGET_UNIQUE_CONFLICT",table:"user",index:"account_username"});
    await source.query("ALTER TABLE user DROP INDEX account_username");
    await source.query("UPDATE user SET username=CASE id WHEN 7001 THEN 'space' WHEN 7002 THEN 'space ' ELSE username END");
    await expect(importIdentityAccounts(source,target,{importKey:"space",profileSelection:manifest}))
      .rejects.toMatchObject({code:"ACCOUNT_TARGET_UNIQUE_CONFLICT",table:"user",index:"account_username"});
    await expectEmpty();
  });

  it("preflights the actual target prefix and composite unique indexes", async () => {
    await target.query("ALTER TABLE user DROP INDEX account_username, ADD UNIQUE account_username_prefix(username(4))");
    await source.query("UPDATE user SET username=CASE id WHEN 7001 THEN 'prefix-a' WHEN 7002 THEN 'prefix-b' ELSE username END");
    const manifest=await selection();
    await expect(importIdentityAccounts(source,target,{importKey:"prefix",profileSelection:manifest}))
      .rejects.toMatchObject({code:"ACCOUNT_TARGET_UNIQUE_CONFLICT",table:"user",index:"account_username_prefix"});
    await target.query("ALTER TABLE user DROP INDEX account_username_prefix, ADD UNIQUE account_pair(username,status)");
    await source.query("ALTER TABLE user DROP INDEX account_username");
    await source.query("UPDATE user SET username='pair' WHERE id IN (7001,7002)");
    await expect(importIdentityAccounts(source,target,{importKey:"pair",profileSelection:manifest}))
      .rejects.toMatchObject({code:"ACCOUNT_TARGET_UNIQUE_CONFLICT",table:"user",index:"account_pair"});
    await expectEmpty();
  });

  it("rejects source role aliases of existing target seed names before writing", async () => {
    await source.query("UPDATE auth_item SET name='ROOT' WHERE name='root'");
    await expect(importIdentityAccounts(source,target,{importKey:"seed-alias",profileSelection:await selection()}))
      .rejects.toMatchObject({code:"ACCOUNT_TARGET_UNIQUE_CONFLICT",table:"auth_item",index:"PRIMARY"});
    await expectEmpty();
    expect((await rows("SELECT name FROM auth_item WHERE name='root'"))[0].name).toBe("root");
  });

  it.each(['"true"','true','123','null'])("rejects unsupported JSON scalar %s before import or sync mutations", async (json) => {
    await source.query("UPDATE user_info SET info=CAST(? AS JSON) WHERE id=11",[json]);
    for(const apply of [false,true])await expect(importIdentityAccounts(source,target,{apply,importKey:"scalar",profileSelection:await selection()}))
      .rejects.toMatchObject({code:"PROFILE_INFO_SCALAR_UNSUPPORTED"});
    await expectEmpty();
    await source.query("UPDATE user_info SET info=JSON_OBJECT('variant',0) WHERE id=11");
    await importBaseline();
    await source.query("UPDATE user_info SET info=CAST(? AS JSON) WHERE id=11",[json]);
    for(const apply of [false,true])await expect(syncIdentityAccounts(source,target,{...syncOptions,apply}))
      .rejects.toMatchObject({code:"PROFILE_INFO_SCALAR_UNSUPPORTED"});
    expect((await rows("SELECT payload_json FROM identity_legacy_profile_rows WHERE id=11"))[0].payload_json.info).toEqual({variant:0});
    expect(await count("identity_legacy_profile_history")).toBe(8);
  });

  it("rejects TEXT info rather than guessing whether strings are serialized JSON", async () => {
    await source.query("ALTER TABLE user_info MODIFY info LONGTEXT NULL");
    await expect(importIdentityAccounts(source,target,{importKey:"text-encoding",profileSelection:await selection()}))
      .rejects.toMatchObject({code:"PROFILE_INFO_ENCODING_UNSUPPORTED"});
    await expectEmpty();
  });

  it("preserves decoded JSON arrays and SQL NULL without reparsing", async () => {
    await source.query("UPDATE user_info SET info=JSON_ARRAY('true',true,123,NULL,JSON_OBJECT('a',1)) WHERE id=14");
    await source.query("UPDATE user_info SET info=NULL WHERE id=11");
    await importBaseline();
    const [original]=await source.query<RowDataPacket[]>("SELECT info FROM user_info WHERE id=14");
    expect((await rows("SELECT info FROM user_info WHERE id=14"))[0].info).toEqual(original[0].info);
    expect((await rows("SELECT payload_json FROM identity_legacy_profile_rows WHERE id=11"))[0].payload_json.info).toBeNull();
    expect(await syncIdentityAccounts(source,target,syncOptions)).toMatchObject({changes:0});
  });

  it("rejects private JSON scalar tampering before baseline's legacy string normalization", async () => {
    await importBaseline();
    await target.query("UPDATE user_info SET info=CAST(? AS JSON) WHERE id=14",['"{\\"variant\\":1}"']);
    await expect(syncIdentityAccounts(source,target,syncOptions)).rejects.toMatchObject({code:"PROFILE_INFO_SCALAR_UNSUPPORTED"});
    expect(await count("identity_legacy_profile_history")).toBe(8);
  });
});
