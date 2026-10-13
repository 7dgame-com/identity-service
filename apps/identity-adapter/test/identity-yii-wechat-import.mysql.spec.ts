import { accountImportTables, importIdentityAccounts } from "../src/identity-account-import.js";
import { finalizeAllocator, readSourceAllocatorInventory } from "../src/identity-allocator-finalizer.js";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import mysql, { Connection, RowDataPacket } from "mysql2/promise";
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
} from "vitest";
import {
  importReviewedYiiWechatBindings,
  importWechatIdentities,
} from "../src/identity-wechat-import.js";
import { activateIdentityAuthority } from "../src/migration-state.js";

describe.skipIf(process.env.IDENTITY_TEST_MYSQL !== "1")(
  "Reviewed Yii WeChat mapping MySQL",
  () => {
    let admin: Connection, source: Connection, target: Connection;
    let sourceName: string, targetName: string;
    const dbOptions = {
      host: process.env.IDENTITY_TEST_MYSQL_HOST ?? "127.0.0.1",
      port: Number(process.env.IDENTITY_TEST_MYSQL_PORT ?? 13316),
      user: process.env.IDENTITY_TEST_MYSQL_USER ?? "identity_test",
      password: process.env.IDENTITY_TEST_MYSQL_PASSWORD ?? "",
      multipleStatements: true,
      timezone: "Z",
    };
    beforeAll(async () => {
      if (!["127.0.0.1", "localhost", "::1"].includes(dbOptions.host))
        throw new Error("Disposable local MySQL only");
      admin = await mysql.createConnection(dbOptions);
    });
    beforeEach(async () => {
      sourceName = `yii_source_${randomUUID().replaceAll("-", "")}`;
      targetName = `yii_target_${randomUUID().replaceAll("-", "")}`;
      for (const name of [sourceName, targetName])
        await admin.query(
          `CREATE DATABASE \`${name}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`,
        );
      source = await mysql.createConnection({
        ...dbOptions,
        database: sourceName,
      });
      target = await mysql.createConnection({
        ...dbOptions,
        database: targetName,
      });
      const account = readFileSync(
        new URL(
          "../../../deploy/mysql/identity-account-schema.sql",
          import.meta.url,
        ),
        "utf8",
      );
      await source.query(account);
      await target.query(account);
      for (const file of [
        "identity-runtime-schema.sql",
        "identity-wechat-oauth-schema.sql",
        "identity-qrcode-schema.sql",
      ])
        await target.query(
          readFileSync(
            new URL(`../../../deploy/mysql/${file}`, import.meta.url),
            "utf8",
          ),
        );
      for (const db of [source, target]) {
        await db.query(
          "INSERT INTO user(id,username,status,wx_openid,created_at,updated_at) VALUES(41,'first',10,'CaseOpenId',1,1),(42,'second',10,'OtherOpenId',1,1)",
        );
        await db.query(
          "INSERT INTO wechat(openid,unionid,user_id,token) VALUES('CaseOpenId','UnionCase',41,'unchanged-first-token'),('OtherOpenId',NULL,42,'unchanged-second-token')",
        );
      }
    });
    afterEach(async () => {
      await Promise.all([source?.end(), target?.end()]);
      for (const name of [sourceName, targetName])
        if (name) await admin.query(`DROP DATABASE IF EXISTS \`${name}\``);
    });
    afterAll(async () => {
      await admin?.end();
    });
    const entry = (extra: Record<string, unknown> = {}) => ({
      provider: "wechat_official_account",
      provider_app_id: "ReviewedApp",
      open_id: "CaseOpenId",
      user_id: 41,
      evidence: "wechat",
      ...extra,
    });
    const manifest = (bindings: Record<string, unknown>[] = [entry()]) => ({
      schema_version: 1,
      source_database: sourceName,
      review: {
        reference: "cutover-reviewed-17",
        reviewed_by: "migration-owner",
        reviewed_at: new Date().toISOString(),
      },
      bindings,
    });
    const options = { importKey: "reviewed-yii-batch", apply: true };
    async function rows(sql: string) {
      const [result] = await target.query<RowDataPacket[]>(sql);
      return result;
    }

    it("defaults to dryrun then applies one exact binding and replays without account/token writes", async () => {
      const input = manifest();
      expect(
        await importReviewedYiiWechatBindings(source, target, input, {
          importKey: options.importKey,
        }),
      ).toMatchObject({ applied: false, wouldImport: 1, imported: 0 });
      expect(
        await rows("SELECT * FROM identity_wechat_identities"),
      ).toHaveLength(0);
      expect(
        await rows("SELECT * FROM identity_wechat_import_runs"),
      ).toHaveLength(0);
      expect(
        await importReviewedYiiWechatBindings(source, target, input, options),
      ).toMatchObject({ applied: true, imported: 1 });
      expect(
        await importReviewedYiiWechatBindings(source, target, input, options),
      ).toMatchObject({ applied: false, replay: true, existing: 1 });
      const bindings = await rows(
        "SELECT provider_app_id,open_id,user_id FROM identity_wechat_identities",
      );
      expect(
        bindings.map((row) => [
          row.provider_app_id,
          row.open_id,
          Number(row.user_id),
        ]),
      ).toEqual([["ReviewedApp", "CaseOpenId", 41]]);
      expect(await rows("SELECT * FROM identity_subject_events")).toHaveLength(
        1,
      );
      expect(
        (
          await rows(
            "SELECT token,user_id FROM wechat WHERE openid='CaseOpenId'",
          )
        )[0],
      ).toMatchObject({ token: "unchanged-first-token", user_id: 41 });
    });

    it("preserves disabled accounts and supports reviewed scalar evidence without guessing union", async () => {
      await target.query("UPDATE user SET status=0 WHERE id=41");
      expect(
        await importReviewedYiiWechatBindings(
          source,
          target,
          manifest([entry({ evidence: "user.wx_openid" })]),
          options,
        ),
      ).toMatchObject({ imported: 1 });
      expect(
        Number((await rows("SELECT status FROM user WHERE id=41"))[0].status),
      ).toBe(0);
      expect(
        (await rows("SELECT union_id FROM identity_wechat_identities"))[0]
          .union_id,
      ).toBeNull();
    });

    it.each(["case", "owner", "union", "scalar-union"])(
      "rejects mismatched source proof: %s",
      async (variant) => {
        const extras =
          variant === "case"
            ? { open_id: "caseopenid" }
            : variant === "owner"
              ? { user_id: 42 }
              : variant === "union"
                ? { union_id: "unioncase" }
                : { evidence: "user.wx_openid", union_id: "UnionCase" };
        await expect(
          importReviewedYiiWechatBindings(
            source,
            target,
            manifest([entry(extras)]),
            options,
          ),
        ).rejects.toThrow("proof does not match");
        expect(
          await rows("SELECT * FROM identity_wechat_identities"),
        ).toHaveLength(0);
      },
    );

    it("accepts only the explicitly reviewed union ID and exact application string", async () => {
      await importReviewedYiiWechatBindings(
        source,
        target,
        manifest([entry({ union_id: "UnionCase" })]),
        options,
      );
      await importReviewedYiiWechatBindings(
        source,
        target,
        manifest([
          entry({ provider_app_id: "reviewedapp", union_id: "UnionCase" }),
        ]),
        { ...options, importKey: "second-app-case" },
      );
      const bindings = await rows(
        "SELECT provider_app_id,union_id FROM identity_wechat_identities ORDER BY BINARY provider_app_id",
      );
      expect(
        bindings.map((row) => [row.provider_app_id, row.union_id]),
      ).toEqual([
        ["ReviewedApp", "UnionCase"],
        ["reviewedapp", "UnionCase"],
      ]);
    });

    it("atomically rejects another exact owner without partially importing a valid tuple", async () => {
      await target.query(
        "INSERT INTO identity_wechat_identities(provider,provider_app_id,open_id,user_id) VALUES('wechat_official_account','ZConflictApp','OtherOpenId',41)",
      );
      await expect(
        importReviewedYiiWechatBindings(
          source,
          target,
          manifest([
            entry(),
            entry({
              provider_app_id: "ZConflictApp",
              open_id: "OtherOpenId",
              user_id: 42,
            }),
          ]),
          options,
        ),
      ).rejects.toThrow("conflicts with the target");
      expect(
        await rows("SELECT * FROM identity_wechat_identities"),
      ).toHaveLength(1);
      expect(await rows("SELECT * FROM identity_subject_events")).toHaveLength(
        0,
      );
      expect(
        await rows("SELECT * FROM identity_wechat_import_runs"),
      ).toHaveLength(0);
    });

    it("rejects a canonical ID reused for a different account and a changed manifest key", async () => {
      const input = manifest();
      await importReviewedYiiWechatBindings(source, target, input, options);
      await expect(
        importReviewedYiiWechatBindings(
          source,
          target,
          { ...input, bindings: [entry({ provider_app_id: "ChangedApp" })] },
          options,
        ),
      ).rejects.toThrow("another reviewed manifest");
      await target.query("UPDATE user SET username='reused-id' WHERE id=42");
      await expect(
        importReviewedYiiWechatBindings(
          source,
          target,
          manifest([entry({ open_id: "OtherOpenId", user_id: 42 })]),
          { ...options, importKey: "reused-id" },
        ),
      ).rejects.toThrow("absent or changed");
    });

    it("permanently refuses apply and dryrun after native authority activation", async () => {
      await target.beginTransaction();
      await activateIdentityAuthority(target);
      await target.commit();
      for (const apply of [false, true])
        await expect(
          importReviewedYiiWechatBindings(source, target, manifest(), {
            ...options,
            apply,
          }),
        ).rejects.toThrow("already authoritative");
      expect(
        await rows("SELECT * FROM identity_wechat_identities"),
      ).toHaveLength(0);
    });

    it("requires the private binary upgrade before either dryrun or apply", async () => {
      await target.query(
        "ALTER TABLE identity_wechat_identities MODIFY provider_app_id VARCHAR(191) COLLATE utf8mb4_unicode_ci NOT NULL",
      );
      await expect(
        importReviewedYiiWechatBindings(source, target, manifest(), options),
      ).rejects.toThrow("binary schema migration");
      await target.query(
        readFileSync(
          new URL(
            "../../../deploy/mysql/identity-wechat-binary-migration.sql",
            import.meta.url,
          ),
          "utf8",
        ),
      );
      expect(
        await importReviewedYiiWechatBindings(
          source,
          target,
          manifest(),
          options,
        ),
      ).toMatchObject({ imported: 1 });
    });

    it("bounds the batch and rejects missing app/review/duplicate/conflicting source evidence", async () => {
      const input = manifest();
      for (const invalid of [
        { ...input, review: undefined },
        { ...input, source_database: "wrong-source" },
        { ...input, bindings: [entry({ provider_app_id: "" })] },
        { ...input, bindings: [entry(), entry()] },
        { ...input, bindings: [entry(), entry({ open_id: "OtherOpenId" })] },
      ]) {
        await expect(
          importReviewedYiiWechatBindings(source, target, invalid, options),
        ).rejects.toThrow();
      }
      await expect(
        importReviewedYiiWechatBindings(source, target, input, {
          ...options,
          maxRows: 0,
        }),
      ).rejects.toThrow("bound");
      expect(
        await rows("SELECT * FROM identity_wechat_identities"),
      ).toHaveLength(0);
    });

    it("imports auth UUIDs only after a reviewed exact Yii mapping, preserving the canonical integer", async () => {
      const init=readFileSync(new URL("../../../deploy/mysql/init.sql",import.meta.url),"utf8");await target.query(init.slice(init.indexOf("CREATE TABLE IF NOT EXISTS `auth_login_events`")));
      for(const file of ["identity-password-reset-token-schema.sql","identity-legacy-challenge-schema.sql","identity-apple-schema.sql","identity-allocator-schema.sql"])await target.query(readFileSync(new URL("../../../deploy/mysql/"+file,import.meta.url),"utf8"));
      const [sourceTables]=await source.query<RowDataPacket[]>("SHOW TABLES");for(const row of sourceTables){const name=String(Object.values(row)[0]);if(!Object.keys(accountImportTables).includes(name))await source.query("DROP TABLE `"+name+"`");}
      await target.query("DELETE FROM wechat;DELETE FROM user");await importIdentityAccounts(source,target,{importKey:"yii-allocator-baseline",apply:true});
      const authName="yii_auth_"+randomUUID().replaceAll("-","");await admin.query("CREATE DATABASE `"+authName+"` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");const authSource=await mysql.createConnection({...dbOptions,database:authName});
      const finalize=async()=>{const info=await readSourceAllocatorInventory(source),fence=await mysql.createConnection({...dbOptions,database:targetName});try{await finalizeAllocator({source,target,fence,review:{version:1,sourceDatabase:sourceName,targetDatabase:targetName,sourceServerUuid:info.serverUuid,importKey:"yii-allocator-baseline",writersDrainedAt:new Date(Date.now()-1000).toISOString(),finalSyncSha256:"a".repeat(64),referenceReviewSha256:info.referenceReviewSha256},reviewSha256:"b".repeat(64),apply:true});}finally{await fence.end();}};
      try{
      await authSource.query(`CREATE TABLE auth_users(id VARCHAR(128) PRIMARY KEY,primary_unionid VARCHAR(191),display_name VARCHAR(255),avatar_url VARCHAR(255),status VARCHAR(32),created_at DATETIME(3),updated_at DATETIME(3));
      CREATE TABLE auth_identities(id VARCHAR(128) PRIMARY KEY,user_id VARCHAR(128),provider VARCHAR(64),provider_app_id VARCHAR(191),openid VARCHAR(191),unionid VARCHAR(191),profile_json JSON);
      INSERT INTO auth_users VALUES('old-uuid',NULL,'Old account',NULL,'active','2026-01-01','2026-01-01');
      INSERT INTO auth_identities VALUES('old-provider','old-uuid','wechat_official_account','ReviewedApp','CaseOpenId',NULL,NULL)`);
      await expect(importWechatIdentities(authSource,target,{importKey:"allocator-missing",apply:true})).rejects.toThrow("ALLOCATOR_NOT_READY");
      await finalize();
      await expect(
        importWechatIdentities(authSource, target, {
          importKey: "auth-unreviewed",
          apply: true,
        }),
      ).rejects.toThrow("exact Yii application binding");
      expect(
        await rows("SELECT * FROM identity_wechat_import_runs"),
      ).toHaveLength(0);
      await importReviewedYiiWechatBindings(
        source,
        target,
        manifest(),
        options,
      );
      await finalize();
      expect(
        await importWechatIdentities(authSource, target, {
          importKey: "auth-reviewed",
          apply: true,
        }),
      ).toMatchObject({ applied: true });
      expect(
        Number(
          (
            await rows(
              "SELECT user_id FROM identity_auth_subject_maps WHERE auth_user_id='old-uuid'",
            )
          )[0].user_id,
        ),
      ).toBe(41);
      }finally{await authSource.end();await admin.query("DROP DATABASE IF EXISTS `"+authName+"`");}
    });
  },
);
