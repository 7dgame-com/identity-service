import "reflect-metadata";
import { readFile } from "node:fs/promises";
import { randomUUID, createHash } from "node:crypto";
import mysql, { type Connection, type RowDataPacket } from "mysql2/promise";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { importLegacyQrManifest } from "../src/legacy-qrcode-import.js";
import { NativeQrcodeRepository } from "../src/native-qrcode.repository.js";

const enabled = process.env.IDENTITY_TEST_MYSQL === "1";
const options = {
  host: process.env.IDENTITY_DB_HOST ?? "127.0.0.1",
  port: Number(process.env.IDENTITY_DB_PORT ?? 3306),
  user: process.env.IDENTITY_DB_USER ?? "root",
  password: process.env.IDENTITY_DB_PASSWORD ?? "",
  multipleStatements: true,
  timezone: "Z",
};
const name = `test_qr_import_${randomUUID().replaceAll("-", "")}`;
const hash = (value: string) =>
  createHash("sha256").update(value).digest("hex");
const issued = Math.floor(Date.now() / 1000) - 10;
const code = (key: string, user = 24) => ({
  code_hash: hash(key),
  user_id: user,
  issued_at: issued,
  expires_at: issued + 60,
  context: {},
});
const scene = (key: string, extra: Record<string, unknown> = {}) => ({
  scene_hash: hash(key),
  issued_at: issued,
  expires_at: issued + 3600,
  provider_app_id: "wx-official",
  open_id: null,
  user_id: null,
  signup_token_hash: null,
  profile: null,
  ...extra,
});
const manifest = (
  login_codes: unknown[] = [],
  wechat_scenes: unknown[] = [],
) => ({ version: 1, captured_at_ms: Date.now(), login_codes, wechat_scenes });
const apply = { apply: true, environment: "staging" };
let admin: Connection, db: Connection, repository: NativeQrcodeRepository;
describe.skipIf(!enabled)("offline pending QR state MySQL import", () => {
  beforeAll(async () => {
    if (!["127.0.0.1", "localhost", "::1"].includes(options.host))
      throw new Error("Disposable local MySQL required.");
    admin = await mysql.createConnection(options);
    await admin.query(`CREATE DATABASE \`${name}\` CHARACTER SET utf8mb4`);
    db = await mysql.createConnection({ ...options, database: name });
    const init = await readFile(
      new URL("../../../deploy/mysql/init.sql", import.meta.url),
      "utf8",
    );
    await db.query(
      init.slice(
        init.indexOf("CREATE TABLE IF NOT EXISTS `auth_login_events`"),
      ),
    );
    for (const schema of [
      "identity-account-schema.sql",
      "identity-runtime-schema.sql",
      "identity-qrcode-schema.sql",
      "identity-wechat-oauth-schema.sql",
    ])
      await db.query(
        await readFile(
          new URL(`../../../deploy/mysql/${schema}`, import.meta.url),
          "utf8",
        ),
      );
    await db.query(
      "INSERT INTO user(id,username,status) VALUES(24,'old-user',10),(25,'other-user',10)",
    );
    await db.query(
      "INSERT INTO wechat(openid,token) VALUES('signup-openid','existing-signup-token')",
    );
    vi.stubEnv("IDENTITY_DATA_SOURCE", "identity");
    vi.stubEnv("IDENTITY_DB_HOST", options.host);
    vi.stubEnv("IDENTITY_DB_PORT", String(options.port));
    vi.stubEnv("IDENTITY_DB_USER", options.user);
    vi.stubEnv("IDENTITY_DB_PASSWORD", options.password);
    vi.stubEnv("IDENTITY_DB_NAME", name);
    repository = new NativeQrcodeRepository();
  }, 30000);
  afterAll(async () => {
    await repository?.onModuleDestroy();
    await db?.end();
    if (admin) {
      await admin.query(`DROP DATABASE IF EXISTS \`${name}\``);
      await admin.end();
    }
    vi.unstubAllEnvs();
  });
  it("imports original multi-device code windows and pending or scanned scenes into the native repository", async () => {
    expect(
      await importLegacyQrManifest(
        db,
        manifest(
          [code("first-device"), code("second-device")],
          [
            scene("waiting"),
            scene("scanned", {
              open_id: "signup-openid",
              profile: {
                openId: "signup-openid",
                providerAppId: "wx-official",
              },
            }),
          ],
        ),
        apply,
      ),
    ).toMatchObject({ imported: 4, applied: true });
    expect(await repository.loginCode(hash("first-device"))).toMatchObject({
      userId: 24,
      expiresAt: issued + 60,
    });
    expect(await repository.loginCode(hash("second-device"))).toMatchObject({
      userId: 24,
      expiresAt: issued + 60,
    });
    expect(await repository.wechatScene(hash("waiting"))).toMatchObject({
      openId: null,
      expiresAt: issued + 3600,
    });
    expect(await repository.wechatScene(hash("scanned"))).toMatchObject({
      openId: "signup-openid",
      providerAppId: "wx-official",
    });
    expect(
      await repository.hasActiveRegistration(
        hash("existing-signup-token"),
        issued + 10,
      ),
    ).toBe(true);
  });
  it("never extends or revives an existing credential or scene on manifest replay", async () => {
    await db.execute(
      "UPDATE identity_login_codes SET expires_at=? WHERE code_hash=?",
      [issued, hash("first-device")],
    );
    await db.execute(
      "UPDATE identity_wechat_scenes SET expires_at=? WHERE scene_hash=?",
      [issued, hash("waiting")],
    );
    expect(
      await importLegacyQrManifest(
        db,
        manifest([code("first-device")], [scene("waiting")]),
        apply,
      ),
    ).toMatchObject({ imported: 0, existing: 2 });
    expect((await repository.loginCode(hash("first-device")))!.expiresAt).toBe(
      issued,
    );
    expect((await repository.wechatScene(hash("waiting")))!.expiresAt).toBe(
      issued,
    );
  });
  it("keeps preview write-free and rolls back a batch with a missing account", async () => {
    expect(
      await importLegacyQrManifest(db, manifest([code("dry")])),
    ).toMatchObject({ imported: 0, wouldImport: 1 });
    expect(await repository.loginCode(hash("dry"))).toBeNull();
    await expect(
      importLegacyQrManifest(
        db,
        manifest([code("rolled-back"), code("missing", 999)]),
        apply,
      ),
    ).rejects.toThrow("missing private account");
    expect(await repository.loginCode(hash("rolled-back"))).toBeNull();
  });
  it("rejects account and provider conflicts while preserving all previous state", async () => {
    await expect(
      importLegacyQrManifest(db, manifest([code("second-device", 25)]), apply),
    ).rejects.toThrow("account conflict");
    await expect(
      importLegacyQrManifest(
        db,
        manifest(
          [],
          [
            scene("scanned", {
              provider_app_id: "another-app",
              open_id: "signup-openid",
              profile: {
                providerAppId: "another-app",
                openId: "signup-openid",
              },
            }),
          ],
        ),
        apply,
      ),
    ).rejects.toThrow("provider subject conflict");
  });
  it("serializes competing imports and rejects staging apply permanently after authority activation", async () => {
    const other = await mysql.createConnection({ ...options, database: name });
    try {
      const reports = await Promise.all([
        importLegacyQrManifest(db, manifest([code("parallel")]), apply),
        importLegacyQrManifest(other, manifest([code("parallel")]), apply),
      ]);
      expect(reports.reduce((sum, row) => sum + row.imported, 0)).toBe(1);
    } finally {
      await other.end();
    }
    await db.execute(
      "UPDATE identity_migration_control SET authority='identity' WHERE id=1",
    );
    await expect(
      importLegacyQrManifest(db, manifest([code("too-late")]), apply),
    ).rejects.toThrow("already authoritative");
    expect(await repository.loginCode(hash("too-late"))).toBeNull();
  });
});
