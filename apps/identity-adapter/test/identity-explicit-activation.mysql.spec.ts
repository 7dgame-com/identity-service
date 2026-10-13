import "reflect-metadata";
import { execFile } from "node:child_process";
import {
  createHash,
  generateKeyPairSync,
  randomBytes,
  randomUUID,
} from "node:crypto";
import { cp, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";
import type { INestApplication } from "@nestjs/common";
import { RequestMethod } from "@nestjs/common";
import { METHOD_METADATA, PATH_METADATA } from "@nestjs/common/constants.js";
import { NestFactory } from "@nestjs/core";
import mysql, { type Connection, type RowDataPacket } from "mysql2/promise";
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";
import { initializeFreshAllocator } from "../src/identity-allocator-state.js";
import type * as Activation from "../src/identity-activation.js";

const enabled = process.env.IDENTITY_TEST_MYSQL === "1";
const root = fileURLToPath(new URL("../../../", import.meta.url));
const options = {
  host: process.env.IDENTITY_TEST_MYSQL_HOST ?? "127.0.0.1",
  port: Number(process.env.IDENTITY_TEST_MYSQL_PORT ?? 13316),
  user: process.env.IDENTITY_TEST_MYSQL_USER ?? "root",
  password: process.env.IDENTITY_TEST_MYSQL_PASSWORD ?? "",
  timezone: "Z",
  multipleStatements: true,
};
const revision = "a".repeat(40),
  upgradeRevision = "b".repeat(40);
const schemas = [
  "identity-account-schema.sql",
  "identity-password-reset-token-schema.sql",
  "identity-legacy-challenge-schema.sql",
  "identity-runtime-schema.sql",
  "identity-wechat-oauth-schema.sql",
  "identity-qrcode-schema.sql",
  "identity-apple-schema.sql",
  "identity-allocator-schema.sql",
  "identity-activation-schema.sql",
];
const execute = promisify(execFile);
const digest = (value: unknown) =>
  createHash("sha256").update(JSON.stringify(value)).digest("hex");
type CompiledModule = { AppModule: new (...args: any[]) => unknown };
type HttpResult = { status: number; body: Record<string, any> | null };

describe.skipIf(!enabled)(
  "explicit activation against compiled Nest and disposable private MySQL",
  () => {
    let admin: Connection,
      db: Connection,
      database: string,
      build: string,
      upgradeBuild: string;
    let activation: typeof Activation, upgradedActivation: typeof Activation;
    let compiled: CompiledModule, upgraded: CompiledModule;
    const connections: Connection[] = [],
      apps: INestApplication[] = [];

    async function connect() {
      const c = await mysql.createConnection({ ...options, database });
      connections.push(c);
      return c;
    }
    async function tableSnapshot() {
      const [tables] = await db.query<RowDataPacket[]>("SHOW TABLES");
      const result: Record<
        string,
        { rows: number; data: string; ddl: string }
      > = {};
      for (const name of tables
        .map((row) => String(Object.values(row)[0]))
        .sort()) {
        if (!/^[a-z_]+$/.test(name))
          throw new Error("Unexpected disposable fixture table");
        const [rows] = await db.query<RowDataPacket[]>(
          `SELECT * FROM \`${name}\``,
        );
        const [definition] = await db.query<RowDataPacket[]>(
          `SHOW CREATE TABLE \`${name}\``,
        );
        result[name] = {
          rows: rows.length,
          data: digest(rows.map((row) => JSON.stringify(row)).sort()),
          ddl: digest(definition[0]["Create Table"]),
        };
      }
      return result;
    }
    async function proof() {
      const [rows] = await db.query<RowDataPacket[]>(
        "SELECT manifest_sha256 FROM identity_migration_allocator_state WHERE id=1",
      );
      expect(rows).toHaveLength(1);
      return String(rows[0].manifest_sha256);
    }
    async function deadline(offset = 60_000) {
      const [rows] = await db.query<RowDataPacket[]>(
        "SELECT UTC_TIMESTAMP(3) AS now",
      );
      return new Date((rows[0].now as Date).getTime() + offset).toISOString();
    }
    async function request(
      app: INestApplication,
      path: string,
      method = "GET",
      body?: unknown,
      headers: Record<string, string> = {},
    ): Promise<HttpResult> {
      const response = await fetch(`${await app.getUrl()}${path}`, {
        method,
        headers: {
          ...(body === undefined ? {} : { "content-type": "application/json" }),
          ...headers,
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        signal: AbortSignal.timeout(10_000),
      });
      const value = await response.text();
      return {
        status: response.status,
        body: value ? JSON.parse(value) : null,
      };
    }
    async function boot(module = compiled) {
      const app = await NestFactory.create(module.AppModule as never, {
        logger: false,
        abortOnError: false,
      });
      apps.push(app);
      await app.listen(0, "127.0.0.1");
      return app;
    }
    async function activate(
      c = db,
      api = activation,
      patch: Partial<Activation.ExplicitActivationOptions> = {},
    ) {
      return api.activateExplicitIdentity({
        connection: c,
        expectedProofSha256: await proof(),
        expectedRevision: api === activation ? revision : upgradeRevision,
        deadline: await deadline(),
        apply: true,
        ...patch,
      });
    }
    async function rows(table: string) {
      const [result] = await db.query<RowDataPacket[]>(
        `SELECT * FROM \`${table}\``,
      );
      return result;
    }

    beforeAll(async () => {
      const githubMysql =
        options.port === 3306 &&
        (process.env.CI === "true" || process.env.GITHUB_ACTIONS === "true");
      if (
        options.host !== "127.0.0.1" ||
        (options.port !== 13316 && !githubMysql)
      )
        throw new Error(
          "Explicit activation fixtures require dedicated local or CI MySQL",
        );
      build = await mkdtemp(join(root, ".identity-activation-build-"));
      await execute(
        process.execPath,
        [
          join(root, "node_modules/typescript/bin/tsc"),
          "--outDir",
          build,
          "--noEmitOnError",
          "true",
        ],
        { cwd: root, timeout: 90_000, maxBuffer: 1024 * 1024 },
      );
      const generated =
        "apps/identity-adapter/src/generated/iam-organization-reconciliation-compiled-revision.js";
      await writeFile(
        join(build, generated),
        `export const ORGANIZATION_RECONCILIATION_COMPILED_BUILD_REVISION = ${JSON.stringify(revision)};\n`,
      );
      upgradeBuild = await mkdtemp(
        join(root, ".identity-activation-upgrade-build-"),
      );
      await cp(build, upgradeBuild, { recursive: true });
      await writeFile(
        join(upgradeBuild, generated),
        `export const ORGANIZATION_RECONCILIATION_COMPILED_BUILD_REVISION = ${JSON.stringify(upgradeRevision)};\n`,
      );
      activation = await import(
        pathToFileURL(
          join(build, "apps/identity-adapter/src/identity-activation.js"),
        ).href
      );
      upgradedActivation = await import(
        pathToFileURL(
          join(
            upgradeBuild,
            "apps/identity-adapter/src/identity-activation.js",
          ),
        ).href
      );
      compiled = await import(
        pathToFileURL(join(build, "apps/identity-adapter/src/app.module.js"))
          .href
      );
      upgraded = await import(
        pathToFileURL(
          join(upgradeBuild, "apps/identity-adapter/src/app.module.js"),
        ).href
      );
      admin = await mysql.createConnection(options);
    }, 120_000);
    beforeEach(async () => {
      database = `test_explicit_activation_${randomUUID().replaceAll("-", "")}`;
      await admin.query(
        `CREATE DATABASE \`${database}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`,
      );
      db = await connect();
      const init = await readFile(join(root, "deploy/mysql/init.sql"), "utf8");
      await db.query(
        init.slice(
          init.indexOf("CREATE TABLE IF NOT EXISTS `auth_login_events`"),
        ),
      );
      for (const schema of schemas)
        await db.query(
          await readFile(join(root, "deploy/mysql", schema), "utf8"),
        );
      const keys = generateKeyPairSync("ec", { namedCurve: "prime256v1" }),
        key = randomBytes(32).toString("hex");
      const env = {
        IDENTITY_DATA_SOURCE: "identity",
        IDENTITY_ACTIVATION_MODE: "explicit",
        IDENTITY_DB_HOST: options.host,
        IDENTITY_DB_PORT: String(options.port),
        IDENTITY_DB_NAME: database,
        IDENTITY_DB_USER: options.user,
        IDENTITY_DB_PASSWORD: options.password,
        IDENTITY_TOKEN_ISSUANCE_ENABLED: "true",
        IDENTITY_REFRESH_REPLAY_KEY: randomBytes(32).toString("base64url"),
        IDENTITY_INTERNAL_API_TOKEN: key,
        IDENTITY_IAM_INTERNAL_API_TOKEN: key,
        IDENTITY_TOKEN_ISSUANCE_INTERNAL_API_TOKEN: key,
        IDENTITY_JWT_PRIVATE_KEY_PEM: keys.privateKey
          .export({ format: "pem", type: "pkcs8" })
          .toString(),
        IDENTITY_JWT_PUBLIC_KEY_PEM: keys.publicKey
          .export({ format: "pem", type: "spki" })
          .toString(),
        IDENTITY_JWT_ISSUER: "https://activation-fixture.test",
        IDENTITY_JWT_AUDIENCE: "activation-fixture",
        IDENTITY_IAM_ENABLED: "false",
        IDENTITY_LOGIN_AUDIT_ENABLED: "false",
        IDENTITY_OIDC_ENABLED: "false",
        IDENTITY_LEGACY_SESSION_REVOKE_ENABLED: "false",
        IDENTITY_ACCOUNT_LIFECYCLE_ENABLED: "true",
        IDENTITY_ACCOUNT_LIFECYCLE_MODE: "native",
        IDENTITY_ACCOUNT_REGISTER_ENABLED: "true",
        LEGACY_DB_HOST: "127.0.0.1",
        LEGACY_DB_PORT: "1",
        LEGACY_DB_USER: "unreachable",
        LEGACY_DB_PASSWORD: "unreachable",
        LEGACY_WRITE_DB_HOST: "127.0.0.1",
        LEGACY_WRITE_DB_PORT: "1",
        LEGACY_WRITE_DB_USER: "unreachable",
        LEGACY_WRITE_DB_PASSWORD: "unreachable",
        DEVICE_SN_DB_HOST: "127.0.0.1",
        DEVICE_SN_DB_PORT: "1",
        DEVICE_SN_DB_NAME: "unreachable",
        DEVICE_SN_DB_USER: "unreachable",
        DEVICE_SN_DB_PASSWORD: "unreachable",
      };
      for (const [name, value] of Object.entries(env)) vi.stubEnv(name, value);
    }, 30_000);
    afterEach(async () => {
      vi.restoreAllMocks();
      for (const app of apps.splice(0)) await app.close();
      await Promise.allSettled(connections.splice(0).map((c) => c.end()));
      if (database)
        await admin.query(`DROP DATABASE IF EXISTS \`${database}\``);
      vi.unstubAllEnvs();
    }, 30_000);
    afterAll(async () => {
      await admin?.end();
      if (build) await rm(build, { recursive: true, force: true });
      if (upgradeBuild)
        await rm(upgradeBuild, { recursive: true, force: true });
    }, 30_000);

    it("warms without any data or DDL change and seals every actual nonprobe controller route before other guards", async () => {
      const before = await tableSnapshot(),
        app = await boot();
      expect((await request(app, "/health/live")).body).toEqual({
        status: "alive",
        service: "identity-adapter",
      });
      expect(await request(app, "/health")).toMatchObject({
        status: 503,
        body: {
          code: "IDENTITY_SEALED",
          ready: false,
          accountAuthority: "staging",
          activation: { warmed: true, state: "sealed" },
        },
      });
      const controllers = Reflect.getMetadata(
        "controllers",
        compiled.AppModule,
      ) as Function[];
      const invalidDeviceToken = `e30.${Buffer.from(JSON.stringify({ auth_method: "device_sn", device_sn_id: 999 })).toString("base64url")}.invalid`;
      const probeHeaders = { authorization: `Bearer ${invalidDeviceToken}` };
      expect(
        (await request(app, "/health/live", "GET", undefined, probeHeaders))
          .status,
      ).toBe(200);
      expect(
        (await request(app, "/health", "GET", undefined, probeHeaders)).body
          ?.code,
      ).toBe("IDENTITY_SEALED");
      let checked = 0;
      for (const controller of controllers) {
        const roots = [Reflect.getMetadata(PATH_METADATA, controller)].flat();
        for (const name of Object.getOwnPropertyNames(controller.prototype)) {
          const handler = Object.getOwnPropertyDescriptor(
            controller.prototype,
            name,
          )?.value;
          if (
            typeof handler !== "function" ||
            !Reflect.hasMetadata(METHOD_METADATA, handler)
          )
            continue;
          if (
            Reflect.getMetadata("identity:activation-probe", handler) ||
            Reflect.getMetadata("identity:activation-probe", controller)
          )
            continue;
          const verb = Reflect.getMetadata(
            METHOD_METADATA,
            handler,
          ) as RequestMethod;
          const method =
            verb === RequestMethod.ALL ? "GET" : RequestMethod[verb];
          for (const prefix of roots)
            for (const suffix of [
              Reflect.getMetadata(PATH_METADATA, handler),
            ].flat()) {
              const path = `/${prefix ?? ""}/${suffix ?? ""}`
                .replace(/\/+/g, "/")
                .replace(/:[A-Za-z0-9_]+/g, "1");
              const response = await request(
                app,
                path,
                method,
                ["GET", "HEAD"].includes(method) ? undefined : {},
                {
                  authorization: `Bearer ${invalidDeviceToken}`,
                  "x-identity-internal-token":
                    process.env.IDENTITY_INTERNAL_API_TOKEN!,
                },
              );
              expect(response.status, `${method} ${path}`).toBe(503);
              if (method !== "HEAD")
                expect(response.body?.code, `${method} ${path}`).toBe(
                  "IDENTITY_SEALED",
                );
              checked++;
            }
        }
      }
      expect(checked).toBeGreaterThan(130);
      expect(await tableSnapshot()).toEqual(before);
      expect(await rows("identity_migration_allocator_state")).toHaveLength(0);
    }, 30_000);

    it("rejects a boot without the preinstalled receipt schema and creates nothing", async () => {
      await db.query("DROP TABLE identity_activation_receipt");
      const before = await tableSnapshot();
      await expect(boot()).rejects.toThrow("ACTIVATION_SCHEMA_REQUIRED");
      expect(await tableSnapshot()).toEqual(before);
    });

    it.each([
      [
        "credential column",
        "ALTER TABLE identity_legacy_refresh_credentials DROP COLUMN a1_compatible",
      ],
      [
        "refresh unique index",
        "ALTER TABLE identity_refresh_sessions DROP INDEX idx_identity_refresh_sessions_token_hash",
      ],
    ])(
      "rejects warmup with a missing %s without repairing schema or writing data",
      async (_label, sql) => {
        await db.query(sql);
        const before = await tableSnapshot();
        await expect(boot()).rejects.toThrow();
        expect(await tableSnapshot()).toEqual(before);
      },
    );

    it.each(["proof", "revision", "expired", "distant", "invalid-date"])(
      "rolls back a %s activation rejection",
      async (kind) => {
        await initializeFreshAllocator(db);
        const before = await tableSnapshot();
        const patch =
          kind === "proof"
            ? { expectedProofSha256: "0".repeat(64) }
            : kind === "revision"
              ? { expectedRevision: "c".repeat(40) }
              : {
                  deadline:
                    kind === "expired"
                      ? await deadline(-1000)
                      : kind === "distant"
                        ? await deadline(600_000)
                        : "2026-02-30T00:00:00.000Z",
                };
        const code = {
          proof: "ACTIVATION_PROOF_MISMATCH",
          revision: "ACTIVATION_REVISION_MISMATCH",
          expired: "ACTIVATION_DEADLINE_EXPIRED",
          distant: "ACTIVATION_DEADLINE_TOO_DISTANT",
          "invalid-date": "ACTIVATION_INVALID_DEADLINE",
        }[kind];
        await expect(activate(db, activation, patch)).rejects.toThrow(code);
        expect(await tableSnapshot()).toEqual(before);
      },
    );

    it("makes default dry-run readonly, commits exactly once concurrently, opens the warmed app and survives a reviewed revision upgrade", async () => {
      await initializeFreshAllocator(db);
      const before = await tableSnapshot(),
        app = await boot();
      expect((await activate(db, activation, { apply: false })).outcome).toBe(
        "dry_run",
      );
      expect(await tableSnapshot()).toEqual(before);
      const second = await connect(),
        until = await deadline();
      const results = await Promise.all([
        activate(db, activation, { deadline: until }),
        activate(second, activation, { deadline: until }),
      ]);
      expect(results.map((result) => result.outcome).sort()).toEqual([
        "activated",
        "already_active",
      ]);
      expect(results[0].receipt).toEqual(results[1].receipt);
      expect(
        (await activate(db, activation, { deadline: until })).outcome,
      ).toBe("already_active");
      await expect(
        activate(db, activation, {
          deadline: new Date(Date.parse(until) + 1000).toISOString(),
        }),
      ).rejects.toThrow("ACTIVATION_ALREADY_ACTIVE_DIFFERENT_REQUEST");
      expect(await rows("identity_activation_receipt")).toHaveLength(1);
      expect((await request(app, "/health")).status).toBe(200);
      expect((await request(app, "/v1/user/info")).status).toBe(401);
      const registered = await request(app, "/v1/auth/register", "POST", {
        username: "activated-user",
        password: "Activation-test!73",
      });
      expect(registered).toMatchObject({
        status: 201,
        body: { success: true },
      });
      const bearer = {
        authorization: `Bearer ${registered.body!.token.accessToken}`,
      };
      expect(
        (await request(app, "/v1/user/info", "GET", undefined, bearer)).status,
      ).toBe(200);
      const afterRegistration = await tableSnapshot();
      const upgradedApp = await boot(upgraded),
        status = await upgradedActivation.inspectExplicitActivation(second);
      expect(status).toMatchObject({
        authority: "identity",
        state: "active",
        receipt: { compiledRevision: revision },
      });
      expect((await request(upgradedApp, "/health")).body).toMatchObject({
        revision: upgradeRevision,
        activation: { ready: true },
      });
      await expect(activate(second, upgradedActivation)).rejects.toThrow(
        "ACTIVATION_ALREADY_ACTIVE_DIFFERENT_REQUEST",
      );
      expect(
        (await request(upgradedApp, "/v1/user/info", "GET", undefined, bearer))
          .status,
      ).toBe(200);
      expect(await tableSnapshot()).toEqual(afterRegistration);
      expect(await rows("identity_activation_receipt")).toHaveLength(1);
    });

    it("rejects a receipt decided exactly at its deadline even when the authority timestamp and request digest agree", async () => {
      await initializeFreshAllocator(db);
      await activate();
      await db.query(
        "UPDATE identity_activation_receipt SET decision_at=deadline WHERE id=1;UPDATE identity_migration_control SET activated_at=(SELECT deadline FROM identity_activation_receipt WHERE id=1) WHERE id=1",
      );
      const before = await tableSnapshot();
      await expect(activation.inspectExplicitActivation(db)).rejects.toThrow(
        "ACTIVATION_INVALID_RECEIPT",
      );
      await expect(boot()).rejects.toThrow("ACTIVATION_INVALID_RECEIPT");
      expect(await tableSnapshot()).toEqual(before);
    });

    it("refuses an already active database with no receipt instead of repairing or resealing it", async () => {
      await initializeFreshAllocator(db);
      await db.query(
        "UPDATE identity_migration_control SET authority='identity',activated_at=UTC_TIMESTAMP(3) WHERE id=1",
      );
      const before = await tableSnapshot();
      await expect(activation.inspectExplicitActivation(db)).rejects.toThrow(
        "ACTIVATION_RECEIPT_REQUIRED",
      );
      await expect(boot()).rejects.toThrow("ACTIVATION_RECEIPT_REQUIRED");
      expect(await tableSnapshot()).toEqual(before);
    });

    it("expires a delayed commit intent and rolls back both the receipt and authority in the actual transaction", async () => {
      await initializeFreshAllocator(db);
      const before = await tableSnapshot();
      let intentRan = false;
      await expect(
        activate(db, activation, {
          deadline: await deadline(3000),
          onCommitIntent: async () => {
            intentRan = true;
            expect(
              (await rows("identity_migration_control"))[0].authority,
            ).toBe("identity");
            await db.query("DO SLEEP(3.5)");
          },
        }),
      ).rejects.toThrow("ACTIVATION_DEADLINE_EXPIRED");
      expect(intentRan).toBe(true);
      expect(await tableSnapshot()).toEqual(before);
    }, 15_000);

    it("reports an actual committed but unacknowledged COMMIT as unknown and lets a new connection prove active", async () => {
      await initializeFreshAllocator(db);
      const commit = db.commit.bind(db);
      vi.spyOn(db, "commit").mockImplementation(async () => {
        await commit();
        throw new Error("Synthetic lost COMMIT acknowledgement");
      });
      const result = await activate();
      expect(result).toMatchObject({
        outcome: "unknown",
        authority: "unknown",
        errorCode: "ACTIVATION_COMMIT_RESULT_UNKNOWN",
      });
      const observer = await connect(),
        status = await activation.inspectExplicitActivation(observer);
      expect(status).toMatchObject({
        authority: "identity",
        state: "active",
        receipt: result.receipt,
      });
      expect((await request(await boot(), "/health")).status).toBe(200);
      expect(
        (
          await observer.query<RowDataPacket[]>(
            "SELECT COUNT(*) AS n FROM identity_activation_receipt",
          )
        )[0][0].n,
      ).toBe(1);
    });

    it("reports a late acknowledgement honestly and permits readonly restart after the activation deadline", async () => {
      await initializeFreshAllocator(db);
      const until = await deadline(3000),
        commit = db.commit.bind(db);
      const delayed = vi.spyOn(db, "commit").mockImplementation(async () => {
        await commit();
        await db.query("DO SLEEP(3.5)");
      });
      const result = await activate(db, activation, { deadline: until });
      delayed.mockRestore();
      expect(result).toMatchObject({
        outcome: "activated",
        authority: "identity",
        acknowledgementAfterDeadline: true,
      });
      const [clock] = await db.query<RowDataPacket[]>(
        "SELECT UTC_TIMESTAMP(3) AS now",
      );
      expect((clock[0].now as Date).getTime()).toBeGreaterThan(
        Date.parse(until),
      );
      const before = await tableSnapshot();
      expect((await request(await boot(), "/health")).status).toBe(200);
      expect(
        (await activate(db, activation, { deadline: until })).outcome,
      ).toBe("already_active");
      expect(await tableSnapshot()).toEqual(before);
    }, 15_000);

    it("reports a failed COMMIT without assuming cancellation and lets a new connection prove sealed", async () => {
      await initializeFreshAllocator(db);
      vi.spyOn(db, "commit").mockRejectedValue(
        new Error("Synthetic failure before COMMIT reaches MySQL"),
      );
      const result = await activate();
      expect(result).toMatchObject({
        outcome: "unknown",
        authority: "unknown",
        errorCode: "ACTIVATION_COMMIT_RESULT_UNKNOWN",
      });
      const observer = await connect(),
        status = await activation.inspectExplicitActivation(observer);
      expect(status).toMatchObject({
        authority: "staging",
        state: "sealed",
        receipt: null,
      });
      expect((await request(await boot(), "/health")).status).toBe(503);
      expect(
        (
          await observer.query<RowDataPacket[]>(
            "SELECT COUNT(*) AS n FROM identity_activation_receipt",
          )
        )[0][0].n,
      ).toBe(0);
    });

    it("does not commit an activation from a caller transaction", async () => {
      await initializeFreshAllocator(db);
      await db.beginTransaction();
      await db.query(
        "INSERT INTO user(id,username,status) VALUES(99,'uncommitted-activation-caller',10)",
      );
      await expect(activate()).rejects.toThrow();
      await db.rollback();
      expect(await rows("user")).toHaveLength(0);
      expect(await rows("identity_activation_receipt")).toHaveLength(0);
      expect((await rows("identity_migration_control"))[0].authority).toBe(
        "staging",
      );
    });

    it("rolls back a failed durable intent before sending COMMIT", async () => {
      await initializeFreshAllocator(db);
      const before = await tableSnapshot();
      await expect(
        activate(db, activation, {
          onCommitIntent: async () => {
            throw new Error("Synthetic fsync failure");
          },
        }),
      ).rejects.toThrow("Synthetic fsync failure");
      expect(await tableSnapshot()).toEqual(before);
      expect(await rows("identity_activation_receipt")).toHaveLength(0);
      expect((await rows("identity_migration_control"))[0].authority).toBe(
        "staging",
      );
    });

    it("keeps the public CLI fixed to development and rejects a fixture target before opening a report or connection", async () => {
      const cli = join(build, "scripts/identity-activate.js"),
        report = join(build, `uncreated-${randomUUID()}.jsonl`);
      expect(
        (
          await execute(process.execPath, [cli, "--help"], {
            cwd: root,
            timeout: 10_000,
          })
        ).stdout,
      ).toContain("Default: dry-run");
      const failure = await execute(
        process.execPath,
        [
          cli,
          "--expected-proof-sha256=" + "0".repeat(64),
          "--expected-revision=" + revision,
          "--deadline=" + (await deadline()),
          "--report=" + report,
        ],
        {
          cwd: root,
          timeout: 10_000,
          env: { ...process.env, IDENTITY_DB_PASSWORD: "must-never-be-logged" },
        },
      ).catch((error) => error);
      expect(failure.code).toBe(1);
      expect(failure.stderr).toContain(
        "ACTIVATION_FIXED_DEVELOPMENT_TARGET_REQUIRED",
      );
      expect(failure.stderr).not.toContain("must-never-be-logged");
      await expect(stat(report)).rejects.toMatchObject({ code: "ENOENT" });
      expect(await rows("identity_activation_receipt")).toHaveLength(0);
    });
  },
);
