import "reflect-metadata";
import {
  frozenAdmissionProtocolDirectory,
  verifyAdmissionProtocolSnapshot,
} from "./support/admission-protocol-fixture.js";
import { execFile } from "node:child_process";
import {
  generateKeyPairSync,
  randomBytes,
  randomUUID,
  createHash,
} from "node:crypto";
import { mkdtemp, readFile, writeFile, rm, chmod } from "node:fs/promises";
import { createServer, request as rawRequest } from "node:http";
import { once } from "node:events";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";
import {
  Controller,
  Get,
  Post,
  Req,
  Res,
  Inject,
  type INestApplication,
} from "@nestjs/common";
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

const enabled = process.env.IDENTITY_TEST_MYSQL === "1",
  root = fileURLToPath(new URL("../../../", import.meta.url)),
  revision = "a".repeat(40);
const options = {
  host: process.env.IDENTITY_TEST_MYSQL_HOST ?? "127.0.0.1",
  port: Number(process.env.IDENTITY_TEST_MYSQL_PORT ?? 13316),
  user: process.env.IDENTITY_TEST_MYSQL_USER ?? "root",
  password: process.env.IDENTITY_TEST_MYSQL_PASSWORD ?? "",
  timezone: "Z",
  multipleStatements: true,
};
const driver = frozenAdmissionProtocolDirectory;
const execute = promisify(execFile),
  pause = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
async function until(check: () => boolean | Promise<boolean>) {
  const deadline = Date.now() + 5000;
  while (!(await check())) {
    if (Date.now() > deadline) throw new Error("Fixture wait expired");
    await pause(10);
  }
}
const gate = () => {
  let resolve!: () => void;
  const promise = new Promise<void>((r) => (resolve = r));
  return { promise, resolve };
};

describe.skipIf(!enabled)(
  "compiled Native admission and real writer lifetime",
  () => {
    let admin: Connection,
      db: Connection,
      database: string,
      build: string,
      compiled: any,
      api: any,
      adapter: any,
      activation: any,
      allocator: any,
      Repo: any,
      Jwt: any,
      Mail: any,
      protocol: any,
      transport: any;
    let app: INestApplication | undefined,
      coordinator: any,
      control: any,
      keys: Map<string, Buffer>,
      roster: any[],
      runtime: any,
      base: string;
    let repository: any,
      pending: Promise<unknown> | null,
      late: string,
      childServer: ReturnType<typeof createServer> | undefined,
      childClient: any,
      childGate: ReturnType<typeof gate>,
      childCalls: number;
    let proxy: ReturnType<typeof createServer> | undefined,
      dropComplete: boolean,
      completeCalls: number;
    let controlFault:
        | "drop"
        | "500"
        | "journal"
        | "malformed"
        | "unknown-refusal"
        | "delay-enter"
        | null,
      enterGate: ReturnType<typeof gate>,
      enterSeen: boolean;
    let originalProviders: unknown[];
    const password = "Admission-fixture!75",
      internal = randomBytes(32).toString("hex");

    class TailController {
      tail(req: any, res: any) {
        pending = repository
          .register(
            { username: String(req.body.username), password },
            String(req.body.username),
          )
          .catch(() => undefined);
        res.json({ accepted: true });
      }
      late() {
        setTimeout(() => {
          void (async () => {
            try {
              await repository.register({
                username: "must-not-write",
                password,
              });
              late = "wrote";
            } catch {
              late = "rejected";
            }
          })();
        }, 30);
        return { accepted: true };
      }
      echo(req: any) {
        return {
          forged: Object.keys(req.headers).some((k) =>
            /admission|continuation|^x-identity-instance/.test(k),
          ),
        };
      }
      async fail() {
        await repository.register({ username: "rollback-fixture", password });
        await repository.register({ username: "rollback-fixture", password });
      }
      async child() {
        const response = await api.admissionFetch(
          `http://127.0.0.1:${(childServer!.address() as any).port}/work`,
          {
            method: "POST",
            headers: { "x-identity-internal-token": internal },
          },
        );
        await response.text();
        return { ok: true };
      }
      async wrongChild() {
        await api.admissionFetch(
          `http://127.0.0.1:${(childServer!.address() as any).port}/not-reviewed`,
          {
            method: "POST",
            headers: { "x-identity-internal-token": internal },
          },
        );
        return { ok: true };
      }
      async email() {
        await app!.get(Mail).sendEmailVerificationCode({
          email: "fixture@example.test",
          code: "123456",
        });
        return { ok: true };
      }
    }
    Controller("admission-fixture")(TailController);
    for (const name of ["tail", "late", "fail", "child", "wrongChild", "email"])
      (Post(name) as any)(
        TailController.prototype,
        name,
        Object.getOwnPropertyDescriptor(TailController.prototype, name),
      );
    Get("echo")(
      TailController.prototype,
      "echo",
      Object.getOwnPropertyDescriptor(TailController.prototype, "echo")!,
    );
    Req()(TailController.prototype, "tail", 0);
    Res()(TailController.prototype, "tail", 1);
    Req()(TailController.prototype, "echo", 0);
    async function count(table = "user") {
      return Number(
        (
          await db.query<RowDataPacket[]>(`SELECT COUNT(*) AS n FROM ${table}`)
        )[0][0].n,
      );
    }
    async function snapshot() {
      const [tables] = await db.query<RowDataPacket[]>("SHOW TABLES");
      const hashes: Record<string, string> = {};
      for (const row of tables) {
        const name = String(Object.values(row)[0]);
        const [rows] = await db.query(`SELECT * FROM \`${name}\``);
        const [ddl] = await db.query<any[]>(`SHOW CREATE TABLE \`${name}\``);
        hashes[name] = createHash("sha256")
          .update(JSON.stringify([rows, ddl]))
          .digest("hex");
      }
      return hashes;
    }
    async function http(
      path: string,
      method = "GET",
      body?: unknown,
      headers: Record<string, string> = {},
    ) {
      const response = await fetch(base + path, {
        method,
        headers: {
          ...(body === undefined ? {} : { "content-type": "application/json" }),
          ...headers,
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      });
      const raw = await response.text();
      return { status: response.status, body: raw ? JSON.parse(raw) : null };
    }
    async function setupControl(fault: typeof controlFault = null) {
      childGate = gate();
      childCalls = 0;
      controlFault = fault;
      dropComplete = fault === "drop";
      completeCalls = 0;
      enterGate = gate();
      enterSeen = false;
      childServer = createServer(async (req, res) => {
        childCalls++;
        if (req.headers["x-identity-internal-token"] !== internal) {
          res.writeHead(401).end();
          return;
        }
        const cap = req.headers["x-identity-admission-lease"];
        try {
          await childClient.enter(cap);
          res.writeHead(200).end("accepted");
          await childGate.promise;
          await childClient.complete(cap, {
            handlerFinished: true,
            sideEffectsFinished: true,
            sessionWriteClosed: true,
          });
        } catch {
          res.destroy();
        }
      });
      childServer.listen(0, "127.0.0.1");
      await once(childServer, "listening");
      const member = (
        id: string,
        generation: string,
        allowedChildren: string[] = [],
      ) => ({
        id,
        bootId: `${id}-boot-0001`,
        revision,
        routerHash: "b".repeat(64),
        generation,
        requiresSessionClose: false,
        allowedChildren,
      });
      roster = [
        member("native-old", "legacy", ["provider-old"]),
        member("provider-old", "legacy"),
        member("native-new", "identity"),
      ];
      coordinator = new protocol.AdmissionCoordinator({
        roster,
        routers: [
          {
            id: "edge-old",
            bootId: "edge-old-boot-0001",
            routerHash: "c".repeat(64),
          },
        ],
        identityInstanceId: "native-new",
        journal: protocol.memoryFixtureJournal(),
        capabilityKey: randomBytes(32),
      });
      keys = new Map(roster.map((i) => [i.id, randomBytes(32)]));
      control = await transport.startControlServer({
        coordinator,
        operatorKey: randomBytes(32),
        participantKeys: keys,
      });
      for (const item of roster.slice(1)) await coordinator.register(item);
      childClient = protocol.participantClient({
        controlUrl: control.url,
        key: keys.get("provider-old"),
        identity: roster[1],
      });
      let controlUrl = control.url;
      if (fault) {
        proxy = createServer((req, res) => {
          void (async () => {
            const chunks: Buffer[] = [];
            for await (const chunk of req) chunks.push(Buffer.from(chunk));
            if (req.url === "/unknown" && controlFault === "unknown-refusal") {
              res
                .writeHead(409, { "content-type": "application/json" })
                .end(JSON.stringify({ code: "OPERATION_NOT_ACTIVE" }));
              return;
            }
            const response = await fetch(new URL(req.url!, control.url), {
              method: "POST",
              headers: req.headers as any,
              body: Buffer.concat(chunks),
            });
            const value = await response.text();
            if (req.url === "/enter" && controlFault === "delay-enter") {
              enterSeen = true;
              await enterGate.promise;
            }
            if (req.url === "/complete") {
              completeCalls++;
              if (dropComplete) {
                dropComplete = false;
                res.destroy();
                return;
              }
              if (controlFault === "500" || controlFault === "journal") {
                res
                  .writeHead(controlFault === "500" ? 500 : 409, {
                    "content-type": "application/json",
                  })
                  .end(
                    JSON.stringify({ code: "JOURNAL_RESULT_UNKNOWN_SEALED" }),
                  );
                return;
              }
              if (controlFault === "malformed") {
                res
                  .writeHead(200, { "content-type": "application/json" })
                  .end(JSON.stringify({ accepted: true }));
                return;
              }
            }
            res
              .writeHead(response.status, {
                "content-type": "application/json",
              })
              .end(value);
          })().catch(() => res.destroy());
        });
        proxy.listen(0, "127.0.0.1");
        await once(proxy, "listening");
        controlUrl = `http://127.0.0.1:${(proxy.address() as any).port}/`;
      }
      runtime = new api.IdentityAdmission(
        {
          version: 1,
          controlUrl,
          identity: (({ requiresSessionClose, allowedChildren, ...identity }) =>
            identity)(roster[0]),
          allowedChildren: [
            {
              id: "provider-old",
              origin: `http://127.0.0.1:${(childServer.address() as any).port}`,
              paths: ["/work"],
            },
          ],
          childWaitMs: 1500,
        },
        keys.get("native-old"),
      );
    }
    async function boot(
      active = true,
      fault: typeof controlFault = null,
      explicitWarm = true,
    ) {
      if (active) {
        const [p] = await db.query<RowDataPacket[]>(
          "SELECT manifest_sha256 FROM identity_migration_allocator_state WHERE id=1",
        );
        await activation.activateExplicitIdentity({
          connection: db,
          expectedRevision: revision,
          expectedProofSha256: p[0].manifest_sha256,
          deadline: new Date(Date.now() + 60000).toISOString(),
          apply: true,
        });
      }
      await setupControl(fault);
      vi.stubEnv("IDENTITY_ADMISSION_ENABLED", "true");
      app = await runtime.bootstrap(async () => {
        const instance = await NestFactory.create(
          compiled.AppModule,
          new adapter.IdentityAdmissionExpressAdapter(runtime),
          { logger: false, abortOnError: false },
        );
        app = instance;
        instance.enableCors({ origin: "https://admission-fixture.test" });
        await instance.init();
        return instance;
      }, explicitWarm);
      repository = app!.get(Repo);
      await app!.listen(0, "127.0.0.1");
      base = await app!.getUrl();
    }
    async function closeAcks() {
      for (const identity of roster.filter((i) => i.generation === "legacy")) {
        const row = coordinator
          .status()
          .instances.find((r: any) => r.id === identity.id);
        await coordinator.acknowledgeClose(identity, {
          epoch: coordinator.status().epoch,
          lastBegin: row.lastBegin,
          lastEnd: row.lastEnd,
        });
      }
    }
    function startupWriter() {
      class BootWriter {
        constructor(readonly repo: any) {}
        async onModuleInit() {
          await this.repo.register({ username: "startup-writer", password });
        }
      }
      Inject(Repo)(BootWriter, undefined, 0);
      Reflect.defineMetadata(
        "providers",
        [...originalProviders, BootWriter],
        compiled.AppModule,
      );
    }

    beforeAll(async () => {
      await verifyAdmissionProtocolSnapshot();
      if (
        options.host !== "127.0.0.1" ||
        (options.port !== 13316 &&
          !(
            options.port === 3306 &&
            (process.env.CI === "true" || process.env.GITHUB_ACTIONS === "true")
          ))
      )
        throw new Error("Dedicated local or CI MySQL required");
      build = await mkdtemp(join(root, ".identity-admission-build-"));
      await execute(
        process.execPath,
        [
          join(root, "node_modules/typescript/bin/tsc"),
          "--outDir",
          build,
          "--noEmitOnError",
          "true",
        ],
        { cwd: root, timeout: 90000, maxBuffer: 1024 * 1024 },
      );
      await writeFile(
        join(
          build,
          "apps/identity-adapter/src/generated/iam-organization-reconciliation-compiled-revision.js",
        ),
        `export const ORGANIZATION_RECONCILIATION_COMPILED_BUILD_REVISION=${JSON.stringify(revision)};\n`,
      );
      const load = (name: string) =>
        import(
          pathToFileURL(join(build, `apps/identity-adapter/src/${name}.js`))
            .href
        );
      [compiled, api, adapter, activation, allocator] = await Promise.all([
        load("app.module"),
        load("identity-admission"),
        load("identity-admission-express"),
        load("identity-activation"),
        load("identity-allocator-state"),
      ]);
      Repo = (await load("account-registration.repository"))
        .AccountRegistrationRepository;
      Jwt = (await load("jwt-issuer.service")).JwtIssuerService;
      Mail = (await load("email-delivery.service")).EmailDeliveryService;
      Reflect.defineMetadata(
        "controllers",
        [
          ...Reflect.getMetadata("controllers", compiled.AppModule),
          TailController,
        ],
        compiled.AppModule,
      );
      originalProviders = Reflect.getMetadata("providers", compiled.AppModule);
      protocol = {
        ...(await import(pathToFileURL(join(driver, "coordinator.mjs")).href)),
        ...(await import(pathToFileURL(join(driver, "journal.mjs")).href)),
        ...(await import(
          pathToFileURL(join(driver, "participant-client.mjs")).href
        )),
      };
      transport = await import(pathToFileURL(join(driver, "gateway.mjs")).href);
      admin = await mysql.createConnection(options);
    }, 120000);
    beforeEach(async () => {
      vi.stubEnv("IDENTITY_ADMISSION_ENABLED", "false");
      database = `test_native_admission_${randomUUID().replaceAll("-", "")}`;
      await admin.query(
        `CREATE DATABASE \`${database}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`,
      );
      db = await mysql.createConnection({ ...options, database });
      const init = await readFile(join(root, "deploy/mysql/init.sql"), "utf8");
      await db.query(
        init.slice(
          init.indexOf("CREATE TABLE IF NOT EXISTS `auth_login_events`"),
        ),
      );
      for (const name of [
        "identity-account-schema.sql",
        "identity-password-reset-token-schema.sql",
        "identity-legacy-challenge-schema.sql",
        "identity-runtime-schema.sql",
        "identity-wechat-oauth-schema.sql",
        "identity-qrcode-schema.sql",
        "identity-apple-schema.sql",
        "identity-allocator-schema.sql",
        "identity-activation-schema.sql",
        "identity-legacy-refresh-graph-schema.sql",
      ])
        await db.query(
          await readFile(join(root, "deploy/mysql", name), "utf8"),
        );
      await allocator.initializeFreshAllocator(db);
      const key = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
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
        IDENTITY_INTERNAL_API_TOKEN: internal,
        IDENTITY_IAM_INTERNAL_API_TOKEN: internal,
        IDENTITY_TOKEN_ISSUANCE_INTERNAL_API_TOKEN: internal,
        IDENTITY_JWT_PRIVATE_KEY_PEM: key.privateKey
          .export({ type: "pkcs8", format: "pem" })
          .toString(),
        IDENTITY_JWT_PUBLIC_KEY_PEM: key.publicKey
          .export({ type: "spki", format: "pem" })
          .toString(),
        IDENTITY_JWT_ISSUER: "https://admission-fixture.test",
        IDENTITY_JWT_AUDIENCE: "admission-fixture",
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
      for (const [k, v] of Object.entries(env)) vi.stubEnv(k, v);
      pending = null;
      late = "";
    }, 30000);
    afterEach(async () => {
      childGate?.resolve();
      enterGate?.resolve();
      await pending;
      await app?.close();
      app = undefined;
      Reflect.defineMetadata(
        "providers",
        originalProviders,
        compiled.AppModule,
      );
      for (const server of [childServer, proxy])
        if (server) {
          server.closeAllConnections();
          await new Promise<void>((resolve) => server.close(() => resolve()));
        }
      childServer = proxy = undefined;
      await control?.close();
      control = undefined;
      await db?.end();
      if (database)
        await admin.query(`DROP DATABASE IF EXISTS \`${database}\``);
      vi.unstubAllEnvs();
      vi.restoreAllMocks();
    }, 30000);
    afterAll(async () => {
      await admin?.end();
      if (build) await rm(build, { recursive: true, force: true });
    }, 30000);

    it("default off ignores absent admission credentials and preserves the original writer path", async () => {
      vi.stubEnv("IDENTITY_ADMISSION_CONFIG_FILE", "/missing");
      expect(api.IdentityAdmission.environment()).toBeNull();
      const repo = new Repo();
      try {
        await repo.register({ username: "default-off", password });
        expect(await count()).toBe(1);
      } finally {
        await repo.onModuleDestroy();
      }
    });
    it("direct writers and official mutation CLI functions fail before SQL without a verified scope", async () => {
      vi.stubEnv("IDENTITY_ADMISSION_ENABLED", "true");
      const before = await snapshot(),
        repo = new Repo();
      try {
        const signer = new Jwt();
        expect(() => signer.issue({}, "unadmitted")).toThrow();
        expect(() => signer.issueOidcIdToken({})).toThrow();
        expect(() =>
          repo.register({ username: "not-admitted", password }),
        ).toThrow();
        await expect(
          activation.activateExplicitIdentity({ connection: db }),
        ).rejects.toThrow();
        expect(await snapshot()).toEqual(before);
      } finally {
        await repo.onModuleDestroy();
      }
    });
    it("enabled configuration requires immutable revision and protected existing key bytes", async () => {
      await setupControl();
      vi.stubEnv("IDENTITY_ADMISSION_ENABLED", "true");
      const dir = await mkdtemp(join(root, ".identity-admission-config-")),
        config = join(dir, "config.json"),
        key = join(dir, "key");
      try {
        await writeFile(config, JSON.stringify(runtime.configuration), {
          mode: 0o600,
        });
        await writeFile(key, keys.get("native-old")!.toString("base64url"), {
          mode: 0o600,
        });
        vi.stubEnv("IDENTITY_ADMISSION_CONFIG_FILE", config);
        vi.stubEnv("IDENTITY_ADMISSION_KEY_FILE", key);
        const loaded = api.IdentityAdmission.environment();
        expect(loaded.configuration.identity.revision).toBe(revision);
        await loaded.register();
        expect(() => new api.AdmissionScope(loaded, null, true)).toThrow();
        await chmod(key, 0o644);
        expect(() => api.IdentityAdmission.environment()).toThrow();
        await chmod(key, 0o600);
        const invalid = Buffer.from(
          keys.get("native-old")!.toString("base64url"),
        );
        invalid[0] |= 0x80;
        await writeFile(key, invalid);
        expect(() => api.IdentityAdmission.environment()).toThrow();
        await writeFile(key, keys.get("native-old")!.toString("base64url"));
        await writeFile(
          config,
          JSON.stringify({
            ...runtime.configuration,
            identity: {
              ...runtime.configuration.identity,
              revision: "b".repeat(40),
            },
          }),
        );
        expect(() => api.IdentityAdmission.environment()).toThrow();
        expect(await count()).toBe(0);
      } finally {
        await rm(dir, { recursive: true, force: true });
      }
    });
    it("warm bootstrap and sealed real routes create no account, session, event or schema writes", async () => {
      const before = await snapshot();
      await boot(false);
      expect((await http("/health/live")).status).toBe(200);
      expect((await http("/health")).status).toBe(503);
      expect(
        (
          await http("/v1/auth/register", "POST", {
            username: "sealed",
            password,
          })
        ).status,
      ).toBe(503);
      await until(() => coordinator.status().active === 0);
      expect(await snapshot()).toEqual(before);
    });
    it("the first global guard rejects an alternate Nest bootstrap without the entry adapter", async () => {
      await boot();
      const before = await snapshot();
      const alternate = await NestFactory.create(compiled.AppModule, {
        logger: false,
        abortOnError: false,
      });
      try {
        await alternate.listen(0, "127.0.0.1");
        const origin = await alternate.getUrl();
        for (const [path, method] of [
          ["/health/live", "GET"],
          ["/admission-fixture/echo", "GET"],
          ["/v1/auth/register", "POST"],
        ]) {
          const response = await fetch(origin + path, {
            method,
            ...(method === "POST"
              ? {
                  headers: { "content-type": "application/json" },
                  body: JSON.stringify({ username: "alternate", password }),
                }
              : {}),
          });
          expect(response.status).toBe(503);
          expect(((await response.json()) as any).code).toBe(
            "ADMISSION_HANDLER_SCOPE_REQUIRED",
          );
        }
        expect(await snapshot()).toEqual(before);
        expect(coordinator.status().active).toBe(0);
      } finally {
        await alternate.close();
      }
    });
    it("a client disconnected during enter acknowledgement never reaches its business writer", async () => {
      await boot(true, "delay-enter");
      const request = rawRequest(base + "/v1/auth/register", {
        method: "POST",
        headers: { "content-type": "application/json" },
      });
      request.on("error", () => {});
      request.end(JSON.stringify({ username: "before-enter-ack", password }));
      await until(() => enterSeen);
      request.destroy();
      await pause(50);
      enterGate.resolve();
      await until(() => coordinator.status().unknown > 0);
      expect(await count()).toBe(0);
      expect(await count("identity_refresh_sessions")).toBe(0);
    });
    it("a standby module init writer is denied without any HTTP or SQL write", async () => {
      const before = await snapshot();
      startupWriter();
      await expect(boot(false)).rejects.toThrow();
      expect(await snapshot()).toEqual(before);
      expect(coordinator.status().active).toBe(0);
    });
    it("a legacy startup writer uses a separate entered scope and finishes before listen", async () => {
      startupWriter();
      await boot(true, null, false);
      expect(await count()).toBe(1);
      expect(coordinator.status().active).toBe(0);
      const row = coordinator
        .status()
        .instances.find((r: any) => r.id === "native-old");
      expect(row.lastBegin).toBe(1);
      expect(row.lastEnd).toBe(1);
    });
    it("real Nest login/logout/guards and parser errors finish their handler lease; probes stay read only", async () => {
      await boot();
      expect(
        (await http("/admission-fixture/tail", "POST", { username: "normal" }))
          .status,
      ).toBe(201);
      await pending;
      await until(() => coordinator.status().active === 0);
      const login = await http("/v1/auth/login", "POST", {
        username: "normal",
        password,
      });
      expect(login.status).toBe(201);
      expect(login.body.token.accessToken).toEqual(expect.any(String));
      expect(
        (
          await http("/v1/auth/logout", "POST", {
            refreshToken: login.body.token.refreshToken,
          })
        ).status,
      ).toBe(201);
      await until(() => coordinator.status().active === 0);
      const invalid = await fetch(base + "/v1/auth/login", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{",
      });
      expect(invalid.status).toBe(400);
      await until(() => coordinator.status().active === 0);
      expect(
        (
          await http("/v1/auth/login", "OPTIONS", undefined, {
            origin: "https://admission-fixture.test",
            "access-control-request-method": "POST",
          })
        ).status,
      ).toBe(204);
      await until(() => coordinator.status().active === 0);
      expect(
        (
          await http("/admission-fixture/echo", "GET", undefined, {
            "x-identity-instance-id": "forged",
            "x-continuation": "forged",
          })
        ).body.forged,
      ).toBe(false);
      await until(() => coordinator.status().active === 0);
      await coordinator.close();
      expect((await http("/health/live")).status).toBe(200);
      expect((await http("/admission-fixture/echo")).status).toBe(503);
    });
    it("HTTP response end cannot complete an unawaited real transaction before commit and release finally", async () => {
      await boot();
      const lock = await mysql.createConnection({ ...options, database });
      try {
        await lock.beginTransaction();
        await lock.query(
          "SELECT id FROM identity_event_clock WHERE id=1 FOR UPDATE",
        );
        const r = await http("/admission-fixture/tail", "POST", {
          username: "async-tail",
        });
        expect(r.body.accepted).toBe(true);
        await pause(50);
        expect(coordinator.status().active).toBe(1);
        expect(await count()).toBe(0);
        await coordinator.close();
        await closeAcks();
        expect(coordinator.status().phase).toBe("closing");
        await lock.rollback();
        await pending;
        await until(() => coordinator.status().active === 0);
        await closeAcks();
        expect(coordinator.status().phase).toBe("drained");
        expect(await count()).toBe(1);
      } finally {
        await lock.rollback();
        await lock.end();
      }
    });
    it("a timed-out registered transaction can finish but cannot clear its unknown latch", async () => {
      await boot();
      const lock = await mysql.createConnection({ ...options, database });
      try {
        await lock.beginTransaction();
        await lock.query(
          "SELECT id FROM identity_event_clock WHERE id=1 FOR UPDATE",
        );
        await http("/admission-fixture/tail", "POST", {
          username: "late-transaction",
        });
        await until(() => coordinator.status().unknown > 0);
        expect(await count()).toBe(0);
        await lock.rollback();
        await pending;
        expect(await count()).toBe(1);
        expect(coordinator.status().unknown).toBeGreaterThan(0);
        await coordinator.close();
        await closeAcks();
        expect(coordinator.status().phase).toBe("closing");
      } finally {
        await lock.rollback();
        await lock.end();
      }
    });
    it("a disconnected client leaves unknown after the real handler eventually commits", async () => {
      await boot();
      const lock = await mysql.createConnection({ ...options, database });
      try {
        await lock.beginTransaction();
        await lock.query(
          "SELECT id FROM identity_event_clock WHERE id=1 FOR UPDATE",
        );
        const request = rawRequest(base + "/v1/auth/register", {
          method: "POST",
          headers: { "content-type": "application/json" },
        });
        request.on("error", () => {});
        request.end(JSON.stringify({ username: "aborted", password }));
        await until(() => coordinator.status().active === 1);
        // Prove the actual transaction reached its lock before disconnecting.
        await until(async () => {
          const [rows] = await admin.query<RowDataPacket[]>(
            "SELECT ID FROM information_schema.PROCESSLIST WHERE DB=? AND INFO LIKE 'SELECT id FROM identity_event_clock%'",
            [database],
          );
          return rows.length > 0;
        });
        request.destroy();
        await until(() => coordinator.status().unknown > 0);
        await lock.rollback();
        await until(async () => (await count()) === 1);
        await pause(100);
        expect(coordinator.status().unknown).toBeGreaterThan(0);
        await coordinator.close();
        await closeAcks();
        expect(coordinator.status().phase).toBe("closing");
      } finally {
        await lock.rollback();
        await lock.end();
      }
    });
    it("a killed real SQL writer and failed rollback retain unknown rather than a false complete", async () => {
      await boot();
      const lock = await mysql.createConnection({ ...options, database });
      try {
        await lock.beginTransaction();
        await lock.query(
          "SELECT id FROM identity_event_clock WHERE id=1 FOR UPDATE",
        );
        await http("/admission-fixture/tail", "POST", { username: "sql-lost" });
        let connectionId = 0;
        await until(async () => {
          const [rows] = await admin.query<RowDataPacket[]>(
            "SELECT ID FROM information_schema.PROCESSLIST WHERE DB=? AND INFO LIKE 'SELECT id FROM identity_event_clock%'",
            [database],
          );
          connectionId = Number(rows[0]?.ID ?? 0);
          return connectionId > 0;
        });
        await admin.query(`KILL CONNECTION ${connectionId}`);
        await pending;
        await until(() => coordinator.status().unknown > 0);
        expect(await count()).toBe(0);
        await coordinator.close();
        await closeAcks();
        expect(coordinator.status().phase).toBe("closing");
      } finally {
        await lock.rollback();
        await lock.end();
      }
    });
    it("a task scheduled after the handler has completed cannot start a later writer", async () => {
      await boot();
      await http("/admission-fixture/late", "POST", {});
      await until(() => late !== "");
      expect(late).toBe("rejected");
      expect(await count()).toBe(0);
      await until(() => coordinator.status().active === 0);
    });
    it("a real failed registration rolls back and an invalid or reused capability never enters twice", async () => {
      await boot();
      expect((await http("/admission-fixture/fail", "POST", {})).status).toBe(
        500,
      );
      await until(() => coordinator.status().active === 0);
      expect(await count()).toBe(1);
      const cap = await runtime.call("begin");
      expect(
        (
          await http("/admission-fixture/echo", "GET", undefined, {
            "x-identity-admission-lease": cap.capability,
          })
        ).status,
      ).toBe(200);
      await until(() => coordinator.status().active === 0);
      expect(
        (
          await http("/admission-fixture/echo", "GET", undefined, {
            "x-identity-admission-lease": cap.capability,
          })
        ).status,
      ).toBe(503);
      expect(coordinator.status().unknown).toBe(0);
    });
    it("duplicate lease headers are rejected before any begin or handler", async () => {
      await boot();
      const status = await new Promise<number>((resolve, reject) => {
        const request = rawRequest(
          base + "/admission-fixture/echo",
          {
            headers: {
              "X-Identity-Admission-Lease": [
                "fake.signature",
                "fake.signature",
              ],
            },
          },
          (response) => {
            response.resume();
            resolve(response.statusCode!);
          },
        );
        request.on("error", reject);
        request.end();
      });
      expect(status).toBe(503);
      expect(coordinator.status().active).toBe(0);
      expect(
        coordinator.status().instances.find((r: any) => r.id === "native-old")
          .lastBegin,
      ).toBe(0);
    });
    it("health enters and completes a provided gateway lease and rejects a forged one", async () => {
      await boot();
      const cap = await runtime.call("begin");
      expect(
        (
          await http("/health/live", "GET", undefined, {
            "x-identity-admission-lease": String(cap.capability),
          })
        ).status,
      ).toBe(200);
      await until(() => coordinator.status().active === 0);
      expect(
        coordinator.status().instances.find((r: any) => r.id === "native-old")
          .lastEnd,
      ).toBe(1);
      expect(
        (
          await http("/health/live", "GET", undefined, {
            "x-identity-admission-lease": "fake.signature",
          })
        ).status,
      ).toBe(503);
      expect(coordinator.status().unknown).toBe(0);
    });
    it("a child HTTP response is not its completion RPC and the parent waits for childrenActive zero", async () => {
      await boot();
      expect((await http("/admission-fixture/child", "POST", {})).status).toBe(
        201,
      );
      expect(childCalls).toBe(1);
      await pause(50);
      expect(coordinator.status().active).toBe(2);
      childGate.resolve();
      await until(() => coordinator.status().active === 0);
    });
    it("unreviewed child URLs fail before a continuation or network request", async () => {
      await boot();
      expect(
        (await http("/admission-fixture/wrongChild", "POST", {})).status,
      ).toBe(503);
      await until(() => coordinator.status().active === 0);
      expect(childCalls).toBe(0);
      expect(coordinator.status().unknown).toBe(0);
    });
    it("a handler cannot begin a child after its original monotonic budget has expired", async () => {
      await boot();
      const scope = await runtime.enter();
      await scope.run(async () => {
        await pause(1550);
        await expect(
          api.admissionFetch(
            `http://127.0.0.1:${(childServer!.address() as any).port}/work`,
            { method: "POST" },
          ),
        ).rejects.toThrow();
      });
      await expect(scope.finish()).rejects.toThrow();
      expect(childCalls).toBe(0);
      expect(
        coordinator.status().instances.find((r: any) => r.id === "provider-old")
          .lastBegin,
      ).toBe(0);
      expect(coordinator.status().unknown).toBeGreaterThan(0);
    });
    it("a child completion deadline leaves permanent parent uncertainty despite a late child complete", async () => {
      await boot();
      await http("/admission-fixture/child", "POST", {});
      await until(() => coordinator.status().unknown > 0);
      childGate.resolve();
      await until(() => coordinator.status().active === 0);
      expect(coordinator.status().unknown).toBeGreaterThan(0);
      await coordinator.close();
      await closeAcks();
      expect(coordinator.status().phase).toBe("closing");
    });
    it("lost complete ACK is never retried and cannot reopen the instance or erase uncertainty", async () => {
      await boot(true, "drop");
      await http("/admission-fixture/tail", "POST", {
        username: "lost-complete",
      });
      await pending;
      await until(() => coordinator.status().unknown > 0);
      expect(completeCalls).toBe(1);
      expect(await count()).toBe(1);
      expect((await http("/admission-fixture/echo")).status).toBe(503);
      await expect(runtime.register()).rejects.toThrow();
    });
    it.each(["500", "journal", "malformed"] as const)(
      "a %s response after actual complete permanently loses the instance",
      async (fault) => {
        await boot(true, fault);
        await http("/admission-fixture/tail", "POST", {
          username: `completed-${fault}`,
        });
        await pending;
        await until(() => coordinator.status().unknown > 0);
        expect(completeCalls).toBe(1);
        expect(await count()).toBe(1);
        expect(
          coordinator.status().instances.find((r: any) => r.id === "native-old")
            .lastEnd,
        ).toBe(1);
        expect((await http("/admission-fixture/echo")).status).toBe(503);
        await expect(runtime.register()).rejects.toThrow();
      },
    );
    it("a refused unknown ACK loses the instance and forbids new work while an existing transaction rolls back", async () => {
      await setupControl("unknown-refusal");
      vi.stubEnv("IDENTITY_ADMISSION_ENABLED", "true");
      await runtime.register();
      const scope = await runtime.enter();
      let nestedRan = false,
        rolledBack = false;
      await scope.run(() =>
        scope.track(async () => {
          await db.beginTransaction();
          try {
            await db.query(
              "INSERT INTO identity_user_revocations(user_id,revoked_before) VALUES(999,UTC_TIMESTAMP(3))",
            );
            await scope.unknown();
            expect(() => scope.run(() => undefined)).toThrow();
            expect(() =>
              scope.track(async () => {
                nestedRan = true;
              }),
            ).toThrow();
            expect(() => api.assertAdmissionWriter()).toThrow();
          } finally {
            await db.rollback();
            rolledBack = true;
          }
        }),
      );
      await expect(scope.finish()).rejects.toThrow();
      expect(rolledBack).toBe(true);
      expect(nestedRan).toBe(false);
      expect(await count("identity_user_revocations")).toBe(0);
      expect(coordinator.status().unknown).toBeGreaterThan(0);
      await expect(runtime.enter()).rejects.toThrow();
      await expect(runtime.register()).rejects.toThrow();
    });
    it("SMTP timeout retains unknown until the original send settles instead of completing on its wrapped HTTP error", async () => {
      vi.stubEnv("IDENTITY_EMAIL_TRANSPORT", "smtp");
      vi.stubEnv("MAILER_USERNAME", "fixture@example.test");
      vi.stubEnv("MAILER_PASSWORD", "synthetic-fixture-password");
      const nodemailer = (
        await import(
          pathToFileURL(
            join(root, "node_modules/nodemailer/dist/esm/nodemailer.js"),
          ).href
        )
      ).default;
      const sendGate = gate();
      let closed = false;
      vi.spyOn(nodemailer, "createTransport").mockReturnValue({
        sendMail: () =>
          sendGate.promise.then(() => {
            throw Object.assign(new Error("fixture transport ended"), {
              code: "ETIMEDOUT",
            });
          }),
        close: () => {
          closed = true;
        },
      });
      await boot();
      const response = http("/admission-fixture/email", "POST", {});
      try {
        await until(() => coordinator.status().unknown > 0);
        await until(() => closed);
        expect(
          coordinator.status().instances.find((r: any) => r.id === "native-old")
            .lastEnd,
        ).toBe(0);
        sendGate.resolve();
        expect((await response).status).toBe(503);
        expect(coordinator.status().unknown).toBeGreaterThan(0);
        expect(
          coordinator.status().instances.find((r: any) => r.id === "native-old")
            .lastEnd,
        ).toBe(0);
      } finally {
        sendGate.resolve();
        await response;
      }
    });
  },
);
