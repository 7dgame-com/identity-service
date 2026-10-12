import "reflect-metadata";
import mysql from "mysql2/promise";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DeviceSnAuthorizationReader } from "../src/device-sn-authorization.reader.js";
import { assertDeviceSnAccount, isDeviceSnUuid } from "../src/device-sn-source.js";
import { LegacyIdentityReader, type LegacyUserReadModel } from "../src/legacy-identity.reader.js";
import { DeviceSnAccessGuard } from "../src/device-sn-access.guard.js";
import type { ExecutionContext } from "@nestjs/common";
import type { JwtIssuerService } from "../src/jwt-issuer.service.js";
import type { IdentitySessionRepository } from "../src/identity-session.repository.js";
import type { PoolConnection } from "mysql2/promise";
import { NativeIdentityService } from "../src/native-identity.service.js";
import { InternalAuthController } from "../src/internal-auth.controller.js";
import type { TokenIssuanceService } from "../src/token-issuance.service.js";

const user: LegacyUserReadModel = { id: 7, username: "device-user", email: null, nickname: null,
  status: 10, emailVerifiedAt: null, createdAt: null, updatedAt: null, userInfo: {},
  roles: ["user"], organizations: [], source: "identity-db" };
const device = { execute: vi.fn(), query: vi.fn(), end: vi.fn() };
const account = { query: vi.fn(), end: vi.fn() };

beforeEach(() => {
  for (const [key, value] of Object.entries({ IDENTITY_DATA_SOURCE: "identity", IDENTITY_DB_HOST: "private-db",
    IDENTITY_DB_NAME: "accounts", IDENTITY_DB_USER: "identity-reader", LEGACY_DB_HOST: "must-not-connect",
    LEGACY_DB_USER: "must-not-connect", DEVICE_SN_DB_HOST: "business-writer", DEVICE_SN_DB_NAME: "devices",
    DEVICE_SN_DB_USER: "device-select-only", IDENTITY_TOKEN_ISSUANCE_INTERNAL_API_TOKEN: "test-device-authority-internal-token" })) vi.stubEnv(key, value);
  device.execute.mockReset().mockResolvedValue([[{ id: 42, deviceUuid: "device-uuid-42" }]]);
  device.query.mockReset().mockResolvedValue([[]]); device.end.mockReset();
  account.query.mockReset().mockResolvedValue([[{ id: 7 }]]); account.end.mockReset();
  vi.spyOn(mysql, "createPool").mockImplementation((options: unknown) => {
    const database = (options as { database: string }).database;
    if (database === "accounts") return account as never;
    if (database === "devices") return device as never;
    throw new Error("Unexpected database connection");
  });
});
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllEnvs(); });

describe("independent device authorization source", () => {
  it("uses only the dedicated business device table and private current account policy", async () => {
    const reader = new LegacyIdentityReader();
    vi.spyOn(reader, "getUserById").mockResolvedValue(user);
    vi.spyOn(reader, "readRbacPolicySnapshot").mockResolvedValue({ items: [], relations: [] });
    await reader.assertDeviceSnAuthorized(42, 7);
    expect(mysql.createPool).toHaveBeenCalledTimes(2);
    expect(device.execute).toHaveBeenCalledWith(expect.stringContaining("FROM device_sn"), [42, 7, 1]);
    expect(device.execute.mock.calls[0][0]).not.toMatch(/JOIN|auth_assignment|password|FROM\s+user\b/i);
    expect(reader.getUserById).toHaveBeenCalledWith(7);
    await reader.onModuleDestroy(); expect(account.end).toHaveBeenCalledOnce(); expect(device.end).toHaveBeenCalledOnce();
  });

  it("fails closed without an explicit device database name rather than using legacy credentials", async () => {
    vi.stubEnv("DEVICE_SN_DB_NAME", "");
    const reader = new LegacyIdentityReader();
    await expect(reader.assertDeviceSnAuthorized(42, 7)).rejects.toMatchObject({ status: 503, response: { code: "DEVICE_SN_VALIDATION_UNAVAILABLE" } });
    expect(await reader.deviceSnReadiness()).toBe(false);
    expect(mysql.createPool).toHaveBeenCalledTimes(1);
    await reader.onModuleDestroy();
  });

  it.each(["root", "ADMIN", "mànager"])("rejects current privileged private account %s", async (role) => {
    const reader = new LegacyIdentityReader();
    vi.spyOn(reader, "getUserById").mockResolvedValue({ ...user, roles: [role] });
    vi.spyOn(reader, "readRbacPolicySnapshot").mockResolvedValue({ items: [], relations: [] });
    await expect(reader.assertDeviceSnAuthorized(42, 7, false)).rejects.toMatchObject({ status: 401, response: { code: "DEVICE_SN_ACCOUNT_INELIGIBLE" } });
    await reader.onModuleDestroy();
  });

  it("denies inherited privilege from the current private graph, even in an access grace period", async () => {
    const reader = new LegacyIdentityReader();
    vi.spyOn(reader, "getUserById").mockResolvedValue(user);
    vi.spyOn(reader, "readRbacPolicySnapshot").mockResolvedValue({ items: [], relations: [{ parent: "user", child: "team" }, { parent: "team", child: "admin" }] });
    await expect(reader.assertDeviceSnAuthorized(42, 7, false)).rejects.toMatchObject({ status: 401 });
    expect(device.execute).toHaveBeenCalledWith(expect.any(String), [42, 7, 0]);
    await reader.onModuleDestroy();
  });

  it("keeps device database errors opaque and source-specific", async () => {
    device.execute.mockRejectedValue(new Error("secret SQL / password detail"));
    const source = new DeviceSnAuthorizationReader({ host: "business-writer", port: 3306, name: "devices", user: "device-select-only" });
    await expect(source.assertAuthorized(42, 7, true)).rejects.toMatchObject({ status: 503,
      response: { code: "DEVICE_SN_VALIDATION_UNAVAILABLE", message: "Device authorization could not be verified." } });
    await source.close();
  });

  it.each([0, -1, NaN, 1.5, Number.MAX_SAFE_INTEGER + 1])("rejects invalid device IDs before querying (%s)", async (id) => {
    const source = new DeviceSnAuthorizationReader({ host: "business-writer", port: 3306, name: "devices", user: "device-select-only" });
    await expect(source.assertAuthorized(id, 7, true)).rejects.toMatchObject({ status: 401 });
    expect(device.execute).not.toHaveBeenCalled(); await source.close();
  });

  it.each([null, "", " ", "UPPERCASE", "device/path", "_leading", "设备", "uuid\n"])("rejects invalid device UUID (%s)", (value) => {
    expect(isDeviceSnUuid(value)).toBe(false);
  });

  it("preserves non-RFC lowercase UUIDs and ordinary accounts", () => {
    expect(isDeviceSnUuid("rokid-uuid-not-rfc-uuid")).toBe(true);
    expect(() => assertDeviceSnAccount(user)).not.toThrow();
  });
});

describe("native device session validation boundaries", () => {
  const token = `x.${Buffer.from(JSON.stringify({ uid: 7, iat: 100, auth_method: "device_sn", device_sn_id: 42 })).toString("base64url")}.x`;
  const jwt = { verifyAccessToken: () => ({ uid: 7, sessionId: "sn-session", authMethod: "device_sn", deviceSnId: 42 }) } as unknown as JwtIssuerService;
  it.each(["/v1/wechat/binding", "/v1/plugin-campus/users/password", "/v1/plugin-user/create-user", "/v1/plugin-user/update-user",
    "/v1/plugin-user/batch-create-users", "/v1/plugin-user/change-role", "/v1/person", "/v1/people/7", "/internal/apple/link"])(
    "blocks device credential or account elevation at %s", async (path) => {
      const reader = { assertDeviceSnAuthorized: vi.fn() };
      const guard = new DeviceSnAccessGuard(jwt, reader as unknown as LegacyIdentityReader);
      const context = { switchToHttp: () => ({ getRequest: () => ({ path, method: "POST", headers: { authorization: `Bearer ${token}` } }) }) } as ExecutionContext;
      await expect(guard.canActivate(context)).rejects.toMatchObject({ status: 403 });
      expect(reader.assertDeviceSnAuthorized).toHaveBeenCalledWith(42, 7, false);
    });
  it("checks the access token in protected internal verification body", async () => {
    const reader = { assertDeviceSnAuthorized: vi.fn() };
    const guard = new DeviceSnAccessGuard(jwt, reader as unknown as LegacyIdentityReader);
    const context = { switchToHttp: () => ({ getRequest: () => ({ path: "/internal/auth/verify-access-token", method: "POST", headers: {}, body: { token } }) }) } as ExecutionContext;
    await expect(guard.canActivate(context)).resolves.toBe(true);
    expect(reader.assertDeviceSnAuthorized).toHaveBeenCalledWith(42, 7, false);
  });
  it("blocks an SN token carried by legacy administration RPC instead of an HTTP bearer", async () => {
    const reader = { assertDeviceSnAuthorized: vi.fn() };
    const guard = new DeviceSnAccessGuard(jwt, reader as unknown as LegacyIdentityReader);
    const context = { switchToHttp: () => ({ getRequest: () => ({ path: "/internal/legacy-admin", method: "POST", headers: {}, body: { accessToken: token, operation: "user-create" } }) }) } as ExecutionContext;
    await expect(guard.canActivate(context)).rejects.toMatchObject({ status: 403 });
  });
  it("revalidates the live device/account source in direct native verify and transaction access checks", async () => {
    const reader = { assertDeviceSnAuthorized: vi.fn() };
    const sessions = { isAccessRevoked: vi.fn().mockResolvedValue(false), isOAuthBound: vi.fn().mockResolvedValue(false) };
    const native = new NativeIdentityService(reader as unknown as LegacyIdentityReader, jwt, sessions as unknown as IdentitySessionRepository);
    vi.spyOn(native, "subject").mockResolvedValue({ ...user, permissions: [], directPermissions: [], avatarId: null, deletedAt: null });
    await expect(native.verify(token)).resolves.toMatchObject({ id: 7 });
    await native.assertAccessInTransaction(token, 7, {} as PoolConnection);
    expect(reader.assertDeviceSnAuthorized).toHaveBeenCalledTimes(2);
    expect(reader.assertDeviceSnAuthorized).toHaveBeenCalledWith(42, 7, false);
    reader.assertDeviceSnAuthorized.mockRejectedValue(new Error("device source unavailable"));
    await expect(native.verify(token)).rejects.toThrow("device source unavailable");
    await expect(native.assertAccessInTransaction(token, 7, {} as PoolConnection)).rejects.toThrow("device source unavailable");
    await native.onModuleDestroy();
  });
});

describe("trusted device account selector", () => {
  const key = "test-device-authority-internal-token";
  function fixture() {
    const reader = { listDeviceSnAccounts: vi.fn().mockResolvedValue({ items: [], total: 0, page: 1, page_size: 20 }) };
    const controller = new InternalAuthController({} as TokenIssuanceService, {} as IdentitySessionRepository, reader as unknown as LegacyIdentityReader);
    return { reader, controller };
  }
  it("requires the auth scoped key and passes only validated minimal selectors", async () => {
    const { reader, controller } = fixture();
    expect(() => controller.deviceSnAccounts("wrong", "", "1", "20")).toThrow();
    expect(reader.listDeviceSnAccounts).not.toHaveBeenCalled();
    await controller.deviceSnAccounts(key, "needle", "2", "10");
    expect(reader.listDeviceSnAccounts).toHaveBeenCalledWith("needle", 2, 10);
  });
  it.each([["", "0", "20"], ["", "1.5", "20"], ["", "1", "101"], ["", ["1"], "20"], ["q".repeat(201), "1", "20"], [{ q: "x" }, "1", "20"]])(
    "rejects invalid selector parameters", (q, page, size) => {
      const { reader, controller } = fixture();
      expect(() => controller.deviceSnAccounts(key, q, page, size)).toThrow();
      expect(reader.listDeviceSnAccounts).not.toHaveBeenCalled();
    });
});
