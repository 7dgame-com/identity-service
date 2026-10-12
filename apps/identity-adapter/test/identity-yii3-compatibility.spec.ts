import "reflect-metadata";
import { createHash } from "node:crypto";
import { BadRequestException, NotFoundException, UnauthorizedException } from "@nestjs/common";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { NativeIdentityService } from "../src/native-identity.service.js";
import type { NativeQrcodeRepository } from "../src/native-qrcode.repository.js";
import type { NativeQrcodeService } from "../src/native-qrcode.service.js";
import type { IdentitySessionRepository } from "../src/identity-session.repository.js";
import type { TokenIssuanceService } from "../src/token-issuance.service.js";
import { Yii3CompatibilityService } from "../src/yii3-compatibility.service.js";
import { Yii3CompatibilityController } from "../src/yii3-compatibility.controller.js";
import { exportYii3RefreshSessions } from "../src/identity-yii3-session-export.js";

const controllerConfig = vi.hoisted(() => ({ dataSource: "identity", tokenIssuance: { internalToken: "bridge-internal-key-32-characters-long" as string | undefined } }));
vi.mock("../src/config.js", async (importOriginal) => ({
  ...await importOriginal<typeof import("../src/config.js")>(), loadConfig: () => controllerConfig,
}));

const NOW = 1_800_000_000;
const CODE = "a_login_code_with_32_bytes_entropy";
const SUBJECT = { id: 42, username: "private-user", roles: ["student"] };
const REQUEST_CONTEXT = { ip: "192.0.2.42", userAgent: "yii3-client", idempotencyKey: "request-id" };
const digest = (value: string) => createHash("sha256").update(value).digest("hex");
const result = (suffix: string) => ({ success: true, token: { accessToken: `access-${suffix}`, refreshToken: `refresh-${suffix}`, expiresIn: 300 } });

describe("Yii3 compatibility credential routing", () => {
  let native: { enabled: boolean; verify: ReturnType<typeof vi.fn> };
  let repository: { loginCode: ReturnType<typeof vi.fn> };
  let codes: { redeemLoginCode: ReturnType<typeof vi.fn> };
  let sessions: { hasRefreshToken: ReturnType<typeof vi.fn> };
  let tokens: { refresh: ReturnType<typeof vi.fn> };
  let service: Yii3CompatibilityService;

  beforeEach(() => {
    vi.spyOn(Date, "now").mockReturnValue(NOW * 1000);
    native = { enabled: true, verify: vi.fn().mockResolvedValue(SUBJECT) };
    repository = { loginCode: vi.fn().mockResolvedValue({ userId: 42, expiresAt: NOW + 60, context: { frontend_domain: "frontend.test" } }) };
    codes = { redeemLoginCode: vi.fn().mockImplementation(async () => result(String(codes.redeemLoginCode.mock.calls.length))) };
    sessions = { hasRefreshToken: vi.fn().mockResolvedValue(false) };
    tokens = { refresh: vi.fn().mockResolvedValue(result("rotated")) };
    service = new Yii3CompatibilityService(native as unknown as NativeIdentityService, repository as unknown as NativeQrcodeRepository,
      codes as unknown as NativeQrcodeService, sessions as unknown as IdentitySessionRepository, tokens as unknown as TokenIssuanceService);
  });
  afterEach(() => vi.restoreAllMocks());

  it("reads login context without redeeming, refreshing or issuing any credential", async () => {
    for (const key of [CODE, `web_${CODE}`, `https://frontend.test/login?web_${CODE}&other=1`]) {
      expect(await service.loginCode({ key, operation: "context" }, REQUEST_CONTEXT)).toEqual({ frontendDomain: "frontend.test" });
    }
    expect(repository.loginCode.mock.calls).toEqual([[digest(CODE)], [digest(CODE)], [digest(CODE)]]);
    expect(codes.redeemLoginCode).not.toHaveBeenCalled();
    expect(tokens.refresh).not.toHaveBeenCalled();
    expect(native.verify).not.toHaveBeenCalled();
    expect(sessions.hasRefreshToken).not.toHaveBeenCalled();
  });

  it("delegates every redemption independently and uses frontend metadata only in the response", async () => {
    repository.loginCode.mockResolvedValue({ userId: 42, expiresAt: NOW + 60,
      context: { frontend_domain: "frontend.test", audience: "untrusted-client", scope: "admin" } });
    const first = await service.loginCode({ key: CODE, operation: "redeem" }, REQUEST_CONTEXT);
    const second = await service.loginCode({ key: `web_${CODE}`, operation: "redeem" }, REQUEST_CONTEXT);
    expect(first).toEqual({ authTokens: result("1").token, subject: SUBJECT, frontendDomain: "frontend.test" });
    expect(second).toEqual({ authTokens: result("2").token, subject: SUBJECT, frontendDomain: "frontend.test" });
    expect(codes.redeemLoginCode.mock.calls).toEqual([[CODE, REQUEST_CONTEXT], [CODE, REQUEST_CONTEXT]]);
    // Default verification retains the global API audience; stored frontend metadata is not an audience option.
    expect(native.verify.mock.calls).toEqual([["access-1"], ["access-2"]]);
    expect(tokens.refresh).not.toHaveBeenCalled();
  });

  it.each([undefined, null, "localhost", "127.0.0.1", "2001:db8::1", "sub.frontend.test"])("keeps the stored host contract: %j", async (domain) => {
    repository.loginCode.mockResolvedValue({ userId: 42, expiresAt: NOW + 60, context: { frontend_domain: domain } });
    expect(await service.loginCode({ key: CODE, operation: "context" })).toEqual({ frontendDomain: domain ?? null });
  });

  it.each(["https://frontend.test", "frontend.test/path", "frontend.test:443", "Frontend.test", "frontend.test.", "", " frontend.test", "frontend.test\n", "frontend.test\r", 42, {}])(
    "rejects malformed stored frontend metadata before any redemption: %j", async (domain) => {
      repository.loginCode.mockResolvedValue({ userId: 42, expiresAt: NOW + 60, context: { frontend_domain: domain } });
      for (const operation of ["context", "redeem"]) {
        await expect(service.loginCode({ key: CODE, operation })).rejects.toBeInstanceOf(UnauthorizedException);
      }
      expect(codes.redeemLoginCode).not.toHaveBeenCalled();
      expect(native.verify).not.toHaveBeenCalled();
    });

  it.each([null, { userId: 42, expiresAt: NOW }, { userId: 42, expiresAt: NOW - 1 }])("rejects absent or expired codes before redemption: %j", async (stored) => {
    repository.loginCode.mockResolvedValue(stored);
    await expect(service.loginCode({ key: CODE, operation: "redeem" })).rejects.toBeInstanceOf(UnauthorizedException);
    expect(codes.redeemLoginCode).not.toHaveBeenCalled();
  });

  it.each(["revoked", "expired"])("never falls back from a known %s refresh to a live login code", async (reason) => {
    sessions.hasRefreshToken.mockResolvedValue(true);
    tokens.refresh.mockRejectedValue(new UnauthorizedException(reason));
    await expect(service.refresh({ refreshToken: CODE, allowLoginCode: true }, REQUEST_CONTEXT)).rejects.toThrow(reason);
    expect(tokens.refresh).toHaveBeenCalledExactlyOnceWith({ refreshToken: CODE }, REQUEST_CONTEXT);
    expect(repository.loginCode).not.toHaveBeenCalled();
    expect(codes.redeemLoginCode).not.toHaveBeenCalled();
    expect(native.verify).not.toHaveBeenCalled();
  });

  it("preserves raw known classification even when the credential resembles a wrapped login code", async () => {
    const raw = `web_${CODE}`;
    sessions.hasRefreshToken.mockResolvedValue(true);
    tokens.refresh.mockRejectedValue(new UnauthorizedException("revoked raw refresh"));
    await expect(service.refresh({ refreshToken: raw, allowLoginCode: true })).rejects.toThrow("revoked raw refresh");
    expect(sessions.hasRefreshToken.mock.calls).toEqual([[raw]]);
    expect(tokens.refresh).toHaveBeenCalledExactlyOnceWith({ refreshToken: raw }, {});
    expect(repository.loginCode).not.toHaveBeenCalled();
    expect(codes.redeemLoginCode).not.toHaveBeenCalled();
  });

  it.each([`web_${CODE}`, `https://frontend.test/login?web_${CODE}`])("checks the unwrapped known credential before allowing fallback: %s", async (raw) => {
    sessions.hasRefreshToken.mockImplementation(async (candidate: string) => candidate === CODE);
    tokens.refresh.mockRejectedValue(new UnauthorizedException("expired normalized refresh"));
    await expect(service.refresh({ refreshToken: raw, allowLoginCode: true })).rejects.toThrow("expired normalized refresh");
    expect(sessions.hasRefreshToken.mock.calls).toEqual([[raw], [CODE]]);
    expect(tokens.refresh).toHaveBeenCalledExactlyOnceWith({ refreshToken: CODE }, {});
    expect(repository.loginCode).not.toHaveBeenCalled();
    expect(codes.redeemLoginCode).not.toHaveBeenCalled();
  });

  it("only redeems an unknown ordinary code when allowLoginCode is explicitly true", async () => {
    const response = await service.refresh({ refreshToken: `web_${CODE}`, allowLoginCode: true }, REQUEST_CONTEXT);
    expect(response).toEqual({ authTokens: result("1").token, subject: SUBJECT, frontendDomain: "frontend.test" });
    expect(sessions.hasRefreshToken.mock.calls).toEqual([[`web_${CODE}`], [CODE]]);
    expect(repository.loginCode).toHaveBeenCalledExactlyOnceWith(digest(CODE));
    expect(codes.redeemLoginCode).toHaveBeenCalledExactlyOnceWith(CODE, REQUEST_CONTEXT);
    expect(tokens.refresh).not.toHaveBeenCalled();
  });

  it.each([CODE, `web_${CODE}`])("never interprets an unknown credential as a login code in strict refresh mode: %s", async (raw) => {
    await expect(service.refresh({ refreshToken: raw, allowLoginCode: false })).rejects.toBeInstanceOf(UnauthorizedException);
    expect(sessions.hasRefreshToken.mock.calls).toEqual([[raw]]);
    expect(tokens.refresh).not.toHaveBeenCalled();
    expect(repository.loginCode).not.toHaveBeenCalled();
    expect(codes.redeemLoginCode).not.toHaveBeenCalled();
  });

  it.each([`dsn_${"a".repeat(64)}`, `web_dsn_${"a".repeat(64)}`, `https://frontend.test?web_dsn_${"a".repeat(64)}`])(
    "never reinterprets unknown SN credentials as ordinary login codes: %s", async (refreshToken) => {
      await expect(service.refresh({ refreshToken, allowLoginCode: true })).rejects.toBeInstanceOf(UnauthorizedException);
      expect(repository.loginCode).not.toHaveBeenCalled();
      expect(codes.redeemLoginCode).not.toHaveBeenCalled();
      expect(tokens.refresh).not.toHaveBeenCalled();
    });

  it("routes known refreshes in strict mode and retains verified SN provenance in the legacy response", async () => {
    const refreshToken = `dsn_${"a".repeat(64)}`;
    sessions.hasRefreshToken.mockResolvedValue(true);
    native.verify.mockResolvedValue({ ...SUBJECT, authContext: { auth_method: "device_sn", device_sn_id: 73 } });
    expect(await service.refresh({ refreshToken, allowLoginCode: false }, REQUEST_CONTEXT)).toEqual({
      authTokens: result("rotated").token,
      subject: { ...SUBJECT, authContext: { auth_method: "device_sn", device_sn_id: 73 }, auth_method: "device_sn", device_sn_id: 73 },
    });
    expect(tokens.refresh).toHaveBeenCalledExactlyOnceWith({ refreshToken }, REQUEST_CONTEXT);
    expect(native.verify).toHaveBeenCalledExactlyOnceWith("access-rotated");
    expect(codes.redeemLoginCode).not.toHaveBeenCalled();
  });

  it("propagates storage and native verification failure without falling back", async () => {
    sessions.hasRefreshToken.mockRejectedValueOnce(new Error("storage unavailable"));
    await expect(service.refresh({ refreshToken: CODE, allowLoginCode: true })).rejects.toThrow("storage unavailable");
    sessions.hasRefreshToken.mockResolvedValue(true);
    native.verify.mockRejectedValueOnce(new UnauthorizedException("account disabled"));
    await expect(service.refresh({ refreshToken: CODE, allowLoginCode: true })).rejects.toThrow("account disabled");
    expect(repository.loginCode).not.toHaveBeenCalled();
    expect(codes.redeemLoginCode).not.toHaveBeenCalled();
  });

  it.each([null, [], {}, { key: CODE }, { key: CODE, operation: "issue" }, { key: 42, operation: "context" },
    { key: "", operation: "context" }, { key: "a".repeat(4097), operation: "redeem" }, { key: CODE, operation: "redeem", audience: "frontend.test" }])(
    "rejects malformed login requests before touching storage: %j", async (input) => {
      await expect(service.loginCode(input)).rejects.toBeInstanceOf(BadRequestException);
      expect(repository.loginCode).not.toHaveBeenCalled();
    });

  it.each([null, [], {}, { refreshToken: CODE }, { refreshToken: CODE, allowLoginCode: "true" },
    { refreshToken: 42, allowLoginCode: false }, { refreshToken: "", allowLoginCode: false },
    { refreshToken: "a".repeat(4097), allowLoginCode: true }, { refreshToken: CODE, allowLoginCode: true, audience: "frontend.test" }])(
    "rejects malformed refresh requests before classification: %j", async (input) => {
      await expect(service.refresh(input)).rejects.toBeInstanceOf(BadRequestException);
      expect(sessions.hasRefreshToken).not.toHaveBeenCalled();
      expect(repository.loginCode).not.toHaveBeenCalled();
    });

  it("keeps the compatibility service disabled under another authority", async () => {
    native.enabled = false;
    await expect(service.loginCode({ key: CODE, operation: "context" })).rejects.toBeInstanceOf(NotFoundException);
    await expect(service.refresh({ refreshToken: CODE, allowLoginCode: true })).rejects.toBeInstanceOf(NotFoundException);
    expect(repository.loginCode).not.toHaveBeenCalled();
    expect(sessions.hasRefreshToken).not.toHaveBeenCalled();
  });
});

describe("Yii3 internal controller authorization", () => {
  let service: { loginCode: ReturnType<typeof vi.fn>; refresh: ReturnType<typeof vi.fn> };
  beforeEach(() => {
    controllerConfig.dataSource = "identity";
    controllerConfig.tokenIssuance.internalToken = "bridge-internal-key-32-characters-long";
    service = { loginCode: vi.fn().mockResolvedValue({ frontendDomain: null }), refresh: vi.fn().mockResolvedValue({ authTokens: {} }) };
  });

  it.each([undefined, "", "wrong", "bridge-internal-keX", "é".repeat(9) + "x"])("rejects missing or wrong internal credentials before delegation: %j", (key) => {
    const controller = new Yii3CompatibilityController(service as unknown as Yii3CompatibilityService);
    expect(() => controller.loginCode(key, {}, {})).toThrow(UnauthorizedException);
    expect(() => controller.refresh(key, {}, {})).toThrow(UnauthorizedException);
    expect(service.loginCode).not.toHaveBeenCalled();
    expect(service.refresh).not.toHaveBeenCalled();
  });

  it("requires native identity authority and a configured internal key", () => {
    for (const [dataSource, key] of [["legacy", "bridge-internal-key-32-characters-long"], ["identity", undefined], ["identity", ""], ["identity", "short"]]) {
      controllerConfig.dataSource = dataSource!;
      controllerConfig.tokenIssuance.internalToken = key;
      const controller = new Yii3CompatibilityController(service as unknown as Yii3CompatibilityService);
      expect(() => controller.loginCode("bridge-internal-key-32-characters-long", {}, {})).toThrow(UnauthorizedException);
      expect(() => controller.refresh("bridge-internal-key-32-characters-long", {}, {})).toThrow(UnauthorizedException);
    }
    expect(service.loginCode).not.toHaveBeenCalled();
    expect(service.refresh).not.toHaveBeenCalled();
  });

  it("forwards only the trusted request IP and explicit headers after authorization", async () => {
    const controller = new Yii3CompatibilityController(service as unknown as Yii3CompatibilityService);
    const login = { key: CODE, operation: "context" }, refresh = { refreshToken: CODE, allowLoginCode: false };
    await controller.loginCode("bridge-internal-key-32-characters-long", login, { ip: "::ffff:192.0.2.42", socket: { remoteAddress: "198.51.100.9" } }, "browser");
    await controller.refresh("bridge-internal-key-32-characters-long", refresh, { socket: { remoteAddress: "::ffff:198.51.100.9" } }, "browser", "operation-id");
    expect(service.loginCode).toHaveBeenCalledExactlyOnceWith(login, { ip: "192.0.2.42", userAgent: "browser" });
    expect(service.refresh).toHaveBeenCalledExactlyOnceWith(refresh, { ip: "198.51.100.9", userAgent: "browser", idempotencyKey: "operation-id" });
  });
});

describe("Yii3 reviewed snapshot rejects trailing line terminators", () => {
  const observedAtMs = NOW * 1000;
  const source = { application: "yii3-a1", sourceRevision: "a".repeat(40), redisDatabase: 1, keyPrefix: "refresh_token:",
    fixedTtlSeconds: 2592000, expiryPolicy: "setex-on-create-only", namespaceWritersReviewed: true };
  const entry = { key: `refresh_token:${"b".repeat(64)}`, value: "42", expiry: { kind: "pexpiretime", observedAtMs, expiresAtMs: observedAtMs + 60000 } };
  const snapshot = { version: 1, source, capturedAtMs: observedAtMs, entries: [entry] };

  it.each(["\n", "\r", "\r\n", "\u2028", "\u2029"])("refuses line terminators in proof revision: %j", (ending) => {
    expect(() => exportYii3RefreshSessions({ ...snapshot, source: { ...source, sourceRevision: source.sourceRevision + ending } })).toThrow();
  });
  it.each(["\n", "\r", "\r\n", "\u2028", "\u2029"])("refuses line terminators in scalar UID value: %j", (ending) => {
    expect(() => exportYii3RefreshSessions({ ...snapshot, entries: [{ ...entry, value: entry.value + ending }] })).toThrow();
  });
  it.each(["\n", "\r", "\r\n", "\u2028", "\u2029"])("refuses line terminators in raw token keys: %j", (ending) => {
    for (const token of ["b".repeat(64), `dsn_${"b".repeat(64)}`]) {
      expect(() => exportYii3RefreshSessions({ ...snapshot, entries: [{ ...entry, key: `refresh_token:${token}${ending}`,
        value: token.startsWith("dsn_") ? { version: 1, user_id: 42, auth_method: "device_sn", device_sn_id: 73 } : "42" }] })).toThrow();
    }
  });
});
