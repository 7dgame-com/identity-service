import "reflect-metadata";
import { createHash } from "node:crypto";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { UnauthorizedException } from "@nestjs/common";
import { NativeIdentityService } from "../src/native-identity.service.js";
import { NativeQrcodeController } from "../src/native-qrcode.controller.js";
import { NativeQrcodeRepository } from "../src/native-qrcode.repository.js";
import { NativeQrcodeService, normalizeLoginCode } from "../src/native-qrcode.service.js";
import { IdentityWechatOAuthService } from "../src/identity-wechat-oauth.service.js";
import { TokenIssuanceService } from "../src/token-issuance.service.js";
import { AccountRegistrationService } from "../src/account-registration.service.js";

const now = 1_800_000_000;
const rawCode = "a_device_login_code_with_32bytes_entropy";
class TestQrcodeService extends NativeQrcodeService {
  clock = now;
  providerCalls: unknown[] = [];
  providerResponse: Record<string, unknown> = { ticket: "wechat-ticket" };
  protected now() { return this.clock; }
  protected async provider(action: "qrcode" | "profile", payload: Record<string, unknown>) {
    this.providerCalls.push({ action, payload }); return this.providerResponse;
  }
}

describe("Independent Identity QR compatibility", () => {
  let repository: Record<string, ReturnType<typeof vi.fn>>;
  let native: { enabled: boolean; config: unknown; actor: ReturnType<typeof vi.fn>; requirePermission: ReturnType<typeof vi.fn> };
  let tokens: { issueLegacyUserToken: ReturnType<typeof vi.fn> };
  let wechat: { resolveWechat: ReturnType<typeof vi.fn> };
  let registration: { register: ReturnType<typeof vi.fn> };
  let service: TestQrcodeService;

  beforeEach(() => {
    repository = { issueLoginCode: vi.fn().mockResolvedValue(undefined), loginCode: vi.fn().mockResolvedValue({ userId: 42, expiresAt: now + 60 }),
      createWechatScene: vi.fn().mockResolvedValue(undefined), wechatScene: vi.fn().mockResolvedValue({ expiresAt: now + 500,
        providerAppId: "wx-app", openId: "wx-subject", userId: 42, profile: { openId: "wx-subject", nickname: "微信用户" } }),
      confirmWechatScene: vi.fn().mockResolvedValue(undefined), hasActiveRegistration: vi.fn().mockResolvedValue(true) };
    native = { enabled: true, config: { tokenIssuance: { internalToken: "internal-secret" } },
      actor: vi.fn().mockResolvedValue({ id: 42, status: 10 }), requirePermission: vi.fn().mockResolvedValue(undefined) };
    tokens = { issueLegacyUserToken: vi.fn().mockImplementation(async () => ({ success: true, token: { refreshToken: `session-${tokens.issueLegacyUserToken.mock.calls.length}` } })) };
    wechat = { resolveWechat: vi.fn().mockResolvedValue({ userId: 42, signupToken: null }) };
    registration = { register: vi.fn().mockResolvedValue({ status: 200, body: { success: true, message: "register", uid: 42, token: { accessToken: "issued-token" } } }) };
    service = new TestQrcodeService(repository as unknown as NativeQrcodeRepository, native as unknown as NativeIdentityService,
      tokens as unknown as TokenIssuanceService, wechat as unknown as IdentityWechatOAuthService, registration as unknown as AccountRegistrationService);
  });

  it("keeps the 60 second protocol and persists only code hash plus subject", async () => {
    const result = await service.issueLoginCode({ headers: {} });
    expect(result.expires_at).toBe(now + 60); expect(result.expires_in).toBe(60);
    expect(repository.issueLoginCode).toHaveBeenCalledWith(42, createHash("sha256").update(result.key).digest("hex"), now, now + 60);
    expect(JSON.stringify(repository.issueLoginCode.mock.calls)).not.toContain(result.key);
    expect(tokens.issueLegacyUserToken).not.toHaveBeenCalled();
    expect(native.requirePermission).toHaveBeenCalledWith({ id: 42, status: 10 }, "/v1/tools/user-linked");
  });

  it("supports several devices with a fresh session for every redemption", async () => {
    const first = await service.redeemLoginCode(`web_${rawCode}`, { ip: "127.0.0.1", idempotencyKey: "same-browser-key" });
    const second = await service.redeemLoginCode(`https://host/login?web_${rawCode}`, { ip: "127.0.0.2", idempotencyKey: "same-browser-key" });
    expect(first.token.refreshToken).not.toBe(second.token.refreshToken);
    expect(tokens.issueLegacyUserToken).toHaveBeenNthCalledWith(1, { legacyUserId: 42 }, { ip: "127.0.0.1" });
    expect(tokens.issueLegacyUserToken).toHaveBeenNthCalledWith(2, { legacyUserId: 42 }, { ip: "127.0.0.2" });
  });

  it("rejects at the exact expiry boundary without signing a session", async () => {
    service.clock = now + 60;
    await expect(service.redeemLoginCode(`web_${rawCode}`)).rejects.toBeInstanceOf(UnauthorizedException);
    expect(tokens.issueLegacyUserToken).not.toHaveBeenCalled();
  });

  it("propagates Identity disabled-user rejection without another authority", async () => {
    tokens.issueLegacyUserToken.mockRejectedValue(new UnauthorizedException("account disabled"));
    await expect(service.redeemLoginCode(`web_${rawCode}`)).rejects.toThrow("account disabled");
    expect(tokens.issueLegacyUserToken).toHaveBeenCalledTimes(1);
  });

  it("hides another subject's code ownership in status", async () => {
    repository.loginCode.mockResolvedValue({ userId: 99, expiresAt: now + 60 });
    expect(await service.loginCodeStatus({ headers: {} }, rawCode)).toEqual({ success: true, message: "user-linked-status", active: false, reason: "not_found" });
  });

  it("returns the existing QR shape and keeps provider state inside Identity", async () => {
    const result = await service.createWechatQr();
    expect(result.qrcode).toEqual({ ticket: "wechat-ticket", url: "https://mp.weixin.qq.com/cgi-bin/showqrcode?ticket=wechat-ticket" });
    expect(result.lifetime).toBe(6 * 24 * 3600);
    expect(repository.createWechatScene).toHaveBeenCalledWith(createHash("sha256").update(result.token).digest("hex"), now + result.lifetime);
    expect(service.providerCalls).toEqual([{ action: "qrcode", payload: { scene: result.token, lifetimeSeconds: result.lifetime } }]);
  });

  it("saves a confirmed scan's subject after provider profile validation", async () => {
    service.providerResponse = { openId: "wx-subject", providerAppId: "wx-app", unionId: "wx-union", nickname: "微信用户" };
    await service.confirmWechatScan({ scene: "created-scene", providerAppId: "wx-app", openId: "wx-subject" });
    expect(repository.confirmWechatScene).toHaveBeenCalledWith(createHash("sha256").update("created-scene").digest("hex"),
      "wx-app", "wx-subject", 42, null, service.providerResponse, now);
    expect(wechat.resolveWechat).toHaveBeenCalledWith(expect.objectContaining({ provider: "wechat_official_account", openId: "wx-subject", unionId: "wx-union" }), false);
  });

  it("rejects a mismatched provider subject before persisting confirmation", async () => {
    service.providerResponse = { openId: "another-subject" };
    await expect(service.confirmWechatScan({ scene: "scene", providerAppId: "wx-app", openId: "wx-subject" })).rejects.toThrow("subject does not match");
    expect(repository.confirmWechatScene).not.toHaveBeenCalled();
    expect(wechat.resolveWechat).not.toHaveBeenCalled();
  });

  it("rejects an unknown callback scene before contacting the provider", async () => {
    repository.wechatScene.mockResolvedValue(null);
    await expect(service.confirmWechatScan({ scene: "unknown", providerAppId: "wx-app", openId: "wx-subject" })).rejects.toBeInstanceOf(UnauthorizedException);
    expect(service.providerCalls).toEqual([]);
  });

  it("returns a registration token for an unbound scan and the same login response for a bound scan", async () => {
    wechat.resolveWechat.mockResolvedValueOnce({ userId: null, signupToken: "registration-token" });
    expect(await service.wechatStatus("created-scene")).toEqual({ success: true, message: "signup", token: "registration-token" });
    expect(repository.confirmWechatScene).toHaveBeenCalledWith(createHash("sha256").update("created-scene").digest("hex"),
      "wx-app","wx-subject",null,createHash("sha256").update("registration-token").digest("hex"),expect.any(Object),now);
    expect(await service.wechatStatus("created-scene")).toEqual({ success: true, message: "signin", token: "created-scene" });
    await service.wechatLogin({ token: "created-scene" }, { userAgent: "browser" });
    expect(tokens.issueLegacyUserToken).toHaveBeenCalledWith({ legacyUserId: 42 }, { userAgent: "browser" });
  });

  it("requires the internal credential before allowing scan assertions", async () => {
    const controller = new NativeQrcodeController(service);
    expect(() => controller.confirm(undefined, {})).toThrow(UnauthorizedException);
    expect(() => controller.confirm("wrong-secret", {})).toThrow(UnauthorizedException);
    expect(repository.confirmWechatScene).not.toHaveBeenCalled();
  });

  it("uses the existing transactional registration only for a live confirmed scan", async () => {
    const payload = { token: "registration-token", username: "new-user", password: "new-password" };
    expect(await service.wechatRegister(payload, {}, "operation-key")).toEqual({ success: true, message: "register", uid: 42, token: { accessToken: "issued-token" } });
    expect(registration.register).toHaveBeenCalledWith("/v1/wechat/register", payload, { idempotencyKey: "operation-key" });
    repository.hasActiveRegistration.mockResolvedValue(false);
    await expect(service.wechatRegister(payload)).rejects.toBeInstanceOf(UnauthorizedException);
    expect(registration.register).toHaveBeenCalledTimes(1);
  });

  it("does not enable native routes while the legacy authority is selected", async () => {
    native.enabled = false;
    await expect(service.issueLoginCode({ headers: {} })).rejects.toThrow();
    expect(native.actor).not.toHaveBeenCalled();
    expect(repository.issueLoginCode).not.toHaveBeenCalled();
  });

  it("normalizes only bounded code values and preserves existing web_ URL syntax", () => {
    expect(normalizeLoginCode(`https://host?web_${rawCode}&other=value`)).toBe(rawCode);
    expect(normalizeLoginCode("web_short")).toBe("");
    expect(normalizeLoginCode("a".repeat(5000))).toBe("");
    expect(normalizeLoginCode({ token: rawCode })).toBe("");
  });
});
