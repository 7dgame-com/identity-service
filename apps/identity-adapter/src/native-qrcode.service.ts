import { createHash, randomBytes } from "node:crypto";
import { BadRequestException, ConflictException, Injectable, NotFoundException, ServiceUnavailableException, UnauthorizedException } from "@nestjs/common";
import { NativeIdentityService, NativeRequest } from "./native-identity.service.js";
import { NativeQrcodeRepository } from "./native-qrcode.repository.js";
import { IdentityWechatOAuthService } from "./identity-wechat-oauth.service.js";
import { AuthTokenResponse, RequestContext, TokenIssuanceService } from "./token-issuance.service.js";
import { AccountRegistrationService } from "./account-registration.service.js";
import { denyDeviceSnCredentialDerivation } from "./device-sn-source.js";
import { loginCodeContext } from "./login-code-context.js";

export const LOGIN_CODE_LIFETIME_SECONDS = 60;
const WECHAT_SCENE_LIFETIME_SECONDS = 6 * 24 * 3600;

@Injectable()
export class NativeQrcodeService {
  constructor(private readonly repository: NativeQrcodeRepository, private readonly native: NativeIdentityService,
    private readonly tokens: TokenIssuanceService, private readonly wechat: IdentityWechatOAuthService,
    private readonly registration: AccountRegistrationService) {}

  get enabled() { return this.native.enabled; }
  get internalToken() { return this.native.config.tokenIssuance.internalToken; }
  private assertEnabled() { if (!this.enabled) throw new NotFoundException(); }
  protected now() { return Math.floor(Date.now() / 1000); }
  protected loginCodeCandidate() { return randomBytes(32).toString("base64url"); }

  async issueLoginCode(request: NativeRequest) {
    this.assertEnabled();
    const actor = await this.native.actor(request);
    if("authContext" in actor && actor.authContext?.auth_method === "device_sn")denyDeviceSnCredentialDerivation();
    await this.native.requirePermission(actor, "/v1/tools/user-linked");
    // These transport/source prefixes are interpreted by historical consumers.
    let key = "";
    for (let attempt = 0; attempt < 20; attempt++) {
      const candidate = this.loginCodeCandidate();
      if (!candidate.startsWith("web_") && !candidate.startsWith("dsn_")) { key = candidate; break; }
    }
    if (!key) throw new ServiceUnavailableException("Login code generation is unavailable.");
    const issuedAt = this.now(); const expiresAt = issuedAt + LOGIN_CODE_LIFETIME_SECONDS;
    await this.repository.issueLoginCode(actor.id, digest(key), issuedAt, expiresAt,
      loginCodeContext(request.headers,this.native.config.corsOrigins));
    return { success: true, message: "user-linked", key, expires_at: expiresAt, expires_in: LOGIN_CODE_LIFETIME_SECONDS };
  }

  async loginCodeStatus(request: NativeRequest, input: unknown) {
    this.assertEnabled();
    const actor = await this.native.actor(request);
    await this.native.requirePermission(actor, "/v1/tools/user-linked");
    const code = normalizeLoginCode(input);
    if (!code) throw new BadRequestException("key is required");
    const stored = await this.repository.loginCode(digest(code));
    if (!stored || stored.userId !== actor.id) return { success: true, message: "user-linked-status", active: false, reason: "not_found" };
    const remaining = stored.expiresAt - this.now();
    return { success: true, message: "user-linked-status", active: remaining > 0, reason: remaining > 0 ? "active" : "expired",
      expires_at: stored.expiresAt, expires_in: Math.max(0, remaining) };
  }

  /** A code intentionally supports several devices inside the fixed 60s window. */
  async redeemLoginCode(input: string, context: RequestContext = {}): Promise<AuthTokenResponse> {
    this.assertEnabled();
    const code = normalizeLoginCode(input);
    const stored = code ? await this.repository.loginCode(digest(code)) : null;
    if (!stored || stored.expiresAt <= this.now()) throw new UnauthorizedException("Login code is invalid or expired.");
    // TokenIssuance rechecks current account status and creates a new session.
    // A caller's refresh idempotency key must not collapse distinct devices.
    const { idempotencyKey: _ignored, ...sessionContext } = context;
    return this.tokens.issueLegacyUserToken({ legacyUserId: stored.userId }, sessionContext);
  }

  async createWechatQr() {
    this.assertEnabled();
    const scene = randomBytes(32).toString("base64url");
    await this.repository.createWechatScene(digest(scene), this.now() + WECHAT_SCENE_LIFETIME_SECONDS);
    const result = await this.provider("qrcode", { scene, lifetimeSeconds: WECHAT_SCENE_LIFETIME_SECONDS });
    const nested = object(result.qrcode);
    const ticket = typeof result.ticket === "string" ? result.ticket : nested.ticket;
    if (typeof ticket !== "string" || !ticket) throw new ServiceUnavailableException("WeChat QR ticket is missing");
    const url = `https://mp.weixin.qq.com/cgi-bin/showqrcode?ticket=${encodeURIComponent(ticket)}`;
    return { qrcode: { ticket, url }, token: scene, lifetime: WECHAT_SCENE_LIFETIME_SECONDS };
  }

  /** Called only after auth-service has validated WeChat's callback signature. */
  async confirmWechatScan(payload: unknown) {
    this.assertEnabled(); const body = object(payload);
    const scene = requiredString(body.scene, "scene", 128);
    const openId = requiredString(body.openId, "openId", 255);
    const providerAppId = requiredString(body.providerAppId, "providerAppId", 128);
    const stored = await this.repository.wechatScene(digest(scene));
    if (!stored || stored.expiresAt <= this.now()) throw new UnauthorizedException("扫码凭据已过期");
    if (stored.openId && (stored.openId !== openId || stored.providerAppId !== providerAppId)) {
      throw new ConflictException("扫码凭据已经绑定其他微信账号");
    }
    const profile = await this.provider("profile", { openId });
    if (profile.openId !== openId) throw new ServiceUnavailableException("WeChat profile subject does not match");
    if (profile.providerAppId !== providerAppId) throw new UnauthorizedException("微信应用不匹配");
    const resolved = await this.resolveWechat({ providerAppId, openId, profile });
    await this.repository.confirmWechatScene(digest(scene), providerAppId, openId, resolved.userId,
      resolved.signupToken ? digest(resolved.signupToken) : null, profile, this.now());
    return { success: true };
  }

  async wechatStatus(input: unknown) {
    this.assertEnabled(); const token = requiredString(input, "token", 128);
    const scene = await this.activeWechatScene(token);
    if (!scene.openId || !scene.profile || !scene.providerAppId) return { success: false, message: "pending" };
    const resolved = await this.resolveWechat(scene);
    await this.repository.confirmWechatScene(digest(token),scene.providerAppId,scene.openId,resolved.userId,
      resolved.signupToken ? digest(resolved.signupToken) : null,scene.profile,this.now());
    return { success: true, message: resolved.userId ? "signin" : "signup", token: resolved.userId ? token : resolved.signupToken };
  }

  async wechatLogin(payload: unknown, context: RequestContext = {}) {
    this.assertEnabled(); const token = requiredString(object(payload).token, "token", 128);
    const scene = await this.activeWechatScene(token);
    if (!scene.openId || !scene.profile || !scene.providerAppId) throw new UnauthorizedException("微信扫码尚未完成");
    const resolved = await this.resolveWechat(scene);
    if (!resolved.userId) throw new UnauthorizedException("微信账号尚未注册");
    return this.tokens.issueLegacyUserToken({ legacyUserId: resolved.userId }, context);
  }

  async wechatRegister(payload: unknown, context: RequestContext = {}, idempotencyKey?: string): Promise<unknown> {
    this.assertEnabled();
    const body = object(payload);
    let token = requiredString(body.token, "token", 255);
    // Older signup pages retain the original scene instead of the polled signup token.
    let active = await this.repository.hasActiveRegistration(digest(token), this.now());
    const scene = active ? null : await this.repository.wechatScene(digest(token));
    if (scene) {
      if (scene.expiresAt <= this.now() || !scene.providerAppId || !scene.openId || !scene.profile)
        throw new UnauthorizedException("微信注册扫码凭据已过期");
      const resolved = await this.resolveWechat(scene);
      if (!resolved.signupToken || resolved.userId) throw new UnauthorizedException("微信账号已经注册");
      await this.repository.confirmWechatScene(
        digest(token),
        scene.providerAppId,
        scene.openId,
        null,
        digest(resolved.signupToken),
        scene.profile,
        this.now()
      );
      token = resolved.signupToken;
      active = await this.repository.hasActiveRegistration(digest(token), this.now());
    }
    if (!active) throw new UnauthorizedException("微信注册扫码凭据已过期");
    const result = await this.registration.register(
      "/v1/wechat/register",
      { ...body, token },
      { ...context, idempotencyKey: idempotencyKey ?? context.idempotencyKey }
    );
    return result.body;
  }

  async wechatBinding(payload: unknown, context: RequestContext = {}) {
    this.assertEnabled();
    const bound = await this.wechat.bindExisting(payload);
    const issued = await this.tokens.issueRegisteredUser(bound.user, context, bound.expectedPasswordHash);
    return { access_token: issued.token.accessToken, code: 20000 };
  }

  private resolveWechat(scene: { providerAppId: string | null; openId: string | null; profile: Record<string, unknown> | null }) {
    const profile = scene.profile!;
    return this.wechat.resolveWechat({ provider: "wechat_official_account", providerAppId: scene.providerAppId!, openId: scene.openId!,
      unionId: typeof profile.unionId === "string" ? profile.unionId : undefined,
      nickname: typeof profile.nickname === "string" ? profile.nickname : undefined,
      avatarUrl: typeof profile.avatarUrl === "string" ? profile.avatarUrl : undefined,
      raw: profile.raw && typeof profile.raw === "object" && !Array.isArray(profile.raw) ? object(profile.raw) : undefined }, false);
  }

  private async activeWechatScene(token: string) {
    const scene = await this.repository.wechatScene(digest(token));
    if (!scene || scene.expiresAt <= this.now()) throw new UnauthorizedException("扫码凭据已过期");
    return scene;
  }

  protected async provider(action: "qrcode" | "profile", payload: Record<string, unknown>): Promise<Record<string, unknown>> {
    const base = process.env.IDENTITY_WECHAT_PROVIDER_BASE_URL?.trim(); const key = this.internalToken;
    if (!base || !key) throw new ServiceUnavailableException("WeChat provider is not configured");
    let response: Response;
    try {
      response = await fetch(`${base.replace(/\/$/, "")}/internal/wechat-provider/${action}`, { method: "POST",
        headers: { "Content-Type": "application/json", "x-identity-internal-token": key },
        body: JSON.stringify(payload), signal: AbortSignal.timeout(5000) });
    } catch { throw new ServiceUnavailableException("WeChat provider is unavailable"); }
    if (!response.ok) throw new ServiceUnavailableException("WeChat provider rejected the request");
    try { const body = object(await response.json()); return body.data ? object(body.data) : body; }
    catch { throw new ServiceUnavailableException("WeChat provider returned an invalid response"); }
  }
}

export function normalizeLoginCode(input: unknown): string {
  if (typeof input !== "string" || input.length > 4096) return "";
  let value = input.trim();
  const urlCode = value.match(/(?:^|[?&])web_([^&#\s]+)/);
  if (urlCode) value = urlCode[1]; else if (value.startsWith("web_")) value = value.slice(4);
  return /^[A-Za-z0-9_-]{16,128}$/.test(value) ? value : "";
}
function object(value: unknown): Record<string, unknown> { return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {}; }
function requiredString(value: unknown, name: string, max: number): string {
  if (typeof value !== "string" || !value.trim() || value.length > max) throw new BadRequestException(`${name} is required`);
  return value;
}
function digest(value: string) { return createHash("sha256").update(value).digest("hex"); }
