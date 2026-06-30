import { HttpException, Injectable, NotFoundException, ServiceUnavailableException } from "@nestjs/common";
import { AccountEmailService, EmailNativeFallbackRequiredError } from "./account-email.service.js";
import { AccountInvitationService, InvitationNativeFallbackRequiredError } from "./account-invitation.service.js";
import { AccountPasswordResetService } from "./account-password-reset.service.js";
import { AccountPasswordService } from "./account-password.service.js";
import { AccountRegistrationService } from "./account-registration.service.js";
import { loadConfig } from "./config.js";

export type AccountLifecycleScope = "register" | "password" | "email" | "invitation";

const LEGACY_REGISTER_PROXY_ONLY_PATHS = new Set(["/v1/wechat/qrcode", "/v1/wechat/refresh"]);

export interface AccountLifecycleProxyResponse {
  status: number;
  body: unknown;
}

@Injectable()
export class AccountLifecycleService {
  private readonly config = loadConfig();

  constructor(
    private readonly accountRegistration: AccountRegistrationService,
    private readonly accountPassword: AccountPasswordService,
    private readonly accountPasswordReset: AccountPasswordResetService,
    private readonly accountEmail: AccountEmailService,
    private readonly accountInvitation: AccountInvitationService
  ) {}

  readiness() {
    const { accountLifecycle } = this.config;

    return {
      enabled: accountLifecycle.enabled,
      mode: accountLifecycle.mode,
      legacyProxyConfigured: Boolean(accountLifecycle.legacyApiBaseUrl),
      nativeRegisterConfigured: this.accountRegistration.isNativeReady(),
      nativePasswordChangeConfigured: this.accountPassword.isChangeNativeReady(),
      nativePasswordResetConfigured: this.accountPasswordReset.isResetNativeReady(),
      nativeEmailVerifyConfigured: this.accountEmail.isVerifyNativeReady(),
      nativeEmailChangeConfigured: this.accountEmail.isChangeNativeReady(),
      nativeInvitationManagementConfigured: this.accountInvitation.isManagementNativeReady(),
      nativeInvitationCheckConfigured: this.accountInvitation.isCheckNativeReady(),
      nativeInvitationRecordsConfigured: this.accountInvitation.isRecordsNativeReady(),
      scopes: {
        register: accountLifecycle.registerEnabled,
        password: accountLifecycle.passwordEnabled,
        passwordChangeNative: accountLifecycle.passwordChangeNativeEnabled,
        passwordResetNative: accountLifecycle.passwordResetNativeEnabled,
        email: accountLifecycle.emailEnabled,
        emailVerifyNative: accountLifecycle.emailVerifyNativeEnabled,
        emailChangeNative: accountLifecycle.emailChangeNativeEnabled,
        invitation: accountLifecycle.invitationEnabled,
        invitationManagementNative: accountLifecycle.invitationManagementNativeEnabled,
        invitationCheckNative: accountLifecycle.invitationCheckNativeEnabled,
        invitationRecordsNative: accountLifecycle.invitationRecordsNativeEnabled
      }
    };
  }

  async proxy(scope: AccountLifecycleScope, request: AccountLifecycleRequest, path: string): Promise<AccountLifecycleProxyResponse> {
    this.assertScopeEnabled(scope);

    const { accountLifecycle } = this.config;
    if (accountLifecycle.mode === "legacy-proxy") {
      if (!accountLifecycle.legacyApiBaseUrl) {
        throw new ServiceUnavailableException({
          code: "ACCOUNT_LIFECYCLE_LEGACY_API_NOT_CONFIGURED",
          message: "Legacy account API base URL is not configured."
        });
      }

      return this.forwardToLegacy(request, path);
    }

    if (accountLifecycle.mode === "native") {
      if (scope === "register") {
        if (LEGACY_REGISTER_PROXY_ONLY_PATHS.has(path) && accountLifecycle.legacyApiBaseUrl) {
          return this.forwardToLegacy(request, path);
        }

        return this.accountRegistration.register(path, request.body, requestContext(request));
      }
      if (scope === "password" && path === "/v1/password/change") {
        return this.accountPassword.changePassword(request.body, request.headers.authorization);
      }
      if (scope === "password" && ["/v1/password/request-reset", "/v1/password/verify-code", "/v1/password/reset"].includes(path)) {
        if (accountLifecycle.passwordResetNativeEnabled) {
          return this.accountPasswordReset.handle(path, request.body);
        }
      }
      if (scope === "email" && this.accountEmail.supports(path) && this.accountEmail.isEnabledForPath(path, request.body)) {
        try {
          return await this.accountEmail.handle(path, request.body, {
            authorization: request.headers.authorization,
            originalUrl: request.originalUrl
          });
        } catch (error) {
          if (!(error instanceof EmailNativeFallbackRequiredError)) {
            throw error;
          }
        }
      }
      if (scope === "invitation" && this.accountInvitation.supports(path) && this.accountInvitation.isEnabledForPath(path)) {
        try {
          return await this.accountInvitation.handle(path, request.body, {
            authorization: request.headers.authorization,
            originalUrl: request.originalUrl
          });
        } catch (error) {
          if (!(error instanceof InvitationNativeFallbackRequiredError)) {
            throw error;
          }
        }
      }
      if (accountLifecycle.legacyApiBaseUrl) {
        return this.forwardToLegacy(request, path);
      }

      throw new NotFoundException({
        code: "ACCOUNT_LIFECYCLE_NATIVE_SCOPE_NOT_READY",
        message: `Account lifecycle scope ${scope} is not native-ready.`
      });
    }

    throw new NotFoundException({
      code: "ACCOUNT_LIFECYCLE_MODE_DISABLED",
      message: "Account lifecycle mode is disabled."
    });
  }

  private assertScopeEnabled(scope: AccountLifecycleScope): void {
    const { accountLifecycle } = this.config;
    if (!accountLifecycle.enabled) {
      throw new NotFoundException({
        code: "ACCOUNT_LIFECYCLE_DISABLED",
        message: "Account lifecycle migration is disabled."
      });
    }

    const enabledByScope: Record<AccountLifecycleScope, boolean> = {
      register: accountLifecycle.registerEnabled,
      password: accountLifecycle.passwordEnabled,
      email: accountLifecycle.emailEnabled,
      invitation: accountLifecycle.invitationEnabled
    };
    if (!enabledByScope[scope]) {
      throw new NotFoundException({
        code: "ACCOUNT_LIFECYCLE_SCOPE_DISABLED",
        message: `Account lifecycle scope ${scope} is disabled.`
      });
    }
  }

  private async forwardToLegacy(request: AccountLifecycleRequest, path: string): Promise<AccountLifecycleProxyResponse> {
    const { accountLifecycle } = this.config;
    const url = new URL(path, `${accountLifecycle.legacyApiBaseUrl!.replace(/\/+$/, "")}/`);
    const query = queryStringFromOriginalUrl(request.originalUrl);
    if (query) {
      url.search = query;
    }

    const headers = new Headers({
      Accept: "application/json",
      "X-Identity-Lifecycle-Proxy": "1"
    });
    const authorization = firstHeader(request.headers.authorization);
    const forwardedFor = firstHeader(request.headers["x-forwarded-for"]);
    const userAgent = firstHeader(request.headers["user-agent"]);
    if (authorization) {
      headers.set("Authorization", authorization);
    }
    if (forwardedFor) {
      headers.set("X-Forwarded-For", forwardedFor);
    }
    if (userAgent) {
      headers.set("User-Agent", userAgent);
    }

    const method = request.method.toUpperCase();
    const hasBody = !["GET", "HEAD"].includes(method);
    const init: RequestInit = {
      method,
      headers,
      signal: AbortSignal.timeout(accountLifecycle.timeoutMs)
    };
    if (hasBody) {
      headers.set("Content-Type", "application/json");
      init.body = JSON.stringify(request.body ?? {});
    }

    let upstream: Response;
    try {
      upstream = await fetch(url, init);
    } catch (error) {
      throw new ServiceUnavailableException({
        code: "ACCOUNT_LIFECYCLE_LEGACY_API_UNAVAILABLE",
        message: "Legacy account API is unavailable.",
        detail: error instanceof Error ? error.message : String(error)
      });
    }

    const body = await parseUpstreamBody(upstream);
    if (upstream.status >= 400) {
      throw new HttpException(toHttpExceptionBody(body), upstream.status);
    }

    return {
      status: upstream.status,
      body
    };
  }
}

export interface AccountLifecycleRequest {
  method: string;
  originalUrl?: string;
  headers: Record<string, string | string[] | undefined>;
  body?: unknown;
}

function firstHeader(value: string | string[] | undefined): string | null {
  if (Array.isArray(value)) {
    return value[0] ?? null;
  }

  return value ?? null;
}

function requestContext(request: AccountLifecycleRequest): { ip?: string | null; userAgent?: string | null } {
  return {
    ip: firstHeader(request.headers["x-forwarded-for"]),
    userAgent: firstHeader(request.headers["user-agent"])
  };
}

function queryStringFromOriginalUrl(originalUrl: string | undefined): string {
  const index = originalUrl?.indexOf("?") ?? -1;
  return index >= 0 && originalUrl ? originalUrl.slice(index + 1) : "";
}

async function parseUpstreamBody(response: Response): Promise<unknown> {
  const text = await response.text();
  if (text.trim() === "") {
    return {};
  }

  try {
    return JSON.parse(text);
  } catch {
    return {
      message: text
    };
  }
}

function toHttpExceptionBody(value: unknown): string | Record<string, unknown> {
  if (typeof value === "string") {
    return value;
  }
  if (value && typeof value === "object" && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }

  return { data: value };
}
