import { HttpException, Injectable, ServiceUnavailableException, UnauthorizedException } from "@nestjs/common";
import { z } from "zod";
import { AccountEmailRepository, EmailUserProfile, NativeEmailError, normalizeEmail } from "./account-email.repository.js";
import { loadConfig } from "./config.js";
import { EmailChangeTokenError, EmailChangeTokenRepository } from "./email-change-token.repository.js";
import { EmailDeliveryService } from "./email-delivery.service.js";
import { EmailVerificationChallengeError, EmailVerificationChallengeRepository } from "./email-verification-challenge.repository.js";
import { JwtIssuerService } from "./jwt-issuer.service.js";

const basicEmailNativePaths = ["/v1/email/status", "/v1/email/send-verification", "/v1/email/verify", "/v1/email/cooldown"];
const emailChangeNativePaths = ["/v1/email/send-change-confirmation", "/v1/email/verify-change-confirmation", "/v1/email/unbind"];

const sendVerificationSchema = z.object({
  email: z.string().trim().email(),
  locale: z.string().trim().optional(),
  i18n: z.record(z.unknown()).optional()
});

const verifyEmailSchema = z.object({
  email: z.string().trim().email(),
  code: z.string().trim().regex(/^\d{6}$/),
  change_token: z.string().trim().optional()
});

const sendChangeConfirmationSchema = z.object({
  locale: z.string().trim().optional(),
  i18n: z.record(z.unknown()).optional()
});

const verifyChangeConfirmationSchema = z.object({
  code: z.string().trim().regex(/^\d{6}$/)
});

const unbindEmailSchema = z.object({
  code: z.string().trim().regex(/^\d{6}$/).optional()
});

export class EmailNativeFallbackRequiredError extends Error {
  constructor(readonly reason: string) {
    super(reason);
    this.name = "EmailNativeFallbackRequiredError";
  }
}

@Injectable()
export class AccountEmailService {
  private readonly config = loadConfig();

  constructor(
    private readonly emails: AccountEmailRepository,
    private readonly challenges: EmailVerificationChallengeRepository,
    private readonly changeTokens: EmailChangeTokenRepository,
    private readonly emailDelivery: EmailDeliveryService,
    private readonly jwtIssuer: JwtIssuerService
  ) {}

  isVerifyNativeReady(): boolean {
    return (
      this.config.accountLifecycle.emailVerifyNativeEnabled &&
      this.emails.isConfigured() &&
      this.challenges.isConfigured() &&
      this.emailDelivery.isConfigured()
    );
  }

  isChangeNativeReady(): boolean {
    return this.config.accountLifecycle.emailChangeNativeEnabled && this.isVerifyNativeReady() && this.changeTokens.isConfigured();
  }

  supports(path: string): boolean {
    return [...basicEmailNativePaths, ...emailChangeNativePaths].includes(path);
  }

  isEnabledForPath(path: string, payload: unknown): boolean {
    if (emailChangeNativePaths.includes(path)) {
      return this.config.accountLifecycle.emailChangeNativeEnabled;
    }
    if (path === "/v1/email/verify" && hasChangeToken(payload)) {
      return this.config.accountLifecycle.emailChangeNativeEnabled;
    }

    return this.config.accountLifecycle.emailVerifyNativeEnabled;
  }

  async handle(
    path: string,
    payload: unknown,
    request: { authorization?: string | string[]; originalUrl?: string }
  ): Promise<{ status: number; body: unknown }> {
    const user = await this.currentUser(request.authorization);

    if (path === "/v1/email/status") {
      this.assertEmailVerifyNativeReady();
      return { status: 200, body: statusResponse(user) };
    }
    if (path === "/v1/email/send-verification") {
      this.assertEmailVerifyNativeReady();
      return { status: 200, body: await this.sendVerification(user, payload) };
    }
    if (path === "/v1/email/verify") {
      this.assertEmailVerifyNativeReady();
      return { status: 200, body: await this.verify(user, payload) };
    }
    if (path === "/v1/email/cooldown") {
      this.assertEmailVerifyNativeReady();
      return { status: 200, body: await this.cooldown(user, request.originalUrl) };
    }
    if (path === "/v1/email/send-change-confirmation") {
      this.assertEmailChangeNativeReady();
      return { status: 200, body: await this.sendChangeConfirmation(user, payload) };
    }
    if (path === "/v1/email/verify-change-confirmation") {
      this.assertEmailChangeNativeReady();
      return { status: 200, body: await this.verifyChangeConfirmation(user, payload) };
    }
    if (path === "/v1/email/unbind") {
      this.assertEmailChangeNativeReady();
      return { status: 200, body: await this.unbind(user, payload) };
    }

    throw new EmailNativeFallbackRequiredError(`Native email path ${path} is not supported.`);
  }

  private async sendVerification(user: EmailUserProfile, payload: unknown) {
    const parsed = parseBody(sendVerificationSchema, payload);
    const email = normalizeEmail(parsed.email);
    this.assertCanSendVerificationForTarget(user, email);

    try {
      await this.assertEmailNotBoundByOther(email, user.id);
      const { code } = await this.challenges.createChallenge({
        email,
        legacyUserId: user.id
      });
      await this.emailDelivery.sendEmailVerificationCode({
        email,
        code,
        locale: parsed.locale,
        i18n: parsed.i18n
      });

      return {
        success: true,
        message: "验证码已发送到您的邮箱"
      };
    } catch (error) {
      throw this.mapEmailError(error);
    }
  }

  private async verify(user: EmailUserProfile, payload: unknown) {
    const parsed = parseBody(verifyEmailSchema, payload);
    const email = normalizeEmail(parsed.email);

    try {
      const changeTokenRecord = await this.verifyChangeTokenIfRequired(user, email, parsed.change_token);
      const challenge = await this.challenges.verifyCode(email, parsed.code);
      if (challenge.legacyUserId !== user.id) {
        throw new EmailVerificationChallengeError(400, "INVALID_CODE", "验证码不存在或已过期");
      }
      await this.assertEmailNotBoundByOther(email, user.id);
      const verifiedAt = Math.floor(Date.now() / 1000);
      const updatedUser = await this.emails.bindVerifiedEmail(user.id, email, verifiedAt);
      await this.challenges.consume(challenge.challengeKey);
      if (changeTokenRecord) {
        await this.changeTokens.consume(changeTokenRecord.tokenKey);
      }

      return {
        success: true,
        message: "邮箱验证并绑定成功",
        data: {
          user: {
            id: updatedUser.id,
            username: updatedUser.username,
            email: updatedUser.email,
            email_verified_at: updatedUser.emailVerifiedAt
          }
        }
      };
    } catch (error) {
      throw this.mapEmailError(error);
    }
  }

  private async sendChangeConfirmation(user: EmailUserProfile, payload: unknown) {
    const parsed = parseBody(sendChangeConfirmationSchema, payload ?? {});
    const currentEmail = this.requireCurrentVerifiedEmail(user, "send-change");

    try {
      const { code } = await this.challenges.createChallenge({
        email: currentEmail,
        legacyUserId: user.id
      });
      await this.emailDelivery.sendEmailVerificationCode({
        email: currentEmail,
        code,
        locale: parsed.locale,
        i18n: parsed.i18n
      });

      return {
        success: true,
        message: "二次确认验证码已发送到当前绑定邮箱"
      };
    } catch (error) {
      throw this.mapEmailError(error);
    }
  }

  private async verifyChangeConfirmation(user: EmailUserProfile, payload: unknown) {
    const parsed = parseBody(verifyChangeConfirmationSchema, payload);
    const currentEmail = this.requireCurrentVerifiedEmail(user, "verify-change");

    try {
      const challenge = await this.challenges.verifyCode(currentEmail, parsed.code);
      if (challenge.legacyUserId !== user.id) {
        throw new EmailVerificationChallengeError(400, "INVALID_CODE", "验证码不存在或已过期");
      }

      await this.challenges.consume(challenge.challengeKey);
      const { token, expiresIn } = await this.changeTokens.createToken(user.id);

      return {
        success: true,
        message: "旧邮箱验证成功，请在 10 分钟内完成新邮箱绑定",
        data: {
          change_token: token,
          expires_in: expiresIn
        }
      };
    } catch (error) {
      throw this.mapEmailError(error);
    }
  }

  private async unbind(user: EmailUserProfile, payload: unknown) {
    const parsed = parseBody(unbindEmailSchema, payload ?? {});
    if (!user.email) {
      throw emailError(400, "INVALID_REQUEST", "当前账号未绑定邮箱");
    }

    const currentEmail = normalizeEmail(user.email);
    let challengeKey: string | null = null;
    try {
      if (user.emailVerifiedAt !== null) {
        if (!parsed.code) {
          throw validationError({
            code: ["验证码不能为空"]
          });
        }
        const challenge = await this.challenges.verifyCode(currentEmail, parsed.code);
        if (challenge.legacyUserId !== user.id) {
          throw new EmailVerificationChallengeError(400, "INVALID_CODE", "验证码不存在或已过期");
        }
        challengeKey = challenge.challengeKey;
      }

      const updatedAt = Math.floor(Date.now() / 1000);
      const updatedUser = await this.emails.unbindEmail(user.id, updatedAt);
      if (challengeKey) {
        await this.challenges.consume(challengeKey);
      }

      return {
        success: true,
        message: "邮箱解绑成功",
        data: {
          user: {
            id: updatedUser.id,
            username: updatedUser.username,
            email: updatedUser.email,
            email_verified_at: updatedUser.emailVerifiedAt
          }
        }
      };
    } catch (error) {
      throw this.mapEmailError(error);
    }
  }

  private async cooldown(user: EmailUserProfile, originalUrl: string | undefined) {
    const email = normalizeEmail(getQueryParam(originalUrl, "email") ?? user.email ?? "");
    if (!email) {
      throw validationError({
        email: ["email cannot be blank."]
      });
    }
    const parsedEmail = z.string().email().safeParse(email);
    if (!parsedEmail.success) {
      throw validationError({
        email: ["email is not a valid email address."]
      });
    }

    const cooldown = await this.challenges.getCooldown(email);
    return {
      success: true,
      data: {
        email,
        can_send: cooldown.canSend,
        retry_after: cooldown.retryAfter,
        limit_seconds: cooldown.limitSeconds
      }
    };
  }

  private async currentUser(authorization: string | string[] | undefined): Promise<EmailUserProfile> {
    const token = bearerToken(authorization);
    if (!token) {
      throw unauthorized("用户未登录");
    }

    let claims: { uid: number };
    try {
      claims = this.jwtIssuer.verifyAccessToken(token);
    } catch {
      throw unauthorized("用户未登录");
    }

    const user = await this.emails.getUserById(claims.uid);
    if (!user) {
      throw unauthorized("用户未登录");
    }

    return user;
  }

  private assertEmailVerifyNativeReady(): void {
    if (!this.config.accountLifecycle.emailVerifyNativeEnabled) {
      throw new ServiceUnavailableException({
        code: "EMAIL_VERIFY_NATIVE_DISABLED",
        message: "Native email verification is disabled."
      });
    }
    if (!this.emails.isConfigured()) {
      throw new ServiceUnavailableException({
        code: "LEGACY_WRITE_DB_NOT_CONFIGURED",
        message: "Legacy write database is not configured."
      });
    }
    if (!this.challenges.isConfigured()) {
      throw new ServiceUnavailableException({
        code: "IDENTITY_DB_REQUIRED_FOR_EMAIL_NATIVE",
        message: "Identity database is required for native email verification."
      });
    }
    if (!this.emailDelivery.isConfigured()) {
      throw new ServiceUnavailableException({
        code: "EMAIL_WEBHOOK_NOT_CONFIGURED",
        message: "Email delivery webhook is not configured."
      });
    }
  }

  private assertEmailChangeNativeReady(): void {
    if (!this.config.accountLifecycle.emailChangeNativeEnabled) {
      throw new ServiceUnavailableException({
        code: "EMAIL_CHANGE_NATIVE_DISABLED",
        message: "Native email change is disabled."
      });
    }
    this.assertEmailVerifyNativeReady();
    if (!this.changeTokens.isConfigured()) {
      throw new ServiceUnavailableException({
        code: "IDENTITY_DB_REQUIRED_FOR_EMAIL_CHANGE_NATIVE",
        message: "Identity database is required for native email change."
      });
    }
  }

  private assertCanSendVerificationForTarget(user: EmailUserProfile, targetEmail: string): void {
    if (user.email && normalizeEmail(user.email) !== targetEmail && user.emailVerifiedAt !== null) {
      if (!this.config.accountLifecycle.emailChangeNativeEnabled) {
        throw new EmailNativeFallbackRequiredError("verified email change requires legacy flow");
      }
      this.assertEmailChangeNativeReady();
    }
  }

  private async verifyChangeTokenIfRequired(user: EmailUserProfile, targetEmail: string, changeToken: string | undefined) {
    if (!user.email || normalizeEmail(user.email) === targetEmail || user.emailVerifiedAt === null) {
      return null;
    }

    if (!this.config.accountLifecycle.emailChangeNativeEnabled) {
      throw new EmailNativeFallbackRequiredError("email change token still requires legacy flow");
    }

    this.assertEmailChangeNativeReady();
    return this.changeTokens.verifyToken(user.id, changeToken);
  }

  private requireCurrentVerifiedEmail(user: EmailUserProfile, action: "send-change" | "verify-change"): string {
    if (!user.email) {
      throw new NativeEmailError(400, "INVALID_STATE", "当前账号未绑定邮箱");
    }
    if (user.emailVerifiedAt === null) {
      const message = action === "send-change" ? "当前邮箱未验证，无需二次确认，可直接改绑" : "当前账号未绑定已验证邮箱";
      throw new NativeEmailError(400, "INVALID_STATE", message);
    }

    return normalizeEmail(user.email);
  }

  private async assertEmailNotBoundByOther(email: string, legacyUserId: number): Promise<void> {
    if (await this.emails.isEmailBoundByOther(email, legacyUserId)) {
      throw new NativeEmailError(400, "INVALID_CODE", "该邮箱已被其他账号绑定");
    }
  }

  private mapEmailError(error: unknown): HttpException {
    if (error instanceof EmailNativeFallbackRequiredError) {
      throw error;
    }
    if (error instanceof EmailVerificationChallengeError) {
      const code =
        error.code === "RATE_LIMIT_EXCEEDED" ? "RATE_LIMIT_EXCEEDED" : error.code === "ACCOUNT_LOCKED" ? "ACCOUNT_LOCKED" : "INVALID_CODE";
      return emailError(error.status, code, error.message, error.retryAfter);
    }
    if (error instanceof EmailChangeTokenError) {
      return emailError(error.status, error.code, error.message);
    }
    if (error instanceof NativeEmailError) {
      return emailError(error.status, error.code, error.message);
    }
    if (error instanceof HttpException) {
      return error;
    }

    throw error;
  }
}

function bearerToken(authorization: string | string[] | undefined): string | null {
  const header = Array.isArray(authorization) ? authorization[0] : authorization;
  if (!header?.startsWith("Bearer ")) {
    return null;
  }

  return header.slice("Bearer ".length).trim() || null;
}

function parseBody<T extends z.ZodTypeAny>(schema: T, payload: unknown): z.infer<T> {
  const parsed = schema.safeParse(payload);
  if (!parsed.success) {
    throw validationError(parsed.error.flatten().fieldErrors);
  }

  return parsed.data;
}

function hasChangeToken(payload: unknown): boolean {
  return Boolean(payload && typeof payload === "object" && "change_token" in payload && typeof (payload as { change_token?: unknown }).change_token === "string");
}

function validationError(details: Record<string, string[] | undefined>): HttpException {
  return new HttpException(
    {
      success: false,
      error: {
        code: "VALIDATION_ERROR",
        message: "请求参数验证失败",
        details
      }
    },
    400
  );
}

function emailError(status: number, code: string, message: string, retryAfter?: number): HttpException {
  return new HttpException(
    {
      success: false,
      error: {
        code,
        message,
        ...(retryAfter ? { retry_after: retryAfter } : {})
      }
    },
    status
  );
}

function unauthorized(message: string): UnauthorizedException {
  return new UnauthorizedException({
    success: false,
    error: {
      code: "UNAUTHORIZED",
      message
    }
  });
}

function statusResponse(user: EmailUserProfile) {
  const isVerified = user.emailVerifiedAt !== null;
  return {
    success: true,
    data: {
      user_id: user.id,
      username: user.username,
      email: user.email,
      email_verified: isVerified,
      email_verified_at: user.emailVerifiedAt,
      email_verified_at_formatted: user.emailVerifiedAt ? formatLegacyTimestamp(user.emailVerifiedAt) : null
    }
  };
}

function formatLegacyTimestamp(seconds: number): string {
  const date = new Date(seconds * 1000);
  return [
    date.getFullYear(),
    pad(date.getMonth() + 1),
    pad(date.getDate())
  ].join("-") + ` ${[pad(date.getHours()), pad(date.getMinutes()), pad(date.getSeconds())].join(":")}`;
}

function pad(value: number): string {
  return String(value).padStart(2, "0");
}

function getQueryParam(originalUrl: string | undefined, name: string): string | null {
  const index = originalUrl?.indexOf("?") ?? -1;
  if (index < 0 || !originalUrl) {
    return null;
  }

  return new URLSearchParams(originalUrl.slice(index + 1)).get(name);
}
