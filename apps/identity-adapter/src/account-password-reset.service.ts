import { HttpException, Injectable, ServiceUnavailableException } from "@nestjs/common";
import { z } from "zod";
import {
  AccountLifecycleOperationInProgressError,
  AccountLifecycleOperationRepository,
  operationKeyForPasswordReset
} from "./account-lifecycle-operation.repository.js";
import { AccountPasswordRepository } from "./account-password.repository.js";
import { loadConfig } from "./config.js";
import { EmailDeliveryService } from "./email-delivery.service.js";
import { IdentitySessionRepository } from "./identity-session.repository.js";
import { LegacySessionRevocationService } from "./legacy-session-revocation.service.js";
import { PasswordResetChallengeError, PasswordResetChallengeRepository } from "./password-reset-challenge.repository.js";
import { validatePasswordPolicy } from "./password-policy.js";

const requestResetSchema = z.object({
  email: z.string().trim().email(),
  locale: z.string().trim().optional(),
  i18n: z.record(z.unknown()).optional()
});

const verifyCodeSchema = z.object({
  email: z.string().trim().email(),
  code: z.string().trim().regex(/^\d{6}$/)
});

const resetSchema = z.object({
  email: z.string().trim().email(),
  code: z.string().trim().regex(/^\d{6}$/),
  password: z.string().min(1).max(1024)
});

@Injectable()
export class AccountPasswordResetService {
  private readonly config = loadConfig();

  constructor(
    private readonly passwords: AccountPasswordRepository,
    private readonly challenges: PasswordResetChallengeRepository,
    private readonly operations: AccountLifecycleOperationRepository,
    private readonly sessions: IdentitySessionRepository,
    private readonly legacySessions: LegacySessionRevocationService,
    private readonly emailDelivery: EmailDeliveryService
  ) {}

  isResetNativeReady(): boolean {
    return (
      this.config.accountLifecycle.passwordResetNativeEnabled &&
      this.passwords.isConfigured() &&
      this.challenges.isConfigured() &&
      this.operations.isConfigured() &&
      this.sessions.isConfigured() &&
      this.emailDelivery.isConfigured()
    );
  }

  async handle(path: string, payload: unknown): Promise<{ status: number; body: unknown }> {
    this.assertResetNativeReady();

    if (path === "/v1/password/request-reset") {
      return { status: 200, body: await this.requestReset(payload) };
    }
    if (path === "/v1/password/verify-code") {
      return { status: 200, body: await this.verifyCode(payload) };
    }
    if (path === "/v1/password/reset") {
      return { status: 200, body: await this.reset(payload) };
    }

    throw new HttpException(
      {
        code: "PASSWORD_RESET_NATIVE_PATH_NOT_SUPPORTED",
        message: `Native password reset path ${path} is not supported.`
      },
      404
    );
  }

  private async requestReset(payload: unknown) {
    const parsed = parseBody(requestResetSchema, payload);
    const email = parsed.email.toLowerCase();
    const user = await this.passwords.getCredentialByEmail(email);
    if (!user || user.emailVerifiedAt === null) {
      throw passwordError(400, "EMAIL_NOT_VERIFIED", "邮箱未验证，无法重置密码");
    }

    try {
      const { code } = await this.challenges.createChallenge({
        email,
        legacyUserId: user.id
      });
      await this.emailDelivery.sendPasswordResetCode({
        email,
        code,
        locale: parsed.locale,
        i18n: parsed.i18n
      });

      return {
        success: true,
        message: "找回密码验证码已发送到您的邮箱"
      };
    } catch (error) {
      throw this.mapChallengeError(error);
    }
  }

  private async verifyCode(payload: unknown) {
    const parsed = parseBody(verifyCodeSchema, payload);
    try {
      await this.challenges.verifyCode(parsed.email, parsed.code);
      return {
        success: true,
        valid: true,
        message: "验证码有效"
      };
    } catch (error) {
      throw this.mapChallengeError(error);
    }
  }

  private async reset(payload: unknown) {
    const parsed = parseBody(resetSchema, payload);
    const email = parsed.email.toLowerCase();
    const operationKey = operationKeyForPasswordReset(email, parsed.code, parsed.password);
    const operation = {
      operationKey,
      operationType: "password.reset",
      username: null,
      email,
      metadata: {
        provider: "identity-service",
        path: "/v1/password/reset"
      }
    };

    try {
      const completed = await this.operations.findCompleted(operationKey);
      if (completed) {
        return resetSuccess();
      }

      await this.operations.begin(operation);
      const challenge = await this.challenges.verifyCode(email, parsed.code);
      const user = await this.passwords.getCredentialByEmail(email);
      if (!user || user.id !== challenge.legacyUserId) {
        throw passwordError(400, "INVALID_CODE", "用户不存在");
      }
      const passwordErrors = validatePasswordPolicy(parsed.password, {
        username: user.username,
        email: user.email
      });
      if (passwordErrors.length > 0) {
        throw validationError({ password: passwordErrors });
      }

      const changedUser = await this.passwords.changePassword(user, parsed.password);
      await this.challenges.consume(challenge.challengeKey);
      await this.operations.complete({
        ...operation,
        username: user.username,
        user: changedUser
      });
      await this.sessions.revokeUserSessions(user.id);
      await this.legacySessions.revokeUserSessions(user.id, "password.reset");

      return resetSuccess();
    } catch (error) {
      if (error instanceof AccountLifecycleOperationInProgressError) {
        throw passwordError(409, "PASSWORD_RESET_OPERATION_IN_PROGRESS", "同一重置密码操作正在处理中");
      }
      if (error instanceof HttpException) {
        await this.failOperationQuietly(operation, error);
        throw error;
      }
      try {
        throw this.mapChallengeError(error);
      } catch (mapped) {
        await this.failOperationQuietly(operation, mapped);
        throw mapped;
      }
    }
  }

  private assertResetNativeReady(): void {
    if (!this.config.accountLifecycle.passwordResetNativeEnabled) {
      throw new ServiceUnavailableException({
        code: "PASSWORD_RESET_NATIVE_DISABLED",
        message: "Native password reset is disabled."
      });
    }
    if (!this.passwords.isConfigured()) {
      throw new ServiceUnavailableException({
        code: "LEGACY_WRITE_DB_NOT_CONFIGURED",
        message: "Legacy write database is not configured."
      });
    }
    if (!this.challenges.isConfigured() || !this.operations.isConfigured()) {
      throw new ServiceUnavailableException({
        code: "IDENTITY_DB_REQUIRED_FOR_PASSWORD_RESET_NATIVE",
        message: "Identity database is required for native password reset."
      });
    }
    if (!this.emailDelivery.isConfigured()) {
      throw new ServiceUnavailableException({
        code: "EMAIL_WEBHOOK_NOT_CONFIGURED",
        message: "Email delivery webhook is not configured."
      });
    }
  }

  private mapChallengeError(error: unknown): HttpException {
    if (error instanceof PasswordResetChallengeError) {
      const code = error.code === "RATE_LIMIT_EXCEEDED" ? "RATE_LIMIT_EXCEEDED" : error.code === "ACCOUNT_LOCKED" ? "ACCOUNT_LOCKED" : "INVALID_CODE";
      return passwordError(error.status, code, error.message, error.retryAfter);
    }

    if (error instanceof HttpException) {
      return error;
    }

    throw error;
  }

  private async failOperationQuietly(
    operation: {
      operationKey: string;
      operationType: string;
      username: string | null;
      email: string | null;
      metadata?: Record<string, unknown> | null;
    },
    error: unknown
  ): Promise<void> {
    try {
      await this.operations.fail({
        ...operation,
        errorCode: error instanceof HttpException ? `HTTP_${error.getStatus()}` : error instanceof Error ? error.name : "UNKNOWN_ERROR"
      });
    } catch {
      // Keep the original reset error visible.
    }
  }
}

function parseBody<T extends z.ZodTypeAny>(schema: T, payload: unknown): z.infer<T> {
  const parsed = schema.safeParse(payload);
  if (!parsed.success) {
    throw validationError(parsed.error.flatten().fieldErrors);
  }

  return parsed.data;
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

function passwordError(status: number, code: string, message: string, retryAfter?: number): HttpException {
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

function resetSuccess() {
  return {
    success: true,
    message: "密码重置成功，请使用新密码登录"
  };
}
