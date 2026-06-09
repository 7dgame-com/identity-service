import { HttpException, Injectable, ServiceUnavailableException, UnauthorizedException } from "@nestjs/common";
import { z } from "zod";
import {
  AccountLifecycleOperationInProgressError,
  AccountLifecycleOperationRepository,
  operationKeyForPasswordChange
} from "./account-lifecycle-operation.repository.js";
import { AccountPasswordRepository, NativePasswordError } from "./account-password.repository.js";
import { loadConfig } from "./config.js";
import { IdentitySessionRepository } from "./identity-session.repository.js";
import { JwtIssuerService } from "./jwt-issuer.service.js";
import { LegacySessionRevocationService } from "./legacy-session-revocation.service.js";
import { validatePasswordPolicy } from "./password-policy.js";

const changePasswordSchema = z.object({
  old_password: z.string().min(1).max(1024),
  new_password: z.string().min(1).max(1024),
  confirm_password: z.string().min(1).max(1024)
});

@Injectable()
export class AccountPasswordService {
  private readonly config = loadConfig();

  constructor(
    private readonly passwords: AccountPasswordRepository,
    private readonly operations: AccountLifecycleOperationRepository,
    private readonly sessions: IdentitySessionRepository,
    private readonly legacySessions: LegacySessionRevocationService,
    private readonly jwtIssuer: JwtIssuerService
  ) {}

  isChangeNativeReady(): boolean {
    return (
      this.config.accountLifecycle.passwordChangeNativeEnabled &&
      this.passwords.isConfigured() &&
      this.operations.isConfigured() &&
      this.sessions.isConfigured()
    );
  }

  async changePassword(payload: unknown, authorization: string | string[] | undefined): Promise<{ status: number; body: unknown }> {
    this.assertChangeNativeReady();
    const token = bearerToken(authorization);
    if (!token) {
      throw unauthorized("用户未登录");
    }

    let claims: { uid: number; username: string | null };
    try {
      claims = this.jwtIssuer.verifyAccessToken(token);
    } catch {
      throw unauthorized("用户未登录");
    }

    const parsed = parseChangePasswordPayload(payload);
    const operationKey = operationKeyForPasswordChange(claims.uid, parsed.old_password, parsed.new_password);
    const operation = {
      operationKey,
      operationType: "password.change",
      username: claims.username,
      email: null,
      metadata: {
        provider: "identity-service",
        path: "/v1/password/change"
      }
    };

    try {
      const completed = await this.operations.findCompleted(operationKey);
      if (completed) {
        return successResponse();
      }

      await this.operations.begin(operation);
      const user = await this.passwords.getCredentialById(claims.uid);
      if (!user) {
        throw unauthorized("用户未登录");
      }
      if (user.emailVerifiedAt === null) {
        throw invalidRequest("邮箱未验证，请先完成邮箱验证后再修改密码");
      }
      if (!(await this.passwords.verifyPassword(parsed.old_password, user.passwordHash))) {
        throw invalidRequest("旧密码不正确");
      }
      if (parsed.old_password === parsed.new_password) {
        throw invalidRequest("新密码不能与旧密码相同");
      }
      if (parsed.new_password !== parsed.confirm_password) {
        throw validationError({
          confirm_password: ["两次输入的新密码不一致"]
        });
      }

      const passwordErrors = validatePasswordPolicy(parsed.new_password, {
        username: user.username,
        email: user.email
      });
      if (passwordErrors.length > 0) {
        throw validationError({
          new_password: passwordErrors
        });
      }

      const changedUser = await this.passwords.changePassword(user, parsed.new_password);
      await this.operations.complete({
        ...operation,
        email: user.email,
        user: changedUser
      });
      await this.sessions.revokeUserSessions(user.id);
      await this.legacySessions.revokeUserSessions(user.id, "password.change");

      return successResponse();
    } catch (error) {
      if (error instanceof AccountLifecycleOperationInProgressError) {
        throw new HttpException(
          {
            success: false,
            error: {
              code: "PASSWORD_OPERATION_IN_PROGRESS",
              message: "同一修改密码操作正在处理中"
            }
          },
          409
        );
      }
      if (error instanceof NativePasswordError) {
        await this.failOperationQuietly(operation, error);
        throw new HttpException(error.body, error.status);
      }
      if (error instanceof HttpException) {
        await this.failOperationQuietly(operation, error);
      }
      throw error;
    }
  }

  private assertChangeNativeReady(): void {
    if (!this.config.accountLifecycle.passwordChangeNativeEnabled) {
      throw new ServiceUnavailableException({
        code: "PASSWORD_CHANGE_NATIVE_DISABLED",
        message: "Native password change is disabled."
      });
    }
    if (!this.passwords.isConfigured()) {
      throw new ServiceUnavailableException({
        code: "LEGACY_WRITE_DB_NOT_CONFIGURED",
        message: "Legacy write database is not configured."
      });
    }
    if (!this.operations.isConfigured()) {
      throw new ServiceUnavailableException({
        code: "IDENTITY_DB_REQUIRED_FOR_PASSWORD_NATIVE",
        message: "Identity database is required for native password operations."
      });
    }
    if (!this.sessions.isConfigured()) {
      throw new ServiceUnavailableException({
        code: "IDENTITY_SESSIONS_REQUIRED_FOR_PASSWORD_NATIVE",
        message: "Identity sessions are required for native password operations."
      });
    }
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
      // Preserve the original password error.
    }
  }
}

function bearerToken(authorization: string | string[] | undefined): string | null {
  const header = Array.isArray(authorization) ? authorization[0] : authorization;
  if (!header?.startsWith("Bearer ")) {
    return null;
  }

  return header.slice("Bearer ".length).trim() || null;
}

function parseChangePasswordPayload(payload: unknown): z.infer<typeof changePasswordSchema> {
  const parsed = changePasswordSchema.safeParse(payload);
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

function invalidRequest(message: string): HttpException {
  return new HttpException(
    {
      success: false,
      error: {
        code: "INVALID_REQUEST",
        message
      }
    },
    400
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

function successResponse(): { status: number; body: unknown } {
  return {
    status: 200,
    body: {
      success: true,
      message: "密码修改成功，请重新登录"
    }
  };
}
