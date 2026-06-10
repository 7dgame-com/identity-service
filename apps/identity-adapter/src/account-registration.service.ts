import { BadRequestException, HttpException, Injectable, ServiceUnavailableException } from "@nestjs/common";
import { z } from "zod";
import {
  AccountLifecycleOperationInProgressError,
  AccountLifecycleOperationRepository,
  operationKeyForRegister
} from "./account-lifecycle-operation.repository.js";
import {
  AccountRegistrationRepository,
  NativeRegistrationError,
  NativeRegisterInput,
  NativeWechatRegisterInput
} from "./account-registration.repository.js";
import { loadConfig } from "./config.js";
import { RequestContext, TokenIssuanceService } from "./token-issuance.service.js";
import { validatePasswordPolicy } from "./password-policy.js";

const registerSchema = z.object({
  username: z.string().trim().min(1).max(255),
  password: z.string().min(1).max(1024),
  email: z.string().trim().email().optional().nullable()
});

const wechatRegisterSchema = registerSchema.extend({
  token: z.string().trim().min(1).max(255)
});

@Injectable()
export class AccountRegistrationService {
  private readonly config = loadConfig();

  constructor(
    private readonly registrationRepository: AccountRegistrationRepository,
    private readonly operations: AccountLifecycleOperationRepository,
    private readonly tokenIssuance: TokenIssuanceService
  ) {}

  isNativeReady(): boolean {
    return this.registrationRepository.isConfigured() && this.operations.isConfigured() && this.config.tokenIssuance.enabled;
  }

  async register(path: string, payload: unknown, context: RequestContext = {}): Promise<{ status: number; body: unknown }> {
    this.assertNativeReady();

    if (path === "/v1/auth/register") {
      return {
        status: 201,
        body: await this.registerStandard(payload, context)
      };
    }

    if (path === "/v1/wechat/register") {
      return {
        status: 200,
        body: await this.registerWechat(payload, context)
      };
    }

    throw new HttpException(
      {
        code: "REGISTER_NATIVE_PATH_NOT_SUPPORTED",
        message: `Native register path ${path} is not supported.`
      },
      404
    );
  }

  private async registerStandard(payload: unknown, context: RequestContext): Promise<RegisterResponse> {
    const parsed = this.parseRegisterPayload(payload);
    return this.createAndIssueToken(parsed, context);
  }

  private async registerWechat(payload: unknown, context: RequestContext): Promise<RegisterResponse> {
    const parsed = this.parseWechatRegisterPayload(payload);
    return this.createAndIssueToken(
      {
        username: parsed.username,
        password: parsed.password,
        email: parsed.email ?? null,
        wechatToken: parsed.token
      },
      context
    );
  }

  private async createAndIssueToken(
    input: NativeRegisterInput | NativeWechatRegisterInput,
    context: RequestContext
  ): Promise<RegisterResponse> {
    this.assertPasswordPolicy(input);
    const operationType = "wechatToken" in input ? "register.wechat" : "register.standard";
    const operationKey =
      "wechatToken" in input
        ? operationKeyForRegister("wechat", [input.wechatToken, input.username])
        : operationKeyForRegister("standard", [input.username]);
    const operation = {
      operationKey,
      operationType,
      username: input.username,
      email: input.email ?? null,
      metadata: {
        provider: "identity-service",
        path: "wechatToken" in input ? "/v1/wechat/register" : "/v1/auth/register"
      }
    };

    try {
      const completed = await this.operations.findCompleted(operationKey);
      if (completed) {
        const token = await this.tokenIssuance.issueRegisteredUser(completed, context);
        return {
          success: true,
          message: "register",
          uid: completed.id,
          token: token.token
        };
      }

      await this.operations.begin(operation);
      const user =
        "wechatToken" in input
          ? await this.registrationRepository.registerWechat(input)
          : await this.registrationRepository.register(input);
      await this.operations.complete({
        ...operation,
        user
      });
      const token = await this.tokenIssuance.issueRegisteredUser(user, context);

      return {
        success: true,
        message: "register",
        uid: user.id,
        token: token.token
      };
    } catch (error) {
      if (error instanceof AccountLifecycleOperationInProgressError) {
        throw new HttpException(
          {
            code: "REGISTER_OPERATION_IN_PROGRESS",
            message: "The same register operation is already in progress."
          },
          409
        );
      }
      if (error instanceof NativeRegistrationError) {
        await this.failOperationQuietly(operation, error);
        throw new HttpException(error.body, error.status);
      }

      await this.failOperationQuietly(operation, error);
      throw error;
    }
  }

  private parseRegisterPayload(payload: unknown): z.infer<typeof registerSchema> {
    const parsed = registerSchema.safeParse(payload);
    if (!parsed.success) {
      throw new BadRequestException({
        code: "INVALID_REGISTER_PAYLOAD",
        message: "Register request payload is invalid.",
        details: parsed.error.flatten()
      });
    }

    return parsed.data;
  }

  private parseWechatRegisterPayload(payload: unknown): z.infer<typeof wechatRegisterSchema> {
    const parsed = wechatRegisterSchema.safeParse(payload);
    if (!parsed.success) {
      throw new BadRequestException({
        code: "INVALID_WECHAT_REGISTER_PAYLOAD",
        message: "Wechat register request payload is invalid.",
        details: parsed.error.flatten()
      });
    }

    return parsed.data;
  }

  private assertPasswordPolicy(input: NativeRegisterInput): void {
    const passwordErrors = validatePasswordPolicy(input.password, {
      username: input.username,
      email: input.email
    });
    if (passwordErrors.length > 0) {
      throw new BadRequestException({
        password: passwordErrors,
        message: passwordErrors[0]
      });
    }
  }

  private assertNativeReady(): void {
    if (!this.registrationRepository.isConfigured()) {
      throw new ServiceUnavailableException({
        code: "LEGACY_WRITE_DB_NOT_CONFIGURED",
        message: "Legacy write database is not configured."
      });
    }
    if (!this.operations.isConfigured()) {
      throw new ServiceUnavailableException({
        code: "IDENTITY_DB_REQUIRED_FOR_REGISTER_NATIVE",
        message: "Identity database is required for native registration idempotency."
      });
    }
    if (!this.config.tokenIssuance.enabled) {
      throw new ServiceUnavailableException({
        code: "TOKEN_ISSUANCE_REQUIRED_FOR_REGISTER_NATIVE",
        message: "Token issuance must be enabled before native registration."
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
        errorCode: error instanceof NativeRegistrationError ? `HTTP_${error.status}` : error instanceof Error ? error.name : "UNKNOWN_ERROR"
      });
    } catch {
      // Registration errors should remain the user-facing failure.
    }
  }
}

interface RegisterResponse {
  success: true;
  message: "register";
  uid: number;
  token: {
    token: string;
    accessToken: string;
    refreshToken: string;
    expires: string;
    tokenType: "Bearer";
  };
}
