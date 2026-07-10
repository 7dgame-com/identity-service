import { Body, Controller, Get, Headers, HttpException, HttpStatus, Post, Put, Query, Req, Res } from "@nestjs/common";
import { loadConfig } from "./config.js";
import { ProfileWriteService } from "./profile-write.service.js";

@Controller()
export class ProfileWriteController {
  private readonly config = loadConfig();

  constructor(private readonly profileWrite: ProfileWriteService) {}

  @Get("internal/profile-write/readiness")
  readiness(@Headers("x-identity-internal-token") token: string | undefined) {
    this.assertInternalToken(token);
    return {
      status: "ok",
      service: "identity-adapter",
      capability: "profile-write",
      data: this.profileWrite.readiness()
    };
  }

  @Get("internal/profile-write/operations/summary")
  async operationLedgerSummary(@Headers("x-identity-internal-token") token: string | undefined, @Query("sinceMinutes") sinceMinutes: string | undefined) {
    this.assertInternalToken(token);
    return {
      status: "ok",
      service: "identity-adapter",
      capability: "profile-write-operation-ledger",
      data: await this.profileWrite.operationLedgerSummary({ sinceMinutes: Number(sinceMinutes) })
    };
  }

  @Get("internal/profile-write/operations/recent")
  async operationLedgerRecent(@Headers("x-identity-internal-token") token: string | undefined, @Query("sinceMinutes") sinceMinutes: string | undefined, @Query("limit") limit: string | undefined) {
    this.assertInternalToken(token);
    return {
      status: "ok",
      service: "identity-adapter",
      capability: "profile-write-operation-ledger",
      data: await this.profileWrite.operationLedgerRecent({ sinceMinutes: Number(sinceMinutes), limit: Number(limit) })
    };
  }

  @Post("internal/profile-write/reconciliation/dry-run")
  async reconciliationDryRun(@Headers("x-identity-internal-token") token: string | undefined, @Body() body: unknown) {
    this.assertInternalToken(token);
    return {
      status: "ok",
      service: "identity-adapter",
      capability: "profile-write-reconciliation",
      data: await this.profileWrite.reconciliationDryRun(body)
    };
  }

  @Post("internal/profile-write/reconciliation/backfill-shadow")
  async reconciliationBackfillShadow(@Headers("x-identity-internal-token") token: string | undefined, @Body() body: unknown) {
    this.assertInternalToken(token);
    return {
      status: "ok",
      service: "identity-adapter",
      capability: "profile-write-reconciliation-backfill-shadow",
      data: await this.profileWrite.reconciliationBackfillShadow(body)
    };
  }

  @Put("v1/user/update")
  updateProfile(
    @Req() request: ProfileWriteExpressRequest,
    @Res({ passthrough: true }) response: ProfileWriteExpressResponse
  ) {
    return this.forward(request, response, "/v1/user/update");
  }

  private async forward(
    request: ProfileWriteExpressRequest,
    response: ProfileWriteExpressResponse,
    path: string
  ): Promise<unknown> {
    const upstream = await this.profileWrite.proxy(request, path);
    response.status(upstream.status);
    response.setHeader("X-Identity-Profile-Write", upstream.mode);

    return upstream.body;
  }

  private assertInternalToken(token: string | undefined): void {
    const configuredToken = this.config.iam.internalToken;
    if (!configuredToken) {
      throw new HttpException(
        { code: "IAM_INTERNAL_TOKEN_NOT_CONFIGURED", message: "Internal API token is required for profile-write operations." },
        HttpStatus.SERVICE_UNAVAILABLE
      );
    }
    if (token !== configuredToken) {
      throw new HttpException(
        { code: "INTERNAL_TOKEN_INVALID", message: "Internal service token is invalid." },
        HttpStatus.UNAUTHORIZED
      );
    }
  }
}

interface ProfileWriteExpressRequest {
  method: string;
  originalUrl?: string;
  headers: Record<string, string | string[] | undefined>;
  body?: unknown;
}

interface ProfileWriteExpressResponse {
  status(code: number): unknown;
  setHeader(name: string, value: string): unknown;
}
