import { Body, Controller, Get, Post, Put, Query, Req, Res } from "@nestjs/common";
import { ProfileWriteService } from "./profile-write.service.js";

@Controller()
export class ProfileWriteController {
  constructor(private readonly profileWrite: ProfileWriteService) {}

  @Get("internal/profile-write/readiness")
  readiness() {
    return {
      status: "ok",
      service: "identity-adapter",
      capability: "profile-write",
      data: this.profileWrite.readiness()
    };
  }

  @Get("internal/profile-write/operations/summary")
  async operationLedgerSummary(@Query("sinceMinutes") sinceMinutes: string | undefined) {
    return {
      status: "ok",
      service: "identity-adapter",
      capability: "profile-write-operation-ledger",
      data: await this.profileWrite.operationLedgerSummary({ sinceMinutes: Number(sinceMinutes) })
    };
  }

  @Get("internal/profile-write/operations/recent")
  async operationLedgerRecent(@Query("sinceMinutes") sinceMinutes: string | undefined, @Query("limit") limit: string | undefined) {
    return {
      status: "ok",
      service: "identity-adapter",
      capability: "profile-write-operation-ledger",
      data: await this.profileWrite.operationLedgerRecent({ sinceMinutes: Number(sinceMinutes), limit: Number(limit) })
    };
  }

  @Post("internal/profile-write/reconciliation/dry-run")
  async reconciliationDryRun(@Body() body: unknown) {
    return {
      status: "ok",
      service: "identity-adapter",
      capability: "profile-write-reconciliation",
      data: await this.profileWrite.reconciliationDryRun(body)
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
