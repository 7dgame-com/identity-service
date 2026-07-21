import { Body, Controller, Get, Headers, HttpException, HttpStatus, Param, Post, Put, Query, Req, Res } from "@nestjs/common";
import { loadConfig } from "./config.js";
import { roleWriteEvidenceHeaders } from "./iam-role-write-evidence.js";
import { IamRoleWriteService } from "./iam-role-write.service.js";

@Controller()
export class IamRoleWriteController {
  private readonly config = loadConfig();

  constructor(private readonly roleWrite: IamRoleWriteService) {}

  @Get("internal/iam/role-write/readiness")
  async readiness(@Headers("x-identity-internal-token") token: string | undefined) {
    this.assertInternalToken(token);
    return {
      status: "ok",
      service: "identity-adapter",
      capability: "iam-role-write",
      data: await this.roleWrite.readiness()
    };
  }

  @Get("internal/iam/role-write/operations/summary")
  async operationLedgerSummary(
    @Headers("x-identity-internal-token") token: string | undefined,
    @Query("sinceMinutes") sinceMinutes: string | undefined
  ) {
    this.assertInternalToken(token);
    return {
      status: "ok",
      service: "identity-adapter",
      capability: "iam-role-write-operation-ledger",
      data: await this.roleWrite.operationLedgerSummary({ sinceMinutes: Number(sinceMinutes) })
    };
  }

  @Get("internal/iam/role-write/operations/recent")
  async operationLedgerRecent(
    @Headers("x-identity-internal-token") token: string | undefined,
    @Query("sinceMinutes") sinceMinutes: string | undefined,
    @Query("limit") limit: string | undefined
  ) {
    this.assertInternalToken(token);
    return {
      status: "ok",
      service: "identity-adapter",
      capability: "iam-role-write-operation-ledger",
      data: await this.roleWrite.operationLedgerRecent({ sinceMinutes: Number(sinceMinutes), limit: Number(limit) })
    };
  }

  @Post("internal/iam/role-write/operations/:operationKey/retry-identity-shadow")
  async retryIdentityShadow(
    @Headers("x-identity-internal-token") token: string | undefined,
    @Param("operationKey") operationKey: string
  ) {
    this.assertInternalToken(token);
    return {
      status: "ok",
      service: "identity-adapter",
      capability: "iam-role-write-recovery",
      data: await this.roleWrite.retryIdentityShadow(operationKey)
    };
  }

  @Put("v1/people/auth")
  async peopleAuth(
    @Req() request: IamRoleWriteExpressRequest,
    @Res({ passthrough: true }) response: IamRoleWriteExpressResponse,
    @Body() _body: unknown
  ): Promise<unknown> {
    const upstream = await this.roleWrite.proxyPeopleAuth(request);
    response.status(upstream.status);
    response.setHeader("X-Identity-IAM-Role-Write", upstream.mode);
    if (upstream.evidence) {
      for (const [name, value] of Object.entries(roleWriteEvidenceHeaders(upstream.evidence))) {
        response.setHeader(name, value);
      }
    }
    return upstream.body;
  }

  private assertInternalToken(token: string | undefined): void {
    const configuredToken = this.config.iam.internalToken;
    if (!configuredToken) {
      throw new HttpException(
        { code: "IAM_INTERNAL_TOKEN_NOT_CONFIGURED", message: "Internal API token is required for IAM role-write operations." },
        HttpStatus.SERVICE_UNAVAILABLE
      );
    }
    if (token !== configuredToken) {
      throw new HttpException({ code: "INTERNAL_TOKEN_INVALID", message: "Internal service token is invalid." }, HttpStatus.UNAUTHORIZED);
    }
  }
}

interface IamRoleWriteExpressRequest {
  method: string;
  originalUrl?: string;
  headers: Record<string, string | string[] | undefined>;
  body?: unknown;
}

interface IamRoleWriteExpressResponse {
  status(code: number): unknown;
  setHeader(name: string, value: string): unknown;
}
