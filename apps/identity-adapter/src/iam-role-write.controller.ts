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

  @Get("internal/iam/role-write/policy-diagnostics")
  async policyDiagnostics(@Headers("x-identity-internal-token") token: string | undefined) {
    this.assertInternalToken(token);
    return {
      status: "ok",
      service: "identity-adapter",
      capability: "iam-role-write-policy-diagnostics",
      data: await this.roleWrite.policyDiagnostics()
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

  @Get("internal/iam/role-write/subjects/:legacyUserId/alignment")
  async subjectAlignment(
    @Headers("x-identity-internal-token") token: string | undefined,
    @Param("legacyUserId") legacyUserId: string,
    @Query("checksum") checksum: string | undefined
  ) {
    this.assertInternalToken(token);
    return {
      status: "ok",
      service: "identity-adapter",
      capability: "iam-role-write-subject-alignment",
      data: await this.roleWrite.subjectAlignment({
        legacyUserId: parseLegacyUserId(legacyUserId),
        policyChecksum: parsePolicyChecksum(checksum)
      })
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

  @Post("internal/iam/role-write/subjects/:legacyUserId/restore-candidate")
  async restoreCandidate(
    @Headers("x-identity-internal-token") token: string | undefined,
    @Param("legacyUserId") legacyUserId: string,
    @Body() body: { policyChecksum?: unknown }
  ) {
    this.assertInternalToken(token);
    return {
      status: "ok",
      service: "identity-adapter",
      capability: "iam-role-write-candidate-restore",
      data: await this.roleWrite.restoreCandidateAssignments({
        legacyUserId: parseLegacyUserId(legacyUserId),
        policyChecksum: parsePolicyChecksum(typeof body?.policyChecksum === "string" ? body.policyChecksum : undefined)
      })
    };
  }

  @Post("internal/iam/role-write/recovery-drill/prepare")
  async prepareRecoveryDrill(@Headers("x-identity-internal-token") token: string | undefined) {
    this.assertInternalToken(token);
    return {
      status: "ok",
      service: "identity-adapter",
      capability: "iam-role-write-recovery-drill",
      data: await this.roleWrite.prepareRecoveryDrill()
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

function parseLegacyUserId(value: string): number {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new HttpException(
      { code: "INVALID_LEGACY_USER_ID", message: "Legacy user id must be a positive integer." },
      HttpStatus.BAD_REQUEST
    );
  }
  return parsed;
}

function parsePolicyChecksum(value: string | undefined): string {
  const checksum = value?.trim() ?? "";
  if (!/^[a-f0-9]{64}$/.test(checksum)) {
    throw new HttpException(
      {
        code: "INVALID_IAM_PERMISSION_CANDIDATE_CHECKSUM",
        message: "A 64-character candidate checksum is required."
      },
      HttpStatus.BAD_REQUEST
    );
  }
  return checksum;
}
