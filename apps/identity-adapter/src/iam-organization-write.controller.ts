import { Controller, Get, Headers, HttpException, HttpStatus, Param, Post, Query } from "@nestjs/common";
import { loadConfig } from "./config.js";
import { IamOrganizationWriteService } from "./iam-organization-write.service.js";

@Controller("internal/iam/organization-write")
export class IamOrganizationWriteController {
  private readonly config = loadConfig();

  constructor(private readonly organizationWrite: IamOrganizationWriteService) {}

  @Get("readiness")
  readiness(@Headers("x-identity-internal-token") token: string | undefined) {
    this.assertInternalToken(token);
    return { status: "ok", service: "identity-adapter", capability: "iam-organization-write", data: this.organizationWrite.readiness() };
  }

  @Get("operations/summary")
  async operationLedgerSummary(
    @Headers("x-identity-internal-token") token: string | undefined,
    @Query("sinceMinutes") sinceMinutes: string | undefined
  ) {
    this.assertInternalToken(token);
    return {
      status: "ok",
      service: "identity-adapter",
      capability: "iam-organization-write-operation-ledger",
      data: await this.organizationWrite.operationLedgerSummary({ sinceMinutes: Number(sinceMinutes) })
    };
  }

  @Get("operations/recent")
  async operationLedgerRecent(
    @Headers("x-identity-internal-token") token: string | undefined,
    @Query("sinceMinutes") sinceMinutes: string | undefined,
    @Query("limit") limit: string | undefined
  ) {
    this.assertInternalToken(token);
    return {
      status: "ok",
      service: "identity-adapter",
      capability: "iam-organization-write-operation-ledger",
      data: await this.organizationWrite.operationLedgerRecent({ sinceMinutes: Number(sinceMinutes), limit: Number(limit) })
    };
  }

  @Get("subjects/:legacyUserId/alignment")
  async subjectAlignment(
    @Headers("x-identity-internal-token") token: string | undefined,
    @Param("legacyUserId") legacyUserId: string
  ) {
    this.assertInternalToken(token);
    return {
      status: "ok",
      service: "identity-adapter",
      capability: "iam-organization-write-subject-alignment",
      data: await this.organizationWrite.subjectAlignment(parseLegacyUserId(legacyUserId))
    };
  }

  @Get("subjects/:legacyUserId/decision")
  previewMembershipRollout(
    @Headers("x-identity-internal-token") token: string | undefined,
    @Param("legacyUserId") legacyUserId: string
  ) {
    this.assertInternalToken(token);
    return {
      status: "ok",
      service: "identity-adapter",
      capability: "iam-organization-write-rollout-preview",
      data: this.organizationWrite.previewMembershipRollout(parseLegacyUserId(legacyUserId))
    };
  }

  @Post("operations/:operationKey/retry-identity-candidate")
  async retryIdentityCandidate(
    @Headers("x-identity-internal-token") token: string | undefined,
    @Param("operationKey") operationKey: string
  ) {
    this.assertInternalToken(token);
    return {
      status: "ok",
      service: "identity-adapter",
      capability: "iam-organization-write-recovery",
      data: await this.organizationWrite.retryIdentityCandidate(operationKey)
    };
  }

  private assertInternalToken(token: string | undefined): void {
    const configuredToken = this.config.iam.internalToken;
    if (!configuredToken) {
      throw new HttpException(
        { code: "IAM_INTERNAL_TOKEN_NOT_CONFIGURED", message: "Internal API token is required for IAM organization-write operations." },
        HttpStatus.SERVICE_UNAVAILABLE
      );
    }
    if (token !== configuredToken) {
      throw new HttpException({ code: "INTERNAL_TOKEN_INVALID", message: "Internal service token is invalid." }, HttpStatus.UNAUTHORIZED);
    }
  }
}

function parseLegacyUserId(value: string): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new HttpException({ code: "INVALID_LEGACY_USER_ID", message: "Legacy user id must be a positive integer." }, HttpStatus.BAD_REQUEST);
  }
  return parsed;
}
