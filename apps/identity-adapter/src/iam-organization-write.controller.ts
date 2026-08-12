import { Body, Controller, Get, Headers, HttpException, HttpStatus, Param, Post, Query } from "@nestjs/common";
import { loadConfig } from "./config.js";
import { currentBuildRevision, normalizeBuildRevision } from "./build-revision.js";
import { IamOrganizationWriteService } from "./iam-organization-write.service.js";

@Controller("internal/iam/organization-write")
export class IamOrganizationWriteController {
  private readonly config = loadConfig();

  constructor(private readonly organizationWrite: IamOrganizationWriteService) {}

  @Get("readiness")
  async readiness(@Headers("x-identity-internal-token") token: string | undefined) {
    this.assertInternalToken(token);
    return { status: "ok", service: "identity-adapter", capability: "iam-organization-write", data: await this.organizationWrite.readiness() };
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

  @Get("subjects/:legacyUserId/candidate")
  async subjectCandidate(
    @Headers("x-identity-internal-token") token: string | undefined,
    @Param("legacyUserId") legacyUserId: string
  ) {
    this.assertInternalToken(token);
    return {
      status: "ok",
      service: "identity-adapter",
      capability: "iam-organization-write-subject-candidate",
      data: await this.organizationWrite.subjectCandidate(parseLegacyUserId(legacyUserId))
    };
  }

  @Get("subjects/:legacyUserId/decision")
  async previewMembershipRollout(
    @Headers("x-identity-internal-token") token: string | undefined,
    @Param("legacyUserId") legacyUserId: string
  ) {
    this.assertInternalToken(token);
    return {
      status: "ok",
      service: "identity-adapter",
      capability: "iam-organization-write-rollout-preview",
      data: await this.organizationWrite.previewMembershipRollout(parseLegacyUserId(legacyUserId))
    };
  }

  @Get("subjects/:legacyUserId/materialization-preview")
  async previewCandidateMaterialization(
    @Headers("x-identity-internal-token") token: string | undefined,
    @Param("legacyUserId") legacyUserId: string
  ) {
    this.assertInternalToken(token);
    return {
      status: "ok",
      service: "identity-adapter",
      capability: "iam-organization-candidate-materialization-preview",
      data: await this.organizationWrite.previewCandidateMaterialization(parseLegacyUserId(legacyUserId))
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

  @Post("recovery-drill/prepare")
  async prepareRecoveryDrill(
    @Headers("x-identity-internal-token") token: string | undefined
  ) {
    this.assertInternalToken(token);
    return {
      status: "ok",
      service: "identity-adapter",
      capability: "iam-organization-write-recovery-drill",
      data: await this.organizationWrite.prepareRecoveryDrill()
    };
  }

  @Post("subjects/:legacyUserId/materialize-candidate")
  async materializeCandidate(
    @Headers("x-identity-internal-token") token: string | undefined,
    @Headers("x-identity-expected-revision") expectedRevisionHeader: string | string[] | undefined,
    @Headers("idempotency-key") idempotencyKey: string | string[] | undefined,
    @Headers("x-idempotency-key") idempotencyKeyAlias: string | string[] | undefined,
    @Param("legacyUserId") legacyUserId: string,
    @Body() body: unknown
  ) {
    this.assertInternalToken(token);
    this.assertExpectedBuildRevision(expectedRevisionHeader);
    return {
      status: "ok",
      service: "identity-adapter",
      capability: "iam-organization-candidate-materialization",
      data: await this.organizationWrite.materializeCandidate({
        legacyUserId: parseLegacyUserId(legacyUserId),
        expectedSnapshotFingerprint: materializationFingerprint(body),
        idempotencyKey: materializationIdempotencyKey(idempotencyKey, idempotencyKeyAlias)
      })
    };
  }

  @Get("candidate-batch-materialization/preview")
  async previewCandidateBatchMaterialization(
    @Headers("x-identity-internal-token") token: string | undefined,
    @Headers("x-identity-expected-revision") expectedRevisionHeader: string | string[] | undefined
  ) {
    this.assertInternalToken(token);
    this.assertExpectedBuildRevision(expectedRevisionHeader);
    return {
      status: "ok",
      service: "identity-adapter",
      capability: "iam-organization-candidate-batch-materialization-preview",
      data: await this.organizationWrite.previewCandidateBatchMaterialization()
    };
  }

  @Post("candidate-batch-materialization/apply")
  async materializeCandidateBatch(
    @Headers("x-identity-internal-token") token: string | undefined,
    @Headers("x-identity-expected-revision") expectedRevisionHeader: string | string[] | undefined,
    @Headers("idempotency-key") idempotencyKey: string | string[] | undefined,
    @Headers("x-idempotency-key") idempotencyKeyAlias: string | string[] | undefined,
    @Body() body: unknown
  ) {
    this.assertInternalToken(token);
    this.assertExpectedBuildRevision(expectedRevisionHeader);
    return {
      status: "ok",
      service: "identity-adapter",
      capability: "iam-organization-candidate-batch-materialization",
      data: await this.organizationWrite.materializeCandidateBatch({
        planToken: batchMaterializationPlanToken(body),
        idempotencyKey: materializationIdempotencyKey(idempotencyKey, idempotencyKeyAlias)
      })
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

  private assertExpectedBuildRevision(value: string | string[] | undefined): void {
    if (Array.isArray(value) && value.length !== 1) {
      throw new HttpException(
        { code: "IDENTITY_EXPECTED_BUILD_REVISION_INVALID", message: "A single full expected build revision is required." },
        HttpStatus.BAD_REQUEST
      );
    }
    const rawExpected = firstHeader(value);
    const expected = normalizeBuildRevision(rawExpected);
    if (!expected || rawExpected?.trim() !== expected) {
      throw new HttpException(
        { code: "IDENTITY_EXPECTED_BUILD_REVISION_INVALID", message: "A full expected build revision is required." },
        HttpStatus.BAD_REQUEST
      );
    }
    const actual = currentBuildRevision();
    if (!actual) {
      throw new HttpException(
        { code: "IDENTITY_BUILD_REVISION_UNAVAILABLE", message: "The running build revision is unavailable." },
        HttpStatus.SERVICE_UNAVAILABLE
      );
    }
    if (actual !== expected) {
      throw new HttpException(
        { code: "IDENTITY_BUILD_REVISION_MISMATCH", message: "The running build does not match the reviewed revision." },
        HttpStatus.CONFLICT
      );
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

function materializationFingerprint(body: unknown): string | undefined {
  if (!body || typeof body !== "object" || Array.isArray(body)) return undefined;
  const value = (body as Record<string, unknown>).expectedSnapshotFingerprint;
  return typeof value === "string" ? value : undefined;
}

function batchMaterializationPlanToken(body: unknown): string | undefined {
  if (!body || typeof body !== "object" || Array.isArray(body)) return undefined;
  const value = (body as Record<string, unknown>).planToken;
  return typeof value === "string" ? value : undefined;
}

function materializationIdempotencyKey(
  primary: string | string[] | undefined,
  alias: string | string[] | undefined
): string | undefined {
  const normalizedPrimary = firstHeader(primary)?.trim();
  const normalizedAlias = firstHeader(alias)?.trim();
  if (normalizedPrimary && normalizedAlias && normalizedPrimary !== normalizedAlias) {
    throw new HttpException(
      { code: "IDEMPOTENCY_KEY_CONFLICT", message: "Conflicting idempotency headers were provided." },
      HttpStatus.BAD_REQUEST
    );
  }
  return normalizedPrimary || normalizedAlias || undefined;
}

function firstHeader(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}
