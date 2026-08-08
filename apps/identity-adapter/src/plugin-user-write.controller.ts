import { BadRequestException, Controller, Get, Post, Query, Req, Res } from "@nestjs/common";
import { roleWriteEvidenceHeaders } from "./iam-role-write-evidence.js";
import { IamRoleWriteService } from "./iam-role-write.service.js";
import { organizationWriteEvidenceHeaders } from "./iam-organization-write-evidence.js";
import { IamOrganizationWriteService } from "./iam-organization-write.service.js";
import { PluginUserWriteService } from "./plugin-user-write.service.js";

@Controller()
export class PluginUserWriteController {
  constructor(
    private readonly pluginUserWrite: PluginUserWriteService,
    private readonly iamRoleWrite: IamRoleWriteService,
    private readonly iamOrganizationWrite: IamOrganizationWriteService
  ) {}

  @Get("internal/plugin-user-write/readiness")
  readiness() {
    return {
      status: "ok",
      service: "identity-adapter",
      capability: "plugin-user-write",
      data: this.pluginUserWrite.readiness()
    };
  }

  @Get("internal/plugin-user-write/operations/summary")
  async operationLedgerSummary(@Query("sinceMinutes") sinceMinutes: string | undefined) {
    return {
      status: "ok",
      service: "identity-adapter",
      capability: "plugin-user-write-operation-ledger",
      data: await this.pluginUserWrite.operationLedgerSummary({ sinceMinutes: Number(sinceMinutes) })
    };
  }

  @Get("internal/plugin-user-write/operations/recent")
  async operationLedgerRecent(@Query("sinceMinutes") sinceMinutes: string | undefined, @Query("limit") limit: string | undefined) {
    return {
      status: "ok",
      service: "identity-adapter",
      capability: "plugin-user-write-operation-ledger",
      data: await this.pluginUserWrite.operationLedgerRecent({ sinceMinutes: Number(sinceMinutes), limit: Number(limit) })
    };
  }

  @Post("v1/plugin-user/create-user")
  createUser(@Req() request: PluginUserWriteExpressRequest, @Res({ passthrough: true }) response: PluginUserWriteExpressResponse) {
    return this.forward(request, response, "/v1/plugin-user/create-user");
  }

  @Post("v1/plugin-user/update-user")
  updateUser(@Req() request: PluginUserWriteExpressRequest, @Res({ passthrough: true }) response: PluginUserWriteExpressResponse) {
    return this.forward(request, response, "/v1/plugin-user/update-user");
  }

  @Post("v1/plugin-user/delete-user")
  deleteUser(@Req() request: PluginUserWriteExpressRequest, @Res({ passthrough: true }) response: PluginUserWriteExpressResponse) {
    return this.forward(request, response, "/v1/plugin-user/delete-user");
  }

  @Post("v1/plugin-user/change-role")
  changeRole(@Req() request: PluginUserWriteExpressRequest, @Res({ passthrough: true }) response: PluginUserWriteExpressResponse) {
    return this.forwardRole(request, response);
  }

  @Get("v1/plugin-user/role-write-decision")
  async roleWriteDecision(
    @Req() request: PluginUserWriteExpressRequest,
    @Res({ passthrough: true }) response: PluginUserWriteExpressResponse,
    @Query("targetLegacyUserId") targetLegacyUserId: string | undefined
  ) {
    const decision = await this.iamRoleWrite.previewPluginUserRollout(
      request,
      parseOptionalLegacyUserId(targetLegacyUserId)
    );
    response.setHeader("X-Identity-IAM-Role-Write", decision.roleWriteMode);
    response.setHeader("X-Identity-IAM-Role-Write-Entry", "plugin-user-change-role");
    this.applyRoleWriteEvidence(response, decision);
    return { code: 0, data: decision };
  }

  @Post("v1/plugin-user/batch-create-users")
  batchCreateUsers(
    @Req() request: PluginUserWriteExpressRequest,
    @Res({ passthrough: true }) response: PluginUserWriteExpressResponse
  ) {
    return this.forward(request, response, "/v1/plugin-user/batch-create-users");
  }

  private async forward(
    request: PluginUserWriteExpressRequest,
    response: PluginUserWriteExpressResponse,
    path: string
  ): Promise<unknown> {
    const organizationUpstream = path === "/v1/plugin-user/update-user"
      ? await this.iamOrganizationWrite.proxyMembershipUpdate(request)
      : null;
    const upstream = organizationUpstream ?? await this.pluginUserWrite.proxy(request, path);
    response.status(upstream.status);
    response.setHeader("X-Identity-Plugin-User-Write", upstream.mode);
    if (organizationUpstream) {
      response.setHeader("X-Identity-IAM-Organization-Write", organizationUpstream.mode);
      for (const [name, value] of Object.entries(organizationWriteEvidenceHeaders(organizationUpstream.evidence))) {
        response.setHeader(name, value);
      }
    }

    return upstream.body;
  }

  private async forwardRole(
    request: PluginUserWriteExpressRequest,
    response: PluginUserWriteExpressResponse
  ): Promise<unknown> {
    const upstream = await this.iamRoleWrite.proxyPluginUser(request);
    response.status(upstream.status);
    response.setHeader("X-Identity-Plugin-User-Write", upstream.mode);
    response.setHeader("X-Identity-IAM-Role-Write", upstream.mode);
    response.setHeader("X-Identity-IAM-Role-Write-Entry", "plugin-user-change-role");
    if (upstream.evidence) {
      this.applyRoleWriteEvidence(response, upstream.evidence);
    }
    return upstream.body;
  }

  private applyRoleWriteEvidence(
    response: PluginUserWriteExpressResponse,
    evidence: Parameters<typeof roleWriteEvidenceHeaders>[0]
  ): void {
    for (const [name, value] of Object.entries(roleWriteEvidenceHeaders(evidence))) {
      response.setHeader(name, value);
    }
  }
}

interface PluginUserWriteExpressRequest {
  method: string;
  originalUrl?: string;
  headers: Record<string, string | string[] | undefined>;
  body?: unknown;
}

interface PluginUserWriteExpressResponse {
  status(code: number): unknown;
  setHeader(name: string, value: string): unknown;
}

function parseOptionalLegacyUserId(value: string | undefined): number | undefined {
  if (value === undefined || value.trim() === "") {
    return undefined;
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new BadRequestException({
      code: "INVALID_LEGACY_USER_ID",
      message: "targetLegacyUserId must be a positive integer."
    });
  }
  return parsed;
}
