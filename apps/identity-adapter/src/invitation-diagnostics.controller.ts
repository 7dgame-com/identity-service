import { Controller, Get, Headers, HttpException, HttpStatus, NotFoundException, Query } from "@nestjs/common";
import { loadConfig } from "./config.js";
import { InvitationDiagnosticsService } from "./invitation-diagnostics.service.js";

@Controller("internal/account-lifecycle/invitations")
export class InvitationDiagnosticsController {
  private readonly config = loadConfig();

  constructor(private readonly diagnosticsService: InvitationDiagnosticsService) {}

  @Get("diagnostics")
  async diagnostics(@Headers("x-identity-internal-token") token: string | undefined, @Query("code") code?: string) {
    this.assertEnabledAndAuthorized(token);

    return {
      status: "ok",
      service: "identity-adapter",
      capability: "invitation-diagnostics",
      data: await this.diagnosticsService.diagnostics(code)
    };
  }

  private assertEnabledAndAuthorized(token: string | undefined): void {
    if (!this.config.accountLifecycle.invitationDiagnosticsEnabled) {
      throw new NotFoundException({
        code: "INVITATION_DIAGNOSTICS_DISABLED",
        message: "Invitation diagnostics is disabled."
      });
    }
    if (!this.config.loginAudit.internalToken) {
      throw new HttpException(
        {
          code: "INTERNAL_TOKEN_NOT_CONFIGURED",
          message: "Internal API token is required before enabling invitation diagnostics."
        },
        HttpStatus.SERVICE_UNAVAILABLE
      );
    }
    if (token !== this.config.loginAudit.internalToken) {
      throw new HttpException(
        {
          code: "INTERNAL_TOKEN_INVALID",
          message: "Internal service token is invalid."
        },
        HttpStatus.UNAUTHORIZED
      );
    }
  }
}
