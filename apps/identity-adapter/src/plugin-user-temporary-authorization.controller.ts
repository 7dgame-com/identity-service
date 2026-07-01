import { Body, Controller, Get, Headers, HttpCode, Post } from "@nestjs/common";
import { PluginUserTemporaryAuthorizationService } from "./plugin-user-temporary-authorization.service.js";

@Controller("internal/plugin-user-temporary-authorization")
export class PluginUserTemporaryAuthorizationController {
  constructor(private readonly temporaryAuthorization: PluginUserTemporaryAuthorizationService) {}

  @Get("readiness")
  readiness() {
    return {
      status: "ok",
      service: "identity-adapter",
      capability: "plugin-user-temporary-authorization",
      data: this.temporaryAuthorization.readiness()
    };
  }

  @Post("grant")
  @HttpCode(200)
  async grant(@Headers("x-identity-internal-token") token: string | undefined, @Body() body: unknown) {
    this.temporaryAuthorization.assertMutatingAccess(token);
    return {
      data: await this.temporaryAuthorization.grant(body)
    };
  }

  @Post("revoke")
  @HttpCode(200)
  async revoke(@Headers("x-identity-internal-token") token: string | undefined, @Body() body: unknown) {
    this.temporaryAuthorization.assertMutatingAccess(token);
    return {
      data: await this.temporaryAuthorization.revoke(body)
    };
  }
}
