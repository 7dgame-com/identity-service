import { Controller, Get, Post, Req, Res } from "@nestjs/common";
import { PluginUserWriteService } from "./plugin-user-write.service.js";

@Controller()
export class PluginUserWriteController {
  constructor(private readonly pluginUserWrite: PluginUserWriteService) {}

  @Get("internal/plugin-user-write/readiness")
  readiness() {
    return {
      status: "ok",
      service: "identity-adapter",
      capability: "plugin-user-write",
      data: this.pluginUserWrite.readiness()
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
    return this.forward(request, response, "/v1/plugin-user/change-role");
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
    const upstream = await this.pluginUserWrite.proxy(request, path);
    response.status(upstream.status);
    response.setHeader("X-Identity-Plugin-User-Write", "legacy-proxy");

    return upstream.body;
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
