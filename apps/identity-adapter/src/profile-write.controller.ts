import { Controller, Get, Put, Req, Res } from "@nestjs/common";
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
