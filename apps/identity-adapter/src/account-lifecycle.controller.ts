import { Controller, Get, Post, Req, Res } from "@nestjs/common";
import { AccountLifecycleScope, AccountLifecycleService } from "./account-lifecycle.service.js";

@Controller()
export class AccountLifecycleController {
  constructor(private readonly accountLifecycle: AccountLifecycleService) {}

  @Get("internal/account-lifecycle/readiness")
  readiness() {
    return {
      status: "ok",
      service: "identity-adapter",
      capability: "account-lifecycle",
      data: this.accountLifecycle.readiness()
    };
  }

  @Post("v1/auth/register")
  authRegister(@Req() request: AccountLifecycleExpressRequest, @Res({ passthrough: true }) response: AccountLifecycleExpressResponse) {
    return this.forward("register", request, response, "/v1/auth/register");
  }

  @Post("v1/wechat/register")
  wechatRegister(@Req() request: AccountLifecycleExpressRequest, @Res({ passthrough: true }) response: AccountLifecycleExpressResponse) {
    return this.forward("register", request, response, "/v1/wechat/register");
  }

  @Get("v1/wechat/qrcode")
  wechatQrcode(@Req() request: AccountLifecycleExpressRequest, @Res({ passthrough: true }) response: AccountLifecycleExpressResponse) {
    return this.forward("register", request, response, "/v1/wechat/qrcode");
  }

  @Get("v1/wechat/refresh")
  wechatRefresh(@Req() request: AccountLifecycleExpressRequest, @Res({ passthrough: true }) response: AccountLifecycleExpressResponse) {
    return this.forward("register", request, response, "/v1/wechat/refresh");
  }

  @Post("v1/password/request-reset")
  passwordRequestReset(@Req() request: AccountLifecycleExpressRequest, @Res({ passthrough: true }) response: AccountLifecycleExpressResponse) {
    return this.forward("password", request, response, "/v1/password/request-reset");
  }

  @Post("v1/password/verify-code")
  passwordVerifyCode(@Req() request: AccountLifecycleExpressRequest, @Res({ passthrough: true }) response: AccountLifecycleExpressResponse) {
    return this.forward("password", request, response, "/v1/password/verify-code");
  }

  @Post("v1/password/reset")
  passwordReset(@Req() request: AccountLifecycleExpressRequest, @Res({ passthrough: true }) response: AccountLifecycleExpressResponse) {
    return this.forward("password", request, response, "/v1/password/reset");
  }

  @Post("v1/password/change")
  passwordChange(@Req() request: AccountLifecycleExpressRequest, @Res({ passthrough: true }) response: AccountLifecycleExpressResponse) {
    return this.forward("password", request, response, "/v1/password/change");
  }

  @Get("v1/email/status")
  emailStatus(@Req() request: AccountLifecycleExpressRequest, @Res({ passthrough: true }) response: AccountLifecycleExpressResponse) {
    return this.forward("email", request, response, "/v1/email/status");
  }

  @Post("v1/email/send-verification")
  emailSendVerification(@Req() request: AccountLifecycleExpressRequest, @Res({ passthrough: true }) response: AccountLifecycleExpressResponse) {
    return this.forward("email", request, response, "/v1/email/send-verification");
  }

  @Post("v1/email/verify")
  emailVerify(@Req() request: AccountLifecycleExpressRequest, @Res({ passthrough: true }) response: AccountLifecycleExpressResponse) {
    return this.forward("email", request, response, "/v1/email/verify");
  }

  @Post("v1/email/send-change-confirmation")
  emailSendChangeConfirmation(@Req() request: AccountLifecycleExpressRequest, @Res({ passthrough: true }) response: AccountLifecycleExpressResponse) {
    return this.forward("email", request, response, "/v1/email/send-change-confirmation");
  }

  @Post("v1/email/verify-change-confirmation")
  emailVerifyChangeConfirmation(@Req() request: AccountLifecycleExpressRequest, @Res({ passthrough: true }) response: AccountLifecycleExpressResponse) {
    return this.forward("email", request, response, "/v1/email/verify-change-confirmation");
  }

  @Post("v1/email/unbind")
  emailUnbind(@Req() request: AccountLifecycleExpressRequest, @Res({ passthrough: true }) response: AccountLifecycleExpressResponse) {
    return this.forward("email", request, response, "/v1/email/unbind");
  }

  @Get("v1/email/cooldown")
  emailCooldown(@Req() request: AccountLifecycleExpressRequest, @Res({ passthrough: true }) response: AccountLifecycleExpressResponse) {
    return this.forward("email", request, response, "/v1/email/cooldown");
  }

  @Get("v1/plugin-user/invitations")
  invitations(@Req() request: AccountLifecycleExpressRequest, @Res({ passthrough: true }) response: AccountLifecycleExpressResponse) {
    return this.forward("invitation", request, response, "/v1/plugin-user/invitations");
  }

  @Post("v1/plugin-user/create-invitation")
  createInvitation(@Req() request: AccountLifecycleExpressRequest, @Res({ passthrough: true }) response: AccountLifecycleExpressResponse) {
    return this.forward("invitation", request, response, "/v1/plugin-user/create-invitation");
  }

  @Post("v1/plugin-user/delete-invitation")
  deleteInvitation(@Req() request: AccountLifecycleExpressRequest, @Res({ passthrough: true }) response: AccountLifecycleExpressResponse) {
    return this.forward("invitation", request, response, "/v1/plugin-user/delete-invitation");
  }

  @Get("v1/plugin-user/check-invitation")
  checkInvitation(@Req() request: AccountLifecycleExpressRequest, @Res({ passthrough: true }) response: AccountLifecycleExpressResponse) {
    return this.forward("invitation", request, response, "/v1/plugin-user/check-invitation");
  }

  @Get("v1/plugin-user/invitation-records")
  invitationRecords(@Req() request: AccountLifecycleExpressRequest, @Res({ passthrough: true }) response: AccountLifecycleExpressResponse) {
    return this.forward("invitation", request, response, "/v1/plugin-user/invitation-records");
  }

  @Post("v1/plugin-user/register-send-code")
  invitationRegisterSendCode(@Req() request: AccountLifecycleExpressRequest, @Res({ passthrough: true }) response: AccountLifecycleExpressResponse) {
    return this.forward("invitation", request, response, "/v1/plugin-user/register-send-code");
  }

  @Post("v1/plugin-user/register")
  invitationRegister(@Req() request: AccountLifecycleExpressRequest, @Res({ passthrough: true }) response: AccountLifecycleExpressResponse) {
    return this.forward("invitation", request, response, "/v1/plugin-user/register");
  }

  private async forward(
    scope: AccountLifecycleScope,
    request: AccountLifecycleExpressRequest,
    response: AccountLifecycleExpressResponse,
    path: string
  ): Promise<unknown> {
    const upstream = await this.accountLifecycle.proxy(scope, request, path);
    response.status(upstream.status);

    return upstream.body;
  }
}

interface AccountLifecycleExpressRequest {
  method: string;
  originalUrl?: string;
  headers: Record<string, string | string[] | undefined>;
  body?: unknown;
}

interface AccountLifecycleExpressResponse {
  status(code: number): unknown;
}
