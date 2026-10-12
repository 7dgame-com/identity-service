import { Body, Controller, Get, Headers, HttpCode, Post, Query, Req, UnauthorizedException } from "@nestjs/common";
import { timingSafeEqual } from "node:crypto";
import { NativeRequest } from "./native-identity.service.js";
import { NativeQrcodeService } from "./native-qrcode.service.js";
import { RequestContext } from "./token-issuance.service.js";

@Controller()
export class NativeQrcodeController {
  constructor(private readonly qrcode: NativeQrcodeService) {}

  @Get("v1/tools/user-linked")
  linked(@Req() request: NativeRequest) { return this.qrcode.issueLoginCode(request); }

  @Get("v1/tools/user-linked/status")
  status(@Req() request: NativeRequest, @Query("key") key: unknown) { return this.qrcode.loginCodeStatus(request, key); }

  @Post("v1/wechat/login")
  login(@Req() request: NativeRequest & { ip?: string }) { return this.qrcode.wechatLogin(request.body, context(request)); }

  @Post("v1/wechat/binding")
  @HttpCode(200)
  binding(@Req() request: NativeRequest & { ip?: string }) { return this.qrcode.wechatBinding(request.body, context(request)); }

  @Post("internal/wechat-provider/confirm-scan")
  confirm(@Headers("x-identity-internal-token") key: string | undefined, @Body() body: unknown) {
    const expected = this.qrcode.internalToken;
    if (!expected || !key || Buffer.byteLength(key) !== Buffer.byteLength(expected)
      || !timingSafeEqual(Buffer.from(expected), Buffer.from(key))) throw new UnauthorizedException();
    return this.qrcode.confirmWechatScan(body);
  }
}

function context(request: NativeRequest & { ip?: string }): RequestContext {
  return { ip: request.ip, userAgent: typeof request.headers["user-agent"] === "string" ? request.headers["user-agent"] : null };
}
