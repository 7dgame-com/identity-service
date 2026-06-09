import { Module } from "@nestjs/common";
import { APP_INTERCEPTOR } from "@nestjs/core";
import { AuthController } from "./auth.controller.js";
import { HealthController } from "./health.controller.js";
import { IdentityController } from "./identity.controller.js";
import { IdentitySessionRepository } from "./identity-session.repository.js";
import { JwtIssuerService } from "./jwt-issuer.service.js";
import { LegacyIdentityReader } from "./legacy-identity.reader.js";
import { LoginAuditController } from "./login-audit.controller.js";
import { LoginAuditRepository } from "./login-audit.repository.js";
import { LoginAuditService } from "./login-audit.service.js";
import { TelemetryInterceptor } from "./telemetry.interceptor.js";
import { TokenIssuanceService } from "./token-issuance.service.js";

@Module({
  controllers: [HealthController, IdentityController, LoginAuditController, AuthController],
  providers: [
    LegacyIdentityReader,
    IdentitySessionRepository,
    JwtIssuerService,
    LoginAuditRepository,
    LoginAuditService,
    TokenIssuanceService,
    { provide: APP_INTERCEPTOR, useClass: TelemetryInterceptor }
  ]
})
export class AppModule {}
