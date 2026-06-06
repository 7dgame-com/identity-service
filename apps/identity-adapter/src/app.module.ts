import { Module } from "@nestjs/common";
import { APP_INTERCEPTOR } from "@nestjs/core";
import { HealthController } from "./health.controller.js";
import { IdentityController } from "./identity.controller.js";
import { LegacyIdentityReader } from "./legacy-identity.reader.js";
import { LoginAuditController } from "./login-audit.controller.js";
import { LoginAuditRepository } from "./login-audit.repository.js";
import { LoginAuditService } from "./login-audit.service.js";
import { TelemetryInterceptor } from "./telemetry.interceptor.js";

@Module({
  controllers: [HealthController, IdentityController, LoginAuditController],
  providers: [
    LegacyIdentityReader,
    LoginAuditRepository,
    LoginAuditService,
    { provide: APP_INTERCEPTOR, useClass: TelemetryInterceptor }
  ]
})
export class AppModule {}
