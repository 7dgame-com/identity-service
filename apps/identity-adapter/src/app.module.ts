import { Module } from "@nestjs/common";
import { APP_INTERCEPTOR } from "@nestjs/core";
import { AccountEmailRepository } from "./account-email.repository.js";
import { AccountEmailService } from "./account-email.service.js";
import { AccountInvitationService } from "./account-invitation.service.js";
import { AccountLifecycleController } from "./account-lifecycle.controller.js";
import { AccountLifecycleOperationRepository } from "./account-lifecycle-operation.repository.js";
import { AccountLifecycleService } from "./account-lifecycle.service.js";
import { AccountPasswordRepository } from "./account-password.repository.js";
import { AccountPasswordResetService } from "./account-password-reset.service.js";
import { AccountPasswordService } from "./account-password.service.js";
import { AccountRegistrationRepository } from "./account-registration.repository.js";
import { AccountRegistrationService } from "./account-registration.service.js";
import { AuthController } from "./auth.controller.js";
import { HealthController } from "./health.controller.js";
import { IamController } from "./iam.controller.js";
import { IamRepository } from "./iam.repository.js";
import { IamService } from "./iam.service.js";
import { IdentityController } from "./identity.controller.js";
import { IdentitySessionRepository } from "./identity-session.repository.js";
import { InternalAuthController } from "./internal-auth.controller.js";
import { InvitationDiagnosticsController } from "./invitation-diagnostics.controller.js";
import { InvitationDiagnosticsService } from "./invitation-diagnostics.service.js";
import { InvitationIdentityRepository } from "./invitation-identity.repository.js";
import { InvitationImportService } from "./invitation-import.service.js";
import { InvitationLegacyRedisRepository } from "./invitation-legacy-redis.repository.js";
import { InvitationRecordRepository } from "./invitation-record.repository.js";
import { InvitationRedisReader } from "./invitation-redis.reader.js";
import { JwtIssuerService } from "./jwt-issuer.service.js";
import { LegacyIdentityReader } from "./legacy-identity.reader.js";
import { LegacySessionRevocationService } from "./legacy-session-revocation.service.js";
import { EmailDeliveryService } from "./email-delivery.service.js";
import { EmailChangeTokenRepository } from "./email-change-token.repository.js";
import { EmailVerificationChallengeRepository } from "./email-verification-challenge.repository.js";
import { LoginAuditController } from "./login-audit.controller.js";
import { LoginAuditRepository } from "./login-audit.repository.js";
import { LoginAuditService } from "./login-audit.service.js";
import { OidcAuthorizationCodeRepository } from "./oidc-authorization-code.repository.js";
import { OidcController } from "./oidc.controller.js";
import { OidcService } from "./oidc.service.js";
import { PasswordResetChallengeRepository } from "./password-reset-challenge.repository.js";
import { PluginUserPrimaryReadService } from "./plugin-user-primary-read.service.js";
import { PluginUserWriteOperationRepository } from "./plugin-user-write-operation.repository.js";
import { PluginUserReadonlyController } from "./plugin-user-readonly.controller.js";
import { PluginUserTemporaryAuthorizationController } from "./plugin-user-temporary-authorization.controller.js";
import { PluginUserTemporaryAuthorizationRepository } from "./plugin-user-temporary-authorization.repository.js";
import { PluginUserTemporaryAuthorizationService } from "./plugin-user-temporary-authorization.service.js";
import { PluginUserWriteController } from "./plugin-user-write.controller.js";
import { PluginUserWriteShadowService } from "./plugin-user-write-shadow.service.js";
import { PluginUserWriteService } from "./plugin-user-write.service.js";
import { ProfileWriteController } from "./profile-write.controller.js";
import { ProfileWriteOperationRepository } from "./profile-write-operation.repository.js";
import { ProfileWriteService } from "./profile-write.service.js";
import { TelemetryInterceptor } from "./telemetry.interceptor.js";
import { TokenIssuanceService } from "./token-issuance.service.js";
import { UsageBillingController } from "./usage-billing.controller.js";
import { UsageBillingRepository } from "./usage-billing.repository.js";
import { UsageBillingService } from "./usage-billing.service.js";

@Module({
  controllers: [
    HealthController,
    IdentityController,
    LoginAuditController,
    AuthController,
    AccountLifecycleController,
    InvitationDiagnosticsController,
    InternalAuthController,
    IamController,
    PluginUserReadonlyController,
    PluginUserTemporaryAuthorizationController,
    PluginUserWriteController,
    ProfileWriteController,
    UsageBillingController,
    OidcController
  ],
  providers: [
    AccountLifecycleService,
    AccountEmailRepository,
    AccountEmailService,
    {
      provide: AccountInvitationService,
      useFactory: (
        identityInvitations: InvitationIdentityRepository,
        legacyRedis: InvitationLegacyRedisRepository,
        redisReader: InvitationRedisReader,
        invitationRecords: InvitationRecordRepository,
        jwtIssuer: JwtIssuerService
      ) => new AccountInvitationService(identityInvitations, legacyRedis, redisReader, invitationRecords, jwtIssuer),
      inject: [
        InvitationIdentityRepository,
        InvitationLegacyRedisRepository,
        InvitationRedisReader,
        InvitationRecordRepository,
        JwtIssuerService
      ]
    },
    AccountLifecycleOperationRepository,
    AccountPasswordRepository,
    AccountPasswordResetService,
    AccountPasswordService,
    AccountRegistrationRepository,
    AccountRegistrationService,
    LegacyIdentityReader,
    LegacySessionRevocationService,
    IdentitySessionRepository,
    InvitationDiagnosticsService,
    InvitationIdentityRepository,
    InvitationImportService,
    InvitationLegacyRedisRepository,
    InvitationRecordRepository,
    InvitationRedisReader,
    JwtIssuerService,
    EmailDeliveryService,
    EmailChangeTokenRepository,
    EmailVerificationChallengeRepository,
    PasswordResetChallengeRepository,
    LoginAuditRepository,
    LoginAuditService,
    IamRepository,
    IamService,
    OidcAuthorizationCodeRepository,
    OidcService,
    UsageBillingRepository,
    UsageBillingService,
    PluginUserPrimaryReadService,
    PluginUserTemporaryAuthorizationRepository,
    PluginUserTemporaryAuthorizationService,
    PluginUserWriteOperationRepository,
    PluginUserWriteShadowService,
    PluginUserWriteService,
    ProfileWriteOperationRepository,
    ProfileWriteService,
    TokenIssuanceService,
    { provide: APP_INTERCEPTOR, useClass: TelemetryInterceptor }
  ]
})
export class AppModule {}
