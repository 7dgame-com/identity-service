import { Controller, Get, Inject } from "@nestjs/common";
import { trace } from "@opentelemetry/api";
import { loadConfig } from "./config.js";
import { LegacyIdentityReader } from "./legacy-identity.reader.js";

@Controller()
export class HealthController {
  private readonly config = loadConfig();

  constructor(@Inject(LegacyIdentityReader) private readonly legacyReader: LegacyIdentityReader) {}

  @Get("health")
  async health() {
    const span = trace.getTracer(this.config.otel.serviceName).startSpan("identity.health");
    try {
      const legacyDatabase = await this.legacyReader.health();
      return {
        status: "ok",
        service: "identity-adapter",
        mode: this.config.readonlyMode ? "readonly" : "unsafe",
        version: process.env.npm_package_version ?? "0.1.0",
        revision: buildRevision(),
        dependencies: {
          legacyDatabase,
          keycloak: this.config.keycloak.baseUrl ? "configured" : "not_configured"
        },
        capabilities: {
          tokenIssuance: this.config.tokenIssuance.enabled ? "enabled" : "disabled",
          oidc: this.config.oidc.enabled ? "enabled" : "disabled",
          loginAudit: this.config.loginAudit.enabled ? "enabled" : "disabled",
          usageBillingShadow: this.config.usageBilling.shadowEnabled ? "enabled" : "disabled",
          iam: this.config.iam.enabled ? this.config.iam.mode : "disabled",
          iamViews: {
            user: this.config.iam.userViewEnabled ? "enabled" : "disabled",
            role: this.config.iam.roleViewEnabled ? "enabled" : "disabled",
            permission: this.config.iam.permissionViewEnabled ? "enabled" : "disabled",
            organization: this.config.iam.organizationViewEnabled ? "enabled" : "disabled",
            plugin: this.config.iam.pluginViewEnabled ? "enabled" : "disabled"
          },
          accountLifecycle: this.config.accountLifecycle.enabled ? "enabled" : "disabled",
          accountLifecycleScopes: {
            register: this.config.accountLifecycle.registerEnabled ? "enabled" : "disabled",
            password: this.config.accountLifecycle.passwordEnabled ? "enabled" : "disabled",
            passwordChangeNative: this.config.accountLifecycle.passwordChangeNativeEnabled ? "enabled" : "disabled",
            passwordResetNative: this.config.accountLifecycle.passwordResetNativeEnabled ? "enabled" : "disabled",
            email: this.config.accountLifecycle.emailEnabled ? "enabled" : "disabled",
            invitation: this.config.accountLifecycle.invitationEnabled ? "enabled" : "disabled"
          },
          profileWrite: this.config.iam.profileWriteMode,
          organizationWrite: {
            mode: this.config.iam.organizationWriteMode,
            routeIntegrationEnabled: this.config.iam.organizationWriteRouteIntegrationEnabled,
            dualWriteExecutionEnabled: this.config.iam.organizationWriteDualWriteExecutionEnabled,
            candidateMaterializationEnabled:
              this.config.iam.organizationWriteCandidateMaterializationEnabled,
            candidateMaterializationTargetConfigured:
              this.config.iam.organizationWriteCandidateMaterializationTargetLegacyUserId > 0,
            rolloutMode: this.config.iam.organizationWriteRolloutMode,
            rolloutAllowlistCount: this.config.iam.organizationWriteRolloutAllowlist
              .split(",")
              .map((item) => item.trim())
              .filter(Boolean).length,
            rolloutPercentage: this.config.iam.organizationWriteRolloutPercentage,
            sourceOfTruth: "legacy",
            identityNativeSupported: false
          },
          pluginUserWrite: this.config.iam.pluginUserWriteMode
        }
      };
    } finally {
      span.end();
    }
  }
}

function buildRevision(): string {
  const value = process.env.IDENTITY_BUILD_REVISION?.trim().toLowerCase() ?? "";
  return /^[a-f0-9]{40}$/.test(value) ? value : "unknown";
}
