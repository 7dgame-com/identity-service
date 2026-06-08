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
        dependencies: {
          legacyDatabase,
          keycloak: this.config.keycloak.baseUrl ? "configured" : "not_configured"
        },
        capabilities: {
          tokenIssuance: this.config.tokenIssuance.enabled ? "enabled" : "disabled",
          loginAudit: this.config.loginAudit.enabled ? "enabled" : "disabled"
        }
      };
    } finally {
      span.end();
    }
  }
}
