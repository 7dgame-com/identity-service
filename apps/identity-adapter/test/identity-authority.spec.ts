import "reflect-metadata";
import { afterEach, describe, expect, it, vi } from "vitest";
import { identityAccountReadDb, identityAccountWriteDb, loadConfig } from "../src/config.js";
import { AccountLifecycleService } from "../src/account-lifecycle.service.js";
import { AccountRegistrationService } from "../src/account-registration.service.js";
import { AccountPasswordService } from "../src/account-password.service.js";
import { AccountPasswordResetService } from "../src/account-password-reset.service.js";
import { AccountEmailService } from "../src/account-email.service.js";
import { AccountInvitationService } from "../src/account-invitation.service.js";
import { InvitationRedisReader } from "../src/invitation-redis.reader.js";
import { operationKeyForRegister } from "../src/account-lifecycle-operation.repository.js";
import { HealthController } from "../src/health.controller.js";
import type { LegacyIdentityReader } from "../src/legacy-identity.reader.js";

afterEach(() => vi.unstubAllEnvs());

describe("independent account authority", () => {
  it("fails readiness when private account storage becomes unavailable",async()=>{
    vi.stubEnv("IDENTITY_DATA_SOURCE","identity");
    const controller=new HealthController({health:vi.fn().mockResolvedValue("unavailable")} as unknown as LegacyIdentityReader);
    await expect(controller.health()).rejects.toMatchObject({status:503});
  });
  it("defaults to legacy and selects only the explicit private database in identity mode", () => {
    const legacy = loadConfig({ LEGACY_DB_HOST: "old-db", LEGACY_WRITE_DB_HOST: "old-writer", IDENTITY_DB_HOST: "private-db" });
    expect(legacy.dataSource).toBe("legacy");
    expect(identityAccountReadDb(legacy).host).toBe("old-db");
    expect(identityAccountWriteDb(legacy).host).toBe("old-writer");
    const independent = loadConfig({ IDENTITY_DATA_SOURCE: "identity", LEGACY_DB_HOST: "old-db", LEGACY_WRITE_DB_HOST: "old-writer", IDENTITY_DB_HOST: "private-db" });
    expect(identityAccountReadDb(independent).host).toBe("private-db");
    expect(identityAccountWriteDb(independent).host).toBe("private-db");
    expect(() => loadConfig({ IDENTITY_DATA_SOURCE: "invalid" })).toThrow();
  });

  it("forbids the legacy lifecycle proxy and disables Redis comparison reads", async () => {
    vi.stubEnv("IDENTITY_DATA_SOURCE", "identity");
    vi.stubEnv("IDENTITY_ACCOUNT_LIFECYCLE_ENABLED", "true");
    vi.stubEnv("IDENTITY_ACCOUNT_LIFECYCLE_MODE", "legacy-proxy");
    vi.stubEnv("IDENTITY_ACCOUNT_REGISTER_ENABLED", "true");
    vi.stubEnv("IDENTITY_ACCOUNT_LIFECYCLE_LEGACY_API_BASE_URL", "http://127.0.0.1:1");
    vi.stubEnv("IDENTITY_INVITATION_REDIS_URL", "redis://127.0.0.1:1/0");
    const service = new AccountLifecycleService({} as AccountRegistrationService, {} as AccountPasswordService,
      {} as AccountPasswordResetService, {} as AccountEmailService, {} as AccountInvitationService);
    await expect(service.proxy("register", { method: "POST", headers: {}, body: {} }, "/v1/auth/register")).rejects.toThrow("Independent identity accounts");
    const reader = new InvitationRedisReader();
    expect(reader.isConfigured()).toBe(false);
    await expect(reader.scanInvitations()).resolves.toMatchObject({ configured: false, invitations: [] });
  });

  it("normalizes account names without weakening password or opaque-token idempotency", () => {
    expect(operationKeyForRegister("standard", ["User", "USER@EXAMPLE.TEST", "Secret!A"]))
      .toBe(operationKeyForRegister("standard", ["user", "user@example.test", "Secret!A"]));
    expect(operationKeyForRegister("standard", ["User", "user@example.test", "Secret!A"]))
      .not.toBe(operationKeyForRegister("standard", ["User", "user@example.test", "secret!a"]));
    expect(operationKeyForRegister("wechat", ["Opaque-A", "user", "", "Secret!A"]))
      .not.toBe(operationKeyForRegister("wechat", ["opaque-a", "user", "", "Secret!A"]));
  });

  it("uses unambiguous keyed credential fingerprints for independent registration",()=>{
    vi.stubEnv("IDENTITY_DATA_SOURCE","identity");vi.stubEnv("IDENTITY_INTERNAL_API_TOKEN","fingerprint-test-secret-with-at-least-32-bytes");
    expect(operationKeyForRegister("standard",["collision\u001f","","Secret-A!73"]))
      .not.toBe(operationKeyForRegister("standard",["collision","","\u001fSecret-A!73"]));
  });
});
