import { Logger } from "@nestjs/common";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { PluginUserWriteOperationRepository } from "../src/plugin-user-write-operation.repository.js";
import { PluginUserWriteShadowService } from "../src/plugin-user-write-shadow.service.js";

describe("plugin user write shadow evidence", () => {
  const originalShadowMode = process.env.IDENTITY_IAM_PLUGIN_USER_WRITE_SHADOW_MODE;

  afterEach(() => {
    if (originalShadowMode === undefined) {
      delete process.env.IDENTITY_IAM_PLUGIN_USER_WRITE_SHADOW_MODE;
    } else {
      process.env.IDENTITY_IAM_PLUGIN_USER_WRITE_SHADOW_MODE = originalShadowMode;
    }
    vi.restoreAllMocks();
  });

  it("logs all plugin-user write plan events with non-sensitive correlation evidence", async () => {
    process.env.IDENTITY_IAM_PLUGIN_USER_WRITE_SHADOW_MODE = "plan";
    const logSpy = vi.spyOn(Logger.prototype, "log").mockImplementation(() => undefined);
    const service = new PluginUserWriteShadowService(fakeOperationRepository());

    await service.observe({
      method: "POST",
      path: "/v1/plugin-user/create-user",
      headers: { authorization: "Bearer secret-token" },
      body: { username: "q2retry_202606291031_xsct", password: "Secret123!" },
      legacyStatus: 201
    });
    await service.observe({
      method: "POST",
      path: "/v1/plugin-user/update-user",
      headers: { authorization: "Bearer secret-token" },
      body: { id: 588, nickname: "Q2 plan shadow temporary user updated", password: "Secret456!" },
      legacyStatus: 200
    });
    await service.observe({
      method: "POST",
      path: "/v1/plugin-user/delete-user",
      headers: { authorization: "Bearer secret-token" },
      body: { id: 588 },
      legacyStatus: 200
    });
    await service.observe({
      method: "POST",
      path: "/v1/plugin-user/change-role",
      headers: { authorization: "Bearer secret-token" },
      body: { id: 588, role: "admin" },
      legacyStatus: 200
    });
    await service.observe({
      method: "POST",
      path: "/v1/plugin-user/batch-create-users",
      headers: { authorization: "Bearer secret-token" },
      body: {
        users: [
          {
            username: "q2retry_batch_001",
            nickname: "Q2 plan batch temporary user",
            password: "BatchSecret123!",
            role: "user",
            status: 10
          }
        ]
      },
      legacyStatus: 200
    });

    const events = logSpy.mock.calls.map(([message]) => JSON.parse(String(message)) as Record<string, unknown>);

    expect(events).toHaveLength(5);
    expect(events.map((event) => event.route)).toEqual([
      "create-user",
      "update-user",
      "delete-user",
      "change-role",
      "batch-create-users"
    ]);

    for (const event of events) {
      expect(event.event).toBe("identity.plugin_user.write.shadow");
      expect(event.mode).toBe("plan");
      expect(event.sideEffect).toBe("none");
      expect(event.operationKey).toMatch(new RegExp(`^plugin-user-write:v1:${event.route}:[a-f0-9]{48}$`));
      expect(event.correlationId).toMatch(/^plugin-user-write:[a-f0-9]{16}$/);
      expect(event.actorSubjectKind).toBe("authorization");
      expect(event.actorSubjectHash).toMatch(/^[a-f0-9]{16}$/);
      expect(event.targetSubjectHash).toMatch(/^[a-f0-9]{16}$/);

      const serialized = JSON.stringify(event);
      expect(serialized).not.toContain("q2retry_202606291031_xsct");
      expect(serialized).not.toContain("Q2 plan shadow temporary user updated");
      expect(serialized).not.toContain("q2retry_batch_001");
      expect(serialized).not.toContain("Q2 plan batch temporary user");
      expect(serialized).not.toContain("Secret123!");
      expect(serialized).not.toContain("Secret456!");
      expect(serialized).not.toContain("BatchSecret123!");
      expect(serialized).not.toContain("secret-token");
    }

    expect(events[0].targetSubjectKind).toBe("username");
    expect(events[1].targetSubjectKind).toBe("legacy-user");
    expect(events[2].targetSubjectKind).toBe("legacy-user");
    expect(events[3].targetSubjectKind).toBe("legacy-user");
    expect(events[4].targetSubjectKind).toBe("batch");
  });
});

function fakeOperationRepository(): PluginUserWriteOperationRepository {
  return {
    isConfigured: () => false,
    begin: async () => ({ duplicate: false })
  } as unknown as PluginUserWriteOperationRepository;
}
