import "reflect-metadata";
import { UnauthorizedException } from "@nestjs/common";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { loadConfig } from "../src/config.js";
import { PluginUserReadonlyController } from "../src/plugin-user-readonly.controller.js";
import { PluginUserPrimaryReadService } from "../src/plugin-user-primary-read.service.js";
import type { LegacyIdentityReader, LegacyUserReadModel } from "../src/legacy-identity.reader.js";
import type { IamRepository } from "../src/iam.repository.js";
import type { JwtIssuerService, VerifiedAccessToken } from "../src/jwt-issuer.service.js";
import type { LoginAuditService } from "../src/login-audit.service.js";
import type { NativeIdentityService } from "../src/native-identity.service.js";

const query = { organization_id: "7", start_at: "2026-09-25T00:00:00+08:00", end_at: "2026-09-27T00:00:00+08:00" };
function user(id: number, roles = ["user"], organizationId = 7): LegacyUserReadModel {
  return { id, username: `native-${id}`, nickname: `成员${id}`, email: null, emailVerifiedAt: null,
    status: 10, createdAt: 1, updatedAt: 1, userInfo: null, roles, source: "legacy",
    organizations: [{ id: organizationId, name: `org-${organizationId}`, title: `组织${organizationId}`, createdAt: null, updatedAt: null }] };
}

describe("activated private organization audit authority", () => {
  let actor: LegacyUserReadModel;
  let members: LegacyUserReadModel[];
  let reader: any;
  let repository: any;
  let native: any;
  let jwt: any;
  let audit: any;
  let controller: PluginUserReadonlyController;
  beforeEach(() => {
    vi.stubEnv("IDENTITY_DATA_SOURCE", "identity");
    vi.stubEnv("IDENTITY_LOGIN_AUDIT_ENABLED", "true");
    vi.stubEnv("IDENTITY_PLUGIN_USER_READONLY_ENABLED", "false");
    actor = user(1, ["manager"]);
    members = [actor, user(2)];
    reader = {
      isConfigured: vi.fn(() => true),
      getUserById: vi.fn(async (id: number) => members.find((member) => member.id === id) ?? null),
      listOrganizationAuditMembers: vi.fn(async () => members),
      listUsersByOrganization: vi.fn(async () => members),
      listOrganizations: vi.fn(async () => actor.organizations),
      listUserPermissions: vi.fn(async () => [{ name: "user-management.view-user" }]),
      listManagedUsers: vi.fn(async () => ({ users: members, page: 1, pageSize: 20, total: members.length, totalPages: 1 }))
    };
    repository = { isConfigured: vi.fn(() => false), listAuditNativeRoles: vi.fn(),
      listOrganizationMembershipsShadow: vi.fn(), listOrganizationMembershipsShadowForUsers: vi.fn() };
    native = { enabled: true, actor: vi.fn(async ({ headers }: { headers: { authorization?: string } }) => {
      if (!headers.authorization) throw new UnauthorizedException();
      return actor;
    }), subject: reader.getUserById, requirePermission: vi.fn() };
    jwt = { verifyAccessToken: vi.fn(() => { throw new Error("stale JWT roles must not authorize native audits"); }) };
    audit = { getUserAudit: vi.fn(async () => ({ stats: null, recentEvents: [] })),
      createUsageInvoice: vi.fn(async () => ({ amountCents: 10000 })),
      listOrganizationEvents: vi.fn(async () => ({ events: [{ eventKey: "native-login", userId: 2, occurredAt: "2026-09-25T01:00:00Z", source: "identity-adapter" }], total: 1 })) };
    controller = new PluginUserReadonlyController(reader, jwt, new PluginUserPrimaryReadService(repository, reader), audit, repository, native);
  });
  afterEach(() => vi.unstubAllEnvs());

  it.each(["root", "admin", "manager"])("uses current private %s roles and members without staged shadow tables", async (role) => {
    actor.roles = [role];
    const result = await controller.organizationLoginEvents("Bearer current", query);
    expect(result).toMatchObject({ code: 0, data: [{ username: "native-2", primaryRole: "user" }], pagination: { total: 1 } });
    expect(native.actor).toHaveBeenCalledWith({ headers: { authorization: "Bearer current" } });
    expect(jwt.verifyAccessToken).not.toHaveBeenCalled();
    expect(repository.listOrganizationMembershipsShadow).not.toHaveBeenCalled();
    expect(repository.listOrganizationMembershipsShadowForUsers).not.toHaveBeenCalled();
    expect(repository.listAuditNativeRoles).not.toHaveBeenCalled();
  });

  it.each(["user", "guest"])("denies current %s roles before exposing members or counts", async (role) => {
    actor.roles = [role];
    await expect(controller.organizationLoginEvents("Bearer current", query)).rejects.toMatchObject({ status: 403 });
    expect(reader.listOrganizationAuditMembers).not.toHaveBeenCalled();
    expect(audit.listOrganizationEvents).not.toHaveBeenCalled();
  });

  it("rejects a revoked session through the native verifier", async () => {
    native.actor.mockRejectedValue(new UnauthorizedException({ code: "SESSION_REVOKED" }));
    await expect(controller.organizationLoginEvents("Bearer revoked", query)).rejects.toMatchObject({ status: 401 });
    expect(reader.listOrganizationAuditMembers).not.toHaveBeenCalled();
  });

  it("denies non-root cross-organization access without an audit count", async () => {
    actor.organizations = user(1, ["manager"], 8).organizations;
    await expect(controller.organizationLoginEvents("Bearer current", query)).rejects.toMatchObject({ status: 403 });
    expect(audit.listOrganizationEvents).not.toHaveBeenCalled();
  });

  it("still requires an explicit organization for root event listings", async () => {
    actor.roles = ["root"];
    await expect(controller.organizationLoginEvents("Bearer current", { ...query, organization_id: undefined })).rejects.toMatchObject({ status: 403 });
  });

  it("fails closed if the private membership database fails, including for an empty filter", async () => {
    reader.listOrganizationAuditMembers.mockRejectedValue(new Error("private database unavailable"));
    await expect(controller.organizationLoginEvents("Bearer current", { ...query, search: "none" })).rejects.toMatchObject({ status: 403 });
    expect(audit.listOrganizationEvents).not.toHaveBeenCalled();
  });

  it.each([["root", "full"], ["admin", "masked"], ["manager", "masked"]])("exposes %s user audit IP addresses as %s", async (role, exposure) => {
    actor.roles = [role];
    await controller.userLoginAudit("Bearer current", "2", { organization_id: "7" });
    expect(audit.getUserAudit).toHaveBeenCalledWith(2, exposure);
  });

  it("calculates invoices from current private members and verifies native sessions", async () => {
    await controller.organizationLoginUsageInvoice("Bearer current", "7", { from: "2026-09-25T00:00:00Z", to: "2026-09-25T23:59:59Z" });
    expect(audit.createUsageInvoice).toHaveBeenCalledWith({ accounts: [{ legacyUserId: 1, username: "native-1" }, { legacyUserId: 2, username: "native-2" }], from: new Date("2026-09-25T00:00:00Z"), to: new Date("2026-09-25T23:59:59Z") });
    expect(repository.listOrganizationMembershipsShadow).not.toHaveBeenCalled();
    expect(jwt.verifyAccessToken).not.toHaveBeenCalled();
  });

  it("rejects cross-organization invoices before querying login history", async () => {
    actor.organizations = user(1, ["manager"], 8).organizations;
    reader.listOrganizations.mockResolvedValue(user(2).organizations);
    await expect(controller.organizationLoginUsageInvoice("Bearer current", "7", {})).rejects.toMatchObject({ status: 403 });
    expect(audit.createUsageInvoice).not.toHaveBeenCalled();
  });

  it("does not enter compatibility endpoints when the native authority provider is absent", async () => {
    const absent = new PluginUserReadonlyController(reader, jwt, {} as PluginUserPrimaryReadService, audit, repository);
    await expect(absent.organizationLoginEvents("Bearer current", query)).rejects.toMatchObject({ status: 503 });
    await expect(absent.users({}, { setHeader: vi.fn() }, "Bearer current")).rejects.toMatchObject({ status: 503 });
    expect(jwt.verifyAccessToken).not.toHaveBeenCalled();
  });

  it("keeps native primary reads on the private account reader even when staged fallback is enabled", async () => {
    const primary = new PluginUserPrimaryReadService(repository, reader);
    const claims = { uid: 1, roles: ["root"] } as VerifiedAccessToken;
    await expect(primary.getUserById(2, claims)).resolves.toMatchObject({ source: "identity-db", data: { id: 2 } });
    await expect(primary.getUserById(999, claims)).resolves.toEqual({ source: "identity-db", data: null });
    reader.isConfigured.mockReturnValue(false);
    await expect(primary.listUsers({ page: 1, pageSize: 20 }, claims)).rejects.toMatchObject({ status: 503 });
    expect(reader.listManagedUsers).not.toHaveBeenCalled();
  });
});

describe("separate optional device serial database configuration", () => {
  it("never fills device database settings from legacy account credentials", () => {
    const config = loadConfig({ IDENTITY_DATA_SOURCE: "identity", LEGACY_DB_HOST: "old-account-db", LEGACY_DB_USER: "old-user", LEGACY_DB_NAME: "old-business" });
    expect(config.deviceSnDb).toEqual({ port: 3306 });
    expect(loadConfig({ DEVICE_SN_DB_HOST: " devices ", DEVICE_SN_DB_PORT: "3307", DEVICE_SN_DB_NAME: " equipment ", DEVICE_SN_DB_USER: " serial_reader ", DEVICE_SN_DB_PASSWORD: "private" }).deviceSnDb)
      .toEqual({ host: "devices", port: 3307, name: "equipment", user: "serial_reader", password: "private" });
  });
});
