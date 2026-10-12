import "reflect-metadata";
import { beforeEach, afterEach, describe, expect, it, vi } from "vitest";
import { PluginUserReadonlyController } from "../src/plugin-user-readonly.controller.js";
import { LegacyIdentityReader, type LegacyAuditMember } from "../src/legacy-identity.reader.js";
import { JwtIssuerService } from "../src/jwt-issuer.service.js";
import { IamRepository } from "../src/iam.repository.js";
import { LoginAuditService } from "../src/login-audit.service.js";
import { PluginUserPrimaryReadService } from "../src/plugin-user-primary-read.service.js";
import { auditPrimaryRole, parseOrganizationLoginQuery } from "../src/organization-login-events.js";

const baseQuery = { organization_id: "7", start_at: "2026-09-25T00:00:00+08:00", end_at: "2026-09-27T00:00:00+08:00" };
const member = (id: number, roles = ["user"]): LegacyAuditMember => ({
  id, username: `account${id}`, nickname: id === 2 ? "张同学" : "老师",
  roles, organizations: [{ id: 7, name: "school", title: "学校", createdAt: null, updatedAt: null }]
});

describe("organization login events authorization and filters", () => {
  let controller: PluginUserReadonlyController;
  let claims: { uid: number; roles: string[] };
  let users: LegacyAuditMember[];
  let reader: any;
  let iam: any;
  let audit: any;
  beforeEach(() => {
    vi.stubEnv("IDENTITY_PLUGIN_USER_READONLY_ENABLED", "true");
    vi.stubEnv("IDENTITY_LOGIN_AUDIT_ENABLED", "true");
    claims = { uid: 1, roles: ["manager"] };
    users = [member(1, ["user", "manager"]), member(2), member(3, ["admin", "user"]), member(4, ["custom"])];
    reader = {
      getUserById: vi.fn(async (id: number) => users.find((user) => user.id === id) ?? null),
      listOrganizationAuditMembers: vi.fn(async () => users),
    };
    iam = {
      isConfigured: () => true,
      listOrganizationMembershipsShadow: vi.fn(async (id: number) => [{ legacyUserId: id, organizationId: 7 }]),
      listOrganizationMembershipsShadowForUsers: vi.fn(async (ids: number[]) => ids.map((id) => ({ legacyUserId: id, organizationId: 7 }))),
    };
    audit = { listOrganizationEvents: vi.fn(async () => ({ events: [{ userId: 2, eventKey: "test-login", source: "identity-adapter", occurredAt: "2026-09-25T01:00:00Z" }], total: 21 })) };
    controller = new PluginUserReadonlyController(
      reader as LegacyIdentityReader,
      { verifyAccessToken: () => claims } as unknown as JwtIssuerService,
      { withAuditMemberRoles: async (value: LegacyAuditMember[]) => value } as unknown as PluginUserPrimaryReadService,
      audit as LoginAuditService, iam as IamRepository
    );
  });
  afterEach(() => vi.unstubAllEnvs());

  it.each(["root", "admin", "manager"])("allows %s and returns a paginated, scoped list", async (role) => {
    claims.roles = [role];
    const response = await controller.organizationLoginEvents("Bearer test", baseQuery);
    expect(response).toMatchObject({ code: 0, data: [{ userId: 2, nickname: "张同学", primaryRole: "user" }], pagination: { total: 21, page: 1, pageSize: 20, totalPages: 2 } });
    expect(audit.listOrganizationEvents).toHaveBeenCalledWith({ userIds: [1, 2, 3, 4], startAt: new Date(baseQuery.start_at), endAt: new Date(baseQuery.end_at), page: 1, pageSize: 20 });
    expect(iam.listOrganizationMembershipsShadowForUsers).toHaveBeenCalledTimes(1);
  });

  it.each(["user", "guest"])("denies %s before reading members or totals", async (role) => {
    claims.roles = [role];
    await expect(controller.organizationLoginEvents("Bearer test", baseQuery)).rejects.toMatchObject({ status: 403 });
    expect(reader.listOrganizationAuditMembers).not.toHaveBeenCalled();
    expect(audit.listOrganizationEvents).not.toHaveBeenCalled();
  });

  it("denies unauthenticated access", async () => {
    await expect(controller.organizationLoginEvents(undefined, baseQuery)).rejects.toMatchObject({ status: 401 });
  });

  it.each(["root", "admin"])("requires organization scope even for %s", async (role) => {
    claims.roles = [role];
    await expect(controller.organizationLoginEvents("Bearer test", { ...baseQuery, organization_id: undefined })).rejects.toMatchObject({ status: 403 });
  });

  it.each(["0", "-1", "1.5", "abc", ["7"], { id: 7 }])("rejects malformed organization %j", async (organization_id) => {
    await expect(controller.organizationLoginEvents("Bearer test", { ...baseQuery, organization_id })).rejects.toMatchObject({ status: 400 });
    expect(audit.listOrganizationEvents).not.toHaveBeenCalled();
  });

  it("denies cross-organization readers without returning a count", async () => {
    users[0].organizations[0].id = 9;
    await expect(controller.organizationLoginEvents("Bearer test", baseQuery)).rejects.toMatchObject({ status: 403 });
    expect(audit.listOrganizationEvents).not.toHaveBeenCalled();
  });

  it.each(["actor", "target", "unavailable"])("fails closed on %s membership inconsistency", async (kind) => {
    if (kind === "actor") iam.listOrganizationMembershipsShadow.mockResolvedValue([]);
    if (kind === "target") iam.listOrganizationMembershipsShadowForUsers.mockResolvedValue([]);
    if (kind === "unavailable") reader.listOrganizationAuditMembers.mockRejectedValue(new Error("database unavailable"));
    await expect(controller.organizationLoginEvents("Bearer test", baseQuery)).rejects.toMatchObject({ status: 403 });
    expect(audit.listOrganizationEvents).not.toHaveBeenCalled();
  });

  it("excludes removed members and filters by current nickname and highest role before querying", async () => {
    users = users.filter((user) => user.id !== 3);
    await controller.organizationLoginEvents("Bearer test", { ...baseQuery, search: " 张同学 ", role: "user", page: "2", pageSize: "10" });
    expect(audit.listOrganizationEvents).toHaveBeenLastCalledWith(expect.objectContaining({ userIds: [2], page: 2, pageSize: 10 }));
  });

  it("returns an empty list for no matching current members", async () => {
    audit.listOrganizationEvents.mockResolvedValue({ events: [], total: 0 });
    const response = await controller.organizationLoginEvents("Bearer test", { ...baseQuery, search: "absent" });
    expect(response.data).toEqual([]);
    expect(response.pagination.total).toBe(0);
    expect(audit.listOrganizationEvents).toHaveBeenCalledWith(expect.objectContaining({ userIds: [] }));
  });
});

describe("login event query validation", () => {
  it.each([
    { start_at: "2026-02-30T00:00:00Z" }, { end_at: "2020-01-01T00:00:00Z" },
    { start_at: "2026-09-25" }, { start_at: [baseQuery.start_at] }, { end_at: baseQuery.start_at },
    { page: "0" }, { page: "1.2" }, { pageSize: "101" }, { pageSize: ["20"] },
    { role: "invalid" }, { search: ["alice"] }, { page: "9007199254740991", pageSize: "100" },
  ])("rejects %j", (change) => {
    expect(() => parseOrganizationLoginQuery({ ...baseQuery, ...change })).toThrow();
  });
  it("chooses the highest current role", () => {
    expect(auditPrimaryRole(["user", "admin", "manager"])).toBe("admin");
    expect(auditPrimaryRole(["custom"])).toBe("other");
    expect(auditPrimaryRole(["manager", "root"])).toBe("root");
  });
});

describe("current role labels during identity-native migration", () => {
  beforeEach(() => {
    vi.stubEnv("IDENTITY_IAM_ROLE_WRITE_MODE", "identity-native");
    vi.stubEnv("IDENTITY_IAM_ROLE_WRITE_IDENTITY_NATIVE_EXECUTION_ENABLED", "true");
    vi.stubEnv("IDENTITY_IAM_ROLE_WRITE_IDENTITY_NATIVE_TARGET_MODE", "single-target");
    vi.stubEnv("IDENTITY_IAM_ROLE_WRITE_IDENTITY_NATIVE_TARGET_LEGACY_USER_ID", "2");
    vi.stubEnv("IDENTITY_IAM_ROLE_WRITE_IDENTITY_NATIVE_TARGET_ALLOWLIST", "");
    vi.stubEnv("IDENTITY_IAM_ROLE_WRITE_POLICY_CHECKSUM", "a".repeat(64));
  });
  afterEach(() => vi.unstubAllEnvs());
  it("uses current native roles for owned accounts and preserves root/legacy roles", async () => {
    const repository = { isConfigured: () => true, listAuditNativeRoles: vi.fn(async () => new Map([[2, ["manager"]]])) };
    const service = new PluginUserPrimaryReadService(repository as unknown as IamRepository, {} as LegacyIdentityReader);
    const result = await service.withAuditMemberRoles([member(1, ["admin"]), member(2), member(3, ["root"])]);
    expect(result.map((user) => user.roles)).toEqual([["admin"], ["manager"], ["root"]]);
    expect(repository.listAuditNativeRoles).toHaveBeenCalledWith([2], "a".repeat(64));
  });
  it("fails closed on unavailable native roles", async () => {
    const service = new PluginUserPrimaryReadService({ isConfigured: () => true, listAuditNativeRoles: async () => new Map() } as unknown as IamRepository, {} as LegacyIdentityReader);
    await expect(service.withAuditMemberRoles([member(2)])).rejects.toMatchObject({ status: 503 });
  });
});
