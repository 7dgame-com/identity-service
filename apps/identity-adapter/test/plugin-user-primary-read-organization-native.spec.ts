import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PluginUserPrimaryReadService } from "../src/plugin-user-primary-read.service.js";
import type { LegacyOrganization, LegacyUserReadModel } from "../src/legacy-identity.reader.js";

const originalEnv = { ...process.env };

describe("plugin-user Identity-native organization read ownership", () => {
  beforeEach(() => {
    process.env = { ...originalEnv };
    process.env.IDENTITY_IAM_PLUGIN_USER_WRITE_MODE = "legacy-proxy";
    process.env.IDENTITY_IAM_ROLE_WRITE_MODE = "disabled";
    process.env.IDENTITY_IAM_ORG_WRITE_MODE = "identity-native";
    process.env.IDENTITY_IAM_ORG_WRITE_ROUTE_INTEGRATION_ENABLED = "true";
    process.env.IDENTITY_IAM_ORG_WRITE_IDENTITY_NATIVE_EXECUTION_ENABLED = "true";
    process.env.IDENTITY_IAM_ORG_WRITE_ROLLOUT_MODE = "allowlist";
    process.env.IDENTITY_IAM_ORG_WRITE_ROLLOUT_ALLOWLIST = "legacy:24";
    process.env.IDENTITY_PLUGIN_USER_PRIMARY_READ_ENABLED = "false";
  });

  afterEach(() => {
    process.env = { ...originalEnv };
  });

  it("overlays the selected Identity candidate on the compatible Legacy user response", async () => {
    const fixture = createFixture();
    const result = await fixture.service.getUserById(24, claims());

    expect(result).toMatchObject({
      source: "legacy",
      data: {
        id: 24,
        organizations: [{ id: 2, name: "candidate", title: "Candidate" }]
      }
    });
    expect(fixture.organizationRepository.candidateForLegacyUser).toHaveBeenCalledWith(24);
  });

  it("keeps unowned targets on their existing Legacy organization response", async () => {
    const fixture = createFixture();
    const result = await fixture.service.getUserById(25, claims());

    expect(result.data?.organizations).toEqual([organization(1, "legacy", "Legacy")]);
    expect(fixture.organizationRepository.candidateForLegacyUser).not.toHaveBeenCalled();
  });

  it("keeps an owned protected root on its read-only Legacy organizations without requiring a candidate", async () => {
    const fixture = createFixture({
      candidateMissing: true,
      username: "root",
      roles: ["root"]
    });

    const result = await fixture.service.getUserById(24, claims());

    expect(result.data?.organizations).toEqual([organization(1, "legacy", "Legacy")]);
    expect(result.data?.roles).toEqual(["root"]);
    expect(fixture.organizationRepository.candidateForLegacyUser).not.toHaveBeenCalled();
  });

  it("keeps the compatible user list available when it contains a protected root without a candidate", async () => {
    const fixture = createFixture({
      candidateMissing: true,
      username: "root",
      roles: ["root"]
    });

    const result = await fixture.service.listUsers({
      page: 1,
      pageSize: 20,
      order: "desc"
    }, claims());

    expect(result.data.users).toHaveLength(1);
    expect(result.data.users[0]?.organizations).toEqual([organization(1, "legacy", "Legacy")]);
    expect(fixture.organizationRepository.candidateForLegacyUser).not.toHaveBeenCalled();
  });

  it("fails closed for an owned target when its Identity candidate is missing", async () => {
    const fixture = createFixture({ candidateMissing: true });

    await expect(fixture.service.getUserById(24, claims()))
      .rejects.toThrow("identity_native_organization_candidate_missing");
  });
});

function createFixture(input: {
  candidateMissing?: boolean;
  username?: string;
  roles?: string[];
} = {}) {
  const managedUser = (id: number): LegacyUserReadModel => ({
    id,
    username: input.username ?? `user-${id}`,
    email: null,
    status: 10,
    nickname: null,
    emailVerifiedAt: null,
    createdAt: 1,
    updatedAt: 2,
    userInfo: {},
    roles: input.roles ?? ["user"],
    organizations: [organization(1, "legacy", "Legacy")],
    source: "legacy"
  });
  const legacyReader = {
    getUserById: vi.fn(async (id: number): Promise<LegacyUserReadModel> => managedUser(id)),
    listManagedUsers: vi.fn(async (request: { page: number; pageSize: number }) => ({
      users: [managedUser(24)],
      page: request.page,
      pageSize: request.pageSize,
      total: 1,
      totalPages: 1
    }))
  };
  const iamRepository = {
    listRoleAssignmentsShadow: vi.fn(async () => (input.roles ?? ["user"]).map((roleName) => ({ roleName })))
  };
  const organizationRepository = {
    isConfigured: vi.fn(() => true),
    candidateForLegacyUser: vi.fn(async () => input.candidateMissing
      ? null
      : { legacyUserId: 24, organizations: [organization(2, "candidate", "Candidate")] })
  };
  return {
    service: new PluginUserPrimaryReadService(
      iamRepository as never,
      legacyReader as never,
      organizationRepository as never
    ),
    organizationRepository
  };
}

function claims() {
  return { uid: 9, username: "root", sessionId: "session", roles: ["root"] };
}

function organization(id: number, name: string, title: string): LegacyOrganization {
  return { id, name, title, createdAt: 1, updatedAt: 2 };
}
