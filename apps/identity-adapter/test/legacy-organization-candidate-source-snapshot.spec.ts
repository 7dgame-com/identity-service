import { describe, expect, it, vi } from "vitest";
import {
  LEGACY_ORGANIZATION_CANDIDATE_SOURCE_SNAPSHOT_CONTRACT,
  LegacyIdentityReader
} from "../src/legacy-identity.reader.js";

describe("Legacy organization candidate source snapshot", () => {
  it("reads users, roles and memberships on one repeatable-read connection and always rolls back", async () => {
    const fixture = snapshotFixture();

    const snapshot = await fixture.reader.readOrganizationCandidateSourceSnapshot();

    expect(snapshot).toEqual({
      contract: LEGACY_ORGANIZATION_CANDIDATE_SOURCE_SNAPSHOT_CONTRACT,
      users: [
        {
          id: 1,
          username: "ordinary",
          status: 10,
          roles: [],
          organizations: [{
            id: 9,
            name: "organization-9",
            title: "Organization 9",
            createdAt: 1,
            updatedAt: 2
          }]
        },
        { id: 2, username: "root", status: 10, roles: ["root"], organizations: [] }
      ]
    });
    expect(Object.isFrozen(snapshot)).toBe(true);
    expect(Object.isFrozen(snapshot.users)).toBe(true);
    expect(Object.isFrozen(snapshot.users[0]?.organizations[0])).toBe(true);
    expect(fixture.connection.query.mock.calls.map(([sql]) => compactSql(String(sql)))).toEqual([
      "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ",
      "START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY",
      "SELECT id, username, status FROM user ORDER BY id ASC LIMIT 5001",
      expect.stringContaining("FROM user u JOIN auth_assignment aa"),
      expect.stringContaining("FROM user u JOIN user_organization uo"),
      "ROLLBACK"
    ]);
    expect(fixture.connection.release).toHaveBeenCalledTimes(1);
    expect(fixture.connection.destroy).not.toHaveBeenCalled();
  });

  it("rejects an incomplete source relation and rolls back without publishing a snapshot", async () => {
    const fixture = snapshotFixture({
      roleRows: [{ legacyUserId: 999, role: "root" }]
    });

    await expect(fixture.reader.readOrganizationCandidateSourceSnapshot()).rejects.toThrow(
      "Legacy role assignment references an unknown subject."
    );
    expect(fixture.connection.query).toHaveBeenLastCalledWith("ROLLBACK");
    expect(fixture.connection.release).toHaveBeenCalledTimes(1);
  });

  it("destroys the session and fails closed when rollback cannot be proven", async () => {
    const fixture = snapshotFixture({ rollbackFails: true });

    await expect(fixture.reader.readOrganizationCandidateSourceSnapshot()).rejects.toThrow(
      "Legacy organization source snapshot rollback failed."
    );
    expect(fixture.connection.destroy).toHaveBeenCalledTimes(1);
    expect(fixture.connection.release).not.toHaveBeenCalled();
  });

  it("rejects empty and over-bound subject universes inside the same read-only transaction", async () => {
    const empty = snapshotFixture({ userRows: [] });
    await expect(empty.reader.readOrganizationCandidateSourceSnapshot()).rejects.toThrow(
      "Legacy organization source subject count is outside the reviewed bound."
    );
    expect(empty.connection.query).toHaveBeenLastCalledWith("ROLLBACK");

    const overBound = snapshotFixture({
      userRows: Array.from({ length: 5001 }, (_, index) => ({
        id: index + 1,
        username: `user-${index + 1}`,
        status: 10
      }))
    });
    await expect(overBound.reader.readOrganizationCandidateSourceSnapshot()).rejects.toThrow(
      "Legacy organization source subject count is outside the reviewed bound."
    );
    expect(overBound.connection.query).toHaveBeenLastCalledWith("ROLLBACK");
  });
});

function snapshotFixture(input: {
  userRows?: Array<Record<string, unknown>>;
  roleRows?: Array<Record<string, unknown>>;
  organizationRows?: Array<Record<string, unknown>>;
  rollbackFails?: boolean;
} = {}) {
  const userRows = input.userRows ?? [
    { id: 1, username: "ordinary", status: 10 },
    { id: 2, username: "root", status: 10 }
  ];
  const roleRows = input.roleRows ?? [{ legacyUserId: 2, role: "root" }];
  const organizationRows = input.organizationRows ?? [{
    legacyUserId: 1,
    id: 9,
    name: "organization-9",
    title: "Organization 9",
    createdAt: 1,
    updatedAt: 2
  }];
  const connection = {
    query: vi.fn(async (sql: string) => {
      const normalized = compactSql(sql);
      if (normalized === "ROLLBACK") {
        if (input.rollbackFails) throw new Error("driver rollback failure containing secret context");
        return [[], []];
      }
      if (normalized.startsWith("SELECT id, username, status FROM user")) return [userRows, []];
      if (normalized.includes("JOIN auth_assignment aa")) return [roleRows, []];
      if (normalized.includes("JOIN user_organization uo")) return [organizationRows, []];
      return [[], []];
    }),
    release: vi.fn(),
    destroy: vi.fn()
  };
  const pool = { getConnection: vi.fn(async () => connection) };
  const reader = Object.create(LegacyIdentityReader.prototype) as LegacyIdentityReader;
  Object.defineProperty(reader, "pool", { value: pool });
  return { reader, connection, pool };
}

function compactSql(sql: string): string {
  return sql.replace(/\s+/g, " ").trim();
}
