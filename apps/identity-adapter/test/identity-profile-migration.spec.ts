import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { ProfileMigrationError, profileArchiveColumns, profileArchiveTable, profileGroupSha256, projectLegacyProfiles, type ProfileSelectionManifest } from "../src/identity-profile-migration.js";

const rows = () => Array.from({ length: 7 }, (_, i) => ({
  id: i + 10, user_id: 3, info: i % 2 ? { private: "B" } : { private: "A" },
  avatar_id: i % 3 === 0 ? null : 100 + i % 3, gold: 100, points: 200,
}));
const manifest = (source: Record<string, unknown>[], profileId = 12): ProfileSelectionManifest => ({
  version: 1, selections: [{ userId: 3, profileId, sourceRowsSha256: profileGroupSha256(source, true) }],
});
function errorCode(run: () => unknown): string {
  try { run(); } catch (error) {
    expect(error).toBeInstanceOf(ProfileMigrationError);
    return (error as ProfileMigrationError).code;
  }
  throw new Error("Expected profile migration rejection.");
}

describe("legacy profile migration projection", () => {
  it("archives seven variants while selecting one canonical row and its own avatar", () => {
    const source = rows();
    const result = projectLegacyProfiles(source, { hasAvatarColumn: true, manifest: manifest(source) });
    expect(profileArchiveTable).toBe("identity_legacy_profile_rows");
    expect(profileArchiveColumns).toEqual(["id", "user_id", "payload_json", "selected_profile_id"]);
    expect(result.canonicalRows).toEqual([{ id: 12, user_id: 3, info: { private: "A" } }]);
    expect(result.archiveRows).toHaveLength(7);
    expect(result.archiveRows.every((row) => row.selected_profile_id === 12)).toBe(true);
    expect(result.archiveRows[0].payload_json).toEqual({ id: 10, user_id: 3, info: { private: "A" }, avatar_id: null });
    expect(result.avatarRows).toEqual([{ user_id: 3, avatar_id: 102 }]);
    expect(result.report).toMatchObject({ sourceRows: 7, owners: 1, duplicateGroups: 1, archivedRows: 7 });
  });

  it("automatically selects singletons, permits absent profiles and respects an absent avatar column", () => {
    const result = projectLegacyProfiles([{ id: "8", user_id: "2", info: null, avatar_id: 99 }], { hasAvatarColumn: false });
    expect(result.canonicalRows).toEqual([{ id: 8, user_id: 2, info: null }]);
    expect(result.archiveRows[0].payload_json.avatar_id).toBeNull();
    expect(result.avatarRows).toEqual([]);
    expect(projectLegacyProfiles([], { hasAvatarColumn: false }).report.owners).toBe(0);
  });

  it("refuses first-time duplicates with only counts and digests in the error", () => {
    const source = rows();
    try { projectLegacyProfiles(source, { hasAvatarColumn: true }); } catch (error) {
      expect(error).toBeInstanceOf(ProfileMigrationError);
      expect((error as ProfileMigrationError).code).toBe("PROFILE_SELECTION_REQUIRED");
      expect((error as ProfileMigrationError).details.groups).toEqual([{ rows: 7, sourceRowsSha256: profileGroupSha256(source, true) }]);
      expect(JSON.stringify(error)).not.toMatch(/private|avatar|userId|profileId/);
      return;
    }
    throw new Error("Expected duplicate rejection.");
  });

  it("keeps the pinned choice when unselected content or group membership changes", () => {
    const source = rows();
    const previous = projectLegacyProfiles(source, { hasAvatarColumn: true, manifest: manifest(source) }).archiveRows;
    const changed = source.map((row) => row.id === 10 ? { ...row, info: { private: "changed" }, avatar_id: 999 } : row);
    changed.push({ id: 999, user_id: 3, info: { private: "new" }, avatar_id: 333, gold: 0, points: 0 });
    const result = projectLegacyProfiles(changed, { hasAvatarColumn: true, previousArchiveRows: previous });
    expect(result.canonicalRows[0].id).toBe(12);
    expect(result.avatarRows).toEqual([{ user_id: 3, avatar_id: 102 }]);
    expect(result.archiveRows).toHaveLength(8);
  });

  it("refuses a new duplicate group without a prior pinned selection", () => {
    expect(errorCode(() => projectLegacyProfiles(rows(), { hasAvatarColumn: true, previousArchiveRows: [] }))).toBe("PROFILE_SELECTION_REQUIRED");
  });

  it("does not replace a deleted canonical row, even when one survivor remains", () => {
    const source = rows();
    const previous = projectLegacyProfiles(source, { hasAvatarColumn: true, manifest: manifest(source) }).archiveRows;
    expect(errorCode(() => projectLegacyProfiles(source.filter((row) => row.id !== 12), { hasAvatarColumn: true, previousArchiveRows: previous }))).toBe("PROFILE_SELECTED_ROW_MISSING");
    expect(errorCode(() => projectLegacyProfiles([source[0]], { hasAvatarColumn: true, previousArchiveRows: previous }))).toBe("PROFILE_SELECTED_ROW_MISSING");
    expect(projectLegacyProfiles([], { hasAvatarColumn: true, previousArchiveRows: previous }).canonicalRows).toEqual([]);
  });

  it("allows an explicit reviewed switch and never fills a NULL avatar from another row", () => {
    const source = rows();
    const previous = projectLegacyProfiles(source, { hasAvatarColumn: true, manifest: manifest(source) }).archiveRows;
    const result = projectLegacyProfiles(source, { hasAvatarColumn: true, previousArchiveRows: previous, manifest: manifest(source, 10) });
    expect(result.canonicalRows[0].id).toBe(10);
    expect(result.avatarRows).toEqual([]);
    const survivors = source.filter((row) => row.id !== 12);
    expect(projectLegacyProfiles(survivors, { hasAvatarColumn: true, previousArchiveRows: previous, manifest: manifest(survivors, 10) }).canonicalRows[0].id).toBe(10);
  });

  it("rejects changed digests, duplicate manifest entries, extra groups and nonexistent choices", () => {
    const source = rows();
    const changed = source.map((row) => row.id === 10 ? { ...row, avatar_id: 1 } : row);
    expect(errorCode(() => projectLegacyProfiles(changed, { hasAvatarColumn: true, manifest: manifest(source) }))).toBe("PROFILE_MANIFEST_SOURCE_CHANGED");
    const duplicate = manifest(source); duplicate.selections.push({ ...duplicate.selections[0] });
    const extra = manifest(source); extra.selections.push({ userId: 999, profileId: 10, sourceRowsSha256: "0".repeat(64) });
    for (const invalid of [duplicate, extra, manifest(source, 999)])
      expect(errorCode(() => projectLegacyProfiles(source, { hasAvatarColumn: true, manifest: invalid }))).toBe("INVALID_PROFILE_MANIFEST");
  });

  it("hashes sorted decimal IDs and recursively sorted JSON independently of row and key order", () => {
    const first = [{ id: 10, user_id: 3, info: '{"z":1,"a":{"b":2,"a":1}}', avatar_id: null }, { id: 2, user_id: 3, info: [{ z: 1, a: 2 }], avatar_id: 7 }];
    const second = [{ id: "2", user_id: "3", info: [{ a: 2, z: 1 }], avatar_id: "7" }, { id: "10", user_id: "3", info: { a: { a: 1, b: 2 }, z: 1 }, avatar_id: null }];
    const expected = [{ id: "2", user_id: "3", info: [{ a: 2, z: 1 }], avatar_id: "7" }, { id: "10", user_id: "3", info: { a: { a: 1, b: 2 }, z: 1 }, avatar_id: null }];
    expect(profileGroupSha256(first, true)).toBe(profileGroupSha256(second, true));
    expect(profileGroupSha256(first, true)).toBe(createHash("sha256").update(JSON.stringify(expected)).digest("hex"));
  });

  it("rejects invalid IDs, repeated source IDs and inconsistent previous selections", () => {
    for (const invalidId of [0, -1, Number.MAX_SAFE_INTEGER + 1, "1e2", null])
      expect(errorCode(() => projectLegacyProfiles([{ id: invalidId, user_id: 3 }], { hasAvatarColumn: false }))).toBe("INVALID_PROFILE_SOURCE");
    expect(errorCode(() => projectLegacyProfiles([{ id: 1, user_id: 3 }, { id: "1", user_id: 4 }], { hasAvatarColumn: false }))).toBe("INVALID_PROFILE_SOURCE");
    expect(errorCode(() => projectLegacyProfiles(rows(), { hasAvatarColumn: true, previousArchiveRows: [{ id: 10, user_id: 3, selected_profile_id: 10 }, { id: 11, user_id: 3, selected_profile_id: 11 }] }))).toBe("INVALID_PROFILE_ARCHIVE");
  });

  it("retains an absent historical row selection when its ID returns and rejects owner reuse", () => {
    const previous = [{ id: 10, user_id: 3, selected_profile_id: 10, is_present: 0 }];
    expect(projectLegacyProfiles(rows(), { hasAvatarColumn: true, previousArchiveRows: previous }).canonicalRows[0].id).toBe(10);
    expect(errorCode(() => projectLegacyProfiles([{ id: 10, user_id: 4 }], { hasAvatarColumn: false, previousArchiveRows: previous }))).toBe("PROFILE_SOURCE_OWNER_CHANGED");
  });
});
