import { createHash } from "node:crypto";

export const profileArchiveTable = "identity_legacy_profile_rows";
export const profileArchiveColumns = ["id", "user_id", "payload_json", "selected_profile_id"] as const;

export type ProfileSelectionManifest = {
  version: 1;
  selections: Array<{ userId: number; profileId: number; sourceRowsSha256: string }>;
};
type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
type SourceRow = Record<string, unknown>;
export interface ProfilePayload {
  id: number;
  user_id: number;
  info: Json;
  avatar_id: number | null;
}
export interface ProfileProjection {
  canonicalRows: Array<{ id: number; user_id: number; info: Json }>;
  archiveRows: Array<{ id: number; user_id: number; payload_json: ProfilePayload; selected_profile_id: number }>;
  avatarRows: Array<{ user_id: number; avatar_id: number }>;
  report: {
    sourceRows: number;
    owners: number;
    duplicateGroups: number;
    archivedRows: number;
    selections: Array<{ userId: number; profileId: number; sourceRowsSha256: string }>;
  };
}
interface SafeDetails {
  sourceRows: number;
  owners: number;
  duplicateGroups: number;
  groups?: Array<{ rows: number; sourceRowsSha256: string }>;
}

/** Error metadata deliberately excludes profile contents, avatar IDs and user IDs. */
export class ProfileMigrationError extends Error {
  code: string;
  details: SafeDetails;
  constructor(code: string, message: string, details?: SafeDetails) {
    super(message);
    this.name = "ProfileMigrationError";
    this.code = code;
    this.details = details ?? { sourceRows: 0, owners: 0, duplicateGroups: 0 };
  }
}

function fail(code: string, message: string, details?: SafeDetails): never {
  throw new ProfileMigrationError(code, message, details);
}
function id(value: unknown): number {
  if (!/^[0-9]+$/.test(String(value)) || !Number.isSafeInteger(Number(value)) || Number(value) < 1)
    fail("INVALID_PROFILE_SOURCE", "Profile migration requires positive safe integer IDs.");
  return Number(value);
}
function sortedJson(value: unknown, ancestors = new Set<object>()): Json {
  if (value === null || value === undefined) return null;
  if (typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value !== "object" || value instanceof Date || Buffer.isBuffer(value) || ancestors.has(value))
    fail("INVALID_PROFILE_SOURCE", "Profile information must contain finite JSON values.");
  ancestors.add(value);
  let result: Json;
  if (Array.isArray(value)) result = value.map((item) => sortedJson(item, ancestors));
  else {
    const object: { [key: string]: Json } = {};
    for (const key of Object.keys(value).sort())
      Object.defineProperty(object, key, { value: sortedJson((value as SourceRow)[key], ancestors), enumerable: true });
    result = object;
  }
  ancestors.delete(value);
  return result;
}
function info(value: unknown): Json {
  if (typeof value === "string") {
    try { value = JSON.parse(value); } catch { /* Preserve an already decoded JSON string. */ }
  }
  return sortedJson(value);
}
function payload(row: SourceRow, hasAvatarColumn: boolean): ProfilePayload {
  if (!row || typeof row !== "object" || Array.isArray(row))
    fail("INVALID_PROFILE_SOURCE", "A profile source row must be an object.");
  return {
    id: id(row.id),
    user_id: id(row.user_id),
    info: info(row.info),
    avatar_id: hasAvatarColumn && row.avatar_id != null ? id(row.avatar_id) : null,
  };
}
function digest(rows: ProfilePayload[]): string {
  return createHash("sha256").update(JSON.stringify([...rows].sort((a, b) => a.id - b.id).map((row) => ({
    id: String(row.id), user_id: String(row.user_id), info: row.info,
    avatar_id: row.avatar_id === null ? null : String(row.avatar_id),
  })))).digest("hex");
}

/** Numeric ID order; decimal string IDs; recursively key-sorted info; UTF-8 JSON SHA-256. */
export function profileGroupSha256(rows: SourceRow[], hasAvatarColumn: boolean): string {
  const normalized = normalizeRows(rows, hasAvatarColumn);
  if (!normalized.length || new Set(normalized.map((row) => row.user_id)).size !== 1)
    fail("INVALID_PROFILE_SOURCE", "A profile digest requires one nonempty owner group.");
  return digest(normalized);
}
function normalizeRows(rows: SourceRow[], hasAvatarColumn: boolean): ProfilePayload[] {
  if (!Array.isArray(rows) || typeof hasAvatarColumn !== "boolean")
    fail("INVALID_PROFILE_SOURCE", "Profile migration requires source rows and an explicit avatar schema flag.");
  const normalized = rows.map((row) => payload(row, hasAvatarColumn)).sort((a, b) => a.id - b.id);
  if (new Set(normalized.map((row) => row.id)).size !== normalized.length)
    fail("INVALID_PROFILE_SOURCE", "Profile source primary keys must be unique.");
  return normalized;
}

/** Pure projection. Source history persistence and the staging transaction belong to the caller. */
export function projectLegacyProfiles(rows: SourceRow[], options: {
  manifest?: ProfileSelectionManifest;
  previousArchiveRows?: SourceRow[];
  hasAvatarColumn: boolean;
}): ProfileProjection {
  const normalized = normalizeRows(rows, options.hasAvatarColumn);
  const groups = new Map<number, ProfilePayload[]>();
  for (const row of normalized) {
    const group = groups.get(row.user_id) ?? [];
    group.push(row);
    groups.set(row.user_id, group);
  }
  const details: SafeDetails = {
    sourceRows: normalized.length, owners: groups.size,
    duplicateGroups: [...groups.values()].filter((group) => group.length > 1).length,
  };
  const previous = new Map<number, number>();
  const previousIds = new Set<number>();
  const sourceOwners = new Map(normalized.map((row) => [row.id, row.user_id]));
  for (const row of options.previousArchiveRows ?? []) {
    const owner = id(row.user_id), selected = id(row.selected_profile_id), sourceId = id(row.id);
    if (previousIds.has(sourceId) || (previous.has(owner) && previous.get(owner) !== selected))
      fail("INVALID_PROFILE_ARCHIVE", "Stored profile selections are inconsistent.", details);
    previousIds.add(sourceId);
    previous.set(owner, selected);
    if (sourceOwners.has(sourceId) && sourceOwners.get(sourceId) !== owner)
      fail("PROFILE_SOURCE_OWNER_CHANGED", "A source profile primary key changed owners.", details);
  }

  const explicit = new Map<number, number>();
  const manifest = options.manifest;
  if (manifest !== undefined) {
    if (!manifest || manifest.version !== 1 || !Array.isArray(manifest.selections)
      || Object.keys(manifest).some((key) => !["version", "selections"].includes(key)))
      fail("INVALID_PROFILE_MANIFEST", "Invalid profile selection manifest.", details);
    for (const selection of manifest.selections) {
      if (!selection || typeof selection !== "object"
        || Object.keys(selection).some((key) => !["userId", "profileId", "sourceRowsSha256"].includes(key))
        || !Number.isSafeInteger(selection.userId) || selection.userId < 1
        || !Number.isSafeInteger(selection.profileId) || selection.profileId < 1
        || typeof selection.sourceRowsSha256 !== "string" || !/^[a-f0-9]{64}$/.test(selection.sourceRowsSha256))
        fail("INVALID_PROFILE_MANIFEST", "Invalid profile selection manifest entry.", details);
      const group = groups.get(selection.userId);
      if (explicit.has(selection.userId) || !group || !group.some((row) => row.id === selection.profileId))
        fail("INVALID_PROFILE_MANIFEST", "Profile selections must reference distinct existing owner groups and rows.", details);
      if (selection.sourceRowsSha256 !== digest(group))
        fail("PROFILE_MANIFEST_SOURCE_CHANGED", "Reviewed profile source digest no longer matches.", details);
      explicit.set(selection.userId, selection.profileId);
    }
  }

  const missing = [...groups].filter(([owner, group]) => group.length > 1 && !explicit.has(owner) && !previous.has(owner));
  if (missing.length)
    fail("PROFILE_SELECTION_REQUIRED", "Ambiguous profiles require a reviewed selection manifest.", {
      ...details, groups: missing.map(([, group]) => ({ rows: group.length, sourceRowsSha256: digest(group) })),
    });
  for (const [owner, selected] of previous) {
    if (groups.has(owner) && !explicit.has(owner) && !groups.get(owner)!.some((row) => row.id === selected))
      fail("PROFILE_SELECTED_ROW_MISSING", "A previously selected profile disappeared; explicit reselection is required.", details);
  }

  const result: ProfileProjection = {
    canonicalRows: [], archiveRows: [], avatarRows: [],
    report: { ...details, archivedRows: normalized.length, selections: [] },
  };
  for (const [owner, group] of [...groups].sort(([a], [b]) => a - b)) {
    const selected = explicit.get(owner) ?? previous.get(owner) ?? group[0].id;
    const chosen = group.find((row) => row.id === selected)!;
    result.canonicalRows.push({ id: chosen.id, user_id: owner, info: chosen.info });
    if (chosen.avatar_id !== null) result.avatarRows.push({ user_id: owner, avatar_id: chosen.avatar_id });
    for (const row of group)
      result.archiveRows.push({ id: row.id, user_id: owner, payload_json: row, selected_profile_id: selected });
    result.report.selections.push({ userId: owner, profileId: selected, sourceRowsSha256: digest(group) });
  }
  result.archiveRows.sort((a, b) => a.id - b.id);
  return result;
}
