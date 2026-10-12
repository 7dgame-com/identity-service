import { ProfileMigrationError } from "./identity-profile-migration.js";

const typeAlias = "__identity_profile_info_type";

/** mysql2 decodes JSON columns already; TEXT must never be guessed to be JSON. */
export function legacyProfileJsonTypeSelection(columns: readonly Record<string, unknown>[]): string {
  if (columns.find(column => column.Field === "info")?.Type !== "json")
    throw new ProfileMigrationError("PROFILE_INFO_ENCODING_UNSUPPORTED", "Profile migration requires an explicit JSON info column.");
  return `,JSON_TYPE(info) AS ${typeAlias}`;
}

/** Reject unsupported scalar encodings before projection, baseline hashing or writes. */
export function assertProfileJsonValues(rows: readonly Record<string, unknown>[], source = false): void {
  for (const row of rows) {
    const value = row.info;
    const jsonType = row[typeAlias];
    const validValue = value === null || (typeof value === "object" && value !== undefined
      && !Buffer.isBuffer(value) && !(value instanceof Date));
    const validSourceType = !source || (jsonType === null && value === null)
      || (jsonType === "OBJECT" && value !== null && typeof value === "object" && !Array.isArray(value))
      || (jsonType === "ARRAY" && Array.isArray(value));
    if (!validValue || !validSourceType)
      throw new ProfileMigrationError("PROFILE_INFO_SCALAR_UNSUPPORTED", "Profile JSON scalars require a separately reviewed encoding migration.");
  }
}
