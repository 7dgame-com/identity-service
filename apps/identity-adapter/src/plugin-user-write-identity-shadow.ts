import { IdentityUserShadowInput } from "./iam.repository.js";
import { PluginUserWriteRoute, redactPluginUserWriteEvidence } from "./plugin-user-write-operation.repository.js";

export interface PluginUserWriteIdentityShadowInput {
  route: PluginUserWriteRoute;
  requestBody: unknown;
  legacyStatus: number;
  legacyBody: unknown;
}

export interface PluginUserWriteIdentityShadowPlan {
  writes: IdentityUserShadowInput[];
  skippedReason?: string;
}

export function planPluginUserIdentityShadow(input: PluginUserWriteIdentityShadowInput): PluginUserWriteIdentityShadowPlan {
  if (input.route === "change-role") {
    return { writes: [], skippedReason: "role-permission-owner-retained" };
  }

  const records =
    input.route === "batch-create-users"
      ? batchCreateRecords(recordValue(input.requestBody), recordValue(input.legacyBody))
      : [singleUserRecord(input.route, recordValue(input.requestBody), recordValue(input.legacyBody))];
  const writes = records
    .map((record) => identityShadowInputFromRecord(input.route, input.legacyStatus, record))
    .filter((record): record is IdentityUserShadowInput => record !== null);

  return {
    writes,
    skippedReason: writes.length === 0 ? "legacy-user-id-missing" : undefined
  };
}

function identityShadowInputFromRecord(
  route: PluginUserWriteRoute,
  legacyStatus: number,
  record: Record<string, unknown>
): IdentityUserShadowInput | null {
  const legacyUserId = numericField(record, ["id", "user_id", "userId", "legacy_user_id", "legacyUserId"]);
  if (!legacyUserId) {
    return null;
  }

  return {
    identityUserId: identityUserIdForLegacy(legacyUserId),
    legacyUserId,
    username: stringField(record, ["username", "name", "account"]),
    email: stringField(record, ["email"]),
    status: statusForRoute(route, record),
    metadata: {
      source: "plugin-user-dual-write",
      route,
      legacyStatus,
      evidence: redactPluginUserWriteEvidence(record)
    }
  };
}

function singleUserRecord(
  route: PluginUserWriteRoute,
  requestBody: Record<string, unknown>,
  legacyBody: Record<string, unknown>
): Record<string, unknown> {
  const legacyData = recordValue(legacyBody.data);
  if (Object.keys(legacyData).length > 0) {
    return { ...requestBody, ...legacyData };
  }

  return {
    ...requestBody,
    status: route === "delete-user" ? "inactive" : requestBody.status
  };
}

function batchCreateRecords(requestBody: Record<string, unknown>, legacyBody: Record<string, unknown>): Record<string, unknown>[] {
  const requestUsers = arrayValue(requestBody.users).map(recordValue);
  const legacyData = recordValue(legacyBody.data);
  const legacyUsers = arrayValue(legacyData.users ?? legacyData.items ?? legacyData.list).map(recordValue);
  const maxLength = Math.max(requestUsers.length, legacyUsers.length);
  const records: Record<string, unknown>[] = [];
  for (let index = 0; index < maxLength; index += 1) {
    records.push({
      ...(requestUsers[index] ?? {}),
      ...(legacyUsers[index] ?? {})
    });
  }

  return records;
}

function statusForRoute(route: PluginUserWriteRoute, record: Record<string, unknown>): string {
  if (route === "delete-user") {
    return "inactive";
  }

  const status = record.status;
  if (typeof status === "string" && status.trim() !== "") {
    return status.trim();
  }

  if (Number(status) === 0) {
    return "inactive";
  }

  return "active";
}

function identityUserIdForLegacy(legacyUserId: number): string {
  return `legacy:${legacyUserId}`;
}

function recordValue(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

function arrayValue(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function numericField(record: Record<string, unknown>, keys: string[]): number | null {
  for (const key of keys) {
    const numeric = Number(record[key]);
    if (Number.isInteger(numeric) && numeric > 0) {
      return numeric;
    }
  }

  return null;
}

function stringField(record: Record<string, unknown>, keys: string[]): string | null {
  for (const key of keys) {
    const value = record[key];
    if (typeof value === "string" && value.trim() !== "") {
      return value.trim();
    }
  }

  return null;
}
