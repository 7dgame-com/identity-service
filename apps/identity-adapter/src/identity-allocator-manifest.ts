import { createHash } from "node:crypto";
export const allocatorTables = [
  "user",
  "user_info",
  "organization",
  "wechat",
  "invitation_record",
  "invitation",
] as const;
export type AllocatorTable = (typeof allocatorTables)[number];
export const allocatorLimit = BigInt(Number.MAX_SAFE_INTEGER);
export class AllocatorError extends Error {
  constructor(readonly code: string) {
    super(code);
  }
}
export function allocatorFail(code: string): never {
  throw new AllocatorError(code);
}
export function integer(value: unknown): bigint {
  if (typeof value !== "string" || !/^(?:0|[1-9][0-9]{0,15})$/.test(value))
    allocatorFail("ALLOCATOR_INVALID_INTEGER");
  const n = BigInt(value);
  if (n > BigInt(Number.MAX_SAFE_INTEGER))
    allocatorFail("ALLOCATOR_INTEGER_CAPACITY");
  return n;
}
export function canonical(value: unknown): string {
  if (typeof value === "number" && Number.isSafeInteger(value))
    return JSON.stringify(value);
  if (value === null || typeof value === "boolean" || typeof value === "string")
    return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  if (
    typeof value === "object" &&
    Object.getPrototypeOf(value) === Object.prototype
  )
    return (
      "{" +
      Object.keys(value as object)
        .sort()
        .map(
          (key) =>
            JSON.stringify(key) +
            ":" +
            canonical((value as Record<string, unknown>)[key]),
        )
        .join(",") +
      "}"
    );
  allocatorFail("ALLOCATOR_NONCANONICAL_VALUE");
}
export const allocatorDigest = (value: unknown) =>
  createHash("sha256").update(canonical(value)).digest("hex");
export interface Floor {
  floor: string;
  capacity: string;
  sourceNext: string | null;
  reservedMax: string;
}
export interface AllocatorManifest {
  version: 1;
  kind: "migrated" | "fresh";
  targetDatabase: string;
  capturedAt: string;
  source: null | {
    database: string;
    host: "10.206.0.5";
    port: "3306";
    serverUuid: string;
  };
  drain: null | {
    reviewSha256: string;
    writersDrainedAt: string;
    finalSyncSha256: string;
  };
  baseline: null | { importKey: string; referenceReviewSha256: string };
  floors: Record<AllocatorTable, Floor>;
}
const exact = (value: unknown, keys: string[]) =>
  value !== null &&
  typeof value === "object" &&
  !Array.isArray(value) &&
  Object.keys(value).sort().join(",") === keys.sort().join(",");
export function normalizeAllocatorManifest(value: unknown): AllocatorManifest {
  if (
    !exact(value, [
      "version",
      "kind",
      "targetDatabase",
      "capturedAt",
      "source",
      "drain",
      "baseline",
      "floors",
    ])
  )
    allocatorFail("ALLOCATOR_INVALID_MANIFEST");
  const m = value as AllocatorManifest;
  if (
    m.version !== 1 ||
    !["fresh", "migrated"].includes(m.kind) ||
    !/^[a-zA-Z0-9_]{1,64}$/.test(m.targetDatabase) ||
    typeof m.capturedAt !== "string" ||
    !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(m.capturedAt) ||
    !Number.isFinite(Date.parse(m.capturedAt)) ||
    new Date(m.capturedAt).toISOString() !== m.capturedAt
  )
    allocatorFail("ALLOCATOR_INVALID_MANIFEST");
  if (m.kind === "fresh") {
    if (m.source !== null || m.drain !== null || m.baseline !== null)
      allocatorFail("ALLOCATOR_INVALID_FRESH_PROOF");
  } else {
    if (
      !exact(m.source, ["database", "host", "port", "serverUuid"]) ||
      typeof m.source?.database !== "string" ||
      !/^[a-zA-Z0-9_]{1,64}$/.test(m.source.database) ||
      m.source.host !== "10.206.0.5" ||
      m.source.port !== "3306" ||
      !/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(
        m.source.serverUuid,
      )
    )
      allocatorFail("ALLOCATOR_INVALID_SOURCE_PROOF");
    if (
      !exact(m.drain, [
        "reviewSha256",
        "writersDrainedAt",
        "finalSyncSha256",
      ]) ||
      !/^[a-f0-9]{64}$/.test(m.drain?.reviewSha256 ?? "") ||
      !/^[a-f0-9]{64}$/.test(m.drain?.finalSyncSha256 ?? "") ||
      !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(
        m.drain?.writersDrainedAt ?? "",
      ) ||
      !Number.isFinite(Date.parse(m.drain?.writersDrainedAt ?? "")) ||
      new Date(m.drain!.writersDrainedAt).toISOString() !==
        m.drain!.writersDrainedAt ||
      Date.parse(m.drain!.writersDrainedAt) > Date.parse(m.capturedAt)
    )
      allocatorFail("ALLOCATOR_INVALID_DRAIN_PROOF");
  }
  if (
    m.kind === "migrated" &&
    (!exact(m.baseline, ["importKey", "referenceReviewSha256"]) ||
      typeof m.baseline?.importKey !== "string" ||
      !/^[A-Za-z0-9_.:-]{1,160}$/.test(m.baseline.importKey) ||
      !/^[a-f0-9]{64}$/.test(m.baseline.referenceReviewSha256))
  )
    allocatorFail("ALLOCATOR_BASELINE_MISMATCH");
  if (
    m.targetDatabase === "xrugc_identity_dev" &&
    m.kind === "migrated" &&
    m.source?.database !== "bujiaban_development"
  )
    allocatorFail("ALLOCATOR_INVALID_SOURCE_PROOF");
  if (!exact(m.floors, [...allocatorTables]))
    allocatorFail("ALLOCATOR_INCOMPLETE_TABLES");
  for (const table of allocatorTables) {
    const f = m.floors[table];
    if (!exact(f, ["floor", "capacity", "sourceNext", "reservedMax"]))
      allocatorFail("ALLOCATOR_INVALID_FLOOR");
    const floor = integer(f.floor),
      capacity = integer(f.capacity),
      reserved = integer(f.reservedMax);
    if (
      floor < 1n ||
      floor <= reserved ||
      floor > capacity ||
      capacity > allocatorLimit ||
      (table === "user" && capacity > 2147483647n) ||
      (m.kind === "fresh"
        ? f.sourceNext !== null
        : f.sourceNext === null ||
          integer(f.sourceNext) < 1n ||
          integer(f.sourceNext) > floor)
    )
      allocatorFail("ALLOCATOR_FLOOR_CAPACITY");
  }
  return m;
}

export function assertZeroAccountSyncReport(value: unknown): void {
  if (
    !exact(value, [
      "applied",
      "changes",
      "inserts",
      "updates",
      "deletions",
      "affectedSubjects",
      "tableChanges",
    ])
  )
    allocatorFail("ALLOCATOR_INVALID_FINAL_SYNC_REPORT");
  const r = value as Record<string, unknown>;
  if (
    r.applied !== false ||
    ["changes", "inserts", "updates", "deletions", "affectedSubjects"].some(
      (k) => r[k] !== 0,
    ) ||
    !exact(r.tableChanges, [])
  )
    allocatorFail("ALLOCATOR_INVALID_FINAL_SYNC_REPORT");
}

/** Every private automatic user insert checks its actual allocated ID before dependent writes or issuance.
 * A failed oversized INSERT rolls back its transaction; consumed AUTO_INCREMENT values are never recycled.
 */
export function assertNativeUserAllocation(value: unknown): number {
  const n =
    typeof value === "number" && Number.isSafeInteger(value)
      ? BigInt(value)
      : typeof value === "string"
        ? integer(value)
        : allocatorFail("ALLOCATOR_USER_CAPACITY_EXHAUSTED");
  if (n < 1n || n > 2147483647n)
    allocatorFail("ALLOCATOR_USER_CAPACITY_EXHAUSTED");
  return Number(n);
}
