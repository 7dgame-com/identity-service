import { NativeIdentityService } from "../src/native-identity.service.js";
import { describe, expect, it, vi } from "vitest";
import {
  allocatorDigest,
  allocatorTables,
  assertNativeUserAllocation,
  assertZeroAccountSyncReport,
  canonical,
  integer,
  normalizeAllocatorManifest,
  type AllocatorManifest,
} from "../src/identity-allocator-manifest.js";
import {
  columnCapacity,
  referenceNamespace,
} from "../src/identity-allocator-state.js";
const proof = (): AllocatorManifest => ({
  version: 1,
  kind: "fresh",
  targetDatabase: "test_allocator_unit",
  capturedAt: "2026-10-13T00:00:00.000Z",
  source: null,
  drain: null,
  baseline: null,
  floors: Object.fromEntries(
    allocatorTables.map((t) => [
      t,
      {
        floor: "1",
        capacity: t === "user" ? "2147483647" : "9007199254740991",
        sourceNext: null,
        reservedMax: "0",
      },
    ]),
  ) as AllocatorManifest["floors"],
});
describe("allocator checkpoint strict contract", () => {
  it("does not require proof or even its table in legacy compatibility mode", async () => {
    vi.stubEnv("IDENTITY_DATA_SOURCE", "legacy");
    const ensureSchema = vi
      .fn()
      .mockRejectedValue(new Error("must not touch private schema"));
    const native = new NativeIdentityService(
      {} as never,
      {} as never,
      { ensureSchema } as never,
    );
    try {
      await expect(native.onApplicationBootstrap()).resolves.toBeUndefined();
      expect(ensureSchema).not.toHaveBeenCalled();
    } finally {
      await native.onModuleDestroy();
      vi.unstubAllEnvs();
    }
  });

  it("allows the last signed business ID and rejects every subsequent or ambiguous allocated value", () => {
    expect(assertNativeUserAllocation(2147483647)).toBe(2147483647);
    for (const v of [
      2147483648,
      0,
      -1,
      1.1,
      "02147483647",
      "2147483648",
      Number.MAX_SAFE_INTEGER + 1,
    ])
      expect(() => assertNativeUserAllocation(v)).toThrow("ALLOCATOR_");
  });
  it("requires the complete actual zero-delta sync shape", () => {
    const r = {
      applied: false,
      changes: 0,
      inserts: 0,
      updates: 0,
      deletions: 0,
      affectedSubjects: 0,
      tableChanges: {},
    };
    expect(() => assertZeroAccountSyncReport(r)).not.toThrow();
    expect(() =>
      assertZeroAccountSyncReport({ applied: false, changes: 0 }),
    ).toThrow();
    for (const k of ["inserts", "updates", "deletions", "affectedSubjects"])
      expect(() => assertZeroAccountSyncReport({ ...r, [k]: 1 })).toThrow();
    expect(() =>
      assertZeroAccountSyncReport({ ...r, tableChanges: { user: 0 } }),
    ).toThrow();
  });
  it("hashes version number and stable sorted JSON without numeric counter rounding", () => {
    const m = proof();
    expect(normalizeAllocatorManifest(m)).toEqual(m);
    expect(allocatorDigest(m)).toHaveLength(64);
    expect(canonical({ b: "2", a: 1 })).toBe('{"a":1,"b":"2"}');
    expect(allocatorDigest({ b: "2", a: 1 })).toBe(
      allocatorDigest({ a: 1, b: "2" }),
    );
  });
  it.each([
    0,
    1.1,
    NaN,
    Infinity,
    9007199254740992,
    undefined,
    Buffer.from("1"),
    new Date(),
  ])("rejects unsafe/noncanonical JSON atom %s", (v) => {
    if (v === 0) expect(canonical(v)).toBe("0");
    else expect(() => canonical(v)).toThrow();
  });
  it.each([
    "-1",
    "+1",
    "01",
    "1.0",
    "1e2",
    " 1",
    "9007199254740992",
    1,
    undefined,
  ])("rejects ambiguous or unsafe decimal %s", (v) =>
    expect(() => integer(v)).toThrow(),
  );
  it.each(allocatorTables)(
    "requires every table and rejects floor <= retained max: %s",
    (table) => {
      const m = proof();
      m.floors[table].reservedMax = "1";
      expect(() => normalizeAllocatorManifest(m)).toThrow(
        "ALLOCATOR_FLOOR_CAPACITY",
      );
      delete (m.floors as Partial<typeof m.floors>)[table];
      expect(() => normalizeAllocatorManifest(m)).toThrow(
        "ALLOCATOR_INCOMPLETE_TABLES",
      );
    },
  );
  it("caps users at signed business INT and permits independently reviewed larger namespaces", () => {
    const m = proof();
    m.floors.user.capacity = "4294967295";
    expect(() => normalizeAllocatorManifest(m)).toThrow();
    m.floors.user.capacity = "2147483647";
    expect(normalizeAllocatorManifest(m).floors.user_info.capacity).toBe(
      "9007199254740991",
    );
  });
  it("forbids fresh source/baseline evidence and unknown root fields", () => {
    const m = proof();
    expect(() => normalizeAllocatorManifest({ ...m, source: {} })).toThrow();
    expect(() =>
      normalizeAllocatorManifest({ ...m, unreviewed: true }),
    ).toThrow();
  });
  it("requires actual migrated source/import/drain evidence", () => {
    const m = proof();
    m.kind = "migrated";
    expect(() => normalizeAllocatorManifest(m)).toThrow();
    m.source = {
      database: "bujiaban_development",
      host: "10.206.0.5",
      port: "3306",
      serverUuid: "12345678-1234-1234-1234-123456789abc",
    };
    m.drain = {
      reviewSha256: "a".repeat(64),
      writersDrainedAt: "2026-10-12T23:59:00.000Z",
      finalSyncSha256: "b".repeat(64),
    };
    m.baseline = {
      importKey: "reviewed-import",
      referenceReviewSha256: "c".repeat(64),
    };
    for (const t of allocatorTables) m.floors[t].sourceNext = "1";
    expect(normalizeAllocatorManifest(m)).toEqual(m);
    m.drain.writersDrainedAt = "2026-02-30T00:00:00.000Z";
    expect(() => normalizeAllocatorManifest(m)).toThrow(
      "ALLOCATOR_INVALID_DRAIN_PROOF",
    );
    m.drain.writersDrainedAt = "2026-10-12T23:59:00.000Z";
    m.source.host = "127.0.0.1" as "10.206.0.5";
    expect(() => normalizeAllocatorManifest(m)).toThrow();
  });
  it.each([
    ["int", "2147483647"],
    ["int unsigned", "4294967295"],
    ["bigint", "9007199254740991"],
    ["smallint unsigned", "65535"],
  ])("derives exact capacity %s", (type, max) =>
    expect(columnCapacity(type).toString()).toBe(max),
  );
  it.each(["varchar(128)", "decimal(65,0)", "int zerofill"])(
    "rejects unreviewed allocator type %s",
    (type) => expect(() => columnCapacity(type)).toThrow(),
  );
  it("distinguishes opaque identity UUID namespaces from legacy numeric references", () => {
    const col = (name: string) => ({
      table_name: "candidate",
      column_name: name,
      column_type: "bigint",
      extra: "",
    });
    expect(referenceNamespace(col("identity_user_id"))).toBeNull();
    expect(referenceNamespace(col("identity_organization_id"))).toBeNull();
    expect(referenceNamespace(col("legacy_user_id"))).toBe("user");
    expect(referenceNamespace(col("legacy_organization_id"))).toBe(
      "organization",
    );
  });
});
