import { describe, expect, it, vi } from "vitest";
import {
  coordinateOrganizationReconciliationSnapshots,
  type OrganizationReconciliationComponentBinding
} from "../src/iam-organization-reconciliation-coordinator.js";
import {
  createOrganizationReconciliationCompositeManifestSha256,
  createOrganizationReconciliationOperationEvidenceSha256,
  ORGANIZATION_RECONCILIATION_COMPOSITE_CONSISTENCY_MODEL,
  ORGANIZATION_RECONCILIATION_COMPOSITE_MANIFEST_CONTRACT,
  validateOrganizationReconciliationCompositeManifest,
  validateOrganizationReconciliationCompositeManifestEvidenceBinding,
  validateOrganizationReconciliationCompositeManifestUnsigned,
  type OrganizationReconciliationCompositeManifestUnsigned,
  type OrganizationReconciliationPhysicalSource
} from "../src/iam-organization-reconciliation-component-manifest.js";
import {
  ORGANIZATION_RECONCILIATION_PAGINATION_MODE,
  ORGANIZATION_RECONCILIATION_SNAPSHOT_MODE,
  type OrganizationReconciliationSourceSnapshot
} from "../src/iam-organization-reconciliation-collector.js";

type Mutable<T> = { -readonly [K in keyof T]: T[K] };
type MutableSnapshot = Mutable<OrganizationReconciliationSourceSnapshot>;
type TestAdapter = {
  sourceId: string;
  openSnapshot: ReturnType<typeof vi.fn<() => Promise<OrganizationReconciliationSourceSnapshot>>>;
  closeSnapshot: ReturnType<
    typeof vi.fn<
      (snapshot: OrganizationReconciliationSourceSnapshot, outcome: "completed" | "failed") => Promise<void>
    >
  >;
};
type MutableBinding = Mutable<OrganizationReconciliationComponentBinding> & { adapter: TestAdapter };

interface ComponentFixture {
  readonly id: OrganizationReconciliationPhysicalSource;
  readonly snapshot: MutableSnapshot;
  readonly adapter: TestAdapter;
  readonly binding: MutableBinding;
}

describe("organization reconciliation multi-source coordinator", () => {
  it("opens all physical sources deterministically and emits a bounded non-atomic manifest", async () => {
    const events: string[] = [];
    const fixtures = fixturesFor(events);
    const result = await coordinateOrganizationReconciliationSnapshots({
      components: [fixtures[2]!.binding, fixtures[0]!.binding, fixtures[1]!.binding],
      maxWindowMilliseconds: 1_000,
      clock: clockAt(0, 10, 20, 30, 40, 50)
    }, async (context) => {
      events.push("operation");
      expect(context).toMatchObject({
        consistencyModel: ORGANIZATION_RECONCILIATION_COMPOSITE_CONSISTENCY_MODEL,
        crossDatabaseAtomic: false
      });
      expect(context.components.map((component) => component.componentId)).toEqual([
        "legacy-main", "identity", "plugin"
      ]);
      expect(Object.isFrozen(context)).toBe(true);
      expect(Object.isFrozen(context.components)).toBe(true);
      expect(context.components.every((component) => Object.isFrozen(component.source))).toBe(true);
      return { comparedSurfaceCount: 8 };
    });

    expect(events).toEqual([
      "open:legacy-main",
      "open:identity",
      "open:plugin",
      "operation",
      "close:plugin:completed",
      "close:identity:completed",
      "close:legacy-main:completed"
    ]);
    expect(result.value).toEqual({ comparedSurfaceCount: 8 });
    expect(result.manifest).toMatchObject({
      contract: ORGANIZATION_RECONCILIATION_COMPOSITE_MANIFEST_CONTRACT,
      consistencyModel: ORGANIZATION_RECONCILIATION_COMPOSITE_CONSISTENCY_MODEL,
      crossDatabaseAtomic: false,
      windowStartedAt: "2026-08-09T00:00:00.000Z",
      windowEndedAt: "2026-08-09T00:00:00.050Z",
      maxWindowMilliseconds: 1_000,
      evidenceContract: "iam-organization-reconciliation-operation-evidence/v2",
      components: [
        {
          componentId: "legacy-main",
          sourceId: "legacy-main-db",
          sourceVersion: "legacy-main-version-1",
          snapshotId: "legacy-main-snapshot-1",
          recordCount: 11,
          subjectUniverseScope: "complete",
          subjectUniverse: { count: 101, sha256: "1".repeat(64) },
          schemaSha256: "4".repeat(64),
          catalogSha256: "7".repeat(64),
          buildSha256: "a".repeat(64),
          openedAt: "2026-08-09T00:00:00.000Z",
          closedAt: "2026-08-09T00:00:00.050Z"
        },
        {
          componentId: "identity",
          subjectUniverseScope: "complete",
          subjectUniverse: { count: 101, sha256: "1".repeat(64) },
          openedAt: "2026-08-09T00:00:00.010Z",
          closedAt: "2026-08-09T00:00:00.040Z"
        },
        {
          componentId: "plugin",
          subjectUniverseScope: "not-applicable",
          subjectUniverse: { count: 0, sha256: "" },
          openedAt: "2026-08-09T00:00:00.020Z",
          closedAt: "2026-08-09T00:00:00.030Z"
        }
      ]
    });
    expect(result.manifest.evidenceSha256).toBe(
      createOrganizationReconciliationOperationEvidenceSha256(result.value)
    );
    expect(result.manifest.manifestSha256).toMatch(/^[a-f0-9]{64}$/);
    const { manifestSha256, ...unsigned } = result.manifest;
    expect(createOrganizationReconciliationCompositeManifestSha256(unsigned)).toBe(manifestSha256);
    expect(JSON.stringify(result.manifest)).not.toContain('"crossDatabaseAtomic":true');
  });

  it("canonicalizes component order and binds every manifest field into the digest", async () => {
    const first = await successfulRun(fixturesFor([]));
    const { manifestSha256, ...unsigned } = first.manifest;
    const reordered = {
      ...unsigned,
      components: [...unsigned.components].reverse()
    } satisfies OrganizationReconciliationCompositeManifestUnsigned;
    expect(createOrganizationReconciliationCompositeManifestSha256(reordered)).toBe(manifestSha256);

    const changedRecordCount = {
      ...unsigned,
      components: unsigned.components.map((component, index) =>
        index === 0 ? { ...component, recordCount: component.recordCount + 1 } : component
      )
    } satisfies OrganizationReconciliationCompositeManifestUnsigned;
    const changedSchema = {
      ...unsigned,
      components: unsigned.components.map((component, index) =>
        index === 1 ? { ...component, schemaSha256: "f".repeat(64) } : component
      )
    } satisfies OrganizationReconciliationCompositeManifestUnsigned;
    const changedEvidence = {
      ...unsigned,
      evidenceSha256: "f".repeat(64)
    } satisfies OrganizationReconciliationCompositeManifestUnsigned;
    expect(createOrganizationReconciliationCompositeManifestSha256(changedRecordCount)).not.toBe(manifestSha256);
    expect(createOrganizationReconciliationCompositeManifestSha256(changedSchema)).not.toBe(manifestSha256);
    expect(createOrganizationReconciliationCompositeManifestSha256(changedEvidence)).not.toBe(manifestSha256);
    expect(validateOrganizationReconciliationCompositeManifestUnsigned(reordered).components
      .map((component) => component.componentId)).toEqual(["legacy-main", "identity", "plugin"]);
  });

  it("binds the exact canonical operation result instead of trusting a caller-reported digest", async () => {
    const callerEvidence = {
      records: [{ subjectRef: "subject-a", decision: "allow" }],
      evidenceSha256: "0".repeat(64)
    };
    const first = await coordinateOrganizationReconciliationSnapshots({
      components: fixturesFor([]).map((fixture) => fixture.binding),
      maxWindowMilliseconds: 1_000,
      clock: clockAt(0, 10, 20, 30, 40, 50)
    }, async () => callerEvidence);

    expect(first.manifest.evidenceSha256).toBe(
      createOrganizationReconciliationOperationEvidenceSha256(first.value)
    );
    expect(first.manifest.evidenceSha256).not.toBe(callerEvidence.evidenceSha256);
    expect(first.value).not.toBe(callerEvidence);
    expect(Object.isFrozen(first.value)).toBe(true);
    expect(Object.isFrozen(first.value.records)).toBe(true);
    expect(validateOrganizationReconciliationCompositeManifest(first.manifest)).toEqual(first.manifest);
    expect(validateOrganizationReconciliationCompositeManifestEvidenceBinding(
      first.manifest,
      first.value
    )).toEqual(first.manifest);

    callerEvidence.records[0]!.decision = "deny";
    expect(first.value.records[0]!.decision).toBe("allow");
    expect(() => validateOrganizationReconciliationCompositeManifestEvidenceBinding(
      first.manifest,
      callerEvidence
    )).toThrow("does not match the composite manifest binding");

    const second = await coordinateOrganizationReconciliationSnapshots({
      components: fixturesFor([]).map((fixture) => fixture.binding),
      maxWindowMilliseconds: 1_000,
      clock: clockAt(0, 10, 20, 30, 40, 50)
    }, async () => callerEvidence);
    expect(second.manifest.evidenceSha256).not.toBe(first.manifest.evidenceSha256);
    expect(second.manifest.manifestSha256).not.toBe(first.manifest.manifestSha256);
  });

  it("rejects non-JSON operation evidence and closes every source with failure", async () => {
    const unsafeValues: unknown[] = [
      { records: [1, undefined] },
      { createdAt: new Date("2026-08-09T00:00:00.000Z") },
      (() => {
        const value: Record<string, unknown> = {};
        value.self = value;
        return value;
      })()
    ];
    for (const unsafeValue of unsafeValues) {
      const fixtures = fixturesFor([]);
      await expect(coordinateOrganizationReconciliationSnapshots({
        components: fixtures.map((fixture) => fixture.binding),
        maxWindowMilliseconds: 1_000,
        clock: clockAt(0, 10, 20, 30, 40, 50)
      }, async () => unsafeValue as never)).rejects.toThrow("canonical JSON-safe evidence");
      for (const fixture of fixtures) {
        expect(fixture.adapter.closeSnapshot).toHaveBeenCalledTimes(1);
        expect(fixture.adapter.closeSnapshot).toHaveBeenCalledWith(fixture.snapshot, "failed");
      }
    }
  });

  it("never accepts caller input that promotes independent snapshots to atomic", async () => {
    const fixtures = fixturesFor([]);
    const result = await coordinateOrganizationReconciliationSnapshots({
      components: fixtures.map((fixture) => fixture.binding),
      maxWindowMilliseconds: 1_000,
      clock: clockAt(0, 10, 20, 30, 40, 50),
      crossDatabaseAtomic: true
    } as never, async (context) => context.crossDatabaseAtomic);
    expect(result.value).toBe(false);
    expect(result.manifest.crossDatabaseAtomic).toBe(false);

    const { manifestSha256: _digest, ...unsigned } = result.manifest;
    expect(() => createOrganizationReconciliationCompositeManifestSha256({
      ...unsigned,
      crossDatabaseAtomic: true
    } as never)).toThrow("cannot claim cross-database atomic consistency");
  });

  it.each([
    ["missing", (fixtures: ComponentFixture[]) => fixtures.slice(0, 2), "missing"],
    ["duplicate component", (fixtures: ComponentFixture[]) => {
      fixtures[1]!.binding.componentId = "legacy-main";
      return fixtures;
    }, "duplicate component"],
    ["duplicate physical source", (fixtures: ComponentFixture[]) => {
      fixtures[1]!.binding.expectedSourceId = fixtures[0]!.binding.expectedSourceId;
      fixtures[1]!.adapter.sourceId = fixtures[0]!.binding.expectedSourceId;
      return fixtures;
    }, "distinct source ID"]
  ])("rejects a %s component set before opening anything", async (_label, alter, message) => {
    const fixtures = fixturesFor([]);
    await expect(coordinateOrganizationReconciliationSnapshots({
      components: alter(fixtures).map((fixture) => fixture.binding),
      maxWindowMilliseconds: 1_000,
      clock: clockAt(0)
    }, async () => null)).rejects.toThrow(message);
    expect(fixtures.every((fixture) => fixture.adapter.openSnapshot.mock.calls.length === 0)).toBe(true);
    expect(fixtures.every((fixture) => fixture.adapter.closeSnapshot.mock.calls.length === 0)).toBe(true);
  });

  it("closes every earlier snapshot exactly once when a later source fails to open", async () => {
    const fixtures = fixturesFor([]);
    fixtures[1]!.adapter.openSnapshot.mockRejectedValueOnce(new Error("private-identity-token"));
    const failure = await coordinateOrganizationReconciliationSnapshots({
      components: fixtures.map((fixture) => fixture.binding),
      maxWindowMilliseconds: 1_000,
      clock: clockAt(0, 10, 20)
    }, async () => null).catch((error: unknown) => error);

    expect(failure).toEqual(new Error("Opening a coordinated authoritative source snapshot failed."));
    expect(JSON.stringify(failure)).not.toContain("private-identity-token");
    expect(fixtures[0]!.adapter.closeSnapshot).toHaveBeenCalledTimes(1);
    expect(fixtures[0]!.adapter.closeSnapshot).toHaveBeenCalledWith(fixtures[0]!.snapshot, "failed");
    expect(fixtures[1]!.adapter.closeSnapshot).not.toHaveBeenCalled();
    expect(fixtures[2]!.adapter.openSnapshot).not.toHaveBeenCalled();
  });

  it("closes a fulfilled but invalid snapshot and all earlier snapshots exactly once", async () => {
    const fixtures = fixturesFor([]);
    Object.assign(fixtures[1]!.snapshot, { snapshotMode: "best-effort" });
    await expect(coordinateOrganizationReconciliationSnapshots({
      components: fixtures.map((fixture) => fixture.binding),
      maxWindowMilliseconds: 1_000,
      clock: clockAt(0, 10, 20, 30)
    }, async () => null)).rejects.toThrow("does not provide an immutable snapshot");

    expect(fixtures[0]!.adapter.closeSnapshot).toHaveBeenCalledTimes(1);
    expect(fixtures[1]!.adapter.closeSnapshot).toHaveBeenCalledTimes(1);
    expect(fixtures[0]!.adapter.closeSnapshot).toHaveBeenCalledWith(fixtures[0]!.snapshot, "failed");
    expect(fixtures[1]!.adapter.closeSnapshot).toHaveBeenCalledWith(fixtures[1]!.snapshot, "failed");
    expect(fixtures[2]!.adapter.openSnapshot).not.toHaveBeenCalled();
  });

  it("redacts operation failures and closes all three snapshots exactly once with failure", async () => {
    const fixtures = fixturesFor([]);
    const failure = await coordinateOrganizationReconciliationSnapshots({
      components: fixtures.map((fixture) => fixture.binding),
      maxWindowMilliseconds: 1_000,
      clock: clockAt(0, 10, 20, 30, 40, 50)
    }, async () => {
      throw new Error("private-cross-db-row");
    }).catch((error: unknown) => error);

    expect(failure).toEqual(new Error("The coordinated snapshot operation failed."));
    expect(JSON.stringify(failure)).not.toContain("private-cross-db-row");
    for (const fixture of fixtures) {
      expect(fixture.adapter.closeSnapshot).toHaveBeenCalledTimes(1);
      expect(fixture.adapter.closeSnapshot).toHaveBeenCalledWith(fixture.snapshot, "failed");
    }
  });

  it("rejects snapshot and binding drift while still closing every source exactly once", async () => {
    for (const drift of ["snapshot", "binding"] as const) {
      const fixtures = fixturesFor([]);
      const failure = coordinateOrganizationReconciliationSnapshots({
        components: fixtures.map((fixture) => fixture.binding),
        maxWindowMilliseconds: 1_000,
        clock: clockAt(0, 10, 20, 30, 40, 50)
      }, async () => {
        if (drift === "snapshot") fixtures[0]!.snapshot.sourceVersion = "changed-private-version";
        else fixtures[1]!.binding.catalogSha256 = "f".repeat(64);
        return null;
      });
      await expect(failure).rejects.toThrow("changed metadata");
      for (const fixture of fixtures) {
        expect(fixture.adapter.closeSnapshot).toHaveBeenCalledTimes(1);
        expect(fixture.adapter.closeSnapshot).toHaveBeenCalledWith(fixture.snapshot, "failed");
      }
    }
  });

  it("continues closing all sources when one close fails and rejects the entire manifest", async () => {
    const fixtures = fixturesFor([]);
    fixtures[2]!.adapter.closeSnapshot.mockRejectedValueOnce(new Error("private-close-token"));
    const failure = await coordinateOrganizationReconciliationSnapshots({
      components: fixtures.map((fixture) => fixture.binding),
      maxWindowMilliseconds: 1_000,
      clock: clockAt(0, 10, 20, 30, 40, 50)
    }, async () => "complete").catch((error: unknown) => error);

    expect(failure).toEqual(new Error(
      "Closing or finalizing coordinated source snapshots failed; composite evidence was rejected."
    ));
    expect(JSON.stringify(failure)).not.toContain("private-close-token");
    for (const fixture of fixtures) expect(fixture.adapter.closeSnapshot).toHaveBeenCalledTimes(1);
  });

  it("detects close-time metadata drift and rejects evidence without retrying close", async () => {
    const fixtures = fixturesFor([]);
    fixtures[2]!.adapter.closeSnapshot.mockImplementationOnce(async () => {
      fixtures[2]!.snapshot.snapshotId = "mutated-during-close";
    });
    await expect(coordinateOrganizationReconciliationSnapshots({
      components: fixtures.map((fixture) => fixture.binding),
      maxWindowMilliseconds: 1_000,
      clock: clockAt(0, 10, 20, 30, 40, 50)
    }, async () => "complete")).rejects.toThrow("composite evidence was rejected");
    for (const fixture of fixtures) expect(fixture.adapter.closeSnapshot).toHaveBeenCalledTimes(1);
  });

  it("requires one identical complete Legacy/Identity universe and an explicit plugin N/A universe", async () => {
    const mismatched = fixturesFor([]);
    mismatched[1]!.snapshot.subjectUniverseCount = 102;
    mismatched[1]!.snapshot.subjectUniverseHash = "2".repeat(64);
    const operation = vi.fn(async () => ({ records: [] }));
    await expect(coordinateOrganizationReconciliationSnapshots({
      components: mismatched.map((fixture) => fixture.binding),
      maxWindowMilliseconds: 1_000,
      clock: clockAt(0, 10, 20, 30, 40, 50)
    }, operation)).rejects.toThrow("subject universes do not match");
    expect(operation).not.toHaveBeenCalled();
    for (const fixture of mismatched) {
      expect(fixture.adapter.closeSnapshot).toHaveBeenCalledTimes(1);
      expect(fixture.adapter.closeSnapshot).toHaveBeenCalledWith(fixture.snapshot, "failed");
    }

    const pluginPretendsComplete = fixturesFor([]);
    pluginPretendsComplete[2]!.snapshot.subjectUniverseCount = 101;
    pluginPretendsComplete[2]!.snapshot.subjectUniverseHash = "1".repeat(64);
    await expect(coordinateOrganizationReconciliationSnapshots({
      components: pluginPretendsComplete.map((fixture) => fixture.binding),
      maxWindowMilliseconds: 1_000,
      clock: clockAt(0, 10, 20, 30, 40, 50)
    }, async () => ({ records: [] }))).rejects.toThrow("explicitly not applicable");
    for (const fixture of pluginPretendsComplete) {
      expect(fixture.adapter.closeSnapshot).toHaveBeenCalledTimes(1);
      expect(fixture.adapter.closeSnapshot).toHaveBeenCalledWith(fixture.snapshot, "failed");
    }
  });

  it("fails closed on a backwards clock or an exceeded composite window", async () => {
    const backwards = fixturesFor([]);
    await expect(coordinateOrganizationReconciliationSnapshots({
      components: backwards.map((fixture) => fixture.binding),
      maxWindowMilliseconds: 1_000,
      clock: clockAt(0, 10, 20, 15, 30, 40)
    }, async () => null)).rejects.toThrow("composite evidence was rejected");
    for (const fixture of backwards) expect(fixture.adapter.closeSnapshot).toHaveBeenCalledTimes(1);

    const unbounded = fixturesFor([]);
    await expect(coordinateOrganizationReconciliationSnapshots({
      components: unbounded.map((fixture) => fixture.binding),
      maxWindowMilliseconds: 25,
      clock: clockAt(0, 10, 20, 30, 40, 50)
    }, async () => null)).rejects.toThrow("composite evidence was rejected");
    for (const fixture of unbounded) expect(fixture.adapter.closeSnapshot).toHaveBeenCalledTimes(1);
  });

  it("validates digest metadata strictly, including complete unique components and bounded timestamps", async () => {
    const { manifest } = await successfulRun(fixturesFor([]));
    const { manifestSha256: _digest, ...unsigned } = manifest;
    expect(() => createOrganizationReconciliationCompositeManifestSha256({
      ...unsigned,
      components: unsigned.components.slice(0, 2)
    })).toThrow("missing a required component");
    expect(() => createOrganizationReconciliationCompositeManifestSha256({
      ...unsigned,
      components: [unsigned.components[0]!, unsigned.components[0]!, unsigned.components[2]!]
    })).toThrow("duplicate component");
    expect(() => createOrganizationReconciliationCompositeManifestSha256({
      ...unsigned,
      windowEndedAt: "2026-08-09T00:00:02.000Z"
    })).toThrow("invalid or unbounded");
    expect(() => createOrganizationReconciliationCompositeManifestSha256({
      ...unsigned,
      unexpected: "not-digest-bound"
    } as never)).toThrow("missing or unknown fields");
    expect(() => createOrganizationReconciliationCompositeManifestSha256({
      ...unsigned,
      components: unsigned.components.map((component) => component.componentId === "identity"
        ? {
            ...component,
            subjectUniverse: { count: 102, sha256: "2".repeat(64) }
          }
        : component)
    })).toThrow("subject universes do not match");
    expect(() => createOrganizationReconciliationCompositeManifestSha256({
      ...unsigned,
      components: unsigned.components.map((component) => component.componentId === "plugin"
        ? {
            ...component,
            subjectUniverseScope: "complete" as const,
            subjectUniverse: { count: 101, sha256: "1".repeat(64) }
          }
        : component)
    })).toThrow("explicitly not applicable");
    expect(() => createOrganizationReconciliationCompositeManifestSha256({
      ...unsigned,
      components: unsigned.components.map((component) => {
        if (component.componentId === "legacy-main") {
          return { ...component, closedAt: "2026-08-09T00:00:00.015Z" };
        }
        if (component.componentId === "identity") {
          return {
            ...component,
            openedAt: "2026-08-09T00:00:00.016Z",
            closedAt: "2026-08-09T00:00:00.045Z"
          };
        }
        return { ...component, openedAt: "2026-08-09T00:00:00.020Z" };
      })
    })).toThrow(/do not share one immutable snapshot interval|lifecycle order is invalid/);
  });
});

const BASE_TIME = Date.parse("2026-08-09T00:00:00.000Z");
const COMPONENT_IDS: readonly OrganizationReconciliationPhysicalSource[] = [
  "legacy-main", "identity", "plugin"
];

function fixturesFor(events: string[]): ComponentFixture[] {
  return COMPONENT_IDS.map((id, index) => {
    const sourceId = `${id}-db`;
    const snapshot: MutableSnapshot = {
      sourceId,
      sourceVersion: `${id}-version-1`,
      snapshotId: `${id}-snapshot-1`,
      recordCount: 11 + index,
      subjectUniverseCount: index === 2 ? 0 : 101,
      subjectUniverseHash: index === 2 ? "" : "1".repeat(64),
      snapshotMode: ORGANIZATION_RECONCILIATION_SNAPSHOT_MODE,
      paginationMode: ORGANIZATION_RECONCILIATION_PAGINATION_MODE
    };
    const adapter: TestAdapter = {
      sourceId,
      openSnapshot: vi.fn(async () => {
        events.push(`open:${id}`);
        return snapshot;
      }),
      closeSnapshot: vi.fn(async (_snapshot, outcome) => {
        events.push(`close:${id}:${outcome}`);
      })
    };
    const binding: MutableBinding = {
      componentId: id,
      expectedSourceId: sourceId,
      schemaSha256: String(index + 4).repeat(64),
      catalogSha256: String(index + 7).repeat(64),
      buildSha256: ["a", "b", "c"][index]!.repeat(64),
      adapter
    };
    return { id, snapshot, adapter, binding };
  });
}

function clockAt(...offsets: number[]) {
  let index = 0;
  return {
    now: vi.fn(() => {
      if (index >= offsets.length) throw new Error("test clock exhausted");
      return new Date(BASE_TIME + offsets[index++]!);
    })
  };
}

function successfulRun(fixtures: ComponentFixture[]) {
  return coordinateOrganizationReconciliationSnapshots({
    components: fixtures.map((fixture) => fixture.binding),
    maxWindowMilliseconds: 1_000,
    clock: clockAt(0, 10, 20, 30, 40, 50)
  }, async () => "complete");
}
