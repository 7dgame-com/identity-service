import { mkdtemp, cp, readFile, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { describe, expect, it } from "vitest";
import {
  frozenAdmissionProtocolDirectory,
  frozenAdmissionProtocolFiles,
  verifyAdmissionProtocolSnapshot,
} from "./support/admission-protocol-fixture.js";

describe("self-contained real admission protocol test snapshot", () => {
  it("verifies frozen source hashes and, when present, the exact superproject bytes", async () => {
    const result = await verifyAdmissionProtocolSnapshot();
    expect(result.files).toBe(5);
    expect(result.upstreamCommit).toBe(
      "f603930906d55c54fc2c3552ed2f431d05cafe18",
    );
  });
  it("loads all five real modules when no external driver checkout exists", async () => {
    const directory = await mkdtemp(
      join(tmpdir(), "identity-protocol-isolated-"),
    );
    try {
      const snapshot = join(directory, "snapshot");
      await cp(frozenAdmissionProtocolDirectory, snapshot, { recursive: true });
      expect(
        (
          await verifyAdmissionProtocolSnapshot({
            snapshotDirectory: snapshot,
            upstreamDirectory: join(directory, "no-superproject"),
          })
        ).upstreamPresent,
      ).toBe(false);
      const modules = await Promise.all(
        frozenAdmissionProtocolFiles.map(
          (name) => import(pathToFileURL(join(snapshot, name)).href),
        ),
      );
      expect(modules[0].AdmissionCoordinator).toEqual(expect.any(Function));
      expect(modules[1].memoryFixtureJournal).toEqual(expect.any(Function));
      expect(modules[2].participantClient).toEqual(expect.any(Function));
      expect(modules[3].startControlServer).toEqual(expect.any(Function));
      expect(modules[4].HoldQueue).toEqual(expect.any(Function));
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
  it("fails rather than silently loading modified frozen code", async () => {
    const directory = await mkdtemp(join(tmpdir(), "identity-protocol-drift-"));
    try {
      await cp(frozenAdmissionProtocolDirectory, directory, {
        recursive: true,
      });
      await writeFile(join(directory, "coordinator.mjs"), "// changed\n");
      await expect(
        verifyAdmissionProtocolSnapshot({
          snapshotDirectory: directory,
          upstreamDirectory: join(directory, "absent"),
        }),
      ).rejects.toThrow("SNAPSHOT_DRIFT");
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
  it("fails when an available upstream disagrees or is incomplete", async () => {
    const directory = await mkdtemp(
      join(tmpdir(), "identity-protocol-upstream-"),
    );
    try {
      await cp(frozenAdmissionProtocolDirectory, directory, {
        recursive: true,
      });
      await writeFile(
        join(directory, "journal.mjs"),
        Buffer.concat([
          await readFile(join(directory, "journal.mjs")),
          Buffer.from("\n"),
        ]),
      );
      await expect(
        verifyAdmissionProtocolSnapshot({ upstreamDirectory: directory }),
      ).rejects.toThrow("UPSTREAM_DRIFT");
      await rm(join(directory, "coordinator.mjs"));
      await expect(
        verifyAdmissionProtocolSnapshot({ upstreamDirectory: directory }),
      ).rejects.toThrow();
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});
