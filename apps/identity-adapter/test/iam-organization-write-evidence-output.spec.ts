import { createHash } from "node:crypto";
import { chmod, lstat, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, describe, expect, it } from "vitest";
import { writeOrganizationEvidenceExclusive0600 } from "../../../scripts/iam-organization-write-evidence-output.js";
import { parseOrganizationIdentityNativeWindowGateArgs } from "../../../scripts/iam-organization-identity-native-window-gate.js";
import { parseOrganizationWritePublicGateArgs } from "../../../scripts/iam-organization-write-public-gate.js";

const roots: string[] = [];

afterEach(async () => Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true }))));

describe("organization evidence output", () => {
  it("creates one canonical owner-only file and returns its exact digest", async () => {
    const root = await privateRoot();
    const path = join(root, "evidence.json");
    const value = { contract: "test/v1", passed: true };
    const result = await writeOrganizationEvidenceExclusive0600(path, value);
    const bytes = Buffer.from(`${JSON.stringify(value)}\n`);
    expect(result).toEqual({ path, sha256: createHash("sha256").update(bytes).digest("hex") });
    expect(await readFile(path)).toEqual(bytes);
    const metadata = await lstat(path);
    expect(metadata.mode & 0o077).toBe(0);
    expect(metadata.nlink).toBe(1);
  });

  it("never overwrites or deletes an existing output", async () => {
    const root = await privateRoot();
    const path = join(root, "evidence.json");
    await writeFile(path, "owner-data\n", { mode: 0o600 });
    await expect(writeOrganizationEvidenceExclusive0600(path, { passed: true })).rejects.toThrow();
    expect(await readFile(path, "utf8")).toBe("owner-data\n");
  });

  it("parsers accept only normalized absolute output paths", async () => {
    const root = await privateRoot();
    const path = join(root, "result.json");
    const env = {
      IDENTITY_IAM_INTERNAL_API_TOKEN: "internal",
      IDENTITY_IAM_ORG_NATIVE_WINDOW_ORGANIZATION_IDS: "1"
    };
    expect(parseOrganizationIdentityNativeWindowGateArgs([
      "--legacy-user-id=24", `--expected-revision=${"a".repeat(40)}`,
      `--expected-before-fingerprint=${"b".repeat(64)}`, `--output=${path}`
    ], env)).toMatchObject({ outputPath: path });
    expect(parseOrganizationWritePublicGateArgs([`--output=${path}`])).toMatchObject({ outputPath: path });
    expect(() => parseOrganizationWritePublicGateArgs(["--output=relative.json"])).toThrow("normalized absolute path");
    expect(() => parseOrganizationWritePublicGateArgs([`--output=${root}/../result.json`])).toThrow("normalized absolute path");
  });
});

async function privateRoot(): Promise<string> {
  const root = await realpath(await mkdtemp(join(tmpdir(), "iam-evidence-output-")));
  roots.push(root);
  await chmod(root, 0o700);
  return root;
}
