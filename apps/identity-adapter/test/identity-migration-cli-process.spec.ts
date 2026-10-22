import { execFile } from "node:child_process";
import {
  mkdtemp,
  readFile,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const execute = promisify(execFile),
  root = fileURLToPath(new URL("../../../", import.meta.url));
const entries = ["account-sync", "allocator-highwater", "identity-activate"];
let directory: string, build: string;
beforeAll(async () => {
  directory = await mkdtemp(join(tmpdir(), "identity-cli-process-"));
  build = join(directory, "build");
  await execute(
    process.execPath,
    [
      join(root, "node_modules/typescript/bin/tsc"),
      "-p",
      join(root, "tsconfig.json"),
      "--outDir",
      build,
    ],
    { cwd: root, timeout: 60_000, maxBuffer: 1024 * 1024 },
  );
  await writeFile(join(build, "package.json"), '{"type":"module"}\n');
  await symlink(join(root, "node_modules"), join(build, "node_modules"));
}, 60_000);
afterAll(async () => {
  await rm(directory, { recursive: true, force: true });
});

describe("actual migration CLI process entrypoints", () => {
  for (const entry of entries) {
    it(`executes compiled ${entry} help as a real CLI`, async () => {
      const result = await execute(
        process.execPath,
        [join(build, `scripts/${entry}.js`), "--help"],
        { cwd: directory, timeout: 10_000 },
      );
      expect(result.stdout).toContain(entry);
      expect(result.stderr).toBe("");
    });
    it(`executes source ${entry} help through the supported tsx CLI`, async () => {
      const result = await execute(
        process.execPath,
        [
          join(root, "node_modules/tsx/dist/cli.mjs"),
          join(root, `scripts/${entry}.ts`),
          "--help",
        ],
        { cwd: directory, timeout: 10_000 },
      );
      expect(result.stdout).toContain(entry);
      expect(result.stderr).toBe("");
    });
    it(`executes symlinked compiled ${entry} instead of silently succeeding`, async () => {
      const link = join(directory, `${entry}.js`);
      await symlink(join(build, `scripts/${entry}.js`), link);
      const result = await execute(process.execPath, [link, "--help"], {
        cwd: directory,
        timeout: 10_000,
      });
      expect(result.stdout).toContain(entry);
      expect(result.stderr).toBe("");
    });
    it(`executes symlinked source ${entry} through tsx`, async () => {
      const link = join(directory, `${entry}.ts`);
      await symlink(join(root, `scripts/${entry}.ts`), link);
      const result = await execute(
        process.execPath,
        [join(root, "node_modules/tsx/dist/cli.mjs"), link, "--help"],
        { cwd: directory, timeout: 10_000 },
      );
      expect(result.stdout).toContain(entry);
      expect(result.stderr).toBe("");
    });
    it(`rejects invalid direct ${entry} arguments without a success output`, async () => {
      let failure: any;
      try {
        await execute(
          process.execPath,
          [join(build, `scripts/${entry}.js`), "--unreviewed-operation"],
          { cwd: directory, timeout: 10_000 },
        );
      } catch (error) {
        failure = error;
      }
      const expected = {
        "account-sync": "Account sync failed",
        "allocator-highwater": "ALLOCATOR_OPERATION_FAILED",
        "identity-activate": "ACTIVATION_OPERATION_FAILED",
      };
      expect(failure?.code).toBe(1);
      expect(failure?.stdout).toBe("");
      expect(failure?.stderr).toContain(
        expected[entry as keyof typeof expected],
      );
    });
  }
  it("imports all compiled wrappers in a real process without running operations or touching a report", async () => {
    const marker = join(directory, "must-not-be-created.json");
    const script =
      `process.argv = [process.execPath, 'not-a-migration-entry.js', '--apply', '--max-changes=100', ${JSON.stringify(`--report=${marker}`)}];\n` +
      entries
        .map(
          (entry) =>
            `await import(${JSON.stringify(pathToFileURL(join(build, `scripts/${entry}.js`)).href)});`,
        )
        .join("\n") +
      "\nconsole.log(JSON.stringify({imported:true,exitCode:process.exitCode ?? 0}));";
    const result = await execute(
      process.execPath,
      ["--input-type=module", "--eval", script],
      {
        cwd: directory,
        timeout: 10_000,
        env: {
          ...process.env,
          IDENTITY_ADMISSION_ENABLED: "true",
          LEGACY_DB_HOST: "must-not-connect.invalid",
          IDENTITY_DB_HOST: "must-not-connect.invalid",
        },
      },
    );
    expect(result.stderr).toBe("");
    expect(JSON.parse(result.stdout)).toEqual({ imported: true, exitCode: 0 });
    await expect(stat(marker)).rejects.toMatchObject({ code: "ENOENT" });
    expect(
      await readFile(join(build, "scripts/account-sync.js"), "utf8"),
    ).toContain("isDirectCli");
  });
});
