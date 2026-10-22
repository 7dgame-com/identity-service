import { execFile } from "node:child_process";
import { copyFile, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
const execute = promisify(execFile), root = fileURLToPath(new URL("../../../", import.meta.url)), relative = "packages/identity-finalization-runtime";
let directory: string;
const revision = "a".repeat(40), hash = (bytes: Buffer) => createHash("sha256").update(bytes).digest("hex");
beforeAll(async () => {
  directory = await mkdtemp(join(tmpdir(), "owned-executor-layout-"));
  await execute(process.execPath, [join(root, "node_modules/typescript/bin/tsc"), "-p", join(root, "tsconfig.json"), "--outDir", join(directory, "dist")], { cwd: root, timeout: 60000, maxBuffer: 1024 * 1024 });
  await writeFile(join(directory, "package.json"), '{"type":"module"}\n'); await symlink(join(root, "node_modules"), join(directory, "node_modules"));
  await mkdir(join(directory, "scripts")); await mkdir(join(directory, relative), { recursive: true });
  await copyFile(join(root, "scripts/verify-identity-finalization-runtime.mjs"), join(directory, "scripts/verify-identity-finalization-runtime.mjs"));
  await copyFile(join(root, relative, "upstream-manifest.json"), join(directory, relative, "upstream-manifest.json"));
  for (const name of ["migration-plan.mjs", "migration-artifacts.mjs"]) await copyFile(join(root, relative, name), join(directory, "dist", relative, name));
  // Public synthetic build metadata only. The actual Docker build invokes the
  // existing immutable revision generator; this fixture tests its binding.
  await writeFile(join(directory, "GIT_COMMIT"), revision + "\n");
  await writeFile(join(directory, "dist/apps/identity-adapter/src/generated/iam-organization-reconciliation-compiled-revision.js"), `export const ORGANIZATION_RECONCILIATION_COMPILED_BUILD_REVISION = ${JSON.stringify(revision)};\n`);
}, 60000);
afterAll(async () => { await rm(directory, { recursive: true, force: true }); });
const verify = () => execute(process.execPath, [join(directory, "scripts/verify-identity-finalization-runtime.mjs"), "--executor"], { cwd: directory, timeout: 10000 });
describe("owned-executor immutable packaging", () => {
  it("keeps the original HTTP runtime as default and adds only an explicit fixed-layout executor target", async () => {
    const docker = await readFile(join(root, "Dockerfile"), "utf8");
    const from = [...docker.matchAll(/^FROM .* AS (\S+)$/gm)].map(m => m[1]); expect(from.at(-1)).toBe("runtime"); expect(from).toContain("migration-executor");
    const executor = docker.split(" AS migration-executor\n")[1].split("\nFROM ")[0], http = docker.split(" AS runtime\n")[1];
    expect(executor).toContain("WORKDIR /opt/xrugc/identity"); expect(executor).toContain('ENTRYPOINT ["node", "dist/scripts/identity-owned-executor.js"]');
    expect(executor).toContain("USER node"); expect(executor).toContain("upstream-manifest.json"); expect(executor).toContain("GIT_COMMIT");
    expect(executor).toContain("/app/packages/identity-finalization-runtime/*.mjs ./dist/packages/identity-finalization-runtime/");
    expect(executor).toContain("verify-identity-finalization-runtime.mjs --executor");
    expect(http).toContain('CMD ["node", "dist/apps/identity-adapter/src/main.js"]'); expect(http).not.toContain("IDENTITY_MIGRATION_");
  });
  it("verifies actual runtime adapter bytes equal pinned source, not TypeScript's emitted approximation", async () => {
    const manifest = JSON.parse(await readFile(join(root, relative, "upstream-manifest.json"), "utf8"));
    expect(manifest.upstreamCommit).toBe("8f24384aee82d8bf03e6e799d57ed7d48d9d8a0a");
    for (const file of manifest.files) {
      const original = await readFile(join(root, relative, file.path)), runtime = await readFile(join(directory, "dist", relative, file.path));
      expect(runtime.equals(original)).toBe(true); expect(hash(runtime)).toBe(file.sha256);
    }
    const checked = await verify(); expect(JSON.parse(checked.stdout)).toMatchObject({ verified: true, executorLayout: true, upstreamCommit: manifest.upstreamCommit }); expect(checked.stderr).toBe("");
    for (const name of ["identity-migration-entry.js", "identity-migration-resources.js"]) {
      const module = await readFile(join(directory, "dist/apps/identity-adapter/src", name), "utf8");
      expect(module).toContain('"../../../packages/identity-finalization-runtime/migration-artifacts.mjs"');
    }
  });
  it("rejects changed runtime bytes even when a caller rewrites the manifest to match", async () => {
    const path = join(directory, "dist", relative, "migration-plan.mjs"), manifestPath = join(directory, relative, "upstream-manifest.json");
    const original = await readFile(path), oldManifest = await readFile(manifestPath), changed = Buffer.concat([original, Buffer.from("\n// fixture drift\n")]);
    try {
      await writeFile(path, changed); const manifest = JSON.parse(oldManifest.toString()); manifest.files.find((f: any) => f.path === "migration-plan.mjs").sha256 = hash(changed); await writeFile(manifestPath, JSON.stringify(manifest));
      await expect(verify()).rejects.toMatchObject({ code: 2, stdout: "", stderr: "MIGRATION_PINNED_RUNTIME_MISMATCH\n" });
    } finally { await writeFile(path, original); await writeFile(manifestPath, oldManifest); }
  });
  it("rejects a GIT_COMMIT inconsistent with the compiled revision", async () => {
    try { await writeFile(join(directory, "GIT_COMMIT"), "b".repeat(40) + "\n"); await expect(verify()).rejects.toMatchObject({ code: 2 }); }
    finally { await writeFile(join(directory, "GIT_COMMIT"), revision + "\n"); }
  });
  it("imports compiled executor without launching, reading FD3, or loading protected configuration", async () => {
    const result = await execute(process.execPath, ["--input-type=module", "-e", `await import(${JSON.stringify(new URL("file://" + join(directory, "dist/scripts/identity-owned-executor.js")).href)});`], { cwd: directory, timeout: 10000 });
    expect(result.stdout).toBe(""); expect(result.stderr).toBe("");
  });
  it("actual CLI rejects absent configuration and extra arguments without opening any control resource", async () => {
    const script = join(directory, "dist/scripts/identity-owned-executor.js"), env = { ...process.env, IDENTITY_MIGRATION_CONFIG_FILE: "", IDENTITY_MIGRATION_KEY_FILE: "" };
    await expect(execute(process.execPath, [script], { cwd: directory, env, timeout: 10000 })).rejects.toMatchObject({ code: 3, stdout: "", stderr: expect.stringContaining("MIGRATION_ENTER_NOT_WIRED") });
    await expect(execute(process.execPath, [script, "--plan=/tmp/untrusted.json"], { cwd: directory, env, timeout: 10000 })).rejects.toMatchObject({ code: 3, stdout: "", stderr: expect.stringContaining("MIGRATION_EXECUTOR_ARGUMENTS_FORBIDDEN") });
  });
});
