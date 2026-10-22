import { createHash } from "node:crypto";
import { lstat, readFile } from "node:fs/promises";

const upstream = "8f24384aee82d8bf03e6e799d57ed7d48d9d8a0a";
const files = Object.freeze({
  "migration-artifacts.mjs": "3413f91456561657323479fe384c7b907b80205e4f2cecf3406c65b24fb05bb0",
  "migration-plan.mjs": "16a863a88f0189d083a09af53b93a39132e36cfe89b4a5f8eaea2d5924567782",
});
const root = new URL("../", import.meta.url);
const fail = () => { throw new Error("MIGRATION_PINNED_RUNTIME_MISMATCH"); };
async function bytes(name, max) {
  const path = new URL(name, root), stat = await lstat(path);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size < 1 || stat.size > max) fail();
  const value = await readFile(path);
  if (value.length !== stat.size) fail();
  return value;
}
try {
  if (process.argv.length > 3 || (process.argv[2] !== undefined && process.argv[2] !== "--executor")) fail();
  const executor = process.argv[2] === "--executor";
  const manifest = JSON.parse((await bytes("packages/identity-finalization-runtime/upstream-manifest.json", 16384)).toString("utf8"));
  if (manifest.version !== 1 || manifest.upstreamRepository !== "xrugc superproject" || manifest.upstreamCommit !== upstream
    || manifest.upstreamDirectory !== "driver/identity-dev-admission" || !Array.isArray(manifest.files) || manifest.files.length !== 2
    || manifest.files.some(item => Object.keys(item).sort().join(",") !== "path,sha256" || files[item.path] !== item.sha256)
    || new Set(manifest.files.map(item => item.path)).size !== 2) fail();
  for (const [name, hash] of Object.entries(files)) {
    const value = await bytes(`${executor ? "dist/" : ""}packages/identity-finalization-runtime/${name}`, 1024 * 1024);
    if (createHash("sha256").update(value).digest("hex") !== hash) fail();
  }
  if (executor) {
    const revision = (await bytes("GIT_COMMIT", 41)).toString("utf8");
    if (!/^[a-f0-9]{40}\n$/.test(revision)) fail();
    const compiled = (await bytes("dist/apps/identity-adapter/src/generated/iam-organization-reconciliation-compiled-revision.js", 16384)).toString("utf8");
    if (!compiled.includes(`export const ORGANIZATION_RECONCILIATION_COMPILED_BUILD_REVISION = ${JSON.stringify(revision.trim())};`)) fail();
  }
  process.stdout.write(JSON.stringify({ verified: true, upstreamCommit: upstream, executorLayout: executor }) + "\n");
} catch {
  process.stderr.write("MIGRATION_PINNED_RUNTIME_MISMATCH\n");
  process.exitCode = 2;
}
