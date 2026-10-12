import { readFile, lstat } from "node:fs/promises";
import { importLegacyRefreshCredentials } from "../apps/identity-adapter/src/legacy-refresh-credential-import.js";
import { connectLegacySessionImportTarget } from "../apps/identity-adapter/src/legacy-session-import.js";

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args.length === 1 && args[0] === "--help") {
    console.log("Usage: NODE_ENV=staging IDENTITY_DATA_SOURCE=identity legacy-refresh-credential-import --file=<protected-manifest.json> [--dry-run|--apply]"); return;
  }
  if (args.filter(arg => arg.startsWith("--file=")).length !== 1 || args.some(arg => !arg.startsWith("--file=") && !["--dry-run", "--apply"].includes(arg)) ||
      (args.includes("--dry-run") && args.includes("--apply")) || new Set(args).size !== args.length) throw new Error("Invalid arguments.");
  const apply = args.includes("--apply");
  if (apply && process.env.NODE_ENV !== "staging") throw new Error("Staging is required.");
  const filename = args.find(arg => arg.startsWith("--file="))!.slice(7), metadata = await lstat(filename);
  if (!metadata.isFile() || metadata.size > 64 * 1024 * 1024 || (metadata.mode & 0o077) !== 0) throw new Error("A bounded owner-only regular manifest is required.");
  const payload: unknown = JSON.parse(await readFile(filename, "utf8")), target = await connectLegacySessionImportTarget();
  try { console.log(JSON.stringify(await importLegacyRefreshCredentials(target, payload, { apply }))); }
  finally { await target.end(); }
}
main().catch(() => { console.error("Offline Yii AR refresh import failed; review source account evidence, staging authority and existing tombstones. Credential input and SQL are never logged."); process.exitCode = 1; });
