import { readFile, lstat, writeFile } from "node:fs/promises";
import { exportLegacyRefreshCredentials } from "../apps/identity-adapter/src/legacy-refresh-credential-manifest.js";

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args.length === 1 && args[0] === "--help") { console.log("Usage: legacy-refresh-credential-export --snapshot=<protected.json> --out=<new-protected-manifest.json>"); return; }
  if (args.length !== 2 || args.filter(arg => arg.startsWith("--snapshot=")).length !== 1 || args.filter(arg => arg.startsWith("--out=")).length !== 1) throw new Error("Invalid arguments.");
  const filename = args.find(arg => arg.startsWith("--snapshot="))!.slice(11), output = args.find(arg => arg.startsWith("--out="))!.slice(6);
  const metadata = await lstat(filename);
  if (!metadata.isFile() || metadata.size > 64 * 1024 * 1024 || (metadata.mode & 0o077) !== 0) throw new Error("A bounded owner-only regular snapshot file is required.");
  const exported = exportLegacyRefreshCredentials(JSON.parse(await readFile(filename, "utf8")));
  await writeFile(output, JSON.stringify(exported.manifest, null, 2) + "\n", { mode: 0o600, flag: "wx" });
  console.log(JSON.stringify({ written: true, ...exported.report }));
}
main().catch(() => { console.error("Offline Yii AR refresh export failed; credential-bearing input and existing files were not changed."); process.exitCode = 1; });
