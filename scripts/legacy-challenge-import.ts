import { readFile, stat } from "node:fs/promises";
import { connectLegacySessionImportTarget } from "../apps/identity-adapter/src/legacy-session-import.js";
import { importLegacyChallenges } from "../apps/identity-adapter/src/legacy-challenge-import.js";

async function main() {
  const args = process.argv.slice(2);
  if (args.includes("--help")) {
    console.log(
      "Usage: NODE_ENV=staging IDENTITY_DATA_SOURCE=identity tsx scripts/legacy-challenge-import.ts --file=<offline-json> [--apply|--dry-run]\nDefault dry-run. Offline input only; never connects to Redis or prints credentials.",
    );
    return;
  }
  if (
    args.some(
      (arg) =>
        !["--apply", "--dry-run"].includes(arg) && !arg.startsWith("--file="),
    )
  )
    throw new Error("Invalid arguments.");
  const files = args.filter((arg) => arg.startsWith("--file="));
  if (files.length !== 1 || !files[0].slice(7))
    throw new Error("Offline file required.");
  const filename = files[0].slice(7);
  if ((await stat(filename)).size > 64 * 1024 * 1024)
    throw new Error("Manifest size limit exceeded.");
  const payload: unknown = JSON.parse(await readFile(filename, "utf8"));
  const target = await connectLegacySessionImportTarget();
  try {
    console.log(
      JSON.stringify(
        await importLegacyChallenges(target, payload, {
          apply: args.includes("--apply") && !args.includes("--dry-run"),
        }),
      ),
    );
  } finally {
    await target.end();
  }
}
main().catch(() => {
  console.error(
    "Challenge import failed. Check final snapshot evidence, reviewed associations, schema and staging fence. Credential-bearing input and SQL are never logged.",
  );
  process.exitCode = 1;
});
