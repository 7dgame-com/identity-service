import { readFile, stat } from "node:fs/promises";
import {
  connectLegacySessionImportTarget,
  importLegacySessions,
} from "../apps/identity-adapter/src/legacy-session-import.js";
import { LegacyIdentityReader } from "../apps/identity-adapter/src/legacy-identity.reader.js";

async function main() {
  const args = process.argv.slice(2);
  if (args.includes("--help")) {
    console.log(
      "Usage: NODE_ENV=staging IDENTITY_DATA_SOURCE=identity tsx scripts/legacy-session-import.ts --file=<offline-json> [--dry-run|--apply]\nDefault: dry-run. No Redis access, token issuance or token/lifetime output.",
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
  const fileArgs = args.filter((arg) => arg.startsWith("--file="));
  if (fileArgs.length !== 1 || !fileArgs[0].slice(7))
    throw new Error("An offline manifest file is required.");
  const apply = args.includes("--apply") && !args.includes("--dry-run");
  if (apply && process.env.NODE_ENV !== "staging")
    throw new Error("Legacy sessions may only be applied in staging.");
  const filename = fileArgs[0].slice(7);
  if ((await stat(filename)).size > 64 * 1024 * 1024)
    throw new Error("Legacy session manifest exceeds the size limit.");
  const manifest: unknown = JSON.parse(await readFile(filename, "utf8"));
  const target = await connectLegacySessionImportTarget();
  const reader = new LegacyIdentityReader();
  try {
    console.log(
      JSON.stringify(await importLegacySessions(target, manifest, { apply,
        assertDeviceSnAuthorized: (deviceSnId, userId) => reader.assertDeviceSnAuthorized(deviceSnId, userId, true) })),
    );
  } finally {
    await target.end();
    await reader.onModuleDestroy();
  }
}

main().catch(() => {
  console.error(
    "Legacy session import failed. Check staging mode, manifest schema, existing accounts and client scope. Credential-bearing input and SQL are never logged.",
  );
  process.exitCode = 1;
});
