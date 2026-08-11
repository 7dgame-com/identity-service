import { constants as fsConstants } from "node:fs";
import { lstat, open } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const FULL_BUILD_REVISION = /^[a-f0-9]{40}$/;
const outputPath = fileURLToPath(new URL(
  "../apps/identity-adapter/src/generated/iam-organization-reconciliation-compiled-revision.ts",
  import.meta.url
));

const args = process.argv.slice(2);
const checkOnly = args[0] === "--check";
const revision = checkOnly ? args[1] : args[0];

if (args.length !== (checkOnly ? 2 : 1) || !FULL_BUILD_REVISION.test(revision ?? "")) {
  process.stderr.write("A full lowercase 40-character BUILD_REVISION is required.\n");
  process.exitCode = 2;
} else if (!checkOnly) {
  await writeGeneratedRevision(revision);
}

async function writeGeneratedRevision(value) {
  const before = await lstat(outputPath);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1) {
    throw new Error("The compiled revision target is not an ordinary source file.");
  }
  const flags = fsConstants.O_WRONLY |
    (typeof fsConstants.O_NOFOLLOW === "number" ? fsConstants.O_NOFOLLOW : 0);
  const handle = await open(outputPath, flags);
  try {
    const opened = await handle.stat();
    if (!opened.isFile() || opened.nlink !== 1 ||
      opened.dev !== before.dev || opened.ino !== before.ino) {
      throw new Error("The compiled revision target changed during generation.");
    }
    await handle.truncate(0);
    await handle.writeFile(renderGeneratedModule(value), "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
}

function renderGeneratedModule(value) {
  return `/*\n` +
    ` * Generated only by scripts/generate-iam-organization-reconciliation-compiled-revision.mjs\n` +
    ` * during an immutable container build. Do not edit or source this value\n` +
    ` * from argv, environment variables, evidence, or runtime configuration.\n` +
    ` */\n` +
    `export const ORGANIZATION_RECONCILIATION_COMPILED_BUILD_REVISION: string | null = ${JSON.stringify(value)};\n`;
}
