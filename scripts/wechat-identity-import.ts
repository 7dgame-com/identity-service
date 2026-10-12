import { readFile, stat } from "node:fs/promises";
import { connectAccountImportDatabases } from "../apps/identity-adapter/src/identity-account-import.js";
import {
  importReviewedYiiWechatBindings,
  importWechatIdentities,
} from "../apps/identity-adapter/src/identity-wechat-import.js";

async function main() {
  const args = process.argv.slice(2);
  if (args.includes("--help")) {
    console.log(
      "wechat-identity-import --import-key=<cutover-key> [--yii-manifest=<reviewed-json>] [--max-rows=<1..100000>] [--apply|--dry-run]. Default: dry-run. Apply private binary schema migration before either mode; Yii manifest mode needs the old Yii DB as readonly source.",
    );
    return;
  }
  if (
    args.some(
      (arg) =>
        !["--apply", "--dry-run"].includes(arg) &&
        !["--import-key=", "--yii-manifest=", "--max-rows="].some((prefix) =>
          arg.startsWith(prefix),
        ),
    )
  )
    throw new Error("Unknown import argument");
  const value = (prefix: string) =>
    args.find((arg) => arg.startsWith(prefix))?.slice(prefix.length);
  const key = value("--import-key=");
  if (!key) throw new Error("An explicit import key is required");
  const maxRows =
    value("--max-rows=") === undefined
      ? undefined
      : Number(value("--max-rows="));
  if (
    maxRows !== undefined &&
    (!Number.isSafeInteger(maxRows) || maxRows < 1 || maxRows > 100000)
  )
    throw new Error("Invalid row bound");
  const manifestPath = value("--yii-manifest=");
  let manifest: unknown;
  if (manifestPath !== undefined) {
    if (!manifestPath || (await stat(manifestPath)).size > 16 * 1024 * 1024)
      throw new Error("Invalid manifest size");
    manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  }
  const { source, target } = await connectAccountImportDatabases();
  try {
    const options = {
      importKey: key,
      maxRows,
      apply: args.includes("--apply") && !args.includes("--dry-run"),
    };
    const result =
      manifestPath !== undefined
        ? await importReviewedYiiWechatBindings(
            source,
            target,
            manifest,
            options,
          )
        : await importWechatIdentities(source, target, options);
    console.log(JSON.stringify(result));
  } finally {
    await Promise.all([source.end(), target.end()]);
  }
}
main().catch(() => {
  console.error(
    "WeChat identity import failed; check staging authority, private binary schema, reviewed evidence and mapping conflicts. No provider identifiers, credentials or SQL are logged.",
  );
  process.exitCode = 1;
});
