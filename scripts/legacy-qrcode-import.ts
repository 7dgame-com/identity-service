import { readFile, stat, writeFile } from "node:fs/promises";
import {
  exportLegacyQrManifest,
  importLegacyQrManifest,
} from "../apps/identity-adapter/src/legacy-qrcode-import.js";
import { connectLegacySessionImportTarget } from "../apps/identity-adapter/src/legacy-session-import.js";

async function main() {
  const args = process.argv.slice(2);
  const usage =
    "legacy-qrcode-import --file=<offline-json> [--export=<new-manifest.json>|--dry-run|--apply]";
  if (args.includes("--help")) {
    console.log(usage);
    return;
  }
  if (
    args.some(
      (arg) =>
        !["--dry-run", "--apply"].includes(arg) &&
        !arg.startsWith("--file=") &&
        !arg.startsWith("--export="),
    ) ||
    args.filter((arg) => arg.startsWith("--file=")).length !== 1 ||
    args.filter((arg) => arg.startsWith("--export=")).length > 1
  )
    throw new Error(usage);
  const apply = args.includes("--apply") && !args.includes("--dry-run");
  const output = args.find((arg) => arg.startsWith("--export="))?.slice(9);
  if (apply && output) throw new Error(usage);
  if (apply && process.env.NODE_ENV !== "staging")
    throw new Error("Legacy QR state may only be applied in staging.");
  const path = args.find((arg) => arg.startsWith("--file="))!.slice(7);
  if ((await stat(path)).size > 64 * 1024 * 1024)
    throw new Error("Offline QR file exceeds the bounded size.");
  const payload: unknown = JSON.parse(await readFile(path, "utf8"));
  if (output) {
    const manifest = exportLegacyQrManifest(payload);
    await writeFile(output, JSON.stringify(manifest), {
      flag: "wx",
      mode: 0o600,
    });
    console.log(
      JSON.stringify({
        exported: true,
        loginCodes: manifest.login_codes.length,
        wechatScenes: manifest.wechat_scenes.length,
      }),
    );
    return;
  }
  const target = await connectLegacySessionImportTarget();
  try {
    console.log(
      JSON.stringify(await importLegacyQrManifest(target, payload, { apply })),
    );
  } finally {
    await target.end();
  }
}
main().catch(() => {
  console.error(
    "Legacy QR migration failed. Check offline evidence, fixed TTL, staging fence and private account mapping; QR values and SQL are never logged.",
  );
  process.exitCode = 1;
});
