import { connectAccountImportDatabases, importIdentityAccounts } from "../apps/identity-adapter/src/identity-account-import.js";

async function main() {
  const args = process.argv.slice(2);
  if (args.some((arg) => arg !== "--apply" && arg !== "--dry-run" && !arg.startsWith("--import-key="))) throw new Error("Usage: account-import [--dry-run|--apply] --import-key=<unique-cutover-key>");
  const importKey = args.find((arg) => arg.startsWith("--import-key="))?.slice("--import-key=".length);
  if (!importKey) throw new Error("An explicit --import-key is required.");
  const { source, target } = await connectAccountImportDatabases();
  try {
    console.log(JSON.stringify(await importIdentityAccounts(source, target, { importKey, apply: args.includes("--apply") && !args.includes("--dry-run") })));
  } finally {
    await Promise.all([source.end(), target.end()]);
  }
}
main().catch(() => { console.error("Account import failed. Check schema, database permissions, empty target, and identity uniqueness; credential-bearing SQL is never logged."); process.exitCode = 1; });
