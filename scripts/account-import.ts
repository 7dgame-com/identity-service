import { connectAccountImportDatabases, importIdentityAccounts } from "../apps/identity-adapter/src/identity-account-import.js";
import { readProfileSelectionFile } from "../apps/identity-adapter/src/identity-profile-manifest-file.js";
import { ProfileMigrationError } from "../apps/identity-adapter/src/identity-profile-migration.js";
import { AccountImportConstraintError } from "../apps/identity-adapter/src/identity-account-constraints.js";

async function main() {
  const args = process.argv.slice(2);
  if (args.some((arg) => arg !== "--apply" && arg !== "--dry-run" && !arg.startsWith("--import-key=")&&!arg.startsWith("--profile-selection="))
    || args.filter(arg=>arg.startsWith("--profile-selection=")).length>1) throw new Error("Usage: account-import [--dry-run|--apply] --import-key=<unique-cutover-key> [--profile-selection=<reviewed.json>]");
  const importKey = args.find((arg) => arg.startsWith("--import-key="))?.slice("--import-key=".length);
  if (!importKey) throw new Error("An explicit --import-key is required.");
  const profileSelection=await readProfileSelectionFile(args.find(arg=>arg.startsWith("--profile-selection="))?.slice("--profile-selection=".length));
  const { source, target } = await connectAccountImportDatabases();
  try {
    console.log(JSON.stringify(await importIdentityAccounts(source, target, { importKey,profileSelection, apply: args.includes("--apply") && !args.includes("--dry-run") })));
  } finally {
    await Promise.all([source.end(), target.end()]);
  }
}
main().catch((error) => {
  if(error instanceof ProfileMigrationError)console.error(JSON.stringify({code:error.code,...error.details}));
  else if(error instanceof AccountImportConstraintError)console.error(JSON.stringify({code:error.code,table:error.table,index:error.index,groups:error.groups}));
  else console.error("Account import failed. Check schema, database permissions, empty target, and identity uniqueness; credential-bearing SQL is never logged.");
  process.exitCode = 1;
});
