import { connectAccountImportDatabases } from "../apps/identity-adapter/src/identity-account-import.js";
import { syncIdentityAccounts } from "../apps/identity-adapter/src/identity-account-sync.js";
import { readProfileSelectionFile } from "../apps/identity-adapter/src/identity-profile-manifest-file.js";
import { ProfileMigrationError } from "../apps/identity-adapter/src/identity-profile-migration.js";
import { AccountImportConstraintError } from "../apps/identity-adapter/src/identity-account-constraints.js";

async function main() {
  const args = process.argv.slice(2);
  const usage =
    "account-sync [--dry-run|--apply] --max-changes=<1..100000> [--max-rows=<1..1000000>] [--profile-selection=<reviewed.json>]";
  if (args.includes("--help")) {
    console.log(usage);
    return;
  }
  if (
    args.some(
      (arg) =>
        !["--apply", "--dry-run"].includes(arg) &&
        !/^--max-(changes|rows)=\d+$/.test(arg)&&!arg.startsWith("--profile-selection="),
    ) ||
    args.filter((arg) => arg.startsWith("--max-changes=")).length !== 1 ||
    args.filter((arg) => arg.startsWith("--max-rows=")).length > 1||args.filter(arg=>arg.startsWith("--profile-selection=")).length>1
  )
    throw new Error(usage);
  const maxChanges = Number(
    args.find((arg) => arg.startsWith("--max-changes="))!.split("=")[1],
  );
  const maxRowsArg = args.find((arg) => arg.startsWith("--max-rows="));
  const profileSelection=await readProfileSelectionFile(args.find(arg=>arg.startsWith("--profile-selection="))?.slice("--profile-selection=".length));
  const { source, target } = await connectAccountImportDatabases();
  try {
    console.log(
      JSON.stringify(
        await syncIdentityAccounts(source, target, {
          apply: args.includes("--apply") && !args.includes("--dry-run"),
          maxChanges,
          maxRows: maxRowsArg ? Number(maxRowsArg.split("=")[1]) : undefined,
          profileSelection,
        }),
      ),
    );
  } finally {
    await Promise.all([source.end(), target.end()]);
  }
}
main().catch((error) => {
  if(error instanceof ProfileMigrationError)console.error(JSON.stringify({code:error.code,...error.details}));
  else if(error instanceof AccountImportConstraintError)console.error(JSON.stringify({code:error.code,table:error.table,index:error.index,groups:error.groups}));
  else console.error(
    "Account sync failed. Check staging authority, baseline drift, source schema and change budget; credential-bearing SQL is never logged.",
  );
  process.exitCode = 1;
});
