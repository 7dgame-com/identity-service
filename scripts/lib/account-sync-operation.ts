import { connectAccountImportDatabases } from "../../apps/identity-adapter/src/identity-account-import.js";
import { syncIdentityAccounts } from "../../apps/identity-adapter/src/identity-account-sync.js";
import { readProfileSelectionFile } from "../../apps/identity-adapter/src/identity-profile-manifest-file.js";
import {
  withMigrationResources,
  writeMigrationReport,
} from "../../apps/identity-adapter/src/identity-migration-resources.js";

export const accountSyncUsage =
  "account-sync [--dry-run|--apply] --max-changes=<1..100000> [--max-rows=<1..1000000>] [--profile-selection=<reviewed.json>] [--report=<new0600.json>]";

/** Awaited business entry. It neither grants admission nor prints or exits. */
export async function runAccountSyncOperation(args: readonly string[]) {
  if (args.includes("--help")) return { help: accountSyncUsage };
  if (
    args.some(
      (arg) =>
        !["--apply", "--dry-run"].includes(arg) &&
        !/^--max-(changes|rows)=\d+$/.test(arg) &&
        !arg.startsWith("--profile-selection=") &&
        !arg.startsWith("--report="),
    ) ||
    args.filter((arg) => arg.startsWith("--max-changes=")).length !== 1 ||
    args.filter((arg) => arg.startsWith("--max-rows=")).length > 1 ||
    args.filter((arg) => arg.startsWith("--profile-selection=")).length > 1 ||
    args.filter((arg) => arg.startsWith("--report=")).length > 1 ||
    args.includes("--report=")
  )
    throw new Error(accountSyncUsage);
  const value = (prefix: string) =>
    args.find((arg) => arg.startsWith(prefix))?.slice(prefix.length);
  const profileSelection = await readProfileSelectionFile(
    value("--profile-selection="),
  );
  return withMigrationResources(async (resources) => {
    const { source, target } = await connectAccountImportDatabases(resources);
    const reportPath = value("--report="),
      report = reportPath ? await resources.openReport(reportPath) : undefined;
    const result = await syncIdentityAccounts(source, target, {
      apply: args.includes("--apply") && !args.includes("--dry-run"),
      maxChanges: Number(value("--max-changes=")),
      maxRows:
        value("--max-rows=") === undefined
          ? undefined
          : Number(value("--max-rows=")),
      profileSelection,
    });
    if (report) await writeMigrationReport(report, result);
    return result;
  });
}
