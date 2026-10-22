import { runAccountSyncOperation } from "./lib/account-sync-operation.js";
import { isDirectCli } from "./lib/direct-cli.js";
import { ProfileMigrationError } from "../apps/identity-adapter/src/identity-profile-migration.js";
import { AccountImportConstraintError } from "../apps/identity-adapter/src/identity-account-constraints.js";
import {
  MigrationReportWriteError,
  MigrationResourceCloseError,
} from "../apps/identity-adapter/src/identity-migration-resources.js";

export { runAccountSyncOperation };
if (isDirectCli(import.meta.url)) {
  try {
    const result = await runAccountSyncOperation(process.argv.slice(2));
    console.log("help" in result ? result.help : JSON.stringify(result));
  } catch (error) {
    if (
      error instanceof MigrationResourceCloseError ||
      error instanceof MigrationReportWriteError
    )
      console.error(
        JSON.stringify({
          code: error.code,
          outcome: error.outcome,
          automaticRetry: false,
        }),
      );
    else if (error instanceof ProfileMigrationError)
      console.error(JSON.stringify({ code: error.code, ...error.details }));
    else if (error instanceof AccountImportConstraintError)
      console.error(
        JSON.stringify({
          code: error.code,
          table: error.table,
          index: error.index,
          groups: error.groups,
        }),
      );
    else
      console.error(
        "Account sync failed. Check staging authority, baseline drift, source schema and change budget; credential-bearing SQL is never logged.",
      );
    process.exitCode =
      error instanceof MigrationResourceCloseError ||
      error instanceof MigrationReportWriteError
        ? 3
        : 1;
  }
}
