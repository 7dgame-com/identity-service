import { runAllocatorHighwaterOperation } from "./lib/allocator-highwater-operation.js";
import { isDirectCli } from "./lib/direct-cli.js";
import { AllocatorError } from "../apps/identity-adapter/src/identity-allocator-manifest.js";
import {
  MigrationReportWriteError,
  MigrationResourceCloseError,
} from "../apps/identity-adapter/src/identity-migration-resources.js";

export { runAllocatorHighwaterOperation };
if (isDirectCli(import.meta.url)) {
  try {
    const result = await runAllocatorHighwaterOperation(process.argv.slice(2));
    console.log("help" in result ? result.help : JSON.stringify(result));
  } catch (error) {
    console.error(
      JSON.stringify({
        success: false,
        code:
          error instanceof MigrationResourceCloseError ||
          error instanceof MigrationReportWriteError
            ? error.code
            : error instanceof AllocatorError
              ? error.code
              : "ALLOCATOR_OPERATION_FAILED",
        ...(error instanceof MigrationResourceCloseError ||
        error instanceof MigrationReportWriteError
          ? { outcome: "unknown" }
          : {}),
        automaticRetry: false,
        authorityActivated: false,
      }),
    );
    process.exitCode =
      error instanceof MigrationResourceCloseError ||
      error instanceof MigrationReportWriteError
        ? 3
        : 1;
  }
}
