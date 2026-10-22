import {
  runIdentityActivateOperation,
  IdentityActivationOperationError,
} from "./lib/identity-activate-operation.js";
import { isDirectCli } from "./lib/direct-cli.js";
import { IdentityActivationError } from "../apps/identity-adapter/src/identity-activation.js";

export { runIdentityActivateOperation, IdentityActivationOperationError };
if (isDirectCli(import.meta.url)) {
  try {
    const result = await runIdentityActivateOperation(process.argv.slice(2));
    console.log("help" in result ? result.help : JSON.stringify(result));
    if ("outcome" in result && result.outcome === "unknown")
      process.exitCode = 3;
  } catch (error) {
    console.error(
      JSON.stringify(
        error instanceof IdentityActivationOperationError
          ? error.failure
          : {
              errorCode:
                error instanceof IdentityActivationError
                  ? error.code
                  : "ACTIVATION_OPERATION_FAILED",
              authority: "unconfirmed",
              statusRequired: false,
            },
      ),
    );
    process.exitCode =
      error instanceof IdentityActivationOperationError ? error.exitCode : 1;
  }
}
