import { resolve } from "node:path";
import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";

/** Importing an operation or its compatibility wrapper never starts a migration. */
export function isDirectCli(moduleUrl: string): boolean {
  if (!process.argv[1]) return false;
  try {
    return (
      realpathSync(resolve(process.argv[1])) ===
      realpathSync(fileURLToPath(moduleUrl))
    );
  } catch {
    return false;
  }
}
