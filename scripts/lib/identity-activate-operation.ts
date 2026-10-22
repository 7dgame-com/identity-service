import mysql, { type RowDataPacket } from "mysql2/promise";
import { loadConfig } from "../../apps/identity-adapter/src/config.js";
import {
  activateExplicitIdentity,
  immutableIdentityRevision,
  inspectExplicitActivation,
  IdentityActivationError,
} from "../../apps/identity-adapter/src/identity-activation.js";
import {
  MigrationResourceCloseError,
  MigrationReportWriteError,
  withMigrationResources,
  writeMigrationReport,
  type MigrationReportFile,
} from "../../apps/identity-adapter/src/identity-migration-resources.js";

export const identityActivateUsage =
  "identity-activate --status | --expected-proof-sha256=<64hex> --expected-revision=<40hex> --deadline=<ISO-UTC> --report=<new0600.jsonl> [--apply]. Default: dry-run. Fixed development private database only.";
export class IdentityActivationOperationError extends Error {
  readonly automaticRetry = false;
  readonly outcome: "failed" | "unknown";
  constructor(
    readonly failure: {
      errorCode: string;
      authority: "identity" | "unconfirmed";
      statusRequired: boolean;
    },
    readonly exitCode: 1 | 3,
    options?: ErrorOptions,
  ) {
    super(failure.errorCode, options);
    this.name = "IdentityActivationOperationError";
    this.outcome = exitCode === 3 ? "unknown" : "failed";
  }
}

/** Awaited business entry, with invocation-local receipt state. No admission authority is created here. */
export async function runIdentityActivateOperation(args: readonly string[]) {
  if (args.length === 1 && args[0] === "--help")
    return { help: identityActivateUsage };
  if (
    new Set(args.map((arg) => arg.split("=")[0])).size !== args.length ||
    args.some(
      (arg) =>
        !["--status", "--apply"].includes(arg) &&
        ![
          "--expected-proof-sha256=",
          "--expected-revision=",
          "--deadline=",
          "--report=",
        ].some((prefix) => arg.startsWith(prefix)),
    )
  )
    throw new Error(identityActivateUsage);
  const value = (prefix: string) =>
    args.find((arg) => arg.startsWith(prefix))?.slice(prefix.length);
  const status = args.includes("--status"),
    apply = args.includes("--apply");
  if (status && (apply || args.length !== 1))
    throw new Error(identityActivateUsage);
  if (
    !status &&
    (!value("--report=") ||
      !value("--expected-proof-sha256=") ||
      !value("--expected-revision=") ||
      !value("--deadline="))
  )
    throw new Error(identityActivateUsage);
  const compiledRevision = immutableIdentityRevision(),
    config = loadConfig(),
    db = config.identityDb;
  if (
    config.dataSource !== "identity" ||
    config.activationMode !== "explicit" ||
    db.host !== "10.206.0.5" ||
    db.port !== 3306 ||
    db.name !== "xrugc_identity_dev" ||
    db.user !== "identity_dev"
  )
    throw new IdentityActivationError(
      "ACTIVATION_FIXED_DEVELOPMENT_TARGET_REQUIRED",
    );
  let commitAcknowledged = false,
    commitUnknown = false;
  // Only fixed safe codes escape. Preserve report failure across a failed attempt
  // to append the failure record itself; never reinterpret lost durability as retryable.
  const reportFailed = (error: unknown): boolean =>
    error instanceof MigrationReportWriteError ||
    (error instanceof AggregateError && error.errors.some(reportFailed));
  const failure = (error: unknown) => ({
    errorCode: commitAcknowledged
      ? "ACTIVATION_COMMITTED_REPORT_FAILED"
      : commitUnknown
        ? "ACTIVATION_COMMIT_RESULT_UNKNOWN"
        : reportFailed(error)
          ? "MIGRATION_REPORT_WRITE_UNKNOWN"
          : error instanceof IdentityActivationError
            ? error.code
            : "ACTIVATION_OPERATION_FAILED",
    authority: commitAcknowledged
      ? ("identity" as const)
      : ("unconfirmed" as const),
    statusRequired: commitAcknowledged || commitUnknown || reportFailed(error),
  });
  try {
    return await withMigrationResources(async (resources) => {
      let file: MigrationReportFile | undefined;
      try {
        if (!status) {
          file = await resources.openReport(value("--report=")!);
          await writeMigrationReport(file, {
            version: 1,
            operation: "explicit-identity-activation",
            phase: "prepared",
            compiledRevision,
            apply,
          });
        }
        const connection = resources.connection(
          await mysql.createConnection({
            host: db.host,
            port: db.port,
            database: db.name,
            user: db.user,
            password: db.password,
            timezone: "Z",
            connectTimeout: 5000,
            multipleStatements: false,
          }),
        );
        const [principal] = await connection.query<RowDataPacket[]>(
          "SELECT SUBSTRING_INDEX(CURRENT_USER(),'@',1) AS principal",
        );
        if (principal[0]?.principal !== "identity_dev")
          throw new IdentityActivationError(
            "ACTIVATION_FIXED_DEVELOPMENT_PRINCIPAL_REQUIRED",
          );
        // Retain the existing fence/lock-wait behavior. This wrapper acquires no additional lock.
        await connection.query("SET SESSION innodb_lock_wait_timeout=5");
        if (status)
          return {
            version: 1,
            compiledRevision,
            ...(await inspectExplicitActivation(connection)),
            readonly: true,
          };
        const report = file!;
        const result = await activateExplicitIdentity({
          connection,
          apply,
          expectedProofSha256: value("--expected-proof-sha256=")!,
          expectedRevision: value("--expected-revision=")!,
          deadline: value("--deadline=")!,
          onCommitIntent: async (intent) => {
            await writeMigrationReport(report, {
              phase: "commit_intent",
              receipt: intent,
            });
          },
        });
        commitAcknowledged =
          result.outcome === "activated" || result.outcome === "already_active";
        commitUnknown = result.outcome === "unknown";
        await writeMigrationReport(report, { phase: "result", ...result });
        return result;
      } catch (error) {
        if (file) {
          try {
            await writeMigrationReport(file, {
              phase: "failure",
              ...failure(error),
            });
          } catch (reportError) {
            throw new AggregateError(
              [error, reportError],
              "ACTIVATION_FAILURE_REPORT_FAILED",
            );
          }
        }
        throw error;
      }
    });
  } catch (error) {
    if (error instanceof MigrationResourceCloseError)
      throw new IdentityActivationOperationError(
        {
          errorCode: error.code,
          authority: commitAcknowledged ? "identity" : "unconfirmed",
          statusRequired: true,
        },
        3,
        { cause: error },
      );
    throw new IdentityActivationOperationError(
      failure(error),
      commitAcknowledged || commitUnknown || reportFailed(error) ? 3 : 1,
      { cause: error },
    );
  }
}
