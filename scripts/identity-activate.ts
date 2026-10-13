import { constants } from "node:fs";
import { open, type FileHandle } from "node:fs/promises";
import mysql, { type Connection, type RowDataPacket } from "mysql2/promise";
import { loadConfig } from "../apps/identity-adapter/src/config.js";
import { activateExplicitIdentity, immutableIdentityRevision, inspectExplicitActivation, IdentityActivationError } from "../apps/identity-adapter/src/identity-activation.js";

const help = "identity-activate --status | --expected-proof-sha256=<64hex> --expected-revision=<40hex> --deadline=<ISO-UTC> --report=<new0600.jsonl> [--apply]. Default: dry-run. Fixed development private database only.";
let file: FileHandle | undefined, connection: Connection | undefined;
let commitAcknowledged = false;
let commitUnknown = false;
async function record(value: unknown) {
  if (!file) throw new Error("Activation report is not open");
  await file.writeFile(`${JSON.stringify(value)}\n`); await file.sync();
}
async function main() {
  const args = process.argv.slice(2);
  if (args.length === 1 && args[0] === "--help") { console.log(help); return; }
  if (new Set(args.map(arg => arg.split("=")[0])).size !== args.length || args.some(arg =>
    !["--status", "--apply"].includes(arg) && !["--expected-proof-sha256=", "--expected-revision=", "--deadline=", "--report="].some(prefix => arg.startsWith(prefix)))) throw new Error(help);
  const value = (prefix: string) => args.find(arg => arg.startsWith(prefix))?.slice(prefix.length);
  const status = args.includes("--status"), apply = args.includes("--apply");
  if (status && (apply || args.length !== 1)) throw new Error(help);
  if (!status && (!value("--report=") || !value("--expected-proof-sha256=") || !value("--expected-revision=") || !value("--deadline="))) throw new Error(help);
  const compiledRevision = immutableIdentityRevision(), config = loadConfig(), db = config.identityDb;
  if (config.dataSource !== "identity" || config.activationMode !== "explicit" || db.host !== "10.206.0.5" || db.port !== 3306
    || db.name !== "xrugc_identity_dev" || db.user !== "identity_dev") throw new IdentityActivationError("ACTIVATION_FIXED_DEVELOPMENT_TARGET_REQUIRED");
  if (!status) {
    file = await open(value("--report=")!, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    const st = await file.stat();
    if (!st.isFile() || st.nlink !== 1 || (st.mode & 0o777) !== 0o600 || st.uid !== process.getuid?.()) throw new IdentityActivationError("ACTIVATION_PROTECTED_REPORT_REQUIRED");
    await record({ version: 1, operation: "explicit-identity-activation", phase: "prepared", compiledRevision, apply });
  }
  connection = await mysql.createConnection({ host: db.host, port: db.port, database: db.name, user: db.user, password: db.password,
    timezone: "Z", connectTimeout: 5000, multipleStatements: false });
  const [principal] = await connection.query<RowDataPacket[]>("SELECT SUBSTRING_INDEX(CURRENT_USER(),'@',1) AS principal");
  if (principal[0]?.principal !== "identity_dev") throw new IdentityActivationError("ACTIVATION_FIXED_DEVELOPMENT_PRINCIPAL_REQUIRED");
  // A lock wait can consume the budget; the transaction checks the DB clock again after obtaining the fence.
  await connection.query("SET SESSION innodb_lock_wait_timeout=5");
  if (status) {
    console.log(JSON.stringify({ version: 1, compiledRevision, ...(await inspectExplicitActivation(connection)), readonly: true }));
    return;
  }
  const result = await activateExplicitIdentity({ connection, apply, expectedProofSha256: value("--expected-proof-sha256=")!,
    expectedRevision: value("--expected-revision=")!, deadline: value("--deadline=")!,
    onCommitIntent: async intent => { await record({ phase: "commit_intent", receipt: intent }); } });
  commitAcknowledged = result.outcome === "activated" || result.outcome === "already_active";
  commitUnknown = result.outcome === "unknown";
  await record({ phase: "result", ...result });
  console.log(JSON.stringify(result));
  if (result.outcome === "unknown") process.exitCode = 3;
}
try { await main(); }
catch (error) {
  const code = commitAcknowledged ? "ACTIVATION_COMMITTED_REPORT_FAILED" : commitUnknown ? "ACTIVATION_COMMIT_RESULT_UNKNOWN" : error instanceof IdentityActivationError ? error.code : "ACTIVATION_OPERATION_FAILED";
  // No SQL, connection credentials, users, or arbitrary exception text is emitted.
  const failure = { errorCode: code, authority: commitAcknowledged ? "identity" : "unconfirmed", statusRequired: commitAcknowledged || commitUnknown };
  if (file) { try { await record({ phase: "failure", ...failure }); } catch { /* Preserve the existing durable intent; do not retry the operation. */ } }
  console.error(JSON.stringify(failure));
  process.exitCode = commitAcknowledged || commitUnknown ? 3 : 1;
} finally {
  try { await connection?.end(); } catch { /* An unknown COMMIT deliberately destroyed this connection. */ }
  finally { await file?.close(); }
}
