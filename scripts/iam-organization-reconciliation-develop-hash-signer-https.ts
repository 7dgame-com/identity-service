import { isAbsolute, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import {
  startOrganizationReconciliationDevelopHashSignerHttpsLauncher,
  type OrganizationReconciliationDevelopHashSignerHttpsLogEvent
} from "../apps/identity-adapter/src/iam-organization-reconciliation-develop-hash-signer-https-launcher.js";

export const organizationReconciliationDevelopHashSignerHttpsHelp = `Usage:
  npm run iam:organization-reconciliation:develop-hash-signer:https -- \\
    --config=<absolute-owner-0600-json-path>

Starts one HTTPS-only xrteeth Develop hash signer from an immutable compiled
trust profile and a separately pinned public trust policy. The config can
select one compiled collector but cannot supply a revision, profile, policy
hash, key fingerprint, key, token, or readiness value. No environment-variable,
HTTP, database, key-generation, publish, Production, or readiness path exists.
`;

export async function runOrganizationReconciliationDevelopHashSignerHttpsCli(
  argv: readonly string[]
): Promise<number> {
  if (Array.isArray(argv) && argv.length === 1 && argv[0] === "--help") {
    process.stdout.write(organizationReconciliationDevelopHashSignerHttpsHelp);
    return 0;
  }
  const configPath = parseConfigPath(argv);
  if (!configPath) {
    writeSanitizedFailure("invalid-arguments");
    return 2;
  }
  try {
    const launcher = await startOrganizationReconciliationDevelopHashSignerHttpsLauncher({
      configPath,
      log: writeSanitizedEvent
    });
    let signalClose = false;
    const close = () => {
      signalClose = true;
      void launcher.close();
    };
    process.once("SIGINT", close);
    process.once("SIGTERM", close);
    try {
      const reason = await launcher.closed;
      return reason === "requested" && signalClose ? 0 : 2;
    } finally {
      process.off("SIGINT", close);
      process.off("SIGTERM", close);
    }
  } catch (error) {
    const failureId = safeFailureId(error);
    writeSanitizedFailure(failureId);
    return 2;
  }
}

function parseConfigPath(argv: readonly string[]): string | undefined {
  if (!Array.isArray(argv) || argv.length !== 1 || typeof argv[0] !== "string" ||
    !argv[0].startsWith("--config=")) return undefined;
  const path = argv[0].slice("--config=".length);
  if (
    path.length < 2 || path.length > 4_096 || /[\u0000-\u001f\u007f]/.test(path) ||
    !isAbsolute(path) || resolve(path) !== path
  ) return undefined;
  return path;
}

function writeSanitizedEvent(event: OrganizationReconciliationDevelopHashSignerHttpsLogEvent): void {
  process.stdout.write(`${JSON.stringify(event)}\n`);
}

function writeSanitizedFailure(failureId: string): void {
  process.stderr.write(`${JSON.stringify(Object.freeze({
    event: "startup-rejected",
    environment: "xrteeth-develop",
    failureId,
    ready: false
  }))}\n`);
}

function safeFailureId(error: unknown): string {
  if (!error || typeof error !== "object") return "startup-rejected";
  const descriptor = Object.getOwnPropertyDescriptor(error, "failureId");
  if (!descriptor || !("value" in descriptor) || typeof descriptor.value !== "string" ||
    !/^[a-z][a-z-]{0,63}$/.test(descriptor.value)) return "startup-rejected";
  return descriptor.value;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = await runOrganizationReconciliationDevelopHashSignerHttpsCli(process.argv.slice(2));
}
