import { constants } from "node:fs";
import { open } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import {
  createOrganizationReconciliationDevelopDualNodePreflightReport
} from "../apps/identity-adapter/src/iam-organization-reconciliation-develop-dual-node-preflight.js";
import type {
  OrganizationReconciliationDevelopSourcePreflightReport
} from "../apps/identity-adapter/src/iam-organization-reconciliation-develop-source-preflight.js";

const MAX_REPORT_BYTES = 1024 * 1024;
const BUILD_REVISION = /^[a-f0-9]{40}$/;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

export const organizationReconciliationDevelopDualNodePreflightHelp = `Usage:
  npm run iam:organization-reconciliation:develop-dual-node-preflight -- \\
    --environment=xrteeth-develop \\
    --expected-build-revision=<40-lowercase-hex> \\
    --node-a-id=<identifier> --node-a-report=<local-json-file> \\
    --node-b-id=<identifier> --node-b-report=<local-json-file>

This command performs no network, database, or write operation. It accepts
exact canonical JSON emitted by two successful xrteeth Develop v3 source
preflights and verifies their structural alignment. Node labels and the
expected revision are caller supplied; hashes are not signatures, collector
identity is not authenticated, production readiness remains false, and the
result does not complete Task 7.2. URL, stdin, final-component symlink,
non-regular, oversized,
non-canonical, failed, stale, future, or A/B-spliced inputs fail closed.
`;

export interface OrganizationReconciliationDevelopDualNodePreflightCliIo {
  readonly readReportFile: (path: string) => Promise<unknown>;
  readonly now: () => Date;
  readonly stdout: (text: string) => void;
  readonly stderr: (text: string) => void;
}

export async function runOrganizationReconciliationDevelopDualNodePreflightCli(
  argv: readonly string[],
  io: OrganizationReconciliationDevelopDualNodePreflightCliIo = {
    readReportFile: readCanonicalDevelopPreflightReportFile,
    now: () => new Date(),
    stdout: (text) => process.stdout.write(text),
    stderr: (text) => process.stderr.write(text)
  }
): Promise<number> {
  if (argv.length === 1 && argv[0] === "--help") {
    io.stdout(organizationReconciliationDevelopDualNodePreflightHelp);
    return 0;
  }
  const options = parseArguments(argv);
  if (!options) {
    io.stderr("The dual-node Develop source-preflight arguments are invalid.\n");
    return 2;
  }
  try {
    const [first, second] = await Promise.all([
      io.readReportFile(options.nodeAReport),
      io.readReportFile(options.nodeBReport)
    ]);
    const report = createOrganizationReconciliationDevelopDualNodePreflightReport([
      {
        nodeId: options.nodeAId,
        report: first as OrganizationReconciliationDevelopSourcePreflightReport
      },
      {
        nodeId: options.nodeBId,
        report: second as OrganizationReconciliationDevelopSourcePreflightReport
      }
    ], {
      expectedBuildRevision: options.expectedBuildRevision,
      now: io.now()
    });
    io.stdout(`${JSON.stringify(report, null, 2)}\n`);
    return 0;
  } catch {
    io.stderr("The dual-node Develop source-preflight evidence is invalid or misaligned.\n");
    return 2;
  }
}

export async function readCanonicalDevelopPreflightReportFile(path: string): Promise<unknown> {
  if (!safeLocalPath(path)) throw new Error("invalid-local-report");
  if (typeof constants.O_NONBLOCK !== "number") throw new Error("invalid-local-report");
  const flags = constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK;
  const handle = await open(path, flags);
  let content: Buffer | undefined;
  try {
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.size < 2n || before.size > BigInt(MAX_REPORT_BYTES) || before.nlink !== 1n) {
      throw new Error("invalid-local-report");
    }
    content = Buffer.alloc(Number(before.size));
    let offset = 0;
    while (offset < content.length) {
      const { bytesRead } = await handle.read(content, offset, content.length - offset, offset);
      if (bytesRead < 1) throw new Error("invalid-local-report");
      offset += bytesRead;
    }
    const overflow = Buffer.alloc(1);
    try {
      if ((await handle.read(overflow, 0, 1, content.length)).bytesRead !== 0) {
        throw new Error("invalid-local-report");
      }
    } finally {
      overflow.fill(0);
    }
    const after = await handle.stat({ bigint: true });
    if (
      before.dev !== after.dev ||
      before.ino !== after.ino ||
      before.size !== after.size ||
      before.mtimeNs !== after.mtimeNs
    ) throw new Error("invalid-local-report");
    const text = content.toString("utf8");
    if (Buffer.byteLength(text, "utf8") !== content.length) throw new Error("invalid-local-report");
    const parsed = JSON.parse(text) as unknown;
    if (`${JSON.stringify(parsed, null, 2)}\n` !== text) throw new Error("invalid-local-report");
    return parsed;
  } finally {
    content?.fill(0);
    await handle.close();
  }
}

interface ParsedArguments {
  readonly expectedBuildRevision: string;
  readonly nodeAId: string;
  readonly nodeAReport: string;
  readonly nodeBId: string;
  readonly nodeBReport: string;
}

function parseArguments(argv: readonly string[]): ParsedArguments | undefined {
  if (argv.length !== 6) return undefined;
  const values = new Map<string, string>();
  for (const argument of argv) {
    const separator = argument.indexOf("=");
    if (separator < 3) return undefined;
    const key = argument.slice(0, separator);
    const value = argument.slice(separator + 1);
    if (values.has(key) || value.length < 1) return undefined;
    values.set(key, value);
  }
  if (
    values.size !== 6 ||
    values.get("--environment") !== "xrteeth-develop" ||
    !BUILD_REVISION.test(values.get("--expected-build-revision") ?? "") ||
    !IDENTIFIER.test(values.get("--node-a-id") ?? "") ||
    !IDENTIFIER.test(values.get("--node-b-id") ?? "") ||
    !safeLocalPath(values.get("--node-a-report") ?? "") ||
    !safeLocalPath(values.get("--node-b-report") ?? "")
  ) return undefined;
  return Object.freeze({
    expectedBuildRevision: values.get("--expected-build-revision")!,
    nodeAId: values.get("--node-a-id")!,
    nodeAReport: values.get("--node-a-report")!,
    nodeBId: values.get("--node-b-id")!,
    nodeBReport: values.get("--node-b-report")!
  });
}

function safeLocalPath(path: string): boolean {
  return path.length > 0 && path.length <= 4_096 && !/[\u0000-\u001f\u007f]/.test(path) && path !== "-" &&
    !/^[A-Za-z][A-Za-z0-9+.-]*:/.test(path);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = await runOrganizationReconciliationDevelopDualNodePreflightCli(process.argv.slice(2));
}
