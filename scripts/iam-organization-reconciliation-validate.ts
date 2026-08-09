import { readFile } from "node:fs/promises";
import { stat } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import { z } from "zod";
import {
  ORGANIZATION_RECONCILIATION_COLLECTOR_CONTRACT,
  ORGANIZATION_RECONCILIATION_COLLECTOR_CONTRACT_HASH,
  OrganizationReconciliationInput,
  validateOrganizationReconciliation
} from "../apps/identity-adapter/src/iam-organization-reconciliation-validator.js";

export type OrganizationReconciliationCliOptions =
  | { readonly mode: "help" }
  | { readonly mode: "validate"; readonly inputPath: string };

export interface OrganizationReconciliationCliIo {
  readonly inspectInputFile: (path: string) => Promise<{ readonly isFile: boolean; readonly size: number }>;
  readonly readInputFile: (path: string) => Promise<string>;
  readonly writeStdout: (text: string) => void;
  readonly writeStderr: (text: string) => void;
}

export const organizationReconciliationCliHelp = `Usage:
  npm run iam:organization-reconciliation:validate -- --input=<local-json-file>

Options:
  --input=<local-json-file>  Explicit local JSON snapshot file (required).
  --help                     Show this help.

The command performs no network or database access. URL, token, stdin, and
network parameters are not supported. This version verifies envelope
self-consistency but has no trusted collector attestation verifier, so even
staticChecksPassed=true remains safetyGate.passed=false and exits with status 1.
Only a future trusted-provenance verifier may allow status 0. Argument, file,
JSON, or schema errors exit with status 2.
`;

const MAX_INPUT_BYTES = 16 * 1024 * 1024;
const nonBlankString = z.string().min(1).refine((value) => value.trim().length > 0);
const organizationId = z.union([z.number().int().positive(), nonBlankString]);
const decision = z.enum(["allow", "deny"]);
const hash = z.string().regex(/^[a-f0-9]{64}$/i);
const cursor = z.string().nullable();

const directoryRecord = z.object({
  legacyOrganizationId: organizationId,
  name: nonBlankString,
  title: z.string().nullable(),
  active: z.boolean()
}).strict();
const mappingRecord = z.object({
  legacyOrganizationId: organizationId,
  identityOrganizationId: nonBlankString,
  active: z.boolean()
}).strict();
const membershipRecord = z.object({
  subjectRef: nonBlankString,
  legacyOrganizationId: organizationId,
  active: z.boolean()
}).strict();
const scopedRoleRecord = z.object({
  subjectRef: nonBlankString,
  legacyOrganizationId: organizationId,
  roleRef: nonBlankString,
  active: z.boolean()
}).strict();
const pluginBindingRecord = z.object({
  pluginRef: nonBlankString,
  bindingRef: nonBlankString,
  organizationRef: nonBlankString,
  active: z.boolean()
}).strict();
const pluginVisibilityRecord = z.object({
  subjectRef: nonBlankString,
  pluginRef: nonBlankString,
  organizationRef: nonBlankString,
  decision
}).strict();
const campusContextRecord = z.object({
  subjectRef: nonBlankString,
  campusRef: nonBlankString,
  organizationRef: nonBlankString,
  decision
}).strict();
const effectiveDecisionRecord = z.object({
  subjectRef: nonBlankString,
  organizationRef: nonBlankString,
  resourceRef: nonBlankString,
  capabilityRef: nonBlankString,
  decision
}).strict();

const pageEvidence = z.object({
  pageNumber: z.number().int().positive(),
  requestCursor: cursor,
  nextCursor: cursor,
  recordOffset: z.number().int().nonnegative(),
  recordCount: z.number().int().nonnegative(),
  recordsHash: hash
}).strict();

const pageCollection = z.object({
  snapshotId: nonBlankString,
  firstCursor: cursor,
  pageCount: z.number().int().positive(),
  recordCount: z.number().int().nonnegative(),
  recordsHash: hash,
  pages: z.array(pageEvidence)
}).strict();

function pairSchema<T extends z.ZodTypeAny>(record: T) {
  const page = z.object({
    records: z.array(record),
    sourceVersion: z.string().nullable().optional(),
    nextCursor: cursor.optional(),
    collection: pageCollection.optional()
  }).strict();
  return z.object({ legacy: page.optional(), identity: page.optional() }).strict();
}

const collectionEnvelope = z.object({
  collectorContract: z.literal(ORGANIZATION_RECONCILIATION_COLLECTOR_CONTRACT),
  collectorContractHash: z.literal(ORGANIZATION_RECONCILIATION_COLLECTOR_CONTRACT_HASH),
  evidenceNonce: z.string().regex(/^[a-f0-9]{32,128}$/i),
  logicalSnapshotId: nonBlankString,
  windowId: nonBlankString,
  windowStartedAt: nonBlankString,
  windowEndedAt: nonBlankString,
  legacy: z.object({ sourceVersion: nonBlankString, snapshotId: nonBlankString }).strict(),
  identity: z.object({ sourceVersion: nonBlankString, snapshotId: nonBlankString }).strict()
}).strict();

const organizationReconciliationInputSchema = z.object({
  collectionEnvelope,
  organizationDirectory: pairSchema(directoryRecord).optional(),
  organizationMappings: pairSchema(mappingRecord).optional(),
  memberships: pairSchema(membershipRecord).optional(),
  organizationScopedRoles: pairSchema(scopedRoleRecord).optional(),
  pluginBindings: pairSchema(pluginBindingRecord).optional(),
  pluginVisibility: pairSchema(pluginVisibilityRecord).optional(),
  campusContexts: pairSchema(campusContextRecord).optional(),
  effectiveDecisions: pairSchema(effectiveDecisionRecord).optional()
}).strict();

export class OrganizationReconciliationCliError extends Error {
  constructor(
    readonly code:
      | "argument-invalid"
      | "input-file-read-failed"
      | "input-file-not-regular"
      | "input-file-too-large"
      | "input-json-invalid"
      | "input-schema-invalid",
    message: string
  ) {
    super(message);
    this.name = "OrganizationReconciliationCliError";
  }
}

export function parseOrganizationReconciliationCliArgs(argv: readonly string[]): OrganizationReconciliationCliOptions {
  if (argv.length === 1 && argv[0] === "--help") return { mode: "help" };
  if (argv.includes("--help")) {
    throw new OrganizationReconciliationCliError("argument-invalid", "--help cannot be combined with other arguments.");
  }

  let inputPath: string | null = null;
  for (const arg of argv) {
    if (arg.startsWith("--input=")) {
      if (inputPath !== null) {
        throw new OrganizationReconciliationCliError("argument-invalid", "--input may be provided only once.");
      }
      const candidate = arg.slice("--input=".length);
      if (!candidate.trim() || candidate === "-" || candidate.includes("\0") || isUrl(candidate)) {
        throw new OrganizationReconciliationCliError(
          "argument-invalid",
          "--input must identify one explicit local JSON file; URL and stdin inputs are forbidden."
        );
      }
      inputPath = candidate;
      continue;
    }
    throw new OrganizationReconciliationCliError(
      "argument-invalid",
      "Unknown argument. Only --input=<local-json-file> and --help are supported; URL and token parameters are forbidden."
    );
  }
  if (inputPath === null) {
    throw new OrganizationReconciliationCliError("argument-invalid", "--input=<local-json-file> is required.");
  }
  return { mode: "validate", inputPath };
}

export function parseOrganizationReconciliationJson(raw: string): OrganizationReconciliationInput {
  if (Buffer.byteLength(raw, "utf8") > MAX_INPUT_BYTES) {
    throw new OrganizationReconciliationCliError("input-file-too-large", "Input JSON exceeds the 16 MiB offline validation limit.");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new OrganizationReconciliationCliError("input-json-invalid", "Input file is not valid JSON.");
  }
  const result = organizationReconciliationInputSchema.safeParse(parsed);
  if (!result.success) {
    throw new OrganizationReconciliationCliError(
      "input-schema-invalid",
      "Input JSON does not match the organization reconciliation snapshot schema."
    );
  }
  return result.data as OrganizationReconciliationInput;
}

export async function runOrganizationReconciliationCli(
  argv: readonly string[],
  io: OrganizationReconciliationCliIo
): Promise<number> {
  let options: OrganizationReconciliationCliOptions;
  try {
    options = parseOrganizationReconciliationCliArgs(argv);
  } catch (error) {
    writeSanitizedError(io, error);
    return 2;
  }
  if (options.mode === "help") {
    io.writeStdout(organizationReconciliationCliHelp);
    return 0;
  }

  let raw: string;
  try {
    const inspection = await io.inspectInputFile(options.inputPath);
    if (!inspection.isFile) {
      throw new OrganizationReconciliationCliError("input-file-not-regular", "Input path must be one regular local file.");
    }
    if (!Number.isSafeInteger(inspection.size) || inspection.size < 0 || inspection.size > MAX_INPUT_BYTES) {
      throw new OrganizationReconciliationCliError("input-file-too-large", "Input JSON exceeds the 16 MiB offline validation limit.");
    }
    raw = await io.readInputFile(options.inputPath);
  } catch (error) {
    if (error instanceof OrganizationReconciliationCliError) {
      writeSanitizedError(io, error);
      return 2;
    }
    writeSanitizedError(
      io,
      new OrganizationReconciliationCliError("input-file-read-failed", "Unable to read the explicit local input file.")
    );
    return 2;
  }

  try {
    const input = parseOrganizationReconciliationJson(raw);
    const report = validateOrganizationReconciliation(input);
    io.writeStdout(`${JSON.stringify(report, null, 2)}\n`);
    return report.safetyGate.passed ? 0 : 1;
  } catch (error) {
    writeSanitizedError(io, error);
    return 2;
  }
}

function writeSanitizedError(io: OrganizationReconciliationCliIo, error: unknown): void {
  const safe = error instanceof OrganizationReconciliationCliError
    ? { status: "error", code: error.code, message: error.message }
    : { status: "error", code: "validation-failed", message: "Offline reconciliation validation failed." };
  io.writeStderr(`${JSON.stringify(safe)}\n`);
}

function isUrl(value: string): boolean {
  return /^[a-z][a-z0-9+.-]*:\/\//i.test(value) || /^file:/i.test(value);
}

async function main(): Promise<void> {
  const exitCode = await runOrganizationReconciliationCli(process.argv.slice(2), {
    inspectInputFile: async (path) => {
      const details = await stat(path);
      return { isFile: details.isFile(), size: details.size };
    },
    readInputFile: (path) => readFile(path, "utf8"),
    writeStdout: (text) => process.stdout.write(text),
    writeStderr: (text) => process.stderr.write(text)
  });
  process.exitCode = exitCode;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
