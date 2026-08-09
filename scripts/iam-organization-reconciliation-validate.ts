import { readFile } from "node:fs/promises";
import { stat } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import { z } from "zod";
import {
  ORGANIZATION_RECONCILIATION_COLLECTOR_CONTRACT,
  ORGANIZATION_RECONCILIATION_COLLECTOR_CONTRACT_HASH,
  ORGANIZATION_RECONCILIATION_DECISION_DERIVATION_CONTRACT,
  OrganizationReconciliationInput,
  validateOrganizationReconciliation
} from "../apps/identity-adapter/src/iam-organization-reconciliation-validator.js";
import {
  parseOrganizationReconciliationAttestationBundle,
  parseOrganizationReconciliationTrustPolicy,
  type OrganizationReconciliationTrustedProfile
} from "../apps/identity-adapter/src/iam-organization-reconciliation-provenance.js";
import {
  resolveCompiledOrganizationReconciliationTrustProfile
} from "../apps/identity-adapter/src/iam-organization-reconciliation-trust-profiles.js";
import {
  isCanonicalLegacyOrganizationId,
  isCanonicalLegacyUserSubjectRef,
  isCanonicalOrganizationRef,
  isCanonicalPluginRef,
  isCanonicalReconciliationToken
} from "../apps/identity-adapter/src/iam-organization-reconciliation-refs.js";
import {
  ORGANIZATION_RECONCILIATION_COMPOSITE_CONSISTENCY_MODEL,
  ORGANIZATION_RECONCILIATION_COMPOSITE_MANIFEST_CONTRACT,
  ORGANIZATION_RECONCILIATION_OPERATION_EVIDENCE_CONTRACT,
  ORGANIZATION_RECONCILIATION_PAGINATION_MODE,
  ORGANIZATION_RECONCILIATION_SNAPSHOT_MODE,
  validateOrganizationReconciliationCompositeManifest
} from "../apps/identity-adapter/src/iam-organization-reconciliation-component-manifest.js";

export type OrganizationReconciliationCliOptions =
  | { readonly mode: "help" }
  | {
      readonly mode: "validate";
      readonly inputPath: string;
      readonly trustedProvenance?: {
        readonly attestationPath: string;
        readonly trustPolicyPath: string;
        readonly trustProfile: string;
      };
    };

export interface OrganizationReconciliationCliIo {
  readonly inspectInputFile: (path: string) => Promise<{ readonly isFile: boolean; readonly size: number }>;
  readonly readInputFile: (path: string) => Promise<string>;
  /** Tests may inject a resolver; production uses only the immutable compiled registry. */
  readonly resolveTrustProfile?: (profileId: string) => OrganizationReconciliationTrustedProfile | undefined;
  readonly now?: () => Date;
  readonly writeStdout: (text: string) => void;
  readonly writeStderr: (text: string) => void;
}

export const organizationReconciliationCliHelp = `Usage:
  npm run iam:organization-reconciliation:validate -- --input=<local-json-file>
  npm run iam:organization-reconciliation:validate -- --input=<local-json-file> \\
    --attestation=<local-json-file> --trust-policy=<local-json-file> \\
    --trust-profile=<compiled-profile-id>

Options:
  --input=<local-json-file>  Explicit local JSON snapshot file (required).
  --attestation=<local-json-file>
                             Signed external collector attestations (optional;
                             requires trust-policy and trust-profile).
  --trust-policy=<local-json-file>
                             Change-controlled Ed25519 public-key policy
                             (optional; requires attestation and trust-profile).
  --trust-profile=<identifier>
                             Resolved only from the immutable compiled trust
                             registry (optional; requires both files).
  --help                     Show this help.

The command performs no network or database access. URL, token, stdin, and
network parameters are not supported. Input requires the v3 collector envelope
plus a v2 three-source composite manifest whose operation-evidence digest binds
the exact manifest-free input body. This artifact intentionally reports
realSourceAdaptersReady=false and a coverage blocker until every reviewed
authoritative adapter is registered in source; caller JSON cannot override it.
The trusted-provenance verifier cannot override this compiled blocker. Trusted
mode additionally
requires a provisioned compiled trust profile; no policy pin is accepted from
arguments, environment, evidence, attestations, or policy JSON. It verifies
every policy-required Ed25519 collector against
the complete evidence digest, environment/node binding, collection window, and
freshness limits. Invalid or absent provenance fails closed. Argument, file,
JSON, schema, or unknown/unprovisioned-profile errors exit with status 2.
`;

const MAX_INPUT_BYTES = 16 * 1024 * 1024;
const MAX_TRUSTED_ARTIFACT_BYTES = 1024 * 1024;
const nonBlankString = z.string().min(1).refine((value) => value.trim().length > 0);
const canonicalRecordString = z.string().refine(isCanonicalReconciliationToken);
const subjectRef = z.string().refine(isCanonicalLegacyUserSubjectRef);
const pluginRef = z.string().refine(isCanonicalPluginRef);
const organizationId = z.union([z.number(), z.string()]).refine(isCanonicalLegacyOrganizationId);
const organizationRef = z.string().refine((value) => isCanonicalOrganizationRef(value, false));
const publicOrganizationRef = z.string().refine((value) => isCanonicalOrganizationRef(value, true));
const decision = z.enum(["allow", "deny"]);
const hash = z.string().regex(/^[a-f0-9]{64}$/i);
const cursor = z.string().nullable();

const directoryRecord = z.object({
  legacyOrganizationId: organizationId,
  name: canonicalRecordString,
  title: canonicalRecordString.nullable(),
  active: z.boolean()
}).strict();
const mappingRecord = z.object({
  legacyOrganizationId: organizationId,
  identityOrganizationId: canonicalRecordString,
  active: z.boolean()
}).strict();
const membershipRecord = z.object({
  subjectRef,
  legacyOrganizationId: organizationId,
  active: z.boolean()
}).strict();
const scopedRoleRecord = z.object({
  subjectRef,
  legacyOrganizationId: organizationId,
  roleRef: canonicalRecordString,
  active: z.boolean()
}).strict();
const pluginBindingRecord = z.object({
  pluginRef,
  bindingRef: canonicalRecordString,
  organizationRef: publicOrganizationRef,
  active: z.boolean()
}).strict();
const pluginVisibilityRecord = z.object({
  subjectRef,
  pluginRef,
  organizationRef: publicOrganizationRef,
  decision
}).strict();
const campusContextRecord = z.object({
  subjectRef,
  campusRef: canonicalRecordString,
  organizationRef,
  decision
}).strict();
const effectiveDecisionRecord = z.object({
  subjectRef,
  organizationRef,
  resourceRef: canonicalRecordString,
  capabilityRef: canonicalRecordString,
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

const decisionDimension = z.object({
  count: z.number().int().nonnegative(),
  hash
}).strict();

function decisionUniverseSchema<T extends z.ZodRawShape>(dimensions: T) {
  return z.object({
    keyCount: z.number().int().nonnegative(),
    keysHash: hash,
    derivationContract: z.literal(ORGANIZATION_RECONCILIATION_DECISION_DERIVATION_CONTRACT),
    derivationBuildRevision: z.string().regex(/^[a-f0-9]{40}$/),
    dimensions: z.object(dimensions).strict()
  }).strict();
}

const decisionUniverses = z.object({
  pluginVisibility: decisionUniverseSchema({
    subjects: decisionDimension,
    plugins: decisionDimension,
    organizations: decisionDimension
  }),
  campusContexts: decisionUniverseSchema({
    subjects: decisionDimension,
    campuses: decisionDimension,
    organizations: decisionDimension
  }),
  effectiveDecisions: decisionUniverseSchema({
    subjects: decisionDimension,
    organizations: decisionDimension,
    resources: decisionDimension,
    capabilities: decisionDimension,
    rulePairs: decisionDimension
  })
}).strict();

const collectionEnvelope = z.object({
  collectorContract: z.literal(ORGANIZATION_RECONCILIATION_COLLECTOR_CONTRACT),
  collectorContractHash: z.literal(ORGANIZATION_RECONCILIATION_COLLECTOR_CONTRACT_HASH),
  collectorBuildRevision: z.string().regex(/^[a-f0-9]{40}$/),
  evidenceNonce: z.string().regex(/^[a-f0-9]{32,128}$/i),
  logicalSnapshotId: nonBlankString,
  windowId: nonBlankString,
  windowStartedAt: nonBlankString,
  windowEndedAt: nonBlankString,
  legacy: z.object({
    sourceVersion: nonBlankString,
    snapshotId: nonBlankString,
    subjectUniverse: z.object({
      subjectCount: z.number().int().positive(),
      subjectsHash: hash
    }).strict(),
    decisionUniverses
  }).strict(),
  identity: z.object({
    sourceVersion: nonBlankString,
    snapshotId: nonBlankString,
    subjectUniverse: z.object({
      subjectCount: z.number().int().positive(),
      subjectsHash: hash
    }).strict(),
    decisionUniverses
  }).strict()
}).strict();

const componentManifest = z.object({
  contract: z.literal(ORGANIZATION_RECONCILIATION_COMPOSITE_MANIFEST_CONTRACT),
  consistencyModel: z.literal(ORGANIZATION_RECONCILIATION_COMPOSITE_CONSISTENCY_MODEL),
  crossDatabaseAtomic: z.literal(false),
  windowStartedAt: nonBlankString,
  windowEndedAt: nonBlankString,
  maxWindowMilliseconds: z.number().int().positive(),
  evidenceContract: z.literal(ORGANIZATION_RECONCILIATION_OPERATION_EVIDENCE_CONTRACT),
  evidenceSha256: hash,
  components: z.array(z.object({
    componentId: z.enum(["legacy-main", "identity", "plugin"]),
    sourceId: nonBlankString,
    sourceVersion: nonBlankString,
    snapshotId: nonBlankString,
    recordCount: z.number().int().nonnegative(),
    subjectUniverseScope: z.enum(["complete", "not-applicable"]),
    subjectUniverse: z.object({
      count: z.number().int().nonnegative(),
      sha256: z.union([hash, z.literal("")])
    }).strict(),
    snapshotMode: z.literal(ORGANIZATION_RECONCILIATION_SNAPSHOT_MODE),
    paginationMode: z.literal(ORGANIZATION_RECONCILIATION_PAGINATION_MODE),
    schemaSha256: hash,
    catalogSha256: hash,
    buildSha256: hash,
    openedAt: nonBlankString,
    closedAt: nonBlankString
  }).strict()).length(3),
  manifestSha256: hash
}).strict();

const organizationReconciliationInputSchema = z.object({
  componentManifest,
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
      | "input-schema-invalid"
      | "trust-profile-unprovisioned"
      | "trusted-artifact-read-failed"
      | "trusted-artifact-not-regular"
      | "trusted-artifact-too-large"
      | "trusted-artifact-json-invalid"
      | "trusted-artifact-schema-invalid",
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
  let attestationPath: string | null = null;
  let trustPolicyPath: string | null = null;
  let trustProfile: string | null = null;
  for (const arg of argv) {
    if (arg.startsWith("--input=")) {
      if (inputPath !== null) {
        throw new OrganizationReconciliationCliError("argument-invalid", "--input may be provided only once.");
      }
      inputPath = parseLocalPathArgument("--input", arg.slice("--input=".length));
      continue;
    }
    if (arg.startsWith("--attestation=")) {
      if (attestationPath !== null) {
        throw new OrganizationReconciliationCliError("argument-invalid", "--attestation may be provided only once.");
      }
      attestationPath = parseLocalPathArgument("--attestation", arg.slice("--attestation=".length));
      continue;
    }
    if (arg.startsWith("--trust-policy=")) {
      if (trustPolicyPath !== null) {
        throw new OrganizationReconciliationCliError("argument-invalid", "--trust-policy may be provided only once.");
      }
      trustPolicyPath = parseLocalPathArgument("--trust-policy", arg.slice("--trust-policy=".length));
      continue;
    }
    if (arg.startsWith("--trust-profile=")) {
      if (trustProfile !== null) {
        throw new OrganizationReconciliationCliError("argument-invalid", "--trust-profile may be provided only once.");
      }
      trustProfile = parseTrustProfileArgument(arg.slice("--trust-profile=".length));
      continue;
    }
    throw new OrganizationReconciliationCliError(
      "argument-invalid",
      "Unknown argument. Only local input, attestation, trust-policy, compiled trust-profile, and --help parameters are supported; URL and token parameters are forbidden."
    );
  }
  if (inputPath === null) {
    throw new OrganizationReconciliationCliError("argument-invalid", "--input=<local-json-file> is required.");
  }
  const trustedArgumentCount = [attestationPath, trustPolicyPath, trustProfile]
    .filter((value) => value !== null).length;
  if (trustedArgumentCount !== 0 && trustedArgumentCount !== 3) {
    throw new OrganizationReconciliationCliError(
      "argument-invalid",
      "--attestation, --trust-policy, and --trust-profile must be provided together."
    );
  }
  if (
    attestationPath !== null &&
    trustPolicyPath !== null &&
    new Set([inputPath, attestationPath, trustPolicyPath]).size !== 3
  ) {
    throw new OrganizationReconciliationCliError(
      "argument-invalid",
      "Input, attestation, and trust-policy must be distinct local files."
    );
  }
  return {
    mode: "validate",
    inputPath,
    ...(attestationPath !== null && trustPolicyPath !== null && trustProfile !== null
      ? { trustedProvenance: { attestationPath, trustPolicyPath, trustProfile } }
      : {})
  };
}

function parseTrustProfileArgument(candidate: string): string {
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(candidate)) {
    throw new OrganizationReconciliationCliError(
      "argument-invalid",
      "--trust-profile must be one explicit compiled profile identifier."
    );
  }
  return candidate;
}

function parseLocalPathArgument(name: string, candidate: string): string {
  if (!candidate.trim() || candidate !== candidate.trim() || candidate === "-" || candidate.includes("\0") || isUrl(candidate)) {
    throw new OrganizationReconciliationCliError(
      "argument-invalid",
      `${name} must identify one explicit local JSON file; URL and stdin inputs are forbidden.`
    );
  }
  return candidate;
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
  try {
    validateOrganizationReconciliationCompositeManifest(result.data.componentManifest);
  } catch {
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
    let trustedProvenance;
    if (options.trustedProvenance) {
      const trustedProfile = io.resolveTrustProfile?.(
        options.trustedProvenance.trustProfile
      );
      if (!trustedProfile || trustedProfile.profileId !== options.trustedProvenance.trustProfile) {
        throw new OrganizationReconciliationCliError(
          "trust-profile-unprovisioned",
          "The requested compiled trust profile is unknown or unprovisioned."
        );
      }
      const [attestationRaw, trustPolicyRaw] = await Promise.all([
        readTrustedArtifact(io, options.trustedProvenance.attestationPath),
        readTrustedArtifact(io, options.trustedProvenance.trustPolicyPath)
      ]);
      const attestationValue = parseTrustedArtifactJson(attestationRaw);
      const trustPolicyValue = parseTrustedArtifactJson(trustPolicyRaw);
      try {
        trustedProvenance = {
          trustedProfile,
          attestationBundle: parseOrganizationReconciliationAttestationBundle(attestationValue),
          trustPolicy: parseOrganizationReconciliationTrustPolicy(trustPolicyValue),
          now: io.now?.() ?? new Date()
        };
      } catch {
        throw new OrganizationReconciliationCliError(
          "trusted-artifact-schema-invalid",
          "Trusted provenance JSON does not match the strict attestation or trust-policy schema."
        );
      }
    }
    const report = validateOrganizationReconciliation(input, { trustedProvenance });
    io.writeStdout(`${JSON.stringify(report, null, 2)}\n`);
    return report.safetyGate.passed ? 0 : 1;
  } catch (error) {
    writeSanitizedError(io, error);
    return 2;
  }
}

async function readTrustedArtifact(io: OrganizationReconciliationCliIo, path: string): Promise<string> {
  try {
    const inspection = await io.inspectInputFile(path);
    if (!inspection.isFile) {
      throw new OrganizationReconciliationCliError(
        "trusted-artifact-not-regular",
        "Trusted provenance paths must be regular local files."
      );
    }
    if (
      !Number.isSafeInteger(inspection.size) ||
      inspection.size < 0 ||
      inspection.size > MAX_TRUSTED_ARTIFACT_BYTES
    ) {
      throw new OrganizationReconciliationCliError(
        "trusted-artifact-too-large",
        "Trusted provenance JSON exceeds the 1 MiB offline limit."
      );
    }
    const raw = await io.readInputFile(path);
    if (Buffer.byteLength(raw, "utf8") > MAX_TRUSTED_ARTIFACT_BYTES) {
      throw new OrganizationReconciliationCliError(
        "trusted-artifact-too-large",
        "Trusted provenance JSON exceeds the 1 MiB offline limit."
      );
    }
    return raw;
  } catch (error) {
    if (error instanceof OrganizationReconciliationCliError) throw error;
    throw new OrganizationReconciliationCliError(
      "trusted-artifact-read-failed",
      "Unable to read a trusted provenance local file."
    );
  }
}

function parseTrustedArtifactJson(raw: string): unknown {
  try {
    return JSON.parse(raw);
  } catch {
    throw new OrganizationReconciliationCliError(
      "trusted-artifact-json-invalid",
      "A trusted provenance file is not valid JSON."
    );
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
    resolveTrustProfile: resolveCompiledOrganizationReconciliationTrustProfile,
    now: () => new Date(),
    writeStdout: (text) => process.stdout.write(text),
    writeStderr: (text) => process.stderr.write(text)
  });
  process.exitCode = exitCode;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
