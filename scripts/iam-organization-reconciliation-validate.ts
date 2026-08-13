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
  createOrganizationReconciliationDevelopDeploymentEvidenceSha256,
  parseOrganizationReconciliationDevelopDeploymentEvidence
} from "../apps/identity-adapter/src/iam-organization-reconciliation-develop-deployment-evidence.js";
import {
  isCanonicalAuthorizationContext,
  isCanonicalLegacyOrganizationId,
  isCanonicalLegacyUserSubjectRef,
  isCanonicalOrganizationRef,
  isCanonicalPluginRef,
  isCanonicalReconciliationToken
} from "../apps/identity-adapter/src/iam-organization-reconciliation-refs.js";
import {
  ORGANIZATION_RECONCILIATION_COMPOSITE_CONSISTENCY_MODEL,
  ORGANIZATION_RECONCILIATION_OPERATION_COMPOSITE_MANIFEST_CONTRACT,
  ORGANIZATION_RECONCILIATION_OPERATION_EVIDENCE_CONTRACT,
  ORGANIZATION_RECONCILIATION_PAGINATION_MODE,
  ORGANIZATION_RECONCILIATION_SNAPSHOT_MODE,
  validateOrganizationReconciliationOperationCompositeManifest
} from "../apps/identity-adapter/src/iam-organization-reconciliation-component-manifest.js";
import {
  IDENTITY_ORGANIZATION_SURFACE_PROJECTOR_CONTRACT,
  LEGACY_ORGANIZATION_SURFACE_PROJECTOR_CONTRACT,
  ORGANIZATION_SURFACE_PROJECTION_BINDING_CONTRACT
} from "../apps/identity-adapter/src/iam-organization-reconciliation-projector-contract.js";

export type OrganizationReconciliationCliOptions =
  | { readonly mode: "help" }
  | {
      readonly mode: "validate";
      readonly inputPath: string;
      readonly trustedProvenance?: {
        readonly attestationPath: string;
        readonly trustPolicyPath: string;
        readonly deploymentEvidencePath: string;
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
    --deployment-evidence=<local-json-file> \\
    --trust-profile=<compiled-profile-id>

Options:
  --input=<local-json-file>  Explicit local JSON snapshot file (required).
  --attestation=<local-json-file>
                             Signed external collector attestations (optional;
                             requires trust-policy and trust-profile).
  --trust-policy=<local-json-file>
                             Change-controlled Ed25519 public-key policy
                             (optional; requires attestation and trust-profile).
  --deployment-evidence=<local-json-file>
                             Independently observed Develop deployment manifest
                             required with provenance v4 trusted verification.
  --trust-profile=<identifier>
                             Resolved only from the immutable compiled trust
                             registry (optional; requires both files).
  --help                     Show this help.

The command performs no network or database access. URL, token, stdin, and
network parameters are not supported. Input requires the v4 collector envelope
plus a v4 final operation composite manifest whose parent lineage and
operation-evidence digests bind
the exact manifest-free input body. This artifact intentionally reports
realSourceAdaptersReady=false and a coverage blocker until every reviewed
authoritative adapter is registered in source; caller JSON cannot override it.
The trusted-provenance verifier cannot override this compiled blocker. Trusted
mode additionally
requires a provisioned compiled trust profile; no policy pin is accepted from
arguments, environment, evidence, attestations, or policy JSON. It verifies
every policy-required Ed25519 collector against the complete evidence digest,
independently domain-hashed deployment evidence, environment/node binding, and
collection window and
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
const publicOrganizationRef = z.string().refine((value) => isCanonicalOrganizationRef(value, true));
const authorizationContextKind = z.enum(["organization", "platform-global", "public"]);
const authorizationContextRef = z.string().min(1).max(256);
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
  contextKind: authorizationContextKind,
  contextRef: authorizationContextRef,
  decision
}).strict().refine(
  (value) => isCanonicalAuthorizationContext(value.contextKind, value.contextRef),
  "context kind/ref mismatch"
);
const effectiveDecisionRecord = z.object({
  subjectRef,
  contextKind: authorizationContextKind,
  contextRef: authorizationContextRef,
  resourceRef: canonicalRecordString,
  capabilityRef: canonicalRecordString,
  decision
}).strict().refine(
  (value) => isCanonicalAuthorizationContext(value.contextKind, value.contextRef),
  "context kind/ref mismatch"
);

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
    contexts: decisionDimension
  }),
  effectiveDecisions: decisionUniverseSchema({
    subjects: decisionDimension,
    contexts: decisionDimension,
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

const projectionMetadata = z.string().min(1).max(1_024)
  .refine((value) => value.trim() === value);
const projectionHash = z.string().regex(/^[a-f0-9]{64}$/);
const projectionSourceBinding = z.object({
  sourceVersion: projectionMetadata,
  snapshotId: projectionMetadata
}).strict();

function projectionSideBinding(projectorContract: string) {
  return z.object({
    projectorContract: z.literal(projectorContract),
    evaluatorId: z.string().regex(/^[a-z0-9][a-z0-9./:-]{0,127}$/)
      .refine((value) => !value.includes("..")),
    evaluatorBuildSha256: projectionHash,
    primarySource: projectionSourceBinding
  }).strict();
}

const projectionBinding = z.object({
  contract: z.literal(ORGANIZATION_SURFACE_PROJECTION_BINDING_CONTRACT),
  semanticRegistrySha256: projectionHash,
  lineageManifestSha256: projectionHash,
  legacy: projectionSideBinding(LEGACY_ORGANIZATION_SURFACE_PROJECTOR_CONTRACT),
  identity: projectionSideBinding(IDENTITY_ORGANIZATION_SURFACE_PROJECTOR_CONTRACT),
  pluginSource: projectionSourceBinding
}).strict().refine(
  (value) => value.legacy.evaluatorId !== value.identity.evaluatorId &&
    value.legacy.evaluatorBuildSha256 !== value.identity.evaluatorBuildSha256,
  "projector sides must be independent"
);

const componentManifest = z.object({
  contract: z.literal(ORGANIZATION_RECONCILIATION_OPERATION_COMPOSITE_MANIFEST_CONTRACT),
  parentLineageManifestSha256: hash,
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
    datasetInventory: z.object({
      contract: z.literal("iam-organization-reconciliation-dataset-inventory/v2"),
      recordCommitmentScheme: z.literal("hmac-sha256-run-secret/v1"),
      componentId: z.string().regex(/^[a-z0-9][a-z0-9-]{0,127}$/),
      sourceId: nonBlankString,
      catalogSha256: hash,
      recordCount: z.number().int().nonnegative(),
      datasets: z.array(z.object({
        datasetId: nonBlankString,
        recordCount: z.number().int().nonnegative(),
        recordsCommitment: hash,
        pageCount: z.number().int().positive(),
        pages: z.array(z.object({
          pageNumber: z.number().int().positive(),
          requestCursorCommitment: hash.nullable(),
          nextCursorCommitment: hash.nullable(),
          recordOffset: z.number().int().nonnegative(),
          recordCount: z.number().int().nonnegative(),
          recordsCommitment: hash
        }).strict()).nonempty(),
        lineageSha256: hash
      }).strict()).nonempty(),
      inventorySha256: hash
    }).strict(),
    openedAt: nonBlankString,
    closedAt: nonBlankString
  }).strict()).length(3),
  manifestSha256: hash
}).strict();

const organizationReconciliationInputSchema = z.object({
  componentManifest,
  projectionBinding,
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
  let deploymentEvidencePath: string | null = null;
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
    if (arg.startsWith("--deployment-evidence=")) {
      if (deploymentEvidencePath !== null) {
        throw new OrganizationReconciliationCliError(
          "argument-invalid",
          "--deployment-evidence may be provided only once."
        );
      }
      deploymentEvidencePath = parseLocalPathArgument(
        "--deployment-evidence",
        arg.slice("--deployment-evidence=".length)
      );
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
  const trustedArgumentCount = [attestationPath, trustPolicyPath, deploymentEvidencePath, trustProfile]
    .filter((value) => value !== null).length;
  if (trustedArgumentCount !== 0 && trustedArgumentCount !== 4) {
    throw new OrganizationReconciliationCliError(
      "argument-invalid",
      "--attestation, --trust-policy, --deployment-evidence, and --trust-profile must be provided together."
    );
  }
  if (
    attestationPath !== null &&
    trustPolicyPath !== null &&
    deploymentEvidencePath !== null &&
    new Set([inputPath, attestationPath, trustPolicyPath, deploymentEvidencePath]).size !== 4
  ) {
    throw new OrganizationReconciliationCliError(
      "argument-invalid",
      "Input, attestation, trust-policy, and deployment-evidence must be distinct local files."
    );
  }
  return {
    mode: "validate",
    inputPath,
    ...(attestationPath !== null && trustPolicyPath !== null && deploymentEvidencePath !== null && trustProfile !== null
      ? { trustedProvenance: { attestationPath, trustPolicyPath, deploymentEvidencePath, trustProfile } }
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
    validateOrganizationReconciliationOperationCompositeManifest(result.data.componentManifest);
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
      const [attestationRaw, trustPolicyRaw, deploymentEvidenceRaw] = await Promise.all([
        readTrustedArtifact(io, options.trustedProvenance.attestationPath),
        readTrustedArtifact(io, options.trustedProvenance.trustPolicyPath),
        readTrustedArtifact(io, options.trustedProvenance.deploymentEvidencePath)
      ]);
      const attestationValue = parseTrustedArtifactJson(attestationRaw);
      const trustPolicyValue = parseTrustedArtifactJson(trustPolicyRaw);
      const deploymentEvidenceValue = parseTrustedArtifactJson(deploymentEvidenceRaw);
      try {
        const deploymentEvidence = parseOrganizationReconciliationDevelopDeploymentEvidence(
          deploymentEvidenceValue
        );
        const trustPolicy = parseOrganizationReconciliationTrustPolicy(trustPolicyValue);
        assertDeploymentEvidenceMatchesTrustPolicy(deploymentEvidence, trustPolicy);
        trustedProvenance = {
          trustedProfile,
          attestationBundle: parseOrganizationReconciliationAttestationBundle(attestationValue),
          trustPolicy,
          expectedDeploymentEvidenceSha256:
            createOrganizationReconciliationDevelopDeploymentEvidenceSha256(deploymentEvidence),
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

function assertDeploymentEvidenceMatchesTrustPolicy(
  deploymentEvidence: ReturnType<typeof parseOrganizationReconciliationDevelopDeploymentEvidence>,
  trustPolicy: ReturnType<typeof parseOrganizationReconciliationTrustPolicy>
): void {
  if (
    deploymentEvidence.environment !== trustPolicy.environment ||
    trustPolicy.requiredCollectors.length !== 1 ||
    deploymentEvidence.signers.length !== trustPolicy.requiredCollectors.length
  ) throw new Error("deployment-policy-mismatch");
  const deployedByKey = new Map(
    deploymentEvidence.signers.map((signer) => [signer.keyId, signer])
  );
  for (const collector of trustPolicy.requiredCollectors) {
    const deployed = deployedByKey.get(collector.keyId);
    if (
      !deployed ||
      deployed.collectorId !== collector.collectorId ||
      deployed.nodeId !== collector.nodeId ||
      deployed.publicKeySha256 !== collector.publicKeySha256 ||
      collector.buildRevision !== deploymentEvidence.buildRevision
    ) throw new Error("deployment-policy-mismatch");
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
