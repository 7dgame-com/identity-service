import { describe, expect, it, vi } from "vitest";
import {
  createOrganizationReconciliationEvidenceHash,
  ORGANIZATION_RECONCILIATION_COLLECTOR_CONTRACT,
  ORGANIZATION_RECONCILIATION_COLLECTOR_CONTRACT_HASH,
  type OrganizationReconciliationInput
} from "../src/iam-organization-reconciliation-validator.js";
import {
  OrganizationReconciliationCliError,
  organizationReconciliationCliHelp,
  parseOrganizationReconciliationCliArgs,
  parseOrganizationReconciliationJson,
  runOrganizationReconciliationCli
} from "../../../scripts/iam-organization-reconciliation-validate.js";

describe("offline IAM organization reconciliation CLI", () => {
  it("accepts one explicit local JSON input and provides help", () => {
    expect(parseOrganizationReconciliationCliArgs(["--input=/tmp/work-package4.json"])).toEqual({
      mode: "validate",
      inputPath: "/tmp/work-package4.json"
    });
    expect(parseOrganizationReconciliationCliArgs(["--help"])).toEqual({ mode: "help" });
    expect(organizationReconciliationCliHelp).toContain("--input=<local-json-file>");
    expect(organizationReconciliationCliHelp).toContain("no network or database access");
    expect(organizationReconciliationCliHelp).toContain("staticChecksPassed=true");
    expect(organizationReconciliationCliHelp).toContain("trusted-provenance verifier");
  });

  it("rejects missing, duplicate, URL, stdin, token, network, and unknown arguments", () => {
    const invalidCases = [
      [],
      ["--input=/tmp/a.json", "--input=/tmp/b.json"],
      ["--input=https://example.invalid/evidence.json"],
      ["--input=file:///tmp/evidence.json"],
      ["--input=-"],
      ["--token=private-token"],
      ["--url=https://example.invalid"],
      ["--network=true"],
      ["/tmp/positional.json"],
      ["--help", "--input=/tmp/a.json"]
    ];
    for (const args of invalidCases) {
      expect(() => parseOrganizationReconciliationCliArgs(args)).toThrow(OrganizationReconciliationCliError);
    }
  });

  it("parses a strict full-scope snapshot without changing its evidence values", () => {
    const input = alignedInput();
    expect(parseOrganizationReconciliationJson(JSON.stringify(input))).toEqual(input);
  });

  it("returns a hash-only static pass but exits one without trusted external provenance", async () => {
    const io = memoryIo(JSON.stringify(alignedInput()));
    const exitCode = await runOrganizationReconciliationCli(["--input=/tmp/full-scope.json"], io);

    expect(exitCode).toBe(1);
    expect(io.readInputFile).toHaveBeenCalledWith("/tmp/full-scope.json");
    expect(io.stderr).toBe("");
    const report = JSON.parse(io.stdout);
    expect(report).toMatchObject({
      dryRun: true,
      writeSideEffects: "none",
      evidencePolicy: "hash-only",
      assuranceScope: "collector-envelope-self-consistency",
      externalProvenanceRequired: true,
      staticChecksPassed: true,
      comparisonPolicy: "pairwise-no-union",
      safetyGate: {
        passed: false,
        blocksDualWrite: true,
        unionForbidden: true,
        externalProvenanceVerified: false,
        blockedReasons: ["external-provenance-required"]
      }
    });
    expect(report.reportHash).toMatch(/^[a-f0-9]{24}$/);
    expectNoRawEvidence(io.stdout);
  });

  it("prints the hash-only report but exits one when safetyGate fails", async () => {
    const input = alignedInput();
    const unsafe: OrganizationReconciliationInput = {
      ...input,
      effectiveDecisions: pair(
        [{ subjectRef: "private-subject", organizationRef: "private-org-name", resourceRef: "private-resource", capabilityRef: "private-capability", decision: "deny" }],
        [{ subjectRef: "private-subject", organizationRef: "private-org-name", resourceRef: "private-resource", capabilityRef: "private-capability", decision: "allow" }]
      )
    };
    const io = memoryIo(JSON.stringify(unsafe));
    const exitCode = await runOrganizationReconciliationCli(["--input=/tmp/unsafe.json"], io);

    expect(exitCode).toBe(1);
    expect(io.stderr).toBe("");
    expect(JSON.parse(io.stdout)).toMatchObject({
      severity: { P0: 1 },
      safetyGate: {
        passed: false,
        blocksDualWrite: true,
        blockedReasons: ["p0-findings", "external-provenance-required"]
      }
    });
    expect(io.stdout).not.toContain("private-subject");
    expect(io.stdout).not.toContain("private-resource");
    expect(io.stdout).not.toContain("private-capability");
  });

  it("treats coverage blockers as a valid report with non-zero safety exit", async () => {
    const { pluginVisibility: _missing, ...incomplete } = alignedInput();
    const io = memoryIo(JSON.stringify(incomplete));
    const exitCode = await runOrganizationReconciliationCli(["--input=/tmp/incomplete.json"], io);

    expect(exitCode).toBe(1);
    expect(JSON.parse(io.stdout)).toMatchObject({
      coverageBlockers: [{ surface: "plugin-visibility", code: "surface-missing" }],
      safetyGate: {
        passed: false,
        coverageComplete: false,
        blockedReasons: ["coverage-incomplete", "external-provenance-required"]
      }
    });
  });

  it("returns exit two and sanitized stderr for malformed or schema-invalid input", async () => {
    const malformed = memoryIo("{private-secret-not-json");
    expect(await runOrganizationReconciliationCli(["--input=/tmp/malformed.json"], malformed)).toBe(2);
    expect(malformed.stdout).toBe("");
    expect(JSON.parse(malformed.stderr)).toEqual({
      status: "error",
      code: "input-json-invalid",
      message: "Input file is not valid JSON."
    });
    expect(malformed.stderr).not.toContain("private-secret-not-json");

    const schemaInvalid = memoryIo(JSON.stringify({
      effectiveDecisions: {
        legacy: { records: [{ subjectRef: "raw-secret", decision: "super-allow" }] }
      }
    }));
    expect(await runOrganizationReconciliationCli(["--input=/tmp/schema.json"], schemaInvalid)).toBe(2);
    expect(schemaInvalid.stdout).toBe("");
    expect(JSON.parse(schemaInvalid.stderr)).toEqual({
      status: "error",
      code: "input-schema-invalid",
      message: "Input JSON does not match the organization reconciliation snapshot schema."
    });
    expect(schemaInvalid.stderr).not.toContain("raw-secret");
    expect(schemaInvalid.stderr).not.toContain("super-allow");

    const arbitraryMetadata = alignedInput() as unknown as Record<string, any>;
    arbitraryMetadata.memberships.legacy.records[0].metadata = { authorizationScope: "raw-secret-scope" };
    expect(() => parseOrganizationReconciliationJson(JSON.stringify(arbitraryMetadata)))
      .toThrow(OrganizationReconciliationCliError);
  });

  it("sanitizes file-read failures without echoing the path or underlying error", async () => {
    const io = memoryIo(new Error("private filesystem detail"));
    const exitCode = await runOrganizationReconciliationCli(["--input=/tmp/private-name.json"], io);

    expect(exitCode).toBe(2);
    expect(io.stdout).toBe("");
    expect(JSON.parse(io.stderr)).toEqual({
      status: "error",
      code: "input-file-read-failed",
      message: "Unable to read the explicit local input file."
    });
    expect(io.stderr).not.toContain("private-name.json");
    expect(io.stderr).not.toContain("private filesystem detail");
  });

  it("rejects non-regular and oversized inputs before reading their contents", async () => {
    const nonRegular = memoryIo(JSON.stringify(alignedInput()));
    nonRegular.inspectInputFile.mockResolvedValue({ isFile: false, size: 0 });
    expect(await runOrganizationReconciliationCli(["--input=/tmp/fifo"], nonRegular)).toBe(2);
    expect(nonRegular.readInputFile).not.toHaveBeenCalled();
    expect(JSON.parse(nonRegular.stderr)).toMatchObject({ code: "input-file-not-regular" });

    const oversized = memoryIo(JSON.stringify(alignedInput()));
    oversized.inspectInputFile.mockResolvedValue({ isFile: true, size: 16 * 1024 * 1024 + 1 });
    expect(await runOrganizationReconciliationCli(["--input=/tmp/oversized.json"], oversized)).toBe(2);
    expect(oversized.readInputFile).not.toHaveBeenCalled();
    expect(JSON.parse(oversized.stderr)).toMatchObject({ code: "input-file-too-large" });
  });

  it("shows help without reading a file", async () => {
    const io = memoryIo(new Error("must not read"));
    const exitCode = await runOrganizationReconciliationCli(["--help"], io);

    expect(exitCode).toBe(0);
    expect(io.stdout).toBe(organizationReconciliationCliHelp);
    expect(io.stderr).toBe("");
    expect(io.inspectInputFile).not.toHaveBeenCalled();
    expect(io.readInputFile).not.toHaveBeenCalled();
  });
});

function memoryIo(input: string | Error) {
  let stdout = "";
  let stderr = "";
  const readInputFile = vi.fn(async () => {
    if (input instanceof Error) throw input;
    return input;
  });
  return {
    inspectInputFile: vi.fn(async () => ({ isFile: true, size: input instanceof Error ? 1 : Buffer.byteLength(input) })),
    readInputFile,
    writeStdout: (text: string) => { stdout += text; },
    writeStderr: (text: string) => { stderr += text; },
    get stdout() { return stdout; },
    get stderr() { return stderr; }
  };
}

function alignedInput(): OrganizationReconciliationInput {
  return {
    collectionEnvelope: collectionEnvelope(),
    organizationDirectory: pair(
      [{ legacyOrganizationId: 1, name: "private-org-name", title: "private-org-title", active: true }],
      [{ legacyOrganizationId: 1, name: "private-org-name", title: "private-org-title", active: true }]
    ),
    organizationMappings: pair(
      [{ legacyOrganizationId: 1, identityOrganizationId: "private-identity-org", active: true }],
      [{ legacyOrganizationId: 1, identityOrganizationId: "private-identity-org", active: true }]
    ),
    memberships: pair(
      [{ subjectRef: "private-subject", legacyOrganizationId: 1, active: true }],
      [{ subjectRef: "private-subject", legacyOrganizationId: 1, active: true }]
    ),
    organizationScopedRoles: pair(
      [{ subjectRef: "private-subject", legacyOrganizationId: 1, roleRef: "private-role", active: true }],
      [{ subjectRef: "private-subject", legacyOrganizationId: 1, roleRef: "private-role", active: true }]
    ),
    pluginBindings: pair(
      [{ pluginRef: "private-plugin", bindingRef: "private-binding", organizationRef: "private-org-name", active: true }],
      [{ pluginRef: "private-plugin", bindingRef: "private-binding", organizationRef: "private-org-name", active: true }]
    ),
    pluginVisibility: pair(
      [{ subjectRef: "private-subject", pluginRef: "private-plugin", organizationRef: "private-org-name", decision: "allow" }],
      [{ subjectRef: "private-subject", pluginRef: "private-plugin", organizationRef: "private-org-name", decision: "allow" }]
    ),
    campusContexts: pair(
      [{ subjectRef: "private-subject", campusRef: "private-campus", organizationRef: "private-org-name", decision: "allow" }],
      [{ subjectRef: "private-subject", campusRef: "private-campus", organizationRef: "private-org-name", decision: "allow" }]
    ),
    effectiveDecisions: pair(
      [{ subjectRef: "private-subject", organizationRef: "private-org-name", resourceRef: "private-resource", capabilityRef: "private-capability", decision: "allow" }],
      [{ subjectRef: "private-subject", organizationRef: "private-org-name", resourceRef: "private-resource", capabilityRef: "private-capability", decision: "allow" }]
    )
  };
}

function pair<T>(legacy: readonly T[], identity: readonly T[]) {
  return {
    legacy: page(legacy, "legacy-private-snapshot"),
    identity: page(identity, "identity-private-snapshot")
  };
}

function page<T>(records: readonly T[], snapshotId: string) {
  const recordsHash = createOrganizationReconciliationEvidenceHash(EVIDENCE_NONCE, records as never);
  return {
    records,
    sourceVersion: "private-source-version",
    nextCursor: null,
    collection: {
      snapshotId,
      firstCursor: null,
      pageCount: 1,
      recordCount: records.length,
      recordsHash,
      pages: [{
        pageNumber: 1,
        requestCursor: null,
        nextCursor: null,
        recordOffset: 0,
        recordCount: records.length,
        recordsHash
      }]
    }
  } as const;
}

const EVIDENCE_NONCE = "b2".repeat(32);

function collectionEnvelope() {
  return {
    collectorContract: ORGANIZATION_RECONCILIATION_COLLECTOR_CONTRACT,
    collectorContractHash: ORGANIZATION_RECONCILIATION_COLLECTOR_CONTRACT_HASH,
    evidenceNonce: EVIDENCE_NONCE,
    logicalSnapshotId: "private-logical-snapshot",
    windowId: "private-window",
    windowStartedAt: "2026-08-09T00:00:00.000Z",
    windowEndedAt: "2026-08-09T00:05:00.000Z",
    legacy: { sourceVersion: "private-source-version", snapshotId: "legacy-private-snapshot" },
    identity: { sourceVersion: "private-source-version", snapshotId: "identity-private-snapshot" }
  } as const;
}

function expectNoRawEvidence(serialized: string): void {
  for (const rawValue of [
    "private-org-name",
    "private-org-title",
    "private-identity-org",
    "private-subject",
    "private-role",
    "private-plugin",
    "private-binding",
    "private-campus",
    "private-resource",
    "private-capability",
    "private-source-version"
  ]) {
    expect(serialized).not.toContain(rawValue);
  }
}
