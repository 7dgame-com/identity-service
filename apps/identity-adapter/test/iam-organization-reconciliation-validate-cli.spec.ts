import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import {
  createOrganizationReconciliationEvidenceHash,
  ORGANIZATION_RECONCILIATION_COLLECTOR_CONTRACT,
  ORGANIZATION_RECONCILIATION_COLLECTOR_CONTRACT_HASH,
  ORGANIZATION_RECONCILIATION_DECISION_DERIVATION_CONTRACT,
  type OrganizationReconciliationInput
} from "../src/iam-organization-reconciliation-validator.js";
import {
  createOrganizationReconciliationAttestationBundleForTest,
  createOrganizationReconciliationPolicyForTest,
  createOrganizationReconciliationTrustedProfileForTest,
  TEST_COLLECTOR_BUILD_REVISION
} from "./iam-organization-reconciliation-provenance.test-fixture.js";
import {
  createOrganizationReconciliationProvenanceBindingFromInput,
  type OrganizationReconciliationTrustedProfile
} from "../src/iam-organization-reconciliation-provenance.js";
import {
  compiledOrganizationReconciliationTrustProfileCount,
  resolveCompiledOrganizationReconciliationTrustProfile
} from "../src/iam-organization-reconciliation-trust-profiles.js";
import {
  OrganizationReconciliationCliError,
  organizationReconciliationCliHelp,
  parseOrganizationReconciliationCliArgs,
  parseOrganizationReconciliationJson,
  runOrganizationReconciliationCli
} from "../../../scripts/iam-organization-reconciliation-validate.js";
import {
  attachTestOrganizationReconciliationComponentManifest
} from "./fixtures/iam-organization-reconciliation-component-manifest.js";
import {
  createOrganizationReconciliationDevelopDeploymentEvidenceForTest
} from "./iam-organization-reconciliation-develop-deployment-evidence.test-fixture.js";
import {
  createOrganizationReconciliationDevelopDeploymentEvidenceSha256
} from "../src/iam-organization-reconciliation-develop-deployment-evidence.js";

describe("offline IAM organization reconciliation CLI", () => {
  it("accepts one explicit local JSON input and provides help", () => {
    expect(parseOrganizationReconciliationCliArgs(["--input=/tmp/work-package4.json"])).toEqual({
      mode: "validate",
      inputPath: "/tmp/work-package4.json"
    });
    expect(parseOrganizationReconciliationCliArgs(["--help"])).toEqual({ mode: "help" });
    expect(parseOrganizationReconciliationCliArgs([
      "--input=/tmp/work-package4.json",
      "--attestation=/tmp/work-package4.attestation.json",
      "--trust-policy=/tmp/work-package4.policy.json",
      "--deployment-evidence=/tmp/work-package4.deployment.json",
      "--trust-profile=test-dual-node"
    ])).toEqual({
      mode: "validate",
      inputPath: "/tmp/work-package4.json",
      trustedProvenance: {
        attestationPath: "/tmp/work-package4.attestation.json",
        trustPolicyPath: "/tmp/work-package4.policy.json",
        deploymentEvidencePath: "/tmp/work-package4.deployment.json",
        trustProfile: "test-dual-node"
      }
    });
    expect(organizationReconciliationCliHelp).toContain("--input=<local-json-file>");
    expect(organizationReconciliationCliHelp).toContain("no network or database access");
    expect(organizationReconciliationCliHelp).toContain("realSourceAdaptersReady=false");
    expect(organizationReconciliationCliHelp).toContain("trusted-provenance verifier");
    expect(organizationReconciliationCliHelp).toContain("--trust-profile=<identifier>");
    expect(organizationReconciliationCliHelp).toContain("immutable compiled trust");
    expect(organizationReconciliationCliHelp).not.toContain("TRUST_POLICY_SHA256");
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
      ["--input=/tmp/a.json", "--attestation=/tmp/a.attestation.json"],
      ["--input=/tmp/a.json", "--trust-policy=/tmp/a.policy.json"],
      ["--input=/tmp/a.json", "--trust-profile=test-profile"],
      ["--input=/tmp/a.json", "--attestation=/tmp/a.attestation.json", "--trust-policy=/tmp/a.policy.json"],
      ["--input=/tmp/a.json", "--attestation=/tmp/a.json", "--trust-policy=/tmp/a.policy.json", "--trust-profile=test-profile"],
      ["--input=/tmp/a.json", "--attestation=/tmp/a.attestation.json", "--trust-policy=/tmp/a.policy.json", "--trust-profile=bad profile"],
      ["--input=/tmp/a.json", "--attestation=/tmp/a.attestation.json", "--trust-policy=/tmp/a.policy.json", "--trust-profile=a", "--trust-profile=b"],
      ["--input=/tmp/a.json", "--trust-policy-sha256=" + "0".repeat(64)],
      ["/tmp/positional.json"],
      ["--help", "--input=/tmp/a.json"]
    ];
    for (const args of invalidCases) {
      expect(() => parseOrganizationReconciliationCliArgs(args)).toThrow(OrganizationReconciliationCliError);
    }
  });

  it("ships with no production trust profile or pin provisioned", () => {
    expect(compiledOrganizationReconciliationTrustProfileCount).toBe(0);
    expect(resolveCompiledOrganizationReconciliationTrustProfile("test-dual-node")).toBeUndefined();
    expect(resolveCompiledOrganizationReconciliationTrustProfile("invalid profile")).toBeUndefined();
  });

  it("parses a strict full-scope snapshot without changing its evidence values", () => {
    const input = alignedInput();
    expect(parseOrganizationReconciliationJson(JSON.stringify(input))).toEqual(input);
  });

  it("returns hash-only evidence but retains provenance and real-adapter blockers", async () => {
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
      realSourceAdaptersReady: false,
      staticChecksPassed: false,
      comparisonPolicy: "pairwise-no-union",
      safetyGate: {
        passed: false,
        blocksDualWrite: true,
        unionForbidden: true,
        externalProvenanceVerified: false,
        blockedReasons: ["coverage-incomplete", "external-provenance-required"]
      }
    });
    expect(report.reportHash).toMatch(/^[a-f0-9]{24}$/);
    expectNoRawEvidence(io.stdout);
  });

  it("verifies a pinned attestation set but cannot pass before real adapters are registered", async () => {
    const fixture = trustedCliFixture();
    const io = artifactIo(fixture.files, fixture.trustedProfile);
    const exitCode = await runOrganizationReconciliationCli([
      "--input=/tmp/full-scope.json",
      "--attestation=/tmp/attestation.json",
      "--trust-policy=/tmp/trust-policy.json",
      "--deployment-evidence=/tmp/deployment-evidence.json",
      "--trust-profile=test-dual-node"
    ], io);

    expect(exitCode).toBe(1);
    expect(io.stderr).toBe("");
    expect(JSON.parse(io.stdout)).toMatchObject({
      assuranceScope: "collector-envelope-with-trusted-external-attestation",
      staticChecksPassed: false,
      provenanceVerification: {
        verified: true,
        reasonCode: "verified",
        requiredAttestationCount: 1,
        verifiedAttestationCount: 1,
        trustProfileHash: expect.stringMatching(/^[a-f0-9]{24}$/),
        environmentHash: expect.stringMatching(/^[a-f0-9]{24}$/)
      },
      safetyGate: {
        passed: false,
        blocksDualWrite: true,
        externalProvenanceVerified: true,
        blockedReasons: ["coverage-incomplete"]
      }
    });
    expectNoRawEvidence(io.stdout);
    expect(io.stdout).not.toContain("trusted-cli-collector");
    expect(io.stdout).not.toContain("trusted-cli-node");
    expect(io.stdout).not.toContain("trusted-cli-key");
  });

  it("fails closed for unknown profiles or a profile resolved to the wrong policy", async () => {
    const fixture = trustedCliFixture();
    const args = [
      "--input=/tmp/full-scope.json",
      "--attestation=/tmp/attestation.json",
      "--trust-policy=/tmp/trust-policy.json",
      "--deployment-evidence=/tmp/deployment-evidence.json",
      "--trust-profile=test-dual-node"
    ];
    const missingPin = artifactIo(fixture.files, undefined);
    expect(await runOrganizationReconciliationCli(args, missingPin)).toBe(2);
    expect(JSON.parse(missingPin.stderr)).toMatchObject({ code: "trust-profile-unprovisioned" });
    expect(missingPin.stdout).toBe("");

    const mismatchedProfile = artifactIo(fixture.files, {
      ...fixture.trustedProfile,
      profileId: "different-compiled-profile"
    });
    expect(await runOrganizationReconciliationCli(args, mismatchedProfile)).toBe(2);
    expect(JSON.parse(mismatchedProfile.stderr)).toMatchObject({ code: "trust-profile-unprovisioned" });

    const wrongPin = artifactIo(fixture.files, {
      ...fixture.trustedProfile,
      policySha256: "0".repeat(64)
    });
    expect(await runOrganizationReconciliationCli(args, wrongPin)).toBe(1);
    expect(JSON.parse(wrongPin.stdout)).toMatchObject({
      staticChecksPassed: false,
      provenanceVerification: { verified: false, reasonCode: "trust-policy-pin-mismatch" },
      safetyGate: {
        passed: false,
        blocksDualWrite: true,
        blockedReasons: ["coverage-incomplete", "external-provenance-required"]
      }
    });
  });

  it("prints the hash-only report but exits one when safetyGate fails", async () => {
    const input = alignedInput();
    const unsafe: OrganizationReconciliationInput = {
      ...input,
      effectiveDecisions: pair(
        baselineEffectiveRecords("deny"),
        baselineEffectiveRecords("allow")
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
        blockedReasons: ["coverage-incomplete", "p0-findings", "external-provenance-required"]
      }
    });
    expect(io.stdout).not.toContain("legacy-user:581");
    expect(io.stdout).not.toContain("private-resource");
    expect(io.stdout).not.toContain("private-capability");
  });

  it("treats coverage blockers as a valid report with non-zero safety exit", async () => {
    const { pluginVisibility: _missing, ...incompleteBody } = alignedInput();
    const incomplete = attachProjectionBoundTestManifest(incompleteBody);
    const io = memoryIo(JSON.stringify(incomplete));
    const exitCode = await runOrganizationReconciliationCli(["--input=/tmp/incomplete.json"], io);

    expect(exitCode).toBe(1);
    expect(JSON.parse(io.stdout)).toMatchObject({
      coverageBlockers: [
        { surface: "collection-envelope", code: "real-source-adapters-not-ready" },
        { surface: "plugin-visibility", code: "surface-missing" }
      ],
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

    const missingBuild = structuredClone(alignedInput()) as unknown as Record<string, any>;
    delete missingBuild.collectionEnvelope.collectorBuildRevision;
    expect(() => parseOrganizationReconciliationJson(JSON.stringify(missingBuild)))
      .toThrow(OrganizationReconciliationCliError);

    const missingManifest = structuredClone(alignedInput()) as unknown as Record<string, any>;
    delete missingManifest.componentManifest;
    expect(() => parseOrganizationReconciliationJson(JSON.stringify(missingManifest)))
      .toThrow(OrganizationReconciliationCliError);

    const missingProjectionBinding = structuredClone(alignedInput()) as unknown as Record<string, any>;
    delete missingProjectionBinding.projectionBinding;
    expect(() => parseOrganizationReconciliationJson(JSON.stringify(missingProjectionBinding)))
      .toThrow(OrganizationReconciliationCliError);

    const extendedProjectionBinding = structuredClone(alignedInput()) as unknown as Record<string, any>;
    extendedProjectionBinding.projectionBinding.untrustedOverride = true;
    expect(() => parseOrganizationReconciliationJson(JSON.stringify(extendedProjectionBinding)))
      .toThrow(OrganizationReconciliationCliError);

    const sameProjectorSides = structuredClone(alignedInput()) as unknown as Record<string, any>;
    sameProjectorSides.projectionBinding.identity.evaluatorId =
      sameProjectorSides.projectionBinding.legacy.evaluatorId;
    expect(() => parseOrganizationReconciliationJson(JSON.stringify(sameProjectorSides)))
      .toThrow(OrganizationReconciliationCliError);

    const invalidManifestWindow = structuredClone(alignedInput()) as unknown as Record<string, any>;
    invalidManifestWindow.componentManifest.windowEndedAt = "not-a-timestamp";
    expect(() => parseOrganizationReconciliationJson(JSON.stringify(invalidManifestWindow)))
      .toThrow(OrganizationReconciliationCliError);

    const oldV3FinalManifest = structuredClone(alignedInput()) as unknown as Record<string, any>;
    oldV3FinalManifest.componentManifest.contract =
      "iam-organization-reconciliation-composite-manifest/v3";
    delete oldV3FinalManifest.componentManifest.parentLineageManifestSha256;
    expect(() => parseOrganizationReconciliationJson(JSON.stringify(oldV3FinalManifest)))
      .toThrow(OrganizationReconciliationCliError);

    const missingSubjectUniverse = structuredClone(alignedInput()) as unknown as Record<string, any>;
    delete missingSubjectUniverse.collectionEnvelope.identity.subjectUniverse;
    expect(() => parseOrganizationReconciliationJson(JSON.stringify(missingSubjectUniverse)))
      .toThrow(OrganizationReconciliationCliError);

    const missingDecisionUniverse = structuredClone(alignedInput()) as unknown as Record<string, any>;
    delete missingDecisionUniverse.collectionEnvelope.legacy.decisionUniverses.effectiveDecisions;
    expect(() => parseOrganizationReconciliationJson(JSON.stringify(missingDecisionUniverse)))
      .toThrow(OrganizationReconciliationCliError);

    const missingDimension = structuredClone(alignedInput()) as unknown as Record<string, any>;
    delete missingDimension.collectionEnvelope.legacy.decisionUniverses.pluginVisibility.dimensions.plugins;
    expect(() => parseOrganizationReconciliationJson(JSON.stringify(missingDimension)))
      .toThrow(OrganizationReconciliationCliError);

    const extraDimension = structuredClone(alignedInput()) as unknown as Record<string, any>;
    extraDimension.collectionEnvelope.identity.decisionUniverses.campusContexts.dimensions.resources = {
      count: 1,
      hash: "b".repeat(64)
    };
    expect(() => parseOrganizationReconciliationJson(JSON.stringify(extraDimension)))
      .toThrow(OrganizationReconciliationCliError);

    const v2Contract = structuredClone(alignedInput()) as unknown as Record<string, any>;
    v2Contract.collectionEnvelope.collectorContract = "iam-organization-reconciliation-collector/v2";
    expect(() => parseOrganizationReconciliationJson(JSON.stringify(v2Contract)))
      .toThrow(OrganizationReconciliationCliError);

    const v2DecisionContract = structuredClone(alignedInput()) as unknown as Record<string, any>;
    v2DecisionContract.collectionEnvelope.legacy.decisionUniverses.pluginVisibility.derivationContract =
      "iam-organization-reconciliation-decision-universe/v2";
    expect(() => parseOrganizationReconciliationJson(JSON.stringify(v2DecisionContract)))
      .toThrow(OrganizationReconciliationCliError);

    for (const mutate of [
      (input: Record<string, any>) => { input.componentManifest.contract =
        "iam-organization-reconciliation-composite-manifest/v2"; },
      (input: Record<string, any>) => { input.componentManifest.components[0].datasetInventory.contract =
        "iam-organization-reconciliation-dataset-inventory/v1"; },
      (input: Record<string, any>) => { input.componentManifest.components[0].datasetInventory.datasets[0].datasetId =
        "legacy-fixturé"; }
    ]) {
      const invalid = structuredClone(alignedInput()) as unknown as Record<string, any>;
      mutate(invalid);
      const io = memoryIo(JSON.stringify(invalid));
      expect(await runOrganizationReconciliationCli(["--input=/tmp/old-or-invalid-contract.json"], io)).toBe(2);
      expect(JSON.parse(io.stderr)).toMatchObject({ code: "input-schema-invalid" });
      expect(io.stdout).toBe("");
    }

    for (const subjectRef of [
      "private-subject",
      "legacy-user:0",
      "legacy-user:01",
      "identity-user:581",
      "legacy-user:legacy-user:581",
      " legacy-user:581",
      "legacy-user:581 ",
      "legacy-user:\u0001581"
    ]) {
      const invalidSubject = structuredClone(alignedInput()) as unknown as Record<string, any>;
      invalidSubject.memberships.legacy.records[0].subjectRef = subjectRef;
      expect(() => parseOrganizationReconciliationJson(JSON.stringify(invalidSubject)))
        .toThrow(OrganizationReconciliationCliError);
    }

    for (const pluginRef of [
      "private-plugin",
      "",
      " plugin:private",
      "plugin:private ",
      "plugin:private tool",
      "plugin:private:tool",
      "plugin:private/tool",
      "plugin:private.tool",
      "plugin:private_tool",
      "plugin:privé",
      "plugin:cafe\u0301",
      "plugin:private\u0000",
      "plugin:plugin:private",
      `plugin:${"a".repeat(65)}`
    ]) {
      const invalidPlugin = structuredClone(alignedInput()) as unknown as Record<string, any>;
      invalidPlugin.pluginBindings.identity.records[0].pluginRef = pluginRef;
      expect(() => parseOrganizationReconciliationJson(JSON.stringify(invalidPlugin)))
        .toThrow(OrganizationReconciliationCliError);
    }

    for (const legacyOrganizationId of ["01", " 1", 0, Number.MAX_SAFE_INTEGER + 1]) {
      const invalidOrganizationId = structuredClone(alignedInput()) as unknown as Record<string, any>;
      invalidOrganizationId.organizationDirectory.legacy.records[0].legacyOrganizationId = legacyOrganizationId;
      expect(() => parseOrganizationReconciliationJson(JSON.stringify(invalidOrganizationId)))
        .toThrow(OrganizationReconciliationCliError);
    }

    for (const organizationRef of ["private-org", "legacy-org:01", " legacy-org:1", "org:public"]) {
      const invalidOrganizationRef = structuredClone(alignedInput()) as unknown as Record<string, any>;
      invalidOrganizationRef.campusContexts.legacy.records[0].organizationRef = organizationRef;
      expect(() => parseOrganizationReconciliationJson(JSON.stringify(invalidOrganizationRef)))
        .toThrow(OrganizationReconciliationCliError);
    }

    for (const roleRef of [" private-role", "private-role ", "cafe\u0301", "private\u0000role"]) {
      const invalidRole = structuredClone(alignedInput()) as unknown as Record<string, any>;
      invalidRole.organizationScopedRoles.legacy.records[0].roleRef = roleRef;
      expect(() => parseOrganizationReconciliationJson(JSON.stringify(invalidRole)))
        .toThrow(OrganizationReconciliationCliError);
    }
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

function artifactIo(
  files: Readonly<Record<string, string>>,
  trustedProfile: OrganizationReconciliationTrustedProfile | undefined
) {
  let stdout = "";
  let stderr = "";
  return {
    inspectInputFile: vi.fn(async (path: string) => {
      const value = files[path];
      if (value === undefined) throw new Error("missing private test file");
      return { isFile: true, size: Buffer.byteLength(value) };
    }),
    readInputFile: vi.fn(async (path: string) => {
      const value = files[path];
      if (value === undefined) throw new Error("missing private test file");
      return value;
    }),
    resolveTrustProfile: (profileId: string) =>
      profileId === "test-dual-node" ? trustedProfile : undefined,
    now: () => new Date("2026-08-09T00:10:00.000Z"),
    writeStdout: (text: string) => { stdout += text; },
    writeStderr: (text: string) => { stderr += text; },
    get stdout() { return stdout; },
    get stderr() { return stderr; }
  };
}

function trustedCliFixture() {
  const input = alignedInput();
  const keys = [generateKeyPairSync("ed25519")];
  const basePolicy = createOrganizationReconciliationPolicyForTest(keys.map(({ publicKey }, index) => ({
    collectorId: `trusted-cli-collector-${index + 1}`,
    nodeId: `trusted-cli-node-${index + 1}`,
    keyId: `trusted-cli-key-${index + 1}`,
    publicKey
  })));
  const policy = { ...basePolicy, environment: "xrteeth-develop" };
  const deploymentEvidence = createOrganizationReconciliationDevelopDeploymentEvidenceForTest(
    policy.requiredCollectors
  );
  const binding = createOrganizationReconciliationProvenanceBindingFromInput(
    input,
    createOrganizationReconciliationDevelopDeploymentEvidenceSha256(deploymentEvidence)
  );
  const bundle = createOrganizationReconciliationAttestationBundleForTest(
    binding,
    policy,
    keys.map(({ privateKey }, index) => ({ keyId: `trusted-cli-key-${index + 1}`, privateKey }))
  );
  return {
    trustedProfile: createOrganizationReconciliationTrustedProfileForTest(policy),
    files: {
      "/tmp/full-scope.json": JSON.stringify(input),
      "/tmp/attestation.json": JSON.stringify(bundle),
      "/tmp/trust-policy.json": JSON.stringify(policy),
      "/tmp/deployment-evidence.json": JSON.stringify(deploymentEvidence)
    }
  };
}

function alignedInput(): OrganizationReconciliationInput {
  return attachProjectionBoundTestManifest({
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
      [{ subjectRef: "legacy-user:581", legacyOrganizationId: 1, active: true }],
      [{ subjectRef: "legacy-user:581", legacyOrganizationId: 1, active: true }]
    ),
    organizationScopedRoles: pair(
      [{ subjectRef: "legacy-user:581", legacyOrganizationId: 1, roleRef: "private-role", active: true }],
      [{ subjectRef: "legacy-user:581", legacyOrganizationId: 1, roleRef: "private-role", active: true }]
    ),
    pluginBindings: pair(
      [{ pluginRef: "plugin:private", bindingRef: "private-binding", organizationRef: "legacy-org:1", active: true }],
      [{ pluginRef: "plugin:private", bindingRef: "private-binding", organizationRef: "legacy-org:1", active: true }]
    ),
    pluginVisibility: pair(
      [{ subjectRef: "legacy-user:581", pluginRef: "plugin:private", organizationRef: "legacy-org:1", decision: "allow" }],
      [{ subjectRef: "legacy-user:581", pluginRef: "plugin:private", organizationRef: "legacy-org:1", decision: "allow" }]
    ),
    campusContexts: pair(
      baselineCampusRecords(),
      baselineCampusRecords()
    ),
    effectiveDecisions: pair(
      baselineEffectiveRecords("allow"),
      baselineEffectiveRecords("allow")
    )
  });
}

function attachProjectionBoundTestManifest(
  candidate: OrganizationReconciliationInput
): OrganizationReconciliationInput {
  const lineage = attachTestOrganizationReconciliationComponentManifest(candidate);
  const manifest = lineage.componentManifest;
  if (!manifest) return lineage;
  const legacy = manifest.components.find((component) => component.componentId === "legacy-main")!;
  const identity = manifest.components.find((component) => component.componentId === "identity")!;
  const plugin = manifest.components.find((component) => component.componentId === "plugin")!;
  return attachTestOrganizationReconciliationComponentManifest({
    ...candidate,
    projectionBinding: {
      contract: "iam-organization-reconciliation-projection-binding/v1",
      semanticRegistrySha256: "6".repeat(64),
      lineageManifestSha256: manifest.parentLineageManifestSha256,
      legacy: {
        projectorContract: "iam-organization-legacy-surface-projector/v2",
        evaluatorId: "test/legacy/cli",
        evaluatorBuildSha256: "7".repeat(64),
        primarySource: {
          sourceVersion: legacy.sourceVersion,
          snapshotId: legacy.snapshotId
        }
      },
      identity: {
        projectorContract: "iam-organization-identity-surface-projector/v2",
        evaluatorId: "test/identity/cli",
        evaluatorBuildSha256: "8".repeat(64),
        primarySource: {
          sourceVersion: identity.sourceVersion,
          snapshotId: identity.snapshotId
        }
      },
      pluginSource: {
        sourceVersion: plugin.sourceVersion,
        snapshotId: plugin.snapshotId
      }
    }
  });
}

function pair<T>(legacy: readonly T[], identity: readonly T[]) {
  return {
    legacy: page(legacy, "legacy-private-source-version", "legacy-private-snapshot"),
    identity: page(identity, "identity-private-source-version", "identity-private-snapshot")
  };
}

function page<T>(records: readonly T[], sourceVersion: string, snapshotId: string) {
  const recordsHash = createOrganizationReconciliationEvidenceHash(EVIDENCE_NONCE, records as never);
  return {
    records,
    sourceVersion,
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
const CONTEXTS = [
  ["organization", "legacy-org:1"],
  ["platform-global", "org:platform-global"],
  ["public", "org:public"]
] as const;
const CONTEXT_DIMENSIONS = CONTEXTS.map((context) => JSON.stringify(context));

function collectionEnvelope() {
  return {
    collectorContract: ORGANIZATION_RECONCILIATION_COLLECTOR_CONTRACT,
    collectorContractHash: ORGANIZATION_RECONCILIATION_COLLECTOR_CONTRACT_HASH,
    collectorBuildRevision: TEST_COLLECTOR_BUILD_REVISION,
    evidenceNonce: EVIDENCE_NONCE,
    logicalSnapshotId: "private-logical-snapshot",
    windowId: "private-window",
    windowStartedAt: "2026-08-09T00:00:00.000Z",
    windowEndedAt: "2026-08-09T00:05:00.000Z",
    legacy: {
      sourceVersion: "legacy-private-source-version",
      snapshotId: "legacy-private-snapshot",
      subjectUniverse: { subjectCount: 1, subjectsHash: SUBJECT_UNIVERSE_HASH },
      decisionUniverses: DECISION_UNIVERSES
    },
    identity: {
      sourceVersion: "identity-private-source-version",
      snapshotId: "identity-private-snapshot",
      subjectUniverse: { subjectCount: 1, subjectsHash: SUBJECT_UNIVERSE_HASH },
      decisionUniverses: DECISION_UNIVERSES
    }
  } as const;
}

const SUBJECT_UNIVERSE_HASH = createOrganizationReconciliationEvidenceHash(
  EVIDENCE_NONCE,
  ["legacy-user:581"]
);
const DECISION_UNIVERSES = {
  pluginVisibility: decisionUniverse(
    [["legacy-user:581", "plugin:private", "legacy-org:1"]],
    { subjects: ["legacy-user:581"], plugins: ["plugin:private"], organizations: ["legacy-org:1"] }
  ),
  campusContexts: decisionUniverse(
    CONTEXTS.map(([contextKind, contextRef]) => ["legacy-user:581", contextKind, contextRef]),
    { subjects: ["legacy-user:581"], contexts: CONTEXT_DIMENSIONS }
  ),
  effectiveDecisions: decisionUniverse(CONTEXTS.map(([contextKind, contextRef]) =>
    ["legacy-user:581", contextKind, contextRef, "private-resource", "private-capability"]
  ), {
    subjects: ["legacy-user:581"],
    contexts: CONTEXT_DIMENSIONS,
    resources: ["private-resource"],
    capabilities: ["private-capability"],
    rulePairs: [JSON.stringify(["private-resource", "private-capability"])]
  })
};

function baselineCampusRecords() {
  return CONTEXTS.map(([contextKind, contextRef], index) => ({
    subjectRef: "legacy-user:581",
    contextKind,
    contextRef,
    decision: index === 0 ? "allow" as const : "deny" as const
  }));
}

function baselineEffectiveRecords(organizationDecision: "allow" | "deny") {
  return CONTEXTS.map(([contextKind, contextRef], index) => ({
    subjectRef: "legacy-user:581",
    contextKind,
    contextRef,
    resourceRef: "private-resource",
    capabilityRef: "private-capability",
    decision: index === 0 ? organizationDecision : "deny" as const
  }));
}

function decisionUniverse(
  keys: readonly (readonly string[])[],
  dimensions: Readonly<Record<string, readonly string[]>>
) {
  const canonicalKeys = [...new Set(keys.map((key) => JSON.stringify(key)))].sort();
  return {
    keyCount: canonicalKeys.length,
    keysHash: createOrganizationReconciliationEvidenceHash(EVIDENCE_NONCE, canonicalKeys),
    derivationContract: ORGANIZATION_RECONCILIATION_DECISION_DERIVATION_CONTRACT,
    derivationBuildRevision: TEST_COLLECTOR_BUILD_REVISION,
    dimensions: Object.fromEntries(Object.entries(dimensions).map(([name, values]) => {
      const canonicalValues = [...new Set(values)].sort();
      return [name, {
        count: canonicalValues.length,
        hash: createOrganizationReconciliationEvidenceHash(EVIDENCE_NONCE, canonicalValues)
      }];
    }))
  } as const;
}

function expectNoRawEvidence(serialized: string): void {
  for (const rawValue of [
    "private-org-name",
    "legacy-org:1",
    "private-org-title",
    "private-identity-org",
    "legacy-user:581",
    "private-role",
    "plugin:private",
    "private-binding",
    "private-campus",
    "private-resource",
    "private-capability",
    "private-source-version"
  ]) {
    expect(serialized).not.toContain(rawValue);
  }
}
