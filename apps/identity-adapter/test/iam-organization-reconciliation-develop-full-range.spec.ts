import { createHash } from "node:crypto";
import { chmod, mkdtemp, readFile, realpath, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/generated/iam-organization-reconciliation-compiled-revision.js", () => ({
  ORGANIZATION_RECONCILIATION_COMPILED_BUILD_REVISION: "a".repeat(40)
}));
import {
  ORGANIZATION_RECONCILIATION_DEVELOP_FULL_RANGE_CONTRACT,
  OrganizationReconciliationDevelopFullRangeError,
  runOrganizationReconciliationDevelopFullRange,
  type OrganizationReconciliationDevelopFullRangeDependencies,
  type OrganizationReconciliationDevelopFullRangeResult
} from "../src/iam-organization-reconciliation-develop-full-range.js";
import {
  createVerifiedOrganizationReconciliationDevelopSourceConnectionFactory
} from "../src/iam-organization-reconciliation-develop-source-preflight.js";
import {
  organizationReconciliationDevelopFullRangeHelp,
  runOrganizationReconciliationDevelopFullRangeCli
} from "../../../scripts/iam-organization-reconciliation-develop-full-range.js";
import type {
  MysqlRepeatableReadSnapshotConnectionFactory
} from "../src/iam-organization-reconciliation/mysql-repeatable-read-snapshot.js";
import {
  createOrganizationReconciliationDevelopDeploymentEvidenceForTest
} from "./iam-organization-reconciliation-develop-deployment-evidence.test-fixture.js";
import {
  createOrganizationReconciliationDevelopDeploymentEvidenceSha256
} from "../src/iam-organization-reconciliation-develop-deployment-evidence.js";

const REVISION = "a".repeat(40);
const USERS = Object.freeze({
  "legacy-main": "iam_org_legacy_ro",
  identity: "iam_org_identity_ro",
  plugin: "iam_org_plugin_ro"
});
const temporaryRoots: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryRoots.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe("xrteeth Develop full-range compiled trust-profile gate", () => {
  it("rejects an invalid public policy before connection, RNG-adjacent clock, signer, or output calls", async () => {
    let connectionOpens = 0;
    let clockCalls = 0;
    let signerCalls = 0;
    let outputCalls = 0;
    const dependencies = blockedDependencies(
      () => { connectionOpens += 1; },
      () => { clockCalls += 1; },
      () => { outputCalls += 1; },
      () => { signerCalls += 1; }
    );

    await expect(runOrganizationReconciliationDevelopFullRange(dependencies)).rejects.toEqual(
      expect.objectContaining({
        name: "OrganizationReconciliationDevelopFullRangeError",
        message: "trust-policy-invalid",
        failureId: "trust-policy-invalid"
      })
    );
    expect(connectionOpens).toBe(0);
    expect(clockCalls).toBe(0);
    expect(signerCalls).toBe(0);
    expect(outputCalls).toBe(0);
  });

  it("rejects environment, caller revision fields, unknown fields, aliases and accessors before dependencies run", async () => {
    let connectionOpens = 0;
    let clockCalls = 0;
    let outputCalls = 0;
    let accessorReads = 0;
    const valid = blockedDependencies(
      () => { connectionOpens += 1; },
      () => { clockCalls += 1; },
      () => { outputCalls += 1; }
    );
    const cases: unknown[] = [
      { ...valid, environment: "production" },
      { ...valid, buildRevision: "a".repeat(39) },
      { ...valid, buildRevision: "A".repeat(40) },
      { ...valid, extra: true },
      { ...valid, identityConnectionFactory: valid.legacyConnectionFactory },
      { ...valid, expectedDatabaseUsers: { ...USERS, plugin: USERS.identity } }
    ];
    const accessorClock: Record<string, unknown> = {};
    Object.defineProperty(accessorClock, "now", {
      enumerable: true,
      get() {
        accessorReads += 1;
        return () => new Date();
      }
    });
    cases.push({ ...valid, clock: accessorClock });

    for (const candidate of cases) {
      await expect(runOrganizationReconciliationDevelopFullRange(
        candidate as OrganizationReconciliationDevelopFullRangeDependencies
      )).rejects.toBeInstanceOf(OrganizationReconciliationDevelopFullRangeError);
      await expect(runOrganizationReconciliationDevelopFullRange(
        candidate as OrganizationReconciliationDevelopFullRangeDependencies
      )).rejects.toMatchObject({ failureId: "invalid-input" });
    }
    expect(connectionOpens).toBe(0);
    expect(clockCalls).toBe(0);
    expect(outputCalls).toBe(0);
    expect(accessorReads).toBe(0);
  });

  it("exports a lazy verified connection wrapper and releases an unaccepted source", async () => {
    let opens = 0;
    let releases = 0;
    const rawFactory: MysqlRepeatableReadSnapshotConnectionFactory = async () => {
      opens += 1;
      return Object.freeze({
        query: async () => [[], []] as [unknown[], unknown[]],
        release: async () => { releases += 1; }
      });
    };
    const verified = createVerifiedOrganizationReconciliationDevelopSourceConnectionFactory(
      "legacy-main",
      rawFactory,
      USERS["legacy-main"]
    );
    expect(opens).toBe(0);
    await expect(verified()).rejects.toThrow("grant set is outside the reviewed bound");
    expect(opens).toBe(1);
    expect(releases).toBe(1);
  });
});

describe("xrteeth Develop full-range CLI", () => {
  it("documents the mandatory exact two-signer HTTPS transport without private-key or pin overrides", async () => {
    const stdout: string[] = [];
    let runtimeCalls = 0;
    expect(await runOrganizationReconciliationDevelopFullRangeCli(
      ["--help"],
      {},
      { stdout: (text) => stdout.push(text), stderr: () => { runtimeCalls += 1; } },
      { assertTrustProfileProvisioned: () => { runtimeCalls += 1; } }
    )).toBe(0);
    expect(stdout).toEqual([organizationReconciliationDevelopFullRangeHelp]);
    expect(stdout[0]).toContain("--signer-transport=<absolute-owner-0600-json-path>");
    expect(stdout[0]).toContain("exactly one compiled-profile key ID, HTTPS");
    expect(stdout[0]).toContain("only keyId, endpoint, bearerTokenFile, and certificateAuthorityFile");
    expect(stdout[0]).toContain("deployment-evidence leaf DER SHA-256");
    expect(stdout[0]).toContain("cannot supply or");
    expect(runtimeCalls).toBe(0);
  });

  it("rejects an illegal environment, revision, or out-of-repository path before runtime construction", async () => {
    let factoryConstructions = 0;
    let executions = 0;
    const stdout: string[] = [];
    const stderr: string[] = [];
    const runtime = {
      repositoryRoot: "/private/tmp/reconciliation-repository",
      connectionFactory: () => {
        factoryConstructions += 1;
        return async () => { throw new Error("must not open"); };
      },
      executeFullRange: async () => {
        executions += 1;
        throw new Error("must not execute");
      }
    };
    for (const argv of [
      ["--environment=production", `--build-revision=${REVISION}`, "--trust-policy=/private/tmp/reconciliation-repository/policy.json", "--signer-transport=/private/tmp/reconciliation-repository/signer-transport.json", "--output=/private/tmp/reconciliation-repository/a.json"],
      ["--environment=xrteeth-develop", "--build-revision=short", "--trust-policy=/private/tmp/reconciliation-repository/policy.json", "--signer-transport=/private/tmp/reconciliation-repository/signer-transport.json", "--output=/private/tmp/reconciliation-repository/a.json"],
      ["--environment=xrteeth-develop", `--build-revision=${REVISION}`, "--trust-policy=/private/tmp/reconciliation-repository/policy.json", "--signer-transport=/private/tmp/reconciliation-repository/signer-transport.json", "--output=/private/tmp/outside.json"],
      ["--environment=xrteeth-develop", `--build-revision=${REVISION}`, "--trust-policy=/private/tmp/reconciliation-repository/policy.json", "--signer-transport=relative.json", "--output=/private/tmp/reconciliation-repository/a.json"]
    ]) {
      expect(await runOrganizationReconciliationDevelopFullRangeCli(argv, {}, {
        stdout: (text) => stdout.push(text),
        stderr: (text) => stderr.push(text)
      }, runtime)).toBe(2);
    }
    expect(factoryConstructions).toBe(0);
    expect(executions).toBe(0);
    expect(stdout).toEqual([]);
    expect(stderr).toHaveLength(4);
  });

  it("uses --build-revision only as an exact compiled-revision assertion", async () => {
    const root = await temporaryRoot();
    const outputPath = join(root, "must-not-exist.json");
    let runtimeCalls = 0;
    const stderr: string[] = [];
    const code = await runOrganizationReconciliationDevelopFullRangeCli(
      validArgv(outputPath, "b".repeat(40)),
      baseEnv(),
      { stdout: () => { runtimeCalls += 1; }, stderr: (text) => stderr.push(text) },
      {
        repositoryRoot: root,
        assertTrustProfileProvisioned: () => { runtimeCalls += 1; },
        loadTrustPolicy: () => { runtimeCalls += 1; return publicTrustPolicy(); },
        connectionFactory: () => { runtimeCalls += 1; return async () => { throw new Error("must not open"); }; },
        executeFullRange: async () => { runtimeCalls += 1; throw new Error("must not execute"); }
      }
    );
    expect(code).toBe(2);
    expect(runtimeCalls).toBe(0);
    expect(JSON.parse(stderr.join(""))).toMatchObject({
      status: "failed",
      failure: "compiled-revision-mismatch"
    });
    await expect(stat(outputPath)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("keeps a CLI with missing public inputs at zero connection opens and does not touch its output path", async () => {
    const root = await temporaryRoot();
    const outputPath = join(root, "blocked.json");
    let connectionOpens = 0;
    const stdout: string[] = [];
    const stderr: string[] = [];
    const code = await runOrganizationReconciliationDevelopFullRangeCli(
      validArgv(outputPath),
      baseEnv(),
      { stdout: (text) => stdout.push(text), stderr: (text) => stderr.push(text) },
      {
        repositoryRoot: root,
        connectionFactory: () => async () => {
          connectionOpens += 1;
          throw new Error("must remain gated");
        }
      }
    );
    expect(code).toBe(2);
    expect(connectionOpens).toBe(0);
    expect(stdout).toEqual([]);
    expect(JSON.parse(stderr.join(""))).toMatchObject({
      environment: "xrteeth-develop",
      mode: "read-only",
      status: "failed",
      failure: "invalid-configuration"
    });
    await expect(stat(outputPath)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("creates one raw artifact at 0600, prints only status/digest, and refuses overwrite or symlink targets", async () => {
    const root = await temporaryRoot();
    const outputPath = join(root, "full-range.json");
    const payload = "{\"rawBusinessEvidence\":\"must-stay-in-file\"}\n";
    const sha256 = createHash("sha256").update(payload, "utf8").digest("hex");
    const stdout: string[] = [];
    const stderr: string[] = [];
    const runtime = successfulRuntime(root, payload, sha256);

    expect(await runOrganizationReconciliationDevelopFullRangeCli(
      validArgv(outputPath),
      baseEnv(),
      { stdout: (text) => stdout.push(text), stderr: (text) => stderr.push(text) },
      runtime
    )).toBe(0);
    expect(stderr).toEqual([]);
    expect(stdout).toEqual([`${JSON.stringify({ status: "completed", sha256 })}\n`]);
    expect(stdout[0]).not.toContain("rawBusinessEvidence");
    expect(await readFile(outputPath, "utf8")).toBe(payload);
    expect((await stat(outputPath)).mode & 0o777).toBe(0o600);

    stdout.length = 0;
    stderr.length = 0;
    expect(await runOrganizationReconciliationDevelopFullRangeCli(
      validArgv(outputPath),
      baseEnv(),
      { stdout: (text) => stdout.push(text), stderr: (text) => stderr.push(text) },
      runtime
    )).toBe(2);
    expect(stdout).toEqual([]);
    expect(await readFile(outputPath, "utf8")).toBe(payload);

    const target = join(root, "ordinary-target.json");
    const link = join(root, "symlink-output.json");
    await writeFile(target, "unchanged", { mode: 0o600 });
    await symlink(target, link);
    stderr.length = 0;
    expect(await runOrganizationReconciliationDevelopFullRangeCli(
      validArgv(link),
      baseEnv(),
      { stdout: (text) => stdout.push(text), stderr: (text) => stderr.push(text) },
      runtime
    )).toBe(2);
    expect(await readFile(target, "utf8")).toBe("unchanged");
  });

  it("reads only an ordinary owner-0600 public trust-policy JSON and rejects permissive or symlink inputs", async () => {
    const payload = "{\"signed\":true}\n";
    const sha256 = createHash("sha256").update(payload, "utf8").digest("hex");

    const acceptedRoot = await temporaryRoot();
    const acceptedOutput = join(acceptedRoot, "accepted.json");
    const acceptedPolicy = join(acceptedRoot, "develop-public-trust-policy.json");
    const acceptedDeployment = join(acceptedRoot, "develop-deployment-evidence.json");
    await writeFile(acceptedPolicy, JSON.stringify(publicTrustPolicy()), { mode: 0o600 });
    await writeFile(
      acceptedDeployment,
      JSON.stringify(createOrganizationReconciliationDevelopDeploymentEvidenceForTest()),
      { mode: 0o600 }
    );
    const acceptedRuntime = successfulRuntime(acceptedRoot, payload, sha256);
    expect(await runOrganizationReconciliationDevelopFullRangeCli(
      validArgv(acceptedOutput),
      baseEnv(),
      { stdout: () => undefined, stderr: () => undefined },
      { ...acceptedRuntime, loadTrustPolicy: undefined, loadDeploymentEvidence: undefined }
    )).toBe(0);

    const permissiveRoot = await temporaryRoot();
    const permissiveOutput = join(permissiveRoot, "rejected.json");
    const permissivePolicy = join(permissiveRoot, "develop-public-trust-policy.json");
    await writeFile(permissivePolicy, JSON.stringify(publicTrustPolicy()), { mode: 0o600 });
    await chmod(permissivePolicy, 0o644);
    expect(await runOrganizationReconciliationDevelopFullRangeCli(
      validArgv(permissiveOutput),
      baseEnv(),
      { stdout: () => undefined, stderr: () => undefined },
      { ...successfulRuntime(permissiveRoot, payload, sha256), loadTrustPolicy: undefined }
    )).toBe(2);
    await expect(stat(permissiveOutput)).rejects.toMatchObject({ code: "ENOENT" });

    const symlinkRoot = await temporaryRoot();
    const symlinkOutput = join(symlinkRoot, "rejected.json");
    const target = join(symlinkRoot, "ordinary-policy.json");
    const link = join(symlinkRoot, "develop-public-trust-policy.json");
    await writeFile(target, JSON.stringify(publicTrustPolicy()), { mode: 0o600 });
    await symlink(target, link);
    expect(await runOrganizationReconciliationDevelopFullRangeCli(
      validArgv(symlinkOutput),
      baseEnv(),
      { stdout: () => undefined, stderr: () => undefined },
      { ...successfulRuntime(symlinkRoot, payload, sha256), loadTrustPolicy: undefined }
    )).toBe(2);
    await expect(stat(symlinkOutput)).rejects.toMatchObject({ code: "ENOENT" });
  });
});

function blockedDependencies(
  onOpen: () => void,
  onClock: () => void,
  onOutput: () => void,
  onSigner: () => void = () => undefined
): OrganizationReconciliationDevelopFullRangeDependencies {
  const factory = (): MysqlRepeatableReadSnapshotConnectionFactory => async () => {
    onOpen();
    throw new Error("must remain gated");
  };
  return {
    environment: "xrteeth-develop",
    deploymentEvidence: createOrganizationReconciliationDevelopDeploymentEvidenceForTest(),
    legacyConnectionFactory: factory(),
    identityConnectionFactory: factory(),
    pluginConnectionFactory: factory(),
    expectedDatabaseUsers: USERS,
    trustPolicy: {} as OrganizationReconciliationDevelopFullRangeDependencies["trustPolicy"],
    externalSigners: [{
      collectorId: "unprovisioned-collector",
      nodeId: "unprovisioned-node",
      keyId: "unprovisioned-key",
      publicKeySha256: "0".repeat(64),
      buildRevision: REVISION,
      sign: () => { onSigner(); return Buffer.alloc(64); }
    }],
    attestationTtlSeconds: 300,
    clock: { now: () => { onClock(); return new Date("2026-08-11T00:00:00.000Z"); } },
    output: { write: () => { onOutput(); } }
  };
}

async function temporaryRoot(): Promise<string> {
  const root = await realpath(await mkdtemp(join(tmpdir(), "iam-develop-full-range-")));
  temporaryRoots.push(root);
  return root;
}

function validArgv(outputPath: string, expectedBuildRevision = REVISION): string[] {
  return [
    "--environment=xrteeth-develop",
    `--build-revision=${expectedBuildRevision}`,
    `--deployment-evidence=${join(dirname(outputPath), "develop-deployment-evidence.json")}`,
    `--trust-policy=${join(dirname(outputPath), "develop-public-trust-policy.json")}`,
    `--signer-transport=${join(dirname(outputPath), "develop-signer-transport.json")}`,
    `--output=${outputPath}`
  ];
}

function successfulRuntime(
  repositoryRoot: string,
  payload: string,
  outputSha256: string
) {
  return {
    repositoryRoot,
    assertTrustProfileProvisioned: () => undefined,
    loadTrustPolicy: () => ({} as OrganizationReconciliationDevelopFullRangeDependencies["trustPolicy"]),
    loadDeploymentEvidence: () => createOrganizationReconciliationDevelopDeploymentEvidenceForTest(),
    externalSigners: [],
    connectionFactory: () => async () => { throw new Error("stub must not open a source"); },
    executeFullRange: async (
      dependencies: OrganizationReconciliationDevelopFullRangeDependencies
    ): Promise<OrganizationReconciliationDevelopFullRangeResult> => {
      expect(Object.hasOwn(dependencies, "buildRevision")).toBe(false);
      await dependencies.output.write(payload);
      return {
        contract: ORGANIZATION_RECONCILIATION_DEVELOP_FULL_RANGE_CONTRACT,
        environment: "xrteeth-develop",
        mode: "read-only",
        scope: "full-range",
        outcome: "completed",
        buildRevision: REVISION,
        deploymentEvidenceSha256:
          createOrganizationReconciliationDevelopDeploymentEvidenceSha256(
            dependencies.deploymentEvidence
          ),
        releaseImageDigest: dependencies.deploymentEvidence.releaseImageDigest,
        outputSha256,
        lineageManifestSha256: "b".repeat(64),
        datasetCount: 21,
        verifiedSurfaceCount: 8,
        externalProvenanceVerified: true,
        verifiedAttestationCount: 1,
        trustPolicySha256: "c".repeat(64),
        physicalIndependenceVerified: false,
        productionReady: false,
        productionPromotionAllowed: false
      };
    }
  };
}

function publicTrustPolicy() {
  const collector = (index: number) => ({
    collectorId: `collector-${index}`,
    nodeId: `node-${index}`,
    keyId: `key-${index}`,
    algorithm: "Ed25519" as const,
    publicKeyPem: `public-key-${index}`,
    publicKeySha256: String(index).repeat(64),
    buildRevision: REVISION,
    validFrom: "2026-08-11T00:00:00.000Z",
    validUntil: "2026-08-11T01:00:00.000Z"
  });
  return {
    contract: "iam-organization-reconciliation-trust-policy/v3" as const,
    profileId: "xrteeth-develop-single-signer",
    audience: "identity-service/iam-organization-reconciliation" as const,
    environment: "xrteeth-develop",
    validFrom: "2026-08-11T00:00:00.000Z",
    validUntil: "2026-08-11T01:00:00.000Z",
    maxEvidenceAgeSeconds: 600,
    maxAttestationTtlSeconds: 600,
    maxCollectionWindowSeconds: 600,
    clockSkewSeconds: 0,
    requiredCollectors: [collector(1)]
  };
}

function baseEnv(): NodeJS.ProcessEnv {
  return {
    LEGACY_DB_HOST: "shared-develop-db",
    LEGACY_DB_PORT: "3306",
    LEGACY_DB_NAME: "bujiaban_development",
    LEGACY_DB_USER: "legacy-service",
    LEGACY_DB_PASSWORD: "legacy-service-secret",
    IDENTITY_DB_HOST: "shared-develop-db",
    IDENTITY_DB_PORT: "3306",
    IDENTITY_DB_NAME: "xrugc_identity_dev",
    IDENTITY_DB_USER: "identity-service",
    IDENTITY_DB_PASSWORD: "identity-service-secret",
    IDENTITY_IAM_ORG_RECONCILIATION_LEGACY_DB_USER: USERS["legacy-main"],
    IDENTITY_IAM_ORG_RECONCILIATION_LEGACY_DB_PASSWORD: "legacy-readonly-secret",
    IDENTITY_IAM_ORG_RECONCILIATION_IDENTITY_DB_USER: USERS.identity,
    IDENTITY_IAM_ORG_RECONCILIATION_IDENTITY_DB_PASSWORD: "identity-readonly-secret",
    PLUGIN_DB_HOST: "shared-develop-db",
    PLUGIN_DB_PORT: "3306",
    PLUGIN_DB_NAME: "bujiaban_development_plugin",
    PLUGIN_DB_USER: USERS.plugin,
    PLUGIN_DB_PASSWORD: "plugin-readonly-secret"
  };
}
