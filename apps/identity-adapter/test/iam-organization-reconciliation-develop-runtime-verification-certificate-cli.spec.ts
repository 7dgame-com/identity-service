import { chmod, lstat, mkdtemp, readFile, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/iam-organization-reconciliation-develop-deployment-topology.js", () => ({
  bindOrganizationReconciliationDevelopDeploymentEvidenceToCompiledTopology: (candidate: unknown) =>
    Object.freeze({ topology: Object.freeze({ profileId: "test" }), deploymentEvidence: candidate,
      physicalIndependenceVerified: false as const, productionPromotionAllowed: false as const })
}));
import {
  organizationReconciliationDevelopRuntimeCertificateHelp,
  runOrganizationReconciliationDevelopRuntimeCertificateCli
} from "../../../scripts/iam-organization-reconciliation-develop-runtime-verification-certificate.js";
import {
  createOrganizationReconciliationDevelopRuntimeCertificateTestFixture
} from "./iam-organization-reconciliation-develop-runtime-verification-certificate.test-fixture.js";

const temporaryRoots: string[] = [];

afterEach(async () => {
  vi.unstubAllGlobals();
  await Promise.all(temporaryRoots.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe("Develop Task 7.2 runtime verification certificate CLI", () => {
  it("creates two owner-0600 O_EXCL outputs and emits only public digests", async () => {
    const prepared = await prepareFiles();
    const stdout: string[] = [];
    const stderr: string[] = [];
    let fetchCalls = 0;
    vi.stubGlobal("fetch", () => {
      fetchCalls += 1;
      throw new Error("network must remain unused");
    });

    expect(await runOrganizationReconciliationDevelopRuntimeCertificateCli(
      argv("create", prepared),
      { stdout: (text) => stdout.push(text), stderr: (text) => stderr.push(text) },
      {
        repositoryRoot: prepared.root,
        resolveTrustProfile: () => prepared.fixture.input.trustedProfile,
        now: () => new Date("2026-08-09T00:07:00.000Z")
      }
    )).toBe(0);
    expect(fetchCalls).toBe(0);
    expect(stderr).toEqual([]);
    expect(JSON.parse(stdout.join(""))).toMatchObject({
      status: "created",
      certificateSha256: expect.stringMatching(/^[a-f0-9]{64}$/),
      authoritativeCertificateSha256: expect.stringMatching(/^[a-f0-9]{64}$/),
      closeoutSha256: expect.stringMatching(/^[a-f0-9]{64}$/)
    });
    expect((await stat(prepared.certificatePath)).mode & 0o777).toBe(0o600);
    expect((await stat(prepared.closeoutPath)).mode & 0o777).toBe(0o600);
    const certificate = await readFile(prepared.certificatePath, "utf8");
    const closeout = await readFile(prepared.closeoutPath, "utf8");
    expect(certificate.endsWith("\n")).toBe(true);
    expect(closeout.endsWith("\n")).toBe(true);
    for (const privateValue of prepared.fixture.privateValues) {
      expect(`${stdout.join("")}\n${certificate}\n${closeout}`).not.toContain(privateValue);
    }
  });

  it("verifies the created files historically without reading a current clock", async () => {
    const prepared = await prepareFiles();
    const runtime = {
      repositoryRoot: prepared.root,
      resolveTrustProfile: () => prepared.fixture.input.trustedProfile,
      now: () => new Date("2026-08-09T00:07:00.000Z")
    };
    expect(await runOrganizationReconciliationDevelopRuntimeCertificateCli(
      argv("create", prepared),
      { stdout: () => undefined, stderr: () => undefined },
      runtime
    )).toBe(0);
    const stdout: string[] = [];
    expect(await runOrganizationReconciliationDevelopRuntimeCertificateCli(
      argv("verify", prepared),
      { stdout: (text) => stdout.push(text), stderr: () => undefined },
      {
        repositoryRoot: prepared.root,
        resolveTrustProfile: () => prepared.fixture.input.trustedProfile,
        now: () => { throw new Error("verify must not read current time"); }
      }
    )).toBe(0);
    expect(JSON.parse(stdout.join(""))).toMatchObject({ status: "verified" });
  });

  it("refuses overwrite and leaves no first output when the second target already exists", async () => {
    const prepared = await prepareFiles();
    await writeFile(prepared.closeoutPath, "unchanged\n", { mode: 0o600 });
    await chmod(prepared.closeoutPath, 0o600);
    const stderr: string[] = [];
    expect(await runOrganizationReconciliationDevelopRuntimeCertificateCli(
      argv("create", prepared),
      { stdout: () => undefined, stderr: (text) => stderr.push(text) },
      {
        repositoryRoot: prepared.root,
        resolveTrustProfile: () => prepared.fixture.input.trustedProfile,
        now: () => new Date("2026-08-09T00:07:00.000Z")
      }
    )).toBe(2);
    await expect(lstat(prepared.certificatePath)).rejects.toMatchObject({ code: "ENOENT" });
    expect(await readFile(prepared.closeoutPath, "utf8")).toBe("unchanged\n");
    expect(JSON.parse(stderr.join(""))).toMatchObject({ failure: "invalid-output-path" });
  });

  it("rejects symlink or permissive inputs before certificate creation", async () => {
    const permissive = await prepareFiles();
    await chmod(permissive.rawPath, 0o644);
    expect(await runOrganizationReconciliationDevelopRuntimeCertificateCli(
      argv("create", permissive),
      { stdout: () => undefined, stderr: () => undefined },
      {
        repositoryRoot: permissive.root,
        resolveTrustProfile: () => permissive.fixture.input.trustedProfile,
        now: () => new Date("2026-08-09T00:07:00.000Z")
      }
    )).toBe(2);
    await expect(lstat(permissive.certificatePath)).rejects.toMatchObject({ code: "ENOENT" });

    const linked = await prepareFiles();
    const ordinary = join(linked.root, "ordinary-raw.json");
    await writeFile(ordinary, linked.fixture.input.rawArtifactBytes, { mode: 0o600 });
    await chmod(ordinary, 0o600);
    const link = join(linked.root, "linked-raw.json");
    await symlink(ordinary, link);
    expect(await runOrganizationReconciliationDevelopRuntimeCertificateCli(
      argv("create", { ...linked, rawPath: link }),
      { stdout: () => undefined, stderr: () => undefined },
      {
        repositoryRoot: linked.root,
        resolveTrustProfile: () => linked.fixture.input.trustedProfile,
        now: () => new Date("2026-08-09T00:07:00.000Z")
      }
    )).toBe(2);
    await expect(lstat(linked.certificatePath)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("fails closed when the compiled profile is absent", async () => {
    const prepared = await prepareFiles();
    const stderr: string[] = [];
    expect(await runOrganizationReconciliationDevelopRuntimeCertificateCli(
      argv("create", prepared),
      { stdout: () => undefined, stderr: (text) => stderr.push(text) },
      { repositoryRoot: prepared.root, resolveTrustProfile: () => undefined }
    )).toBe(1);
    expect(JSON.parse(stderr.join(""))).toMatchObject({ failure: "trust-profile-not-provisioned" });
    await expect(lstat(prepared.certificatePath)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it.each([
    ["both actions", ["--create", "--verify"]],
    ["neither action", []],
    ["wrong environment", ["--create", "--environment=production"]]
  ])("rejects invalid arguments: %s", async (_label, prefix) => {
    const root = await temporaryRoot();
    const args = prefix.length === 2
      ? [...prefix, "--environment=xrteeth-develop"]
      : prefix;
    expect(await runOrganizationReconciliationDevelopRuntimeCertificateCli(
      args,
      { stdout: () => undefined, stderr: () => undefined },
      { repositoryRoot: root }
    )).toBe(2);
  });

  it("shows help without resolving a repository or reading a file", async () => {
    const stdout: string[] = [];
    expect(await runOrganizationReconciliationDevelopRuntimeCertificateCli(
      ["--help"],
      { stdout: (text) => stdout.push(text), stderr: () => undefined },
      { repositoryRoot: "/path/that/must/not/be/read" }
    )).toBe(0);
    expect(stdout.join("")).toBe(organizationReconciliationDevelopRuntimeCertificateHelp);
  });
});

interface PreparedFiles {
  readonly root: string;
  readonly fixture: ReturnType<typeof createOrganizationReconciliationDevelopRuntimeCertificateTestFixture>;
  readonly rawPath: string;
  readonly deploymentPath: string;
  readonly physicalProbePath: string;
  readonly trustPolicyPath: string;
  readonly certificatePath: string;
  readonly closeoutPath: string;
}

async function prepareFiles(): Promise<PreparedFiles> {
  const root = await temporaryRoot();
  const fixture = createOrganizationReconciliationDevelopRuntimeCertificateTestFixture();
  const prepared = {
    root,
    fixture,
    rawPath: join(root, "raw-full-range.json"),
    deploymentPath: join(root, "deployment-evidence.json"),
    physicalProbePath: join(root, "physical-probe.json"),
    trustPolicyPath: join(root, "trust-policy.json"),
    certificatePath: join(root, "runtime-certificate.json"),
    closeoutPath: join(root, "runtime-closeout.json")
  };
  await Promise.all([
    privateWrite(prepared.rawPath, fixture.input.rawArtifactBytes),
    privateWrite(prepared.deploymentPath, fixture.input.deploymentEvidenceBytes),
    privateWrite(prepared.physicalProbePath, fixture.input.physicalProbeBytes),
    privateWrite(prepared.trustPolicyPath, fixture.input.trustPolicyBytes)
  ]);
  return prepared;
}

function argv(action: "create" | "verify", prepared: Omit<PreparedFiles, "fixture">): string[] {
  return [
    action === "create" ? "--create" : "--verify",
    "--environment=xrteeth-develop",
    `--raw=${prepared.rawPath}`,
    `--deployment-evidence=${prepared.deploymentPath}`,
    `--physical-probe=${prepared.physicalProbePath}`,
    `--trust-policy=${prepared.trustPolicyPath}`,
    `--certificate=${prepared.certificatePath}`,
    `--closeout=${prepared.closeoutPath}`
  ];
}

async function privateWrite(path: string, bytes: Buffer): Promise<void> {
  await writeFile(path, bytes, { mode: 0o600 });
  await chmod(path, 0o600);
}

async function temporaryRoot(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "iam-runtime-certificate-"));
  temporaryRoots.push(root);
  return root;
}
