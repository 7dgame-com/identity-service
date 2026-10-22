import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
const execute = promisify(execFile), root = fileURLToPath(new URL("../../../", import.meta.url));
const workflow = await readFile(join(root, ".github/workflows/ci-cd.yml"), "utf8");
const executor = workflow.split("\n  build-executor:\n")[1];
function code(step: string): string {
  const section = executor.split(`      - name: ${step}\n`)[1]?.split("\n      - name:")[0];
  const script = section?.match(/node -e '\n([\s\S]*?)\n          '/)?.[1];
  if (!script) throw new Error("FIXTURE_WORKFLOW_SCRIPT_MISSING");
  return script.split("\n").map(line => line.slice(10)).join("\n");
}
const sha = "a".repeat(40), digest = "sha256:" + "b".repeat(64), repository = "hkccr.ccs.tencentyun.com/gdgeek/identity-service";
describe("dedicated executor publication contract", () => {
  it("keeps the complete existing HTTP publication job unchanged", () => {
    const http = workflow.slice(workflow.indexOf("\n  build:\n") + 1, workflow.indexOf("\n  build-executor:\n")).trimEnd() + "\n";
    expect(createHash("sha256").update(http).digest("hex")).toBe("26095ce07062e3949f00237f2028ec906bbe42e93d6aeb2f62bf549392969d18");
  });
  it("is dispatch-only, false by default and requires both mandatory jobs", () => {
    expect(workflow).toMatch(/publish_executor:\n(?:[^\n]*\n)*?        type: boolean\n        required: false\n        default: false/);
    expect(executor).toContain("needs: [test, mysql-integration]");
    expect(executor).toContain("if: github.event_name == 'workflow_dispatch' && inputs.publish_executor == true");
    expect(executor).not.toContain("continue-on-error");
    expect(executor).toContain("target: migration-executor"); expect(executor).toContain("platforms: linux/amd64");
    expect(executor).toContain("tags: ${{ steps.executor-tag.outputs.tag }}");
    expect(executor).not.toMatch(/type=ref|value=latest|value=develop|value=candidate/);
  });
  it("runs every opt-in MySQL file once with the new owner/source cases mandatory and the independent group serial", () => {
    const mysql = workflow.split("\n  mysql-integration:\n")[1].split("\n  build:\n")[0];
    const paths = mysql.match(/apps\/identity-adapter\/test\/[A-Za-z0-9.-]+\.spec\.ts/g) ?? [];
    expect(new Set(paths).size).toBe(paths.length);
    for (const name of ["identity-owned-executor.mysql.spec.ts", "identity-source-fingerprint.mysql.spec.ts"])
      expect(paths.filter(p => p.endsWith("/" + name))).toHaveLength(1);
    const group = mysql.split("- name: Run independent authority and migration integration tests")[1].split("- name:")[0];
    expect(group).toContain("npm test -- --maxWorkers=1 --no-file-parallelism");
    expect(group).not.toMatch(/timeout|skip|300[1-9]|4000/);
  });
  it("reuses only the existing registry and credentials and verifies a pulled exact digest without network", () => {
    expect(executor).toContain("registry: ${{ env.REGISTRY }}");
    expect(executor).toContain("${{ secrets.TENCENT_REGISTRY_USER || secrets.TENCENT_REGISTRY_USERNAME }}");
    expect(executor).toContain("${{ secrets.TENCENT_REGISTRY_PASSWORD }}");
    expect(executor).toContain("@${{ steps.executor-build.outputs.digest }}");
    expect(executor).toContain('docker pull "${EXECUTOR_IMAGE}"');
    expect(executor).toContain('docker run --rm --network=none --read-only --entrypoint=node "${EXECUTOR_IMAGE}" scripts/verify-identity-finalization-runtime.mjs --executor');
    expect(executor).toContain("path: identity-executor-image-provenance.json");
    expect(executor).not.toContain("path: identity-executor-image-config.json");
    expect(executor).toContain("if-no-files-found: error");
  });
});

describe("actual workflow provenance programs", () => {
  let directory: string, env: NodeJS.ProcessEnv, config: any, runtime: any, layout: any, adapter: any;
  beforeEach(async () => {
    directory = await mkdtemp(join(tmpdir(), "executor-provenance-")); await mkdir(join(directory, "packages/identity-finalization-runtime"), { recursive: true });
    adapter = JSON.parse(await readFile(join(root, "packages/identity-finalization-runtime/upstream-manifest.json"), "utf8"));
    env = { ...process.env, EXECUTOR_SOURCE_SHA: sha, EXECUTOR_IMAGE_DIGEST: digest, EXECUTOR_REPOSITORY: repository,
      EXECUTOR_TAG: `${repository}:executor-${sha}-123-2`, EXECUTOR_RUN_ID: "123", EXECUTOR_RUN_ATTEMPT: "2", GITHUB_OUTPUT: join(directory, "public-action-output") };
    config = { User: "node", WorkingDir: "/opt/xrugc/identity", Entrypoint: ["node", "dist/scripts/identity-owned-executor.js"], Cmd: [],
      Labels: { "org.opencontainers.image.revision": sha, "io.xrugc.identity.stage": "migration-executor" }, Env: ["FORBIDDEN_ENV_CONTENT=must-never-appear-in-artifact"] };
    runtime = { gitCommit: sha, compiledRevision: sha, entrySha256: Object.fromEntries(["account-sync", "allocator-highwater", "identity-activate", "identity-owned-executor"].map(n => [n, "c".repeat(64)])),
      vendorSha256: Object.fromEntries(adapter.files.map((f: any) => [f.path, f.sha256])) };
    layout = { verified: true, executorLayout: true, upstreamCommit: adapter.upstreamCommit };
  });
  afterEach(async () => { await rm(directory, { recursive: true, force: true }); });
  const writeFixtures = async () => {
    await writeFile(join(directory, "identity-executor-layout-validation.json"), JSON.stringify(layout));
    await writeFile(join(directory, "identity-executor-runtime-metadata.json"), JSON.stringify(runtime));
    await writeFile(join(directory, "identity-executor-image-config.json"), JSON.stringify(config));
    await writeFile(join(directory, "packages/identity-finalization-runtime/upstream-manifest.json"), JSON.stringify(adapter));
  };
  it("emits exactly one unique SHA/run/attempt tag, with no floating publication", async () => {
    await execute(process.execPath, ["-e", code("Fix one immutable run-scoped executor tag")], { cwd: directory, env });
    expect(await readFile(env.GITHUB_OUTPUT!, "utf8")).toBe(`tag=${env.EXECUTOR_TAG}\n`);
  });
  it("records actual source, stage, digest, compiled/OCI/layout and runtime hashes without exposing environment", async () => {
    await writeFixtures(); await execute(process.execPath, ["-e", code("Record separate immutable executor provenance")], { cwd: directory, env });
    const raw = await readFile(join(directory, "identity-executor-image-provenance.json"), "utf8"), artifact = JSON.parse(raw);
    expect(artifact).toMatchObject({ contract: "identity-service/executor-image-provenance/v1", stage: "migration-executor", sourceGitSha: sha,
      gitSha: sha, image: `${repository}@${digest}`, imageDigest: digest, tag: env.EXECUTOR_TAG, compiledRevision: sha, gitCommit: sha, runtimeLayoutVerified: true,
      adapter: { upstreamCommit: adapter.upstreamCommit, runtimeSha256: runtime.vendorSha256 }, entrySha256: runtime.entrySha256,
      imageConfig: { user: "node", workingDir: "/opt/xrugc/identity", ociRevision: sha, stageLabel: "migration-executor" } });
    expect(raw).not.toContain("FORBIDDEN_ENV_CONTENT"); expect(raw).not.toContain("must-never-appear-in-artifact");
  });
  for (const field of ["tag", "stage", "compiled", "runtime-vendor", "layout", "entrypoint"])
    it(`rejects ${field} substitution without emitting provenance`, async () => {
      if (field === "tag") env.EXECUTOR_TAG = `${repository}:develop`;
      if (field === "stage") config.Labels["io.xrugc.identity.stage"] = "runtime";
      if (field === "compiled") runtime.compiledRevision = "d".repeat(40);
      if (field === "runtime-vendor") runtime.vendorSha256["migration-plan.mjs"] = "d".repeat(64);
      if (field === "layout") layout.verified = false;
      if (field === "entrypoint") config.Entrypoint = ["node", "dist/apps/identity-adapter/src/main.js"];
      await writeFixtures();
      await expect(execute(process.execPath, ["-e", code("Record separate immutable executor provenance")], { cwd: directory, env })).rejects.toMatchObject({ code: 2, stdout: "" });
      await expect(readFile(join(directory, "identity-executor-image-provenance.json"))).rejects.toMatchObject({ code: "ENOENT" });
    });
});
