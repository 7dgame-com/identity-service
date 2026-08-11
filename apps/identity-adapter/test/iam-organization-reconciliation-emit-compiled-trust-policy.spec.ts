import { createHash, generateKeyPairSync, type KeyObject } from "node:crypto";
import { mkdtemp, readFile, realpath, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  ORGANIZATION_RECONCILIATION_PROVENANCE_ALGORITHM,
  ORGANIZATION_RECONCILIATION_PROVENANCE_AUDIENCE,
  ORGANIZATION_RECONCILIATION_TRUST_POLICY_CONTRACT,
  createOrganizationReconciliationTrustPolicySha256
} from "../src/iam-organization-reconciliation-provenance.js";
import {
  compileOrganizationReconciliationTrustPolicyTemplates,
  compiledOrganizationReconciliationTrustProfileCount,
  resolveCompiledOrganizationReconciliationTrustPolicy,
  resolveCompiledOrganizationReconciliationTrustProfile,
  resolveSoleCompiledOrganizationReconciliationTrustBinding,
  selectSoleOrganizationReconciliationCompiledTrustBinding,
  serializeOrganizationReconciliationCompiledTrustPolicy,
  type OrganizationReconciliationCompiledTrustBindingRegistry,
  type OrganizationReconciliationTrustPolicyTemplate
} from "../src/iam-organization-reconciliation-trust-profiles.js";
import {
  organizationReconciliationEmitCompiledTrustPolicyHelp,
  runOrganizationReconciliationEmitCompiledTrustPolicyCli
} from "../../../scripts/iam-organization-reconciliation-emit-compiled-trust-policy.js";

const REVISION = "a".repeat(40);
const temporaryRoots: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryRoots.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe("compiled public reconciliation trust policy", () => {
  it("keeps the production registry empty and both public resolvers fail closed", async () => {
    expect(compiledOrganizationReconciliationTrustProfileCount).toBe(0);
    expect(resolveSoleCompiledOrganizationReconciliationTrustBinding()).toBeUndefined();
    expect(resolveCompiledOrganizationReconciliationTrustProfile("xrteeth-develop-7.2")).toBeUndefined();
    expect(resolveCompiledOrganizationReconciliationTrustPolicy("xrteeth-develop-7.2")).toBeUndefined();

    const root = await temporaryRoot();
    const output = join(root, "public-policy.json");
    const stdout: string[] = [];
    const stderr: string[] = [];
    expect(await runOrganizationReconciliationEmitCompiledTrustPolicyCli(
      [`--output=${output}`],
      { stdout: (text) => stdout.push(text), stderr: (text) => stderr.push(text) }
    )).toBe(1);
    expect(stdout).toEqual([]);
    expect(JSON.parse(stderr.join(""))).toMatchObject({
      environment: "xrteeth-develop",
      mode: "read-only",
      status: "failed",
      failure: "trust-profile-not-provisioned"
    });
    await expect(stat(output)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("derives one exact policy and profile from the same revision-independent public template", () => {
    const registry = compileOrganizationReconciliationTrustPolicyTemplates({
      "xrteeth-develop-7.2": template("xrteeth-develop-7.2")
    }, REVISION);
    const binding = selectSoleOrganizationReconciliationCompiledTrustBinding(registry);
    expect(binding).toBeDefined();
    expect(binding!.profile.policySha256).toBe(
      createOrganizationReconciliationTrustPolicySha256(binding!.policy)
    );
    expect(binding!.profile.expectedEnvironment).toBe(binding!.policy.environment);
    expect(binding!.profile.requiredCollectors).toEqual(binding!.policy.requiredCollectors.map((collector) => ({
      collectorId: collector.collectorId,
      nodeId: collector.nodeId,
      keyId: collector.keyId,
      publicKeySha256: collector.publicKeySha256,
      buildRevision: REVISION
    })));
    expect(binding!.policy.requiredCollectors.every((collector) => collector.buildRevision === REVISION)).toBe(true);
    expect(Object.isFrozen(binding)).toBe(true);
    expect(Object.isFrozen(binding!.policy)).toBe(true);
    expect(Object.isFrozen(binding!.policy.requiredCollectors)).toBe(true);

    const payload = serializeOrganizationReconciliationCompiledTrustPolicy(binding!);
    expect(payload.endsWith("\n")).toBe(true);
    expect(JSON.parse(payload)).toEqual(binding!.policy);
    expect(payload).not.toMatch(/PRIVATE KEY|privateKey|private_key|pkcs8/i);
    expect(payload.indexOf('"audience"')).toBeLessThan(payload.indexOf('"contract"'));
  });

  it("rejects zero, multiple, revision-invalid, public-key-invalid, and mismatched compilations", () => {
    expect(selectSoleOrganizationReconciliationCompiledTrustBinding(Object.freeze({}))).toBeUndefined();
    const two = compileOrganizationReconciliationTrustPolicyTemplates({
      "xrteeth-develop-7.2-a": template("xrteeth-develop-7.2-a"),
      "xrteeth-develop-7.2-b": template("xrteeth-develop-7.2-b")
    }, REVISION);
    expect(Object.keys(two)).toHaveLength(2);
    expect(selectSoleOrganizationReconciliationCompiledTrustBinding(two)).toBeUndefined();
    expect(Object.keys(compileOrganizationReconciliationTrustPolicyTemplates({
      "xrteeth-develop-7.2": template("xrteeth-develop-7.2")
    }, null))).toHaveLength(0);

    const privateKey = generateKeyPairSync("ed25519").privateKey.export({
      format: "pem", type: "pkcs8"
    }).toString();
    const invalidPublic = template("xrteeth-develop-7.2");
    invalidPublic.requiredCollectors[0]!.publicKeyPem = privateKey;
    expect(Object.keys(compileOrganizationReconciliationTrustPolicyTemplates({
      "xrteeth-develop-7.2": invalidPublic
    }, REVISION))).toHaveLength(0);

    const one = compileOrganizationReconciliationTrustPolicyTemplates({
      "xrteeth-develop-7.2": template("xrteeth-develop-7.2")
    }, REVISION);
    const valid = one["xrteeth-develop-7.2"]!;
    const mismatch = {
      "xrteeth-develop-7.2": {
        policy: valid.policy,
        profile: { ...valid.profile, policySha256: "f".repeat(64) }
      }
    } as OrganizationReconciliationCompiledTrustBindingRegistry;
    expect(selectSoleOrganizationReconciliationCompiledTrustBinding(mismatch)).toBeUndefined();
  });
});

describe("compiled public trust-policy emitter CLI", () => {
  it("documents and enforces an output-only interface with no pin/revision/collector override", async () => {
    const stdout: string[] = [];
    let resolverCalls = 0;
    expect(await runOrganizationReconciliationEmitCompiledTrustPolicyCli(
      ["--help"],
      { stdout: (text) => stdout.push(text), stderr: () => { resolverCalls += 1; } },
      { resolveCompiledBinding: () => { resolverCalls += 1; return undefined; } }
    )).toBe(0);
    expect(stdout).toEqual([organizationReconciliationEmitCompiledTrustPolicyHelp]);
    expect(stdout[0]).toContain("--output=<absolute-new-json-path>");
    expect(stdout[0]).toContain("There is no profile, revision, collector, key/pin, environment");
    expect(resolverCalls).toBe(0);

    for (const argv of [
      [],
      ["--profile=xrteeth-develop-7.2"],
      ["--revision=" + REVISION],
      ["--collector=collector-a"],
      ["--output=/tmp/a.json", "--pin=" + "a".repeat(64)]
    ]) {
      expect(await runOrganizationReconciliationEmitCompiledTrustPolicyCli(
        argv,
        { stdout: () => undefined, stderr: () => undefined },
        { resolveCompiledBinding: () => { resolverCalls += 1; return undefined; } }
      )).toBe(2);
    }
    expect(resolverCalls).toBe(0);
  });

  it("writes canonical public JSON exactly once with owner mode 0600", async () => {
    const root = await temporaryRoot();
    const output = join(root, "public-policy.json");
    const binding = selectSoleOrganizationReconciliationCompiledTrustBinding(
      compileOrganizationReconciliationTrustPolicyTemplates({
        "xrteeth-develop-7.2": template("xrteeth-develop-7.2")
      }, REVISION)
    )!;
    const expected = serializeOrganizationReconciliationCompiledTrustPolicy(binding);
    const stdout: string[] = [];
    const stderr: string[] = [];
    const runtime = { resolveCompiledBinding: () => binding };
    expect(await runOrganizationReconciliationEmitCompiledTrustPolicyCli(
      [`--output=${output}`],
      { stdout: (text) => stdout.push(text), stderr: (text) => stderr.push(text) },
      runtime
    )).toBe(0);
    expect(stderr).toEqual([]);
    expect(await readFile(output, "utf8")).toBe(expected);
    expect((await stat(output)).mode & 0o777).toBe(0o600);
    expect(JSON.parse(stdout.join(""))).toEqual({
      status: "emitted",
      policySha256: createHash("sha256").update(expected.slice(0, -1), "utf8").digest("hex")
    });

    stdout.length = 0;
    stderr.length = 0;
    expect(await runOrganizationReconciliationEmitCompiledTrustPolicyCli(
      [`--output=${output}`],
      { stdout: (text) => stdout.push(text), stderr: (text) => stderr.push(text) },
      runtime
    )).toBe(2);
    expect(stdout).toEqual([]);
    expect(await readFile(output, "utf8")).toBe(expected);

    const ordinary = join(root, "ordinary.json");
    const link = join(root, "linked.json");
    await writeFile(ordinary, "unchanged", { mode: 0o600 });
    await symlink(ordinary, link);
    expect(await runOrganizationReconciliationEmitCompiledTrustPolicyCli(
      [`--output=${link}`],
      { stdout: () => undefined, stderr: () => undefined },
      runtime
    )).toBe(2);
    expect(await readFile(ordinary, "utf8")).toBe("unchanged");
  });
});

async function temporaryRoot(): Promise<string> {
  const root = await realpath(await mkdtemp(join(tmpdir(), "iam-compiled-policy-")));
  temporaryRoots.push(root);
  return root;
}

function template(profileId: string): OrganizationReconciliationTrustPolicyTemplate {
  const first = publicCollector("collector-a", "node-a", "key-a", generateKeyPairSync("ed25519").publicKey);
  return {
    contract: ORGANIZATION_RECONCILIATION_TRUST_POLICY_CONTRACT,
    profileId,
    audience: ORGANIZATION_RECONCILIATION_PROVENANCE_AUDIENCE,
    environment: "xrteeth-develop",
    validFrom: "2026-08-01T00:00:00.000Z",
    validUntil: "2026-09-01T00:00:00.000Z",
    maxEvidenceAgeSeconds: 3_600,
    maxAttestationTtlSeconds: 300,
    maxCollectionWindowSeconds: 600,
    clockSkewSeconds: 30,
    requiredCollectors: [first]
  };
}

function publicCollector(
  collectorId: string,
  nodeId: string,
  keyId: string,
  publicKey: KeyObject
): OrganizationReconciliationTrustPolicyTemplate["requiredCollectors"][number] {
  const publicKeyPem = publicKey.export({ format: "pem", type: "spki" }).toString();
  const publicKeySha256 = createHash("sha256")
    .update(publicKey.export({ format: "der", type: "spki" }))
    .digest("hex");
  return {
    collectorId,
    nodeId,
    keyId,
    algorithm: ORGANIZATION_RECONCILIATION_PROVENANCE_ALGORITHM,
    publicKeyPem,
    publicKeySha256,
    validFrom: "2026-08-01T00:00:00.000Z",
    validUntil: "2026-09-01T00:00:00.000Z"
  };
}
