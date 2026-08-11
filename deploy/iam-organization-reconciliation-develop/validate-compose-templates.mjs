#!/usr/bin/env node

import { isIP } from "node:net";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const ROOT = dirname(fileURLToPath(import.meta.url));
const ONE_GIB = 1_073_741_824;
const SHA256_DIGEST = /^sha256:[a-f0-9]{64}$/;
const REVISION = /^[a-f0-9]{40}$/;
const SAFE_NAME = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/;
const SAFE_USER = /^[A-Za-z0-9_.-]{1,64}$/;
const SAFE_EVIDENCE_FILE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,126}\.json$/;
const REPOSITORY = /^[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]{1,5})?(?:\/[a-z0-9]+(?:[._-][a-z0-9]+)*)+$/;

const COMMON_KEYS = Object.freeze([
  "IDENTITY_DEVELOP_IMAGE_REPOSITORY",
  "IDENTITY_DEVELOP_IMAGE_DIGEST"
]);
const SIGNER_KEYS = Object.freeze([
  ...COMMON_KEYS,
  "DEVELOP_SIGNER_CONTAINER_IPV4",
  "DEVELOP_SIGNER_BIND_IPV4",
  "DEVELOP_SIGNER_PRIVATE_NETWORK",
  "DEVELOP_SIGNER_PRIVATE_SUBNET",
  "DEVELOP_SIGNER_LOCAL_SECRET_VOLUME"
]);
const RUNNER_KEYS = Object.freeze([
  ...COMMON_KEYS,
  "IDENTITY_DEVELOP_BUILD_REVISION",
  "IDENTITY_DEVELOP_EVIDENCE_FILE",
  "DEVELOP_LEGACY_DB_HOST",
  "DEVELOP_LEGACY_DB_PORT",
  "DEVELOP_LEGACY_RO_DB_USER",
  "DEVELOP_LEGACY_RO_DB_PASSWORD",
  "DEVELOP_IDENTITY_DB_HOST",
  "DEVELOP_IDENTITY_DB_PORT",
  "DEVELOP_IDENTITY_RO_DB_USER",
  "DEVELOP_IDENTITY_RO_DB_PASSWORD",
  "DEVELOP_PLUGIN_DB_HOST",
  "DEVELOP_PLUGIN_DB_PORT",
  "DEVELOP_PLUGIN_RO_DB_USER",
  "DEVELOP_PLUGIN_RO_DB_PASSWORD",
  "DEVELOP_RUNNER_EGRESS_NETWORK",
  "DEVELOP_RUNNER_LOCAL_CONFIG_VOLUME",
  "DEVELOP_RUNNER_LOCAL_EVIDENCE_VOLUME",
  "DEVELOP_RUNNER_EVIDENCE_CAPACITY_BYTES"
]);
const ALL_KEYS = Object.freeze([...new Set([...SIGNER_KEYS, ...RUNNER_KEYS])]);

class ValidationError extends Error {}

function fail() {
  throw new ValidationError("invalid-develop-compose-input");
}

function ownText(env, key, maximum = 4_096) {
  if (!Object.hasOwn(env, key) || typeof env[key] !== "string") fail();
  const value = env[key];
  if (value.length < 1 || value.length > maximum || /[\u0000-\u001f\u007f]/.test(value)) fail();
  return value;
}

function assertNotPlaceholder(value) {
  if (/[<>]/.test(value) || /(?:^|[._/-])(example|placeholder|changeme|todo)(?:$|[._/-])/i.test(value)) fail();
}

function assertCommon(env) {
  const repository = ownText(env, "IDENTITY_DEVELOP_IMAGE_REPOSITORY", 255);
  const digest = ownText(env, "IDENTITY_DEVELOP_IMAGE_DIGEST", 71);
  assertNotPlaceholder(repository);
  if (!REPOSITORY.test(repository) || repository.includes("@") || !SHA256_DIGEST.test(digest) ||
    /^sha256:0{64}$/.test(digest)) fail();
  return `${repository}@${digest}`;
}

function parsePort(env, key) {
  const value = ownText(env, key, 5);
  if (!/^[1-9][0-9]{0,4}$/.test(value)) fail();
  const port = Number(value);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) fail();
  return port;
}

function parseIpv4(value) {
  if (isIP(value) !== 4) fail();
  const octets = value.split(".").map(Number);
  if (octets.length !== 4) fail();
  return octets.reduce((accumulator, octet) => ((accumulator << 8) | octet) >>> 0, 0);
}

function isRfc1918Ipv4(value) {
  const octets = value.split(".").map(Number);
  return octets[0] === 10 || octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31 ||
    octets[0] === 192 && octets[1] === 168;
}

function parsePrivateIpv4(env, key) {
  const value = ownText(env, key, 15);
  parseIpv4(value);
  if (!isRfc1918Ipv4(value)) fail();
  return value;
}

function parsePrivateCidr(env, key) {
  const value = ownText(env, key, 18);
  const parts = value.split("/");
  if (parts.length !== 2 || !/^(?:[89]|[12][0-9]|30)$/.test(parts[1])) fail();
  const address = parts[0];
  const prefix = Number(parts[1]);
  const numeric = parseIpv4(address);
  if (!isRfc1918Ipv4(address)) fail();
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  if (((numeric & mask) >>> 0) !== numeric) fail();
  return Object.freeze({ value, numeric, prefix, mask });
}

function parseSafeName(env, key) {
  const value = ownText(env, key, 128);
  assertNotPlaceholder(value);
  if (!SAFE_NAME.test(value)) fail();
  return value;
}

function validateSigner(env) {
  const expectedImage = assertCommon(env);
  const containerAddress = parsePrivateIpv4(env, "DEVELOP_SIGNER_CONTAINER_IPV4");
  const bindAddress = parsePrivateIpv4(env, "DEVELOP_SIGNER_BIND_IPV4");
  const cidr = parsePrivateCidr(env, "DEVELOP_SIGNER_PRIVATE_SUBNET");
  const numericContainerAddress = parseIpv4(containerAddress);
  const broadcast = (cidr.numeric | (~cidr.mask >>> 0)) >>> 0;
  if (((numericContainerAddress & cidr.mask) >>> 0) !== cidr.numeric ||
    numericContainerAddress === cidr.numeric || numericContainerAddress === cidr.numeric + 1 ||
    numericContainerAddress === broadcast ||
    containerAddress === bindAddress) fail();
  parseSafeName(env, "DEVELOP_SIGNER_PRIVATE_NETWORK");
  parseSafeName(env, "DEVELOP_SIGNER_LOCAL_SECRET_VOLUME");
  return renderAndInspect("signer", env, expectedImage);
}

function parseHost(env, key) {
  const value = ownText(env, key, 253);
  assertNotPlaceholder(value);
  if (isIP(value) === 4) return value;
  if (!/^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$/.test(value) || value.includes("..")) fail();
  return value;
}

function validateRunner(env) {
  const expectedImage = assertCommon(env);
  if (!REVISION.test(ownText(env, "IDENTITY_DEVELOP_BUILD_REVISION", 40))) fail();
  const evidenceFile = ownText(env, "IDENTITY_DEVELOP_EVIDENCE_FILE", 132);
  assertNotPlaceholder(evidenceFile);
  if (!SAFE_EVIDENCE_FILE.test(evidenceFile)) fail();
  for (const prefix of ["LEGACY", "IDENTITY", "PLUGIN"]) {
    parseHost(env, `DEVELOP_${prefix}_DB_HOST`);
    parsePort(env, `DEVELOP_${prefix}_DB_PORT`);
    if (!SAFE_USER.test(ownText(env, `DEVELOP_${prefix}_RO_DB_USER`, 64))) fail();
    ownText(env, `DEVELOP_${prefix}_RO_DB_PASSWORD`);
  }
  const users = ["LEGACY", "IDENTITY", "PLUGIN"].map((prefix) => env[`DEVELOP_${prefix}_RO_DB_USER`]);
  if (new Set(users).size !== 3) fail();
  parseSafeName(env, "DEVELOP_RUNNER_EGRESS_NETWORK");
  parseSafeName(env, "DEVELOP_RUNNER_LOCAL_CONFIG_VOLUME");
  parseSafeName(env, "DEVELOP_RUNNER_LOCAL_EVIDENCE_VOLUME");
  if (env.DEVELOP_RUNNER_LOCAL_CONFIG_VOLUME === env.DEVELOP_RUNNER_LOCAL_EVIDENCE_VOLUME) fail();
  const capacity = ownText(env, "DEVELOP_RUNNER_EVIDENCE_CAPACITY_BYTES", 20);
  if (!/^[1-9][0-9]{9,19}$/.test(capacity) || BigInt(capacity) < BigInt(ONE_GIB)) fail();
  return renderAndInspect("runner", env, expectedImage);
}

function renderAndInspect(kind, candidateEnv, expectedImage) {
  const template = resolve(ROOT, kind === "signer" ? "compose.signer.yml" : "compose.full-range-runner.yml");
  const childEnv = { ...process.env };
  for (const key of ALL_KEYS) delete childEnv[key];
  Object.assign(childEnv, candidateEnv);
  const result = spawnSync("docker", ["compose", "-f", template, "config", "--format", "json"], {
    cwd: ROOT,
    env: childEnv,
    encoding: "utf8",
    maxBuffer: 4 * 1024 * 1024,
    timeout: 15_000
  });
  if (result.error || result.status !== 0 || typeof result.stdout !== "string") {
    throw new ValidationError("docker-compose-config-rejected");
  }
  let rendered;
  try {
    rendered = JSON.parse(result.stdout);
  } catch {
    throw new ValidationError("docker-compose-config-rejected");
  }
  if (kind === "signer") inspectSigner(rendered, expectedImage, candidateEnv);
  else inspectRunner(rendered, expectedImage, candidateEnv);
  return rendered;
}

function exactService(rendered, expectedName, expectedProjectName) {
  if (!rendered || typeof rendered !== "object" || Array.isArray(rendered) ||
    JSON.stringify(Object.keys(rendered).sort()) !== JSON.stringify(["name", "networks", "services", "volumes"]) ||
    rendered.name !== expectedProjectName ||
    !rendered.services || typeof rendered.services !== "object" ||
    JSON.stringify(Object.keys(rendered.services)) !== JSON.stringify([expectedName])) fail();
  const service = rendered.services[expectedName];
  if (!service || typeof service !== "object" || Array.isArray(service)) fail();
  return service;
}

const SIGNER_SERVICE_KEYS = Object.freeze([
  "cap_drop", "command", "entrypoint", "image", "init", "networks", "pids_limit", "ports",
  "pull_policy", "read_only", "restart", "security_opt", "stop_grace_period", "tmpfs", "user", "volumes"
]);
const RUNNER_SERVICE_KEYS = Object.freeze([
  "cap_drop", "command", "entrypoint", "environment", "image", "init", "labels", "networks", "pids_limit",
  "pull_policy", "read_only", "restart", "security_opt", "stop_grace_period", "tmpfs", "user", "volumes",
  "working_dir"
]);

function assertExactKeys(candidate, expected) {
  if (!candidate || typeof candidate !== "object" || Array.isArray(candidate) ||
    JSON.stringify(Object.keys(candidate).sort()) !== JSON.stringify([...expected].sort())) fail();
}

function assertBaseline(service, expectedImage, expectedTmpfsSize, expectedPids, expectedStopGracePeriod) {
  if (service.image !== expectedImage || service.user !== "1000:1000" || service.read_only !== true ||
    service.restart !== "no" || service.init !== true || service.pull_policy !== "always" || service.privileged === true ||
    service.entrypoint !== null || service.stop_grace_period !== expectedStopGracePeriod ||
    service.pids_limit !== expectedPids || !Array.isArray(service.cap_drop) ||
    JSON.stringify(service.cap_drop) !== '["ALL"]' || !Array.isArray(service.security_opt) ||
    JSON.stringify(service.security_opt) !== '["no-new-privileges:true"]' || !Array.isArray(service.tmpfs) ||
    JSON.stringify(service.tmpfs) !== JSON.stringify([
      `/tmp:rw,noexec,nosuid,nodev,size=${expectedTmpfsSize},uid=1000,gid=1000,mode=0700`
    ])) fail();
}

function assertNoDockerSocket(service) {
  for (const mount of service.volumes ?? []) {
    if (JSON.stringify(mount).includes("docker.sock")) fail();
  }
}

function inspectSigner(rendered, expectedImage, env) {
  const service = exactService(
    rendered,
    "develop-hash-signer",
    "identity-organization-reconciliation-develop-signer"
  );
  assertExactKeys(service, SIGNER_SERVICE_KEYS);
  assertBaseline(service, expectedImage, 16_777_216, 128, "10s");
  assertNoDockerSocket(service);
  if (service.environment && Object.keys(service.environment).length !== 0) fail();
  if (!Array.isArray(service.command) || JSON.stringify(service.command) !== JSON.stringify([
    "node", "dist/scripts/iam-organization-reconciliation-develop-hash-signer-https.js",
    "--config=/run/identity-develop-signer/launcher.json"
  ])) fail();
  if (!Array.isArray(service.volumes) || service.volumes.length !== 1 ||
    service.volumes[0].type !== "volume" || service.volumes[0].source !== "signer-local-secrets" ||
    service.volumes[0].target !== "/run/identity-develop-signer" || service.volumes[0].read_only !== true ||
    service.volumes[0].volume?.nocopy !== true) fail();
  assertExactKeys(service.volumes[0], ["type", "source", "target", "read_only", "volume"]);
  assertExactKeys(service.volumes[0].volume, ["nocopy"]);
  const networks = service.networks;
  assertExactKeys(networks, ["signer-private"]);
  assertExactKeys(rendered.networks, ["signer-private"]);
  assertExactKeys(rendered.volumes, ["signer-local-secrets"]);
  if (networks["signer-private"]?.ipv4_address !== env.DEVELOP_SIGNER_CONTAINER_IPV4 ||
    rendered.networks?.["signer-private"]?.internal !== true ||
    rendered.networks?.["signer-private"]?.driver !== "bridge") fail();
  assertExactKeys(networks["signer-private"], ["ipv4_address"]);
  assertExactKeys(rendered.networks["signer-private"], ["name", "driver", "ipam", "internal"]);
  assertExactKeys(rendered.networks["signer-private"].ipam, ["config"]);
  if (!Array.isArray(rendered.networks["signer-private"].ipam.config) ||
    rendered.networks["signer-private"].ipam.config.length !== 1 ||
    rendered.networks["signer-private"].ipam.config[0]?.subnet !== env.DEVELOP_SIGNER_PRIVATE_SUBNET) fail();
  assertExactKeys(rendered.networks["signer-private"].ipam.config[0], ["subnet"]);
  if (!Array.isArray(service.ports) || service.ports.length !== 1 || service.ports[0].target !== 8443 ||
    String(service.ports[0].published) !== "8443" || service.ports[0].protocol !== "tcp" ||
    service.ports[0].mode !== "host" ||
    service.ports[0].host_ip !== env.DEVELOP_SIGNER_BIND_IPV4) fail();
  assertExactKeys(service.ports[0], ["mode", "host_ip", "target", "published", "protocol"]);
  const volume = rendered.volumes?.["signer-local-secrets"];
  assertExactKeys(volume, ["name", "external"]);
  if (volume.external !== true || volume.name !== env.DEVELOP_SIGNER_LOCAL_SECRET_VOLUME) fail();
}

const RUNNER_ENVIRONMENT_KEYS = Object.freeze([
  "IDENTITY_DB_HOST", "IDENTITY_DB_NAME", "IDENTITY_DB_PORT",
  "IDENTITY_IAM_ORG_RECONCILIATION_IDENTITY_DB_PASSWORD",
  "IDENTITY_IAM_ORG_RECONCILIATION_IDENTITY_DB_USER",
  "IDENTITY_IAM_ORG_RECONCILIATION_LEGACY_DB_PASSWORD",
  "IDENTITY_IAM_ORG_RECONCILIATION_LEGACY_DB_USER",
  "IDENTITY_IAM_ORG_WRITE_DUAL_WRITE_EXECUTION_ENABLED", "IDENTITY_IAM_ORG_WRITE_MODE",
  "IDENTITY_IAM_ORG_WRITE_ROUTE_INTEGRATION_ENABLED", "IDENTITY_READONLY_MODE",
  "LEGACY_DB_HOST", "LEGACY_DB_NAME", "LEGACY_DB_PORT", "NODE_ENV",
  "PLUGIN_DB_HOST", "PLUGIN_DB_NAME", "PLUGIN_DB_PASSWORD", "PLUGIN_DB_PORT", "PLUGIN_DB_USER"
]);

function inspectRunner(rendered, expectedImage, env) {
  const service = exactService(
    rendered,
    "develop-full-range-runner",
    "identity-organization-reconciliation-develop-full-range"
  );
  assertExactKeys(service, RUNNER_SERVICE_KEYS);
  assertBaseline(service, expectedImage, 268_435_456, 256, "30s");
  assertNoDockerSocket(service);
  if (service.working_dir !== "/app" || !Array.isArray(service.command) ||
    JSON.stringify(service.command) !== JSON.stringify([
      "node", "dist/scripts/iam-organization-reconciliation-develop-full-range.js",
      "--environment=xrteeth-develop", `--build-revision=${env.IDENTITY_DEVELOP_BUILD_REVISION}`,
      "--deployment-evidence=/app/develop-config/deployment-evidence.json",
      "--trust-policy=/app/develop-config/trust-policy.json",
      "--signer-transport=/app/develop-config/signer-transport.json",
      `--output=/app/evidence/${env.IDENTITY_DEVELOP_EVIDENCE_FILE}`
    ])) fail();
  if (Array.isArray(service.ports) && service.ports.length !== 0) fail();
  if (!service.environment || JSON.stringify(Object.keys(service.environment).sort()) !==
    JSON.stringify([...RUNNER_ENVIRONMENT_KEYS].sort())) fail();
  const expectedEnvironment = {
    NODE_ENV: "production",
    IDENTITY_READONLY_MODE: "true",
    IDENTITY_IAM_ORG_WRITE_MODE: "disabled",
    IDENTITY_IAM_ORG_WRITE_ROUTE_INTEGRATION_ENABLED: "false",
    IDENTITY_IAM_ORG_WRITE_DUAL_WRITE_EXECUTION_ENABLED: "false",
    LEGACY_DB_HOST: env.DEVELOP_LEGACY_DB_HOST,
    LEGACY_DB_PORT: env.DEVELOP_LEGACY_DB_PORT,
    LEGACY_DB_NAME: "bujiaban_development",
    IDENTITY_IAM_ORG_RECONCILIATION_LEGACY_DB_USER: env.DEVELOP_LEGACY_RO_DB_USER,
    IDENTITY_IAM_ORG_RECONCILIATION_LEGACY_DB_PASSWORD: env.DEVELOP_LEGACY_RO_DB_PASSWORD,
    IDENTITY_DB_HOST: env.DEVELOP_IDENTITY_DB_HOST,
    IDENTITY_DB_PORT: env.DEVELOP_IDENTITY_DB_PORT,
    IDENTITY_DB_NAME: "xrugc_identity_dev",
    IDENTITY_IAM_ORG_RECONCILIATION_IDENTITY_DB_USER: env.DEVELOP_IDENTITY_RO_DB_USER,
    IDENTITY_IAM_ORG_RECONCILIATION_IDENTITY_DB_PASSWORD: env.DEVELOP_IDENTITY_RO_DB_PASSWORD,
    PLUGIN_DB_HOST: env.DEVELOP_PLUGIN_DB_HOST,
    PLUGIN_DB_PORT: env.DEVELOP_PLUGIN_DB_PORT,
    PLUGIN_DB_NAME: "bujiaban_development_plugin",
    PLUGIN_DB_USER: env.DEVELOP_PLUGIN_RO_DB_USER,
    PLUGIN_DB_PASSWORD: env.DEVELOP_PLUGIN_RO_DB_PASSWORD
  };
  if (Object.entries(expectedEnvironment).some(([key, value]) => service.environment[key] !== value)) fail();
  if (Object.keys(service.environment).some((key) => /SIGNING|PRIVATE_KEY|TLS|DOCKER|SOCKET/.test(key))) fail();
  if (!Array.isArray(service.volumes) || service.volumes.length !== 2) fail();
  const config = service.volumes.find((mount) => mount.target === "/app/develop-config");
  const evidence = service.volumes.find((mount) => mount.target === "/app/evidence");
  if (!config || config.type !== "volume" || config.source !== "runner-local-config" ||
    config.read_only !== true || config.volume?.nocopy !== true || !evidence || evidence.type !== "volume" ||
    evidence.source !== "runner-local-evidence" || evidence.read_only === true || evidence.volume?.nocopy !== true) fail();
  assertExactKeys(config, ["type", "source", "target", "read_only", "volume"]);
  assertExactKeys(config.volume, ["nocopy"]);
  assertExactKeys(evidence, ["type", "source", "target", "volume"]);
  assertExactKeys(evidence.volume, ["nocopy"]);
  assertExactKeys(service.networks, ["runner-egress"]);
  assertExactKeys(rendered.networks, ["runner-egress"]);
  assertExactKeys(rendered.volumes, ["runner-local-config", "runner-local-evidence"]);
  if (service.networks["runner-egress"] !== null) fail();
  assertExactKeys(rendered.networks["runner-egress"], ["name", "ipam", "external"]);
  assertExactKeys(rendered.networks["runner-egress"].ipam, []);
  assertExactKeys(rendered.volumes["runner-local-config"], ["name", "external"]);
  assertExactKeys(rendered.volumes["runner-local-evidence"], ["name", "external"]);
  assertExactKeys(service.labels, [
    "com.7dgame.identity.develop-only", "com.7dgame.identity.evidence-minimum-capacity-bytes"
  ]);
  if (service.labels?.["com.7dgame.identity.evidence-minimum-capacity-bytes"] !==
    env.DEVELOP_RUNNER_EVIDENCE_CAPACITY_BYTES) fail();
  if (rendered.volumes?.["runner-local-config"]?.external !== true ||
    rendered.volumes?.["runner-local-config"]?.name !== env.DEVELOP_RUNNER_LOCAL_CONFIG_VOLUME ||
    rendered.volumes?.["runner-local-evidence"]?.external !== true ||
    rendered.volumes?.["runner-local-evidence"]?.name !== env.DEVELOP_RUNNER_LOCAL_EVIDENCE_VOLUME ||
    rendered.networks?.["runner-egress"]?.external !== true ||
    rendered.networks?.["runner-egress"]?.name !== env.DEVELOP_RUNNER_EGRESS_NETWORK) fail();
}

function signerFixture() {
  return {
    IDENTITY_DEVELOP_IMAGE_REPOSITORY: "registry.private.invalid/identity/identity-service",
    IDENTITY_DEVELOP_IMAGE_DIGEST: `sha256:${"1".repeat(64)}`,
    DEVELOP_SIGNER_CONTAINER_IPV4: "172.29.72.10",
    DEVELOP_SIGNER_BIND_IPV4: "10.72.0.11",
    DEVELOP_SIGNER_PRIVATE_NETWORK: "identity-develop-signer",
    DEVELOP_SIGNER_PRIVATE_SUBNET: "172.29.72.0/24",
    DEVELOP_SIGNER_LOCAL_SECRET_VOLUME: "identity-develop-signer-secrets"
  };
}

function runnerFixture() {
  return {
    IDENTITY_DEVELOP_IMAGE_REPOSITORY: "registry.private.invalid/identity/identity-service",
    IDENTITY_DEVELOP_IMAGE_DIGEST: `sha256:${"1".repeat(64)}`,
    IDENTITY_DEVELOP_BUILD_REVISION: "2".repeat(40),
    IDENTITY_DEVELOP_EVIDENCE_FILE: "full-range-2.json",
    DEVELOP_LEGACY_DB_HOST: "legacy-db.private.invalid",
    DEVELOP_LEGACY_DB_PORT: "3306",
    DEVELOP_LEGACY_RO_DB_USER: "iam72_legacy_ro",
    DEVELOP_LEGACY_RO_DB_PASSWORD: "fixture-legacy-password",
    DEVELOP_IDENTITY_DB_HOST: "identity-db.private.invalid",
    DEVELOP_IDENTITY_DB_PORT: "3306",
    DEVELOP_IDENTITY_RO_DB_USER: "iam72_identity_ro",
    DEVELOP_IDENTITY_RO_DB_PASSWORD: "fixture-identity-password",
    DEVELOP_PLUGIN_DB_HOST: "plugin-db.private.invalid",
    DEVELOP_PLUGIN_DB_PORT: "3306",
    DEVELOP_PLUGIN_RO_DB_USER: "iam72_plugin_ro",
    DEVELOP_PLUGIN_RO_DB_PASSWORD: "fixture-plugin-password",
    DEVELOP_RUNNER_EGRESS_NETWORK: "identity-develop-reconciliation-egress",
    DEVELOP_RUNNER_LOCAL_CONFIG_VOLUME: "identity-develop-runner-config",
    DEVELOP_RUNNER_LOCAL_EVIDENCE_VOLUME: "identity-develop-runner-evidence",
    DEVELOP_RUNNER_EVIDENCE_CAPACITY_BYTES: String(ONE_GIB)
  };
}

function expectRejected(action) {
  try {
    action();
  } catch (error) {
    if (error instanceof ValidationError) return;
    throw error;
  }
  throw new Error("expected rejection");
}

function selfTest() {
  const renderedSigner = validateSigner(signerFixture());
  const renderedRunner = validateRunner(runnerFixture());

  const missing = signerFixture();
  delete missing.IDENTITY_DEVELOP_IMAGE_DIGEST;
  expectRejected(() => validateSigner(missing));

  expectRejected(() => validateSigner({
    ...signerFixture(),
    IDENTITY_DEVELOP_IMAGE_REPOSITORY: "registry.private.invalid/identity/identity-service:develop"
  }));
  expectRejected(() => validateSigner({
    ...signerFixture(),
    IDENTITY_DEVELOP_IMAGE_DIGEST: "develop"
  }));
  expectRejected(() => validateSigner({
    ...signerFixture(),
    IDENTITY_DEVELOP_IMAGE_DIGEST: `sha256:${"0".repeat(64)}`
  }));
  expectRejected(() => validateSigner({
    ...signerFixture(),
    DEVELOP_SIGNER_LOCAL_SECRET_VOLUME: "<secret-volume>"
  }));
  expectRejected(() => validateSigner({
    ...signerFixture(),
    DEVELOP_SIGNER_CONTAINER_IPV4: "172.29.72.0"
  }));
  expectRejected(() => validateRunner({
    ...runnerFixture(),
    DEVELOP_RUNNER_EVIDENCE_CAPACITY_BYTES: String(ONE_GIB - 1)
  }));
  expectRejected(() => validateRunner({
    ...runnerFixture(),
    DEVELOP_PLUGIN_RO_DB_USER: "iam72_identity_ro"
  }));
  expectRejected(() => validateRunner({
    ...runnerFixture(),
    IDENTITY_DEVELOP_EVIDENCE_FILE: "../escape.json"
  }));

  const signerDevice = structuredClone(renderedSigner);
  signerDevice.services["develop-hash-signer"].devices = ["/dev/null:/dev/null"];
  expectRejected(() => inspectSigner(signerDevice, signerDevice.services["develop-hash-signer"].image, signerFixture()));
  const signerExtraNetwork = structuredClone(renderedSigner);
  signerExtraNetwork.networks.extra = { external: true };
  expectRejected(() => inspectSigner(
    signerExtraNetwork, signerExtraNetwork.services["develop-hash-signer"].image, signerFixture()
  ));
  const signerMountSource = structuredClone(renderedSigner);
  signerMountSource.services["develop-hash-signer"].volumes[0].source = "unreviewed-source";
  expectRejected(() => inspectSigner(
    signerMountSource, signerMountSource.services["develop-hash-signer"].image, signerFixture()
  ));
  const runnerSecrets = structuredClone(renderedRunner);
  runnerSecrets.secrets = { unreviewed: { external: true } };
  expectRejected(() => inspectRunner(
    runnerSecrets, runnerSecrets.services["develop-full-range-runner"].image, runnerFixture()
  ));
  const runnerMountSource = structuredClone(renderedRunner);
  runnerMountSource.services["develop-full-range-runner"].volumes[0].source = "unreviewed-source";
  expectRejected(() => inspectRunner(
    runnerMountSource, runnerMountSource.services["develop-full-range-runner"].image, runnerFixture()
  ));
}

function main(argv, env) {
  if (argv.length !== 1) fail();
  if (argv[0] === "--self-test") {
    selfTest();
    process.stdout.write("Develop Compose template self-test: PASS\n");
    return;
  }
  if (argv[0] === "signer") validateSigner(env);
  else if (argv[0] === "runner") validateRunner(env);
  else fail();
  process.stdout.write(`Develop ${argv[0]} Compose template validation: PASS\n`);
}

try {
  main(process.argv.slice(2), process.env);
} catch (error) {
  const failure = error instanceof ValidationError ? error.message : "develop-compose-validation-failed";
  process.stderr.write(`${failure}\n`);
  process.exitCode = 1;
}
