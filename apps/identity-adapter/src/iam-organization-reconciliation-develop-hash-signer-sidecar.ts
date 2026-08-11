import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  timingSafeEqual,
  type KeyObject
} from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import { type IncomingMessage, type ServerResponse } from "node:http";
import { dirname, isAbsolute, resolve } from "node:path";
import { isProxy } from "node:util/types";
import {
  ORGANIZATION_RECONCILIATION_PROVENANCE_ALGORITHM,
  ORGANIZATION_RECONCILIATION_PROVENANCE_AUDIENCE,
  ORGANIZATION_RECONCILIATION_PROVENANCE_CONTRACT,
  ORGANIZATION_RECONCILIATION_PROVENANCE_SIGNATURE_DOMAIN,
  serializeOrganizationReconciliationProvenancePayload,
  type OrganizationReconciliationProvenancePayload
} from "./iam-organization-reconciliation-provenance.js";
import {
  ORGANIZATION_RECONCILIATION_DEVELOP_HASH_SIGNER_HTTP_CONTRACT,
  ORGANIZATION_RECONCILIATION_DEVELOP_HASH_SIGNER_HTTP_PATH
} from "./iam-organization-reconciliation-develop-hash-signer-client.js";
import {
  ORGANIZATION_RECONCILIATION_COMPILED_BUILD_REVISION
} from "./generated/iam-organization-reconciliation-compiled-revision.js";
import {
  createOrganizationReconciliationDevelopDeploymentEvidenceSha256,
  type OrganizationReconciliationDevelopDeploymentEvidence
} from "./iam-organization-reconciliation-develop-deployment-evidence.js";
import {
  bindOrganizationReconciliationDevelopDeploymentEvidenceToCompiledTopology
} from "./iam-organization-reconciliation-develop-deployment-topology.js";

const MAX_REQUEST_BYTES = 64 * 1024;
const MAX_CANONICAL_PAYLOAD_BYTES = 45 * 1024;
const MAX_PRIVATE_KEY_BYTES = 16 * 1024;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const FULL_REVISION = /^[a-f0-9]{40}$/;

/** This sidecar has no readiness promotion path. */
export const ORGANIZATION_RECONCILIATION_DEVELOP_HASH_SIGNER_READY = false as const;

export interface OrganizationReconciliationDevelopHashSignerExpectedPayload {
  readonly profileId: string;
  readonly environment: "xrteeth-develop";
  readonly collectorId: string;
  readonly nodeId: string;
  readonly keyId: string;
  readonly publicKeySha256: string;
  readonly trustPolicySha256: string;
  readonly deploymentEvidenceSha256: string;
  readonly buildRevision: string;
  readonly validFrom: string;
  readonly validUntil: string;
  readonly maxEvidenceAgeSeconds: number;
  readonly maxAttestationTtlSeconds: number;
  readonly maxCollectionWindowSeconds: number;
  readonly clockSkewSeconds: number;
}

export interface OrganizationReconciliationDevelopHashSignerSidecarOptions {
  readonly privateKeyPath: string;
  readonly bearerToken: string;
  readonly expected: OrganizationReconciliationDevelopHashSignerExpectedPayload;
  readonly deploymentEvidence: OrganizationReconciliationDevelopDeploymentEvidence;
  readonly now?: () => Date;
  readonly ready?: false;
}

export interface OrganizationReconciliationDevelopHashSignerSidecar {
  readonly handle: (request: IncomingMessage, response: ServerResponse) => Promise<void>;
  readonly signHttpRequest: (request: OrganizationReconciliationDevelopHashSignerHttpRequest) =>
    OrganizationReconciliationDevelopHashSignerHttpResponse;
}

/** Transport-neutral shape for the one internal HTTP endpoint, useful for hermetic tests. */
export interface OrganizationReconciliationDevelopHashSignerHttpRequest {
  readonly method: string | undefined;
  readonly url: string | undefined;
  readonly contentType: string | undefined;
  readonly authorization: string | undefined;
  readonly body: Uint8Array;
}

export interface OrganizationReconciliationDevelopHashSignerHttpResponse {
  readonly status: 200 | 400 | 404;
  readonly body: Readonly<Record<string, string>>;
}

export class OrganizationReconciliationDevelopHashSignerSidecarError extends Error {
  constructor(readonly failureId: "invalid-config" | "private-key-invalid") {
    super(failureId);
    this.name = "OrganizationReconciliationDevelopHashSignerSidecarError";
  }
}

interface CapturedOptions {
  readonly privateKeyPath: string;
  readonly bearerToken: string;
  readonly expected: OrganizationReconciliationDevelopHashSignerExpectedPayload;
  readonly now: () => Date;
}

/**
 * Loads exactly one local PKCS#8 Ed25519 key and returns an internal-only HTTP
 * handler. It has no database, output, readiness, or key-generation behavior.
 */
export async function createOrganizationReconciliationDevelopHashSignerSidecar(
  candidate: OrganizationReconciliationDevelopHashSignerSidecarOptions
): Promise<OrganizationReconciliationDevelopHashSignerSidecar> {
  const options = captureOptions(candidate);
  const privateKey = await loadOrganizationReconciliationDevelopHashSignerPrivateKey(options);
  return Object.freeze({
    handle: async (request: IncomingMessage, response: ServerResponse) =>
      handleRequest(request, response, options, privateKey),
    signHttpRequest: (request: OrganizationReconciliationDevelopHashSignerHttpRequest) =>
      signHttpRequest(request, options, privateKey)
  });
}

/** Strict ordinary-file reader used by the sidecar before it accepts traffic. */
async function loadOrganizationReconciliationDevelopHashSignerPrivateKey(
  options: Pick<OrganizationReconciliationDevelopHashSignerSidecarOptions, "privateKeyPath" | "expected">
): Promise<KeyObject> {
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  let bytes: Buffer | undefined;
  try {
    const path = options.privateKeyPath;
    const expected = captureExpected(options.expected);
    if (
      !isAbsolute(path) || resolve(path) !== path || path.length > 4_096 ||
      typeof fsConstants.O_NOFOLLOW !== "number" || typeof fsConstants.O_NONBLOCK !== "number"
    ) throw new Error("invalid");
    const [before, parent] = await Promise.all([lstat(path), lstat(dirname(path))]);
    if (
      !before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || (before.mode & 0o777) !== 0o600 ||
      before.size < 32 || before.size > MAX_PRIVATE_KEY_BYTES || !parent.isDirectory() || parent.isSymbolicLink() ||
      (typeof process.getuid === "function" && before.uid !== process.getuid())
    ) throw new Error("invalid");
    const [parentReal, fileReal] = await Promise.all([realpath(dirname(path)), realpath(path)]);
    if (parentReal !== dirname(path) || fileReal !== path) throw new Error("invalid");
    handle = await open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK);
    const opened = await handle.stat();
    if (
      !opened.isFile() || opened.nlink !== 1 || (opened.mode & 0o777) !== 0o600 ||
      opened.dev !== before.dev || opened.ino !== before.ino || opened.size !== before.size ||
      opened.mtimeMs !== before.mtimeMs || opened.ctimeMs !== before.ctimeMs ||
      (typeof process.getuid === "function" && opened.uid !== process.getuid())
    ) throw new Error("invalid");
    bytes = Buffer.alloc(opened.size);
    let offset = 0;
    while (offset < bytes.byteLength) {
      const { bytesRead } = await handle.read(bytes, offset, bytes.byteLength - offset, offset);
      if (bytesRead < 1) throw new Error("invalid");
      offset += bytesRead;
    }
    const overflow = Buffer.alloc(1);
    try {
      if ((await handle.read(overflow, 0, 1, bytes.byteLength)).bytesRead !== 0) throw new Error("invalid");
    } finally {
      overflow.fill(0);
    }
    const after = await handle.stat();
    if (
      after.dev !== opened.dev || after.ino !== opened.ino || after.size !== opened.size ||
      after.mtimeMs !== opened.mtimeMs || after.ctimeMs !== opened.ctimeMs ||
      after.nlink !== 1 || (after.mode & 0o777) !== 0o600
    ) throw new Error("invalid");
    const key = createPrivateKey({ key: bytes, format: "pem", type: "pkcs8" });
    if (key.asymmetricKeyType !== "ed25519") throw new Error("invalid");
    const publicDer = createPublicKey(key).export({ format: "der", type: "spki" });
    const fingerprint = createHash("sha256").update(publicDer).digest("hex");
    if (!safeHexEqual(fingerprint, expected.publicKeySha256)) throw new Error("invalid");
    return key;
  } catch {
    throw new OrganizationReconciliationDevelopHashSignerSidecarError("private-key-invalid");
  } finally {
    bytes?.fill(0);
    await handle?.close().catch(() => undefined);
  }
}

function captureOptions(candidate: OrganizationReconciliationDevelopHashSignerSidecarOptions): CapturedOptions {
  try {
    if (!candidate || typeof candidate !== "object" || Array.isArray(candidate) || isProxy(candidate)) throw new Error("invalid");
    const descriptors = Object.getOwnPropertyDescriptors(candidate);
    const allowed = new Set(["privateKeyPath", "bearerToken", "expected", "deploymentEvidence", "now", "ready"]);
    if (Object.keys(descriptors).some((key) => !allowed.has(key)) || Object.getOwnPropertySymbols(candidate).length !== 0) {
      throw new Error("invalid");
    }
    const privateKeyPath = ownString(descriptors, "privateKeyPath");
    const bearerToken = ownString(descriptors, "bearerToken");
    const expected = captureExpected(ownValue(descriptors, "expected"));
    const deployment = bindOrganizationReconciliationDevelopDeploymentEvidenceToCompiledTopology(
      ownValue(descriptors, "deploymentEvidence"),
      expected.profileId
    ).deploymentEvidence;
    const now = ownOptionalFunction(descriptors, "now") ?? (() => new Date());
    const ready = ownOptionalValue(descriptors, "ready");
    if (
      !isAbsolute(privateKeyPath) || resolve(privateKeyPath) !== privateKeyPath ||
      !/^[\x21-\x7e]{16,1024}$/.test(bearerToken) || ready === true || (ready !== undefined && ready !== false)
    ) throw new Error("invalid");
    const localSigner = deployment.signers.find((signer) => signer.keyId === expected.keyId);
    if (
      deployment.buildRevision !== expected.buildRevision || !localSigner ||
      localSigner.collectorId !== expected.collectorId || localSigner.nodeId !== expected.nodeId ||
      !safeHexEqual(localSigner.publicKeySha256, expected.publicKeySha256) ||
      !safeHexEqual(
        createOrganizationReconciliationDevelopDeploymentEvidenceSha256(deployment),
        expected.deploymentEvidenceSha256
      )
    ) throw new Error("invalid");
    return Object.freeze({ privateKeyPath, bearerToken, expected, now });
  } catch {
    throw new OrganizationReconciliationDevelopHashSignerSidecarError("invalid-config");
  }
}

function captureExpected(candidate: unknown): OrganizationReconciliationDevelopHashSignerExpectedPayload {
  if (!candidate || typeof candidate !== "object" || Array.isArray(candidate) || isProxy(candidate) ||
    Object.getPrototypeOf(candidate) !== Object.prototype || Object.getOwnPropertySymbols(candidate).length !== 0) {
    throw new Error("invalid");
  }
  const keys = [
    "profileId", "environment", "collectorId", "nodeId", "keyId", "publicKeySha256", "trustPolicySha256",
    "deploymentEvidenceSha256",
    "buildRevision", "validFrom", "validUntil", "maxEvidenceAgeSeconds", "maxAttestationTtlSeconds",
    "maxCollectionWindowSeconds", "clockSkewSeconds"
  ];
  const descriptors = Object.getOwnPropertyDescriptors(candidate);
  if (JSON.stringify(Object.keys(descriptors).sort()) !== JSON.stringify([...keys].sort())) throw new Error("invalid");
  const string = (key: string) => typeof ownValue(descriptors, key) === "string" ? ownValue(descriptors, key) as string : invalidExpected();
  const number = (key: string) => typeof ownValue(descriptors, key) === "number" ? ownValue(descriptors, key) as number : invalidExpected();
  const expected = {
    profileId: string("profileId"), environment: string("environment"), collectorId: string("collectorId"),
    nodeId: string("nodeId"), keyId: string("keyId"), publicKeySha256: string("publicKeySha256"),
    trustPolicySha256: string("trustPolicySha256"), deploymentEvidenceSha256: string("deploymentEvidenceSha256"),
    buildRevision: string("buildRevision"),
    validFrom: string("validFrom"), validUntil: string("validUntil"), maxEvidenceAgeSeconds: number("maxEvidenceAgeSeconds"),
    maxAttestationTtlSeconds: number("maxAttestationTtlSeconds"),
    maxCollectionWindowSeconds: number("maxCollectionWindowSeconds"), clockSkewSeconds: number("clockSkewSeconds")
  };
  const validFrom = parseCanonicalTime(expected.validFrom);
  const validUntil = parseCanonicalTime(expected.validUntil);
  if (
    !IDENTIFIER.test(expected.profileId) || expected.environment !== "xrteeth-develop" ||
    !IDENTIFIER.test(expected.collectorId) || !IDENTIFIER.test(expected.nodeId) || !IDENTIFIER.test(expected.keyId) ||
    !SHA256.test(expected.publicKeySha256) || !SHA256.test(expected.trustPolicySha256) ||
    !SHA256.test(expected.deploymentEvidenceSha256) || !FULL_REVISION.test(expected.buildRevision) ||
    !FULL_REVISION.test(ORGANIZATION_RECONCILIATION_COMPILED_BUILD_REVISION ?? "") ||
    expected.buildRevision !== ORGANIZATION_RECONCILIATION_COMPILED_BUILD_REVISION ||
    validFrom >= validUntil || !isWholeRange(expected.maxEvidenceAgeSeconds, 1, 86_400) ||
    !isWholeRange(expected.maxAttestationTtlSeconds, 1, 3_600) ||
    !isWholeRange(expected.maxCollectionWindowSeconds, 1, 3_600) || !isWholeRange(expected.clockSkewSeconds, 0, 300)
  ) throw new Error("invalid");
  return Object.freeze(expected as OrganizationReconciliationDevelopHashSignerExpectedPayload);
}

async function handleRequest(
  request: IncomingMessage,
  response: ServerResponse,
  options: CapturedOptions,
  privateKey: KeyObject
): Promise<void> {
  if (!hasAcceptedHeaders(
    request.method,
    request.url,
    request.headers["content-type"],
    request.headers.authorization,
    options
  )) return reject(response, 404);
  let bytes: Buffer | undefined;
  try {
    bytes = await readBoundedRequestBody(request);
    const result = signHttpRequest({
      method: request.method,
      url: request.url,
      contentType: request.headers["content-type"],
      authorization: request.headers.authorization,
      body: bytes
    }, options, privateKey);
    return respond(response, result.status, result.body);
  } catch {
    return reject(response, 400);
  } finally {
    bytes?.fill(0);
  }
}

function signHttpRequest(
  request: OrganizationReconciliationDevelopHashSignerHttpRequest,
  options: CapturedOptions,
  privateKey: KeyObject
): OrganizationReconciliationDevelopHashSignerHttpResponse {
  if (!hasAcceptedHeaders(request.method, request.url, request.contentType, request.authorization, options)) return rejected(404);
  if (!(request.body instanceof Uint8Array) || request.body.byteLength < 2 || request.body.byteLength > MAX_REQUEST_BYTES) {
    return rejected(400);
  }
  const bytes = Buffer.from(request.body);
  try {
    const payload = parseAndValidateRequest(bytes, options);
    const canonicalBytes = serializeOrganizationReconciliationProvenancePayload(payload);
    try {
      const signature = sign(null, canonicalBytes, privateKey);
      try {
        if (signature.byteLength !== 64) return rejected(400);
        return Object.freeze({
          status: 200 as const,
          body: Object.freeze({
            contract: ORGANIZATION_RECONCILIATION_DEVELOP_HASH_SIGNER_HTTP_CONTRACT,
            signatureEncoding: "base64url",
            signature: signature.toString("base64url")
          })
        });
      } finally {
        signature.fill(0);
      }
    } finally {
      canonicalBytes.fill(0);
    }
  } catch {
    return rejected(400);
  } finally {
    bytes.fill(0);
  }
}

function hasAcceptedHeaders(
  method: string | undefined,
  url: string | undefined,
  contentType: string | undefined,
  authorization: string | undefined,
  options: CapturedOptions
): boolean {
  return method === "POST" && url === ORGANIZATION_RECONCILIATION_DEVELOP_HASH_SIGNER_HTTP_PATH &&
    contentType === "application/json" && safeTokenEqual(authorization, `Bearer ${options.bearerToken}`);
}

function parseAndValidateRequest(bytes: Buffer, options: CapturedOptions): OrganizationReconciliationProvenancePayload {
  const text = bytes.toString("utf8");
  if (Buffer.byteLength(text, "utf8") !== bytes.byteLength) throw new Error("invalid");
  const request = JSON.parse(text) as unknown;
  if (!request || typeof request !== "object" || Array.isArray(request) || Object.getPrototypeOf(request) !== Object.prototype) {
    throw new Error("invalid");
  }
  const record = request as Record<string, unknown>;
  if (
    JSON.stringify(Object.keys(record)) !== JSON.stringify(["contract", "payloadBytesEncoding", "payloadBytesBase64url", "payloadSha256"]) ||
    JSON.stringify(record) !== text || record.contract !== ORGANIZATION_RECONCILIATION_DEVELOP_HASH_SIGNER_HTTP_CONTRACT ||
    record.payloadBytesEncoding !== "base64url" || typeof record.payloadBytesBase64url !== "string" ||
    typeof record.payloadSha256 !== "string" || !SHA256.test(record.payloadSha256)
  ) throw new Error("invalid");
  const payloadBytes = Buffer.from(record.payloadBytesBase64url, "base64url");
  try {
    if (
      payloadBytes.byteLength < 1 || payloadBytes.byteLength > MAX_CANONICAL_PAYLOAD_BYTES ||
      payloadBytes.toString("base64url") !== record.payloadBytesBase64url ||
      !safeHexEqual(createHash("sha256").update(payloadBytes).digest("hex"), record.payloadSha256)
    ) throw new Error("invalid");
    const domain = Buffer.from(ORGANIZATION_RECONCILIATION_PROVENANCE_SIGNATURE_DOMAIN, "utf8");
    try {
      if (payloadBytes.byteLength <= domain.byteLength || !payloadBytes.subarray(0, domain.byteLength).equals(domain)) {
        throw new Error("invalid");
      }
      const payloadText = payloadBytes.subarray(domain.byteLength).toString("utf8");
      if (Buffer.byteLength(payloadText, "utf8") !== payloadBytes.byteLength - domain.byteLength) throw new Error("invalid");
      const payload = JSON.parse(payloadText) as OrganizationReconciliationProvenancePayload;
      const canonical = serializeOrganizationReconciliationProvenancePayload(payload);
      try {
        if (!safeBufferEqual(canonical, payloadBytes)) throw new Error("invalid");
      } finally {
        canonical.fill(0);
      }
      validateExpectedPayload(payload, options);
      return payload;
    } finally {
      domain.fill(0);
    }
  } finally {
    payloadBytes.fill(0);
  }
}

function validateExpectedPayload(payload: OrganizationReconciliationProvenancePayload, options: CapturedOptions): void {
  const expected = options.expected;
  if (
    payload.contract !== ORGANIZATION_RECONCILIATION_PROVENANCE_CONTRACT ||
    payload.audience !== ORGANIZATION_RECONCILIATION_PROVENANCE_AUDIENCE ||
    payload.algorithm !== ORGANIZATION_RECONCILIATION_PROVENANCE_ALGORITHM ||
    payload.profileId !== expected.profileId || payload.environment !== expected.environment ||
    payload.collectorId !== expected.collectorId || payload.nodeId !== expected.nodeId || payload.keyId !== expected.keyId ||
    payload.collectorBuildRevision !== expected.buildRevision ||
    !safeHexEqual(payload.trustPolicySha256, expected.trustPolicySha256) ||
    !safeHexEqual(payload.deploymentEvidenceSha256, expected.deploymentEvidenceSha256)
  ) throw new Error("invalid");
  const now = validNow(options.now);
  const skew = expected.clockSkewSeconds * 1_000;
  const policyStart = parseCanonicalTime(expected.validFrom);
  const policyEnd = parseCanonicalTime(expected.validUntil);
  const windowStart = parseCanonicalTime(payload.windowStartedAt);
  const windowEnd = parseCanonicalTime(payload.windowEndedAt);
  const issuedAt = parseCanonicalTime(payload.issuedAt);
  const expiresAt = parseCanonicalTime(payload.expiresAt);
  if (
    windowStart > windowEnd || windowStart < policyStart || windowEnd > policyEnd ||
    windowEnd - windowStart > expected.maxCollectionWindowSeconds * 1_000 ||
    issuedAt < windowEnd || issuedAt > now + skew || expiresAt <= issuedAt ||
    expiresAt < now - skew || expiresAt - issuedAt > expected.maxAttestationTtlSeconds * 1_000 ||
    issuedAt < policyStart || expiresAt > policyEnd || now - windowEnd > expected.maxEvidenceAgeSeconds * 1_000 + skew
  ) throw new Error("invalid");
}

async function readBoundedRequestBody(request: IncomingMessage): Promise<Buffer> {
  const length = request.headers["content-length"];
  if (typeof length === "string" && (!/^\d+$/.test(length) || Number(length) > MAX_REQUEST_BYTES)) throw new Error("invalid");
  const chunks: Buffer[] = [];
  let size = 0;
  try {
    for await (const chunk of request) {
      const bytes = Buffer.isBuffer(chunk) ? Buffer.from(chunk) : Buffer.from(chunk);
      if (bytes.byteLength > MAX_REQUEST_BYTES - size) {
        bytes.fill(0);
        throw new Error("invalid");
      }
      chunks.push(bytes);
      size += bytes.byteLength;
    }
    if (size < 2) throw new Error("invalid");
    return Buffer.concat(chunks, size);
  } catch (error) {
    if (error instanceof Error) throw error;
    throw new Error("invalid");
  } finally {
    for (const chunk of chunks) chunk.fill(0);
  }
}

function respond(response: ServerResponse, status: number, body: Record<string, string>): void {
  const payload = JSON.stringify(body);
  response.writeHead(status, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(payload, "utf8") });
  response.end(payload);
}

function reject(response: ServerResponse, status: number): void {
  const result = rejected(status === 404 ? 404 : 400);
  respond(response, result.status, result.body);
}

function rejected(status: 400 | 404): OrganizationReconciliationDevelopHashSignerHttpResponse {
  return Object.freeze({
    status,
    body: Object.freeze({ contract: ORGANIZATION_RECONCILIATION_DEVELOP_HASH_SIGNER_HTTP_CONTRACT, status: "rejected" })
  });
}

function safeTokenEqual(actual: string | undefined, expected: string): boolean {
  if (typeof actual !== "string") return false;
  const left = Buffer.from(actual, "utf8");
  const right = Buffer.from(expected, "utf8");
  try {
    return left.byteLength === right.byteLength && timingSafeEqual(left, right);
  } finally {
    left.fill(0);
    right.fill(0);
  }
}

function safeHexEqual(left: string, right: string): boolean {
  if (!SHA256.test(left) || !SHA256.test(right)) return false;
  return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

function safeBufferEqual(left: Buffer, right: Buffer): boolean {
  return left.byteLength === right.byteLength && timingSafeEqual(left, right);
}

function parseCanonicalTime(value: string): number {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) throw new Error("invalid");
  return parsed;
}

function validNow(now: () => Date): number {
  const value = now();
  if (
    Object.getPrototypeOf(value) !== Date.prototype || Object.getOwnPropertyNames(value).length !== 0 ||
    Object.getOwnPropertySymbols(value).length !== 0
  ) throw new Error("invalid");
  const milliseconds = Date.prototype.getTime.call(value);
  if (!Number.isFinite(milliseconds)) throw new Error("invalid");
  return milliseconds;
}

function isWholeRange(value: number, min: number, max: number): boolean {
  return Number.isSafeInteger(value) && value >= min && value <= max;
}

function ownValue(descriptors: PropertyDescriptorMap, key: string): unknown {
  const descriptor = descriptors[key];
  if (!descriptor || !("value" in descriptor)) throw new Error("invalid");
  return descriptor.value;
}

function ownOptionalValue(descriptors: PropertyDescriptorMap, key: string): unknown {
  const descriptor = descriptors[key];
  if (!descriptor) return undefined;
  if (!("value" in descriptor)) throw new Error("invalid");
  return descriptor.value;
}

function ownString(descriptors: PropertyDescriptorMap, key: string): string {
  const value = ownValue(descriptors, key);
  if (typeof value !== "string") throw new Error("invalid");
  return value;
}

function ownOptionalFunction(descriptors: PropertyDescriptorMap, key: string): (() => Date) | undefined {
  const value = ownOptionalValue(descriptors, key);
  if (value === undefined) return undefined;
  if (typeof value !== "function" || isProxy(value)) throw new Error("invalid");
  return value as () => Date;
}

function invalidExpected(): never {
  throw new Error("invalid");
}
