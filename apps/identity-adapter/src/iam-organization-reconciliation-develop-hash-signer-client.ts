import { createHash, timingSafeEqual, X509Certificate } from "node:crypto";
import type { IncomingMessage } from "node:http";
import { request as httpsRequest } from "node:https";
import { isIP } from "node:net";
import { checkServerIdentity } from "node:tls";
import { isProxy } from "node:util/types";
import {
  ORGANIZATION_RECONCILIATION_PROVENANCE_SIGNATURE_DOMAIN,
  serializeOrganizationReconciliationProvenancePayload,
  type OrganizationReconciliationProvenancePayload
} from "./iam-organization-reconciliation-provenance.js";

export const ORGANIZATION_RECONCILIATION_DEVELOP_HASH_SIGNER_HTTP_CONTRACT =
  "iam-organization-reconciliation-xrteeth-develop-hash-signer-http/v1" as const;
export const ORGANIZATION_RECONCILIATION_DEVELOP_HASH_SIGNER_HTTP_PATH =
  "/v1/iam-organization-reconciliation/sign" as const;

// Base64url plus the strict JSON envelope must remain within the 64 KiB HTTP limit.
const MAX_PAYLOAD_BYTES = 45 * 1024;
const MAX_RESPONSE_BYTES = 16 * 1024;
const MAX_CA_CERTIFICATE_BYTES = 64 * 1024;
const DEFAULT_TIMEOUT_MS = 3_000;
const SHA256 = /^[a-f0-9]{64}$/;

export interface OrganizationReconciliationDevelopHashSignerClientOptions {
  readonly endpointUrl: string;
  readonly bearerToken: string;
  /** SHA-256 of the peer leaf certificate's exact DER bytes. Required outside a fixture. */
  readonly tlsCertificateSha256?: string;
  /** One explicitly supplied private root CA certificate. System/global trust is never used. */
  readonly certificateAuthorityPem?: Uint8Array;
  readonly timeoutMs?: number;
  /** Test-only escape hatch. Never set this from a runtime environment variable or config file. */
  readonly allowLocalhostForDevelopmentFixture?: boolean;
  /** Test-only transport seam; accepted only with allowLocalhostForDevelopmentFixture=true. */
  readonly fetchImplementation?: typeof fetch;
}

export class OrganizationReconciliationDevelopHashSignerClientError extends Error {
  constructor(readonly failureId: "invalid-config" | "invalid-payload" | "transport-failed" | "response-invalid") {
    super(failureId);
    this.name = "OrganizationReconciliationDevelopHashSignerClientError";
  }
}

interface ProductionClientOptions {
  readonly mode: "production";
  readonly endpoint: URL;
  readonly bearerToken: string;
  readonly tlsCertificateSha256: string;
  readonly certificateAuthorityPem: Buffer;
  readonly timeoutMs: number;
}

interface FixtureClientOptions {
  readonly mode: "fixture";
  readonly endpoint: URL;
  readonly bearerToken: string;
  readonly timeoutMs: number;
  readonly fetchImplementation: typeof fetch;
}

type CapturedClientOptions = Readonly<ProductionClientOptions | FixtureClientOptions>;

/**
 * Creates a signer callback for the full-range runner. The only transmitted
 * input is already-domain-separated, canonical provenance bytes; this module
 * never accepts records, reconciliation input, keys, or signer metadata.
 */
export function createOrganizationReconciliationDevelopHashSignerClient(
  options: OrganizationReconciliationDevelopHashSignerClientOptions
): (canonicalPayloadBytes: Uint8Array) => Promise<Uint8Array> {
  const captured = captureOptions(options);
  return async (candidate: Uint8Array): Promise<Uint8Array> => {
    const payload = copyAndValidatePayload(candidate);
    try {
      const payloadSha256 = createHash("sha256").update(payload).digest("hex");
      const requestBody = JSON.stringify({
        contract: ORGANIZATION_RECONCILIATION_DEVELOP_HASH_SIGNER_HTTP_CONTRACT,
        payloadBytesEncoding: "base64url",
        payloadBytesBase64url: payload.toString("base64url"),
        payloadSha256
      });
      const responseBytes = captured.mode === "fixture"
        ? await executeFixtureRequest(captured, requestBody)
        : await executePinnedHttpsRequest(captured, requestBody);
      try {
        return parseSignatureResponse(responseBytes);
      } finally {
        responseBytes.fill(0);
      }
    } finally {
      payload.fill(0);
    }
  };
}

/** Endpoint-only preflight used before the transport loader reads any secrets. */
export function assertOrganizationReconciliationDevelopHashSignerProductionEndpoint(candidate: string): string {
  try {
    return captureEndpoint(candidate, false).href;
  } catch {
    throw new OrganizationReconciliationDevelopHashSignerClientError("invalid-config");
  }
}

function captureOptions(candidate: OrganizationReconciliationDevelopHashSignerClientOptions): CapturedClientOptions {
  try {
    if (
      !candidate || typeof candidate !== "object" || Array.isArray(candidate) || isProxy(candidate) ||
      Object.getPrototypeOf(candidate) !== Object.prototype || Object.getOwnPropertySymbols(candidate).length !== 0
    ) throw new Error("invalid");
    const descriptors = Object.getOwnPropertyDescriptors(candidate);
    const allowed = new Set([
      "endpointUrl", "bearerToken", "tlsCertificateSha256", "certificateAuthorityPem", "timeoutMs",
      "allowLocalhostForDevelopmentFixture", "fetchImplementation"
    ]);
    if (Object.keys(descriptors).some((key) => !allowed.has(key))) throw new Error("invalid");
    const endpointUrl = ownString(descriptors, "endpointUrl");
    const bearerToken = ownString(descriptors, "bearerToken");
    const developmentFixture = ownBoolean(descriptors, "allowLocalhostForDevelopmentFixture", false);
    const timeoutMs = ownNumber(descriptors, "timeoutMs", DEFAULT_TIMEOUT_MS);
    const fetchImplementation = ownOptionalFunction(descriptors, "fetchImplementation") as typeof fetch | undefined;
    if (
      !/^[\x21-\x7e]{16,1024}$/.test(bearerToken) ||
      !Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 10_000
    ) throw new Error("invalid");
    const endpoint = captureEndpoint(endpointUrl, developmentFixture);
    if (fetchImplementation) {
      if (!developmentFixture) throw new Error("invalid");
      if (descriptors["tlsCertificateSha256"] || descriptors["certificateAuthorityPem"]) throw new Error("invalid");
      return Object.freeze({
        mode: "fixture" as const,
        endpoint,
        bearerToken,
        timeoutMs,
        fetchImplementation
      });
    }
    if (endpoint.protocol !== "https:") throw new Error("invalid");
    const tlsCertificateSha256 = ownString(descriptors, "tlsCertificateSha256");
    if (!SHA256.test(tlsCertificateSha256) || /^0+$/.test(tlsCertificateSha256)) throw new Error("invalid");
    const certificateAuthorityPem = captureCertificateAuthority(ownValue(descriptors, "certificateAuthorityPem"));
    return Object.freeze({
      mode: "production" as const,
      endpoint,
      bearerToken,
      tlsCertificateSha256,
      certificateAuthorityPem,
      timeoutMs
    });
  } catch {
    throw new OrganizationReconciliationDevelopHashSignerClientError("invalid-config");
  }
}

function captureEndpoint(value: string, allowLocalhost: boolean): URL {
  const url = new URL(value);
  if (
    url.href !== value || (url.protocol !== "http:" && url.protocol !== "https:") ||
    url.username !== "" || url.password !== "" || url.search !== "" || url.hash !== "" ||
    url.pathname !== ORGANIZATION_RECONCILIATION_DEVELOP_HASH_SIGNER_HTTP_PATH ||
    isIP(url.hostname) !== 0
  ) throw new Error("invalid");
  if (url.protocol === "http:") {
    if (url.hostname !== "localhost" || !allowLocalhost) throw new Error("invalid");
    return url;
  }
  if (url.hostname === "localhost") {
    if (!allowLocalhost) throw new Error("invalid");
    return url;
  }
  if (!/^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/.test(url.hostname) || url.hostname.length > 253) {
    throw new Error("invalid");
  }
  // Production transport is HTTPS-only; dotted names must be explicitly internal.
  if (url.hostname.includes(".") && !url.hostname.endsWith(".internal") && !url.hostname.endsWith(".local")) {
    throw new Error("invalid");
  }
  return url;
}

function captureCertificateAuthority(candidate: unknown): Buffer {
  if (
    !(candidate instanceof Uint8Array) || isProxy(candidate) ||
    (Object.getPrototypeOf(candidate) !== Buffer.prototype && Object.getPrototypeOf(candidate) !== Uint8Array.prototype) ||
    candidate.byteLength < 64 || candidate.byteLength > MAX_CA_CERTIFICATE_BYTES
  ) throw new Error("invalid");
  const bytes = Buffer.from(candidate);
  try {
    const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
    const matches = text.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
    if (!matches || matches.length !== 1 || text.trim() !== matches[0]) throw new Error("invalid");
    const certificate = new X509Certificate(bytes);
    const now = Date.now();
    if (
      !certificate.ca || !certificate.checkIssued(certificate) || !certificate.verify(certificate.publicKey) ||
      Date.parse(certificate.validFrom) > now || Date.parse(certificate.validTo) < now
    ) throw new Error("invalid");
    return bytes;
  } catch (error) {
    bytes.fill(0);
    throw error;
  }
}

async function executeFixtureRequest(options: FixtureClientOptions, requestBody: string): Promise<Buffer> {
  let response: Response;
  try {
    response = await options.fetchImplementation.call(undefined, options.endpoint.href, {
      method: "POST",
      redirect: "error",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        Authorization: `Bearer ${options.bearerToken}`
      },
      body: requestBody,
      signal: AbortSignal.timeout(options.timeoutMs)
    });
  } catch {
    throw new OrganizationReconciliationDevelopHashSignerClientError("transport-failed");
  }
  if (response.status !== 200) throw new OrganizationReconciliationDevelopHashSignerClientError("transport-failed");
  if (response.headers.get("content-type") !== "application/json") {
    throw new OrganizationReconciliationDevelopHashSignerClientError("response-invalid");
  }
  return readBoundedFetchBody(response, MAX_RESPONSE_BYTES);
}

async function executePinnedHttpsRequest(options: ProductionClientOptions, requestBody: string): Promise<Buffer> {
  try {
    return await new Promise<Buffer>((resolvePromise, rejectPromise) => {
      let settled = false;
      let timer: NodeJS.Timeout | undefined;
      const settle = (error: unknown, bytes?: Buffer) => {
        if (settled) {
          bytes?.fill(0);
          return;
        }
        settled = true;
        if (timer) clearTimeout(timer);
        if (error) rejectPromise(error);
        else resolvePromise(bytes!);
      };
      const request = httpsRequest({
        protocol: "https:",
        hostname: options.endpoint.hostname,
        port: options.endpoint.port === "" ? 443 : Number(options.endpoint.port),
        path: options.endpoint.pathname,
        method: "POST",
        agent: false,
        ca: options.certificateAuthorityPem,
        rejectUnauthorized: true,
        servername: options.endpoint.hostname,
        minVersion: "TLSv1.2",
        maxVersion: "TLSv1.3",
        checkServerIdentity: (hostname, certificate) => {
          const hostnameFailure = checkServerIdentity(hostname, certificate);
          if (hostnameFailure) return hostnameFailure;
          const raw = certificate.raw;
          if (!Buffer.isBuffer(raw)) return new Error("peer-certificate-invalid");
          const actual = createHash("sha256").update(raw).digest("hex");
          return safeHexEqual(actual, options.tlsCertificateSha256)
            ? undefined
            : new Error("peer-certificate-pin-mismatch");
        },
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
          Authorization: `Bearer ${options.bearerToken}`,
          "Content-Length": Buffer.byteLength(requestBody, "utf8")
        }
      }, (response) => {
        void capturePinnedResponse(response).then(
          (bytes) => settle(undefined, bytes),
          (error) => settle(error)
        );
      });
      request.once("error", (error) => settle(error));
      timer = setTimeout(() => request.destroy(new Error("signer-request-timeout")), options.timeoutMs);
      timer.unref();
      request.end(requestBody, "utf8");
    });
  } catch (error) {
    if (error instanceof OrganizationReconciliationDevelopHashSignerClientError) throw error;
    throw new OrganizationReconciliationDevelopHashSignerClientError("transport-failed");
  }
}

async function capturePinnedResponse(response: IncomingMessage): Promise<Buffer> {
  if (response.statusCode !== 200) {
    response.destroy();
    throw new OrganizationReconciliationDevelopHashSignerClientError("transport-failed");
  }
  if (response.headers["content-type"] !== "application/json") {
    response.destroy();
    throw new OrganizationReconciliationDevelopHashSignerClientError("response-invalid");
  }
  return readBoundedNodeBody(response, MAX_RESPONSE_BYTES);
}

function copyAndValidatePayload(candidate: Uint8Array): Buffer {
  if (!(candidate instanceof Uint8Array) || candidate.byteLength < 1 || candidate.byteLength > MAX_PAYLOAD_BYTES) {
    throw new OrganizationReconciliationDevelopHashSignerClientError("invalid-payload");
  }
  const copied = Buffer.from(candidate);
  const domain = Buffer.from(ORGANIZATION_RECONCILIATION_PROVENANCE_SIGNATURE_DOMAIN, "utf8");
  try {
    if (copied.byteLength <= domain.byteLength || !copied.subarray(0, domain.byteLength).equals(domain)) {
      throw new OrganizationReconciliationDevelopHashSignerClientError("invalid-payload");
    }
    const payloadText = copied.subarray(domain.byteLength).toString("utf8");
    if (Buffer.byteLength(payloadText, "utf8") !== copied.byteLength - domain.byteLength) {
      throw new OrganizationReconciliationDevelopHashSignerClientError("invalid-payload");
    }
    const parsed = JSON.parse(payloadText) as OrganizationReconciliationProvenancePayload;
    const canonical = serializeOrganizationReconciliationProvenancePayload(parsed);
    try {
      if (canonical.byteLength !== copied.byteLength || !canonical.equals(copied)) {
        throw new OrganizationReconciliationDevelopHashSignerClientError("invalid-payload");
      }
    } finally {
      canonical.fill(0);
    }
    return copied;
  } catch (error) {
    copied.fill(0);
    if (error instanceof OrganizationReconciliationDevelopHashSignerClientError) throw error;
    throw new OrganizationReconciliationDevelopHashSignerClientError("invalid-payload");
  } finally {
    domain.fill(0);
  }
}

async function readBoundedFetchBody(response: Response, maxBytes: number): Promise<Buffer> {
  const contentLength = response.headers.get("content-length");
  if (contentLength !== null && (!/^\d+$/.test(contentLength) || Number(contentLength) > maxBytes)) {
    throw new OrganizationReconciliationDevelopHashSignerClientError("response-invalid");
  }
  const reader = response.body?.getReader();
  if (!reader) throw new OrganizationReconciliationDevelopHashSignerClientError("response-invalid");
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const next = await reader.read();
      if (next.done) break;
      if (!(next.value instanceof Uint8Array) || next.value.byteLength > maxBytes - size) {
        throw new OrganizationReconciliationDevelopHashSignerClientError("response-invalid");
      }
      chunks.push(next.value);
      size += next.value.byteLength;
    }
    return Buffer.concat(chunks, size);
  } catch (error) {
    await reader.cancel().catch(() => undefined);
    if (error instanceof OrganizationReconciliationDevelopHashSignerClientError) throw error;
    throw new OrganizationReconciliationDevelopHashSignerClientError("response-invalid");
  } finally {
    for (const chunk of chunks) chunk.fill(0);
  }
}

async function readBoundedNodeBody(response: IncomingMessage, maxBytes: number): Promise<Buffer> {
  const contentLength = response.headers["content-length"];
  if (
    Array.isArray(contentLength) ||
    (typeof contentLength === "string" && (!/^\d+$/.test(contentLength) || Number(contentLength) > maxBytes))
  ) {
    response.destroy();
    throw new OrganizationReconciliationDevelopHashSignerClientError("response-invalid");
  }
  const chunks: Buffer[] = [];
  let size = 0;
  try {
    for await (const chunk of response) {
      const bytes = Buffer.from(chunk);
      if (bytes.byteLength > maxBytes - size) {
        bytes.fill(0);
        response.destroy();
        throw new OrganizationReconciliationDevelopHashSignerClientError("response-invalid");
      }
      chunks.push(bytes);
      size += bytes.byteLength;
    }
    if (!response.complete) throw new OrganizationReconciliationDevelopHashSignerClientError("response-invalid");
    return Buffer.concat(chunks, size);
  } catch (error) {
    response.destroy();
    if (error instanceof OrganizationReconciliationDevelopHashSignerClientError) throw error;
    throw new OrganizationReconciliationDevelopHashSignerClientError("response-invalid");
  } finally {
    for (const chunk of chunks) chunk.fill(0);
  }
}

function parseSignatureResponse(bytes: Buffer): Uint8Array {
  try {
    const text = bytes.toString("utf8");
    if (Buffer.byteLength(text, "utf8") !== bytes.byteLength) throw new Error("invalid");
    const value = JSON.parse(text) as unknown;
    if (!value || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
      throw new Error("invalid");
    }
    const record = value as Record<string, unknown>;
    if (JSON.stringify(Object.keys(record).sort()) !== JSON.stringify(["contract", "signature", "signatureEncoding"])) {
      throw new Error("invalid");
    }
    if (
      record.contract !== ORGANIZATION_RECONCILIATION_DEVELOP_HASH_SIGNER_HTTP_CONTRACT ||
      record.signatureEncoding !== "base64url" || typeof record.signature !== "string"
    ) throw new Error("invalid");
    const signature = Buffer.from(record.signature, "base64url");
    try {
      if (signature.byteLength !== 64 || signature.toString("base64url") !== record.signature) {
        throw new Error("invalid");
      }
      return Uint8Array.from(signature);
    } finally {
      signature.fill(0);
    }
  } catch {
    throw new OrganizationReconciliationDevelopHashSignerClientError("response-invalid");
  }
}

function safeHexEqual(left: string, right: string): boolean {
  if (!SHA256.test(left) || !SHA256.test(right)) return false;
  const leftBytes = Buffer.from(left, "hex");
  const rightBytes = Buffer.from(right, "hex");
  try {
    return timingSafeEqual(leftBytes, rightBytes);
  } finally {
    leftBytes.fill(0);
    rightBytes.fill(0);
  }
}

function ownValue(descriptors: PropertyDescriptorMap, key: string): unknown {
  const descriptor = descriptors[key];
  if (!descriptor || !("value" in descriptor)) throw new Error("invalid");
  return descriptor.value;
}

function ownString(descriptors: PropertyDescriptorMap, key: string): string {
  const value = ownValue(descriptors, key);
  if (typeof value !== "string") throw new Error("invalid");
  return value;
}

function ownBoolean(descriptors: PropertyDescriptorMap, key: string, defaultValue: boolean): boolean {
  const descriptor = descriptors[key];
  if (!descriptor) return defaultValue;
  if (!("value" in descriptor) || typeof descriptor.value !== "boolean") throw new Error("invalid");
  return descriptor.value;
}

function ownNumber(descriptors: PropertyDescriptorMap, key: string, defaultValue: number): number {
  const descriptor = descriptors[key];
  if (!descriptor) return defaultValue;
  if (!("value" in descriptor) || typeof descriptor.value !== "number") throw new Error("invalid");
  return descriptor.value;
}

function ownOptionalFunction(descriptors: PropertyDescriptorMap, key: string): Function | undefined {
  const descriptor = descriptors[key];
  if (!descriptor) return undefined;
  if (!("value" in descriptor) || typeof descriptor.value !== "function" || isProxy(descriptor.value)) {
    throw new Error("invalid");
  }
  return descriptor.value;
}
