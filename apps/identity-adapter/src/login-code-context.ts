import { isIP } from "node:net";

export type LoginCodeHeaders = Readonly<Record<string, string | string[] | undefined>>;

/** Stored metadata must already be a lowercase host, without URL syntax or IPv6 brackets. Invalid/absent values return null. */
export function validateFrontendDomain(value: unknown): string | null {
  if (typeof value !== "string" || !value || value.length > 253 || value !== value.toLowerCase()
    || value !== value.trim() || value.endsWith(".")) return null;
  if (value === "localhost" || isIP(value)) return value;
  return /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?![\s\S])/.test(value) ? value : null;
}

function phpTrim(value: string): string {
  return value.replace(/^[ \t\n\r\0\v]+/, "").replace(/[ \t\n\r\0\v]+$/, "");
}

function header(headers: LoginCodeHeaders, name: string): string {
  const key = Object.keys(headers).find((candidate) => candidate.toLowerCase() === name);
  const value = key === undefined ? undefined : headers[key];
  // Yii HeaderCollection::get defaults to the first value of a repeated header.
  const first = Array.isArray(value) ? value[0] : value;
  return typeof first === "string" ? phpTrim(first) : "";
}

function normalizeOrigin(candidate: string): { origin: string; host: string } | null {
  // Parse the original authority rather than letting WHATWG URL rewrite short/numeric IPv4 hosts or IDNs.
  const parts = /^(https?):\/\/(\[[0-9a-f:.]+\]|[a-z0-9.-]+)(?::([0-9]{1,5}))?(?![\s\S])/i.exec(candidate);
  if (!parts) return null;
  const scheme = parts[1].toLowerCase(), serializedHost = parts[2].toLowerCase();
  const bracketed = serializedHost.startsWith("[");
  const host = bracketed ? serializedHost.slice(1, -1) : serializedHost;
  if (!validateFrontendDomain(host) || (bracketed && isIP(host) !== 6)) return null;
  if (scheme === "http" && !["localhost", "127.0.0.1", "::1"].includes(host)) return null;
  let port = parts[3] === undefined ? null : Number(parts[3]);
  if (port !== null && (port < 1 || port > 65535)) return null;
  if ((scheme === "https" && port === 443) || (scheme === "http" && port === 80)) port = null;
  const authority = host.includes(":") ? `[${host}]` : host;
  return { origin: `${scheme}://${authority}${port === null ? "" : `:${port}`}`, host };
}

/**
 * Preserve only a configured browser origin's host as white-label routing metadata.
 * An explicit untrusted Origin never falls back to Referer. This metadata is never a JWT audience.
 */
export function loginCodeContext(headers: LoginCodeHeaders, allowedOrigins: string): { frontend_domain?: string } {
  const originHeader = header(headers, "origin");
  let candidate = originHeader;
  if (!candidate) {
    const referer = header(headers, "referer");
    // Referer's path/query/fragment are allowed, but userinfo in its authority is not.
    const parts = /^([a-z][a-z0-9+.-]*):\/\/([^/?#]*)(?:[/?#][\s\S]*)?(?![\s\S])/i.exec(referer);
    if (!parts || parts[2].includes("@")) return {};
    candidate = `${parts[1]}://${parts[2]}`;
  }
  const requested = normalizeOrigin(candidate);
  if (!requested || typeof allowedOrigins !== "string") return {};
  const allowed = allowedOrigins.split(",").some((entry) => normalizeOrigin(phpTrim(entry))?.origin === requested.origin);
  return allowed ? { frontend_domain: requested.host } : {};
}
