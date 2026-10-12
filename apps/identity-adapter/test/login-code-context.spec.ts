import { describe, expect, it } from "vitest";
import { loginCodeContext, validateFrontendDomain } from "../src/login-code-context.js";

describe("login-code browser origin metadata", () => {
  it("matches PHP's reviewed uppercase/default-port normalization and comma-separated allowlist", () => {
    expect(loginCodeContext({ Origin: "https://D.DEV.XRUGC.COM:443" }, " https://d.dev.xrugc.com, https://port.xrteeth.com "))
      .toEqual({ frontend_domain: "d.dev.xrugc.com" });
    expect(loginCodeContext({ origin: " HTTPS://PORT.XRTEETH.COM:00443\r\n" }, "https://port.xrteeth.com"))
      .toEqual({ frontend_domain: "port.xrteeth.com" });
  });

  it("uses only Referer's origin when Origin is absent or PHP-trim-empty", () => {
    const referer = "https://D.DEV.XRUGC.COM:443/home/index?lang=zh-CN#qr";
    for (const origin of [undefined, "", " \t\n\r\0\v"]) {
      expect(loginCodeContext({ origin, referer }, "https://d.dev.xrugc.com")).toEqual({ frontend_domain: "d.dev.xrugc.com" });
    }
    expect(loginCodeContext({ Referer: "https://frontend.test?lang=zh#qr" }, "https://frontend.test"))
      .toEqual({ frontend_domain: "frontend.test" });
  });

  it.each(["https://attacker.test", "null", "https://frontend.test/", "https://frontend.test?x=1", "malformed"])(
    "never falls back to a trusted Referer after an explicit invalid or untrusted Origin: %s", (origin) => {
      expect(loginCodeContext({ origin, referer: "https://frontend.test/page" }, "https://frontend.test")).toEqual({});
    });

  it("adapts case-insensitive native header names and PHP's first repeated-header value", () => {
    expect(loginCodeContext({ ORIGIN: ["https://frontend.test", "https://other.test"] }, "https://frontend.test"))
      .toEqual({ frontend_domain: "frontend.test" });
    expect(loginCodeContext({ origin: ["https://other.test", "https://frontend.test"], referer: "https://frontend.test/page" }, "https://frontend.test"))
      .toEqual({});
    expect(loginCodeContext({ origin: [], ReFeReR: ["https://frontend.test/page", "https://other.test"] }, "https://frontend.test"))
      .toEqual({ frontend_domain: "frontend.test" });
  });

  it.each(["", "*", "https://*.frontend.test", "https://frontend.test.attacker.test", "https://other.test", "https://frontend.test:444", "https://frontend.test/path"])(
    "requires an exact configured origin rather than a wildcard, hostname suffix or another port: %s", (allowed) => {
      expect(loginCodeContext({ origin: "https://frontend.test" }, allowed)).toEqual({});
    });

  it("preserves nondefault ports for origin matching while storing only the hostname", () => {
    expect(loginCodeContext({ origin: "https://frontend.test:8443" }, "https://frontend.test:08443"))
      .toEqual({ frontend_domain: "frontend.test" });
    expect(loginCodeContext({ origin: "https://frontend.test:8443" }, "https://frontend.test")).toEqual({});
    expect(loginCodeContext({ origin: "https://frontend.test" }, "https://frontend.test:443")).toEqual({ frontend_domain: "frontend.test" });
  });

  it.each([
    ["http://localhost", "localhost"], ["http://localhost:80", "localhost"], ["http://localhost:3001", "localhost"],
    ["http://127.0.0.1:3001", "127.0.0.1"], ["http://[::1]:3001", "::1"],
    ["https://[2001:DB8::1]:443", "2001:db8::1"], ["https://frontend.test", "frontend.test"],
  ])("accepts reviewed HTTPS origins or the exact HTTP loopback hosts: %s", (origin, host) => {
    expect(loginCodeContext({ origin }, origin)).toEqual({ frontend_domain: host });
  });

  it.each([
    "http://frontend.test", "http://192.168.1.2", "http://127.0.0.2", "http://127.1", "http://localhost.attacker.test",
    "http://[0:0:0:0:0:0:0:1]", "http://[2001:db8::1]", "ftp://frontend.test", "ws://localhost", "//frontend.test",
  ])("rejects remote/inexact HTTP and unsupported schemes even if allowlisted: %s", (origin) => {
    expect(loginCodeContext({ origin }, origin)).toEqual({});
  });

  it.each([
    "https://user@frontend.test", "https://user:pass@frontend.test", "https://@frontend.test", "https://frontend.test/",
    "https://frontend.test/path", "https://frontend.test?query=1", "https://frontend.test#fragment",
    "https://frontend.test:", "https://frontend.test:0", "https://frontend.test:65536", "https://frontend.test:000443",
    "https://frontend.test:-1", "https://frontend.test:4.43", "https://frontend.test.", "https://bad_host.test",
    "https://-bad.test", "https://bad-.test", "https://bad..test", "https://[127.0.0.1]", "https://[gg::1]",
    "https://[2001:db8::1", "https://::1", "https://[::1%25lo0]", "https://前端.test", "https://%66rontend.test",
  ])("refuses non-origin URL syntax and invalid authority shapes: %s", (origin) => {
    expect(loginCodeContext({ origin }, origin)).toEqual({});
  });

  it.each([
    "https://user@frontend.test/page", "https://user:pass@frontend.test/page", "https://@frontend.test/page", "/relative/page",
    "//frontend.test/page", "frontend.test/page", "https://frontend.test.attacker.test/page", "http://frontend.test/page",
    "https://frontend.test:65536/page", "https://frontend.test\\attacker.test/page", "https://frontend.test\n.attacker.test/page",
  ])("rejects untrusted or malformed Referer authorities: %s", (referer) => {
    expect(loginCodeContext({ referer }, "https://frontend.test")).toEqual({});
  });

  it("parses IPv6 Referer authorities and ignores path/query/fragment as metadata inputs", () => {
    expect(loginCodeContext({ referer: "https://[2001:DB8::1]:8443/page?audience=attacker#scope-admin" }, "https://[2001:db8::1]:8443"))
      .toEqual({ frontend_domain: "2001:db8::1" });
    expect(loginCodeContext({ origin: "https://frontend.test", host: "attacker.test", "x-forwarded-host": "attacker.test",
      "x-forwarded-proto": "http", audience: "attacker-client" }, "https://frontend.test"))
      .toEqual({ frontend_domain: "frontend.test" });
    expect(loginCodeContext({ host: "frontend.test", "x-forwarded-host": "frontend.test" }, "https://frontend.test")).toEqual({});
  });

  it("does not let WHATWG URL numeric-host rewriting broaden the configured origin", () => {
    for (const origin of ["https://127.1", "https://2130706433", "https://0x7f000001", "https://0177.0.0.1"]) {
      expect(loginCodeContext({ origin }, "https://127.0.0.1")).toEqual({});
      expect(loginCodeContext({ referer: `${origin}/page` }, "https://127.0.0.1")).toEqual({});
    }
  });

  it("returns only domain metadata and never copies audience, port, path or scope", () => {
    expect(loginCodeContext({ referer: "https://frontend.test:8443/path?aud=other&scope=admin#secret" }, "https://frontend.test:8443"))
      .toEqual({ frontend_domain: "frontend.test" });
    expect(loginCodeContext({}, "https://frontend.test")).toEqual({});
  });
});

describe("stored frontend-domain validation", () => {
  it.each(["localhost", "frontend.test", "a", "xn--fsqu00a.test", "127.0.0.1", "2001:db8::1", "::1"])("accepts canonical host metadata: %s", (value) => {
    expect(validateFrontendDomain(value)).toBe(value);
  });

  it("enforces 63-character labels and a 253-character complete hostname", () => {
    const longest = `${"a".repeat(63)}.${"b".repeat(63)}.${"c".repeat(63)}.${"d".repeat(61)}`;
    expect(longest).toHaveLength(253);
    expect(validateFrontendDomain(longest)).toBe(longest);
    expect(loginCodeContext({ origin: `https://${longest}` }, `https://${longest}`)).toEqual({ frontend_domain: longest });
    expect(validateFrontendDomain(longest + "d")).toBeNull();
    expect(validateFrontendDomain(`${"a".repeat(64)}.test`)).toBeNull();
  });

  it.each([undefined, null, 42, {}, [], "", "Frontend.test", "2001:DB8::1", " frontend.test", "frontend.test ",
    "frontend.test\n", "frontend.test\r", "frontend.test\r\n", "frontend.test\u2028", "frontend.test\u2029", "frontend.test\0",
    "frontend.test.", "https://frontend.test", "frontend.test:8443", "[::1]", "[::1]:3001", "a_b.test", "-a.test", "a-.test", "a..test"])(
    "returns null rather than throwing for invalid or absent metadata: %j", (value) => {
      expect(validateFrontendDomain(value)).toBeNull();
    });
});
