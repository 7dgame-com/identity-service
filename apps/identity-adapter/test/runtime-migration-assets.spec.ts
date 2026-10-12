import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

describe("runtime migration assets", () => {
  it("ships complete versioned native DDL alongside compiled migration CLIs", () => {
    const root = new URL("../../../", import.meta.url);
    const dockerfile = readFileSync(new URL("Dockerfile", root), "utf8");
    const runtime = dockerfile.split(/FROM[^\n]+ AS runtime\s*\n/i)[1];
    expect(runtime).toBeDefined();
    expect(runtime).toMatch(/^COPY deploy\/mysql \.\/deploy\/mysql\s*$/m);
    expect(runtime).toMatch(/^COPY --from=build \/app\/dist \.\/dist\s*$/m);
    expect(readFileSync(new URL(".dockerignore", root), "utf8")).not.toMatch(/^\/?deploy(?:\/mysql)?\/?\s*$/m);
    for (const asset of ["init.sql", "identity-account-schema.sql", "identity-runtime-schema.sql",
      "identity-legacy-wechat-signup-schema.sql", "identity-password-reset-token-schema.sql", "identity-legacy-challenge-schema.sql", "identity-qrcode-schema.sql",
      "identity-wechat-oauth-schema.sql", "identity-wechat-binary-migration.sql", "identity-apple-schema.sql",
      "migrations/20260926_device_sn_sessions.sql"]) {
      expect(readFileSync(new URL(`deploy/mysql/${asset}`, root), "utf8").trim(), asset).not.toBe("");
    }
  });
});
