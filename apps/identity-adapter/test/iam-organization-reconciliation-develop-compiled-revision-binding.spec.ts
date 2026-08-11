import { describe, expect, it, vi } from "vitest";

const COMPILED_REVISION_B = "b".repeat(40);
const CALLER_REVISION_A = "a".repeat(40);

vi.mock("../src/generated/iam-organization-reconciliation-compiled-revision.js", () => ({
  ORGANIZATION_RECONCILIATION_COMPILED_BUILD_REVISION: "b".repeat(40)
}));

import {
  assertOrganizationReconciliationDevelopFullRangeCompiledRevision,
  runOrganizationReconciliationDevelopFullRange
} from "../src/iam-organization-reconciliation-develop-full-range.js";

describe("Develop full-range immutable compiled revision binding", () => {
  it("accepts only the exact compiled revision as an expected assertion", () => {
    expect(assertOrganizationReconciliationDevelopFullRangeCompiledRevision(COMPILED_REVISION_B))
      .toBe(COMPILED_REVISION_B);
    expect(() => assertOrganizationReconciliationDevelopFullRangeCompiledRevision(CALLER_REVISION_A))
      .toThrowError("compiled-revision-mismatch");
  });

  it("rejects code B with a caller-supplied revision A before any dependency callback", async () => {
    let callbacks = 0;
    const callback = () => {
      callbacks += 1;
      throw new Error("must not run");
    };
    await expect(runOrganizationReconciliationDevelopFullRange({
      environment: "xrteeth-develop",
      buildRevision: CALLER_REVISION_A,
      legacyConnectionFactory: callback,
      identityConnectionFactory: callback,
      pluginConnectionFactory: callback,
      expectedDatabaseUsers: {},
      trustPolicy: {},
      externalSigners: [],
      attestationTtlSeconds: 300,
      clock: { now: callback },
      output: { write: callback }
    } as never)).rejects.toMatchObject({ failureId: "invalid-input" });
    expect(callbacks).toBe(0);
  });
});
