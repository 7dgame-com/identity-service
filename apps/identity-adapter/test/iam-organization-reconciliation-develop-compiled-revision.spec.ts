import { afterEach, describe, expect, it } from "vitest";
import {
  assertOrganizationReconciliationDevelopFullRangeCompiledRevision,
  runOrganizationReconciliationDevelopFullRange
} from "../src/iam-organization-reconciliation-develop-full-range.js";

const originalRuntimeRevision = process.env.IDENTITY_BUILD_REVISION;

afterEach(() => {
  if (originalRuntimeRevision === undefined) delete process.env.IDENTITY_BUILD_REVISION;
  else process.env.IDENTITY_BUILD_REVISION = originalRuntimeRevision;
});

describe("Develop full-range fail-closed committed revision", () => {
  it("rejects a missing compiled revision before caller dependencies can substitute one", async () => {
    process.env.IDENTITY_BUILD_REVISION = "a".repeat(40);

    expect(() => assertOrganizationReconciliationDevelopFullRangeCompiledRevision())
      .toThrowError("compiled-revision-unavailable");
    await expect(runOrganizationReconciliationDevelopFullRange({
      buildRevision: "a".repeat(40)
    } as never)).rejects.toMatchObject({ failureId: "compiled-revision-unavailable" });
  });
});
