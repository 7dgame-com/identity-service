import { describe, expect, it } from "vitest";
import {
  ORGANIZATION_WORK_PACKAGE4_DEVELOP_REQUIRED_TEST_FILES,
  createOrganizationWorkPackage4DevelopRegressionSummary
} from "../../../scripts/iam-organization-work-package4-develop-regression.js";

const root = "/workspace/identity-service";
const revision = "a".repeat(40);

function report(overrides: Record<string, unknown> = {}) {
  return {
    numTotalTests: 931,
    numPassedTests: 926,
    numFailedTests: 0,
    numPendingTests: 5,
    success: true,
    testResults: ORGANIZATION_WORK_PACKAGE4_DEVELOP_REQUIRED_TEST_FILES.map((name) => ({
      name: `${root}/apps/identity-adapter/test/${name}`, status: "passed"
    })),
    ...overrides
  };
}

describe("Work Package 4 Develop regression summary", () => {
  it("derives the completion evidence only from a passing full revision-bound report", () => {
    expect(createOrganizationWorkPackage4DevelopRegressionSummary(report(), revision, root)).toEqual({
      contract: "iam-organization-work-package4-develop-regression-summary/v1",
      environment: "xrteeth-develop",
      buildRevision: revision,
      success: true,
      passedTests: 926,
      failedTests: 0,
      skippedTests: 5,
      totalTests: 931,
      requiredTestFiles: [...ORGANIZATION_WORK_PACKAGE4_DEVELOP_REQUIRED_TEST_FILES]
    });
  });

  it("rejects failures, low coverage, arithmetic drift, missing required tests, and foreign paths", () => {
    expect(() => createOrganizationWorkPackage4DevelopRegressionSummary(report({ success: false }), revision, root)).toThrow("regression-suite-not-passed");
    expect(() => createOrganizationWorkPackage4DevelopRegressionSummary(report({ numPassedTests: 899, numTotalTests: 904 }), revision, root)).toThrow("regression-suite-not-passed");
    expect(() => createOrganizationWorkPackage4DevelopRegressionSummary(report({ numTotalTests: 930 }), revision, root)).toThrow("regression-suite-not-passed");
    expect(() => createOrganizationWorkPackage4DevelopRegressionSummary(report({ testResults: [] }), revision, root)).toThrow("required-regression-test-missing");
    expect(() => createOrganizationWorkPackage4DevelopRegressionSummary(report({
      testResults: [{ name: "/foreign/identity-adapter.spec.ts", status: "passed" }]
    }), revision, root)).toThrow("vitest-result-path-invalid");
  });
});
