import { describe, expect, it } from "vitest";
import {
  OrganizationReconciliationDevelopRuntimeCertificateError,
  createOrganizationReconciliationDevelopRuntimeCertificate
} from "../src/iam-organization-reconciliation-develop-runtime-verification-certificate.js";
import {
  compiledOrganizationReconciliationDevelopDeploymentTopologyCount
} from "../src/iam-organization-reconciliation-develop-deployment-topology.js";
import { createOrganizationReconciliationDevelopRuntimeCertificateTestFixture } from
  "./iam-organization-reconciliation-develop-runtime-verification-certificate.test-fixture.js";

describe("runtime certificate compiled topology gate", () => {
  it("rejects otherwise complete raw/profile evidence when production topology count is zero", () => {
    expect(compiledOrganizationReconciliationDevelopDeploymentTopologyCount).toBe(0);
    const fixture = createOrganizationReconciliationDevelopRuntimeCertificateTestFixture();
    expect(() => createOrganizationReconciliationDevelopRuntimeCertificate(fixture.input))
      .toThrowError(OrganizationReconciliationDevelopRuntimeCertificateError);
    try {
      createOrganizationReconciliationDevelopRuntimeCertificate(fixture.input);
    } catch (error) {
      expect(error).toMatchObject({ failureId: "deployment-binding-invalid" });
    }
  });
});
