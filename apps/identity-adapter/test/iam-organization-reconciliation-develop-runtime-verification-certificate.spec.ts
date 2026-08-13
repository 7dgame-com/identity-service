import { describe, expect, it, vi } from "vitest";

vi.mock("../src/iam-organization-reconciliation-develop-deployment-topology.js", () => ({
  bindOrganizationReconciliationDevelopDeploymentEvidenceToCompiledTopology: (candidate: unknown) =>
    Object.freeze({ topology: Object.freeze({ profileId: "test" }), deploymentEvidence: candidate,
      physicalIndependenceVerified: false as const, productionPromotionAllowed: false as const })
}));
import {
  createOrganizationReconciliationDevelopAuthoritativeCertificateSha256,
  createOrganizationReconciliationDevelopRuntimeCertificate,
  assertOrganizationReconciliationDevelopRuntimeCertificateChronology,
  serializeOrganizationReconciliationDevelopRuntimeCertificate,
  serializeOrganizationReconciliationDevelopRuntimeCloseout,
  verifyOrganizationReconciliationDevelopRuntimeCertificate
} from "../src/iam-organization-reconciliation-develop-runtime-verification-certificate.js";
import {
  createOrganizationReconciliationDevelopRuntimeCertificateTestFixture
} from "./iam-organization-reconciliation-develop-runtime-verification-certificate.test-fixture.js";

describe("Develop Task 7.2 runtime verification certificate", () => {
  it("enforces observed <= raw start <= union/intersection <= signed <= raw completion", () => {
    const baseline = {
      deploymentObservedAt: "2026-08-09T00:00:00.000Z",
      rawStartedAt: "2026-08-09T00:00:30.000Z",
      unionStartedAt: "2026-08-09T00:00:45.000Z",
      intersectionStartedAt: "2026-08-09T00:01:00.000Z",
      intersectionEndedAt: "2026-08-09T00:05:00.000Z",
      unionEndedAt: "2026-08-09T00:05:30.000Z",
      signedAt: "2026-08-09T00:06:30.000Z",
      rawCompletedAt: "2026-08-09T00:07:00.000Z"
    };
    expect(() => assertOrganizationReconciliationDevelopRuntimeCertificateChronology(baseline)).not.toThrow();
    expect(() => assertOrganizationReconciliationDevelopRuntimeCertificateChronology({
      ...baseline,
      unionEndedAt: "2026-08-09T00:06:31.000Z"
    })).toThrow(expect.objectContaining({ failureId: "collection-binding-invalid" }));
    expect(() => assertOrganizationReconciliationDevelopRuntimeCertificateChronology({
      ...baseline,
      rawStartedAt: "2026-08-09T00:00:46.000Z",
      unionStartedAt: "2026-08-09T00:00:45.000Z"
    })).toThrow(expect.objectContaining({ failureId: "collection-binding-invalid" }));
  });

  it("creates one self-hashed, PII-free certificate and a pure 21/8/1/6 closeout projection", () => {
    const fixture = createOrganizationReconciliationDevelopRuntimeCertificateTestFixture();
    const artifacts = createOrganizationReconciliationDevelopRuntimeCertificate(fixture.input);

    expect(artifacts.certificate).toMatchObject({
      task: "7.2",
      environment: "xrteeth-develop",
      mode: "read-only",
      scope: "full-range",
      outcome: "completed",
      provenance: {
        contract: "iam-organization-reconciliation-provenance/v4",
        requiredAttestationCount: 1,
        verifiedAttestationCount: 1,
        replayMode: "historical-at-shared-signed-issued-at",
        attestedAt: "2026-08-09T00:06:30.000Z"
      },
      deployment: {
        contract: "iam-organization-reconciliation-xrteeth-develop-deployment-evidence/v2",
        signerCount: 1,
        physicalIndependenceVerified: false
      },
      collection: { cursorChainCount: 21 },
      physicalProbe: {
        componentCount: 3,
        datasetCount: 21,
        physicalTableCount: 19,
        derivedDatasetCount: 1,
        completedProbePassCount: 6,
        passed: true
      },
      verification: {
        verifiedSurfaceCount: 8,
        severity: { P0: 0, P1: 0, P2: 0, info: 12 },
        mismatchCount: 0,
        allowedCoverageBlockerCount: 1
      },
      safety: {
        runtimeSafetyGatePassed: false,
        blocksDualWrite: true,
        physicalIndependenceVerified: false,
        productionReady: false,
        productionPromotionAllowed: false
      }
    });
    expect(artifacts.certificate.collection.cursorChains).toHaveLength(21);
    expect(artifacts.certificate.collection.cursorChains.every((entry) => entry.complete)).toBe(true);
    expect(artifacts.certificate.verification.surfaces).toHaveLength(8);
    expect(artifacts.certificate.provenance.attestations).toHaveLength(1);
    expect(artifacts.certificate.raw).toEqual({
      contract: "iam-organization-reconciliation-xrteeth-develop-full-range/v2",
      verificationScope: "signed-reconciliation-input-only",
      wrapperDataCertified: false,
      signedEvidenceSha256: expect.stringMatching(/^[a-f0-9]{64}$/),
      transientRawLocator: {
        sourceFileSha256: expect.stringMatching(/^[a-f0-9]{64}$/)
      }
    });
    expect(artifacts.closeout).toMatchObject({
      datasets: { verified: 21, required: 21 },
      surfaces: { verified: 8, required: 8 },
      attestations: { verified: 1, required: 1 },
      physicalProbePasses: { verified: 6, required: 6 },
      mismatchCount: 0,
      authoritativeCertificateSha256: expect.stringMatching(/^[a-f0-9]{64}$/),
      safety: {
        physicalIndependenceVerified: false,
        productionReady: false,
        productionPromotionAllowed: false
      }
    });
    expect(artifacts.closeout.authoritativeCertificateSha256).toBe(
      createOrganizationReconciliationDevelopAuthoritativeCertificateSha256(artifacts.certificate)
    );

    const serialized = [
      serializeOrganizationReconciliationDevelopRuntimeCertificate(artifacts.certificate),
      serializeOrganizationReconciliationDevelopRuntimeCloseout(
        artifacts.closeout,
        artifacts.certificate
      )
    ].join("");
    for (const privateValue of [
      ...fixture.privateValues,
      "private-collector-1", "private-node-1", "private-key-1",
      "private-logical-snapshot", "private-window", "private-legacy-main-source"
    ]) expect(serialized).not.toContain(privateValue);
    expect(serialized).not.toMatch(/"(?:records|signature|publicKeyPem|token|password|dsn|host|url)"\s*:/i);
    expect(serialized).not.toContain("BEGIN PUBLIC KEY");
  });

  it("treats unsigned wrapper artifacts as transient location data, not certified authority", () => {
    const fixture = createOrganizationReconciliationDevelopRuntimeCertificateTestFixture();
    const baseline = createOrganizationReconciliationDevelopRuntimeCertificate(fixture.input);
    const wrapperOnlyPrivateValue = "unsigned-wrapper-private-record-947";
    const changed = createOrganizationReconciliationDevelopRuntimeCertificate({
      ...fixture.input,
      rawArtifactBytes: mutateJson(fixture.input.rawArtifactBytes, (raw) => {
        const lineageRun = raw.lineageRun as Record<string, unknown>;
        lineageRun.artifacts = [{
          records: [{ name: wrapperOnlyPrivateValue }],
          unsignedWrapperOnly: true
        }];
      })
    });

    expect(changed.certificate.raw.signedEvidenceSha256).toBe(
      baseline.certificate.raw.signedEvidenceSha256
    );
    expect(changed.certificate.raw.transientRawLocator.sourceFileSha256).not.toBe(
      baseline.certificate.raw.transientRawLocator.sourceFileSha256
    );
    expect(changed.certificate.certificateSha256).not.toBe(baseline.certificate.certificateSha256);
    expect(certificateAuthorityView(changed.certificate)).toEqual(
      certificateAuthorityView(baseline.certificate)
    );
    expect(createOrganizationReconciliationDevelopAuthoritativeCertificateSha256(
      changed.certificate
    )).toBe(createOrganizationReconciliationDevelopAuthoritativeCertificateSha256(
      baseline.certificate
    ));
    expect(changed.closeout).toEqual(baseline.closeout);
    expect(serializeOrganizationReconciliationDevelopRuntimeCertificate(
      changed.certificate
    )).not.toContain(wrapperOnlyPrivateValue);
  });

  it("verifies the exact source chain historically after short-lived attestations expire", () => {
    const fixture = createOrganizationReconciliationDevelopRuntimeCertificateTestFixture();
    const created = createOrganizationReconciliationDevelopRuntimeCertificate(fixture.input);
    const verified = verifyOrganizationReconciliationDevelopRuntimeCertificate({
      rawArtifactBytes: fixture.input.rawArtifactBytes,
      deploymentEvidenceBytes: fixture.input.deploymentEvidenceBytes,
      physicalProbeBytes: fixture.input.physicalProbeBytes,
      trustPolicyBytes: fixture.input.trustPolicyBytes,
      trustedProfile: fixture.input.trustedProfile,
      certificateBytes: Buffer.from(
        serializeOrganizationReconciliationDevelopRuntimeCertificate(created.certificate),
        "utf8"
      ),
      closeoutBytes: Buffer.from(
        serializeOrganizationReconciliationDevelopRuntimeCloseout(created.closeout, created.certificate),
        "utf8"
      )
    });
    expect(verified).toEqual(created);

    expect(() => createOrganizationReconciliationDevelopRuntimeCertificate({
      ...fixture.input,
      now: new Date("2026-08-09T00:20:00.000Z")
    })).toThrow(expect.objectContaining({ failureId: "current-provenance-invalid" }));
  });

  it.each([
    ["physical probe exact bytes", (fixture: ReturnType<
      typeof createOrganizationReconciliationDevelopRuntimeCertificateTestFixture
    >) => ({ ...fixture.input, physicalProbeBytes: Buffer.concat([fixture.input.physicalProbeBytes, Buffer.from(" ")]) })],
    ["raw verification report", (fixture: ReturnType<
      typeof createOrganizationReconciliationDevelopRuntimeCertificateTestFixture
    >) => ({ ...fixture.input, rawArtifactBytes: mutateJson(fixture.input.rawArtifactBytes, (raw) => {
      (raw.verificationReport as Record<string, unknown>).reportHash = "f".repeat(64);
    }) })],
    ["operation evidence duplicate", (fixture: ReturnType<
      typeof createOrganizationReconciliationDevelopRuntimeCertificateTestFixture
    >) => ({ ...fixture.input, rawArtifactBytes: mutateJson(fixture.input.rawArtifactBytes, (raw) => {
      const operation = raw.operationEvidence as Record<string, unknown>;
      const evidence = operation.evidence as Record<string, unknown>;
      const pair = evidence.organizationDirectory as Record<string, unknown>;
      const legacy = pair.legacy as Record<string, unknown>;
      const records = legacy.records as Array<Record<string, unknown>>;
      records[0]!.name = "tampered-operation-duplicate";
    }) })],
    ["operation component-manifest duplicate", (fixture: ReturnType<
      typeof createOrganizationReconciliationDevelopRuntimeCertificateTestFixture
    >) => ({ ...fixture.input, rawArtifactBytes: mutateJson(fixture.input.rawArtifactBytes, (raw) => {
      const operation = raw.operationEvidence as Record<string, unknown>;
      const manifest = operation.componentManifest as Record<string, unknown>;
      manifest.manifestSha256 = "f".repeat(64);
    }) })],
    ["operation projection-binding duplicate", (fixture: ReturnType<
      typeof createOrganizationReconciliationDevelopRuntimeCertificateTestFixture
    >) => ({ ...fixture.input, rawArtifactBytes: mutateJson(fixture.input.rawArtifactBytes, (raw) => {
      const operation = raw.operationEvidence as Record<string, unknown>;
      const binding = operation.projectionBinding as Record<string, unknown>;
      const legacy = binding.legacy as Record<string, unknown>;
      legacy.evaluatorId = "tampered-operation-evaluator";
    }) })],
    ["legacy projection duplicate", (fixture: ReturnType<
      typeof createOrganizationReconciliationDevelopRuntimeCertificateTestFixture
    >) => ({ ...fixture.input, rawArtifactBytes: mutateJson(fixture.input.rawArtifactBytes, (raw) => {
      const projection = raw.legacyProjection as Record<string, unknown>;
      const surfaces = projection.surfaces as Record<string, unknown>;
      const records = surfaces.organizationDirectory as Array<Record<string, unknown>>;
      records[0]!.name = "tampered-legacy-projection";
    }) })],
    ["identity projection duplicate", (fixture: ReturnType<
      typeof createOrganizationReconciliationDevelopRuntimeCertificateTestFixture
    >) => ({ ...fixture.input, rawArtifactBytes: mutateJson(fixture.input.rawArtifactBytes, (raw) => {
      const projection = raw.identityProjection as Record<string, unknown>;
      const surfaces = projection.surfaces as Record<string, unknown>;
      const records = surfaces.organizationDirectory as Array<Record<string, unknown>>;
      records[0]!.name = "tampered-identity-projection";
    }) })],
    ["signed reconciliation input", (fixture: ReturnType<
      typeof createOrganizationReconciliationDevelopRuntimeCertificateTestFixture
    >) => ({ ...fixture.input, rawArtifactBytes: mutateJson(fixture.input.rawArtifactBytes, (raw) => {
      const input = raw.reconciliationInput as Record<string, unknown>;
      const pair = input.organizationDirectory as Record<string, unknown>;
      const legacy = pair.legacy as Record<string, unknown>;
      const records = legacy.records as Array<Record<string, unknown>>;
      records[0]!.name = "tampered-private-name";
    }) })],
    ["parent lineage", (fixture: ReturnType<
      typeof createOrganizationReconciliationDevelopRuntimeCertificateTestFixture
    >) => ({ ...fixture.input, rawArtifactBytes: mutateJson(fixture.input.rawArtifactBytes, (raw) => {
      const run = raw.lineageRun as Record<string, unknown>;
      const manifest = run.coordinatorManifest as Record<string, unknown>;
      manifest.manifestSha256 = "f".repeat(64);
    }) })],
    ["attestation signature", (fixture: ReturnType<
      typeof createOrganizationReconciliationDevelopRuntimeCertificateTestFixture
    >) => ({ ...fixture.input, rawArtifactBytes: mutateJson(fixture.input.rawArtifactBytes, (raw) => {
      const bundle = raw.attestationBundle as Record<string, unknown>;
      const entries = bundle.attestations as Array<Record<string, unknown>>;
      entries[0]!.signature = Buffer.alloc(64, 1).toString("base64url");
    }) })]
  ])("fails closed when %s is altered", (_label, mutate) => {
    const fixture = createOrganizationReconciliationDevelopRuntimeCertificateTestFixture();
    expect(() => createOrganizationReconciliationDevelopRuntimeCertificate(mutate(fixture)))
      .toThrow();
  });

  it("rejects duplicate JSON keys and descriptor accessors without invoking them", () => {
    const fixture = createOrganizationReconciliationDevelopRuntimeCertificateTestFixture();
    const duplicateDeployment = Buffer.from(
      fixture.input.deploymentEvidenceBytes.toString("utf8").replace(
        "{",
        '{"environment":"xrteeth-develop",'
      ),
      "utf8"
    );
    expect(() => createOrganizationReconciliationDevelopRuntimeCertificate({
      ...fixture.input,
      deploymentEvidenceBytes: duplicateDeployment
    })).toThrow(expect.objectContaining({ failureId: "invalid-json-artifact" }));

    let getterCalls = 0;
    const profile = structuredClone(fixture.input.trustedProfile) as Record<string, unknown>;
    Object.defineProperty(profile, "profileId", {
      enumerable: true,
      get: () => {
        getterCalls += 1;
        return "forged-profile";
      }
    });
    expect(() => createOrganizationReconciliationDevelopRuntimeCertificate({
      ...fixture.input,
      trustedProfile: profile as never
    })).toThrow();
    expect(getterCalls).toBe(0);
  });

  it("rejects certificate or closeout mutation even when source evidence remains valid", () => {
    const fixture = createOrganizationReconciliationDevelopRuntimeCertificateTestFixture();
    const created = createOrganizationReconciliationDevelopRuntimeCertificate(fixture.input);
    const certificateBytes = Buffer.from(
      serializeOrganizationReconciliationDevelopRuntimeCertificate(created.certificate),
      "utf8"
    );
    const closeoutBytes = Buffer.from(
      serializeOrganizationReconciliationDevelopRuntimeCloseout(created.closeout, created.certificate),
      "utf8"
    );
    const base = {
      rawArtifactBytes: fixture.input.rawArtifactBytes,
      deploymentEvidenceBytes: fixture.input.deploymentEvidenceBytes,
      physicalProbeBytes: fixture.input.physicalProbeBytes,
      trustPolicyBytes: fixture.input.trustPolicyBytes,
      trustedProfile: fixture.input.trustedProfile
    };
    expect(() => verifyOrganizationReconciliationDevelopRuntimeCertificate({
      ...base,
      certificateBytes: mutateJson(certificateBytes, (certificate) => {
        certificate.buildRevision = "b".repeat(40);
      }),
      closeoutBytes
    })).toThrow(expect.objectContaining({ failureId: "certificate-invalid" }));
    expect(() => verifyOrganizationReconciliationDevelopRuntimeCertificate({
      ...base,
      certificateBytes,
      closeoutBytes: mutateJson(closeoutBytes, (closeout) => {
        (closeout.datasets as Record<string, unknown>).verified = 20;
      })
    })).toThrow(expect.objectContaining({ failureId: "closeout-invalid" }));
  });
});

function mutateJson(
  bytes: Buffer,
  mutate: (value: Record<string, unknown>) => void
): Buffer {
  const value = JSON.parse(bytes.toString("utf8")) as Record<string, unknown>;
  mutate(value);
  return Buffer.from(`${JSON.stringify(value)}\n`, "utf8");
}

function certificateAuthorityView(
  certificate: ReturnType<typeof createOrganizationReconciliationDevelopRuntimeCertificate>["certificate"]
): Record<string, unknown> {
  const view = structuredClone(certificate) as unknown as Record<string, unknown>;
  delete view.certificateSha256;
  const raw = view.raw as Record<string, unknown>;
  delete raw.transientRawLocator;
  return view;
}
