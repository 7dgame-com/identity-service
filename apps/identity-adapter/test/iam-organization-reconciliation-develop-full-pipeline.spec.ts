import { generateKeyPairSync, sign as signEd25519 } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import type {
  OrganizationReconciliationTrustedProfile
} from "../src/iam-organization-reconciliation-provenance.js";

const compiled = vi.hoisted(() => ({
  profile: undefined as OrganizationReconciliationTrustedProfile | undefined,
  deploymentEvidence: undefined as unknown
}));

vi.mock("../src/generated/iam-organization-reconciliation-compiled-revision.js", () => ({
  ORGANIZATION_RECONCILIATION_COMPILED_BUILD_REVISION: "a".repeat(40)
}));

vi.mock("../src/iam-organization-reconciliation-trust-profiles.js", () => ({
  compiledOrganizationReconciliationTrustProfileCount: 1,
  resolveCompiledOrganizationReconciliationTrustProfile: (profileId: string) =>
    compiled.profile?.profileId === profileId ? structuredClone(compiled.profile) : undefined
}));

vi.mock("../src/iam-organization-reconciliation-develop-deployment-topology.js", async (
  importOriginal
) => {
  const original = await importOriginal<typeof import(
    "../src/iam-organization-reconciliation-develop-deployment-topology.js"
  )>();
  return {
    ...original,
    bindOrganizationReconciliationDevelopDeploymentEvidenceToCompiledTopology: (
      candidate: unknown,
      profileId: string
    ) => {
      if (
        profileId !== compiled.profile?.profileId ||
        JSON.stringify(candidate) !== JSON.stringify(compiled.deploymentEvidence)
      ) {
        throw new Error("test deployment topology policy mismatch");
      }
      return Object.freeze({
        topology: Object.freeze({ profileId }),
        deploymentEvidence: candidate,
        physicalIndependenceVerified: false as const,
        productionPromotionAllowed: false as const
      });
    }
  };
});

import {
  ORGANIZATION_OWNER_DEVELOP_DECISION_CATALOGS
} from "../src/iam-organization-owner-semantic-registry.js";
import {
  createOrganizationReconciliationDevelopDeploymentEvidenceSha256
} from "../src/iam-organization-reconciliation-develop-deployment-evidence.js";
import {
  runOrganizationReconciliationDevelopFullRange,
  type OrganizationReconciliationDevelopFullRangeDependencies,
  type OrganizationReconciliationDevelopFullRangeExternalSigner
} from "../src/iam-organization-reconciliation-develop-full-range.js";
import {
  createOrganizationReconciliationDevelopPhysicalProbeFileSha256,
  createOrganizationReconciliationDevelopRuntimeCertificate,
  serializeOrganizationReconciliationDevelopRuntimeCertificate,
  serializeOrganizationReconciliationDevelopRuntimeCloseout
} from "../src/iam-organization-reconciliation-develop-runtime-verification-certificate.js";
import {
  ORGANIZATION_RECONCILIATION_DEVELOP_IAM_POLICY_CHECKSUM,
  ORGANIZATION_RECONCILIATION_MYSQL_STATEMENTS,
  type MysqlRepeatableReadSnapshotConnectionFactory,
  type OrganizationReconciliationMysqlStatementId
} from "../src/iam-organization-reconciliation/mysql-repeatable-read-snapshot.js";
import type {
  OrganizationReconciliationMysqlRawComponentId
} from "../src/iam-organization-reconciliation/mysql-source-adapters/raw-source-snapshots.js";
import {
  createOrganizationReconciliationDevelopDeploymentEvidenceForTest
} from "./iam-organization-reconciliation-develop-deployment-evidence.test-fixture.js";
import {
  createOrganizationReconciliationPolicyForTest,
  createOrganizationReconciliationTrustedProfileForTest
} from "./iam-organization-reconciliation-provenance.test-fixture.js";
import {
  createOrganizationReconciliationDevelopRuntimeCertificateTestFixture
} from "./iam-organization-reconciliation-develop-runtime-verification-certificate.test-fixture.js";

const REVISION = "a".repeat(40);
const CHECKSUM = ORGANIZATION_RECONCILIATION_DEVELOP_IAM_POLICY_CHECKSUM;
const DATABASE_USERS = Object.freeze({
  "legacy-main": "legacy-main-reader",
  identity: "identity-reader",
  plugin: "plugin-reader"
});
const PRIVATE_VALUES = Object.freeze([
  "secret-campus",
  "Sensitive Campus Title",
  "identity:1",
  "identity:2",
  "legacy-user:1",
  "legacy-user:2",
  "secret-collector-alpha",
  "secret-collector-beta",
  "secret-node-alpha",
  "secret-node-beta",
  "secret-key-alpha",
  "secret-key-beta"
]);

type JsonRow = Record<string, unknown>;
type ComponentRows = Readonly<Record<
  OrganizationReconciliationMysqlRawComponentId,
  Partial<Record<OrganizationReconciliationMysqlStatementId, readonly JsonRow[]>>
>>;

describe("Develop Task 7.2 real full pipeline", () => {
  it("runs 21 datasets through eight surfaces, one real Ed25519 signature, and a PII-free 21/8/1/6 closeout", async () => {
    const keys = [generateKeyPairSync("ed25519")] as const;
    const basePolicy = createOrganizationReconciliationPolicyForTest(keys.map(({ publicKey }, index) => ({
      collectorId: "secret-collector-alpha",
      nodeId: "secret-node-alpha",
      keyId: "secret-key-alpha",
      publicKey
    })));
    const trustPolicy = { ...basePolicy, environment: "xrteeth-develop" };
    const trustedProfile = createOrganizationReconciliationTrustedProfileForTest(trustPolicy);
    compiled.profile = trustedProfile;

    // Reuse the independently validated six-pass physical-probe fixture, but
    // bind it to this run's exact deployment and one test-only public key.
    const physicalProbeBytes = createOrganizationReconciliationDevelopRuntimeCertificateTestFixture()
      .input.physicalProbeBytes;
    const deploymentEvidence = {
      ...createOrganizationReconciliationDevelopDeploymentEvidenceForTest(
        trustPolicy.requiredCollectors,
        REVISION
      ),
      physicalProbeSha256:
        createOrganizationReconciliationDevelopPhysicalProbeFileSha256(physicalProbeBytes)
    };
    const deploymentEvidenceSha256 =
      createOrganizationReconciliationDevelopDeploymentEvidenceSha256(deploymentEvidence);
    compiled.deploymentEvidence = deploymentEvidence;

    const rows = createAlignedRows();
    const legacy = createHermeticSource("legacy-main", rows["legacy-main"]);
    const identity = createHermeticSource("identity", rows.identity);
    const plugin = createHermeticSource("plugin", rows.plugin);
    const signerCalls: Uint8Array[] = [];
    const externalSigners = trustPolicy.requiredCollectors.map((collector, index) => ({
      collectorId: collector.collectorId,
      nodeId: collector.nodeId,
      keyId: collector.keyId,
      publicKeySha256: collector.publicKeySha256,
      buildRevision: collector.buildRevision,
      sign: (payload: Uint8Array) => {
        signerCalls.push(Uint8Array.from(payload));
        return signEd25519(null, Buffer.from(payload), keys[index]!.privateKey);
      }
    } satisfies OrganizationReconciliationDevelopFullRangeExternalSigner));

    let rawPayload = "";
    let clockTick = 0;
    const result = await runOrganizationReconciliationDevelopFullRange({
      environment: "xrteeth-develop",
      deploymentEvidence,
      legacyConnectionFactory: legacy.factory,
      identityConnectionFactory: identity.factory,
      pluginConnectionFactory: plugin.factory,
      expectedDatabaseUsers: DATABASE_USERS,
      trustPolicy,
      externalSigners,
      attestationTtlSeconds: 300,
      clock: {
        now: () => new Date(
          Date.parse("2026-08-09T00:01:00.000Z") + clockTick++ * 1_000
        )
      },
      output: {
        write: (payload) => {
          expect(rawPayload).toBe("");
          rawPayload = payload;
        }
      }
    } satisfies OrganizationReconciliationDevelopFullRangeDependencies);

    expect(result).toMatchObject({
      outcome: "completed",
      datasetCount: 21,
      verifiedSurfaceCount: 8,
      externalProvenanceVerified: true,
      verifiedAttestationCount: 1,
      deploymentEvidenceSha256,
      physicalIndependenceVerified: false,
      productionReady: false,
      productionPromotionAllowed: false
    });
    expect([legacy.opens, identity.opens, plugin.opens]).toEqual([3, 3, 3]);
    expect(signerCalls).toHaveLength(1);
    expect(signerCalls.every((payload) => payload.length > 32)).toBe(true);

    const rawArtifactBytes = Buffer.from(rawPayload, "utf8");
    const raw = JSON.parse(rawPayload) as Record<string, unknown>;
    expect(raw).toMatchObject({
      contract: "iam-organization-reconciliation-xrteeth-develop-full-range/v2",
      datasetCount: 21,
      verifiedSurfaceCount: 8,
      externalProvenanceVerified: true,
      verifiedAttestationCount: 1,
      physicalIndependenceVerified: false,
      productionReady: false,
      productionPromotionAllowed: false,
      deploymentEvidenceSha256
    });
    expect((raw.lineageRun as { artifacts: unknown[] }).artifacts).toHaveLength(21);
    expect((raw.verificationReport as { coverage: unknown[] }).coverage).toHaveLength(8);
    const coordinatorManifest = (raw.lineageRun as {
      coordinatorManifest: {
        windowStartedAt: string;
        windowEndedAt: string;
        components: readonly { openedAt: string; closedAt: string }[];
      };
    }).coordinatorManifest;
    const collectionEnvelope = (raw.reconciliationInput as {
      collectionEnvelope: { windowStartedAt: string; windowEndedAt: string };
    }).collectionEnvelope;
    const provenanceManifest = (raw.reconciliationInput as {
      componentManifest: { windowStartedAt: string; windowEndedAt: string };
    }).componentManifest;
    const expectedIntersectionStart = coordinatorManifest.components.reduce(
      (latest, component) => Date.parse(component.openedAt) > Date.parse(latest)
        ? component.openedAt
        : latest,
      coordinatorManifest.components[0]!.openedAt
    );
    const expectedIntersectionEnd = coordinatorManifest.components.reduce(
      (earliest, component) => Date.parse(component.closedAt) < Date.parse(earliest)
        ? component.closedAt
        : earliest,
      coordinatorManifest.components[0]!.closedAt
    );
    expect(collectionEnvelope).toMatchObject({
      windowStartedAt: expectedIntersectionStart,
      windowEndedAt: expectedIntersectionEnd
    });
    expect(provenanceManifest).toMatchObject({
      windowStartedAt: coordinatorManifest.windowStartedAt,
      windowEndedAt: coordinatorManifest.windowEndedAt
    });
    expect(Date.parse(collectionEnvelope.windowStartedAt))
      .toBeGreaterThan(Date.parse(coordinatorManifest.windowStartedAt));
    expect(Date.parse(collectionEnvelope.windowEndedAt))
      .toBeLessThan(Date.parse(coordinatorManifest.windowEndedAt));
    expect(rawPayload).toContain("secret-campus");
    expect(rawPayload).toContain("Sensitive Campus Title");

    const certificateInput = {
      rawArtifactBytes,
      deploymentEvidenceBytes: Buffer.from(`${JSON.stringify(deploymentEvidence)}\n`, "utf8"),
      physicalProbeBytes,
      trustPolicyBytes: Buffer.from(`${JSON.stringify(trustPolicy)}\n`, "utf8"),
      trustedProfile,
      now: new Date(String(raw.completedAt))
    } as const;
    const artifacts = createOrganizationReconciliationDevelopRuntimeCertificate(certificateInput);
    expect(artifacts.certificate).toMatchObject({
      task: "7.2",
      outcome: "completed",
      provenance: { requiredAttestationCount: 1, verifiedAttestationCount: 1 },
      deployment: { signerCount: 1, physicalIndependenceVerified: false },
      collection: { cursorChainCount: 21 },
      physicalProbe: { completedProbePassCount: 6, passed: true },
      verification: {
        verifiedSurfaceCount: 8,
        severity: { P0: 0, P1: 0, P2: 0 },
        mismatchCount: 0
      },
      safety: {
        runtimeSafetyGatePassed: false,
        physicalIndependenceVerified: false,
        productionReady: false,
        productionPromotionAllowed: false
      }
    });
    expect(artifacts.certificate.collection.cursorChains).toHaveLength(21);
    expect(artifacts.certificate.verification.surfaces).toHaveLength(8);
    expect(artifacts.certificate.provenance.attestations).toHaveLength(1);
    expect(artifacts.closeout).toMatchObject({
      datasets: { verified: 21, required: 21 },
      surfaces: { verified: 8, required: 8 },
      attestations: { verified: 1, required: 1 },
      physicalProbePasses: { verified: 6, required: 6 },
      severity: { P0: 0, P1: 0, P2: 0 },
      mismatchCount: 0,
      authoritativeCertificateSha256: expect.stringMatching(/^[a-f0-9]{64}$/),
      safety: {
        physicalIndependenceVerified: false,
        productionReady: false,
        productionPromotionAllowed: false
      }
    });

    const sanitized = [
      serializeOrganizationReconciliationDevelopRuntimeCertificate(artifacts.certificate),
      serializeOrganizationReconciliationDevelopRuntimeCloseout(
        artifacts.closeout,
        artifacts.certificate
      )
    ].join("");
    for (const privateValue of PRIVATE_VALUES) expect(sanitized).not.toContain(privateValue);
    expect(sanitized).not.toMatch(
      /"(?:records|signature|publicKeyPem|token|password|dsn|host|url)"\s*:/i
    );
    expect(sanitized).not.toContain("BEGIN PUBLIC KEY");

    const bitFlippedRaw = flipOneSignatureBit(rawArtifactBytes);
    expect(() => JSON.parse(bitFlippedRaw.toString("utf8"))).not.toThrow();
    expect(() => createOrganizationReconciliationDevelopRuntimeCertificate({
      ...certificateInput,
      rawArtifactBytes: bitFlippedRaw
    })).toThrow();
  });
});

function createAlignedRows(): ComponentRows {
  const entries = capabilityEntries();
  const permissions = [...new Set(entries.flatMap((entry) => stringArray(entry.permissionItems)))].sort();
  const roles = [...new Set([
    ...entries.flatMap((entry) => {
      const roleCatalog = entry.roles as Record<string, unknown>;
      return [...stringArray(roleCatalog.global), ...stringArray(roleCatalog.organization)];
    }),
    ...approvedRoleNames()
  ])].sort();
  const legacyItems = [
    ...roles.map((name) => ({ name, type: 1, description: null, rule_name: null })),
    ...permissions.map((name) => ({ name, type: 2, description: null, rule_name: null }))
  ].sort((left, right) => left.name.localeCompare(right.name));
  const legacyEdges = permissions.map((permission) => ({ parent: "root", child: permission }));
  const identityRoles = roles.map((role_name) => candidateNamedItem("role_name", role_name));
  const identityPermissions = permissions.map((permission_name) =>
    candidateNamedItem("permission_name", permission_name));
  const identityRelations = permissions.map((permission) => ({
    policy_checksum: CHECKSUM,
    parent_name: "root",
    parent_type: "role",
    child_name: permission,
    child_type: "permission",
    source: "legacy-import-candidate",
    status: "candidate"
  }));

  return {
    "legacy-main": {
      "legacy-membership-page/v3": [{ user_id: 2, organization_id: 7 }],
      "legacy-organization-directory-page/v3": [{
        id: 7,
        name: "secret-campus",
        title: "Sensitive Campus Title",
        created_at: 1,
        updated_at: 2
      }],
      "legacy-rbac-assignment-page/v1": [
        { user_id: 1, item_name: "root", type: 1 },
        { user_id: 2, item_name: "admin", type: 1 },
        { user_id: 2, item_name: "organization.list", type: 2 }
      ],
      "legacy-rbac-edge-page/v1": legacyEdges,
      "legacy-rbac-item-page/v1": legacyItems,
      "legacy-role-assignment-page/v3": [
        { user_id: 1, item_name: "root" },
        { user_id: 2, item_name: "admin" }
      ],
      "legacy-subject-universe-page/v3": [
        { id: 1, status: 10 },
        { id: 2, status: 10 },
        { id: 3, status: 0 }
      ]
    },
    identity: {
      "identity-iam-item-relation-page/v1": identityRelations,
      "identity-iam-permission-page/v1": identityPermissions,
      "identity-iam-policy-version-page/v1": [{
        checksum: CHECKSUM,
        source: "legacy-import-candidate",
        status: "candidate",
        role_count: identityRoles.length,
        permission_count: identityPermissions.length,
        relation_count: identityRelations.length
      }],
      "identity-iam-role-page/v1": identityRoles,
      "identity-iam-subject-assignment-page/v1": [
        identityAssignment(1, "root", "role"),
        identityAssignment(2, "admin", "role"),
        identityAssignment(2, "organization.list", "permission")
      ],
      "identity-iam-subject-assignment-snapshot-page/v1": [
        identityAssignmentSnapshot(1, 1),
        identityAssignmentSnapshot(2, 2),
        identityAssignmentSnapshot(3, 0)
      ],
      "identity-membership-candidate-page/v3": [{
        legacy_user_id: 2,
        legacy_organization_id: 7,
        identity_user_id: "identity:2",
        identity_organization_id: "legacy:7",
        organization_role: "member",
        source: "legacy",
        candidate_status: "candidate",
        operation_key: "membership-2"
      }],
      "identity-membership-candidate-snapshot-page/v1": [
        identityMembershipSnapshot(1, 0),
        identityMembershipSnapshot(2, 1),
        identityMembershipSnapshot(3, 0)
      ],
      "identity-membership-shadow-page/v3": [],
      "identity-organization-candidate-page/v3": [{
        legacy_organization_id: 7,
        identity_organization_id: "legacy:7",
        name: "secret-campus",
        title: "Sensitive Campus Title",
        source: "legacy",
        candidate_status: "candidate"
      }],
      "identity-organization-id-map-page/v3": [{
        legacy_organization_id: 7,
        identity_organization_id: "legacy:7",
        source: "legacy",
        mapping_status: "active"
      }],
      "identity-role-shadow-page/v3": [
        { legacy_user_id: 1, role_name: "root", source: "legacy-shadow", status: "shadow" },
        { legacy_user_id: 2, role_name: "admin", source: "legacy-shadow", status: "shadow" }
      ],
      "identity-subject-universe-page/v3": [
        { legacy_user_id: 1, status: "active", source: "legacy-shadow" },
        { legacy_user_id: 2, status: "active", source: "legacy-shadow" },
        { legacy_user_id: 3, status: "inactive", source: "legacy-shadow" }
      ]
    },
    plugin: { "plugin-registry-page/v3": [] }
  };
}

function candidateNamedItem(column: "role_name" | "permission_name", itemName: string): JsonRow {
  return {
    policy_checksum: CHECKSUM,
    [column]: itemName,
    description: null,
    source: "legacy-import-candidate",
    status: "candidate"
  };
}

function identityAssignment(
  legacyUserId: number,
  itemName: string,
  itemType: "role" | "permission"
): JsonRow {
  return {
    identity_user_id: `identity:${legacyUserId}`,
    legacy_user_id: legacyUserId,
    item_name: itemName,
    item_type: itemType,
    policy_checksum: CHECKSUM,
    source: "legacy-import-candidate",
    status: "candidate"
  };
}

function identityAssignmentSnapshot(legacyUserId: number, assignmentCount: number): JsonRow {
  return {
    identity_user_id: `identity:${legacyUserId}`,
    legacy_user_id: legacyUserId,
    policy_checksum: CHECKSUM,
    snapshot_key: CHECKSUM,
    assignment_count: assignmentCount,
    source: "legacy-import-candidate",
    status: "candidate"
  };
}

function identityMembershipSnapshot(legacyUserId: number, organizationCount: number): JsonRow {
  return {
    identity_user_id: `identity:${legacyUserId}`,
    legacy_user_id: legacyUserId,
    operation_key: `membership-${legacyUserId}`,
    organization_count: organizationCount,
    source: "legacy",
    candidate_status: "candidate"
  };
}

function createHermeticSource(
  component: OrganizationReconciliationMysqlRawComponentId,
  datasetRows: Partial<Record<OrganizationReconciliationMysqlStatementId, readonly JsonRow[]>>
): {
  readonly factory: MysqlRepeatableReadSnapshotConnectionFactory;
  readonly opens: number;
} {
  const state = { opens: 0 };
  const reviewedSql = new Map<string, OrganizationReconciliationMysqlStatementId>(
    Object.entries(ORGANIZATION_RECONCILIATION_MYSQL_STATEMENTS)
    .map(([statementId, sql]) => [sql, statementId as OrganizationReconciliationMysqlStatementId]));
  const factory: MysqlRepeatableReadSnapshotConnectionFactory = async () => {
    state.opens += 1;
    return {
      async query(statement, parameters = []) {
        if (statement === "SHOW GRANTS FOR CURRENT_USER()") {
          return [[
            { grant: `GRANT USAGE ON *.* TO \`${DATABASE_USERS[component]}\`@\`%\`` },
            { grant: `GRANT SELECT, SHOW VIEW ON \`${databaseName(component)}\`.* TO \`${DATABASE_USERS[component]}\`@\`%\`` }
          ], []];
        }
        if (statement.startsWith("SELECT DATABASE()")) {
          return [[{
            database_name: databaseName(component),
            current_user: `${DATABASE_USERS[component]}@%`,
            server_hostname: "hermetic-develop-db",
            server_port: 3306,
            server_version: "8.0-hermetic"
          }], []];
        }
        if (statement.includes("INFORMATION_SCHEMA.COLUMNS")) {
          return [schemaRows(component), []];
        }
        if (statement.includes(" AS metric")) return [aggregateRows(component), []];
        if (statement === "SELECT id AS subject_id FROM `user` ORDER BY id ASC") {
          return [[1, 2, 3].map((subject_id) => ({ subject_id })), []];
        }
        if (statement.startsWith("SELECT legacy_user_id AS subject_id FROM identity_users")) {
          return [[1, 2, 3].map((subject_id) => ({ subject_id })), []];
        }
        if (statement.startsWith(
          "SELECT legacy_user_id AS subject_id FROM identity_organization_membership_snapshots"
        )) {
          return [[1, 2, 3].map((subject_id) => ({ subject_id })), []];
        }
        if (statement.startsWith("SELECT name, type, rule_name FROM auth_item")) {
          const rows = datasetRows["legacy-rbac-item-page/v1"] ?? [];
          return [rows.map((row) => ({ name: row.name, type: row.type, rule_name: row.rule_name })), []];
        }
        if (statement ===
          "SELECT parent, child FROM auth_item_child ORDER BY CAST(parent AS BINARY) ASC, CAST(child AS BINARY) ASC"
        ) {
          return [[...(datasetRows["legacy-rbac-edge-page/v1"] ?? [])], []];
        }
        const statementId = reviewedSql.get(statement);
        if (statementId) {
          const pageSize = Number(parameters.at(-1));
          return [[...(datasetRows[statementId] ?? [])].slice(0, pageSize), []];
        }
        return [[], []];
      },
      release() {}
    };
  };
  return Object.defineProperties({ factory }, {
    opens: { enumerable: true, get: () => state.opens }
  }) as {
    readonly factory: MysqlRepeatableReadSnapshotConnectionFactory;
    readonly opens: number;
  };
}

function databaseName(component: OrganizationReconciliationMysqlRawComponentId): string {
  return component === "legacy-main" ? "bujiaban_development" :
    component === "identity" ? "xrugc_identity_dev" : "bujiaban_development_plugin";
}

function schemaRows(component: OrganizationReconciliationMysqlRawComponentId): JsonRow[] {
  const columns: Record<OrganizationReconciliationMysqlRawComponentId, Record<string, readonly string[]>> = {
    "legacy-main": {
      organization: ["id", "name", "title", "created_at", "updated_at"],
      user: ["id", "status"],
      user_organization: ["user_id", "organization_id"],
      auth_assignment: ["item_name", "user_id"],
      auth_item: ["name", "type", "description", "rule_name"],
      auth_item_child: ["parent", "child"]
    },
    identity: {
      identity_users: ["id", "legacy_user_id", "status", "source"],
      identity_organizations_candidate: [
        "legacy_organization_id", "identity_organization_id", "name", "title", "source", "candidate_status"
      ],
      identity_organization_id_map: [
        "legacy_organization_id", "identity_organization_id", "source", "mapping_status"
      ],
      identity_organization_memberships_shadow: [
        "legacy_user_id", "organization_id", "organization_role", "source", "status"
      ],
      identity_organization_memberships_candidate: [
        "legacy_user_id", "legacy_organization_id", "identity_user_id", "identity_organization_id",
        "organization_role", "source", "candidate_status", "operation_key"
      ],
      identity_organization_membership_snapshots: [
        "identity_user_id", "legacy_user_id", "operation_key", "organization_count", "source", "candidate_status"
      ],
      identity_role_assignments_shadow: ["legacy_user_id", "role_name", "source", "status"],
      identity_iam_policy_versions: [
        "checksum", "source", "status", "role_count", "permission_count", "relation_count"
      ],
      identity_iam_roles: ["policy_checksum", "role_name", "description", "source", "status"],
      identity_iam_permissions: ["policy_checksum", "permission_name", "description", "source", "status"],
      identity_iam_item_relations: [
        "policy_checksum", "parent_name", "parent_type", "child_name", "child_type", "source", "status"
      ],
      identity_iam_subject_assignments: [
        "identity_user_id", "legacy_user_id", "item_name", "item_type", "policy_checksum", "source", "status"
      ]
    },
    plugin: { plugins: ["id", "enabled", "access_scope", "organization_name"] }
  };
  return Object.entries(columns[component]).flatMap(([table, names]) => names.map((column, index) => ({
    table_name: table,
    column_name: column,
    data_type: column.endsWith("_id") || column.endsWith("_count") ? "bigint" : "varchar",
    column_type: column.endsWith("_id") || column.endsWith("_count") ? "bigint" : "varchar(255)",
    is_nullable: "NO",
    collation_name: column.endsWith("_id") || column.endsWith("_count") ? "" : "utf8mb4_unicode_ci",
    ordinal_position: index + 1
  })));
}

function aggregateRows(component: OrganizationReconciliationMysqlRawComponentId): JsonRow[] {
  const rows = createAlignedRows();
  const legacyItems = rows["legacy-main"]["legacy-rbac-item-page/v1"] ?? [];
  const legacyEdges = rows["legacy-main"]["legacy-rbac-edge-page/v1"] ?? [];
  const identityRoles = rows.identity["identity-iam-role-page/v1"] ?? [];
  const identityPermissions = rows.identity["identity-iam-permission-page/v1"] ?? [];
  const identityRelations = rows.identity["identity-iam-item-relation-page/v1"] ?? [];
  const values: Record<OrganizationReconciliationMysqlRawComponentId, Record<string, number>> = {
    "legacy-main": {
      legacy_organization_count: 1,
      legacy_subject_count: 3,
      legacy_active_subject_count: 2,
      legacy_membership_count: 1,
      legacy_rbac_item_count: legacyItems.length,
      legacy_named_rule_count: 0,
      legacy_rbac_edge_count: legacyEdges.length,
      legacy_role_assignment_count: 2,
      legacy_rbac_assignment_count: 3
    },
    identity: {
      identity_subject_count: 3,
      identity_subject_collision_count: 0,
      identity_organization_candidate_count: 1,
      identity_organization_id_map_count: 1,
      identity_membership_candidate_count: 1,
      identity_membership_snapshot_count: 3,
      identity_membership_snapshot_organization_sum: 1,
      identity_membership_shadow_count: 0,
      identity_role_shadow_count: 2,
      identity_iam_policy_version_count: 1,
      identity_iam_declared_role_count: identityRoles.length,
      identity_iam_declared_permission_count: identityPermissions.length,
      identity_iam_declared_relation_count: identityRelations.length,
      identity_iam_role_count: identityRoles.length,
      identity_iam_permission_count: identityPermissions.length,
      identity_iam_relation_count: identityRelations.length,
      identity_iam_subject_assignment_count: 3
    },
    plugin: {
      plugin_count: 0,
      plugin_enabled_count: 0,
      plugin_invalid_scope_count: 0,
      plugin_empty_organization_name_count: 0
    }
  };
  return Object.entries(values[component]).map(([metric, metricValue]) => ({
    metric,
    metric_value: String(metricValue)
  }));
}

function capabilityEntries(): readonly Record<string, unknown>[] {
  const catalog = ORGANIZATION_OWNER_DEVELOP_DECISION_CATALOGS.capabilityCatalog as unknown;
  const entries = (catalog as { entries?: unknown }).entries;
  if (!Array.isArray(entries)) throw new Error("test fixture requires the approved capability catalog");
  return entries as readonly Record<string, unknown>[];
}

function approvedRoleNames(): string[] {
  const catalog = ORGANIZATION_OWNER_DEVELOP_DECISION_CATALOGS.roleScopes as unknown as
    Record<string, unknown>;
  return [...stringArray(catalog.globalOnly), ...stringArray(catalog.memberOrganization)];
}

function stringArray(value: unknown): string[] {
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== "string")) {
    throw new Error("test fixture catalog array is invalid");
  }
  return value as string[];
}

function flipOneSignatureBit(rawArtifactBytes: Buffer): Buffer {
  const output = Buffer.from(rawArtifactBytes);
  const marker = Buffer.from('"signature":"', "utf8");
  const markerOffset = output.indexOf(marker);
  if (markerOffset < 0) throw new Error("raw artifact has no signature");
  const signatureStart = markerOffset + marker.length;
  const signatureEnd = output.indexOf(0x22, signatureStart);
  for (let index = signatureStart; index < signatureEnd; index += 1) {
    const flipped = output[index]! ^ 1;
    if (/^[A-Za-z0-9_-]$/.test(String.fromCharCode(flipped))) {
      output[index] = flipped;
      return output;
    }
  }
  throw new Error("raw signature has no safely flippable bit");
}
