import { createHash } from "node:crypto";

export const migrationEntries = Object.freeze({
  "account-sync": "dist/scripts/account-sync.js",
  "allocator-highwater": "dist/scripts/allocator-highwater.js",
  "identity-activate": "dist/scripts/identity-activate.js",
});
export const migrationTarget = Object.freeze({
  host: "10.206.0.5",
  port: 3306,
  database: "xrugc_identity_dev",
  principal: "identity_dev",
  fenceId: 1,
});
export const migrationStepOrder = Object.freeze([
  "sync-apply",
  "sync-zero",
  "allocator",
  "activation",
]);
export const migrationFailure = (code) => {
  throw Object.assign(new Error(code), { safeCode: code });
};
export const canonicalMigrationJson = (value) =>
  value === null || typeof value !== "object"
    ? JSON.stringify(value)
    : Array.isArray(value)
      ? `[${value.map(canonicalMigrationJson).join(",")}]`
      : `{${Object.keys(value)
          .sort()
          .map(
            (key) =>
              `${JSON.stringify(key)}:${canonicalMigrationJson(value[key])}`,
          )
          .join(",")}}`;
export const migrationDigest = (value) =>
  createHash("sha256").update(canonicalMigrationJson(value)).digest("hex");
export const migrationBytesDigest = (bytes) =>
  createHash("sha256").update(bytes).digest("hex");
export function exactMigrationObject(value, keys) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value)) ||
    Object.keys(value).sort().join(",") !== [...keys].sort().join(",")
  )
    migrationFailure("MIGRATION_INVALID_SHAPE");
}
export const migrationHash = (value) => {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value))
    migrationFailure("MIGRATION_INVALID_HASH");
  return value;
};
export const migrationInteger = (value, min, max) => {
  if (!Number.isSafeInteger(value) || value < min || value > max)
    migrationFailure("MIGRATION_INVALID_BOUND");
  return value;
};
export function migrationTime(value) {
  if (
    typeof value !== "string" ||
    !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(value) ||
    !Number.isFinite(Date.parse(value)) ||
    new Date(value).toISOString() !== value
  )
    migrationFailure("MIGRATION_INVALID_DEADLINE");
  return Date.parse(value);
}
export function freezeMigration(value) {
  if (value && typeof value === "object") {
    for (const child of Object.values(value)) freezeMigration(child);
    Object.freeze(value);
  }
  return value;
}
/** A closed plan vocabulary, not a shell command or evidence of real drain. */
export function validateMigrationPlan(value) {
  exactMigrationObject(value, [
    "version",
    "kind",
    "epoch",
    "drainSha256",
    "rosterSha256",
    "compiledRevision",
    "imageDigest",
    "executor",
    "target",
    "window",
    "inputs",
    "limits",
    "steps",
  ]);
  if (
    value.version !== 1 ||
    value.kind !== "identity-development-finalization-plan"
  )
    migrationFailure("MIGRATION_PLAN_VERSION");
  migrationInteger(value.epoch, 1, Number.MAX_SAFE_INTEGER);
  migrationHash(value.drainSha256);
  migrationHash(value.rosterSha256);
  if (
    typeof value.compiledRevision !== "string" ||
    !/^[a-f0-9]{40}$/.test(value.compiledRevision) ||
    typeof value.imageDigest !== "string" ||
    !/^sha256:[a-f0-9]{64}$/.test(value.imageDigest)
  )
    migrationFailure("MIGRATION_BUILD_BINDING");
  exactMigrationObject(value.executor, ["id", "bootId"]);
  if (
    typeof value.executor.id !== "string" ||
    !/^[a-z][a-z0-9_-]{0,63}$/.test(value.executor.id) ||
    typeof value.executor.bootId !== "string" ||
    !/^[A-Za-z0-9_-]{8,80}$/.test(value.executor.bootId)
  )
    migrationFailure("MIGRATION_EXECUTOR_BINDING");
  exactMigrationObject(value.target, Object.keys(migrationTarget));
  if (
    canonicalMigrationJson(value.target) !==
    canonicalMigrationJson(migrationTarget)
  )
    migrationFailure("MIGRATION_FIXED_TARGET_REQUIRED");
  exactMigrationObject(value.window, ["startedAt", "deadline"]);
  const duration =
    migrationTime(value.window.deadline) -
    migrationTime(value.window.startedAt);
  // Matches the existing fixture queue's hard ceiling, not activation's 5 minute DB ceiling.
  if (duration < 1 || duration > 3000)
    migrationFailure("MIGRATION_WINDOW_BOUND");
  exactMigrationObject(value.inputs, [
    "sourceSnapshotSha256",
    "profileSelectionSha256",
    "allocatorReviewSha256",
  ]);
  migrationHash(value.inputs.sourceSnapshotSha256);
  migrationHash(value.inputs.allocatorReviewSha256);
  if (value.inputs.profileSelectionSha256 !== null)
    migrationHash(value.inputs.profileSelectionSha256);
  exactMigrationObject(value.limits, ["maxChanges", "maxRows"]);
  migrationInteger(value.limits.maxChanges, 1, 100000);
  migrationInteger(value.limits.maxRows, 1, 1000000);
  const expected = [
    ["sync-apply", "account-sync", "apply"],
    ["sync-zero", "account-sync", "dry-run"],
    ["allocator", "allocator-highwater", "apply"],
    ["activation", "identity-activate", "apply"],
  ];
  if (!Array.isArray(value.steps) || value.steps.length !== expected.length)
    migrationFailure("MIGRATION_FIXED_STEP_ORDER");
  value.steps.forEach((step, i) => {
    exactMigrationObject(step, ["id", "entry", "mode", "entrySha256"]);
    if ([step.id, step.entry, step.mode].some((v, n) => v !== expected[i][n]))
      migrationFailure("MIGRATION_FIXED_STEP_ORDER");
    migrationHash(step.entrySha256);
  });
  if (value.steps[0].entrySha256 !== value.steps[1].entrySha256)
    migrationFailure("MIGRATION_BUILD_BINDING");
  return freezeMigration(JSON.parse(canonicalMigrationJson(value)));
}
export function migrationPlanBytes(value) {
  return Buffer.from(
    canonicalMigrationJson(validateMigrationPlan(value)) + "\n",
  );
}
export function parseMigrationPlan(bytes) {
  if (
    !Buffer.isBuffer(bytes) ||
    bytes.length < 2 ||
    bytes.length > 16384 ||
    !Buffer.from(bytes.toString("utf8")).equals(bytes)
  )
    migrationFailure("MIGRATION_PLAN_BYTES_BOUND");
  let value;
  try {
    value = JSON.parse(bytes.toString("utf8"));
  } catch {
    migrationFailure("MIGRATION_INVALID_JSON");
  }
  const plan = validateMigrationPlan(value);
  // One canonical format prevents duplicate-key, whitespace and ambiguous input hashing.
  if (!migrationPlanBytes(plan).equals(bytes))
    migrationFailure("MIGRATION_CANONICAL_PLAN_REQUIRED");
  return freezeMigration({ plan, planSha256: migrationBytesDigest(bytes) });
}
