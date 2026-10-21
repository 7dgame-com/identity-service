import { createHash } from "node:crypto";
import { readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

export const frozenAdmissionProtocolDirectory = fileURLToPath(
  new URL("./admission-protocol/", import.meta.url),
);
const upstreamDirectory = fileURLToPath(
  new URL("../../../../../../driver/identity-dev-admission/", import.meta.url),
);
export const frozenAdmissionProtocolFiles = Object.freeze([
  "coordinator.mjs",
  "journal.mjs",
  "participant-client.mjs",
  "gateway.mjs",
  "hold-queue.mjs",
]);
const fail = (code: string): never => {
  throw new Error(code);
};
/** Always use the frozen bytes. A superproject checkout additionally detects upstream drift. */
export async function verifyAdmissionProtocolSnapshot(
  options: { snapshotDirectory?: string; upstreamDirectory?: string } = {},
) {
  const directory =
    options.snapshotDirectory ?? frozenAdmissionProtocolDirectory;
  const upstream = options.upstreamDirectory ?? upstreamDirectory;
  const bytes = await readFile(join(directory, "manifest.json"));
  if (
    bytes.length > 16384 ||
    !Buffer.from(bytes.toString("utf8")).equals(bytes)
  )
    fail("ADMISSION_FIXTURE_MANIFEST_INVALID");
  const manifest = JSON.parse(bytes.toString("utf8"));
  const keys = (value: unknown) =>
    value && typeof value === "object" && !Array.isArray(value)
      ? Object.keys(value).sort().join(",")
      : "";
  if (
    keys(manifest) !== "files,kind,upstream,version" ||
    manifest.version !== 1 ||
    manifest.kind !== "identity-admission-test-protocol-snapshot" ||
    keys(manifest.upstream) !== "commit,directory,repository" ||
    manifest.upstream.repository !== "xrugc-superproject" ||
    manifest.upstream.directory !== "driver/identity-dev-admission" ||
    !/^[a-f0-9]{40}$/.test(manifest.upstream.commit) ||
    keys(manifest.files) !== [...frozenAdmissionProtocolFiles].sort().join(",")
  )
    fail("ADMISSION_FIXTURE_MANIFEST_INVALID");
  let upstreamPresent = false;
  try {
    upstreamPresent = (await stat(upstream)).isDirectory();
    if (!upstreamPresent) fail("ADMISSION_FIXTURE_UPSTREAM_INVALID");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  for (const name of frozenAdmissionProtocolFiles) {
    const expected = manifest.files[name];
    if (typeof expected !== "string" || !/^[a-f0-9]{64}$/.test(expected))
      fail("ADMISSION_FIXTURE_MANIFEST_INVALID");
    const snapshot = await readFile(join(directory, name));
    if (
      snapshot.length > 512 * 1024 ||
      createHash("sha256").update(snapshot).digest("hex") !== expected
    )
      fail(`ADMISSION_FIXTURE_SNAPSHOT_DRIFT:${name}`);
    if (upstreamPresent) {
      const source = await readFile(join(upstream, name));
      if (!snapshot.equals(source))
        fail(`ADMISSION_FIXTURE_UPSTREAM_DRIFT:${name}`);
    }
  }
  return {
    upstreamPresent,
    upstreamCommit: manifest.upstream.commit as string,
    files: frozenAdmissionProtocolFiles.length,
  };
}
