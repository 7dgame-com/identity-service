import { createHash } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { lstat, open, realpath, rm } from "node:fs/promises";
import { dirname, isAbsolute, resolve } from "node:path";

export async function writeOrganizationEvidenceExclusive0600(
  outputPath: string,
  value: unknown
): Promise<{ path: string; sha256: string }> {
  if (typeof outputPath !== "string" || !isAbsolute(outputPath) || outputPath !== resolve(outputPath) ||
      typeof fsConstants.O_NOFOLLOW !== "number") throw new Error("output must be a normalized absolute path");
  const parent = dirname(outputPath);
  if (await realpath(parent) !== parent) throw new Error("output parent must be canonical");
  const parentBefore = await lstat(parent);
  if (!parentBefore.isDirectory() || parentBefore.uid !== process.getuid?.() || (parentBefore.mode & 0o022) !== 0) {
    throw new Error("output parent must be owner-controlled");
  }
  const bytes = Buffer.from(`${JSON.stringify(value)}\n`, "utf8");
  let handle;
  let identity: { dev: number; ino: number } | null = null;
  try {
    handle = await open(outputPath,
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW, 0o600);
    const created = await handle.stat();
    identity = { dev: created.dev, ino: created.ino };
    await handle.writeFile(bytes);
    await handle.sync();
    const after = await handle.stat();
    if (!after.isFile() || after.nlink !== 1 || after.dev !== created.dev || after.ino !== created.ino ||
        (after.mode & 0o077) !== 0 || after.size !== bytes.length) throw new Error("output verification failed");
    const parentAfter = await lstat(parent);
    if (parentAfter.dev !== parentBefore.dev || parentAfter.ino !== parentBefore.ino || await realpath(parent) !== parent) {
      throw new Error("output parent changed");
    }
    await handle.close();
    return { path: outputPath, sha256: createHash("sha256").update(bytes).digest("hex") };
  } catch (error) {
    if (handle) await handle.close().catch(() => undefined);
    const current = await lstat(outputPath).catch(() => null);
    if (identity && current?.isFile() && current.dev === identity.dev && current.ino === identity.ino) {
      await rm(outputPath, { force: true });
    }
    throw error;
  }
}
