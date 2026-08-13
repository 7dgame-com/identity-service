const FULL_BUILD_REVISION = /^[a-f0-9]{40}$/;

export function normalizeBuildRevision(value: unknown): string | null {
  if (typeof value !== "string") return null;
  return FULL_BUILD_REVISION.test(value) ? value : null;
}

export function currentBuildRevision(env: NodeJS.ProcessEnv = process.env): string | null {
  return normalizeBuildRevision(env.IDENTITY_BUILD_REVISION);
}

export function publicBuildRevision(env: NodeJS.ProcessEnv = process.env): string {
  return currentBuildRevision(env) ?? "unknown";
}
