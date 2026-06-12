interface SmokeArgs {
  adapterUrl: string;
  token: string | null;
  scopes: string[];
  legacyUserIds: number[];
  afterLegacyUserId: number | null;
  limit: number;
  runKey: string | null;
  dryRun: boolean;
  applyShadow: boolean;
  confirmApplyShadow: boolean;
  requireGate: boolean;
  help: boolean;
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    printHelp();
    return;
  }

  if (!args.token) {
    throw new Error("IDENTITY_IAM_INTERNAL_API_TOKEN or IDENTITY_INTERNAL_API_TOKEN is required.");
  }
  if (args.applyShadow && !args.confirmApplyShadow) {
    throw new Error("Shadow apply requires --confirm-apply-shadow.");
  }

  await checkHealth(args.adapterUrl);
  const readiness = await getJson(`${args.adapterUrl}/internal/iam/readiness`);
  printSection("readiness", readiness);

  const statusBefore = await getJson(`${args.adapterUrl}/internal/iam/reconciliation/status`, args.token);
  printSection("reconciliation.status.before", statusBefore);

  if (args.dryRun || args.applyShadow) {
    const body = reconciliationPayload(args);
    const result = await postJson(`${args.adapterUrl}/internal/iam/reconciliation/run`, args.token, body);
    printSection(args.applyShadow ? "reconciliation.apply" : "reconciliation.dryRun", result);

    if (args.applyShadow && result?.data?.runKey) {
      const report = await getJson(`${args.adapterUrl}/internal/iam/reconciliation/runs/${encodeURIComponent(result.data.runKey)}`, args.token);
      printSection("reconciliation.report", report);
    }
  }

  const statusAfter = await getJson(`${args.adapterUrl}/internal/iam/reconciliation/status`, args.token);
  printSection("reconciliation.status.after", statusAfter);

  if (args.requireGate && statusAfter?.data?.safetyGate?.passed !== true) {
    throw new Error(`Stage 7 safety gate is not passed: ${JSON.stringify(statusAfter?.data?.blockers ?? [])}`);
  }
}

function parseArgs(argv: string[]): SmokeArgs {
  const parsed: SmokeArgs = {
    adapterUrl: process.env.IDENTITY_ADAPTER_URL ?? `http://127.0.0.1:${process.env.PORT ?? "8086"}`,
    token: process.env.IDENTITY_IAM_INTERNAL_API_TOKEN ?? process.env.IDENTITY_INTERNAL_API_TOKEN ?? null,
    scopes: ["user", "role", "permission", "organization", "plugin"],
    legacyUserIds: [],
    afterLegacyUserId: null,
    limit: 10,
    runKey: null,
    dryRun: false,
    applyShadow: false,
    confirmApplyShadow: false,
    requireGate: false,
    help: false
  };

  for (const arg of argv) {
    if (arg === "--help" || arg === "-h") {
      parsed.help = true;
      continue;
    }
    if (arg === "--dry-run") {
      parsed.dryRun = true;
      continue;
    }
    if (arg === "--apply-shadow") {
      parsed.applyShadow = true;
      continue;
    }
    if (arg === "--confirm-apply-shadow") {
      parsed.confirmApplyShadow = true;
      continue;
    }
    if (arg === "--require-gate") {
      parsed.requireGate = true;
      continue;
    }
    if (arg.startsWith("--adapter-url=")) {
      parsed.adapterUrl = trimTrailingSlash(arg.slice("--adapter-url=".length));
      continue;
    }
    if (arg.startsWith("--token=")) {
      parsed.token = arg.slice("--token=".length).trim() || null;
      continue;
    }
    if (arg.startsWith("--scopes=")) {
      parsed.scopes = splitCsv(arg.slice("--scopes=".length));
      continue;
    }
    if (arg.startsWith("--legacy-user-id=")) {
      parsed.legacyUserIds.push(parsePositiveInt(arg.slice("--legacy-user-id=".length), "legacy-user-id"));
      continue;
    }
    if (arg.startsWith("--legacy-user-ids=")) {
      parsed.legacyUserIds.push(...splitCsv(arg.slice("--legacy-user-ids=".length)).map((value) => parsePositiveInt(value, "legacy-user-ids")));
      continue;
    }
    if (arg.startsWith("--after=")) {
      parsed.afterLegacyUserId = parseNonNegativeInt(arg.slice("--after=".length), "after");
      continue;
    }
    if (arg.startsWith("--limit=")) {
      parsed.limit = parsePositiveInt(arg.slice("--limit=".length), "limit");
      continue;
    }
    if (arg.startsWith("--run-key=")) {
      parsed.runKey = arg.slice("--run-key=".length).trim() || null;
      continue;
    }

    throw new Error(`Unknown argument: ${arg}`);
  }

  parsed.adapterUrl = trimTrailingSlash(parsed.adapterUrl);
  if (parsed.dryRun && parsed.applyShadow) {
    throw new Error("Use only one of --dry-run or --apply-shadow.");
  }
  if (parsed.legacyUserIds.length > 0 && parsed.afterLegacyUserId !== null) {
    throw new Error("Use explicit legacy users or cursor mode, not both.");
  }

  return parsed;
}

async function checkHealth(adapterUrl: string): Promise<void> {
  const health = await getJson(`${adapterUrl}/health`);
  printSection("health", health);
  if (health?.status !== "ok") {
    throw new Error(`Health status is not ok: ${JSON.stringify(health)}`);
  }
}

function reconciliationPayload(args: SmokeArgs): Record<string, unknown> {
  const apply = args.applyShadow;
  const payload: Record<string, unknown> = {
    dryRun: !apply,
    applyShadow: apply,
    runKey: args.runKey ?? `stage7-${apply ? "apply" : "dry-run"}-${Date.now()}`,
    scopes: args.scopes,
    limit: args.limit
  };

  if (args.legacyUserIds.length > 0) {
    payload.legacyUserIds = args.legacyUserIds;
  } else if (args.afterLegacyUserId !== null) {
    payload.afterLegacyUserId = args.afterLegacyUserId;
  }

  return payload;
}

async function getJson(url: string, token?: string | null): Promise<any> {
  const response = await fetch(url, {
    headers: token ? { "x-identity-internal-token": token } : undefined
  });
  return parseResponse(response, "GET", url);
}

async function postJson(url: string, token: string, body: Record<string, unknown>): Promise<any> {
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-identity-internal-token": token
    },
    body: JSON.stringify(body)
  });
  return parseResponse(response, "POST", url);
}

async function parseResponse(response: Response, method: string, url: string): Promise<any> {
  const text = await response.text();
  let body: any = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = text;
  }

  if (!response.ok) {
    throw new Error(`${method} ${url} failed with ${response.status}: ${text}`);
  }

  return body;
}

function printSection(name: string, value: unknown): void {
  console.log(`\n[${name}]`);
  console.log(JSON.stringify(value, null, 2));
}

function splitCsv(value: string): string[] {
  return value
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function parsePositiveInt(value: string, field: string): number {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new Error(`${field} must be a positive integer.`);
  }

  return parsed;
}

function parseNonNegativeInt(value: string, field: string): number {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 0) {
    throw new Error(`${field} must be a non-negative integer.`);
  }

  return parsed;
}

function trimTrailingSlash(value: string): string {
  return value.replace(/\/+$/, "");
}

function printHelp(): void {
  console.log(`Usage:
  npm run iam:reconciliation:smoke -- [options]
  node dist/scripts/iam-reconciliation-smoke.js [options]

Default mode checks /health, /internal/iam/readiness and
/internal/iam/reconciliation/status without writing data.

Options:
  --dry-run                         Run reconciliation dry-run.
  --apply-shadow                    Apply shadow reconciliation.
  --confirm-apply-shadow            Required with --apply-shadow.
  --legacy-user-id=<id>             Add one explicit legacy user id.
  --legacy-user-ids=<id,id>         Add multiple explicit legacy user ids.
  --after=<id>                      Cursor mode after legacy user id.
  --limit=<n>                       Batch size, default 10.
  --scopes=user,role,...            Default user,role,permission,organization,plugin.
  --run-key=<key>                   Optional deterministic run key.
  --require-gate                    Exit non-zero unless status safetyGate.passed is true.
  --adapter-url=<url>               Default IDENTITY_ADAPTER_URL or http://127.0.0.1:PORT.
  --token=<token>                   Default IDENTITY_IAM_INTERNAL_API_TOKEN or IDENTITY_INTERNAL_API_TOKEN.

Safe examples inside the identity-adapter container:
  node dist/scripts/iam-reconciliation-smoke.js
  node dist/scripts/iam-reconciliation-smoke.js --dry-run --legacy-user-id=25
  node dist/scripts/iam-reconciliation-smoke.js --apply-shadow --confirm-apply-shadow --legacy-user-id=25
`);
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
