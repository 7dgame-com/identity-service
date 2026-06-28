import { Injectable, NotFoundException, ServiceUnavailableException } from "@nestjs/common";
import { loadConfig } from "./config.js";
import { PluginUserWriteOperationRepository } from "./plugin-user-write-operation.repository.js";
import { PluginUserWriteShadowService } from "./plugin-user-write-shadow.service.js";

export interface PluginUserWriteProxyResponse {
  status: number;
  body: unknown;
}

const PLUGIN_USER_WRITE_EXECUTABLE_MODES = ["disabled", "legacy-proxy"] as const;
const PLUGIN_USER_WRITE_ROUTES = [
  "create-user",
  "update-user",
  "delete-user",
  "change-role",
  "batch-create-users"
] as const;
const REQUIRED_BEFORE_DUAL_WRITE = [
  "operation-ledger",
  "idempotency-keys",
  "compensation-records",
  "secret-redaction-gate",
  "develop-rollback-drill",
  "ordinary-user-negative-regression"
] as const;
const REQUIRED_BEFORE_IDENTITY_NATIVE = [
  "clean-dual-write-production-evidence",
  "profile-owner-closed-or-retained",
  "role-permission-owner-closed-or-retained",
  "organization-owner-closed-or-retained",
  "legacy-proxy-rollback-window"
] as const;

@Injectable()
export class PluginUserWriteService {
  private readonly config = loadConfig();

  constructor(
    private readonly operations: PluginUserWriteOperationRepository,
    private readonly shadow: PluginUserWriteShadowService
  ) {}

  readiness() {
    const { iam } = this.config;
    const unsupportedModeBlocked = iam.pluginUserWriteMode === "dual-write" || iam.pluginUserWriteMode === "identity-native";

    return {
      enabled: iam.pluginUserWriteMode !== "disabled",
      mode: iam.pluginUserWriteMode,
      legacyProxyConfigured: Boolean(iam.pluginUserWriteLegacyApiBaseUrl),
      timeoutMs: iam.pluginUserWriteTimeoutMs,
      operationLedgerConfigured: this.operations.isConfigured(),
      operationLedgerSchemaAutoEnsure: false,
      idempotencyKeyFormat: "plugin-user-write:v1:<route>:<sha256-48>",
      redactionPolicy: "metadata-only-no-secret-payloads",
      compensationRecordsRequired: true,
      shadow: this.shadow.readiness(),
      allowedExecutableModes: [...PLUGIN_USER_WRITE_EXECUTABLE_MODES],
      unsupportedModeBlocked,
      blockedReasons: blockedReasonsForMode(iam.pluginUserWriteMode),
      dualWriteSupported: false,
      identityNativeSupported: false,
      nextRequiredSpec: "identity-plugin-user-native-write",
      sourceOfTruth: sourceOfTruthForMode(iam.pluginUserWriteMode),
      routes: [...PLUGIN_USER_WRITE_ROUTES],
      requiredBeforeDualWrite: [...REQUIRED_BEFORE_DUAL_WRITE],
      requiredBeforeIdentityNative: [...REQUIRED_BEFORE_IDENTITY_NATIVE]
    };
  }

  async proxy(request: PluginUserWriteRequest, path: string): Promise<PluginUserWriteProxyResponse> {
    const { iam } = this.config;

    if (iam.pluginUserWriteMode === "disabled") {
      throw new NotFoundException({
        code: "PLUGIN_USER_WRITE_DISABLED",
        message: "Plugin user write migration is disabled."
      });
    }

    if (iam.pluginUserWriteMode !== "legacy-proxy") {
      throw new NotFoundException({
        code: "PLUGIN_USER_WRITE_UNSUPPORTED_MODE",
        message: `Plugin user write mode ${iam.pluginUserWriteMode} is not executable yet.`
      });
    }

    if (!iam.pluginUserWriteLegacyApiBaseUrl) {
      throw new ServiceUnavailableException({
        code: "PLUGIN_USER_WRITE_LEGACY_API_NOT_CONFIGURED",
        message: "Legacy plugin-user API base URL is not configured."
      });
    }

    const url = new URL(path, `${iam.pluginUserWriteLegacyApiBaseUrl.replace(/\/+$/, "")}/`);
    const query = queryStringFromOriginalUrl(request.originalUrl);
    if (query) {
      url.search = query;
    }

    const headers = new Headers({
      Accept: "application/json",
      "X-Identity-Plugin-User-Write-Proxy": "1"
    });
    const authorization = firstHeader(request.headers.authorization);
    const forwardedFor = firstHeader(request.headers["x-forwarded-for"]);
    const userAgent = firstHeader(request.headers["user-agent"]);
    if (authorization) {
      headers.set("Authorization", authorization);
    }
    if (forwardedFor) {
      headers.set("X-Forwarded-For", forwardedFor);
    }
    if (userAgent) {
      headers.set("User-Agent", userAgent);
    }

    const init: RequestInit = {
      method: request.method.toUpperCase(),
      headers,
      signal: AbortSignal.timeout(iam.pluginUserWriteTimeoutMs)
    };
    headers.set("Content-Type", "application/json");
    init.body = JSON.stringify(request.body ?? {});

    let upstream: Response;
    try {
      upstream = await fetch(url, init);
    } catch (error) {
      throw new ServiceUnavailableException({
        code: "PLUGIN_USER_WRITE_LEGACY_API_UNAVAILABLE",
        message: "Legacy plugin-user API is unavailable.",
        detail: error instanceof Error ? error.message : String(error)
      });
    }

    const body = await parseUpstreamBody(upstream);
    await this.shadow.observe({
      method: request.method,
      path,
      headers: request.headers,
      body: request.body,
      legacyStatus: upstream.status
    });

    return {
      status: upstream.status,
      body
    };
  }
}

function blockedReasonsForMode(mode: string): string[] {
  if (mode === "dual-write") {
    return [
      "identity-plugin-user-native-write closeout is required before dual-write execution.",
      "Operation ledger, idempotency keys, compensation records, redaction gates, and rollback drills are not configured."
    ];
  }

  if (mode === "identity-native") {
    return [
      "identity-native plugin-user writes require clean dual-write evidence first.",
      "Profile, role, permission, organization, and rollback ownership gates must be closed or explicitly retained."
    ];
  }

  return [];
}

function sourceOfTruthForMode(mode: string): string {
  if (mode === "legacy-proxy") {
    return "legacy";
  }

  if (mode === "disabled") {
    return "legacy-unproxied";
  }

  return "unsupported";
}

export interface PluginUserWriteRequest {
  method: string;
  originalUrl?: string;
  headers: Record<string, string | string[] | undefined>;
  body?: unknown;
}

function firstHeader(value: string | string[] | undefined): string | null {
  if (Array.isArray(value)) {
    return value[0] ?? null;
  }

  return value ?? null;
}

function queryStringFromOriginalUrl(originalUrl: string | undefined): string {
  const index = originalUrl?.indexOf("?") ?? -1;
  return index >= 0 && originalUrl ? originalUrl.slice(index + 1) : "";
}

async function parseUpstreamBody(response: Response): Promise<unknown> {
  const text = await response.text();
  if (text.trim() === "") {
    return {};
  }

  try {
    return JSON.parse(text);
  } catch {
    return {
      message: text
    };
  }
}
