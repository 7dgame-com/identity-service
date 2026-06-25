import { Injectable, NotFoundException, ServiceUnavailableException } from "@nestjs/common";
import { loadConfig } from "./config.js";

export interface PluginUserWriteProxyResponse {
  status: number;
  body: unknown;
}

@Injectable()
export class PluginUserWriteService {
  private readonly config = loadConfig();

  readiness() {
    const { iam } = this.config;

    return {
      enabled: iam.pluginUserWriteMode !== "disabled",
      mode: iam.pluginUserWriteMode,
      legacyProxyConfigured: Boolean(iam.pluginUserWriteLegacyApiBaseUrl),
      timeoutMs: iam.pluginUserWriteTimeoutMs,
      dualWriteSupported: false,
      identityNativeSupported: false,
      sourceOfTruth: iam.pluginUserWriteMode === "legacy-proxy" ? "legacy" : "legacy-unproxied",
      routes: [
        "create-user",
        "update-user",
        "delete-user",
        "change-role",
        "batch-create-users"
      ]
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

    return {
      status: upstream.status,
      body: await parseUpstreamBody(upstream)
    };
  }
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
