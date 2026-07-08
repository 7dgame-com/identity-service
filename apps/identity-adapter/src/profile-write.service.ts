import {
  HttpException,
  Injectable,
  NotFoundException,
  ServiceUnavailableException
} from "@nestjs/common";
import { loadConfig } from "./config.js";

export interface ProfileWriteProxyResponse {
  status: number;
  body: unknown;
  mode: "legacy-proxy";
}

export interface ProfileWriteRequest {
  method: string;
  originalUrl?: string;
  headers: Record<string, string | string[] | undefined>;
  body?: unknown;
}

@Injectable()
export class ProfileWriteService {
  private readonly config = loadConfig();

  readiness() {
    const { iam } = this.config;

    return {
      enabled: iam.profileWriteMode !== "disabled",
      mode: iam.profileWriteMode,
      legacyProxyConfigured: Boolean(iam.profileWriteLegacyApiBaseUrl),
      timeoutMs: iam.profileWriteTimeoutMs,
      sourceOfTruth: iam.profileWriteMode === "legacy-proxy" ? "legacy" : "none",
      routes: ["v1/user/update"],
      allowedExecutableModes: ["disabled", "legacy-proxy"],
      unsupportedModesBlocked: ["dual-write", "identity-native"],
      responseShapePreserved: true,
      redactionPolicy: "no-profile-payload-logging"
    };
  }

  async proxy(
    request: ProfileWriteRequest,
    path: string
  ): Promise<ProfileWriteProxyResponse> {
    const { iam } = this.config;

    if (iam.profileWriteMode === "disabled") {
      throw new NotFoundException({
        code: "PROFILE_WRITE_DISABLED",
        message: "Profile write migration is disabled."
      });
    }

    if (iam.profileWriteMode === "legacy-proxy") {
      return this.forwardToLegacy(request, path);
    }

    throw new NotFoundException({
      code: "PROFILE_WRITE_UNSUPPORTED_MODE",
      message: `Profile write mode ${iam.profileWriteMode} is not executable yet.`
    });
  }

  private async forwardToLegacy(
    request: ProfileWriteRequest,
    path: string
  ): Promise<ProfileWriteProxyResponse> {
    const { iam } = this.config;
    if (!iam.profileWriteLegacyApiBaseUrl) {
      throw new ServiceUnavailableException({
        code: "PROFILE_WRITE_LEGACY_API_NOT_CONFIGURED",
        message: "Legacy profile API base URL is not configured."
      });
    }

    const url = new URL(path, `${iam.profileWriteLegacyApiBaseUrl.replace(/\/+$/, "")}/`);
    const query = queryStringFromOriginalUrl(request.originalUrl);
    if (query) {
      url.search = query;
    }

    const headers = new Headers({
      Accept: "application/json",
      "X-Identity-Profile-Write-Proxy": "1"
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

    const method = request.method.toUpperCase();
    const init: RequestInit = {
      method,
      headers,
      signal: AbortSignal.timeout(iam.profileWriteTimeoutMs)
    };
    if (!["GET", "HEAD"].includes(method)) {
      headers.set("Content-Type", "application/json");
      init.body = JSON.stringify(request.body ?? {});
    }

    let upstream: Response;
    try {
      upstream = await fetch(url, init);
    } catch (error) {
      throw new ServiceUnavailableException({
        code: "PROFILE_WRITE_LEGACY_API_UNAVAILABLE",
        message: "Legacy profile API is unavailable.",
        detail: error instanceof Error ? error.message : String(error)
      });
    }

    const body = await parseUpstreamBody(upstream);
    if (upstream.status >= 400) {
      throw new HttpException(toHttpExceptionBody(body), upstream.status);
    }

    return {
      status: upstream.status,
      body,
      mode: "legacy-proxy"
    };
  }
}

function firstHeader(value: string | string[] | undefined): string | null {
  if (Array.isArray(value)) {
    return value[0] ?? null;
  }

  return value ?? null;
}

function queryStringFromOriginalUrl(originalUrl: string | undefined): string {
  const queryStart = originalUrl?.indexOf("?") ?? -1;
  return queryStart >= 0 ? originalUrl!.slice(queryStart + 1) : "";
}

async function parseUpstreamBody(response: Response): Promise<unknown> {
  const text = await response.text();
  if (!text) {
    return null;
  }

  const contentType = response.headers.get("content-type") ?? "";
  if (contentType.includes("application/json")) {
    try {
      return JSON.parse(text);
    } catch {
      return { message: text };
    }
  }

  try {
    return JSON.parse(text);
  } catch {
    return { message: text };
  }
}

function toHttpExceptionBody(body: unknown): string | Record<string, unknown> {
  if (body && typeof body === "object") {
    return body as Record<string, unknown>;
  }

  return { message: String(body ?? "Profile write upstream request failed.") };
}
