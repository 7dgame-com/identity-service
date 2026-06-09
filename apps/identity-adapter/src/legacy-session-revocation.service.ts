import { Injectable, Logger } from "@nestjs/common";
import { loadConfig } from "./config.js";

export interface LegacySessionRevokeResult {
  attempted: boolean;
  ok: boolean;
  revoked?: number;
  error?: string;
}

@Injectable()
export class LegacySessionRevocationService {
  private readonly config = loadConfig();
  private readonly logger = new Logger(LegacySessionRevocationService.name);

  isConfigured(): boolean {
    return Boolean(this.config.legacySessionRevoke.enabled && this.config.legacySessionRevoke.url && this.config.legacySessionRevoke.token);
  }

  async revokeUserSessions(legacyUserId: number, reason: "password.change" | "password.reset"): Promise<LegacySessionRevokeResult> {
    if (!this.isConfigured()) {
      return { attempted: false, ok: true };
    }

    const { url, token, timeoutMs } = this.config.legacySessionRevoke;
    try {
      const response = await fetch(url!, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
          "X-Identity-Internal-Token": token!
        },
        body: JSON.stringify({
          legacyUserId,
          reason
        }),
        signal: AbortSignal.timeout(timeoutMs)
      });

      const body = await parseJsonResponse(response);
      if (!response.ok) {
        const message = `Legacy session revoke returned HTTP ${response.status}`;
        this.logger.warn(`${message} for user ${legacyUserId}: ${JSON.stringify(body)}`);
        return { attempted: true, ok: false, error: message };
      }

      return {
        attempted: true,
        ok: true,
        revoked: extractRevokedCount(body)
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.logger.warn(`Legacy session revoke failed for user ${legacyUserId}: ${message}`);
      return {
        attempted: true,
        ok: false,
        error: message
      };
    }
  }
}

async function parseJsonResponse(response: Response): Promise<unknown> {
  const text = await response.text();
  if (text.trim() === "") {
    return null;
  }

  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

function extractRevokedCount(body: unknown): number | undefined {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return undefined;
  }

  const data = (body as { data?: unknown }).data;
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    return undefined;
  }

  const revoked = (data as { revoked?: unknown }).revoked;
  return typeof revoked === "number" ? revoked : undefined;
}
