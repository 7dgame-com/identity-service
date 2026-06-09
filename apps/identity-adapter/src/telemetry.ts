import { OTLPTraceExporter } from "@opentelemetry/exporter-trace-otlp-http";
import { NodeSDK } from "@opentelemetry/sdk-node";
import { IdentityConfig } from "./config.js";

let telemetrySdk: NodeSDK | undefined;

export type TelemetryStartState =
  | { enabled: true; endpoint: string }
  | { enabled: false; reason: "not_configured" | "disabled" };

export function startTelemetry(config: IdentityConfig, env: NodeJS.ProcessEnv = process.env): TelemetryStartState {
  if (isDisabled(env.OTEL_SDK_DISABLED)) {
    return { enabled: false, reason: "disabled" };
  }

  const endpoint = config.otel.exporterOtlpEndpoint;
  if (!endpoint) {
    return { enabled: false, reason: "not_configured" };
  }

  const traceEndpoint = normalizeOtlpTraceEndpoint(endpoint);
  telemetrySdk = new NodeSDK({
    serviceName: config.otel.serviceName,
    traceExporter: new OTLPTraceExporter({
      url: traceEndpoint,
      headers: parseOtlpHeaders(config.otel.exporterOtlpHeaders),
      concurrencyLimit: 4
    }),
    logRecordProcessors: [],
    metricReaders: []
  });

  telemetrySdk.start();
  return { enabled: true, endpoint: traceEndpoint };
}

export async function shutdownTelemetry(): Promise<void> {
  if (!telemetrySdk) {
    return;
  }

  const sdk = telemetrySdk;
  telemetrySdk = undefined;
  await sdk.shutdown();
}

export function normalizeOtlpTraceEndpoint(endpoint: string): string {
  const url = new URL(endpoint);
  if (!url.pathname.endsWith("/v1/traces")) {
    url.pathname = `${url.pathname.replace(/\/$/, "")}/v1/traces`;
  }
  return url.toString();
}

function parseOtlpHeaders(headers?: string): Record<string, string> | undefined {
  if (!headers) {
    return undefined;
  }

  const parsedHeaders: Record<string, string> = {};
  for (const pair of headers.split(",")) {
    const [rawKey, ...rawValueParts] = pair.split("=");
    const key = rawKey?.trim();
    const value = rawValueParts.join("=").trim();
    if (key && value) {
      parsedHeaders[key] = value;
    }
  }

  return Object.keys(parsedHeaders).length > 0 ? parsedHeaders : undefined;
}

function isDisabled(value?: string): boolean {
  return ["1", "true", "yes", "on"].includes(value?.toLowerCase() ?? "");
}
