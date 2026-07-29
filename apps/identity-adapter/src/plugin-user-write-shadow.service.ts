import { createHash } from "node:crypto";
import { Injectable, Logger } from "@nestjs/common";
import { loadConfig } from "./config.js";
import {
  PluginUserWriteOperationRepository,
  PluginUserWriteRoute,
  pluginUserWriteOperationKey,
  pluginUserWriteRequestFingerprint,
  redactPluginUserWriteMetadata
} from "./plugin-user-write-operation.repository.js";

const PLUGIN_USER_WRITE_SHADOW_ROUTES: PluginUserWriteRoute[] = [
  "create-user",
  "update-user",
  "delete-user",
  "change-role",
  "batch-create-users"
];

export interface PluginUserWriteShadowRequest {
  method: string;
  path: string;
  headers: Record<string, string | string[] | undefined>;
  body?: unknown;
  legacyStatus: number;
}

export interface PluginUserWriteShadowResult {
  enabled: boolean;
  mode: "off" | "plan" | "ledger-only";
  sideEffect: "none" | "operation-ledger";
  route?: PluginUserWriteRoute;
  operationKey?: string;
  correlationId?: string;
  actorSubjectKind?: string | null;
  actorSubjectHash?: string | null;
  targetSubjectKind?: string | null;
  targetSubjectHash?: string | null;
  duplicate?: boolean;
  errorCode?: string;
}

export interface PluginUserWritePlanOptions {
  actorSubject?: string | null;
  operationIdentity?: string | null;
  operationNonce?: string | null;
  idempotencySource?: "client-header" | "per-request";
}

@Injectable()
export class PluginUserWriteShadowService {
  private readonly config = loadConfig();
  private readonly logger = new Logger(PluginUserWriteShadowService.name);

  constructor(private readonly operations: PluginUserWriteOperationRepository) {}

  readiness() {
    const mode = this.config.iam.pluginUserWriteShadowMode;

    return {
      enabled: mode !== "off",
      mode,
      supportedModes: ["off", "plan", "ledger-only"],
      sideEffect: mode === "ledger-only" ? "operation-ledger" : "none",
      operationLedgerConfigured: this.operations.isConfigured(),
      responseShapePreserved: true,
      legacyProxyRequired: true,
      routes: PLUGIN_USER_WRITE_SHADOW_ROUTES
    };
  }

  async observe(input: PluginUserWriteShadowRequest): Promise<PluginUserWriteShadowResult> {
    const mode = this.config.iam.pluginUserWriteShadowMode;
    if (mode === "off") {
      return {
        enabled: false,
        mode,
        sideEffect: "none"
      };
    }

    const plan = planShadowOperation(input);
    if (mode === "plan") {
      const result: PluginUserWriteShadowResult = {
        enabled: true,
        mode,
        sideEffect: "none",
        route: plan.route,
        operationKey: plan.operationKey,
        correlationId: plan.correlationId,
        actorSubjectKind: subjectKind(plan.actorSubject),
        actorSubjectHash: subjectHash(plan.actorSubject),
        targetSubjectKind: subjectKind(plan.targetSubject),
        targetSubjectHash: subjectHash(plan.targetSubject)
      };
      this.logShadowResult(result);
      return result;
    }

    try {
      const result = await this.operations.begin({
        operationKey: plan.operationKey,
        idempotencyKey: plan.operationKey,
        route: plan.route,
        mode: "dual-write",
        actorSubject: plan.actorSubject,
        targetSubject: plan.targetSubject,
        legacyUserId: plan.legacyUserId,
        metadata: plan.metadata
      });
      const shadowResult: PluginUserWriteShadowResult = {
        enabled: true,
        mode,
        sideEffect: "operation-ledger",
        route: plan.route,
        operationKey: plan.operationKey,
        correlationId: plan.correlationId,
        actorSubjectKind: subjectKind(plan.actorSubject),
        actorSubjectHash: subjectHash(plan.actorSubject),
        targetSubjectKind: subjectKind(plan.targetSubject),
        targetSubjectHash: subjectHash(plan.targetSubject),
        duplicate: result.duplicate
      };
      this.logShadowResult(shadowResult);
      return shadowResult;
    } catch (error) {
      const shadowResult: PluginUserWriteShadowResult = {
        enabled: true,
        mode,
        sideEffect: "operation-ledger",
        route: plan.route,
        operationKey: plan.operationKey,
        correlationId: plan.correlationId,
        actorSubjectKind: subjectKind(plan.actorSubject),
        actorSubjectHash: subjectHash(plan.actorSubject),
        targetSubjectKind: subjectKind(plan.targetSubject),
        targetSubjectHash: subjectHash(plan.targetSubject),
        errorCode: error instanceof Error ? error.name : "PluginUserWriteShadowError"
      };
      this.logShadowResult(shadowResult);
      return shadowResult;
    }
  }

  private logShadowResult(result: PluginUserWriteShadowResult): void {
    const payload = {
      event: "identity.plugin_user.write.shadow",
      mode: result.mode,
      sideEffect: result.sideEffect,
      route: result.route ?? null,
      operationKey: result.operationKey ?? null,
      correlationId: result.correlationId ?? null,
      actorSubjectKind: result.actorSubjectKind ?? null,
      actorSubjectHash: result.actorSubjectHash ?? null,
      targetSubjectKind: result.targetSubjectKind ?? null,
      targetSubjectHash: result.targetSubjectHash ?? null,
      duplicate: result.duplicate ?? null,
      errorCode: result.errorCode ?? null
    };

    if (result.errorCode) {
      this.logger.warn(JSON.stringify(payload));
      return;
    }

    this.logger.log(JSON.stringify(payload));
  }
}

export function planShadowOperation(input: PluginUserWriteShadowRequest, options: PluginUserWritePlanOptions = {}) {
  const route = routeFromPath(input.path);
  const redactedBody = redactPluginUserWriteMetadata(input.body ?? {});
  const targetSubject = targetSubjectForRoute(route, redactedBody);
  const legacyShadowActorSubject = actorSubjectFromHeaders(input.headers);
  const actorSubject =
    options.actorSubject === undefined ? legacyShadowActorSubject : options.actorSubject;
  const requestFingerprint = pluginUserWriteRequestFingerprint(route, redactedBody);
  const legacyShadowOperationKey = pluginUserWriteOperationKey({
    route,
    actorSubject: legacyShadowActorSubject,
    targetSubject,
    requestFingerprint
  });
  const operationKey = pluginUserWriteOperationKey({
    route,
    actorSubject,
    targetSubject,
    requestFingerprint: options.operationIdentity ?? (options.operationNonce
      ? `${requestFingerprint}\u001f${options.operationNonce}`
      : requestFingerprint)
  });
  const correlationId = shadowCorrelationId(operationKey);

  return {
    operationKey,
    legacyShadowOperationKey,
    legacyShadowActorSubject,
    correlationId,
    route,
    actorSubject,
    targetSubject,
    legacyUserId: legacyUserIdFromBody(redactedBody),
    metadata: {
      route,
      method: input.method.toUpperCase(),
      legacyStatus: input.legacyStatus,
      targetSubject,
      ...(options.idempotencySource ? { idempotencySource: options.idempotencySource } : {}),
      requestFingerprint,
      redactedBody
    }
  };
}

function shadowCorrelationId(operationKey: string): string {
  const digest = createHash("sha256").update(operationKey).digest("hex");
  return `plugin-user-write:${digest.slice(0, 16)}`;
}

function subjectKind(subject: string | null): string | null {
  return subject?.split(":")[0] ?? null;
}

function subjectHash(subject: string | null): string | null {
  if (!subject) {
    return null;
  }

  return createHash("sha256").update(subject).digest("hex").slice(0, 16);
}

function routeFromPath(path: string): PluginUserWriteRoute {
  const route = path.replace(/\/+$/, "").split("/").pop();
  if (PLUGIN_USER_WRITE_SHADOW_ROUTES.includes(route as PluginUserWriteRoute)) {
    return route as PluginUserWriteRoute;
  }

  throw new Error(`unsupported plugin-user write route: ${path}`);
}

function actorSubjectFromHeaders(headers: Record<string, string | string[] | undefined>): string | null {
  const explicitUser = firstHeader(headers["x-user-id"]) ?? firstHeader(headers["x-legacy-user-id"]);
  if (explicitUser) {
    return `legacy-user:${explicitUser}`;
  }

  return firstHeader(headers.authorization) ? "authorization:present" : null;
}

function targetSubjectForRoute(route: PluginUserWriteRoute, body: Record<string, unknown>): string | null {
  const legacyUserId = legacyUserIdFromBody(body);
  if (legacyUserId !== null) {
    return `legacy-user:${legacyUserId}`;
  }

  const username = stringField(body, "username");
  if (username) {
    return `username:${username.toLowerCase()}`;
  }

  const email = stringField(body, "email");
  if (email) {
    return `email:${email.toLowerCase()}`;
  }

  if (route === "batch-create-users") {
    const users = Array.isArray(body.users) ? body.users.length : 0;
    return `batch:${users}`;
  }

  return null;
}

function legacyUserIdFromBody(body: Record<string, unknown>): number | null {
  const value = body.id ?? body.user_id ?? body.userId ?? body.legacy_user_id ?? body.legacyUserId;
  const numeric = Number(value);
  return Number.isInteger(numeric) && numeric > 0 ? numeric : null;
}

function stringField(body: Record<string, unknown>, key: string): string | null {
  const value = body[key];
  return typeof value === "string" && value.trim() !== "" ? value.trim() : null;
}

function firstHeader(value: string | string[] | undefined): string | null {
  if (Array.isArray(value)) {
    return value[0] ?? null;
  }

  return value ?? null;
}
