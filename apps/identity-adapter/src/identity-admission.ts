import { AsyncLocalStorage } from "node:async_hooks";
import {
  constants,
  readFileSync,
  closeSync,
  fstatSync,
  openSync,
} from "node:fs";
import { ServiceUnavailableException } from "@nestjs/common";
import { z } from "zod";
import { performance } from "node:perf_hooks";
import { ORGANIZATION_RECONCILIATION_COMPILED_BUILD_REVISION as compiledRevision } from "./generated/iam-organization-reconciliation-compiled-revision.js";

const identitySchema = z
  .object({
    id: z.string().regex(/^[a-z][a-z0-9_-]{0,63}$/),
    bootId: z.string().regex(/^[A-Za-z0-9_-]{8,80}$/),
    revision: z.string().regex(/^[a-f0-9]{40}$/),
    routerHash: z.string().regex(/^[a-f0-9]{64}$/),
    generation: z.enum(["legacy", "identity"]),
  })
  .strict();
const configurationSchema = z
  .object({
    version: z.literal(1),
    controlUrl: z.string(),
    identity: identitySchema,
    allowedChildren: z
      .array(
        z
          .object({
            id: z.string().regex(/^[a-z][a-z0-9_-]{0,63}$/),
            origin: z.string(),
            paths: z
              .array(z.string().regex(/^\/[a-zA-Z0-9/_-]*$/))
              .min(1)
              .max(100),
          })
          .strict(),
      )
      .max(16),
    childWaitMs: z.number().int().min(25).max(5000).default(1500),
  })
  .strict();
type Configuration = z.infer<typeof configurationSchema>;
type ControlResult = {
  capability?: string;
  unknown?: boolean;
  childrenActive?: number;
  [key: string]: unknown;
};
type Task = { active: boolean };
type Context = { scope: AdmissionScope; task: Task | null };
const storage = new AsyncLocalStorage<Context>();
const verifiedScope = Symbol("verified coordinator enter");
const controlActions = new Set([
  "register",
  "begin",
  "enter",
  "continue",
  "complete",
  "unknown",
  "lost",
  "validate",
  "status",
  "close-ack",
  "warm-ack",
]);
// Only these reviewed coordinator precondition refusals have no side effect.
// Arbitrary status/error codes are not evidence that a mutation did not commit.
const definitiveRefusals: Readonly<Record<string, readonly string[]>> = {
  begin: [
    "ROOT_ADMISSION_CLOSED",
    "REVIEWED_GENERATION_NOT_READY",
    "MAX_INFLIGHT_REACHED",
  ],
  enter: [
    "INVALID_OPERATION_CAPABILITY",
    "OPERATION_NOT_ACTIVE",
    "HANDLER_CAPABILITY_ALREADY_ENTERED_OR_WRONG_INSTANCE",
  ],
  continue: [
    "CONTINUATION_NOT_AUTHORIZED",
    "CONTINUATION_TARGET_NOT_REVIEWED",
    "MAX_INFLIGHT_REACHED",
    "CONTINUATION_DEPTH_REACHED",
  ],
};
const enteredSchema = z
  .object({
    operationId: z.string().uuid(),
    rootOperationId: z.string().uuid(),
    epoch: z.number().int().positive().safe(),
  })
  .strict();
type Entered = z.infer<typeof enteredSchema>;
const unavailable = (code: string) =>
  new ServiceUnavailableException({
    code,
    message: "Identity admission is unavailable",
  });
const safe = (error: unknown) =>
  error &&
  typeof error === "object" &&
  "safeCode" in error &&
  /^[A-Z][A-Z0-9_]{0,100}$/.test(String(error.safeCode))
    ? String(error.safeCode)
    : "ADMISSION_CONTROL_UNKNOWN";
export function admissionEnabled() {
  const raw = process.env.IDENTITY_ADMISSION_ENABLED;
  if (raw === undefined || raw === "" || raw === "false" || raw === "0")
    return false;
  if (raw === "true" || raw === "1") return true;
  throw unavailable("INVALID_ADMISSION_FEATURE_FLAG");
}
function privateFile(filename: string | undefined, bound: number) {
  if (!filename)
    throw unavailable("ADMISSION_PROTECTED_CONFIGURATION_REQUIRED");
  const fd = openSync(
    filename,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  try {
    const stat = fstatSync(fd);
    if (
      !stat.isFile() ||
      stat.nlink !== 1 ||
      (stat.mode & 0o077) !== 0 ||
      stat.uid !== process.getuid?.() ||
      stat.size > bound
    )
      throw unavailable("ADMISSION_PROTECTED_CONFIGURATION_REQUIRED");
    const bytes = readFileSync(fd);
    if (
      bytes.length !== stat.size ||
      !Buffer.from(bytes.toString("utf8")).equals(bytes)
    )
      throw unavailable("ADMISSION_PROTECTED_CONFIGURATION_REQUIRED");
    return bytes.toString("utf8");
  } finally {
    closeSync(fd);
  }
}
function loopback(value: string, root = false) {
  let u: URL;
  try {
    u = new URL(value);
  } catch {
    throw unavailable("LOOPBACK_ADMISSION_FIXTURE_REQUIRED");
  }
  if (
    u.protocol !== "http:" ||
    u.hostname !== "127.0.0.1" ||
    u.username ||
    u.password ||
    u.search ||
    u.hash ||
    (root ? u.pathname !== "/" : u.origin !== value)
  )
    throw unavailable("LOOPBACK_ADMISSION_FIXTURE_REQUIRED");
  return u;
}

/** Only the reviewed entry/typed writer adapters create scopes. Header values never create one. */
export class AdmissionScope {
  readonly startedAt: number;
  private readonly pending = new Set<Promise<unknown>>();
  private state: "open" | "sealing" | "closed" = "open";
  private uncertain = false;
  private childrenIssued = false;
  private unknownRecorded: Promise<void> | null = null;
  private finishing: Promise<void> | null = null;
  constructor(
    readonly runtime: IdentityAdmission,
    readonly capability: string | null,
    readonly writable: boolean,
    authorization?: symbol,
    private readonly entered: Entered | null = null,
    startedAt = performance.now(),
  ) {
    this.startedAt = startedAt;
    if (writable && (authorization !== verifiedScope || !entered))
      throw unavailable("ADMISSION_VERIFIED_ENTER_REQUIRED");
  }
  run<T>(work: () => T): T {
    if (this.uncertain || this.state !== "open")
      throw unavailable("ADMISSION_OPERATION_UNKNOWN");
    return storage.run({ scope: this, task: null }, work);
  }
  noteChild() {
    this.assertWritable();
    this.childrenIssued = true;
  }
  assertHandler(probe: boolean) {
    if (this.state !== "open" || this.uncertain || (!this.writable && !probe))
      throw unavailable("ADMISSION_HANDLER_SCOPE_REQUIRED");
  }
  assertWritable() {
    const context = storage.getStore();
    if (
      !this.writable ||
      this.uncertain ||
      this.state === "closed" ||
      (this.state === "sealing" && !context?.task?.active)
    )
      throw unavailable("ADMISSION_WRITER_SCOPE_REQUIRED");
  }
  track<T>(work: () => Promise<T>): Promise<T> {
    this.assertWritable();
    const task: Task = { active: true };
    const promise = storage.run({ scope: this, task }, async () => {
      try {
        return await work();
      } catch (error) {
        const e = error as { fatal?: boolean; code?: string };
        if (
          e?.fatal ||
          [
            "ECONNRESET",
            "EPIPE",
            "ETIMEDOUT",
            "PROTOCOL_CONNECTION_LOST",
            "PROTOCOL_ENQUEUE_AFTER_FATAL_ERROR",
          ].includes(e?.code ?? "")
        )
          await this.unknown();
        throw error;
      } finally {
        task.active = false;
      }
    });
    this.pending.add(promise);
    const settled = () => {
      this.pending.delete(promise);
      if (!this.pending.size && this.uncertain && this.finishing)
        this.state = "closed";
    };
    void promise.then(settled, settled);
    return promise;
  }
  unknown() {
    this.uncertain = true;
    return (this.unknownRecorded ??= this.recordUnknown());
  }
  private async recordUnknown() {
    if (this.capability)
      try {
        await this.runtime.call("unknown", { capability: this.capability });
      } catch {
        // Removed/completed operations cannot retain unknown on their own.
        await this.runtime.lose();
      }
  }
  finish() {
    return (this.finishing ??= this.finishOnce());
  }
  private async finishOnce() {
    this.state = "sealing";
    try {
      while (this.pending.size) {
        if (
          performance.now() - this.startedAt >=
          this.runtime.configuration.childWaitMs
        )
          throw unavailable("ADMISSION_TASK_COMPLETION_UNKNOWN");
        await Promise.race([
          Promise.allSettled([...this.pending]),
          new Promise((resolve) => setTimeout(resolve, 25)),
        ]);
      }
      if (!this.capability) {
        if (this.uncertain) throw unavailable("ADMISSION_OPERATION_UNKNOWN");
        return;
      }
      for (;;) {
        if (this.uncertain) throw unavailable("ADMISSION_OPERATION_UNKNOWN");
        const remaining =
          this.runtime.configuration.childWaitMs -
          (performance.now() - this.startedAt);
        if (this.childrenIssued && remaining < 1)
          throw unavailable("ADMISSION_CHILD_COMPLETION_UNKNOWN");
        const result = await this.runtime.call(
          "validate",
          {
            capability: this.capability,
          },
          this.childrenIssued
            ? Math.max(1, Math.min(2000, Math.floor(remaining)))
            : 2000,
        );
        if (
          result.unknown !== false ||
          !this.entered ||
          ["operationId", "rootOperationId", "epoch"].some(
            (k) => result[k] !== this.entered![k as keyof Entered],
          ) ||
          !Number.isSafeInteger(result.childrenActive) ||
          Number(result.childrenActive) < 0
        )
          throw unavailable("ADMISSION_OPERATION_UNKNOWN");
        if (
          this.childrenIssued &&
          performance.now() - this.startedAt >=
            this.runtime.configuration.childWaitMs
        )
          throw unavailable("ADMISSION_CHILD_COMPLETION_UNKNOWN");
        if (result.childrenActive === 0) break;
        if (!this.childrenIssued)
          throw unavailable("ADMISSION_UNTRACKED_CHILD_UNKNOWN");
        if (
          performance.now() - this.startedAt >=
          this.runtime.configuration.childWaitMs
        )
          throw unavailable("ADMISSION_CHILD_COMPLETION_UNKNOWN");
        await new Promise((resolve) => setTimeout(resolve, 25));
      }
      if (this.uncertain) throw unavailable("ADMISSION_OPERATION_UNKNOWN");
      // One private mutation only. A lost completion ACK is never automatically retried.
      await this.runtime.call("complete", {
        capability: this.capability,
        evidence: {
          handlerFinished: true,
          sideEffectsFinished: true,
          sessionWriteClosed: true,
        },
      });
    } catch (error) {
      await this.unknown();
      throw error;
    } finally {
      // Timing out is uncertainty, not cancellation of a known transaction.
      // Its registered descendants may finish/rollback, but no new root task
      // may enter and no late ordinary completion clears the unknown latch.
      this.state = this.pending.size ? "sealing" : "closed";
    }
  }
}

export class IdentityAdmission {
  readonly configuration: Configuration;
  private readonly key: Buffer;
  private readonly control: URL;
  private ready = false;
  private failed = false;
  private losing: Promise<void> | null = null;
  constructor(configuration: unknown, key: Buffer) {
    this.configuration = configurationSchema.parse(configuration);
    this.control = loopback(this.configuration.controlUrl, true);
    if (
      !Buffer.isBuffer(key) ||
      key.length < 32 ||
      key.length > 128 ||
      !compiledRevision ||
      this.configuration.identity.revision !== compiledRevision
    )
      throw unavailable("ADMISSION_IMMUTABLE_REVISION_REQUIRED");
    if (
      new Set(this.configuration.allowedChildren.map((c) => c.id)).size !==
      this.configuration.allowedChildren.length
    )
      throw unavailable("ADMISSION_REVIEWED_CHILDREN_REQUIRED");
    for (const child of this.configuration.allowedChildren)
      loopback(child.origin);
    const routes = this.configuration.allowedChildren.flatMap((c) =>
      c.paths.map((p) => `${c.origin}${p}`),
    );
    if (new Set(routes).size !== routes.length)
      throw unavailable("ADMISSION_REVIEWED_CHILDREN_REQUIRED");
    Object.freeze(this.configuration.identity);
    for (const child of this.configuration.allowedChildren) {
      Object.freeze(child.paths);
      Object.freeze(child);
    }
    Object.freeze(this.configuration.allowedChildren);
    Object.freeze(this.configuration);
    this.key = Buffer.from(key);
  }
  static environment() {
    if (!admissionEnabled()) return null;
    const config = JSON.parse(
        privateFile(process.env.IDENTITY_ADMISSION_CONFIG_FILE, 32768),
      ),
      encoded = privateFile(process.env.IDENTITY_ADMISSION_KEY_FILE, 256);
    const key = Buffer.from(encoded, "base64url");
    if (key.toString("base64url") !== encoded)
      throw unavailable("ADMISSION_CANONICAL_KEY_REQUIRED");
    return new IdentityAdmission(config, key);
  }
  async call(
    action: string,
    payload: Record<string, unknown> = {},
    timeoutMs = 2000,
  ): Promise<ControlResult> {
    if (!controlActions.has(action))
      throw unavailable("ADMISSION_CONTROL_OPERATION_NOT_ALLOWED");
    if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 2000)
      throw unavailable("ADMISSION_CONTROL_BUDGET_INVALID");
    const i = this.configuration.identity;
    let definitive = false;
    try {
      const response = await fetch(new URL(action, this.control), {
        method: "POST",
        headers: {
          authorization: `Bearer ${this.key.toString("base64url")}`,
          "x-identity-instance-id": i.id,
          "x-identity-instance-boot-id": i.bootId,
          "x-identity-instance-revision": i.revision,
          "x-identity-router-hash": i.routerHash,
          "x-identity-generation": i.generation,
          "content-type": "application/json",
        },
        body: JSON.stringify(payload),
        redirect: "error",
        signal: AbortSignal.timeout(timeoutMs),
      });
      const chunks: Uint8Array[] = [];
      let size = 0;
      const reader = response.body?.getReader();
      if (!reader) throw unavailable("ADMISSION_CONTROL_RESPONSE_INVALID");
      for (;;) {
        const part = await reader.read();
        if (part.done) break;
        size += part.value.length;
        if (size > 65536) {
          await reader.cancel();
          throw unavailable("ADMISSION_CONTROL_RESPONSE_BOUND");
        }
        chunks.push(part.value);
      }
      const bytes = Buffer.concat(chunks);
      if (!Buffer.from(bytes.toString("utf8")).equals(bytes))
        throw unavailable("ADMISSION_CONTROL_RESPONSE_INVALID");
      const result = JSON.parse(bytes.toString("utf8"));
      if (!result || typeof result !== "object" || Array.isArray(result))
        throw unavailable("ADMISSION_CONTROL_RESPONSE_INVALID");
      if (!response.ok) {
        const code = result.code;
        definitive =
          response.status === 409 &&
          Object.keys(result).length === 1 &&
          (definitiveRefusals[action]?.includes(code) ?? false);
        throw Object.assign(new Error("Private admission operation rejected"), {
          safeCode:
            typeof code === "string" && /^[A-Z][A-Z0-9_]{0,100}$/.test(code)
              ? code
              : "ADMISSION_CONTROL_REJECTED",
        });
      }
      if (["unknown", "lost"].includes(action)) {
        if (Object.keys(result).length !== 1 || result.accepted !== true)
          throw unavailable("ADMISSION_CONTROL_RESPONSE_INVALID");
      } else if (["register", "complete", "status"].includes(action)) {
        if (
          ![
            "legacy_open",
            "closing",
            "drained",
            "prepared",
            "committing",
            "identity_open",
          ].includes(result.phase) ||
          typeof result.unknownSealed !== "boolean" ||
          !Number.isSafeInteger(result.active) ||
          result.active < 0 ||
          !Number.isSafeInteger(result.unknown) ||
          result.unknown < 0 ||
          !Array.isArray(result.instances)
        )
          throw unavailable("ADMISSION_CONTROL_RESPONSE_INVALID");
      }
      return result;
    } catch (error) {
      if (!definitive) {
        this.failed = true;
        this.ready = false;
        if (action !== "lost") await this.lose();
      }
      throw Object.assign(unavailable(safe(error)), { safeCode: safe(error) });
    }
  }
  /** Irreversible latch; one private lost attempt, never a mutation retry. */
  lose(): Promise<void> {
    this.failed = true;
    this.ready = false;
    return (this.losing ??= this.call("lost").then(
      () => undefined,
      () => undefined,
    ));
  }
  async register() {
    if (this.failed) throw unavailable("ADMISSION_INSTANCE_UNKNOWN");
    await this.call("register", { identity: this.configuration.identity });
    this.ready = true;
  }
  async enter(
    capability?: string,
    startedAt = performance.now(),
  ): Promise<AdmissionScope> {
    if (
      !Number.isFinite(startedAt) ||
      startedAt < 0 ||
      startedAt > performance.now()
    )
      throw unavailable("ADMISSION_MONOTONIC_START_REQUIRED");
    if (!this.ready) throw unavailable("ADMISSION_INSTANCE_NOT_REGISTERED");
    let cap = capability;
    if (cap === undefined) {
      const lease = await this.call("begin");
      cap = lease.capability;
    }
    if (
      typeof cap !== "string" ||
      cap.length > 2048 ||
      !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(cap)
    ) {
      if (capability === undefined) {
        await this.lose();
      }
      throw unavailable("INVALID_ADMISSION_CAPABILITY");
    }
    // A definitive wrong/reused capability rejection must not mutate somebody
    // else's operation. Transport uncertainty is latched by call() as instance loss.
    const response = await this.call("enter", { capability: cap });
    let entered: Entered;
    try {
      entered = enteredSchema.parse(response);
    } catch {
      await this.lose();
      throw unavailable("ADMISSION_CONTROL_RESPONSE_INVALID");
    }
    return new AdmissionScope(
      this,
      cap,
      true,
      verifiedScope,
      Object.freeze(entered),
      startedAt,
    );
  }
  probe() {
    return new AdmissionScope(this, null, false);
  }
  async bootstrap<T>(
    work: () => Promise<T>,
    explicitWarm: boolean,
  ): Promise<T> {
    await this.register();
    if (explicitWarm) {
      const scope = this.probe();
      try {
        return await scope.run(work);
      } catch (error) {
        await this.lose();
        throw error;
      } finally {
        await scope.finish();
      }
    }
    if (this.configuration.identity.generation !== "legacy")
      throw unavailable("ADMISSION_EXPLICIT_WARM_REQUIRED");
    const scope = await this.enter();
    try {
      return await scope.run(work);
    } catch (error) {
      await scope.unknown();
      throw error;
    } finally {
      await scope.finish();
    }
  }
  child(input: string | URL, init: RequestInit = {}): Promise<Response> {
    const scope = storage.getStore()?.scope;
    if (!scope || scope.runtime !== this || !scope.capability)
      throw unavailable("ADMISSION_WRITER_SCOPE_REQUIRED");
    scope.assertWritable();
    return scope.track(() => this.childWithinScope(scope, input, init));
  }
  private async childWithinScope(
    scope: AdmissionScope,
    input: string | URL,
    init: RequestInit,
  ): Promise<Response> {
    const target = new URL(input),
      child = this.configuration.allowedChildren.find(
        (c) => c.origin === target.origin && c.paths.includes(target.pathname),
      );
    if (!child || target.username || target.password || target.hash)
      throw unavailable("ADMISSION_CHILD_TARGET_NOT_REVIEWED");
    const remaining = () =>
      Math.floor(
        this.configuration.childWaitMs - (performance.now() - scope.startedAt),
      );
    if (remaining() < 1) {
      await scope.unknown();
      throw unavailable("ADMISSION_CHILD_COMPLETION_UNKNOWN");
    }
    const result = await this.call(
      "continue",
      {
        capability: scope.capability,
        targetId: child.id,
      },
      Math.min(2000, remaining()),
    );
    const cap = result.capability;
    if (
      typeof cap !== "string" ||
      cap.length > 2048 ||
      !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(cap)
    ) {
      await scope.unknown();
      throw unavailable("ADMISSION_CHILD_CAPABILITY_INVALID");
    }
    scope.noteChild();
    if (remaining() < 1) {
      await scope.unknown();
      try {
        await this.call("unknown", { capability: cap });
      } catch {
        await this.lose();
      }
      throw unavailable("ADMISSION_CHILD_COMPLETION_UNKNOWN");
    }
    const headers = new Headers(init.headers);
    for (const name of [...headers.keys()])
      if (admissionHeader(name)) headers.delete(name);
    headers.set("x-identity-admission-lease", cap);
    try {
      const signal = AbortSignal.timeout(Math.max(1, remaining()));
      return await fetch(target, {
        ...init,
        headers,
        redirect: "error",
        signal: init.signal ? AbortSignal.any([init.signal, signal]) : signal,
      });
    } catch (error) {
      await scope.unknown();
      try {
        await this.call("unknown", { capability: cap });
      } catch {
        await this.lose();
      }
      throw error;
    }
  }
}
export function assertAdmissionWriter() {
  if (!admissionEnabled()) return;
  const scope = storage.getStore()?.scope;
  if (!scope) throw unavailable("ADMISSION_WRITER_SCOPE_REQUIRED");
  scope.assertWritable();
}
export function assertAdmissionRequest(probe: boolean) {
  if (!admissionEnabled()) return;
  const scope = storage.getStore()?.scope;
  if (!scope) throw unavailable("ADMISSION_HANDLER_SCOPE_REQUIRED");
  scope.assertHandler(probe);
}
export async function markAdmissionUnknown() {
  if (admissionEnabled()) {
    const scope = storage.getStore()?.scope;
    if (!scope) throw unavailable("ADMISSION_WRITER_SCOPE_REQUIRED");
    await scope.unknown();
  }
}
/** Typed audited write boundary; nested and deliberately unawaited work remain registered. */
export function AdmissionWriter(): MethodDecorator {
  return (_target, _name, descriptor: PropertyDescriptor) => {
    const original = descriptor.value;
    descriptor.value = function (...args: unknown[]) {
      if (!admissionEnabled()) return original.apply(this, args);
      assertAdmissionWriter();
      return storage.getStore()!.scope.track(() => original.apply(this, args));
    };
  };
}
export function admissionFetch(
  input: string | URL,
  init: RequestInit = {},
): Promise<Response> {
  if (!admissionEnabled()) return fetch(input, init);
  const scope = storage.getStore()?.scope;
  if (!scope) throw unavailable("ADMISSION_WRITER_SCOPE_REQUIRED");
  return scope.runtime.child(input, init);
}
export const admissionHeader = (name: string) =>
  /^x-(?:identity-)?admission(?:-|$)/i.test(name) ||
  /^x-.*continu(?:ation|ed)/i.test(name) ||
  /^x-identity-(?:instance(?:-|$)|router(?:-|$)|generation$)/i.test(name);
