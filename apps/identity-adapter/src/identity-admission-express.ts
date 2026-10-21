import { ExpressAdapter } from "@nestjs/platform-express";
import type {
  AdmissionScope,
  IdentityAdmission,
} from "./identity-admission.js";
import { admissionHeader } from "./identity-admission.js";
import { performance } from "node:perf_hooks";

/** Nest RouterProxy awaits the real handler; this adapter wraps that promise, never response finish. */
export class IdentityAdmissionExpressAdapter extends ExpressAdapter {
  private readonly scopes = new WeakMap<object, AdmissionScope>();
  constructor(readonly admission: IdentityAdmission | null) {
    super();
    this.use(async (req: any, res: any, next: () => void) => {
      const arrivedAt = performance.now();
      const values: string[] = [];
      for (let i = 0; i < req.rawHeaders.length; i += 2)
        if (req.rawHeaders[i].toLowerCase() === "x-identity-admission-lease")
          values.push(req.rawHeaders[i + 1]);
      req.rawHeaders = req.rawHeaders.filter(
        (_value: string, index: number, all: string[]) =>
          !admissionHeader(all[index - (index % 2)]),
      );
      for (const name of Object.keys(req.headers))
        if (admissionHeader(name)) delete req.headers[name];
      if (!admission) return next();
      try {
        if (
          values.length > 1 ||
          values.some(
            (v) =>
              Buffer.byteLength(v) !== v.length ||
              v.length > 2048 ||
              !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(v),
          )
        )
          throw new Error("INVALID_ADMISSION_CAPABILITY");
        // These are the only reviewed read-only probes. Arbitrary GET is admitted normally.
        const probe =
          values.length === 0 &&
          req.method === "GET" &&
          ["/health", "/health/live"].includes(req.url);
        const scope = probe
          ? admission.probe()
          : await admission.enter(values[0], arrivedAt);
        this.scopes.set(req, scope);
        req.once("aborted", () => {
          void scope.unknown();
        });
        res.once("close", () => {
          if (!res.writableFinished) void scope.unknown();
        });
        // The client may disappear during the private begin/enter RPC, before
        // these event listeners existed. Never start its business handler.
        if (req.aborted || res.destroyed) {
          await scope.unknown();
          return;
        }
        scope.run(next);
      } catch {
        if (!res.headersSent)
          res.status(503).json({
            code: "IDENTITY_ADMISSION_REJECTED",
            message: "Identity admission is unavailable",
          });
      }
    });
  }
  private callback(handler: Function, error = false): Function {
    const invoke = async (req: any, res: any, args: unknown[]) => {
      const scope = this.scopes.get(req);
      if (!scope) return handler(...args);
      try {
        return await scope.run(() => handler(...args));
      } finally {
        try {
          await scope.finish();
        } catch {
          if (!res.headersSent)
            res.status(503).json({
              code: "IDENTITY_ADMISSION_UNKNOWN",
              message: "Identity admission is unavailable",
            });
        }
      }
    };
    return error
      ? function (err: unknown, req: unknown, res: unknown, next: unknown) {
          return invoke(req, res, [err, req, res, next]);
        }
      : function (req: unknown, res: unknown, next: unknown) {
          return invoke(req, res, [req, res, next]);
        };
  }
  private route(args: any[]): [any, any] {
    return [args[0], this.callback(args[1])];
  }
  override get(...args: any[]) {
    return super.get(...this.route(args));
  }
  override post(...args: any[]) {
    return super.post(...this.route(args));
  }
  override put(...args: any[]) {
    return super.put(...this.route(args));
  }
  override patch(...args: any[]) {
    return super.patch(...this.route(args));
  }
  override delete(...args: any[]) {
    return super.delete(...this.route(args));
  }
  override head(...args: any[]) {
    return super.head(...this.route(args));
  }
  override options(...args: any[]) {
    return super.options(...this.route(args));
  }
  override all(...args: any[]) {
    return super.all(...this.route(args));
  }
  override setErrorHandler(handler: Function, prefix?: string) {
    return super.setErrorHandler(this.callback(handler, true), prefix);
  }
  override setNotFoundHandler(handler: Function, prefix?: string) {
    return super.setNotFoundHandler(
      this.callback((req: any, res: any, next: unknown) =>
        this.admission && req.method === "OPTIONS"
          ? res.status(204).end()
          : handler(req, res, next),
      ),
      prefix,
    );
  }
  override enableCors(options: any) {
    return super.enableCors(
      this.admission ? { ...options, preflightContinue: true } : options,
    );
  }
}
