import { CallHandler, ExecutionContext, Injectable, NestInterceptor } from "@nestjs/common";
import { context as otelContext, SpanKind, SpanStatusCode, trace } from "@opentelemetry/api";
import { Observable, catchError, finalize, throwError } from "rxjs";
import { loadConfig } from "./config.js";

type HttpRequest = {
  method?: string;
  originalUrl?: string;
  route?: { path?: string };
};

type HttpResponse = {
  statusCode?: number;
};

@Injectable()
export class TelemetryInterceptor implements NestInterceptor {
  private readonly config = loadConfig();
  private readonly tracer = trace.getTracer(this.config.otel.serviceName);

  intercept(executionContext: ExecutionContext, next: CallHandler): Observable<unknown> {
    if (executionContext.getType() !== "http") {
      return next.handle();
    }

    const request = executionContext.switchToHttp().getRequest<HttpRequest>();
    const response = executionContext.switchToHttp().getResponse<HttpResponse>();
    const method = request.method ?? "UNKNOWN";
    const route = request.route?.path ?? request.originalUrl ?? "unknown";
    const span = this.tracer.startSpan(`HTTP ${method} ${route}`, {
      kind: SpanKind.SERVER,
      attributes: {
        "http.request.method": method,
        "http.route": route,
        "url.path": request.originalUrl ?? route,
        "service.mode": this.config.readonlyMode ? "readonly" : "unsafe"
      }
    });

    return otelContext.with(trace.setSpan(otelContext.active(), span), () =>
      next.handle().pipe(
        catchError((error: unknown) => {
          span.setStatus({
            code: SpanStatusCode.ERROR,
            message: error instanceof Error ? error.message : "Request failed"
          });
          if (error instanceof Error) {
            span.recordException(error);
          }
          return throwError(() => error);
        }),
        finalize(() => {
          const statusCode = response.statusCode ?? 0;
          span.setAttribute("http.response.status_code", statusCode);
          if (statusCode >= 500) {
            span.setStatus({ code: SpanStatusCode.ERROR });
          } else if (statusCode > 0) {
            span.setStatus({ code: SpanStatusCode.OK });
          }
          span.end();
        })
      )
    );
  }
}
