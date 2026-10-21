import "reflect-metadata";
import { NestFactory } from "@nestjs/core";
import { AppModule } from "./app.module.js";
import { loadConfig } from "./config.js";
import { shutdownTelemetry, startTelemetry } from "./telemetry.js";
import { IdentityAdmission } from "./identity-admission.js";
import { IdentityAdmissionExpressAdapter } from "./identity-admission-express.js";

async function bootstrap() {
  const config = loadConfig();
  startTelemetry(config);

  const admission = IdentityAdmission.environment();
  if (
    admission &&
    config.dataSource === "identity" &&
    config.activationMode !== "explicit"
  )
    throw new Error("Admission requires explicit native warm/activation");
  const create = async () => {
    const instance = await NestFactory.create(
      AppModule,
      new IdentityAdmissionExpressAdapter(admission),
      {
        logger: ["error", "warn", "log"],
        ...(admission ? { abortOnError: false } : {}),
      },
    );
    // Do not trust X-Forwarded-For by default. Deployments behind a known proxy
    // must explicitly set IDENTITY_TRUST_PROXY_HOPS (normally 1).
    const httpServer = instance.getHttpAdapter().getInstance() as {
      set(name: string, value: unknown): void;
    };
    httpServer.set("trust proxy", config.network.trustProxyHops);

    const corsOrigins = new Set(
      config.corsOrigins
        .split(",")
        .map((origin) => origin.trim())
        .filter(Boolean),
    );

    instance.enableCors({
      origin: (
        origin: string | undefined,
        callback: (error: Error | null, allow?: boolean) => void,
      ) => {
        // Non-browser/internal calls do not carry Origin. Browser requests must
        // originate from an explicit allowlist rather than being reflected.
        if (!origin || corsOrigins.has(origin)) {
          callback(null, true);
          return;
        }
        callback(null, false);
      },
      credentials: true,
    });

    await instance.init();
    return instance;
  };
  const app = admission
    ? await admission.bootstrap(
        create,
        config.dataSource === "identity" &&
          config.activationMode === "explicit",
      )
    : await create();

  await app.listen(config.port, "0.0.0.0");

  const shutdown = async () => {
    await app.close();
    await shutdownTelemetry();
  };
  process.once("SIGINT", () => void shutdown());
  process.once("SIGTERM", () => void shutdown());
}

void bootstrap();
