import "reflect-metadata";
import { NestFactory } from "@nestjs/core";
import { AppModule } from "./app.module.js";
import { loadConfig } from "./config.js";
import { shutdownTelemetry, startTelemetry } from "./telemetry.js";

async function bootstrap() {
  const config = loadConfig();
  startTelemetry(config);

  const app = await NestFactory.create(AppModule, {
    logger: ["error", "warn", "log"]
  });

  const corsOrigins = new Set(
    config.corsOrigins.split(",").map((origin) => origin.trim()).filter(Boolean)
  );

  app.enableCors({
    origin: (origin: string | undefined, callback: (error: Error | null, allow?: boolean) => void) => {
      // Non-browser/internal calls do not carry Origin. Browser requests must
      // originate from an explicit allowlist rather than being reflected.
      if (!origin || corsOrigins.has(origin)) {
        callback(null, true);
        return;
      }
      callback(null, false);
    },
    credentials: true
  });

  await app.listen(config.port, "0.0.0.0");

  const shutdown = async () => {
    await app.close();
    await shutdownTelemetry();
  };
  process.once("SIGINT", () => void shutdown());
  process.once("SIGTERM", () => void shutdown());
}

void bootstrap();
