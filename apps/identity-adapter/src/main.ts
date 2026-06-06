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

  app.enableCors({
    origin: true,
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
