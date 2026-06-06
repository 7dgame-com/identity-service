import { Module } from "@nestjs/common";
import { HealthController } from "./health.controller.js";
import { IdentityController } from "./identity.controller.js";
import { LegacyIdentityReader } from "./legacy-identity.reader.js";

@Module({
  controllers: [HealthController, IdentityController],
  providers: [LegacyIdentityReader]
})
export class AppModule {}

