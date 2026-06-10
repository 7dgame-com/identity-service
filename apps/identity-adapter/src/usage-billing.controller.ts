import { Body, Controller, Get, Headers, HttpException, HttpStatus, Param, Post, Query } from "@nestjs/common";
import { loadConfig } from "./config.js";
import { UsageBillingService } from "./usage-billing.service.js";

@Controller("internal/usage-billing")
export class UsageBillingController {
  private readonly config = loadConfig();

  constructor(private readonly usageBilling: UsageBillingService) {}

  @Get("readiness")
  readiness(@Headers("x-identity-internal-token") token: string | undefined) {
    this.assertAuthorized(token);
    return {
      data: this.usageBilling.readiness()
    };
  }

  @Post("replay")
  async replay(@Headers("x-identity-internal-token") token: string | undefined, @Body() body: unknown) {
    this.assertAuthorized(token);
    return {
      data: await this.usageBilling.replay(body)
    };
  }

  @Get("runs/:runKey")
  async run(@Headers("x-identity-internal-token") token: string | undefined, @Param("runKey") runKey: string) {
    this.assertAuthorized(token);
    return {
      data: await this.usageBilling.getRun(runKey)
    };
  }

  @Get("subjects/:type/:id/balance")
  async balance(
    @Headers("x-identity-internal-token") token: string | undefined,
    @Param("type") type: string,
    @Param("id") id: string
  ) {
    this.assertAuthorized(token);
    return {
      data: await this.usageBilling.getBalance(type, id)
    };
  }

  @Get("ledger")
  async ledger(@Headers("x-identity-internal-token") token: string | undefined, @Query("limit") limit?: string) {
    this.assertAuthorized(token);
    const parsedLimit = limit ? Number(limit) : undefined;
    return {
      data: await this.usageBilling.listLedger(Number.isFinite(parsedLimit) ? parsedLimit : undefined)
    };
  }

  @Get("reports/login-usage")
  async loginUsageReport(
    @Headers("x-identity-internal-token") token: string | undefined,
    @Query("from") from?: string,
    @Query("to") to?: string
  ) {
    this.assertAuthorized(token);
    return {
      data: await this.usageBilling.loginUsageReport({ from, to })
    };
  }

  private assertAuthorized(token: string | undefined): void {
    if (!this.config.usageBilling.internalToken) {
      throw new HttpException(
        {
          code: "USAGE_BILLING_TOKEN_NOT_CONFIGURED",
          message: "Internal API token is required before using usage billing."
        },
        HttpStatus.SERVICE_UNAVAILABLE
      );
    }
    if (token !== this.config.usageBilling.internalToken) {
      throw new HttpException(
        {
          code: "INTERNAL_TOKEN_INVALID",
          message: "Internal service token is invalid."
        },
        HttpStatus.UNAUTHORIZED
      );
    }
  }
}
