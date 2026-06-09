import { Injectable } from "@nestjs/common";
import { loadConfig } from "./config.js";
import { RedisClient } from "./invitation-redis.reader.js";

export interface InvitationLegacyRedisInput {
  code: string;
  quota: number;
  remaining: number;
  expiresAt: number;
  creatorId: number;
  creatorName: string;
  note: string;
  createdAt: number;
}

@Injectable()
export class InvitationLegacyRedisRepository {
  private readonly config = loadConfig();

  isConfigured(): boolean {
    return Boolean(this.config.invitationDiagnostics.redisUrl);
  }

  async create(input: InvitationLegacyRedisInput): Promise<void> {
    const client = await this.client();
    try {
      const key = keyForCode(input.code);
      await client.hmset(key, {
        quota: String(input.quota),
        remaining: String(input.remaining),
        expiresAt: String(input.expiresAt),
        creatorId: String(input.creatorId),
        creatorName: input.creatorName,
        note: input.note,
        createdAt: String(input.createdAt)
      });
      await client.expire(key, Math.max(1, input.expiresAt - Math.floor(Date.now() / 1000)));
    } finally {
      client.close();
    }
  }

  async exists(code: string): Promise<boolean> {
    const client = await this.client();
    try {
      return client.exists(keyForCode(code));
    } finally {
      client.close();
    }
  }

  async delete(code: string): Promise<boolean> {
    const client = await this.client();
    try {
      return (await client.del(keyForCode(code))) > 0;
    } finally {
      client.close();
    }
  }

  private async client(): Promise<RedisClient> {
    if (!this.config.invitationDiagnostics.redisUrl) {
      throw new Error("legacy invitation Redis is not configured");
    }

    const client = new RedisClient(this.config.invitationDiagnostics.redisUrl);
    await client.connect();
    return client;
  }
}

function keyForCode(code: string): string {
  return `invite:${code}`;
}
