import { Socket } from "node:net";
import { Injectable } from "@nestjs/common";
import { loadConfig } from "./config.js";

export interface LegacyRedisInvitation {
  code: string;
  key: string;
  quota: number | null;
  remaining: number | null;
  expiresAt: number | null;
  creatorId: number | null;
  creatorName: string | null;
  note: string | null;
  createdAt: number | null;
  ttl: number | null;
  raw: Record<string, string>;
}

export interface LegacyRedisInvitationScan {
  configured: boolean;
  scannedKeys: number;
  truncated: boolean;
  invitations: LegacyRedisInvitation[];
}

@Injectable()
export class InvitationRedisReader {
  private readonly config = loadConfig();

  isConfigured(): boolean {
    return Boolean(this.config.invitationDiagnostics.redisUrl);
  }

  async scanInvitations(code?: string | null): Promise<LegacyRedisInvitationScan> {
    if (!this.config.invitationDiagnostics.redisUrl) {
      return {
        configured: false,
        scannedKeys: 0,
        truncated: false,
        invitations: []
      };
    }

    const client = new RedisClient(this.config.invitationDiagnostics.redisUrl);
    try {
      await client.connect();
      if (code) {
        const key = `invite:${code}`;
        const raw = await client.hgetall(key);
        if (Object.keys(raw).length === 0) {
          return {
            configured: true,
            scannedKeys: 1,
            truncated: false,
            invitations: []
          };
        }

        return {
          configured: true,
          scannedKeys: 1,
          truncated: false,
          invitations: [normalizeInvitation(key, raw, await client.ttl(key))]
        };
      }

      return await this.scanAll(client);
    } finally {
      client.close();
    }
  }

  private async scanAll(client: RedisClient): Promise<LegacyRedisInvitationScan> {
    let cursor = "0";
    const invitations: LegacyRedisInvitation[] = [];
    let scannedKeys = 0;
    let truncated = false;
    const scanCount = this.config.invitationDiagnostics.scanCount;
    const maxKeys = this.config.invitationDiagnostics.maxKeys;

    do {
      const result = await client.scan(cursor, "invite:*", scanCount);
      cursor = result.cursor;
      for (const key of result.keys) {
        if (scannedKeys >= maxKeys) {
          truncated = true;
          cursor = "0";
          break;
        }

        scannedKeys += 1;
        const raw = await client.hgetall(key);
        if (Object.keys(raw).length > 0) {
          invitations.push(normalizeInvitation(key, raw, await client.ttl(key)));
        }
      }
    } while (cursor !== "0");

    return {
      configured: true,
      scannedKeys,
      truncated,
      invitations
    };
  }
}

export class RedisClient {
  private socket: Socket | null = null;
  private buffer = Buffer.alloc(0);

  constructor(private readonly redisUrl: string) {}

  async connect(): Promise<void> {
    const url = new URL(this.redisUrl);
    const socket = new Socket();
    this.socket = socket;
    socket.on("data", (chunk) => {
      this.buffer = Buffer.concat([this.buffer, chunk]);
    });

    await new Promise<void>((resolve, reject) => {
      socket.once("error", reject);
      socket.connect(Number(url.port || 6379), url.hostname, () => {
        socket.off("error", reject);
        resolve();
      });
    });

    if (url.password) {
      await this.command("AUTH", decodeURIComponent(url.password));
    }
    const db = Number(url.pathname.replace("/", "") || 0);
    if (Number.isInteger(db) && db > 0) {
      await this.command("SELECT", String(db));
    }
  }

  close(): void {
    this.socket?.end();
    this.socket = null;
  }

  async scan(cursor: string, match: string, count: number): Promise<{ cursor: string; keys: string[] }> {
    const result = await this.command("SCAN", cursor, "MATCH", match, "COUNT", String(count));
    if (!Array.isArray(result) || result.length !== 2 || !Array.isArray(result[1])) {
      throw new Error("invalid redis SCAN response");
    }

    return {
      cursor: String(result[0]),
      keys: result[1].map(String)
    };
  }

  async hgetall(key: string): Promise<Record<string, string>> {
    const result = await this.command("HGETALL", key);
    if (!Array.isArray(result)) {
      return {};
    }

    const hash: Record<string, string> = {};
    for (let i = 0; i < result.length; i += 2) {
      hash[String(result[i])] = String(result[i + 1] ?? "");
    }

    return hash;
  }

  async ttl(key: string): Promise<number | null> {
    const result = await this.command("TTL", key);
    const ttl = Number(result);
    return Number.isFinite(ttl) ? ttl : null;
  }

  async hmset(key: string, values: Record<string, string>): Promise<void> {
    const args = Object.entries(values).flatMap(([field, value]) => [field, value]);
    const result = await this.command("HMSET", key, ...args);
    if (result !== "OK") {
      throw new Error("invalid redis HMSET response");
    }
  }

  async expire(key: string, seconds: number): Promise<boolean> {
    const result = await this.command("EXPIRE", key, String(seconds));
    return Number(result) === 1;
  }

  async del(key: string): Promise<number> {
    const result = await this.command("DEL", key);
    return Number(result);
  }

  async exists(key: string): Promise<boolean> {
    const result = await this.command("EXISTS", key);
    return Number(result) === 1;
  }

  async command(...args: string[]): Promise<RedisValue> {
    if (!this.socket) {
      throw new Error("redis socket is not connected");
    }

    this.socket.write(encodeCommand(args));
    return this.readResponse();
  }

  private async readResponse(): Promise<RedisValue> {
    for (;;) {
      const parsed = parseRedisValue(this.buffer);
      if (parsed) {
        this.buffer = this.buffer.subarray(parsed.bytes);
        return parsed.value;
      }

      await new Promise<void>((resolve, reject) => {
        const socket = this.socket;
        if (!socket) {
          reject(new Error("redis socket is closed"));
          return;
        }
        const onData = () => {
          cleanup();
          resolve();
        };
        const onError = (error: Error) => {
          cleanup();
          reject(error);
        };
        const cleanup = () => {
          socket.off("data", onData);
          socket.off("error", onError);
        };
        socket.once("data", onData);
        socket.once("error", onError);
      });
    }
  }
}

type RedisValue = string | number | null | RedisValue[];

function encodeCommand(args: string[]): string {
  return `*${args.length}\r\n${args.map((arg) => `$${Buffer.byteLength(arg)}\r\n${arg}\r\n`).join("")}`;
}

function parseRedisValue(buffer: Buffer, offset = 0): { value: RedisValue; bytes: number } | null {
  if (offset >= buffer.length) {
    return null;
  }

  const type = String.fromCharCode(buffer[offset]);
  if (type === "+" || type === "-" || type === ":") {
    const line = readLine(buffer, offset + 1);
    if (!line) {
      return null;
    }
    if (type === "-") {
      throw new Error(line.value);
    }
    return {
      value: type === ":" ? Number(line.value) : line.value,
      bytes: line.nextOffset - offset
    };
  }

  if (type === "$") {
    const line = readLine(buffer, offset + 1);
    if (!line) {
      return null;
    }
    const length = Number(line.value);
    if (length < 0) {
      return { value: null, bytes: line.nextOffset - offset };
    }
    const end = line.nextOffset + length;
    if (buffer.length < end + 2) {
      return null;
    }
    return {
      value: buffer.subarray(line.nextOffset, end).toString("utf8"),
      bytes: end + 2 - offset
    };
  }

  if (type === "*") {
    const line = readLine(buffer, offset + 1);
    if (!line) {
      return null;
    }
    const count = Number(line.value);
    if (count < 0) {
      return { value: null, bytes: line.nextOffset - offset };
    }
    const values: RedisValue[] = [];
    let cursor = line.nextOffset;
    for (let i = 0; i < count; i += 1) {
      const parsed = parseRedisValue(buffer, cursor);
      if (!parsed) {
        return null;
      }
      values.push(parsed.value);
      cursor += parsed.bytes;
    }
    return {
      value: values,
      bytes: cursor - offset
    };
  }

  throw new Error(`unsupported redis response type: ${type}`);
}

function readLine(buffer: Buffer, offset: number): { value: string; nextOffset: number } | null {
  const end = buffer.indexOf("\r\n", offset);
  if (end < 0) {
    return null;
  }

  return {
    value: buffer.subarray(offset, end).toString("utf8"),
    nextOffset: end + 2
  };
}

function normalizeInvitation(key: string, raw: Record<string, string>, ttl: number | null): LegacyRedisInvitation {
  return {
    code: key.replace(/^invite:/, ""),
    key,
    quota: numberOrNull(raw.quota),
    remaining: numberOrNull(raw.remaining),
    expiresAt: numberOrNull(raw.expiresAt),
    creatorId: numberOrNull(raw.creatorId),
    creatorName: raw.creatorName ?? null,
    note: raw.note ?? null,
    createdAt: numberOrNull(raw.createdAt),
    ttl,
    raw
  };
}

function numberOrNull(value: string | undefined): number | null {
  if (value === undefined || value.trim() === "") {
    return null;
  }

  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}
