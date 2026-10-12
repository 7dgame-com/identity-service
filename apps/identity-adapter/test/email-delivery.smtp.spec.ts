import { execFile as execFileCallback } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { createServer, type Server, type Socket } from "node:net";
import { createServer as createTlsServer, createSecureContext, TLSSocket } from "node:tls";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const execFile = promisify(execFileCallback);
const servicePath = fileURLToPath(new URL("../src/email-delivery.service.ts", import.meta.url));
let directory: string, key: Buffer, cert: Buffer;
type Settings = { implicit?: boolean; starttls?: boolean; rejectAuth?: boolean; rejectRecipient?: boolean; delay?: number };

// A loopback-only SMTP peer; it never relays mail or uses real addresses/credentials.
async function fixture(settings: Settings) {
  const sockets = new Set<Socket>(); const messages: string[] = []; let authCount = 0;
  const timers = new Set<ReturnType<typeof setTimeout>>();
  const reply = (socket: Socket, value: string) => {
    if (!settings.delay) { if (!socket.destroyed) socket.write(value); return; }
    const timer = setTimeout(() => { timers.delete(timer); if (!socket.destroyed) socket.write(value); }, settings.delay); timers.add(timer);
  };
  const handle = (socket: Socket, secured: boolean, greeting: boolean) => {
    socket.on("error", () => {}); socket.setEncoding("utf8");
    let buffer = "", data = false, message: string[] = [];
    if (greeting) reply(socket, "220 localhost fixture SMTP\r\n");
    const onData = (chunk: string) => {
      buffer += chunk;
      while (buffer.includes("\r\n")) {
        const end = buffer.indexOf("\r\n"), line = buffer.slice(0, end); buffer = buffer.slice(end + 2);
        if (data) {
          if (line === ".") { messages.push(message.join("\r\n")); data = false; message = []; reply(socket, "250 2.0.0 accepted\r\n"); }
          else message.push(line);
          continue;
        }
        if (/^EHLO /i.test(line)) reply(socket, `250-localhost\r\n${settings.starttls && !secured ? "250-STARTTLS\r\n" : ""}250 AUTH PLAIN\r\n`);
        else if (/^STARTTLS$/i.test(line)) {
          if (!settings.starttls || secured) { reply(socket, "502 5.5.1 TLS unavailable\r\n"); continue; }
          socket.removeListener("data", onData); socket.write("220 2.0.0 begin TLS\r\n");
          const upgraded = new TLSSocket(socket, { isServer: true, secureContext: createSecureContext({ key, cert, minVersion: "TLSv1.2" }) });
          upgraded.on("error", () => {}); handle(upgraded, true, false); return;
        } else if (/^AUTH /i.test(line)) { authCount++; reply(socket, settings.rejectAuth ? "535 5.7.8 fixture auth rejected\r\n" : "235 2.7.0 authenticated\r\n"); }
        else if (/^RCPT TO:/i.test(line)) reply(socket, settings.rejectRecipient ? "550 5.1.1 fixture recipient rejected\r\n" : "250 2.1.5 recipient accepted\r\n");
        else if (/^DATA$/i.test(line)) { data = true; reply(socket, "354 send data\r\n"); }
        else if (/^QUIT$/i.test(line)) socket.end("221 closing\r\n");
        else reply(socket, "250 2.1.0 accepted\r\n");
      }
    };
    socket.on("data", onData);
  };
  const server: Server = settings.implicit
    ? createTlsServer({ key, cert, minVersion: "TLSv1.2" }, (socket) => handle(socket, true, true))
    : createServer((socket) => handle(socket, false, true));
  server.on("tlsClientError", () => {});
  server.on("connection", (socket) => { sockets.add(socket); socket.once("close", () => sockets.delete(socket)); });
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  const address = server.address(); if (!address || typeof address === "string") throw new Error("No loopback SMTP address");
  return { port: address.port, messages, authCount: () => authCount, sockets,
    async close() { for (const timer of timers) clearTimeout(timer); for (const socket of sockets) socket.destroy(); await new Promise<void>((resolve) => server.close(() => resolve())); }
  };
}

async function send(port: number, mode: "implicit" | "starttls", options: { trust?: boolean; method?: string } = {}) {
  const env = { ...process.env };
  for (const name of Object.keys(env)) if (name.startsWith("IDENTITY_EMAIL_") || name.startsWith("MAILER_") || name === "NODE_TLS_REJECT_UNAUTHORIZED") delete env[name];
  Object.assign(env, { NODE_ENV: "test", NODE_OPTIONS: "", IDENTITY_EMAIL_TRANSPORT: "smtp", IDENTITY_EMAIL_SMTP_HOST: "127.0.0.1",
    IDENTITY_EMAIL_SMTP_PORT: String(port), IDENTITY_EMAIL_SMTP_TLS_MODE: mode, IDENTITY_EMAIL_SMTP_SERVER_NAME: "localhost",
    MAILER_USERNAME: "sender@example.test", MAILER_PASSWORD: "fixture-smtp-password", IDENTITY_EMAIL_APP_NAME: "Fixture" });
  if (options.trust !== false) env.NODE_EXTRA_CA_CERTS = path.join(directory, "cert.pem"); else delete env.NODE_EXTRA_CA_CERTS;
  const script = `import { EmailDeliveryService } from ${JSON.stringify(servicePath)};
    const start=performance.now();try {await new EmailDeliveryService().${options.method ?? "sendEmailVerificationCode"}({email:"recipient@example.test",code:"123456"});console.log(JSON.stringify({ok:true,elapsed:performance.now()-start}));}
    catch(error){console.log(JSON.stringify({ok:false,status:error.getStatus?.(),body:error.getResponse?.(),elapsed:performance.now()-start}));}`;
  const result = await execFile(process.execPath, ["--import", "tsx", "--input-type=module", "-e", script], { env, timeout: 6500, maxBuffer: 16384 });
  expect(result.stderr).toBe("");
  for (const secret of ["recipient@example.test", "fixture-smtp-password", "123456"]) expect(result.stdout).not.toContain(secret);
  return JSON.parse(result.stdout.trim()) as { ok: boolean; status?: number; body?: { code: string }; elapsed: number };
}

describe("native delivery against a real loopback SMTP/TLS peer", () => {
  beforeAll(async () => {
    directory = await mkdtemp(path.join(tmpdir(), "identity-smtp-test-"));
    await execFile(process.env.IDENTITY_TEST_OPENSSL ?? "openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
      "-keyout", path.join(directory, "key.pem"), "-out", path.join(directory, "cert.pem"), "-subj", "/CN=localhost",
      "-addext", "subjectAltName=DNS:localhost", "-addext", "basicConstraints=critical,CA:TRUE"], { env: { ...process.env, OPENSSL_CONF: "/dev/null" } });
    [key, cert] = await Promise.all([readFile(path.join(directory, "key.pem")), readFile(path.join(directory, "cert.pem"))]);
  }, 10000);
  afterAll(async () => { if (directory) await rm(directory, { recursive: true, force: true }); });

  it("delivers verification and reset multipart messages with authenticated implicit TLS", async () => {
    const server = await fixture({ implicit: true });
    try {
      expect((await send(server.port, "implicit")).ok).toBe(true);
      expect((await send(server.port, "implicit", { method: "sendPasswordResetCode" })).ok).toBe(true);
      expect(server.authCount()).toBe(2); expect(server.messages).toHaveLength(2);
      for (const message of server.messages) {
        expect(message).toContain("To: recipient@example.test"); expect(message).toContain("multipart/alternative"); expect(message).toContain("123456");
        expect(message).toContain("Content-Type: text/plain"); expect(message).toContain("Content-Type: text/html");
      }
    } finally { await server.close(); }
  });
  it("upgrades STARTTLS before authenticating or sending a message", async () => {
    const server = await fixture({ starttls: true });
    try { expect((await send(server.port, "starttls")).ok).toBe(true); expect(server.authCount()).toBe(1); expect(server.messages).toHaveLength(1); }
    finally { await server.close(); }
  });
  it("refuses a peer without STARTTLS before exposing credentials or mail", async () => {
    const server = await fixture({});
    try { expect(await send(server.port, "starttls")).toMatchObject({ ok: false, status: 503 }); expect(server.authCount()).toBe(0); expect(server.messages).toHaveLength(0); }
    finally { await server.close(); }
  });
  it("rejects an untrusted TLS certificate without sending credentials or mail", async () => {
    const server = await fixture({ implicit: true });
    try { expect(await send(server.port, "implicit", { trust: false })).toMatchObject({ ok: false, status: 503, body: { code: "EMAIL_SMTP_UNAVAILABLE" } }); expect(server.authCount()).toBe(0); expect(server.messages).toHaveLength(0); }
    finally { await server.close(); }
  });
  it.each([{ rejectAuth: true }, { rejectRecipient: true }])("normalizes a real SMTP rejection %j without reporting delivery", async (settings) => {
    const server = await fixture({ implicit: true, ...settings });
    try { expect(await send(server.port, "implicit")).toMatchObject({ ok: false, status: 503, body: { code: "EMAIL_SMTP_REJECTED" } }); expect(server.messages).toHaveLength(0); }
    finally { await server.close(); }
  });
  it("closes an active progressing SMTP connection at the total three-second deadline", async () => {
    const server = await fixture({ implicit: true, delay: 650 });
    try {
      const result = await send(server.port, "implicit");
      expect(result).toMatchObject({ ok: false, status: 503, body: { code: "EMAIL_SMTP_TIMEOUT" } });
      expect(result.elapsed).toBeGreaterThanOrEqual(2900); expect(result.elapsed).toBeLessThan(3500);
      expect(server.messages).toHaveLength(0); expect(server.sockets.size).toBe(0);
    } finally { await server.close(); }
  }, 8000);
});
