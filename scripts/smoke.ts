const baseUrl = process.env.IDENTITY_ADAPTER_URL ?? "http://localhost:8086";

async function main() {
  const checks = [
    { path: "/health", expectStatus: 200 },
    { path: "/jwks.json", expectStatus: 200 }
  ];

  for (const check of checks) {
    const response = await fetch(`${baseUrl}${check.path}`);
    if (response.status !== check.expectStatus) {
      const text = await response.text();
      throw new Error(`${check.path} expected ${check.expectStatus}, got ${response.status}: ${text}`);
    }
    console.log(`${check.path} ok`);
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});

