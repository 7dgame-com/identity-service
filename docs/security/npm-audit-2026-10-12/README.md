# Dependency audit, 2026-10-12

The original committed service revision `24584c26814ac5afa18ae932efed8840744e85cd`
had six production findings (one critical) and nine findings with development
dependencies included. The CI workflow runs unrestricted `npm audit`, so both
scopes are release gates. The accompanying JSON contains public package and
advisory metadata only; it does not contain environment values or credentials.

After the compatible dependency updates, both scopes report **zero findings**.
The after reports identify the exact package-lock content by SHA-256. A successful
standard `npm ci` rebuilt the installed tree from that lock; the previous local
pnpm tree differed from the npm lock and was not used as validation evidence.
Nest remains `11.1.27`, Vite remains `8.0.16`, and no dependency crosses a major
version. Existing security overrides are retained.

Validation passed: TypeScript `--noEmit`, plus the complete regression under
`TZ=Asia/Shanghai`: **75 files, 1171 tests passed, zero failed or skipped**,
including 167 tests against disposable MySQL 8.4.11 databases. This includes the
compiled Nest HTTP routing/DI and native account/session/provider flows. It does
not claim live external Apple or WeChat provider verification.

| Package | Previous lock | Fixed floor | Updated lock | Current code exposure |
| --- | --- | --- | --- | --- |
| `proxy-addr` | 2.0.7 | 2.0.8 | 2.0.8 | Express uses this for `request.ip`; the app does not configure `trust proxy` or the affected mapped-IPv6 trust subnet. IP values are session/audit metadata, not authorization. |
| `multer` | 2.2.0 | 2.4.0 | 2.4.0 | Transitive Nest Express dependency; no multipart/upload handler uses it. The platform-express audit finding is inherited from Multer. |
| `@grpc/grpc-js` | 1.14.4 | 1.14.5 | 1.14.6 | Transitive telemetry dependency; no gRPC server, `getAuthContext` or server-handler use. Enabled telemetry explicitly sends HTTP JSON traces. |
| `mysql2` | 3.22.4 | 3.23.1 | 3.24.5 | Used by the service and migration tools. No connection enables `compress`, which the reported inflate issue requires. |
| `qs` | 6.15.2 | 6.16.0 | 6.16.0 | Public URL-encoded forms pass through Nest's default extended body parser, including `/token`. Package reachability is established; exploit payloads were not executed. |
| `vitest`, `@vitest/mocker` | 4.1.8 | 4.1.11 | 4.1.11 | Development only; tests use the Node environment, without browser/UI servers. All Vitest subpackages update together. |
| `source-map-js` | 1.2.1 | 1.2.2 | 1.2.2 | Development dependency through Vite/PostCSS; omitted from the runtime image. |

The fixed floors come from the maintainer advisories:

- [proxy-addr mapped-IPv6 trust bypass](https://github.com/advisories/GHSA-jqcg-44mw-7w3h)
- [Multer orphaned upload writes](https://github.com/advisories/GHSA-3pph-fpjx-jg34),
  [crafted field names](https://github.com/advisories/GHSA-wc9g-mqfw-jrwm),
  [descriptor leak](https://github.com/advisories/GHSA-qfvm-cv95-jqjf),
  [asynchronous filter race](https://github.com/advisories/GHSA-qvfw-j98x-7q72),
  [array-index denial of service](https://github.com/advisories/GHSA-535w-7cp7-47q4)
- [gRPC unauthorized certificate context](https://github.com/advisories/GHSA-m9gg-hp2v-232j),
  [server error disclosure](https://github.com/advisories/GHSA-f596-whhp-79r4)
- [mysql2 compressed-packet expansion](https://github.com/advisories/GHSA-rgwj-5xj2-c3m3)
- [qs isBuffer error](https://github.com/advisories/GHSA-4mjr-xmp4-gh2g),
  [comma-array limit bypass](https://github.com/advisories/GHSA-x5fp-wj9c-mxmx)
- [Vitest mocker file disclosure](https://github.com/advisories/GHSA-82fw-gwwq-j7x9)
- [source-map-js indexed-map denial of service](https://github.com/advisories/GHSA-68fv-2mgg-jv7q)

Code reviewed: `main.ts` default Nest bootstrap, `oidc.controller.ts` token
endpoint, `native-qrcode.controller.ts` request context, session repository IP
storage, `telemetry.ts`, every application/CLI MySQL connection, and
`vitest.config.ts`. Conditional exposure does not exempt a package from the gate;
all reported packages were repaired.

Reproduce from the committed service checkout:

```bash
npm ci
npm audit --omit=dev --json
npm audit --include=dev --json
npx tsc --noEmit
TZ=Asia/Shanghai npm test
```

The full database regression additionally requires the disposable MySQL fixture
settings documented by the individual `*.mysql.spec.ts` tests. It must not run
against application or production databases. Audit results are a point-in-time
registry check; CI repeats them on subsequent builds.
