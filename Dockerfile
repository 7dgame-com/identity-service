FROM node:22-alpine AS deps
WORKDIR /app
COPY package*.json ./
RUN npm ci

FROM deps AS build
ARG BUILD_REVISION=unknown
COPY tsconfig.json vitest.config.ts ./
COPY apps ./apps
COPY packages ./packages
COPY scripts ./scripts
RUN node scripts/verify-identity-finalization-runtime.mjs
RUN npm run build:compiled-revision -- "${BUILD_REVISION}"
RUN npm run build

# Explicit target only. The HTTP runtime below remains the default final stage.
FROM node:22-alpine AS migration-executor
WORKDIR /opt/xrugc/identity
ARG BUILD_REVISION=unknown
ENV NODE_ENV=production \
    IDENTITY_BUILD_REVISION=${BUILD_REVISION} \
    IDENTITY_MIGRATION_CONFIG_FILE=/run/xrugc/identity-finalization/config/migration.json \
    IDENTITY_MIGRATION_KEY_FILE=/run/xrugc/identity-finalization/config/migration.key
COPY package*.json ./
RUN npm ci --omit=dev
COPY --from=build /app/dist ./dist
# Preserve the pinned adapter's actual source bytes and same-module lease brand.
COPY --from=build /app/packages/identity-finalization-runtime/*.mjs ./dist/packages/identity-finalization-runtime/
COPY --from=build /app/packages/identity-finalization-runtime/upstream-manifest.json ./packages/identity-finalization-runtime/
COPY --from=build /app/scripts/verify-identity-finalization-runtime.mjs ./scripts/
RUN node --input-type=module -e 'import {writeFileSync,mkdirSync,chmodSync,chownSync} from "node:fs"; const r=process.argv[1]; if(!/^[a-f0-9]{40}$/.test(r))throw Error("BUILD_REVISION_REQUIRED"); writeFileSync("GIT_COMMIT",r+"\n",{mode:0o444,flag:"wx"}); mkdirSync("/run/xrugc/identity-finalization",{recursive:true,mode:0o755}); for(const n of ["config","inputs","reports"]){const p="/run/xrugc/identity-finalization/"+n; mkdirSync(p,{mode:0o700}); chmodSync(p,0o700); chownSync(p,1000,1000);}' "${BUILD_REVISION}"
RUN node scripts/verify-identity-finalization-runtime.mjs --executor
USER node
ENTRYPOINT ["node", "dist/scripts/identity-owned-executor.js"]
CMD []

FROM node:22-alpine AS runtime
WORKDIR /app
ARG BUILD_REVISION=unknown
ENV NODE_ENV=production \
    IDENTITY_BUILD_REVISION=${BUILD_REVISION}
COPY package*.json ./
RUN npm ci --omit=dev
COPY --from=build /app/dist ./dist
COPY deploy/mysql ./deploy/mysql
EXPOSE 8086
CMD ["node", "dist/apps/identity-adapter/src/main.js"]
