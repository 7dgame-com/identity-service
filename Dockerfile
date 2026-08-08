FROM node:22-alpine AS deps
WORKDIR /app
COPY package*.json ./
RUN npm ci

FROM deps AS build
COPY tsconfig.json vitest.config.ts ./
COPY apps ./apps
COPY packages ./packages
COPY scripts ./scripts
RUN npm run build

FROM node:22-alpine AS runtime
WORKDIR /app
ARG BUILD_REVISION=unknown
ENV NODE_ENV=production \
    IDENTITY_BUILD_REVISION=${BUILD_REVISION}
COPY package*.json ./
RUN npm ci --omit=dev
COPY --from=build /app/dist ./dist
EXPOSE 8086
CMD ["node", "dist/apps/identity-adapter/src/main.js"]
