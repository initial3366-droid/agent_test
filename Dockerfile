# syntax=docker/dockerfile:1.7
FROM node:22-bookworm-slim AS build
ENV PNPM_HOME=/pnpm
ENV PATH=$PNPM_HOME:$PATH
RUN corepack enable
WORKDIR /app

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json turbo.json ./
COPY apps/api/package.json apps/api/package.json
COPY apps/web/package.json apps/web/package.json
COPY packages/protocol/package.json packages/protocol/package.json
COPY packages/agent-core/package.json packages/agent-core/package.json
RUN --mount=type=cache,id=pnpm,target=/pnpm/store \
    pnpm install --frozen-lockfile --filter @forge/api... --filter @forge/web...

COPY apps/api apps/api
COPY apps/web apps/web
COPY packages/protocol packages/protocol
COPY packages/agent-core packages/agent-core
RUN pnpm --filter @forge/protocol build \
 && pnpm --filter @forge/api build \
 && pnpm --filter @forge/web build \
 && pnpm --filter @forge/api --prod deploy --legacy /out/api

FROM node:22-bookworm-slim AS api
ENV NODE_ENV=production
WORKDIR /app
RUN groupadd --system --gid 10001 forge && useradd --system --uid 10001 --gid forge forge
COPY --from=build --chown=forge:forge /out/api ./
USER forge
EXPOSE 4000
CMD ["node", "dist/server.js"]

FROM node:22-bookworm-slim AS web
ENV NODE_ENV=production
ENV HOSTNAME=0.0.0.0
ENV PORT=3000
WORKDIR /app
RUN groupadd --system --gid 10001 forge && useradd --system --uid 10001 --gid forge forge
COPY --from=build --chown=forge:forge /app/apps/web/.next/standalone ./
COPY --from=build --chown=forge:forge /app/apps/web/.next/static ./apps/web/.next/static
USER forge
EXPOSE 3000
CMD ["node", "apps/web/server.js"]
