# Dockerfile.hardened.node-distroless
# Hardened template for Node.js 22 (Google Distroless - No Shell)

ARG NODE_VERSION=22-alpine

# Stage 1: Builder
FROM node:${NODE_VERSION} AS builder

WORKDIR /app

RUN apk add --no-cache python3 make g++ && rm -rf /var/cache/apk/*

COPY package*.json ./
RUN npm ci --only=production && npm cache clean --force

COPY . .
RUN npm run build || true

# Stage 2: Distroless Runtime (Zero Shell)
FROM gcr.io/distroless/nodejs22-debian12:nonroot

LABEL security.scanner="dockerls"
LABEL security.hardened="true"
LABEL maintainer="security@company.com"
LABEL security.cve-contact="security@company.com"

ENV NODE_ENV=production

WORKDIR /app

COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/package.json ./package.json

ARG GIT_SHA=unknown
ARG BUILD_TIME=unknown
LABEL org.opencontainers.image.revision="${GIT_SHA}"
LABEL org.opencontainers.image.created="${BUILD_TIME}"

# nonroot user in Distroless is 65532:65532
USER 65532:65532

EXPOSE 3000

ENTRYPOINT ["/nodejs/bin/node"]
CMD ["--enable-source-maps", "dist/index.js"]
