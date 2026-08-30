# Dockerfile.hardened.node-alpine
# Hardened template for Node.js 22 (Alpine Linux musl)

ARG NODE_VERSION=22-alpine

# Stage 1: Builder
FROM node:${NODE_VERSION} AS builder

WORKDIR /app

RUN apk add --no-cache python3 make g++ && rm -rf /var/cache/apk/*

COPY package*.json ./
RUN npm ci --only=production && npm cache clean --force

COPY . .
RUN npm run build || true

# Stage 2: Runtime
FROM node:${NODE_VERSION}

LABEL security.scanner="dockerls"
LABEL security.hardened="true"
LABEL maintainer="security@company.com"
LABEL security.cve-contact="security@company.com"

ENV NODE_ENV=production

WORKDIR /app

COPY --from=builder --chown=node:node /app/node_modules ./node_modules
COPY --chown=node:node . .

ARG GIT_SHA=unknown
ARG BUILD_TIME=unknown
LABEL org.opencontainers.image.revision="${GIT_SHA}"
LABEL org.opencontainers.image.created="${BUILD_TIME}"

USER node

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD node -e "require('http').get('http://localhost:3000/health', (r) => {if (r.statusCode !== 200) process.exit(1)}).on('error', () => process.exit(1))"

EXPOSE 3000

ENTRYPOINT ["node"]
CMD ["--enable-source-maps", "dist/index.js"]
