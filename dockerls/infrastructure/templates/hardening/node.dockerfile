# Dockerfile.hardened.node
# Hardened template for Node.js - Production Ready

ARG NODE_VERSION=22-alpine

# Stage 1: Builder
FROM node:${NODE_VERSION} AS builder

WORKDIR /app

# Install build dependencies if needed (stay only in the builder)
RUN apk add --no-cache \
    python3 \
    make \
    g++ \
    && rm -rf /var/cache/apk/*

# Copy package manifests and install clean dependencies
COPY package*.json ./
RUN npm ci --only=production \
    && npm cache clean --force

# Copy source and build
COPY . .
RUN npm run build || true

# Stage 2: Runtime
FROM node:${NODE_VERSION}

# Security labels
LABEL security.scanner="dockerls"
LABEL security.hardened="true"
LABEL maintainer="your-team@company.com"
LABEL security.cve-contact="security@company.com"

# Production environment variables
ENV NODE_ENV=production

WORKDIR /app

# Copy only the necessary artifacts with ownership for the 'node' user
COPY --from=builder --chown=node:node /app/node_modules ./node_modules
COPY --chown=node:node . .

# Build metadata
ARG GIT_SHA=unknown
ARG BUILD_TIME=unknown
LABEL org.opencontainers.image.revision="${GIT_SHA}"
LABEL org.opencontainers.image.created="${BUILD_TIME}"

USER node

# Secure native health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD node -e "require('http').get('http://localhost:3000/health', (r) => {if (r.statusCode !== 200) process.exit(1)}).on('error', () => process.exit(1))"

EXPOSE 3000

# No shell - exec form
ENTRYPOINT ["node"]
CMD ["--enable-source-maps", "dist/index.js"]
