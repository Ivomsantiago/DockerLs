# Dockerfile.hardened.node-ubuntu
# Hardened template for Node.js 22 (Ubuntu 24.04 LTS)

ARG UBUNTU_VERSION=24.04

# Stage 1: Builder
FROM ubuntu:${UBUNTU_VERSION} AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates build-essential \
    && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production && npm cache clean --force

COPY . .
RUN npm run build || true

# Stage 2: Runtime
FROM ubuntu:${UBUNTU_VERSION}

LABEL security.scanner="dockerls"
LABEL security.hardened="true"
LABEL maintainer="security@company.com"
LABEL security.cve-contact="security@company.com"

ENV DEBIAN_FRONTEND=noninteractive
ENV NODE_ENV=production

RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && groupadd -g 10001 nodeuser \
    && useradd -u 10001 -g nodeuser -s /usr/sbin/nologin -m nodeuser \
    && apt-get purge -y curl \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

WORKDIR /app

COPY --from=builder --chown=nodeuser:nodeuser /app/node_modules ./node_modules
COPY --chown=nodeuser:nodeuser . .

ARG GIT_SHA=unknown
ARG BUILD_TIME=unknown
LABEL org.opencontainers.image.revision="${GIT_SHA}"
LABEL org.opencontainers.image.created="${BUILD_TIME}"

USER nodeuser

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD node -e "require('http').get('http://localhost:3000/health', (r) => {if (r.statusCode !== 200) process.exit(1)}).on('error', () => process.exit(1))"

EXPOSE 3000

ENTRYPOINT ["node"]
CMD ["--enable-source-maps", "dist/index.js"]
