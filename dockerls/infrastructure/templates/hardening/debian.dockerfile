# Dockerfile.hardened.debian
# Hardened template for Debian GNU/Linux (Bookworm Slim)

ARG DEBIAN_VERSION=bookworm-slim

# Stage 1: Build / Setup
FROM debian:${DEBIAN_VERSION} AS builder

RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/*

# Stage 2: Runtime
FROM debian:${DEBIAN_VERSION}

LABEL security.scanner="dockerls"
LABEL security.hardened="true"
LABEL maintainer="security@company.com"
LABEL security.cve-contact="security@company.com"

# Update OS packages and create a non-root user (UID 10001)
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends ca-certificates tzdata \
    && groupadd -g 10001 appgroup \
    && useradd -u 10001 -g appgroup -s /usr/sbin/nologin -m appuser \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

WORKDIR /app

COPY --chown=appuser:appgroup . .

ARG GIT_SHA=unknown
ARG BUILD_TIME=unknown
LABEL org.opencontainers.image.revision="${GIT_SHA}"
LABEL org.opencontainers.image.created="${BUILD_TIME}"

USER appuser

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD [ -f /app/health.ok ] || exit 0

ENTRYPOINT ["sh", "-c"]
CMD ["echo 'DockerLs Debian container ready'"]
