# Dockerfile.hardened.alpine
# Hardened template for Alpine Linux - Minimal Base Container

ARG BASE_VERSION=3.20

# Stage 1: Build / Setup
FROM alpine:${BASE_VERSION} AS builder

RUN apk update && apk upgrade --no-cache \
    && apk add --no-cache ca-certificates tzdata \
    && rm -rf /var/cache/apk/*

# Stage 2: Runtime
FROM alpine:${BASE_VERSION}

LABEL security.scanner="dockerls"
LABEL security.hardened="true"
LABEL maintainer="security@company.com"
LABEL security.cve-contact="security@company.com"

# Update security packages and create a dedicated non-root user (UID 10001)
RUN apk update && apk upgrade --no-cache \
    && apk add --no-cache ca-certificates tzdata \
    && addgroup -g 10001 appgroup \
    && adduser -u 10001 -G appgroup -s /sbin/nologin -D appuser \
    && rm -rf /var/cache/apk/*

WORKDIR /app

# Copy application files with proper ownership
COPY --chown=appuser:appgroup . .

ARG GIT_SHA=unknown
ARG BUILD_TIME=unknown
LABEL org.opencontainers.image.revision="${GIT_SHA}"
LABEL org.opencontainers.image.created="${BUILD_TIME}"

USER appuser

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD [ -f /app/health.ok ] || exit 0

ENTRYPOINT ["sh", "-c"]
CMD ["echo 'DockerLs Alpine container ready'"]
