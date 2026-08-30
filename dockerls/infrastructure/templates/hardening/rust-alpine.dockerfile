# Dockerfile.hardened.rust-alpine
# Hardened template for Rust (Alpine Linux)

ARG RUST_VERSION=1.82-alpine
ARG ALPINE_VERSION=3.20

# Stage 1: Builder
FROM rust:${RUST_VERSION} AS builder

RUN apk update && apk add --no-cache musl-dev

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release \
    && cp /app/target/release/app /app/binary || cp /app/target/release/* /app/binary

# Stage 2: Alpine Runtime
FROM alpine:${ALPINE_VERSION}

LABEL security.scanner="dockerls"
LABEL security.hardened="true"
LABEL maintainer="security@company.com"
LABEL security.cve-contact="security@company.com"

RUN apk update && apk upgrade --no-cache \
    && apk add --no-cache ca-certificates tzdata \
    && addgroup -g 10001 appgroup \
    && adduser -u 10001 -G appgroup -s /sbin/nologin -D appuser \
    && rm -rf /var/cache/apk/*

WORKDIR /app

COPY --from=builder /app/binary /app/binary

ARG GIT_SHA=unknown
ARG BUILD_TIME=unknown
LABEL org.opencontainers.image.revision="${GIT_SHA}"
LABEL org.opencontainers.image.created="${BUILD_TIME}"

USER appuser

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD [ -f /app/binary ] || exit 1

EXPOSE 8080

ENTRYPOINT ["/app/binary"]
