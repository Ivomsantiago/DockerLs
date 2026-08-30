# Dockerfile.hardened.rust-debian
# Hardened template for Rust (Debian Bookworm Slim)

ARG RUST_VERSION=1.82-bookworm
ARG DEBIAN_VERSION=bookworm-slim

# Stage 1: Builder
FROM rust:${RUST_VERSION} AS builder

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release \
    && cp /app/target/release/app /app/binary || cp /app/target/release/* /app/binary

# Stage 2: Debian Runtime
FROM debian:${DEBIAN_VERSION}

LABEL security.scanner="dockerls"
LABEL security.hardened="true"
LABEL maintainer="security@company.com"
LABEL security.cve-contact="security@company.com"

RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends ca-certificates tzdata \
    && groupadd -g 10001 appgroup \
    && useradd -u 10001 -g appgroup -s /usr/sbin/nologin -m appuser \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

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
