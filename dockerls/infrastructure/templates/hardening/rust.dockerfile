# Dockerfile.hardened.rust
# Hardened template for Rust - Production Ready Static Binary

# Stage 1: Builder
FROM rust:1.82-alpine AS builder

WORKDIR /app

# musl build dependencies
RUN apk add --no-cache musl-dev ca-certificates && rm -rf /var/cache/apk/*

COPY Cargo.toml Cargo.lock* ./

# Copy source code
COPY src ./src

# Static release compilation
RUN RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --target x86_64-unknown-linux-musl || \
    cargo build --release

# Locate the generated binary
RUN if [ -f target/x86_64-unknown-linux-musl/release/app ]; then \
        cp target/x86_64-unknown-linux-musl/release/app /app/binary; \
    else \
        find target/release -maxdepth 1 -type f -executable -exec cp {} /app/binary \; ; \
    fi

# Stage 2: Runtime minimal (scratch)
FROM scratch

LABEL security.scanner="dockerls"
LABEL security.hardened="true"
LABEL maintainer="your-team@company.com"
LABEL security.cve-contact="security@company.com"

# Build metadata
ARG GIT_SHA=unknown
ARG BUILD_TIME=unknown
LABEL org.opencontainers.image.revision="${GIT_SHA}"
LABEL org.opencontainers.image.created="${BUILD_TIME}"

# Copy SSL root certificates
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the application binary
COPY --from=builder /app/binary /app

EXPOSE 8080

# Non-root user (nobody)
USER 65534:65534

# Formato exec
ENTRYPOINT ["/app"]
