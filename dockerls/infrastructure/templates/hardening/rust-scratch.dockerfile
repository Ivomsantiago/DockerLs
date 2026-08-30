# Dockerfile.hardened.rust-scratch
# Hardened template for Rust (Scratch - Zero OS CVEs)

ARG RUST_VERSION=1.82-alpine

# Stage 1: Builder (Alpine musl static compilation)
FROM rust:${RUST_VERSION} AS builder

RUN apk update && apk add --no-cache musl-dev ca-certificates tzdata \
    && rustup target add x86_64-unknown-linux-musl

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY src ./src

# Secure static compilation
RUN RUSTFLAGS="-C target-feature=+crt-static" \
    cargo build --release --target x86_64-unknown-linux-musl \
    && cp /app/target/x86_64-unknown-linux-musl/release/app /app/binary || cp /app/target/x86_64-unknown-linux-musl/release/* /app/binary

# Stage 2: Scratch Runtime
FROM scratch

LABEL security.scanner="dockerls"
LABEL security.hardened="true"
LABEL maintainer="security@company.com"
LABEL security.cve-contact="security@company.com"

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /app/binary /app/binary

ARG GIT_SHA=unknown
ARG BUILD_TIME=unknown
LABEL org.opencontainers.image.revision="${GIT_SHA}"
LABEL org.opencontainers.image.created="${BUILD_TIME}"

# nobody user (UID 65534:65534)
USER 65534:65534

EXPOSE 8080

ENTRYPOINT ["/app/binary"]
