# Dockerfile.hardened.go
# Hardened template for Go - Minimal Production Ready

FROM golang:1.23-alpine AS builder

WORKDIR /app

# Install CA certificates and git
RUN apk add --no-cache ca-certificates git && update-ca-certificates && rm -rf /var/cache/apk/*

COPY go.mod go.sum* ./
RUN go mod download || true

COPY . .

# Static build with CGO disabled and stripping flags
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o app .

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

# Copy SSL root certificates for HTTPS calls
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy only the static binary
COPY --from=builder /app/app /app

# Expose default port
EXPOSE 8080

# Numeric non-root user (nobody) for scratch
USER 65534:65534

# Secure health check in exec form
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/app", "-health"]

# No shell - exec form only
ENTRYPOINT ["/app"]
