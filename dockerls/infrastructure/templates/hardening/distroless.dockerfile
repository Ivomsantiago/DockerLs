# Dockerfile.hardened.distroless
# Hardened template for Google Distroless (Debian 12 base)

ARG BUILDER_VERSION=3.20

# Stage 1: Builder
FROM alpine:${BUILDER_VERSION} AS builder

RUN apk update && apk add --no-cache ca-certificates tzdata

WORKDIR /app
COPY . .

# Stage 2: Distroless Runtime
FROM gcr.io/distroless/base-debian12:nonroot

LABEL security.scanner="dockerls"
LABEL security.hardened="true"
LABEL maintainer="security@company.com"
LABEL security.cve-contact="security@company.com"

WORKDIR /app

COPY --from=builder /app /app

ARG GIT_SHA=unknown
ARG BUILD_TIME=unknown
LABEL org.opencontainers.image.revision="${GIT_SHA}"
LABEL org.opencontainers.image.created="${BUILD_TIME}"

# nonroot user in Distroless is 65532:65532
USER 65532:65532

ENTRYPOINT ["/app/binary"]
