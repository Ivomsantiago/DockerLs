# Dockerfile.hardened.go-distroless
# Hardened template for Go (Google Distroless Static)

ARG GO_VERSION=1.23-alpine

# Stage 1: Builder
FROM golang:${GO_VERSION} AS builder

RUN apk update && apk add --no-cache git ca-certificates tzdata

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /app/binary .

# Stage 2: Distroless Static Runtime
FROM gcr.io/distroless/static-debian12:nonroot

LABEL security.scanner="dockerls"
LABEL security.hardened="true"
LABEL maintainer="security@company.com"
LABEL security.cve-contact="security@company.com"

WORKDIR /app

COPY --from=builder /app/binary /app/binary

ARG GIT_SHA=unknown
ARG BUILD_TIME=unknown
LABEL org.opencontainers.image.revision="${GIT_SHA}"
LABEL org.opencontainers.image.created="${BUILD_TIME}"

# nonroot user in Distroless
USER 65532:65532

EXPOSE 8080

ENTRYPOINT ["/app/binary"]
