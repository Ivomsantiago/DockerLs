# Dockerfile.hardened.python-distroless
# Hardened template for Python 3.12 (Google Distroless - No Shell)

ARG DEBIAN_VERSION=bookworm-slim

# Stage 1: Builder
FROM debian:${DEBIAN_VERSION} AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements*.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Stage 2: Distroless Runtime (No Shell)
FROM gcr.io/distroless/python3-debian12:nonroot

LABEL security.scanner="dockerls"
LABEL security.hardened="true"
LABEL maintainer="security@company.com"
LABEL security.cve-contact="security@company.com"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH"

WORKDIR /app

COPY --from=builder /opt/venv /opt/venv
COPY --from=builder /app /app

ARG GIT_SHA=unknown
ARG BUILD_TIME=unknown
LABEL org.opencontainers.image.revision="${GIT_SHA}"
LABEL org.opencontainers.image.created="${BUILD_TIME}"

# nonroot user in Distroless is 65532:65532
USER 65532:65532

EXPOSE 8000

ENTRYPOINT ["/usr/bin/python3"]
CMD ["-u", "main.py"]
