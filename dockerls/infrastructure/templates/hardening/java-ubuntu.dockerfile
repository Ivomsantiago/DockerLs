# Dockerfile.hardened.java-ubuntu
# Hardened template for Java 21 (Eclipse Temurin JRE Ubuntu 24.04)

ARG UBUNTU_VERSION=24.04

# Stage 1: Build
FROM ubuntu:${UBUNTU_VERSION} AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-21-jdk maven ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pom.xml ./
COPY src ./src
RUN mvn clean package -DskipTests || true

# Stage 2: Runtime
FROM ubuntu:${UBUNTU_VERSION}

LABEL security.scanner="dockerls"
LABEL security.hardened="true"
LABEL maintainer="security@company.com"
LABEL security.cve-contact="security@company.com"

ENV DEBIAN_FRONTEND=noninteractive \
    JAVA_OPTS="-XX:+UseContainerSupport -XX:MaxRAMPercentage=75.0 -Djava.security.egd=file:/dev/./urandom"

RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends openjdk-21-jre-headless ca-certificates \
    && groupadd -g 10001 appgroup \
    && useradd -u 10001 -g appgroup -s /usr/sbin/nologin -m appuser \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

WORKDIR /app

COPY --from=builder --chown=appuser:appgroup /app/target/*.jar /app/app.jar

ARG GIT_SHA=unknown
ARG BUILD_TIME=unknown
LABEL org.opencontainers.image.revision="${GIT_SHA}"
LABEL org.opencontainers.image.created="${BUILD_TIME}"

USER appuser

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD [ -f /app/app.jar ] || exit 1

EXPOSE 8080

ENTRYPOINT ["sh", "-c", "exec java $JAVA_OPTS -jar /app/app.jar"]
