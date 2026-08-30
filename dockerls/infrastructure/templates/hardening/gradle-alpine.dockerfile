# Dockerfile.hardened.gradle-alpine
# Hardened template for a Java application built with Gradle (Alpine).
#
# Same separation as the Maven template: the official Gradle image builds,
# and the runtime carries only the JRE. The Gradle daemon is disabled during
# the build -- inside a container it is never reused across runs, so keeping
# it running only wastes memory.

ARG GRADLE_VERSION=8-jdk21-alpine
ARG JRE_VERSION=21-jre-alpine

# Stage 1: Build
FROM gradle:${GRADLE_VERSION} AS builder

WORKDIR /app

COPY --chown=gradle:gradle build.gradle* settings.gradle* ./
COPY --chown=gradle:gradle src ./src
RUN gradle --no-daemon clean build -x test

# Stage 2: Runtime
FROM eclipse-temurin:${JRE_VERSION}

LABEL security.scanner="dockerls"
LABEL security.hardened="true"
LABEL maintainer="security@company.com"
LABEL security.cve-contact="security@company.com"

ENV JAVA_OPTS="-XX:+UseContainerSupport -XX:MaxRAMPercentage=75.0 -Djava.security.egd=file:/dev/./urandom"

RUN apk upgrade --no-cache \
    && addgroup -g 10001 appgroup \
    && adduser -u 10001 -G appgroup -s /sbin/nologin -D appuser

WORKDIR /app

COPY --from=builder --chown=appuser:appgroup /app/build/libs/*.jar /app/app.jar

ARG GIT_SHA=unknown
ARG BUILD_TIME=unknown
LABEL org.opencontainers.image.revision="${GIT_SHA}"
LABEL org.opencontainers.image.created="${BUILD_TIME}"

USER appuser

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD [ -f /app/app.jar ] || exit 1

EXPOSE 8080

ENTRYPOINT ["sh", "-c", "exec java $JAVA_OPTS -jar /app/app.jar"]
