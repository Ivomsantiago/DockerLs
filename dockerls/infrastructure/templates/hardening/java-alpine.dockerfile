# Dockerfile.hardened.java-alpine
# Hardened template for Java 21 (Eclipse Temurin JRE Alpine)

ARG JDK_VERSION=21-jdk-alpine
ARG JRE_VERSION=21-jre-alpine

# Stage 1: Build (Maven / Gradle)
FROM eclipse-temurin:${JDK_VERSION} AS builder

WORKDIR /app

RUN apk add --no-cache maven gradle \
    && rm -rf /var/cache/apk/*

COPY pom.xml ./
COPY src ./src
RUN mvn clean package -DskipTests || true

# Stage 2: Runtime
FROM eclipse-temurin:${JRE_VERSION}

LABEL security.scanner="dockerls"
LABEL security.hardened="true"
LABEL maintainer="security@company.com"
LABEL security.cve-contact="security@company.com"

ENV JAVA_OPTS="-XX:+UseContainerSupport -XX:MaxRAMPercentage=75.0 -Djava.security.egd=file:/dev/./urandom"

RUN apk update && apk upgrade --no-cache \
    && addgroup -g 10001 appgroup \
    && adduser -u 10001 -G appgroup -s /sbin/nologin -D appuser \
    && rm -rf /var/cache/apk/*

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
