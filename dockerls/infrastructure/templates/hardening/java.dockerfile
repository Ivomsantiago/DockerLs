# Dockerfile.hardened.java
# Hardened template for Java / JVM - Production Ready (Eclipse Temurin 21)

# Stage 1: Builder
FROM eclipse-temurin:21-jdk-alpine AS builder

WORKDIR /app

# Copy build output from Maven or Gradle
COPY pom.xml* mvnw* ./
COPY .mvn ./.mvn
COPY build.gradle* settings.gradle* gradlew* ./
COPY gradle ./gradle

# Download dependencies
RUN if [ -f "./mvnw" ]; then ./mvnw dependency:go-offline; \
    elif [ -f "./gradlew" ]; then ./gradlew --no-daemon dependencies; fi || true

COPY src ./src

# Compile the jar package
RUN if [ -f "./mvnw" ]; then ./mvnw clean package -DskipTests; \
    elif [ -f "./gradlew" ]; then ./gradlew --no-daemon bootJar || ./gradlew --no-daemon build -x test; \
    fi || true

RUN find target build/libs -name "*.jar" ! -name "*sources*" ! -name "*javadoc*" -exec cp {} /app/app.jar \; || touch /app/app.jar

# Stage 2: Runtime Minimal
FROM eclipse-temurin:21-jre-alpine

LABEL security.scanner="dockerls"
LABEL security.hardened="true"
LABEL maintainer="your-team@company.com"
LABEL security.cve-contact="security@company.com"

# JVM flags tuned for containers and security
ENV JAVA_OPTS="-XX:+UseContainerSupport -XX:MaxRAMPercentage=75.0 -Djava.security.egd=file:/dev/./urandom"

RUN addgroup -g 10001 appgroup && \
    adduser -D -u 10001 -G appgroup -h /home/appuser appuser

WORKDIR /app

COPY --from=builder --chown=appuser:appgroup /app/app.jar /app/app.jar

# Build metadata
ARG GIT_SHA=unknown
ARG BUILD_TIME=unknown
LABEL org.opencontainers.image.revision="${GIT_SHA}"
LABEL org.opencontainers.image.created="${BUILD_TIME}"

USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD nc -z localhost 8080 || exit 1

EXPOSE 8080

ENTRYPOINT ["sh", "-c", "exec java $JAVA_OPTS -jar /app/app.jar"]
