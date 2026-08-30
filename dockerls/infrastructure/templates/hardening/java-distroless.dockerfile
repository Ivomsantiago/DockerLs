# Dockerfile.hardened.java-distroless
# Hardened template for Java 21 (Google Distroless - No Shell)

ARG JDK_VERSION=21-jdk-alpine

# Stage 1: Build
FROM eclipse-temurin:${JDK_VERSION} AS builder

WORKDIR /app

RUN apk add --no-cache maven

COPY pom.xml ./
COPY src ./src
RUN mvn clean package -DskipTests || true

# Stage 2: Distroless Java 21 Runtime (No Shell)
FROM gcr.io/distroless/java21-debian12:nonroot

LABEL security.scanner="dockerls"
LABEL security.hardened="true"
LABEL maintainer="security@company.com"
LABEL security.cve-contact="security@company.com"

WORKDIR /app

COPY --from=builder /app/target/*.jar /app/app.jar

ARG GIT_SHA=unknown
ARG BUILD_TIME=unknown
LABEL org.opencontainers.image.revision="${GIT_SHA}"
LABEL org.opencontainers.image.created="${BUILD_TIME}"

# nonroot user in Distroless
USER 65532:65532

EXPOSE 8080

ENTRYPOINT ["java", "-XX:+UseContainerSupport", "-XX:MaxRAMPercentage=75.0", "-jar", "/app/app.jar"]
