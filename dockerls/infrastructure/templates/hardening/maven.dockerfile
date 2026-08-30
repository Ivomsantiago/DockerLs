# Dockerfile.hardened.maven
# Hardened template for a Java application built with Maven (Debian slim).
#
# The build uses the official Maven image, which carries the JDK and the
# tool; the runtime uses only the JRE. This separation keeps the compiler,
# the Maven cache, and the build dependency tree out of the image that ships
# to production -- none of it is needed to *run* the application, and each
# one is attack surface and CVEs to triage later.

ARG MAVEN_VERSION=3.9-eclipse-temurin-21
ARG JRE_VERSION=21-jre

# Stage 1: Build
FROM maven:${MAVEN_VERSION} AS builder

WORKDIR /app

# The POM goes in alone first: that way the dependency layer is only
# rebuilt when the POM changes, not on every code change.
COPY pom.xml ./
RUN mvn -B dependency:go-offline

COPY src ./src
RUN mvn -B clean package -DskipTests

# Stage 2: Runtime
FROM eclipse-temurin:${JRE_VERSION}

LABEL security.scanner="dockerls"
LABEL security.hardened="true"
LABEL maintainer="security@company.com"
LABEL security.cve-contact="security@company.com"

ENV JAVA_OPTS="-XX:+UseContainerSupport -XX:MaxRAMPercentage=75.0 -Djava.security.egd=file:/dev/./urandom"

RUN apt-get update && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 10001 appgroup \
    && useradd -u 10001 -g appgroup -s /usr/sbin/nologin -m appuser

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
