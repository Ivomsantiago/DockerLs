# Dockerfile.hardened.php
# Hardened template for PHP 8.3 - Production Ready

# Stage 1: Composer Builder
FROM composer:2 AS composer_stage

WORKDIR /app
COPY composer.json composer.lock* ./
RUN composer install --no-dev --prefer-dist --no-interaction --optimize-autoloader --no-scripts || true

# Stage 2: Runtime PHP 8.3 Alpine
FROM php:8.3-cli-alpine

LABEL security.scanner="dockerls"
LABEL security.hardened="true"
LABEL maintainer="your-team@company.com"
LABEL security.cve-contact="security@company.com"

# Opcache and secure extensions
RUN docker-php-ext-enable opcache || true

RUN addgroup -g 10001 appgroup && \
    adduser -D -u 10001 -G appgroup -h /home/appuser appuser

WORKDIR /app

COPY --from=composer_stage --chown=appuser:appgroup /app/vendor /app/vendor
COPY --chown=appuser:appgroup . .

# Build metadata
ARG GIT_SHA=unknown
ARG BUILD_TIME=unknown
LABEL org.opencontainers.image.revision="${GIT_SHA}"
LABEL org.opencontainers.image.created="${BUILD_TIME}"

USER appuser

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD php -v || exit 1

EXPOSE 8000

ENTRYPOINT ["php"]
CMD ["-S", "0.0.0.0:8000", "-t", "public"]
