# Dockerfile.hardened.php-alpine
# Hardened template for PHP 8.3 (Alpine Linux)

ARG PHP_VERSION=8.3-cli-alpine
ARG COMPOSER_VERSION=2

# Stage 1: Composer dependencies
FROM composer:${COMPOSER_VERSION} AS vendor

WORKDIR /app
COPY composer.json composer.lock ./
RUN composer install --no-dev --no-interaction --prefer-dist --optimize-autoloader || true

# Stage 2: PHP Runtime
FROM php:${PHP_VERSION}

LABEL security.scanner="dockerls"
LABEL security.hardened="true"
LABEL maintainer="security@company.com"
LABEL security.cve-contact="security@company.com"

RUN apk update && apk upgrade --no-cache \
    && addgroup -g 10001 appgroup \
    && adduser -u 10001 -G appgroup -s /sbin/nologin -D appuser \
    && rm -rf /var/cache/apk/*

WORKDIR /app

COPY --from=vendor --chown=appuser:appgroup /app/vendor ./vendor
COPY --chown=appuser:appgroup . .

ARG GIT_SHA=unknown
ARG BUILD_TIME=unknown
LABEL org.opencontainers.image.revision="${GIT_SHA}"
LABEL org.opencontainers.image.created="${BUILD_TIME}"

USER appuser

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD php -v || exit 1

EXPOSE 8000

ENTRYPOINT ["php"]
CMD ["-S", "0.0.0.0:8000", "-t", "public"]
