# Dockerfile.hardened.php-debian
# Hardened template for PHP 8.3 (Debian Bookworm Slim)

ARG PHP_VERSION=8.3-cli-bookworm
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

RUN apt-get update && apt-get upgrade -y \
    && groupadd -g 10001 appgroup \
    && useradd -u 10001 -g appgroup -s /usr/sbin/nologin -m appuser \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

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
