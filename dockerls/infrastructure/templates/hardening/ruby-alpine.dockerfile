# Dockerfile.hardened.ruby-alpine
# Hardened template for Ruby 3.3 (Alpine Linux)

ARG RUBY_VERSION=3.3-alpine

# Stage 1: Builder
FROM ruby:${RUBY_VERSION} AS builder

WORKDIR /app

RUN apk add --no-cache build-base

COPY Gemfile Gemfile.lock* ./
RUN bundle config set --local without 'development test' \
    && bundle install --jobs=4 --retry=3

# Stage 2: Runtime
FROM ruby:${RUBY_VERSION}

LABEL security.scanner="dockerls"
LABEL security.hardened="true"
LABEL maintainer="security@company.com"
LABEL security.cve-contact="security@company.com"

RUN apk update && apk upgrade --no-cache \
    && addgroup -g 10001 appgroup \
    && adduser -u 10001 -G appgroup -s /sbin/nologin -D appuser \
    && rm -rf /var/cache/apk/*

WORKDIR /app

COPY --from=builder --chown=appuser:appgroup /usr/local/bundle /usr/local/bundle
COPY --chown=appuser:appgroup . .

ARG GIT_SHA=unknown
ARG BUILD_TIME=unknown
LABEL org.opencontainers.image.revision="${GIT_SHA}"
LABEL org.opencontainers.image.created="${BUILD_TIME}"

USER appuser

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ruby -v || exit 1

EXPOSE 3000

ENTRYPOINT ["bundle", "exec"]
CMD ["ruby", "app.rb"]
