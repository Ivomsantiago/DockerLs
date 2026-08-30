# Dockerfile.hardened.ruby-debian
# Hardened template for Ruby 3.3 (Debian Bookworm Slim)

ARG RUBY_VERSION=3.3-slim-bookworm

# Stage 1: Builder
FROM ruby:${RUBY_VERSION} AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY Gemfile Gemfile.lock* ./
RUN bundle config set --local without 'development test' \
    && bundle install --jobs=4 --retry=3

# Stage 2: Runtime
FROM ruby:${RUBY_VERSION}

LABEL security.scanner="dockerls"
LABEL security.hardened="true"
LABEL maintainer="security@company.com"
LABEL security.cve-contact="security@company.com"

RUN apt-get update && apt-get upgrade -y \
    && groupadd -g 10001 appgroup \
    && useradd -u 10001 -g appgroup -s /usr/sbin/nologin -m appuser \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

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
