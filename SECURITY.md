# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability in DockerLs, please report it responsibly.

**Do not open a public issue.**

Use GitHub's private vulnerability reporting for this repository:
[Report a vulnerability](https://github.com/Ivomsantiago/DockerLs/security/advisories/new).

That form is the only official reporting channel — it keeps the report private
until a fix is released and notifies the maintainers directly.

### What to include

- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (if any)

### Response timeline

- Acknowledgment: within 48 hours
- Initial assessment: within 1 week
- Fix and disclosure: coordinated with reporter

## Security Design

DockerLs follows these security principles:

### Input validation
- All image names are validated against a strict regex pattern
- Path traversal attacks are blocked
- Command injection is prevented (no shell=True, no string interpolation in commands)

### Credential handling
- Credentials are stored in the system keyring (never in plaintext files)
- Environment variables are supported as an alternative
- All credentials are masked in log output
- Bearer tokens and passwords are filtered from structured logging

### Network security
- All HTTP requests use HTTPS
- Timeouts are enforced on all external calls
- Retry logic uses exponential backoff to avoid overwhelming services
- Rate limiting is respected

### Supply chain
- Dependencies are pinned in pyproject.toml
- Dependabot monitors for vulnerable dependencies
- pip-audit runs in CI
- Docker image uses multi-stage builds with specific version tags

### Container security
- Non-root user in Docker image
- Read-only filesystem support
- All capabilities dropped
- No new privileges flag
- Healthcheck configured
