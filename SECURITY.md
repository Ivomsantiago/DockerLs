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

### Scanner installation (`dockerls doctor --install`)

`doctor --install` downloads Trivy or Grype from their GitHub releases on
your behalf. Two independent checks apply, and it matters which ones
actually ran for the binary you ended up with:

1. **SHA-256, always.** The archive is checked against the checksum line
   published in that release's `checksums.txt`. This runs for every
   install, unconditionally, and an install aborts if it fails.
2. **Cosign keyless signature on `checksums.txt`, conditionally.** When
   `cosign` is on `PATH` *and* the project is known to publish
   `checksums.txt.sig`/`checksums.txt.pem` next to its `checksums.txt`,
   `doctor` runs `cosign verify-blob` against a pinned signer identity and
   OIDC issuer before trusting the checksum file at all — an invalid
   signature aborts the install outright.

That second check is currently confirmed only for **Grype**, whose own
`install.sh` verifies its release the same way. **Trivy is not currently
known to sign its `checksums.txt`**, so a Trivy install is checksum-only:
it downloads over HTTPS from GitHub and verifies SHA-256, with no signature
of the checksum file itself. This is not a project decision to skip Trivy —
it is an unconfirmed fact recorded as an unconfirmed fact rather than
guessed either way. `doctor --install` reports which check actually ran for
each binary it installs; do not assume a signature was verified just
because `cosign` is installed on your machine.

If your threat model requires signed provenance for every scanner binary,
verify Trivy's release out-of-band before running `doctor --install`, or
install it through a channel you already trust (a pinned OS package, a
container image you already verify).

### Container security
- Non-root user in Docker image
- Read-only filesystem support
- All capabilities dropped
- No new privileges flag
- Healthcheck configured
