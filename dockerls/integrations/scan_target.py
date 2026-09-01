"""Refuse a scan target the network policy would not let us contact.

`trivy image X` and `grype X` open their own sockets. The SSRF guard that
protects the registry inspector never saw those pulls, so a reference like
`169.254.169.254/latest:v1` -- syntactically valid, and arriving from a CI
variable, a config file or a pull request -- aimed the scanner's connection
at the cloud metadata endpoint while the guarded door stayed shut.

The check runs *before* the binary is invoked, and its refusal is an
`ERROR` result with `BLOCKED_BY_POLICY`, never an empty finding list: an
image nobody was allowed to measure has not been measured, and the whole
pipeline already treats an unmeasured image as unverified rather than clean.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from loguru import logger

from dockerls.domain.entities.scan_result import ScanErrorKind, ScanResult, ScanStatus
from dockerls.domain.value_objects.image_reference import registry_host_of

if TYPE_CHECKING:
    from dockerls.infrastructure.network.host_guard import HostGuard


def blocked_target_reason(reference: str, guard: HostGuard | None) -> str:
    """Why `reference` may not be scanned, or "" when it may.

    No guard means no policy was configured for this scanner, and the answer
    is "" -- the caller decides whether to run unguarded. Docker Hub
    references carry no host and are never judged: contacting Docker Hub is
    what this tool is for.
    """
    if guard is None:
        return ""
    host = registry_host_of(reference)
    if not host:
        return ""
    if guard.allows(host):
        return ""
    return guard.explain(host)


def blocked_scan_result(reference: str, scanner: str, reason: str) -> ScanResult:
    """The result a refused target produces: an error, not an empty scan."""
    logger.warning(f"Refusing to scan {reference} with {scanner}: {reason}")
    return ScanResult(
        image_reference=reference,
        scanner=scanner,
        scan_timestamp=datetime.now(tz=UTC).isoformat(),
        status=ScanStatus.ERROR,
        error_message=reason,
        error_kind=ScanErrorKind.BLOCKED_BY_POLICY,
    )


def invalid_reference_scan_result(reference: str, scanner: str, reason: str) -> ScanResult:
    """The result an unparseable target produces: an error naming *this*
    reference, not an exception that aborts every other target in the same
    batch.

    A single malformed entry -- a stray CLI-option lookalike, a name over
    the length limit -- reaching `sanitize_image_name` inside a batch loop
    used to raise `ValueError` past the loop entirely, turning one bad tag
    into a hard failure for every other tag queued alongside it.
    """
    logger.warning(f"Refusing to scan {reference!r} with {scanner}: {reason}")
    return ScanResult(
        image_reference=reference,
        scanner=scanner,
        scan_timestamp=datetime.now(tz=UTC).isoformat(),
        status=ScanStatus.ERROR,
        error_message=reason,
        error_kind=ScanErrorKind.UNKNOWN,
    )
