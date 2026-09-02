from __future__ import annotations

import json
import os
import shutil
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from loguru import logger

from dockerls.domain.entities.scan_result import ScanErrorKind, ScanResult, ScanStatus
from dockerls.domain.entities.vulnerability import Severity, Vulnerability
from dockerls.domain.interfaces.scanner import ScannerInterface
from dockerls.integrations.engine.batch import EngineBatchScanner
from dockerls.integrations.scan_errors import classify_scanner_error
from dockerls.integrations.scan_target import blocked_scan_result, blocked_target_reason
from dockerls.utils.executables import ExecutableNotFoundError, resolve_executable
from dockerls.utils.subprocess_runner import (
    VERSION_TIMEOUT_SECONDS,
    OutputTooLargeError,
    run_capture,
)
from dockerls.utils.validation import sanitize_image_name

if TYPE_CHECKING:
    from dockerls.infrastructure.evidence import EvidenceStore
    from dockerls.infrastructure.network.host_guard import HostGuard


def _safe_list(value: Any) -> list[Any]:
    """`value` as a list, or `[]` for anything else -- missing key, explicit
    `null`, or a scalar where Grype's schema promises an array."""
    return value if isinstance(value, list) else []


class GrypeScanner(ScannerInterface):
    def __init__(
        self,
        timeout: int = 300,
        evidence: EvidenceStore | None = None,
        guard: HostGuard | None = None,
        workers: int = 1,
    ):
        self._timeout = timeout
        self._evidence = evidence
        self._version: str | None = None
        self._skip_db_update = False
        self._batch: EngineBatchScanner | None = None
        self._workers = max(1, workers)
        # Grype pulls the image itself, so the reference has to clear the
        # network policy here or it never clears it at all.
        self._guard = guard

    @property
    def batch(self) -> EngineBatchScanner:
        """O caminho em lote, quando a engine Go estiver disponível.

        O Grype não tem `--cache-dir`: a base dele mora num diretório único
        e o que desliga a atualização automática são variáveis de ambiente.
        Por isso o lote vai sem diretórios de cache e com o mesmo par de
        variáveis que o caminho individual usa -- e a engine sabe que, sem
        o lock BoltDB do Trivy, não há motivo para serializar.
        """
        if self._batch is None:
            self._batch = EngineBatchScanner(
                scanner="grype",
                timeout_seconds=float(self._timeout),
                skip_db_update=self._skip_db_update,
                workers=self._workers,
                guard=self._guard,
                evidence=self._evidence,
                raw_dir=None,
                # Só o par que interessa, e nunca `_scan_env()`: aquele
                # devolve `os.environ.copy()` inteiro, e mandá-lo pela
                # fronteira escreveria DOCKERHUB_TOKEN e companhia dentro
                # de um documento JSON. A engine soma o que recebe ao
                # ambiente que ela própria herdou.
                env=self._batch_env(),
            )
        return self._batch

    def _batch_env(self) -> dict[str, str]:
        """As variáveis que o lote precisa, e só elas."""
        if not self._skip_db_update:
            return {}
        return {"GRYPE_DB_AUTO_UPDATE": "false", "GRYPE_CHECK_FOR_APP_UPDATE": "false"}

    async def is_available(self) -> bool:
        return shutil.which("grype") is not None

    async def version(self) -> str:
        """The scanner's own version string, memoised for the run.

        Recorded so an analysis can be reconstructed: a score produced by
        grype 0.48 and one produced by 0.58 are different measurements of
        the same image, and until this existed nothing wrote down which one
        happened. It is also what keeps a cached result from being served
        across a scanner upgrade.

        Returns "" when the binary is missing or does not answer -- an
        unknown version, which the cache key treats as its own value rather
        than as "same as before".
        """
        if self._version is not None:
            return self._version
        self._version = await self._read_version()
        return self._version

    async def _read_version(self) -> str:
        try:
            returncode, stdout, _ = await run_capture(
                [resolve_executable("grype"), "--version"], timeout=VERSION_TIMEOUT_SECONDS
            )
        except (TimeoutError, OSError, ExecutableNotFoundError) as e:
            logger.debug(f"Could not read grype version: {e}")
            return ""
        if returncode != 0 or not stdout:
            return ""
        # `<tool> --version` prints a banner; the first line carries the
        # version and the rest is database metadata that changes on its own
        # schedule and would churn the cache key for no reason.
        return stdout.decode(errors="replace").strip().splitlines()[0].strip()

    def _scan_env(self) -> dict[str, str] | None:
        """Environment for a scan invocation.

        Left at None until the DB has been refreshed once, so a scanner used
        without `refresh_db()` still behaves exactly as before.
        """
        if not self._skip_db_update:
            return None
        env = os.environ.copy()
        env["GRYPE_DB_AUTO_UPDATE"] = "false"
        env["GRYPE_CHECK_FOR_APP_UPDATE"] = "false"
        return env

    async def refresh_db(self) -> bool:
        """Update the vulnerability DB once, up front.

        Grype otherwise checks its DB freshness on *every* invocation, which
        is a network round trip per scan -- the dominant cost when
        cross-validating several images. After this succeeds, scans run with
        GRYPE_DB_AUTO_UPDATE=false so they go straight to matching.
        """
        try:
            returncode, _, stderr = await run_capture(
                [resolve_executable("grype"), "db", "update"], timeout=self._timeout
            )
            if returncode != 0:
                logger.warning(f"Grype DB refresh failed: {stderr.decode()[:200]}")
                return False
        except (TimeoutError, OSError, ExecutableNotFoundError) as e:
            logger.warning(f"Grype DB refresh failed: {e}")
            return False

        self._skip_db_update = True
        logger.info("Grype DB ready; per-scan auto-update disabled")
        return True

    async def scan(self, image_reference: str) -> ScanResult:
        safe_ref = sanitize_image_name(image_reference)
        blocked = blocked_target_reason(safe_ref, self._guard)
        if blocked:
            return blocked_scan_result(safe_ref, "grype", blocked)
        logger.info(f"Scanning {safe_ref} with Grype")
        timestamp = datetime.now(tz=UTC).isoformat()

        try:
            returncode, stdout, stderr = await run_capture(
                [resolve_executable("grype"), safe_ref, "-o", "json", "--quiet"],
                timeout=self._timeout,
                env=self._scan_env(),
            )

            if returncode != 0:
                err = stderr.decode(errors="replace")[:500]
                logger.error(f"Grype returned code {returncode} for {safe_ref}: {err}")
                return ScanResult(
                    image_reference=safe_ref,
                    scanner="grype",
                    scan_timestamp=timestamp,
                    status=ScanStatus.ERROR,
                    error_message=err,
                    error_kind=classify_scanner_error(err),
                )

            if not stdout:
                return ScanResult(
                    image_reference=safe_ref,
                    scanner="grype",
                    scan_timestamp=timestamp,
                    status=ScanStatus.ERROR,
                    error_message="Grype produced no output",
                    error_kind=ScanErrorKind.INVALID_OUTPUT,
                )

            raw = stdout.decode()
            data = json.loads(raw)
            result = self._parse_results(safe_ref, data)
            if self._evidence is not None:
                result.evidence_path = await self._evidence.record_scan(safe_ref, "grype", raw)
            return result

        except OutputTooLargeError as e:
            # Unbounded output is not a measurement: the document was never
            # read in full, so there is nothing to parse and nothing to
            # conclude. INVALID_OUTPUT is already a non-verified state.
            logger.error(f"Grype output exceeded the size limit for {safe_ref}: {e}")
            return ScanResult(
                image_reference=safe_ref,
                scanner="grype",
                scan_timestamp=timestamp,
                status=ScanStatus.ERROR,
                error_message=str(e),
                error_kind=ScanErrorKind.INVALID_OUTPUT,
            )
        except TimeoutError:
            logger.error(f"Grype scan timed out for {safe_ref}")
            return ScanResult(
                image_reference=safe_ref,
                scanner="grype",
                scan_timestamp=timestamp,
                status=ScanStatus.TIMEOUT,
                error_message=f"Scan exceeded {self._timeout}s timeout",
                error_kind=ScanErrorKind.TIMEOUT,
            )
        except json.JSONDecodeError as e:
            logger.error(f"Grype produced unparseable JSON for {safe_ref}: {e}")
            return ScanResult(
                image_reference=safe_ref,
                scanner="grype",
                scan_timestamp=timestamp,
                status=ScanStatus.ERROR,
                error_message=str(e),
                error_kind=ScanErrorKind.INVALID_OUTPUT,
            )
        except ExecutableNotFoundError as e:
            logger.error(f"Grype scan failed for {safe_ref}: {e}")
            return ScanResult(
                image_reference=safe_ref,
                scanner="grype",
                scan_timestamp=timestamp,
                status=ScanStatus.ERROR,
                error_message=str(e),
                error_kind=ScanErrorKind.SCANNER_MISSING,
            )
        except OSError as e:
            logger.error(f"Grype scan failed for {safe_ref}: {e}")
            return ScanResult(
                image_reference=safe_ref,
                scanner="grype",
                scan_timestamp=timestamp,
                status=ScanStatus.ERROR,
                error_message=str(e),
                error_kind=classify_scanner_error(str(e)),
            )

    def _parse_results(self, image_ref: str, data: dict[str, Any]) -> ScanResult:
        """Convert Grype's JSON into vulnerabilities, without trusting any
        single field to be present, of the right type, or non-null.

        `.get(key, default)` only supplies the default for a *missing* key;
        Grype emits explicit nulls for several of these (an advisory with no
        description, no fix, no CVSS), and each null used to sail past its
        default and break on the next `.upper()`, slice, or nested `.get()`
        -- turning a completed scan into an ERROR result instead of a
        finding with an empty field.
        """
        vulns: list[Vulnerability] = []
        for match in _safe_list(data.get("matches")):
            if not isinstance(match, dict):
                continue
            vd = match.get("vulnerability")
            vd = vd if isinstance(vd, dict) else {}
            sev_str = str(vd.get("severity") or "Unknown").upper()
            if sev_str == "NEGLIGIBLE":
                sev_str = "LOW"
            try:
                severity = Severity(sev_str)
            except ValueError:
                severity = Severity.UNKNOWN

            artifact = match.get("artifact")
            artifact = artifact if isinstance(artifact, dict) else {}
            fix = vd.get("fix")
            fixed_versions = fix.get("versions") if isinstance(fix, dict) else None
            fixed_versions = fixed_versions if isinstance(fixed_versions, list) else []
            fixed_version = fixed_versions[0] if fixed_versions else ""

            cvss_score, cvss_source = self._extract_cvss(_safe_list(vd.get("cvss")))

            vulns.append(
                Vulnerability(
                    cve_id=str(vd.get("id") or ""),
                    severity=severity,
                    cvss_score=cvss_score,
                    cvss_source=cvss_source,
                    package_name=str(artifact.get("name") or ""),
                    installed_version=str(artifact.get("version") or ""),
                    fixed_version=str(fixed_version or ""),
                    description=str(vd.get("description") or "")[:200],
                    package_type=str(artifact.get("type") or ""),
                    target=self._first_location_path(artifact.get("locations")),
                )
            )

        family, version = self._parse_distro(data)
        return ScanResult(
            image_reference=image_ref,
            scanner="grype",
            vulnerabilities=vulns,
            scan_timestamp=datetime.now(tz=UTC).isoformat(),
            os_family=family,
            os_version=version,
        )

    @staticmethod
    def _first_location_path(locations: Any) -> str:
        """The path of the first location entry, or "" for anything that
        isn't a non-empty list of dicts -- `null`, `[]`, or a list holding a
        bare string/`None` instead of the expected `{"path": ...}` shape."""
        for entry in _safe_list(locations):
            if isinstance(entry, dict):
                return str(entry.get("path") or "")
            break
        return ""

    @staticmethod
    def _parse_distro(data: dict[str, Any]) -> tuple[str, str]:
        """The base distribution Grype identified, from its `distro` block.

        Same fact Trivy reports under `Metadata.OS`, spelled differently.
        Normalising it here means the migration analysis reads one field
        regardless of which scanner produced the result.
        """
        distro = data.get("distro")
        if not isinstance(distro, dict):
            return "", ""
        return str(distro.get("name") or ""), str(distro.get("version") or "")

    @staticmethod
    def _extract_cvss(entries: list[dict[str, Any]]) -> tuple[float, str]:
        """Deterministic CVSS selection: NVD source > any other vendor
        source > first available, instead of an arbitrary max() across
        differently-scored advisories. Returns (score, source) so the report
        can say which base produced the number."""
        # A non-dict member (a bare string, a null slipped into the array)
        # is as unusable as an absent list -- skip it rather than let
        # `.get("source", ...)` raise on something that isn't a mapping.
        dict_entries = [e for e in entries if isinstance(e, dict)]
        if not dict_entries:
            return 0.0, ""

        def base_score(entry: dict[str, Any]) -> float:
            # Grype emits `"metrics": null` for advisories with no CVSS
            # vector, and a null/non-numeric score must read as "unscored",
            # not blow up the whole parse of an otherwise good scan.
            metrics = entry.get("metrics") or {}
            if not isinstance(metrics, dict):
                return 0.0
            try:
                return float(metrics.get("baseScore", 0.0))
            except (TypeError, ValueError):
                return 0.0

        for entry in dict_entries:
            source = str(entry.get("source", ""))
            if "nvd" in source.lower():
                return base_score(entry), source or "nvd"

        return base_score(dict_entries[0]), str(dict_entries[0].get("source", ""))
