from __future__ import annotations

import asyncio
import contextlib
import json
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from loguru import logger

from dockerls.domain.entities.scan_result import ScanErrorKind, ScanResult, ScanStatus
from dockerls.domain.entities.vulnerability import Severity, Vulnerability
from dockerls.domain.interfaces.scanner import ScannerInterface
from dockerls.integrations.engine.client import EngineClient, EngineOutcome, EngineTarget
from dockerls.integrations.engine.locator import find_engine, probe
from dockerls.integrations.scan_errors import classify_scanner_error
from dockerls.integrations.scan_target import blocked_scan_result, blocked_target_reason
from dockerls.integrations.trivy.cache_pool import TrivyCachePool, default_trivy_cache_dir
from dockerls.utils.executables import ExecutableNotFoundError, resolve_executable
from dockerls.utils.subprocess_runner import (
    VERSION_TIMEOUT_SECONDS,
    OutputTooLargeError,
    run_capture,
)
from dockerls.utils.validation import sanitize_image_name

if TYPE_CHECKING:
    from collections.abc import Sequence

    from dockerls.infrastructure.evidence import EvidenceStore
    from dockerls.infrastructure.network.host_guard import HostGuard


class TrivyScanner(ScannerInterface):
    def __init__(
        self,
        timeout: int = 300,
        skip_db_update: bool = False,
        cache_dir: Path | None = None,
        workers: int = 1,
        evidence: EvidenceStore | None = None,
        guard: HostGuard | None = None,
    ):
        self._timeout = timeout
        self._skip_db_update = skip_db_update
        self._workers = max(1, workers)
        self._cache_pool = TrivyCachePool(cache_dir or default_trivy_cache_dir(), workers)
        self._evidence = evidence
        self._version: str | None = None
        self._batch: _EngineBatchScanner | None = None
        # Trivy performs its own pull, so the reference has to clear the
        # network policy here or it never clears it at all.
        self._guard = guard

    @property
    def cache_pool(self) -> TrivyCachePool:
        return self._cache_pool

    @property
    def batch(self) -> _EngineBatchScanner:
        """O caminho em lote, quando a engine Go estiver disponível."""
        if self._batch is None:
            self._batch = _EngineBatchScanner(self)
        return self._batch

    def _evidence_raw_dir(self) -> Path | None:
        """Onde a engine deposita o JSON cru para este lado redigir.

        `None` quando a evidência está desligada: sem ninguém para ler e
        arquivar, gravar o documento **não redigido** em disco seria deixar
        para trás exatamente o que a redação existe para não deixar.
        """
        if self._evidence is None:
            return None
        return self._cache_pool.base_dir / "engine-raw"

    async def is_available(self) -> bool:
        return shutil.which("trivy") is not None

    async def version(self) -> str:
        """The scanner's own version string, memoised for the run.

        Recorded so an analysis can be reconstructed: a score produced by
        trivy 0.48 and one produced by 0.58 are different measurements of
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
                [resolve_executable("trivy"), "--version"], timeout=VERSION_TIMEOUT_SECONDS
            )
        except (TimeoutError, OSError, ExecutableNotFoundError) as e:
            logger.debug(f"Could not read trivy version: {e}")
            return ""
        if returncode != 0 or not stdout:
            return ""
        # `<tool> --version` prints a banner; the first line carries the
        # version and the rest is database metadata that changes on its own
        # schedule and would churn the cache key for no reason.
        return stdout.decode(errors="replace").strip().splitlines()[0].strip()

    def _cache_args(self, cache_dir: Path) -> list[str]:
        return ["--cache-dir", str(cache_dir)]

    async def generate_sbom(self, image_reference: str, fmt: str = "cyclonedx") -> str | None:
        """Generate an SBOM for `image_reference` using Trivy's built-in
        generators. `fmt` is one of "cyclonedx" or "spdx-json"."""
        if fmt not in ("cyclonedx", "spdx-json"):
            raise ValueError(f"Unsupported SBOM format: {fmt}")

        safe_ref = sanitize_image_name(image_reference)
        blocked = blocked_target_reason(safe_ref, self._guard)
        if blocked:
            logger.warning(f"Refusing to generate an SBOM for {safe_ref}: {blocked}")
            return None

        async with self._cache_pool.acquire() as cache_dir:
            try:
                cmd = [
                    resolve_executable("trivy"),
                    "image",
                    "--format",
                    fmt,
                    "--quiet",
                    *self._cache_args(cache_dir),
                ]
                if self._skip_db_update:
                    cmd.append("--skip-db-update")
                cmd.append(safe_ref)

                returncode, stdout, stderr = await run_capture(cmd, timeout=self._timeout)
                if returncode != 0 or not stdout:
                    logger.error(f"SBOM generation failed for {safe_ref}: {stderr.decode()[:300]}")
                    return None
                return stdout.decode()
            except (TimeoutError, OSError, ExecutableNotFoundError) as e:
                logger.error(f"SBOM generation failed for {safe_ref}: {e}")
                return None

    #: Tentativas do download da DB antes de desistir. A baixa vem do GHCR e
    #: falha de forma transitória com muito mais frequência que um scan: rate
    #: limit, corte de conexão no meio de centenas de MB, 5xx do registry.
    DB_DOWNLOAD_ATTEMPTS = 3
    DB_BACKOFF_SECONDS = 2.0

    async def refresh_db(self) -> bool:
        """Download the vulnerability DB once, up front, then build the
        per-worker cache dir pool.

        Doing the download here (rather than letting the first scan trigger
        it) is what makes `--skip-db-update` safe for every subsequent scan,
        and it removes the single biggest source of cache lock contention.

        Retorna False quando a DB não ficou pronta -- e isso **importa**: sem
        ela, `_skip_db_update` continua False e cada worker sai baixando a
        própria cópia em paralelo, que é precisamente a corrida que produz
        `init error: DB error` em série. Quem chama precisa tratar o False.
        """
        base = self._cache_pool.base_dir
        for attempt in range(1, self.DB_DOWNLOAD_ATTEMPTS + 1):
            ok, detail = await self._download_db(base)
            if ok:
                break
            if attempt == self.DB_DOWNLOAD_ATTEMPTS:
                logger.warning(
                    f"Trivy DB refresh failed after {attempt} attempts: {detail}. "
                    "Scans will be unable to skip the DB update."
                )
                return False
            wait = self.DB_BACKOFF_SECONDS * (2 ** (attempt - 1))
            logger.warning(
                f"Trivy DB refresh attempt {attempt}/{self.DB_DOWNLOAD_ATTEMPTS} "
                f"failed ({detail}); retrying in {wait:.0f}s"
            )
            await asyncio.sleep(wait)

        self._skip_db_update = True
        isolated = await self._cache_pool.prepare()
        logger.info(
            f"Trivy DB ready at {base}; "
            f"cache isolation {'enabled' if isolated else 'unavailable (scans serialized)'}"
        )
        return True

    async def _download_db(self, base: Path) -> tuple[bool, str]:
        """One `--download-db-only` attempt. Returns (ok, detail)."""
        try:
            returncode, _, stderr = await run_capture(
                [
                    resolve_executable("trivy"),
                    "image",
                    "--download-db-only",
                    "--quiet",
                    *self._cache_args(base),
                ],
                timeout=self._timeout,
            )
        except ExecutableNotFoundError as e:
            # Binário ausente não melhora com repetição.
            return False, str(e)
        except (TimeoutError, OSError) as e:
            return False, str(e)
        if returncode != 0:
            return False, stderr.decode(errors="replace")[:200]
        return True, ""

    async def close(self) -> None:
        await self._cache_pool.cleanup()

    async def scan(self, image_reference: str) -> ScanResult:
        safe_ref = sanitize_image_name(image_reference)
        blocked = blocked_target_reason(safe_ref, self._guard)
        if blocked:
            return blocked_scan_result(safe_ref, "trivy", blocked)
        logger.info(f"Scanning {safe_ref} with Trivy")
        timestamp = datetime.now(tz=UTC).isoformat()

        async with self._cache_pool.acquire() as cache_dir:
            try:
                cmd = [
                    resolve_executable("trivy"),
                    "image",
                    "--format",
                    "json",
                    "--severity",
                    "CRITICAL,HIGH,MEDIUM,LOW",
                    "--quiet",
                    *self._cache_args(cache_dir),
                ]
                if self._skip_db_update:
                    # A DB de Java é baixada separadamente da principal. Sem
                    # este par, o `--download-db-only` do warm-up cobria só
                    # metade: cada worker ainda saía para a rede buscar a
                    # java-db, que é a corrida que o pool de cache existe
                    # para eliminar.
                    cmd.extend(["--skip-db-update", "--skip-java-db-update"])
                cmd.append(safe_ref)

                returncode, stdout, stderr = await run_capture(cmd, timeout=self._timeout)

                if returncode != 0:
                    # Trivy writes its own diagnostics to stderr; they are
                    # captured into the log file and folded into the run
                    # summary rather than dumped raw onto the terminal.
                    err = stderr.decode(errors="replace")[:500]
                    logger.error(f"Trivy returned code {returncode} for {safe_ref}: {err}")
                    return ScanResult(
                        image_reference=safe_ref,
                        scanner="trivy",
                        scan_timestamp=timestamp,
                        status=ScanStatus.ERROR,
                        error_message=err,
                        error_kind=classify_scanner_error(err),
                    )

                if not stdout:
                    return ScanResult(
                        image_reference=safe_ref,
                        scanner="trivy",
                        scan_timestamp=timestamp,
                        status=ScanStatus.ERROR,
                        error_message="Trivy produced no output",
                        error_kind=ScanErrorKind.INVALID_OUTPUT,
                    )

                raw = stdout.decode()
                data = json.loads(raw)
                result = self._parse_results(safe_ref, data)
                if self._evidence is not None:
                    result.evidence_path = await self._evidence.record_scan(safe_ref, "trivy", raw)
                return result

            except TimeoutError:
                logger.error(f"Trivy scan timed out for {safe_ref}")
                return ScanResult(
                    image_reference=safe_ref,
                    scanner="trivy",
                    scan_timestamp=timestamp,
                    status=ScanStatus.TIMEOUT,
                    error_message=f"Scan exceeded {self._timeout}s timeout",
                    error_kind=ScanErrorKind.TIMEOUT,
                )
            except OutputTooLargeError as e:
                # Unbounded output is not a measurement: the document was
                # never read in full, so there is nothing to parse and
                # nothing to conclude.
                logger.error(f"{'trivy'} output exceeded the size limit for {safe_ref}: {e}")
                return ScanResult(
                    image_reference=safe_ref,
                    scanner="trivy",
                    scan_timestamp=timestamp,
                    status=ScanStatus.ERROR,
                    error_message=str(e),
                    error_kind=ScanErrorKind.INVALID_OUTPUT,
                )
            except json.JSONDecodeError as e:
                logger.error(f"Trivy produced unparseable JSON for {safe_ref}: {e}")
                return ScanResult(
                    image_reference=safe_ref,
                    scanner="trivy",
                    scan_timestamp=timestamp,
                    status=ScanStatus.ERROR,
                    error_message=str(e),
                    error_kind=ScanErrorKind.INVALID_OUTPUT,
                )
            except ExecutableNotFoundError as e:
                logger.error(f"Trivy scan failed for {safe_ref}: {e}")
                return ScanResult(
                    image_reference=safe_ref,
                    scanner="trivy",
                    scan_timestamp=timestamp,
                    status=ScanStatus.ERROR,
                    error_message=str(e),
                    error_kind=ScanErrorKind.SCANNER_MISSING,
                )
            except OSError as e:
                logger.error(f"Trivy scan failed for {safe_ref}: {e}")
                return ScanResult(
                    image_reference=safe_ref,
                    scanner="trivy",
                    scan_timestamp=timestamp,
                    status=ScanStatus.ERROR,
                    error_message=str(e),
                    error_kind=classify_scanner_error(str(e)),
                )

    def _parse_results(self, image_ref: str, data: dict[str, Any]) -> ScanResult:
        vulns: list[Vulnerability] = []
        for result in data.get("Results", []):
            # `Type` distingue pacote de SO ("alpine", "debian") de pacote de
            # linguagem ("node-pkg", "python-pkg"); `Target` diz onde ele mora.
            pkg_type = str(result.get("Class") or "") or str(result.get("Type") or "")
            target = str(result.get("Target") or "")
            for v in result.get("Vulnerabilities", []):
                sev_str = v.get("Severity", "UNKNOWN").upper()
                try:
                    severity = Severity(sev_str)
                except ValueError:
                    severity = Severity.UNKNOWN

                score, source = self._extract_cvss(v)
                vulns.append(
                    Vulnerability(
                        cve_id=v.get("VulnerabilityID", ""),
                        severity=severity,
                        cvss_score=score,
                        cvss_source=source,
                        package_name=v.get("PkgName", ""),
                        installed_version=v.get("InstalledVersion", ""),
                        fixed_version=v.get("FixedVersion", ""),
                        description=v.get("Title", "")[:200],
                        published_date=v.get("PublishedDate", ""),
                        package_type=pkg_type,
                        target=target,
                    )
                )

        family, version = self._parse_os(data)
        return ScanResult(
            image_reference=image_ref,
            scanner="trivy",
            vulnerabilities=vulns,
            scan_timestamp=datetime.now(tz=UTC).isoformat(),
            os_family=family,
            os_version=version,
        )

    @staticmethod
    def _parse_os(data: dict[str, Any]) -> tuple[str, str]:
        """The base distribution Trivy identified, from `Metadata.OS`.

        Reported by the scanner rather than guessed from the tag: a tag
        called `-alpine` is a naming convention, while this is what the
        package database inside the image actually is.
        """
        metadata = data.get("Metadata")
        os_block = metadata.get("OS") if isinstance(metadata, dict) else None
        if not isinstance(os_block, dict):
            return "", ""
        return str(os_block.get("Family") or ""), str(os_block.get("Name") or "")

    # Ordem de desempate quando a base que definiu a severidade não publica
    # CVSS (Debian, Alpine e Ubuntu classificam sem pontuar). NVD primeiro por
    # ser a canônica; o resto é determinístico só para que o mesmo achado
    # produza sempre o mesmo número.
    _CVSS_SOURCE_PRIORITY = ("nvd", "redhat", "ghsa", "amazon", "photon", "oracle-oval")

    def _extract_cvss(self, vuln_data: dict[str, Any]) -> tuple[float, str]:
        """Return (score, source), preferring the base that set the severity.

        O Trivy define `Severity` pela fonte em `SeveritySource` -- em geral o
        vendor da distro -- enquanto o bloco `CVSS` traz o score de várias
        bases ao mesmo tempo. Pegar a severidade de uma e o número de outra
        produzia linhas como `CRITICAL ... 7.5`, que pelo CVSS v3 é uma
        contradição (CRITICAL começa em 9.0). Não era erro de conta: eram duas
        bases diferentes exibidas como se fossem uma. Casar as duas pontas --
        e dizer qual base respondeu -- é o que torna o número conferível.
        """
        cvss = vuln_data.get("CVSS")
        if not isinstance(cvss, dict) or not cvss:
            return 0.0, ""

        severity_source = str(vuln_data.get("SeveritySource") or "").strip().lower()
        candidates: list[str] = []
        if severity_source:
            candidates.append(severity_source)
        candidates.extend(s for s in self._CVSS_SOURCE_PRIORITY if s != severity_source)
        candidates.extend(k for k in cvss if k not in candidates)

        for source in candidates:
            score = self._score_from_entry(cvss.get(source))
            if score is not None:
                return score, source
        return 0.0, ""

    @staticmethod
    def _score_from_entry(entry: dict[str, Any] | None) -> float | None:
        if not isinstance(entry, dict):
            return None
        for key in ("V4Score", "V3Score"):
            value = entry.get(key)
            if value is None:
                continue
            try:
                return float(value)
            except (TypeError, ValueError):
                continue
        return None


# ---------------------------------------------------------------------------
# Caminho em lote: a engine Go
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BatchOutcome:
    """O que um lote medido pela engine produziu."""

    #: Um resultado por alvo, na ordem em que foram pedidos.
    results: list[ScanResult]
    #: Scans que de fato aconteceram -- irmãos do mesmo digest não contam.
    scans_performed: int
    #: Alvos servidos pelo digest de um irmão.
    duplicates_collapsed: int
    #: Quanto o lote levou, medido pela engine.
    wall_seconds: float


class _EngineBatchScanner:
    """Mede um lote inteiro com uma travessia de processo, não N.

    Este é o ganho que o Go traz aqui, e é bom ser exato sobre qual é: o
    Trivy já é Go, e cada scan continua custando os mesmos 1,2-2,5s. O que
    muda é o que envolve os scans -- criar e colher N processos, revezar o
    diretório de cache, coordenar o dedup por digest -- que sai de N
    travessias Python<->processo para uma.

    Nada de política mora aqui. `sanitize_image_name` e o `HostGuard` são
    aplicados **antes** de montar a requisição, no mesmo ponto e com o
    mesmo código do caminho individual: uma referência recusada vira um
    `BLOCKED_BY_POLICY` sem nunca chegar ao binário Go.
    """

    def __init__(self, scanner: TrivyScanner) -> None:
        self._scanner = scanner
        self._client: EngineClient | None = None
        self._resolved = False

    def _resolve(self) -> EngineClient | None:
        """Localiza o binário uma vez por processo.

        `probe()` custa milissegundos e `find_engine()` toca o disco; fazer
        isso por lote seria pagar a descoberta repetidamente para uma
        resposta que não muda dentro de um run.
        """
        if self._resolved:
            return self._client
        self._resolved = True

        path = find_engine()
        if not path or not probe(path):
            return None
        try:
            scanner_path = resolve_executable("trivy")
        except ExecutableNotFoundError:
            # Sem Trivy não há o que a engine dirija, e o caminho Python
            # dará a mesma resposta -- SCANNER_MISSING -- por si.
            return None

        logger.info(f"Using the Go engine at {path} for batch scans")
        self._client = EngineClient(
            engine_path=path,
            scanner_path=scanner_path,
            timeout_seconds=float(self._scanner._timeout),
            skip_db_update=self._scanner._skip_db_update,
            raw_dir=self._scanner._evidence_raw_dir(),
        )
        return self._client

    async def scan_batch(self, targets: Sequence[tuple[str, str]]) -> BatchOutcome | None:
        """Mede `(referência, chave_de_dedup)`, ou None para usar o Python."""
        client = self._resolve()
        if client is None:
            return None

        # A política primeiro, e do lado de cá. Um alvo recusado é um
        # resultado ERROR/BLOCKED_BY_POLICY como sempre foi, e não entra na
        # requisição: o binário Go nunca vê a referência que a política
        # negou.
        blocked: dict[int, ScanResult] = {}
        allowed: list[tuple[int, EngineTarget]] = []
        for index, (reference, dedup_key) in enumerate(targets):
            safe_ref = sanitize_image_name(reference)
            reason = blocked_target_reason(safe_ref, self._scanner._guard)
            if reason:
                blocked[index] = blocked_scan_result(safe_ref, "trivy", reason)
                continue
            allowed.append((index, EngineTarget(reference=safe_ref, dedup_key=dedup_key)))

        cache_dirs = await self._scanner.cache_pool.slot_paths()
        outcome = await client.scan_batch(
            [target for _, target in allowed],
            workers=self._scanner._workers,
            cache_dirs=cache_dirs,
        )
        if outcome is None:
            return None

        results: list[ScanResult] = [None] * len(targets)  # type: ignore[list-item]
        for position, (index, _) in enumerate(allowed):
            results[index] = outcome.results[position]
        for index, result in blocked.items():
            results[index] = result

        await self._archive_evidence(outcome)
        return BatchOutcome(
            results=results,
            scans_performed=outcome.scans_performed,
            duplicates_collapsed=outcome.duplicates_collapsed,
            wall_seconds=outcome.wall_seconds,
        )

    async def _archive_evidence(self, outcome: EngineOutcome) -> None:
        """Lê o JSON cru que a engine guardou, redige e arquiva.

        A redação continua aqui de propósito: `redact()` é um controle de
        segurança, e uma segunda implementação dele em Go seria uma segunda
        a divergir desta. A engine só guarda o arquivo; quem decide o que
        vai para o disco definitivo é o EvidenceStore.
        """
        evidence = self._scanner._evidence
        if evidence is None:
            return
        for result, raw_path in zip(outcome.results, outcome.raw_paths, strict=True):
            if not raw_path:
                continue
            try:
                raw = await asyncio.to_thread(Path(raw_path).read_text, encoding="utf-8")
            except OSError as e:
                logger.warning(f"Could not read engine evidence at {raw_path}: {e}")
                continue
            finally:
                # O temporário sai do disco em qualquer caminho: ele é o
                # documento não redigido, e deixá-lo para trás desfaria a
                # redação que acabou de acontecer.
                with contextlib.suppress(OSError):
                    await asyncio.to_thread(Path(raw_path).unlink)
            result.evidence_path = await evidence.record_scan(result.image_reference, "trivy", raw)
