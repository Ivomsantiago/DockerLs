"""Fala com o binário Go que mede um lote de imagens de uma vez.

O que a engine é: um pool de goroutines em volta do Trivy. Ela recebe um
lote de referências já sanitizadas e já aprovadas pela política de rede,
dispara os scans com paralelismo limitado e rodízio de diretório de cache,
e devolve um documento JSON.

O que a engine **não** é, e por que:

* **não decide política.** `HostGuard` e `sanitize_image_name` continuam do
  lado Python, e este cliente os aplica *antes* de montar a requisição. Uma
  referência recusada nunca chega ao Go -- ela vira um resultado
  `BLOCKED_BY_POLICY` aqui mesmo, pelo mesmo caminho de sempre.
  Reimplementar um controle de segurança em outra linguagem é criar uma
  segunda cópia dele para divergir da primeira;
* **não redige segredo.** O JSON cru volta como caminho de arquivo, e é
  `redact()` -- o mesmo do sink de log e do EvidenceStore -- que decide o
  que vai para o disco definitivo;
* **não pontua nada.** Score, tier, EOL, KEV, EPSS e ranking seguem no
  Python, onde estão os testes que os travam.

Qualquer falha deste caminho -- binário ausente, versão incompatível,
timeout, saída ilegível -- devolve `None`, e o chamador roda o pipeline
Python. A engine é uma otimização, e uma otimização que pode derrubar o
comando não vale o ganho.
"""

from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from loguru import logger

from dockerls.domain.entities.scan_result import ScanErrorKind, ScanResult, ScanStatus
from dockerls.domain.entities.vulnerability import Severity, Vulnerability
from dockerls.integrations.engine.locator import PROTOCOL_VERSION
from dockerls.utils.subprocess_runner import MAX_OUTPUT_BYTES

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

#: Teto do documento de resposta. Um lote de cem imagens muito ruidosas
#: produz alguns MiB; o teto existe para que uma engine adulterada não vire
#: consumo de memória sem limite deste lado da fronteira.
MAX_RESPONSE_BYTES = 512 * 1024 * 1024

#: Folga sobre a soma dos timeouts individuais. A engine já limita cada
#: scan; isto só cobre o caso de ela própria travar sem medir nada.
_ENGINE_OVERHEAD_SECONDS = 30.0


@dataclass(frozen=True)
class EngineTarget:
    """Uma imagem a medir, com a chave que a une aos irmãos do mesmo digest."""

    reference: str
    dedup_key: str


@dataclass(frozen=True)
class EngineOutcome:
    """O que o lote produziu."""

    #: Resultado por referência, na ordem em que os alvos foram pedidos.
    results: list[ScanResult]
    #: Caminho do JSON cru de cada resultado, na mesma ordem, ou "" quando
    #: não houve (evidência desligada, ou resultado servido pelo digest de
    #: um irmão -- a evidência pertence ao scan que realmente aconteceu).
    raw_paths: list[str]
    #: Quantos scans de fato aconteceram (irmãos de digest não contam).
    scans_performed: int
    #: Quantos alvos foram servidos pelo digest de um irmão.
    duplicates_collapsed: int
    #: Quanto o lote inteiro levou, medido pela engine.
    wall_seconds: float


class EngineClient:
    """Executa a engine uma vez por lote."""

    def __init__(
        self,
        engine_path: str,
        scanner_path: str,
        *,
        timeout_seconds: float,
        skip_db_update: bool,
        raw_dir: Path | None,
    ) -> None:
        self._engine_path = engine_path
        self._scanner_path = scanner_path
        self._timeout_seconds = timeout_seconds
        self._skip_db_update = skip_db_update
        self._raw_dir = raw_dir

    async def scan_batch(
        self,
        targets: Sequence[EngineTarget],
        *,
        workers: int,
        cache_dirs: Sequence[Path],
    ) -> EngineOutcome | None:
        """Mede o lote, ou devolve None para o chamador usar o caminho Python."""
        if not targets:
            return EngineOutcome(
                results=[],
                raw_paths=[],
                scans_performed=0,
                duplicates_collapsed=0,
                wall_seconds=0.0,
            )

        request = {
            "version": PROTOCOL_VERSION,
            "scanner": "trivy",
            "scanner_path": self._scanner_path,
            "workers": workers,
            "timeout_seconds": self._timeout_seconds,
            "skip_db_update": self._skip_db_update,
            "max_output_bytes": MAX_OUTPUT_BYTES,
            "cache_dirs": [str(d) for d in cache_dirs],
            "raw_dir": str(self._raw_dir) if self._raw_dir else "",
            "targets": [{"reference": t.reference, "dedup_key": t.dedup_key} for t in targets],
        }

        payload = await self._run(json.dumps(request).encode(), len(targets))
        if payload is None:
            return None
        return self._decode(payload, targets)

    async def _run(self, request: bytes, target_count: int) -> dict[str, Any] | None:
        # Teto do run inteiro: a engine já limita cada scan, mas o número
        # de scans é conhecido só aqui.
        budget = self._timeout_seconds * max(1, target_count) + _ENGINE_OVERHEAD_SECONDS
        try:
            process = await asyncio.create_subprocess_exec(
                self._engine_path,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                # Grupo próprio, para que um Ctrl-C aqui derrube a engine e
                # os scanners que ela abriu, e não só este processo.
                start_new_session=True,
            )
        except OSError as e:
            logger.warning(f"Could not start the Go engine: {e}")
            return None

        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(request), timeout=budget)
        except TimeoutError:
            logger.warning(f"The Go engine exceeded its {budget:.0f}s budget; killing it")
            await self._kill(process)
            return None
        except (OSError, ValueError) as e:
            logger.warning(f"The Go engine failed: {e}")
            await self._kill(process)
            return None

        if process.returncode != 0:
            detail = stderr.decode(errors="replace")[:500]
            logger.warning(f"The Go engine exited {process.returncode}: {detail}")
            return None
        if len(stdout) > MAX_RESPONSE_BYTES:
            logger.warning("The Go engine produced a response beyond the size limit")
            return None

        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError as e:
            logger.warning(f"The Go engine produced unparseable JSON: {e}")
            return None
        if not isinstance(payload, dict):
            logger.warning("The Go engine produced a document that is not an object")
            return None
        return payload

    @staticmethod
    async def _kill(process: asyncio.subprocess.Process) -> None:
        """Encerra a engine e a colhe.

        Sem o `wait` a engine vira zumbi e os scanners que ela abriu ficam
        segurando o lock do cache -- que é a contenção que o pool de
        diretórios existe para eliminar.
        """
        if process.returncode is not None:
            return
        try:
            os.killpg(os.getpgid(process.pid), 15)
        except (OSError, ProcessLookupError):
            with_fallback = getattr(process, "kill", None)
            if with_fallback is not None:
                with_fallback()
        try:
            await asyncio.wait_for(process.wait(), timeout=5.0)
        except (TimeoutError, ProcessLookupError):
            logger.warning("The Go engine did not exit after being signalled")

    def _decode(
        self, payload: dict[str, Any], targets: Sequence[EngineTarget]
    ) -> EngineOutcome | None:
        if payload.get("version") != PROTOCOL_VERSION:
            logger.warning(
                f"The Go engine answered with protocol {payload.get('version')!r}, "
                f"but this CLI speaks {PROTOCOL_VERSION}"
            )
            return None
        fatal = payload.get("fatal_error")
        if fatal:
            logger.warning(f"The Go engine refused the batch: {fatal}")
            return None

        raw_results = payload.get("results")
        if not isinstance(raw_results, list) or len(raw_results) != len(targets):
            got = len(raw_results) if isinstance(raw_results, list) else "no"
            logger.warning(f"The Go engine answered {got} results for {len(targets)} targets")
            return None

        metrics = payload.get("metrics")
        metrics = metrics if isinstance(metrics, dict) else {}

        return EngineOutcome(
            results=[_scan_result_from(entry) for entry in raw_results],
            raw_paths=[raw_path_of(entry) for entry in raw_results],
            scans_performed=_as_int(metrics.get("scans_performed")),
            duplicates_collapsed=_as_int(metrics.get("duplicates_collapsed")),
            wall_seconds=_as_float(metrics.get("wall_seconds")),
        )


def _scan_result_from(entry: Any) -> ScanResult:
    """Converte um resultado da engine no `ScanResult` do domínio.

    Um campo que a engine não reconhece vira o default do domínio em vez de
    exceção: o documento vem de um processo separado, e um campo estranho é
    motivo para desconfiar dele, não para derrubar o run.
    """
    if not isinstance(entry, dict):
        return ScanResult(
            image_reference="",
            status=ScanStatus.ERROR,
            error_message="the engine returned a result that is not an object",
            error_kind=ScanErrorKind.INVALID_OUTPUT,
        )

    return ScanResult(
        image_reference=str(entry.get("image_reference") or ""),
        scanner=str(entry.get("scanner") or "trivy"),
        vulnerabilities=[_vulnerability_from(v) for v in _as_list(entry.get("vulnerabilities"))],
        scan_timestamp=str(entry.get("scan_timestamp") or ""),
        status=_as_enum(ScanStatus, entry.get("status"), ScanStatus.ERROR),
        error_message=str(entry.get("error_message") or ""),
        error_kind=_as_enum(ScanErrorKind, entry.get("error_kind"), ScanErrorKind.UNKNOWN),
        os_family=str(entry.get("os_family") or ""),
        os_version=str(entry.get("os_version") or ""),
    )


def _vulnerability_from(entry: Any) -> Vulnerability:
    if not isinstance(entry, dict):
        return Vulnerability(cve_id="", severity=Severity.UNKNOWN)
    # Os campos de inteligência de ameaça (KEV, EPSS, Exploit-DB) ficam
    # deliberadamente de fora: a engine não os consulta, e um default
    # `False` atravessando a fronteira viraria "consultado e negativo" --
    # exatamente a confusão que o Tristate existe para impedir.
    return Vulnerability(
        cve_id=str(entry.get("cve_id") or ""),
        severity=_as_enum(Severity, entry.get("severity"), Severity.UNKNOWN),
        cvss_score=_as_float(entry.get("cvss_score")),
        cvss_source=str(entry.get("cvss_source") or ""),
        package_type=str(entry.get("package_type") or ""),
        target=str(entry.get("target") or ""),
        package_name=str(entry.get("package_name") or ""),
        installed_version=str(entry.get("installed_version") or ""),
        fixed_version=str(entry.get("fixed_version") or ""),
        description=str(entry.get("description") or ""),
        published_date=str(entry.get("published_date") or ""),
    )


def raw_path_of(entry: Any) -> str:
    """O arquivo temporário com o JSON cru, quando a engine guardou um."""
    if not isinstance(entry, dict):
        return ""
    return str(entry.get("raw_path") or "")


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _as_int(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _as_float(value: Any) -> float:
    return float(value) if isinstance(value, int | float) and not isinstance(value, bool) else 0.0


def _as_enum(enum_cls: Any, value: Any, default: Any) -> Any:
    try:
        return enum_cls(str(value))
    except ValueError:
        return default
