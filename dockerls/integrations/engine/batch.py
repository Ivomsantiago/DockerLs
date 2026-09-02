"""Medir um lote com a engine Go, sem tirar nenhuma decisão do Python.

Este módulo é a fronteira, e ela é estreita de propósito. A engine recebe
referências **já sanitizadas e já aprovadas pela política de rede**, e
devolve resultados. Tudo que decide alguma coisa continua deste lado:

* `sanitize_image_name` e o `HostGuard` são aplicados aqui, antes de a
  requisição existir. `trivy image X` e `grype X` abrem os próprios
  sockets, e foi para cobrir esse buraco que `scan_target.py` existe -- um
  lote que contornasse o guard abriria a mesma porta em nome de desempenho;
* `redact()` continua aqui. A engine guarda o JSON cru em arquivo `0600` e
  devolve o caminho; quem decide o que vai para a evidência definitiva é o
  `EvidenceStore`;
* nada de score, tier, EOL ou inteligência de ameaça atravessa.

Serve Trivy e Grype: o que difere entre os dois -- argv, forma do JSON,
diretório de cache versus variável de ambiente -- está inteiramente do lado
Go. Aqui os dois são o mesmo lote.
"""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from loguru import logger

from dockerls.integrations.engine.client import EngineClient, EngineTarget
from dockerls.integrations.engine.locator import find_engine, probe
from dockerls.integrations.scan_target import (
    blocked_scan_result,
    blocked_target_reason,
    invalid_reference_scan_result,
)
from dockerls.utils.executables import ExecutableNotFoundError, resolve_executable
from dockerls.utils.validation import sanitize_image_name

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Mapping, Sequence

    from dockerls.domain.entities.scan_result import ScanResult
    from dockerls.infrastructure.evidence import EvidenceStore
    from dockerls.infrastructure.network.host_guard import HostGuard
    from dockerls.integrations.engine.client import EngineOutcome


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


class EngineBatchScanner:
    """Mede um lote inteiro com uma travessia de processo, não N.

    O ganho é bom ser exato sobre qual é: Trivy e Grype já são Go, e cada
    scan continua custando os mesmos 1,2-2,5s. O que muda é o entorno --
    criar e colher N processos, revezar o diretório de cache, coordenar o
    dedup por digest --, que sai de N travessias Python<->processo para uma.
    """

    def __init__(
        self,
        *,
        scanner: str,
        timeout_seconds: float,
        skip_db_update: bool,
        workers: int,
        guard: HostGuard | None = None,
        evidence: EvidenceStore | None = None,
        raw_dir: Path | None = None,
        cache_dirs: Callable[[], Awaitable[Sequence[Path]]] | None = None,
        env: Mapping[str, str] | None = None,
    ) -> None:
        self._scanner = scanner
        self._timeout_seconds = timeout_seconds
        self._skip_db_update = skip_db_update
        self._workers = workers
        self._guard = guard
        self._evidence = evidence
        self._raw_dir = raw_dir
        self._cache_dirs = cache_dirs
        self._env = dict(env or {})
        self._client: EngineClient | None = None
        self._resolved = False

    def _resolve(self) -> EngineClient | None:
        """Localiza o binário uma vez por processo.

        `probe()` custa milissegundos e `find_engine()` toca o disco; fazer
        isso por lote seria pagar a descoberta repetidamente por uma
        resposta que não muda dentro de um run.
        """
        if self._resolved:
            return self._client
        self._resolved = True

        path = find_engine()
        if not path or not probe(path):
            return None
        try:
            scanner_path = resolve_executable(self._scanner)
        except ExecutableNotFoundError:
            # Sem o scanner não há o que a engine dirija, e o caminho Python
            # dará a mesma resposta -- SCANNER_MISSING -- por si.
            return None

        logger.info(f"Using the Go engine at {path} for {self._scanner} batch scans")
        self._client = EngineClient(
            engine_path=path,
            scanner=self._scanner,
            scanner_path=scanner_path,
            timeout_seconds=self._timeout_seconds,
            skip_db_update=self._skip_db_update,
            raw_dir=self._raw_dir,
            env=self._env,
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
            # One malformed reference is that reference's problem, not the
            # whole batch's: an unhandled `ValueError` here used to abort
            # every other, perfectly valid target queued alongside it.
            try:
                safe_ref = sanitize_image_name(reference)
            except ValueError as e:
                blocked[index] = invalid_reference_scan_result(reference, self._scanner, str(e))
                continue
            reason = blocked_target_reason(safe_ref, self._guard)
            if reason:
                blocked[index] = blocked_scan_result(safe_ref, self._scanner, reason)
                continue
            allowed.append((index, EngineTarget(reference=safe_ref, dedup_key=dedup_key)))

        cache_dirs = list(await self._cache_dirs()) if self._cache_dirs is not None else []
        outcome = await client.scan_batch(
            [target for _, target in allowed],
            workers=self._workers,
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
        evidence = self._evidence
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
            result.evidence_path = await evidence.record_scan(
                result.image_reference, self._scanner, raw
            )
