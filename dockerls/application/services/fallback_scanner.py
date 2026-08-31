"""Um scanner que tenta o secundário quando o primário falha por culpa própria.

O fallback para o Grype existia só na *escolha* do scanner: `ScannerFactory`
olhava `is_available()` -- que é `shutil.which(...)` -- e, se o binário do
Trivy estivesse no PATH, o Grype nunca mais entrava na conversa. Um Trivy
instalado porém quebrado (DB corrompida, sem rede para baixá-la, timeout) não
acionava fallback nenhum: as tags simplesmente eram marcadas como não
verificadas, uma por uma.

Aqui o fallback passa a ser por *scan*, e não por processo. A condição de
acionamento é o `ScanErrorKind`: erro de DB, timeout, saída inválida e
rate limit são falhas do scanner, e o outro tem chance real de responder.
`NOT_FOUND` e `AUTH_REQUIRED` são fatos sobre a imagem -- perguntar de novo,
a outra ferramenta, só dobra a espera pela mesma resposta.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from loguru import logger

from dockerls.domain.interfaces.scanner import ScannerInterface

if TYPE_CHECKING:
    from dockerls.domain.entities.scan_result import ScanResult


class FallbackScanner(ScannerInterface):
    """Delegates to `primary`, retrying with `secondary` on scanner-side faults."""

    def __init__(self, primary: ScannerInterface, secondary: ScannerInterface):
        self._primary = primary
        self._secondary = secondary
        # Contabilidade para o resumo da execução: quantas vezes o secundário
        # salvou um alvo que o primário não conseguiu medir.
        self.fallback_successes = 0
        self.fallback_attempts = 0

    @property
    def primary(self) -> ScannerInterface:
        return self._primary

    @property
    def secondary(self) -> ScannerInterface:
        return self._secondary

    async def is_available(self) -> bool:
        return await self._primary.is_available() or await self._secondary.is_available()

    async def scan(self, image_reference: str) -> ScanResult:
        result = await self._primary.scan(image_reference)
        if result.is_verified or not result.error_kind.is_scanner_fault:
            return result

        self.fallback_attempts += 1
        logger.warning(
            f"{result.scanner} failed on {image_reference} "
            f"({result.error_kind.value}); retrying with the secondary scanner"
        )
        if not await self._secondary.is_available():
            logger.info("No secondary scanner available; keeping the primary result")
            return result

        fallback = await self._secondary.scan(image_reference)
        if not fallback.is_verified:
            # Nenhum dos dois conseguiu: devolve o resultado do primário, que
            # é o que descreve a falha da ferramenta que deveria ter medido.
            logger.warning(
                f"Secondary scanner also failed on {image_reference} ({fallback.error_kind.value})"
            )
            return result

        self.fallback_successes += 1
        logger.info(f"{fallback.scanner} recovered {image_reference} after {result.scanner} failed")
        return fallback

    async def refresh_db(self) -> bool:
        """Prepara os dois bancos, em paralelo.

        Eram sequenciais -- o secundário só começava a baixar depois que o
        primário terminasse -- e as duas baixas não competem por nada que
        torne isso necessário: bancos diferentes, ferramentas diferentes.
        Rodando juntas, o tempo de preparo passa a ser o maior dos dois, não
        a soma, o que soma minutos num run que nunca chega a precisar do
        secundário. O secundário só é útil se estiver pronto antes de a
        primeira falha acontecer, então o paralelismo é o que garante isso
        sem alongar o caminho comum.
        """
        primary_ok, _ = await asyncio.gather(_refresh(self._primary), _refresh(self._secondary))
        return primary_ok

    async def close(self) -> None:
        for scanner in (self._primary, self._secondary):
            close = getattr(scanner, "close", None)
            if callable(close):
                await close()


async def _refresh(scanner: ScannerInterface) -> bool:
    refresh = getattr(scanner, "refresh_db", None)
    if not callable(refresh):
        return True
    ok: bool = await refresh()
    return ok
