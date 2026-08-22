"""Onde o histórico de uma tag persiste entre execuções.

A metade pura está em `domain/value_objects/tag_history.py`. Aqui mora só o
que ela não pode fazer: guardar o que foi visto para que a próxima execução
saiba comparar.

O cache já existente serve, com uma diferença que importa: entradas de cache
normais expiram porque uma resposta velha é pior que nenhuma. Um histórico é o
oposto -- ele *é* o passado, e vale mais quanto mais antigo. Por isso o TTL
aqui é de um ano e é renovado a cada gravação: um histórico que expira em 24h
nunca chega a registrar a segunda observação, e a pergunta que este módulo
existe para responder ("com que frequência esta tag muda?") ficaria sem
resposta para sempre.

Nada aqui levanta exceção para fora. O histórico enriquece o diagnóstico do
`base`; se o cache estiver indisponível ou corrompido, o diagnóstico continua,
apenas sem a frase extra. Um extra que derruba o principal não é um extra.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from loguru import logger

from dockerls.domain.value_objects.tag_history import TagHistory, record

if TYPE_CHECKING:
    from dockerls.domain.interfaces.cache_store import CacheStoreInterface

#: Um ano. O histórico é o passado; ele não fica obsoleto, fica valioso.
HISTORY_TTL_SECONDS = 365 * 24 * 60 * 60

_KEY_PREFIX = "tag-history"


class TagHistoryStore:
    """Lê e grava o histórico de digests por referência de tag."""

    def __init__(self, cache: CacheStoreInterface | None = None):
        self._cache = cache

    async def get(self, reference: str) -> TagHistory:
        """O histórico guardado, ou um vazio quando não há (ou não deu para ler)."""
        if self._cache is None or not reference:
            return TagHistory(reference=reference)
        try:
            raw = await self._cache.get(_key(reference))
        except Exception as e:  # pragma: no cover - o cache é o caminho instável
            logger.debug(f"Não foi possível ler o histórico de {reference}: {e}")
            return TagHistory(reference=reference)
        return TagHistory.from_dict(reference, raw)

    async def observe(self, reference: str, digest: str) -> TagHistory:
        """Incorpora o digest observado agora e devolve o histórico resultante.

        Grava apenas quando algo mudou: reescrever a mesma entrada a cada
        consulta só serviria para renovar o TTL, e a renovação já acontece na
        gravação que importa.
        """
        current = await self.get(reference)
        updated = record(current, digest, datetime.now(UTC))
        if updated is current or self._cache is None:
            return updated
        try:
            await self._cache.set(
                _key(reference), updated.to_dict(), ttl_seconds=HISTORY_TTL_SECONDS
            )
        except Exception as e:  # pragma: no cover - o cache é o caminho instável
            logger.debug(f"Não foi possível gravar o histórico de {reference}: {e}")
        return updated


def _key(reference: str) -> str:
    return f"{_KEY_PREFIX}:{reference}"
