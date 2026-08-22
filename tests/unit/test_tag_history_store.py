"""A persistência do histórico: um extra que nunca derruba o principal."""

from __future__ import annotations

from typing import Any

import pytest

from dockerls.application.services.tag_history_store import (
    HISTORY_TTL_SECONDS,
    TagHistoryStore,
)


class FakeCache:
    def __init__(self) -> None:
        self.data: dict[str, Any] = {}
        self.writes: list[tuple[str, int]] = []

    async def get(self, key: str) -> Any | None:
        return self.data.get(key)

    async def set(self, key: str, value: Any, ttl_seconds: int = 86400) -> None:
        self.data[key] = value
        self.writes.append((key, ttl_seconds))

    async def delete(self, key: str) -> None:
        self.data.pop(key, None)

    async def clear(self) -> None:
        self.data.clear()


class ExplodingCache(FakeCache):
    async def get(self, key: str) -> Any | None:
        raise RuntimeError("banco indisponível")

    async def set(self, key: str, value: Any, ttl_seconds: int = 86400) -> None:
        raise RuntimeError("disco cheio")


class TestTagHistoryStore:
    @pytest.mark.asyncio
    async def test_primeira_observacao_e_gravada(self) -> None:
        cache = FakeCache()
        store = TagHistoryStore(cache)

        history = await store.observe("python:3.12", "sha256:aaa")

        assert history.current_digest == "sha256:aaa"
        assert cache.writes == [("tag-history:python:3.12", HISTORY_TTL_SECONDS)]

    @pytest.mark.asyncio
    async def test_ttl_e_de_um_ano_para_o_historico_chegar_a_segunda_observacao(self) -> None:
        """Um histórico que expira em 24h nunca registra a segunda observação,
        e a pergunta que ele existe para responder fica sem resposta."""
        assert HISTORY_TTL_SECONDS == 365 * 24 * 60 * 60

    @pytest.mark.asyncio
    async def test_observacao_repetida_nao_reescreve(self) -> None:
        cache = FakeCache()
        store = TagHistoryStore(cache)

        await store.observe("r", "sha256:aaa")
        await store.observe("r", "sha256:aaa")

        assert len(cache.writes) == 1

    @pytest.mark.asyncio
    async def test_movimento_acumula_entre_execucoes(self) -> None:
        cache = FakeCache()

        await TagHistoryStore(cache).observe("r", "sha256:aaa")
        history = await TagHistoryStore(cache).observe("r", "sha256:bbb")

        assert history.moves == 1
        assert history.current_digest == "sha256:bbb"

    @pytest.mark.asyncio
    async def test_sem_cache_o_historico_e_sempre_vazio_mas_nunca_quebra(self) -> None:
        store = TagHistoryStore(None)

        history = await store.observe("r", "sha256:aaa")

        assert history.current_digest == "sha256:aaa"
        assert (await store.get("r")).is_empty

    @pytest.mark.asyncio
    async def test_cache_que_explode_nao_propaga(self) -> None:
        """O histórico enriquece o diagnóstico; se ele falhar, o diagnóstico
        continua sem a frase extra."""
        store = TagHistoryStore(ExplodingCache())

        history = await store.observe("r", "sha256:aaa")

        assert history.current_digest == "sha256:aaa"

    @pytest.mark.asyncio
    async def test_referencia_vazia_nao_consulta_o_cache(self) -> None:
        cache = FakeCache()
        history = await TagHistoryStore(cache).get("")

        assert history.is_empty
        assert not cache.writes
