"""A persistência do histórico de contagens: um extra que nunca derruba o principal."""

from __future__ import annotations

from typing import Any

import pytest

from dockerls.application.services.scan_history_store import (
    HISTORY_TTL_SECONDS,
    ScanHistoryStore,
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


class TestScanHistoryStore:
    @pytest.mark.asyncio
    async def test_the_first_observation_is_written(self) -> None:
        cache = FakeCache()
        store = ScanHistoryStore(cache)

        history = await store.observe(
            "node:22", digest="sha256:aaa", critical=1, high=0, medium=0, low=0, total=1
        )

        assert history.latest is not None
        assert history.latest.critical == 1
        assert cache.writes == [("scan-history:node:22", HISTORY_TTL_SECONDS)]

    @pytest.mark.asyncio
    async def test_ttl_is_a_year_so_history_survives_to_a_second_observation(self) -> None:
        """A history that expired in 24h would never reach a second
        observation, and the question it exists to answer would go
        unanswered forever."""
        assert HISTORY_TTL_SECONDS == 365 * 24 * 60 * 60

    @pytest.mark.asyncio
    async def test_a_repeated_observation_does_not_rewrite(self) -> None:
        cache = FakeCache()
        store = ScanHistoryStore(cache)

        await store.observe("r", digest="sha256:aaa", critical=1, high=0, medium=0, low=0, total=1)
        await store.observe("r", digest="sha256:aaa", critical=1, high=0, medium=0, low=0, total=1)

        assert len(cache.writes) == 1

    @pytest.mark.asyncio
    async def test_a_change_accumulates_across_invocations(self) -> None:
        cache = FakeCache()

        await ScanHistoryStore(cache).observe(
            "r", digest="sha256:aaa", critical=1, high=0, medium=0, low=0, total=1
        )
        history = await ScanHistoryStore(cache).observe(
            "r", digest="sha256:aaa", critical=4, high=0, medium=0, low=0, total=4
        )

        assert history.scans == 2
        assert history.latest is not None
        assert history.latest.critical == 4

    @pytest.mark.asyncio
    async def test_without_a_cache_the_history_is_always_empty_but_never_breaks(self) -> None:
        store = ScanHistoryStore(None)

        history = await store.observe(
            "r", digest="sha256:aaa", critical=1, high=0, medium=0, low=0, total=1
        )

        assert history.latest is not None
        assert (await store.get("r")).is_empty

    @pytest.mark.asyncio
    async def test_an_exploding_cache_does_not_propagate(self) -> None:
        """The history enriches the diagnosis; if it fails, the diagnosis
        continues without the extra sentence."""
        store = ScanHistoryStore(ExplodingCache())

        history = await store.observe(
            "r", digest="sha256:aaa", critical=1, high=0, medium=0, low=0, total=1
        )

        assert history.latest is not None

    @pytest.mark.asyncio
    async def test_an_empty_reference_does_not_query_the_cache(self) -> None:
        cache = FakeCache()
        history = await ScanHistoryStore(cache).get("")

        assert history.is_empty
        assert not cache.writes
