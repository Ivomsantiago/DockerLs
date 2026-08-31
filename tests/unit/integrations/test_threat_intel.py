from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from dockerls.integrations.threat_intel.client import ThreatIntelClient


class TestThreatIntelClient:
    @pytest.mark.asyncio
    async def test_known_exploited_matches_kev_catalog(self):
        # `min_kev_entries=1` because this test is about parsing and
        # matching, not about the plausibility floor -- which has its own
        # tests in TestKevPlausibility and is left at its real value there.
        client = ThreatIntelClient(min_kev_entries=1)
        kev_payload = {"vulnerabilities": [{"cveID": "CVE-2024-0001"}]}
        request = httpx.Request("GET", "https://x")
        resp = httpx.Response(200, json=kev_payload, request=request)
        with patch("httpx.AsyncClient.get", AsyncMock(return_value=resp)):
            result = await client.known_exploited(["CVE-2024-0001", "CVE-2024-9999"])
        assert result == {"CVE-2024-0001"}

    @pytest.mark.asyncio
    async def test_kev_unreachable_degrades_gracefully(self):
        client = ThreatIntelClient(max_attempts=1)
        with patch(
            "httpx.AsyncClient.get",
            AsyncMock(
                side_effect=httpx.ConnectError("boom", request=httpx.Request("GET", "https://x"))
            ),
        ):
            result = await client.known_exploited(["CVE-2024-0001"])
        assert result == set()

    @pytest.mark.asyncio
    async def test_epss_scores_parsed(self):
        client = ThreatIntelClient()
        payload = {"data": [{"cve": "CVE-2024-0001", "epss": "0.87"}]}
        request = httpx.Request("GET", "https://x")
        resp = httpx.Response(200, json=payload, request=request)
        with patch("httpx.AsyncClient.get", AsyncMock(return_value=resp)):
            scores = await client.epss_scores(["CVE-2024-0001"])
        assert scores == {"CVE-2024-0001": 0.87}

    @pytest.mark.asyncio
    async def test_epss_unreachable_degrades_gracefully(self):
        client = ThreatIntelClient(max_attempts=1)
        with patch(
            "httpx.AsyncClient.get",
            AsyncMock(
                side_effect=httpx.ConnectError("boom", request=httpx.Request("GET", "https://x"))
            ),
        ):
            scores = await client.epss_scores(["CVE-2024-0001"])
        assert scores == {}

    @pytest.mark.asyncio
    async def test_empty_input_short_circuits(self):
        client = ThreatIntelClient()
        assert await client.known_exploited([]) == set()
        assert await client.epss_scores([]) == {}


class TestEpssBatching:
    """A API do FIRST pagina o resultado. Pedir todos os CVEs de uma vez
    devolvia calado só a primeira página, e o sinal de EPSS sumia justamente
    nas imagens com mais CRITICAL/HIGH -- as que mais precisam dele."""

    @pytest.mark.asyncio
    async def test_more_than_one_page_of_cves_is_fully_resolved(self):
        client = ThreatIntelClient()
        cve_ids = [f"CVE-2026-{i:05d}" for i in range(250)]

        seen_batches: list[list[str]] = []

        async def fake_get(self, url, params=None, **kwargs):
            requested = params["cve"].split(",")
            seen_batches.append(requested)
            return httpx.Response(
                200,
                json={"data": [{"cve": c, "epss": "0.5"} for c in requested]},
                request=httpx.Request("GET", url),
            )

        with patch.object(httpx.AsyncClient, "get", fake_get):
            scores = await client.epss_scores(cve_ids)

        assert len(scores) == 250, "CVEs beyond the first page lost their EPSS score"
        assert len(seen_batches) == 3
        assert all(len(b) <= ThreatIntelClient.EPSS_BATCH_SIZE for b in seen_batches)

    @pytest.mark.asyncio
    async def test_an_explicit_limit_is_sent_so_the_default_cannot_truncate(self):
        client = ThreatIntelClient()
        captured: dict[str, str] = {}

        async def fake_get(self, url, params=None, **kwargs):
            captured.update(params)
            return httpx.Response(200, json={"data": []}, request=httpx.Request("GET", url))

        with patch.object(httpx.AsyncClient, "get", fake_get):
            await client.epss_scores(["CVE-2026-0001", "CVE-2026-0002"])

        assert captured["limit"] == "2"

    @pytest.mark.asyncio
    async def test_one_failed_batch_does_not_discard_the_others(self):
        """Sinal parcial ainda é melhor que nenhum.

        `max_attempts=1` keeps the failing batch a sustained failure -- one
        attempt, no retry -- so it does not consume the second batch's
        response and inflate the count this test asserts on. Retry
        recovery itself has its own test below.
        """
        client = ThreatIntelClient(max_attempts=1)
        cve_ids = [f"CVE-2026-{i:05d}" for i in range(150)]
        calls = {"n": 0}

        async def fake_get(self, url, params=None, **kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                raise httpx.ConnectError("boom")
            requested = params["cve"].split(",")
            return httpx.Response(
                200,
                json={"data": [{"cve": c, "epss": "0.9"} for c in requested]},
                request=httpx.Request("GET", url),
            )

        with patch.object(httpx.AsyncClient, "get", fake_get):
            scores = await client.epss_scores(cve_ids)

        assert len(scores) == 50


class TestRetryRecovery:
    """A transient 5xx followed by success must be recovered by the retry
    policy wired into both feeds -- the point of item 2."""

    @pytest.mark.asyncio
    async def test_kev_recovers_from_a_transient_5xx(self):
        client = ThreatIntelClient(min_kev_entries=1, max_attempts=3, backoff_base=1.1)
        kev_payload = {"vulnerabilities": [{"cveID": "CVE-2024-0001"}]}
        calls = {"n": 0}

        async def fake_get(self, url, **kwargs):
            calls["n"] += 1
            request = httpx.Request("GET", url)
            if calls["n"] == 1:
                return httpx.Response(503, request=request)
            return httpx.Response(200, json=kev_payload, request=request)

        with (
            patch("httpx.AsyncClient.get", fake_get),
            patch("asyncio.sleep", AsyncMock()),
        ):
            result = await client.known_exploited(["CVE-2024-0001"])

        assert result == {"CVE-2024-0001"}
        assert calls["n"] == 2
        assert client.kev_available is True

    @pytest.mark.asyncio
    async def test_epss_recovers_from_a_transient_5xx(self):
        client = ThreatIntelClient(max_attempts=3, backoff_base=1.1)
        calls = {"n": 0}

        async def fake_get(self, url, params=None, **kwargs):
            calls["n"] += 1
            request = httpx.Request("GET", url)
            if calls["n"] == 1:
                return httpx.Response(503, request=request)
            return httpx.Response(
                200, json={"data": [{"cve": "CVE-2024-0001", "epss": "0.87"}]}, request=request
            )

        with (
            patch("httpx.AsyncClient.get", fake_get),
            patch("asyncio.sleep", AsyncMock()),
        ):
            scores = await client.epss_scores(["CVE-2024-0001"])

        assert scores == {"CVE-2024-0001": 0.87}
        assert calls["n"] == 2


class TestKevIsFetchedOnce:
    """`recommend` enriches every tag concurrently. The KEV memo is only
    populated after a download completes, so without a lock a 100-tag run
    started 100 simultaneous downloads of the same multi-megabyte catalogue.
    """

    @pytest.mark.asyncio
    async def test_concurrent_lookups_share_one_download(self):
        import asyncio

        # See above: this test is about the single-flight lock, so the
        # plausibility floor is lowered to let the one-entry fixture count.
        client = ThreatIntelClient(min_kev_entries=1)
        calls = 0

        async def slow_get(self, url, **kwargs):
            nonlocal calls
            calls += 1
            await asyncio.sleep(0.01)
            return httpx.Response(
                200,
                json={"vulnerabilities": [{"cveID": "CVE-2024-0001"}]},
                request=httpx.Request("GET", url),
            )

        with patch("httpx.AsyncClient.get", slow_get):
            results = await asyncio.gather(
                *[client.known_exploited(["CVE-2024-0001"]) for _ in range(25)]
            )

        assert calls == 1, f"KEV catalogue downloaded {calls} times for one run"
        assert all(r == {"CVE-2024-0001"} for r in results)


class _Cache:
    def __init__(self) -> None:
        self.store: dict[str, Any] = {}

    async def get(self, key: str) -> Any | None:
        return self.store.get(key)

    async def set(self, key: str, value: Any, ttl_seconds: int = 86400) -> None:
        self.store[key] = value

    async def delete(self, key: str) -> None:
        self.store.pop(key, None)

    async def clear(self) -> None:
        self.store.clear()


class TestKevCache:
    """Sem persistir em disco, todo processo baixava o catálogo inteiro do
    zero -- inclusive dois `recommend` seguidos contra a mesma imagem."""

    @pytest.mark.asyncio
    async def test_a_second_client_reads_the_cache_instead_of_the_network(self):
        cache = _Cache()
        kev_payload = {"vulnerabilities": [{"cveID": "CVE-2024-0001"}]}
        request = httpx.Request("GET", "https://x")
        resp = httpx.Response(200, json=kev_payload, request=request)
        with patch("httpx.AsyncClient.get", AsyncMock(return_value=resp)):
            # min_kev_entries=1: this fixture tests cache reuse, not the
            # catalogue-plausibility floor (covered separately in
            # tests/adversarial/test_threat_intel_values.py).
            first = ThreatIntelClient(cache=cache, min_kev_entries=1)
            await first.known_exploited(["CVE-2024-0001"])

        with patch(
            "httpx.AsyncClient.get",
            AsyncMock(side_effect=AssertionError("should not hit the network")),
        ):
            second = ThreatIntelClient(cache=cache, min_kev_entries=1)
            result = await second.known_exploited(["CVE-2024-0001"])

        assert result == {"CVE-2024-0001"}
        assert second.kev_available is True

    @pytest.mark.asyncio
    async def test_an_unreadable_cache_falls_back_to_the_network(self):
        class _Broken(_Cache):
            async def get(self, key: str) -> Any | None:
                raise RuntimeError("cache is broken")

        kev_payload = {"vulnerabilities": [{"cveID": "CVE-2024-0001"}]}
        request = httpx.Request("GET", "https://x")
        resp = httpx.Response(200, json=kev_payload, request=request)
        with patch("httpx.AsyncClient.get", AsyncMock(return_value=resp)):
            client = ThreatIntelClient(cache=_Broken(), min_kev_entries=1)
            result = await client.known_exploited(["CVE-2024-0001"])

        assert result == {"CVE-2024-0001"}


class TestEpssCache:
    """A mesma CVE de OS aparece em dezenas de tags da mesma família de
    imagem -- sem cache, cada uma delas requeria FIRST.org de novo."""

    @pytest.mark.asyncio
    async def test_a_cached_cve_is_never_requested_again(self):
        cache = _Cache()
        payload = {"data": [{"cve": "CVE-2024-0001", "epss": "0.87", "percentile": "0.9"}]}
        request = httpx.Request("GET", "https://x")
        resp = httpx.Response(200, json=payload, request=request)
        with patch("httpx.AsyncClient.get", AsyncMock(return_value=resp)):
            first = ThreatIntelClient(cache=cache)
            await first.epss_scores(["CVE-2024-0001"])

        with patch(
            "httpx.AsyncClient.get",
            AsyncMock(side_effect=AssertionError("should not hit the network")),
        ):
            second = ThreatIntelClient(cache=cache)
            scores = await second.epss_scores(["CVE-2024-0001"])

        assert scores == {"CVE-2024-0001": 0.87}
        assert second.percentile_of("CVE-2024-0001") == 0.9
        assert second.epss_available is True

    @pytest.mark.asyncio
    async def test_only_the_uncached_cves_are_requested(self):
        cache = _Cache()
        cache.store["threat-intel:epss:v1:CVE-2024-0001"] = {"score": 0.5, "percentile": 0.4}

        requested: list[str] = []

        async def fake_get(self, url, params=None, **kwargs):
            requested.extend(params["cve"].split(","))
            return httpx.Response(
                200,
                json={"data": [{"cve": "CVE-2024-0002", "epss": "0.1"}]},
                request=httpx.Request("GET", url),
            )

        with patch.object(httpx.AsyncClient, "get", fake_get):
            client = ThreatIntelClient(cache=cache)
            scores = await client.epss_scores(["CVE-2024-0001", "CVE-2024-0002"])

        assert requested == ["CVE-2024-0002"]
        assert scores == {"CVE-2024-0001": 0.5, "CVE-2024-0002": 0.1}
