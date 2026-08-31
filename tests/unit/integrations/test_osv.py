from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from dockerls.integrations.threat_intel.osv import OSVClient, OSVEnrichment, _parse_osv_record


class TestParseOsvRecord:
    def test_extracts_aliases_and_ranges(self):
        data = {
            "id": "GHSA-xxxx",
            "aliases": ["CVE-2024-0001", "GHSA-abcd-1234"],
            "affected": [
                {
                    "package": {"name": "lodash"},
                    "ranges": [
                        {
                            "type": "SEMVER",
                            "events": [{"introduced": "0"}, {"fixed": "4.17.21"}],
                        }
                    ],
                }
            ],
        }
        enrichment = _parse_osv_record(data)
        assert enrichment.aliases == ["CVE-2024-0001", "GHSA-abcd-1234"]
        assert enrichment.affected_ranges == ["lodash: introduced=0, fixed=4.17.21"]

    @pytest.mark.parametrize(
        "hostile",
        [
            None,
            "not-a-dict",
            {},
            {"aliases": "not-a-list"},
            {"affected": "not-a-list"},
            {"affected": [{"ranges": "not-a-list"}]},
            {"affected": [{"ranges": [{"events": "not-a-list"}]}]},
            {"affected": [None, 7]},
        ],
    )
    def test_malformed_shapes_never_raise(self, hostile):
        enrichment = _parse_osv_record(hostile)
        assert isinstance(enrichment, OSVEnrichment)
        assert enrichment.aliases == [] or isinstance(enrichment.aliases, list)


class TestOSVClient:
    @pytest.mark.asyncio
    async def test_enrich_parses_a_found_record(self):
        client = OSVClient()
        payload = {"aliases": ["GHSA-1234"], "affected": []}
        request = httpx.Request("GET", "https://x")
        resp = httpx.Response(200, json=payload, request=request)
        with patch("httpx.AsyncClient.get", AsyncMock(return_value=resp)):
            result = await client.enrich(["CVE-2024-0001"])
        assert result["CVE-2024-0001"].aliases == ["GHSA-1234"]
        assert client.available is True

    @pytest.mark.asyncio
    async def test_a_404_is_a_real_answer_not_a_failure(self):
        """OSV not having a record for this CVE is a fact, and must count
        as `available`, not as an unreachable source."""
        client = OSVClient()
        request = httpx.Request("GET", "https://x")
        resp = httpx.Response(404, request=request)
        with patch("httpx.AsyncClient.get", AsyncMock(return_value=resp)):
            result = await client.enrich(["CVE-2024-0001"])
        assert result == {}
        assert client.available is True

    @pytest.mark.asyncio
    async def test_unreachable_degrades_to_unavailable(self):
        client = OSVClient(max_attempts=1)
        with patch(
            "httpx.AsyncClient.get",
            AsyncMock(
                side_effect=httpx.ConnectError("boom", request=httpx.Request("GET", "https://x"))
            ),
        ):
            result = await client.enrich(["CVE-2024-0001"])
        assert result == {}
        assert client.available is False

    @pytest.mark.asyncio
    async def test_malformed_json_degrades_to_unavailable(self):
        client = OSVClient(max_attempts=1)
        request = httpx.Request("GET", "https://x")
        resp = httpx.Response(200, text="<html>not json</html>", request=request)
        with patch("httpx.AsyncClient.get", AsyncMock(return_value=resp)):
            result = await client.enrich(["CVE-2024-0001"])
        assert result == {}
        assert client.available is False

    @pytest.mark.asyncio
    async def test_empty_input_short_circuits(self):
        client = OSVClient()
        assert await client.enrich([]) == {}
        assert client.available is None

    @pytest.mark.asyncio
    async def test_a_transient_5xx_is_recovered_by_retry(self):
        client = OSVClient(max_attempts=3, backoff_base=1.1)
        calls = {"n": 0}

        async def fake_get(self, url, **kwargs):
            calls["n"] += 1
            request = httpx.Request("GET", url)
            if calls["n"] == 1:
                return httpx.Response(503, request=request)
            return httpx.Response(200, json={"aliases": ["GHSA-xyz"]}, request=request)

        with (
            patch("httpx.AsyncClient.get", fake_get),
            patch("asyncio.sleep", AsyncMock()),
        ):
            result = await client.enrich(["CVE-2024-0001"])

        assert result["CVE-2024-0001"].aliases == ["GHSA-xyz"]
        assert calls["n"] == 2


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


class TestOSVCache:
    @pytest.mark.asyncio
    async def test_a_cached_cve_is_never_requested_again(self):
        cache = _Cache()
        payload = {"aliases": ["GHSA-1234"], "affected": []}
        request = httpx.Request("GET", "https://x")
        resp = httpx.Response(200, json=payload, request=request)
        with patch("httpx.AsyncClient.get", AsyncMock(return_value=resp)):
            first = OSVClient(cache=cache)
            await first.enrich(["CVE-2024-0001"])

        with patch(
            "httpx.AsyncClient.get",
            AsyncMock(side_effect=AssertionError("should not hit the network")),
        ):
            second = OSVClient(cache=cache)
            result = await second.enrich(["CVE-2024-0001"])

        assert result["CVE-2024-0001"].aliases == ["GHSA-1234"]
        assert second.available is True
