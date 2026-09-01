from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from dockerls.integrations.dockerhub.client import DockerHubClient


def _response(status_code: int, json_body: dict | None = None, headers: dict | None = None):
    request = httpx.Request("GET", "https://hub.docker.com/v2/x")
    return httpx.Response(status_code, json=json_body, headers=headers or {}, request=request)


class TestParseImages:
    def test_prefers_amd64(self):
        images = [
            {"architecture": "arm64", "size": 10, "digest": "sha256:arm"},
            {"architecture": "amd64", "size": 20, "digest": "sha256:amd"},
        ]
        size, digest, arch, archs = DockerHubClient._parse_images(images)
        assert arch == "amd64"
        assert digest == "sha256:amd"
        assert archs == ["arm64", "amd64"]

    def test_falls_back_to_first_when_no_amd64(self):
        images = [{"architecture": "arm64", "size": 5, "digest": "sha256:arm"}]
        size, digest, arch, archs = DockerHubClient._parse_images(images)
        assert arch == "arm64"
        assert archs == ["arm64"]

    def test_empty_images(self):
        size, digest, arch, archs = DockerHubClient._parse_images([])
        assert size == 0
        assert digest == ""
        assert archs == []

    def test_images_that_is_not_a_list_is_treated_as_empty(self):
        """`tag_data.get("images", [])` returns whatever the API answered
        for that key -- `null` included, since the default only applies
        when the key is absent. `for img in None` used to raise
        `TypeError`."""
        size, digest, arch, archs = DockerHubClient._parse_images(None)
        assert (size, digest, arch, archs) == (0, "", "amd64", [])

    def test_a_non_dict_entry_is_skipped_not_crashed_on(self):
        images = ["not-a-dict", {"architecture": "amd64", "size": 5, "digest": "sha256:a"}]
        size, digest, arch, archs = DockerHubClient._parse_images(images)
        assert arch == "amd64"
        assert digest == "sha256:a"


class TestSearchTagsPartialResults:
    @pytest.mark.asyncio
    async def test_network_error_mid_pagination_returns_partial_results(self):
        client = DockerHubClient()
        page1 = {
            "results": [{"name": "22-alpine", "images": [{"architecture": "amd64"}]}],
            "next": "https://hub.docker.com/v2/x?page=2",
        }

        call_count = {"n": 0}

        async def fake_get_json(_self, _client, _url):
            call_count["n"] += 1
            if call_count["n"] == 1:
                return _response(200, page1)
            raise httpx.ConnectError("boom", request=httpx.Request("GET", "https://x"))

        with patch.object(DockerHubClient, "_get_json", fake_get_json):
            tags = await client.search_tags("node", limit=100)

        assert len(tags) == 1
        assert tags[0].tag == "22-alpine"

    @pytest.mark.asyncio
    async def test_populates_multi_arch_field(self):
        client = DockerHubClient()
        page = {
            "results": [
                {
                    "name": "22-alpine",
                    "images": [
                        {"architecture": "amd64", "size": 10, "digest": "sha256:a"},
                        {"architecture": "arm64", "size": 9, "digest": "sha256:b"},
                    ],
                }
            ],
            "next": None,
        }
        mock_get_json = AsyncMock(return_value=_response(200, page))
        with patch.object(DockerHubClient, "_get_json", mock_get_json):
            tags = await client.search_tags("node", limit=100)

        assert tags[0].available_architectures == ["amd64", "arm64"]


class TestMalformedResponsesDegradeGracefully:
    """A well-formed but wrongly-shaped 200 body -- a JSON array where an
    object is expected, or a body that is not JSON at all -- used to raise
    past `search_tags`, `get_image_metadata` and `authenticate`: only
    `httpx.HTTPError` was caught around them, never `ValueError`
    (`json.JSONDecodeError` is a subclass) or the `AttributeError` from
    `.get(...)` on a non-dict body."""

    @pytest.mark.asyncio
    async def test_a_json_array_search_body_returns_no_tags(self):
        client = DockerHubClient()
        request = httpx.Request("GET", "https://hub.docker.com/v2/x")
        resp = httpx.Response(200, json=["not", "an", "object"], request=request)
        with patch.object(DockerHubClient, "_get_json", AsyncMock(return_value=resp)):
            tags = await client.search_tags("node", limit=100)
        assert tags == []

    @pytest.mark.asyncio
    async def test_a_non_dict_results_entry_is_skipped(self):
        client = DockerHubClient()
        page = {"results": ["not-a-dict", {"name": "22-alpine", "images": []}], "next": None}
        with patch.object(
            DockerHubClient, "_get_json", AsyncMock(return_value=_response(200, page))
        ):
            tags = await client.search_tags("node", limit=100)
        assert [t.tag for t in tags] == ["22-alpine"]

    @pytest.mark.asyncio
    async def test_a_non_json_search_body_returns_partial_results(self):
        client = DockerHubClient()
        request = httpx.Request("GET", "https://hub.docker.com/v2/x")
        resp = httpx.Response(200, text="<html>proxy error</html>", request=request)
        with patch.object(DockerHubClient, "_get_json", AsyncMock(return_value=resp)):
            tags = await client.search_tags("node", limit=100)
        assert tags == []

    @pytest.mark.asyncio
    async def test_a_json_array_metadata_body_returns_none(self):
        client = DockerHubClient()
        request = httpx.Request("GET", "https://hub.docker.com/v2/x")
        resp = httpx.Response(200, json=["not", "an", "object"], request=request)
        with patch.object(DockerHubClient, "_get_json", AsyncMock(return_value=resp)):
            assert await client.get_image_metadata("node", "22") is None

    @pytest.mark.asyncio
    async def test_a_non_json_metadata_body_returns_none(self):
        client = DockerHubClient()
        request = httpx.Request("GET", "https://hub.docker.com/v2/x")
        resp = httpx.Response(200, text="<html>proxy error</html>", request=request)
        with patch.object(DockerHubClient, "_get_json", AsyncMock(return_value=resp)):
            assert await client.get_image_metadata("node", "22") is None

    @pytest.mark.asyncio
    async def test_a_json_array_auth_body_fails_authentication(self):
        client = DockerHubClient(username="user", token="tok")  # nosec B106
        request = httpx.Request("POST", "https://hub.docker.com/v2/users/login/")
        resp = httpx.Response(200, json=["not", "an", "object"], request=request)
        with patch("httpx.AsyncClient.post", AsyncMock(return_value=resp)):
            assert await client.authenticate() is False


class TestRetryAfter:
    @pytest.mark.asyncio
    async def test_get_json_sleeps_for_retry_after_header(self):
        """Exhausted retries must surface as an httpx error, not RetryError.

        This previously asserted `RetryError`, which encoded a latent bug:
        `tenacity.RetryError` is not an `httpx.HTTPError`, so the
        `except httpx.HTTPError` handlers in `search_tags` and `tag_exists`
        never caught it -- a sustained Hub rate limit crashed the command
        instead of degrading to partial results. The retry policy now sets
        `reraise=True` so the original error reaches those handlers.
        """
        client = DockerHubClient()
        resp_429 = _response(429, {}, headers={"Retry-After": "3"})

        with (
            patch("httpx.AsyncClient.get", AsyncMock(return_value=resp_429)),
            patch("asyncio.sleep", AsyncMock()) as mock_sleep,
        ):
            async with await client._get_client() as http_client:
                with pytest.raises(httpx.HTTPError):
                    await client._get_json(http_client, "https://hub.docker.com/v2/x")

        retry_after_calls = [c for c in mock_sleep.await_args_list if c.args == (3.0,)]
        assert len(retry_after_calls) >= 1

    @pytest.mark.asyncio
    async def test_sustained_rate_limit_degrades_instead_of_crashing(self):
        """The bug the above test used to hide: `search_tags` must return
        whatever it has rather than propagating out of the command."""
        client = DockerHubClient()
        resp_429 = _response(429, {}, headers={"Retry-After": "1"})

        with (
            patch("httpx.AsyncClient.get", AsyncMock(return_value=resp_429)),
            patch("asyncio.sleep", AsyncMock()),
        ):
            tags = await client.search_tags("node", limit=5)

        assert tags == []

    @pytest.mark.asyncio
    async def test_sustained_rate_limit_makes_tag_exists_unknown(self):
        client = DockerHubClient()
        resp_429 = _response(429, {}, headers={"Retry-After": "1"})

        with (
            patch("httpx.AsyncClient.get", AsyncMock(return_value=resp_429)),
            patch("asyncio.sleep", AsyncMock()),
        ):
            # Unknown, never False: a rate limit is not evidence of absence.
            assert await client.tag_exists("node", "22-alpine") is None


class _RecordingCache:
    def __init__(self):
        self.store: dict = {}
        self.gets: list[str] = []

    async def get(self, key):
        self.gets.append(key)
        return self.store.get(key)

    async def set(self, key, value, ttl_seconds=86400):
        self.store[key] = value

    async def delete(self, key):
        self.store.pop(key, None)

    async def clear(self):
        self.store.clear()


class TestTagExists:
    @pytest.mark.asyncio
    async def test_present_tag_returns_true(self):
        client = DockerHubClient()
        with patch.object(
            DockerHubClient, "_get_json", AsyncMock(return_value=_response(200, {"name": "22"}))
        ):
            assert await client.tag_exists("node", "22") is True

    @pytest.mark.asyncio
    async def test_missing_tag_returns_false(self):
        client = DockerHubClient()
        with patch.object(DockerHubClient, "_get_json", AsyncMock(return_value=_response(404))):
            assert await client.tag_exists("node", "does-not-exist") is False

    @pytest.mark.asyncio
    async def test_network_failure_returns_none_not_false(self):
        """`None` means "unverified"; reporting it as False would drop a
        perfectly good image because the network hiccuped."""
        client = DockerHubClient()
        with patch.object(
            DockerHubClient, "_get_json", AsyncMock(side_effect=httpx.ConnectError("boom"))
        ):
            assert await client.tag_exists("node", "22") is None

    @pytest.mark.asyncio
    async def test_unexpected_status_returns_none(self):
        client = DockerHubClient()
        with patch.object(DockerHubClient, "_get_json", AsyncMock(return_value=_response(500))):
            assert await client.tag_exists("node", "22") is None

    @pytest.mark.asyncio
    async def test_non_dockerhub_image_is_not_queried(self):
        client = DockerHubClient()
        get_json = AsyncMock()
        with patch.object(DockerHubClient, "_get_json", get_json):
            assert await client.tag_exists("ghcr.io/org/app", "v1") is None
        get_json.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_result_is_cached_so_hub_is_hit_once(self):
        cache = _RecordingCache()
        client = DockerHubClient(cache=cache)
        get_json = AsyncMock(return_value=_response(200, {"name": "22"}))
        with patch.object(DockerHubClient, "_get_json", get_json):
            assert await client.tag_exists("node", "22") is True
            assert await client.tag_exists("node", "22") is True
        assert get_json.await_count == 1

    @pytest.mark.asyncio
    async def test_unknown_results_are_not_cached(self):
        cache = _RecordingCache()
        client = DockerHubClient(cache=cache)
        with patch.object(
            DockerHubClient, "_get_json", AsyncMock(side_effect=httpx.ConnectError("boom"))
        ):
            await client.tag_exists("node", "22")
        assert cache.store == {}

    @pytest.mark.asyncio
    async def test_uses_library_namespace_for_official_images(self):
        client = DockerHubClient()
        get_json = AsyncMock(return_value=_response(200, {"name": "22"}))
        with patch.object(DockerHubClient, "_get_json", get_json):
            await client.tag_exists("node", "22")
        url = get_json.await_args.args[-1]
        assert url == "https://hub.docker.com/v2/repositories/library/node/tags/22"
