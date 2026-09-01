"""Cliente OCI Distribution v2.

Só o filtro de tags e o parser do desafio `WWW-Authenticate` eram cobertos;
o token dance e o tratamento de erro do `list_tags` -- que é o que decide se
um catálogo hardened entra ou não na recomendação -- não eram.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from dockerls.integrations.registry.oci import OCIRegistryClient

# Capturado antes de qualquer patch: referenciar httpx.AsyncClient de dentro
# do substituto resolveria para o próprio patch.
_REAL_ASYNC_CLIENT = httpx.AsyncClient


def _use_handler(handler):
    """Faz todo httpx.AsyncClient construído responder por `handler`."""
    transport = httpx.MockTransport(handler)

    def factory(**kwargs):
        kwargs.pop("transport", None)
        return _REAL_ASYNC_CLIENT(transport=transport, **kwargs)

    return patch.object(httpx, "AsyncClient", factory)


class TestListTags:
    @pytest.mark.asyncio
    async def test_returns_the_payload_when_anonymous_access_works(self):
        def handler(request):
            return httpx.Response(200, json={"name": "chainguard/node", "tags": ["latest"]})

        with _use_handler(handler):
            payload = await OCIRegistryClient("cgr.dev").list_tags("chainguard/node")

        assert payload == {"name": "chainguard/node", "tags": ["latest"]}

    @pytest.mark.asyncio
    async def test_the_first_request_asks_for_a_large_page(self):
        """A repository with hundreds of tags and no explicit page size
        falls back to the registry's own (often small) default, which turns
        one listing into a dozen-plus sequential round trips once `Link`
        pagination is followed. Asking for a large page up front collapses
        that back to one request for the common case."""
        from dockerls.integrations.registry.oci import INITIAL_PAGE_SIZE

        seen_queries: list[str] = []

        def handler(request):
            seen_queries.append(request.url.query.decode())
            return httpx.Response(200, json={"tags": []})

        with _use_handler(handler):
            await OCIRegistryClient("cgr.dev").list_tags("chainguard/node")

        assert seen_queries == [f"n={INITIAL_PAGE_SIZE}"]

    @pytest.mark.asyncio
    async def test_completes_the_bearer_token_dance(self):
        """401 com desafio -> pega token no realm -> repete com Authorization.

        É o único fluxo que registries públicos oferecem para pull anônimo;
        se ele quebra, o catálogo inteiro some da recomendação em silêncio.
        """
        seen: list[httpx.Request] = []

        def handler(request):
            seen.append(request)
            if request.url.path == "/token":
                return httpx.Response(200, json={"token": "tok-123"})
            if "Authorization" not in request.headers:
                return httpx.Response(
                    401,
                    headers={
                        "WWW-Authenticate": 'Bearer realm="https://cgr.dev/token",'
                        'service="cgr.dev",scope="repository:chainguard/node:pull"'
                    },
                )
            return httpx.Response(200, json={"tags": ["latest"]})

        with _use_handler(handler):
            payload = await OCIRegistryClient("cgr.dev").list_tags("chainguard/node")

        assert payload == {"tags": ["latest"]}
        assert seen[-1].headers["Authorization"] == "Bearer tok-123"
        # O scope do desafio precisa ser repassado ao realm, senão o token
        # volta sem permissão para o repositório pedido.
        assert "repository%3Achainguard%2Fnode%3Apull" in str(seen[1].url) or (
            "repository:chainguard/node:pull" in str(seen[1].url)
        )

    @pytest.mark.asyncio
    async def test_credentials_are_sent_as_basic_auth_to_the_token_realm(self):
        """A private registry's token endpoint is the standard Docker
        Registry HTTP API V2 realm, credentialed with Basic auth -- the
        same flow ECR, Harbor and GHCR's container registry all expect."""
        seen: list[httpx.Request] = []

        def handler(request):
            seen.append(request)
            if request.url.path == "/token":
                return httpx.Response(200, json={"token": "tok-private"})
            if "Authorization" not in request.headers:
                return httpx.Response(
                    401,
                    headers={
                        "WWW-Authenticate": 'Bearer realm="https://registry.example.com/token"'
                    },
                )
            return httpx.Response(200, json={"tags": ["1.0.0"]})

        with _use_handler(handler):
            client = OCIRegistryClient("registry.example.com", username="AWS", password="ecr-tok")
            payload = await client.list_tags("team/app")

        assert payload == {"tags": ["1.0.0"]}
        token_request = next(r for r in seen if r.url.path == "/token")
        assert token_request.headers["Authorization"].startswith("Basic ")

    @pytest.mark.asyncio
    async def test_no_credentials_means_the_token_request_is_anonymous(self):
        seen: list[httpx.Request] = []

        def handler(request):
            seen.append(request)
            if request.url.path == "/token":
                return httpx.Response(200, json={"token": "tok"})
            if "Authorization" not in request.headers:
                return httpx.Response(
                    401, headers={"WWW-Authenticate": 'Bearer realm="https://cgr.dev/token"'}
                )
            return httpx.Response(200, json={"tags": []})

        with _use_handler(handler):
            await OCIRegistryClient("cgr.dev").list_tags("chainguard/node")

        token_request = next(r for r in seen if r.url.path == "/token")
        assert "Authorization" not in token_request.headers

    @pytest.mark.asyncio
    async def test_accepts_access_token_field(self):
        """GCR e ECR devolvem `access_token` em vez de `token`."""

        def handler(request):
            if request.url.path == "/token":
                return httpx.Response(200, json={"access_token": "tok-gcr"})
            if "Authorization" not in request.headers:
                return httpx.Response(
                    401, headers={"WWW-Authenticate": 'Bearer realm="https://gcr.io/token"'}
                )
            return httpx.Response(200, json={"tags": []})

        with _use_handler(handler):
            payload = await OCIRegistryClient("gcr.io").list_tags("distroless/base")

        assert payload == {"tags": []}

    @pytest.mark.asyncio
    async def test_401_without_a_usable_challenge_returns_none(self):
        def handler(request):
            return httpx.Response(401, headers={"WWW-Authenticate": "Basic realm=x"})

        with _use_handler(handler):
            assert await OCIRegistryClient("cgr.dev").list_tags("private/repo") is None

    @pytest.mark.asyncio
    async def test_missing_repository_returns_none(self):
        def handler(request):
            return httpx.Response(404)

        with _use_handler(handler):
            assert await OCIRegistryClient("cgr.dev").list_tags("nope/nope") is None

    @pytest.mark.asyncio
    async def test_server_error_returns_none_instead_of_raising(self):
        """Um registry fora do ar degrada a busca, não derruba o comando.

        `max_attempts=1` keeps this a real, sustained failure (every
        attempt sees the same 503) rather than exercising the retry policy.
        """

        def handler(request):
            return httpx.Response(503)

        with _use_handler(handler):
            client = OCIRegistryClient("cgr.dev", max_attempts=1)
            assert await client.list_tags("chainguard/node") is None

    @pytest.mark.asyncio
    async def test_network_failure_returns_none(self):
        def handler(request):
            raise httpx.ConnectError("no route to host")

        with _use_handler(handler):
            client = OCIRegistryClient("cgr.dev", max_attempts=1)
            assert await client.list_tags("chainguard/node") is None

    @pytest.mark.asyncio
    async def test_transient_server_error_is_recovered_by_retry(self):
        """A 503 followed by a 200 must be recovered transparently -- the
        whole point of wiring the retry policy into this client."""
        calls = {"n": 0}

        def handler(request):
            calls["n"] += 1
            if calls["n"] == 1:
                return httpx.Response(503)
            return httpx.Response(200, json={"tags": ["1.0.0"]})

        with _use_handler(handler), patch("asyncio.sleep", new=AsyncMock()):
            client = OCIRegistryClient("cgr.dev", max_attempts=3, backoff_base=1.1)
            payload = await client.list_tags("chainguard/node")

        assert payload == {"tags": ["1.0.0"]}
        assert calls["n"] == 2

    @pytest.mark.asyncio
    async def test_sustained_server_error_opens_the_circuit_breaker(self):
        """After enough consecutive failures, further calls fail fast
        instead of repeating a doomed request against the same host."""
        calls = {"n": 0}

        def handler(request):
            calls["n"] += 1
            return httpx.Response(503)

        with _use_handler(handler), patch("asyncio.sleep", new=AsyncMock()):
            client = OCIRegistryClient("cgr.dev", max_attempts=1, backoff_base=1.1)
            client._breaker.threshold = 2
            assert await client.get("chainguard/node/manifests/latest") is None
            assert await client.get("chainguard/node/manifests/latest") is None
            calls_before_open = calls["n"]
            assert await client.get("chainguard/node/manifests/latest") is None
            # The breaker is now open: this call must not have reached the
            # network at all.
            assert calls["n"] == calls_before_open

    @pytest.mark.asyncio
    async def test_non_json_body_returns_none(self):
        def handler(request):
            return httpx.Response(200, text="<html>proxy error</html>")

        with _use_handler(handler):
            assert await OCIRegistryClient("cgr.dev").list_tags("chainguard/node") is None


class TestPagination:
    """GHCR, Harbor e Artifactory paginam `/tags/list` via `Link: rel="next"`."""

    @pytest.mark.asyncio
    async def test_all_pages_are_merged(self):
        from dockerls.integrations.registry.oci import INITIAL_PAGE_SIZE

        pages = {
            f"/v2/org/app/tags/list?n={INITIAL_PAGE_SIZE}": (
                ["a", "b"],
                "/v2/org/app/tags/list?next=2",
            ),
            "/v2/org/app/tags/list?next=2": (["c", "d"], "/v2/org/app/tags/list?next=3"),
            "/v2/org/app/tags/list?next=3": (["e"], None),
        }

        def handler(request):
            key = request.url.path
            if request.url.query:
                key += "?" + request.url.query.decode()
            tags, next_path = pages[key]
            headers = {"Link": f'<{next_path}>; rel="next"'} if next_path else {}
            return httpx.Response(200, json={"name": "org/app", "tags": tags}, headers=headers)

        with _use_handler(handler):
            payload = await OCIRegistryClient("registry.example.com").list_tags("org/app")

        assert payload is not None
        assert payload["tags"] == ["a", "b", "c", "d", "e"]

    @pytest.mark.asyncio
    async def test_a_registry_that_never_stops_paginating_is_capped(self):
        """A server that always advertises another `next` link must not
        hang this process forever; whatever was gathered up to the cap is
        returned instead."""
        calls = {"n": 0}

        def handler(request):
            calls["n"] += 1
            return httpx.Response(
                200,
                json={"tags": [f"tag-{calls['n']}"]},
                headers={"Link": '</v2/org/app/tags/list?forever=1>; rel="next"'},
            )

        with _use_handler(handler):
            payload = await OCIRegistryClient("registry.example.com").list_tags("org/app")

        assert payload is not None
        # One initial request plus MAX_TAG_PAGES-1 follow-up pages, capped
        # rather than unbounded.
        from dockerls.integrations.registry.oci import MAX_TAG_PAGES

        assert calls["n"] == MAX_TAG_PAGES
        assert len(payload["tags"]) == MAX_TAG_PAGES


class TestStopWhenEndsPaginationEarly:
    """A caller that only needs a handful of tags (a hardened-catalogue
    search) should not pay for a listing dominated by cosign signature
    tags -- see `HardenedRepository._gathered_enough_runnable_tags`."""

    @pytest.mark.asyncio
    async def test_stops_as_soon_as_the_predicate_is_satisfied(self):
        pages = {
            "1": (["a"], "2"),
            "2": (["b"], "3"),
            "3": (["c"], None),
        }
        calls = {"n": 0}

        def handler(request):
            calls["n"] += 1
            page = request.url.params.get("next") or "1"
            tags, next_page = pages[page]
            headers = {"Link": f'</v2/org/app/tags/list?next={next_page}>; rel="next"'}
            return httpx.Response(200, json={"tags": tags}, headers=headers if next_page else {})

        with _use_handler(handler):
            payload = await OCIRegistryClient("registry.example.com").list_tags(
                "org/app", stop_when=lambda tags: len(tags) >= 2
            )

        assert payload is not None
        assert payload["tags"] == ["a", "b"]
        assert calls["n"] == 2, "pagination should have stopped once 2 tags were seen"

    @pytest.mark.asyncio
    async def test_a_bounded_fetch_satisfies_a_later_call_with_the_same_predicate(self):
        """`search_tags` finding a candidate and `tag_exists` verifying it
        right after must not re-fetch: the second call's predicate is
        already true of what the first call cached."""
        calls = {"n": 0}

        def handler(request):
            calls["n"] += 1
            return httpx.Response(200, json={"tags": ["a", "b"]})

        client = OCIRegistryClient("registry.example.com")
        with _use_handler(handler):
            first = await client.list_tags("org/app", stop_when=lambda tags: len(tags) >= 2)
            second = await client.list_tags("org/app", stop_when=lambda tags: len(tags) >= 1)

        assert first == second
        assert calls["n"] == 1

    @pytest.mark.asyncio
    async def test_a_bounded_fetch_does_not_satisfy_a_later_call_wanting_everything(self):
        """A truncated listing -- one that stopped with more pages still
        available -- must never stand in for the complete one
        `tag_exists`/`get_image_metadata` rely on: a tag beyond the
        truncation point would otherwise be reported as not found."""
        pages = {"1": (["a"], "2"), "2": (["b"], None)}
        calls = {"n": 0}

        def handler(request):
            calls["n"] += 1
            page = request.url.params.get("next") or "1"
            tags, next_page = pages[page]
            headers = {"Link": f'</v2/org/app/tags/list?next={next_page}>; rel="next"'}
            return httpx.Response(200, json={"tags": tags}, headers=headers if next_page else {})

        client = OCIRegistryClient("registry.example.com")
        with _use_handler(handler):
            # Stops after page 1 -- page 2 exists but was never fetched.
            bounded = await client.list_tags("org/app", stop_when=lambda tags: len(tags) >= 1)
            full = await client.list_tags("org/app")  # wants the full listing

        assert bounded is not None
        assert bounded["tags"] == ["a"]
        assert full is not None
        assert full["tags"] == ["a", "b"]
        assert calls["n"] == 3, "a bounded cache entry must not satisfy an unbounded call"

    @pytest.mark.asyncio
    async def test_reaching_the_true_end_during_a_bounded_fetch_is_cached_as_complete(self):
        """When a `stop_when` fetch happens to reach the last page anyway
        (no `Link: rel=\"next\"`), that listing *is* the complete one and a
        later unbounded call should reuse it rather than re-fetching."""
        calls = {"n": 0}

        def handler(request):
            calls["n"] += 1
            return httpx.Response(200, json={"tags": ["a", "b"]})

        client = OCIRegistryClient("registry.example.com")
        with _use_handler(handler):
            # A predicate that is never satisfied by what comes back --
            # the fetch still ends because there is no next page.
            await client.list_tags("org/app", stop_when=lambda tags: len(tags) >= 1000)
            await client.list_tags("org/app")

        assert calls["n"] == 1


class TestHost:
    def test_exposes_the_host_it_was_built_with(self):
        assert OCIRegistryClient("cgr.dev").host == "cgr.dev"
