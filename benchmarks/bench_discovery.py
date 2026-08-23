"""Count real HTTP requests through the `recommend` discovery path.

No network is touched: every request is served by an httpx MockTransport
that records what was asked for and adds a fixed latency, so request counts
and wall time are reproducible and comparable between revisions.

The scenario is what `recommend` actually does against a hardened source --
list a repository's tags once, then verify each surviving candidate --
against a registry that behaves like the real ones (401 challenge, token
fetch, then data).

Run it with `python benchmarks/bench_discovery.py`.

Measured on this repository:

    before (one AsyncClient and one listing per call)  33 requests, 0.128s
    after  (shared client, memoised single-flight)      3 requests, 0.064s
"""

from __future__ import annotations

import asyncio
import collections
import sys
import time

import httpx

LATENCY = 0.02  # seconds per request, both directions

counts: collections.Counter[str] = collections.Counter()

CHAINGUARD_TAGS = {
    "tags": ["latest", "latest-dev", "22", "20", "22-dev", "20-dev", "21", "18", "18-dev", "23"],
    "name": "chainguard/node",
}
DISTROLESS_TAGS = {"tags": ["latest", "nonroot", "debug"], "name": "distroless/nodejs"}


async def handler(request: httpx.Request) -> httpx.Response:
    url = str(request.url)
    counts[_bucket(request)] += 1
    await asyncio.sleep(LATENCY)

    if "token" in url or "auth" in url:
        return httpx.Response(200, json={"token": "t"})
    # Real registries answer an anonymous /v2/ listing with a Bearer
    # challenge first; the client then fetches a token and retries.
    if request.headers.get("Authorization") is None and "/v2/" in url:
        return httpx.Response(
            401,
            headers={"WWW-Authenticate": 'Bearer realm="https://cgr.dev/token",service="cgr.dev"'},
        )
    if request.url.host == "cgr.dev":
        return httpx.Response(200, json=CHAINGUARD_TAGS)
    if request.url.host == "gcr.io":
        return httpx.Response(200, json=DISTROLESS_TAGS)
    return httpx.Response(200, json={"results": [], "next": None})


def _bucket(request: httpx.Request) -> str:
    """Em qual registry esta requisição caiu, pelo host e não por substring.

    `"cgr.dev" in url` casa com `https://cgr.dev.attacker.test/v2/`, que não é
    o Chainguard. Aqui isso só produziria um número errado no benchmark, mas é
    o mesmo padrão que seria confusão de host em código de produção -- e um
    padrão que passa na revisão num arquivo reaparece no outro.
    """
    if "token" in request.url.path:
        return "token"
    host = request.url.host
    if host in ("cgr.dev", "gcr.io"):
        return host
    return "other"


def install() -> None:
    transport = httpx.MockTransport(handler)
    original = httpx.AsyncClient.__init__

    def patched(self, *args, **kwargs):
        kwargs["transport"] = transport
        original(self, *args, **kwargs)

    httpx.AsyncClient.__init__ = patched


async def main() -> None:
    install()
    from dockerls.integrations.registry.hardened import ChainguardRepository

    repo = ChainguardRepository(timeout=5)

    start = time.perf_counter()
    # What `recommend` actually does: discover once, then verify each of the
    # candidates that survived ranking.
    tags = await repo.search_tags("node", limit=10)
    await asyncio.gather(*[repo.tag_exists("node", t.tag) for t in tags])
    elapsed = time.perf_counter() - start

    close = getattr(repo, "close", None)
    if close:
        await close()

    print(f"candidates verified : {len(tags)}")
    print(f"requests (listing)  : {counts['cgr.dev']}")
    print(f"requests (token)    : {counts['token']}")
    print(f"requests (total)    : {sum(counts.values())}")
    print(f"wall time           : {elapsed:.3f}s")


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
