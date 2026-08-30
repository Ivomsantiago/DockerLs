"""Digest resolution + OCI config read, fanned out with asyncio.gather +
Semaphore -- the exact pattern `RegistryInspector`/`_pin_digests` already
use in `recommend_images.py`.

This is the Python half of a two-language, same-machine comparison. The Go
half is `engine/cmd/bench-fanout`, and both hit the *same* local HTTP
server with the same injected latency, so the difference measured is the
fan-out orchestration, not which side has a faster network.

    go run ./cmd/bench-fanout -serve -latency-ms 40 &            # from engine/
    python3 benchmarks/bench_fanout.py --targets 300 --workers 16

See docs/ENGINE_BENCHMARK.md for the numbers this produced and the
conclusion drawn from them.
"""

from __future__ import annotations

import argparse
import asyncio
import time

import httpx


async def _fetch(client: httpx.AsyncClient, url: str) -> int:
    try:
        resp = await client.get(url)
    except httpx.HTTPError:
        return 0
    await resp.aread()
    return 1


async def run(addr: str, targets: int, workers: int) -> None:
    semaphore = asyncio.Semaphore(workers)
    requests = 0

    async def one(i: int, client: httpx.AsyncClient) -> None:
        nonlocal requests
        async with semaphore:
            repo = f"bench/repo-{i}"
            n = await _fetch(client, f"http://{addr}/v2/{repo}/manifests/tag")
            n += await _fetch(client, f"http://{addr}/v2/{repo}/blobs/sha256:{i}")
        requests += n

    start = time.perf_counter()
    async with httpx.AsyncClient() as client:
        await asyncio.gather(*[one(i, client) for i in range(targets)])
    elapsed = time.perf_counter() - start

    print(
        f"python-asyncio targets={targets} workers={workers} "
        f"requests={requests} elapsed={elapsed:.3f}s"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--addr", default="127.0.0.1:8991")
    parser.add_argument("--targets", type=int, default=200)
    parser.add_argument("--workers", type=int, default=16)
    args = parser.parse_args()
    asyncio.run(run(args.addr, args.targets, args.workers))


if __name__ == "__main__":
    main()
