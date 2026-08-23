"""What the multi-source engine costs, measured rather than asserted.

Three questions this answers, all of which were unanswerable before the
engine existed and all of which decide whether it is usable:

1. **Does digest deduplication actually remove scans?** Deduplication is the
   only reason resolving digests is worth a request per tag, and a scan is
   two to three orders of magnitude more expensive than a HEAD.
2. **Does the DHI catalogue cost a clone?** It must not. The index is one
   API request per TTL, and a warm cache must cost zero.
3. **How does discovery scale to a large candidate set?** 1000 candidates is
   the shape of a `--limit 1000` run against a busy repository.

No network is touched: registry and catalogue HTTP is served by an httpx
MockTransport with a fixed latency, and the "scanner" is a coroutine that
sleeps for the time a real scan takes. That makes the numbers reproducible
and comparable across revisions -- they measure the pipeline's *shape*, not
the weather.

Run with `python benchmarks/bench_multi_source.py`.

Measured on this repository (LATENCY=5ms, SCAN=250ms):

    scans without digest resolution : 40 scans, 10.0s
    scans with digest resolution    : 12 scans,  3.0s  (40 HEADs, 28 scans avoided)
    catalogue index, cold           : 1 API request, 14ms over 11k blobs
    catalogue index, warm cache     : 0 API requests, 5ms
    ranking 1000 candidates         : 1.3ms (10k: 22ms)
"""

from __future__ import annotations

import asyncio
import collections
import json
import sys
import time
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dockerls.application.dto.analysis import DimensionReport, ImageAnalysis  # noqa: E402
from dockerls.application.services.verdict import rank  # noqa: E402
from dockerls.domain.entities.image import DockerImage  # noqa: E402
from dockerls.domain.entities.scan_result import ScanResult, ScanStatus  # noqa: E402
from dockerls.domain.value_objects.confidence import Confidence  # noqa: E402
from dockerls.integrations.dhi.catalog import DHICatalogClient  # noqa: E402

#: Per-request latency for the mocked registry/catalogue.
LATENCY = 0.005
#: What one scanner invocation costs. Conservative: a real Trivy scan of an
#: uncached image is measured in seconds, not milliseconds.
SCAN_SECONDS = 0.25

#: 40 tags, 12 distinct manifests: the shape of a real repository, where
#: `22`, `22.13`, `22-bookworm` and `latest` are frequently one image.
TAG_COUNT = 40
DISTINCT_MANIFESTS = 12

counts: collections.Counter[str] = collections.Counter()


def _tags() -> list[DockerImage]:
    return [DockerImage(name="node", tag=f"t{i}") for i in range(TAG_COUNT)]


def _digest_for(index: int) -> str:
    return f"sha256:{index % DISTINCT_MANIFESTS:064d}"


async def _scan(reference: str) -> None:
    counts["scans"] += 1
    await asyncio.sleep(SCAN_SECONDS)


async def _resolve(index: int) -> str:
    counts["head"] += 1
    await asyncio.sleep(LATENCY)
    return _digest_for(index)


async def bench_deduplication() -> None:
    """Scans performed with and without pre-scan digest resolution."""
    print("== digest deduplication ==")

    counts.clear()
    start = time.monotonic()
    seen: set[str] = set()
    for image in _tags():
        if image.full_reference not in seen:
            seen.add(image.full_reference)
            await _scan(image.full_reference)
    naive_scans, naive_time = counts["scans"], time.monotonic() - start

    counts.clear()
    start = time.monotonic()
    tags = _tags()
    digests = await asyncio.gather(*[_resolve(i) for i in range(len(tags))])
    for image, digest in zip(tags, digests, strict=True):
        image.digest = digest
    scanned: set[str] = set()
    for image in tags:
        key = image.digest or image.full_reference
        if key not in scanned:
            scanned.add(key)
            await _scan(image.full_reference)
    pinned_scans, pinned_time = counts["scans"], time.monotonic() - start

    print(f"  tags discovered            : {TAG_COUNT}")
    print(f"  scans without resolution   : {naive_scans}  ({naive_time:.2f}s)")
    print(f"  scans with resolution      : {pinned_scans}  ({pinned_time:.2f}s)")
    print(f"  HEAD requests spent        : {counts['head']}")
    print(f"  scans avoided              : {naive_scans - pinned_scans}")
    print(f"  wall-clock saved           : {naive_time - pinned_time:.2f}s")


class _Cache:
    def __init__(self) -> None:
        self.data: dict[str, object] = {}

    async def get(self, key: str) -> object | None:
        return self.data.get(key)

    async def set(self, key: str, value: object, ttl_seconds: int = 86400) -> None:
        self.data[key] = value

    async def delete(self, key: str) -> None:
        self.data.pop(key, None)

    async def clear(self) -> None:
        self.data.clear()


def _catalog_transport() -> httpx.MockTransport:
    """A catalogue tree the size of the real one (~11k blobs)."""
    tree = {
        "sha": "a" * 40,
        "tree": [
            {"type": "blob", "path": f"image/img{i // 12}/debian-13/{i % 12}.yaml"}
            for i in range(11_000)
        ],
    }
    body = json.dumps(tree)

    def handler(request: httpx.Request) -> httpx.Response:
        # Igualdade em vez de substring: ver a nota em test_dhi_catalog.py.
        counts["api" if request.url.host == "api.github.com" else "raw"] += 1
        return httpx.Response(200, text=body)

    return httpx.MockTransport(handler)


async def bench_catalog() -> None:
    """Catalogue index cost, cold and warm. A clone is never acceptable."""
    print("\n== DHI catalogue index ==")
    cache = _Cache()
    transport = _catalog_transport()

    counts.clear()
    client = DHICatalogClient(cache=cache, ttl_seconds=3600)
    client._client = httpx.AsyncClient(transport=transport)  # noqa: SLF001
    start = time.monotonic()
    variants = await client.variants("img0")
    cold = time.monotonic() - start
    cold_requests = counts["api"]
    await client.close()

    counts.clear()
    warm_client = DHICatalogClient(cache=cache, ttl_seconds=3600)
    warm_client._client = httpx.AsyncClient(transport=transport)  # noqa: SLF001
    start = time.monotonic()
    await warm_client.variants("img0")
    warm = time.monotonic() - start
    await warm_client.close()

    print("  catalogue blobs indexed    : 11000")
    print(f"  variants for one image     : {list(variants)}")
    print(f"  cold: {cold_requests} API request(s), {cold * 1000:.0f}ms")
    print(f"  warm: {counts['api']} API request(s), {warm * 1000:.0f}ms")
    print("  target: warm cache hit < 100ms and zero API requests")


def _analysis(i: int) -> ImageAnalysis:
    return ImageAnalysis(
        image=DockerImage(name="node", tag=f"t{i}"),
        scan=ScanResult(
            image_reference=f"node:t{i}",
            status=ScanStatus.OK,
            scan_timestamp="2026-01-01T00:00:00Z",
        ),
        security_score=float(i % 100),
        tier="B",
        remediation_score=i % 100,
        confidence=Confidence.HIGH if i % 3 else Confidence.MEDIUM,
        hardening=DimensionReport(score=float(i % 100), coverage=0.6, reportable=True),
        attack_surface=DimensionReport(score=float(i % 50), coverage=0.6, reportable=True),
    )


def bench_ranking() -> None:
    """Ranking a large candidate set must not be the bottleneck."""
    print("\n== multi-source ranking ==")
    for size in (100, 1000, 10_000):
        analyses = [_analysis(i) for i in range(size)]
        start = time.monotonic()
        ranked = rank(analyses)
        elapsed = time.monotonic() - start
        print(f"  {size:6d} candidates: {elapsed * 1000:7.1f}ms  (top={ranked[0].image.tag})")
    print("  target: 1000 candidates < 20ms")


async def main() -> None:
    await bench_deduplication()
    await bench_catalog()
    bench_ranking()


if __name__ == "__main__":
    asyncio.run(main())
