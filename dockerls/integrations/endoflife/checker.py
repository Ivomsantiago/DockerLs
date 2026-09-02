from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

import httpx
from loguru import logger

from dockerls.domain.interfaces.eol_checker import EOLCheckerInterface
from dockerls.domain.value_objects.tristate import Tristate
from dockerls.utils.retry import (
    DEFAULT_BACKOFF_BASE,
    DEFAULT_MAX_ATTEMPTS,
    retry_policy,
)

# Docker Hub image name -> endoflife.date product slug. Docker Hub names and
# endoflife.date slugs frequently diverge (e.g. "node" vs "nodejs").
DOCKER_TO_ENDOFLIFE: dict[str, str] = {
    "node": "nodejs",
    "python": "python",
    "postgres": "postgresql",
    "postgresql": "postgresql",
    "mysql": "mysql",
    "mariadb": "mariadb",
    "redis": "redis",
    "nginx": "nginx",
    "httpd": "apache",
    "php": "php",
    "ruby": "ruby",
    "golang": "go",
    "go": "go",
    "django": "django",
    "rails": "rails",
    "ubuntu": "ubuntu",
    "debian": "debian",
    "alpine": "alpine",
    "elasticsearch": "elasticsearch",
    "rabbitmq": "rabbitmq",
    "mongo": "mongodb",
    "mongodb": "mongodb",
    "dotnet": "dotnet",
    "grafana": "grafana",
    "prometheus": "prometheus",
    "kafka": "kafka",
    "cassandra": "cassandra",
    "erlang": "erlang",
    "haproxy": "haproxy",
    "jenkins": "jenkins",
    "traefik": "traefik",
}


def _version_parts(version: str) -> tuple[int, ...]:
    """Parse the leading numeric dot-separated segments of a version string."""
    parts: list[int] = []
    for segment in version.split("."):
        if segment.isdigit():
            parts.append(int(segment))
        else:
            break
    return tuple(parts)


def _cycle_matches(version: str, cycle: str) -> bool:
    """True if `version` falls under endoflife.date `cycle`, using SemVer-aware
    segment comparison (not naive substring prefix matching)."""
    vparts = _version_parts(version)
    cparts = _version_parts(cycle)
    if not vparts or not cparts:
        return version == cycle
    if len(cparts) > len(vparts):
        return False
    return vparts[: len(cparts)] == cparts


class EndOfLifeChecker(EOLCheckerInterface):
    BASE_URL = "https://endoflife.date/api"

    def __init__(
        self,
        timeout: int = 15,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        backoff_base: float = DEFAULT_BACKOFF_BASE,
    ):
        self._timeout = timeout
        self._max_attempts = max_attempts
        self._backoff_base = backoff_base
        self._cache: dict[str, list[dict[str, Any]]] = {}
        # One lock per product slug. The memo below only closes the window
        # *after* a response lands, and `recommend` asks `is_eol` + `is_lts`
        # for ~100 tags concurrently -- so a single-product run fired up to
        # 200 identical requests before the first one returned. That is the
        # rate limiting (and the resulting inconsistent EOL verdicts within
        # one run) that the memo was added to stop.
        self._locks: dict[str, asyncio.Lock] = {}

    def _resolve_product(self, product: str) -> str:
        return DOCKER_TO_ENDOFLIFE.get(product.lower(), product.lower())

    async def _fetch_product(self, product: str) -> list[dict[str, Any]]:
        slug = self._resolve_product(product)
        cached = self._cache.get(slug)
        if cached is not None:
            return cached

        lock = self._locks.setdefault(slug, asyncio.Lock())
        async with lock:
            cached = self._cache.get(slug)
            if cached is not None:
                return cached
            policy = retry_policy(self._max_attempts, self._backoff_base)
            result: list[dict[str, Any]] = await policy(self._fetch_product_once, product)
            return result

    async def _fetch_product_once(self, product: str) -> list[dict[str, Any]]:
        slug = self._resolve_product(product)
        if slug in self._cache:
            return self._cache[slug]
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            try:
                resp = await client.get(f"{self.BASE_URL}/{slug}.json")
                if resp.status_code == 200:
                    parsed = resp.json()
                    # A well-formed but wrongly-shaped body -- an object
                    # instead of the documented array, a cycle entry that
                    # is a bare string -- is as unusable as no body: every
                    # reader below calls `.get(...)` on each element. The
                    # `cast` this replaced was a type-checker annotation
                    # only, with no runtime effect on what actually came
                    # back over the wire.
                    if not isinstance(parsed, list):
                        logger.debug(f"EOL check for {slug} returned a non-array body")
                        self._cache[slug] = []
                        return []
                    data = [cycle for cycle in parsed if isinstance(cycle, dict)]
                    self._cache[slug] = data
                    return data
                if resp.status_code == 404:
                    # O produto não existe no catálogo -- uma resposta
                    # definitiva, e cacheável. Sem isso, cada uma das ~100
                    # tags de uma execução repetia a mesma consulta perdida
                    # (duas, contando is_eol e is_lts). Além do desperdício,
                    # o volume provocava rate limiting: parte das tags então
                    # recebia dados e parte recebia lista vazia, e a mesma
                    # execução emitia vereditos de EOL inconsistentes entre
                    # tags do mesmo produto.
                    self._cache[slug] = []
                    return []
                logger.debug(f"EOL check for {slug} returned HTTP {resp.status_code}")
                return []
            except (httpx.HTTPError, ValueError) as e:
                # `ValueError` covers `resp.json()` on a non-JSON body
                # (`json.JSONDecodeError` is a `ValueError` subclass) --
                # previously uncaught here, so a proxy error page served
                # as a 200 crashed the check instead of degrading it.
                logger.debug(f"EOL check failed for {slug}: {e}")
                return []

    def _find_cycle(self, cycles: list[dict[str, Any]], version: str) -> dict[str, Any] | None:
        best: dict[str, Any] | None = None
        best_len = -1
        for cycle in cycles:
            cycle_ver = str(cycle.get("cycle", ""))
            if _cycle_matches(version, cycle_ver):
                clen = len(_version_parts(cycle_ver))
                if clen > best_len:
                    best = cycle
                    best_len = clen
        return best

    async def is_eol(self, product: str, version: str) -> bool:
        """Whether this release is past its end-of-life date.

        Kept as the boolean the interface has always published. It answers
        `False` for "supported" *and* for "nobody could tell", which is why
        `eol_status` exists -- callers that can represent the difference
        should ask that instead.
        """
        return (await self.eol_status(product, version)).is_true

    async def eol_status(self, product: str, version: str) -> Tristate:
        """Three-valued end-of-life: TRUE, FALSE, or UNKNOWN.

        Every path that previously answered `False` had one of two very
        different meanings behind it, and collapsing them meant an image
        whose lifecycle nobody could look up was scored, and gated, exactly
        like one confirmed to be inside its support window:

        * no version could be extracted from the tag -- UNKNOWN;
        * the product is not in the catalogue (404) -- UNKNOWN;
        * the catalogue could not be reached -- UNKNOWN;
        * no cycle matches this version -- UNKNOWN;
        * the cycle exists and carries a date or a boolean -- TRUE/FALSE,
          the only two answers actually supported by evidence.
        """
        if not version:
            return Tristate.UNKNOWN
        cycles = await self._fetch_product(product)
        if not cycles:
            # Empty covers "unknown product" and "request failed" alike;
            # neither is a statement that the release is supported.
            return Tristate.UNKNOWN
        cycle = self._find_cycle(cycles, version)
        if cycle is None:
            return Tristate.UNKNOWN

        eol = cycle.get("eol")
        if isinstance(eol, bool):
            return Tristate.of(eol)
        if isinstance(eol, str):
            try:
                eol_date = datetime.strptime(eol, "%Y-%m-%d").replace(tzinfo=UTC)
            except ValueError:
                # A date the catalogue publishes but we cannot parse is a
                # gap in our reading of it, not a supported release.
                logger.debug(f"Unparseable EOL date for {product} {version}: {eol!r}")
                return Tristate.UNKNOWN
            return Tristate.of(datetime.now(tz=UTC) > eol_date)
        # `eol: false` arrives as a bool; anything else (null, missing) means
        # the catalogue has not set a date yet.
        return Tristate.UNKNOWN

    async def is_lts(self, product: str, version: str) -> bool:
        if not version:
            return False
        cycles = await self._fetch_product(product)
        cycle = self._find_cycle(cycles, version)
        if cycle is None:
            return False
        return bool(cycle.get("lts", False))
