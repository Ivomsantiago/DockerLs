from __future__ import annotations

import asyncio
import math
from typing import TYPE_CHECKING

import httpx
from loguru import logger

if TYPE_CHECKING:
    from dockerls.domain.interfaces.cache_store import CacheStoreInterface

#: Smallest catalogue that could plausibly be the real KEV feed. It has
#: carried more than a thousand entries since 2023 and only grows, so a
#: floor an order of magnitude below that discriminates against proxy error
#: pages and truncated transfers, not against the feed.
MIN_PLAUSIBLE_KEV_ENTRIES = 100


def _probability(value: object) -> float | None:
    """A finite 0.0-1.0 float, or None when the value is not one."""
    try:
        number = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    if not math.isfinite(number) or not (0.0 <= number <= 1.0):
        return None
    return number


class ThreatIntelClient:
    """Best-effort CISA KEV + FIRST EPSS lookups. Both sources are treated
    as optional enrichment: any network/parse failure degrades to "no
    signal" (empty set / 0.0 score) instead of breaking the scan."""

    KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    EPSS_URL = "https://api.first.org/data/v1/epss"

    # Both feeds move roughly daily -- KEV gets a handful of new entries a
    # day, EPSS republishes once a day -- so a fresher copy buys nothing and
    # costs a full re-download (KEV) or one HTTP round trip per CVE (EPSS)
    # on every single invocation. Without this, `recommend` re-fetched the
    # whole KEV catalogue and re-queried EPSS for every CRITICAL/HIGH CVE on
    # every run, even back-to-back runs against the same image.
    CACHE_TTL_SECONDS = 24 * 60 * 60
    _KEV_CACHE_KEY = "threat-intel:kev:v1"
    _EPSS_CACHE_PREFIX = "threat-intel:epss:v1:"

    def __init__(
        self,
        timeout: int = 15,
        cache: CacheStoreInterface | None = None,
        min_kev_entries: int = MIN_PLAUSIBLE_KEV_ENTRIES,
    ):
        self._timeout = timeout
        self._cache = cache
        # Injectable so a test can exercise the parsing path with a small
        # fixture without lowering the floor that protects real runs.
        self._min_kev_entries = min_kev_entries
        self._kev_ids: set[str] | None = None
        # Whether each feed actually answered during this run. Without this,
        # "no KEV hits" and "the KEV catalogue was unreachable" are the same
        # empty set, and the caller cannot tell a negative finding from a
        # missing lookup.
        self._kev_available: bool | None = None
        self._epss_available: bool | None = None
        # EPSS percentiles, kept alongside the probabilities. A probability
        # of 0.42 means little on its own; the percentile says where that
        # sits among everything FIRST scored, which is what makes it
        # comparable between runs on different days.
        self._percentiles: dict[str, float] = {}
        # `recommend` enriches every tag concurrently, and the memo below is
        # only populated *after* the first download finishes. Without this
        # lock, a 100-tag run started 100 simultaneous downloads of the same
        # multi-megabyte KEV catalogue -- a self-inflicted burst against
        # cisa.gov that the memo was written to prevent.
        self._kev_lock = asyncio.Lock()

    async def _load_kev(self) -> set[str]:
        if self._kev_ids is not None:
            return self._kev_ids
        async with self._kev_lock:
            if self._kev_ids is not None:
                return self._kev_ids
            cached = await self._kev_from_cache()
            if cached is not None:
                self._kev_available = True
                self._kev_ids = cached
                return self._kev_ids
            self._kev_ids = await self._fetch_kev()
            if self._kev_ids:
                await self._store_kev_cache(self._kev_ids)
        return self._kev_ids

    async def _kev_from_cache(self) -> set[str] | None:
        if self._cache is None:
            return None
        try:
            data = await self._cache.get(self._KEV_CACHE_KEY)
        except Exception as e:  # pragma: no cover - an unreadable cache is a miss
            logger.debug(f"Could not read the cached KEV catalogue: {e}")
            return None
        if not isinstance(data, list) or not data:
            return None
        return {str(cve).upper() for cve in data}

    async def _store_kev_cache(self, ids: set[str]) -> None:
        if self._cache is None:
            return
        try:
            await self._cache.set(
                self._KEV_CACHE_KEY, sorted(ids), ttl_seconds=self.CACHE_TTL_SECONDS
            )
        except Exception as e:  # pragma: no cover - a cache that will not write is not fatal
            logger.debug(f"Could not cache the KEV catalogue: {e}")

    @property
    def kev_available(self) -> bool | None:
        """True once the KEV catalogue answered, False after it failed,
        None before anything was asked."""
        return self._kev_available

    @property
    def epss_available(self) -> bool | None:
        """True once at least one EPSS batch answered; see `kev_available`."""
        return self._epss_available

    async def _fetch_kev(self) -> set[str]:
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.get(self.KEV_URL)
                resp.raise_for_status()
                data = resp.json()
                entries = data.get("vulnerabilities", [])
                if not isinstance(entries, list):
                    raise ValueError(f"KEV payload 'vulnerabilities' was {type(entries).__name__}")
                ids = {
                    str(v.get("cveID", "")).upper()
                    for v in entries
                    if isinstance(v, dict) and v.get("cveID")
                }
                # A short catalogue is not a successful lookup either. The
                # real feed carries thousands of entries, so a handful means
                # a proxy error page, a truncated transfer or a captive
                # portal parsed as JSON. Accepting it would mark every CVE
                # not in that handful as `kev_status = FALSE` -- an
                # affirmative "not known to be exploited" derived from a
                # response that was never the catalogue.
                self._kev_available = len(ids) >= self._min_kev_entries
                if ids and not self._kev_available:
                    logger.warning(
                        f"CISA KEV answered with only {len(ids)} entries, far below the "
                        f"{self._min_kev_entries} a real catalogue carries; treating "
                        f"exploitation status as UNKNOWN rather than trusting it"
                    )
                    return set()
                return ids
        except (httpx.HTTPError, ValueError) as e:
            logger.warning(
                f"CISA KEV catalog unavailable: exploitation status will be UNKNOWN ({e})"
            )
            self._kev_available = False
            return set()

    async def known_exploited(self, cve_ids: list[str]) -> set[str]:
        """Return the subset of `cve_ids` present in the CISA KEV catalog."""
        if not cve_ids:
            return set()
        kev = await self._load_kev()
        return {cve.upper() for cve in cve_ids if cve.upper() in kev}

    # A API do FIRST pagina o resultado e a query vai na URL. Pedir 200 CVEs
    # de uma vez devolvia calado só a primeira página -- e o restante perdia
    # o sinal de EPSS justamente nas imagens que mais têm CRITICAL/HIGH, que
    # são as que mais precisam dele. O lote é pedido com `limit` explícito
    # em vez de confiar no default do serviço.
    EPSS_BATCH_SIZE = 100

    async def epss_scores(self, cve_ids: list[str]) -> dict[str, float]:
        """Return {cve_id: epss_probability} for whatever FIRST.org returns;
        missing/unreachable CVEs are simply absent from the result.

        Checked against the cache first, one CVE at a time: `recommend`
        enriches dozens of tags of the same image family, and their
        CRITICAL/HIGH findings overlap heavily (the same OS package CVE
        shows up in `node:20`, `node:22` and every variant of each). Without
        this, every one of those tags re-queried FIRST.org for CVEs this
        process, or an earlier run today, had already scored.
        """
        if not cve_ids:
            return {}

        wanted = sorted({cve.upper() for cve in cve_ids})
        scores: dict[str, float] = {}
        if self._cache is not None:
            cached = await asyncio.gather(*[self._epss_from_cache(cve) for cve in wanted])
            for cve, hit in zip(wanted, cached, strict=True):
                if hit is not None:
                    scores[cve] = hit[0]
                    self._percentiles[cve] = hit[1]
        missing = [cve for cve in wanted if cve not in scores]
        if cached_hit := bool(scores):
            self._epss_available = True

        if missing:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                for start in range(0, len(missing), self.EPSS_BATCH_SIZE):
                    batch = missing[start : start + self.EPSS_BATCH_SIZE]
                    # Um lote que falha não pode descartar os que já vieram: o
                    # sinal parcial ainda é melhor que nenhum.
                    batch_scores = await self._epss_batch(client, batch)
                    if batch_scores:
                        self._epss_available = True
                    scores.update(batch_scores)
                    await self._store_epss_cache(batch_scores)
        if self._epss_available is None and not cached_hit:
            # Every batch came back empty and nothing was cached: either the
            # service is down or it knows none of these CVEs. Neither
            # supports a claim of low exploitation probability.
            self._epss_available = False
        return scores

    async def _epss_from_cache(self, cve: str) -> tuple[float, float] | None:
        if self._cache is None:
            return None
        try:
            data = await self._cache.get(self._EPSS_CACHE_PREFIX + cve)
        except Exception as e:  # pragma: no cover - an unreadable cache is a miss
            logger.debug(f"Could not read the cached EPSS score for {cve}: {e}")
            return None
        if not isinstance(data, dict) or "score" not in data:
            return None
        score = _probability(data["score"])
        if score is None:
            # A row written before this check existed may still carry a
            # NaN/out-of-range value on disk; treat it the same as a miss
            # rather than serving it back as a probability.
            return None
        percentile = _probability(data.get("percentile", 0.0)) or 0.0
        return score, percentile

    async def _store_epss_cache(self, batch_scores: dict[str, float]) -> None:
        if self._cache is None or not batch_scores:
            return
        for cve, score in batch_scores.items():
            payload = {"score": score, "percentile": self._percentiles.get(cve, 0.0)}
            try:
                await self._cache.set(
                    self._EPSS_CACHE_PREFIX + cve, payload, ttl_seconds=self.CACHE_TTL_SECONDS
                )
            except Exception as e:  # pragma: no cover - a cache that will not write is not fatal
                logger.debug(f"Could not cache the EPSS score for {cve}: {e}")

    def percentile_of(self, cve_id: str) -> float:
        """EPSS percentile for `cve_id`, or 0.0 when the source did not
        provide one. Only meaningful when `epss_available` is True."""
        return self._percentiles.get(cve_id.upper(), 0.0)

    async def _epss_batch(self, client: httpx.AsyncClient, batch: list[str]) -> dict[str, float]:
        try:
            resp = await client.get(
                self.EPSS_URL,
                params={"cve": ",".join(batch), "limit": str(len(batch))},
            )
            resp.raise_for_status()
            data = resp.json()
            scores: dict[str, float] = {}
            for entry in data.get("data", []):
                if "cve" not in entry or "epss" not in entry:
                    continue
                cve = entry["cve"].upper()
                probability = _probability(entry["epss"])
                if probability is None:
                    # `float()` accepts "nan", "inf" and "-1"; none of them
                    # is a probability, and all of them reached the scoring
                    # engine. Dropping the CVE from the result leaves it
                    # `epss_known = False` downstream, which is the honest
                    # reading: the feed answered, but not with a number.
                    logger.warning(
                        f"Discarding implausible EPSS value for {cve}: {entry['epss']!r}"
                    )
                    continue
                scores[cve] = probability
                percentile = _probability(entry.get("percentile"))
                if percentile is not None:
                    self._percentiles[cve] = percentile
            return scores
        except (httpx.HTTPError, ValueError, KeyError, TypeError) as e:
            logger.debug(f"EPSS lookup unavailable for {len(batch)} CVEs, continuing without: {e}")
            return {}
