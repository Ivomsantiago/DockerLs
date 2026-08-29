"""Where an image's vulnerability-count history persists between runs.

Mirrors `tag_history_store.py` exactly, for the same reason its own module
docstring gives: the cache that scores lean on expires because a stale
score is worse than none, while a history *is* the past and is worth more
the longer it has been kept. A year-long TTL, renewed on every write, is
what lets the second observation ever recorded still answer "since when".
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from loguru import logger

from dockerls.domain.value_objects.scan_history import ScanHistory, ScanObservation, record

if TYPE_CHECKING:
    from dockerls.domain.interfaces.cache_store import CacheStoreInterface

#: A year, matching `tag_history_store.HISTORY_TTL_SECONDS`: this is the
#: past, and it does not go stale.
HISTORY_TTL_SECONDS = 365 * 24 * 60 * 60

_KEY_PREFIX = "scan-history"


class ScanHistoryStore:
    """Reads and writes vulnerability-count history, keyed by reference."""

    def __init__(self, cache: CacheStoreInterface | None = None):
        self._cache = cache

    async def get(self, reference: str) -> ScanHistory:
        """The stored history, or an empty one when there is none (or it
        could not be read)."""
        if self._cache is None or not reference:
            return ScanHistory(reference=reference)
        try:
            raw = await self._cache.get(_key(reference))
        except Exception as e:  # pragma: no cover - the cache is the unstable path
            logger.debug(f"Could not read the scan history of {reference}: {e}")
            return ScanHistory(reference=reference)
        return ScanHistory.from_dict(reference, raw)

    async def observe(
        self,
        reference: str,
        *,
        digest: str,
        critical: int,
        high: int,
        medium: int,
        low: int,
        total: int,
        observed_at: datetime | None = None,
    ) -> ScanHistory:
        """Incorporates this scan's counts and returns the resulting history.

        Writes only when something changed: rewriting an unchanged entry on
        every query would do nothing but renew the TTL, which the write
        that matters already does.
        """
        current = await self.get(reference)
        observation = ScanObservation(
            digest=digest,
            observed_at=(observed_at or datetime.now(UTC)).isoformat(timespec="seconds"),
            critical=critical,
            high=high,
            medium=medium,
            low=low,
            total=total,
        )
        updated = record(current, observation)
        if updated is current or self._cache is None:
            return updated
        try:
            await self._cache.set(
                _key(reference), updated.to_dict(), ttl_seconds=HISTORY_TTL_SECONDS
            )
        except Exception as e:  # pragma: no cover - the cache is the unstable path
            logger.debug(f"Could not write the scan history of {reference}: {e}")
        return updated


def _key(reference: str) -> str:
    return f"{_KEY_PREFIX}:{reference}"
