from __future__ import annotations

import asyncio
import json
import time
from typing import TYPE_CHECKING, Any, NamedTuple, cast

from sqlalchemy import CursorResult, delete, func, select
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from dockerls.domain.interfaces.cache_store import CacheStoreInterface
from dockerls.infrastructure.database.models import CacheEntry, create_db_engine

if TYPE_CHECKING:
    from pathlib import Path

    from sqlalchemy.orm import Session

# Bump this when the shape of cached payloads changes so stale entries from
# an older schema are treated as misses instead of crashing on load.
# v2: ImageAnalysis gained verification metadata (scan evidence paths, Hub
# tag state, scanner divergence) and ScanResult gained `evidence_path`.
# v3: ImageAnalysis gained the assessment fields (hardening facts, hardening
# and attack-surface reports, confidence, why/trade-offs) and ScanResult
# gained the scanner-reported base distribution. A v2 row would still
# *validate* against the new model -- pydantic would fill the missing fields
# with their defaults -- and that is exactly the problem: the defaults are
# "nothing determined" and `UNVERIFIED`, so a stale row would present an
# image as uninspected rather than as unscanned. Orphaning the old rows
# costs one cold run and removes the ambiguity entirely.
# v4: ImageAnalysis gained the readiness verdict (production_ready is now
# written by the central policy, and its default flipped to False), the
# three-valued EOL status, and the cross-validation outcome; Vulnerability
# gained the three-valued KEV status and the EPSS provenance fields. A v3 row
# would validate and fill all of them with defaults -- which read as
# "nothing determined" and would present a cached image as uninspected
# rather than as measured.
CACHE_SCHEMA_VERSION = "v4"


class CacheStats(NamedTuple):
    """What `dockerls cache stats` reports.

    Entries expire lazily -- a stale row is dropped when it is next read --
    so `expired` is the amount `dockerls cache cleanup` would reclaim right
    now, and the gap between it and `total` is what the cache is holding on
    to for nothing.
    """

    total: int
    expired: int
    size_bytes: int
    path: str


class SQLiteCache(CacheStoreInterface):
    def __init__(self, db_path: Path):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._db_path = db_path
        self._engine, self._session_factory = create_db_engine(str(db_path))

    def _session(self) -> Session:
        return self._session_factory()

    def close(self) -> None:
        """Dispose the SQLAlchemy engine and release its pooled connection.

        Nothing here ever called this: the engine opened in `__init__` lived
        until the process exited, which is why `pytest` -- which keeps the
        interpreter running across thousands of these -- reported unclosed
        `sqlite3.Connection` objects (`ResourceWarning`) from tests that
        never mention caching at all. A short-lived CLI invocation masked
        the same leak by exiting anyway.
        """
        self._engine.dispose()

    def __enter__(self) -> SQLiteCache:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def _versioned_key(self, key: str) -> str:
        return f"{CACHE_SCHEMA_VERSION}:{key}"

    async def get(self, key: str) -> Any | None:
        return await asyncio.to_thread(self._get_sync, key)

    def _get_sync(self, key: str) -> Any | None:
        vkey = self._versioned_key(key)
        with self._session() as session:
            stmt = select(CacheEntry).where(CacheEntry.key == vkey)
            entry = session.execute(stmt).scalar_one_or_none()
            if entry is None:
                return None
            if entry.expires_at < time.time():
                session.delete(entry)
                session.commit()
                return None
            return json.loads(entry.value)

    async def set(self, key: str, value: Any, ttl_seconds: int = 86400) -> None:
        await asyncio.to_thread(self._set_sync, key, value, ttl_seconds)

    def _set_sync(self, key: str, value: Any, ttl_seconds: int) -> None:
        vkey = self._versioned_key(key)
        serialized = json.dumps(value, default=str)
        expires_at = time.time() + ttl_seconds
        # Writes run on a thread pool (`asyncio.to_thread`) and `recommend`
        # issues them concurrently, so select-then-insert had a real window:
        # two threads could both miss and then both INSERT the same unique
        # key. A single atomic upsert closes it -- SQLite's ON CONFLICT does
        # the check and the write in one statement.
        stmt = (
            sqlite_insert(CacheEntry)
            .values(key=vkey, value=serialized, expires_at=expires_at)
            .on_conflict_do_update(
                index_elements=[CacheEntry.key],
                set_={"value": serialized, "expires_at": expires_at},
            )
        )
        with self._session() as session:
            session.execute(stmt)
            session.commit()

    async def delete(self, key: str) -> None:
        await asyncio.to_thread(self._delete_sync, key)

    def _delete_sync(self, key: str) -> None:
        vkey = self._versioned_key(key)
        with self._session() as session:
            session.execute(delete(CacheEntry).where(CacheEntry.key == vkey))
            session.commit()

    async def clear(self) -> None:
        await asyncio.to_thread(self._clear_sync)

    def _clear_sync(self) -> None:
        with self._session() as session:
            session.execute(delete(CacheEntry))
            session.commit()

    async def cleanup_expired(self) -> int:
        return await asyncio.to_thread(self._cleanup_expired_sync)

    def _cleanup_expired_sync(self) -> int:
        with self._session() as session:
            stmt = delete(CacheEntry).where(CacheEntry.expires_at < time.time())
            result = cast("CursorResult[Any]", session.execute(stmt))
            session.commit()
            return result.rowcount

    async def stats(self) -> CacheStats:
        return await asyncio.to_thread(self._stats_sync)

    def _stats_sync(self) -> CacheStats:
        now = time.time()
        with self._session() as session:
            total = session.execute(select(func.count()).select_from(CacheEntry)).scalar_one()
            expired = session.execute(
                select(func.count()).select_from(CacheEntry).where(CacheEntry.expires_at < now)
            ).scalar_one()
        return CacheStats(
            total=int(total),
            expired=int(expired),
            size_bytes=self._size_on_disk(),
            path=str(self._db_path),
        )

    def _size_on_disk(self) -> int:
        """Bytes the cache occupies, including the WAL sidecar.

        The write-ahead log holds committed data that has not been
        checkpointed back into the main file yet, so reporting only the
        `.db` would understate the footprint -- sometimes by most of it.
        """
        total = 0
        for suffix in ("", "-wal", "-shm"):
            part = self._db_path.with_name(self._db_path.name + suffix)
            try:
                total += part.stat().st_size
            except OSError:
                continue
        return total
