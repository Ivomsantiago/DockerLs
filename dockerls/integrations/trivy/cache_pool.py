from __future__ import annotations

import asyncio
import contextlib
import os
import shutil
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from loguru import logger

if TYPE_CHECKING:
    from collections.abc import AsyncIterator


def default_trivy_cache_dir() -> Path:
    """Mirror Trivy's own default cache location resolution."""
    env = os.environ.get("TRIVY_CACHE_DIR")
    if env:
        return Path(env)
    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg:
        return Path(xdg) / "trivy"
    return Path.home() / ".cache" / "trivy"


class TrivyCachePool:
    """Hands out an isolated ``--cache-dir`` to each concurrent Trivy scan.

    Root cause of the "cache may be in use by another process: timeout"
    errors: Trivy takes an exclusive BoltDB lock on its cache directory, so
    N parallel `trivy image` calls sharing one cache dir serialize on that
    lock and the losers time out and exit non-zero.

    The fix is to give every in-flight scan its own cache directory. The
    vulnerability DB itself is downloaded once into the shared cache and
    then **hard-linked** into each slot -- a copy would multiply a
    multi-hundred-MB DB by the worker count.

    If hard-linking is unavailable (different filesystem, restricted
    permissions) the pool degrades to a single slot pointing at the shared
    cache dir. That serializes scans, which is slower but still correct --
    only one process touches the lock at a time, so nothing times out.
    """

    _DB_FILES = ("trivy.db", "metadata.json")

    def __init__(self, base_cache_dir: Path, size: int):
        self._base = base_cache_dir
        self._size = max(1, size)
        self._slots: asyncio.Queue[Path] | None = None
        # A mesma lista que alimenta a fila, guardada para quem faz o
        # próprio rodízio -- a engine Go recebe todos os slots de uma vez e
        # os reveza por dentro, em vez de pedir um por scan.
        self._slot_paths: list[Path] = []
        self._temp_dirs: list[Path] = []
        self._isolated = False
        # prepare() awaits before assigning _slots, so concurrent first
        # scans could otherwise each build a full pool -- leaking temp dirs
        # and handing out more slots than there are workers.
        self._prepare_lock = asyncio.Lock()

    @property
    def isolated(self) -> bool:
        """True when each concurrent scan got its own cache directory."""
        return self._isolated

    @property
    def base_dir(self) -> Path:
        return self._base

    async def prepare(self) -> bool:
        """Build the slot pool. Returns True when isolation was achieved."""
        await self._ensure_slots()
        return self._isolated

    async def _ensure_slots(self) -> asyncio.Queue[Path]:
        if self._slots is not None:
            return self._slots

        async with self._prepare_lock:
            if self._slots is not None:
                return self._slots

            slots: list[Path] = []
            if self._size > 1:
                slots = await asyncio.to_thread(self._build_isolated_slots)

            if slots:
                self._isolated = True
            else:
                if self._size > 1:
                    logger.warning(
                        "Falling back to a single shared Trivy cache dir; scans will be "
                        "serialized to avoid cache lock contention"
                    )
                slots = [self._base]
                self._isolated = False

            queue: asyncio.Queue[Path] = asyncio.Queue()
            for slot in slots:
                queue.put_nowait(slot)
            self._slot_paths = list(slots)
            self._slots = queue
            return queue

    def _build_isolated_slots(self) -> list[Path]:
        db_dir = self._base / "db"
        sources = [db_dir / name for name in self._DB_FILES]
        if not all(src.exists() for src in sources):
            logger.warning(f"Trivy DB not found under {db_dir}; cannot build isolated cache dirs")
            return []

        parent = self._base.parent
        try:
            parent.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            logger.warning(f"Cannot create Trivy cache pool parent {parent}: {e}")
            return []

        slots: list[Path] = []
        for _ in range(self._size):
            try:
                slot = Path(tempfile.mkdtemp(prefix="dockerls-trivy-", dir=parent))
            except OSError as e:
                logger.warning(f"Cannot create isolated Trivy cache dir: {e}")
                break
            self._temp_dirs.append(slot)
            try:
                (slot / "db").mkdir(parents=True, exist_ok=True)
                for src in sources:
                    os.link(src, slot / "db" / src.name)
            except OSError as e:
                logger.warning(f"Cannot hard-link Trivy DB into {slot}: {e}")
                break
            slots.append(slot)

        if len(slots) < self._size:
            # Partial pools are still safe, but an empty one is not usable.
            logger.warning(f"Prepared {len(slots)}/{self._size} isolated Trivy cache dirs")
        return slots

    async def slot_paths(self) -> list[Path]:
        """Todos os slots do pool, para um chamador que faz o próprio rodízio.

        `acquire()` empresta um slot por vez, que é o que o pipeline Python
        precisa. A engine Go recebe o lote inteiro e reveza por dentro, e
        para isso precisa da lista.
        """
        await self._ensure_slots()
        return list(self._slot_paths)

    @contextlib.asynccontextmanager
    async def acquire(self) -> AsyncIterator[Path]:
        slots = await self._ensure_slots()
        slot = await slots.get()
        try:
            yield slot
        finally:
            slots.put_nowait(slot)

    async def cleanup(self) -> None:
        """Remove every temporary cache dir created by this pool."""
        dirs, self._temp_dirs = self._temp_dirs, []
        if not dirs:
            return
        await asyncio.to_thread(self._cleanup_sync, dirs)

    @staticmethod
    def _cleanup_sync(dirs: list[Path]) -> None:
        for path in dirs:
            try:
                shutil.rmtree(path, ignore_errors=True)
            except OSError as e:  # pragma: no cover - rmtree already swallows
                logger.warning(f"Could not remove temporary Trivy cache dir {path}: {e}")
