from __future__ import annotations

import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from loguru import logger

from dockerls.infrastructure.redaction import redact

if TYPE_CHECKING:
    from loguru import Record


_FILE_FORMAT = "{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | {name}:{function}:{line} - {message}"
_CONSOLE_FORMAT = (
    "<level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan> - {message}"
)


def _log_filter(record: Record) -> bool:
    record["message"] = redact(record["message"])
    return True


def _resolve_log_file(log_dir: Path) -> Path | None:
    """Return a writable `<log_dir>/dockerls_<timestamp>.log`, or None when
    no directory in the fallback chain can be created."""
    stamp = datetime.now(tz=UTC).strftime("%Y-%m-%d_%H-%M-%S")
    candidates = [log_dir]
    fallback = Path.home() / ".cache" / "dockerls" / "logs"
    if fallback != log_dir:
        candidates.append(fallback)

    for candidate in candidates:
        try:
            candidate.mkdir(parents=True, exist_ok=True)
            path = candidate / f"dockerls_{stamp}.log"
            path.touch()
        except OSError:
            continue
        return path
    return None


# Nothing below this level ever reaches the terminal on its own. Normal CLI
# use is not a debugging session: an INFO line on stderr is noise a pipeline
# has to filter out, and it corrupts the Rich progress display.
DEFAULT_CONSOLE_LEVEL = "WARNING"


def setup_logging(
    level: str = "INFO",
    log_dir: Path | None = None,
    console: bool = False,
    console_level: str | None = None,
) -> Path | None:
    """Route diagnostics to a rotating log file instead of the terminal.

    The CLI owns the terminal (Rich progress bars and tables), so loguru's
    default stderr sink is always removed: scanner failures, retries and
    debug chatter would otherwise interleave with -- and corrupt -- the
    progress display. Set `console=True` (``--verbose``) to opt back into
    stderr logging on top of the file sink.

    `level` is the file sink's level; `console_level` is the stderr sink's
    and defaults to WARNING regardless of `level`, so raising
    DOCKERLS_LOG_LEVEL to DEBUG for the log file never starts spraying the
    terminal. ``--verbose`` passes `console_level` explicitly to raise it.

    Returns the active log file path so callers can point the user at it.
    """
    logger.remove()

    log_file = _resolve_log_file(log_dir or Path("logs"))
    if log_file is not None:
        logger.add(
            log_file,
            level=level.upper(),
            format=_FILE_FORMAT,
            filter=_log_filter,
            enqueue=True,
            retention=20,
            encoding="utf-8",
        )

    if console or log_file is None:
        logger.add(
            sys.stderr,
            level=(console_level or DEFAULT_CONSOLE_LEVEL).upper(),
            format=_CONSOLE_FORMAT,
            filter=_log_filter,
        )

    return log_file
