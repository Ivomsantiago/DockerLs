from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

import typer
from rich.console import Console
from rich.table import Table

from dockerls.cli.dependencies import build_cache
from dockerls.exit_codes import EXIT_ERROR

if TYPE_CHECKING:
    from collections.abc import Coroutine

console = Console()
cache_app = typer.Typer(help="Manage the scan cache")


def _run(coro: Coroutine[Any, Any, None]) -> None:
    """Run a cache operation, reporting storage failures as user errors.

    A corrupt or unreadable cache database is a normal operational state --
    it must not exit with a traceback, especially for `clear`, which is
    exactly what a user reaches for when the cache is broken.
    """
    # Import tardio: `sqlalchemy.exc` arrasta o SQLAlchemy inteiro, e este
    # módulo é importado no arranque de *toda* invocação do CLI para registrar
    # o subcomando. Aqui dentro ele só é pago por quem realmente mexe no cache.
    from sqlalchemy.exc import SQLAlchemyError

    try:
        asyncio.run(coro)
    except (OSError, SQLAlchemyError) as e:
        console.print(f"[red]Cache operation failed:[/red] {e}")
        raise typer.Exit(EXIT_ERROR) from e


@cache_app.command("clear")
def cache_clear() -> None:
    """Clear all cached scan results."""
    _run(_clear())


async def _clear() -> None:
    cache = build_cache()
    await cache.clear()
    console.print("[green]Cache cleared.[/green]")


@cache_app.command("cleanup")
def cache_cleanup() -> None:
    """Remove expired cache entries."""
    _run(_cleanup())


async def _cleanup() -> None:
    cache = build_cache()
    count = await cache.cleanup_expired()
    console.print(f"[green]Removed {count} expired entries.[/green]")


@cache_app.command("stats")
def cache_stats() -> None:
    """Show cache size, entry count, and how much is reclaimable."""
    _run(_stats())


async def _stats() -> None:
    """Report what the cache is holding.

    Entries expire lazily -- a stale row is dropped when it is next read --
    so a cache can carry entries for tags nobody asks about again. Without a
    way to see that, "why is this directory large" and "would cleanup help"
    were both unanswerable.
    """
    cache = build_cache()
    stats = await cache.stats()

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Field", style="bold")
    table.add_column("Value")
    table.add_row("Location", stats.path)
    table.add_row("Entries", str(stats.total))
    table.add_row("Expired (reclaimable)", str(stats.expired))
    table.add_row("Size on disk", _human_bytes(stats.size_bytes))
    console.print(table)

    if stats.expired:
        console.print(
            f"\n[dim]Run `dockerls cache cleanup` to remove {stats.expired} expired entries.[/dim]"
        )


def _human_bytes(size: int) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{value:.1f} GB"  # pragma: no cover - unreachable, loop returns first
