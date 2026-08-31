from __future__ import annotations

import asyncio

import typer
from rich.console import Console
from rich.table import Table

from dockerls.application.services.source_registry import UnknownSourceError
from dockerls.cli.dependencies import build_search_use_case
from dockerls.cli.image_names import reject_tagged_reference
from dockerls.cli.progress import scan_status
from dockerls.cli.validators import check_limit
from dockerls.exit_codes import EXIT_ERROR

console = Console()


def search(
    image: str = typer.Argument(
        help=(
            "Docker image name only, without a tag (e.g. 'node', not 'node:18'). "
            "Use 'analyze' or 'advisor' for a specific tag."
        )
    ),
    limit: int = typer.Option(100, "--limit", "-l", help="Maximum tags to retrieve"),
    source: list[str] = typer.Option(
        [],
        "--source",
        "-s",
        help=(
            "Image source to search; repeatable. "
            "One of: dockerhub, chainguard, distroless, dhi, private (if configured), all"
        ),
    ),
    all_sources: bool = typer.Option(
        False, "--all-sources", help="Search every configured source, including opt-in ones"
    ),
) -> None:
    """Search for available tags of an image, on Docker Hub or any configured source."""
    limit = check_limit(limit)
    error = reject_tagged_reference(image, "search")
    if error:
        console.print(f"[red]{error}[/red]")
        raise typer.Exit(EXIT_ERROR)
    try:
        asyncio.run(_search(image, limit, list(source) or None, all_sources))
    except UnknownSourceError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(EXIT_ERROR) from e
    except ValueError as e:
        # `sanitize_image_name` rejects a malformed reference inside the
        # client; surfacing it as a message keeps `search` in line with
        # every other command instead of answering with a stack trace.
        console.print(f"[red]Invalid image reference:[/red] {e}")
        raise typer.Exit(EXIT_ERROR) from e


async def _search(
    image: str,
    limit: int,
    sources: list[str] | None = None,
    all_sources: bool = False,
) -> None:
    use_case = await build_search_use_case(sources, all_sources=all_sources)
    with scan_status(f"Searching tags for {image}..."):
        tags = await use_case.execute(image, limit=limit)

    if not tags:
        console.print(f"[red]No tags found for '{image}'[/red]")
        raise typer.Exit(EXIT_ERROR)

    table = Table(title=f"Tags for {image}")
    table.add_column("Tag", style="cyan")
    table.add_column("Source", style="magenta")
    table.add_column("Size (MB)", justify="right")
    table.add_column("Architecture")
    table.add_column("Last Updated")
    table.add_column("Official", justify="center")

    for tag in tags:
        size_mb = f"{tag.size_bytes / (1024 * 1024):.1f}" if tag.size_bytes else "-"
        updated = tag.last_updated.strftime("%Y-%m-%d") if tag.last_updated else "-"
        official = "Yes" if tag.is_official else "No"
        table.add_row(tag.tag, tag.source, size_mb, tag.architecture, updated, official)

    console.print(table)
    console.print(f"\n[dim]Total: {len(tags)} tags[/dim]")
