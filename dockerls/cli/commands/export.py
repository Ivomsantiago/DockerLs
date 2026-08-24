from __future__ import annotations

import asyncio
from pathlib import Path

import typer
from rich.console import Console

from dockerls.cli.dependencies import build_recommend_use_case, resolve_tag_limit
from dockerls.cli.image_names import reject_tagged_reference
from dockerls.cli.validators import check_limit, check_workers
from dockerls.exit_codes import EXIT_ERROR
from dockerls.exporters.factory import ExporterFactory

console = Console()


def export(
    image: str = typer.Argument(
        help=(
            "Docker image name only, without a tag (e.g. 'node', not 'node:18'). "
            "Use 'analyze' or 'advisor' for a specific tag."
        )
    ),
    output_format: str = typer.Option(
        "json", "--format", "-f", help="Export format: json, csv, html, markdown, sarif"
    ),
    output: str = typer.Option("", "--output", "-o", help="Output file path (default: stdout)"),
    workers: int | None = typer.Option(
        None, "--workers", "-w", help="Concurrent workers [config: workers, default 10]"
    ),
    limit: int | None = typer.Option(
        None, "--limit", "-l", help="Max tags to scan [config: max_tags, default 100]"
    ),
) -> None:
    """Export analysis results in various formats."""
    # `None` means "not given", so the configured value applies; only an
    # explicitly supplied value is range-checked here.
    if workers is not None:
        workers = check_workers(workers)
    if limit is not None:
        limit = check_limit(limit)
    error = reject_tagged_reference(image, "export")
    if error:
        console.print(f"[red]{error}[/red]")
        raise typer.Exit(EXIT_ERROR)
    try:
        asyncio.run(_export(image, output_format, output, workers, limit))
    except ValueError as e:
        console.print(f"[red]Invalid configuration:[/red] {e}")
        raise typer.Exit(EXIT_ERROR) from e


async def _export(
    image: str, fmt: str, output: str, workers: int | None, limit: int | None
) -> None:
    # Same fallback as `recommend`: omitting a flag means "use the
    # configured value", rather than a hard-coded default shadowing it.
    use_case = await build_recommend_use_case(workers=workers)
    result = await use_case.execute(image, limit=resolve_tag_limit(limit))

    try:
        exporter = ExporterFactory.create(fmt)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(EXIT_ERROR) from e

    if output:
        path = Path(output)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            exporter.export(result, path)
        except OSError as e:
            # An unwritable destination is user error, not a crash.
            console.print(f"[red]Could not write {path}:[/red] {e}")
            raise typer.Exit(EXIT_ERROR) from e
        console.print(f"[green]Report exported to {path}[/green]")
    else:
        # soft_wrap avoids Rich reflowing/inserting newlines into
        # machine-readable output (JSON, CSV, SARIF).
        console.print(exporter.export_string(result), soft_wrap=True)
