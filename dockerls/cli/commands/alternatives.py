"""`dockerls alternatives <image:tag>` -- safer replacements for what you run today.

`recommend` answers "what should I use for node"; this answers the question
people actually have, which is "I am running *this*, is there something
better, and what does switching cost me". The difference is the baseline: a
concrete image the user already depends on, scanned under the same pipeline
as the candidates so the comparison is between two measurements rather than
between a measurement and a reputation.

Three properties make the output honest:

* the current image is scanned, not assumed. If it cannot be scanned, the
  command says so and refuses to claim an improvement it cannot compute;
* every alternative is ranked by the same multi-source policy as
  `recommend`, so a hardened-catalogue image wins on evidence rather than
  on the name of its vendor;
* trade-offs are printed next to gains. A libc change, a missing shell or a
  different package manager will break somebody's build, and a migration
  suggestion that hides that is worse than no suggestion.
"""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from dockerls.application.services.migration import MigrationPlan, plan_migration
from dockerls.application.services.source_registry import UnknownSourceError
from dockerls.cli.dependencies import build_analyze_use_case, build_recommend_use_case
from dockerls.cli.image_names import display_reference, split_repository_and_tag
from dockerls.cli.options import OutputFormat, parse_output_format
from dockerls.cli.progress import RichScanObserver
from dockerls.cli.scan_failure import describe_scan_failure
from dockerls.cli.text import safe
from dockerls.cli.validators import check_workers
from dockerls.exit_codes import EXIT_ERROR, EXIT_OK

if TYPE_CHECKING:
    from dockerls.application.dto.analysis import ImageAnalysis

console = Console()
# Diagnostics go to stderr, results to stdout. Printing a warning to stdout
# put a human sentence in front of the JSON document and made `--format json`
# unparseable -- a machine-readable format is only machine-readable if
# nothing else can land in the stream.
diagnostics = Console(stderr=True)

#: Exit codes, consistent with `recommend`:
#:   0 = a safer alternative was found (or the current image is already best)
#:   1 = a technical failure: the current image could not be measured
#:   2 = alternatives exist but none of them clears the baseline
EXIT_FOUND = EXIT_OK
EXIT_BELOW_BASELINE = 2

#: How many alternatives to present. More than this and the output stops
#: being a decision and becomes a catalogue.
TOP_ALTERNATIVES = 4


def alternatives(
    image: str = typer.Argument(help="The image you run today (e.g. node:22, python:3.12-slim)"),
    workers: int | None = typer.Option(
        None,
        "--workers",
        "-w",
        help="Concurrent scanner processes; 0 sizes it to this machine [config: workers]",
    ),
    source: list[str] = typer.Option(
        [],
        "--source",
        "-s",
        help="Image source to search; repeatable. dockerhub, chainguard, distroless, dhi, "
        "private (if configured), all",
    ),
    all_sources: bool = typer.Option(
        False, "--all-sources", help="Search every configured source, including opt-in ones"
    ),
    output_format: str = typer.Option(
        OutputFormat.TABLE.value, "--format", "-f", help="Output format: table or json"
    ),
    no_color: bool = typer.Option(False, "--no-color", help="Disable colored output"),
    no_progress: bool = typer.Option(False, "--no-progress", help="Disable the progress display"),
) -> None:
    """Find safer alternatives to an image you already run, with trade-offs."""
    if no_color:
        console.no_color = True
    fmt = parse_output_format(output_format)
    # `0` means "size it to this machine", so it is passed through rather
    # than validated: the resolver, not the flag, decides what it becomes.
    if workers:
        workers = check_workers(workers)
    try:
        asyncio.run(
            _alternatives(
                image,
                workers,
                fmt,
                sources=list(source) or None,
                all_sources=all_sources,
                show_progress=not no_progress and fmt != OutputFormat.JSON,
            )
        )
    except UnknownSourceError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(EXIT_ERROR) from e
    except ValueError as e:
        console.print(f"[red]Invalid configuration:[/red] {e}")
        raise typer.Exit(EXIT_ERROR) from e


async def _alternatives(
    reference: str,
    workers: int | None,
    output_format: OutputFormat,
    *,
    sources: list[str] | None = None,
    all_sources: bool = False,
    show_progress: bool = True,
) -> None:
    # A regra compartilhada, e não um `rsplit(":", 1)`: a porta de um
    # registry (`registry.internal:5000/app`) não é tag, e procurar o
    # repositório "registry.internal" não devolve nada.
    repository, tag = split_repository_and_tag(reference)

    current = await _analyze_current(reference)
    if current is None:
        # No measurement of the current image means no honest claim about
        # an improvement over it. The command fails rather than presenting
        # candidates against an unknown baseline.
        _report_unmeasurable(reference, output_format)
        raise typer.Exit(EXIT_ERROR)

    with RichScanObserver(enabled=show_progress) as observer:
        use_case = await build_recommend_use_case(
            workers=workers,
            observer=observer,
            sources=sources,
            all_sources=all_sources,
        )
        result = await use_case.execute(repository)

    candidates = [
        a
        for a in (result.recommendations or result.alternatives)
        if a.image.full_reference != current.image.full_reference and a.confidence.is_recommendable
    ][:TOP_ALTERNATIVES]

    plans = [plan_migration(current, candidate) for candidate in candidates]

    if output_format == OutputFormat.JSON:
        console.print(
            json.dumps(
                {
                    "current": current.model_dump(),
                    "alternatives": [
                        {"image": c.model_dump(), "migration": p.model_dump()}
                        for c, p in zip(candidates, plans, strict=True)
                    ],
                    "baseline_met": result.baseline_met,
                    "sources_searched": result.sources_searched,
                    "metrics": result.metrics.model_dump(),
                },
                indent=2,
                default=str,
            ),
            soft_wrap=True,
        )
        raise typer.Exit(EXIT_FOUND if result.baseline_met else EXIT_BELOW_BASELINE)

    _render(reference, tag, current, candidates, plans)
    raise typer.Exit(EXIT_FOUND if result.baseline_met else EXIT_BELOW_BASELINE)


async def _analyze_current(reference: str) -> ImageAnalysis | None:
    """Scan the image the user runs today, or return None if it cannot be.

    A falha do scan chega de duas formas, e as duas significam a mesma
    coisa aqui. Uma exceção é o caso antigo; o caso comum é um
    `ImageAnalysis` cujo scan não completou, que carrega score 0.0 e tier F
    por construção. Tratar o segundo como medição faria a baseline desta
    comparação valer zero, e toda alternativa apareceria como uma melhoria
    enorme sobre uma imagem que ninguém mediu.
    """
    use_case = await build_analyze_use_case()
    try:
        analysis = await use_case.execute(reference)
    except (ValueError, RuntimeError) as e:
        diagnostics.print(f"[yellow]Could not analyze {reference}: {e}[/yellow]")
        return None
    finally:
        # O scanner e o pool de conexões do repositório ficam abertos até
        # alguém fechá-los, e este comando abre um segundo conjunto logo
        # abaixo para a busca. `analyze` fecha no mesmo ponto.
        await use_case.close()

    if not analysis.scan.is_verified:
        cause = describe_scan_failure(analysis.scan.error_kind, analysis.scan.error_message)
        diagnostics.print(f"[yellow]Could not analyze {safe(reference)}: {safe(cause)}[/yellow]")
        return None
    return analysis


def _report_unmeasurable(reference: str, output_format: OutputFormat) -> None:
    message = (
        f"{reference} could not be scanned, so no improvement over it can be measured. "
        "This is a technical failure, not a verdict about the image."
    )
    if output_format == OutputFormat.JSON:
        console.print(json.dumps({"error": message, "current": reference}), soft_wrap=True)
    else:
        console.print(f"[red]{message}[/red]")


def _render(
    reference: str,
    tag: str,
    current: ImageAnalysis,
    candidates: list[ImageAnalysis],
    plans: list[MigrationPlan],
) -> None:
    console.print(Panel(f"[bold cyan]Alternatives to {reference}[/bold cyan]", expand=False))

    console.print("\n[bold]CURRENT[/bold]")
    console.print(
        f"  {safe(current.image.full_reference)}  [dim]{safe(current.image.source)}[/dim]"
    )
    console.print(
        f"  score {current.security_score}  tier {current.tier}  "
        f"C/H/M {current.scan.critical_count}/{current.scan.high_count}/"
        f"{current.scan.medium_count}" + (f"  [dim](tag {tag})[/dim]" if tag else "")
    )

    if not candidates:
        console.print(
            "\n[yellow]No alternative scored better than what you already run.[/yellow]\n"
            "[dim]That is a result, not a failure: staying put is the right call "
            "when nothing measured better.[/dim]"
        )
        return

    console.print("\n[bold]RECOMMENDED ALTERNATIVES[/bold]")
    table = Table()
    table.add_column("#", justify="right", style="dim")
    table.add_column("Image", style="cyan bold", overflow="fold")
    table.add_column("Source", style="magenta")
    table.add_column("Score", justify="right")
    table.add_column("Delta", justify="right")
    table.add_column("C/H/M", justify="center", no_wrap=True)
    table.add_column("Conf", justify="center")

    for i, (candidate, plan) in enumerate(zip(candidates, plans, strict=True), 1):
        delta = plan.score_delta
        delta_text = f"[green]+{delta:.1f}[/green]" if delta > 0 else f"[red]{delta:.1f}[/red]"
        table.add_row(
            str(i),
            safe(display_reference(candidate.image.name, candidate.image.tag)),
            safe(candidate.image.source),
            f"{candidate.security_score:.1f}",
            delta_text,
            f"{candidate.scan.critical_count}/{candidate.scan.high_count}/"
            f"{candidate.scan.medium_count}",
            candidate.confidence.value[:4],
        )
    console.print(table)

    best, best_plan = candidates[0], plans[0]
    console.print(f"\n[bold]WHY {safe(best.image.full_reference)}[/bold]")
    for reason in best_plan.improvements[:8]:
        console.print(f"  [green]+[/green] {safe(reason)}")

    if best_plan.trade_offs:
        console.print("\n[bold]TRADE-OFFS[/bold]")
        for cost in best_plan.trade_offs[:8]:
            console.print(f"  [yellow]![/yellow] {safe(cost)}")

    console.print("\n[bold]MIGRATION CHECKLIST[/bold]")
    for step_number, step in enumerate(best_plan.checklist, 1):
        console.print(f"  {step_number}. {safe(step)}")

    if best.image.digest_known:
        console.print(f"\n[dim]Pin to: {best.pinned_reference}[/dim]", soft_wrap=True)
    console.print(
        "\n[dim]Compatibility is never assumed: the checklist above exists because "
        "no scan can tell you whether your application still runs.[/dim]"
    )
