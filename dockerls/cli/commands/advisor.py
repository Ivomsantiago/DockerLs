from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from dockerls.application.services.ecosystems import get_ecosystem_insights
from dockerls.application.services.migration import MigrationPlan, plan_migration
from dockerls.application.use_cases.recommend_images import build_recommendation
from dockerls.cli.dependencies import build_analyze_use_case, build_recommend_use_case
from dockerls.cli.image_names import split_repository_and_tag
from dockerls.cli.options import OutputFormat, parse_output_format
from dockerls.cli.scan_failure import describe_scan_failure
from dockerls.cli.text import safe
from dockerls.cli.validators import check_workers
from dockerls.exit_codes import EXIT_ERROR

if TYPE_CHECKING:
    from dockerls.application.dto.analysis import ImageAnalysis

console = Console()
# Diagnostics go to stderr, results to stdout. Printing a warning to stdout
# put a human sentence in front of the JSON document and made `--format json`
# unparseable -- a machine-readable format is only machine-readable if
# nothing else can land in the stream.
diagnostics = Console(stderr=True)


def advisor(
    image: str = typer.Argument(help="Docker image name (e.g., node, python, nginx)"),
    workers: int | None = typer.Option(
        None,
        "--workers",
        "-w",
        help="Concurrent scanner processes; 0 sizes it to this machine [config: workers]",
    ),
    output_format: str = typer.Option(
        OutputFormat.TABLE.value, "--format", "-f", help="Output format: table or json"
    ),
    no_color: bool = typer.Option(False, "--no-color", help="Disable colored output"),
) -> None:
    """Security advisor: analyze and provide actionable remediation plan."""
    if no_color:
        console.no_color = True
    fmt = parse_output_format(output_format)
    # `0` means "size it to this machine", so it is passed through rather
    # than validated: the resolver, not the flag, decides what it becomes.
    if workers:
        workers = check_workers(workers)
    try:
        asyncio.run(_advisor(image, workers, fmt))
    except ValueError as e:
        console.print(f"[red]Invalid configuration:[/red] {e}")
        raise typer.Exit(EXIT_ERROR) from e


async def _advisor(image: str, workers: int | None, output_format: OutputFormat) -> None:
    # A tagged argument names an image the user runs *today*, so the advice
    # can be a migration rather than a standalone suggestion. A bare name
    # ("node") has no current image to move away from, and the command
    # behaves exactly as it always has.
    # O `rsplit(":", 1)` que morava aqui lia a porta do registry como tag:
    # `advisor registry.internal:5000/app` procurava o repositório
    # "registry.internal". A regra compartilhada só aceita dois-pontos no
    # último segmento do caminho.
    repository, current_tag = split_repository_and_tag(image)
    current = await _analyze_current(image) if current_tag else None

    use_case = await build_recommend_use_case(workers=workers)
    result = await use_case.execute(repository)

    items = result.recommendations or result.alternatives
    if not items:
        if output_format == OutputFormat.JSON:
            error_payload = {"error": "No images found to advise on", "errors": result.errors}
            console.print(json.dumps(error_payload), soft_wrap=True)
        else:
            console.print("[red]No images found to advise on.[/red]")
        raise typer.Exit(EXIT_ERROR)

    best = items[0]
    # O plano de remediação é sobre a imagem que o usuário roda **hoje**,
    # sempre que ele nomeou uma. Montá-lo sobre `best` -- a candidata que a
    # busca elegeu -- descrevia as CVEs de outra imagem sob o título da que
    # foi pedida: `advisor eclipse-temurin:21-jre-alpine` respondia com
    # "Update stdlib (go1.26.5 -> 1.25.13)" e IDs `GO-...`, que não existem
    # dentro de um JRE. Corrigir a saída não bastaria: os passos precisam
    # nascer das vulnerabilidades que o scanner devolveu para *aquela*
    # imagem, e é isso que a escolha do alvo aqui garante.
    #
    # Sem tag na linha de comando não há imagem atual, e o plano sobre a
    # melhor candidata é o comportamento correto (e o original).
    target = current if current is not None else best
    rec = target.recommendation or build_recommendation(target)
    insights = get_ecosystem_insights(target.image.full_reference or image)
    # Only when the target is genuinely a different image: a "migration"
    # from an image to itself is noise, and printing a checklist for it
    # would suggest work that does not exist.
    plan = (
        plan_migration(current, best)
        if current is not None and current.image.full_reference != best.image.full_reference
        else None
    )

    if output_format == OutputFormat.JSON:
        payload = best.model_dump()
        payload["remediation"] = rec.model_dump()
        # Qual imagem o plano endereça, dito explicitamente: o documento
        # carrega `best` na raiz, e sem este campo um consumidor não teria
        # como saber que a remediação é sobre outra imagem.
        payload["remediation_target"] = target.image.full_reference
        payload["ecosystem_insights"] = {
            # As particularidades seguem o mesmo alvo do plano, e não a raiz
            # do documento (que carrega `best`). Sem este campo um consumidor
            # leria conselho sobre Debian ao lado de uma candidata Alpine sem
            # nada dizendo que são imagens diferentes.
            "for": target.image.full_reference,
            "ecosystem": insights.ecosystem,
            "version": insights.version,
            "runtime_features": insights.runtime_features,
            "base_distro_advice": insights.base_distro_advice,
            "security_guidelines": insights.security_guidelines,
            "common_pitfalls": insights.common_pitfalls,
            "snippets": insights.recommended_dockerfile_snippets,
        }
        if plan is not None:
            payload["migration"] = plan.model_dump()
        if current is not None:
            payload["current"] = current.model_dump()
        console.print(json.dumps(payload, indent=2, default=str), soft_wrap=True)
        return

    console.print(Panel(f"[bold cyan]DockerLs Security Advisor: {image}[/bold cyan]", expand=False))
    console.print()

    info = Table(show_header=False, box=None, padding=(0, 2))
    info.add_column("Key", style="bold")
    info.add_column("Value")
    info.add_row("Current Best Image", f"[cyan]{safe(best.image.full_reference)}[/cyan]")
    info.add_row("Ecosystem / Runtime", f"{insights.ecosystem} ({insights.version})")
    info.add_row("Security Score", f"[green]{best.security_score}[/green]")
    info.add_row("Tier", best.tier)
    info.add_row("Critical", f"[red]{best.scan.critical_count}[/red]")
    info.add_row("High", f"[yellow]{best.scan.high_count}[/yellow]")
    info.add_row("Medium", str(best.scan.medium_count))
    info.add_row("Fixable High", str(best.scan.fixable_high_count))
    info.add_row("Remediation Score", f"{best.remediation_score}%")
    info.add_row("EOL", "Yes" if best.is_eol else "No")
    info.add_row("LTS", "Yes" if best.is_lts else "No")
    console.print(info)

    if insights.base_distro_advice or insights.security_guidelines:
        console.print()
        console.print(
            Panel(
                "[bold magenta]Ecosystem Particularities & Hardening[/bold magenta]",
                expand=False,
            )
        )
        if insights.base_distro_advice:
            console.print("\n[bold]Base Image & Distribution Notes:[/bold]")
            for advice in insights.base_distro_advice:
                console.print(f"  - {advice}")
        if insights.security_guidelines:
            console.print("\n[bold]Production & Security Guidelines:[/bold]")
            for item in insights.security_guidelines:
                console.print(f"  - {item}")
        if insights.common_pitfalls:
            console.print("\n[bold red]Common Pitfalls to Avoid:[/bold red]")
            for pit in insights.common_pitfalls:
                console.print(f"  [yellow]![/yellow] {pit}")

    if plan is not None:
        _print_migration(plan)

    if rec.steps:
        console.print()
        # A imagem nomeada no cabeçalho: um plano cujos passos citam versões
        # de pacote precisa dizer de qual imagem essas versões vieram.
        console.print(
            f"[bold]Remediation Plan[/bold] [dim]for {safe(target.image.full_reference)}[/dim]"
        )
        console.print()
        for step in rec.steps:
            desc = step.description
            if step.from_value and step.to_value:
                desc += f" [dim]({step.from_value} -> {step.to_value})[/dim]"
            console.print(f"  STEP {step.step_number}: {desc}")
            if step.expected_impact:
                console.print(f"         [dim]{step.expected_impact}[/dim]")

    if rec.summary:
        console.print()
        console.print(f"[bold]Summary:[/bold] {rec.summary}")


async def _analyze_current(reference: str) -> ImageAnalysis | None:
    """Scan the image named on the command line, or give up quietly.

    Failing to measure the current image costs the migration section, not
    the command: the advice about the best available image is still valid,
    and claiming an improvement over something never measured would not be.
    """
    use_case = await build_analyze_use_case()
    try:
        analysis = await use_case.execute(reference)
    except (ValueError, RuntimeError) as e:
        diagnostics.print(f"[yellow]Could not analyze {reference} for comparison: {e}[/yellow]")
        return None
    finally:
        # O scanner e o pool de conexões do repositório ficam abertos até
        # alguém fechá-los, e este comando abre um segundo conjunto logo
        # abaixo para a busca. `analyze` fecha no mesmo ponto; não fechar
        # aqui era o único caminho que vazava.
        await use_case.close()

    # Um scan que não completou devolve score 0.0 e tier F por construção.
    # Aceitá-lo como medição faria o plano de migração afirmar uma melhora
    # sobre um número que não mede nada.
    if not analysis.scan.is_verified:
        cause = describe_scan_failure(analysis.scan.error_kind, analysis.scan.error_message)
        diagnostics.print(
            f"[yellow]Could not analyze {safe(reference)} for comparison: {safe(cause)}[/yellow]"
        )
        return None
    return analysis


def _print_migration(plan: MigrationPlan) -> None:
    """The move from what the user runs to what was measured as better."""
    console.print()
    console.print(Panel("[bold green]Migration[/bold green]", expand=False))
    console.print(f"  CURRENT      [cyan]{plan.from_reference}[/cyan]")
    console.print(f"  RECOMMENDED  [green]{plan.to_reference}[/green]")
    if plan.to_pinned_reference != plan.to_reference:
        console.print(f"  PIN TO       [dim]{plan.to_pinned_reference}[/dim]")

    delta = plan.score_delta
    colour = "green" if delta > 0 else "red"
    console.print(f"\n  SECURITY IMPROVEMENT  [{colour}]{delta:+.1f} points[/{colour}]")

    if plan.improvements:
        console.print("\n[bold]WHY[/bold]")
        for reason in plan.improvements:
            console.print(f"  [green]OK[/green] {safe(reason)}")
    if plan.trade_offs:
        console.print("\n[bold]TRADE-OFFS[/bold]")
        for cost in plan.trade_offs:
            console.print(f"  [yellow]![/yellow] {safe(cost)}")
    if plan.checklist:
        console.print("\n[bold]MIGRATION CHECKLIST[/bold]")
        for i, step in enumerate(plan.checklist, 1):
            console.print(f"  {i}. {safe(step)}")
    console.print(
        "\n[dim]Compatibility is never assumed: nothing here can tell you your "
        "application still runs. That is what the checklist is for.[/dim]"
    )
