"""`dockerls base` -- as bases do seu Dockerfile, conferidas contra o registry.

O `analyze-dockerfile` lia o seu projeto e não media nada; o `recommend` media
e nunca olhava o seu projeto. Este comando é a ponte: ele lê os `FROM`,
pergunta ao registry qual digest cada tag aponta **agora**, e diz quais bases
apodreceram.

Aplicar por padrão é escolha deliberada, e `--dry-run` existe para quem quer
ver antes. O motivo é o caso que este comando existe para pegar: uma base
fixada num digest velho não avisa ninguém, não quebra nada, e continua entrando
em produção build após build. Um comando que só relata delega ao esquecimento
exatamente o problema que o esquecimento causou.
"""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING

import typer
from loguru import logger
from rich.console import Console

from dockerls.cli.dependencies import build_host_guard
from dockerls.cli.options import OutputFormat, parse_output_format
from dockerls.cli.text import safe
from dockerls.domain.value_objects.base_upgrade import BaseStatus
from dockerls.exit_codes import EXIT_ERROR, EXIT_OK, EXIT_POLICY

if TYPE_CHECKING:
    from dockerls.application.services.alternatives_lookup import (
        AlternativeFailure,
        AlternativeSuggestion,
    )
    from dockerls.application.use_cases.upgrade_base import UpgradeBaseResult

    Alternative = AlternativeSuggestion | AlternativeFailure

console = Console()

#: Cor por estado. `UNRESOLVED` é amarelo, não verde: não medir não é estar em
#: dia.
_COLORS = {
    BaseStatus.PINNED_CURRENT: "green",
    BaseStatus.PINNED_STALE: "red",
    BaseStatus.UNPINNED: "yellow",
    BaseStatus.UNRESOLVED: "yellow",
}


def base(
    path: str = typer.Argument(".", help="Directory containing a Dockerfile, or the file itself"),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Show what would change without writing to the file"
    ),
    alternatives: bool = typer.Option(
        False,
        "--alternatives",
        help=(
            "Beyond refreshing the digest, look for a safer base for each FROM and "
            "measure both. Requires a scanner and takes minutes"
        ),
    ),
    output_format: str = typer.Option(
        OutputFormat.TABLE.value, "--format", "-f", help="Output format: table or json"
    ),
    no_color: bool = typer.Option(False, "--no-color", help="Disable colored output"),
) -> None:
    """Check the Dockerfile bases against the registry and refresh their digests."""
    if no_color:
        console.no_color = True
    fmt = parse_output_format(output_format)
    asyncio.run(_base(path, apply=not dry_run, output_format=fmt, with_alternatives=alternatives))


async def _base(
    path: str, *, apply: bool, output_format: OutputFormat, with_alternatives: bool = False
) -> None:
    # Import tardio: montar o inspector puxa configuração e cliente HTTP, e o
    # `--help` deste comando não precisa de nada disso.
    from dockerls.application.services.tag_history_store import TagHistoryStore
    from dockerls.application.use_cases.upgrade_base import UpgradeBaseUseCase
    from dockerls.cli.dependencies import build_cache
    from dockerls.integrations.registry.inspector import RegistryInspector

    inspector = RegistryInspector(guard=build_host_guard())
    # O histórico é um extra sobre o diagnóstico: se o cache não abrir, o
    # comando continua sem ele em vez de falhar por causa de um enfeite.
    try:
        history = TagHistoryStore(build_cache())
    except Exception as e:  # pragma: no cover - abrir o cache é o caminho instável
        logger.debug(f"Tag history unavailable: {e}")
        history = TagHistoryStore(None)
    try:
        result = await UpgradeBaseUseCase(inspector, history).execute(path, apply=apply)
    finally:
        await inspector.close()

    suggestions = await _alternatives_for(result) if with_alternatives else []

    if output_format == OutputFormat.JSON:
        payload = result.to_dict()
        if with_alternatives:
            payload["alternatives"] = [s.to_dict() for s in suggestions]
        console.print(json.dumps(payload, indent=2, ensure_ascii=False), soft_wrap=True)
    else:
        _render(result, apply=apply)
        if with_alternatives:
            _render_alternatives(suggestions)

    if result.error:
        raise typer.Exit(EXIT_ERROR)
    # Reprova quando sobrou base desatualizada: em `--dry-run` isso é o portão
    # de CI, e depois de aplicar só sobra o que não deu para corrigir.
    raise typer.Exit(EXIT_POLICY if result.needs_action and not result.applied else EXIT_OK)


def _render(result: UpgradeBaseResult, *, apply: bool) -> None:
    if result.error:
        console.print(f"[red]Error:[/red] {safe(result.error)}")
        return

    console.print(f"[bold]{safe(result.dockerfile)}[/bold]\n")
    for finding in result.findings:
        color = _COLORS.get(finding.status, "white")
        stage = f"  [dim](stage {safe(finding.base.stage)})[/dim]" if finding.base.stage else ""
        console.print(
            f"  line {finding.base.line}  [{color}]{finding.status}[/{color}]{stage}\n"
            f"    {safe(finding.base.reference)}"
        )
        console.print(f"    [dim]{safe(finding.explain())}[/dim]")
        historico = result.history_for(finding.base)
        if historico is not None and historico.moves:
            console.print(f"    [dim]history: {safe(historico.explain())}[/dim]")
        if finding.proposed_reference:
            alvo = (
                f"ARG {safe(finding.base.digest_arg)}"
                if finding.base.digest_arg
                else f"line {finding.base.line}"
            )
            console.print(
                f"    [green]->[/green] {safe(finding.proposed_reference)}  [dim]({alvo})[/dim]"
            )
        console.print()

    resumo = []
    if result.outdated:
        resumo.append(f"{len(result.outdated)} outdated")
    if result.unpinned:
        resumo.append(f"{len(result.unpinned)} without a digest")
    if resumo:
        console.print(f"[bold]{', '.join(resumo)}[/bold]\n")

    if result.applied:
        console.print(
            f"[green]{result.applied} update(s) written to {safe(result.dockerfile)}.[/green]"
        )
        console.print(
            "[dim]Rebuild and scan before publishing: changing the base digest "
            "changes the image, and only a scan tells you whether for the better.[/dim]"
        )
    elif result.needs_action:
        acao = "Nothing was written (--dry-run)." if not apply else "Nothing could be written."
        console.print(f"[yellow]{acao}[/yellow]")
    else:
        console.print("[green]Every base is at the digest its tag points to today.[/green]")

    if result.unresolved:
        console.print(
            f"[yellow]{len(result.unresolved)} base(s) could not be queried on the "
            "registry -- that is an absent answer, not confirmation that they are "
            "up to date.[/yellow]"
        )


async def _alternatives_for(result: UpgradeBaseResult) -> list[Alternative]:
    """Uma alternativa medida para cada base distinta do Dockerfile.

    Cada base é consultada uma vez: um Dockerfile multi-estágio costuma repetir
    a mesma imagem, e escanear a mesma coisa três vezes só gastaria minutos
    para imprimir a mesma linha.
    """
    from dockerls.application.services.alternatives_lookup import best_alternative
    from dockerls.cli.dependencies import build_analyze_use_case, build_recommend_use_case

    referencias: list[str] = []
    for finding in result.findings:
        reference = f"{finding.base.name}:{finding.base.tag or 'latest'}"
        if finding.base.name and reference not in referencias:
            referencias.append(reference)
    if not referencias:
        return []

    console.print(
        "\n[dim]Measuring alternatives: each base is scanned alongside the "
        "candidates, because a comparison between a measurement and a reputation is "
        "not a comparison.[/dim]"
    )
    analyzer = await build_analyze_use_case()
    recommender = await build_recommend_use_case()
    return [
        await best_alternative(reference, analyzer=analyzer, recommender=recommender)
        for reference in referencias
    ]


def _render_alternatives(suggestions: list[Alternative]) -> None:
    from dockerls.application.services.alternatives_lookup import AlternativeFailure

    console.print("\n[bold]Measured alternatives[/bold]\n")
    for item in suggestions:
        if isinstance(item, AlternativeFailure):
            # Não medir nunca vira "não há nada melhor": são frases diferentes
            # e levam a decisões diferentes.
            console.print(f"  [yellow]?[/yellow] {safe(item.reference)}")
            console.print(f"      [dim]{safe(item.reason)}[/dim]")
            continue
        cor = "green" if item.improves else "yellow"
        console.print(f"  {safe(item.reference)}")
        console.print(
            f"    [{cor}]-> {safe(item.plan.to_pinned_reference or item.plan.to_reference)}[/{cor}]"
        )
        console.print(
            f"      [dim]CRITICAL {item.plan.critical_delta:+d}, "
            f"HIGH {item.plan.high_delta:+d}, score {item.plan.score_delta:+.1f}[/dim]"
        )
        for troca in item.plan.trade_offs:
            console.print(f"      [yellow]![/yellow] [dim]{safe(troca)}[/dim]")
        if not item.improves:
            console.print(
                "      [dim]the best-placed candidate does not improve on what was "
                "measured; reported anyway, because hiding what came out worse would "
                "turn the list into an argument.[/dim]"
            )
        console.print()

    console.print(
        "[dim]Nothing here is applied: switching base family is an architecture "
        "decision, not a digest refresh. `base` writes digests; swapping the image "
        "is yours.[/dim]"
    )
