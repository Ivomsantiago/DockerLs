"""`dockerls fleet` -- o retrato de todos os Dockerfiles de uma vez.

Cada comando desta ferramenta olha para um artefato. Isso resolve a pergunta
de quem está com o arquivo aberto e não resolve nenhuma das perguntas de quem
responde por trinta repositórios: "quantos ainda rodam como root?", "quantos
fixam a base?", "por onde eu começo?". Sem resposta, a resposta na prática vira
"por onde alguém reclamar".

A saída é uma fila de trabalho, ordenada por violações e desempatada pelo
caminho -- para que duas varreduras da mesma frota sejam comparáveis.

O que este comando não faz está dito na própria saída, e não é modéstia: ele
lê Dockerfiles, não constrói imagem nem chama scanner. Um "relatório de
segurança da frota" que na verdade leu arquivos seria exatamente a promessa
que o resto desta ferramenta existe para não fazer.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

import typer
from rich.console import Console

from dockerls.cli.options import OutputFormat, parse_output_format
from dockerls.cli.text import safe
from dockerls.domain.value_objects.tristate import Tristate
from dockerls.exit_codes import EXIT_ERROR, EXIT_OK, EXIT_POLICY

if TYPE_CHECKING:
    from dockerls.domain.value_objects.fleet import FleetReport

console = Console()

_USER_LABEL = {
    Tristate.TRUE: "[green]non-root[/green]",
    Tristate.FALSE: "[red]root[/red]",
    Tristate.UNKNOWN: "[yellow]undetermined[/yellow]",
}


def fleet(
    root: str = typer.Argument(".", help="Root of the tree to scan"),
    policy_path: str | None = typer.Option(
        None,
        "--policy",
        help=(
            "Policy to check every Dockerfile against (default: .dockerls-policy.yaml "
            "at the root, when present). Only rules decidable without a build apply"
        ),
    ),
    output_format: str = typer.Option(
        OutputFormat.TABLE.value, "--format", "-f", help="Output format: table or json"
    ),
    limit: int = typer.Option(0, "--limit", help="Show only the first N in the queue (0 = all)"),
    no_color: bool = typer.Option(False, "--no-color", help="Disable colored output"),
) -> None:
    """Scan a tree of repositories and summarise the state of its Dockerfiles."""
    if no_color:
        console.no_color = True
    fmt = parse_output_format(output_format)

    from dockerls.application.use_cases.fleet_scan import FleetScanRequest, FleetScanUseCase
    from dockerls.infrastructure.config.policy_file import (
        PolicyFileError,
        find_policy_file,
        load_policy,
    )
    from dockerls.infrastructure.dockerfile_validator import DockerfileValidator

    target = Path(root)
    if not target.is_dir():
        console.print(f"[red]Error:[/red] {safe(root)} is not a directory")
        raise typer.Exit(EXIT_ERROR)

    policy_file = Path(policy_path) if policy_path else find_policy_file(target)
    declared = None
    if policy_file is not None:
        if not policy_file.is_file():
            console.print(f"[red]Error:[/red] policy not found: {safe(str(policy_file))}")
            raise typer.Exit(EXIT_ERROR)
        try:
            declared = load_policy(policy_file)
        except PolicyFileError as e:
            console.print(f"[red]Error:[/red] {safe(str(e))}")
            raise typer.Exit(EXIT_ERROR) from e

    report = FleetScanUseCase(DockerfileValidator()).execute(
        FleetScanRequest(root=str(target), policy=declared)
    )

    if fmt == OutputFormat.JSON:
        console.print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False), soft_wrap=True)
    else:
        _render(report, limit=limit)

    # Reprova quando há violação: é o que torna a varredura utilizável como
    # portão de um repositório-guarda-chuva. Sem política declarada não há o
    # que reprovar, e o silêncio aqui não é conformidade.
    raise typer.Exit(EXIT_POLICY if report.total_violations else EXIT_OK)


def _render(report: FleetReport, *, limit: int) -> None:
    console.print(f"\n[bold]{safe(report.root)}[/bold]")
    console.print(f"[dim]{safe(report.summary())}[/dim]\n")

    if not report.total:
        console.print("[yellow]No Dockerfile found under this root.[/yellow]")
        return

    fila = report.worst_first()
    mostrados = fila[:limit] if limit > 0 else fila
    for entry in mostrados:
        if not entry.readable:
            console.print(f"  [red]![/red] {safe(entry.path)}  [dim]{safe(entry.error)}[/dim]")
            continue

        fixadas = (
            f"{entry.pinned_bases}/{entry.total_bases} pinned"
            if entry.total_bases
            else "no readable FROM"
        )
        cor = "green" if entry.fully_pinned else "yellow"
        console.print(
            f"  {safe(entry.path)}\n"
            f"    [{cor}]{fixadas}[/{cor}]  {_USER_LABEL[entry.nonroot]}  "
            f"[dim]{entry.stages} stage(s)[/dim]"
        )
        for violation in entry.violations:
            console.print(
                f"    [red]x[/red] {violation.rule}  [dim]{safe(violation.message)}[/dim]"
            )

    if limit > 0 and len(fila) > limit:
        console.print(f"\n[dim]... and {len(fila) - limit} more (use --limit 0 for all).[/dim]")

    console.print()
    if report.truncated:
        console.print(
            "[yellow]The scan hit the file or depth ceiling: this picture is incomplete.[/yellow]"
        )
    for path in report.unreadable_paths:
        console.print(f"[yellow]Directory not walked: {safe(path)}[/yellow]")

    if report.policy_applied:
        console.print(
            f"[bold]{report.with_violations} file(s) with violations, "
            f"{report.total_violations} in total.[/bold]\n"
            "[dim]Only rules decidable without a build were applied; the ones that "
            "need a scan still hold in `dockerls build`.[/dim]"
        )
    else:
        console.print(
            "[dim]No policy declared: nothing was checked against any rule, and that "
            "is not the same as being compliant.[/dim]"
        )
    console.print(f"[dim]{safe(report.caveat())}[/dim]")
