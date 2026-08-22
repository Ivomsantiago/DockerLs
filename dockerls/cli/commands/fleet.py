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
    Tristate.TRUE: "[green]sem privilégio[/green]",
    Tristate.FALSE: "[red]root[/red]",
    Tristate.UNKNOWN: "[yellow]indeterminado[/yellow]",
}


def fleet(
    root: str = typer.Argument(".", help="Raiz da árvore a varrer"),
    policy_path: str | None = typer.Option(
        None,
        "--policy",
        help=(
            "Política a conferir em cada Dockerfile (padrão: .dockerls-policy.yaml "
            "na raiz, quando existir). Só as regras decidíveis sem build são aplicadas"
        ),
    ),
    output_format: str = typer.Option(
        OutputFormat.TABLE.value, "--format", "-f", help="Formato de saída: table ou json"
    ),
    limit: int = typer.Option(0, "--limit", help="Mostra só os N primeiros da fila (0 = todos)"),
    no_color: bool = typer.Option(False, "--no-color", help="Desativa cor na saída"),
) -> None:
    """Varre uma árvore de repositórios e resume o estado dos Dockerfiles."""
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
        console.print(f"[red]Erro:[/red] {safe(root)} não é um diretório")
        raise typer.Exit(EXIT_ERROR)

    policy_file = Path(policy_path) if policy_path else find_policy_file(target)
    declared = None
    if policy_file is not None:
        if not policy_file.is_file():
            console.print(f"[red]Erro:[/red] política não encontrada: {safe(str(policy_file))}")
            raise typer.Exit(EXIT_ERROR)
        try:
            declared = load_policy(policy_file)
        except PolicyFileError as e:
            console.print(f"[red]Erro:[/red] {safe(str(e))}")
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
        console.print("[yellow]Nenhum Dockerfile encontrado sob esta raiz.[/yellow]")
        return

    fila = report.worst_first()
    mostrados = fila[:limit] if limit > 0 else fila
    for entry in mostrados:
        if not entry.readable:
            console.print(f"  [red]![/red] {safe(entry.path)}  [dim]{safe(entry.error)}[/dim]")
            continue

        fixadas = (
            f"{entry.pinned_bases}/{entry.total_bases} fixada(s)"
            if entry.total_bases
            else "sem FROM legível"
        )
        cor = "green" if entry.fully_pinned else "yellow"
        console.print(
            f"  {safe(entry.path)}\n"
            f"    [{cor}]{fixadas}[/{cor}]  {_USER_LABEL[entry.nonroot]}  "
            f"[dim]{entry.stages} estágio(s)[/dim]"
        )
        for violation in entry.violations:
            console.print(
                f"    [red]x[/red] {violation.rule}  [dim]{safe(violation.message)}[/dim]"
            )

    if limit > 0 and len(fila) > limit:
        console.print(f"\n[dim]... e mais {len(fila) - limit} (use --limit 0 para todos).[/dim]")

    console.print()
    if report.truncated:
        console.print(
            "[yellow]A varredura foi truncada no teto de arquivos ou de "
            "profundidade: este retrato está incompleto.[/yellow]"
        )
    for path in report.unreadable_paths:
        console.print(f"[yellow]Diretório não percorrido: {safe(path)}[/yellow]")

    if report.policy_applied:
        console.print(
            f"[bold]{report.with_violations} arquivo(s) com violação, "
            f"{report.total_violations} no total.[/bold]\n"
            "[dim]Só as regras decidíveis sem build foram aplicadas; as que dependem "
            "de scan continuam valendo no `dockerls build`.[/dim]"
        )
    else:
        console.print(
            "[dim]Nenhuma política declarada: nada foi conferido contra regras, e "
            "isso não é o mesmo que estar em conformidade.[/dim]"
        )
    console.print(f"[dim]{safe(report.caveat())}[/dim]")
