"""`dockerls policy` -- ler o regulamento sem precisar de um build para isso.

Uma política que só se manifesta quando um build reprova é uma política que
ninguém revisa. Este comando existe para as duas perguntas que aparecem antes
disso: "o que este repositório exige?" e "este arquivo que acabei de escrever
está válido?".

A segunda importa mais do que parece. O carregador recusa chave desconhecida,
tipo errado e severidade inexistente -- e recusa com razão, porque uma regra
que não carrega deixa de exigir alguma coisa. Mas descobrir isso no meio de um
build de dez minutos é caro; descobrir aqui custa um segundo.
"""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console

from dockerls.cli.options import OutputFormat, parse_output_format
from dockerls.cli.text import safe
from dockerls.exit_codes import EXIT_ERROR, EXIT_OK
from dockerls.infrastructure.config.policy_file import (
    DEFAULT_POLICY_FILENAME,
    PolicyFileError,
    find_policy_file,
    load_policy,
)

console = Console()

#: O que cada regra exige, em uma linha, para a saída de tabela.
_DESCRIPTIONS = {
    "fail_on": "fails the build from this severity upwards",
    "max_vulnerabilities": "ceiling on findings per severity",
    "require_scan": "requires that a scanner has run",
    "require_pinned_bases": "requires every FROM pinned by digest",
    "require_nonroot": "requires the image to run without privilege",
    "required_labels": "labels the image must carry",
    "allowed_base_registries": "where bases may come from",
    "require_provenance": "requires verified provenance",
}


def policy(
    path: str = typer.Argument(
        ".", help="Directory containing the policy file, or the file itself"
    ),
    output_format: str = typer.Option(
        OutputFormat.TABLE.value, "--format", "-f", help="Output format: table or json"
    ),
    no_color: bool = typer.Option(False, "--no-color", help="Disable colored output"),
) -> None:
    """Show and validate the policy declared in `.dockerls-policy.yaml`."""
    if no_color:
        console.no_color = True
    fmt = parse_output_format(output_format)

    target = Path(path)
    if target.is_dir():
        found = find_policy_file(target)
        if found is None:
            if fmt == OutputFormat.JSON:
                console.print(json.dumps({"policy": None}, indent=2), soft_wrap=True)
            else:
                console.print(
                    f"[yellow]No {DEFAULT_POLICY_FILENAME} in {safe(str(target))}.[/yellow]\n"
                    "[dim]With no declared policy, only the gates the command line "
                    "asks for apply -- and a rule that lives on the command line is a "
                    "rule every pipeline rewrites by hand.[/dim]"
                )
            raise typer.Exit(EXIT_OK)
        target = found

    try:
        declared = load_policy(target)
    except PolicyFileError as e:
        console.print(f"[red]Error:[/red] {safe(str(e))}")
        raise typer.Exit(EXIT_ERROR) from e

    if fmt == OutputFormat.JSON:
        console.print(
            json.dumps({"file": str(target), "policy": declared.to_dict()}, indent=2),
            soft_wrap=True,
        )
        raise typer.Exit(EXIT_OK)

    console.print(f"\n[bold]{safe(str(target))}[/bold]\n")
    for key, value in declared.to_dict().items():
        if not value:
            continue
        console.print(
            f"  [cyan]{key}[/cyan]  [dim]{_DESCRIPTIONS.get(key, '')}[/dim]\n"
            f"    {safe(_format(value))}"
        )
    console.print(
        "\n[dim]Checked on every `dockerls build` in this context. Between the "
        "threshold here and the one on the command line, the stricter wins: a file in "
        "the repository cannot switch off a gate the pipeline asked for.[/dim]"
    )
    raise typer.Exit(EXIT_OK)


def _format(value: object) -> str:
    if isinstance(value, dict):
        return ", ".join(f"{k}: {v}" for k, v in value.items())
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    return str(value)
