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
    "fail_on": "reprova o build a partir desta severidade",
    "max_vulnerabilities": "teto de achados por severidade",
    "require_scan": "exige que um scanner tenha rodado",
    "require_pinned_bases": "exige todo FROM fixado por digest",
    "require_nonroot": "exige execução sem privilégio",
    "required_labels": "rótulos que a imagem precisa carregar",
    "allowed_base_registries": "de onde as bases podem vir",
    "require_provenance": "exige procedência verificada",
}


def policy(
    path: str = typer.Argument(
        ".", help="Diretório com o arquivo de política, ou o próprio arquivo"
    ),
    output_format: str = typer.Option(
        OutputFormat.TABLE.value, "--format", "-f", help="Formato de saída: table ou json"
    ),
    no_color: bool = typer.Option(False, "--no-color", help="Desativa cor na saída"),
) -> None:
    """Mostra e valida a política declarada em `.dockerls-policy.yaml`."""
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
                    f"[yellow]Nenhum {DEFAULT_POLICY_FILENAME} em {safe(str(target))}.[/yellow]\n"
                    "[dim]Sem política declarada, só valem os portões que a linha de "
                    "comando pedir -- e uma regra que mora na linha de comando é uma "
                    "regra que cada pipeline reescreve à mão.[/dim]"
                )
            raise typer.Exit(EXIT_OK)
        target = found

    try:
        declared = load_policy(target)
    except PolicyFileError as e:
        console.print(f"[red]Erro:[/red] {safe(str(e))}")
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
        "\n[dim]Conferida em todo `dockerls build` neste contexto. Entre o limiar "
        "daqui e o da linha de comando vence o mais estrito: um arquivo no "
        "repositório não pode desligar um portão que o pipeline pediu.[/dim]"
    )
    raise typer.Exit(EXIT_OK)


def _format(value: object) -> str:
    if isinstance(value, dict):
        return ", ".join(f"{k}: {v}" for k, v in value.items())
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    return str(value)
