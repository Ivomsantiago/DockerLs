"""Emite as isenções deste repositório como um documento OpenVEX.

O `.dockerls-ignore.yaml` já é um VEX em tudo menos no formato: tem o CVE,
tem a justificativa e tem o prazo. O que faltava era escrevê-lo num formato
que o resto do mundo lê -- Trivy e Grype consomem OpenVEX nativamente --,
para que uma exceção decidida uma vez valha no pipeline inteiro em vez de
só dentro desta ferramenta.

O que este comando **não** faz é transformar risco aceito em alegação
técnica. Ver `domain/value_objects/vex.py`: `not_affected` só sai quando a
regra declara uma das cinco justificativas do padrão.
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

from dockerls.cli.text import safe
from dockerls.domain.value_objects.image_reference import split_repository_and_tag
from dockerls.domain.value_objects.vex import ExemptionInput, build_document
from dockerls.exit_codes import EXIT_ERROR, EXIT_OK
from dockerls.utils.ignore_file import DEFAULT_IGNORE_FILENAME, load_ignore_rules

console = Console()
diagnostics = Console(stderr=True)


def vex(
    image: str = typer.Argument(
        help="Image the statements are about (e.g. ghcr.io/org/app:1.0, or a digest)"
    ),
    ignore_file: str | None = typer.Option(
        None,
        "--ignore-file",
        help=f"Exemptions to translate (default: {DEFAULT_IGNORE_FILENAME} in this directory)",
    ),
    author: str = typer.Option(
        "",
        "--author",
        help="Who is making these statements. Required: a VEX with no author "
        "names nobody, and nobody is not accountable",
    ),
    output: str | None = typer.Option(
        None, "--output", "-o", help="Write to a file instead of stdout"
    ),
) -> None:
    """Emit this repository's exemptions as an OpenVEX document."""
    if not author.strip():
        console.print(
            "[red]Error:[/red] --author is required.\n"
            "[dim]A VEX statement is an assertion someone makes. Without an author it "
            "asserts nothing anyone can be held to, and consumers have no way to decide "
            "whether to trust it.[/dim]"
        )
        raise typer.Exit(EXIT_ERROR)

    path = Path(ignore_file) if ignore_file else Path.cwd() / DEFAULT_IGNORE_FILENAME
    if ignore_file and not path.exists():
        # Um caminho explícito que não existe é erro de configuração. Cair
        # no silêncio de "nenhuma regra" produziria um documento vazio que
        # parece uma resposta.
        console.print(f"[red]Error:[/red] {safe(str(path))} does not exist")
        raise typer.Exit(EXIT_ERROR)

    rules = load_ignore_rules(path)
    document = build_document(
        [
            ExemptionInput(
                cve=rule.cve,
                justification=rule.justification,
                expires=rule.expires,
                vex_justification=rule.vex_justification,
            )
            for rule in rules
        ],
        products=[_product_id(image)],
        author=author.strip(),
    )

    rendered = document.to_json()
    if output:
        try:
            Path(output).write_text(rendered + "\n", encoding="utf-8")
        except OSError as e:
            console.print(f"[red]Error:[/red] could not write {safe(output)}: {e}")
            raise typer.Exit(EXIT_ERROR) from e
        diagnostics.print(f"[green]Wrote {len(rules)} statement(s) to {safe(output)}[/green]")
    else:
        console.print(rendered, soft_wrap=True)

    if not rules:
        # Documento vazio é uma resposta válida -- "nada foi isentado" --,
        # mas quem rodou o comando quase sempre esperava statements, e o
        # silêncio faria parecer que o arquivo foi lido e ignorado.
        diagnostics.print(
            f"[yellow]No active exemptions in {safe(str(path))}: the document is empty.[/yellow]\n"
            "[dim]Expired rules are dropped on read, so an exemption that lapsed no longer "
            "appears here -- which is the point of the expiry date.[/dim]"
        )
    raise typer.Exit(EXIT_OK)


def _product_id(image: str) -> str:
    """A referência como um purl OCI, que é o que o padrão espera.

    Um digest sobrevive intacto: ele já aponta para bytes específicos, que
    é exatamente o que uma afirmação VEX deveria cobrir. Uma tag entra como
    versão porque é o que existe -- e é o consumidor que decide o quanto
    confia numa afirmação sobre um ponteiro móvel.
    """
    reference = image.strip()
    if "@" in reference:
        name, _, digest = reference.partition("@")
        return f"pkg:oci/{name.rsplit('/', 1)[-1]}@{digest}?repository_url={name}"
    repository, tag = split_repository_and_tag(reference)
    short = repository.rsplit("/", 1)[-1]
    version = f"?tag={tag}" if tag else ""
    return f"pkg:oci/{short}{version}&repository_url={repository}" if tag else f"pkg:oci/{short}"
