"""`dockerls verify` -- quem publicou estes bytes?

O `scan` diz o que há dentro de uma imagem e o `provenance` diz de onde ela
veio. Nenhum dos dois impede alguém com acesso de escrita ao registry de
sobrescrever a tag com outra coisa: os dois falam sobre o artefato que
mediram, e a tag deixou de apontar para ele. A assinatura é o elo que fecha
isso.

O comando tem uma regra acima de todas: **`cosign` ausente nunca vira "não
assinado"**. Confundir os dois acusaria alguém de não assinar por causa de uma
ferramenta que faltava na máquina -- e, na direção oposta, uma verificação que
falha em silêncio produz confiança sem base, que é pior do que desconfiança.

Verificar sem restringir identidade e emissor responde "alguém assinou", e não
"quem você espera assinou". O comando aceita rodar assim porque é útil num
diagnóstico rápido, e **diz na saída** que foi isso que aconteceu.
"""

from __future__ import annotations

import asyncio
import json

import typer
from rich.console import Console

from dockerls.cli.options import OutputFormat, parse_output_format
from dockerls.cli.text import safe
from dockerls.exit_codes import EXIT_ERROR, EXIT_OK, EXIT_POLICY
from dockerls.integrations.signing.cosign import CosignClient, SignatureStatus

console = Console()

_COLORS = {
    SignatureStatus.VERIFIED: "green",
    SignatureStatus.SIGNED: "green",
    SignatureStatus.UNSIGNED: "red",
    SignatureStatus.SIGNER_MISSING: "yellow",
    SignatureStatus.FAILED: "yellow",
}


def verify(
    reference: str = typer.Argument(..., help="Image to verify (ideally by digest)"),
    identity: str = typer.Option(
        "",
        "--identity",
        help="Regex for the identity that must have signed (e.g. 'https://github.com/org/.*')",
    ),
    issuer: str = typer.Option(
        "",
        "--issuer",
        help="Emissor OIDC esperado (ex: https://token.actions.githubusercontent.com)",
    ),
    output_format: str = typer.Option(
        OutputFormat.TABLE.value, "--format", "-f", help="Output format: table or json"
    ),
    no_color: bool = typer.Option(False, "--no-color", help="Disable colored output"),
) -> None:
    """Check an image signature with cosign."""
    if no_color:
        console.no_color = True
    fmt = parse_output_format(output_format)

    result = asyncio.run(
        CosignClient().verify(
            reference,
            certificate_identity_regexp=identity,
            certificate_oidc_issuer=issuer,
        )
    )

    if fmt == OutputFormat.JSON:
        console.print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False), soft_wrap=True)
    else:
        color = _COLORS.get(result.status, "white")
        console.print(f"\n[bold]{safe(result.reference)}[/bold]")
        console.print(f"  [{color}]{result.status}[/{color}]  [dim]{safe(result.explain())}[/dim]")
        for who in result.identities:
            console.print(f"    [dim]assinada por {safe(who)}[/dim]")
        if result.detail and result.status is SignatureStatus.VERIFIED:
            console.print(f"  [yellow]![/yellow] [dim]{safe(result.detail)}[/dim]")
        if "@sha256:" not in reference:
            console.print(
                "\n[dim]This reference is not a digest: the signature checked is the "
                "one for what the tag points at now, and the tag can move.[/dim]"
            )
        console.print()

    # Três saídas distintas de propósito. Sem isso, um pipeline não conseguiria
    # diferenciar "esta imagem não está assinada" de "não deu para conferir",
    # e trataria as duas do mesmo jeito -- que é exatamente o erro.
    if result.trustworthy:
        raise typer.Exit(EXIT_OK)
    if result.status.is_conclusive:
        # O cosign rodou e respondeu: a imagem não está assinada. Veredito.
        raise typer.Exit(EXIT_POLICY)
    # O cosign não rodou, ou rodou e falhou. Isso é falha do medidor, e sai
    # como erro técnico -- nunca como "não assinado".
    raise typer.Exit(EXIT_ERROR)
