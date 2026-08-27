"""`dockerls registry-audit` -- o que o registry conta sobre uma imagem.

Auditar a configuração de um registry -- retenção, IAM, content trust -- exige
credencial de nuvem e uma API diferente para cada provedor. Este comando não
faz isso, e a saída diz que não faz: ele usa o protocolo OCI e mais nada. A
troca é deliberada. Um relatório que precisa de acesso administrativo para
existir é um relatório que ninguém roda, e o que dá para medir sem credencial
é menos do que parece e mais do que se costuma olhar.

Cada achado é tri-estado. `UNKNOWN` não é enfeite de formato: sem ele, "o
registry não respondeu sobre a assinatura" viraria "não há assinatura", e as
duas frases levam a decisões opostas.
"""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING

import typer
from rich.console import Console

from dockerls.cli.dependencies import build_host_guard
from dockerls.cli.options import OutputFormat, parse_output_format
from dockerls.cli.text import safe
from dockerls.exit_codes import EXIT_ERROR, EXIT_OK, EXIT_POLICY

if TYPE_CHECKING:
    from dockerls.domain.value_objects.registry_audit import RegistryAudit

console = Console()


def registry_audit(
    reference: str = typer.Argument(..., help="Published image (`ghcr.io/org/app:1.0`)"),
    output_format: str = typer.Option(
        OutputFormat.TABLE.value, "--format", "-f", help="Output format: table or json"
    ),
    no_color: bool = typer.Option(False, "--no-color", help="Disable colored output"),
) -> None:
    """Establish, through the registry, what is known about a published image."""
    if no_color:
        console.no_color = True
    fmt = parse_output_format(output_format)
    asyncio.run(_audit(reference, output_format=fmt))


async def _audit(reference: str, *, output_format: OutputFormat) -> None:
    from dockerls.application.services.tag_history_store import TagHistoryStore
    from dockerls.application.use_cases.registry_audit import RegistryAuditUseCase
    from dockerls.cli.dependencies import build_cache
    from dockerls.integrations.registry.inspector import RegistryInspector

    inspector = RegistryInspector(guard=build_host_guard())
    try:
        history = TagHistoryStore(build_cache())
    except Exception:  # pragma: no cover - abrir o cache é o caminho instável
        history = TagHistoryStore(None)

    try:
        audit = await RegistryAuditUseCase(inspector, history).execute(reference)
    finally:
        await inspector.close()

    if output_format == OutputFormat.JSON:
        console.print(json.dumps(audit.to_dict(), indent=2, ensure_ascii=False), soft_wrap=True)
    else:
        _render(audit)

    if not audit.findings:
        raise typer.Exit(EXIT_ERROR)
    raise typer.Exit(EXIT_POLICY if audit.alerts else EXIT_OK)


def _render(audit: RegistryAudit) -> None:
    console.print(f"\n[bold]{safe(audit.reference)}[/bold]")
    if audit.digest:
        console.print(f"[dim]{safe(audit.digest)}[/dim]")
    console.print()

    if not audit.findings:
        console.print("[red]Invalid reference: nothing could be established.[/red]")
        return

    for finding in audit.findings:
        if finding.is_unmeasured:
            marca, cor = "?", "yellow"
        elif finding.is_alert:
            marca, cor = "x", "red"
        elif finding.is_informational:
            # Fato relatado sem juízo: se ser público é problema depende de
            # para que a imagem existe, e isso a ferramenta não sabe.
            marca, cor = "i", "cyan"
        else:
            marca, cor = "v", "green"
        console.print(f"  [{cor}]{marca}[/{cor}] [bold]{finding.check}[/bold]")
        console.print(f"      [dim]{safe(finding.explain())}[/dim]")

    console.print(f"\n[bold]{safe(audit.summary())}[/bold]")
    console.print(f"[dim]{safe(audit.caveat())}[/dim]\n")
