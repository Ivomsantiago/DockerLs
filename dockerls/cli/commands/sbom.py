from __future__ import annotations

import asyncio
import contextlib
import tempfile
from pathlib import Path

import typer
from rich.console import Console

from dockerls.cli.dependencies import build_host_guard
from dockerls.cli.text import safe
from dockerls.exit_codes import EXIT_ERROR
from dockerls.integrations.trivy.scanner import TrivyScanner

console = Console()

_FORMAT_ALIASES = {"cyclonedx": "cyclonedx", "spdx": "spdx-json", "spdx-json": "spdx-json"}


def sbom(
    image: str = typer.Argument(help="Full image reference (e.g., node:22-alpine)"),
    output_format: str = typer.Option("cyclonedx", "--format", "-f", help="cyclonedx or spdx"),
    output: str = typer.Option("", "--output", "-o", help="Output file path (default: stdout)"),
    attest: bool = typer.Option(
        False,
        "--attest",
        help="Publish the SBOM to the registry as a signed cosign attestation. Requires "
        "cosign and a reference by digest",
    ),
) -> None:
    """Generate a Software Bill of Materials (SBOM) for an image via Trivy.

    `--attest` publishes it: the SBOM is signed with cosign and attached to
    the image manifest, which is what `dockerls registry-audit` looks for
    when it asks whether an attestation exists. Without it the SBOM is a
    file on your disk -- useful, and invisible to anyone pulling the image.

    Attestation is by **digest** only. A tag can move, and an attestation
    that outlives the move would go on describing an image it never saw.
    """
    fmt = _FORMAT_ALIASES.get(output_format.lower())
    if fmt is None:
        console.print(
            f"[red]Unsupported SBOM format: {output_format}. Use cyclonedx or spdx.[/red]"
        )
        raise typer.Exit(EXIT_ERROR)
    if attest and "@sha256:" not in image:
        # Recusado aqui, antes de gerar: descobrir isso depois de escanear
        # a imagem inteira desperdiça o trabalho, e a correção é uma linha
        # de comando diferente e não uma flag a mais.
        console.print(
            "[red]Error:[/red] --attest needs a digest reference "
            "(name@sha256:...), not a tag.\n"
            "[dim]A tag can move, and the attestation would go on describing an image "
            "it never saw. `docker inspect --format='{{index .RepoDigests 0}}' "
            "<image>` gives you the digest.[/dim]"
        )
        raise typer.Exit(EXIT_ERROR)

    try:
        asyncio.run(_sbom(image, fmt, output, attest=attest))
    except ValueError as e:
        # A malformed image reference is rejected by `sanitize_image_name`
        # inside the scanner; surfacing it as a message keeps `sbom` in line
        # with every other command.
        console.print(f"[red]Invalid image reference:[/red] {e}")
        raise typer.Exit(EXIT_ERROR) from e


async def _sbom(image: str, fmt: str, output: str, *, attest: bool = False) -> None:
    scanner = TrivyScanner(guard=build_host_guard())
    if not await scanner.is_available():
        console.print("[red]Trivy is required for SBOM generation. Run `dockerls doctor`.[/red]")
        raise typer.Exit(EXIT_ERROR)

    content = await scanner.generate_sbom(image, fmt=fmt)
    if content is None:
        console.print(f"[red]Failed to generate SBOM for {image}[/red]")
        raise typer.Exit(EXIT_ERROR)

    if output:
        path = Path(output)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        except OSError as e:
            # An unwritable destination is user error, not a traceback.
            console.print(f"[red]Could not write {path}:[/red] {e}")
            raise typer.Exit(EXIT_ERROR) from e
        console.print(f"[green]SBOM written to {output}[/green]")
    elif not attest:
        console.print(content, soft_wrap=True)

    if attest:
        await _attest(image, content, fmt)


#: O tipo de predicado que o cosign espera para cada formato de SBOM. Sem
#: isto, o documento é anexado como um predicado genérico e quem consome não
#: sabe que é um SBOM -- o que é quase o mesmo que não ter anexado.
_PREDICATE_TYPES = {"cyclonedx": "cyclonedx", "spdx-json": "spdxjson"}


async def _attest(image: str, content: str, fmt: str) -> None:
    """Publica o SBOM como atestação assinada, ou diz por que não publicou.

    O documento vai para um arquivo temporário e sai dele em qualquer
    caminho: é o inventário completo da imagem, e deixá-lo para trás em
    `/tmp` seria vazar por descuido o que o comando existe para publicar de
    forma controlada.
    """
    from dockerls.integrations.signing.cosign import CosignClient, SignatureStatus

    with tempfile.NamedTemporaryFile("w", suffix=".json", encoding="utf-8", delete=False) as handle:
        handle.write(content)
        predicate = Path(handle.name)

    try:
        result = await CosignClient().attest(
            image, predicate=str(predicate), predicate_type=_PREDICATE_TYPES[fmt]
        )
    finally:
        with contextlib.suppress(OSError):
            predicate.unlink()

    if result.status is SignatureStatus.SIGNED:
        console.print(f"[green]SBOM attested to {safe(image)}[/green]")
        console.print(
            "[dim]`dockerls registry-audit` will now find it, and so will anyone "
            "running `cosign verify-attestation`.[/dim]"
        )
        return

    if result.status is SignatureStatus.SIGNER_MISSING:
        # Ausência de ferramenta, não falha da imagem. O SBOM foi gerado e
        # continua válido; o que não aconteceu foi a publicação.
        console.print(
            "[yellow]The SBOM was generated but not attested:[/yellow] cosign is not installed."
        )
        raise typer.Exit(EXIT_ERROR)

    console.print(f"[red]Attestation failed:[/red] {safe(result.detail or result.explain())}")
    raise typer.Exit(EXIT_ERROR)
