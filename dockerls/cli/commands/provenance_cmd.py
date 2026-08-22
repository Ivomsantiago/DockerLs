"""`dockerls provenance` -- conferir um documento de procedência, e atestá-lo.

O `build --provenance` arquiva um JSON dizendo o que entrou no build e o que
saiu. Arquivar é metade do controle; a outra metade é alguém conferir antes de
o artefato seguir adiante -- e era exatamente essa metade que faltava. Um
documento que ninguém lê descreve com precisão uma imagem que ninguém sabe se
deveria ter sido publicada.

Este comando é essa leitura, e ele faz duas coisas que só fazem sentido juntas:

* **Recalcula o veredito** em vez de acreditar no que está escrito. O campo
  `"status": "VERIFIED"` de um arquivo JSON é editável por qualquer pessoa com
  um editor de texto; a comparação entre os digests de antes e depois do build
  não é. Ler o status gravado seria pedir ao documento que se auto-aprovasse.
* **Recusa por código de saída** quando a procedência não fecha. É o que
  transforma o documento em portão: num workflow, o passo de atestação só roda
  se este comando passar, e uma imagem cuja entrada mudou durante o build nunca
  chega a receber uma assinatura dizendo que veio dali.

`--github-output` existe para o último elo: `actions/attest-build-provenance`
precisa do nome e do digest do artefato, e tirá-los do documento (em vez de
redigitá-los no YAML) garante que a atestação fala da mesma imagem que o scan
mediu. Redigitar é onde a cadeia arrebenta sem ninguém perceber.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import typer
from rich.console import Console

from dockerls.cli.options import OutputFormat, parse_output_format
from dockerls.cli.text import safe
from dockerls.domain.value_objects.provenance import BuildProvenance, ProvenanceStatus
from dockerls.exit_codes import EXIT_ERROR, EXIT_OK, EXIT_POLICY

console = Console()

_COLORS = {
    ProvenanceStatus.VERIFIED: "green",
    ProvenanceStatus.INCOMPLETE: "yellow",
    ProvenanceStatus.INPUT_CHANGED: "red",
}


def provenance(
    document: str = typer.Argument(..., help="Arquivo JSON escrito por `build --provenance`"),
    output_format: str = typer.Option(
        OutputFormat.TABLE.value, "--format", "-f", help="Formato de saída: table ou json"
    ),
    github_output: bool = typer.Option(
        False,
        "--github-output",
        help=(
            "Escreve subject-name e subject-digest em $GITHUB_OUTPUT para "
            "actions/attest-build-provenance consumir"
        ),
    ),
    no_color: bool = typer.Option(False, "--no-color", help="Desativa cor na saída"),
) -> None:
    """Confere um documento de procedência e prepara a atestação."""
    if no_color:
        console.no_color = True
    fmt = parse_output_format(output_format)

    path = Path(document)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except OSError as e:
        console.print(f"[red]Erro:[/red] não foi possível ler {safe(str(path))}: {safe(str(e))}")
        raise typer.Exit(EXIT_ERROR) from e
    except json.JSONDecodeError as e:
        console.print(f"[red]Erro:[/red] {safe(str(path))} não é JSON válido: {safe(str(e))}")
        raise typer.Exit(EXIT_ERROR) from e

    record = BuildProvenance.from_dict(raw)
    subject_name, subject_digest = _subject(record)

    if fmt == OutputFormat.JSON:
        payload = record.to_dict()
        payload["subject_name"] = subject_name
        payload["subject_digest"] = subject_digest
        payload["attestable"] = record.is_verified and bool(subject_digest)
        console.print(json.dumps(payload, indent=2, ensure_ascii=False), soft_wrap=True)
    else:
        _render(record, subject_name, subject_digest)

    if github_output:
        _write_github_output(subject_name, subject_digest, record)

    if not record.is_verified:
        raise typer.Exit(EXIT_POLICY)
    if not subject_digest:
        # Sem digest não há o que atestar: uma assinatura precisa apontar para
        # bytes específicos, e "a imagem com esta tag" não são bytes.
        console.print(
            "[yellow]O documento não traz digest do artefato: não há sujeito para "
            "atestar.[/yellow]\n[dim]Publique a imagem (`build --push`) para que o "
            "registry devolva o digest do manifesto.[/dim]"
        )
        raise typer.Exit(EXIT_POLICY)
    raise typer.Exit(EXIT_OK)


def _subject(record: BuildProvenance) -> tuple[str, str]:
    """Nome e digest do que será atestado.

    O digest do manifesto no registry vem primeiro: é o único identificador
    que outra máquina consegue usar para puxar exatamente estes bytes. O id
    local serve de segundo melhor, e é rotulado como tal na saída.
    """
    name = record.artifact.published_reference or record.tag
    digest = record.artifact.repo_digest or record.artifact.image_id
    return name, digest


def _render(record: BuildProvenance, subject_name: str, subject_digest: str) -> None:
    color = _COLORS.get(record.status, "white")
    console.print(f"\n[bold]{safe(record.tag or '(sem tag)')}[/bold]")
    console.print(f"  [{color}]{record.status}[/{color}]  [dim]{safe(record.explain())}[/dim]\n")

    console.print("  [bold]entrada[/bold]")
    console.print(f"    Dockerfile  {safe(record.source.dockerfile or '(não medido)')}")
    console.print(
        f"    contexto    {safe(record.source.context or '(não medido)')}"
        f"  [dim]({record.source.context_files} arquivo(s))[/dim]"
    )
    if record.source.git_revision:
        sujo = (
            " [yellow](com alterações não commitadas)[/yellow]" if record.source.git_dirty else ""
        )
        console.print(f"    revisão     {safe(record.source.git_revision)}{sujo}")
    for reference, digest in record.source.base_images.items():
        console.print(f"    base        {safe(reference)} -> {safe(digest or '(tag móvel)')}")

    console.print("\n  [bold]saída[/bold]")
    console.print(f"    sujeito     {safe(subject_name or '(sem nome)')}")
    origem = "manifesto no registry" if record.artifact.repo_digest else "id local da imagem"
    console.print(
        f"    digest      {safe(subject_digest or '(sem digest)')}  [dim]({origem})[/dim]"
    )
    console.print(f"    scanner     {safe(record.artifact.scanner or '(não registrado)')}\n")


def _write_github_output(name: str, digest: str, record: BuildProvenance) -> None:
    """Publica o sujeito da atestação para o próximo passo do workflow.

    Fora do Actions a variável não existe, e escrever num caminho arbitrário
    seria efeito colateral fora de contexto: o comando avisa e segue.
    """
    destination = os.environ.get("GITHUB_OUTPUT", "")
    if not destination:
        console.print(
            "[yellow]$GITHUB_OUTPUT não está definido: --github-output só tem efeito "
            "dentro de um workflow do GitHub Actions.[/yellow]"
        )
        return
    linhas = f"subject-name={name}\nsubject-digest={digest}\nprovenance-status={record.status}\n"
    try:
        with Path(destination).open("a", encoding="utf-8") as handle:
            handle.write(linhas)
    except OSError as e:
        console.print(
            f"[yellow]Não foi possível escrever em $GITHUB_OUTPUT: {safe(str(e))}[/yellow]"
        )
