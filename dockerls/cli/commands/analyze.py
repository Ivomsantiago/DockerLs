from __future__ import annotations

import asyncio
from pathlib import Path
from typing import TYPE_CHECKING

import typer
from rich.console import Console
from rich.measure import Measurement
from rich.table import Table

from dockerls.application.dto.analysis import AnalysisResult
from dockerls.application.services.remediation import (
    build_remediation_plan,
    render_dockerfile_patch,
)
from dockerls.cli.dependencies import build_analyze_use_case
from dockerls.cli.scan_failure import describe_scan_failure
from dockerls.cli.text import safe
from dockerls.cli.vulnerability_view import (
    count_by_origin,
    exploit_urls,
    npm_remediation_hint,
    origin_label,
    sort_by_severity,
    threat_label,
    threat_style,
)
from dockerls.domain.entities.vulnerability import PackageOrigin, Vulnerability
from dockerls.exit_codes import EXIT_ERROR, EXIT_OK, EXIT_POLICY
from dockerls.exporters.factory import ExporterFactory

if TYPE_CHECKING:
    from dockerls.application.dto.analysis import ImageAnalysis
    from dockerls.application.services.remediation import RemediationPlan
    from dockerls.domain.entities.scan_result import ScanResult

console = Console()


_FORMATS = ("table", "json", "sarif")

#: Limiares de `--fail-on`, do mais severo para o mais brando. Cada um reprova
#: também tudo que for pior que ele -- mesma semântica de `build --fail-on`,
#: para que a mesma palavra não signifique duas coisas na mesma ferramenta.
FAIL_ON_THRESHOLDS = ("critical", "high", "medium", "low")


def analyze(
    image: str = typer.Argument(help="Full image reference (e.g., node:22-alpine)"),
    output_format: str = typer.Option(
        "table", "--format", "-f", help="Output format: table, json or sarif"
    ),
    output: str = typer.Option(
        "", "--output", "-o", help="Write the report (or, with --fix, the patch) to a file"
    ),
    fix: bool = typer.Option(
        False, "--fix", help="Emit a Dockerfile patch that remediates the findings"
    ),
    fail_on: str | None = typer.Option(
        None,
        "--fail-on",
        help="Exit with the policy code when findings at/above this severity exist",
    ),
    no_color: bool = typer.Option(False, "--no-color", help="Disable colored output"),
    wide: bool = typer.Option(
        False, "--wide", help="Render the table without truncating any column"
    ),
) -> None:
    """Deep-analyze a specific Docker image tag."""
    if no_color:
        console.no_color = True
    if output_format not in _FORMATS:
        console.print(
            f"[red]Error:[/red] unsupported --format {output_format!r}. "
            f"Use one of: {', '.join(_FORMATS)}"
        )
        raise typer.Exit(EXIT_ERROR)
    # `--fix` produz um Dockerfile; `json`/`sarif` produzem um relatório. Um
    # `--output` só pode receber um dos dois, e adivinhar qual seria pior que
    # recusar.
    if fix and output_format != "table":
        console.print(
            f"[red]Error:[/red] --fix produces a Dockerfile patch and cannot be combined "
            f"with --format {output_format}. Run it on its own, or with --output."
        )
        raise typer.Exit(EXIT_ERROR)
    # Um limiar que a ferramenta não entende viraria um portão aberto com cara
    # de fechado -- rejeitado antes de qualquer scan começar.
    if fail_on is not None and fail_on.strip().lower() not in FAIL_ON_THRESHOLDS:
        console.print(
            f"[red]Error:[/red] invalid --fail-on {fail_on!r}. "
            f"Use one of: {', '.join(FAIL_ON_THRESHOLDS)}"
        )
        raise typer.Exit(EXIT_ERROR)
    asyncio.run(
        _analyze(
            image,
            wide=wide,
            output_format=output_format,
            output=output,
            fail_on=fail_on,
            fix=fix,
        )
    )


# A CVE ID is the primary key of a finding: "CVE-2026…" identifies nothing and
# cannot be looked up. `CVE-YYYY-NNNNN` is 14 cells, so the column reserves
# that much and the flexible columns (package, versions) give up width first.
_CVE_MIN_WIDTH = 14

# Used to measure what the table would like to be, free of the terminal's
# width -- Measurement clamps to the console otherwise, which makes an
# overflowing table look like a table that fits.
_UNBOUNDED_WIDTH = 10_000


async def _analyze(
    image: str,
    wide: bool = False,
    output_format: str = "table",
    output: str = "",
    fail_on: str | None = None,
    fix: bool = False,
) -> None:
    use_case = await build_analyze_use_case()
    try:
        result = await use_case.execute(image)
    except ValueError as e:
        console.print(f"[red]Scan failed: {e}[/red]")
        raise typer.Exit(EXIT_ERROR) from e
    finally:
        # The scanner and the repository's connection pool are held for the
        # length of the run; releasing them is the caller's job. Rendering
        # below needs only `result`, so this is the right moment.
        await use_case.close()

    if not result.scan.is_verified:
        # Sem scan não há veredito. Sair 0 aqui deixaria um portão de CI
        # passar uma imagem que ninguém mediu.
        #
        # A causa vai resumida: o stderr cru do Trivy para uma tag
        # inexistente ocupa várias linhas e menciona o socket do Docker,
        # que este modo de scan nem usa. O texto completo continua no
        # arquivo de log e em `--format json`.
        console.print(
            f"[red]Scan did not complete for {safe(result.image.full_reference)}:[/red] "
            f"{safe(describe_scan_failure(result.scan.error_kind, result.scan.error_message))}"
        )
        raise typer.Exit(EXIT_ERROR)

    if output_format in ("json", "sarif"):
        _emit_machine_readable(result, output_format, output)
        raise typer.Exit(_fail_on_exit_code(result, fail_on))

    if fix:
        _emit_fix(result, output)
        raise typer.Exit(_fail_on_exit_code(result, fail_on))

    _render_table(result, wide)
    raise typer.Exit(_fail_on_exit_code(result, fail_on))


def _emit_fix(result: ImageAnalysis, output: str) -> None:
    """Emit the Dockerfile patch derived from this image's findings."""
    plan = build_remediation_plan(result)
    patch = render_dockerfile_patch(plan)

    if output:
        path = Path(output)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(patch, encoding="utf-8")
        except OSError as e:
            console.print(f"[red]Could not write {path}:[/red] {e}")
            raise typer.Exit(EXIT_ERROR) from e
        console.print(f"[green]Dockerfile patch written to {path}[/green]")
        console.print(_fix_summary(plan))
        return

    # soft_wrap: o destino provável é um `>` ou um copiar-e-colar, e o Rich
    # quebraria as linhas na largura do terminal.
    console.print(patch, soft_wrap=True, highlight=False)


def _fix_summary(plan: RemediationPlan) -> str:
    resolved = plan.resolved_count
    parts = [f"[dim]{len(plan.actions)} layer(s), addressing {resolved} finding(s)"]
    if plan.unresolved:
        parts.append(f"{len(plan.unresolved)} with no published fix")
    return " | ".join(parts) + "[/dim]"


def _fail_on_exit_code(result: ImageAnalysis, fail_on: str | None) -> int:
    """Honours the tool-wide exit contract: 2 means "measured, and it fails".

    Deliberadamente igual a `build --fail-on`: `1` continua sendo "não
    consegui medir" e `2` "medi, e reprovou". Inverter os dois só aqui faria a
    mesma flag significar coisas opostas em dois comandos da mesma ferramenta.
    """
    if not fail_on:
        return EXIT_OK
    counts = {
        "critical": result.scan.critical_count,
        "high": result.scan.high_count,
        "medium": result.scan.medium_count,
        "low": result.scan.low_count,
    }
    cutoff = FAIL_ON_THRESHOLDS.index(fail_on.strip().lower())
    triggering = [level for level in FAIL_ON_THRESHOLDS[: cutoff + 1] if counts[level] > 0]
    if not triggering:
        return EXIT_OK

    # Um portão que só diz "reprovou" obriga a reabrir o relatório. Ele nomeia
    # os CVEs que o dispararam.
    offenders = [
        v
        for v in sort_by_severity(result.scan.vulnerabilities)
        if v.severity.value.lower() in triggering
    ]
    console.print(
        f"\n[bold red]Gate failed (--fail-on {fail_on}):[/bold red] "
        f"{len(offenders)} finding(s) at or above {fail_on.upper()}"
    )
    for v in offenders[:10]:
        console.print(
            f"  {v.cve_id}  {v.severity.value}  {v.package_name} {v.installed_version}"
            + (f" -> {v.fixed_version}" if v.fixed_version else " (no fix)")
        )
    if len(offenders) > 10:
        console.print(f"  ... and {len(offenders) - 10} more")
    return EXIT_POLICY


def _emit_machine_readable(result: ImageAnalysis, fmt: str, output: str) -> None:
    """Reuse the existing exporters by wrapping the single analysis in the
    same `AnalysisResult` they already consume -- one report shape for the
    whole tool rather than a second one that can drift."""
    wrapped = AnalysisResult(
        query=result.image.full_reference,
        total_tags_scanned=1,
        total_tags_analyzed=1,
        baseline_met=result.production_ready,
        recommendations=[result],
    )
    payload = ExporterFactory.create(fmt).export_string(wrapped)

    if not output:
        # soft_wrap: o Rich quebraria a linha na largura do terminal, e uma
        # quebra no meio de uma string do JSON produz documento inválido.
        console.print(payload, soft_wrap=True)
        return

    path = Path(output)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(payload, encoding="utf-8")
    except OSError as e:
        console.print(f"[red]Could not write {path}:[/red] {e}")
        raise typer.Exit(EXIT_ERROR) from e
    console.print(f"[green]Report written to {path}[/green]")


def _render_table(result: ImageAnalysis, wide: bool) -> None:
    console.print(f"\n[bold]Analysis: {safe(result.image.full_reference)}[/bold]\n")

    info = Table(show_header=False, box=None, padding=(0, 2))
    info.add_column("Key", style="bold")
    info.add_column("Value")
    info.add_row("Score", f"[green]{result.security_score}[/green]")
    info.add_row("Tier", result.tier)
    info.add_row("Critical", f"[red]{result.scan.critical_count}[/red]")
    info.add_row("High", f"[yellow]{result.scan.high_count}[/yellow]")
    info.add_row("Medium", str(result.scan.medium_count))
    info.add_row("Low", str(result.scan.low_count))
    info.add_row("Total Vulns", str(result.scan.total_count))
    # A proporção crua ao lado da contagem: é ela que o "Remediation Score"
    # resume num degrau, e vê-las juntas é o que impede de ler o degrau 20
    # como "20% corrigíveis".
    info.add_row("Fixable", f"{result.scan.fixable_count} ({_fixable_pct(result.scan)})")
    info.add_row("Remediation Score", f"{result.remediation_score}/100")
    info.add_row("EOL", "Yes" if result.is_eol else "No")
    info.add_row("LTS", "Yes" if result.is_lts else "No")
    info.add_row("Scanner", result.scan.scanner)
    console.print(info)

    if result.scan.vulnerabilities:
        console.print("\n[bold]Vulnerabilities[/bold]\n")
        vtable = Table()
        # `overflow="fold"` rather than the default ellipsis: a CVE ID that
        # somehow exceeds the reserved width wraps to a second line, still
        # readable, instead of being cut.
        vtable.add_column("CVE", style="cyan", min_width=_CVE_MIN_WIDTH, overflow="fold")
        vtable.add_column("Severity")
        vtable.add_column("CVSS", justify="right")
        # Qual base publicou o CVSS ao lado. Sem isso, um CRITICAL com score
        # 7.5 -- severidade do vendor, número do NVD -- lê como erro de conta
        # da ferramenta, e quem desconfia de um número desconfia do relatório.
        vtable.add_column("Src", style="dim")
        # `ratio` marks these three as the flexible ones: when the terminal is
        # too narrow, they are what shrinks.
        vtable.add_column("Package", overflow="ellipsis", ratio=1)
        vtable.add_column("Origin", style="magenta", overflow="ellipsis")
        # Explorabilidade: KEV e Exploit-DB numa coluna só. Ambos os sinais
        # já existiam no modelo e nunca chegavam à tabela -- ver
        # `threat_label` para o motivo de dividirem uma célula, e para o
        # motivo de "não consultado" nunca virar "No".
        vtable.add_column("Threat", justify="center", no_wrap=True)
        vtable.add_column("Installed", overflow="ellipsis", ratio=1)
        vtable.add_column("Fixed", overflow="ellipsis", ratio=1)
        vtable.add_column("Status")

        sev_styles = {
            "CRITICAL": "bold red",
            "HIGH": "yellow",
            "MEDIUM": "white",
            "LOW": "dim",
        }
        for v in sort_by_severity(result.scan.vulnerabilities)[:30]:
            st = sev_styles.get(v.severity.value, "")
            status = "FIX AVAILABLE" if v.is_fixable else "NO FIX"
            status_style = "green" if v.is_fixable else "red"
            # Every value below originates outside this process: the CVE id
            # and versions come from an upstream advisory, the package name
            # from inside the image being analysed. Rich would interpret
            # bracket markup in any of them, so a crafted package name could
            # style a CRITICAL row to look benign.
            threat = threat_label(v)
            tstyle = threat_style(v)
            vtable.add_row(
                safe(v.cve_id),
                f"[{st}]{v.severity.value}[/{st}]" if st else v.severity.value,
                f"{v.cvss_score:.1f}",
                safe(v.cvss_source) if v.cvss_source else "-",
                safe(v.package_name),
                origin_label(v),
                f"[{tstyle}]{threat}[/{tstyle}]",
                safe(v.installed_version),
                safe(v.fixed_version) if v.fixed_version else "-",
                f"[{status_style}]{status}[/{status_style}]",
            )
        _print_vulnerabilities(vtable, wide)
        _print_origin_summary(result.scan.vulnerabilities)
        _print_exploit_links(result.scan.vulnerabilities)


def _fixable_pct(scan: ScanResult) -> str:
    if scan.total_count == 0:
        return "n/a"
    return f"{scan.fixable_count / scan.total_count:.0%} of {scan.total_count}"


def _print_vulnerabilities(vtable: Table, wide: bool) -> None:
    """Render the findings table, never at the cost of a CVE ID.

    Rich only redistributes width among columns marked flexible, and only
    when the table is told to fill the available width. Left alone, a table
    wider than the terminal is cropped on the right instead -- which is how
    the CVE column ended up truncated and the last column lost its border.
    """
    natural_width = Measurement.get(
        console, console.options.update(max_width=_UNBOUNDED_WIDTH), vtable
    ).maximum

    if wide:
        # Give the table exactly the width it asked for: nothing truncates.
        Console(width=natural_width, no_color=console.no_color).print(vtable)
        return

    # Only fit-to-width when the terminal is too narrow. On a wide terminal
    # the table keeps its natural layout rather than being stretched.
    vtable.expand = natural_width > console.width
    console.print(vtable)


def _print_origin_summary(vulns: list[Vulnerability]) -> None:
    """Break the findings down by where the affected package lives.

    Uma contagem única de "16 vulnerabilidades" não diz o que fazer com elas.
    Saber que as 16 estão em pacotes de linguagem, e não no SO, é a diferença
    entre `apk upgrade` (que não resolve nada) e remover o npm da imagem
    final (que resolve todas).
    """
    if not vulns:
        return
    counts = count_by_origin(vulns)
    parts = [
        f"OS packages: {counts[PackageOrigin.OS]}",
        f"language packages: {counts[PackageOrigin.LANGUAGE]}",
    ]
    if counts[PackageOrigin.UNKNOWN]:
        parts.append(f"unclassified: {counts[PackageOrigin.UNKNOWN]}")
    console.print(f"\n[bold]By origin:[/bold] {' | '.join(parts)}")

    hint = npm_remediation_hint(vulns)
    if hint:
        console.print(f"\n[bold yellow]Remediation[/bold yellow]\n{hint}")


def _print_exploit_links(vulns: list[Vulnerability]) -> None:
    """Onde ler o exploit, para quem quer julgar a fonte em vez de confiar
    na coluna.

    Abaixo da tabela, e não dentro dela: uma URL não cabe numa célula, e a
    decisão que a coluna sustenta ("isto tem exploit publicado?") é anterior
    à de abrir o link.
    """
    linked = [(v, exploit_urls(v)) for v in sort_by_severity(vulns)]
    linked = [(v, urls) for v, urls in linked if urls]
    if not linked:
        return

    console.print("\n[bold]Published exploits[/bold]")
    for vuln, urls in linked[:10]:
        mark = " [red](verified)[/red]" if vuln.exploitdb_verified else ""
        console.print(f"  {safe(vuln.cve_id)}{mark}")
        for url in urls[:5]:
            # soft_wrap: uma URL quebrada na largura do terminal deixa de ser
            # copiável, que é a única coisa que se faz com ela.
            console.print(f"    [link={url}]{url}[/link]", soft_wrap=True)
    remaining = len(linked) - 10
    if remaining > 0:
        console.print(f"  [dim]... and {remaining} more (see --format json)[/dim]")
