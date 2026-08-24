from __future__ import annotations

import asyncio
import os
import platform
import shutil
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import typer
from loguru import logger
from rich.console import Console
from rich.table import Table

from dockerls.cli.dependencies import available_source_names, build_source_registry
from dockerls.cli.text import safe
from dockerls.domain.value_objects.tool_release import (
    INSTALLABLE,
    OS,
    Arch,
    ToolSpec,
    detect_arch,
    detect_os,
)
from dockerls.exit_codes import EXIT_ERROR, EXIT_OK
from dockerls.infrastructure.toolchain.installer import (
    InstallError,
    InstallOutcome,
    InstallPlan,
    ToolInstaller,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

    from dockerls.infrastructure.network.host_guard import HostGuard

console = Console()

TRIVY_INSTALL_URL = "https://aquasecurity.github.io/trivy"
GRYPE_INSTALL_URL = "https://github.com/anchore/grype"


def doctor(
    install: bool = typer.Option(
        False,
        "--install",
        help=(
            "Download and install the missing scanners from their projects' official "
            "GitHub releases, verifying the published SHA-256 before installing. "
            "Asks for confirmation first unless --yes is given"
        ),
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Skip the confirmation prompt for --install (for non-interactive CI)",
    ),
    install_dir: str = typer.Option(
        "",
        "--install-dir",
        help="Where to install the binaries [default: ~/.local/bin, no privilege required]",
    ),
) -> None:
    """Check system dependencies and configuration.

    Diagnosis is read-only and is what runs by default. `--install` is the
    only thing that writes anything, and it never runs without either an
    interactive confirmation or an explicit `--yes`.

    What `--install` downloads, and from where:

    \b
      trivy  https://github.com/aquasecurity/trivy/releases
      grype  https://github.com/anchore/grype/releases

    For each tool it fetches the release archive and the `checksums.txt`
    published alongside it, verifies the SHA-256, and extracts only the
    binary. Nothing downloaded is ever executed, and no install script is
    fetched or run. When `cosign` is on PATH the signature is checked too.
    """
    # `doctor` is the documented way for a pipeline to check its
    # prerequisites before a scan job, so it has to *gate*: it used to print
    # "Some components are missing" and exit 0 anyway, which meant a runner
    # with no Trivy installed sailed past the check and failed later, in the
    # scan, where the cause is far less obvious. `health` already gates the
    # same way for network dependencies.
    if install:
        raise typer.Exit(asyncio.run(_install_missing(assume_yes=yes, install_dir=install_dir)))
    raise typer.Exit(asyncio.run(_doctor()))


def _print_sources() -> None:
    """List the catalogues this build can search, and their caveats.

    `--source` accepts these names, and a source whose registry needs
    credentials is called out here rather than discovered as a wall of
    failed scans: an unauthenticated DHI run produces UNVERIFIED
    candidates, which is correct behaviour but a confusing surprise.
    """
    console.print("\n[bold]Image sources[/bold] [dim](--source ...)[/dim]")
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Name", style="bold cyan")
    table.add_column("Detail")
    for spec in build_source_registry().specs:
        notes = [spec.description]
        notes.append("searched by default" if spec.default_enabled else "opt-in")
        if spec.requires_auth:
            notes.append("[yellow]registry requires credentials to scan[/yellow]")
        table.add_row(spec.name, " -- ".join(n for n in notes if n))
    console.print(table)
    console.print(f"  [dim]accepted: {', '.join(available_source_names())}, all[/dim]")


async def _doctor() -> int:
    console.print("[bold]DockerLs System Check[/bold]\n")

    checks = Table(show_header=False, box=None, padding=(0, 2))
    checks.add_column("Component", style="bold")
    checks.add_column("Status")

    has_trivy = shutil.which("trivy") is not None
    has_grype = shutil.which("grype") is not None

    for tool, desc, available in (
        ("trivy", "Primary vulnerability scanner", has_trivy),
        ("grype", "Fallback scanner / cross-validation", has_grype),
    ):
        status = "[green]Available[/green]" if available else "[yellow]Not found[/yellow]"
        checks.add_row(f"{tool} ({desc})", status)

    has_httpx = True
    try:
        import httpx  # noqa: F401

        checks.add_row("httpx", "[green]Available[/green]")
    except ImportError:  # pragma: no cover - httpx is a hard dependency
        checks.add_row("httpx", "[red]Missing[/red]")
        has_httpx = False

    try:
        import keyring  # noqa: F401

        checks.add_row("keyring", "[green]Available[/green]")
    except ImportError:
        checks.add_row("keyring", "[yellow]Not installed (optional)[/yellow]")

    console.print(checks)
    _print_sources()

    # The requirement is *a* scanner, not Trivy specifically: `ScannerFactory`
    # runs on Grype alone. Flagging a Grype-only machine as broken would have
    # been a false alarm, and flagging a machine with neither as fine was the
    # real failure.
    if has_httpx and (has_trivy or has_grype):
        if not (has_trivy and has_grype):
            console.print(
                "\n[yellow]Only one scanner is installed.[/yellow] "
                "[dim]Cross-validation needs both, so scores will be reported "
                "unconfirmed by a second tool.[/dim]"
            )
        else:
            console.print("\n[green]All required components are available.[/green]")
        return EXIT_OK

    console.print("\n[red]DockerLs cannot measure anything on this machine.[/red]")
    console.print("\n[bold]Cause[/bold]")
    if not (has_trivy or has_grype):
        console.print("  No vulnerability scanner is installed (needs Trivy or Grype).")
    if not has_httpx:  # pragma: no cover - httpx is a hard dependency
        console.print("  The httpx package is missing; reinstall dockerls.")

    console.print("\n[bold]Suggested action[/bold]")
    if not (has_trivy or has_grype):
        console.print(f"  Install Trivy:  [cyan]{TRIVY_INSTALL_URL}[/cyan]")
        console.print(f"  or install Grype: [cyan]{GRYPE_INSTALL_URL}[/cyan]")
    console.print(
        "\n[dim]Without a scanner, `recommend`, `analyze` and `advisor` report "
        "every tag as unverified rather than as safe.[/dim]"
    )
    return EXIT_ERROR


def default_install_dir() -> Path:
    """Onde instalar sem pedir privilégio a ninguém.

    `~/.local/bin` no Linux/macOS e o equivalente no Windows: são diretórios
    do próprio usuário, então a instalação nunca precisa de sudo nem de
    prompt de administrador. Um destino que exigisse privilégio teria de
    aparecer na confirmação, e a forma de nunca precisar disso é não
    escolher um.
    """
    if platform.system().strip().lower() == "windows":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "Programs" / "dockerls" / "bin"
    return Path.home() / ".local" / "bin"


def _writable_without_privilege(target: Path) -> bool:
    """Se dá para escrever ali com o usuário atual.

    Sobe até o primeiro ancestral existente: um destino que ainda não existe
    é criável se o pai deixar.
    """
    probe = target
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    return os.access(probe, os.W_OK)


def _plan_for(spec: ToolSpec, version: str, os_: OS, arch: Arch, destination: Path) -> InstallPlan:
    asset = spec.asset_for(version, os_, arch)
    if asset is None:  # pragma: no cover - guarded by the caller
        raise InstallError(f"{spec.name} publishes no build for {os_.value}/{arch.value}")
    return InstallPlan(
        tool=spec.name,
        version=version,
        asset=asset,
        destination=destination,
        needs_privilege=not _writable_without_privilege(destination),
    )


def _print_plans(plans: list[InstallPlan]) -> None:
    """Exatamente o que será baixado, antes de baixar qualquer coisa.

    Consentimento só é informado se a pessoa vê a URL antes de dizer sim --
    e isso inclui dizer, aqui, se algo vai exigir privilégio, em vez de
    descobrir isso no meio da instalação.
    """
    console.print("\n[bold]The following will be downloaded and verified[/bold]\n")
    for plan in plans:
        console.print(f"  [bold cyan]{plan.tool} {plan.version}[/bold cyan]")
        console.print(f"    archive   [dim]{safe(plan.asset.archive_url)}[/dim]", soft_wrap=True)
        console.print(f"    checksums [dim]{safe(plan.asset.checksums_url)}[/dim]", soft_wrap=True)
        console.print(f"    install   [dim]{safe(str(plan.destination))}[/dim]", soft_wrap=True)
        console.print()

    console.print(
        "[dim]The SHA-256 published by each project is verified before anything is "
        "installed, and only the binary is extracted. No install script is fetched "
        "or run, and nothing downloaded is executed.[/dim]"
    )
    if any(p.needs_privilege for p in plans):
        console.print(
            "\n[yellow]This destination is not writable by the current user, so the "
            "install will need elevated privileges.[/yellow]\n"
            "[dim]Use --install-dir to pick a directory you own instead.[/dim]"
        )


async def _install_missing(*, assume_yes: bool, install_dir: str) -> int:
    """Instala os scanners que faltam, um independente do outro."""
    system, machine = platform.system(), platform.machine()
    os_, arch = detect_os(system), detect_arch(machine)
    if os_ is None or arch is None:
        console.print(
            f"[red]Unsupported platform:[/red] {safe(system)} / {safe(machine)}.\n"
            "[dim]Install Trivy or Grype manually; see the links in `dockerls doctor`.[/dim]"
        )
        return EXIT_ERROR

    missing = [spec for spec in INSTALLABLE if shutil.which(spec.name) is None]
    if not missing:
        console.print("[green]Nothing to install: every scanner is already available.[/green]")
        return EXIT_OK

    destination = Path(install_dir).expanduser() if install_dir else default_install_dir()
    unsupported = [s for s in missing if not s.supports(os_, arch)]
    for spec in unsupported:
        console.print(
            f"[yellow]{spec.name} publishes no build for {os_.value}/{arch.value}; "
            f"skipping it.[/yellow] [dim]{spec.repo_url}/releases[/dim]"
        )
    installable = [s for s in missing if s.supports(os_, arch)]
    if not installable:
        return EXIT_ERROR

    installer = ToolInstaller(guard=_install_guard())
    plans: list[InstallPlan] = []
    for spec in installable:
        # Uma ferramenta que não resolve versão não impede a outra.
        try:
            version = await installer.latest_version(spec)
            plans.append(_plan_for(spec, version, os_, arch, destination))
        except InstallError as e:
            console.print(f"[red]{spec.name}:[/red] {safe(str(e))}")

    if not plans:
        return EXIT_ERROR

    _print_plans(plans)
    if not _confirmed(assume_yes):
        console.print("\n[yellow]Nothing was installed.[/yellow]")
        return EXIT_ERROR

    outcomes = []
    for plan in plans:
        console.print(f"\n[bold]{plan.tool}[/bold] downloading and verifying...")
        outcome = await installer.install(plan, cosign=_cosign_if_available())
        outcomes.append(outcome)
        if outcome.installed:
            signed = (
                "  [dim](cosign signature verified)[/dim]" if outcome.signature_verified else ""
            )
            console.print(f"  [green]OK[/green] {safe(outcome.detail)}{signed}")
        else:
            console.print(f"  [red]FAILED[/red] {safe(outcome.detail)}")

    _warn_if_not_on_path(destination, outcomes)

    console.print("\n[bold]Re-running the diagnosis[/bold]\n")
    # O veredito final é o mesmo diagnóstico de sempre, sobre o estado real
    # da máquina: dizer "instalado" sem reconferir seria reportar a intenção
    # em vez do resultado.
    return await _doctor()


def _confirmed(assume_yes: bool) -> bool:
    """Consentimento explícito, e nunca presumido num terminal não-interativo.

    Sem `--yes` e sem alguém do outro lado, a resposta é não: um pipeline
    que não pediu instalação explicitamente não deve receber uma.
    """
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        console.print(
            "\n[yellow]Not an interactive terminal, and --yes was not given.[/yellow]\n"
            "[dim]Re-run with --yes to install without confirmation.[/dim]"
        )
        return False
    return typer.confirm("Proceed with the download and install?", default=False)


def _install_guard() -> HostGuard | None:
    """A mesma política de rede que governa registries e scanners."""
    try:
        from dockerls.cli.dependencies import build_host_guard

        return build_host_guard()
    except Exception as e:  # pragma: no cover - a guard is best-effort here
        logger.debug(f"Network policy unavailable for the installer: {e}")
        return None


def _cosign_if_available() -> object | None:
    """O cosign quando estiver no PATH; a assinatura é um reforço, não um
    requisito -- o checksum publicado já é obrigatório."""
    if shutil.which("cosign") is None:
        return None
    try:
        from dockerls.integrations.signing.cosign import CosignClient

        return CosignClient()
    except Exception as e:  # pragma: no cover
        logger.debug(f"cosign client unavailable: {e}")
        return None


def _warn_if_not_on_path(destination: Path, outcomes: Sequence[InstallOutcome]) -> None:
    """Instalar fora do PATH deixa a ferramenta invisível para o próximo
    comando, e o diagnóstico abaixo diria "Not found" sem explicar por quê."""
    if not any(o.installed for o in outcomes):
        return
    entries = {Path(p).expanduser() for p in os.environ.get("PATH", "").split(os.pathsep) if p}
    if destination.expanduser() in entries:
        return
    console.print(
        f"\n[yellow]{safe(str(destination))} is not on your PATH.[/yellow]\n"
        f"[dim]Add it, or the scanners will not be found by the next command.[/dim]"
    )
