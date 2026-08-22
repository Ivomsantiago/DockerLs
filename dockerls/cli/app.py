from __future__ import annotations

import typer

from dockerls.cli.commands.advisor import advisor
from dockerls.cli.commands.alternatives import alternatives
from dockerls.cli.commands.analyze import analyze as analyze_image
from dockerls.cli.commands.analyze_dockerfile import analyze as analyze_dockerfile_cmd
from dockerls.cli.commands.base_cmd import base
from dockerls.cli.commands.base_image import base_image
from dockerls.cli.commands.build import build
from dockerls.cli.commands.cache_cmd import cache_app
from dockerls.cli.commands.compare import compare
from dockerls.cli.commands.controls import controls
from dockerls.cli.commands.doctor import doctor
from dockerls.cli.commands.export import export
from dockerls.cli.commands.fleet import fleet
from dockerls.cli.commands.health import health
from dockerls.cli.commands.login import login, logout
from dockerls.cli.commands.policy_cmd import policy
from dockerls.cli.commands.provenance_cmd import provenance
from dockerls.cli.commands.recommend import recommend
from dockerls.cli.commands.registry_audit_cmd import registry_audit
from dockerls.cli.commands.sbom import sbom
from dockerls.cli.commands.search import search
from dockerls.cli.commands.verify import verify
from dockerls.cli.commands.version import version
from dockerls.cli.dependencies import configure_logging

app = typer.Typer(
    name="dockerls",
    help="DockerLs -- Enterprise Docker Image Security Advisor. "
    "Discover the most secure Docker images available on Docker Hub.",
    no_args_is_help=True,
    pretty_exceptions_enable=False,
)


@app.callback()
def _bootstrap() -> None:
    """Runs before every subcommand, so no command can start with loguru's
    default DEBUG-to-stderr sink still attached."""
    configure_logging()


app.command()(search)
app.command()(recommend)
app.command()(advisor)
app.command()(alternatives)
app.command(name="analyze")(analyze_image)
app.command(name="analyze-dockerfile")(analyze_dockerfile_cmd)
app.command()(base)
app.command(name="base-image")(base_image)
app.command()(build)
app.command()(compare)
app.command()(controls)
app.command()(fleet)
app.command()(policy)
app.command()(provenance)
app.command(name="registry-audit")(registry_audit)
app.command()(verify)
app.command()(export)
app.command()(login)
app.command()(logout)
app.command()(version)
app.command()(doctor)
app.command()(health)
app.command()(sbom)
app.add_typer(cache_app, name="cache", help="Manage scan cache")


def main() -> None:
    app()
