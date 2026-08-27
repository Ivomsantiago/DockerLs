"""O ponto de entrada da CLI, com os subcomandos carregados sob demanda.

Este módulo importava os 24 comandos no topo, e cada um deles puxa a
árvore inteira da aplicação: o pipeline de scan, os clientes HTTP, o
pydantic-settings, o SQLAlchemy. Como o `import` é o que registra o
comando no Typer, `dockerls version` -- que só imprime uma string --
pagava os mesmos ~390ms de arranque que `dockerls advisor`.

Aqui o registro deixa de depender do import. `_LazyGroup` conhece os
comandos por uma tabela estática (nome, módulo, resumo) e só importa o
módulo quando o comando é de fato invocado. O `--help` do grupo é
desenhado a partir da tabela, sem importar nada.

O preço é a tabela precisar acompanhar as docstrings, e é por isso que
`tests/unit/cli/test_lazy_command_table.py` compara as duas: um comando
novo, renomeado ou com o resumo alterado quebra o teste antes de chegar
na CLI.
"""

from __future__ import annotations

from dataclasses import dataclass
from importlib import import_module
from typing import TYPE_CHECKING, Any

import typer
from typer.core import TyperCommand, TyperGroup
from typer.main import get_command_from_info, get_group
from typer.models import CommandInfo

if TYPE_CHECKING:
    from collections.abc import MutableMapping

    from typer import _click

#: O click que o Typer usa. A partir do Typer 0.27 ele é vendorizado em
#: `typer._click`, e não há mais um `click` de topo garantido no ambiente;
#: `typer.core.TyperCommand`/`TyperGroup` são as classes públicas
#: correspondentes, e é delas que herdamos.


@dataclass(frozen=True)
class _Lazy:
    """Um subcomando e onde encontrá-lo, sem importá-lo."""

    #: Nome na linha de comando.
    name: str
    #: Módulo em `dockerls.cli.commands`.
    module: str
    #: Nome do objeto dentro do módulo.
    attr: str
    #: Primeiro parágrafo da docstring, que é o que o `--help` do grupo
    #: mostra. Duplicado aqui de propósito: é o único jeito de listar os
    #: comandos sem importar todos eles.
    summary: str
    #: `True` quando o objeto é um `typer.Typer` (um subgrupo) em vez de
    #: uma função de comando.
    is_group: bool = False

    def load(self, *, rich_markup_mode: Any) -> _click.Command:
        """Importa o módulo e monta o comando click de verdade."""
        target = getattr(import_module(f"dockerls.cli.commands.{self.module}"), self.attr)
        if self.is_group:
            group = get_group(target)
            group.name = self.name
            group.help = self.summary
            return group
        command = get_command_from_info(
            CommandInfo(name=self.name, callback=target),
            pretty_exceptions_short=False,
            rich_markup_mode=rich_markup_mode,
        )
        return command


#: Os subcomandos, na ordem em que aparecem no `--help`.
COMMANDS: tuple[_Lazy, ...] = (
    _Lazy(
        "search",
        "search",
        "search",
        "Search for available tags of an image, on Docker Hub or any configured source.",
    ),
    _Lazy("recommend", "recommend", "recommend", "Recommend the most secure Docker image tags."),
    _Lazy(
        "advisor",
        "advisor",
        "advisor",
        "Security advisor: analyze and provide actionable remediation plan.",
    ),
    _Lazy(
        "alternatives",
        "alternatives",
        "alternatives",
        "Find safer alternatives to an image you already run, with trade-offs.",
    ),
    _Lazy("analyze", "analyze", "analyze", "Deep-analyze a specific Docker image tag."),
    _Lazy(
        "analyze-dockerfile",
        "analyze_dockerfile",
        "analyze",
        "Analyze a Dockerfile for security problems.",
    ),
    _Lazy(
        "base",
        "base_cmd",
        "base",
        "Check the Dockerfile bases against the registry and refresh their digests.",
    ),
    _Lazy(
        "base-image",
        "base_image",
        "base_image",
        "Generate the Dockerfile for a base image from a menu of choices.",
    ),
    _Lazy(
        "build",
        "build",
        "build",
        "Build secure Docker images with validation, scanning and auto-remediation.",
    ),
    _Lazy("compare", "compare", "compare", "Compare security posture of multiple Docker images."),
    _Lazy(
        "controls",
        "controls",
        "controls",
        "Show the security controls each Dockerfile rule implements.",
    ),
    _Lazy(
        "fleet",
        "fleet",
        "fleet",
        "Scan a tree of repositories and summarise the state of its Dockerfiles.",
    ),
    _Lazy(
        "policy",
        "policy_cmd",
        "policy",
        "Show and validate the policy declared in `.dockerls-policy.yaml`.",
    ),
    _Lazy(
        "provenance",
        "provenance_cmd",
        "provenance",
        "Check a provenance document and prepare the attestation.",
    ),
    _Lazy(
        "registry-audit",
        "registry_audit_cmd",
        "registry_audit",
        "Establish, through the registry, what is known about a published image.",
    ),
    _Lazy("verify", "verify", "verify", "Check an image signature with cosign."),
    _Lazy("export", "export", "export", "Export analysis results in various formats."),
    _Lazy(
        "login",
        "login",
        "login",
        "Authenticate with Docker Hub. Credentials are stored in your system keyring.",
    ),
    _Lazy("logout", "login", "logout", "Remove stored Docker Hub credentials."),
    _Lazy("version", "version", "version", "Show DockerLs version."),
    _Lazy("doctor", "doctor", "doctor", "Check system dependencies and configuration."),
    _Lazy("health", "health", "health", "Check connectivity to external services."),
    _Lazy(
        "sbom",
        "sbom",
        "sbom",
        "Generate a Software Bill of Materials (SBOM) for an image via Trivy.",
    ),
    _Lazy("cache", "cache_cmd", "cache_app", "Manage scan cache", is_group=True),
)

_BY_NAME: dict[str, _Lazy] = {spec.name: spec for spec in COMMANDS}


class _Stub(TyperCommand):
    """O comando como o `--help` do grupo o vê: nome e resumo, mais nada.

    Existe para que listar os comandos não importe nenhum deles. Tudo que
    precisa do comando de verdade -- executar, mostrar o próprio `--help`,
    completar argumentos -- passa por `make_context`/`shell_complete`, e
    esses resolvem o módulo antes de responder.
    """

    def __init__(self, spec: _Lazy, rich_markup_mode: Any) -> None:
        super().__init__(name=spec.name, short_help=spec.summary)
        self._spec = spec
        self._rich_markup_mode = rich_markup_mode

    def _real(self) -> _click.Command:
        return self._spec.load(rich_markup_mode=self._rich_markup_mode)

    def make_context(
        self,
        info_name: str | None,
        args: list[str],
        parent: _click.Context | None = None,
        **extra: Any,
    ) -> _click.Context:
        # O contexto devolvido carrega o comando de verdade, e é dele que
        # o click tira o `invoke`: o stub some da execução aqui.
        return self._real().make_context(info_name, args, parent=parent, **extra)

    def shell_complete(self, ctx: _click.Context, incomplete: str) -> list[Any]:
        return self._real().shell_complete(ctx, incomplete)


class _LazyGroup(TyperGroup):
    """O grupo raiz: conhece os nomes sempre, os módulos só quando preciso."""

    def list_commands(self, ctx: _click.Context) -> list[str]:
        return [spec.name for spec in COMMANDS]

    def get_command(self, ctx: _click.Context, cmd_name: str) -> _click.Command | None:
        spec = _BY_NAME.get(cmd_name)
        if spec is None:
            return None
        return _Stub(spec, self.rich_markup_mode)

    @property
    def commands(self) -> MutableMapping[str, _click.Command]:
        """Compatibilidade: click e typer leem `.commands` em alguns
        caminhos (completação, `to_info_dict`). Devolver os stubs mantém
        esses caminhos funcionando sem importar nada."""
        return {spec.name: _Stub(spec, self.rich_markup_mode) for spec in COMMANDS}

    @commands.setter
    def commands(self, value: MutableMapping[str, _click.Command]) -> None:
        # `TyperGroup.__init__` atribui o dicionário (vazio) de comandos
        # registrados; a tabela estática é a fonte da verdade, então a
        # atribuição é descartada.
        return


app = typer.Typer(
    name="dockerls",
    cls=_LazyGroup,
    help="DockerLs -- Enterprise Docker Image Security Advisor. "
    "Discover the most secure Docker images available on Docker Hub.",
    no_args_is_help=True,
    pretty_exceptions_enable=False,
)


def configure_logging() -> None:
    """Detach loguru's default sink, importing the container only now.

    Indireção de propósito: nem `cli.runtime` pode ser importado no topo,
    ou `dockerls --help` -- que não configura sink nenhum, porque nem chega
    a invocar um subcomando -- pagaria o pydantic-settings junto. Manter o
    nome aqui, em vez de esconder o import dentro de `_bootstrap`, preserva
    o ponto de substituição que os testes de bootstrap usam.
    """
    from dockerls.cli import runtime

    runtime.configure_logging()


@app.callback()
def _bootstrap() -> None:
    """Runs before every subcommand, so no command can start with loguru's
    default DEBUG-to-stderr sink still attached."""
    configure_logging()


def main() -> None:
    app()
