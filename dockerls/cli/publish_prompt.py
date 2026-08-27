"""Perguntar destino e responsabilidade **antes** do build, não depois.

Três coisas precisam estar decididas antes de um `docker build` começar: para
onde a imagem vai, quem responde por ela, e para quem se avisa quando ela
tiver uma vulnerabilidade. Nenhuma delas era perguntada -- o `--push` publicava
a tag local como está, e `--labels` aceitava um JSON vazio sem exigir nada.

A ordem importa e é o ponto do módulo. Descobrir que o destino está errado
depois de validar, construir e escanear desperdiça o trabalho inteiro, e é
exatamente quando alguém está mais propenso a publicar em qualquer lugar só
para não repetir a espera. Rotular depois do build é pior ainda: a imagem já
existe, e rotular passa a significar reconstruir.

Nada aqui pergunta o que já foi respondido por opção de linha de comando, e
`--non-interactive` (assim como `--ci-mode`) troca a pergunta por uma falha
explícita, porque um pipeline não tem quem responda e travar esperando entrada
é o pior comportamento possível num runner.
"""

from __future__ import annotations

import sys

from rich.console import Console
from rich.prompt import Prompt

from dockerls.domain.value_objects.build_labels import REQUIRED_FIELDS, BuildIdentity
from dockerls.domain.value_objects.registry_target import RegistryTarget

console = Console()

#: Exemplos por provedor, mostrados na pergunta do destino. Um formato errado
#: de Artifact Registry só falharia na hora do push, minutos depois.
DESTINATION_EXAMPLES = (
    "Azure ACR        meuregistro.azurecr.io/apps/minha-app",
    "Google Artifact  us-central1-docker.pkg.dev/meu-projeto/containers/minha-app",
    "Google GCR       gcr.io/meu-projeto/minha-app",
    "Docker Hub       minhaorg/minha-app",
    "Registry privado registry.interna:5000/time/minha-app",
)


def interactive_available(*, non_interactive: bool) -> bool:
    """Se dá para perguntar: alguém precisa estar do outro lado do terminal."""
    return not non_interactive and sys.stdin.isatty()


def resolve_destination(
    destination: str | None,
    tag: str,
    *,
    non_interactive: bool,
) -> RegistryTarget | None:
    """O destino de publicação, perguntado quando não veio por opção.

    None significa "não publicar", que é uma resposta legítima e o padrão:
    construir sem publicar é o fluxo mais comum.
    """
    answer = (destination or "").strip()
    if not answer:
        if not interactive_available(non_interactive=non_interactive):
            return None
        console.print("\n[bold]Where is this image going?[/bold]")
        for example in DESTINATION_EXAMPLES:
            console.print(f"  [dim]{example}[/dim]")
        answer = Prompt.ask(
            "Destination (empty = do not publish)",
            default="",
            show_default=False,
            console=console,
        ).strip()
        if not answer:
            return None

    target = RegistryTarget.parse(answer, tag)
    target.validate()
    console.print(
        f"[dim]Destino: {target.reference}  ({target.provider})\n"
        f"Authentication: {target.login_hint}[/dim]"
    )
    return target


def resolve_identity(
    identity: BuildIdentity,
    *,
    non_interactive: bool,
) -> BuildIdentity:
    """Completa os rótulos obrigatórios, perguntando o que falta.

    Em modo não interativo os que faltarem viram erro em vez de pergunta: um
    pipeline não tem quem responda, e publicar sem responsável é o cenário que
    estes campos existem para impedir.
    """
    missing = identity.missing()
    if not missing:
        return identity
    if not interactive_available(non_interactive=non_interactive):
        identity.require_complete()
        return identity

    prompts = dict(REQUIRED_FIELDS)
    answers: dict[str, str] = {}
    console.print("\n[bold]Who answers for this image?[/bold]")
    console.print(
        "[dim]Becomes an OCI label on the manifest. It is what someone reads at three "
        "in the morning to find out where the image came from and who to call.[/dim]"
    )
    for name in missing:
        answers[name] = Prompt.ask(f"  {prompts[name]}", console=console).strip()

    completed = BuildIdentity(
        owner=answers.get("owner", identity.owner),
        security_contact=answers.get("security_contact", identity.security_contact),
        source=answers.get("source", identity.source),
        title=identity.title,
        description=identity.description,
        version=identity.version,
        revision=identity.revision,
        extra=identity.extra,
    )
    completed.require_complete()
    return completed
