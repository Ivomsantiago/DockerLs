"""`dockerls base-image` -- gerar e construir a imagem base, item a item.

Uma imagem base é o piso de tudo que vem depois: cada pacote marcado aqui
existe em toda aplicação que a consome, e toda CVE dele vira triagem para
times que nem sabem que ele está lá. Por isso a escolha é uma tela em vez de
um Dockerfile copiado de outro projeto -- e por isso cada item aparece com o
que serve **e** o que custa, na hora de marcar e não depois.

O menu é curto de propósito. Uma lista com tudo que a distribuição publica
faria as pessoas marcarem tudo "por via das dúvidas", que é exatamente o
resultado que uma imagem base não pode ter.

A base sai fixada por digest sempre que o registry responder: uma imagem base
com tag móvel propaga a mesma incerteza para cada projeto que a consome, o que
é o oposto do que ela existe para fazer.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import typer
from rich.console import Console
from rich.prompt import Prompt

from dockerls.cli.dependencies import build_host_guard
from dockerls.cli.text import safe
from dockerls.domain.value_objects.base_recipe import (
    PACKAGE_CATALOG,
    REFUSED_PACKAGES,
    BaseRecipe,
    OsFamily,
    PackageChoice,
    Runtime,
    UnsupportedCombinationError,
    render,
)
from dockerls.domain.value_objects.build_labels import BuildIdentity
from dockerls.domain.value_objects.recipe_diff import RecipeDiff
from dockerls.domain.value_objects.recipe_diff import compare as compare_recipes
from dockerls.exit_codes import EXIT_ERROR, EXIT_OK

console = Console()


def base_image(
    output: str = typer.Option(
        "Dockerfile", "--output", "-o", help="Where to write the generated Dockerfile"
    ),
    os_family: str | None = typer.Option(None, "--os", help="alpine, debian, ubuntu ou distroless"),
    runtime: str | None = typer.Option(None, "--runtime", help="none, java, node, python ou go"),
    with_packages: str | None = typer.Option(
        None, "--with", help="Comma-separated packages, no menu (for pipelines)"
    ),
    owner: str | None = typer.Option(None, "--owner", help="Owning team or person"),
    source_url: str | None = typer.Option(None, "--source", help="Repository URL"),
    title: str | None = typer.Option(None, "--title", help="Image name in the labels"),
    keep_manager: bool = typer.Option(
        False,
        "--keep-manager",
        help=(
            "Keep the package manager the official image bundles (npm, yarn). It is "
            "removed by default: in a runtime base, the dependencies it carries inside "
            "itself are pure surface and sit outside apk/apt"
        ),
    ),
    no_pin: bool = typer.Option(
        False, "--no-pin", help="Do not resolve the base digest (leaves the tag moving)"
    ),
    force: bool = typer.Option(False, "--force", help="Overwrite the output file"),
    build: bool = typer.Option(
        False,
        "--build",
        help="Build and scan the image right after generating it, gated at critical",
    ),
    tag: str | None = typer.Option(
        None, "--tag", "-t", help="Image tag when --build is used (default: <title>:latest)"
    ),
    compare: str | None = typer.Option(
        None,
        "--compare",
        help=(
            "Compare this recipe with the same one on another family (alpine, debian, "
            "ubuntu, distroless) and show the surface difference. Writes nothing"
        ),
    ),
    compare_with: str | None = typer.Option(
        None,
        "--compare-with",
        help="Packages on the compared side, comma-separated (default: the same ones)",
    ),
) -> None:
    """Generate the Dockerfile for a base image from a menu of choices."""
    try:
        family = _resolve_family(os_family)
        chosen_runtime = _resolve_runtime(runtime, family)
        packages = _resolve_packages(with_packages, family)
    except UnsupportedCombinationError as e:
        console.print(f"[red]Error:[/red] {safe(str(e))}")
        raise typer.Exit(EXIT_ERROR) from e

    strip = _resolve_strip(chosen_runtime, family, keep_manager=keep_manager)
    recipe = BaseRecipe(
        family=family,
        runtime=chosen_runtime,
        packages=tuple(packages),
        strip_bundled_manager=strip,
        title=title or _default_title(family, chosen_runtime),
        description=_default_description(family, chosen_runtime),
        owner=(owner or "").strip(),
        source=(source_url or "").strip(),
    )

    if compare is not None:
        _compare_recipes(recipe, compare, compare_with)
        raise typer.Exit(EXIT_OK)

    if not no_pin:
        digest = asyncio.run(_resolve_digest(recipe))
        if digest:
            recipe = BaseRecipe(**{**recipe.__dict__, "digest": digest})
        else:
            console.print(
                "[yellow]The registry did not say which digest the tag points "
                "at.[/yellow]\n"
                "[dim]The Dockerfile goes out without a digest and says so out loud -- "
                "a base image on a moving tag propagates that uncertainty to every "
                "project consuming it.[/dim]"
            )

    try:
        content = render(recipe)
    except UnsupportedCombinationError as e:
        console.print(f"[red]Error:[/red] {safe(str(e))}")
        raise typer.Exit(EXIT_ERROR) from e

    destination = Path(output)
    if destination.exists() and not force:
        console.print(
            f"[red]Error:[/red] {destination} already exists. Use --force to "
            "overwrite, or --output to write elsewhere."
        )
        raise typer.Exit(EXIT_ERROR)

    destination.write_text(content, encoding="utf-8")
    console.print(f"\n[green]Dockerfile escrito em {safe(str(destination))}.[/green]")

    if not build:
        console.print(
            "\n[bold]Next step[/bold]\n"
            f"  [dim]dockerls build -t {safe(recipe.title)}:1.0 --fail-on critical "
            f"{safe(str(destination.parent))}[/dim]\n"
            "  [dim]Building and scanning is what turns this recipe into a claim "
            "about security; until then it is only an intention.[/dim]"
        )
        raise typer.Exit(EXIT_OK)

    _build_now(recipe, destination, tag=tag, owner=owner, source_url=source_url)


def _compare_recipes(left: BaseRecipe, family_name: str, packages: str | None) -> None:
    """Mostra a diferença de superfície entre a receita montada e uma alternativa.

    Comparar não escreve arquivo nenhum: é uma pergunta ("alpine ou debian
    para isto?"), e responder uma pergunta sobrescrevendo um Dockerfile seria
    um efeito colateral que ninguém pediu.
    """
    try:
        outra = _resolve_family(family_name)
    except UnsupportedCombinationError as e:
        console.print(f"[red]Error:[/red] {safe(str(e))}")
        raise typer.Exit(EXIT_ERROR) from e

    if packages is not None:
        try:
            escolhidos = tuple(_resolve_packages(packages, outra))
        except UnsupportedCombinationError as e:
            console.print(f"[red]Error:[/red] {safe(str(e))}")
            raise typer.Exit(EXIT_ERROR) from e
    elif outra.installs_packages:
        # Sem gerenciador de pacotes não há o que carregar: os pacotes viram
        # `removed` no diff, que é exatamente o que a troca significa.
        escolhidos = tuple(p for p in left.packages if _catalog_entry(p).package_for(outra))
    else:
        escolhidos = ()

    try:
        right = BaseRecipe(
            **{
                **left.__dict__,
                "family": outra,
                "packages": escolhidos,
                # A intenção da pessoa é carregada para o outro lado: se ela
                # mandou remover o gerenciador, o lado comparado também remove
                # -- comparar duas políticas diferentes mediria a política, e
                # não a família, que é o que ela perguntou.
                "strip_bundled_manager": _resolve_strip(
                    left.runtime,
                    outra,
                    keep_manager=not left.strip_bundled_manager,
                    quiet=True,
                ),
            }
        )
        right.validate()
        left.validate()
    except UnsupportedCombinationError as e:
        console.print(f"[red]Error:[/red] {safe(str(e))}")
        raise typer.Exit(EXIT_ERROR) from e

    _render_diff(compare_recipes(left, right))


def _catalog_entry(key: str) -> PackageChoice:
    for choice in PACKAGE_CATALOG:
        if choice.key == key:
            return choice
    return PackageChoice(key=key, purpose="", cost="")


def _render_diff(diff: RecipeDiff) -> None:
    esquerda = _side_label(diff.left)
    direita = _side_label(diff.right)
    console.print(f"\n[bold]{safe(esquerda)}[/bold]  ->  [bold]{safe(direita)}[/bold]\n")

    if not diff.has_changes:
        console.print("[dim]The two recipes produce the same surface.[/dim]")
        return

    for delta in diff.added:
        console.print(f"  [green]+ {safe(delta.key)}[/green]  [dim]{safe(delta.purpose)}[/dim]")
        console.print(f"      [dim]custo: {safe(delta.cost)}[/dim]")
    for delta in diff.removed:
        console.print(f"  [red]- {safe(delta.key)}[/red]  [dim]{safe(delta.purpose)}[/dim]")

    notas = diff.notes()
    if notas:
        console.print()
        for nota in notas:
            console.print(f"  [yellow]![/yellow] {safe(nota)}")

    console.print(f"\n[dim]{safe(diff.verdict())}[/dim]")


def _side_label(recipe: BaseRecipe) -> str:
    try:
        return recipe.base.reference
    except UnsupportedCombinationError:
        return f"{recipe.runtime} sobre {recipe.family}"


def _build_now(
    recipe: BaseRecipe,
    destination: Path,
    *,
    tag: str | None,
    owner: str | None,
    source_url: str | None,
) -> None:
    """Constrói a receita recém-gerada, com o portão em `critical`.

    Gerar e construir em dois comandos deixava um vão onde a receita existe e
    ninguém a mediu -- e uma receita não medida é uma intenção, não uma
    afirmação sobre segurança. O portão entra em `critical` porque este
    caminho existe para quem vai usar a imagem, não para quem está brincando.
    """
    from dockerls.application.use_cases.build_image import (
        BuildImageRequest,
        BuildImageUseCase,
    )
    from dockerls.infrastructure.dockerfile_validator import (
        DockerfileValidator,
        HardeningTemplates,
    )

    image_tag = (tag or f"{recipe.title}:latest").strip()
    console.print(f"\n[bold]Building {safe(image_tag)}[/bold]  [dim]gate: critical[/dim]\n")

    identity = BuildIdentity(
        owner=(owner or "").strip(),
        source=(source_url or "").strip(),
        title=recipe.title,
        description=recipe.description,
    )
    use_case = BuildImageUseCase(DockerfileValidator(), HardeningTemplates())
    response = use_case.execute(
        BuildImageRequest(
            context_path=str(destination.parent),
            dockerfile_path=destination.name,
            tag=image_tag,
            fail_on="critical",
            # Os rótulos da receita seguem para a imagem: gerar com dono
            # declarado e construir sem ele perderia metade do ponto.
            labels=identity.to_labels(),
        )
    )

    if response.success:
        console.print(f"[green]Image {safe(image_tag)} built and scanned.[/green]")
        raise typer.Exit(EXIT_OK)

    console.print(f"[red]{safe(response.error or 'build falhou')}[/red]")
    raise typer.Exit(response.exit_code)


def _resolve_strip(
    runtime: Runtime, family: OsFamily, *, keep_manager: bool, quiet: bool = False
) -> bool:
    """Se o gerenciador embutido sai da imagem.

    Isto virou opção por um caso medido: uma `node:22-alpine` recém-construída
    reportava 1 CRITICAL e 7 HIGH, e **todas** vinham das dependências que o
    npm carrega dentro de `node_modules` -- fora do alcance do `apk upgrade`,
    porque não são pacotes da distribuição. As camadas geradas por este comando
    reportavam zero.

    O padrão é remover, porque a pergunta certa numa base de *execução* é o que
    justifica manter: as dependências da aplicação são instaladas no estágio de
    build de quem consome, e nada aqui precisa instalar nada. Quem tem um
    `npm start` que resolve pacotes na subida passa `--keep-manager`.
    """
    from dockerls.domain.value_objects.base_recipe import RUNTIME_BASES

    base = RUNTIME_BASES.get((runtime, family))
    if base is None or not base.bundled_manager:
        return False
    if keep_manager:
        if quiet:
            return False
        console.print(
            f"\n[yellow]{base.bundled_manager_note} stay in the image.[/yellow]\n"
            "[dim]The dependencies they carry inside themselves are usually where "
            "almost every CVE in this base comes from, and a system upgrade does not "
            "reach them.[/dim]"
        )
        return False
    if not quiet:
        console.print(
            f"\n[dim]{base.bundled_manager_note} will be removed from the final image "
            "(--keep-manager keeps them).[/dim]"
        )
    return True


def _resolve_family(value: str | None) -> OsFamily:
    if value:
        try:
            return OsFamily(value.strip().lower())
        except ValueError as e:
            escolhas = ", ".join(f.value for f in OsFamily)
            raise UnsupportedCombinationError(f"invalid --os: {value!r}. Use: {escolhas}") from e

    console.print("\n[bold]Base operating system[/bold]")
    for index, family in enumerate(OsFamily, 1):
        nota = (
            "no shell and no package manager -- the smallest surface, and nothing can be installed"
            if family is OsFamily.DISTROLESS
            else f"libc {family.libc}"
        )
        console.print(f"  {index}. [cyan]{family.value}[/cyan]  [dim]{nota}[/dim]")
    escolha = Prompt.ask(
        "Escolha", choices=[str(i) for i in range(1, len(OsFamily) + 1)], default="1"
    )
    return list(OsFamily)[int(escolha) - 1]


def _resolve_runtime(value: str | None, family: OsFamily) -> Runtime:
    from dockerls.domain.value_objects.base_recipe import RUNTIME_BASES

    disponiveis = [r for r in Runtime if (r, family) in RUNTIME_BASES]
    if value:
        try:
            escolhido = Runtime(value.strip().lower())
        except ValueError as e:
            raise UnsupportedCombinationError(
                f"invalid --runtime: {value!r}. Use: {', '.join(r.value for r in Runtime)}"
            ) from e
        if escolhido not in disponiveis:
            raise UnsupportedCombinationError(
                f"no base image is published for {escolhido} on {family}. "
                f"Available in this family: {', '.join(r.value for r in disponiveis)}"
            )
        return escolhido

    console.print(f"\n[bold]Runtime sobre {family.value}[/bold]")
    for index, runtime in enumerate(disponiveis, 1):
        base = RUNTIME_BASES[(runtime, family)]
        console.print(f"  {index}. [cyan]{runtime.value}[/cyan]  [dim]{base.reference}[/dim]")
    escolha = Prompt.ask(
        "Escolha", choices=[str(i) for i in range(1, len(disponiveis) + 1)], default="1"
    )
    return disponiveis[int(escolha) - 1]


def _resolve_packages(value: str | None, family: OsFamily) -> list[str]:
    if not family.installs_packages:
        if value:
            raise UnsupportedCombinationError(
                "distroless has no package manager and no shell: nothing can be instalar nada nela"
            )
        console.print(
            "\n[dim]distroless installs no packages -- that is precisely its point. "
            "There is no menu to show.[/dim]"
        )
        return []

    if value is not None:
        pedidos = [p.strip() for p in value.split(",") if p.strip()]
        for pedido in pedidos:
            if pedido in REFUSED_PACKAGES:
                raise UnsupportedCombinationError(
                    f"{pedido} is not offered: {REFUSED_PACKAGES[pedido]}"
                )
        return pedidos

    console.print("\n[bold]Packages in the base image[/bold]")
    console.print(
        "[dim]Each one exists in every application that consumes this base, and every "
        "CVE in it becomes triage for someone who does not even know it is "
        "there.[/dim]\n"
    )
    disponiveis = [c for c in PACKAGE_CATALOG if c.package_for(family)]
    for index, choice in enumerate(disponiveis, 1):
        marca = " [dim](already present in most bases)[/dim]" if choice.usually_present else ""
        console.print(f"  {index}. [cyan]{choice.key}[/cyan]{marca}")
        console.print(f"       [dim]used for: {choice.purpose}[/dim]")
        console.print(f"       [yellow]custa:[/yellow] [dim]{choice.cost}[/dim]")

    resposta = Prompt.ask(
        "\nComma-separated numbers (empty = no packages)", default="", show_default=False
    ).strip()
    if not resposta:
        return []

    escolhidos: list[str] = []
    for parte in resposta.split(","):
        parte = parte.strip()
        if not parte.isdigit() or not (1 <= int(parte) <= len(disponiveis)):
            raise UnsupportedCombinationError(f"invalid choice: {parte!r}")
        escolhidos.append(disponiveis[int(parte) - 1].key)

    console.print(f"\n[dim]Marcados: {', '.join(escolhidos)}[/dim]")
    # `s`/`n`, não `y`/`n`: a interface inteira está em português, e um prompt
    # que recusa "s" faz a pessoa duvidar do que ela acabou de marcar.
    if Prompt.ask("Confirma?", choices=["s", "n"], default="s", console=console) == "n":
        console.print("[dim]Nothing was written.[/dim]")
        raise typer.Exit(EXIT_OK)
    return escolhidos


async def _resolve_digest(recipe: BaseRecipe) -> str:
    """Pergunta ao registry qual digest a tag da base aponta agora."""
    from dockerls.domain.entities.image import DockerImage
    from dockerls.integrations.registry.inspector import RegistryInspector

    base = recipe.base
    inspector = RegistryInspector(guard=build_host_guard())
    try:
        return await inspector.resolve_digest(DockerImage(name=base.image, tag=base.tag))
    except Exception:  # pragma: no cover - rede é o caminho instável
        return ""
    finally:
        await inspector.close()


def _default_title(family: OsFamily, runtime: Runtime) -> str:
    return "base-" + (runtime.value if runtime is not Runtime.NONE else family.value)


def _default_description(family: OsFamily, runtime: Runtime) -> str:
    if runtime is Runtime.NONE:
        return f"Base image {family.value}, with no language runtime"
    return f"Base image {family.value} + {runtime.value}"
