"""Montar uma imagem base a partir de escolhas, e dizer o que cada uma custa.

Uma imagem base é o piso de tudo que vem depois: cada pacote instalado aqui
existe em toda aplicação que a consome, e toda CVE dele vira trabalho de
triagem para times que nem sabem que ele está lá. É por isso que a escolha
merece uma tela em vez de um Dockerfile copiado de outro projeto -- e é por
isso que cada item deste catálogo carrega **para que serve** e **o que custa**,
lado a lado.

O catálogo não é uma lista de pacotes disponíveis; é a lista curta do que
aparece de verdade numa imagem base de produção. Oferecer tudo que existe no
repositório da distribuição transformaria a escolha em paralisia e faria as
pessoas marcarem tudo "por via das dúvidas", que é exatamente o resultado que
uma imagem base não pode ter.

Três recusas estão codificadas aqui, e todas vêm da mesma ideia -- conveniência
que se paga em superfície de ataque não é conveniência:

* **distroless não instala nada.** Não há gerenciador de pacotes nem shell na
  imagem; pedir pacotes ali é um mal-entendido sobre o que distroless é, e a
  resposta certa é explicar isso em vez de gerar um Dockerfile que falha.
* **`sudo` não está no catálogo.** Numa imagem que já roda sem privilégio, ele
  existe para cruzar a fronteira que a imagem acabou de estabelecer.
* **o cache do gerenciador sai na mesma camada que o criou**, sempre, sem ser
  uma opção. Removê-lo depois deixa os bytes na camada anterior e a imagem
  carrega o peso e a superfície mesmo parecendo não carregar.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class OsFamily(StrEnum):
    """A distribuição base. Decide libc, gerenciador de pacotes e nomes."""

    ALPINE = "alpine"
    DEBIAN = "debian"
    UBUNTU = "ubuntu"
    DISTROLESS = "distroless"

    @property
    def uses_apk(self) -> bool:
        return self is OsFamily.ALPINE

    @property
    def installs_packages(self) -> bool:
        """Distroless não tem gerenciador de pacotes -- é o ponto dele."""
        return self is not OsFamily.DISTROLESS

    @property
    def libc(self) -> str:
        return "musl" if self is OsFamily.ALPINE else "glibc"


class Runtime(StrEnum):
    """O runtime de linguagem que a base carrega, se carregar algum."""

    NONE = "none"
    JAVA = "java"
    NODE = "node"
    PYTHON = "python"
    GO = "go"


@dataclass(frozen=True)
class RuntimeBase:
    """A imagem oficial que serve de ponto de partida para um runtime."""

    image: str
    tag: str
    #: Caminhos de um gerenciador de pacotes que a imagem oficial embute e que
    #: uma base de *runtime* não precisa. O npm é o caso que motivou isto: ele
    #: vem com a própria árvore de dependências em node_modules, fora do
    #: alcance do apk, e é de onde saem quase todas as CVEs de uma imagem
    #: `node:*-alpine` recém-construída.
    bundled_manager: tuple[str, ...] = ()
    bundled_manager_note: str = ""
    #: Usuário não-root que a imagem oficial já traz, quando traz. Criar outro
    #: por cima seria duplicar o que existe e confundir quem consome.
    builtin_user: str = ""
    note: str = ""

    @property
    def reference(self) -> str:
        return f"{self.image}:{self.tag}"


#: (runtime, família) -> imagem base. Só combinações que existem de verdade:
#: oferecer `go` sobre distroless levaria a `gcr.io/distroless/static`, que não
#: tem runtime nenhum e é uma resposta diferente da que a pessoa pediu.
RUNTIME_BASES: dict[tuple[Runtime, OsFamily], RuntimeBase] = {
    (Runtime.NONE, OsFamily.ALPINE): RuntimeBase("alpine", "3.21"),
    (Runtime.NONE, OsFamily.DEBIAN): RuntimeBase("debian", "12-slim"),
    (Runtime.NONE, OsFamily.UBUNTU): RuntimeBase("ubuntu", "24.04"),
    (Runtime.NONE, OsFamily.DISTROLESS): RuntimeBase(
        "gcr.io/distroless/base-debian12", "nonroot", builtin_user="nonroot"
    ),
    (Runtime.JAVA, OsFamily.ALPINE): RuntimeBase(
        "eclipse-temurin",
        "21-jre-alpine",
        note="JRE, not JDK: a compiler and build tooling are not needed to run a jar",
    ),
    (Runtime.JAVA, OsFamily.DEBIAN): RuntimeBase("eclipse-temurin", "21-jre"),
    (Runtime.JAVA, OsFamily.UBUNTU): RuntimeBase("eclipse-temurin", "21-jre-noble"),
    (Runtime.JAVA, OsFamily.DISTROLESS): RuntimeBase(
        "gcr.io/distroless/java21-debian12", "nonroot", builtin_user="nonroot"
    ),
    (Runtime.NODE, OsFamily.ALPINE): RuntimeBase(
        "node",
        "22-alpine",
        builtin_user="node",
        note="the official image already ships the `node` user",
        bundled_manager=(
            "/usr/local/lib/node_modules/npm",
            "/usr/local/bin/npm",
            "/usr/local/bin/npx",
            "/opt/yarn-*",
            "/usr/local/bin/yarn",
            "/usr/local/bin/yarnpkg",
        ),
        bundled_manager_note="npm and yarn",
    ),
    (Runtime.NODE, OsFamily.DEBIAN): RuntimeBase(
        "node",
        "22-slim",
        builtin_user="node",
        bundled_manager=(
            "/usr/local/lib/node_modules/npm",
            "/usr/local/bin/npm",
            "/usr/local/bin/npx",
            "/opt/yarn-*",
            "/usr/local/bin/yarn",
            "/usr/local/bin/yarnpkg",
        ),
        bundled_manager_note="npm and yarn",
    ),
    (Runtime.NODE, OsFamily.DISTROLESS): RuntimeBase(
        "gcr.io/distroless/nodejs22-debian12", "nonroot", builtin_user="nonroot"
    ),
    (Runtime.PYTHON, OsFamily.ALPINE): RuntimeBase(
        "python",
        "3.12-alpine",
        note="musl: wheels must be musllinux or the package compiles at build time",
    ),
    (Runtime.PYTHON, OsFamily.DEBIAN): RuntimeBase("python", "3.12-slim-bookworm"),
    (Runtime.PYTHON, OsFamily.DISTROLESS): RuntimeBase(
        "gcr.io/distroless/python3-debian12", "nonroot", builtin_user="nonroot"
    ),
    (Runtime.GO, OsFamily.ALPINE): RuntimeBase("golang", "1.23-alpine"),
    (Runtime.GO, OsFamily.DEBIAN): RuntimeBase("golang", "1.23-bookworm"),
}


@dataclass(frozen=True)
class PackageChoice:
    """Um pacote oferecido no menu, com o que ganha e o que custa."""

    key: str
    purpose: str
    #: O preço em superfície de ataque, dito na hora da escolha e não depois.
    cost: str
    #: Nome no apk (Alpine) e no apt (Debian/Ubuntu). Divergem com frequência.
    apk: str = ""
    apt: str = ""
    #: Já presente na maioria das bases; marcar não faz mal, mas não faz nada.
    usually_present: bool = False

    def package_for(self, family: OsFamily) -> str:
        """O nome nesta família, ou "" quando o pacote não existe nela.

        O fallback para `key` só vale quando *nenhum* nome específico foi
        declarado. Aplicá-lo a um pacote que existe só numa família --
        `libc6-compat`, que é do Alpine -- geraria um `apt-get install
        libc6-compat` que quebra o build: o vazio aqui significa "não se
        aplica", e é o que faz o menu não oferecê-lo onde não cabe.
        """
        if not self.apk and not self.apt:
            return self.key
        return self.apk if family.uses_apk else self.apt


#: O menu. Curto de propósito: uma lista longa faz as pessoas marcarem tudo
#: "por via das dúvidas", que é o pior resultado possível numa imagem base.
PACKAGE_CATALOG: tuple[PackageChoice, ...] = (
    PackageChoice(
        key="ca-certificates",
        purpose="validating TLS when talking to any HTTPS service",
        cost="practically none; without it every TLS connection fails verification",
        apk="ca-certificates",
        apt="ca-certificates",
        usually_present=True,
    ),
    PackageChoice(
        key="tzdata",
        purpose="time zones; without it the container stays on UTC and local dates are wrong",
        cost="a few MB of data, no new executable",
        apk="tzdata",
        apt="tzdata",
    ),
    PackageChoice(
        key="curl",
        purpose="HTTP HEALTHCHECK and network diagnostics",
        cost="a full HTTP client inside the container -- what an attacker uses to "
        "fetch the second stage",
        apk="curl",
        apt="curl",
    ),
    PackageChoice(
        key="wget",
        purpose="an alternative to curl for downloading files",
        cost="the same cost as curl; having both doubles the surface, not the use",
        apk="wget",
        apt="wget",
    ),
    PackageChoice(
        key="bash",
        purpose="scripts relying on features the Alpine `sh` does not have",
        cost="a more capable shell is a more useful shell for whoever breaks in",
        apk="bash",
        apt="bash",
    ),
    PackageChoice(
        key="git",
        purpose="cloning or inspecting repositories at runtime",
        cost="rarely needed in production, and pulls a large dependency tree; it "
        "almost always belongs in the build stage",
        apk="git",
        apt="git",
    ),
    PackageChoice(
        key="jq",
        purpose="processar JSON em scripts de entrypoint",
        cost="pequeno e autocontido",
        apk="jq",
        apt="jq",
    ),
    PackageChoice(
        key="openssl",
        purpose="gerar certificados ou depurar TLS de dentro do container",
        cost="the library is already there; this adds the command-line *tool*",
        apk="openssl",
        apt="openssl",
    ),
    PackageChoice(
        key="tini",
        purpose="a minimal init that forwards signals and reaps orphaned processes",
        cost="almost nothing, and it fixes the pid 1 that ignores SIGTERM",
        apk="tini",
        apt="tini",
    ),
    PackageChoice(
        key="libc6-compat",
        purpose="a glibc compatibility layer on Alpine, for pre-compiled binaries",
        cost="only makes sense on Alpine; a Debian already has real glibc",
        apk="libc6-compat",
        apt="",
    ),
)

#: Pacotes que este catálogo recusa a oferecer, com o motivo. São recusas, não
#: omissões: alguém que procurar por eles merece a explicação.
REFUSED_PACKAGES: dict[str, str] = {
    "sudo": (
        "in an image that already runs unprivileged, `sudo` exists to cross the "
        "boundary it just established -- and it is setuid in order to"
    ),
    "su-exec": (
        "switching user at runtime undoes the image `USER`; if the process needs a "
        "different user, declare it in `USER`"
    ),
    "docker": (
        "o cliente Docker dentro do container implica acesso ao socket do "
        "daemon, which is equivalent to root on the host"
    ),
}


class UnsupportedCombinationError(ValueError):
    """A combinação de runtime e sistema operacional não existe."""


@dataclass(frozen=True)
class BaseRecipe:
    """Tudo que decide o conteúdo do Dockerfile de uma imagem base."""

    family: OsFamily
    runtime: Runtime = Runtime.NONE
    packages: tuple[str, ...] = ()
    #: Digest resolvido da base. Vazio deixa a tag móvel -- e o gerador diz
    #: isso em voz alta em vez de fingir que está fixado.
    digest: str = ""
    title: str = "base"
    description: str = ""
    owner: str = ""
    source: str = ""
    uid: int = 10001
    user_name: str = "appuser"
    #: Remover o gerenciador de pacotes que a imagem oficial embute. Vale para
    #: uma base de execução: as dependências que o npm carrega dentro de si
    #: respondem por quase toda CVE de uma `node:*-alpine`, e nada delas é
    #: necessário para *rodar* uma aplicação cujas dependências já foram
    #: instaladas no estágio de build.
    strip_bundled_manager: bool = False
    extra: dict[str, str] = field(default_factory=dict)

    @property
    def base(self) -> RuntimeBase:
        try:
            return RUNTIME_BASES[(self.runtime, self.family)]
        except KeyError as e:
            raise UnsupportedCombinationError(
                f"no base image is published for {self.runtime} on {self.family}"
            ) from e

    def validate(self) -> None:
        base = self.base  # levanta se a combinação não existe
        if self.packages and not self.family.installs_packages:
            raise UnsupportedCombinationError(
                "distroless has no package manager and no shell: nothing can be "
                "installed into it. Use alpine or debian if you need packages, or no "
                "packages at all if what you want is the smallest possible surface"
            )
        for package in self.packages:
            if package in REFUSED_PACKAGES:
                raise UnsupportedCombinationError(
                    f"{package} is not offered: {REFUSED_PACKAGES[package]}"
                )
            if package not in {choice.key for choice in PACKAGE_CATALOG}:
                raise UnsupportedCombinationError(f"unknown package: {package}")
        if base.builtin_user and self.user_name != base.builtin_user:
            # Não é erro -- só não vale a pena criar um usuário quando a
            # imagem oficial já traz um. O gerador reaproveita o existente.
            pass


def render(recipe: BaseRecipe) -> str:
    """O Dockerfile da imagem base, pronto para construir."""
    recipe.validate()
    base = recipe.base
    lines: list[str] = ["# syntax=docker/dockerfile:1", ""]
    lines += _header(recipe, base)

    reference = base.reference
    if recipe.digest:
        lines += [
            f"ARG BASE_DIGEST={recipe.digest}",
            "",
            f"FROM {reference}@${{BASE_DIGEST}}",
        ]
    else:
        lines += [
            "# WARNING: base not pinned by digest. What you test and what is built",
            "# tomorrow can be different bytes, with no change of yours.",
            f"FROM {reference}",
        ]
    lines.append("")
    lines += _labels(recipe)
    lines.append("")

    if recipe.family.installs_packages:
        lines += _packages(recipe)
        lines.append("")

    if recipe.strip_bundled_manager and base.bundled_manager:
        lines += _strip_manager(base)
        lines.append("")

    user = base.builtin_user or recipe.user_name
    if not base.builtin_user and recipe.family.installs_packages:
        lines += _create_user(recipe)
        lines.append("")

    lines += [
        "WORKDIR /app",
        f"USER {user}",
        "",
        "# No ENTRYPOINT, EXPOSE or HEALTHCHECK: a base image does not know which",
        "# port the application listens on, nor what 'healthy' means for it.",
        "# Declaring them here would be inherited wrongly by every consumer.",
    ]
    return "\n".join(lines) + "\n"


def _header(recipe: BaseRecipe, base: RuntimeBase) -> list[str]:
    lines = [
        f"# BASE image generated by DockerLs: {recipe.family}"
        + (f" + {recipe.runtime}" if recipe.runtime is not Runtime.NONE else ""),
        "#",
        "# Contains no application. Consumers do `FROM this-image` and bring",
        "# their own artifact.",
    ]
    if base.note:
        lines += ["#", f"# {base.note}."]
    lines += ["#", f"# libc: {recipe.family.libc}.", ""]
    return lines


def _labels(recipe: BaseRecipe) -> list[str]:
    labels = {
        "maintainer": recipe.owner,
        "security.scanner": "dockerls",
        "org.opencontainers.image.title": recipe.title,
        "org.opencontainers.image.description": recipe.description,
        "org.opencontainers.image.source": recipe.source,
        **recipe.extra,
    }
    entries = [(key, value) for key, value in labels.items() if value]
    if not entries:
        return []
    rendered = ["LABEL " + f'{entries[0][0]}="{entries[0][1]}"' + (" \\" if entries[1:] else "")]
    for index, (key, value) in enumerate(entries[1:]):
        suffix = " \\" if index < len(entries) - 2 else ""
        rendered.append(f'      {key}="{value}"{suffix}')
    return rendered


def _packages(recipe: BaseRecipe) -> list[str]:
    chosen = [choice for choice in PACKAGE_CATALOG if choice.key in recipe.packages]
    names = sorted(
        {
            choice.package_for(recipe.family)
            for choice in chosen
            if choice.package_for(recipe.family)
        }
    )

    comment = [
        "# The digest freezes the base on the day it was published; without this line,",
        "# a package fixed after that date would stay old here.",
    ]
    if recipe.family.uses_apk:
        if not names:
            return [*comment, "RUN apk upgrade --no-cache"]
        pacotes = " \\\n    ".join(names)
        return [
            *comment,
            "# `--no-cache` leaves no index behind: there is nothing to clean up in",
            "# a later layer, and removing the cache afterwards would still leave it",
            "# behind in this layer.",
            "RUN apk upgrade --no-cache && \\",
            "    apk add --no-cache \\",
            f"    {pacotes}",
        ]

    if not names:
        return [
            *comment,
            "RUN apt-get update && apt-get upgrade -y --no-install-recommends && \\",
            "    rm -rf /var/lib/apt/lists/*",
        ]
    pacotes = " \\\n    ".join(names)
    return [
        *comment,
        "# The index lists go out in the layer that created them: removing them later",
        "# would still leave the bytes behind in the earlier layer.",
        "RUN apt-get update && apt-get upgrade -y --no-install-recommends && \\",
        "    apt-get install -y --no-install-recommends \\",
        f"    {pacotes} && \\",
        "    rm -rf /var/lib/apt/lists/*",
    ]


def _create_user(recipe: BaseRecipe) -> list[str]:
    comment = [
        "# a high, fixed uid: consumers inherit the user without recreating it,",
        "# and a high uid does not collide with host users on a bind mount.",
    ]
    if recipe.family.uses_apk:
        return [
            *comment,
            f"RUN addgroup -g {recipe.uid} {recipe.user_name} && \\",
            f"    adduser -u {recipe.uid} -G {recipe.user_name} "
            f"-h /home/{recipe.user_name} -s /sbin/nologin -D {recipe.user_name}",
        ]
    return [
        *comment,
        f"RUN groupadd -g {recipe.uid} {recipe.user_name} && \\",
        f"    useradd -u {recipe.uid} -g {recipe.user_name} "
        f"-s /usr/sbin/nologin -m {recipe.user_name}",
    ]


def _strip_manager(base: RuntimeBase) -> list[str]:
    """Remove o gerenciador de pacotes que a imagem oficial embute.

    O `apk upgrade` não alcança essas dependências: elas vivem em
    `node_modules` dentro do próprio npm, não no banco de pacotes da
    distribuição. Numa base de execução elas são superfície pura -- as
    dependências da aplicação já foram instaladas no estágio de build de quem
    consome, e nada aqui precisa instalar mais nada.

    Quem *precisa* de npm em runtime (um `npm start` que resolve dependências
    na subida, por exemplo) simplesmente não marca esta opção.
    """
    caminhos = " \\\n        ".join(base.bundled_manager)
    return [
        f"# Removes {base.bundled_manager_note}: in a runtime base, the dependencies",
        "# a package manager carries inside itself are pure surface -- and they sit",
        "# outside the reach of a system upgrade, not being distribution packages.",
        "USER root",
        "RUN rm -rf \\",
        f"        {caminhos}",
    ]
