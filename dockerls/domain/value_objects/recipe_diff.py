"""O que muda de superfície entre duas receitas de imagem base.

O menu do `base-image` faz a pessoa escolher família, runtime e pacotes, e
cada escolha custa alguma coisa. O custo aparece na hora de marcar o pacote,
uma linha por vez -- o que não ajuda em nada na pergunta que de fato se faz:
"alpine ou debian para isto?". Comparar exigia gerar os dois Dockerfiles e ler
os dois lado a lado, contando pacotes na mão.

Este módulo responde a pergunta como diferença: o que a receita B tem que a A
não tem, o que ela perde, e o que cada uma dessas trocas significa. É puro --
recebe duas receitas e devolve o delta, sem tocar em registry, disco ou build.

**O que ele deliberadamente não faz é eleger uma vencedora.** Contar pacotes
não mede vulnerabilidade: uma base com menos pacotes e um deles desatualizado
é pior do que uma com mais pacotes e todos corrigidos, e esta ferramenta
inteira é construída sobre a recusa de apresentar como medido o que não foi
medido. O delta descreve as trocas com precisão e manda escanear as duas -- que
é a única coisa que responde de verdade.

A troca de família tem destaque próprio porque é a única que muda o contrato
binário: alpine é musl, debian e ubuntu são glibc. Uma dependência compilada
sem roda musllinux não instala do outro lado, e descobrir isso no diff custa
segundos; descobrir no build de produção custa a janela de deploy.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from dockerls.domain.value_objects.base_recipe import PACKAGE_CATALOG, BaseRecipe

_BY_KEY = {choice.key: choice for choice in PACKAGE_CATALOG}


@dataclass(frozen=True)
class PackageDelta:
    """Um pacote que existe só de um lado, com o que ele traz junto."""

    key: str
    purpose: str
    cost: str

    @staticmethod
    def of(key: str) -> PackageDelta:
        choice = _BY_KEY.get(key)
        if choice is None:
            # Pacote fora do catálogo não deveria chegar aqui (a receita
            # valida antes), mas o diff não é lugar de levantar: descrever o
            # que não se conhece como desconhecido é mais útil que estourar.
            return PackageDelta(key=key, purpose="not catalogued", cost="unknown")
        return PackageDelta(key=choice.key, purpose=choice.purpose, cost=choice.cost)

    def to_dict(self) -> dict[str, str]:
        return {"package": self.key, "purpose": self.purpose, "cost": self.cost}


@dataclass(frozen=True)
class RecipeDiff:
    """As diferenças entre duas receitas, da esquerda para a direita."""

    left: BaseRecipe
    right: BaseRecipe
    added: tuple[PackageDelta, ...] = field(default_factory=tuple)
    removed: tuple[PackageDelta, ...] = field(default_factory=tuple)

    @property
    def family_changed(self) -> bool:
        return self.left.family is not self.right.family

    @property
    def libc_changed(self) -> bool:
        """A troca que quebra binário compilado, e não só tamanho de imagem."""
        return self.left.family.libc != self.right.family.libc

    @property
    def runtime_changed(self) -> bool:
        return self.left.runtime is not self.right.runtime

    @property
    def manager_strip_changed(self) -> bool:
        return self.left.strip_bundled_manager != self.right.strip_bundled_manager

    @property
    def pinning_changed(self) -> bool:
        return bool(self.left.digest) != bool(self.right.digest)

    @property
    def has_changes(self) -> bool:
        return bool(
            self.added
            or self.removed
            or self.family_changed
            or self.runtime_changed
            or self.manager_strip_changed
            or self.pinning_changed
        )

    def notes(self) -> list[str]:
        """As trocas que não são pacote, ditas em uma linha cada."""
        lines: list[str] = []
        both_install = self.left.family.installs_packages and self.right.family.installs_packages
        if self.libc_changed:
            lines.append(
                f"libc changes from {self.left.family.libc} to "
                f"{self.right.family.libc}: compiled dependencies need a wheel for the "
                "new one, or they get built from source -- and some simply do not build"
            )
        elif self.family_changed:
            lines.append(
                f"family changes from {self.left.family} to {self.right.family}, "
                "keeping the same libc"
            )
        if self.runtime_changed:
            lines.append(f"runtime changes from {self.left.runtime} to {self.right.runtime}")
        if not both_install:
            distroless = (
                self.right.family if not self.right.family.installs_packages else self.left.family
            )
            lines.append(
                f"{distroless} has no package manager and no shell: nothing can be "
                "installed into it afterwards, and no `docker exec` will work"
            )
        # Numa distroless não há gerenciador embutido para remover: dizer que
        # um lado "remove e o outro não" descreveria uma diferença que não
        # existe, e a nota do distroless logo acima já cobre o caso.
        if self.manager_strip_changed and both_install:
            quem = "the right" if self.right.strip_bundled_manager else "the left"
            lines.append(
                f"only {quem} removes the package manager the official image ships -- "
                "the largest surface difference between the two, and it does not show "
                "up in a package count"
            )
        if self.pinning_changed:
            solta = "the right" if not self.right.digest else "the left"
            lines.append(
                f"{solta} sits on a moving tag, with no digest: two builds of the same "
                "file can produce different images"
            )
        return lines

    def verdict(self) -> str:
        """Por que este diff não elege uma vencedora."""
        return (
            "this is a content diff, not a vulnerability diff: counting packages does "
            "not measure CVEs, and the only answer to which of the two is safer comes "
            "from scanning both. Build them and run `dockerls scan` on each"
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "left": _describe(self.left),
            "right": _describe(self.right),
            "added": [d.to_dict() for d in self.added],
            "removed": [d.to_dict() for d in self.removed],
            "libc_changed": self.libc_changed,
            "notes": self.notes(),
            "verdict": self.verdict(),
        }


def compare(left: BaseRecipe, right: BaseRecipe) -> RecipeDiff:
    """As diferenças da receita `left` para a `right`."""
    esquerda = set(left.packages)
    direita = set(right.packages)
    return RecipeDiff(
        left=left,
        right=right,
        added=tuple(PackageDelta.of(k) for k in sorted(direita - esquerda)),
        removed=tuple(PackageDelta.of(k) for k in sorted(esquerda - direita)),
    )


def _describe(recipe: BaseRecipe) -> dict[str, object]:
    try:
        reference = recipe.base.reference
    except Exception:
        # Combinação sem imagem publicada: o diff ainda descreve o resto, e
        # `validate()` é quem recusa a receita impossível.
        reference = f"{recipe.runtime} on {recipe.family} (no published image)"
    return {
        "family": str(recipe.family),
        "runtime": str(recipe.runtime),
        "libc": recipe.family.libc,
        "reference": reference,
        "packages": list(recipe.packages),
        "pinned": bool(recipe.digest),
        "strips_bundled_manager": recipe.strip_bundled_manager,
    }
