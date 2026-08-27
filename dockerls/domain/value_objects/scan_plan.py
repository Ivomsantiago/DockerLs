"""Quais tags medir, quando medir todas custa minutos.

`recommend node` descobre até `max_tags` tags e mostra cinco. Com o padrão
de 100 e o Trivy a 1,2-2,5s por imagem, isso são dois a quatro minutos de
relógio -- e 95 dos 100 scans existem só para serem descartados no
ranqueamento.

O corte podia ser feito de dois jeitos, e só um deles é honesto neste
projeto:

* **baixar `max_tags`** faria uma tag boa fora da janela simplesmente não
  existir, sem nada dizendo que ela existiu;
* **escolher quem medir, e declarar quem ficou de fora**, que é o que este
  módulo faz.

A distinção que sustenta tudo aqui: uma tag adiada **não é uma tag pior**.
Ela é uma tag *não medida*, e o resultado a carrega com o motivo, do mesmo
jeito que `UnverifiedImage` carrega um scan que falhou. Em nenhum momento a
ausência de medição é gasta como se fosse medição.

Nenhuma regra aqui consulta rede, disco ou scanner: todas usam fatos que a
listagem de tags já trouxe. Uma função pura de decisão se testa
exaustivamente, e é isso que torna defensável cortar 75 scans.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

    from dockerls.domain.entities.image import DockerImage

#: Quantas tags medir quando nada é configurado. `TOP_N` é 5 e a
#: verificação final olha 10 finalistas, então 25 deixa folga de sobra para
#: o ranqueamento ter de quem escolher.
DEFAULT_SCAN_BUDGET = 25

#: Versão no começo da tag: `22`, `22.14`, `3.21.0`. O resto, depois do
#: primeiro `-`, é a variante (`alpine`, `bookworm-slim`, `jre-alpine`).
_VERSION_PREFIX = re.compile(r"^v?(\d+(?:\.\d+)*)(?:[-_.](.*))?$", re.IGNORECASE)


class DeferralReason(StrEnum):
    """Por que uma tag não foi medida. Nunca "por ser pior"."""

    #: Existe uma tag mais nova da mesma linha, com a mesma precisão de
    #: versão e a mesma variante -- `22.13-alpine` diante de `22.14-alpine`.
    SUPERSEDED = "SUPERSEDED"
    #: Coube fora do orçamento de scans deste run.
    OVER_BUDGET = "OVER_BUDGET"


@dataclass(frozen=True)
class DeferredTag:
    """Uma tag que existe, foi descoberta, e não foi medida."""

    reference: str
    reason: DeferralReason
    #: Frase para o humano. Diz o fato que motivou o adiamento, e nunca
    #: uma conclusão sobre a segurança da imagem.
    detail: str


@dataclass(frozen=True)
class ScanPlan:
    """O que este run vai medir, e o que ele declaradamente não vai."""

    selected: list[DockerImage]
    deferred: list[DeferredTag] = field(default_factory=list)
    #: Quantas tags a busca trouxe, antes de qualquer corte.
    discovered: int = 0
    #: O orçamento em vigor; 0 significa "medir todas".
    budget: int = 0

    @property
    def deferred_count(self) -> int:
        return len(self.deferred)


def _version_and_variant(tag: str) -> tuple[tuple[int, ...] | None, str]:
    """A versão numérica no início da tag e a variante que sobra.

    `22.14-alpine` -> `((22, 14), "alpine")`. Uma tag sem versão numérica
    (`latest`, `lts`, `bookworm`) devolve `None`, e tags assim nunca são
    adiadas por sucessão: não há como ordenar o que não tem número.
    """
    match = _VERSION_PREFIX.match(tag.strip())
    if match is None:
        return None, tag.strip().lower()
    version = tuple(int(part) for part in match.group(1).split("."))
    return version, (match.group(2) or "").lower()


def _superseded(tags: Sequence[DockerImage]) -> dict[str, DeferredTag]:
    """As tags que uma irmã mais nova da mesma linha já representa.

    "Mesma linha" é: mesma variante, mesmo major, e mesma quantidade de
    componentes de versão. As duas primeiras condições são a linha em si;
    a terceira é o que impede colapsar `22-alpine` com `22.14-alpine`, que
    são respostas diferentes para perguntas diferentes -- uma acompanha a
    linha, a outra fixa o patch, e escolher entre as duas é do usuário.

    Majors não competem entre si: `20-alpine` continua sendo uma resposta
    legítima ao lado de `22-alpine`, e frequentemente é a certa (LTS).
    """
    newest: dict[tuple[str, int, tuple[int, ...]], DockerImage] = {}
    for image in tags:
        version, variant = _version_and_variant(image.tag)
        if version is None:
            continue
        key = (variant, len(version), version[:1])
        current = newest.get(key)
        if current is None:
            newest[key] = image
            continue
        current_version, _ = _version_and_variant(current.tag)
        if current_version is not None and version > current_version:
            newest[key] = image

    winners = {id(image) for image in newest.values()}
    deferred: dict[str, DeferredTag] = {}
    for image in tags:
        version, variant = _version_and_variant(image.tag)
        if version is None or id(image) in winners:
            continue
        key = (variant, len(version), version[:1])
        winner = newest[key]
        deferred[image.full_reference] = DeferredTag(
            reference=image.full_reference,
            reason=DeferralReason.SUPERSEDED,
            detail=(f"a newer tag of the same line was measured instead ({winner.tag})"),
        )
    return deferred


def _priority(image: DockerImage) -> tuple[int, float, str]:
    """Ordem de preferência para gastar o orçamento.

    Critérios que a listagem já conhece, sem scan: imagem oficial primeiro,
    depois a mais recentemente publicada, depois o nome -- este último só
    para que dois runs sobre os mesmos dados escolham as mesmas tags.
    """
    published = image.last_updated.timestamp() if image.last_updated is not None else 0.0
    return (0 if image.is_official else 1, -published, image.full_reference)


def plan_scans(tags: Sequence[DockerImage], budget: int = DEFAULT_SCAN_BUDGET) -> ScanPlan:
    """Escolhe quem medir, e nomeia quem ficou de fora.

    `budget <= 0` mede tudo, que é o comportamento de sempre e continua
    disponível por configuração -- quem precisa da varredura completa não
    perdeu nada.
    """
    discovered = len(tags)
    if budget <= 0 or discovered <= budget:
        return ScanPlan(
            selected=list(tags), deferred=[], discovered=discovered, budget=max(0, budget)
        )

    superseded = _superseded(tags)
    survivors = [image for image in tags if image.full_reference not in superseded]

    deferred = [
        superseded[image.full_reference] for image in tags if image.full_reference in superseded
    ]

    if len(survivors) > budget:
        ranked = sorted(survivors, key=_priority)
        kept = set(map(id, ranked[:budget]))
        survivors = [image for image in tags if id(image) in kept]
        for image in ranked[budget:]:
            deferred.append(
                DeferredTag(
                    reference=image.full_reference,
                    reason=DeferralReason.OVER_BUDGET,
                    detail=f"beyond this run's budget of {budget} scans",
                )
            )

    # A ordem de saída é a da descoberta: o ranqueamento por segurança
    # acontece depois, sobre medições, e reordenar aqui embaralharia a
    # entrada de uma decisão que nada tem a ver com esta.
    return ScanPlan(
        selected=survivors,
        deferred=deferred,
        discovered=discovered,
        budget=budget,
    )
