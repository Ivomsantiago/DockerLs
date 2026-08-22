"""De quem é cada CVE: da base que você escolheu, ou das camadas que você escreveu.

Um relatório de build diz "47 vulnerabilidades" e manda a pessoa consertar. A
pergunta que ela faz em seguida -- toda vez -- é "consertar *o quê*?", e a
contagem não responde. Nesta ferramenta a resposta apareceu por acaso: uma
`base-node` recém-gerada reprovava com um CRITICAL que não vinha de nada que o
Dockerfile fazia, e sim do npm que a imagem oficial embute. Foi preciso um
terceiro produto para descobrir isso.

Este módulo faz esse cruzamento em casa. Escaneia-se a base declarada no `FROM`
e a imagem construída, e comparam-se os dois conjuntos de achados pela mesma
identidade que a validação cruzada entre scanners já usa (`CVE|pacote`). O
resultado divide as vulnerabilidades em três, e as três levam a ações
completamente diferentes:

* **`INHERITED`** -- está na base e continua na sua imagem. Nada no seu
  Dockerfile causou, e nada no seu Dockerfile resolve: ou a base é atualizada,
  ou é trocada. É aqui que costuma morar a grande maioria.
* **`INTRODUCED`** -- não está na base e está na sua imagem. Veio do que você
  instalou, copiou ou construiu. É a única parte sobre a qual o seu código tem
  poder direto.
* **`REMOVED`** -- estava na base e não está mais. O `apk upgrade` do seu
  Dockerfile, ou a remoção de um pacote, resolveu. Aparece porque é a medida
  do que o seu endurecimento efetivamente comprou.

A regra que sustenta o módulo é a de sempre: **sem os dois scans não há
atribuição.** Se a base não pôde ser escaneada, o resultado é `UNAVAILABLE` e
o relatório diz isso -- nunca "tudo é seu" nem "tudo é herdado", que seriam as
duas maneiras de transformar ausência de medição em acusação.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

from dockerls.domain.entities.vulnerability import finding_identity

if TYPE_CHECKING:
    from collections.abc import Iterable

    from dockerls.domain.entities.vulnerability import Vulnerability


class FindingOrigin(StrEnum):
    """De onde cada achado veio, do ponto de vista de quem escreveu o build."""

    INHERITED = "INHERITED"
    INTRODUCED = "INTRODUCED"
    REMOVED = "REMOVED"


#: O que fazer com cada grupo, dito em uma linha.
ACTIONS: dict[FindingOrigin, str] = {
    FindingOrigin.INHERITED: (
        "veio da base e nenhuma linha do seu Dockerfile resolve: atualize a base "
        "(`dockerls base`) ou troque-a (`dockerls base --alternatives`)"
    ),
    FindingOrigin.INTRODUCED: (
        "veio do que este Dockerfile instala, copia ou constrói: é a parte sobre a "
        "qual você tem poder direto"
    ),
    FindingOrigin.REMOVED: (
        "estava na base e não está mais na imagem final: é a medida do que o seu "
        "endurecimento comprou"
    ),
}


@dataclass(frozen=True)
class AttributedFinding:
    """Um achado, e de quem ele é."""

    identity: str
    cve_id: str
    package_name: str
    severity: str
    origin: FindingOrigin
    #: Versão em que o upstream publicou a correção, quando publicou. Vazio é
    #: "não há correção", e essa distinção é metade do plano de trabalho:
    #: atualizar não resolve o que ninguém corrigiu.
    fixed_version: str = ""

    @property
    def fixable(self) -> bool:
        return bool(self.fixed_version.strip())

    def to_dict(self) -> dict[str, object]:
        return {
            "cve": self.cve_id,
            "package": self.package_name,
            "severity": self.severity,
            "origin": str(self.origin),
            "fixed_version": self.fixed_version,
            "fixable": self.fixable,
        }


#: Severidades da mais grave para a menos, para o plano abrir pelo que importa.
_SEVERITY_RANK = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")


@dataclass(frozen=True)
class RemediationBucket:
    """Um grupo do plano de trabalho: mesma origem, mesma situação de correção.

    Existe porque origem sozinha não é plano. "41 vêm da base" ainda não diz se
    atualizar a base adianta -- e a resposta muda tudo: se nenhuma delas tem
    correção publicada, atualizar é trabalho perdido e trocar a base é o único
    caminho.
    """

    origin: FindingOrigin
    fixable: bool
    findings: tuple[AttributedFinding, ...]

    @property
    def count(self) -> int:
        return len(self.findings)

    @property
    def critical(self) -> int:
        return sum(1 for f in self.findings if f.severity.upper() == "CRITICAL")

    def action(self) -> str:
        """O que fazer com este grupo, e o que essa ação não garante."""
        if self.origin is FindingOrigin.INHERITED:
            if self.fixable:
                return (
                    "há correção publicada upstream: atualizar a base pode "
                    "resolver -- pode, porque a correção existir não significa que "
                    "quem publica a base já reconstruiu com ela. `dockerls base` "
                    "confere se a tag moveu"
                )
            return (
                "não há correção publicada: atualizar a base não resolve nada aqui. "
                "Trocar de base é o único caminho -- `dockerls base --alternatives` "
                "mede as candidatas"
            )
        if self.fixable:
            return (
                "há correção publicada: suba a versão da dependência no seu manifesto e reconstrua"
            )
        return (
            "não há correção publicada e o pacote é seu: avalie remover, substituir "
            "ou isolar. É o grupo em que uma isenção documentada em "
            "`.dockerls-ignore.yaml` faz sentido -- com prazo"
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "origin": str(self.origin),
            "fixable": self.fixable,
            "count": self.count,
            "critical": self.critical,
            "action": self.action(),
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass(frozen=True)
class InheritanceReport:
    """A divisão entre o que é da base e o que é seu."""

    base_reference: str = ""
    #: Vazio quando a atribuição foi possível. Preenchido com o motivo quando
    #: não foi -- e aí nenhuma contagem abaixo significa coisa alguma.
    unavailable_reason: str = ""
    findings: tuple[AttributedFinding, ...] = field(default_factory=tuple)

    @property
    def available(self) -> bool:
        return not self.unavailable_reason

    def of(self, origin: FindingOrigin) -> tuple[AttributedFinding, ...]:
        return tuple(f for f in self.findings if f.origin is origin)

    @property
    def inherited(self) -> tuple[AttributedFinding, ...]:
        return self.of(FindingOrigin.INHERITED)

    @property
    def introduced(self) -> tuple[AttributedFinding, ...]:
        return self.of(FindingOrigin.INTRODUCED)

    @property
    def removed(self) -> tuple[AttributedFinding, ...]:
        return self.of(FindingOrigin.REMOVED)

    @property
    def inherited_share(self) -> float:
        """Fração das vulnerabilidades da imagem que vieram da base, 0.0--1.0.

        Só conta o que está *na imagem*: `REMOVED` descreve o que não está lá,
        e incluí-lo no denominador diluiria a conta com achados que ninguém
        precisa tratar.
        """
        presentes = len(self.inherited) + len(self.introduced)
        return len(self.inherited) / presentes if presentes else 0.0

    def plan(self) -> tuple[RemediationBucket, ...]:
        """O plano de trabalho: origem cruzada com "existe correção?".

        Origem sozinha diz de quem é o problema; correção diz se ele tem
        solução. Só as duas juntas dizem o que fazer na segunda-feira.

        `REMOVED` fica de fora: não está na imagem, e um plano que lista o que
        já não existe faz a lista parecer maior do que o trabalho é.
        """
        buckets: list[RemediationBucket] = []
        for origin in (FindingOrigin.INHERITED, FindingOrigin.INTRODUCED):
            for fixable in (True, False):
                achados = tuple(
                    sorted(
                        (f for f in self.of(origin) if f.fixable is fixable),
                        key=_by_severity,
                    )
                )
                if achados:
                    buckets.append(
                        RemediationBucket(origin=origin, fixable=fixable, findings=achados)
                    )
        # O grupo com mais CRITICAL abre a lista: é onde a primeira hora de
        # trabalho rende mais, e ordenar por total faria um monte de LOW passar
        # à frente de dois CRITICAL sem correção.
        return tuple(sorted(buckets, key=lambda b: (-b.critical, -b.count)))

    @property
    def fixable_inherited(self) -> int:
        return sum(1 for f in self.inherited if f.fixable)

    def explain(self) -> str:
        """A frase que responde "consertar o quê?"."""
        if not self.available:
            return (
                f"não foi possível atribuir as vulnerabilidades: {self.unavailable_reason}. "
                "Sem os dois scans, dizer que elas são suas ou da base seria inventar"
            )
        herdadas, suas = len(self.inherited), len(self.introduced)
        if not herdadas and not suas:
            if self.removed:
                # É o melhor resultado possível, e a versão anterior o
                # escondia atrás de "nada a atribuir": a imagem está limpa
                # *e* o build tirou coisa da base. Vale dizer.
                quantas = len(self.removed)
                if quantas == 1:
                    return (
                        "nenhuma vulnerabilidade nesta imagem, e a 1 que a base tinha "
                        "não sobreviveu ao build"
                    )
                return (
                    f"nenhuma vulnerabilidade nesta imagem, e as {quantas} que a base "
                    "tinha não sobreviveram ao build"
                )
            return "nenhuma vulnerabilidade a atribuir nesta imagem"
        partes = [
            f"{herdadas} de {herdadas + suas} {_vir(herdadas)} da base {self.base_reference}",
            f"{suas} {_vir(suas)} das camadas deste Dockerfile",
        ]
        if self.removed:
            quantas = len(self.removed)
            verbo = "foi removida" if quantas == 1 else "foram removidas"
            partes.append(f"{quantas} que a base tinha {verbo} no build")
        if herdadas:
            # A pergunta imediatamente seguinte a "41 vêm da base" é "e
            # atualizar a base resolve?". Responder junto poupa a viagem.
            corrigiveis = self.fixable_inherited
            partes.append(
                f"{corrigiveis} das herdadas {_ter(corrigiveis)} correção publicada upstream"
            )
        return "; ".join(partes)

    def to_dict(self) -> dict[str, object]:
        return {
            "base": self.base_reference,
            "available": self.available,
            "unavailable_reason": self.unavailable_reason,
            "explanation": self.explain(),
            "counts": {
                "inherited": len(self.inherited),
                "introduced": len(self.introduced),
                "removed": len(self.removed),
            },
            "inherited_share": round(self.inherited_share, 3),
            "actions": {str(origin): action for origin, action in ACTIONS.items()},
            "plan": [b.to_dict() for b in self.plan()],
            "findings": [f.to_dict() for f in self.findings],
        }


def attribute(
    built: Iterable[Vulnerability],
    base: Iterable[Vulnerability],
    *,
    base_reference: str,
) -> InheritanceReport:
    """Divide os achados entre herdados da base, introduzidos e removidos.

    A identidade comparada é `CVE|pacote`, a mesma da validação cruzada entre
    scanners: o mesmo CVE em dois pacotes são dois problemas a resolver, e o
    mesmo pacote com dois CVEs também. A versão instalada fica de fora de
    propósito -- a base e a imagem final frequentemente reportam o mesmo pacote
    com strings de versão normalizadas de formas diferentes, e comparar isso
    fabricaria diferença a partir de formatação.
    """
    por_identidade_construida = {finding_identity(v): v for v in built}
    identidades_base = {finding_identity(v): v for v in base}

    achados: list[AttributedFinding] = []
    for identity, vuln in por_identidade_construida.items():
        origin = (
            FindingOrigin.INHERITED if identity in identidades_base else FindingOrigin.INTRODUCED
        )
        achados.append(_attributed(identity, vuln, origin))

    for identity, vuln in identidades_base.items():
        if identity not in por_identidade_construida:
            achados.append(_attributed(identity, vuln, FindingOrigin.REMOVED))

    return InheritanceReport(base_reference=base_reference, findings=tuple(achados))


def unavailable(base_reference: str, reason: str) -> InheritanceReport:
    """A atribuição que não pôde ser feita, com o motivo em vez de um palpite."""
    return InheritanceReport(base_reference=base_reference, unavailable_reason=reason)


def _attributed(identity: str, vuln: Vulnerability, origin: FindingOrigin) -> AttributedFinding:
    return AttributedFinding(
        identity=identity,
        cve_id=vuln.cve_id,
        package_name=vuln.package_name,
        severity=str(vuln.severity),
        origin=origin,
        fixed_version=vuln.fixed_version,
    )


def _vir(quantidade: int) -> str:
    return "vem" if quantidade == 1 else "vêm"


def _ter(quantidade: int) -> str:
    return "tem" if quantidade == 1 else "têm"


def _by_severity(finding: AttributedFinding) -> tuple[int, str]:
    """Mais grave primeiro; CVE desempata para a ordem ser estável."""
    severity = finding.severity.upper()
    rank = _SEVERITY_RANK.index(severity) if severity in _SEVERITY_RANK else len(_SEVERITY_RANK)
    return rank, finding.cve_id
