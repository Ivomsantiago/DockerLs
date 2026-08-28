"""O `.dockerls-ignore.yaml` dito em OpenVEX, sem inventar a afirmação.

Um arquivo de isenção já é um documento VEX em tudo menos no formato: ele
tem o CVE, tem a justificativa e tem o prazo. O que faltava era emiti-lo
num formato que o resto do mundo lê -- Trivy e Grype consomem OpenVEX
nativamente --, para que uma exceção decidida uma vez valesse no pipeline
inteiro em vez de só dentro desta ferramenta.

**A parte difícil, e é onde quase toda implementação erra.** VEX tem quatro
estados, e o que quase todo mundo emite para uma isenção é `not_affected`.
Mas `not_affected` é uma afirmação **técnica**: diz que o código vulnerável
não está presente, ou não é alcançável, ou já está mitigado -- e o padrão
exige que se diga qual das cinco razões é, de um vocabulário fechado.

Uma justificativa em texto livre como "a equipe aceitou o risco até o Q3"
não é nenhuma das cinco. Traduzi-la para `not_affected` seria transformar
uma decisão de risco numa afirmação técnica que ninguém fez -- exatamente o
tipo de substituição que este projeto existe para não cometer.

Então:

* se a regra **declara** uma das cinco justificativas do padrão, o
  documento sai como `not_affected` com ela;
* se não declara, sai como `affected` com um `action_statement` carregando
  o texto que a pessoa escreveu. O consumidor vê a exceção, vê o motivo, e
  não recebe uma alegação técnica que a ferramenta inventou.

O prazo entra no `action_statement` porque VEX não tem campo para
expiração: uma isenção sem prazo visível é uma isenção que ninguém revisa.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Sequence
    from datetime import date

#: A versão do vocabulário que este módulo emite.
OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"


class VexStatus(StrEnum):
    """Os quatro estados do padrão. Não há um quinto para "risco aceito"."""

    NOT_AFFECTED = "not_affected"
    AFFECTED = "affected"
    FIXED = "fixed"
    UNDER_INVESTIGATION = "under_investigation"


class VexJustification(StrEnum):
    """O vocabulário fechado que `not_affected` exige.

    Fechado é o ponto: cada uma destas é uma afirmação verificável sobre o
    código, e é por isso que texto livre não cabe aqui.
    """

    COMPONENT_NOT_PRESENT = "component_not_present"
    VULNERABLE_CODE_NOT_PRESENT = "vulnerable_code_not_present"
    VULNERABLE_CODE_NOT_IN_EXECUTE_PATH = "vulnerable_code_not_in_execute_path"
    VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY = (
        "vulnerable_code_cannot_be_controlled_by_adversary"
    )
    INLINE_MITIGATIONS_ALREADY_EXIST = "inline_mitigations_already_exist"


def parse_justification(value: str) -> VexJustification | None:
    """A justificativa do padrão, ou None quando o texto não é uma delas.

    None não é erro: é o caso normal. A maioria das isenções é decisão de
    risco, e o documento sai como `affected` por causa disso.
    """
    try:
        return VexJustification(value.strip().lower())
    except ValueError:
        return None


@dataclass(frozen=True)
class VexStatement:
    """Uma afirmação sobre um CVE num produto."""

    cve: str
    status: VexStatus
    justification: VexJustification | None = None
    action_statement: str = ""

    def to_dict(self, products: Sequence[str], timestamp: str) -> dict[str, Any]:
        statement: dict[str, Any] = {
            "vulnerability": {"name": self.cve},
            "products": [{"@id": product} for product in products],
            "status": str(self.status),
            "timestamp": timestamp,
        }
        if self.justification is not None:
            statement["justification"] = str(self.justification)
        if self.action_statement:
            # `action_statement` é o campo que o padrão prevê para
            # `affected`, e é onde o texto humano cabe sem virar alegação
            # técnica.
            statement["action_statement"] = self.action_statement
        return statement


@dataclass(frozen=True)
class VexDocument:
    """Um documento OpenVEX pronto para ser lido por outra ferramenta."""

    author: str
    products: tuple[str, ...]
    statements: tuple[VexStatement, ...]
    timestamp: str = ""
    version: int = 1

    def to_dict(self) -> dict[str, Any]:
        stamp = self.timestamp or datetime.now(tz=UTC).isoformat()
        return {
            "@context": OPENVEX_CONTEXT,
            # O `@id` precisa ser estável para o mesmo conteúdo e diferente
            # para conteúdos diferentes; derivá-lo do documento é o que
            # torna dois arquivos comparáveis sem abrir os dois.
            "@id": f"https://openvex.dev/docs/dockerls/{self._fingerprint(stamp)}",
            "author": self.author,
            "timestamp": stamp,
            "version": self.version,
            "statements": [s.to_dict(self.products, stamp) for s in self.statements],
        }

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=False)

    def _fingerprint(self, stamp: str) -> str:
        import hashlib

        material = "|".join(
            [self.author, stamp, *self.products, *(f"{s.cve}:{s.status}" for s in self.statements)]
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


@dataclass(frozen=True)
class ExemptionInput:
    """O que uma regra de isenção traz, sem depender do modelo que a leu."""

    cve: str
    justification: str = ""
    expires: date | None = None
    #: A justificativa do padrão, quando quem escreveu declarou uma.
    vex_justification: str = ""
    extra: dict[str, str] = field(default_factory=dict)


def statement_for(exemption: ExemptionInput) -> VexStatement:
    """Traduz uma isenção, sem transformar risco aceito em alegação técnica."""
    declared = parse_justification(exemption.vex_justification)
    if declared is not None:
        return VexStatement(
            cve=exemption.cve,
            status=VexStatus.NOT_AFFECTED,
            justification=declared,
            action_statement=_with_expiry("", exemption),
        )
    return VexStatement(
        cve=exemption.cve,
        status=VexStatus.AFFECTED,
        action_statement=_with_expiry(
            exemption.justification or "exempted in .dockerls-ignore.yaml, with no reason given",
            exemption,
        ),
    )


def _with_expiry(text: str, exemption: ExemptionInput) -> str:
    """Anexa o prazo, que o VEX não tem campo para carregar.

    Uma isenção sem prazo visível é uma isenção que ninguém revisa, e o
    prazo é justamente a parte que o arquivo de origem sabe e o documento
    perderia.
    """
    if exemption.expires is None:
        return text
    note = f"exemption expires on {exemption.expires.isoformat()}"
    return f"{text}; {note}" if text else note


def build_document(
    exemptions: Sequence[ExemptionInput],
    *,
    products: Sequence[str],
    author: str,
    timestamp: str = "",
) -> VexDocument:
    """Monta o documento a partir das isenções ativas."""
    return VexDocument(
        author=author,
        products=tuple(products),
        statements=tuple(statement_for(e) for e in exemptions),
        timestamp=timestamp,
    )
