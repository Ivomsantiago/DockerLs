"""O que se consegue apurar sobre uma imagem *pelo registry*, sem credencial.

Auditar a configuração de um registry -- políticas de retenção, IAM, content
trust -- exige credencial de nuvem e uma API diferente para cada provedor. Não
é isto aqui. Este módulo é a parte que se mede com o protocolo OCI e mais nada,
e é deliberadamente essa: um relatório que precisa de acesso administrativo
para existir é um relatório que ninguém roda.

O que dá para apurar assim é menos do que parece e mais do que se costuma
olhar:

* a referência resolve para um digest, e qual;
* a referência que a pessoa usou já era um digest, ou era uma tag;
* a tag já mudou de digest desde que esta ferramenta começou a olhar -- que é
  a única evidência *medida* de que ela é mutável, em vez da configuração
  declarada de imutabilidade, que ninguém confere;
* existe assinatura cosign publicada para aquele digest;
* existe atestação cosign publicada para aquele digest;
* o registry respondeu sem nenhuma credencial -- ou seja, a imagem é legível
  por qualquer pessoa da internet.

Cada achado é tri-estado por construção. `UNKNOWN` não é um detalhe do formato:
sem ele, "o registry não respondeu" viraria "não há assinatura", e essa é
exatamente a substituição que faz um relatório de segurança mentir.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from dockerls.domain.value_objects.tristate import Tristate


class AuditCheck(StrEnum):
    """Cada coisa que se pergunta ao registry."""

    RESOLVABLE = "RESOLVABLE"
    PINNED_REFERENCE = "PINNED_REFERENCE"
    TAG_STABLE = "TAG_STABLE"
    SIGNATURE_PRESENT = "SIGNATURE_PRESENT"
    ATTESTATION_PRESENT = "ATTESTATION_PRESENT"
    PUBLICLY_READABLE = "PUBLICLY_READABLE"


#: Checagens que são relatadas e nunca alertam. `PUBLICLY_READABLE` está aqui
#: porque "público" é o estado *correto* de uma imagem base oficial e o estado
#: errado de um artefato interno -- e a diferença entre os dois é a intenção de
#: quem publicou, que esta ferramenta não tem como medir. Transformar o fato em
#: alerta seria afirmar uma intenção; relatá-lo sem alertar entrega o fato a
#: quem sabe qual era.
_INFORMATIONAL = frozenset({AuditCheck.PUBLICLY_READABLE})


@dataclass(frozen=True)
class AuditFinding:
    """Uma resposta do registry, com o que ela significa."""

    check: AuditCheck
    state: Tristate
    detail: str = ""

    @property
    def is_informational(self) -> bool:
        """Se é um fato relatado sem juízo de valor. Ver `_INFORMATIONAL`."""
        return self.check in _INFORMATIONAL

    @property
    def is_alert(self) -> bool:
        """Se este achado pede ação.

        `UNKNOWN` nunca é alerta e nunca é aprovação: é ausência de resposta, e
        entra no relatório como tal.
        """
        if not self.state.is_known or self.check in _INFORMATIONAL:
            return False
        return self.state.is_false

    @property
    def is_unmeasured(self) -> bool:
        return not self.state.is_known

    def explain(self) -> str:
        return _EXPLANATIONS[self.check][str(self.state)]

    def to_dict(self) -> dict[str, object]:
        return {
            "check": str(self.check),
            "state": str(self.state),
            "alert": self.is_alert,
            "explanation": self.explain(),
            "detail": self.detail,
        }


_EXPLANATIONS: dict[AuditCheck, dict[str, str]] = {
    AuditCheck.RESOLVABLE: {
        "true": "o registry respondeu qual digest esta referência aponta",
        "false": (
            "o registry não resolveu esta referência: sem digest, nada mais aqui pode ser medido"
        ),
        "unknown": "não foi possível perguntar ao registry",
    },
    AuditCheck.PINNED_REFERENCE: {
        "true": "a referência já é um digest: aponta para bytes específicos",
        "false": (
            "a referência é uma tag: o que foi testado e o que roda podem ser bytes "
            "diferentes sem nenhuma mudança sua"
        ),
        "unknown": "não foi possível determinar a forma da referência",
    },
    AuditCheck.TAG_STABLE: {
        "true": "esta tag não mudou de digest desde que passamos a observá-la",
        "false": (
            "esta tag já mudou de digest: é a evidência medida de que ela é mutável, "
            "independente do que a configuração de imutabilidade do registry diga"
        ),
        "unknown": (
            "não há histórico desta tag: o que aconteceu antes da primeira observação "
            "é desconhecido, não ausente"
        ),
    },
    AuditCheck.SIGNATURE_PRESENT: {
        "true": "há assinatura cosign publicada para este digest",
        "false": (
            "não há assinatura cosign publicada para este digest: ninguém atestou "
            "publicamente quem produziu estes bytes"
        ),
        "unknown": "não foi possível perguntar ao registry sobre a assinatura",
    },
    AuditCheck.ATTESTATION_PRESENT: {
        "true": "há atestação cosign publicada para este digest",
        "false": (
            "não há atestação publicada para este digest: não existe registro no "
            "registry de como esta imagem foi construída"
        ),
        "unknown": "não foi possível perguntar ao registry sobre a atestação",
    },
    AuditCheck.PUBLICLY_READABLE: {
        "true": (
            "o registry respondeu sem nenhuma credencial: qualquer pessoa da internet "
            "consegue baixar esta imagem e inspecionar o que há dentro dela. Se isso é "
            "problema depende de para que ela existe, e essa parte só você sabe"
        ),
        "false": "o registry exigiu credencial para responder",
        "unknown": "não foi possível determinar se o acesso anônimo é permitido",
    },
}


@dataclass(frozen=True)
class RegistryAudit:
    """O conjunto de respostas para uma referência."""

    reference: str
    digest: str = ""
    findings: tuple[AuditFinding, ...] = field(default_factory=tuple)

    @property
    def alerts(self) -> tuple[AuditFinding, ...]:
        return tuple(f for f in self.findings if f.is_alert)

    @property
    def unmeasured(self) -> tuple[AuditFinding, ...]:
        return tuple(f for f in self.findings if f.is_unmeasured)

    def summary(self) -> str:
        if not self.findings:
            return "nada pôde ser apurado sobre esta referência"
        partes = [f"{len(self.alerts)} achado(s) que pedem atenção"]
        if self.unmeasured:
            partes.append(f"{len(self.unmeasured)} não medido(s)")
        return ", ".join(partes)

    def caveat(self) -> str:
        return (
            "esta auditoria usa só o protocolo OCI, sem credencial de nuvem: ela não "
            "lê políticas de retenção, IAM nem configuração de imutabilidade do "
            "provedor. O que ela mede, mede de verdade; o que não mede, diz que não "
            "mediu"
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "reference": self.reference,
            "digest": self.digest,
            "summary": self.summary(),
            "caveat": self.caveat(),
            "alerts": len(self.alerts),
            "unmeasured": len(self.unmeasured),
            "findings": [f.to_dict() for f in self.findings],
        }
