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
        "true": "the registry answered which digest this reference points at",
        "false": (
            "the registry did not resolve this reference: without a digest, nothing "
            "else here can be measured"
        ),
        "unknown": "the registry could not be asked",
    },
    AuditCheck.PINNED_REFERENCE: {
        "true": "the reference is already a digest: it points at specific bytes",
        "false": (
            "the reference is a tag: what was tested and what runs can be different "
            "bytes with no change of yours"
        ),
        "unknown": "the shape of the reference could not be determined",
    },
    AuditCheck.TAG_STABLE: {
        "true": "this tag has not changed digest since we started watching it",
        "false": (
            "this tag has already changed digest: measured evidence that it is "
            "mutable, whatever the registry immutability setting says"
        ),
        "unknown": (
            "there is no history for this tag: what happened before the first "
            "observation is unknown, not absent"
        ),
    },
    AuditCheck.SIGNATURE_PRESENT: {
        "true": "a cosign signature is published for this digest",
        "false": (
            "no cosign signature is published for this digest: nobody publicly "
            "attested to producing these bytes"
        ),
        "unknown": "the registry could not be asked about the signature",
    },
    AuditCheck.ATTESTATION_PRESENT: {
        "true": "a cosign attestation is published for this digest",
        "false": (
            "no attestation is published for this digest: the registry holds no "
            "record of how this image was built"
        ),
        "unknown": "the registry could not be asked about the attestation",
    },
    AuditCheck.PUBLICLY_READABLE: {
        "true": (
            "the registry answered with no credential at all: anyone on the internet "
            "can pull this image and inspect what is inside it. Whether that is a "
            "problem depends on what it exists for, and only you know that part"
        ),
        "false": "the registry required a credential to answer",
        "unknown": "whether anonymous access is allowed could not be determined",
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
            return "nothing could be established about this reference"
        partes = [f"{len(self.alerts)} finding(s) that want attention"]
        if self.unmeasured:
            partes.append(f"{len(self.unmeasured)} not measured")
        return ", ".join(partes)

    def caveat(self) -> str:
        return (
            "this audit uses the OCI protocol alone, with no cloud credential: it "
            "does not read retention policies, IAM, or the provider immutability "
            "settings. What it measures, it measures for real; what it does not, it "
            "says it did not"
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
