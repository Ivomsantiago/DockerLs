"""Achar uma alternativa **medida** para uma imagem, e dizer o que ela custa.

O `alternatives` já respondia isto para uma referência digitada à mão. O que
faltava era ligar a resposta ao lugar onde a pergunta nasce: o `FROM` de um
Dockerfile. O `base` sabia dizer que uma base apodreceu e sabia atualizar o
digest -- e continuava propondo a mesma imagem, mais nova. Trocar `node:22`
por `node:22` de ontem resolve a data e não resolve a escolha.

Este serviço é a metade compartilhada entre os dois comandos, e existe para
que eles não divirjam: a mesma definição de "melhor", o mesmo baseline medido,
os mesmos trade-offs impressos ao lado dos ganhos.

Duas recusas o definem:

* **Sem baseline medido não há sugestão.** Se a imagem atual não pôde ser
  escaneada, não há como afirmar que outra é melhor. O serviço devolve o
  motivo, e quem chama reporta isso -- nunca uma alternativa apresentada
  contra um baseline desconhecido.
* **Uma alternativa pior não é escondida.** O plano de migração carrega
  `score_delta` negativo quando é o caso, e quem chama decide. Filtrar
  silenciosamente o que ficou pior transformaria a lista num argumento em vez
  de uma medição.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from loguru import logger

from dockerls.application.services.migration import plan_migration

if TYPE_CHECKING:
    from dockerls.application.dto.analysis import ImageAnalysis
    from dockerls.application.services.migration import MigrationPlan
    from dockerls.application.use_cases.analyze_image import AnalyzeImageUseCase
    from dockerls.application.use_cases.recommend_images import RecommendImagesUseCase


@dataclass(frozen=True)
class AlternativeSuggestion:
    """A melhor alternativa medida para uma referência, com o custo da troca."""

    reference: str
    current: ImageAnalysis
    candidate: ImageAnalysis
    plan: MigrationPlan

    @property
    def improves(self) -> bool:
        """Se a troca melhora alguma coisa que foi medida.

        Um `score_delta` positivo sozinho não basta: o que decide na prática é
        CVE a menos, e um score melhor com mais CRITICAL seria uma melhora no
        papel.
        """
        return (
            self.plan.critical_delta < 0
            or self.plan.high_delta < 0
            or (
                self.plan.score_delta > 0
                and self.plan.critical_delta <= 0
                and self.plan.high_delta <= 0
            )
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "for": self.reference,
            "candidate": self.candidate.image.full_reference,
            "pinned": self.plan.to_pinned_reference,
            "improves": self.improves,
            "score_delta": self.plan.score_delta,
            "critical_delta": self.plan.critical_delta,
            "high_delta": self.plan.high_delta,
            "improvements": list(self.plan.improvements),
            "trade_offs": list(self.plan.trade_offs),
        }


@dataclass(frozen=True)
class AlternativeFailure:
    """Por que não houve sugestão. Nunca confundido com "não há nada melhor"."""

    reference: str
    reason: str

    def to_dict(self) -> dict[str, str]:
        return {"for": self.reference, "reason": self.reason}


async def best_alternative(
    reference: str,
    *,
    analyzer: AnalyzeImageUseCase,
    recommender: RecommendImagesUseCase,
) -> AlternativeSuggestion | AlternativeFailure:
    """A melhor alternativa medida para `reference`, ou o motivo de não haver.

    O tipo de retorno é a garantia que importa: quem chama é obrigado a
    distinguir "não achamos nada melhor" de "não conseguimos medir", porque as
    duas coisas chegam como valores diferentes em vez de como `None`.
    """
    # Uma medição que não aconteceu nunca vira baseline. A frase é a mesma
    # para as duas formas de falhar, porque significam a mesma coisa.
    unmeasured = (
        f"{reference} could not be scanned, so no improvement over it can be measured. "
        "This is a technical failure, not a verdict about the image"
    )
    try:
        current = await analyzer.execute(reference)
    except (ValueError, RuntimeError) as e:
        logger.debug(f"Could not analyze {reference}: {e}")
        return AlternativeFailure(reference=reference, reason=unmeasured)

    # A falha chega de duas formas e as duas valem o mesmo aqui. A exceção
    # é o caso antigo; hoje um scan que não completou devolve um
    # `ImageAnalysis` com score 0.0 e tier F por construção, e aceitá-lo
    # como baseline faria toda candidata aparecer como uma melhora enorme
    # sobre uma imagem que ninguém mediu -- exatamente a substituição que a
    # primeira recusa deste módulo existe para impedir.
    if not current.scan.is_verified:
        return AlternativeFailure(reference=reference, reason=unmeasured)

    repository = _repository_of(reference)
    try:
        result = await recommender.execute(repository)
    except (ValueError, RuntimeError) as e:
        logger.debug(f"Could not search for alternatives to {repository}: {e}")
        return AlternativeFailure(
            reference=reference,
            reason=f"the search for alternatives to {repository} failed: {e}",
        )

    for candidate in result.recommendations or result.alternatives:
        if candidate.image.full_reference == current.image.full_reference:
            continue
        if not candidate.confidence.is_recommendable:
            # Uma candidata que a própria ferramenta não consegue afirmar não
            # entra: sugerir com pouca confiança é transferir a incerteza para
            # quem vai fazer a migração sem dizer que ela existe.
            continue
        return AlternativeSuggestion(
            reference=reference,
            current=current,
            candidate=candidate,
            plan=plan_migration(current, candidate),
        )

    return AlternativeFailure(
        reference=reference,
        reason=(
            f"no alternative to {repository} was measured with enough confidence to be recommended"
        ),
    )


def _repository_of(reference: str) -> str:
    """A parte que a descoberta procura: `node:22@sha256:...` -> `node`."""
    head = reference.split("@", 1)[0]
    repository, separator, tail = head.rpartition(":")
    # `registry:5000/app` tem `:` no host, não na tag: só é tag se o que vem
    # depois não contiver barra.
    if separator and "/" not in tail:
        return repository
    return head
