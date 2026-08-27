"""Quantas vezes uma tag mudou de bytes debaixo de quem a usa.

`base` já sabe dizer que a tag `python:3.12-alpine` aponta hoje para um digest
diferente do que o Dockerfile fixou. O que ele não sabia dizer é o que essa
frase significa: uma tag que mudou uma vez em oito meses e uma que muda toda
semana pedem decisões opostas, e as duas produziam exatamente o mesmo
`PINNED_STALE`.

Este módulo guarda o histórico dessas observações -- digest e quando foi
visto -- para que a mensagem deixe de ser "mudou" e passe a ser "mudou 6 vezes
desde que começamos a olhar, a última há 3 dias". É a diferença entre um alerta
e uma medida.

Duas escolhas moldam o formato:

* **Só a mudança entra.** Observar a mesma tag no mesmo digest cem vezes não é
  cem eventos; é um. Registrar cada consulta encheria o histórico de ruído e
  faria "6 observações" parecer "6 mudanças".
* **A primeira observação nunca é descartada.** O histórico tem teto, mas
  quando ele estoura são as do meio que caem. Perder a primeira apagaria
  desde-quando -- e "mudou 6 vezes" sem o intervalo é um número sem unidade.

Nada aqui afirma que uma tag *não* mudou: o histórico começa na primeira vez
que esta ferramenta olhou, e o que aconteceu antes disso é desconhecido, não
ausente. `explain()` diz isso em vez de esconder.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime

#: Teto de observações guardadas por tag. Suficiente para enxergar uma cadência
#: e pequeno o bastante para o histórico de um Dockerfile inteiro caber no
#: cache sem virar um banco de dados por acidente.
MAX_OBSERVATIONS = 24


@dataclass(frozen=True)
class TagObservation:
    """Um digest, e quando esta ferramenta o viu pela primeira vez."""

    digest: str
    observed_at: str

    def to_dict(self) -> dict[str, str]:
        return {"digest": self.digest, "observed_at": self.observed_at}

    @staticmethod
    def from_dict(raw: object) -> TagObservation | None:
        """Uma observação vinda do cache, ou `None` se a linha não presta.

        O cache é conteúdo de fora do processo: uma entrada corrompida ou
        gravada por uma versão anterior não deve derrubar um `dockerls base`.
        """
        if not isinstance(raw, dict):
            return None
        digest = raw.get("digest")
        observed = raw.get("observed_at")
        if not isinstance(digest, str) or not isinstance(observed, str):
            return None
        if not digest.strip():
            return None
        return TagObservation(digest=digest.strip(), observed_at=observed.strip())


@dataclass(frozen=True)
class TagHistory:
    """O que se sabe sobre os movimentos de uma tag, em ordem cronológica."""

    reference: str
    observations: tuple[TagObservation, ...] = field(default_factory=tuple)
    #: Movimentos que já não têm observação guardada, por terem caído no teto.
    #: Sem este contador a poda faria a contagem regredir, e uma tag que muda
    #: toda semana -- justamente a que mais importa -- apareceria como a mais
    #: estável de todas assim que passasse de `MAX_OBSERVATIONS`.
    dropped: int = 0

    @property
    def moves(self) -> int:
        """Quantas vezes a tag trocou de digest desde a primeira observação.

        Uma única observação é zero movimentos: é o ponto de partida, não um
        evento.
        """
        return max(len(self.observations) - 1, 0) + self.dropped

    @property
    def current_digest(self) -> str:
        return self.observations[-1].digest if self.observations else ""

    @property
    def first_seen(self) -> str:
        return self.observations[0].observed_at if self.observations else ""

    @property
    def last_moved_at(self) -> str:
        """Quando a tag mudou pela última vez, ou "" se ela nunca mudou aqui."""
        return self.observations[-1].observed_at if self.moves else ""

    @property
    def is_empty(self) -> bool:
        return not self.observations

    def explain(self) -> str:
        """A frase que transforma o histórico numa decisão."""
        if self.is_empty:
            return "first time this tag is observed: there is no history to compare against"
        if not self.moves:
            return (
                f"observed since {self.first_seen}, always on the same digest -- what "
                "happened before that is unknown, not absent"
            )
        vezes = "vez" if self.moves == 1 else "vezes"
        return (
            f"mudou de digest {self.moves} {vezes} desde {self.first_seen}, "
            f"the last on {self.last_moved_at}"
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "reference": self.reference,
            "moves": self.moves,
            "dropped_observations": self.dropped,
            "first_seen": self.first_seen,
            "last_moved_at": self.last_moved_at,
            "explanation": self.explain(),
            "observations": [o.to_dict() for o in self.observations],
        }

    @staticmethod
    def from_dict(reference: str, raw: object) -> TagHistory:
        """Reconstrói do cache, descartando em silêncio o que não presta.

        Um histórico ilegível vira um histórico vazio -- que é honesto: não se
        sabe nada sobre esta tag. Nunca uma exceção: o histórico é um extra
        sobre o diagnóstico, e não pode ser o que impede o diagnóstico.
        """
        if not isinstance(raw, dict):
            return TagHistory(reference=reference)
        entries = raw.get("observations")
        if not isinstance(entries, list):
            return TagHistory(reference=reference)
        parsed = [o for o in (TagObservation.from_dict(e) for e in entries) if o is not None]
        dropped = raw.get("dropped_observations")
        return TagHistory(
            reference=reference,
            observations=tuple(parsed),
            dropped=dropped if isinstance(dropped, int) and dropped >= 0 else 0,
        )


def record(history: TagHistory, digest: str, observed_at: datetime) -> TagHistory:
    """O histórico com esta observação incorporada.

    Digest vazio não entra: "não foi possível perguntar ao registry" não é uma
    observação de nada, e gravá-lo como se fosse inventaria um movimento que
    nunca houve.
    """
    digest = digest.strip()
    if not digest:
        return history
    if history.observations and history.observations[-1].digest == digest:
        return history

    observation = TagObservation(
        digest=digest, observed_at=observed_at.isoformat(timespec="seconds")
    )
    entries = (*history.observations, observation)
    dropped = history.dropped
    if len(entries) > MAX_OBSERVATIONS:
        # A primeira sobrevive porque é ela que ancora o "desde quando"; quem
        # cai é o meio. O que cai vira contagem em `dropped`, para que podar o
        # histórico nunca faça a tag parecer mais estável do que ela é.
        dropped += len(entries) - MAX_OBSERVATIONS
        entries = (entries[0], *entries[-(MAX_OBSERVATIONS - 1) :])
    return replace(history, observations=entries, dropped=dropped)
