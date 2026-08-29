"""Há quanto tempo o medidor foi atualizado, e o que isso permite afirmar.

`doctor` conferia que o scanner **existe**. Não conferia que ele mede: um
Trivy com base de vulnerabilidades de três semanas produz um scan limpo,
verde e sem erro nenhum que simplesmente não conhece os CVEs do último mês.

É a falha de medição mais silenciosa que existe aqui, e a mais perigosa
justamente por ser silenciosa -- nada no relatório indica que a resposta
está velha. É o tema central do projeto ("ausência de medição nunca é gasta
como tranquilidade") aplicado ao próprio medidor.

O tristate aparece de novo, e pela mesma razão de sempre: não conseguir ler
a data da base **não** é a base estar fresca. `UNKNOWN` é o valor honesto
para um arquivo de metadados ausente, ilegível ou com um formato que este
código não reconhece, e ele nunca é apresentado como aprovação.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum

#: Até aqui, a base cobre o que se publicou recentemente. O Trivy reconstrói
#: a dele a cada 6h e carimba `NextUpdate` cerca de 24h à frente; o Grype
#: publica diariamente. Um dia é a janela normal dos dois.
FRESH_WITHIN = timedelta(hours=24)

#: Daqui em diante a base já perdeu dias de publicação. Não é inutilizável
#: -- a maioria dos CVEs de uma imagem é antiga --, mas quem está decidindo
#: um deploy precisa saber que a resposta tem essa idade.
STALE_AFTER = timedelta(hours=72)


class DatabaseState(StrEnum):
    FRESH = "FRESH"
    #: Entre um e três dias. Ainda mede, e já vale dizer a idade.
    AGING = "AGING"
    STALE = "STALE"
    #: Não foi possível ler a data. **Não** é o mesmo que fresca.
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class DatabaseFreshness:
    """O que se sabe sobre a idade da base de um scanner."""

    scanner: str
    state: DatabaseState
    #: Quando a base foi construída, quando se conseguiu ler.
    built_at: datetime | None = None
    #: Idade no momento da checagem.
    age: timedelta | None = None
    #: Por que não foi possível ler, quando não foi.
    detail: str = ""

    @property
    def is_usable_measurement(self) -> bool:
        """Se um scan feito agora mediria o que se publicou recentemente.

        `UNKNOWN` responde `False` de propósito: a pergunta é "dá para
        confiar na atualidade desta base", e "não sei" não é sim.
        """
        return self.state in (DatabaseState.FRESH, DatabaseState.AGING)

    def explain(self) -> str:
        """A frase que diz o que se sabe, sem arredondar para o lado bom."""
        match self.state:
            case DatabaseState.FRESH:
                return f"updated {_human(self.age)} ago"
            case DatabaseState.AGING:
                return (
                    f"updated {_human(self.age)} ago: still usable, and already missing "
                    "whatever was published since"
                )
            case DatabaseState.STALE:
                return (
                    f"updated {_human(self.age)} ago. A scan against it comes back clean "
                    "for anything published since, which reads exactly like a clean "
                    "image and is not one"
                )
            case DatabaseState.UNKNOWN:
                reason = self.detail or "no readable metadata"
                return (
                    f"age unknown ({reason}). This is not the same as up to date: "
                    "nothing here says how old the answers are"
                )

    def to_dict(self) -> dict[str, object]:
        return {
            "scanner": self.scanner,
            "state": str(self.state),
            "built_at": self.built_at.isoformat() if self.built_at else "",
            "age_hours": round(self.age.total_seconds() / 3600, 1) if self.age else None,
            "explanation": self.explain(),
        }


def classify(
    scanner: str,
    built_at: datetime | None,
    *,
    now: datetime | None = None,
    detail: str = "",
) -> DatabaseFreshness:
    """Classifica a idade de uma base a partir da data em que foi construída.

    Puro: recebe a data já lida, para que a regra se teste sem tocar disco.
    """
    if built_at is None:
        return DatabaseFreshness(scanner, DatabaseState.UNKNOWN, detail=detail)

    moment = now or datetime.now(tz=UTC)
    stamped = built_at if built_at.tzinfo is not None else built_at.replace(tzinfo=UTC)
    age = moment - stamped

    if age < timedelta(0):
        # Uma base "do futuro" é relógio errado numa das duas pontas, e
        # tratá-la como fresquíssima esconderia o problema.
        return DatabaseFreshness(
            scanner,
            DatabaseState.UNKNOWN,
            built_at=stamped,
            detail="the database is stamped in the future; check the clock",
        )
    if age <= FRESH_WITHIN:
        state = DatabaseState.FRESH
    elif age <= STALE_AFTER:
        state = DatabaseState.AGING
    else:
        state = DatabaseState.STALE
    return DatabaseFreshness(scanner, state, built_at=stamped, age=age)


def _human(age: timedelta | None) -> str:
    if age is None:
        return "an unknown time"
    hours = age.total_seconds() / 3600
    if hours < 1:
        return f"{int(age.total_seconds() // 60)} minutes"
    if hours < 48:
        return f"{hours:.0f} hours"
    return f"{hours / 24:.1f} days"
