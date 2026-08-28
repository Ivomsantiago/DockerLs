"""O que faz um build reprovar, dito como um valor e não como um `if`.

O portão olhava só severidade -- `critical`, `high`, `medium`, `low` --, e
isso era uma incoerência do projeto inteiro: a ferramenta consulta o
catálogo CISA KEV, o EPSS e o Exploit-DB, usa os três para pontuar
(`SecurityScore`) e para redigir o veredito, e então reprovava o build por
um rótulo que o vendor da distro escolheu.

O caso concreto que isso deixava passar: um CVE **sendo explorado hoje**,
classificado MEDIUM pelo vendor, atravessava um `--fail-on high` sem um
pio. E o caso inverso: um CRITICAL teórico, sem exploit publicado e com
EPSS de 0,0003, reprovava o build. A ferramenta sabia a diferença e não a
usava onde ela decide alguma coisa.

`kev` e `epss>=N` são medições, não heurísticas -- é por isso que cabem num
portão, e é por isso que este módulo é puro: a regra que reprova um build
tem de ser testável sem rede, sem scanner e sem Docker.

**O tristate no portão.** `kev_status` UNKNOWN significa "ninguém
consultou", e há duas formas erradas de tratá-lo aqui. Reprovar por ele
diria que a imagem tem CVE explorado, o que é inventar. Aprovar por ele
gastaria a ausência de medição como tranquilidade, que é exatamente o que
este projeto existe para não fazer -- e pior, desligaria um portão de
segurança em silêncio numa oscilação de rede.

A saída é a terceira: quem pediu `--fail-on kev` pediu que a exploração
fosse *conferida*. Não conseguir conferir reprova o **run**, com uma
mensagem que nomeia a causa como falta de medição e não como veredito
sobre a imagem. São coisas diferentes e a mensagem diz qual das duas é.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from dockerls.domain.value_objects.tristate import Tristate

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

#: Limiares de severidade, do mais severo para o mais brando. Cada um
#: reprova também tudo que for pior que ele.
SEVERITY_THRESHOLDS: tuple[str, ...] = ("critical", "high", "medium", "low")

#: `epss>=0.5`, `epss >= 0.5`, `epss>0.5`. O `>=` é o sentido pretendido; o
#: `>` é aceito porque alguém vai escrevê-lo e recusar seria pedantismo.
_EPSS = re.compile(r"^epss\s*>=?\s*(\d*\.?\d+)$", re.IGNORECASE)


class GateKind(StrEnum):
    """Sobre o que este portão pergunta."""

    SEVERITY = "SEVERITY"
    #: Listado no catálogo CISA KEV: exploração observada no mundo real.
    KEV = "KEV"
    #: Probabilidade EPSS de exploração nos próximos 30 dias.
    EPSS = "EPSS"


class GateOutcome(StrEnum):
    """O que o portão concluiu."""

    PASS = "PASS"  # noqa: S105 -- veredito de portão, não senha
    #: Achado que dispara o portão. É um veredito sobre a imagem.
    FAIL = "FAIL"
    #: O portão foi pedido e não pôde ser avaliado. **Não** é um veredito
    #: sobre a imagem: é a constatação de que a pergunta ficou sem resposta.
    UNMEASURED = "UNMEASURED"


class InvalidGateError(ValueError):
    """O valor de `--fail-on` não nomeia um portão que existe."""


@dataclass(frozen=True)
class Finding:
    """O mínimo que o portão precisa saber sobre um achado.

    Deliberadamente não é a `Vulnerability` do domínio: o `build` carrega
    seus achados como dicionários vindos do scanner, e obrigar uma
    conversão só para consultar quatro campos acoplaria o portão à forma de
    quem o chama.
    """

    cve_id: str
    severity: str
    kev: Tristate = Tristate.UNKNOWN
    #: Probabilidade EPSS, ou None quando ninguém consultou. `0.0` é uma
    #: resposta ("o FIRST pontuou em zero") e `None` é a falta dela.
    epss: float | None = None
    package: str = ""
    fixed_version: str = ""

    @property
    def severity_rank(self) -> int:
        """Posição na escala, ou -1 para uma severidade fora dela."""
        try:
            return SEVERITY_THRESHOLDS.index(self.severity.strip().lower())
        except ValueError:
            return -1


@dataclass(frozen=True)
class GateVerdict:
    """O que o portão decidiu, e por quê."""

    outcome: GateOutcome
    kind: GateKind
    #: Os achados que dispararam, na ordem em que serão mostrados.
    offenders: tuple[Finding, ...] = ()
    #: Frase para o humano. Nomeia a causa, nunca só "reprovou".
    reason: str = ""

    @property
    def failed(self) -> bool:
        """Se o build não deve prosseguir.

        `UNMEASURED` conta: quem pediu o portão pediu que a pergunta fosse
        respondida, e ela não foi.
        """
        return self.outcome is not GateOutcome.PASS


@dataclass(frozen=True)
class Gate:
    """Um `--fail-on` já interpretado."""

    kind: GateKind
    #: Para SEVERITY, o limiar (`"high"`). Para EPSS, o piso (`0.5`).
    severity: str = ""
    epss_floor: float = 0.0
    #: O texto original, para a mensagem citar o que o usuário escreveu.
    raw: str = ""

    @classmethod
    def parse(cls, value: str) -> Gate:
        """Interpreta o valor de `--fail-on`, ou recusa nomeando as opções.

        Recusar aqui é o ponto: um limiar desconhecido caindo num
        `return False` seria um portão que nunca reprova, em silêncio -- e
        esse bug já existiu neste arquivo com `--fail-on medium`.
        """
        text = value.strip().lower()
        if not text:
            raise InvalidGateError("no gate was named")

        if text in SEVERITY_THRESHOLDS:
            return cls(kind=GateKind.SEVERITY, severity=text, raw=text)
        if text == "kev":
            return cls(kind=GateKind.KEV, raw=text)

        match = _EPSS.match(text)
        if match is not None:
            floor = float(match.group(1))
            if not 0.0 <= floor <= 1.0:
                raise InvalidGateError(
                    f"EPSS is a probability between 0 and 1; {floor} is outside it"
                )
            return cls(kind=GateKind.EPSS, epss_floor=floor, raw=text)

        raise InvalidGateError(
            f"unknown --fail-on gate {value!r}; expected one of "
            f"{', '.join(SEVERITY_THRESHOLDS)}, kev, or epss>=N (e.g. epss>=0.5)"
        )

    def evaluate(
        self, findings: Sequence[Finding], counts: Mapping[str, int] | None = None
    ) -> GateVerdict:
        """Decide, e diz por quê.

        `counts` é a contagem por severidade do scan **completo**. Ela
        existe porque `findings` costuma ser uma amostra: o relatório retém
        um número limitado de achados, e deixar o portão contar a amostra
        faria o número que reprova ser menor que o número que existe. O que
        reprova e o que se lê têm de ser o mesmo número.
        """
        match self.kind:
            case GateKind.SEVERITY:
                return self._severity(findings, counts)
            case GateKind.KEV:
                return self._kev(findings)
            case GateKind.EPSS:
                return self._epss(findings)

    def _severity(
        self, findings: Sequence[Finding], counts: Mapping[str, int] | None
    ) -> GateVerdict:
        cutoff = SEVERITY_THRESHOLDS.index(self.severity)
        levels = SEVERITY_THRESHOLDS[: cutoff + 1]
        offenders = tuple(f for f in findings if 0 <= f.severity_rank <= cutoff)
        total = (
            sum(counts.get(level, 0) for level in levels) if counts is not None else len(offenders)
        )
        if total == 0:
            return GateVerdict(GateOutcome.PASS, self.kind)
        return GateVerdict(
            GateOutcome.FAIL,
            self.kind,
            offenders,
            f"{total} finding(s) at or above {self.severity.upper()}",
        )

    def _kev(self, findings: Sequence[Finding]) -> GateVerdict:
        listed = tuple(f for f in findings if f.kev is Tristate.TRUE)
        if listed:
            return GateVerdict(
                GateOutcome.FAIL,
                self.kind,
                listed,
                f"{len(listed)} finding(s) are in the CISA KEV catalogue, which means "
                "exploitation observed in the wild",
            )
        # Nada listado. Resta saber se a pergunta chegou a ser feita.
        if findings and all(f.kev is Tristate.UNKNOWN for f in findings):
            return GateVerdict(
                GateOutcome.UNMEASURED,
                self.kind,
                (),
                "the KEV gate was requested and the catalogue was never consulted, so "
                "nothing here was checked against it. This is an absent measurement, "
                "not a finding: the image may or may not carry an exploited CVE, and "
                "this run cannot say which",
            )
        return GateVerdict(GateOutcome.PASS, self.kind)

    def _epss(self, findings: Sequence[Finding]) -> GateVerdict:
        scored = tuple(f for f in findings if f.epss is not None)
        over = tuple(f for f in scored if f.epss is not None and f.epss >= self.epss_floor)
        if over:
            worst = max(f.epss or 0.0 for f in over)
            return GateVerdict(
                GateOutcome.FAIL,
                self.kind,
                over,
                f"{len(over)} finding(s) at or above an EPSS of {self.epss_floor:g} "
                f"(worst: {worst:.3f}), the probability of exploitation in the next "
                "30 days",
            )
        if findings and not scored:
            return GateVerdict(
                GateOutcome.UNMEASURED,
                self.kind,
                (),
                f"the EPSS gate was requested and no finding carries a score, so "
                f"nothing here was compared against {self.epss_floor:g}. This is an "
                "absent measurement, not a finding",
            )
        return GateVerdict(GateOutcome.PASS, self.kind)


@dataclass(frozen=True)
class GateSet:
    """Vários portões, todos obrigatórios.

    Existe porque "mais estrito" deixou de ser uma comparação possível.
    Entre `high` e `critical` dá para dizer qual reprova mais; entre
    `critical` e `kev` não dá -- são perguntas diferentes sobre coisas
    diferentes, e escolher uma seria descartar a outra em silêncio.

    Quando a política do repositório pede um portão e a linha de comando
    pede outro, os dois valem. É a única regra que não afrouxa nenhum dos
    dois lados.
    """

    gates: tuple[Gate, ...]

    @classmethod
    def parse(cls, value: str) -> GateSet:
        """Interpreta `"critical"`, `"kev"` ou `"critical,kev,epss>=0.5"`."""
        parts = [piece.strip() for piece in value.split(",") if piece.strip()]
        if not parts:
            raise InvalidGateError("no gate was named")
        return cls(tuple(Gate.parse(part) for part in parts))

    @property
    def raw(self) -> str:
        return ",".join(gate.raw for gate in self.gates)

    def evaluate(
        self, findings: Sequence[Finding], counts: Mapping[str, int] | None = None
    ) -> tuple[GateVerdict, ...]:
        """Os vereditos que **não** passaram, na ordem declarada.

        Vazio significa aprovado. Devolver só as falhas é deliberado: o
        chamador precisa listar o que reprovou, e um veredito PASS na
        mensagem seria ruído no log do CI.
        """
        return tuple(
            verdict
            for verdict in (gate.evaluate(findings, counts) for gate in self.gates)
            if verdict.failed
        )


def merge_gates(declared: str, requested: str) -> str:
    """O portão que vale, entre a política do repositório e a linha de comando.

    Severidade contra severidade continua sendo a regra antiga: vence a
    **mais baixa na escala**, porque `--fail-on low` reprova em LOW e em
    tudo acima enquanto `critical` só olha CRITICAL. Nem o arquivo desliga
    o que o pipeline pediu, nem a flag afrouxa o que a organização exige.

    Portões de tipos diferentes não competem: somam. Um `.dockerls-policy.yaml`
    que exige `kev` e um `--fail-on high` na linha de comando produzem os
    dois, porque descartar qualquer um seria afrouxar sem dizer.
    """
    sides = [value.strip() for value in (declared, requested) if value.strip()]
    if not sides:
        return ""
    if len(sides) == 1:
        return sides[0]

    kept: list[str] = []
    severities: list[str] = []
    for side in sides:
        for gate in GateSet.parse(side).gates:
            if gate.kind is GateKind.SEVERITY:
                severities.append(gate.severity)
            elif gate.raw not in kept:
                kept.append(gate.raw)
    if severities:
        strictest = max(severities, key=SEVERITY_THRESHOLDS.index)
        kept.insert(0, strictest)
    return ",".join(kept)
