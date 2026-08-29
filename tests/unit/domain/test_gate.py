"""Guard: o portão olha o que a ferramenta mede, e nunca inventa.

O portão só sabia severidade, e isso era uma incoerência: o projeto
consulta CISA KEV, EPSS e Exploit-DB, pontua com os três, e então reprovava
o build por um rótulo que o vendor da distro escolheu.

O que estes testes fixam, em ordem de importância:

1. um CVE **sendo explorado hoje** reprova mesmo quando o vendor o chamou
   de MEDIUM -- é o caso que o portão antigo deixava passar;
2. um portão pedido e não avaliado **não passa em silêncio**. Aprovar por
   ausência de consulta gastaria falta de medição como tranquilidade, e
   desligaria um portão de segurança numa oscilação de rede;
3. um portão que não pôde ser avaliado também **não acusa a imagem**: a
   mensagem diz "não medido", não "explorado".
"""

from __future__ import annotations

import pytest

from dockerls.domain.value_objects.gate import (
    Finding,
    Gate,
    GateKind,
    GateOutcome,
    GateSet,
    InvalidGateError,
    merge_gates,
)
from dockerls.domain.value_objects.tristate import Tristate


class TestParsing:
    @pytest.mark.parametrize("value", ["critical", "HIGH", " medium ", "low"])
    def test_severities_are_understood(self, value: str):
        assert Gate.parse(value).kind is GateKind.SEVERITY

    def test_kev_is_understood(self):
        assert Gate.parse("kev").kind is GateKind.KEV

    @pytest.mark.parametrize(
        ("value", "floor"),
        [("epss>=0.5", 0.5), ("epss >= 0.1", 0.1), ("EPSS>0.944", 0.944), ("epss>=1", 1.0)],
    )
    def test_epss_is_understood_with_its_floor(self, value: str, floor: float):
        gate = Gate.parse(value)
        assert gate.kind is GateKind.EPSS
        assert gate.epss_floor == pytest.approx(floor)

    def test_an_epss_outside_zero_to_one_is_refused(self):
        """EPSS é uma probabilidade. `epss>=50` quase certamente quis dizer
        50%, e aceitá-lo produziria um portão que nunca reprova."""
        with pytest.raises(InvalidGateError, match="probability"):
            Gate.parse("epss>=50")

    def test_an_unknown_gate_is_refused_naming_the_options(self):
        """Um valor desconhecido caindo num `return False` seria um portão
        que nunca reprova, em silêncio -- e esse bug já existiu."""
        with pytest.raises(InvalidGateError, match="kev"):
            Gate.parse("exploitable")

    def test_an_empty_gate_is_refused(self):
        with pytest.raises(InvalidGateError):
            Gate.parse("   ")


class TestTheCaseTheOldGateMissed:
    def test_an_exploited_medium_fails_the_kev_gate(self):
        """O caso concreto: CVE explorado no mundo real, classificado MEDIUM
        pelo vendor da distro. `--fail-on high` deixava passar."""
        findings = [Finding("CVE-2024-1", "MEDIUM", kev=Tristate.TRUE)]

        assert Gate.parse("kev").evaluate(findings).outcome is GateOutcome.FAIL
        assert Gate.parse("high").evaluate(findings).outcome is GateOutcome.PASS

    def test_a_theoretical_critical_does_not_fail_the_kev_gate(self):
        """O inverso, e ele importa igual: CRITICAL sem exploração observada
        não reprova um portão que pergunta sobre exploração."""
        findings = [Finding("CVE-2024-2", "CRITICAL", kev=Tristate.FALSE)]

        assert Gate.parse("kev").evaluate(findings).outcome is GateOutcome.PASS
        assert Gate.parse("critical").evaluate(findings).outcome is GateOutcome.FAIL

    def test_the_reason_says_what_kev_means(self):
        findings = [Finding("CVE-2024-1", "LOW", kev=Tristate.TRUE)]
        reason = Gate.parse("kev").evaluate(findings).reason
        assert "exploitation observed in the wild" in reason


class TestAbsenceIsNeverApproval:
    def test_a_kev_gate_with_nothing_consulted_does_not_pass(self):
        """Quem pediu `--fail-on kev` pediu que a exploração fosse
        conferida. Não conseguir conferir deixa a pergunta sem resposta, e
        aprovar aí desligaria o portão em silêncio."""
        findings = [Finding("CVE-1", "HIGH"), Finding("CVE-2", "CRITICAL")]

        verdict = Gate.parse("kev").evaluate(findings)

        assert verdict.outcome is GateOutcome.UNMEASURED
        assert verdict.failed is True

    def test_an_unmeasured_verdict_does_not_accuse_the_image(self):
        """A distinção que impede o log do CI de culpar uma imagem por uma
        falha de rede."""
        verdict = Gate.parse("kev").evaluate([Finding("CVE-1", "HIGH")])

        assert "absent measurement" in verdict.reason
        assert "not a finding" in verdict.reason
        assert verdict.offenders == ()

    def test_an_epss_gate_with_no_score_anywhere_does_not_pass(self):
        verdict = Gate.parse("epss>=0.5").evaluate([Finding("CVE-1", "HIGH")])

        assert verdict.outcome is GateOutcome.UNMEASURED

    def test_a_partial_answer_is_an_answer(self):
        """Um CVE respondido e outro não é uma consulta que aconteceu. O
        portão julga o que foi medido, sem exigir que tudo tenha sido."""
        findings = [
            Finding("CVE-1", "HIGH", kev=Tristate.FALSE),
            Finding("CVE-2", "HIGH"),
        ]

        assert Gate.parse("kev").evaluate(findings).outcome is GateOutcome.PASS

    def test_no_findings_at_all_is_not_unmeasured(self):
        """Uma imagem sem achado nenhum não tem o que consultar, e isso não
        é falta de medição -- é ausência de vulnerabilidade."""
        assert Gate.parse("kev").evaluate([]).outcome is GateOutcome.PASS
        assert Gate.parse("epss>=0.5").evaluate([]).outcome is GateOutcome.PASS


class TestEPSS:
    def test_a_score_at_or_above_the_floor_fails(self):
        findings = [Finding("CVE-1", "LOW", epss=0.5)]
        assert Gate.parse("epss>=0.5").evaluate(findings).outcome is GateOutcome.FAIL

    def test_a_score_below_the_floor_passes(self):
        findings = [Finding("CVE-1", "CRITICAL", epss=0.4999)]
        assert Gate.parse("epss>=0.5").evaluate(findings).outcome is GateOutcome.PASS

    def test_a_zero_score_is_an_answer_and_not_an_absence(self):
        """`0.0` é o FIRST pontuando em zero; `None` é ninguém tendo
        perguntado. Colapsar os dois faria uma consulta ausente parecer uma
        probabilidade baixa."""
        verdict = Gate.parse("epss>=0.5").evaluate([Finding("CVE-1", "HIGH", epss=0.0)])

        assert verdict.outcome is GateOutcome.PASS

    def test_the_reason_carries_the_worst_score(self):
        findings = [Finding("CVE-1", "LOW", epss=0.6), Finding("CVE-2", "LOW", epss=0.97)]
        reason = Gate.parse("epss>=0.5").evaluate(findings).reason
        assert "0.970" in reason


class TestSeverityKeepsItsOldSemantics:
    def test_a_lower_threshold_also_catches_the_severer(self):
        findings = [Finding("CVE-1", "CRITICAL")]
        assert Gate.parse("low").evaluate(findings).outcome is GateOutcome.FAIL

    def test_the_count_comes_from_the_scan_not_the_sample(self):
        """O relatório retém uma amostra. Deixar o portão contar a amostra
        faria o número que reprova ser menor que o número que existe."""
        verdict = Gate.parse("critical").evaluate(
            [Finding("CVE-1", "CRITICAL")], counts={"critical": 47}
        )

        assert "47 finding(s)" in verdict.reason

    def test_a_severity_outside_the_scale_never_trips_a_gate(self):
        """`UNKNOWN` é severidade válida numa contagem e não é limiar: o
        portão não sabe onde colocá-la, e chutar seria inventar."""
        assert Gate.parse("low").evaluate([Finding("CVE-1", "UNKNOWN")]).outcome is GateOutcome.PASS


class TestGateSet:
    def test_all_gates_must_pass(self):
        findings = [Finding("CVE-1", "CRITICAL", kev=Tristate.FALSE)]
        failures = GateSet.parse("critical,kev").evaluate(findings)

        assert len(failures) == 1
        assert failures[0].kind is GateKind.SEVERITY

    def test_an_empty_result_means_approved(self):
        findings = [Finding("CVE-1", "LOW", kev=Tristate.FALSE)]
        assert GateSet.parse("critical,kev").evaluate(findings) == ()

    def test_every_failing_gate_is_reported_not_just_the_first(self):
        """Quem lê o log do CI precisa consertar tudo, não descobrir um
        problema por build."""
        findings = [Finding("CVE-1", "CRITICAL", kev=Tristate.TRUE, epss=0.9)]
        failures = GateSet.parse("critical,kev,epss>=0.5").evaluate(findings)

        assert {f.kind for f in failures} == {GateKind.SEVERITY, GateKind.KEV, GateKind.EPSS}


class TestMergingPolicyAndCommandLine:
    def test_severity_against_severity_keeps_the_stricter(self):
        assert merge_gates("high", "critical") == "high"
        assert merge_gates("critical", "low") == "low"

    def test_different_kinds_are_added_not_chosen(self):
        """Entre `critical` e `kev` não dá para dizer qual é mais estrito --
        são perguntas diferentes --, e escolher uma descartaria a outra."""
        assert merge_gates("kev", "high") == "high,kev"

    def test_one_side_alone_is_kept_verbatim(self):
        assert merge_gates("", "kev") == "kev"
        assert merge_gates("epss>=0.2", "") == "epss>=0.2"

    def test_neither_side_invents_a_gate(self):
        assert merge_gates("", "") == ""

    def test_the_same_gate_on_both_sides_is_not_duplicated(self):
        assert merge_gates("kev", "kev") == "kev"
