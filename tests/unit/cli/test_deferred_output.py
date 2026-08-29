"""Guard: uma tabela limpa não pode esconder o que não foi medido.

O orçamento de scans corta 75 medições num `recommend node`. Isso só é
defensável porque o corte é *dito*: quantas tags ficaram de fora, por quê,
e como pedir a varredura completa. Sem essa saída, o corte vira a coisa que
este projeto inteiro existe para não fazer -- apresentar ausência de
medição como se fosse resultado.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

from typer.testing import CliRunner

from dockerls.application.dto.analysis import AnalysisResult, ImageAnalysis
from dockerls.cli.app import app
from dockerls.domain.entities.image import DockerImage
from dockerls.domain.entities.scan_result import ScanResult, ScanStatus
from dockerls.domain.value_objects.scan_plan import DeferralReason, DeferredTag

runner = CliRunner()


def _analysis(tag: str) -> ImageAnalysis:
    return ImageAnalysis(
        image=DockerImage(name="node", tag=tag, is_official=True),
        scan=ScanResult(
            image_reference=f"node:{tag}",
            status=ScanStatus.OK,
            scan_timestamp="2026-01-01T00:00:00+00:00",
        ),
        security_score=95.0,
        tier="A",
        remediation_score=100.0,
    )


def _result(deferred_count: int = 3) -> AnalysisResult:
    return AnalysisResult(
        query="node",
        total_tags_scanned=25,
        total_tags_analyzed=25,
        tags_discovered=25 + deferred_count,
        baseline_met=True,
        recommendations=[_analysis("22-alpine")],
        deferred=[
            DeferredTag(
                reference=f"node:22.{i}-alpine",
                reason=DeferralReason.SUPERSEDED,
                detail="a newer tag of the same line was measured instead (22.19-alpine)",
            )
            for i in range(deferred_count)
        ],
    )


def _run(result: AnalysisResult, *args: str):
    use_case = AsyncMock()
    use_case.execute = AsyncMock(return_value=result)
    use_case.close = AsyncMock()
    with patch(
        "dockerls.cli.commands.recommend.build_recommend_use_case",
        AsyncMock(return_value=use_case),
    ):
        return runner.invoke(app, ["recommend", "node", "--no-progress", *args])


class TestTheTableCannotHideTheCut:
    def test_the_summary_line_names_what_was_not_measured(self):
        output = _run(_result()).output
        assert "3 not measured" in output

    def test_a_block_explains_each_deferral(self):
        output = _run(_result()).output
        assert "Not Measured" in output
        assert "SUPERSEDED" in output
        assert "node:22.0-alpine" in output

    def test_the_block_says_nothing_is_being_claimed_about_them(self):
        """A frase importa: `deferred` é ausência de medição, e ausência de
        medição nunca é gasta como tranquilidade nem como acusação."""
        output = _run(_result()).output
        assert "nothing here is being claimed" in output

    def test_the_block_says_how_to_undo_the_cut(self):
        output = _run(_result()).output
        assert "--budget 0" in output

    def test_a_run_that_measured_everything_prints_no_block(self):
        result = _result(deferred_count=0)
        output = _run(result).output
        assert "Not Measured" not in output
        assert "not measured" not in output

    def test_long_lists_are_truncated_with_a_pointer_to_the_json(self):
        output = _run(_result(deferred_count=40)).output
        assert "and 30 more" in output
        assert "--format json" in output


class TestTheJSONCarriesEverything:
    def test_every_deferred_tag_is_in_the_document(self):
        """O terminal corta em dez; o documento que uma auditoria lê não
        pode cortar em lugar nenhum."""
        output = _run(_result(deferred_count=40), "--format", "json").output
        payload = json.loads(output)

        assert len(payload["deferred"]) == 40
        assert payload["tags_discovered"] == 65
        first = payload["deferred"][0]
        assert first["reference"] == "node:22.0-alpine"
        assert first["reason"] == "SUPERSEDED"
        assert first["detail"]


class TestTheBudgetFlag:
    def test_a_negative_budget_is_refused(self):
        result = _run(_result(), "--budget", "-5")
        assert result.exit_code != 0

    def test_zero_is_accepted_because_it_means_measure_everything(self):
        # `check_limit` recusa zero; o orçamento não pode passar por ele,
        # ou a única forma de pedir a varredura completa seria recusada.
        result = _run(_result(deferred_count=0), "--budget", "0")
        assert result.exit_code == 0
