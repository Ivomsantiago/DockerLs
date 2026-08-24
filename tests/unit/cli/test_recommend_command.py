from __future__ import annotations

from unittest.mock import AsyncMock, patch

from typer.testing import CliRunner

from dockerls.application.dto.analysis import AnalysisResult, ImageAnalysis
from dockerls.cli.app import app
from dockerls.domain.entities.image import DockerImage
from dockerls.domain.entities.scan_result import ScanResult
from dockerls.domain.entities.vulnerability import Severity, Vulnerability

runner = CliRunner()


def _analysis(critical=0, high=0) -> ImageAnalysis:
    vulns = []
    if critical:
        vulns += [
            Vulnerability(cve_id=f"C{i}", severity=Severity.CRITICAL) for i in range(critical)
        ]
    if high:
        vulns += [Vulnerability(cve_id=f"H{i}", severity=Severity.HIGH) for i in range(high)]
    scan = ScanResult(image_reference="node:22-alpine", vulnerabilities=vulns)
    return ImageAnalysis(
        image=DockerImage(name="node", tag="22-alpine"),
        scan=scan,
        security_score=90.0,
        tier="A",
        remediation_score=100,
    )


def _mock_use_case(result: AnalysisResult):
    uc = AsyncMock()
    uc.execute = AsyncMock(return_value=result)
    return AsyncMock(return_value=uc)


class TestRecommendExitCodes:
    def test_baseline_met_exits_zero(self):
        result = AnalysisResult(
            query="node",
            total_tags_scanned=1,
            baseline_met=True,
            recommendations=[_analysis()],
        )
        with patch(
            "dockerls.cli.commands.recommend.build_recommend_use_case",
            _mock_use_case(result),
        ):
            r = runner.invoke(app, ["recommend", "node"])
        assert r.exit_code == 0

    def test_alternatives_only_exits_two(self):
        result = AnalysisResult(
            query="node",
            total_tags_scanned=1,
            baseline_met=False,
            alternatives=[_analysis(high=1)],
        )
        with patch(
            "dockerls.cli.commands.recommend.build_recommend_use_case",
            _mock_use_case(result),
        ):
            r = runner.invoke(app, ["recommend", "node"])
        assert r.exit_code == 2

    def test_nothing_found_exits_three(self):
        result = AnalysisResult(
            query="node",
            total_tags_scanned=1,
            baseline_met=False,
        )
        with patch(
            "dockerls.cli.commands.recommend.build_recommend_use_case",
            _mock_use_case(result),
        ):
            r = runner.invoke(app, ["recommend", "node"])
        assert r.exit_code == 3

    def test_no_tags_found_exits_one(self):
        result = AnalysisResult(
            query="node",
            total_tags_scanned=0,
            baseline_met=False,
            errors=["No tags found for image"],
        )
        with patch(
            "dockerls.cli.commands.recommend.build_recommend_use_case",
            _mock_use_case(result),
        ):
            r = runner.invoke(app, ["recommend", "node"])
        assert r.exit_code == 1

    def test_rejects_an_image_tag_with_a_clear_message(self):
        """`node:18` used to be searched as a literal repository name."""
        with patch(
            "dockerls.cli.commands.recommend.build_recommend_use_case",
            _mock_use_case(
                AnalysisResult(query="node:18", total_tags_scanned=0, baseline_met=False)
            ),
        ) as build:
            r = runner.invoke(app, ["recommend", "node:18"])
        collapsed = " ".join(r.stdout.split())
        assert r.exit_code == 1
        assert "dockerls recommend node" in collapsed
        assert "dockerls analyze node:18" in collapsed
        build.assert_not_called()

    def test_bare_name_still_works(self):
        result = AnalysisResult(
            query="node",
            total_tags_scanned=1,
            baseline_met=True,
            recommendations=[_analysis()],
        )
        with patch(
            "dockerls.cli.commands.recommend.build_recommend_use_case",
            _mock_use_case(result),
        ):
            r = runner.invoke(app, ["recommend", "node"])
        assert r.exit_code == 0

    def test_private_registry_with_port_still_works(self):
        result = AnalysisResult(
            query="registry.internal:5000/app",
            total_tags_scanned=1,
            baseline_met=True,
            recommendations=[_analysis()],
        )
        with patch(
            "dockerls.cli.commands.recommend.build_recommend_use_case",
            _mock_use_case(result),
        ) as build:
            r = runner.invoke(app, ["recommend", "registry.internal:5000/app"])
        assert r.exit_code == 0
        build.assert_called_once()

    def test_fail_on_critical_forces_error_exit(self):
        result = AnalysisResult(
            query="node",
            total_tags_scanned=1,
            baseline_met=False,
            alternatives=[_analysis(critical=1)],
        )
        with patch(
            "dockerls.cli.commands.recommend.build_recommend_use_case",
            _mock_use_case(result),
        ):
            r = runner.invoke(app, ["recommend", "node", "--fail-on", "critical"])
        assert r.exit_code == 1

    def test_json_format_outputs_valid_json(self):
        import json

        result = AnalysisResult(
            query="node",
            total_tags_scanned=1,
            baseline_met=True,
            recommendations=[_analysis()],
        )
        with patch(
            "dockerls.cli.commands.recommend.build_recommend_use_case",
            _mock_use_case(result),
        ):
            r = runner.invoke(app, ["recommend", "node", "--format", "json"])
        assert r.exit_code == 0
        parsed = json.loads(r.stdout)
        assert parsed["baseline_met"] is True
