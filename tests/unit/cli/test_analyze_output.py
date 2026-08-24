"""`analyze` como portão de CI: formatos estruturados e exit codes.

Sem saída legível por máquina e sem código de saída significativo, a análise
de uma imagem não pluga em pipeline nenhum -- ela só existia como tabela para
leitura humana.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from dockerls.application.dto.analysis import ImageAnalysis
from dockerls.cli.app import app
from dockerls.domain.entities.image import DockerImage
from dockerls.domain.entities.scan_result import ScanErrorKind, ScanResult, ScanStatus
from dockerls.domain.entities.vulnerability import Severity, Vulnerability
from dockerls.exit_codes import EXIT_ERROR, EXIT_OK, EXIT_POLICY

runner = CliRunner()


def _analysis(critical=0, high=0, medium=0, verified=True) -> ImageAnalysis:
    vulns = [
        Vulnerability(cve_id=f"CVE-C{i}", severity=Severity.CRITICAL, package_name="tar")
        for i in range(critical)
    ]
    vulns += [
        Vulnerability(cve_id=f"CVE-H{i}", severity=Severity.HIGH, package_name="openssl")
        for i in range(high)
    ]
    vulns += [
        Vulnerability(cve_id=f"CVE-M{i}", severity=Severity.MEDIUM, package_name="zlib")
        for i in range(medium)
    ]
    scan = ScanResult(
        image_reference="node:22-alpine",
        vulnerabilities=vulns,
        scan_timestamp="2026-01-01T00:00:00+00:00" if verified else "",
        status=ScanStatus.OK if verified else ScanStatus.ERROR,
        error_kind=ScanErrorKind.NONE if verified else ScanErrorKind.DB_INIT_FAILED,
        error_message="" if verified else "init error: DB error",
    )
    return ImageAnalysis(
        image=DockerImage(name="node", tag="22-alpine"),
        scan=scan,
        security_score=80.0,
        tier="B",
        remediation_score=100,
    )


def _run(analysis, *args):
    use_case = AsyncMock()
    use_case.execute = AsyncMock(return_value=analysis)
    with patch(
        "dockerls.cli.commands.analyze.build_analyze_use_case", AsyncMock(return_value=use_case)
    ):
        return runner.invoke(app, ["analyze", "node:22-alpine", *args])


class TestStructuredOutput:
    def test_json_is_parseable(self):
        result = _run(_analysis(high=2), "--format", "json")

        assert result.exit_code == EXIT_OK
        payload = json.loads(result.stdout)
        assert payload["query"] == "node:22-alpine"
        assert payload["recommendations"][0]["scan"]["vulnerabilities"]

    def test_sarif_carries_the_findings(self):
        result = _run(_analysis(high=1), "--format", "sarif")

        assert result.exit_code == EXIT_OK
        sarif = json.loads(result.stdout)
        assert sarif["version"] == "2.1.0"
        assert sarif["runs"][0]["tool"]["driver"]["name"] == "DockerLs"
        assert sarif["runs"][0]["results"][0]["ruleId"] == "CVE-H0"

    def test_unknown_format_is_rejected_before_scanning(self):
        result = _run(_analysis(), "--format", "yaml")

        assert result.exit_code == EXIT_ERROR
        assert "--format" in result.stdout

    def test_output_file_is_written(self, tmp_path):
        out = tmp_path / "nested" / "report.json"
        result = _run(_analysis(high=1), "--format", "json", "-o", str(out))

        assert result.exit_code == EXIT_OK
        assert json.loads(out.read_text())["query"] == "node:22-alpine"

    def test_unwritable_output_is_a_message(self, tmp_path):
        blocked = tmp_path / "afile"
        blocked.write_text("x")
        result = _run(_analysis(), "--format", "json", "-o", str(blocked / "n" / "r.json"))

        assert result.exit_code == EXIT_ERROR
        assert "Could not write" in result.stdout


class TestFailOnGate:
    """Mesma semântica de `build --fail-on`: cada nível reprova também tudo
    que for mais severo que ele."""

    def test_clean_image_passes(self):
        assert _run(_analysis(), "--fail-on", "critical").exit_code == EXIT_OK

    def test_critical_trips_the_critical_gate(self):
        assert _run(_analysis(critical=1), "--fail-on", "critical").exit_code == EXIT_POLICY

    def test_high_does_not_trip_the_critical_gate(self):
        assert _run(_analysis(high=9), "--fail-on", "critical").exit_code == EXIT_OK

    def test_critical_also_trips_the_high_gate(self):
        assert _run(_analysis(critical=1), "--fail-on", "high").exit_code == EXIT_POLICY

    def test_medium_gate_catches_everything_above_it(self):
        assert _run(_analysis(medium=1), "--fail-on", "medium").exit_code == EXIT_POLICY
        assert _run(_analysis(high=1), "--fail-on", "medium").exit_code == EXIT_POLICY

    def test_no_gate_means_exit_zero_even_with_criticals(self):
        assert _run(_analysis(critical=5)).exit_code == EXIT_OK

    def test_the_gate_names_the_cves_that_tripped_it(self):
        """Um portão que só diz "reprovou" obriga a reabrir o relatório."""
        result = _run(_analysis(critical=2), "--fail-on", "critical")

        assert "Gate failed" in result.stdout
        assert "CVE-C0" in result.stdout
        assert "CVE-C1" in result.stdout

    def test_invalid_threshold_is_rejected_up_front(self):
        result = _run(_analysis(), "--fail-on", "sevre")

        assert result.exit_code == EXIT_ERROR
        assert "--fail-on" in result.stdout

    def test_the_gate_works_in_json_mode_too(self):
        result = _run(_analysis(critical=1), "--format", "json", "--fail-on", "critical")

        assert result.exit_code == EXIT_POLICY


class TestUnverifiedScanNeverPasses:
    @pytest.mark.parametrize("args", [(), ("--fail-on", "critical"), ("--format", "json")])
    def test_a_failed_scan_exits_with_the_execution_code(self, args):
        """Sair 0 aqui deixaria um portão de CI passar uma imagem que
        ninguém mediu."""
        result = _run(_analysis(verified=False), *args)

        assert result.exit_code == EXIT_ERROR

    def test_it_names_the_classified_cause(self):
        result = _run(_analysis(verified=False))

        assert "DB_INIT_FAILED" in result.stdout


class TestNonexistentTagShowsAClassifiedMessage:
    """End-to-end through the real `AnalyzeImageUseCase`: a scan that fails
    with Trivy's actual "image not found" stderr must never reach the CLI as
    a raw `SecurityScore` ValueError (which used to happen because
    `execute()` unconditionally scored every scan, verified or not).
    """

    def test_a_real_not_found_scan_is_reported_by_kind_not_as_a_raw_crash(self):
        from dockerls.application.use_cases.analyze_image import AnalyzeImageUseCase
        from dockerls.domain.entities.scan_result import ScanResult
        from dockerls.integrations.scan_errors import classify_scanner_error

        raw_stderr = (
            "FATAL image scan error: unable to find the specified image "
            '"node:does-not-exist": unable to find the specified image'
        )
        kind = classify_scanner_error(raw_stderr)

        class _NotFoundScanner:
            async def scan(self, image_reference):
                return ScanResult(
                    image_reference=image_reference,
                    status=ScanStatus.ERROR,
                    error_message=raw_stderr,
                    error_kind=kind,
                )

            async def is_available(self):
                return True

        class _EmptyRepo:
            async def search_tags(self, image_name, limit=100):
                return []

            async def get_image_metadata(self, image_name, tag):
                return None

        class _NoEOL:
            async def is_eol(self, product, version):
                return False

            async def is_lts(self, product, version):
                return False

        use_case = AnalyzeImageUseCase(
            repository=_EmptyRepo(), scanner=_NotFoundScanner(), eol_checker=_NoEOL()
        )
        with patch(
            "dockerls.cli.commands.analyze.build_analyze_use_case",
            AsyncMock(return_value=use_case),
        ):
            result = runner.invoke(app, ["analyze", "node:does-not-exist"])

        assert result.exit_code == EXIT_ERROR
        assert "NOT_FOUND" in result.stdout
        assert "Traceback" not in result.stdout
        assert "Cannot score" not in result.stdout


class TestFixEmitsADockerfilePatch:
    """`--fix` transforma o scanner em motor de remediação: a saída é
    aplicável, não descritiva."""

    def _npm_analysis(self):
        analysis = _analysis(high=2)
        for v in analysis.scan.vulnerabilities:
            v.package_type = "lang-pkgs"
            v.target = "/usr/local/lib/node_modules/npm/node_modules/package-lock.json"
            v.fixed_version = "9.9.9"
        return analysis

    def test_it_prints_a_dockerfile(self):
        result = _run(self._npm_analysis(), "--fix")

        assert result.exit_code == EXIT_OK
        assert "FROM node:22-alpine" in result.stdout
        assert "RUN npm install -g npm@latest" in result.stdout

    def test_it_writes_to_a_file(self, tmp_path):
        out = tmp_path / "Dockerfile.hardened"
        result = _run(self._npm_analysis(), "--fix", "-o", str(out))

        assert result.exit_code == EXIT_OK
        assert "FROM node:22-alpine" in out.read_text()
        assert "patch written to" in result.stdout

    def test_writing_reports_how_much_it_covers(self, tmp_path):
        out = tmp_path / "Dockerfile.hardened"
        result = _run(self._npm_analysis(), "--fix", "-o", str(out))

        assert "addressing 2 finding(s)" in result.stdout

    def test_an_unwritable_target_is_a_message(self, tmp_path):
        blocked = tmp_path / "afile"
        blocked.write_text("x")
        result = _run(self._npm_analysis(), "--fix", "-o", str(blocked / "n" / "D"))

        assert result.exit_code == EXIT_ERROR
        assert "Could not write" in result.stdout

    def test_it_cannot_be_combined_with_a_report_format(self):
        """`--fix` produz um Dockerfile e `--format json` um relatório; um
        `--output` só recebe um dos dois, e adivinhar seria pior que recusar."""
        result = _run(self._npm_analysis(), "--fix", "--format", "json")

        assert result.exit_code == EXIT_ERROR
        assert "--fix" in result.stdout

    def test_it_still_honours_the_gate(self):
        analysis = self._npm_analysis()
        analysis.scan.vulnerabilities[0].severity = Severity.CRITICAL
        result = _run(analysis, "--fix", "--fail-on", "critical")

        assert result.exit_code == EXIT_POLICY

    def test_an_unverified_scan_produces_no_patch(self):
        """Um patch derivado de um scan que não rodou seria invenção."""
        result = _run(_analysis(verified=False), "--fix")

        assert result.exit_code == EXIT_ERROR
        assert "FROM" not in result.stdout
