from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
from typer.testing import CliRunner

from dockerls.application.dto.analysis import ComparisonResult, ImageAnalysis
from dockerls.application.use_cases.search_images import SearchImagesUseCase
from dockerls.cli.app import app
from dockerls.domain.entities.image import DockerImage
from dockerls.domain.entities.scan_result import ScanResult
from dockerls.domain.entities.vulnerability import Severity, Vulnerability
from dockerls.exit_codes import EXIT_ERROR

runner = CliRunner()


def _analysis() -> ImageAnalysis:
    vuln = Vulnerability(
        cve_id="CVE-2024-0001",
        severity=Severity.HIGH,
        package_name="openssl",
        installed_version="1.0",
        fixed_version="1.1",
    )
    # Um scan real sempre carrega timestamp: é ele que `is_verified` exige, e
    # `analyze` agora recusa emitir veredito sem scan verificado.
    scan = ScanResult(
        image_reference="node:22-alpine",
        vulnerabilities=[vuln],
        scan_timestamp="2026-01-01T00:00:00+00:00",
    )
    return ImageAnalysis(
        image=DockerImage(name="node", tag="22-alpine"),
        scan=scan,
        security_score=80.0,
        tier="B",
        remediation_score=100,
    )


class TestSearchCommand:
    def test_search_lists_tags(self):
        repo = AsyncMock()
        repo.search_tags = AsyncMock(
            return_value=[
                DockerImage(name="node", tag="22-alpine", is_official=True),
            ]
        )
        with patch(
            "dockerls.cli.commands.search.build_search_use_case",
            AsyncMock(return_value=SearchImagesUseCase(repo)),
        ):
            result = runner.invoke(app, ["search", "node"])
        assert result.exit_code == 0
        assert "22-alpine" in result.stdout

    def test_search_no_tags_exits_one(self):
        repo = AsyncMock()
        repo.search_tags = AsyncMock(return_value=[])
        with patch(
            "dockerls.cli.commands.search.build_search_use_case",
            AsyncMock(return_value=SearchImagesUseCase(repo)),
        ):
            result = runner.invoke(app, ["search", "nope"])
        assert result.exit_code == 1

    def test_search_rejects_an_image_tag_with_a_clear_message(self):
        """`node:18` used to be looked up as a literal (nonexistent)
        repository name and fail with an opaque "No tags found"."""
        result = runner.invoke(app, ["search", "node:18"])
        collapsed = " ".join(result.stdout.split())
        assert result.exit_code == 1
        assert "dockerls search node" in collapsed
        assert "dockerls analyze node:18" in collapsed
        assert "No tags found" not in collapsed

    def test_search_still_accepts_a_private_registry_with_a_port(self):
        repo = AsyncMock()
        repo.search_tags = AsyncMock(
            return_value=[DockerImage(name="registry.internal:5000/app", tag="1.0")]
        )
        with patch(
            "dockerls.cli.commands.search.build_search_use_case",
            AsyncMock(return_value=SearchImagesUseCase(repo)),
        ):
            result = runner.invoke(app, ["search", "registry.internal:5000/app"])
        assert result.exit_code == 0
        repo.search_tags.assert_awaited_once()


class TestAnalyzeCommand:
    def test_analyze_prints_results(self):
        use_case = AsyncMock()
        use_case.execute = AsyncMock(return_value=_analysis())
        with patch(
            "dockerls.cli.commands.analyze.build_analyze_use_case",
            AsyncMock(return_value=use_case),
        ):
            result = runner.invoke(app, ["analyze", "node:22-alpine"])
        assert result.exit_code == 0
        assert "CVE-2024-0001" in result.stdout

    def test_cve_id_is_never_truncated_in_a_narrow_terminal(self):
        """The CVE ID is the primary key of a finding.

        At 80 columns the table used to render `CVE-2026…`, which identifies
        nothing and cannot be looked up. Package and version may be shortened
        instead; the ID may not.
        """
        analysis = _analysis()
        analysis.scan.vulnerabilities[0].cve_id = "CVE-2026-12345"
        analysis.scan.vulnerabilities[0].package_name = "perl-base-with-a-very-long-name"
        analysis.scan.vulnerabilities[0].installed_version = "5.36.0-7+deb12u2-longsuffix"

        use_case = AsyncMock()
        use_case.execute = AsyncMock(return_value=analysis)
        with patch(
            "dockerls.cli.commands.analyze.build_analyze_use_case",
            AsyncMock(return_value=use_case),
        ):
            result = CliRunner(env={"COLUMNS": "80"}).invoke(app, ["analyze", "node:22-alpine"])

        assert result.exit_code == 0
        assert "CVE-2026-12345" in result.stdout

    def test_wide_does_not_truncate_any_column(self):
        analysis = _analysis()
        analysis.scan.vulnerabilities[0].package_name = "perl-base-with-a-very-long-name"

        use_case = AsyncMock()
        use_case.execute = AsyncMock(return_value=analysis)
        with patch(
            "dockerls.cli.commands.analyze.build_analyze_use_case",
            AsyncMock(return_value=use_case),
        ):
            result = CliRunner(env={"COLUMNS": "80"}).invoke(
                app, ["analyze", "node:22-alpine", "--wide"]
            )

        assert result.exit_code == 0
        assert "perl-base-with-a-very-long-name" in result.stdout
        assert "…" not in result.stdout

    def test_analyze_scan_failure_exits_one(self):
        use_case = AsyncMock()
        use_case.execute = AsyncMock(side_effect=ValueError("scan ERROR"))
        with patch(
            "dockerls.cli.commands.analyze.build_analyze_use_case",
            AsyncMock(return_value=use_case),
        ):
            result = runner.invoke(app, ["analyze", "node:22-alpine"])
        assert result.exit_code == 1


class TestCompareCommand:
    def test_compare_requires_two_images(self):
        result = runner.invoke(app, ["compare", "node:22-alpine"])
        assert result.exit_code == 1

    def test_compare_prints_winner(self):
        use_case = AsyncMock()
        a1, a2 = _analysis(), _analysis()
        use_case.execute = AsyncMock(
            return_value=ComparisonResult(
                images=[a1, a2],
                winner=a1.image.full_reference,
                summary="best wins",
            )
        )
        with patch(
            "dockerls.cli.commands.compare.build_compare_use_case",
            AsyncMock(return_value=use_case),
        ):
            result = runner.invoke(app, ["compare", "node:22-alpine", "node:20-alpine"])
        assert result.exit_code == 0
        assert "Winner" in result.stdout


class TestExportCommand:
    def test_export_json_to_stdout(self):
        from dockerls.application.dto.analysis import AnalysisResult

        use_case = AsyncMock()
        use_case.execute = AsyncMock(
            return_value=AnalysisResult(
                query="node",
                total_tags_scanned=1,
                baseline_met=True,
                recommendations=[_analysis()],
            )
        )
        with patch(
            "dockerls.cli.commands.export.build_recommend_use_case",
            AsyncMock(return_value=use_case),
        ):
            result = runner.invoke(app, ["export", "node", "--format", "json"])
        assert result.exit_code == 0
        assert '"query"' in result.stdout

    def test_export_unsupported_format(self):
        from dockerls.application.dto.analysis import AnalysisResult

        use_case = AsyncMock()
        use_case.execute = AsyncMock(
            return_value=AnalysisResult(
                query="node",
                total_tags_scanned=0,
                baseline_met=False,
            )
        )
        with patch(
            "dockerls.cli.commands.export.build_recommend_use_case",
            AsyncMock(return_value=use_case),
        ):
            result = runner.invoke(app, ["export", "node", "--format", "xml"])
        assert result.exit_code == 1

    def test_export_to_file(self, tmp_path):
        from dockerls.application.dto.analysis import AnalysisResult

        use_case = AsyncMock()
        use_case.execute = AsyncMock(
            return_value=AnalysisResult(
                query="node",
                total_tags_scanned=1,
                baseline_met=True,
                recommendations=[_analysis()],
            )
        )
        out_file = tmp_path / "report.json"
        with patch(
            "dockerls.cli.commands.export.build_recommend_use_case",
            AsyncMock(return_value=use_case),
        ):
            result = runner.invoke(
                app, ["export", "node", "--format", "json", "--output", str(out_file)]
            )
        assert result.exit_code == 0
        assert out_file.exists()


class TestSbomCommand:
    def test_sbom_prints_content(self):
        scanner = AsyncMock()
        scanner.is_available = AsyncMock(return_value=True)
        scanner.generate_sbom = AsyncMock(return_value='{"bomFormat": "CycloneDX"}')
        with patch("dockerls.cli.commands.sbom.TrivyScanner", return_value=scanner):
            result = runner.invoke(app, ["sbom", "node:22-alpine"])
        assert result.exit_code == 0
        assert "CycloneDX" in result.stdout

    def test_sbom_invalid_format_exits_one(self):
        result = runner.invoke(app, ["sbom", "node:22-alpine", "--format", "bogus"])
        assert result.exit_code == 1

    def test_sbom_trivy_unavailable_exits_one(self):
        scanner = AsyncMock()
        scanner.is_available = AsyncMock(return_value=False)
        with patch("dockerls.cli.commands.sbom.TrivyScanner", return_value=scanner):
            result = runner.invoke(app, ["sbom", "node:22-alpine"])
        assert result.exit_code == 1


class TestLoginCommand:
    def test_login_success(self):
        client = AsyncMock()
        client.authenticate = AsyncMock(return_value=True)
        with (
            patch("dockerls.cli.commands.login.DockerHubClient", return_value=client),
            patch("dockerls.cli.commands.login.store_credentials", return_value=True),
        ):
            result = runner.invoke(app, ["login", "--username", "u", "--token", "t"])
        assert result.exit_code == 0

    def test_login_failure_exits_one(self):
        client = AsyncMock()
        client.authenticate = AsyncMock(return_value=False)
        with patch("dockerls.cli.commands.login.DockerHubClient", return_value=client):
            result = runner.invoke(app, ["login", "--username", "u", "--token", "bad"])
        assert result.exit_code == 1

    def test_login_missing_credentials_exits_one(self):
        result = runner.invoke(app, ["login", "--username", "", "--token", ""])
        assert result.exit_code == 1


class TestDoctorCommand:
    def test_doctor_runs(self, monkeypatch):
        # `doctor` gates on its findings now, so the outcome depends on what
        # is installed on the host. Pinning the lookup keeps the test about
        # the command running cleanly rather than about this machine.
        monkeypatch.setattr("shutil.which", lambda name: f"/usr/bin/{name}")
        result = runner.invoke(app, ["doctor"])
        assert result.exit_code == 0


class TestHealthCommand:
    def test_health_reports_status(self):
        ok_resp = httpx.Response(200, request=httpx.Request("GET", "https://x"))
        with patch("httpx.AsyncClient.get", AsyncMock(return_value=ok_resp)):
            result = runner.invoke(app, ["health"])
        assert result.exit_code == 0
        assert "Docker Hub API" in result.stdout

    def test_health_handles_errors(self):
        """A total outage must be reported *and* must fail the command.

        This previously asserted exit_code == 0, which codified the bug:
        `health` could not gate anything because it reported success no
        matter what it found.
        """
        with patch(
            "httpx.AsyncClient.get",
            AsyncMock(
                side_effect=httpx.ConnectError("boom", request=httpx.Request("GET", "https://x"))
            ),
        ):
            result = runner.invoke(app, ["health"])
        assert result.exit_code == 1
        assert "Unreachable" in result.stdout
        assert "degraded" in result.stdout


class TestCacheCommand:
    def test_cache_clear(self):
        cache = AsyncMock()
        with patch("dockerls.cli.commands.cache_cmd.build_cache", return_value=cache):
            result = runner.invoke(app, ["cache", "clear"])
        assert result.exit_code == 0
        cache.clear.assert_awaited_once()

    def test_cache_cleanup(self):
        cache = AsyncMock()
        cache.cleanup_expired = AsyncMock(return_value=3)
        with patch("dockerls.cli.commands.cache_cmd.build_cache", return_value=cache):
            result = runner.invoke(app, ["cache", "cleanup"])
        assert result.exit_code == 0
        assert "3" in result.stdout


class TestVersionCommand:
    def test_version_prints(self):
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "DockerLs v" in result.stdout


class TestMalformedImageReferencesAreUserErrors:
    """`sanitize_image_name` rejects malformed references by raising
    `ValueError`. `analyze`, `compare`, `export` and `recommend` already
    reported that as a message; `search` and `sbom` still answered with a
    stack trace, which in a pipeline is indistinguishable from a crash.
    """

    def test_search_reports_it_without_a_traceback(self):
        result = runner.invoke(app, ["search", "bad name!"])

        assert result.exit_code == 1
        assert result.exception is None or isinstance(result.exception, SystemExit)
        assert "Invalid image reference" in result.stdout

    def test_sbom_reports_it_without_a_traceback(self):
        scanner = AsyncMock()
        scanner.is_available = AsyncMock(return_value=True)
        scanner.generate_sbom = AsyncMock(side_effect=ValueError("Invalid image name: bad name!"))
        with patch("dockerls.cli.commands.sbom.TrivyScanner", return_value=scanner):
            result = runner.invoke(app, ["sbom", "bad name!"])

        assert result.exit_code == 1
        assert result.exception is None or isinstance(result.exception, SystemExit)
        assert "Invalid image reference" in result.stdout

    def test_sbom_unwritable_output_is_reported(self, tmp_path):
        scanner = AsyncMock()
        scanner.is_available = AsyncMock(return_value=True)
        scanner.generate_sbom = AsyncMock(return_value="{}")
        blocked = tmp_path / "afile"
        blocked.write_text("x")
        with patch("dockerls.cli.commands.sbom.TrivyScanner", return_value=scanner):
            result = runner.invoke(
                app, ["sbom", "node:22-alpine", "-o", str(blocked / "nested" / "sbom.json")]
            )

        assert result.exit_code == 1
        assert "Could not write" in result.stdout


class TestSbomAttestation:
    """Sem `--attest` o SBOM é um arquivo no seu disco: útil, e invisível
    para quem baixa a imagem. É a atestação que o `registry-audit` procura
    -- e que, até agora, ele nunca encontrava para imagens construídas por
    esta própria ferramenta."""

    _DIGEST = "reg.io/app@sha256:" + "a" * 64

    def _trivy(self, monkeypatch, content='{"bomFormat":"CycloneDX"}'):
        from unittest.mock import AsyncMock

        scanner = AsyncMock()
        scanner.is_available = AsyncMock(return_value=True)
        scanner.generate_sbom = AsyncMock(return_value=content)
        monkeypatch.setattr("dockerls.cli.commands.sbom.TrivyScanner", lambda *a, **k: scanner)
        return scanner

    def test_a_tag_is_refused_before_the_image_is_scanned(self, monkeypatch):
        """Descobrir isso depois de escanear a imagem inteira desperdiça o
        trabalho, e a correção é outra referência, não outra flag."""
        scanner = self._trivy(monkeypatch)

        result = CliRunner().invoke(app, ["sbom", "node:22", "--attest"])

        assert result.exit_code == EXIT_ERROR
        assert "needs a digest reference" in result.output
        scanner.generate_sbom.assert_not_called()

    def test_the_sbom_is_attested_by_digest(self, monkeypatch):
        from unittest.mock import AsyncMock

        from dockerls.integrations.signing.cosign import SignatureResult, SignatureStatus

        self._trivy(monkeypatch)
        client = AsyncMock()
        client.attest = AsyncMock(
            return_value=SignatureResult(reference=self._DIGEST, status=SignatureStatus.SIGNED)
        )
        monkeypatch.setattr(
            "dockerls.integrations.signing.cosign.CosignClient", lambda *a, **k: client
        )

        result = CliRunner().invoke(app, ["sbom", self._DIGEST, "--attest"])

        assert result.exit_code == 0
        assert "attested" in result.output
        assert client.attest.await_args.kwargs["predicate_type"] == "cyclonedx"

    def test_the_predicate_file_does_not_survive_the_command(self, monkeypatch):
        """O SBOM é o inventário completo da imagem. Deixá-lo em `/tmp`
        vazaria por descuido o que o comando existe para publicar de forma
        controlada."""
        from pathlib import Path
        from unittest.mock import AsyncMock

        from dockerls.integrations.signing.cosign import SignatureResult, SignatureStatus

        self._trivy(monkeypatch)
        seen: dict[str, str] = {}

        async def capture(reference, *, predicate, predicate_type, **kwargs):
            seen["path"] = predicate
            seen["content"] = Path(predicate).read_text(encoding="utf-8")
            return SignatureResult(reference=reference, status=SignatureStatus.SIGNED)

        client = AsyncMock()
        client.attest = capture
        monkeypatch.setattr(
            "dockerls.integrations.signing.cosign.CosignClient", lambda *a, **k: client
        )

        CliRunner().invoke(app, ["sbom", self._DIGEST, "--attest"])

        assert seen["content"] == '{"bomFormat":"CycloneDX"}'
        assert not Path(seen["path"]).exists()

    def test_spdx_is_attested_with_the_spdx_predicate_type(self, monkeypatch):
        from unittest.mock import AsyncMock

        from dockerls.integrations.signing.cosign import SignatureResult, SignatureStatus

        self._trivy(monkeypatch)
        client = AsyncMock()
        client.attest = AsyncMock(
            return_value=SignatureResult(reference=self._DIGEST, status=SignatureStatus.SIGNED)
        )
        monkeypatch.setattr(
            "dockerls.integrations.signing.cosign.CosignClient", lambda *a, **k: client
        )

        CliRunner().invoke(app, ["sbom", self._DIGEST, "--attest", "--format", "spdx"])

        assert client.attest.await_args.kwargs["predicate_type"] == "spdxjson"

    def test_a_missing_cosign_says_the_sbom_was_generated_anyway(self, monkeypatch):
        """Ausência de ferramenta, não falha da imagem: o SBOM existe e
        continua válido; o que não aconteceu foi a publicação."""
        from unittest.mock import AsyncMock

        from dockerls.integrations.signing.cosign import SignatureResult, SignatureStatus

        self._trivy(monkeypatch)
        client = AsyncMock()
        client.attest = AsyncMock(
            return_value=SignatureResult(
                reference=self._DIGEST, status=SignatureStatus.SIGNER_MISSING
            )
        )
        monkeypatch.setattr(
            "dockerls.integrations.signing.cosign.CosignClient", lambda *a, **k: client
        )

        result = CliRunner().invoke(app, ["sbom", self._DIGEST, "--attest"])

        assert result.exit_code == EXIT_ERROR
        assert "generated but not attested" in result.output
