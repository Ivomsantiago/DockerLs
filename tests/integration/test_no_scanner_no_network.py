"""Every scan-dependent command, run as a CI runner with neither trivy/grype
on PATH nor a reachable network would see it.

`analyze` and `recommend` already had this covered; this file closes the
same gap for `advisor`, `alternatives`, `compare` and `build --production`.
The one behaviour under test everywhere: a command that cannot measure
anything must say so plainly (SCANNER_MISSING, or an equivalent explicit
"could not be scanned") and exit with the documented error code -- never a
raw traceback, and never a report that reads as "0 vulnerabilities" when the
truth is "nothing was scanned at all".
"""

from __future__ import annotations

from unittest.mock import patch

import httpx
import pytest
from typer.testing import CliRunner

from dockerls.application.use_cases.build_image import (
    BuildImageRequest,
    BuildImageUseCase,
    BuildResult,
)
from dockerls.cli.app import app
from dockerls.domain.value_objects.build_policy import BuildPolicy
from dockerls.exit_codes import EXIT_ERROR
from dockerls.infrastructure.dockerfile_validator import DockerfileValidator, HardeningTemplates

runner = CliRunner()


@pytest.fixture
def no_scanner_no_network(monkeypatch):
    """Neither trivy/grype is on PATH, and every outbound HTTP request fails
    the way it would on a runner with no network reachability at all."""
    monkeypatch.setattr("shutil.which", lambda name: None)

    async def _blocked_send(self, request, **kwargs):
        raise httpx.ConnectError("simulated: no network access", request=request)

    monkeypatch.setattr(httpx.AsyncClient, "send", _blocked_send)


def _assert_no_leaked_false_verdict(output: str) -> None:
    lowered = output.lower()
    assert "traceback (most recent call last)" not in lowered
    assert "0 vulnerabilit" not in lowered
    assert "0 critical" not in lowered


class TestAdvisorWithoutScannerOrNetwork:
    def test_exits_with_an_execution_error_not_a_traceback(self, no_scanner_no_network):
        result = runner.invoke(app, ["advisor", "node"])

        assert isinstance(result.exception, SystemExit) or result.exception is None
        assert result.exit_code == EXIT_ERROR
        _assert_no_leaked_false_verdict(result.stdout)


class TestAlternativesWithoutScannerOrNetwork:
    def test_current_image_cannot_be_scanned_so_the_command_refuses_to_compare(
        self, no_scanner_no_network
    ):
        result = runner.invoke(app, ["alternatives", "node:22"])

        assert isinstance(result.exception, SystemExit) or result.exception is None
        assert result.exit_code == EXIT_ERROR
        _assert_no_leaked_false_verdict(result.stdout)


class TestCompareWithoutScannerOrNetwork:
    def test_no_image_could_be_scanned_is_reported_as_an_execution_error(
        self, no_scanner_no_network
    ):
        result = runner.invoke(app, ["compare", "node:22", "python:3.12"])

        assert isinstance(result.exception, SystemExit) or result.exception is None
        assert result.exit_code == EXIT_ERROR
        assert "No image could be scanned" in result.stdout
        assert "technical failure, not a security verdict" in result.stdout.lower()
        _assert_no_leaked_false_verdict(result.stdout)


class TestBuildProductionWithoutScannerOrNetwork:
    """`--production` merges in `BuildPolicy.production()`, which sets
    `fail_on="critical"` -- the same gate that already refuses to publish an
    unscanned image under a plain `--fail-on critical`. This exercises that
    same refusal through the real use case, with the real scanner-selection
    path (`shutil.which` finds nothing), rather than a mocked response."""

    def test_exits_one_instead_of_reporting_a_clean_build(self, no_scanner_no_network, tmp_path):
        (tmp_path / "Dockerfile").write_text("FROM node:22-alpine\nUSER node\n")
        use_case = BuildImageUseCase(
            validator=DockerfileValidator(),
            template_provider=HardeningTemplates(),
        )

        with patch.object(use_case, "_build_image") as mock_build:
            mock_build.return_value = BuildResult(success=True, image_tag="ci-app:1.0")
            response = use_case.execute(
                BuildImageRequest(
                    context_path=str(tmp_path),
                    tag="ci-app:1.0",
                    scan=True,
                    policy=BuildPolicy.production(),
                )
            )

        assert response.success is False
        assert response.exit_code == EXIT_ERROR
        assert response.error is not None
        assert "no scanner" in response.error.lower()
        _assert_no_leaked_false_verdict(response.error)
