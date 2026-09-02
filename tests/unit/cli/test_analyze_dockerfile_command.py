"""Testes do comando `analyze-dockerfile`.

Ele e `build --validate-only` renderizam o mesmo relatório pelo mesmo
renderer (`dockerls/cli/rendering.py`); estes testes fixam o contrato de
saída e de exit code desse caminho compartilhado.
"""

from __future__ import annotations

import json

import pytest
import typer
from typer.testing import CliRunner

from dockerls.application.use_cases.analyze_dockerfile import AnalyzeDockerfileResponse
from dockerls.cli.app import app
from dockerls.cli.commands.analyze_dockerfile import _print_table_output
from dockerls.exit_codes import EXIT_ERROR, EXIT_OK, EXIT_POLICY

runner = CliRunner()

CLEAN_DOCKERFILE = """\
FROM node:22-alpine AS builder
WORKDIR /app
RUN npm ci --no-cache-dir

FROM node:22-alpine
LABEL security.scanner="dockerls"
LABEL maintainer="team@example.com"
COPY --from=builder /app /app
USER node
HEALTHCHECK --interval=30s CMD ["node", "healthcheck.js"]
ENTRYPOINT ["node", "index.js"]
"""

BAD_DOCKERFILE = "FROM node:latest\nENV API_KEY=abc123\nCMD npm start\n"


@pytest.fixture
def clean_context(tmp_path):
    (tmp_path / "Dockerfile").write_text(CLEAN_DOCKERFILE)
    (tmp_path / ".dockerignore").write_text("node_modules\n")
    return tmp_path


@pytest.fixture
def bad_context(tmp_path):
    (tmp_path / "Dockerfile").write_text(BAD_DOCKERFILE)
    return tmp_path


class TestAnalyzeDockerfile:
    def test_clean_dockerfile_exits_zero_with_the_checks_table(self, clean_context):
        result = runner.invoke(app, ["analyze-dockerfile", str(clean_context)])

        assert result.exit_code == EXIT_OK
        assert "Validation Checks" in result.stdout
        assert "Security Score" in result.stdout

    def test_failing_checks_exit_two(self, bad_context):
        result = runner.invoke(app, ["analyze-dockerfile", str(bad_context)])

        assert result.exit_code == EXIT_POLICY
        assert "secrets_not_in_env" in result.stdout

    def test_warnings_alone_do_not_fail(self, clean_context):
        """Aviso não reprova build -- só erro reprova."""
        result = runner.invoke(app, ["analyze-dockerfile", str(clean_context)])

        assert result.exit_code == EXIT_OK

    def test_missing_dockerfile_exits_one(self, tmp_path):
        result = runner.invoke(app, ["analyze-dockerfile", str(tmp_path)])

        assert result.exit_code == EXIT_ERROR
        assert "not found" in result.stdout.lower()

    def test_json_format_is_parseable(self, bad_context):
        result = runner.invoke(app, ["analyze-dockerfile", str(bad_context), "--format", "json"])

        payload = json.loads(result.stdout)
        assert payload["success"] is True
        assert payload["validation"]["errors"] > 0
        assert payload["suggestions"]

    def test_an_unrecognised_format_is_rejected_not_silently_tabled(self, clean_context):
        """`--format` accepted only `table`/`json` in its help text, but a
        plain `str` compared with `== "json"` let any other value -- a typo
        like `jsonn`, or `yaml` -- fall through to the table renderer
        without a word of complaint."""
        result = runner.invoke(app, ["analyze-dockerfile", str(clean_context), "--format", "yaml"])

        assert result.exit_code == EXIT_ERROR
        assert "yaml" in result.stdout
        assert "Validation Checks" not in result.stdout

    def test_validate_only_skips_suggestions(self, bad_context):
        result = runner.invoke(app, ["analyze-dockerfile", str(bad_context), "--validate-only"])

        assert result.exit_code == EXIT_POLICY
        assert "Recommendations" not in result.stdout

    def test_no_suggestions_flag_hides_them(self, bad_context):
        result = runner.invoke(app, ["analyze-dockerfile", str(bad_context), "--no-suggestions"])

        assert "Recommendations" not in result.stdout
        assert "Validation Checks" in result.stdout

    def test_output_never_contains_the_string_none(self, clean_context):
        result = runner.invoke(app, ["analyze-dockerfile", str(clean_context)])

        assert "None" not in result.stdout


class TestOutputFlag:
    """`--output` writes the full report to a file, so a later `build
    --compare-to-analysis` can reference it."""

    def test_writes_a_parseable_report(self, bad_context, tmp_path):
        report_path = tmp_path / "report.json"
        result = runner.invoke(
            app, ["analyze-dockerfile", str(bad_context), "-o", str(report_path)]
        )

        assert report_path.exists()
        document = json.loads(report_path.read_text())
        assert "validation" in document
        assert result.exit_code == EXIT_POLICY

    def test_json_format_still_writes_the_file_and_prints_json(self, bad_context, tmp_path):
        report_path = tmp_path / "report.json"
        result = runner.invoke(
            app,
            ["analyze-dockerfile", str(bad_context), "--format", "json", "-o", str(report_path)],
        )

        assert report_path.exists()
        assert json.loads(result.stdout)  # stdout is still parseable JSON alone

    def test_an_unwritable_path_is_reported_not_raised(self, bad_context):
        result = runner.invoke(
            app, ["analyze-dockerfile", str(bad_context), "-o", "/no/such/dir/report.json"]
        )

        assert result.exit_code == EXIT_ERROR
        assert "Error" in result.stdout


class TestPrintTableOutputDefensiveBranch:
    """`success=True` with no `validation` should be unreachable through the
    use case, but `_print_table_output` guards against it directly instead
    of trusting that invariant -- this locks that guard in place."""

    def test_success_with_no_validation_is_reported_as_an_execution_error(self):
        response = AnalyzeDockerfileResponse(success=True, validation=None)

        with pytest.raises(typer.Exit) as exc_info:
            _print_table_output(response)

        assert exc_info.value.exit_code == EXIT_ERROR
