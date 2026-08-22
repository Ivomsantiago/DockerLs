"""Testes do comando `build`.

O defeito que motivou estes testes: `build --validate-only` imprimia
literalmente `None` e mais nada — nem a tabela de checks, nem qual regra
falhou —, e o contrato de exit code não existia. Nada disso era coberto,
então nada disso quebrou nenhum teste.
"""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from dockerls.application.use_cases.build_image import BuildImageResponse, BuildReport
from dockerls.cli.app import app
from dockerls.cli.commands.build import BuildImageUseCase
from dockerls.domain.entities.dockerfile_analysis import HardeningRule, SeverityLevel
from dockerls.exit_codes import EXIT_ERROR, EXIT_OK, EXIT_POLICY
from dockerls.infrastructure.dockerfile_validator import HardeningTemplates

runner = CliRunner()

CLEAN_DOCKERFILE = """\
FROM node:22-alpine AS builder
WORKDIR /app
RUN npm ci --no-cache-dir && rm -rf ~/.cache/pip

FROM node:22-alpine
LABEL security.scanner="dockerls"
LABEL maintainer="team@example.com"
COPY --from=builder /app /app
USER node
HEALTHCHECK --interval=30s CMD ["node", "healthcheck.js"]
ENTRYPOINT ["node", "index.js"]
"""

# Reprova em três regras: base :latest, root, e segredos em ENV.
BAD_DOCKERFILE = """\
FROM node:latest
ENV DOCKER_TOKEN=dckr_pat_example
ENV API_KEY=abc123
RUN apt-get update && apt-get install -y curl
CMD npm start
"""


@pytest.fixture
def clean_context(tmp_path):
    (tmp_path / "Dockerfile").write_text(CLEAN_DOCKERFILE)
    (tmp_path / ".dockerignore").write_text("node_modules\n")
    return tmp_path


@pytest.fixture
def bad_context(tmp_path):
    (tmp_path / "Dockerfile").write_text(BAD_DOCKERFILE)
    return tmp_path


class TestValidateOnly:
    def test_clean_dockerfile_passes_with_the_checks_table(self, clean_context):
        result = runner.invoke(app, ["build", "--validate-only", str(clean_context)])

        assert result.exit_code == EXIT_OK
        assert "Validation Checks" in result.stdout
        assert "non_root_user" in result.stdout
        assert "Validation Passed" in result.stdout

    def test_output_never_contains_the_string_none(self, clean_context):
        """O sintoma original: um `None` solto onde deveria estar o relatório."""
        result = runner.invoke(app, ["build", "--validate-only", str(clean_context)])

        assert "None" not in result.stdout

    def test_failing_dockerfile_names_every_violated_rule(self, bad_context):
        result = runner.invoke(app, ["build", "--validate-only", str(bad_context)])

        # Política violada -- a validação rodou bem, o Dockerfile é que reprova.
        assert result.exit_code == EXIT_POLICY
        assert "Validation Failed" in result.stdout
        for rule in ("base_image_pinned", "non_root_user", "secrets_not_in_env"):
            assert rule in result.stdout
        assert "None" not in result.stdout

    def test_missing_dockerfile_is_an_execution_error(self, tmp_path):
        result = runner.invoke(app, ["build", "--validate-only", str(tmp_path)])

        assert result.exit_code == EXIT_ERROR
        assert "not found" in result.stdout.lower()

    def test_secret_values_are_not_echoed_back(self, bad_context):
        """Reportar o nome da variável é o objetivo; imprimir o valor dela
        transformaria o relatório num vazamento a mais."""
        result = runner.invoke(app, ["build", "--validate-only", str(bad_context)])

        assert "DOCKER_TOKEN" in result.stdout
        assert "dckr_pat_example" not in result.stdout


class TestCiMode:
    def test_emits_parseable_json_on_stdout(self, clean_context):
        result = runner.invoke(app, ["build", "--validate-only", "--ci-mode", str(clean_context)])

        assert result.exit_code == EXIT_OK
        payload = json.loads(result.stdout)
        assert payload["status"] == "SUCCESS"
        assert payload["exit_code"] == EXIT_OK
        assert payload["report"]["validation"]["errors"] == 0

    def test_failed_validation_still_carries_the_report(self, bad_context):
        """É exatamente quando reprova que o CI precisa do relatório: sem ele
        o pipeline sabe que falhou e não sabe em quê."""
        result = runner.invoke(app, ["build", "--validate-only", "--ci-mode", str(bad_context)])

        assert result.exit_code == EXIT_POLICY
        payload = json.loads(result.stdout)
        assert payload["status"] == "FAILED"
        checks = payload["report"]["validation"]["checks"]
        failed = [c["check"] for c in checks if c["status"] == "FAIL"]
        assert "secrets_not_in_env" in failed
        assert "secrets_not_in_env" in payload["error"]

    def test_output_has_no_table_borders(self, clean_context):
        result = runner.invoke(app, ["build", "--validate-only", "--ci-mode", str(clean_context)])

        assert "┏" not in result.stdout
        assert "│" not in result.stdout


class TestSuggestHardening:
    def test_lists_recommendations_without_building(self, bad_context):
        result = runner.invoke(app, ["build", "--suggest-hardening", str(bad_context)])

        assert result.exit_code == EXIT_OK
        assert "Recommendations" in result.stdout
        assert "Remove secrets from ENV" in result.stdout
        assert "None" not in result.stdout


class TestListTemplates:
    def test_lists_the_templates_base_accepts(self):
        result = runner.invoke(app, ["build", "--list-templates"])

        assert result.exit_code == EXIT_OK
        for template in ("node", "python", "go"):
            assert template in result.stdout

    def test_only_lists_templates_that_actually_exist(self):
        """The list used to advertise "java", for which no template file has
        ever existed: `--base java` then fell through to a generic template
        with a different base than the one the user asked for."""
        listed = json.loads(runner.invoke(app, ["build", "--list-templates", "--ci-mode"]).stdout)[
            "templates"
        ]

        provider = HardeningTemplates()
        for name in listed:
            assert provider.get_template(name).strip(), f"{name} listed but yields no template"

    def test_ci_mode_lists_them_as_json(self):
        result = runner.invoke(app, ["build", "--list-templates", "--ci-mode"])

        assert result.exit_code == EXIT_OK
        assert "node" in json.loads(result.stdout)["templates"]


class TestArgumentErrors:
    def test_build_without_tag_exits_one(self, clean_context):
        result = runner.invoke(app, ["build", str(clean_context)])

        assert result.exit_code == EXIT_ERROR
        assert "--tag" in result.stdout

    def test_malformed_build_args_json_exits_one(self, clean_context):
        result = runner.invoke(
            app, ["build", "-t", "x:1", "--build-args", "{nope", str(clean_context)]
        )

        assert result.exit_code == EXIT_ERROR
        assert "--build-args" in result.stdout

    def test_malformed_labels_json_exits_one(self, clean_context):
        result = runner.invoke(app, ["build", "-t", "x:1", "--labels", "{nope", str(clean_context)])

        assert result.exit_code == EXIT_ERROR
        assert "--labels" in result.stdout


class TestReportFile:
    def test_json_report_is_written_for_a_validation_run(self, bad_context, tmp_path):
        out = tmp_path / "report.json"
        result = runner.invoke(
            app, ["build", "--validate-only", "--report", str(out), str(bad_context)]
        )

        assert result.exit_code == EXIT_POLICY
        report = json.loads(out.read_text(encoding="utf-8"))
        assert report["validation"]["errors"] > 0
        assert report["security_tier"] in {"A", "B", "C", "D", "F"}

    def test_html_report_is_written(self, bad_context, tmp_path):
        out = tmp_path / "report.html"
        runner.invoke(app, ["build", "--validate-only", "--report", str(out), str(bad_context)])

        html = out.read_text(encoding="utf-8")
        assert html.startswith("<!DOCTYPE html>")
        assert "DockerLs Build Report" in html

    def test_output_flag_writes_json_and_prints_no_table(self, clean_context, tmp_path):
        out = tmp_path / "ci.json"
        result = runner.invoke(
            app, ["build", "--validate-only", "--output", str(out), str(clean_context)]
        )

        assert result.exit_code == EXIT_OK
        assert json.loads(out.read_text(encoding="utf-8"))["status"] == "SUCCESS"
        assert "Validation Checks" not in result.stdout


def _build_report(**overrides) -> BuildReport:
    defaults: dict = {
        "build_id": "deadbeef01234567",
        "timestamp": "2026-01-01T00:00:00+00:00",
        "image": "myapp:1.0",
        "dockerfile_path": "Dockerfile",
        "validation": {
            "dockerfile_path": "Dockerfile",
            "passed": 5,
            "warnings": 0,
            "errors": 0,
            "checks": [],
        },
        "scan_results": {"trivy": {"critical": 0, "high": 1, "medium": 2, "low": 3}},
        "security_score": 88,
        "security_tier": "B",
        "recommendations": [
            {
                "priority": "HIGH",
                "title": "Pin base image",
                "current": "node:latest",
                "suggested": "node:22-alpine",
                "reason": "Floating tags drift under you",
            }
        ],
        "build_metadata": {
            "git_sha": "deadbeef",
            "built_by": "ci",
            "docker_version": "Docker version 24.0.0",
            "buildkit": True,
        },
    }
    defaults.update(overrides)
    return BuildReport(**defaults)


class TestFullBuildFlow:
    """The real build path: `_print_build_output`, `_print_report`, and the
    HTML/JSON report writers. Every other class in this file only exercises
    `validate-only`/`suggest-hardening`/`list-templates`, none of which ever
    reach these functions.
    """

    def test_successful_build_renders_the_security_score_and_scan_results(
        self, clean_context, monkeypatch
    ):
        response = BuildImageResponse(
            success=True,
            image_tag="myapp:1.0",
            image_sha256="sha256:deadbeef",
            report=_build_report(),
            exit_code=EXIT_OK,
        )
        monkeypatch.setattr(BuildImageUseCase, "execute", lambda self, request: response)

        result = runner.invoke(app, ["build", "-t", "myapp:1.0", str(clean_context)])

        assert result.exit_code == EXIT_OK
        assert "Build Successful" in result.stdout
        assert "myapp:1.0" in result.stdout
        assert "Security Score: 88/100" in result.stdout
        assert "Tier: B" in result.stdout
        assert "HIGH: " in result.stdout and "1" in result.stdout
        assert "MEDIUM: " in result.stdout and "2" in result.stdout

    def test_hardening_suggestions_are_listed_after_a_successful_build(
        self, clean_context, monkeypatch
    ):
        suggestion = HardeningRule(
            priority=SeverityLevel.HIGH,
            title="Add HEALTHCHECK",
            description="No healthcheck configured",
            current_state="none",
            suggested_fix='HEALTHCHECK CMD ["node", "healthcheck.js"]',
            reason="Orchestrators need a health signal to restart a stuck container",
        )
        response = BuildImageResponse(
            success=True,
            image_tag="myapp:1.0",
            report=_build_report(),
            recommendations=[suggestion],
            exit_code=EXIT_OK,
        )
        monkeypatch.setattr(BuildImageUseCase, "execute", lambda self, request: response)

        result = runner.invoke(app, ["build", "-t", "myapp:1.0", str(clean_context)])

        assert "Hardening Suggestions" in result.stdout
        assert "Add HEALTHCHECK" in result.stdout
        assert "No healthcheck configured" in result.stdout

    def test_failed_build_via_fail_on_threshold_renders_build_failed_panel(
        self, clean_context, monkeypatch
    ):
        """Only the `--fail-on` rejection path sets `image_tag` on a failed
        response; a raw `docker build` failure leaves it unset, which routes
        `_print_table_output` to the validation renderer instead."""
        response = BuildImageResponse(
            success=False,
            image_tag="myapp:1.0",
            error="Vulnerabilities exceed threshold (critical)",
            exit_code=EXIT_POLICY,
        )
        monkeypatch.setattr(BuildImageUseCase, "execute", lambda self, request: response)

        result = runner.invoke(
            app, ["build", "-t", "myapp:1.0", "--fail-on", "critical", str(clean_context)]
        )

        assert result.exit_code == EXIT_POLICY
        assert "Build Failed" in result.stdout
        assert "Vulnerabilities exceed threshold (critical)" in result.stdout

    def test_ci_mode_emits_the_full_report_as_json(self, clean_context, monkeypatch):
        response = BuildImageResponse(
            success=True,
            image_tag="myapp:1.0",
            report=_build_report(),
            exit_code=EXIT_OK,
        )
        monkeypatch.setattr(BuildImageUseCase, "execute", lambda self, request: response)

        result = runner.invoke(app, ["build", "-t", "myapp:1.0", "--ci-mode", str(clean_context)])

        assert result.exit_code == EXIT_OK
        payload = json.loads(result.stdout)
        assert payload["status"] == "SUCCESS"
        assert payload["report"]["security_score"] == 88
        assert payload["report"]["scan_results"]["trivy"]["high"] == 1

    def test_html_report_includes_the_vulnerability_scan_table(
        self, clean_context, tmp_path, monkeypatch
    ):
        response = BuildImageResponse(
            success=True,
            image_tag="myapp:1.0",
            report=_build_report(),
            exit_code=EXIT_OK,
        )
        monkeypatch.setattr(BuildImageUseCase, "execute", lambda self, request: response)
        out = tmp_path / "build_report.html"

        result = runner.invoke(
            app, ["build", "-t", "myapp:1.0", "--report", str(out), str(clean_context)]
        )

        assert result.exit_code == EXIT_OK
        html = out.read_text(encoding="utf-8")
        assert "Vulnerability Scan" in html
        assert "No scan was run." not in html
        assert '<td class="high">High</td><td>1</td>' in html


class TestHtmlReportIsEscaped:
    """The build report interpolated `--tag`, the Dockerfile path and the
    tier straight into markup. A tag is attacker-influenced in any CI that
    builds from a branch name, so `x"><script>` turned a report someone opens
    in a browser into an execution vector. The `export --format html` path
    already escaped; this one did not.
    """

    HOSTILE = '"><script>alert(1)</script>'

    def test_image_tag_is_escaped(self, tmp_path):
        from dockerls.cli.commands.build import _render_html_report

        html = _render_html_report(_build_report(image=self.HOSTILE))

        assert "<script>" not in html
        assert "&lt;script&gt;" in html

    def test_dockerfile_path_is_escaped(self, tmp_path):
        from dockerls.cli.commands.build import _render_html_report

        html = _render_html_report(_build_report(image="", dockerfile_path=self.HOSTILE))

        assert "<script>" not in html

    def test_tier_and_timestamp_are_escaped(self):
        from dockerls.cli.commands.build import _render_html_report

        html = _render_html_report(
            _build_report(security_tier=self.HOSTILE, timestamp=self.HOSTILE)
        )

        assert "<script>" not in html

    def test_non_numeric_counts_cannot_inject_markup(self):
        """Counts come from scanner JSON -- numbers by convention, not by
        guarantee."""
        from dockerls.cli.commands.build import _render_html_report

        html = _render_html_report(
            _build_report(scan_results={"trivy": {"critical": "<img onerror=x>"}})
        )

        assert "<img" not in html

    def test_the_page_still_reads_correctly(self):
        from dockerls.cli.commands.build import _render_html_report

        html = _render_html_report(_build_report())

        assert html.startswith("<!DOCTYPE html>")
        assert "myapp:1.0" in html
        assert '<div class="score">88/100</div>' in html


class TestBaseTemplateValidation:
    def test_unknown_base_is_rejected_before_anything_is_built(self, clean_context):
        result = runner.invoke(
            app, ["build", "-t", "x:1", "--hardened", "--base", "unknown_xyz", str(clean_context)]
        )

        assert result.exit_code == EXIT_ERROR
        assert "--base" in result.stdout
        for name in HardeningTemplates().list_templates():
            assert name in result.stdout


class TestPublishFlow:
    """Destino e responsabilidade resolvidos antes do build começar.

    Perguntar depois desperdiça validação, build e scan -- e é exatamente
    quando alguém publica em qualquer lugar só para não repetir a espera.
    """

    def _run(self, tmp_path, args, **kwargs):
        (tmp_path / "Dockerfile").write_text("FROM python:3.12-alpine\nUSER 1001\n")
        return CliRunner().invoke(app, ["build", str(tmp_path), *args], **kwargs)

    def test_an_invalid_destination_fails_before_any_build(self, tmp_path):
        with patch("dockerls.cli.commands.build.BuildImageUseCase") as use_case:
            result = self._run(tmp_path, ["-t", "app:1.0", "--registry", "dhi.io/app", "--push"])
        assert result.exit_code == EXIT_ERROR
        assert "não aceita push" in result.output
        # O build nunca chegou a ser instanciado.
        use_case.assert_not_called()

    def test_publishing_without_an_owner_fails_in_non_interactive_mode(self, tmp_path):
        with patch("dockerls.cli.commands.build.BuildImageUseCase") as use_case:
            result = self._run(
                tmp_path,
                [
                    "-t",
                    "app:1.0",
                    "--registry",
                    "meuacr.azurecr.io/apps/app",
                    "--push",
                    "--non-interactive",
                ],
            )
        assert result.exit_code == EXIT_ERROR
        assert "owner" in result.output
        use_case.assert_not_called()

    def test_a_complete_destination_reaches_the_use_case(self, tmp_path):
        with patch("dockerls.cli.commands.build.BuildImageUseCase") as use_case:
            use_case.FAIL_ON_THRESHOLDS = ("critical", "high", "medium", "low")
            self._run(
                tmp_path,
                [
                    "-t",
                    "app:1.5.0",
                    "--registry",
                    "meuacr.azurecr.io/apps/app",
                    "--push",
                    "--owner",
                    "Plataforma",
                    "--security-contact",
                    "sec@empresa",
                    "--source",
                    "https://git/repo",
                    "--non-interactive",
                ],
            )
        request = use_case.return_value.execute.call_args.args[0]
        assert request.push_reference == "meuacr.azurecr.io/apps/app:1.5.0"
        assert request.labels["maintainer"] == "Plataforma"
        assert request.labels["security.contact"] == "sec@empresa"
        assert request.labels["security.scanner"] == "dockerls"

    def test_a_local_build_needs_no_owner(self, tmp_path):
        # Exigir dono de um build local para experimentar faria as pessoas
        # desligarem a checagem inteira.
        with patch("dockerls.cli.commands.build.BuildImageUseCase") as use_case:
            use_case.FAIL_ON_THRESHOLDS = ("critical", "high", "medium", "low")
            result = self._run(tmp_path, ["-t", "app:1.0", "--non-interactive"])
        assert result.exit_code != EXIT_ERROR or "owner" not in result.output


class TestPublishingRequiresAVerdict:
    """Publicar sem veredito é a contradição que esta ferramenta existe para
    não cometer.

    O portão dependia de alguém lembrar de passar `--fail-on`: `--push` sozinho
    publicava qualquer coisa, inclusive uma imagem que ninguém mediu.
    """

    def _dockerfile(self, tmp_path):
        (tmp_path / "Dockerfile").write_text("FROM python:3.12-alpine\nUSER 1001\n")
        return str(tmp_path)

    def test_push_with_no_scan_is_refused(self, tmp_path):
        with patch("dockerls.cli.commands.build.BuildImageUseCase") as use_case:
            result = CliRunner().invoke(
                app,
                ["build", self._dockerfile(tmp_path), "-t", "app:1.0", "--push", "--no-scan"],
            )
        assert result.exit_code == EXIT_ERROR
        assert "não medida" in result.output
        use_case.assert_not_called()

    def test_publishing_defaults_the_gate_to_critical(self, tmp_path):
        with patch("dockerls.cli.commands.build.BuildImageUseCase") as use_case:
            use_case.FAIL_ON_THRESHOLDS = ("critical", "high", "medium", "low")
            CliRunner().invoke(
                app,
                [
                    "build",
                    self._dockerfile(tmp_path),
                    "-t",
                    "app:1.0",
                    "--registry",
                    "meuacr.azurecr.io/apps/app",
                    "--owner",
                    "Plataforma",
                    "--security-contact",
                    "s@e",
                    "--source",
                    "https://git/r",
                    "--non-interactive",
                ],
            )
        request = use_case.return_value.execute.call_args.args[0]
        assert request.fail_on == "critical"

    def test_an_explicit_threshold_is_respected(self, tmp_path):
        with patch("dockerls.cli.commands.build.BuildImageUseCase") as use_case:
            use_case.FAIL_ON_THRESHOLDS = ("critical", "high", "medium", "low")
            CliRunner().invoke(
                app,
                [
                    "build",
                    self._dockerfile(tmp_path),
                    "-t",
                    "app:1.0",
                    "--registry",
                    "meuacr.azurecr.io/apps/app",
                    "--fail-on",
                    "high",
                    "--owner",
                    "P",
                    "--security-contact",
                    "s@e",
                    "--source",
                    "https://git/r",
                    "--non-interactive",
                ],
            )
        assert use_case.return_value.execute.call_args.args[0].fail_on == "high"

    def test_a_local_build_keeps_no_gate_by_default(self, tmp_path):
        with patch("dockerls.cli.commands.build.BuildImageUseCase") as use_case:
            use_case.FAIL_ON_THRESHOLDS = ("critical", "high", "medium", "low")
            CliRunner().invoke(
                app, ["build", self._dockerfile(tmp_path), "-t", "app:1.0", "--non-interactive"]
            )
        assert use_case.return_value.execute.call_args.args[0].fail_on is None

    def test_the_provenance_path_reaches_the_use_case(self, tmp_path):
        with patch("dockerls.cli.commands.build.BuildImageUseCase") as use_case:
            use_case.FAIL_ON_THRESHOLDS = ("critical", "high", "medium", "low")
            CliRunner().invoke(
                app,
                [
                    "build",
                    self._dockerfile(tmp_path),
                    "-t",
                    "app:1.0",
                    "--provenance",
                    str(tmp_path / "sc.json"),
                    "--non-interactive",
                ],
            )
        request = use_case.return_value.execute.call_args.args[0]
        assert request.provenance_path.endswith("sc.json")


class TestTemplateDiscovery:
    """Escolher base não pode ser adivinhação.

    A lista era plana, com quase quarenta nomes e nenhuma indicação do sistema
    operacional de cada um -- ela não respondia a pergunta que a pessoa tem,
    que é "qual serve para a minha aplicação, e sobre qual SO ela roda".
    """

    def test_every_stack_and_os_is_listed(self):
        result = CliRunner().invoke(app, ["build", "--list-templates"])
        assert result.exit_code == EXIT_OK
        for expected in ("alpine", "debian", "ubuntu", "distroless", "go-scratch"):
            assert expected in result.output
        for stack in ("Node.js", "Python", "Java", "Go", "Rust", "PHP", "Ruby"):
            assert stack in result.output

    def test_java_build_tools_are_covered(self):
        # `--base maven` respondia que o template não existe, mandando a pessoa
        # escrever o multi-stage na mão -- justamente onde um projeto Java
        # começa o Dockerfile.
        result = CliRunner().invoke(app, ["build", "--list-templates"])
        assert "maven" in result.output
        assert "maven-alpine" in result.output
        assert "gradle" in result.output

    def test_examples_are_shown(self):
        result = CliRunner().invoke(app, ["build", "--list-templates"])
        assert "--base node-alpine" in result.output
        assert "--base maven-alpine" in result.output
        # E a frase que evita a confusão de origem: sem --base, o build usa o
        # Dockerfile que já está lá.
        assert "Dockerfile que já está no diretório" in result.output

    def test_an_unknown_base_fails_before_building(self, tmp_path):
        (tmp_path / "Dockerfile").write_text("FROM python:3.12-alpine\n")
        result = CliRunner().invoke(
            app, ["build", str(tmp_path), "-t", "a:1", "--base", "alpine-inexistente"]
        )
        assert result.exit_code == EXIT_ERROR
        assert "inválido" in result.output

    def test_json_mode_still_lists_plain_names(self):
        result = CliRunner().invoke(app, ["build", "--list-templates", "--ci-mode"])
        payload = json.loads(result.output)
        assert "maven" in payload["templates"]
        assert len(payload["templates"]) >= 39


class TestBaseImageCommand:
    """O menu que monta a imagem base.

    Marcar um pacote aqui o coloca em toda aplicação que consumir a base, então
    o menu mostra o custo junto do propósito -- e recusa o que não deveria
    estar numa imagem base, com o motivo.
    """

    def test_the_menu_shows_purpose_and_cost_of_each_package(self, tmp_path):
        result = CliRunner().invoke(
            app,
            ["base-image", "-o", str(tmp_path / "Dockerfile"), "--no-pin"],
            input="1\n1\n1,2\ns\n",
        )
        assert "serve para:" in result.output
        assert "custa:" in result.output

    def test_a_refused_package_names_the_reason(self, tmp_path):
        result = CliRunner().invoke(
            app,
            [
                "base-image",
                "-o",
                str(tmp_path / "Dockerfile"),
                "--os",
                "alpine",
                "--runtime",
                "none",
                "--with",
                "sudo",
                "--no-pin",
            ],
        )
        assert result.exit_code == EXIT_ERROR
        assert "sudo" in result.output
        assert "privilégio" in result.output

    def test_distroless_refuses_packages_instead_of_generating_a_broken_file(self, tmp_path):
        destination = tmp_path / "Dockerfile"
        result = CliRunner().invoke(
            app,
            [
                "base-image",
                "-o",
                str(destination),
                "--os",
                "distroless",
                "--runtime",
                "java",
                "--with",
                "curl",
                "--no-pin",
            ],
        )
        assert result.exit_code == EXIT_ERROR
        assert not destination.exists()

    def test_non_interactive_generation_writes_the_file(self, tmp_path):
        destination = tmp_path / "Dockerfile"
        result = CliRunner().invoke(
            app,
            [
                "base-image",
                "-o",
                str(destination),
                "--os",
                "alpine",
                "--runtime",
                "java",
                "--with",
                "ca-certificates,tzdata",
                "--owner",
                "Plataforma",
                "--source",
                "https://git/r",
                "--no-pin",
            ],
        )
        assert result.exit_code == EXIT_OK
        content = destination.read_text()
        assert "FROM eclipse-temurin:21-jre-alpine" in content
        assert "ca-certificates" in content
        assert 'maintainer="Plataforma"' in content

    def test_an_existing_file_is_not_overwritten_without_force(self, tmp_path):
        destination = tmp_path / "Dockerfile"
        destination.write_text("FROM scratch\n")
        result = CliRunner().invoke(
            app,
            [
                "base-image",
                "-o",
                str(destination),
                "--os",
                "alpine",
                "--runtime",
                "none",
                "--with",
                "",
                "--no-pin",
            ],
        )
        assert result.exit_code == EXIT_ERROR
        assert destination.read_text() == "FROM scratch\n"

    def test_an_invalid_os_is_refused_with_the_choices(self, tmp_path):
        result = CliRunner().invoke(
            app,
            [
                "base-image",
                "-o",
                str(tmp_path / "D"),
                "--os",
                "arch",
                "--runtime",
                "none",
                "--with",
                "",
                "--no-pin",
            ],
        )
        assert result.exit_code == EXIT_ERROR
        assert "alpine" in result.output


class TestBaseImageBuildsInOneStep:
    def test_the_build_flag_reaches_the_use_case_with_the_gate_on(self, tmp_path):
        # Gerar e construir em dois comandos deixava um vão onde a receita
        # existe e ninguém a mediu.
        with patch("dockerls.application.use_cases.build_image.BuildImageUseCase") as use_case:
            use_case.return_value.execute.return_value.success = True
            CliRunner().invoke(
                app,
                [
                    "base-image",
                    "-o",
                    str(tmp_path / "Dockerfile"),
                    "--os",
                    "alpine",
                    "--runtime",
                    "none",
                    "--with",
                    "",
                    "--no-pin",
                    "--build",
                    "-t",
                    "base:1.0",
                    "--owner",
                    "Plataforma",
                ],
            )
        request = use_case.return_value.execute.call_args.args[0]
        assert request.tag == "base:1.0"
        assert request.fail_on == "critical"
        assert request.labels["maintainer"] == "Plataforma"

    def test_without_the_flag_nothing_is_built(self, tmp_path):
        with patch("dockerls.application.use_cases.build_image.BuildImageUseCase") as use_case:
            result = CliRunner().invoke(
                app,
                [
                    "base-image",
                    "-o",
                    str(tmp_path / "Dockerfile"),
                    "--os",
                    "alpine",
                    "--runtime",
                    "none",
                    "--with",
                    "",
                    "--no-pin",
                ],
            )
        assert result.exit_code == EXIT_OK
        use_case.assert_not_called()


class TestSignFlag:
    """`--sign` -- assinar é afirmar que você publicou estes bytes.

    Emiti-la sobre um artefato que não se sabe de onde veio transforma a
    assinatura em carimbo, e um carimbo é exatamente o que ela não pode ser.
    """

    @staticmethod
    def _response(*, success=True, provenance=None):
        from dockerls.application.use_cases.build_image import BuildImageResponse

        return BuildImageResponse(
            success=success,
            image_tag="reg.io/app:1.0",
            image_sha256="sha256:local",
            provenance=provenance,
            exit_code=0 if success else 1,
        )

    @staticmethod
    def _provenance(*, verified=True, repo_digest="sha256:" + "b" * 64):
        from dockerls.domain.value_objects.provenance import (
            ArtifactDigests,
            BuildProvenance,
            SourceDigests,
        )

        source = SourceDigests(dockerfile="sha256:aa", context="sha256:bb")
        depois = source if verified else SourceDigests(dockerfile="sha256:zz")
        return BuildProvenance(
            tag="reg.io/app:1.0",
            source=source,
            source_after=depois,
            artifact=ArtifactDigests(
                image_id="sha256:local",
                repo_digest=repo_digest,
                published_reference="reg.io/app:1.0",
            ),
        )

    def test_sem_push_a_assinatura_e_ignorada(self):
        from dockerls.cli.commands.build import _sign_if_requested

        assert _sign_if_requested(self._response(), sign=True, publishing=False) is None

    def test_procedencia_nao_verificada_recusa_a_assinatura(self):
        from dockerls.cli.commands.build import _sign_if_requested
        from dockerls.integrations.signing.cosign import SignatureStatus

        result = _sign_if_requested(
            self._response(provenance=self._provenance(verified=False)),
            sign=True,
            publishing=True,
        )

        assert result is not None
        assert result.status is SignatureStatus.FAILED
        assert not result.trustworthy

    def test_sem_digest_do_manifesto_recusa_a_assinatura(self):
        """Assinar a tag assinaria o que ela aponta agora, e ela pode mover."""
        from dockerls.cli.commands.build import _sign_if_requested
        from dockerls.integrations.signing.cosign import SignatureStatus

        result = _sign_if_requested(
            self._response(provenance=self._provenance(repo_digest="")),
            sign=True,
            publishing=True,
        )

        assert result is not None
        assert result.status is SignatureStatus.FAILED
        assert "sem digest" in result.detail

    def test_assina_o_digest_e_nao_a_tag(self):
        from unittest.mock import AsyncMock, patch

        from dockerls.cli.commands.build import _sign_if_requested
        from dockerls.integrations.signing.cosign import SignatureResult, SignatureStatus

        assinado = AsyncMock(
            return_value=SignatureResult(reference="x", status=SignatureStatus.SIGNED)
        )
        with patch("dockerls.integrations.signing.cosign.CosignClient.sign", assinado):
            _sign_if_requested(
                self._response(provenance=self._provenance()),
                sign=True,
                publishing=True,
            )

        alvo = assinado.await_args.args[0]
        assert alvo == "reg.io/app@sha256:" + "b" * 64

    def test_sem_a_flag_nada_e_assinado(self):
        from dockerls.cli.commands.build import _sign_if_requested

        assert (
            _sign_if_requested(
                self._response(provenance=self._provenance()), sign=False, publishing=True
            )
            is None
        )
