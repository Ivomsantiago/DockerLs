"""Testes para o BuildImageUseCase.

Os fixtures mockam `DockerfileValidatorInterface`, que é o que o caso de uso
realmente depende. Antes eles devolviam de `validate()` um objeto no formato
de `AnalyzeDockerfileResponse`; como `BuildImageUseCase` instancia um
`AnalyzeDockerfileUseCase` internamente, esse retorno era envelopado numa
segunda camada e `response.validation.errors` caía num `MagicMock`, que nunca
é igual a `0` -- então todo cenário "sem erros" chegava como reprovado.
"""

from __future__ import annotations

import json
import subprocess
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from dockerls.application.use_cases.analyze_dockerfile import AnalyzeDockerfileResponse
from dockerls.application.use_cases.build_image import (
    BuildImageRequest,
    BuildImageUseCase,
    BuildOptions,
    BuildResult,
    ScanResult,
)
from dockerls.domain.entities.dockerfile_analysis import (
    DockerfileAnalysis,
    DockerfileInfo,
    DockerfileValidationResult,
    HardeningRule,
    SeverityLevel,
    ValidationCheck,
    ValidationStatus,
)
from dockerls.domain.interfaces.dockerfile_validator import (
    DockerfileValidatorInterface,
    HardeningTemplateProvider,
)
from dockerls.domain.value_objects.network_policy import NetworkPolicy
from dockerls.domain.value_objects.provenance import SourceDigests
from dockerls.exit_codes import EXIT_ERROR, EXIT_OK, EXIT_POLICY
from dockerls.infrastructure.dockerfile_validator import DockerfileValidator, HardeningTemplates
from dockerls.infrastructure.network.host_guard import HostGuard
from dockerls.utils.executables import ExecutableNotFoundError


def _validation(
    passed: int = 10,
    warnings: int = 0,
    errors: int = 0,
    checks: list[ValidationCheck] | None = None,
) -> DockerfileValidationResult:
    return DockerfileValidationResult(
        dockerfile_path="Dockerfile",
        passed=passed,
        warnings=warnings,
        errors=errors,
        checks=checks or [],
    )


def _analysis(validation: DockerfileValidationResult, score: int = 90) -> DockerfileAnalysis:
    return DockerfileAnalysis(
        info=DockerfileInfo(),
        validation=validation,
        security_score=score,
        security_tier="A" if score >= 90 else "C",
    )


class TestBuildImageUseCase:
    """Testes para o caso de uso de build de imagem."""

    @pytest.fixture
    def context(self, tmp_path):
        """Diretório de contexto com um Dockerfile real.

        O caso de uso resolve `<context>/Dockerfile` no disco antes de
        chamar o validador, então o arquivo precisa existir mesmo com o
        validador mockado.
        """
        (tmp_path / "Dockerfile").write_text("FROM node:22-alpine\nUSER node\n")
        return tmp_path

    @pytest.fixture
    def validator(self):
        """Mock da interface do validador, com os tipos que ela devolve."""
        mock = MagicMock(spec=DockerfileValidatorInterface)
        validation = _validation()
        mock.validate.return_value = validation
        mock.analyze.return_value = _analysis(validation)
        mock.suggest_hardening.return_value = []
        return mock

    @pytest.fixture
    def template_provider(self):
        return MagicMock(spec=HardeningTemplateProvider)

    @pytest.fixture
    def use_case(self, validator, template_provider):
        return BuildImageUseCase(validator, template_provider)

    def test_build_valid_dockerfile_succeeds(self, use_case, context):
        """Dockerfile sem erros passa na validação com exit 0."""
        response = use_case.execute(
            BuildImageRequest(context_path=str(context), tag="test:latest", validate_only=True)
        )

        assert response.success is True
        assert response.exit_code == EXIT_OK
        assert response.error is None

    def test_validate_only_response_carries_the_checks(self, use_case, validator, context):
        """A resposta precisa levar o resultado da validação inteiro.

        É o defeito que fazia a CLI imprimir `None`: sem `validation` e sem
        `report`, não havia o que renderizar.
        """
        validation = _validation(
            passed=1,
            warnings=1,
            checks=[
                ValidationCheck(
                    check="no_latest_tag",
                    status=ValidationStatus.WARN,
                    message="Base image uses :latest tag",
                ),
            ],
        )
        validator.validate.return_value = validation
        validator.analyze.return_value = _analysis(validation, score=80)

        response = use_case.execute(
            BuildImageRequest(context_path=str(context), tag="test:latest", validate_only=True)
        )

        assert response.validation is validation
        assert [c.check for c in response.validation.checks] == ["no_latest_tag"]
        assert response.report is not None
        assert response.report.validation["checks"][0]["check"] == "no_latest_tag"
        assert response.report.security_score == 80

    def test_validation_fails_on_secrets_in_env(self, use_case, validator, context):
        """Deve rejeitar secrets em ENV, dizendo qual regra falhou."""
        validation = _validation(
            passed=8,
            errors=2,
            checks=[
                ValidationCheck(
                    check="secrets_not_in_env",
                    status=ValidationStatus.FAIL,
                    message="ENV DOCKER_TOKEN detected",
                    line=15,
                ),
                ValidationCheck(
                    check="non_root_user",
                    status=ValidationStatus.FAIL,
                    message="No USER directive found",
                ),
            ],
        )
        validator.validate.return_value = validation
        validator.analyze.return_value = _analysis(validation, score=40)

        response = use_case.execute(
            BuildImageRequest(context_path=str(context), tag="test:latest", validate_only=True)
        )

        assert response.success is False
        # Política violada, não erro de execução: a validação rodou bem.
        assert response.exit_code == EXIT_POLICY
        assert "validation failed" in response.error.lower()
        # O resumo precisa nomear as regras -- é a única coisa que um log de
        # CI guarda quando ninguém está olhando o terminal.
        assert "secrets_not_in_env" in response.error
        assert "line 15" in response.error
        assert "non_root_user" in response.error

    def test_validation_warns_on_latest_tag(self, use_case, validator, context):
        """Warnings não reprovam o build."""
        validation = _validation(
            passed=9,
            warnings=1,
            checks=[
                ValidationCheck(
                    check="no_latest_tag",
                    status=ValidationStatus.WARN,
                    message="Base image uses :latest tag",
                ),
            ],
        )
        validator.validate.return_value = validation
        validator.analyze.return_value = _analysis(validation, score=85)

        response = use_case.execute(
            BuildImageRequest(context_path=str(context), tag="test:latest", validate_only=True)
        )

        assert response.success is True
        assert response.exit_code == EXIT_OK

    def test_missing_dockerfile_is_an_execution_error(self, use_case, tmp_path):
        """Dockerfile inexistente é exit 1, não 2: nada foi medido."""
        response = use_case.execute(
            BuildImageRequest(context_path=str(tmp_path), tag="test:latest", validate_only=True)
        )

        assert response.success is False
        assert response.exit_code == EXIT_ERROR
        assert "not found" in response.error.lower()

    def test_validation_errors_block_the_build(self, use_case, validator, context):
        """Um Dockerfile reprovado não chega a ser construído.

        O portão antigo era `if not validation_result`, e um objeto é sempre
        verdadeiro -- então nunca disparava.
        """
        validation = _validation(passed=1, errors=1)
        validator.validate.return_value = validation
        validator.analyze.return_value = _analysis(validation, score=20)

        with patch.object(use_case, "_build_image") as mock_build:
            response = use_case.execute(
                BuildImageRequest(context_path=str(context), tag="test:latest", scan=False)
            )

        mock_build.assert_not_called()
        assert response.success is False
        assert response.exit_code == EXIT_POLICY

    def test_force_builds_despite_validation_errors(self, use_case, validator, context):
        """`--force` é a saída documentada para construir mesmo reprovado."""
        validation = _validation(passed=1, errors=1)
        validator.validate.return_value = validation
        validator.analyze.return_value = _analysis(validation, score=20)

        with patch.object(use_case, "_build_image") as mock_build:
            mock_build.return_value = BuildResult(success=True, image_tag="test:latest")
            response = use_case.execute(
                BuildImageRequest(
                    context_path=str(context), tag="test:latest", scan=False, force=True
                )
            )

        mock_build.assert_called_once()
        assert response.success is True
        assert response.exit_code == EXIT_OK

    def test_suggests_hardening_rules(self, use_case, validator, context):
        """Deve sugerir melhorias de hardening."""
        validator.suggest_hardening.return_value = [
            HardeningRule(
                priority=SeverityLevel.HIGH,
                title="Add non-root user",
                description="Container should run as non-root",
                current_state="Running as root",
                suggested_fix="USER appuser",
                reason="Security best practice",
            ),
        ]

        response = use_case.execute(
            BuildImageRequest(context_path=str(context), tag="test:latest", suggest_only=True)
        )

        assert response.success is True
        assert response.exit_code == EXIT_OK
        assert [r.title for r in response.recommendations] == ["Add non-root user"]

    def test_validate_only_does_not_write_hardened_dockerfile(self, validator, context):
        """`--validate-only` é dry-run: não pode escrever em disco.

        Com um provider real, gerar o arquivo seria efeito colateral de um
        comando que o usuário pediu para não construir nada.
        """
        use_case = BuildImageUseCase(validator, HardeningTemplates())

        response = use_case.execute(
            BuildImageRequest(
                context_path=str(context),
                tag="test:latest",
                hardened=True,
                base_template="node",
                validate_only=True,
            )
        )

        assert response.success is True
        assert not (context / "Dockerfile.hardened").exists()

    def test_hardened_build_writes_dockerfile(self, validator, context):
        """Sem `--validate-only`, o template hardened vai para o disco.

        A escrita acontece na infraestrutura, por trás de
        `generate_hardened_dockerfile()`, e não no caso de uso.
        """
        use_case = BuildImageUseCase(validator, HardeningTemplates())

        with patch.object(use_case, "_build_image") as mock_build:
            mock_build.return_value = BuildResult(success=True, image_tag="test:latest")
            response = use_case.execute(
                BuildImageRequest(
                    context_path=str(context),
                    tag="test:latest",
                    hardened=True,
                    base_template="node",
                    scan=False,
                )
            )

        hardened_path = context / "Dockerfile.hardened"
        assert response.success is True
        assert hardened_path.exists()
        assert "FROM" in hardened_path.read_text()
        # E é esse arquivo que o build recebe, não o Dockerfile original.
        assert mock_build.call_args.kwargs["dockerfile_path"] == str(hardened_path)

    def test_ci_mode_returns_json_only(self, use_case, context):
        """CI mode não muda o veredito, só a formatação (feita na CLI)."""
        response = use_case.execute(
            BuildImageRequest(
                context_path=str(context),
                tag="test:latest",
                ci_mode=True,
                validate_only=True,
            )
        )

        assert response.success is True
        assert response.exit_code == EXIT_OK
        assert response.report is not None

    def test_fail_on_critical_reproofs_build(self, use_case, context):
        """`--fail-on critical` é violação de política: exit 2."""
        with (
            patch.object(use_case, "_scan_image") as mock_scan,
            patch.object(use_case, "_build_image") as mock_build,
        ):
            mock_scan.return_value = ScanResult(critical=2, high=0, medium=5, low=10)
            mock_build.return_value = BuildResult(
                success=True, image_tag="test:latest", image_sha256="sha256:abc123"
            )

            response = use_case.execute(
                BuildImageRequest(
                    context_path=str(context),
                    tag="test:latest",
                    scan=True,
                    fail_on="critical",
                )
            )

        assert response.success is False
        assert response.exit_code == EXIT_POLICY
        assert "Gate failed (severity)" in response.error

    def test_fail_on_without_a_scan_is_an_execution_error(self, use_case, context):
        """Um portão que não pôde ser avaliado não é um portão aprovado.

        Numa máquina sem trivy nem grype, `--fail-on critical` deixava passar
        qualquer imagem, com exit 0.
        """
        with (
            patch.object(use_case, "_build_image") as mock_build,
            patch.object(use_case, "_scan_image", return_value=None),
        ):
            mock_build.return_value = BuildResult(success=True, image_tag="test:latest")
            response = use_case.execute(
                BuildImageRequest(
                    context_path=str(context),
                    tag="test:latest",
                    scan=True,
                    fail_on="critical",
                )
            )

        assert response.success is False
        assert response.exit_code == EXIT_ERROR
        assert "no scanner" in response.error

    def test_production_without_a_scanner_is_an_execution_error_not_a_pass(self, use_case, context):
        """`--production` sets `fail_on="critical"` through `BuildPolicy.production()`,
        the same gate `--fail-on critical` sets by hand. A CI runner with neither trivy
        nor grype installed must fail this exactly like the explicit flag does -- never
        publish an image nobody scanned, and never report it as if 0 vulnerabilities
        were an actual measurement.
        """
        from dockerls.domain.value_objects.build_policy import BuildPolicy

        with (
            patch.object(use_case, "_build_image") as mock_build,
            patch.object(use_case, "_scan_image", return_value=None),
        ):
            mock_build.return_value = BuildResult(success=True, image_tag="test:latest")
            response = use_case.execute(
                BuildImageRequest(
                    context_path=str(context),
                    tag="test:latest",
                    scan=True,
                    policy=BuildPolicy.production(),
                )
            )

        assert response.success is False
        assert response.exit_code == EXIT_ERROR
        assert "no scanner" in response.error
        assert "0 vulnerabilit" not in (response.error or "").lower()

    def test_docker_build_failure_is_an_execution_error(self, use_case, context):
        """Erro do `docker build` é exit 1: infraestrutura, não política."""
        with patch.object(use_case, "_build_image") as mock_build:
            mock_build.return_value = BuildResult(
                success=False, error_message="Build failed: no such file"
            )
            response = use_case.execute(
                BuildImageRequest(context_path=str(context), tag="test:latest", scan=False)
            )

        assert response.success is False
        assert response.exit_code == EXIT_ERROR

    def test_security_score_calculation(self, use_case):
        """Testa cálculo do security score."""
        analyze_response = AnalyzeDockerfileResponse(
            success=True,
            validation=_validation(passed=8, warnings=2, errors=0),
        )
        scan_result = ScanResult(critical=0, high=1, medium=3, low=5)

        score = use_case._calculate_security_score(analyze_response, scan_result)

        # 100 - (0*10) - (2*3) - (0*15) - (1*10) - (3*3) - (5*1) = 70
        assert score == 70

    def test_security_tier_calculation(self, use_case):
        """Testa cálculo do security tier."""
        assert use_case._calculate_security_tier(95) == "A"
        assert use_case._calculate_security_tier(80) == "B"
        assert use_case._calculate_security_tier(65) == "C"
        assert use_case._calculate_security_tier(50) == "D"
        assert use_case._calculate_security_tier(30) == "F"

    def test_report_generation(self, use_case):
        """Deve gerar relatório JSON válido."""
        validation = _validation(passed=10)
        analyze_response = AnalyzeDockerfileResponse(
            success=True,
            validation=validation,
            analysis=_analysis(validation),
            suggestions=[
                HardeningRule(
                    priority=SeverityLevel.MEDIUM,
                    title="Add HEALTHCHECK",
                    description="No health check",
                    current_state="absent",
                    suggested_fix="HEALTHCHECK ...",
                    reason="orchestrators need it",
                ),
            ],
        )

        report = use_case._generate_report(
            validation=analyze_response,
            build=BuildResult(
                success=True,
                image_tag="test:latest",
                image_sha256="sha256:abc123",
                build_time_seconds=45.0,
            ),
            scan=ScanResult(critical=0, high=0, medium=2, low=5),
            image_tag="test:latest",
            dockerfile_path="Dockerfile",
        )

        assert report.build_id is not None
        assert report.timestamp is not None
        assert report.image == "test:latest"
        assert report.security_score > 0
        assert report.security_tier in ["A", "B", "C", "D", "F"]
        assert isinstance(report.validation, dict)
        assert report.scan_results is not None
        # As recomendações vêm das sugestões de hardening; ler
        # `analysis.recommendations` era acesso a um atributo inexistente.
        assert report.recommendations[0]["title"] == "Add HEALTHCHECK"

    def test_git_sha_extraction(self, use_case):
        """Testa extração do git SHA."""
        git_sha = use_case._get_git_sha()
        assert git_sha is None or len(git_sha) == 40

    def test_docker_version_extraction(self, use_case):
        """Testa extração da versão do Docker."""
        assert isinstance(use_case._get_docker_version(), str)


class _CompletedProcess:
    """Substituto de `subprocess.CompletedProcess` para os testes."""

    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


TRIVY_OUTPUT = json.dumps(
    {
        "Results": [
            {
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2026-0001",
                        "PkgName": "openssl",
                        "Severity": "CRITICAL",
                        "InstalledVersion": "3.0.11",
                        "FixedVersion": "3.0.12",
                    },
                    {
                        "VulnerabilityID": "CVE-2026-0002",
                        "PkgName": "perl-base",
                        "Severity": "HIGH",
                        "InstalledVersion": "5.36.0",
                    },
                    {
                        "VulnerabilityID": "CVE-2026-0003",
                        "PkgName": "zlib",
                        "Severity": "MEDIUM",
                        "InstalledVersion": "1.2",
                        "FixedVersion": "1.3",
                    },
                    {
                        "VulnerabilityID": "CVE-2026-0004",
                        "PkgName": "bash",
                        "Severity": "LOW",
                        "InstalledVersion": "5.1",
                    },
                    {
                        "VulnerabilityID": "CVE-2026-0005",
                        "PkgName": "misc",
                        "Severity": "SOMETHING-ELSE",
                        "InstalledVersion": "1.0",
                    },
                ]
            }
        ]
    }
)


@pytest.fixture
def bare_use_case():
    return BuildImageUseCase(
        MagicMock(spec=DockerfileValidatorInterface), MagicMock(spec=HardeningTemplateProvider)
    )


class TestDockerBuildInvocation:
    """`docker build` é montado à mão; um argumento errado silenciosamente
    constrói a imagem errada."""

    def _run(self, use_case, options, **kwargs):
        with (
            patch("dockerls.application.use_cases.build_image.resolve_executable") as resolve,
            patch("dockerls.application.use_cases.build_image.subprocess.run") as run,
            patch.object(use_case, "_get_image_info", return_value={}),
        ):
            resolve.side_effect = lambda name: f"/usr/bin/{name}"
            run.return_value = _CompletedProcess(returncode=kwargs.get("returncode", 0))
            result = use_case._build_image(
                context_path=options.context_path,
                dockerfile_path=options.dockerfile_path,
                tag=options.tag,
                options=options,
            )
        return result, run

    def test_passes_tag_dockerfile_and_context(self, bare_use_case):
        options = BuildOptions(tag="app:1.0", dockerfile_path="Dockerfile", context_path="./ctx")
        _, run = self._run(bare_use_case, options)

        argv = run.call_args.args[0]
        assert argv[0] == "/usr/bin/docker"
        assert argv[1] == "build"
        assert argv[argv.index("-t") + 1] == "app:1.0"
        assert argv[argv.index("-f") + 1] == "Dockerfile"
        assert argv[-1] == "./ctx"

    def test_forwards_build_args_labels_and_no_cache(self, bare_use_case):
        options = BuildOptions(
            tag="app:1.0",
            no_cache=True,
            build_args={"NODE_ENV": "production"},
            labels={"org.opencontainers.image.source": "repo"},
        )
        _, run = self._run(bare_use_case, options)

        argv = run.call_args.args[0]
        assert "--no-cache" in argv
        assert "NODE_ENV=production" in argv
        assert "org.opencontainers.image.source=repo" in argv

    def test_enables_buildkit_through_the_environment(self, bare_use_case):
        """BuildKit é ligado por variável de ambiente; a flag antiga que o
        código montava e descartava nunca fez nada."""
        _, run = self._run(bare_use_case, BuildOptions(tag="app:1.0", buildkit=True))

        assert run.call_args.kwargs["env"]["DOCKER_BUILDKIT"] == "1"

    def test_non_zero_exit_is_a_failure_carrying_stderr(self, bare_use_case):
        with (
            patch("dockerls.application.use_cases.build_image.resolve_executable") as resolve,
            patch("dockerls.application.use_cases.build_image.subprocess.run") as run,
        ):
            resolve.side_effect = lambda name: f"/usr/bin/{name}"
            run.return_value = _CompletedProcess(returncode=1, stderr="no such file")
            result = bare_use_case._build_image(
                ".", "Dockerfile", "app:1", BuildOptions(tag="app:1")
            )

        assert result.success is False
        assert "no such file" in result.error_message

    def test_missing_docker_fails_with_a_named_message(self, bare_use_case):
        with patch("dockerls.application.use_cases.build_image.resolve_executable") as resolve:
            resolve.side_effect = ExecutableNotFoundError("docker")
            result = bare_use_case._build_image(
                ".", "Dockerfile", "app:1", BuildOptions(tag="app:1")
            )

        assert result.success is False
        assert "docker" in result.error_message

    def test_timeout_is_reported_as_such(self, bare_use_case):
        with (
            patch("dockerls.application.use_cases.build_image.resolve_executable") as resolve,
            patch("dockerls.application.use_cases.build_image.subprocess.run") as run,
        ):
            resolve.side_effect = lambda name: f"/usr/bin/{name}"
            run.side_effect = subprocess.TimeoutExpired(cmd="docker", timeout=3600)
            result = bare_use_case._build_image(
                ".", "Dockerfile", "app:1", BuildOptions(tag="app:1")
            )

        assert result.success is False
        assert "timeout" in result.error_message.lower()


class TestScanParsing:
    """As contagens que saem daqui são as que `--fail-on` usa para reprovar
    um build. Um erro de parsing deixa passar a imagem que deveria barrar."""

    def test_counts_each_severity_and_the_fixable_ones(self, bare_use_case):
        with (
            patch("dockerls.application.use_cases.build_image.resolve_executable") as resolve,
            patch("dockerls.application.use_cases.build_image.subprocess.run") as run,
        ):
            resolve.side_effect = lambda name: f"/usr/bin/{name}"
            run.return_value = _CompletedProcess(returncode=0, stdout=TRIVY_OUTPUT)
            scan = bare_use_case._scan_image("app:1.0")

        assert scan is not None
        assert (scan.critical, scan.high, scan.medium, scan.low) == (1, 1, 1, 1)
        # Severidade desconhecida não pode ser descartada nem contada como LOW.
        assert scan.unknown == 1
        assert scan.total_vulnerabilities == 5
        assert scan.fixable == 2
        assert scan.scan_tool == "trivy"

    def test_grype_output_is_actually_parsed(self, bare_use_case):
        """O fallback devolvia um `ScanResult()` zerado com um comentário
        "parse similar ao Trivy...". Numa máquina só com Grype, todo build
        era reportado com zero vulnerabilidades e passava em `--fail-on`.
        """
        grype_output = json.dumps(
            {
                "matches": [
                    {
                        "vulnerability": {
                            "id": "CVE-2026-1",
                            "severity": "Critical",
                            "fix": {"versions": ["3.0.12"]},
                        },
                        "artifact": {"name": "openssl", "version": "3.0.11"},
                    },
                    {
                        "vulnerability": {"id": "CVE-2026-2", "severity": "High"},
                        "artifact": {"name": "curl", "version": "7.88"},
                    },
                    # Faixa que só o Grype tem: precisa virar LOW, não sumir.
                    {
                        "vulnerability": {"id": "CVE-2026-3", "severity": "Negligible"},
                        "artifact": {"name": "bash", "version": "5.1"},
                    },
                ]
            }
        )

        def resolve(name):
            if name == "trivy":
                raise ExecutableNotFoundError("trivy")
            return f"/usr/bin/{name}"

        with (
            patch(
                "dockerls.application.use_cases.build_image.resolve_executable", side_effect=resolve
            ),
            patch("dockerls.application.use_cases.build_image.subprocess.run") as run,
        ):
            run.return_value = _CompletedProcess(returncode=0, stdout=grype_output)
            scan = bare_use_case._scan_image("app:1.0")

        assert scan is not None
        assert scan.scan_tool == "grype"
        assert (scan.critical, scan.high, scan.low) == (1, 1, 1)
        assert scan.total_vulnerabilities == 3
        assert scan.fixable == 1
        # E o resultado precisa reprovar um portão que antes ele deixava passar.
        assert bare_use_case._should_fail(scan, "critical") is True

    def test_falls_back_to_grype_when_trivy_is_absent(self, bare_use_case):
        def resolve(name):
            if name == "trivy":
                raise ExecutableNotFoundError("trivy")
            return f"/usr/bin/{name}"

        with (
            patch(
                "dockerls.application.use_cases.build_image.resolve_executable", side_effect=resolve
            ),
            patch("dockerls.application.use_cases.build_image.subprocess.run") as run,
        ):
            run.return_value = _CompletedProcess(returncode=0, stdout='{"matches": []}')
            scan = bare_use_case._scan_image("app:1.0")

        assert scan is not None
        assert scan.scan_tool == "grype"

    def test_returns_none_when_no_scanner_is_installed(self, bare_use_case):
        with patch("dockerls.application.use_cases.build_image.resolve_executable") as resolve:
            resolve.side_effect = ExecutableNotFoundError("trivy")
            assert bare_use_case._scan_image("app:1.0") is None

    def test_malformed_scanner_output_does_not_raise(self, bare_use_case):
        with (
            patch("dockerls.application.use_cases.build_image.resolve_executable") as resolve,
            patch("dockerls.application.use_cases.build_image.subprocess.run") as run,
        ):
            resolve.side_effect = lambda name: f"/usr/bin/{name}"
            run.return_value = _CompletedProcess(returncode=0, stdout="not json")
            assert bare_use_case._scan_image("app:1.0") is None


class TestScanTargetIsGuarded:
    """`trivy image X` / `grype X` open their own connection -- the same
    SSRF door `blocked_target_reason` closes for every other scanner path.
    A Dockerfile's `FROM 169.254.169.254/latest:v1` reaches here through
    `--attribute`/`--production`, which scan the declared base directly."""

    @pytest.fixture
    def guarded_use_case(self):
        # Loopback/link-local blocked by default; this is the SSRF case.
        guard = HostGuard(NetworkPolicy(allow_loopback=False, allow_link_local=False))
        return BuildImageUseCase(
            MagicMock(spec=DockerfileValidatorInterface),
            MagicMock(spec=HardeningTemplateProvider),
            guard=guard,
        )

    def test_a_link_local_target_is_never_handed_to_the_scanner(self, guarded_use_case):
        with (
            patch("dockerls.application.use_cases.build_image.resolve_executable") as resolve,
            patch("dockerls.application.use_cases.build_image.subprocess.run") as run,
        ):
            resolve.side_effect = lambda name: f"/usr/bin/{name}"
            result = guarded_use_case._scan_image("169.254.169.254/latest:v1")

        assert result is None
        run.assert_not_called()

    def test_a_loopback_registry_target_is_blocked(self, guarded_use_case):
        with (
            patch("dockerls.application.use_cases.build_image.resolve_executable") as resolve,
            patch("dockerls.application.use_cases.build_image.subprocess.run") as run,
        ):
            resolve.side_effect = lambda name: f"/usr/bin/{name}"
            result = guarded_use_case._scan_image("127.0.0.1:5000/evil:1")

        assert result is None
        run.assert_not_called()

    def test_a_public_registry_target_is_still_scanned(self, guarded_use_case):
        with (
            patch("dockerls.application.use_cases.build_image.resolve_executable") as resolve,
            patch("dockerls.application.use_cases.build_image.subprocess.run") as run,
        ):
            resolve.side_effect = lambda name: f"/usr/bin/{name}"
            run.return_value = _CompletedProcess(returncode=0, stdout=TRIVY_OUTPUT)
            result = guarded_use_case._scan_image("node:22-alpine")

        assert result is not None
        run.assert_called_once()

    def test_no_guard_configured_still_scans_local_and_registry_alike(self, bare_use_case):
        """`bare_use_case` carries no guard (tests, and callers that never
        wire one) -- unchanged behaviour: nothing here narrows an existing
        caller that has not opted in."""
        with (
            patch("dockerls.application.use_cases.build_image.resolve_executable") as resolve,
            patch("dockerls.application.use_cases.build_image.subprocess.run") as run,
        ):
            resolve.side_effect = lambda name: f"/usr/bin/{name}"
            run.return_value = _CompletedProcess(returncode=0, stdout=TRIVY_OUTPUT)
            result = bare_use_case._scan_image("169.254.169.254/latest:v1")

        assert result is not None
        run.assert_called_once()

    def test_an_invalid_reference_is_refused_before_it_reaches_the_scanner(self, bare_use_case):
        with (
            patch("dockerls.application.use_cases.build_image.resolve_executable") as resolve,
            patch("dockerls.application.use_cases.build_image.subprocess.run") as run,
        ):
            resolve.side_effect = lambda name: f"/usr/bin/{name}"
            result = bare_use_case._scan_image("--offline-scan")

        assert result is None
        run.assert_not_called()


class TestFailOnThreshold:
    @pytest.mark.parametrize(
        ("threshold", "scan", "expected"),
        [
            ("critical", ScanResult(critical=1), True),
            ("critical", ScanResult(high=9), False),
            ("high", ScanResult(high=1), True),
            ("high", ScanResult(critical=1), True),
            ("high", ScanResult(medium=50), False),
            # `medium` e `low` caíam num `return False`: eram portões que
            # nunca reprovavam, em silêncio.
            ("medium", ScanResult(critical=1), True),
            ("medium", ScanResult(medium=1), True),
            ("medium", ScanResult(low=99), False),
            ("low", ScanResult(low=1), True),
            ("low", ScanResult(), False),
        ],
    )
    def test_threshold_semantics(self, bare_use_case, threshold, scan, expected):
        """`--fail-on high` também reprova em CRITICAL: um limiar que ignora
        o que é pior que ele não é um limiar."""
        assert bare_use_case._should_fail(scan, threshold) is expected

    def test_unknown_threshold_raises_instead_of_passing(self, bare_use_case):
        """Falhar alto é a única opção segura: devolver False para um limiar
        que não se entende é um portão aberto que parece fechado."""
        with pytest.raises(ValueError, match="unknown --fail-on gate"):
            bare_use_case._should_fail(ScanResult(critical=5), "kritikal")


class TestImageInfo:
    def test_parses_docker_inspect_output(self, bare_use_case):
        payload = json.dumps([{"Id": "sha256:abc", "Size": 1234, "RootFS": {"Layers": ["a", "b"]}}])
        with (
            patch("dockerls.application.use_cases.build_image.resolve_executable") as resolve,
            patch("dockerls.application.use_cases.build_image.subprocess.run") as run,
        ):
            resolve.side_effect = lambda name: f"/usr/bin/{name}"
            run.return_value = _CompletedProcess(returncode=0, stdout=payload)
            info = bare_use_case._get_image_info("app:1.0")

        assert info["Id"] == "sha256:abc"

    def test_missing_docker_degrades_to_empty_info(self, bare_use_case):
        with patch("dockerls.application.use_cases.build_image.resolve_executable") as resolve:
            resolve.side_effect = ExecutableNotFoundError("docker")
            assert bare_use_case._get_image_info("app:1.0") == {}


if __name__ == "__main__":
    pytest.main([__file__, "-v"])


class TestFailOnGateNamesTheOffenders:
    """`Vulnerabilities exceed threshold (critical)` obriga quem lê o log do
    CI a reabrir o relatório para descobrir *o quê* reprovou."""

    def _scan(self, **counts):
        from dockerls.application.use_cases.build_image import ScanResult as BuildScanResult

        vulns = []
        for severity, n in counts.items():
            vulns += [
                {
                    "cve_id": f"CVE-{severity[:1].upper()}{i}",
                    "severity": severity.upper(),
                    "package": "openssl",
                    "installed_version": "1.0",
                    "fixed_version": "1.1" if i % 2 == 0 else None,
                }
                for i in range(n)
            ]
        return BuildScanResult(
            critical=counts.get("critical", 0),
            high=counts.get("high", 0),
            medium=counts.get("medium", 0),
            low=counts.get("low", 0),
            vulnerabilities=vulns,
        )

    def _use_case(self):
        from unittest.mock import MagicMock

        from dockerls.application.use_cases.build_image import BuildImageUseCase

        return BuildImageUseCase(MagicMock(), MagicMock())

    def test_it_names_the_cves(self):
        summary = self._use_case()._gate_failure_summary(self._scan(critical=2), "critical")

        assert "CVE-C0" in summary
        assert "CVE-C1" in summary
        assert "2 finding(s)" in summary

    def test_it_includes_the_fix_when_there_is_one(self):
        summary = self._use_case()._gate_failure_summary(self._scan(critical=1), "critical")

        assert "-> 1.1" in summary

    def test_it_says_so_when_there_is_no_fix(self):
        scan = self._scan(critical=2)
        summary = self._use_case()._gate_failure_summary(scan, "critical")

        assert "(no fix)" in summary

    def test_a_lower_threshold_also_lists_the_severer_findings(self):
        summary = self._use_case()._gate_failure_summary(self._scan(critical=1, high=1), "high")

        assert "CVE-C0" in summary
        assert "CVE-H0" in summary

    def test_it_does_not_list_findings_below_the_threshold(self):
        summary = self._use_case()._gate_failure_summary(
            self._scan(critical=1, medium=3), "critical"
        )

        assert "CVE-M0" not in summary

    def test_long_lists_are_capped_but_counted(self):
        summary = self._use_case()._gate_failure_summary(self._scan(critical=25), "critical")

        assert "25 finding(s)" in summary
        assert "and 15 more" in summary


class TestGateReportsWhatTrippedIt:
    """A amostra do relatório não pode contradizer o portão.

    Caso real: um build reprovou com "0 finding(s) at or above CRITICAL". O
    portão estava certo -- as *contagens* vinham do scan completo e havia
    CRITICAL. O resumo, não: ele procurava os culpados na amostra, que era
    `vulnerabilities[:100]` cortada na ordem em que o scanner devolveu (ordem
    de pacote, não de gravidade). Numa imagem com mais de cem achados, as
    CRITICAL caíam fora da amostra e o leitor recebia uma reprovação que se
    contradizia, sem nenhum CVE para investigar.
    """

    def _trivy_payload(self, criticals: int, lows: int) -> dict:
        vulns = [
            {
                "VulnerabilityID": f"CVE-LOW-{i}",
                "PkgName": f"pkg{i}",
                "Severity": "LOW",
                "InstalledVersion": "1.0",
            }
            for i in range(lows)
        ]
        vulns += [
            {
                "VulnerabilityID": f"CVE-CRIT-{i}",
                "PkgName": f"crit{i}",
                "Severity": "CRITICAL",
                "InstalledVersion": "1.0",
                "FixedVersion": "1.1",
            }
            for i in range(criticals)
        ]
        return {"Results": [{"Vulnerabilities": vulns}]}

    def test_criticals_survive_the_sample_even_when_listed_last(self):
        # 150 LOW antes de 2 CRITICAL: no corte antigo, em ordem de scanner,
        # as duas CRITICAL não entravam nos primeiros 100.
        result = BuildImageUseCase._parse_trivy_scan(self._trivy_payload(criticals=2, lows=150))
        assert result.critical == 2
        retained = [v["severity"] for v in result.vulnerabilities]
        assert retained.count("CRITICAL") == 2
        assert retained[:2] == ["CRITICAL", "CRITICAL"]

    def test_the_summary_counts_the_scan_not_the_sample(self):
        use_case = BuildImageUseCase(MagicMock(), MagicMock())
        scan = BuildImageUseCase._parse_trivy_scan(self._trivy_payload(criticals=2, lows=150))
        summary = use_case._gate_failure_summary(scan, "critical")
        assert "2 finding(s) at or above CRITICAL" in summary
        assert "CVE-CRIT-0" in summary

    def test_a_clean_image_never_reaches_the_summary(self):
        use_case = BuildImageUseCase(MagicMock(), MagicMock())
        scan = BuildImageUseCase._parse_trivy_scan(self._trivy_payload(criticals=0, lows=5))
        assert use_case._should_fail(scan, "critical") is False

    def test_the_sample_stays_bounded(self):
        result = BuildImageUseCase._parse_trivy_scan(self._trivy_payload(criticals=0, lows=500))
        assert len(result.vulnerabilities) == BuildImageUseCase.MAX_RETAINED_VULNERABILITIES
        assert result.low == 500


class TestPushRefusesABrokenChain:
    """A entrada mudou durante o build: a imagem existe, mas não é a medida.

    Publicá-la seria distribuir um artefato cuja procedência esta ferramenta
    acabou de declarar quebrada -- a mesma substituição que ela recusa em todo
    lugar.
    """

    def _use_case(self, tmp_path, digests):
        (tmp_path / "Dockerfile").write_text("FROM python:3.12-alpine\nUSER 1001\n")
        use_case = BuildImageUseCase(DockerfileValidator(), HardeningTemplates())
        use_case._digest_source = MagicMock(side_effect=digests)
        use_case._build_image = MagicMock(
            return_value=BuildResult(success=True, image_tag="app:1.0", image_sha256="sha256:cc")
        )
        use_case._scan_image = MagicMock(return_value=None)
        use_case._get_image_info = MagicMock(return_value={})
        use_case._push_image = MagicMock(return_value=None)
        return use_case

    def _request(self, tmp_path):
        return BuildImageRequest(
            context_path=str(tmp_path),
            tag="app:1.0",
            scan=False,
            push=True,
            push_reference="meuacr.azurecr.io/apps/app:1.0",
            force=True,
        )

    def test_a_changed_input_blocks_the_push(self, tmp_path):
        changed = [
            SourceDigests(dockerfile="sha256:aa", context="sha256:bb"),
            SourceDigests(dockerfile="sha256:OUTRO", context="sha256:bb"),
        ]
        use_case = self._use_case(tmp_path, changed)
        response = use_case.execute(self._request(tmp_path))

        assert response.success is False
        assert response.exit_code == EXIT_POLICY
        assert "does not correspond to the input" in (response.error or "")
        use_case._push_image.assert_not_called()

    def test_a_stable_input_publishes_normally(self, tmp_path):
        stable = SourceDigests(dockerfile="sha256:aa", context="sha256:bb")
        use_case = self._use_case(tmp_path, [stable, stable])
        response = use_case.execute(self._request(tmp_path))

        assert response.success is True
        use_case._push_image.assert_called_once()
        assert response.provenance is not None
        assert response.provenance.is_verified is True


class TestReportCarriesTheCitations:
    """O relatório é o arquivo que vai para auditoria.

    O terminal citava o controle publicado (CIS 4.1, NIST 4.1.2) e o relatório
    perdia a citação -- exatamente onde ela vale mais, diante de quem precisa
    mapear achado para programa de conformidade.
    """

    def _validation(self, tmp_path):
        (tmp_path / "Dockerfile").write_text("FROM python:3.12-alpine\n")
        return DockerfileValidator().validate(tmp_path)

    def test_checks_carry_rule_id_references_and_rationale(self, tmp_path):
        document = BuildImageUseCase._validation_dict(self._validation(tmp_path))
        checks = document["checks"]
        assert checks
        for check in checks:
            assert "rule_id" in check
            assert "references" in check
            assert "rationale" in check

    def test_a_documented_rule_names_its_control(self, tmp_path):
        document = BuildImageUseCase._validation_dict(self._validation(tmp_path))
        non_root = next(c for c in document["checks"] if c["rule_id"] == "DF002")
        assert any("CIS Docker Benchmark 4.1" in ref for ref in non_root["references"])
        assert non_root["rationale"]


class TestPolicyGate:
    """A política de `.dockerls-policy.yaml`, conferida contra o que o build mediu.

    Ela existe porque `--fail-on` mora na linha de comando, e uma regra que
    mora na linha de comando é uma regra que cada pipeline reescreve à mão.
    """

    @pytest.fixture
    def context(self, tmp_path):
        (tmp_path / "Dockerfile").write_text("FROM node:22-alpine\nUSER node\n")
        return tmp_path

    @pytest.fixture
    def use_case(self, tmp_path):
        validation = _validation()
        validator = MagicMock(spec=DockerfileValidatorInterface)
        validator.validate.return_value = validation
        validator.analyze.return_value = _analysis(validation)
        return BuildImageUseCase(validator, MagicMock())

    def test_base_sem_digest_reprova_o_build(self, use_case, context):
        from dockerls.domain.value_objects.build_policy import BuildPolicy

        with patch.object(use_case, "_build_image") as mock_build:
            mock_build.return_value = BuildResult(
                success=True, image_tag="test:latest", image_sha256="sha256:abc"
            )
            response = use_case.execute(
                BuildImageRequest(
                    context_path=str(context),
                    tag="test:latest",
                    scan=False,
                    policy=BuildPolicy(require_pinned_bases=True),
                )
            )

        assert response.exit_code == EXIT_POLICY
        assert response.policy_violations
        assert "node:22-alpine" in response.policy_violations[0].message

    def test_a_politica_nao_afrouxa_o_que_a_linha_de_comando_apertou(self, use_case, context):
        """Senão bastaria commitar um YAML para publicar o que não passaria."""
        from dockerls.domain.value_objects.build_policy import BuildPolicy

        with (
            patch.object(use_case, "_scan_image") as mock_scan,
            patch.object(use_case, "_build_image") as mock_build,
        ):
            mock_scan.return_value = ScanResult(critical=3, high=0, medium=0, low=0)
            mock_build.return_value = BuildResult(
                success=True, image_tag="test:latest", image_sha256="sha256:abc"
            )
            response = use_case.execute(
                BuildImageRequest(
                    context_path=str(context),
                    tag="test:latest",
                    scan=True,
                    fail_on="critical",
                    policy=BuildPolicy(fail_on="low"),
                )
            )

        assert response.exit_code == EXIT_POLICY
        assert "Gate failed (severity)" in response.error

    def test_a_politica_aperta_o_que_a_linha_de_comando_nao_pediu(self, use_case, context):
        from dockerls.domain.value_objects.build_policy import BuildPolicy

        with (
            patch.object(use_case, "_scan_image") as mock_scan,
            patch.object(use_case, "_build_image") as mock_build,
        ):
            mock_scan.return_value = ScanResult(critical=0, high=1, medium=0, low=0)
            mock_build.return_value = BuildResult(
                success=True, image_tag="test:latest", image_sha256="sha256:abc"
            )
            response = use_case.execute(
                BuildImageRequest(
                    context_path=str(context),
                    tag="test:latest",
                    scan=True,
                    policy=BuildPolicy(fail_on="high"),
                )
            )

        assert response.exit_code == EXIT_POLICY

    def test_imagem_que_viola_a_politica_nao_e_publicada(self, use_case, context):
        """O portão vem antes do push pelo mesmo motivo do portão de scan."""
        from dockerls.domain.value_objects.build_policy import BuildPolicy

        with (
            patch.object(use_case, "_build_image") as mock_build,
            patch.object(use_case, "_push_image") as mock_push,
        ):
            mock_build.return_value = BuildResult(
                success=True, image_tag="test:latest", image_sha256="sha256:abc"
            )
            response = use_case.execute(
                BuildImageRequest(
                    context_path=str(context),
                    tag="test:latest",
                    scan=False,
                    push=True,
                    policy=BuildPolicy(required_labels=("owner",)),
                )
            )

        assert response.exit_code == EXIT_POLICY
        mock_push.assert_not_called()

    def test_politica_cumprida_deixa_o_build_passar(self, use_case, context):
        from dockerls.domain.value_objects.build_policy import BuildPolicy

        with patch.object(use_case, "_build_image") as mock_build:
            mock_build.return_value = BuildResult(
                success=True, image_tag="test:latest", image_sha256="sha256:abc"
            )
            response = use_case.execute(
                BuildImageRequest(
                    context_path=str(context),
                    tag="test:latest",
                    scan=False,
                    labels={"owner": "Plataforma"},
                    policy=BuildPolicy(required_labels=("owner",)),
                )
            )

        assert response.exit_code == EXIT_OK
        assert not response.policy_violations

    def test_sem_politica_nada_muda(self, use_case, context):
        with patch.object(use_case, "_build_image") as mock_build:
            mock_build.return_value = BuildResult(
                success=True, image_tag="test:latest", image_sha256="sha256:abc"
            )
            response = use_case.execute(
                BuildImageRequest(context_path=str(context), tag="test:latest", scan=False)
            )

        assert response.exit_code == EXIT_OK
        assert not response.policy_violations

    def _use_case_with(self, checks):
        validation = _validation(checks=checks)
        validator = MagicMock(spec=DockerfileValidatorInterface)
        validator.validate.return_value = validation
        validator.analyze.return_value = _analysis(validation)
        return BuildImageUseCase(validator, MagicMock())

    def _df002(self, status: ValidationStatus) -> ValidationCheck:
        return ValidationCheck(
            check="non_root_user",
            status=status,
            message="",
            severity=SeverityLevel.HIGH,
            rule_id="DF002",
        )

    def _run(self, use_case, context, policy):
        with patch.object(use_case, "_build_image") as mock_build:
            mock_build.return_value = BuildResult(
                success=True, image_tag="test:latest", image_sha256="sha256:abc"
            )
            return use_case.execute(
                BuildImageRequest(
                    context_path=str(context), tag="test:latest", scan=False, policy=policy
                )
            )

    def test_require_nonroot_le_o_veredito_do_df002(self, context):
        """A regra reaproveita o DF002, que já sabe que `USER 0` é root tanto
        quanto `USER root`."""
        from dockerls.domain.value_objects.build_policy import BuildPolicy

        use_case = self._use_case_with([self._df002(ValidationStatus.PASS)])

        response = self._run(use_case, context, BuildPolicy(require_nonroot=True))

        assert response.exit_code == EXIT_OK

    def test_require_nonroot_reprova_quando_o_df002_reprovou(self, context):
        from dockerls.domain.value_objects.build_policy import BuildPolicy

        use_case = self._use_case_with([self._df002(ValidationStatus.FAIL)])

        response = self._run(use_case, context, BuildPolicy(require_nonroot=True))

        assert response.exit_code == EXIT_POLICY
        assert "the image runs as root" in response.policy_violations[0].message

    def test_sem_a_checagem_a_regra_reprova_por_ausencia_de_medida(self, context):
        """Não determinar não é o mesmo que estar em ordem."""
        from dockerls.domain.value_objects.build_policy import BuildPolicy

        use_case = self._use_case_with([])

        response = self._run(use_case, context, BuildPolicy(require_nonroot=True))

        assert response.exit_code == EXIT_POLICY
        assert "could not be determined" in response.policy_violations[0].message


class TestAttribution:
    """Cruzar os achados da imagem com os da base declarada.

    Custa um segundo scan, e por isso é escolha e não padrão: dobrar o tempo
    de portão faria as pessoas desligarem o portão.
    """

    @pytest.fixture
    def context(self, tmp_path):
        (tmp_path / "Dockerfile").write_text("FROM node:22-alpine\nUSER node\n")
        return tmp_path

    @pytest.fixture
    def use_case(self):
        validation = _validation()
        validator = MagicMock(spec=DockerfileValidatorInterface)
        validator.validate.return_value = validation
        analysis = _analysis(validation)
        analysis.info.final_base_image = "node:22-alpine"
        validator.analyze.return_value = analysis
        return BuildImageUseCase(validator, MagicMock())

    @staticmethod
    def _scan(*findings):
        return ScanResult(
            total_vulnerabilities=len(findings),
            vulnerabilities=[{"cve_id": c, "package": p, "severity": "HIGH"} for c, p in findings],
        )

    def _run(self, use_case, context, built, base, *, attribute=True):
        scans = {"test:latest": built, "node:22-alpine": base}
        with (
            patch.object(use_case, "_build_image") as mock_build,
            patch.object(use_case, "_scan_image", side_effect=lambda tag: scans.get(tag)),
        ):
            mock_build.return_value = BuildResult(
                success=True, image_tag="test:latest", image_sha256="sha256:abc"
            )
            return use_case.execute(
                BuildImageRequest(
                    context_path=str(context),
                    tag="test:latest",
                    scan=True,
                    attribute_findings=attribute,
                )
            )

    def test_separa_o_que_veio_da_base_do_que_veio_das_suas_camadas(self, use_case, context):
        response = self._run(
            use_case,
            context,
            self._scan(("CVE-1", "openssl"), ("CVE-2", "requests")),
            self._scan(("CVE-1", "openssl")),
        )

        report = response.inheritance
        assert report is not None and report.available
        assert [f.cve_id for f in report.inherited] == ["CVE-1"]
        assert [f.cve_id for f in report.introduced] == ["CVE-2"]

    def test_conta_o_que_o_build_removeu_da_base(self, use_case, context):
        response = self._run(use_case, context, self._scan(), self._scan(("CVE-9", "zlib")))

        assert response.inheritance is not None
        assert [f.cve_id for f in response.inheritance.removed] == ["CVE-9"]

    def test_base_que_nao_escaneia_nao_vira_tudo_seu(self, use_case, context):
        """Seria transformar ausência de medição em acusação."""
        response = self._run(use_case, context, self._scan(("CVE-1", "a")), None)

        report = response.inheritance
        assert report is not None
        assert not report.available
        assert "could not be scanned" in report.unavailable_reason
        assert not report.introduced

    def test_sem_a_flag_nada_e_atribuido(self, use_case, context):
        response = self._run(
            use_case, context, self._scan(("CVE-1", "a")), self._scan(), attribute=False
        )

        assert response.inheritance is None

    def test_scratch_nao_e_escaneada_e_tudo_e_atribuido_ao_build(self, use_case, context):
        """`scratch` não é uma imagem: não há o que escanear, e tudo que a
        imagem carrega veio das camadas deste build."""
        use_case.validator.analyze.return_value.info.final_base_image = "scratch"

        response = self._run(use_case, context, self._scan(("CVE-1", "a")), None)

        report = response.inheritance
        assert report is not None and report.available
        assert [f.cve_id for f in report.introduced] == ["CVE-1"]


class TestPreflight:
    """Reprovar antes de construir o que já dá para reprovar.

    Descobrir um rótulo obrigatório faltando depois de dez minutos de build e
    um scan é o tipo de atrito que faz as pessoas pararem de rodar o portão.
    """

    @pytest.fixture
    def context(self, tmp_path):
        (tmp_path / "Dockerfile").write_text("FROM node:22\n")
        return tmp_path

    @pytest.fixture
    def use_case(self):
        validation = _validation(
            checks=[
                ValidationCheck(
                    check="non_root_user",
                    status=ValidationStatus.FAIL,
                    message="",
                    severity=SeverityLevel.HIGH,
                    rule_id="DF002",
                )
            ]
        )
        validator = MagicMock(spec=DockerfileValidatorInterface)
        validator.validate.return_value = validation
        validator.analyze.return_value = _analysis(validation)
        return BuildImageUseCase(validator, MagicMock())

    def test_base_sem_digest_reprova_sem_construir(self, use_case, context):
        from dockerls.domain.value_objects.build_policy import BuildPolicy

        with patch.object(use_case, "_build_image") as mock_build:
            response = use_case.execute(
                BuildImageRequest(
                    context_path=str(context),
                    tag="test:latest",
                    validate_only=True,
                    policy=BuildPolicy(require_pinned_bases=True),
                )
            )

        mock_build.assert_not_called()
        assert response.exit_code == EXIT_POLICY
        assert any(v.rule == "require_pinned_bases" for v in response.policy_violations)

    def test_regras_que_dependem_de_medicao_nao_reprovam_no_preflight(self, use_case, context):
        """Elas não são consideradas cumpridas -- apenas não são conferíveis
        sem construir."""
        from dockerls.domain.value_objects.build_policy import BuildPolicy

        response = use_case.execute(
            BuildImageRequest(
                context_path=str(context),
                tag="test:latest",
                validate_only=True,
                policy=BuildPolicy(require_scan=True, require_provenance=True),
            )
        )

        assert not response.policy_violations

    def test_digest_vindo_de_arg_conta_como_fixado(self, use_case, tmp_path):
        from dockerls.domain.value_objects.build_policy import BuildPolicy

        (tmp_path / "Dockerfile").write_text("ARG D=sha256:aa\nFROM node:22@${D}\n")

        response = use_case.execute(
            BuildImageRequest(
                context_path=str(tmp_path),
                tag="test:latest",
                validate_only=True,
                policy=BuildPolicy(require_pinned_bases=True),
            )
        )

        assert not response.policy_violations

    def test_sem_politica_o_preflight_nao_faz_nada(self, use_case, context):
        response = use_case.execute(
            BuildImageRequest(context_path=str(context), tag="test:latest", validate_only=True)
        )

        assert not response.policy_violations


class TestGateOriginHint:
    """A linha do portão diz de onde vieram os achados, quando se sabe.

    Quem lê o log do CI está decidindo, naquele segundo, se mexe no Dockerfile
    ou na base -- e sem isso a decisão é um palpite.
    """

    @pytest.fixture
    def context(self, tmp_path):
        (tmp_path / "Dockerfile").write_text("FROM node:22-alpine\nUSER node\n")
        return tmp_path

    @pytest.fixture
    def use_case(self):
        validation = _validation()
        validator = MagicMock(spec=DockerfileValidatorInterface)
        validator.validate.return_value = validation
        analysis = _analysis(validation)
        analysis.info.final_base_image = "node:22-alpine"
        validator.analyze.return_value = analysis
        return BuildImageUseCase(validator, MagicMock())

    @staticmethod
    def _scan(*findings, critical=0):
        return ScanResult(
            critical=critical,
            total_vulnerabilities=len(findings),
            vulnerabilities=[
                {
                    "cve_id": c,
                    "package": p,
                    "severity": "CRITICAL",
                    "fixed_version": fix,
                }
                for c, p, fix in findings
            ],
        )

    def _run(self, use_case, context, built, base, *, attribute=True):
        scans = {"test:latest": built, "node:22-alpine": base}
        with (
            patch.object(use_case, "_build_image") as mock_build,
            patch.object(use_case, "_scan_image", side_effect=lambda tag: scans.get(tag)),
        ):
            mock_build.return_value = BuildResult(
                success=True, image_tag="test:latest", image_sha256="sha256:abc"
            )
            return use_case.execute(
                BuildImageRequest(
                    context_path=str(context),
                    tag="test:latest",
                    scan=True,
                    fail_on="critical",
                    attribute_findings=attribute,
                )
            )

    def test_o_portao_diz_quantas_vieram_da_base(self, use_case, context):
        built = self._scan(("CVE-1", "openssl", "3.0.15"), ("CVE-2", "requests", ""), critical=2)
        base = self._scan(("CVE-1", "openssl", "3.0.15"), critical=1)

        response = self._run(use_case, context, built, base)

        assert response.exit_code == EXIT_POLICY
        assert "1 from the base node:22-alpine (1 with a published fix)" in response.error
        assert "1 from your layers" in response.error

    def test_sem_atribuicao_o_portao_nao_insinua_origem(self, use_case, context):
        """Um portão que insinua uma origem que não mediu é pior do que um
        portão calado."""
        built = self._scan(("CVE-1", "openssl", ""), critical=1)

        response = self._run(use_case, context, built, None, attribute=False)

        assert response.exit_code == EXIT_POLICY
        assert "da base" not in response.error

    def test_atribuicao_que_nao_fechou_tambem_nao_insinua(self, use_case, context):
        built = self._scan(("CVE-1", "openssl", ""), critical=1)

        response = self._run(use_case, context, built, None, attribute=True)

        assert response.inheritance is not None
        assert not response.inheritance.available
        assert "da base" not in response.error

    def test_a_base_e_escaneada_uma_vez_so_na_reprovacao(self, use_case, context):
        """Escanear a base duas vezes para dizer a mesma coisa duas vezes
        seria pagar minutos por nada."""
        built = self._scan(("CVE-1", "openssl", ""), critical=1)
        base = self._scan(("CVE-1", "openssl", ""), critical=1)
        scans = {"test:latest": built, "node:22-alpine": base}

        with (
            patch.object(use_case, "_build_image") as mock_build,
            patch.object(
                use_case, "_scan_image", side_effect=lambda tag: scans.get(tag)
            ) as mock_scan,
        ):
            mock_build.return_value = BuildResult(
                success=True, image_tag="test:latest", image_sha256="sha256:abc"
            )
            use_case.execute(
                BuildImageRequest(
                    context_path=str(context),
                    tag="test:latest",
                    scan=True,
                    fail_on="critical",
                    attribute_findings=True,
                )
            )

        base_scans = [c for c in mock_scan.call_args_list if c.args[0] == "node:22-alpine"]
        assert len(base_scans) == 1


class TestTheGateSeesExploitability:
    """O `build` escaneia direto com Trivy/Grype, fora do pipeline que
    enriquece com KEV e EPSS -- então os portões novos não tinham dado
    nenhum para olhar, e não reprovariam nunca. Um portão de segurança que
    não avalia é a pior falha possível: a que não aparece."""

    @staticmethod
    def _scan(*vulns, **counts):
        from dockerls.application.use_cases.build_image import ScanResult as BuildScanResult

        return BuildScanResult(
            vulnerabilities=list(vulns),
            total_vulnerabilities=len(vulns),
            **counts,
        )

    @staticmethod
    def _intel(
        kev: set[str] | None = None, epss: dict[str, float] | None = None, *, available=True
    ):
        client = MagicMock()
        client.known_exploited = AsyncMock(return_value=kev or set())
        client.epss_scores = AsyncMock(return_value=epss or {})
        client.kev_available = available
        return client

    def _use_case(self, intel=None):
        return BuildImageUseCase(MagicMock(), MagicMock(), threat_intel=intel)

    def test_the_enrichment_marks_what_the_catalogue_listed(self):
        scan = self._scan(
            {"cve_id": "CVE-1", "severity": "CRITICAL"},
            {"cve_id": "CVE-2", "severity": "HIGH"},
            critical=1,
            high=1,
        )
        use_case = self._use_case(self._intel(kev={"CVE-1"}, epss={"CVE-2": 0.87}))

        enriched = use_case._enrich(scan)

        assert enriched is not None
        by_id = {v["cve_id"]: v for v in enriched.vulnerabilities}
        assert by_id["CVE-1"]["kev"] == "true"
        assert by_id["CVE-2"]["kev"] == "false"
        assert by_id["CVE-2"]["epss"] == 0.87

    def test_a_catalogue_that_did_not_answer_marks_nothing(self):
        """O erro que este projeto existe para não cometer: transformar um
        feed fora do ar em "nenhuma vulnerabilidade explorada"."""
        scan = self._scan({"cve_id": "CVE-1", "severity": "CRITICAL"}, critical=1)
        use_case = self._use_case(self._intel(available=False))

        enriched = use_case._enrich(scan)

        assert enriched is not None
        assert "kev" not in enriched.vulnerabilities[0]

    def test_only_critical_and_high_are_looked_up(self):
        """Como no `recommend`. O que fica de fora permanece não consultado,
        e isso é correto: não foi consultado."""
        intel = self._intel()
        scan = self._scan(
            {"cve_id": "CVE-1", "severity": "CRITICAL"},
            {"cve_id": "CVE-2", "severity": "LOW"},
            critical=1,
            low=1,
        )

        self._use_case(intel)._enrich(scan)

        assert intel.known_exploited.await_args.args[0] == ["CVE-1"]

    def test_without_a_client_nothing_is_consulted(self):
        """`--fail-on high` não deve sair para a rede buscar o catálogo KEV."""
        scan = self._scan({"cve_id": "CVE-1", "severity": "CRITICAL"}, critical=1)
        assert self._use_case()._enrich(scan) is scan

    def test_a_lookup_that_blows_up_leaves_everything_unmeasured(self):
        """Derrubar o build aqui trocaria uma medição ausente por um erro
        técnico. O portão é quem decide o que fazer com a ausência."""
        intel = self._intel()
        intel.known_exploited = AsyncMock(side_effect=OSError("network down"))
        scan = self._scan({"cve_id": "CVE-1", "severity": "CRITICAL"}, critical=1)

        enriched = self._use_case(intel)._enrich(scan)

        assert enriched is not None
        assert "kev" not in enriched.vulnerabilities[0]

    def test_an_exploited_medium_now_fails_where_it_used_to_pass(self):
        """O caso que motivou tudo isto."""
        scan = self._scan(
            {"cve_id": "CVE-1", "severity": "MEDIUM", "kev": "TRUE", "package": "openssl"},
            medium=1,
        )
        use_case = self._use_case()

        assert use_case._should_fail(scan, "high") is False
        assert use_case._should_fail(scan, "kev") is True
        assert "CVE-1" in use_case._gate_failure_summary(scan, "kev")

    def test_a_requested_gate_that_could_not_run_stops_the_build(self):
        scan = self._scan({"cve_id": "CVE-1", "severity": "CRITICAL"}, critical=1)
        use_case = self._use_case()

        assert use_case._should_fail(scan, "kev") is True
        summary = use_case._gate_failure_summary(scan, "kev")
        assert "Gate not evaluated" in summary
        assert "absent measurement" in summary

    def test_the_summary_names_every_gate_that_failed(self):
        scan = self._scan(
            {"cve_id": "CVE-1", "severity": "CRITICAL", "kev": "TRUE", "epss": 0.9},
            critical=1,
        )

        summary = self._use_case()._gate_failure_summary(scan, "critical,kev,epss>=0.5")

        assert "Gate failed (severity)" in summary
        assert "Gate failed (kev)" in summary
        assert "Gate failed (epss)" in summary
        assert "[--fail-on critical,kev,epss>=0.5]" in summary


class TestDeclaredBases:
    """`_declared_bases` used to be its own `stripped.split()[1]` parser,
    which read a `--platform=` flag as the image itself, raised `IndexError`
    on a bare `FROM`, and never resolved an `ARG`-pinned digest. It now
    delegates to `parse_bases`, the same parser `dockerls base` uses."""

    def test_a_platform_flag_is_not_read_as_the_image(self, tmp_path):
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM --platform=linux/amd64 node:22\n")

        bases = BuildImageUseCase._declared_bases(dockerfile)

        assert bases == {"node:22": ""}

    def test_an_inline_digest_is_recorded_as_pinned(self, tmp_path):
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM node@sha256:" + "a" * 64 + "\n")

        bases = BuildImageUseCase._declared_bases(dockerfile)

        assert bases == {"node": "sha256:" + "a" * 64}

    def test_an_arg_pinned_digest_is_resolved(self, tmp_path):
        """The old split-based parser only understood an inline `@sha256:`;
        an `ARG`-pinned digest -- exactly what `dockerls base` writes --
        always came back unpinned."""
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("ARG NODE_DIGEST=sha256:" + "b" * 64 + "\nFROM node@${NODE_DIGEST}\n")

        bases = BuildImageUseCase._declared_bases(dockerfile)

        assert bases == {"node": "sha256:" + "b" * 64}

    def test_a_bare_from_with_no_argument_does_not_raise(self, tmp_path):
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM\nRUN echo hi\n")

        bases = BuildImageUseCase._declared_bases(dockerfile)

        assert bases == {}

    def test_a_moving_tag_is_recorded_with_an_empty_digest(self, tmp_path):
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM node:22-alpine\n")

        bases = BuildImageUseCase._declared_bases(dockerfile)

        assert bases == {"node:22-alpine": ""}

    def test_an_unreadable_dockerfile_returns_an_empty_dict(self, tmp_path):
        assert BuildImageUseCase._declared_bases(tmp_path / "missing") == {}
