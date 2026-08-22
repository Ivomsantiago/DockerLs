"""Use case para construir imagens Docker com segurança."""

from __future__ import annotations

import hashlib
import json
import os

# subprocess é necessário para invocar docker/trivy/grype; todas as chamadas
# usam listas de argumentos, sem shell, com argv[0] resolvido por caminho.
import subprocess  # nosec B404
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from loguru import logger

from dockerls.domain.entities.dockerfile_analysis import (
    DockerfileAnalysis,
    DockerfileValidationResult,
    HardeningRule,
    ValidationStatus,
)
from dockerls.domain.entities.vulnerability import Severity, Vulnerability
from dockerls.domain.value_objects.base_upgrade import parse_bases
from dockerls.domain.value_objects.build_policy import (
    BaseFact,
    BuildPolicy,
    PolicyFacts,
    PolicyViolation,
    evaluate,
)
from dockerls.domain.value_objects.image_reference import registry_host_of
from dockerls.domain.value_objects.inheritance import (
    InheritanceReport,
    attribute,
    unavailable,
)
from dockerls.domain.value_objects.provenance import (
    ArtifactDigests,
    BuildProvenance,
    SourceDigests,
)
from dockerls.domain.value_objects.tristate import Tristate
from dockerls.exit_codes import EXIT_ERROR, EXIT_OK, EXIT_POLICY
from dockerls.infrastructure.hashing import ContextTooLargeError, hash_context, hash_file
from dockerls.utils.executables import ExecutableNotFoundError, resolve_executable

if TYPE_CHECKING:
    from dockerls.application.use_cases.analyze_dockerfile import AnalyzeDockerfileResponse
    from dockerls.domain.interfaces.dockerfile_validator import (
        DockerfileValidatorInterface,
        HardeningTemplateProvider,
    )


@dataclass
class BuildOptions:
    """Opções de build."""

    tag: str
    dockerfile_path: str = "Dockerfile"
    context_path: str = "."
    no_cache: bool = False
    build_args: dict[str, str] | None = None
    labels: dict[str, str] | None = None
    platform: str | None = None
    target: str | None = None
    pull: bool = True
    buildkit: bool = True
    secrets: dict[str, str] | None = None  # id -> file_path
    ssh: list[str] | None = None  # SSH agents


@dataclass
class BuildResult:
    """Resultado do build."""

    success: bool
    image_tag: str | None = None
    image_id: str | None = None
    image_sha256: str | None = None
    build_time_seconds: float = 0.0
    layers_count: int = 0
    image_size_bytes: int = 0
    error_message: str | None = None
    logs: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class ScanResult:
    """Resultado do scan de segurança."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    unknown: int = 0
    total_vulnerabilities: int = 0
    fixable: int = 0
    scan_tool: str = "trivy"
    scan_time_seconds: float = 0.0
    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    sbom_components_count: int = 0


@dataclass
class BuildReport:
    """Relatório completo de build."""

    build_id: str
    timestamp: str
    image: str
    dockerfile_path: str
    validation: dict[str, Any]
    scan_results: dict[str, Any] | None = None
    security_score: int = 0
    security_tier: str = "F"
    layers: list[dict[str, Any]] = field(default_factory=list)
    recommendations: list[dict[str, Any]] = field(default_factory=list)
    sbom: dict[str, Any] | None = None
    build_metadata: dict[str, Any] | None = None
    remediation_history: list[dict[str, Any]] = field(default_factory=list)
    auto_remediated: bool = False


@dataclass
class BuildImageRequest:
    """Request para build de imagem."""

    context_path: str
    tag: str
    dockerfile_path: str = "Dockerfile"
    hardened: bool = False
    base_template: str | None = None
    scan: bool = True
    validate_only: bool = False
    suggest_only: bool = False
    no_cache: bool = False
    build_args: dict[str, str] | None = None
    labels: dict[str, str] | None = None
    fail_on: str | None = None  # "critical", "high"
    ci_mode: bool = False
    verbose: bool = False
    force: bool = False
    push: bool = False
    auto_remediate: bool = False
    max_remediation_rounds: int = 3
    target_zero_vulns: bool = False
    #: Onde arquivar o documento de procedência. Vazio desliga o arquivamento
    #: mas não a medição: o registro continua na resposta.
    provenance_path: str = ""
    #: Destino completo da publicação (`meuacr.azurecr.io/apps/dockerls:1.5.0`).
    #: Vazio significa publicar a própria tag local, que só funciona quando ela
    #: já nomeia um registry -- e era o comportamento anterior, que falhava com
    #: "denied" para toda tag sem host.
    push_reference: str = ""
    #: A política declarada em `.dockerls-policy.yaml`, já carregada pela
    #: camada CLI. O caso de uso confere; ler o arquivo é trabalho da borda.
    policy: BuildPolicy | None = None
    #: Escanear também a base declarada, para dizer de quem é cada CVE. Custa
    #: um segundo scan, e por isso é escolha e não padrão.
    attribute_findings: bool = False


@dataclass
class BuildImageResponse:
    """Resposta do build de imagem.

    `validation` e `analysis` carregam o resultado bruto da validação para
    que a camada CLI possa renderizar a tabela de checks. Sem eles o
    comando só sabia dizer "falhou", sem qual regra falhou.
    """

    success: bool
    image_tag: str | None = None
    image_sha256: str | None = None
    report: BuildReport | None = None
    validation: DockerfileValidationResult | None = None
    analysis: DockerfileAnalysis | None = None
    recommendations: list[HardeningRule] = field(default_factory=list)
    #: A cadeia entre o que entrou no build e o que saiu dele. Presente em
    #: todo build que chegou a produzir imagem.
    provenance: BuildProvenance | None = None
    #: Regras de `.dockerls-policy.yaml` que este build não cumpriu.
    policy_violations: list[PolicyViolation] = field(default_factory=list)
    #: De quem é cada vulnerabilidade: da base declarada ou das suas camadas.
    inheritance: InheritanceReport | None = None
    error: str | None = None
    exit_code: int = EXIT_OK


class BuildImageUseCase:
    """Caso de uso para construção segura de imagens Docker."""

    def __init__(
        self,
        validator: DockerfileValidatorInterface,
        template_provider: HardeningTemplateProvider,
    ):
        self.validator = validator
        self.template_provider = template_provider

    def execute(self, request: BuildImageRequest) -> BuildImageResponse:
        """Executa o build seguro da imagem."""
        logger.debug(f"Iniciando build seguro: {request.context_path}")

        try:
            # 1. Validar Dockerfile. Uma falha aqui (Dockerfile ausente,
            #    ilegível) é erro de execução, não violação de política, e
            #    --force não cria um Dockerfile que não existe.
            validation_result = self._validate_dockerfile(request)
            if not validation_result.success:
                return BuildImageResponse(
                    success=False,
                    error=validation_result.error or "Dockerfile validation could not run",
                    exit_code=EXIT_ERROR,
                )

            # 2. Modo validate-only. A política entra aqui pelo subconjunto
            #    estático: sem build não há scan, procedência nem imagem, e
            #    aplicar as regras que dependem deles produziria uma violação
            #    por execução dizendo sempre a mesma coisa. O que dá para
            #    conferir só lendo o Dockerfile é conferido -- e é justamente
            #    o que evita descobrir um rótulo faltando depois de dez
            #    minutos de build.
            if request.validate_only:
                response = self._format_validation_response(validation_result)
                response.policy_violations = self._preflight(request, validation_result)
                if response.policy_violations and response.exit_code == EXIT_OK:
                    response.success = False
                    response.error = (
                        f"{len(response.policy_violations)} regra(s) de política não "
                        "cumprida(s) no que dá para conferir sem construir"
                    )
                    response.exit_code = EXIT_POLICY
                return response

            # 3. Modo suggest-only
            if request.suggest_only:
                return self._format_suggestions_response(validation_result)

            # 3b. Validação com erros barra o build (a menos que --force).
            #     A resposta carrega os checks para o CLI dizer o que falhou.
            validation = validation_result.validation
            if validation is not None and validation.errors > 0 and not request.force:
                return self._format_validation_response(validation_result)

            # 4. Gerar Dockerfile hardened se solicitado
            dockerfile_path = request.dockerfile_path
            if request.hardened or request.base_template:
                dockerfile_path = self._generate_hardened_dockerfile(
                    request.context_path,
                    request.base_template or "node",
                )

            # 4b. Digerir a entrada **antes** de construir. Sem isto, dois
            #     builds do mesmo --tag produzem relatórios indistinguíveis
            #     mesmo partindo de Dockerfiles diferentes, e o scan não fica
            #     ligado a artefato nenhum.
            started_at = datetime.now(tz=UTC).isoformat()
            source_before = self._digest_source(request.context_path, dockerfile_path)

            # 5. Construir imagem
            build_result = self._build_image(
                context_path=request.context_path,
                dockerfile_path=dockerfile_path,
                tag=request.tag,
                options=BuildOptions(
                    tag=request.tag,
                    dockerfile_path=dockerfile_path,
                    context_path=request.context_path,
                    no_cache=request.no_cache,
                    build_args=request.build_args,
                    labels=request.labels,
                    buildkit=True,
                ),
            )

            if not build_result.success:
                return BuildImageResponse(
                    success=False,
                    error=build_result.error_message,
                    exit_code=EXIT_ERROR,
                )

            # 5b. Digerir a entrada de novo. A comparação é o que transforma
            #     o registro em controle: uma entrada que mudou durante o
            #     build não é a entrada que a imagem representa.
            source_after = self._digest_source(request.context_path, dockerfile_path)

            # 6. Scan pós-build
            scan_result = None
            if request.scan:
                scan_result = self._scan_image(request.tag)

            # 6b. Ciclo de Auto-Remediação Iterativo (Zero Vulnerabilidades)
            remediation_history: list[dict[str, Any]] = []
            if (
                (request.auto_remediate or request.target_zero_vulns)
                and request.scan
                and scan_result
                and scan_result.total_vulnerabilities > 0
            ):
                current_df_path = dockerfile_path
                for round_num in range(1, request.max_remediation_rounds + 1):
                    remediated_path, applied_actions = self._derive_and_write_remediated_dockerfile(
                        context_path=request.context_path,
                        original_dockerfile_path=current_df_path,
                        scan_result=scan_result,
                        round_num=round_num,
                    )
                    if not applied_actions:
                        logger.info("No further automated remediation actions available.")
                        break

                    logger.info(
                        f"[Auto-Remediation Round {round_num}] "
                        f"Rebuilding with {len(applied_actions)} fix(es)..."
                    )
                    new_build = self._build_image(
                        context_path=request.context_path,
                        dockerfile_path=remediated_path,
                        tag=request.tag,
                        options=BuildOptions(
                            tag=request.tag,
                            dockerfile_path=remediated_path,
                            context_path=request.context_path,
                            no_cache=request.no_cache,
                            build_args=request.build_args,
                            labels=request.labels,
                            buildkit=True,
                        ),
                    )
                    if not new_build.success:
                        logger.warning(
                            f"Remediated build round {round_num} failed: {new_build.error_message}"
                        )
                        break

                    build_result = new_build
                    current_df_path = remediated_path
                    prev_scan = scan_result
                    new_scan = self._scan_image(request.tag)
                    if new_scan:
                        scan_result = new_scan
                        remediation_history.append(
                            {
                                "round": round_num,
                                "actions": applied_actions,
                                "critical_before": prev_scan.critical,
                                "critical_after": new_scan.critical,
                                "high_before": prev_scan.high,
                                "high_after": new_scan.high,
                                "total_before": prev_scan.total_vulnerabilities,
                                "total_after": new_scan.total_vulnerabilities,
                            }
                        )
                        if new_scan.total_vulnerabilities == 0:
                            logger.info(
                                "✨ Success: Image achieved ZERO "
                                f"vulnerabilities in round {round_num}!"
                            )
                            break

            # 7. Verificar thresholds de falha. Entre o limiar da política e o
            #    da linha de comando vence o mais estrito: um arquivo no
            #    repositório não pode desligar um portão que o pipeline pediu.
            threshold = (
                request.policy.effective_fail_on(request.fail_on or "")
                if request.policy
                else (request.fail_on or "")
            )
            if threshold:
                # Um portão que não pôde ser avaliado não é um portão
                # aprovado. Sem scan, `--fail-on` deixava passar em silêncio
                # qualquer imagem numa máquina sem scanner instalado.
                if scan_result is None:
                    return BuildImageResponse(
                        success=False,
                        image_tag=request.tag,
                        image_sha256=build_result.image_sha256,
                        validation=validation,
                        analysis=validation_result.analysis,
                        error=(
                            f"--fail-on {threshold} requires a vulnerability scan, "
                            "and no scanner (trivy, grype) could be run"
                        ),
                        exit_code=EXIT_ERROR,
                    )
                if self._should_fail(scan_result, threshold):
                    return BuildImageResponse(
                        success=False,
                        image_tag=request.tag,
                        image_sha256=build_result.image_sha256,
                        validation=validation,
                        analysis=validation_result.analysis,
                        error=self._gate_failure_summary(scan_result, threshold),
                        inheritance=self._attribute_findings(
                            request, validation_result, scan_result
                        ),
                        exit_code=EXIT_POLICY,
                    )

            # 7a. Cruzar os achados com os da base: a contagem sozinha diz
            #     "conserte", e não diz o quê. Roda antes dos portões porque
            #     precisa aparecer no relatório mesmo quando o build reprova --
            #     é justamente aí que a pergunta "de quem é isso?" é feita.
            inheritance = self._attribute_findings(request, validation_result, scan_result)

            # 7b. Conferir a política declarada. Antes do push, pelo mesmo
            #     motivo do portão de scan: uma imagem que viola a política da
            #     organização não é publicada por ter sido construída.
            if request.policy is not None:
                violations = evaluate(
                    request.policy,
                    self._policy_facts(
                        request=request,
                        analysis=validation_result.analysis,
                        scan_result=scan_result,
                        source_before=source_before,
                        source_after=source_after,
                        image_id=build_result.image_sha256 or "",
                    ),
                )
                if violations:
                    return BuildImageResponse(
                        success=False,
                        image_tag=request.tag,
                        image_sha256=build_result.image_sha256,
                        validation=validation,
                        analysis=validation_result.analysis,
                        policy_violations=violations,
                        inheritance=inheritance,
                        error=(
                            f"{len(violations)} regra(s) de .dockerls-policy.yaml não cumprida(s)"
                        ),
                        exit_code=EXIT_POLICY,
                    )

            # 8. Push, se pedido. Só depois dos portões: publicar uma imagem
            #    que reprovou no scan derrota o propósito de ter o portão.
            if request.push:
                # A entrada mudou durante o build: a imagem existe, mas não é a
                # que foi medida. Publicá-la seria distribuir um artefato cuja
                # procedência esta ferramenta acabou de declarar quebrada --
                # a mesma substituição que ela recusa em todo lugar.
                if source_before.dockerfile and source_before != source_after:
                    return BuildImageResponse(
                        success=False,
                        image_tag=request.tag,
                        image_sha256=build_result.image_sha256,
                        validation=validation,
                        analysis=validation_result.analysis,
                        error=(
                            "publicação recusada: o Dockerfile ou o contexto mudaram "
                            "durante o build, então a imagem não corresponde à entrada "
                            "que foi medida. Reconstrua a partir de uma árvore estável."
                        ),
                        exit_code=EXIT_POLICY,
                    )
                push_error = self._push_image(request.tag, request.push_reference)
                if push_error is not None:
                    return BuildImageResponse(
                        success=False,
                        image_tag=request.tag,
                        image_sha256=build_result.image_sha256,
                        error=push_error,
                        exit_code=EXIT_ERROR,
                    )

            # 8b. Fechar a cadeia: o digest do manifesto só existe depois do
            #     push, e é o único identificador que outra máquina consegue
            #     usar para puxar exatamente esta imagem.
            provenance = BuildProvenance(
                tag=request.tag,
                source=source_before,
                source_after=source_after,
                artifact=ArtifactDigests(
                    image_id=build_result.image_sha256 or "",
                    repo_digest=self._repo_digest(request.push_reference or request.tag),
                    published_reference=request.push_reference,
                    scanner=scan_result.scan_tool if scan_result else "",
                ),
                started_at=started_at,
                finished_at=datetime.now(tz=UTC).isoformat(),
            )
            self._archive_provenance(provenance, request.provenance_path)

            # 9. Gerar relatório
            report = self._generate_report(
                validation=validation_result,
                build=build_result,
                scan=scan_result,
                image_tag=request.tag,
                dockerfile_path=request.dockerfile_path,
                remediation_history=remediation_history,
            )

            return BuildImageResponse(
                success=True,
                image_tag=request.tag,
                image_sha256=build_result.image_sha256,
                provenance=provenance,
                inheritance=inheritance,
                report=report,
                validation=validation,
                analysis=validation_result.analysis,
                recommendations=list(validation_result.suggestions or []),
                exit_code=EXIT_OK,
            )

        except Exception as e:
            logger.exception(f"Erro no build: {e}")
            return BuildImageResponse(
                success=False,
                error=str(e),
                exit_code=EXIT_ERROR,
            )

    def _validate_dockerfile(self, request: BuildImageRequest) -> AnalyzeDockerfileResponse:
        """Valida o Dockerfile."""
        from dockerls.application.use_cases.analyze_dockerfile import (
            AnalyzeDockerfileRequest,
            AnalyzeDockerfileUseCase,
        )

        analyze_request = AnalyzeDockerfileRequest(
            dockerfile_path=Path(request.context_path) / request.dockerfile_path,
            include_suggestions=True,
            validate_only=False,
        )

        analyze_use_case = AnalyzeDockerfileUseCase(self.validator, self.template_provider)
        return analyze_use_case.execute(analyze_request)

    def _format_validation_response(
        self, validation_result: AnalyzeDockerfileResponse
    ) -> BuildImageResponse:
        """Formata resposta apenas de validação.

        Propaga o `DockerfileValidationResult` inteiro -- checks, contagens e
        score -- porque é ele que a CLI renderiza. Devolver só `success` e
        `exit_code` deixava o comando sem nada para imprimir.
        """
        validation = validation_result.validation
        if validation is None:
            return BuildImageResponse(
                success=False,
                error="Dockerfile validation produced no result",
                exit_code=EXIT_ERROR,
            )

        analysis = validation_result.analysis
        suggestions = list(validation_result.suggestions or [])
        failed = validation.errors > 0

        return BuildImageResponse(
            success=not failed,
            report=self._build_validation_report(validation_result, validation, analysis),
            validation=validation,
            analysis=analysis,
            recommendations=suggestions,
            error=self._validation_error_summary(validation) if failed else None,
            exit_code=EXIT_POLICY if failed else EXIT_OK,
        )

    def _format_suggestions_response(
        self, validation_result: AnalyzeDockerfileResponse
    ) -> BuildImageResponse:
        """Formata resposta apenas com sugestões.

        Carrega também a validação: mostrar as sugestões sem dizer quais
        checks as motivaram não é acionável.
        """
        validation = validation_result.validation
        analysis = validation_result.analysis
        return BuildImageResponse(
            success=True,
            report=self._build_validation_report(validation_result, validation, analysis)
            if validation is not None
            else None,
            validation=validation,
            analysis=analysis,
            recommendations=list(validation_result.suggestions or []),
            exit_code=EXIT_OK,
        )

    def _build_validation_report(
        self,
        validation_result: AnalyzeDockerfileResponse,
        validation: DockerfileValidationResult,
        analysis: DockerfileAnalysis | None,
    ) -> BuildReport:
        """Relatório de um run que só validou -- sem imagem, sem scan.

        Existe para que `--ci-mode` emita o mesmo JSON estruturado nos dois
        modos, em vez de um objeto vazio quando nada foi construído.
        """
        score = (
            analysis.security_score
            if analysis is not None
            else self._calculate_security_score(validation_result, None)
        )
        tier = (
            analysis.security_tier if analysis is not None else self._calculate_security_tier(score)
        )
        return BuildReport(
            build_id=self._new_build_id(validation.dockerfile_path),
            timestamp=datetime.now(tz=UTC).isoformat(),
            image="",
            dockerfile_path=validation.dockerfile_path,
            validation=self._validation_dict(validation),
            security_score=score,
            security_tier=tier,
            recommendations=self._recommendation_dicts(validation_result.suggestions or []),
        )

    @staticmethod
    def _validation_error_summary(validation: DockerfileValidationResult) -> str:
        """Resumo textual das regras violadas, para `error` e para logs de CI."""
        failures = [c for c in validation.checks if c.status == ValidationStatus.FAIL]
        header = f"Dockerfile validation failed: {validation.errors} error(s)"
        if not failures:
            return header
        details = "; ".join(
            f"{check.check}"
            f"{f' (line {check.line})' if check.line is not None else ''}: {check.message}"
            for check in failures
        )
        return f"{header} -- {details}"

    @staticmethod
    def _validation_dict(validation: DockerfileValidationResult) -> dict[str, Any]:
        return {
            "dockerfile_path": validation.dockerfile_path,
            "passed": validation.passed,
            "warnings": validation.warnings,
            "errors": validation.errors,
            # `rule_id`, `references` e `rationale` entram aqui porque este é o
            # arquivo que vai para auditoria. O terminal citava o controle
            # publicado (CIS 4.1, NIST 4.1.2) e o relatório perdia a citação --
            # exatamente onde ela vale mais, que é diante de quem precisa
            # mapear achado para programa de conformidade.
            "checks": [
                {
                    "check": check.check,
                    "rule_id": check.rule_id,
                    "status": check.status.value,
                    "message": check.message,
                    "severity": check.severity.value,
                    "line": check.line,
                    "references": check.references,
                    "rationale": check.rationale,
                }
                for check in validation.checks
            ],
        }

    @staticmethod
    def _recommendation_dicts(rules: list[HardeningRule]) -> list[dict[str, Any]]:
        return [
            {
                "priority": rule.priority.value,
                "title": rule.title,
                "current": rule.current_state,
                "suggested": rule.suggested_fix,
                "reason": rule.reason,
            }
            for rule in rules
        ]

    @staticmethod
    def _new_build_id(seed: str) -> str:
        stamp = datetime.now(tz=UTC).isoformat()
        return hashlib.sha256(f"{seed}{stamp}".encode()).hexdigest()[:16]

    def _generate_hardened_dockerfile(self, context_path: str, template: str) -> str:
        """Gera Dockerfile hardened delegando à infraestrutura.

        Escrever arquivo é responsabilidade do provider, não do caso de uso:
        aqui só decidimos onde ele deve sair.
        """
        output_path = Path(context_path) / "Dockerfile.hardened"
        self.template_provider.generate_hardened_dockerfile(
            dockerfile_path=Path(context_path),
            base_image=template,
            output_path=output_path,
        )
        logger.debug(f"Dockerfile hardened gerado: {output_path}")
        return str(output_path)

    def _derive_and_write_remediated_dockerfile(
        self,
        context_path: str,
        original_dockerfile_path: str,
        scan_result: ScanResult,
        round_num: int,
    ) -> tuple[str, list[str]]:
        """Gera um Dockerfile com patches automáticos de segurança aplicados."""
        full_orig = Path(original_dockerfile_path)
        if not full_orig.is_absolute():
            full_orig = Path(context_path) / original_dockerfile_path

        if not full_orig.exists():
            return original_dockerfile_path, []

        content = full_orig.read_text(encoding="utf-8")
        applied: list[str] = []
        lower_content = content.lower()

        # Identificar distro e tipo de pacote
        is_alpine = "alpine" in lower_content
        is_debian_ubuntu = any(d in lower_content for d in ("debian", "ubuntu", "slim"))

        # 1. Patch de SO
        os_vulns = [
            v
            for v in scan_result.vulnerabilities
            if v.get("fixed_version")
            and not any(
                lang in (v.get("package") or "").lower() for lang in ("npm", "pip", "node_modules")
            )
        ]
        if os_vulns:
            if is_alpine and "apk upgrade" not in lower_content:
                upgrade_cmd = "RUN apk upgrade --no-cache && rm -rf /var/cache/apk/*"
                content = self._insert_instruction(content, upgrade_cmd)
                applied.append(f"Applied Alpine OS security upgrade ({len(os_vulns)} fixable CVEs)")
            elif is_debian_ubuntu and "apt-get upgrade" not in lower_content:
                upgrade_cmd = (
                    "RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*"
                )
                content = self._insert_instruction(content, upgrade_cmd)
                applied.append(
                    f"Applied Debian/Ubuntu OS security upgrade ({len(os_vulns)} fixable CVEs)"
                )

        # 2. Patch de npm embutido
        has_npm_vulns = any(
            "npm" in (v.get("package") or "").lower() for v in scan_result.vulnerabilities
        )
        if has_npm_vulns and "npm install -g npm" not in lower_content:
            npm_cmd = "RUN npm install -g npm@latest && npm cache clean --force"
            content = self._insert_instruction(content, npm_cmd)
            applied.append("Upgraded bundled npm CLI to latest patched release")

        # 3. Patch de pip embutido
        has_pip_vulns = any(
            (v.get("package") or "").lower() in ("pip", "setuptools", "wheel")
            for v in scan_result.vulnerabilities
        )
        if has_pip_vulns and "pip install --upgrade pip" not in lower_content:
            pip_cmd = "RUN pip install --no-cache-dir --upgrade pip setuptools wheel"
            content = self._insert_instruction(content, pip_cmd)
            applied.append("Upgraded pip/setuptools to secure versions")

        if not applied:
            return original_dockerfile_path, []

        remediated_filename = f"Dockerfile.remediated.{round_num}"
        remediated_path = Path(context_path) / remediated_filename
        remediated_path.write_text(content, encoding="utf-8")
        return str(remediated_path), applied

    @staticmethod
    def _insert_instruction(dockerfile_content: str, instruction: str) -> str:
        """Insere uma instrução RUN de forma segura antes do USER ou no final do primeiro stage."""
        lines = dockerfile_content.splitlines()
        insert_idx = -1
        for i, line in enumerate(lines):
            stripped = line.strip().upper()
            if stripped.startswith("USER ") and insert_idx == -1:
                insert_idx = i
                break

        if insert_idx != -1:
            lines.insert(insert_idx, instruction)
        else:
            last_from_idx = 0
            for i, line in enumerate(lines):
                if line.strip().upper().startswith("FROM "):
                    last_from_idx = i
            lines.insert(last_from_idx + 1, instruction)

        return "\n".join(lines) + "\n"

    def _build_image(
        self,
        context_path: str,
        dockerfile_path: str,
        tag: str,
        options: BuildOptions,
    ) -> BuildResult:
        """Executa o build da imagem Docker."""
        start_time = datetime.now()
        logs: list[str] = []
        warnings: list[str] = []

        try:
            # Comando docker build. O binário é resolvido para caminho
            # absoluto: deixar a escolha para o $PATH é o próprio PATH
            # hijacking que esta ferramenta reporta nas imagens dos outros.
            # BuildKit é ativado via variável de ambiente, não por argumento.
            cmd = [resolve_executable("docker"), "build"]

            cmd.extend(["-t", tag])
            cmd.extend(["-f", dockerfile_path])

            if options.no_cache:
                cmd.append("--no-cache")

            if options.pull:
                cmd.append("--pull")

            if options.platform:
                cmd.extend(["--platform", options.platform])

            if options.target:
                cmd.extend(["--target", options.target])

            if options.build_args:
                for key, value in options.build_args.items():
                    cmd.extend(["--build-arg", f"{key}={value}"])

            if options.labels:
                for key, value in options.labels.items():
                    cmd.extend(["--label", f"{key}={value}"])

            # Adicionar contexto
            cmd.append(context_path)

            logger.debug(f"Executando comando: {' '.join(cmd)}")

            # Executar build
            env = {}
            if options.buildkit:
                env["DOCKER_BUILDKIT"] = "1"

            result = subprocess.run(  # nosec B603  # noqa: S603
                cmd,
                capture_output=True,
                text=True,
                timeout=3600,  # 1 hora timeout
                env={**os.environ, **env},
                check=False,
            )

            logs.append(result.stdout)
            if result.stderr:
                logs.append(result.stderr)
                warnings.append(result.stderr)

            if result.returncode != 0:
                return BuildResult(
                    success=False,
                    error_message=f"Build failed: {result.stderr}",
                    logs=logs,
                    warnings=warnings,
                )

            # Extrair informações da imagem
            image_info = self._get_image_info(tag)

            end_time = datetime.now()
            build_time = (end_time - start_time).total_seconds()

            return BuildResult(
                success=True,
                image_tag=tag,
                image_id=image_info.get("Id"),
                image_sha256=image_info.get("Id"),
                build_time_seconds=build_time,
                layers_count=len(image_info.get("RootFS", {}).get("Layers", [])),
                image_size_bytes=image_info.get("Size", 0),
                logs=logs,
                warnings=warnings,
            )

        except ExecutableNotFoundError as e:
            return BuildResult(success=False, error_message=str(e), logs=logs)
        except subprocess.TimeoutExpired:
            return BuildResult(
                success=False,
                error_message="Build timeout (1 hour)",
                logs=logs,
            )
        except Exception as e:
            logger.exception(f"Erro no build: {e}")
            return BuildResult(
                success=False,
                error_message=str(e),
                logs=logs,
            )

    def _push_image(self, tag: str, destination: str = "") -> str | None:
        """Publica a imagem no destino. Devolve a mensagem de erro, ou None.

        Antes disto o push usava a tag local como está. Numa tag sem host --
        `dockerls:1.5.0`, que é a forma que todo mundo digita -- isso vira uma
        tentativa de publicar em `docker.io/library/dockerls`, recusada com um
        "denied" que não explica nada. Com um destino, a imagem é reetiquetada
        antes: é o passo que faltava entre escolher o registry e publicar nele.
        """
        target = destination.strip() or tag
        if target != tag:
            retag_error = self._run_docker(
                ["tag", tag, target], timeout=60, action=f"Retag para {target}"
            )
            if retag_error is not None:
                return retag_error

        logger.debug(f"Publicando imagem: {target}")
        return self._run_docker(["push", target], timeout=1800, action=f"Push de {target}")

    @staticmethod
    def _run_docker(args: list[str], *, timeout: int, action: str) -> str | None:
        """Um comando do docker, com o erro em texto em vez de exceção."""
        try:
            result = subprocess.run(  # nosec B603  # noqa: S603
                [resolve_executable("docker"), *args],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except (ExecutableNotFoundError, OSError, subprocess.SubprocessError) as e:
            return f"{action} falhou: {e}"

        if result.returncode != 0:
            return f"{action} falhou: {result.stderr.strip()[:500]}"
        return None

    def _get_image_info(self, tag: str) -> dict[str, Any]:
        """Obtém informações da imagem construída."""
        try:
            result = subprocess.run(  # nosec B603  # noqa: S603
                [resolve_executable("docker"), "image", "inspect", tag],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode == 0:
                images = json.loads(result.stdout)
                if images:
                    info: dict[str, Any] = images[0]
                    return info

            return {}
        except Exception as e:
            logger.warning(f"Não foi possível obter info da imagem: {e}")
            return {}

    def _scan_image(self, image_tag: str) -> ScanResult | None:
        """Executa scan de segurança na imagem."""
        logger.info(f"Iniciando scan da imagem: {image_tag}")
        start_time = datetime.now()

        try:
            # Tentar usar Trivy
            result = subprocess.run(  # nosec B603  # noqa: S603
                [
                    resolve_executable("trivy"),
                    "image",
                    "--format",
                    "json",
                    "--severity",
                    "CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN",
                    image_tag,
                ],
                capture_output=True,
                text=True,
                timeout=600,  # 10 minutos
                check=False,
            )

            if result.returncode == 0 and result.stdout:
                scan = self._parse_trivy_scan(json.loads(result.stdout))
                scan.scan_time_seconds = (datetime.now() - start_time).total_seconds()
                return scan
            logger.warning(f"Trivy falhou (exit {result.returncode}), tentando Grype...")

        except ExecutableNotFoundError:
            logger.warning("Trivy não encontrado, tentando Grype...")
        except Exception as e:
            logger.warning(f"Erro no scan com Trivy: {e}")

        # Fallback: tentar Grype
        try:
            result = subprocess.run(  # nosec B603  # noqa: S603
                [
                    resolve_executable("grype"),
                    image_tag,
                    "-o",
                    "json",
                ],
                capture_output=True,
                text=True,
                timeout=600,
                check=False,
            )

            if result.returncode == 0 and result.stdout:
                scan = self._parse_grype_scan(json.loads(result.stdout))
                scan.scan_time_seconds = (datetime.now() - start_time).total_seconds()
                return scan

        except Exception as e:
            logger.warning(f"Grype também falhou: {e}")

        logger.warning("Nenhuma ferramenta de scan disponível")
        return None

    @staticmethod
    def _parse_trivy_scan(data: dict[str, Any]) -> ScanResult:
        """Converte o JSON do Trivy em contagens por severidade."""
        counts = dict.fromkeys(("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"), 0)
        fixable = 0
        vulnerabilities: list[dict[str, Any]] = []

        for finding in data.get("Results", []):
            for vuln in finding.get("Vulnerabilities", []):
                severity = str(vuln.get("Severity", "UNKNOWN")).upper()
                counts[severity if severity in counts else "UNKNOWN"] += 1
                if vuln.get("FixedVersion"):
                    fixable += 1
                vulnerabilities.append(
                    {
                        "cve_id": vuln.get("VulnerabilityID"),
                        "package": vuln.get("PkgName"),
                        "severity": severity,
                        "installed_version": vuln.get("InstalledVersion"),
                        "fixed_version": vuln.get("FixedVersion"),
                    }
                )

        return BuildImageUseCase._scan_result(counts, fixable, vulnerabilities, "trivy")

    @staticmethod
    def _parse_grype_scan(data: dict[str, Any]) -> ScanResult:
        """Converte o JSON do Grype em contagens por severidade.

        Este parser não existia: o fallback devolvia um `ScanResult()` zerado
        com um comentário "parse similar ao Trivy...". Numa máquina só com
        Grype, todo build era reportado com zero vulnerabilidades e
        `--fail-on critical` nunca reprovava nada.
        """
        counts = dict.fromkeys(("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"), 0)
        fixable = 0
        vulnerabilities: list[dict[str, Any]] = []

        for match in data.get("matches", []):
            vuln = match.get("vulnerability", {})
            severity = str(vuln.get("severity", "UNKNOWN")).upper()
            # Grype tem uma faixa a mais que o Trivy; sem isso ela cairia em
            # UNKNOWN e sumiria da contagem de LOW.
            if severity == "NEGLIGIBLE":
                severity = "LOW"
            counts[severity if severity in counts else "UNKNOWN"] += 1

            artifact = match.get("artifact", {})
            fixed_versions = vuln.get("fix", {}).get("versions", []) or []
            if fixed_versions:
                fixable += 1
            vulnerabilities.append(
                {
                    "cve_id": vuln.get("id"),
                    "package": artifact.get("name"),
                    "severity": severity,
                    "installed_version": artifact.get("version"),
                    "fixed_version": fixed_versions[0] if fixed_versions else None,
                }
            )

        return BuildImageUseCase._scan_result(counts, fixable, vulnerabilities, "grype")

    @staticmethod
    def _scan_result(
        counts: dict[str, int],
        fixable: int,
        vulnerabilities: list[dict[str, Any]],
        tool: str,
    ) -> ScanResult:
        return ScanResult(
            critical=counts["CRITICAL"],
            high=counts["HIGH"],
            medium=counts["MEDIUM"],
            low=counts["LOW"],
            unknown=counts["UNKNOWN"],
            total_vulnerabilities=sum(counts.values()),
            fixable=fixable,
            scan_tool=tool,
            vulnerabilities=BuildImageUseCase._worst_first(vulnerabilities),
        )

    #: Achados mantidos na amostra do relatório. As contagens acima são
    #: completas; esta lista existe para o relatório não carregar milhares de
    #: entradas.
    MAX_RETAINED_VULNERABILITIES = 100

    @staticmethod
    def _worst_first(vulnerabilities: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Ordena por severidade antes de cortar a amostra.

        O corte era `vulnerabilities[:100]` na ordem em que o scanner
        devolveu, que é ordem de pacote e não de gravidade. Numa imagem com
        mais de cem achados, as CRITICAL podiam cair inteiramente fora da
        amostra -- e foi o que aconteceu: o portão reprovava (as *contagens*
        estavam certas) enquanto o resumo, que lê a amostra, anunciava
        "0 finding(s) at or above CRITICAL". O leitor recebia uma reprovação
        que se contradizia e nenhum CVE para investigar.

        Ordenar antes de cortar garante que o que decide o portão é o que
        sobrevive na amostra.
        """
        order = {level: index for index, level in enumerate(("CRITICAL", "HIGH", "MEDIUM", "LOW"))}
        ranked = sorted(
            vulnerabilities,
            key=lambda v: order.get(str(v.get("severity", "")).upper(), len(order)),
        )
        return ranked[: BuildImageUseCase.MAX_RETAINED_VULNERABILITIES]

    #: Limiares aceitos por `--fail-on`, do mais severo para o mais brando.
    #: Cada um reprova também tudo que for pior que ele.
    FAIL_ON_THRESHOLDS = ("critical", "high", "medium", "low")

    def _gate_failure_summary(self, scan_result: ScanResult, threshold: str) -> str:
        """Nomeia os CVEs que dispararam o portão.

        "Vulnerabilities exceed threshold (critical)" obriga quem lê o log do
        CI a reabrir o relatório para descobrir *o quê*. O portão passa a
        dizer qual achado o disparou, com pacote e versão de correção.
        """
        cutoff = self.FAIL_ON_THRESHOLDS.index(threshold.strip().lower())
        levels = self.FAIL_ON_THRESHOLDS[: cutoff + 1]
        # A contagem vem do scan completo, nunca da amostra: foi a amostra
        # dizendo "0 finding(s)" numa reprovação que tornou o portão
        # incompreensível. O número que reprova e o número que se lê têm de
        # ser o mesmo número.
        counts = {
            "critical": scan_result.critical,
            "high": scan_result.high,
            "medium": scan_result.medium,
            "low": scan_result.low,
        }
        total = sum(counts[level] for level in levels)
        tripping = {level.upper() for level in levels}
        offenders = [
            v for v in scan_result.vulnerabilities if str(v.get("severity", "")).upper() in tripping
        ]
        header = (
            f"Vulnerabilities exceed threshold ({threshold}): "
            f"{total} finding(s) at or above {threshold.upper()}"
        )
        if not offenders:
            # Não deveria acontecer agora que a amostra é ordenada por
            # severidade, mas se acontecer o leitor precisa saber que o
            # silêncio é falta de amostra, não falta de achado.
            return (
                header
                if total == 0
                else f"{header} (não retidos na amostra do relatório; rode o scanner para a lista)"
            )
        listed = "; ".join(
            f"{v.get('cve_id') or '?'} ({v.get('severity')}) in "
            f"{v.get('package') or '?'} {v.get('installed_version') or ''}".strip()
            + (f" -> {v['fixed_version']}" if v.get("fixed_version") else " (no fix)")
            for v in offenders[:10]
        )
        more = f"; ... and {len(offenders) - 10} more" if len(offenders) > 10 else ""
        return f"{header} -- {listed}{more}"

    def _should_fail(self, scan_result: ScanResult, threshold: str) -> bool:
        """Verifica se deve falhar o build baseado no threshold.

        Só `critical` e `high` eram tratados; qualquer outro valor caía num
        `return False`, então `--fail-on medium` era um portão que nunca
        reprovava -- silenciosamente. Valores desconhecidos agora são
        rejeitados na CLI, antes do build começar.
        """
        counts = {
            "critical": scan_result.critical,
            "high": scan_result.high,
            "medium": scan_result.medium,
            "low": scan_result.low,
        }
        normalized = threshold.strip().lower()
        if normalized not in self.FAIL_ON_THRESHOLDS:
            raise ValueError(
                f"Unknown --fail-on threshold {threshold!r}; "
                f"expected one of: {', '.join(self.FAIL_ON_THRESHOLDS)}"
            )
        cutoff = self.FAIL_ON_THRESHOLDS.index(normalized)
        return any(counts[level] > 0 for level in self.FAIL_ON_THRESHOLDS[: cutoff + 1])

    def _preflight(
        self, request: BuildImageRequest, validation: AnalyzeDockerfileResponse
    ) -> list[PolicyViolation]:
        """As regras que já dá para reprovar sem construir nada.

        Descobrir um rótulo obrigatório faltando depois de dez minutos de build
        e um scan é o tipo de atrito que faz as pessoas pararem de rodar o
        portão. As regras que dependem de medição continuam para depois: elas
        não são consideradas cumpridas aqui, apenas não são conferíveis.
        """
        if request.policy is None:
            return []
        return evaluate(
            request.policy.static_subset(),
            PolicyFacts(
                bases=self._base_facts(request),
                labels=dict(request.labels or {}),
                nonroot=self._nonroot_state(validation.analysis),
            ),
        )

    def _base_facts(self, request: BuildImageRequest) -> tuple[BaseFact, ...]:
        """As bases declaradas, lidas do arquivo com expansão de `ARG`."""
        path = Path(request.context_path) / request.dockerfile_path
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            logger.debug(f"Não foi possível reler {path}: {e}")
            return ()
        return tuple(
            BaseFact(
                reference=base.reference,
                registry=registry_host_of(base.name),
                pinned=base.is_pinned,
            )
            for base in parse_bases(content)
        )

    def _attribute_findings(
        self,
        request: BuildImageRequest,
        validation: AnalyzeDockerfileResponse,
        scan_result: ScanResult | None,
    ) -> InheritanceReport | None:
        """De quem é cada CVE: da base declarada, ou das camadas deste build.

        Um relatório que diz "47 vulnerabilidades" manda consertar sem dizer o
        quê. A resposta exige um segundo scan -- o da base -- e por isso é
        escolha explícita: dobrar o tempo de portão por padrão faria as pessoas
        desligarem o portão.

        Devolve `None` quando ninguém pediu, e um relatório `UNAVAILABLE` com o
        motivo quando pediram e não deu. As duas coisas são diferentes de "tudo
        é seu" e de "tudo é herdado", que seriam as duas formas de transformar
        ausência de medição em acusação.
        """
        if not request.attribute_findings:
            return None
        if scan_result is None:
            return unavailable("", "a imagem construída não pôde ser escaneada")

        analysis = validation.analysis
        base_reference = (analysis.info.final_base_image or "") if analysis else ""
        if not base_reference:
            return unavailable(
                "",
                "não foi possível determinar a base do estágio final a partir do Dockerfile",
            )
        if base_reference.lower() == "scratch":
            # `scratch` não é uma imagem: não há o que escanear, e tudo que a
            # imagem carrega veio das camadas deste build. Dizer isso é
            # atribuição, não omissão.
            return attribute(
                _as_vulnerabilities(scan_result.vulnerabilities), [], base_reference=base_reference
            )

        logger.info(f"Escaneando a base {base_reference} para atribuir os achados")
        base_scan = self._scan_image(base_reference)
        if base_scan is None:
            return unavailable(
                base_reference,
                f"a base {base_reference} não pôde ser escaneada",
            )
        return attribute(
            _as_vulnerabilities(scan_result.vulnerabilities),
            _as_vulnerabilities(base_scan.vulnerabilities),
            base_reference=base_reference,
        )

    def _policy_facts(
        self,
        *,
        request: BuildImageRequest,
        analysis: DockerfileAnalysis | None,
        scan_result: ScanResult | None,
        source_before: SourceDigests,
        source_after: SourceDigests,
        image_id: str,
    ) -> PolicyFacts:
        """Os fatos medidos neste build, no formato que a política avalia.

        Nada aqui infere: cada campo ou vem de uma medição que aconteceu ou
        fica no valor que significa "não medido". É o que faz a política
        reprovar por ausência de prova em vez de aprovar por falta de sinal.
        """
        counts: dict[str, int] = {}
        if scan_result is not None:
            counts = {
                "critical": scan_result.critical,
                "high": scan_result.high,
                "medium": scan_result.medium,
                "low": scan_result.low,
            }

        bases = tuple(
            BaseFact(
                reference=reference,
                registry=registry_host_of(reference),
                pinned=bool(digest) or "@sha256:" in reference,
            )
            for reference, digest in source_before.base_images.items()
        )

        # A procedência é recalculada aqui e não lida do documento: o registro
        # final só existe depois do push, e a política precisa decidir antes.
        parcial = BuildProvenance(
            tag=request.tag,
            source=source_before,
            source_after=source_after,
            artifact=ArtifactDigests(image_id=image_id),
        )

        return PolicyFacts(
            scan_ran=scan_result is not None,
            severity_counts=counts,
            bases=bases,
            labels=dict(request.labels or {}),
            nonroot=self._nonroot_state(analysis),
            provenance_status=str(parcial.status),
        )

    @staticmethod
    def _nonroot_state(analysis: DockerfileAnalysis | None) -> Tristate:
        """Se a imagem roda sem privilégio, segundo o que a validação mediu.

        A ausência da checagem é `UNKNOWN`, e não `FALSE`: não ter medido não
        é ter medido e reprovado, e a política distingue os dois na mensagem.
        O veredito vem do DF002, que já sabe que `USER 0` e `USER 0:0` são root
        tanto quanto `USER root` -- reimplementar a leitura aqui seria manter
        duas definições de "sem privilégio" que divergiriam na primeira
        correção.
        """
        if analysis is None:
            return Tristate.UNKNOWN
        for check in analysis.validation.checks:
            if check.rule_id == "DF002":
                return Tristate.of(check.status is ValidationStatus.PASS)
        return Tristate.UNKNOWN

    def _digest_source(self, context_path: str, dockerfile_path: str) -> SourceDigests:
        """Digere a entrada do build: Dockerfile, contexto, bases e revisão.

        Nada aqui é fatal. Um contexto que não pôde ser digerido devolve
        campos vazios, e a procedência se declara `INCOMPLETE` -- que é a
        ausência de prova, não uma acusação, e é muito diferente de fingir
        que a cadeia fechou.
        """
        root = Path(context_path)
        dockerfile = (
            root / dockerfile_path
            if not Path(dockerfile_path).is_absolute()
            else Path(dockerfile_path)
        )

        dockerfile_digest = ""
        base_images: dict[str, str] = {}
        if dockerfile.is_file():
            try:
                dockerfile_digest = hash_file(dockerfile)
                base_images = self._declared_bases(dockerfile)
            except OSError as e:
                logger.warning(f"Não foi possível digerir {dockerfile}: {e}")

        context_digest, counted = "", 0
        try:
            context_digest, counted = hash_context(root)
        except (OSError, ContextTooLargeError) as e:
            logger.warning(f"Não foi possível digerir o contexto {root}: {e}")

        revision, dirty = self._git_state(root)
        return SourceDigests(
            dockerfile=dockerfile_digest,
            context=context_digest,
            context_files=counted,
            base_images=base_images,
            git_revision=revision,
            git_dirty=dirty,
        )

    @staticmethod
    def _declared_bases(dockerfile: Path) -> dict[str, str]:
        """Cada `FROM` e o digest que ele fixa, quando fixa.

        Uma base sem digest é uma tag móvel, e registrar isso vale mais do
        que omitir: é exatamente a diferença entre um build reproduzível e um
        que depende do dia.
        """
        bases: dict[str, str] = {}
        try:
            content = dockerfile.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return bases
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped.upper().startswith("FROM "):
                continue
            reference = stripped.split()[1]
            _, separator, digest = reference.partition("@")
            bases[reference] = digest if separator else ""
        return bases

    @staticmethod
    def _git_state(root: Path) -> tuple[str, bool]:
        """Commit e limpeza da árvore. Um commit sozinho mentiria sobre o que
        gerou a imagem se houvesse alteração não commitada."""
        try:
            revision = subprocess.run(  # nosec B603  # noqa: S603
                [resolve_executable("git"), "-C", str(root), "rev-parse", "HEAD"],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            if revision.returncode != 0:
                return "", False
            status = subprocess.run(  # nosec B603  # noqa: S603
                [resolve_executable("git"), "-C", str(root), "status", "--porcelain"],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            return revision.stdout.strip(), bool(status.stdout.strip())
        except (ExecutableNotFoundError, OSError, subprocess.SubprocessError):
            return "", False

    def _repo_digest(self, reference: str) -> str:
        """O digest do manifesto, que só existe depois de um push."""
        info = self._get_image_info(reference)
        digests = info.get("RepoDigests") or []
        for entry in digests:
            _, separator, digest = str(entry).partition("@")
            if separator:
                return digest
        return ""

    @staticmethod
    def _archive_provenance(provenance: BuildProvenance, destination: str) -> None:
        """Arquiva o documento ao lado do relatório. Falhar aqui não invalida
        o build: a procedência já está na resposta."""
        if not destination:
            return
        try:
            path = Path(destination)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps(provenance.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8"
            )
            logger.info(f"Procedência arquivada em {path}")
        except OSError as e:
            logger.warning(f"Não foi possível arquivar a procedência: {e}")

    def _generate_report(
        self,
        validation: Any,
        build: BuildResult,
        scan: ScanResult | None,
        image_tag: str,
        dockerfile_path: str,
        remediation_history: list[dict[str, Any]] | None = None,
    ) -> BuildReport:
        """Gera relatório completo do build."""
        now = datetime.now(tz=UTC)
        build_id = self._new_build_id(image_tag)

        # Calcular score de segurança
        security_score = self._calculate_security_score(validation, scan)
        security_tier = self._calculate_security_tier(security_score)

        # Extrair checks de validação
        validation_dict = self._validation_dict(validation.validation)

        # Resultados do scan
        scan_dict = None
        if scan:
            scan_dict = {
                "trivy" if scan.scan_tool == "trivy" else "grype": {
                    "critical": scan.critical,
                    "high": scan.high,
                    "medium": scan.medium,
                    "low": scan.low,
                },
            }

        # Metadados do build
        git_sha = self._get_git_sha()
        metadata = {
            "timestamp": now.isoformat(),
            "git_sha": git_sha,
            "built_by": os.environ.get("USER", "unknown"),
            "docker_version": self._get_docker_version(),
            "buildkit": True,
        }

        # Recomendações: vêm das sugestões de hardening. `DockerfileAnalysis`
        # nunca teve um atributo `recommendations` -- o acesso antigo só não
        # explodia porque `analysis` era sempre None nos testes.
        recommendations = self._recommendation_dicts(list(validation.suggestions or []))

        history = remediation_history or []
        return BuildReport(
            build_id=build_id,
            timestamp=now.isoformat(),
            image=image_tag,
            dockerfile_path=dockerfile_path,
            validation=validation_dict,
            scan_results=scan_dict,
            security_score=security_score,
            security_tier=security_tier,
            recommendations=recommendations,
            build_metadata=metadata,
            remediation_history=history,
            auto_remediated=bool(history),
        )

    def _calculate_security_score(self, validation: Any, scan: ScanResult | None) -> int:
        """Calcula score de segurança (0-100)."""
        score = 100

        # Penalizar erros de validação
        if validation.validation:
            score -= validation.validation.errors * 10
            score -= validation.validation.warnings * 3

        # Penalizar vulnerabilidades
        if scan:
            score -= scan.critical * 15
            score -= scan.high * 10
            score -= scan.medium * 3
            score -= scan.low * 1

        return max(0, min(100, score))

    def _calculate_security_tier(self, score: int) -> str:
        """Calcula tier de segurança baseado no score."""
        if score >= 90:
            return "A"
        elif score >= 75:
            return "B"
        elif score >= 60:
            return "C"
        elif score >= 40:
            return "D"
        else:
            return "F"

    def _get_git_sha(self) -> str | None:
        """Obtém SHA do git atual.

        Metadado opcional do relatório: fora de um repositório, ou sem git
        instalado, o relatório sai sem ele em vez de falhar o build.
        """
        return self._capture_output(["git", "rev-parse", "HEAD"], "git SHA")

    def _get_docker_version(self) -> str:
        """Obtém versão do Docker."""
        return self._capture_output(["docker", "--version"], "versão do Docker") or "unknown"

    @staticmethod
    def _capture_output(argv: list[str], what: str) -> str | None:
        """Roda `argv` e devolve seu stdout, ou None se não der.

        A falha é registrada em DEBUG em vez de engolida em silêncio: um
        `except: pass` esconde exatamente o caso que a gente quer investigar
        quando o metadado sai vazio.
        """
        try:
            resolved = [resolve_executable(argv[0]), *argv[1:]]
            result = subprocess.run(  # nosec B603  # noqa: S603
                resolved,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except (ExecutableNotFoundError, OSError, subprocess.SubprocessError) as e:
            logger.debug(f"Não foi possível obter {what}: {e}")
            return None

        if result.returncode != 0:
            logger.debug(f"Não foi possível obter {what}: exit {result.returncode}")
            return None
        return result.stdout.strip()


def _as_vulnerabilities(raw: list[dict[str, Any]]) -> list[Vulnerability]:
    """Converte os achados crus do scanner nas entidades do domínio.

    O `ScanResult` deste módulo carrega dicionários porque o relatório de build
    os serializa direto. A atribuição, porém, é lógica de domínio e trabalha
    com a entidade -- converter aqui é o que evita duas definições de "o que é
    um achado" convivendo no mesmo processo.

    Uma severidade que o scanner reporte com um nome que não conhecemos vira
    `UNKNOWN` em vez de derrubar o build: a atribuição usa CVE e pacote, e a
    severidade é só o que se mostra ao lado.
    """
    findings: list[Vulnerability] = []
    for item in raw:
        severity = str(item.get("severity") or "").strip().upper()
        findings.append(
            Vulnerability(
                cve_id=str(item.get("cve_id") or ""),
                package_name=str(item.get("package") or ""),
                severity=Severity(severity)
                if severity in Severity.__members__
                else Severity.UNKNOWN,
                installed_version=str(item.get("installed_version") or ""),
                fixed_version=str(item.get("fixed_version") or ""),
            )
        )
    return findings
