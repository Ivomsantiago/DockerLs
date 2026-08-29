"""Entidades para análise e validação de Dockerfiles."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from dockerls.domain.security_controls import mapping_for, references_for


class ValidationStatus(StrEnum):
    """Status de uma validação de Dockerfile."""

    # "a verificação passou", não uma senha.
    PASS = "PASS"  # nosec B105  # noqa: S105
    WARN = "WARN"
    FAIL = "FAIL"
    SKIP = "SKIP"


class SeverityLevel(StrEnum):
    """Níveis de severidade para regras de segurança."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class ValidationCheck:
    """Resultado de uma única verificação de validação."""

    check: str
    status: ValidationStatus
    message: str
    severity: SeverityLevel = SeverityLevel.INFO
    line: int | None = None
    rule_id: str | None = None
    fix_suggestion: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def references(self) -> list[str]:
        """Published controls this finding implements, as citable strings.

        Empty when the rule is DockerLs's own guidance rather than a
        published control -- which the renderers state, instead of leaving
        the reader to assume a citation was merely omitted.
        """
        return references_for(self.rule_id)

    @property
    def rationale(self) -> str:
        """Why the rule matters, in terms of what an attacker gains."""
        mapping = mapping_for(self.rule_id)
        return mapping.rationale if mapping else ""

    def model_dump(self) -> dict[str, Any]:
        """Retorna dicionário serializável."""
        return {
            "check": self.check,
            "status": self.status.value,
            "message": self.message,
            "severity": self.severity.value,
            "line": self.line,
            "rule_id": self.rule_id,
            # The published controls this rule implements, resolved from the
            # catalogue rather than stored per check: the mapping is static,
            # and duplicating it into every finding is how the two drift.
            # Emitted in the payload because a consumer mapping findings onto
            # a compliance programme should not have to know the catalogue.
            "references": self.references,
            "rationale": self.rationale,
            "fix_suggestion": self.fix_suggestion,
            "details": self.details,
        }


@dataclass
class HardeningRule:
    """Regra de hardening sugerida para um Dockerfile."""

    priority: SeverityLevel
    title: str
    description: str
    current_state: str
    suggested_fix: str
    reason: str
    line: int | None = None
    dockerfile_snippet: str | None = None

    def model_dump(self) -> dict[str, Any]:
        """Retorna dicionário serializável."""
        return {
            "priority": self.priority.value,
            "title": self.title,
            "description": self.description,
            "current_state": self.current_state,
            "suggested_fix": self.suggested_fix,
            "reason": self.reason,
            "line": self.line,
            "dockerfile_snippet": self.dockerfile_snippet,
        }


@dataclass
class DockerfileValidationResult:
    """Resultado da validação completa de um Dockerfile."""

    dockerfile_path: str
    passed: int = 0
    warnings: int = 0
    errors: int = 0
    skipped: int = 0
    checks: list[ValidationCheck] = field(default_factory=list)
    recommendations: list[HardeningRule] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_valid(self) -> bool:
        """True se não houver erros críticos."""
        return self.errors == 0

    @property
    def total_checks(self) -> int:
        """Total de verificações realizadas."""
        return self.passed + self.warnings + self.errors + self.skipped

    def add_check(self, check: ValidationCheck) -> None:
        """Adiciona um resultado de verificação."""
        self.checks.append(check)
        if check.status == ValidationStatus.PASS:
            self.passed += 1
        elif check.status == ValidationStatus.WARN:
            self.warnings += 1
        elif check.status == ValidationStatus.FAIL:
            self.errors += 1
        elif check.status == ValidationStatus.SKIP:
            self.skipped += 1

    def model_dump(self) -> dict[str, Any]:
        """Retorna dicionário serializável."""
        return {
            "dockerfile_path": self.dockerfile_path,
            "passed": self.passed,
            "warnings": self.warnings,
            "errors": self.errors,
            "skipped": self.skipped,
            "total_checks": self.total_checks,
            "is_valid": self.is_valid,
            "checks": [c.model_dump() for c in self.checks],
            "recommendations": [r.model_dump() for r in self.recommendations],
            "metadata": self.metadata,
        }


@dataclass
class DockerfileInfo:
    """Informações extraídas de um Dockerfile.

    Os campos de usuário e de base descrevem o **estágio final** -- o único
    que vira a imagem que roda. Um `USER node` num estágio de build não
    protege nada em produção, e por um tempo era exatamente isso que fazia a
    validação dar PASS num container que subia como root.
    """

    base_images: list[str] = field(default_factory=list)
    stages: int = 1
    has_user_directive: bool = False
    user_name: str | None = None
    user_uid: int | None = None
    # Base do estágio final, já resolvida através de `FROM <alias>`.
    final_base_image: str | None = None
    has_healthcheck: bool = False
    has_labels: bool = False
    labels: dict[str, str] = field(default_factory=dict)
    exposes_ports: list[int] = field(default_factory=list)
    entrypoint: str | None = None
    cmd: str | None = None
    uses_buildkit: bool = False
    has_secrets_in_env: bool = False
    secret_env_vars: list[str] = field(default_factory=list)
    package_managers_used: list[str] = field(default_factory=list)
    cache_cleaned: bool = False
    uses_sudo: bool = False
    uses_latest_tag: bool = False
    copy_commands: list[dict[str, Any]] = field(default_factory=list)
    #: Cada `ADD`, com o que nele é diferente de um `COPY`: origens
    #: remotas, arquivos que serão descompactados sozinhos, e se veio com
    #: `--checksum`.
    add_commands: list[dict[str, Any]] = field(default_factory=list)
    run_commands: list[dict[str, Any]] = field(default_factory=list)
    #: `ARG SEGREDO=valor`. Um ARG **com valor** fica no Dockerfile e no
    #: histórico; um ARG sem valor é parâmetro de build e não é infração.
    has_secrets_in_build_args: bool = False
    secret_build_args: list[str] = field(default_factory=list)
    #: `curl ... | sh`: script da rede executado sem nada tê-lo conferido.
    pipes_remote_script_to_shell: bool = False
    remote_script_lines: list[int] = field(default_factory=list)
    #: `chmod u+s` / `chmod 4755`: binário setuid deixado dentro da imagem.
    sets_setuid_bit: bool = False
    setuid_lines: list[int] = field(default_factory=list)
    raw_lines: list[str] = field(default_factory=list)

    def model_dump(self) -> dict[str, Any]:
        """Retorna dicionário serializável."""
        return {
            "base_images": self.base_images,
            "final_base_image": self.final_base_image,
            "stages": self.stages,
            "has_user_directive": self.has_user_directive,
            "user_name": self.user_name,
            "user_uid": self.user_uid,
            "has_healthcheck": self.has_healthcheck,
            "has_labels": self.has_labels,
            "labels": self.labels,
            "exposes_ports": self.exposes_ports,
            "entrypoint": self.entrypoint,
            "cmd": self.cmd,
            "uses_buildkit": self.uses_buildkit,
            "has_secrets_in_env": self.has_secrets_in_env,
            "secret_env_vars": self.secret_env_vars,
            "package_managers_used": self.package_managers_used,
            "cache_cleaned": self.cache_cleaned,
            "uses_sudo": self.uses_sudo,
            "uses_latest_tag": self.uses_latest_tag,
            "copy_commands": self.copy_commands,
            "add_commands": self.add_commands,
            "run_commands": self.run_commands,
            "has_secrets_in_build_args": self.has_secrets_in_build_args,
            "secret_build_args": self.secret_build_args,
            "pipes_remote_script_to_shell": self.pipes_remote_script_to_shell,
            "sets_setuid_bit": self.sets_setuid_bit,
        }


@dataclass
class DockerfileAnalysis:
    """Análise completa de um Dockerfile."""

    info: DockerfileInfo
    validation: DockerfileValidationResult
    security_score: int = 0
    security_tier: str = "C"

    @property
    def is_production_ready(self) -> bool:
        """True se o Dockerfile está pronto para produção."""
        return self.security_tier in ("A", "B") and self.validation.is_valid

    def model_dump(self) -> dict[str, Any]:
        """Retorna dicionário serializável."""
        return {
            "info": self.info.model_dump(),
            "validation": self.validation.model_dump(),
            "security_score": self.security_score,
            "security_tier": self.security_tier,
            "is_production_ready": self.is_production_ready,
        }
