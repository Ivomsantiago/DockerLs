"""Implementação do validador de Dockerfiles."""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from pathlib import Path

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


class UnknownHardeningTemplateError(ValueError):
    """Pediu-se um template hardened que esta instalação não tem.

    `ValueError` de propósito: a CLI já trata `ValueError` como erro de uso
    (mensagem, sem stack trace), e o caso de uso de build o converte numa
    resposta com `EXIT_ERROR`.
    """


@dataclass
class _Stage:
    """Um estágio (`FROM ... [AS alias]`) e o que foi declarado dentro dele.

    O parser precisa disso porque quase toda propriedade de runtime -- quem
    é o usuário, qual é a base -- só importa no estágio final.
    """

    base: str
    alias: str | None = None
    user: str | None = None
    uid: int | None = None


class DockerfileParser:
    """Parser simples para Dockerfiles.

    Extrai informações estruturais de um Dockerfile sem depender
    de bibliotecas externas complexas.
    """

    # Padrões regex para diretivas Dockerfile
    FROM_PATTERN = re.compile(r"^FROM\s+(.+?)(?:\s+AS\s+(\S+))?$", re.IGNORECASE)
    RUN_PATTERN = re.compile(r"^RUN\s+(.+)$", re.IGNORECASE | re.DOTALL)
    COPY_PATTERN = re.compile(
        r"^COPY\s+(?:--chown=(\S+:\S+)\s+)?(?:--from=(\S+)\s+)?(\S+)\s+(\S+)$",
        re.IGNORECASE,
    )
    ENV_PREFIX = re.compile(r"^ENV\s+(.+)$", re.IGNORECASE)
    # Pares chave=valor de uma linha ENV, com valor opcionalmente entre aspas.
    ENV_KV = re.compile(r"""([\w.\-]+)=(?:"[^"]*"|'[^']*'|\S*)""")
    LABEL_PREFIX = re.compile(r"^LABEL\s+(.+)$", re.IGNORECASE | re.DOTALL)
    EXPOSE_PATTERN = re.compile(r"^EXPOSE\s+(\d+)", re.IGNORECASE)
    USER_PATTERN = re.compile(r"^USER\s+(\S+)(?::(\d+))?$", re.IGNORECASE)
    HEALTHCHECK_PATTERN = re.compile(r"^HEALTHCHECK\s+", re.IGNORECASE)
    ENTRYPOINT_PATTERN = re.compile(r"^ENTRYPOINT\s+(.+)$", re.IGNORECASE)
    CMD_PATTERN = re.compile(r"^CMD\s+(.+)$", re.IGNORECASE)
    ARG_PATTERN = re.compile(r"^ARG\s+(\S+)(?:=(.*))?$", re.IGNORECASE)
    WORKDIR_PATTERN = re.compile(r"^WORKDIR\s+(\S+)$", re.IGNORECASE)

    # Secret patterns - variáveis que podem conter segredos
    SECRET_ENV_PATTERNS = [
        r"(?i)password",
        r"(?i)passwd",
        r"(?i)secret",
        r"(?i)token",
        r"(?i)api[_-]?key",
        r"(?i)auth",
        r"(?i)credential",
        r"(?i)private[_-]?key",
        r"(?i)access[_-]?key",
    ]

    def __init__(self) -> None:
        self._lines: list[str] = []
        self._info = DockerfileInfo()
        self._stages: list[_Stage] = []

    def parse(self, content: str) -> DockerfileInfo:
        """Parseia o conteúdo de um Dockerfile.

        Args:
            content: Conteúdo do Dockerfile como string.

        Returns:
            DockerfileInfo com informações extraídas.
        """
        self._lines = content.splitlines()
        self._info = DockerfileInfo(raw_lines=self._lines.copy())
        self._stages = []

        line_continuation = ""
        continuation_start = 0

        for line_num, line in enumerate(self._lines, 1):
            # Handle line continuations with backslash
            if line.rstrip().endswith("\\"):
                if not line_continuation:
                    continuation_start = line_num
                line_continuation += line.rstrip()[:-1] + " "
                continue
            elif line_continuation:
                line = line_continuation + line.lstrip()
                line_num = continuation_start
                line_continuation = ""

            line = line.strip()

            # Skip comments and empty lines
            if not line or line.startswith("#"):
                continue

            self._parse_line(line, line_num)

        # Um arquivo que termina numa barra invertida deixava a diretiva
        # pendente no buffer e ela sumia: um `RUN ... \` final -- com sudo,
        # com segredo, com o que fosse -- nunca era verificado.
        if line_continuation.strip():
            self._parse_line(line_continuation.strip(), continuation_start)

        self._info.stages = max(1, len(self._stages))
        self._resolve_final_stage()
        return self._info

    def _resolve_final_stage(self) -> None:
        """Projeta no `DockerfileInfo` o que vale no estágio final.

        `FROM builder` herda o USER do estágio referenciado, então a
        resolução caminha pela cadeia de aliases até achar um USER ou uma
        base externa. Sem isso, um `USER node` num estágio de build fazia a
        imagem final -- que sobe como root -- passar na validação.
        """
        if not self._stages:
            return

        final = self._stages[-1]
        by_alias = {s.alias.lower(): s for s in self._stages if s.alias}

        stage: _Stage | None = final
        visited: set[int] = set()
        while stage is not None and id(stage) not in visited:
            visited.add(id(stage))
            if stage.user is not None:
                self._info.has_user_directive = True
                self._info.user_name = stage.user
                self._info.user_uid = stage.uid
                break
            stage = by_alias.get(stage.base.lower())

        # Base efetiva do estágio final, resolvida pela mesma cadeia.
        stage = final
        visited = set()
        while stage is not None and id(stage) not in visited:
            visited.add(id(stage))
            parent = by_alias.get(stage.base.lower())
            if parent is None:
                self._info.final_base_image = stage.base
                break
            stage = parent

    def _parse_line(self, line: str, line_num: int) -> None:
        """Parseia uma linha específica do Dockerfile."""

        # FROM
        if match := self.FROM_PATTERN.match(line):
            image = match.group(1).strip()
            alias = match.group(2)
            self._info.base_images.append(image)
            self._stages.append(_Stage(base=image, alias=alias))
            # `FROM builder` referencia um estágio anterior, não um registry:
            # a ausência de tag ali não é um :latest implícito.
            is_stage_reference = any(
                s.alias and s.alias.lower() == image.lower() for s in self._stages[:-1]
            )
            if (
                not is_stage_reference
                and not self._is_scratch(image)
                and (":latest" in image or (":" not in image and "@" not in image))
            ):
                self._info.uses_latest_tag = True

        # RUN
        elif match := self.RUN_PATTERN.match(line):
            cmd = match.group(1)
            self._info.run_commands.append({"line": line_num, "command": cmd})

            # Check for sudo
            if "sudo" in cmd:
                self._info.uses_sudo = True

            # Check package managers
            pkg_managers = ["apt-get", "apt", "apk", "yum", "dnf", "pip", "npm", "yarn"]
            for pm in pkg_managers:
                if pm in cmd and pm not in self._info.package_managers_used:
                    self._info.package_managers_used.append(pm)

            # Check cache cleaning
            cache_clean_patterns = [
                "rm -rf /var/cache/apk/*",
                "rm -rf /var/cache/apt/archives",
                "apt-get clean",
                "rm -rf ~/.cache/pip",
                "npm cache clean",
                "--no-cache-dir",
                "--no-install-recommends",
            ]
            if any(pattern in cmd for pattern in cache_clean_patterns):
                self._info.cache_cleaned = True

        # COPY
        elif match := self.COPY_PATTERN.match(line):
            chown = match.group(1)
            from_stage = match.group(2)
            src = match.group(3)
            dest = match.group(4)
            self._info.copy_commands.append(
                {
                    "line": line_num,
                    "chown": chown,
                    "from_stage": from_stage,
                    "source": src,
                    "destination": dest,
                }
            )

        # ENV
        elif self.ENV_PREFIX.match(line):
            for env_name in self._env_names(line):
                if self._is_secret_name(env_name):
                    self._info.has_secrets_in_env = True
                    if env_name not in self._info.secret_env_vars:
                        self._info.secret_env_vars.append(env_name)

        # LABEL
        elif match := self.LABEL_PREFIX.match(line):
            for label_key, label_value in _parse_label_pairs(match.group(1)).items():
                self._info.labels[label_key] = label_value
                self._info.has_labels = True

        # EXPOSE
        elif match := self.EXPOSE_PATTERN.match(line):
            port = int(match.group(1))
            if port not in self._info.exposes_ports:
                self._info.exposes_ports.append(port)

        # USER -- registrado no estágio corrente; qual deles vale é decidido
        # em _resolve_final_stage().
        elif match := self.USER_PATTERN.match(line):
            if self._stages:
                name, _, group = match.group(1).partition(":")
                self._stages[-1].user = name
                uid = match.group(2) or (group if group.isdigit() else None)
                self._stages[-1].uid = int(uid) if uid else None

        # HEALTHCHECK
        elif self.HEALTHCHECK_PATTERN.match(line):
            self._info.has_healthcheck = True

        # ENTRYPOINT
        elif match := self.ENTRYPOINT_PATTERN.match(line):
            self._info.entrypoint = match.group(1).strip()

        # CMD
        elif match := self.CMD_PATTERN.match(line):
            self._info.cmd = match.group(1).strip()

        # ARG (BuildKit detection)
        elif match := self.ARG_PATTERN.match(line):
            arg_name = match.group(1)
            if arg_name in ("BUILDKIT_INLINE_CACHE", "DOCKER_BUILDKIT"):
                self._info.uses_buildkit = True

    @staticmethod
    def _is_scratch(image: str) -> bool:
        """`FROM scratch` é a imagem vazia embutida no Docker -- não é um
        repositório e não tem tag nenhuma para pinar.

        Tratá-la como "sem tag, logo :latest" reprovava com severidade HIGH
        exatamente os Dockerfiles mais enxutos que existem (binário estático
        sobre scratch), inclusive o template Go desta própria ferramenta.
        """
        # `FROM --platform=$BUILDPLATFORM scratch` também precisa casar.
        parts = [p for p in image.split() if not p.startswith("--")]
        return bool(parts) and parts[-1].lower() == "scratch"

    def _env_names(self, line: str) -> list[str]:
        """Nomes de variáveis declarados numa linha ENV.

        Cobre as duas formas que o Docker aceita, e a antiga regex cobria
        meia: `ENV A=1 B=2` (só via `A`, então um segredo em `B` passava
        batido) e `ENV KEY value` (não casava, então nunca era verificada).
        A regra do Docker para distinguir: se o primeiro token tem `=`, é a
        forma de múltiplos pares.
        """
        match = self.ENV_PREFIX.match(line)
        if not match:
            return []

        body = match.group(1).strip()
        first = body.split(maxsplit=1)[0] if body else ""
        if "=" not in first:
            return [first] if first else []
        return self.ENV_KV.findall(body)

    def _is_secret_name(self, name: str) -> bool:
        """Verifica se um nome de variável parece ser um segredo."""
        return any(re.search(pattern, name) for pattern in self.SECRET_ENV_PATTERNS)


class DockerfileValidator(DockerfileValidatorInterface):
    """Validador de Dockerfiles baseado em regras OWASP."""

    def __init__(self, template_provider: HardeningTemplateProvider | None = None):
        self._parser = DockerfileParser()
        self._template_provider = template_provider

    def validate(self, dockerfile_path: str | Path) -> DockerfileValidationResult:
        """Valida um Dockerfile contra regras OWASP."""
        path = Path(dockerfile_path)
        if path.is_dir():
            path = path / "Dockerfile"

        if not path.exists():
            raise FileNotFoundError(f"Dockerfile not found at {path}")

        content = path.read_text(encoding="utf-8")
        info = self._parser.parse(content)

        result = DockerfileValidationResult(
            dockerfile_path=str(path),
            metadata={
                "base_images": info.base_images,
                "stages": info.stages,
            },
        )

        # Executar todas as verificações
        self._check_base_image(info, result)
        self._check_non_root_user(info, result)
        self._check_multi_stage(info, result)
        self._check_secrets_in_env(info, result)
        self._check_package_cache(info, result)
        self._check_healthcheck(info, result)
        self._check_security_labels(info, result)
        self._check_minimal_base(info, result)
        self._check_no_sudo(info, result)
        self._check_entrypoint_form(info, result)
        self._check_shell_usage(info, result)
        self._check_dockerignore(info, result, path.parent)

        return result

    def analyze(self, dockerfile_path: str | Path) -> DockerfileAnalysis:
        """Analisa um Dockerfile e retorna análise completa."""
        path = Path(dockerfile_path)
        if path.is_dir():
            path = path / "Dockerfile"

        if not path.exists():
            raise FileNotFoundError(f"Dockerfile not found at {path}")

        content = path.read_text(encoding="utf-8")
        info = self._parser.parse(content)
        validation = self.validate(path)

        # Calcular score de segurança
        security_score = self._calculate_security_score(validation)
        security_tier = self._calculate_security_tier(security_score, validation)

        return DockerfileAnalysis(
            info=info,
            validation=validation,
            security_score=security_score,
            security_tier=security_tier,
        )

    def suggest_hardening(self, dockerfile_path: str | Path) -> list[HardeningRule]:
        """Sugere melhorias de hardening para um Dockerfile."""
        analysis = self.analyze(dockerfile_path)
        suggestions = []

        # Base image upgrade
        if analysis.info.uses_latest_tag or not self._is_minimal_base(analysis.info):
            base = analysis.info.base_images[0] if analysis.info.base_images else "unknown"
            suggestions.append(
                HardeningRule(
                    priority=SeverityLevel.HIGH,
                    title="Upgrade base image",
                    description="Use a pinned, minimal base image",
                    current_state=base,
                    # Esta sugestão era a string fixa
                    # `"FROM node:22-alpine or FROM chainguard/node:latest-dev"`,
                    # devolvida igual para qualquer Dockerfile -- inclusive um
                    # de Python, onde nomear uma imagem Node é simplesmente
                    # errado. Nomear uma imagem que ninguém mediu é o oposto do
                    # que esta ferramenta faz em todo o resto, então ela agora
                    # aponta para os comandos que medem de verdade.
                    suggested_fix=(
                        "dockerls base --dry-run          # pins the base by digest\n"
                        "dockerls base --alternatives     # measures safer alternatives"
                    ),
                    reason=(
                        "Pinned versions ensure reproducibility; minimal bases reduce "
                        "attack surface. Which base is actually safer for this project "
                        "is a measurement, not a name -- `dockerls base --alternatives` "
                        "scans the current base alongside the candidates"
                    ),
                )
            )

        # Non-root user
        if not analysis.info.has_user_directive:
            suggestions.append(
                HardeningRule(
                    priority=SeverityLevel.HIGH,
                    title="Add non-root user",
                    description="Container should not run as root",
                    current_state="No USER directive",
                    suggested_fix="RUN adduser -D appuser && USER appuser",
                    reason="Running as root increases impact of container breakout",
                )
            )

        # Secrets in ENV
        if analysis.info.has_secrets_in_env:
            suggestions.append(
                HardeningRule(
                    priority=SeverityLevel.CRITICAL,
                    title="Remove secrets from ENV",
                    description="Secrets in ENV are visible in image history",
                    current_state=f"Secrets: {', '.join(analysis.info.secret_env_vars)}",
                    suggested_fix="Use BuildKit secrets: RUN --mount=type=secret,id=token",
                    reason="ENV values persist in all layers and can be extracted",
                )
            )

        # Healthcheck
        if not analysis.info.has_healthcheck:
            suggestions.append(
                HardeningRule(
                    priority=SeverityLevel.LOW,
                    title="Add HEALTHCHECK",
                    description="Containers should have health checks",
                    current_state="No HEALTHCHECK directive",
                    suggested_fix="HEALTHCHECK --interval=30s --timeout=5s CMD curl http://localhost/health",
                    reason="Health checks enable orchestration platforms to detect failures",
                )
            )

        # Security labels
        if not analysis.info.has_labels or "security.scanner" not in analysis.info.labels:
            suggestions.append(
                HardeningRule(
                    priority=SeverityLevel.LOW,
                    title="Add security labels",
                    description="Labels improve traceability and incident response",
                    current_state="Missing security labels",
                    suggested_fix=(
                        'LABEL security.scanner="dockerls"\n'
                        'LABEL security.cve-contact="security@company.com"'
                    ),
                    reason=(
                        "Labels enable automated policy enforcement and contact during incidents"
                    ),
                )
            )

        # Package cache
        if analysis.info.package_managers_used and not analysis.info.cache_cleaned:
            suggestions.append(
                HardeningRule(
                    priority=SeverityLevel.MEDIUM,
                    title="Clean package manager cache",
                    description="Package caches increase image size unnecessarily",
                    current_state="Cache not cleaned",
                    suggested_fix=(
                        "Add && rm -rf /var/cache/apk/* || rm -rf /var/cache/apt/archives"
                    ),
                    reason="Smaller images have smaller attack surface and faster pulls",
                )
            )

        # Multi-stage
        if analysis.info.stages < 2 and len(analysis.info.package_managers_used) > 0:
            suggestions.append(
                HardeningRule(
                    priority=SeverityLevel.MEDIUM,
                    title="Use multi-stage build",
                    description="Multi-stage builds reduce final image size",
                    current_state=f"Single stage ({analysis.info.stages} stage(s))",
                    suggested_fix="Create separate builder and runtime stages",
                    reason="Build tools and intermediate files don't belong in production images",
                )
            )

        return suggestions

    def _check_base_image(self, info: DockerfileInfo, result: DockerfileValidationResult) -> None:
        """Verifica se a base image usa tag pinned."""
        if info.uses_latest_tag:
            result.add_check(
                ValidationCheck(
                    check="base_image_pinned",
                    status=ValidationStatus.FAIL,
                    message="Base image uses 'latest' tag or no tag (implies latest)",
                    severity=SeverityLevel.HIGH,
                    rule_id="DF001",
                    fix_suggestion="Use specific version: FROM node:22-alpine (not :latest)",
                    details={"base_images": info.base_images},
                )
            )
        else:
            # PASS aqui significa apenas "não é `latest`". Dizer "pinned" sem
            # mais nada punha um ✅ ao lado de `node:22` na mesma tela em que a
            # política reprovava a mesma linha por "não está fixada por
            # digest" -- duas frases verdadeiras que, lidas juntas, pareciam
            # contradição. A distinção agora está na própria mensagem.
            por_digest = all("@sha256:" in reference for reference in info.base_images)
            message = (
                "Base image pinned by digest"
                if por_digest
                else "Base image tag is not 'latest' (still a moving tag -- "
                "`dockerls base` pins it by digest)"
            )
            result.add_check(
                ValidationCheck(
                    check="base_image_pinned",
                    status=ValidationStatus.PASS,
                    message=message,
                    severity=SeverityLevel.INFO,
                    rule_id="DF001",
                    details={"base_images": info.base_images, "pinned_by_digest": por_digest},
                )
            )

    def _check_non_root_user(
        self, info: DockerfileInfo, result: DockerfileValidationResult
    ) -> None:
        """Verifica se o container roda como usuário não-root.

        `USER 0` e `USER 0:0` são root tanto quanto `USER root` -- e passavam,
        porque a checagem só comparava com a string "root". Um Dockerfile
        podia rodar como uid 0 e ainda assim receber PASS nesta regra.
        """
        if info.has_user_directive and info.user_name and not self._is_root_user(info):
            result.add_check(
                ValidationCheck(
                    check="non_root_user",
                    status=ValidationStatus.PASS,
                    message=f"Container runs as non-root user: {info.user_name}",
                    severity=SeverityLevel.INFO,
                    rule_id="DF002",
                    details={"user": info.user_name, "uid": info.user_uid},
                )
            )
        else:
            result.add_check(
                ValidationCheck(
                    check="non_root_user",
                    status=ValidationStatus.FAIL,
                    message="Container runs as root (no USER directive or USER root)",
                    severity=SeverityLevel.HIGH,
                    rule_id="DF002",
                    fix_suggestion="ADD USER appuser\nUSER appuser",
                )
            )

    @staticmethod
    def _is_root_user(info: DockerfileInfo) -> bool:
        name = (info.user_name or "").strip().lower()
        return name in ("root", "0") or info.user_uid == 0

    def _check_multi_stage(self, info: DockerfileInfo, result: DockerfileValidationResult) -> None:
        """Verifica se usa multi-stage build."""
        if info.stages > 1:
            result.add_check(
                ValidationCheck(
                    check="multi_stage_build",
                    status=ValidationStatus.PASS,
                    message=f"Multi-stage build detected ({info.stages} stages)",
                    severity=SeverityLevel.INFO,
                    rule_id="DF003",
                    details={"stages": info.stages},
                )
            )
        else:
            result.add_check(
                ValidationCheck(
                    check="multi_stage_build",
                    status=ValidationStatus.WARN,
                    message="Single-stage build detected",
                    severity=SeverityLevel.MEDIUM,
                    rule_id="DF003",
                    fix_suggestion="Create builder stage separate from runtime",
                )
            )

    def _check_secrets_in_env(
        self, info: DockerfileInfo, result: DockerfileValidationResult
    ) -> None:
        """Verifica se há segredos em variáveis ENV."""
        if info.has_secrets_in_env:
            result.add_check(
                ValidationCheck(
                    check="secrets_not_in_env",
                    status=ValidationStatus.FAIL,
                    message=f"Potential secrets in ENV: {', '.join(info.secret_env_vars)}",
                    severity=SeverityLevel.CRITICAL,
                    rule_id="DF004",
                    fix_suggestion="Use BuildKit: RUN --mount=type=secret,id=token",
                    details={"secret_vars": info.secret_env_vars},
                )
            )
        else:
            result.add_check(
                ValidationCheck(
                    check="secrets_not_in_env",
                    status=ValidationStatus.PASS,
                    message="No obvious secrets in ENV variables",
                    severity=SeverityLevel.INFO,
                    rule_id="DF004",
                )
            )

    def _check_package_cache(
        self, info: DockerfileInfo, result: DockerfileValidationResult
    ) -> None:
        """Verifica se o cache do package manager foi limpo."""
        if info.package_managers_used:
            if info.cache_cleaned:
                result.add_check(
                    ValidationCheck(
                        check="package_cache_clean",
                        status=ValidationStatus.PASS,
                        message="Package manager cache is cleaned",
                        severity=SeverityLevel.INFO,
                        rule_id="DF005",
                    )
                )
            else:
                result.add_check(
                    ValidationCheck(
                        check="package_cache_clean",
                        status=ValidationStatus.WARN,
                        message="Package manager cache not cleaned",
                        severity=SeverityLevel.MEDIUM,
                        rule_id="DF005",
                        fix_suggestion=(
                            "Add: && rm -rf /var/cache/apk/* || rm -rf /var/cache/apt/archives"
                        ),
                    )
                )

    def _check_healthcheck(self, info: DockerfileInfo, result: DockerfileValidationResult) -> None:
        """Verifica se existe HEALTHCHECK."""
        if info.has_healthcheck:
            result.add_check(
                ValidationCheck(
                    check="healthcheck_present",
                    status=ValidationStatus.PASS,
                    message="HEALTHCHECK directive present",
                    severity=SeverityLevel.INFO,
                    rule_id="DF006",
                )
            )
        else:
            result.add_check(
                ValidationCheck(
                    check="healthcheck_present",
                    status=ValidationStatus.WARN,
                    message="No HEALTHCHECK directive",
                    severity=SeverityLevel.LOW,
                    rule_id="DF006",
                    fix_suggestion="HEALTHCHECK --interval=30s --timeout=5s CMD curl http://localhost/health",
                )
            )

    def _check_security_labels(
        self, info: DockerfileInfo, result: DockerfileValidationResult
    ) -> None:
        """Verifica se existem labels de segurança."""
        required_labels = ["security.scanner", "maintainer"]
        missing = [lbl for lbl in required_labels if lbl not in info.labels]

        if not missing:
            result.add_check(
                ValidationCheck(
                    check="security_labels",
                    status=ValidationStatus.PASS,
                    message="Security labels present",
                    severity=SeverityLevel.INFO,
                    rule_id="DF007",
                )
            )
        else:
            result.add_check(
                ValidationCheck(
                    check="security_labels",
                    status=ValidationStatus.WARN,
                    message=f"Missing security labels: {', '.join(missing)}",
                    severity=SeverityLevel.LOW,
                    rule_id="DF007",
                    fix_suggestion=(
                        'LABEL security.scanner="dockerls"\nLABEL maintainer="team@company.com"'
                    ),
                )
            )

    def _check_minimal_base(self, info: DockerfileInfo, result: DockerfileValidationResult) -> None:
        """Verifica se a base image é minimal."""
        if self._is_minimal_base(info):
            result.add_check(
                ValidationCheck(
                    check="minimal_base",
                    status=ValidationStatus.PASS,
                    message="Using minimal base image",
                    severity=SeverityLevel.INFO,
                    rule_id="DF008",
                )
            )
        else:
            result.add_check(
                ValidationCheck(
                    check="minimal_base",
                    status=ValidationStatus.WARN,
                    message="Base image may not be minimal (consider Alpine or Distroless)",
                    severity=SeverityLevel.MEDIUM,
                    rule_id="DF008",
                    fix_suggestion="FROM alpine:latest or FROM gcr.io/distroless/nodejs",
                )
            )

    def _is_minimal_base(self, info: DockerfileInfo) -> bool:
        """Verifica se a base do estágio **final** é minimal.

        Antes bastava qualquer estágio ser minimal: um builder em Alpine
        fazia um runtime em Ubuntu passar. O que vai para produção é só o
        último estágio.
        """
        minimal_markers = ["alpine", "distroless", "slim", "chainguard", "wolfi"]
        base = info.final_base_image or (info.base_images[-1] if info.base_images else "")
        return any(marker in base.lower() for marker in minimal_markers)

    def _check_no_sudo(self, info: DockerfileInfo, result: DockerfileValidationResult) -> None:
        """Verifica se usa sudo."""
        if info.uses_sudo:
            result.add_check(
                ValidationCheck(
                    check="no_sudo",
                    status=ValidationStatus.FAIL,
                    message="sudo usage detected",
                    severity=SeverityLevel.HIGH,
                    rule_id="DF009",
                    fix_suggestion="Remove sudo dependency",
                )
            )
        else:
            result.add_check(
                ValidationCheck(
                    check="no_sudo",
                    status=ValidationStatus.PASS,
                    message="No sudo usage detected",
                    severity=SeverityLevel.INFO,
                    rule_id="DF009",
                )
            )

    def _check_entrypoint_form(
        self, info: DockerfileInfo, result: DockerfileValidationResult
    ) -> None:
        """Verifica se ENTRYPOINT usa forma exec (não shell)."""
        if not info.entrypoint:
            # SKIP, não silêncio: um check que simplesmente some da tabela é
            # indistinguível de um check que passou.
            result.add_check(
                ValidationCheck(
                    check="entrypoint_exec_form",
                    status=ValidationStatus.SKIP,
                    message="No ENTRYPOINT directive to check",
                    severity=SeverityLevel.INFO,
                    rule_id="DF010",
                )
            )
        else:
            # Exec form starts with [
            if info.entrypoint.startswith("["):
                result.add_check(
                    ValidationCheck(
                        check="entrypoint_exec_form",
                        status=ValidationStatus.PASS,
                        message="ENTRYPOINT uses exec form",
                        severity=SeverityLevel.INFO,
                        rule_id="DF010",
                    )
                )
            else:
                result.add_check(
                    ValidationCheck(
                        check="entrypoint_exec_form",
                        status=ValidationStatus.WARN,
                        message="ENTRYPOINT uses shell form (should use exec form)",
                        severity=SeverityLevel.MEDIUM,
                        rule_id="DF010",
                        fix_suggestion='ENTRYPOINT ["node"] instead of ENTRYPOINT node',
                    )
                )

    def _check_shell_usage(self, info: DockerfileInfo, result: DockerfileValidationResult) -> None:
        """Verifica se CMD usa forma exec (não shell).

        Este check devolvia PASS incondicionalmente -- não olhava nada. Uma
        regra que sempre passa é pior que regra nenhuma: ela afirma ao
        usuário que o ponto foi verificado, e ainda infla o score.

        Na forma shell o processo vira filho de `/bin/sh -c`, que não repassa
        sinais: o container ignora SIGTERM e morre no SIGKILL do timeout.
        """
        if not info.cmd:
            result.add_check(
                ValidationCheck(
                    check="shell_usage",
                    status=ValidationStatus.SKIP,
                    message="No CMD directive to check",
                    severity=SeverityLevel.INFO,
                    rule_id="DF011",
                )
            )
        elif info.cmd.startswith("["):
            result.add_check(
                ValidationCheck(
                    check="shell_usage",
                    status=ValidationStatus.PASS,
                    message="CMD uses exec form",
                    severity=SeverityLevel.INFO,
                    rule_id="DF011",
                )
            )
        else:
            result.add_check(
                ValidationCheck(
                    check="shell_usage",
                    status=ValidationStatus.WARN,
                    message="CMD uses shell form (signals are not forwarded to the process)",
                    severity=SeverityLevel.MEDIUM,
                    rule_id="DF011",
                    fix_suggestion='CMD ["npm", "start"] instead of CMD npm start',
                )
            )

    def _check_dockerignore(
        self, info: DockerfileInfo, result: DockerfileValidationResult, context_path: Path
    ) -> None:
        """Verifica se .dockerignore existe e é adequado."""
        dockerignore_path = context_path / ".dockerignore"

        if dockerignore_path.exists():
            try:
                content = dockerignore_path.read_text(encoding="utf-8", errors="replace").lower()
            except OSError as e:
                # Present but unreadable is its own answer -- reporting it as
                # SKIP is honest, where letting the OSError escape aborted
                # the entire validation over one optional check.
                result.add_check(
                    ValidationCheck(
                        check="dockerignore_complete",
                        status=ValidationStatus.SKIP,
                        message=f".dockerignore could not be read: {e}",
                        severity=SeverityLevel.INFO,
                        rule_id="DF012",
                    )
                )
                return
            recommended = [".git", ".env", "node_modules", "__pycache__", "*.log"]
            missing = [item for item in recommended if item not in content]

            if missing:
                result.add_check(
                    ValidationCheck(
                        check="dockerignore_complete",
                        status=ValidationStatus.WARN,
                        message=f".dockerignore missing recommended entries: {', '.join(missing)}",
                        severity=SeverityLevel.LOW,
                        rule_id="DF012",
                    )
                )
            else:
                result.add_check(
                    ValidationCheck(
                        check="dockerignore_complete",
                        status=ValidationStatus.PASS,
                        message=".dockerignore contains recommended entries",
                        severity=SeverityLevel.INFO,
                        rule_id="DF012",
                    )
                )
        else:
            result.add_check(
                ValidationCheck(
                    check="dockerignore_exists",
                    status=ValidationStatus.WARN,
                    message=".dockerignore not found",
                    severity=SeverityLevel.LOW,
                    rule_id="DF012",
                    fix_suggestion="Create .dockerignore with .git, .env, node_modules, etc.",
                )
            )

    def _calculate_security_score(self, validation: DockerfileValidationResult) -> int:
        """Calcula score de segurança baseado nos resultados."""
        score = 100

        # Pesos por severidade
        severity_weights = {
            SeverityLevel.CRITICAL: 25,
            SeverityLevel.HIGH: 15,
            SeverityLevel.MEDIUM: 8,
            SeverityLevel.LOW: 3,
        }

        for check in validation.checks:
            if check.status == ValidationStatus.FAIL:
                score -= severity_weights.get(check.severity, 0)
            elif check.status == ValidationStatus.WARN:
                score -= severity_weights.get(check.severity, 0) // 2

        return max(0, min(100, score))

    def _calculate_security_tier(self, score: int, validation: DockerfileValidationResult) -> str:
        """Calcula tier de segurança baseado no score."""
        if validation.errors > 0:
            return "C"  # Não pronto para produção

        if score >= 90:
            return "A"  # Production-ready
        elif score >= 70:
            return "B"  # Requires review
        else:
            return "C"  # Not recommended


class HardeningTemplates(HardeningTemplateProvider):
    """Provedor de templates hardened para diferentes linguagens."""

    # `Path(__file__).parent` já é `dockerls/infrastructure`. Subir mais dois
    # níveis e reentrar em "infrastructure/templates" apontava para
    # `<raiz-do-repo>/infrastructure/templates`, que não existe -- e em uma
    # instalação por wheel apontava para dentro de site-packages/. Resultado:
    # `exists()` era sempre False, os três templates versionados no repositório
    # nunca eram lidos, e todo `--hardened` caía no template básico. Um
    # gerador de Dockerfile "hardened" que na prática emitia outra coisa é
    # exatamente o tipo de silêncio que esta ferramenta existe para denunciar.
    TEMPLATES_DIR = Path(__file__).parent / "templates"

    #: Chave aceita por `--base` -> arquivo de template versionado.
    #: Só entra aqui o que existe de fato: anunciar um template inexistente
    #: fazia `--base java` cair calado no template básico, com uma base
    #: destoante da que o usuário pediu.
    TEMPLATE_FILES = {
        # Standalone Operating Systems
        "alpine": "alpine.dockerfile",
        "debian": "debian.dockerfile",
        "ubuntu": "ubuntu.dockerfile",
        "distroless": "distroless.dockerfile",
        # Node.js
        "node": "node.dockerfile",
        "node-alpine": "node-alpine.dockerfile",
        "node-debian": "node-debian.dockerfile",
        "node-ubuntu": "node-ubuntu.dockerfile",
        "node-distroless": "node-distroless.dockerfile",
        # Python
        "python": "python.dockerfile",
        "python-alpine": "python-alpine.dockerfile",
        "python-debian": "python-debian.dockerfile",
        "python-ubuntu": "python-ubuntu.dockerfile",
        "python-distroless": "python-distroless.dockerfile",
        # Go
        "go": "go.dockerfile",
        "go-scratch": "go-scratch.dockerfile",
        "go-alpine": "go-alpine.dockerfile",
        "go-debian": "go-debian.dockerfile",
        "go-distroless": "go-distroless.dockerfile",
        # Java
        "java": "java.dockerfile",
        "java-alpine": "java-alpine.dockerfile",
        "java-debian": "java-debian.dockerfile",
        "java-ubuntu": "java-ubuntu.dockerfile",
        "java-distroless": "java-distroless.dockerfile",
        # Ferramentas de build Java. São onde um projeto Java de verdade
        # começa o Dockerfile, e não existiam: `--base maven` respondia que o
        # template não existe, mandando a pessoa escrever o multi-stage na mão.
        "maven": "maven.dockerfile",
        "maven-alpine": "maven-alpine.dockerfile",
        "gradle": "gradle.dockerfile",
        "gradle-alpine": "gradle-alpine.dockerfile",
        # Rust
        "rust": "rust.dockerfile",
        "rust-scratch": "rust-scratch.dockerfile",
        "rust-alpine": "rust-alpine.dockerfile",
        "rust-debian": "rust-debian.dockerfile",
        # PHP
        "php": "php.dockerfile",
        "php-alpine": "php-alpine.dockerfile",
        "php-debian": "php-debian.dockerfile",
        "php-ubuntu": "php-ubuntu.dockerfile",
        # Ruby
        "ruby": "ruby-alpine.dockerfile",
        "ruby-alpine": "ruby-alpine.dockerfile",
        "ruby-debian": "ruby-debian.dockerfile",
    }

    def _template_path(self, name: str) -> Path:
        return self.TEMPLATES_DIR / "hardening" / name

    def get_template(self, base_image: str) -> str:
        """Retorna o template hardened correspondente a `base_image` e distribuição do SO."""
        base_lower = base_image.lower().strip()

        # 1. Correspondência exata de chave
        template_file = self.TEMPLATE_FILES.get(base_lower)

        # 2. Resolução inteligente de Ecossistema + SO
        if template_file is None:
            # Identificar ecossistema
            detected_eco = None
            for eco in ("node", "python", "golang", "go", "java", "rust", "php", "ruby"):
                if eco in base_lower:
                    detected_eco = "go" if eco == "golang" else eco
                    break

            # Identificar SO
            detected_os = None
            if "alpine" in base_lower or "musl" in base_lower:
                detected_os = "alpine"
            elif any(d in base_lower for d in ("debian", "slim", "bookworm", "bullseye")):
                detected_os = "debian"
            elif any(u in base_lower for u in ("ubuntu", "noble", "jammy", "focal")):
                detected_os = "ubuntu"
            elif "distroless" in base_lower:
                detected_os = "distroless"
            elif "scratch" in base_lower:
                detected_os = "scratch"

            if detected_eco and detected_os:
                compound_key = f"{detected_eco}-{detected_os}"
                template_file = self.TEMPLATE_FILES.get(compound_key)

            if template_file is None and detected_eco:
                template_file = self.TEMPLATE_FILES.get(detected_eco)

            if template_file is None and detected_os:
                template_file = self.TEMPLATE_FILES.get(detected_os)

        # 3. Fallback para correspondência parcial de chave
        if template_file is None:
            for key, filename in self.TEMPLATE_FILES.items():
                if key in base_lower:
                    template_file = filename
                    break

        if template_file is not None:
            path = self._template_path(template_file)
            if path.exists():
                return path.read_text(encoding="utf-8")
            raise UnknownHardeningTemplateError(
                f"Hardened template file is missing from the installation: {path}"
            )

        available = ", ".join(self.list_templates()) or "none"
        raise UnknownHardeningTemplateError(
            f"No hardened template for base image {base_image!r}. Available: {available}"
        )

    def list_templates(self) -> list[str]:
        """Lista os templates hardened realmente disponíveis em disco."""
        return sorted(
            name
            for name, filename in self.TEMPLATE_FILES.items()
            if self._template_path(filename).exists()
        )

    def generate_hardened_dockerfile(
        self,
        dockerfile_path: str | Path,
        base_image: str | None = None,
        output_path: str | Path | None = None,
    ) -> str:
        """Gera um Dockerfile hardened baseado no original ou template."""
        path = Path(dockerfile_path)
        if path.is_dir():
            path = path / "Dockerfile"

        # Se base_image fornecida, usar template
        if base_image:
            content = self.get_template(base_image)
        else:
            # Analisar Dockerfile existente e sugerir melhorias
            validator = DockerfileValidator(self)
            suggestions = validator.suggest_hardening(path)

            # Gerar conteúdo baseado nas sugestões
            content = self._apply_suggestions(path, suggestions)

        # Salvar se output_path fornecido
        if output_path:
            output = Path(output_path)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(content, encoding="utf-8")

        return content

    def _apply_suggestions(self, path: Path, suggestions: list[HardeningRule]) -> str:
        """Aplica sugestões ao Dockerfile existente."""
        content = path.read_text(encoding="utf-8")

        # Aplicar cada sugestão
        for suggestion in suggestions:
            # Lógica simples de aplicação - em produção seria mais sofisticado
            if "non-root user" in suggestion.title.lower() and "USER" not in content:
                content += "\nUSER appuser\n"

        return content


def _parse_label_pairs(text: str) -> dict[str, str]:
    """Todos os pares de uma instrução LABEL, não só o primeiro.

    O padrão anterior era `^LABEL\\s+([^=]+)=(.*)$`: ele casava até o primeiro
    `=` e engolia o resto da linha como *valor*. Numa instrução idiomática --

        LABEL maintainer="Ivomsantiago" \\
              security.scanner="dockerls"

    -- as continuações já vêm unidas numa linha lógica, então o resultado era a
    chave `maintainer` com valor `"Ivomsantiago" security.scanner="dockerls"`, e
    `security.scanner` simplesmente não existia. A regra DF007 então reprovava
    um Dockerfile que declara o rótulo que ela cobra. Um falso positivo é pior
    que nenhuma checagem: ele ensina o leitor a ignorar o aviso.

    `shlex` faz o trabalho de aspas, que é onde um split ingênuo erra: o valor
    pode conter espaços e é isso que exige o parser em vez de um regex.
    """
    try:
        tokens = shlex.split(text)
    except ValueError:
        # Aspas desbalanceadas: o Docker também recusaria. Cai para o split
        # simples em vez de descartar a instrução inteira.
        tokens = text.split()
    if not tokens:
        return {}

    # Forma legada `LABEL chave valor com espaços`, sem `=` nenhum.
    if "=" not in tokens[0]:
        return {tokens[0]: " ".join(tokens[1:])}

    pairs: dict[str, str] = {}
    for token in tokens:
        key, separator, value = token.partition("=")
        if separator and key:
            pairs[key.strip()] = value.strip()
    return pairs
