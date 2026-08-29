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
from dockerls.domain.value_objects.image_reference import split_repository_and_tag

#: `sudo` como comando, e não como substring de `pseudo` ou de uma frase
#: dentro de um `echo`.
_SUDO = re.compile(r"(?:^|[\s;&|(])sudo(?:$|[\s;&|)])")

#: Cada gerenciador de pacotes com uma borda de palavra em volta. Sem ela,
#: `apt` casava com `adapt` e `pip` com `pipeline`.
_PACKAGE_MANAGERS = {
    name: re.compile(rf"(?:^|[\s;&|(]){re.escape(name)}(?:$|[\s;&|)])")
    for name in ("apt-get", "apt", "apk", "yum", "dnf", "pip", "pip3", "npm", "yarn")
}

#: Texto entre aspas dentro de um `RUN`. Removido antes de procurar por
#: comandos, porque `RUN echo 'no sudo here'` não usa sudo -- fala dele.
_QUOTED = re.compile(r"'[^']*'|\"[^\"]*\"")

#: Quem baixa da rede, à esquerda de um pipe.
_DOWNLOADER = re.compile(r"(?:^|[\s;&(]) *(?:curl|wget|fetch)\b", re.IGNORECASE)

#: Um interpretador **no começo** do segmento à direita do pipe. A posição é
#: a regra inteira: `curl ... | sh` executa o que veio da rede, enquanto
#: `curl -o f && echo ... | sha256sum -c && sh f` também tem um `sh` depois
#: de um pipe e é exatamente a forma correta. Só o primeiro é acusado.
#: `[^\s=]+=\S+` rather than `\S+=\S+`: the key half excludes `=`, so there
#: is exactly one place the assignment can split. Two unbounded `\S+`
#: sharing an unbounded search space around one `=` is the textbook
#: catastrophic-backtracking shape (CodeQL flagged it); a real env var name
#: never contains `=` or whitespace, so this loses no matches.
_SHELL_AT_HEAD = re.compile(
    r"^\s*(?:sudo\s+|env\s+[^\s=]+=\S+\s+)*(?:ba|z|k|da)?sh\b", re.IGNORECASE
)

#: Bit setuid/setgid posto na imagem, simbólico (`chmod u+s`) ou octal
#: (`chmod 4755`). O primeiro dígito de um modo de quatro é o que carrega
#: setuid(4), setgid(2) e sticky(1); só os dois primeiros interessam.
_SETUID_BIT = re.compile(
    r"\bchmod\b[^;&|]*?(?:\b[4267]\d{3}\b|[ugo]*[+=][a-z]*s\b)",
    re.IGNORECASE,
)

#: Fontes que um `ADD` busca na rede. O Docker as baixa sem verificar
#: assinatura nem checksum, e sem seguir o proxy configurado para o build.
_ADD_REMOTE = re.compile(r"^(?:https?|ftp|git)://|^git@", re.IGNORECASE)

#: Arquivos que o `ADD` **descompacta sozinho** ao copiar. É o
#: comportamento que separa `ADD` de `COPY`, e o que transforma um tarball
#: hostil em escrita de arquivo arbitrária dentro da imagem.
_ADD_ARCHIVE = re.compile(
    r"\.(?:tar|tar\.gz|tgz|tar\.bz2|tbz2|tar\.xz|txz|tar\.zst|gz|bz2|xz)$",
    re.IGNORECASE,
)


def _strip_quoted(command: str) -> str:
    """O comando sem o que está entre aspas.

    `RUN echo 'no sudo needed here'` não usa sudo: fala dele. Sem esta
    remoção, toda menção a uma ferramenta dentro de uma mensagem vira uma
    acusação, e uma regra que acusa texto perde a confiança de quem a lê.
    """
    return _QUOTED.sub(" ", command)


def _pipes_remote_script_to_shell(command: str) -> bool:
    """Se um download é canalizado direto para um interpretador.

    Olha o **par**, e não cada metade: um baixador em algum segmento à
    esquerda de um pipe, e um interpretador *no começo* do segmento à
    direita. É essa segunda condição que separa

        curl -fsSL https://x/i.sh | sh                      (acusado)

    de

        curl -o /tmp/i.sh https://x/i.sh \\
          && echo '<sha>  /tmp/i.sh' | sha256sum -c \\
          && sh /tmp/i.sh                                   (a forma certa)

    -- que também tem um `sh` depois de um pipe, e é exatamente o que a
    regra quer que as pessoas façam.
    """
    text = _strip_quoted(command)
    # `||` é um operador, não um pipe.
    segments = re.split(r"(?<!\|)\|(?!\|)", text)
    for left, right in zip(segments, segments[1:], strict=False):
        if _DOWNLOADER.search(left) and _SHELL_AT_HEAD.match(right):
            return True
    return False


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
    #: `ADD` inteiro, argumentos incluídos. Ao contrário do `COPY_PATTERN`
    #: acima, não exige exatamente dois operandos: `ADD a b c/` é legal, e
    #: uma regex que não casasse com ele deixaria a diretiva invisível --
    #: que é o modo de falhar que esta regra existe para não ter.
    ADD_PATTERN = re.compile(r"^ADD\s+(.+)$", re.IGNORECASE)
    ENV_PREFIX = re.compile(r"^ENV\s+(.+)$", re.IGNORECASE)
    # Pares chave=valor de uma linha ENV, com valor opcionalmente entre aspas.
    ENV_KV = re.compile(r"""([\w.\-]+)=(?:"[^"]*"|'[^']*'|\S*)""")
    LABEL_PREFIX = re.compile(r"^LABEL\s+(.+)$", re.IGNORECASE | re.DOTALL)
    EXPOSE_PATTERN = re.compile(r"^EXPOSE\s+(\d+)", re.IGNORECASE)
    USER_PATTERN = re.compile(r"^USER\s+(\S+)(?::(\d+))?$", re.IGNORECASE)
    HEALTHCHECK_PATTERN = re.compile(r"^HEALTHCHECK\s+", re.IGNORECASE)
    ENTRYPOINT_PATTERN = re.compile(r"^ENTRYPOINT\s+(.+)$", re.IGNORECASE)
    CMD_PATTERN = re.compile(r"^CMD\s+(.+)$", re.IGNORECASE)
    #: `(\S+)` era ganancioso e engolia o `=valor` inteiro: em
    #: `ARG TOKEN=abc` o nome saía como `TOKEN=abc` e o grupo do valor vinha
    #: vazio, então nada nesta classe conseguia distinguir um ARG com valor
    #: -- que é um segredo escrito no Dockerfile -- de um sem.
    ARG_PATTERN = re.compile(r"^ARG\s+([A-Za-z_][\w.\-]*)(?:=(.*))?$", re.IGNORECASE)
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
                and self._is_moving_reference(image)
            ):
                self._info.uses_latest_tag = True

        # RUN
        elif match := self.RUN_PATTERN.match(line):
            cmd = match.group(1)
            self._info.run_commands.append({"line": line_num, "command": cmd})

            # `"sudo" in cmd` casava com `pseudo`, `sudoku` e com a palavra
            # dentro de um `echo`. A borda de palavra é o que separa a
            # ferramenta da string.
            unquoted = _strip_quoted(cmd)
            if _SUDO.search(unquoted):
                self._info.uses_sudo = True

            # Idem: `"apt" in cmd` casava com `adapt` e `captured`, `"pip"`
            # com `pipeline` e `pipx`. Um gerenciador de pacotes detectado
            # onde não há nenhum acusa a DF005 de cache não limpo num
            # Dockerfile que não instalou nada.
            for pm, pattern in _PACKAGE_MANAGERS.items():
                if pattern.search(unquoted) and pm not in self._info.package_managers_used:
                    self._info.package_managers_used.append(pm)

            if _pipes_remote_script_to_shell(cmd):
                self._info.pipes_remote_script_to_shell = True
                self._info.remote_script_lines.append(line_num)

            if _SETUID_BIT.search(unquoted):
                self._info.sets_setuid_bit = True
                self._info.setuid_lines.append(line_num)

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

        # ADD -- não é um COPY com outro nome, e a diferença é a regra.
        elif match := self.ADD_PATTERN.match(line):
            self._record_add(match.group(1), line_num)

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

        # ARG
        elif match := self.ARG_PATTERN.match(line):
            arg_name = match.group(1)
            if arg_name in ("BUILDKIT_INLINE_CACHE", "DOCKER_BUILDKIT"):
                self._info.uses_buildkit = True
            # Um ARG **com valor** é um segredo escrito no Dockerfile e no
            # histórico de camadas; um ARG sem valor é um parâmetro de build,
            # e acusá-lo transformaria a forma correta de passar um segredo
            # numa infração. A DF004 já dizia no seu texto que cobria "ENV e
            # ARG" -- e não olhava ARG nenhum. Uma regra que afirma cobrir o
            # que não cobre é pior do que não existir.
            if match.group(2) and self._is_secret_name(arg_name):
                self._info.has_secrets_in_build_args = True
                if arg_name not in self._info.secret_build_args:
                    self._info.secret_build_args.append(arg_name)

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

    @staticmethod
    def _is_moving_reference(image: str) -> bool:
        """Se este `FROM` aponta para algo que pode mudar debaixo do build.

        A checagem anterior era `":latest" in image or (":" not in image and
        "@" not in image)`, e errava nos dois sentidos:

        * **Falso negativo, e é o grave.** `FROM registry.local:5000/app` não
          tem tag -- o Docker resolve para `:latest` --, mas *tem* dois
          pontos, no host. A regra concluía "está com tag" e dava PASS na
          DF001, com severidade HIGH, exatamente para a base mais móvel que
          existe. Toda organização com registry interno por porta escapava
          da regra. `split_repository_and_tag` já sabia separar host de tag
          e é a mesma pergunta sobre a mesma string, então é ela que
          responde aqui -- duas leituras diferentes de "isto está fixado?"
          no mesmo binário é como um dos dois lados fica errado sem que
          ninguém note.
        * **Falso positivo.** `:latest` como substring casa com
          `FROM ghcr.io/org/app:latest-stable`, que é uma tag comum e não é
          `latest`. A comparação agora é com a tag inteira.

        Um digest (`@sha256:...`) nunca move, tenha tag ou não.
        """
        reference = next((p for p in image.split() if not p.startswith("--")), "")
        if not reference or "$" in reference:
            # `FROM $BASE_IMAGE` é resolvido por um ARG que este parser não
            # avalia. Chamar isso de fixado ou de móvel seria inventar; a
            # DF001 não fala sobre o que não leu.
            return False
        if "@sha256:" in reference:
            return False
        _, tag = split_repository_and_tag(reference)
        return not tag or tag.lower() == "latest"

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

    def _record_add(self, body: str, line_num: int) -> None:
        """Registra um `ADD` e o que nele é diferente de um `COPY`.

        `ADD` faz duas coisas que `COPY` não faz, e as duas são a regra:

        * **busca uma URL**, sem conferir assinatura nem checksum, e o
          resultado vira uma camada da imagem. Quem controlar aquele host,
          ou o caminho até ele, escolhe o que roda dentro do container;
        * **descompacta um arquivo local sozinho**. Um tarball com
          `../../etc/passwd` dentro escreve fora do destino, e o Dockerfile
          não diz em lugar nenhum que uma extração vai acontecer.

        Um `ADD --checksum=sha256:...` de uma URL é a forma que o BuildKit
        oferece para fazer isso com integridade, e não é acusada: o que a
        regra combate é o download não verificado, não a diretiva.
        """
        try:
            parts = shlex.split(body)
        except ValueError:
            # Aspas desbalanceadas: a linha é registrada mesmo assim, com os
            # tokens crus. Deixar de registrar seria a diretiva sumindo por
            # causa de um erro de digitação.
            parts = body.split()

        flags = [p for p in parts if p.startswith("--")]
        operands = [p for p in parts if not p.startswith("--")]
        checksummed = any(f.lower().startswith("--checksum=") for f in flags)
        sources = operands[:-1] if len(operands) > 1 else operands
        self._info.add_commands.append(
            {
                "line": line_num,
                "sources": sources,
                "destination": operands[-1] if len(operands) > 1 else "",
                "remote": [s for s in sources if _ADD_REMOTE.match(s)],
                "archives": [
                    s for s in sources if not _ADD_REMOTE.match(s) and _ADD_ARCHIVE.search(s)
                ],
                "checksummed": checksummed,
            }
        )

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
        self._check_add_vs_copy(info, result)
        self._check_remote_script_execution(info, result)
        self._check_setuid(info, result)

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
        """Verifica se há segredos em ENV **ou em ARG**.

        A DF004 se chama "Keep secrets out of ENV and ARG" desde sempre, no
        catálogo de controles, e não olhava ARG nenhum: um
        `ARG GITHUB_TOKEN=ghp_...` passava com PASS e a mensagem "No obvious
        secrets". Uma regra que afirma cobrir o que não cobre é pior que
        regra nenhuma, porque o PASS é lido como uma verificação que
        aconteceu.

        Um ARG **com valor** é o caso: o valor fica escrito no Dockerfile e
        no histórico da camada. Um `ARG TOKEN` sem valor é a forma correta
        de parametrizar um build e não é acusado.
        """
        env_vars = list(info.secret_env_vars)
        arg_vars = list(info.secret_build_args)
        if env_vars or arg_vars:
            partes = []
            if env_vars:
                partes.append(f"ENV: {', '.join(env_vars)}")
            if arg_vars:
                partes.append(f"ARG with a default value: {', '.join(arg_vars)}")
            result.add_check(
                ValidationCheck(
                    check="secrets_not_in_env",
                    status=ValidationStatus.FAIL,
                    message=f"Potential secrets in {'; '.join(partes)}",
                    severity=SeverityLevel.CRITICAL,
                    rule_id="DF004",
                    fix_suggestion=(
                        "Use BuildKit: RUN --mount=type=secret,id=token\n"
                        "An ARG default is written into the Dockerfile and the layer "
                        "history; declare `ARG TOKEN` with no value and pass it at "
                        "build time if it has to be an ARG at all."
                    ),
                    details={"secret_vars": env_vars, "secret_build_args": arg_vars},
                )
            )
        else:
            result.add_check(
                ValidationCheck(
                    check="secrets_not_in_env",
                    status=ValidationStatus.PASS,
                    message="No obvious secrets in ENV variables or ARG defaults",
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

    def _check_add_vs_copy(self, info: DockerfileInfo, result: DockerfileValidationResult) -> None:
        """DF013 -- `ADD` faz duas coisas que `COPY` não faz.

        Não é estilo. `ADD` de uma URL baixa e assa na imagem bytes que nada
        conferiu, e `ADD` de um tarball local o **descompacta sozinho**, o
        que transforma um arquivo com `../../etc/` dentro em escrita fora do
        destino. Nenhuma das duas está escrita na linha; quem lê o
        Dockerfile vê o que parece um `COPY`.

        `ADD --checksum=sha256:...` de uma URL é a forma que o BuildKit
        oferece para baixar com integridade, e passa: o alvo é o download
        não verificado, não a diretiva.
        """
        remote = [a for a in info.add_commands if a["remote"] and not a["checksummed"]]
        archives = [a for a in info.add_commands if a["archives"]]

        if not info.add_commands:
            result.add_check(
                ValidationCheck(
                    check="add_not_used_for_copy",
                    status=ValidationStatus.PASS,
                    message="No ADD directives (COPY is used to bring files in)",
                    severity=SeverityLevel.INFO,
                    rule_id="DF013",
                )
            )
            return

        if remote:
            sources = ", ".join(s for a in remote for s in a["remote"])
            result.add_check(
                ValidationCheck(
                    check="add_not_used_for_copy",
                    status=ValidationStatus.FAIL,
                    message=(
                        f"ADD fetches over the network without verifying what it got: {sources}"
                    ),
                    severity=SeverityLevel.HIGH,
                    rule_id="DF013",
                    line=remote[0]["line"],
                    fix_suggestion=(
                        "RUN curl -fsSL <url> -o /tmp/f && echo '<sha256>  /tmp/f' | sha256sum -c\n"
                        "or, on BuildKit: ADD --checksum=sha256:<digest> <url> <dest>"
                    ),
                    details={"sources": sources},
                )
            )
            return

        if archives:
            sources = ", ".join(s for a in archives for s in a["archives"])
            result.add_check(
                ValidationCheck(
                    check="add_not_used_for_copy",
                    status=ValidationStatus.WARN,
                    message=(
                        f"ADD auto-extracts these archives, which the line does not say: {sources}"
                    ),
                    severity=SeverityLevel.MEDIUM,
                    rule_id="DF013",
                    line=archives[0]["line"],
                    fix_suggestion=(
                        "COPY the archive and extract it explicitly:\n"
                        "COPY app.tar.gz /tmp/\nRUN tar -xzf /tmp/app.tar.gz -C /app"
                    ),
                    details={"sources": sources},
                )
            )
            return

        result.add_check(
            ValidationCheck(
                check="add_not_used_for_copy",
                status=ValidationStatus.WARN,
                message="ADD used where COPY would do the same thing with fewer behaviours",
                severity=SeverityLevel.LOW,
                rule_id="DF013",
                line=info.add_commands[0]["line"],
                fix_suggestion="Replace ADD with COPY for plain files and directories",
            )
        )

    def _check_remote_script_execution(
        self, info: DockerfileInfo, result: DockerfileValidationResult
    ) -> None:
        """DF014 -- um script baixado da rede e executado sem ser conferido.

        `curl ... | sh` não deixa o script em lugar nenhum: nada o assina,
        nada compara um checksum, nada o registra numa camada onde alguém
        pudesse lê-lo depois. Quem controlar aquele host -- ou o caminho até
        ele, ou o DNS no meio -- escolhe o que roda como root dentro do
        build, e o Dockerfile continua parecendo o mesmo.

        `curl -o arquivo` seguido de um `sha256sum -c` é a forma correta, e
        não casa aqui: a regra olha o pipe entre o baixador e o
        interpretador, não cada metade sozinha.
        """
        if not info.pipes_remote_script_to_shell:
            result.add_check(
                ValidationCheck(
                    check="no_unverified_remote_script",
                    status=ValidationStatus.PASS,
                    message="No remote script is piped straight into a shell",
                    severity=SeverityLevel.INFO,
                    rule_id="DF014",
                )
            )
            return

        result.add_check(
            ValidationCheck(
                check="no_unverified_remote_script",
                status=ValidationStatus.FAIL,
                message=(
                    "A script is downloaded and piped into a shell: nothing verifies "
                    "what runs, and it runs as root during the build"
                ),
                severity=SeverityLevel.HIGH,
                rule_id="DF014",
                line=info.remote_script_lines[0] if info.remote_script_lines else None,
                fix_suggestion=(
                    "Download, verify, then run:\n"
                    "RUN curl -fsSL <url> -o /tmp/install.sh \\\n"
                    "    && echo '<sha256>  /tmp/install.sh' | sha256sum -c \\\n"
                    "    && sh /tmp/install.sh && rm /tmp/install.sh"
                ),
                details={"lines": list(info.remote_script_lines)},
            )
        )

    def _check_setuid(self, info: DockerfileInfo, result: DockerfileValidationResult) -> None:
        """DF015 -- bit setuid/setgid posto num binário da imagem.

        Um binário setuid roda com o dono do arquivo, e o dono é root. Num
        container que faz a coisa certa e roda como usuário sem privilégio,
        é justamente o caminho pronto de volta para o uid 0: a única peça
        que faltava para transformar uma execução de comando limitada numa
        completa.
        """
        if not info.sets_setuid_bit:
            result.add_check(
                ValidationCheck(
                    check="no_setuid_binaries_added",
                    status=ValidationStatus.PASS,
                    message="No setuid or setgid bit is set in the build",
                    severity=SeverityLevel.INFO,
                    rule_id="DF015",
                )
            )
            return

        result.add_check(
            ValidationCheck(
                check="no_setuid_binaries_added",
                status=ValidationStatus.FAIL,
                message=(
                    "A setuid/setgid bit is set: the binary runs as its owner, and its "
                    "owner is root -- a ready-made way back to uid 0"
                ),
                severity=SeverityLevel.HIGH,
                rule_id="DF015",
                line=info.setuid_lines[0] if info.setuid_lines else None,
                fix_suggestion=(
                    "Drop the setuid bit and give the process what it needs directly:\n"
                    "RUN chmod 0755 /usr/local/bin/tool\n"
                    "For port binding below 1024, listen high and map the port instead."
                ),
                details={"lines": list(info.setuid_lines)},
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
