"""Regras de validação de Dockerfile.

Estes testes existem por causa de uma classe específica de defeito: o
validador dando **PASS numa imagem insegura**. Num scanner de segurança esse
é o pior modo de falha possível — um falso FAIL custa tempo de quem lê, um
falso PASS entrega a imagem em produção com o carimbo da ferramenta.

Quatro regras erravam assim, e as quatro têm caso aqui.
"""

from __future__ import annotations

import time

import pytest

from dockerls.domain.entities.dockerfile_analysis import ValidationStatus
from dockerls.infrastructure.dockerfile_validator import (
    DockerfileParser,
    DockerfileValidator,
    HardeningTemplates,
)


@pytest.fixture
def validate(tmp_path):
    def _validate(content: str, dockerignore: str | None = None):
        (tmp_path / "Dockerfile").write_text(content)
        if dockerignore is not None:
            (tmp_path / ".dockerignore").write_text(dockerignore)
        result = DockerfileValidator().validate(tmp_path)
        return {c.check: c.status for c in result.checks}

    return _validate


class TestNonRootUserAcrossStages:
    def test_user_in_a_build_stage_does_not_protect_the_final_image(self, validate):
        """`USER node` no builder não protege nada: o estágio final sobe como
        root. A regra olhava qualquer USER do arquivo e dava PASS."""
        checks = validate(
            "FROM node:22-alpine AS builder\n"
            "USER node\n"
            "RUN npm ci\n"
            "\n"
            "FROM node:22-alpine\n"
            'CMD ["node", "index.js"]\n'
        )

        assert checks["non_root_user"] == ValidationStatus.FAIL

    def test_user_in_the_final_stage_passes(self, validate):
        checks = validate(
            "FROM node:22-alpine AS builder\n"
            "RUN npm ci\n"
            "\n"
            "FROM node:22-alpine\n"
            "USER node\n"
            'CMD ["node", "index.js"]\n'
        )

        assert checks["non_root_user"] == ValidationStatus.PASS

    def test_final_stage_inherits_user_from_the_stage_it_extends(self, validate):
        """`FROM builder` herda o USER do estágio referenciado."""
        checks = validate(
            'FROM node:22-alpine AS builder\nUSER node\n\nFROM builder\nCMD ["node"]\n'
        )

        assert checks["non_root_user"] == ValidationStatus.PASS

    def test_explicit_user_root_at_the_end_fails(self, validate):
        checks = validate('FROM node:22-alpine\nUSER node\nUSER root\nCMD ["node"]\n')

        assert checks["non_root_user"] == ValidationStatus.FAIL

    def test_user_with_a_group_is_still_non_root(self, validate):
        checks = validate('FROM node:22-alpine\nUSER appuser:appgroup\nCMD ["node"]\n')

        assert checks["non_root_user"] == ValidationStatus.PASS


class TestSecretsInEnv:
    def test_secret_in_a_multi_variable_env_line_is_caught(self, validate):
        """`ENV A=1 B=2` só tinha o primeiro par lido, então um segredo em
        qualquer posição depois da primeira passava batido."""
        checks = validate(
            "FROM node:22-alpine\nUSER node\nENV NODE_ENV=production DOCKER_TOKEN=dckr_pat_leaked\n"
        )

        assert checks["secrets_not_in_env"] == ValidationStatus.FAIL

    def test_legacy_env_form_is_caught(self, validate):
        """A forma antiga `ENV KEY value` não casava com a regex, então essa
        linha nunca era verificada."""
        checks = validate("FROM node:22-alpine\nUSER node\nENV API_KEY abcdef123456\n")

        assert checks["secrets_not_in_env"] == ValidationStatus.FAIL

    def test_quoted_values_do_not_hide_the_key(self, validate):
        checks = validate('FROM node:22-alpine\nUSER node\nENV A="x y" DB_PASSWORD="s3cr3t" B=2\n')

        assert checks["secrets_not_in_env"] == ValidationStatus.FAIL

    def test_benign_env_passes(self, validate):
        checks = validate("FROM node:22-alpine\nUSER node\nENV NODE_ENV=production PORT=8080\n")

        assert checks["secrets_not_in_env"] == ValidationStatus.PASS


class TestMinimalBase:
    def test_a_minimal_builder_does_not_excuse_a_fat_runtime(self, validate):
        """O que vai para produção é o último estágio. Um builder em Alpine
        fazia um runtime em Ubuntu passar como "minimal"."""
        checks = validate(
            "FROM alpine:3.19 AS builder\n"
            "RUN apk add --no-cache build-base\n"
            "\n"
            "FROM ubuntu:22.04\n"
            "USER nobody\n"
        )

        assert checks["minimal_base"] == ValidationStatus.WARN

    def test_minimal_final_stage_passes(self, validate):
        checks = validate("FROM ubuntu:22.04 AS builder\n\nFROM alpine:3.19\nUSER nobody\n")

        assert checks["minimal_base"] == ValidationStatus.PASS


class TestBaseImagePinned:
    def test_stage_reference_without_a_tag_is_not_an_implicit_latest(self, validate):
        """`FROM builder` aponta para um estágio, não para um registry: a
        ausência de tag ali não é `:latest`."""
        checks = validate("FROM node:22-alpine AS builder\n\nFROM builder\nUSER node\n")

        assert checks["base_image_pinned"] == ValidationStatus.PASS

    def test_latest_in_any_stage_fails(self, validate):
        checks = validate("FROM node:latest AS builder\n\nFROM node:22-alpine\nUSER node\n")

        assert checks["base_image_pinned"] == ValidationStatus.FAIL


class TestShellUsage:
    def test_shell_form_cmd_warns(self, validate):
        """Este check devolvia PASS incondicionalmente -- não olhava nada."""
        checks = validate("FROM node:22-alpine\nUSER node\nCMD npm start\n")

        assert checks["shell_usage"] == ValidationStatus.WARN

    def test_exec_form_cmd_passes(self, validate):
        checks = validate('FROM node:22-alpine\nUSER node\nCMD ["npm", "start"]\n')

        assert checks["shell_usage"] == ValidationStatus.PASS

    def test_no_cmd_is_skipped_not_passed(self, validate):
        """SKIP e PASS dizem coisas diferentes: um check que não teve o que
        verificar não pode contar como verificação aprovada."""
        checks = validate("FROM node:22-alpine\nUSER node\n")

        assert checks["shell_usage"] == ValidationStatus.SKIP

    def test_missing_entrypoint_is_skipped_not_absent(self, validate):
        checks = validate("FROM node:22-alpine\nUSER node\n")

        assert checks["entrypoint_exec_form"] == ValidationStatus.SKIP


class TestScratchIsNotAFloatingTag:
    """`FROM scratch` é a imagem vazia embutida no Docker: não é um
    repositório e não tem tag nenhuma para pinar. Tratá-la como "sem tag,
    logo :latest" reprovava com severidade HIGH justamente os Dockerfiles
    mais enxutos que existem -- inclusive o template Go desta ferramenta."""

    def test_scratch_runtime_stage_does_not_fail_the_pin_rule(self, validate):
        checks = validate(
            "FROM golang:1.23-alpine AS builder\n"
            "RUN go build -o app .\n"
            "\n"
            "FROM scratch\n"
            "COPY --from=builder /app/app /app\n"
            "USER 65534:65534\n"
            'ENTRYPOINT ["/app"]\n'
        )

        assert checks["base_image_pinned"] == ValidationStatus.PASS
        assert checks["non_root_user"] == ValidationStatus.PASS

    def test_scratch_with_a_platform_flag_is_still_scratch(self, validate):
        checks = validate("FROM --platform=$BUILDPLATFORM scratch\nUSER 65534\n")

        assert checks["base_image_pinned"] == ValidationStatus.PASS

    def test_an_actually_untagged_image_still_fails(self, validate):
        checks = validate("FROM ubuntu\nUSER app\n")

        assert checks["base_image_pinned"] == ValidationStatus.FAIL


class TestNumericRootUser:
    """`USER 0` e `USER 0:0` são root tanto quanto `USER root`, e passavam:
    a checagem só comparava com a string "root". Um falso PASS em
    non_root_user é o pior desfecho possível desta regra."""

    @pytest.mark.parametrize("directive", ["USER 0", "USER 0:0", "USER root", "USER root:root"])
    def test_root_by_any_spelling_fails(self, validate, directive):
        checks = validate(f"FROM node:22-alpine\n{directive}\n")

        assert checks["non_root_user"] == ValidationStatus.FAIL

    @pytest.mark.parametrize("directive", ["USER 1000", "USER 65534:65534", "USER appuser"])
    def test_a_real_non_root_user_still_passes(self, validate, directive):
        checks = validate(f"FROM node:22-alpine\n{directive}\n")

        assert checks["non_root_user"] == ValidationStatus.PASS


class TestTrailingLineContinuation:
    """Um arquivo terminado em barra invertida deixava a diretiva pendente
    no buffer do parser, e ela sumia sem ser verificada."""

    def test_a_final_unterminated_run_is_still_inspected(self, validate):
        checks = validate("FROM node:22-alpine\nUSER node\nRUN sudo apt-get update && \\")

        assert checks["no_sudo"] == ValidationStatus.FAIL

    def test_a_final_unterminated_env_still_reports_its_secret(self, tmp_path):
        (tmp_path / "Dockerfile").write_text("FROM node:22-alpine\nUSER node\nENV API_KEY=abc \\")
        result = DockerfileValidator().validate(tmp_path)

        secret_check = next(c for c in result.checks if c.check == "secrets_not_in_env")
        assert secret_check.status == ValidationStatus.FAIL
        assert "API_KEY" in secret_check.message


class TestUnreadableDockerignore:
    def test_it_is_reported_as_skip_not_as_a_crash(self, tmp_path, monkeypatch):
        """Um `.dockerignore` presente mas ilegível derrubava a validação
        inteira por causa de um check opcional."""
        (tmp_path / "Dockerfile").write_text("FROM node:22-alpine\nUSER node\n")
        (tmp_path / ".dockerignore").write_text(".git\n")

        real_read_text = type(tmp_path).read_text

        def boom(self, *args, **kwargs):
            if self.name == ".dockerignore":
                raise PermissionError("denied")
            return real_read_text(self, *args, **kwargs)

        monkeypatch.setattr(type(tmp_path), "read_text", boom)

        result = DockerfileValidator().validate(tmp_path)
        check = next(c for c in result.checks if c.check == "dockerignore_complete")
        assert check.status == ValidationStatus.SKIP


class TestLabelParsing:
    """Uma instrução LABEL declara vários pares, e todos contam.

    O padrão anterior casava até o primeiro `=` e engolia o resto como valor,
    então a forma idiomática -- vários pares numa instrução, quebrada com
    barras invertidas -- produzia uma chave só, com um valor sem sentido. A
    consequência era um falso positivo em DF007: o Dockerfile deste próprio
    repositório declarava `security.scanner` e era reprovado por não declarar
    `security.scanner`. Um aviso que dispara sobre algo que está lá ensina o
    leitor a ignorar o aviso.
    """

    def _labels(self, content: str) -> dict[str, str]:
        return DockerfileParser().parse(content).labels

    def test_every_pair_of_a_multi_pair_label_is_parsed(self):
        labels = self._labels(
            'FROM x\nLABEL maintainer="me" security.scanner="dockerls" org.foo="bar"\n'
        )
        assert labels == {
            "maintainer": "me",
            "security.scanner": "dockerls",
            "org.foo": "bar",
        }

    def test_pairs_survive_line_continuations(self):
        labels = self._labels(
            'FROM x\nLABEL maintainer="me" \\\n      security.scanner="dockerls"\n'
        )
        assert labels["security.scanner"] == "dockerls"

    def test_a_quoted_value_may_contain_spaces(self):
        labels = self._labels('FROM x\nLABEL org.opencontainers.image.title="Docker Ls"\n')
        assert labels["org.opencontainers.image.title"] == "Docker Ls"

    def test_the_legacy_space_separated_form_still_parses(self):
        labels = self._labels("FROM x\nLABEL description some text here\n")
        assert labels == {"description": "some text here"}

    def test_unbalanced_quotes_do_not_discard_the_instruction(self):
        # O Docker recusaria isto; o parser não pode explodir por causa disso.
        labels = self._labels('FROM x\nLABEL maintainer="me security.scanner=dockerls\n')
        assert labels

    def test_a_dockerfile_declaring_the_required_labels_passes_df007(self, validate):
        checks = validate(
            "FROM python:3.12-slim\n"
            'LABEL maintainer="Ivomsantiago" security.scanner="dockerls"\n'
            "USER 1001\n"
        )
        assert checks["security_labels"] == ValidationStatus.PASS


class TestBaseSuggestionIsMeasured:
    """A sugestão de base não nomeia imagem que ninguém mediu.

    Era a string fixa `"FROM node:22-alpine or FROM chainguard/node:latest-dev"`,
    devolvida igual para qualquer Dockerfile -- inclusive um de Python, onde
    nomear uma imagem Node é simplesmente errado.
    """

    def _suggestion(self, tmp_path, content: str):
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text(content, encoding="utf-8")
        rules = DockerfileValidator().suggest_hardening(str(dockerfile))
        return next((r for r in rules if r.title == "Upgrade base image"), None)

    def test_nao_nomeia_uma_imagem_node_num_projeto_python(self, tmp_path):
        rule = self._suggestion(tmp_path, "FROM python:3.12\nUSER 10001\n")

        assert rule is not None
        assert "node" not in rule.suggested_fix.lower()
        assert "chainguard" not in rule.suggested_fix.lower()

    def test_aponta_para_os_comandos_que_medem(self, tmp_path):
        rule = self._suggestion(tmp_path, "FROM ubuntu:24.04\nUSER 10001\n")

        assert rule is not None
        assert "dockerls base --alternatives" in rule.suggested_fix

    def test_a_razao_diz_que_a_escolha_e_medicao_e_nao_nome(self, tmp_path):
        rule = self._suggestion(tmp_path, "FROM ubuntu:24.04\nUSER 10001\n")

        assert rule is not None
        assert "measurement, not a name" in rule.reason


class TestPinnedMessageIsUnambiguous:
    """PASS em DF001 significa apenas "não é `latest`".

    Dizer "pinned" sem mais nada punha um PASS ao lado de `node:22` na mesma
    tela em que a política reprovava a mesma linha por "não está fixada por
    digest".
    """

    def _check(self, tmp_path, content: str):
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text(content, encoding="utf-8")
        result = DockerfileValidator().validate(str(dockerfile))
        return next(c for c in result.checks if c.check == "base_image_pinned")

    def test_tag_sem_digest_diz_que_ainda_e_movel(self, tmp_path):
        check = self._check(tmp_path, "FROM node:22\nUSER 10001\n")

        assert check.status is ValidationStatus.PASS
        assert "moving tag" in check.message
        assert check.details["pinned_by_digest"] is False

    def test_digest_e_reconhecido_como_tal(self, tmp_path):
        check = self._check(tmp_path, f"FROM node:22@sha256:{'a' * 64}\nUSER 10001\n")

        assert "pinned by digest" in check.message.lower()
        assert check.details["pinned_by_digest"] is True


@pytest.fixture
def check_for(tmp_path):
    """Um único `ValidationCheck` pelo nome, para inspecionar mensagem e
    severidade e não só o status."""

    def _check(content: str, name: str):
        (tmp_path / "Dockerfile").write_text(content, encoding="utf-8")
        result = DockerfileValidator().validate(tmp_path)
        return next(c for c in result.checks if c.check == name)

    return _check


class TestAPortInTheRegistryHostHidAnUnpinnedBase:
    """O pior modo de falha desta ferramenta, e estava na DF001.

    A checagem era `":latest" in image or (":" not in image and "@" not in
    image)`. `FROM registry.local:5000/app` não tem tag -- o Docker resolve
    para `:latest` -- mas *tem* dois pontos, no host. A regra lia "está com
    tag" e dava PASS, com severidade HIGH, para a base mais móvel que
    existe. Toda organização com registry interno por porta escapava.
    """

    def test_a_host_with_a_port_and_no_tag_is_still_a_moving_base(self, validate):
        checks = validate("FROM registry.local:5000/app\nUSER 10001\n")

        assert checks["base_image_pinned"] == ValidationStatus.FAIL

    def test_a_host_with_a_port_and_a_real_tag_passes(self, validate):
        checks = validate("FROM registry.local:5000/app:1.4.2\nUSER 10001\n")

        assert checks["base_image_pinned"] == ValidationStatus.PASS

    def test_a_host_with_a_port_and_latest_still_fails(self, validate):
        checks = validate("FROM registry.local:5000/app:latest\nUSER 10001\n")

        assert checks["base_image_pinned"] == ValidationStatus.FAIL

    def test_a_host_with_a_port_and_a_digest_passes(self, validate):
        checks = validate(f"FROM registry.local:5000/app@sha256:{'a' * 64}\nUSER 10001\n")

        assert checks["base_image_pinned"] == ValidationStatus.PASS

    @pytest.mark.parametrize(
        "reference",
        [
            "ghcr.io/org/app:latest-stable",
            "node:22-latest-lts",
            "myorg/latestwatch:1.0",
            "registry.io/team/latest-builds:2024.11",
        ],
    )
    def test_the_word_latest_inside_a_real_tag_is_not_the_latest_tag(self, validate, reference):
        """`":latest" in image` acusava `:latest-stable`, que é uma tag
        comum e fixa o suficiente. Um falso FAIL custa a confiança na
        regra, e uma regra em que ninguém confia é uma regra desligada."""
        checks = validate(f"FROM {reference}\nUSER 10001\n")

        assert checks["base_image_pinned"] == ValidationStatus.PASS

    def test_a_from_built_from_an_arg_is_not_judged_either_way(self, validate):
        """`FROM $BASE` é resolvido por um ARG que este parser não avalia.
        Chamá-lo de fixado ou de móvel seria inventar."""
        checks = validate("ARG BASE=node:22-alpine\nFROM $BASE\nUSER 10001\n")

        assert checks["base_image_pinned"] == ValidationStatus.PASS


class TestAddIsNotACopyWithAnotherName:
    """DF013. `ADD` busca URLs sem conferir nada e descompacta arquivos
    sozinho, e nenhuma das duas coisas está escrita na linha."""

    def test_a_remote_add_is_a_failure(self, check_for):
        check = check_for(
            "FROM node:22-alpine\nADD https://example.com/tool.sh /usr/local/bin/\nUSER 10001\n",
            "add_not_used_for_copy",
        )

        assert check.status is ValidationStatus.FAIL
        assert check.severity.value == "HIGH"
        assert check.rule_id == "DF013"
        assert "without verifying" in check.message
        # As cinco propriedades: detecção, severidade, racional, remediação
        # e citação.
        assert check.fix_suggestion
        assert check.rationale
        assert any("4.9" in ref for ref in check.references)

    def test_a_checksummed_remote_add_is_the_correct_form_and_passes(self, check_for):
        """`ADD --checksum=` é o que o BuildKit oferece para baixar com
        integridade. A regra é contra o download não verificado, não contra
        a diretiva."""
        check = check_for(
            "FROM node:22-alpine\n"
            f"ADD --checksum=sha256:{'a' * 64} https://example.com/t.tgz /opt/\n"
            "USER 10001\n",
            "add_not_used_for_copy",
        )

        assert check.status is not ValidationStatus.FAIL

    def test_an_auto_extracted_archive_warns(self, check_for):
        check = check_for(
            "FROM node:22-alpine\nADD app.tar.gz /app/\nUSER 10001\n",
            "add_not_used_for_copy",
        )

        assert check.status is ValidationStatus.WARN
        assert "auto-extracts" in check.message

    def test_a_multi_source_add_is_still_seen(self, check_for):
        """A regex do COPY exige exatamente dois operandos; a do ADD não
        pode, ou `ADD a b c/` seria uma diretiva invisível."""
        check = check_for(
            "FROM node:22-alpine\nADD one.txt two.tar.gz /dest/\nUSER 10001\n",
            "add_not_used_for_copy",
        )

        assert check.status is ValidationStatus.WARN
        assert "two.tar.gz" in check.message

    def test_a_dockerfile_that_only_uses_copy_passes(self, check_for):
        check = check_for(
            "FROM node:22-alpine\nCOPY . /app\nUSER 10001\n",
            "add_not_used_for_copy",
        )

        assert check.status is ValidationStatus.PASS


class TestARemoteScriptPipedIntoAShell:
    """DF014. Nada assina o script, nada compara um digest, e ele roda como
    root durante o build."""

    @pytest.mark.parametrize(
        "command",
        [
            "curl -fsSL https://get.example.com | sh",
            "curl https://x.io/i.sh | bash",
            "wget -qO- https://x.io/i.sh | sh -s -- --yes",
            "curl -sL https://x.io/i.sh|bash",
        ],
    )
    def test_the_pipe_is_detected(self, check_for, command):
        check = check_for(
            f"FROM node:22-alpine\nRUN {command}\nUSER 10001\n",
            "no_unverified_remote_script",
        )

        assert check.status is ValidationStatus.FAIL
        assert check.severity.value == "HIGH"
        assert check.fix_suggestion and "sha256sum" in check.fix_suggestion
        assert check.rationale

    @pytest.mark.parametrize(
        "command",
        [
            # A forma correta: baixa, confere, depois roda.
            "curl -fsSL https://x.io/i.sh -o /tmp/i.sh "
            "&& echo 'abc  /tmp/i.sh' | sha256sum -c && sh /tmp/i.sh",
            # Um pipe que não termina num interpretador.
            "curl -s https://x.io/data.json | jq .version",
            "wget -qO- https://x.io/list.txt | sort -u > /etc/list",
            # Nem sequer é um download.
            "cat /etc/os-release | grep VERSION",
        ],
    )
    def test_a_verified_download_or_an_unrelated_pipe_is_not_accused(self, check_for, command):
        check = check_for(
            f"FROM node:22-alpine\nRUN {command}\nUSER 10001\n",
            "no_unverified_remote_script",
        )

        assert check.status is ValidationStatus.PASS

    def test_a_long_env_prefixed_command_does_not_hang(self, check_for):
        """The `env KEY=VALUE` prefix branch used two unbounded `\\S+`
        tokens around a shared `=`, the textbook catastrophic-backtracking
        shape: many ways to split "a=a=a=...=a" between them, multiplied
        across the outer repetition, when the overall match ultimately
        fails. CodeQL flagged this (dockerfile_validator.py:47, high
        severity) on this exact rule. A Dockerfile a build worker parses
        must never be able to hang the analysis regardless of what a RUN
        line contains."""
        adversarial = "env " + "=".join(["a"] * 200) + " " * 200 + "X"
        command = f"echo start && {adversarial} && echo end"

        start = time.monotonic()
        check_for(
            f"FROM node:22-alpine\nRUN {command}\nUSER 10001\n", "no_unverified_remote_script"
        )
        elapsed = time.monotonic() - start

        assert elapsed < 1.0, f"Dockerfile validation took {elapsed:.2f}s -- regex backtracking?"


class TestSetuidBinariesLeftInTheImage:
    """DF015. Um binário setuid roda como o dono, e o dono é root: é o
    caminho pronto de volta ao uid 0 num container que roda sem privilégio."""

    @pytest.mark.parametrize(
        "command",
        [
            "chmod u+s /usr/local/bin/tool",
            "chmod 4755 /usr/local/bin/tool",
            "chmod g+s /srv/shared",
            "chmod 2755 /srv/shared",
            "chmod u+xs /usr/local/bin/tool",
        ],
    )
    def test_the_bit_is_detected(self, check_for, command):
        check = check_for(
            f"FROM node:22-alpine\nRUN {command}\nUSER 10001\n",
            "no_setuid_binaries_added",
        )

        assert check.status is ValidationStatus.FAIL
        assert check.severity.value == "HIGH"
        assert check.rule_id == "DF015"
        assert any("4.8" in ref for ref in check.references)
        assert check.fix_suggestion and check.rationale

    @pytest.mark.parametrize(
        "command",
        [
            "chmod 0755 /usr/local/bin/tool",
            "chmod 755 /usr/local/bin/tool",
            "chmod +x /usr/local/bin/tool",
            "chmod -R a-s /usr/bin",
            "chown root:root /usr/local/bin/tool",
        ],
    )
    def test_an_ordinary_chmod_is_not_accused(self, check_for, command):
        check = check_for(
            f"FROM node:22-alpine\nRUN {command}\nUSER 10001\n",
            "no_setuid_binaries_added",
        )

        assert check.status is ValidationStatus.PASS


class TestSecretsInBuildArgs:
    """A DF004 se chama "Keep secrets out of ENV **and ARG**" no catálogo de
    controles, e não olhava ARG nenhum. Um PASS é lido como uma verificação
    que aconteceu."""

    def test_an_arg_with_a_secret_default_fails(self, check_for):
        check = check_for(
            "FROM node:22-alpine\nARG GITHUB_TOKEN=ghp_realvalue\nUSER 10001\n",
            "secrets_not_in_env",
        )

        assert check.status is ValidationStatus.FAIL
        assert "ARG with a default value" in check.message
        assert check.details["secret_build_args"] == ["GITHUB_TOKEN"]

    def test_an_arg_without_a_value_is_the_correct_form_and_passes(self, check_for):
        """`ARG TOKEN` sem valor é como se parametriza um build; acusá-lo
        transformaria a forma correta numa infração."""
        check = check_for(
            "FROM node:22-alpine\nARG GITHUB_TOKEN\nUSER 10001\n",
            "secrets_not_in_env",
        )

        assert check.status is ValidationStatus.PASS

    def test_an_ordinary_arg_with_a_value_is_not_a_secret(self, check_for):
        check = check_for(
            "FROM node:22-alpine\nARG NODE_VERSION=22.3.0\nUSER 10001\n",
            "secrets_not_in_env",
        )

        assert check.status is ValidationStatus.PASS

    def test_env_and_arg_are_reported_together(self, check_for):
        check = check_for(
            "FROM node:22-alpine\nARG API_KEY=abc\nENV DB_PASSWORD=hunter2\nUSER 10001\n",
            "secrets_not_in_env",
        )

        assert check.details["secret_vars"] == ["DB_PASSWORD"]
        assert check.details["secret_build_args"] == ["API_KEY"]


class TestSubstringMatchesWereFalsePositives:
    """`"sudo" in cmd` casava com `pseudo`; `"apt" in cmd` com `adapt`; e um
    gerenciador de pacotes detectado onde não há nenhum acusa a DF005 de
    cache não limpo num Dockerfile que não instalou nada."""

    @pytest.mark.parametrize(
        "command",
        [
            "apk add --no-cache pseudo-terminal",
            "echo 'no sudo in this image' > /etc/motd",
            "./configure --with-pseudoterminal",
        ],
    )
    def test_sudo_as_a_substring_is_not_sudo(self, validate, command):
        checks = validate(f"FROM alpine:3.20\nRUN {command}\nUSER 10001\n")

        assert checks["no_sudo"] == ValidationStatus.PASS

    def test_sudo_as_a_command_still_fails(self, validate):
        checks = validate("FROM alpine:3.20\nRUN sudo apk add curl\nUSER 10001\n")

        assert checks["no_sudo"] == ValidationStatus.FAIL

    def test_a_word_that_merely_contains_a_package_manager_is_not_one(self):
        info = DockerfileParser().parse(
            "FROM alpine:3.20\nRUN ./build.sh --adapt --pipeline captured\n"
        )

        assert info.package_managers_used == []

    def test_a_real_package_manager_is_still_found(self):
        info = DockerfileParser().parse("FROM alpine:3.20\nRUN apk add curl && pip install x\n")

        assert set(info.package_managers_used) == {"apk", "pip"}


class TestBuildKitSecretMount:
    """`--mount=type=secret` is the correct answer to DF004, and using it
    must say so -- without letting it excuse a secret still sitting in
    ENV/ARG on the same Dockerfile."""

    def test_a_secret_mount_passes_and_names_the_id(self, validate):
        checks = validate(
            "FROM alpine:3.20\n"
            "RUN --mount=type=secret,id=npm_token cat /run/secrets/npm_token > /tmp/t\n"
            "USER 10001\n"
        )

        assert checks["buildkit_secret_mount_used"] == ValidationStatus.PASS

    def test_absent_when_no_run_uses_a_secret_mount(self, validate):
        checks = validate("FROM alpine:3.20\nRUN apk add curl=8.9.1-r2\nUSER 10001\n")

        assert "buildkit_secret_mount_used" not in checks

    def test_a_secret_mount_does_not_excuse_a_secret_in_env(self, validate):
        checks = validate(
            "FROM alpine:3.20\n"
            "ENV DB_PASSWORD=hunter2\n"
            "RUN --mount=type=secret,id=npm_token npm ci\n"
            "USER 10001\n"
        )

        assert checks["secrets_not_in_env"] == ValidationStatus.FAIL
        assert checks["buildkit_secret_mount_used"] == ValidationStatus.PASS


class TestPinnedPackageVersions:
    """DF016: reproducibility, not confidentiality -- an unpinned install
    can resolve different bytes, and a different CVE, on the next build."""

    def test_unpinned_apk_package_warns(self, validate):
        checks = validate("FROM alpine:3.20\nRUN apk add curl\nUSER 10001\n")

        assert checks["package_versions_pinned"] == ValidationStatus.WARN

    def test_pinned_apk_package_passes(self, validate):
        checks = validate("FROM alpine:3.20\nRUN apk add curl=8.9.1-r2\nUSER 10001\n")

        assert checks["package_versions_pinned"] == ValidationStatus.PASS

    def test_unpinned_apt_package_warns(self, validate):
        checks = validate("FROM debian:12-slim\nRUN apt-get install -y curl\nUSER 10001\n")

        assert checks["package_versions_pinned"] == ValidationStatus.WARN

    def test_pinned_apt_package_with_flags_passes(self, validate):
        checks = validate(
            "FROM debian:12-slim\n"
            "RUN apt-get install -y --no-install-recommends curl=8.5.0-2\n"
            "USER 10001\n"
        )

        assert checks["package_versions_pinned"] == ValidationStatus.PASS

    def test_pip_install_without_exact_pin_warns(self, validate):
        checks = validate("FROM python:3.12-slim\nRUN pip install requests\nUSER 10001\n")

        assert checks["package_versions_pinned"] == ValidationStatus.WARN

    def test_pip_install_with_exact_pin_passes(self, validate):
        checks = validate("FROM python:3.12-slim\nRUN pip install requests==2.32.3\nUSER 10001\n")

        assert checks["package_versions_pinned"] == ValidationStatus.PASS

    def test_pip_requirements_file_flag_is_not_mistaken_for_a_package(self, tmp_path):
        """`-r requirements.txt` names a file, not a package -- it must
        never appear in `unpinned_packages`."""
        (tmp_path / "Dockerfile").write_text(
            "FROM python:3.12-slim\nRUN pip install -r requirements.txt\nUSER 10001\n"
        )
        result = DockerfileValidator().validate(tmp_path)
        check = next(c for c in result.checks if c.check == "package_versions_pinned")

        assert check.status == ValidationStatus.PASS
        assert check.details.get("unpinned_packages", []) == []

    def test_npm_install_without_a_version_warns(self, validate):
        checks = validate("FROM node:22-alpine\nRUN npm install lodash\nUSER 10001\n")

        assert checks["package_versions_pinned"] == ValidationStatus.WARN

    def test_npm_install_with_a_version_still_warns_without_a_lockfile(self, validate):
        """The version pin on the package and a committed lockfile are two
        different signals; either missing is its own finding."""
        checks = validate("FROM node:22-alpine\nRUN npm install lodash@4.17.21\nUSER 10001\n")

        assert checks["package_versions_pinned"] == ValidationStatus.WARN

    def test_npm_ci_with_a_committed_lockfile_and_no_direct_install_passes(
        self, validate, tmp_path
    ):
        (tmp_path / "package-lock.json").write_text("{}")
        checks = validate("FROM node:22-alpine\nRUN npm ci\nUSER 10001\n")

        assert checks["package_versions_pinned"] == ValidationStatus.PASS

    def test_multiple_managers_are_all_named_in_one_message(self, validate):
        checks = validate(
            "FROM node:22-alpine\nRUN apk add curl && pip install requests\nUSER 10001\n"
        )

        assert checks["package_versions_pinned"] == ValidationStatus.WARN


class TestMultiArchAwareness:
    """DF017 is informational: presence, not a correct/incorrect state."""

    def test_no_platform_reference_emits_nothing(self, validate):
        checks = validate("FROM alpine:3.20\nUSER 10001\n")

        assert "multi_arch_build_declared" not in checks

    def test_target_platform_arg_is_detected(self, validate):
        checks = validate("FROM alpine:3.20\nARG TARGETPLATFORM\nUSER 10001\n")

        assert checks["multi_arch_build_declared"] == ValidationStatus.PASS

    def test_from_platform_flag_is_detected(self, validate):
        checks = validate(
            "FROM --platform=$BUILDPLATFORM golang:1.23 AS builder\nFROM alpine:3.20\nUSER 10001\n"
        )

        assert checks["multi_arch_build_declared"] == ValidationStatus.PASS

    def test_multi_arch_with_unpinned_packages_warns_about_the_combination(self, validate):
        checks = validate("FROM alpine:3.20\nARG TARGETPLATFORM\nRUN apk add curl\nUSER 10001\n")

        assert checks["multi_arch_pinned_packages"] == ValidationStatus.WARN

    def test_multi_arch_with_pinned_packages_does_not_add_the_combination_warning(self, validate):
        checks = validate(
            "FROM alpine:3.20\nARG TARGETPLATFORM\nRUN apk add curl=8.9.1-r2\nUSER 10001\n"
        )

        assert "multi_arch_pinned_packages" not in checks


class TestTemplateOrigin:
    """A Dockerfile derived from one of the 39 hardened templates, edited
    by hand, should be recognised as that template plus a diff -- not
    treated as an anonymous Dockerfile."""

    def test_an_edited_template_is_recognised_with_its_diff(self, tmp_path):
        templates = HardeningTemplates()
        edited = templates.get_template("alpine").replace(
            'LABEL maintainer="security@company.com"', 'LABEL maintainer="me@example.com"'
        )
        (tmp_path / "Dockerfile").write_text(edited)

        analysis = DockerfileValidator(templates).analyze(tmp_path)

        assert analysis.template_origin is not None
        assert analysis.template_origin.template_name == "alpine"
        assert analysis.template_origin.similarity > 0.9
        assert any("me@example.com" in line for line in analysis.template_origin.diff)

    def test_an_unrelated_dockerfile_matches_no_template(self, tmp_path):
        (tmp_path / "Dockerfile").write_text("FROM ubuntu:24.04\nRUN echo hi\n")

        analysis = DockerfileValidator(HardeningTemplates()).analyze(tmp_path)

        assert analysis.template_origin is None

    def test_without_a_template_provider_the_field_stays_none(self, tmp_path):
        """A validator built without a `template_provider` -- most call
        sites, most of the time -- must not error, just say nothing."""
        (tmp_path / "Dockerfile").write_text("FROM ubuntu:24.04\nRUN echo hi\n")

        analysis = DockerfileValidator().analyze(tmp_path)

        assert analysis.template_origin is None
