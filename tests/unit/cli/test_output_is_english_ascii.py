"""Guard: a saída ao usuário é inglês em ASCII, sem emoji.

Dois critérios que andam juntos, num único varredor por comando:

* **idioma** -- a ferramenta é publicada em inglês (README, PyPI, nomes de
  comando), e metade dos comandos respondia em português. Um caractere
  acentuado na saída é a assinatura de uma string que escapou da tradução;
* **emoji** -- um "Enterprise Docker Image Security Advisor" não decora o
  terminal. A cor do Rich já carrega o sinal visual, e ela sobrevive a um
  `--no-color` ou a um pipe para arquivo de log, coisa que um ✅ não faz.

O que a varredura **não** cobre: comentários de código e docstrings, que
seguem em português por convenção do projeto, e os comandos ainda não
traduzidos (`build`, `base-image`, `provenance`, `verify`, `registry-audit`)
-- ver `_NOT_YET_TRANSLATED` no fim deste arquivo.
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING

import pytest
from typer.testing import CliRunner

from dockerls.cli.app import app

if TYPE_CHECKING:
    from pathlib import Path

runner = CliRunner()

#: Emoji e pictogramas. Deliberadamente **não** inclui Box Drawing
#: (U+2500-U+257F): `├─` e `└─` desenham a árvore de fatos do `advisor` e são
#: a mesma convenção que `tree` usa -- estrutura, não decoração.
EMOJI = re.compile(
    "["
    "\U0001f000-\U0001faff"  # pictogramas, símbolos suplementares, emoticons
    "☀-➿"  # dingbats, símbolos diversos (✅ ⚠ ❌ ✨ ➖)
    "⬀-⯿"  # setas e formas suplementares
    "️"  # variation selector-16 (o "-16" que transforma ⚠ em ⚠️)
    "•"  # bullet tipográfico
    "]"
)

#: Qualquer letra acentuada da faixa Latin-1 Supplement. É o sinal barato de
#: português: `ã`, `ç`, `é`, `í`, `ú`.
NON_ASCII_LETTER = re.compile(r"[À-ÿ]")


def _offending(output: str) -> list[str]:
    """As linhas que violam qualquer um dos dois critérios."""
    bad = []
    for line in output.splitlines():
        if EMOJI.search(line) or NON_ASCII_LETTER.search(line):
            bad.append(line.strip())
    return bad


def _assert_clean(result, label: str) -> None:
    offenders = _offending(result.output)
    assert not offenders, f"{label}: saída com português ou emoji.\n" + "\n".join(
        f"  {line!r}" for line in offenders[:10]
    )


@pytest.fixture
def project(tmp_path: Path) -> Path:
    """Um Dockerfile mínimo, suficiente para os comandos que leem arquivos."""
    (tmp_path / "Dockerfile").write_text("FROM node:22\nUSER 10001\n", encoding="utf-8")
    return tmp_path


class TestCommandsReadingFiles:
    """Comandos que rodam sem rede nem scanner, contra um fixture mínimo."""

    def test_fleet_without_a_policy(self, project: Path):
        _assert_clean(runner.invoke(app, ["fleet", str(project), "--no-color"]), "fleet")

    def test_fleet_reporting_a_violation(self, project: Path):
        """O caminho que imprime a mensagem da regra violada, que vem do
        domínio -- foi por aqui que o português vazou por baixo do comando."""
        (project / ".dockerls-policy.yaml").write_text(
            "require_pinned_bases: true\n", encoding="utf-8"
        )
        result = runner.invoke(app, ["fleet", str(project), "--no-color"])

        assert "require_pinned_bases" in result.output
        _assert_clean(result, "fleet (violation)")

    def test_policy_without_a_file(self, project: Path):
        _assert_clean(runner.invoke(app, ["policy", str(project), "--no-color"]), "policy")

    def test_policy_showing_declared_rules(self, project: Path):
        (project / ".dockerls-policy.yaml").write_text(
            "require_pinned_bases: true\nrequire_nonroot: true\nfail_on: high\n",
            encoding="utf-8",
        )
        _assert_clean(
            runner.invoke(app, ["policy", str(project), "--no-color"]), "policy (declared)"
        )

    def test_policy_rejecting_a_broken_file(self, project: Path):
        """As mensagens de erro do carregador também são saída ao usuário."""
        (project / ".dockerls-policy.yaml").write_text("nao_existe: true\n", encoding="utf-8")
        result = runner.invoke(app, ["policy", str(project), "--no-color"])

        assert result.exit_code != 0
        _assert_clean(result, "policy (invalid)")

    def test_analyze_dockerfile(self, project: Path):
        _assert_clean(
            runner.invoke(app, ["analyze-dockerfile", str(project)]), "analyze-dockerfile"
        )

    def test_controls(self):
        """Onde vivia o cabeçalho 'Controles de referencia'."""
        _assert_clean(runner.invoke(app, ["controls"]), "controls")


class TestTagRejectionMessage:
    """A mensagem de `image:tag` nasceu em português no PR #37, dentro de
    comandos que eram 100% ingleses."""

    @pytest.mark.parametrize("command", ["search", "recommend", "export"])
    def test_the_rejection_is_english(self, command: str):
        result = runner.invoke(app, [command, "node:18"])

        assert result.exit_code == 1
        _assert_clean(result, f"{command} node:18")


def _command_names() -> list[str]:
    """Todo subcomando da CLI, tirado da tabela que os registra.

    Listar à mão deixava cinco comandos de fora -- os cinco que ainda
    respondiam em português. Tirar a lista da própria tabela faz o guard
    crescer sozinho: um comando novo já nasce conferido.
    """
    from dockerls.cli.app import COMMANDS

    return [spec.name for spec in COMMANDS]


class TestHelpText:
    """`--help` é a primeira saída que qualquer pessoa vê de um comando."""

    @pytest.mark.parametrize("command", _command_names())
    def test_help_is_english(self, command: str):
        _assert_clean(runner.invoke(app, [command, "--help"]), f"{command} --help")

    def test_the_root_help_is_english(self):
        """A listagem de comandos vem da tabela de `app.py`, e o resumo de
        cada um é copiado da docstring -- dois lugares para o português
        voltar sem ninguém notar."""
        _assert_clean(runner.invoke(app, ["--help"]), "--help")


class TestTheCommandsThatWereTranslatedLast:
    """`build`, `base-image`, `provenance`, `verify` e `registry-audit`
    respondiam em português e estavam fora do guard por isenção declarada.
    Estes exercícios são o que substitui a isenção: saída de verdade, não
    só `--help`."""

    def test_build_listing_templates(self):
        _assert_clean(runner.invoke(app, ["build", "--list-templates"]), "build --list-templates")

    def test_build_refusing_an_unknown_base(self, project: Path):
        result = runner.invoke(app, ["build", str(project), "-t", "a:1", "--base", "nao-existe"])
        _assert_clean(result, "build --base desconhecida")

    def test_build_refusing_to_publish_without_a_scan(self, project: Path):
        result = runner.invoke(app, ["build", str(project), "-t", "a:1", "--push", "--no-scan"])
        _assert_clean(result, "build --push --no-scan")

    def test_base_image_refusing_an_unknown_os(self, tmp_path: Path):
        result = runner.invoke(
            app, ["base-image", "--os", "nao-existe", "--output", str(tmp_path / "D")]
        )
        _assert_clean(result, "base-image --os desconhecido")

    def test_base_image_refusing_a_refused_package(self, tmp_path: Path):
        result = runner.invoke(
            app,
            [
                "base-image",
                "--os",
                "alpine",
                "--runtime",
                "none",
                "--with",
                "sudo",
                "--no-pin",
                "--output",
                str(tmp_path / "D"),
            ],
        )
        _assert_clean(result, "base-image --with sudo")

    def test_provenance_reading_a_broken_document(self, tmp_path: Path):
        broken = tmp_path / "provenance.json"
        broken.write_text("{not json", encoding="utf-8")
        _assert_clean(runner.invoke(app, ["provenance", str(broken)]), "provenance")

    def test_provenance_reading_a_verified_document(self, tmp_path: Path):
        document = tmp_path / "provenance.json"
        document.write_text(
            json.dumps(
                {
                    "tag": "app:1.0",
                    "status": "VERIFIED",
                    "source": {
                        "dockerfile": "sha256:aa",
                        "context": "sha256:bb",
                        "context_files": 12,
                        "git_revision": "abc123",
                        "git_dirty": False,
                        "base_images": {"alpine:3.21": "sha256:cc"},
                    },
                    "source_after": {"dockerfile": "sha256:aa", "context": "sha256:bb"},
                    "artifact": {
                        "image_id": "sha256:dd",
                        "repo_digest": "sha256:ee",
                        "published_reference": "ghcr.io/org/app@sha256:ee",
                        "scanner": "trivy 0.58.1",
                    },
                }
            ),
            encoding="utf-8",
        )
        _assert_clean(runner.invoke(app, ["provenance", str(document)]), "provenance verificada")


class TestEcosystemInsights:
    """A seção 'Ecosystem Particularities & Hardening' do `advisor` vinha
    inteira em português, com emoji nos bullets -- o texto mora em
    `application/services/ecosystems.py`, não no comando."""

    @pytest.mark.parametrize(
        "reference",
        [
            "node:22-alpine",
            "node:22-bookworm-slim",
            "python:3.12-alpine",
            "python:3.12-slim",
            "golang:1.23",
            "eclipse-temurin:21-jre",
            "rust:1.82",
            "php:8.3",
            "mystery:1.0",
        ],
    )
    def test_every_ecosystem_branch_is_english_and_emoji_free(self, reference: str):
        from dockerls.application.services.ecosystems import get_ecosystem_insights

        insight = get_ecosystem_insights(reference)
        text = "\n".join(
            [
                *insight.runtime_features,
                *insight.base_distro_advice,
                *insight.security_guidelines,
                *insight.common_pitfalls,
                *insight.recommended_dockerfile_snippets,
            ]
        )
        offenders = _offending(text)
        assert not offenders, f"{reference}: {offenders}"


class TestValidationReportSymbols:
    """Os status de check eram '✅ PASS' / '⚠️ WARN' / '❌ FAIL' / '➖ SKIP'.
    Viraram texto puro, com a cor do Rich fazendo o trabalho visual -- que é
    o que sobrevive a um pipe para arquivo de log."""

    def test_status_labels_are_plain_text(self):
        from dockerls.cli.rendering import _STATUS_ICONS

        for status, rendered in _STATUS_ICONS.items():
            assert not EMOJI.search(rendered), f"{status}: {rendered!r}"
            assert status in rendered


#: Vazio, e é para continuar assim. Aqui ficavam `build`, `base-image`,
#: `provenance`, `verify` e `registry-audit` -- os cinco comandos que ainda
#: respondiam em português. A lista existia para que ninguém lesse a
#: ausência deles do guard como aprovação; agora ela existe para que
#: ninguém acrescente um sexto sem que isso seja uma decisão explícita.
_NOT_YET_TRANSLATED: tuple[str, ...] = ()


def test_no_command_is_exempt_from_the_language_guard():
    """A lista de isenções está vazia, e cada nome que voltar a ela é um
    comando que deixou de ser conferido -- o que tem de doer para ser
    notado."""
    assert _NOT_YET_TRANSLATED == (), (
        f"commands exempted from the English/no-emoji guard: {list(_NOT_YET_TRANSLATED)}"
    )


def test_the_untranslated_commands_are_declared():
    """Trava a lista acima contra o esquecimento: um nome que sobre nela
    tem de nomear um comando que existe de verdade."""
    from dockerls.cli.app import COMMANDS

    # Os subcomandos são carregados sob demanda, então a fonte da verdade é
    # a tabela de `app.py` e não `registered_commands` (que está vazia).
    registered = {spec.name for spec in COMMANDS}
    for command in _NOT_YET_TRANSLATED:
        assert command in registered or command.replace("-", "_") in registered
