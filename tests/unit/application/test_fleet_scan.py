"""A varredura da árvore: onde ela anda, onde não anda, e o que ela lê.

Andar no disco é onde este comando pode se machucar, e os testes fixam os três
limites que existem por isso: symlink nunca é seguido, diretórios de
dependência ficam de fora, e o truncamento é dito em voz alta.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

import pytest

from dockerls.application.use_cases.fleet_scan import FleetScanRequest, FleetScanUseCase
from dockerls.domain.value_objects.build_policy import BuildPolicy
from dockerls.domain.value_objects.tristate import Tristate
from dockerls.infrastructure.dockerfile_validator import DockerfileValidator

if TYPE_CHECKING:
    from pathlib import Path


def _scan(root: Path, policy: BuildPolicy | None = None, **kwargs: int):
    return FleetScanUseCase(DockerfileValidator()).execute(
        FleetScanRequest(root=str(root), policy=policy, **kwargs)  # type: ignore[arg-type]
    )


class TestDiscovery:
    def test_encontra_dockerfiles_em_subdiretorios(self, tmp_path: Path) -> None:
        (tmp_path / "a").mkdir()
        (tmp_path / "b").mkdir()
        (tmp_path / "a" / "Dockerfile").write_text("FROM alpine:3.21\n")
        (tmp_path / "b" / "Dockerfile").write_text("FROM alpine:3.21\n")

        report = _scan(tmp_path)

        assert report.total == 2
        assert {e.path for e in report.entries} == {"a/Dockerfile", "b/Dockerfile"}

    def test_variantes_do_nome_entram(self, tmp_path: Path) -> None:
        """`Dockerfile.prod` constrói imagem de verdade, e deixá-lo de fora
        esconderia exatamente as variantes que ninguém revisa."""
        (tmp_path / "Dockerfile.prod").write_text("FROM alpine:3.21\n")
        (tmp_path / "app.dockerfile").write_text("FROM alpine:3.21\n")

        assert _scan(tmp_path).total == 2

    def test_diretorios_de_dependencia_sao_pulados(self, tmp_path: Path) -> None:
        """Incluí-los encheria o relatório de linhas sobre as quais ninguém
        pode agir, e a lista deixaria de ser fila de trabalho."""
        for pasta in ("node_modules", ".git", ".venv", "vendor"):
            (tmp_path / pasta).mkdir()
            (tmp_path / pasta / "Dockerfile").write_text("FROM alpine:3.21\n")

        assert _scan(tmp_path).total == 0

    @pytest.mark.skipif(os.name == "nt", reason="symlink exige privilégio no Windows")
    def test_symlink_nunca_e_seguido(self, tmp_path: Path) -> None:
        """Um link para `/` transformaria a varredura de um repositório numa
        varredura da máquina inteira."""
        real = tmp_path / "real"
        real.mkdir()
        (real / "Dockerfile").write_text("FROM alpine:3.21\n")
        (tmp_path / "link").symlink_to(real, target_is_directory=True)

        assert _scan(tmp_path).total == 1

    def test_raiz_inexistente_e_reportada_e_nao_explode(self, tmp_path: Path) -> None:
        report = _scan(tmp_path / "ausente")

        assert report.total == 0
        assert report.unreadable_paths

    def test_teto_de_arquivos_trunca_e_diz_que_truncou(self, tmp_path: Path) -> None:
        """Um retrato parcial que se apresenta como completo é pior do que
        nenhum retrato."""
        for i in range(5):
            (tmp_path / f"Dockerfile.{i}").write_text("FROM alpine:3.21\n")

        report = _scan(tmp_path, max_dockerfiles=2)

        assert report.total == 2
        assert report.truncated

    def test_profundidade_excedida_tambem_trunca(self, tmp_path: Path) -> None:
        fundo = tmp_path
        for i in range(4):
            fundo = fundo / f"n{i}"
            fundo.mkdir()
        (fundo / "Dockerfile").write_text("FROM alpine:3.21\n")

        report = _scan(tmp_path, max_depth=1)

        assert report.truncated
        assert report.total == 0


class TestReading:
    def test_digest_vindo_de_arg_conta_como_fixado(self, tmp_path: Path) -> None:
        """É a forma *correta* de fixar: uma varredura que reprova quem fez
        certo é uma varredura que ensina a fazer errado."""
        (tmp_path / "Dockerfile").write_text(
            "ARG PY=sha256:aa\nFROM python:3.12-alpine@${PY}\nUSER 10001\n"
        )

        entry = _scan(tmp_path).entries[0]

        assert entry.pinned_bases == 1
        assert entry.fully_pinned

    def test_tag_movel_nao_conta_como_fixada(self, tmp_path: Path) -> None:
        (tmp_path / "Dockerfile").write_text("FROM node:22\n")

        entry = _scan(tmp_path).entries[0]

        assert entry.pinned_bases == 0
        assert not entry.fully_pinned

    def test_usuario_sem_privilegio_e_detectado(self, tmp_path: Path) -> None:
        (tmp_path / "Dockerfile").write_text("FROM alpine:3.21\nUSER 10001\n")
        assert _scan(tmp_path).entries[0].nonroot is Tristate.TRUE

    def test_root_e_detectado(self, tmp_path: Path) -> None:
        (tmp_path / "Dockerfile").write_text("FROM alpine:3.21\n")
        assert _scan(tmp_path).entries[0].nonroot is Tristate.FALSE


class TestPolicy:
    def test_violacoes_sao_anexadas_a_cada_arquivo(self, tmp_path: Path) -> None:
        (tmp_path / "Dockerfile").write_text("FROM node:22\n")

        report = _scan(tmp_path, BuildPolicy(require_pinned_bases=True))

        assert report.policy_applied
        assert report.total_violations == 1

    def test_regras_que_dependem_de_scan_nao_geram_ruido(self, tmp_path: Path) -> None:
        """Elas produziriam uma violação idêntica por arquivo, todas dizendo
        "não houve scan"."""
        (tmp_path / "Dockerfile").write_text(
            "ARG PY=sha256:aa\nFROM python:3.12-alpine@${PY}\nUSER 10001\n"
        )

        report = _scan(
            tmp_path,
            BuildPolicy(require_scan=True, max_vulnerabilities={"critical": 0}),
        )

        assert report.total_violations == 0

    def test_sem_politica_nao_ha_violacao_e_isso_nao_e_conformidade(self, tmp_path: Path) -> None:
        (tmp_path / "Dockerfile").write_text("FROM node:22\n")

        report = _scan(tmp_path)

        assert report.total_violations == 0
        assert not report.policy_applied
