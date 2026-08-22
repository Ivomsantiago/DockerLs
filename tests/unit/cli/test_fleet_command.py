"""`dockerls fleet` -- a fila de trabalho de quem responde por trinta repositórios."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from typer.testing import CliRunner

from dockerls.cli.app import app
from dockerls.exit_codes import EXIT_ERROR, EXIT_OK, EXIT_POLICY

if TYPE_CHECKING:
    from pathlib import Path

runner = CliRunner()


def test_lista_os_dockerfiles_encontrados(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text("FROM alpine:3.21\nUSER 10001\n", encoding="utf-8")

    result = runner.invoke(app, ["fleet", str(tmp_path), "--no-color"])

    assert result.exit_code == EXIT_OK
    assert "Dockerfile" in result.output


def test_violacao_de_politica_reprova(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text("FROM node:22\n", encoding="utf-8")
    (tmp_path / ".dockerls-policy.yaml").write_text(
        "require_pinned_bases: true\n", encoding="utf-8"
    )

    result = runner.invoke(app, ["fleet", str(tmp_path), "--no-color"])

    assert result.exit_code == EXIT_POLICY
    assert "require_pinned_bases" in result.output


def test_sem_politica_a_saida_diz_que_nada_foi_conferido(tmp_path: Path):
    """Silêncio não é conformidade."""
    (tmp_path / "Dockerfile").write_text("FROM node:22\n", encoding="utf-8")

    result = runner.invoke(app, ["fleet", str(tmp_path), "--no-color"])

    assert result.exit_code == EXIT_OK
    assert "conformidade" in result.output
    assert "Nenhuma política declarada" in result.output


def test_a_saida_diz_o_que_nao_foi_medido(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text("FROM alpine:3.21\n", encoding="utf-8")

    result = runner.invoke(app, ["fleet", str(tmp_path), "--no-color"])

    assert "não constrói imagem nem chama scanner" in " ".join(result.output.split())


def test_politica_invalida_falha_em_vez_de_varrer_sem_ela(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text("FROM alpine:3.21\n", encoding="utf-8")
    (tmp_path / ".dockerls-policy.yaml").write_text("require_non_root: true\n", encoding="utf-8")

    result = runner.invoke(app, ["fleet", str(tmp_path), "--no-color"])

    assert result.exit_code == EXIT_ERROR


def test_raiz_que_nao_e_diretorio_e_erro(tmp_path: Path):
    arquivo = tmp_path / "Dockerfile"
    arquivo.write_text("FROM alpine:3.21\n", encoding="utf-8")

    result = runner.invoke(app, ["fleet", str(arquivo), "--no-color"])

    assert result.exit_code == EXIT_ERROR


def test_formato_json_traz_totais_e_fila(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text("FROM node:22\n", encoding="utf-8")

    result = runner.invoke(app, ["fleet", str(tmp_path), "--format", "json", "--no-color"])

    payload = json.loads(result.output)
    assert payload["totals"]["dockerfiles"] == 1
    assert payload["dockerfiles"][0]["path"] == "Dockerfile"
    assert payload["caveat"]


def test_limite_corta_a_fila_e_diz_quantos_ficaram(tmp_path: Path):
    for i in range(4):
        (tmp_path / f"Dockerfile.{i}").write_text("FROM node:22\n", encoding="utf-8")

    result = runner.invoke(app, ["fleet", str(tmp_path), "--limit", "2", "--no-color"])

    assert "e mais 2" in result.output


def test_frota_vazia_nao_finge_sucesso(tmp_path: Path):
    result = runner.invoke(app, ["fleet", str(tmp_path), "--no-color"])

    assert result.exit_code == EXIT_OK
    assert "Nenhum Dockerfile" in result.output
