"""`dockerls policy` -- ler o regulamento sem precisar de um build para isso."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from typer.testing import CliRunner

from dockerls.cli.app import app
from dockerls.exit_codes import EXIT_ERROR, EXIT_OK

if TYPE_CHECKING:
    from pathlib import Path

runner = CliRunner()

_VALIDA = """
fail_on: high
require_pinned_bases: true
required_labels:
  - org.opencontainers.image.source
"""


def test_mostra_as_regras_declaradas(tmp_path: Path):
    (tmp_path / ".dockerls-policy.yaml").write_text(_VALIDA, encoding="utf-8")

    result = runner.invoke(app, ["policy", str(tmp_path), "--no-color"])

    assert result.exit_code == EXIT_OK
    assert "fail_on" in result.output
    assert "require_pinned_bases" in result.output


def test_arquivo_invalido_falha_aqui_em_vez_de_no_meio_do_build(tmp_path: Path):
    (tmp_path / ".dockerls-policy.yaml").write_text("require_non_root: true\n", encoding="utf-8")

    result = runner.invoke(app, ["policy", str(tmp_path), "--no-color"])

    assert result.exit_code == EXIT_ERROR
    assert "unknown rule" in result.output


def test_sem_arquivo_diz_que_nao_ha_politica(tmp_path: Path):
    result = runner.invoke(app, ["policy", str(tmp_path), "--no-color"])

    assert result.exit_code == EXIT_OK
    assert "No .dockerls-policy.yaml" in result.output


def test_formato_json_traz_a_politica(tmp_path: Path):
    (tmp_path / ".dockerls-policy.yaml").write_text(_VALIDA, encoding="utf-8")

    result = runner.invoke(app, ["policy", str(tmp_path), "--format", "json", "--no-color"])

    payload = json.loads(result.output)
    assert payload["policy"]["fail_on"] == "high"
    assert payload["policy"]["require_pinned_bases"] is True


def test_formato_json_sem_arquivo_e_json_puro(tmp_path: Path):
    result = runner.invoke(app, ["policy", str(tmp_path), "--format", "json", "--no-color"])
    assert json.loads(result.output) == {"policy": None}
