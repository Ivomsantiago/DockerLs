"""`dockerls provenance` -- o portão que confere o documento antes da assinatura.

O que estes testes fixam é a recusa: um documento cujo `status` gravado diz
`VERIFIED` mas cujos digests não batem tem de reprovar, porque o campo é
editável e a comparação não é. Um comando que acreditasse no arquivo
transformaria o controle em decoração.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from typer.testing import CliRunner

from dockerls.cli.app import app
from dockerls.exit_codes import EXIT_ERROR, EXIT_OK, EXIT_POLICY

if TYPE_CHECKING:
    from pathlib import Path

runner = CliRunner()

_VERIFICADO = {
    "tag": "app:1.0",
    "status": "VERIFIED",
    "source": {
        "dockerfile_sha256": "sha256:aaa",
        "context_sha256": "sha256:bbb",
        "context_files": 12,
        "base_images": {"python:3.12-alpine": "sha256:ccc"},
        "git_revision": "abc123",
        "git_dirty": False,
    },
    "source_after_build": {"dockerfile_sha256": "sha256:aaa", "context_sha256": "sha256:bbb"},
    "artifact": {
        "image_id": "sha256:ddd",
        "repo_digest": "sha256:eee",
        "published_reference": "reg.io/app:1.0",
        "scanner": "trivy 0.58",
    },
}


def _write(tmp_path: Path, payload: object) -> str:
    destination = tmp_path / "provenance.json"
    destination.write_text(json.dumps(payload), encoding="utf-8")
    return str(destination)


def test_documento_integro_passa(tmp_path: Path):
    result = runner.invoke(app, ["provenance", _write(tmp_path, _VERIFICADO), "--no-color"])

    assert result.exit_code == EXIT_OK
    assert "VERIFIED" in result.output
    assert "sha256:eee" in result.output


def test_status_gravado_nao_e_acreditado(tmp_path: Path):
    """O campo é editável por qualquer um; a comparação entre os digests não."""
    adulterado = json.loads(json.dumps(_VERIFICADO))
    adulterado["source_after_build"]["dockerfile_sha256"] = "sha256:outro"

    result = runner.invoke(app, ["provenance", _write(tmp_path, adulterado), "--no-color"])

    assert result.exit_code == EXIT_POLICY
    assert "INPUT_CHANGED" in result.output


def test_contexto_alterado_durante_o_build_reprova(tmp_path: Path):
    adulterado = json.loads(json.dumps(_VERIFICADO))
    adulterado["source_after_build"]["context_sha256"] = "sha256:outro"

    result = runner.invoke(app, ["provenance", _write(tmp_path, adulterado), "--no-color"])

    assert result.exit_code == EXIT_POLICY
    assert "contexto de build" in result.output


def test_documento_sem_digest_do_artefato_nao_e_atestavel(tmp_path: Path):
    """Uma assinatura aponta para bytes, e "a imagem com esta tag" não são bytes."""
    sem_saida = json.loads(json.dumps(_VERIFICADO))
    sem_saida["artifact"] = {}

    result = runner.invoke(app, ["provenance", _write(tmp_path, sem_saida), "--no-color"])

    assert result.exit_code == EXIT_POLICY


def test_arquivo_inexistente_e_erro_e_nao_aprovacao(tmp_path: Path):
    result = runner.invoke(app, ["provenance", str(tmp_path / "ausente.json"), "--no-color"])
    assert result.exit_code == EXIT_ERROR


def test_json_invalido_e_erro(tmp_path: Path):
    destination = tmp_path / "provenance.json"
    destination.write_text("{ isto não é json", encoding="utf-8")

    result = runner.invoke(app, ["provenance", str(destination), "--no-color"])

    assert result.exit_code == EXIT_ERROR


def test_formato_json_traz_o_sujeito_da_atestacao(tmp_path: Path):
    result = runner.invoke(
        app, ["provenance", _write(tmp_path, _VERIFICADO), "--format", "json", "--no-color"]
    )

    payload = json.loads(result.output)
    assert payload["subject_name"] == "reg.io/app:1.0"
    assert payload["subject_digest"] == "sha256:eee"
    assert payload["attestable"] is True


def test_github_output_recebe_o_sujeito(tmp_path: Path, monkeypatch):
    saida = tmp_path / "github_output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(saida))

    result = runner.invoke(
        app, ["provenance", _write(tmp_path, _VERIFICADO), "--github-output", "--no-color"]
    )

    assert result.exit_code == EXIT_OK
    escrito = saida.read_text(encoding="utf-8")
    assert "subject-name=reg.io/app:1.0" in escrito
    assert "subject-digest=sha256:eee" in escrito
    assert "provenance-status=VERIFIED" in escrito


def test_github_output_fora_do_actions_avisa_em_vez_de_escrever_em_qualquer_lugar(
    tmp_path: Path, monkeypatch
):
    monkeypatch.delenv("GITHUB_OUTPUT", raising=False)

    result = runner.invoke(
        app, ["provenance", _write(tmp_path, _VERIFICADO), "--github-output", "--no-color"]
    )

    assert result.exit_code == EXIT_OK
    assert "GITHUB_OUTPUT" in result.output


def test_id_local_serve_de_sujeito_quando_nao_houve_push(tmp_path: Path):
    local = json.loads(json.dumps(_VERIFICADO))
    local["artifact"] = {"image_id": "sha256:ddd"}

    result = runner.invoke(
        app, ["provenance", _write(tmp_path, local), "--format", "json", "--no-color"]
    )

    payload = json.loads(result.output)
    assert payload["subject_digest"] == "sha256:ddd"
