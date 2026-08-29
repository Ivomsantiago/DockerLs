"""Guard: a engine Go é opcional, e descobrir isso não pode custar caro.

O binário não é dependência do projeto -- `pip install dockerls` não o
instala, e o pipeline Python continua sendo o caminho completo. Estes
testes travam as duas metades disso: encontrar o binário quando ele existe,
e recusá-lo sem drama quando ele não serve.
"""

from __future__ import annotations

import os
import stat
from typing import TYPE_CHECKING

from dockerls.integrations.engine.locator import PROTOCOL_VERSION, find_engine, probe

if TYPE_CHECKING:
    from pathlib import Path


def _executable(path: Path, body: str) -> Path:
    path.write_text(f"#!/bin/sh\n{body}", encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


class TestFindEngine:
    def test_the_env_var_wins(self, tmp_path, monkeypatch):
        binary = _executable(tmp_path / "custom-engine", "exit 0\n")
        monkeypatch.setenv("DOCKERLS_ENGINE_PATH", str(binary))
        assert find_engine() == str(binary.resolve())

    def test_an_env_var_pointing_at_nothing_does_not_fall_through(self, tmp_path, monkeypatch):
        """Cair calado no PATH esconderia justamente o engano que a
        variável foi criada para evitar."""
        monkeypatch.setenv("DOCKERLS_ENGINE_PATH", str(tmp_path / "absent"))
        assert find_engine() == ""

    def test_a_non_executable_file_is_not_an_engine(self, tmp_path, monkeypatch):
        plain = tmp_path / "not-executable"
        plain.write_text("#!/bin/sh\n", encoding="utf-8")
        plain.chmod(0o600)
        monkeypatch.setenv("DOCKERLS_ENGINE_PATH", str(plain))
        assert find_engine() == ""

    def test_the_path_is_the_last_resort(self, tmp_path, monkeypatch):
        monkeypatch.delenv("DOCKERLS_ENGINE_PATH", raising=False)
        _executable(tmp_path / "dockerls-engine", "exit 0\n")
        monkeypatch.setenv("PATH", str(tmp_path))
        found = find_engine()
        # O build local do repositório tem precedência sobre o PATH, e numa
        # árvore onde ele existe é ele que responde -- as duas respostas
        # são corretas, e o que se afirma aqui é que alguma foi encontrada.
        assert found.endswith("dockerls-engine")

    def test_no_engine_anywhere_is_an_empty_string_and_not_an_exception(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.delenv("DOCKERLS_ENGINE_PATH", raising=False)
        monkeypatch.setenv("PATH", str(tmp_path))
        monkeypatch.setattr(
            "dockerls.integrations.engine.locator._repository_build",
            lambda: tmp_path / "nope",
        )
        assert find_engine() == ""


class TestProbe:
    def test_a_matching_protocol_is_accepted(self, tmp_path):
        binary = _executable(
            tmp_path / "engine", f"echo 'dockerls-engine protocol {PROTOCOL_VERSION}'\n"
        )
        assert probe(str(binary)) is True

    def test_a_different_protocol_is_refused(self, tmp_path):
        """É assim que um contrato entre linguagens apodrece em silêncio:
        um binário antigo lendo campos que mudaram de sentido."""
        binary = _executable(tmp_path / "engine", "echo 'dockerls-engine protocol 99'\n")
        assert probe(str(binary)) is False

    def test_a_binary_that_fails_is_refused(self, tmp_path):
        binary = _executable(tmp_path / "engine", "exit 3\n")
        assert probe(str(binary)) is False

    def test_a_binary_that_hangs_does_not_hang_the_cli(self, tmp_path):
        """`--version` responde na hora ou não responde. Um binário que
        trava aqui não vai medir imagem nenhuma."""
        binary = _executable(tmp_path / "engine", "sleep 30\n")
        monkey = os.environ.copy()
        assert probe(str(binary)) is False
        assert os.environ == monkey

    def test_an_empty_path_is_refused_without_touching_the_disk(self):
        assert probe("") is False

    def test_a_path_that_is_not_executable_is_refused(self, tmp_path):
        plain = tmp_path / "plain"
        plain.write_text("hello", encoding="utf-8")
        assert probe(str(plain)) is False
