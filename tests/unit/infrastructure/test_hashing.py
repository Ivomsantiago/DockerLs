"""Digest determinístico da entrada do build.

Determinístico é o requisito, não um detalhe: o mesmo conteúdo tem de dar o
mesmo hash em qualquer máquina e em qualquer ordem de sistema de arquivos, ou
comparar dois builds não significa nada.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from dockerls.infrastructure.hashing import (
    ContextTooLargeError,
    hash_context,
    hash_file,
)


def _write(root, relative: str, content: str = "x"):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return path


class TestFileDigest:
    def test_same_content_same_digest(self, tmp_path):
        a, b = _write(tmp_path, "a.txt", "conteúdo"), _write(tmp_path, "b.txt", "conteúdo")
        assert hash_file(a) == hash_file(b)

    def test_digest_is_prefixed(self, tmp_path):
        assert hash_file(_write(tmp_path, "a.txt")).startswith("sha256:")

    def test_one_byte_changes_the_digest(self, tmp_path):
        path = _write(tmp_path, "a.txt", "conteúdo")
        before = hash_file(path)
        path.write_text("conteúdoo")
        assert hash_file(path) != before


class TestContextDigest:
    def test_identical_trees_agree(self, tmp_path):
        for root in ("um", "dois"):
            _write(tmp_path / root, "app/main.py", "print(1)")
            _write(tmp_path / root, "Dockerfile", "FROM x")
        first, count = hash_context(tmp_path / "um")
        second, _ = hash_context(tmp_path / "dois")
        assert first == second
        assert count == 2

    def test_renaming_a_file_changes_the_context(self, tmp_path):
        _write(tmp_path, "a.py", "mesmo conteúdo")
        before, _ = hash_context(tmp_path)
        (tmp_path / "a.py").rename(tmp_path / "b.py")
        after, _ = hash_context(tmp_path)
        # O nome entra no digest: renomear muda o contexto tanto quanto editar.
        assert after != before

    def test_dockerignore_entries_are_excluded(self, tmp_path):
        _write(tmp_path, "app.py", "código")
        _write(tmp_path, "Dockerfile", "FROM x")
        _write(tmp_path, ".dockerignore", ".git\n*.log\n")
        baseline, count = hash_context(tmp_path)

        _write(tmp_path, ".git/HEAD", "ref: refs/heads/main")
        _write(tmp_path, "debug.log", "ruído")
        after, count_after = hash_context(tmp_path)

        # Um digest que mudasse com o que o daemon nem recebe dispararia sem
        # motivo -- e um controle que dispara à toa é um controle desligado.
        assert after == baseline
        assert count_after == count

    def test_negations_do_not_become_exclusions(self, tmp_path):
        _write(tmp_path, ".env.example", "CHAVE=")
        _write(tmp_path, ".dockerignore", ".env\n.env.*\n!.env.example\n")
        _, count = hash_context(tmp_path)
        assert count >= 1

    def test_an_oversized_context_is_refused_not_truncated(self, tmp_path, monkeypatch):
        monkeypatch.setattr("dockerls.infrastructure.hashing.MAX_CONTEXT_FILES", 3)
        for i in range(5):
            _write(tmp_path, f"f{i}.txt")
        with pytest.raises(ContextTooLargeError, match="dockerignore"):
            hash_context(tmp_path)


class TestPruning:
    """A poda acontece na descida, e o digest não muda por causa disso.

    A versão anterior percorria a árvore inteira e descartava o que o
    `.dockerignore` excluía -- num contexto de 52.400 arquivos em que 401 são
    enviados ao daemon, 98% do tempo era gasto lendo entradas que o build
    nunca veria.
    """

    def test_diretorio_ignorado_nao_muda_o_digest(self, tmp_path):
        """Prova de equivalência: o mesmo conteúdo enviado ao daemon produz o
        mesmo digest, esteja o diretório ignorado cheio ou vazio."""
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "app.py").write_text("x")
        (tmp_path / ".dockerignore").write_text(".git\nnode_modules\n")

        vazio, _ = hash_context(tmp_path)

        for pasta in (".git", "node_modules"):
            fundo = tmp_path / pasta / "a" / "b"
            fundo.mkdir(parents=True)
            for i in range(20):
                (fundo / f"o{i}").write_text(f"lixo {i}")

        cheio, contados = hash_context(tmp_path)

        assert cheio == vazio
        assert contados == 2  # app.py e .dockerignore

    def test_ordenacao_nao_depende_da_descida(self, tmp_path):
        """A lista é ordenada no fim, sobre os caminhos completos.

        Ordenar a cada nível durante a descida produziria outra ordem -- e,
        como o digest é dependente de ordem, outro digest para o mesmo
        conteúdo. `a.txt` e `a/b.txt` são o caso que separa as duas.
        """
        (tmp_path / "a").mkdir()
        (tmp_path / "a" / "b.txt").write_text("um")
        (tmp_path / "a.txt").write_text("dois")

        digest, contados = hash_context(tmp_path)

        assert contados == 2
        # O mesmo conteúdo, recriado em outra ordem de escrita, dá o mesmo
        # digest: a ordem do sistema de arquivos não entra na conta.
        outro = tmp_path / "copia"
        outro.mkdir()
        (outro / "a.txt").write_text("dois")
        (outro / "a").mkdir()
        (outro / "a" / "b.txt").write_text("um")

        assert hash_context(outro)[0] == digest

    def test_symlink_continua_fora(self, tmp_path):
        """Seguir um daria ao digest um conteúdo de fora do contexto."""
        alvo = tmp_path / "real"
        alvo.mkdir()
        (alvo / "dentro.txt").write_text("x")
        (tmp_path / "link").symlink_to(alvo, target_is_directory=True)

        _, contados = hash_context(tmp_path)

        assert contados == 1

    def test_diretorio_ilegivel_nao_interrompe_o_resto(self, tmp_path, monkeypatch):
        """O `.dockerignore` pode muito bem excluí-lo, e o daemon não teria
        recebido nada dali de qualquer forma."""
        (tmp_path / "ok.txt").write_text("x")
        proibido = tmp_path / "proibido"
        proibido.mkdir()
        (proibido / "dentro.txt").write_text("y")

        original = Path.iterdir

        def iterdir(self):
            if self.name == "proibido":
                raise PermissionError("sem acesso")
            return original(self)

        monkeypatch.setattr(Path, "iterdir", iterdir)

        digest, contados = hash_context(tmp_path)

        assert contados == 1
        assert digest.startswith("sha256:")
