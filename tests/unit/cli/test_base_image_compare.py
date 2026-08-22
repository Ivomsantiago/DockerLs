"""`base-image --compare` -- responder "alpine ou debian para isto?".

O menu diz o custo de cada pacote uma linha por vez, o que não ajuda na
pergunta que de fato se faz. Comparar exigia gerar os dois Dockerfiles e ler
lado a lado, contando pacotes na mão.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from typer.testing import CliRunner

from dockerls.cli.app import app
from dockerls.exit_codes import EXIT_ERROR, EXIT_OK

if TYPE_CHECKING:
    from pathlib import Path

runner = CliRunner()


def test_troca_de_familia_mostra_a_mudanca_de_libc(tmp_path: Path):
    result = runner.invoke(
        app,
        [
            "base-image",
            "--os",
            "alpine",
            "--runtime",
            "node",
            "--with",
            "ca-certificates",
            "--compare",
            "debian",
            "--output",
            str(tmp_path / "Dockerfile"),
        ],
    )

    assert result.exit_code == EXIT_OK
    assert "musl" in result.output
    assert "glibc" in result.output


def test_comparar_nao_escreve_arquivo_nenhum(tmp_path: Path):
    """Responder uma pergunta sobrescrevendo um Dockerfile seria um efeito
    colateral que ninguém pediu."""
    destination = tmp_path / "Dockerfile"

    result = runner.invoke(
        app,
        [
            "base-image",
            "--os",
            "alpine",
            "--runtime",
            "none",
            "--with",
            "ca-certificates",
            "--compare",
            "debian",
            "--output",
            str(destination),
        ],
    )

    assert result.exit_code == EXIT_OK
    assert not destination.exists()


def test_pacotes_do_lado_comparado_podem_ser_outros(tmp_path: Path):
    result = runner.invoke(
        app,
        [
            "base-image",
            "--os",
            "alpine",
            "--runtime",
            "none",
            "--with",
            "ca-certificates",
            "--compare",
            "debian",
            "--compare-with",
            "ca-certificates,curl",
            "--output",
            str(tmp_path / "Dockerfile"),
        ],
    )

    assert result.exit_code == EXIT_OK
    assert "+ curl" in result.output


def test_comparar_com_distroless_lista_os_pacotes_que_se_perdem(tmp_path: Path):
    result = runner.invoke(
        app,
        [
            "base-image",
            "--os",
            "alpine",
            "--runtime",
            "node",
            "--with",
            "ca-certificates,tzdata",
            "--compare",
            "distroless",
            "--output",
            str(tmp_path / "Dockerfile"),
        ],
    )

    assert result.exit_code == EXIT_OK
    assert "- ca-certificates" in result.output
    assert "- tzdata" in result.output
    assert "nem shell" in result.output


def test_o_diff_nao_elege_vencedora(tmp_path: Path):
    result = runner.invoke(
        app,
        [
            "base-image",
            "--os",
            "alpine",
            "--runtime",
            "none",
            "--with",
            "ca-certificates",
            "--compare",
            "debian",
            "--output",
            str(tmp_path / "Dockerfile"),
        ],
    )

    assert "escanear" in result.output


def test_familia_desconhecida_e_erro(tmp_path: Path):
    result = runner.invoke(
        app,
        [
            "base-image",
            "--os",
            "alpine",
            "--runtime",
            "none",
            "--with",
            "ca-certificates",
            "--compare",
            "gentoo",
            "--output",
            str(tmp_path / "Dockerfile"),
        ],
    )

    assert result.exit_code == EXIT_ERROR
