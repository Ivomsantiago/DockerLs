"""Guard: a tabela de comandos tardios não se descola do código.

`cli/app.py` deixou de importar os 24 subcomandos no topo -- era isso que
fazia `dockerls version` pagar os ~390ms de arranque de `dockerls advisor`.
O registro passou a vir de uma tabela estática (nome, módulo, resumo), e o
resumo é o único trecho duplicado: o `--help` do grupo precisa dele para
listar os comandos sem importar nenhum.

Duplicação sem guard apodrece. Estes testes comparam a tabela com o que os
módulos de fato definem: um comando renomeado, movido, removido ou com a
docstring alterada quebra aqui, e não na mão de quem usa a CLI.
"""

from __future__ import annotations

import inspect
import pathlib
from importlib import import_module

import pytest
from typer.testing import CliRunner

from dockerls.cli.app import COMMANDS, app

runner = CliRunner()

COMMANDS_DIR = pathlib.Path(__file__).resolve().parents[3] / "dockerls" / "cli" / "commands"


def _first_paragraph(text: str) -> str:
    """O que o Typer mostra na listagem: o primeiro parágrafo, sem quebras."""
    return " ".join(inspect.cleandoc(text).split("\n\n")[0].split())


@pytest.mark.parametrize("spec", COMMANDS, ids=lambda s: s.name)
class TestTheTableMatchesTheCode:
    def test_the_target_exists(self, spec):
        module = import_module(f"dockerls.cli.commands.{spec.module}")
        assert hasattr(module, spec.attr), (
            f"'{spec.name}' aponta para {spec.module}.{spec.attr}, que não existe"
        )

    def test_the_summary_is_the_docstring(self, spec):
        """O resumo da tabela é o que o Typer mostraria se importasse tudo."""
        target = getattr(import_module(f"dockerls.cli.commands.{spec.module}"), spec.attr)
        if spec.is_group:
            # Um subgrupo carrega o help no próprio `typer.Typer`, e o
            # `add_typer` original já o sobrescrevia.
            assert spec.summary
            return
        assert target.__doc__, f"'{spec.name}' não tem docstring"
        assert spec.summary == _first_paragraph(target.__doc__)

    def test_its_own_help_still_renders(self, spec):
        """`dockerls <cmd> --help` resolve o comando de verdade: é o caminho
        que prova que o stub não fica no lugar dele na hora de executar."""
        result = runner.invoke(app, [spec.name, "--help"])
        assert result.exit_code == 0, result.output


class TestTheTableCoversEveryCommand:
    def test_every_command_module_is_listed(self):
        """Um módulo novo em `cli/commands/` que ninguém pôs na tabela seria
        um comando que simplesmente não existe na CLI -- e, sem isto,
        nenhum teste notaria."""
        on_disk = {
            path.stem
            for path in COMMANDS_DIR.glob("*.py")
            if path.name != "__init__.py" and not path.name.startswith("_")
        }
        listed = {spec.module for spec in COMMANDS}
        assert on_disk - listed == set()

    def test_the_group_help_lists_them_all(self):
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        for spec in COMMANDS:
            assert spec.name in result.output

    def test_the_names_are_unique(self):
        names = [spec.name for spec in COMMANDS]
        assert len(names) == len(set(names))


class TestHelpIsGroupedAndHasAQuickStart:
    """22 commands in one flat list made `--help` a wall of text a newcomer
    had to read end to end to find where to start. Every command's
    category must be a real panel Typer renders, and the quick-start
    examples must survive."""

    def test_every_command_declares_a_known_category(self):
        from dockerls.cli.app import _BUILD, _FIND, _SETUP, _SUPPLY_CHAIN

        known = {_FIND, _BUILD, _SUPPLY_CHAIN, _SETUP}
        for spec in COMMANDS:
            assert spec.category in known, f"'{spec.name}' has no recognised category"

    def test_the_help_output_shows_every_panel_and_a_quick_start(self):
        result = runner.invoke(app, ["--help"])

        assert result.exit_code == 0
        assert "Quick start" in result.output
        assert "dockerls recommend" in result.output
        for spec in COMMANDS:
            assert spec.category in result.output


class TestListingDoesNotImportCommands:
    def test_the_group_help_leaves_the_heavy_modules_alone(self, tmp_path):
        """O ponto inteiro da tabela: listar os comandos não pode importar
        nenhum deles. Rodado num subprocesso porque, dentro da suíte, os
        módulos já estão todos em `sys.modules`."""
        import subprocess
        import sys

        script = (
            "import sys\n"
            "from typer.testing import CliRunner\n"
            "from dockerls.cli.app import app\n"
            "assert CliRunner().invoke(app, ['--help']).exit_code == 0\n"
            "leaked = [m for m in sys.modules if m.startswith('dockerls.cli.commands.')]\n"
            "print('\\n'.join(leaked))\n"
        )
        out = subprocess.run(  # noqa: S603 -- o script é literal, logo acima
            [sys.executable, "-c", script], capture_output=True, text=True, check=True
        )
        assert out.stdout.strip() == "", f"--help importou comandos: {out.stdout}"
