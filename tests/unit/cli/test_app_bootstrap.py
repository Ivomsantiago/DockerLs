"""Testes para o callback de bootstrap em `dockerls/cli/app.py`.

Antes deste callback existir, comandos que nunca tocavam `Settings` (como
`build`) herdavam o sink padrão do loguru -- DEBUG direto para o stderr --
e vazavam log interno por cima da tabela Rich. `_bootstrap` roda antes de
qualquer subcomando e força `configure_logging()` a acontecer sempre.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from loguru import logger
from typer.testing import CliRunner

from dockerls.cli import app as app_module
from dockerls.cli.app import app
from dockerls.cli.dependencies import _settings

runner = CliRunner()


@pytest.fixture(autouse=True)
def _clear_settings_cache():
    _settings.cache_clear()
    yield
    _settings.cache_clear()


class TestBootstrapCallback:
    def test_configure_logging_runs_before_a_lightweight_command(self, monkeypatch):
        fake_configure = MagicMock()
        monkeypatch.setattr(app_module, "configure_logging", fake_configure)

        result = runner.invoke(app, ["version"])

        assert result.exit_code == 0
        fake_configure.assert_called_once()

    def test_configure_logging_runs_before_build_specifically(self, monkeypatch):
        """`build` is the command that motivated this fix: it never touched
        `Settings` on its own, so its body could previously run with
        loguru's default sink still attached."""
        fake_configure = MagicMock()
        monkeypatch.setattr(app_module, "configure_logging", fake_configure)

        runner.invoke(app, ["build", "--list-templates"])

        fake_configure.assert_called_once()

    def test_configure_logging_runs_even_when_the_subcommand_itself_fails(self, monkeypatch):
        """The callback fires before argument-level errors inside the
        command body, since it is the Typer app callback, not part of the
        command's own logic."""
        fake_configure = MagicMock()
        monkeypatch.setattr(app_module, "configure_logging", fake_configure)

        runner.invoke(app, ["build", "missing-tag-dir-that-does-not-exist"])

        fake_configure.assert_called_once()


class TestNoDebugLeakToTheTerminal:
    def test_build_leaves_no_default_debug_sink_attached(self, monkeypatch, tmp_path, capsys):
        """Regression for the `build` INFO leak: after the command runs,
        loguru must be left on the file-only sink (or WARNING-floored
        console sink), never on its pre-configuration DEBUG-to-stderr
        default.
        """
        monkeypatch.setenv("DOCKERLS_LOG_DIR", str(tmp_path))

        result = runner.invoke(app, ["build", "--list-templates"])
        assert result.exit_code == 0

        logger.info("regression: this must not leak to the terminal")
        logger.complete()
        captured = capsys.readouterr()
        assert "regression: this must not leak to the terminal" not in captured.err
        assert "regression: this must not leak to the terminal" not in captured.out


class TestBootstrapErrorHandling:
    """A `DOCKERLS_*` value invalid enough to break `Settings()` or the
    logging sink -- a non-integer `DOCKERLS_MAX_TAGS`, a `DOCKERLS_LOG_LEVEL`
    loguru does not recognise -- used to reach the user as a raw pydantic or
    loguru traceback, on every command, before a single line of application
    code ran."""

    def test_an_invalid_max_tags_value_is_reported_cleanly(self, monkeypatch):
        monkeypatch.setenv("DOCKERLS_MAX_TAGS", "not-a-number")

        result = runner.invoke(app, ["version"])

        assert result.exit_code == 1
        # A clean `typer.Exit` becomes `SystemExit(1)` here, not a raw
        # pydantic/loguru traceback -- that distinction is the fix.
        assert isinstance(result.exception, SystemExit)
        assert "Error" in result.output
        assert "DOCKERLS_MAX_TAGS" in result.output

    def test_an_invalid_log_level_is_reported_cleanly(self, monkeypatch):
        monkeypatch.setenv("DOCKERLS_LOG_LEVEL", "NOPE")

        result = runner.invoke(app, ["version"])

        assert result.exit_code == 1
        assert isinstance(result.exception, SystemExit)
        assert "Error" in result.output

    def test_valid_configuration_is_unaffected(self, monkeypatch, tmp_path):
        monkeypatch.setenv("DOCKERLS_LOG_DIR", str(tmp_path))

        result = runner.invoke(app, ["version"])

        assert result.exit_code == 0
