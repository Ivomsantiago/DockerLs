from unittest.mock import MagicMock

import pytest

from dockerls.cli import dependencies, runtime

# `configure_logging` e companhia moram em `cli/runtime.py` (o módulo leve
# que o bootstrap importa) e são reexportados por `cli/dependencies.py`. O
# patch de `setup_logging` tem que ir onde a chamada acontece; o resto
# continua sendo lido de `dependencies`, que é de onde a CLI os importa.
from dockerls.cli.dependencies import _settings, configure_logging, enable_console_logging


@pytest.fixture(autouse=True)
def _clear_settings_cache():
    """`_settings` is a process-wide `lru_cache` singleton; without clearing
    it, whichever test runs first decides what every other test in this
    module observes."""
    _settings.cache_clear()
    yield
    _settings.cache_clear()


class TestSettingsSingleton:
    def test_settings_is_cached(self):
        first = _settings()
        second = _settings()
        assert first is second


class TestConfigureLogging:
    """`build` never touched `Settings` before this existed, so it inherited
    loguru's default DEBUG-to-stderr sink. `configure_logging` is the fix:
    it forces `_settings()` -- and therefore `setup_logging` -- to run
    before any command's body executes.
    """

    def test_forces_setup_logging_to_run(self, monkeypatch):
        fake_setup = MagicMock(return_value=None)
        monkeypatch.setattr(runtime, "setup_logging", fake_setup)

        configure_logging()

        fake_setup.assert_called_once()

    def test_is_idempotent_across_repeated_calls(self, monkeypatch):
        """`_settings()` is cached, so calling this twice (as would happen
        across two commands in the same process) must not reconfigure
        logging a second time."""
        fake_setup = MagicMock(return_value=None)
        monkeypatch.setattr(runtime, "setup_logging", fake_setup)

        configure_logging()
        configure_logging()

        fake_setup.assert_called_once()


class TestEnableConsoleLogging:
    def test_passes_console_true_and_the_configured_level_as_console_level(self, monkeypatch):
        fake_setup = MagicMock(return_value=None)
        monkeypatch.setattr(runtime, "setup_logging", fake_setup)
        monkeypatch.setenv("DOCKERLS_LOG_LEVEL", "DEBUG")

        enable_console_logging()

        _, kwargs = fake_setup.call_args
        assert kwargs["console"] is True
        assert kwargs["console_level"] == "DEBUG"

    def test_updates_the_shared_log_file_reference(self, monkeypatch, tmp_path):
        fake_log_file = tmp_path / "dockerls_test.log"
        monkeypatch.setattr(runtime, "setup_logging", MagicMock(return_value=fake_log_file))

        enable_console_logging()

        assert dependencies.current_log_file() == fake_log_file
