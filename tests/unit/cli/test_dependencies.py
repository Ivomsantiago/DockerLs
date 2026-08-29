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


class TestBuildCacheLifecycle:
    """`build_cache()` opens a real SQLAlchemy engine against `cache.db`.
    Every command that touches it -- `recommend`, `cache`, `registry-audit`,
    plus `_threat_intel`/`_exploitdb` internally -- used to get its own
    engine, and none of them was ever disposed: `pytest`, which keeps the
    interpreter alive across thousands of these, reported the leak as
    `ResourceWarning: unclosed database` from tests that never mention
    caching. `build_cache()` is now a process-wide singleton (one engine per
    process, like `_settings`) and `close_cache()` -- called from
    `cli.app.main()`'s `finally` -- is what actually releases it.
    """

    @pytest.fixture(autouse=True)
    def _clear_cache_singleton(self, tmp_path, monkeypatch):
        monkeypatch.setenv("DOCKERLS_CACHE_DIR", str(tmp_path))
        dependencies.build_cache.cache_clear()
        yield
        dependencies.close_cache()
        dependencies.build_cache.cache_clear()

    def test_build_cache_is_a_singleton(self):
        first = dependencies.build_cache()
        second = dependencies.build_cache()
        assert first is second

    def test_close_cache_disposes_the_engine_and_clears_the_memo(self):
        cache = dependencies.build_cache()

        dependencies.close_cache()

        assert dependencies.build_cache.cache_info().currsize == 0
        # A disposed pool has recycled/closed whatever connection it held.
        assert cache._engine.pool.checkedin() == 0  # noqa: SLF001

    def test_close_cache_on_an_untouched_process_is_a_no_op(self):
        # Nothing built a cache yet in this test -- closing must not raise
        # or conjure one into existence just to close it.
        dependencies.close_cache()
        assert dependencies.build_cache.cache_info().currsize == 0

    def test_dispose_cache_if_loaded_closes_it_when_the_module_was_imported(self):
        """This is what `cli.app.main()` actually calls in its `finally`.
        Simulates the real shape: a command ran, built a cache along the
        way, and the process is about to exit."""
        from dockerls.cli import app as app_module

        dependencies.build_cache()

        app_module._dispose_cache_if_loaded()

        assert dependencies.build_cache.cache_info().currsize == 0

    def test_dispose_cache_if_loaded_skips_the_import_when_nothing_used_it(self, monkeypatch):
        """`dockerls --help` / `version` never import `cli.dependencies` --
        that is the whole point of the lazy command table in `cli/app.py`
        -- so closing at the end must not import it just to find nothing to
        close, or it would silently reintroduce the ~1s startup cost those
        commands were written to avoid."""
        import sys

        from dockerls.cli import app as app_module

        monkeypatch.delitem(sys.modules, "dockerls.cli.dependencies", raising=False)

        app_module._dispose_cache_if_loaded()  # must not raise or import anything

        assert "dockerls.cli.dependencies" not in sys.modules
