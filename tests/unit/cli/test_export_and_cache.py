"""Failure paths for the two least-covered commands.

`cache` had no tests at all, and `export` repeated the shadowed-settings
bug that was fixed only in `recommend`: its `--workers` carried a
hard-coded default of 10 and it never passed a tag limit, so
`DOCKERLS_WORKERS` and `DOCKERLS_MAX_TAGS` had no effect there. It also
wrote to disk with no error handling, so an unwritable path produced a
traceback instead of a message.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy.exc import OperationalError
from typer.testing import CliRunner

from dockerls.application.dto.analysis import AnalysisResult
from dockerls.cache.sqlite_cache import SQLiteCache
from dockerls.cli import dependencies
from dockerls.cli.app import app

runner = CliRunner()


@pytest.fixture(autouse=True)
def _clear_settings_cache():
    dependencies._settings.cache_clear()
    yield
    dependencies._settings.cache_clear()


def _fake_use_case(captured=None, executed=None):
    async def build(**kwargs):
        if captured is not None:
            captured.update(kwargs)
        uc = AsyncMock()

        async def execute(image, limit=None):
            if executed is not None:
                executed["limit"] = limit
            return AnalysisResult(
                query=image, total_tags_scanned=1, total_tags_analyzed=1, baseline_met=False
            )

        uc.execute = execute
        return uc

    return build


class TestExportHonoursConfiguration:
    def test_omitting_workers_delegates_to_configuration(self, monkeypatch):
        """The fix: the CLI must pass None rather than a hard-coded 10,
        which is what shadowed `Settings.workers`. Resolution of None into
        the configured value is proven in test_settings_are_wired.py."""
        captured: dict = {}
        with patch(
            "dockerls.cli.commands.export.build_recommend_use_case", _fake_use_case(captured)
        ):
            runner.invoke(app, ["export", "node", "--format", "json"])
        assert captured["workers"] is None

    def test_tag_limit_falls_back_to_the_configured_value(self, monkeypatch):
        monkeypatch.setenv("DOCKERLS_MAX_TAGS", "9")
        executed: dict = {}
        with patch(
            "dockerls.cli.commands.export.build_recommend_use_case",
            _fake_use_case(executed=executed),
        ):
            runner.invoke(app, ["export", "node", "--format", "json"])
        assert executed["limit"] == 9

    def test_explicit_flag_still_wins(self, monkeypatch):
        monkeypatch.setenv("DOCKERLS_WORKERS", "17")
        captured: dict = {}
        with patch(
            "dockerls.cli.commands.export.build_recommend_use_case", _fake_use_case(captured)
        ):
            runner.invoke(app, ["export", "node", "--workers", "2"])
        assert captured["workers"] == 2

    def test_invalid_configuration_is_a_message_not_a_traceback(self, monkeypatch):
        monkeypatch.setenv("DOCKERLS_MAX_TAGS", "-1")
        with patch("dockerls.cli.commands.export.build_recommend_use_case", _fake_use_case()):
            result = runner.invoke(app, ["export", "node"])

        assert result.exit_code == 1
        assert "Invalid configuration" in result.stdout
        assert "Traceback" not in result.stdout


class TestExportFileWriting:
    def test_writes_the_report_and_creates_missing_directories(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        target = tmp_path / "nested" / "dir" / "report.json"
        with patch("dockerls.cli.commands.export.build_recommend_use_case", _fake_use_case()):
            result = runner.invoke(app, ["export", "node", "-f", "json", "-o", str(target)])

        assert result.exit_code == 0
        assert target.is_file()
        assert "exported to" in result.stdout

    def test_unwritable_path_reports_an_error_not_a_traceback(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        blocker = tmp_path / "blocked"
        blocker.write_text("i am a file, not a directory")
        target = blocker / "report.json"

        with patch("dockerls.cli.commands.export.build_recommend_use_case", _fake_use_case()):
            result = runner.invoke(app, ["export", "node", "-f", "json", "-o", str(target)])

        assert result.exit_code == 1
        assert "Could not write" in result.stdout
        assert "Traceback" not in result.stdout

    def test_unknown_format_exits_one(self, monkeypatch):
        with patch("dockerls.cli.commands.export.build_recommend_use_case", _fake_use_case()):
            result = runner.invoke(app, ["export", "node", "--format", "bogus"])
        assert result.exit_code == 1

    def test_rejects_an_image_tag_with_a_clear_message(self):
        """`node:18` used to be searched as a literal repository name."""
        captured: dict = {}
        with patch(
            "dockerls.cli.commands.export.build_recommend_use_case", _fake_use_case(captured)
        ):
            result = runner.invoke(app, ["export", "node:18"])
        collapsed = " ".join(result.stdout.split())
        assert result.exit_code == 1
        assert "dockerls export node" in collapsed
        assert "dockerls analyze node:18" in collapsed
        assert captured == {}

    def test_private_registry_with_port_still_works(self):
        captured: dict = {}
        with patch(
            "dockerls.cli.commands.export.build_recommend_use_case", _fake_use_case(captured)
        ):
            result = runner.invoke(
                app, ["export", "registry.internal:5000/app", "--format", "json"]
            )
        assert result.exit_code == 0
        assert captured != {}


class TestCacheCommands:
    """These had no tests at all."""

    def test_clear_reports_success(self, tmp_path, monkeypatch):
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
        result = runner.invoke(app, ["cache", "clear"])

        assert result.exit_code == 0
        assert "Cache cleared" in result.stdout

    def test_cleanup_reports_the_number_removed(self, tmp_path, monkeypatch):
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
        result = runner.invoke(app, ["cache", "cleanup"])

        assert result.exit_code == 0
        assert "expired entries" in result.stdout

    def test_broken_cache_database_is_a_message_not_a_traceback(self, tmp_path, monkeypatch):
        """`clear` is exactly what a user reaches for when the cache is
        broken; it must not be the thing that crashes."""
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
        broken = OperationalError("SELECT 1", {}, Exception("database disk image is malformed"))

        with patch.object(SQLiteCache, "clear", AsyncMock(side_effect=broken)):
            result = runner.invoke(app, ["cache", "clear"])

        assert result.exit_code == 1
        assert "Cache operation failed" in result.stdout
        assert "Traceback" not in result.stdout

    def test_cleanup_survives_a_storage_error(self, tmp_path, monkeypatch):
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
        with patch.object(
            SQLiteCache, "cleanup_expired", AsyncMock(side_effect=OSError("disk full"))
        ):
            result = runner.invoke(app, ["cache", "cleanup"])

        assert result.exit_code == 1
        assert "Cache operation failed" in result.stdout


class TestLogout:
    """`login` could store credentials with no supported way to remove
    them, which left `clear_credentials` implemented and unreachable."""

    def test_logout_removes_stored_credentials(self):
        with patch("dockerls.cli.commands.login.clear_credentials", return_value=True) as clear:
            result = runner.invoke(app, ["logout"])

        clear.assert_called_once()
        assert result.exit_code == 0
        assert "removed" in result.stdout

    def test_logout_without_stored_credentials_exits_one(self):
        with patch("dockerls.cli.commands.login.clear_credentials", return_value=False):
            result = runner.invoke(app, ["logout"])

        assert result.exit_code == 1
        assert "No stored credentials" in result.stdout
