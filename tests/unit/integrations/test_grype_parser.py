from unittest.mock import AsyncMock, patch

import pytest

from dockerls.domain.entities.scan_result import ScanStatus
from dockerls.integrations.grype.scanner import GrypeScanner
from tests.unit.integrations.conftest import stub_path


class TestGrypeParser:
    def test_parse_results(self):
        scanner = GrypeScanner()
        data = {
            "matches": [
                {
                    "vulnerability": {
                        "id": "CVE-2024-1111",
                        "severity": "High",
                        "fix": {"versions": ["2.0.0"]},
                        "cvss": [{"metrics": {"baseScore": 8.1}}],
                    },
                    "artifact": {
                        "name": "libxml2",
                        "version": "1.9.0",
                    },
                },
                {
                    "vulnerability": {
                        "id": "CVE-2024-2222",
                        "severity": "Negligible",
                        "fix": {"versions": []},
                        "cvss": [],
                    },
                    "artifact": {"name": "zlib", "version": "1.2.11"},
                },
            ]
        }
        result = scanner._parse_results("python:3.12", data)
        assert result.high_count == 1
        assert result.low_count == 1
        assert result.fixable_count == 1
        assert result.vulnerabilities[0].cvss_score == 8.1

    def test_parse_empty(self):
        scanner = GrypeScanner()
        result = scanner._parse_results("nginx:latest", {"matches": []})
        assert result.total_count == 0


class TestGrypeParserIsNullSafe:
    """Grype emits explicit nulls for several fields on a normal, completed
    scan (no description, no fix, no locations). Each used to sail past a
    bare `.get(key, default)` and break the parse, turning a completed scan
    into an ERROR result instead of a finding with an empty field."""

    def test_null_description_does_not_raise(self):
        scanner = GrypeScanner()
        data = {
            "matches": [
                {
                    "vulnerability": {"id": "CVE-1", "severity": "High", "description": None},
                    "artifact": {"name": "libz", "version": "1.0"},
                }
            ]
        }
        result = scanner._parse_results("node:22", data)
        assert result.vulnerabilities[0].description == ""

    def test_null_severity_does_not_raise(self):
        scanner = GrypeScanner()
        data = {
            "matches": [
                {
                    "vulnerability": {"id": "CVE-1", "severity": None},
                    "artifact": {"name": "libz", "version": "1.0"},
                }
            ]
        }
        result = scanner._parse_results("node:22", data)
        assert result.vulnerabilities[0].severity.value == "UNKNOWN"

    def test_null_fix_block_does_not_raise(self):
        scanner = GrypeScanner()
        data = {
            "matches": [
                {
                    "vulnerability": {"id": "CVE-1", "severity": "High", "fix": None},
                    "artifact": {"name": "libz", "version": "1.0"},
                }
            ]
        }
        result = scanner._parse_results("node:22", data)
        assert result.vulnerabilities[0].fixed_version == ""

    def test_null_artifact_does_not_raise(self):
        scanner = GrypeScanner()
        data = {
            "matches": [{"vulnerability": {"id": "CVE-1", "severity": "High"}, "artifact": None}]
        }
        result = scanner._parse_results("node:22", data)
        assert result.vulnerabilities[0].package_name == ""

    def test_a_non_dict_location_entry_does_not_raise(self):
        scanner = GrypeScanner()
        data = {
            "matches": [
                {
                    "vulnerability": {"id": "CVE-1", "severity": "High"},
                    "artifact": {"name": "libz", "version": "1.0", "locations": [None]},
                }
            ]
        }
        result = scanner._parse_results("node:22", data)
        assert result.vulnerabilities[0].target == ""

    def test_null_locations_does_not_raise(self):
        scanner = GrypeScanner()
        data = {
            "matches": [
                {
                    "vulnerability": {"id": "CVE-1", "severity": "High"},
                    "artifact": {"name": "libz", "version": "1.0", "locations": None},
                }
            ]
        }
        result = scanner._parse_results("node:22", data)
        assert result.vulnerabilities[0].target == ""

    def test_null_matches_list_does_not_raise(self):
        scanner = GrypeScanner()
        result = scanner._parse_results("node:22", {"matches": None})
        assert result.total_count == 0

    def test_missing_matches_key_does_not_raise(self):
        scanner = GrypeScanner()
        result = scanner._parse_results("node:22", {})
        assert result.total_count == 0

    def test_a_match_entry_that_is_not_a_dict_is_skipped(self):
        scanner = GrypeScanner()
        data = {
            "matches": [
                "not-a-dict",
                {
                    "vulnerability": {"id": "CVE-1", "severity": "High"},
                    "artifact": {"name": "libz", "version": "1.0"},
                },
            ]
        }
        result = scanner._parse_results("node:22", data)
        assert result.total_count == 1

    def test_a_non_dict_cvss_entry_does_not_raise(self):
        scanner = GrypeScanner()
        data = {
            "matches": [
                {
                    "vulnerability": {
                        "id": "CVE-1",
                        "severity": "High",
                        "cvss": ["not-a-dict"],
                    },
                    "artifact": {"name": "libz", "version": "1.0"},
                }
            ]
        }
        result = scanner._parse_results("node:22", data)
        assert result.vulnerabilities[0].cvss_score == 0.0


class _FakeProc:
    """Stand-in for an `asyncio` subprocess.

    `hangs=True` makes `communicate()` itself raise `TimeoutError`, which is
    what `asyncio.wait_for` would raise around a real one. Patching
    `asyncio.wait_for` instead left the `communicate()` coroutine created and
    never awaited, so the suite emitted a `RuntimeWarning` attributed to
    whichever unrelated test happened to be running when it was collected.
    """

    def __init__(self, stdout=b"", stderr=b"", returncode=0, hangs=False):
        self._stdout = stdout
        self._stderr = stderr
        self.returncode = returncode
        self._hangs = hangs

    async def communicate(self):
        if self._hangs:
            raise TimeoutError
        return self._stdout, self._stderr


class TestGrypeScanErrorPaths:
    @pytest.mark.asyncio
    async def test_nonzero_exit_is_error_status(self):
        scanner = GrypeScanner()
        proc = _FakeProc(stdout=b"", stderr=b"boom", returncode=1)
        with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)):
            result = await scanner.scan("nginx:latest")
        assert result.status == ScanStatus.ERROR
        assert result.is_verified is False

    @pytest.mark.asyncio
    async def test_timeout_is_timeout_status(self):
        scanner = GrypeScanner(timeout=1)
        proc = _FakeProc(hangs=True)
        with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)):
            result = await scanner.scan("nginx:latest")
        assert result.status == ScanStatus.TIMEOUT

    @pytest.mark.asyncio
    async def test_successful_scan_has_ok_status(self):
        scanner = GrypeScanner()
        proc = _FakeProc(stdout=b'{"matches": []}', returncode=0)
        with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)):
            result = await scanner.scan("nginx:latest")
        assert result.status == ScanStatus.OK


class _FakeProcRC:
    def __init__(self, stdout=b"", stderr=b"", returncode=0):
        self._stdout, self._stderr, self.returncode = stdout, stderr, returncode

    async def communicate(self):
        return self._stdout, self._stderr


class TestGrypeDatabaseRefresh:
    """Grype checks its DB on every invocation unless told not to; that
    round trip per image was the dominant cross-validation cost."""

    @pytest.mark.asyncio
    async def test_refresh_db_runs_db_update(self):
        scanner = GrypeScanner()
        mock_exec = AsyncMock(return_value=_FakeProcRC(returncode=0))
        with patch("asyncio.create_subprocess_exec", mock_exec):
            assert await scanner.refresh_db() is True

        # argv[0] is the absolute path `shutil.which` resolved, not the bare
        # name: running the bare name would leave the choice of binary to
        # $PATH, which is the PATH hijacking this tool reports on others.
        assert list(mock_exec.call_args.args) == [stub_path("grype"), "db", "update"]

    @pytest.mark.asyncio
    async def test_scans_before_refresh_use_default_env(self):
        scanner = GrypeScanner()
        mock_exec = AsyncMock(return_value=_FakeProcRC(stdout=b'{"matches": []}'))
        with patch("asyncio.create_subprocess_exec", mock_exec):
            await scanner.scan("node:22-alpine")

        assert mock_exec.call_args.kwargs["env"] is None

    @pytest.mark.asyncio
    async def test_scans_after_refresh_disable_auto_update(self):
        scanner = GrypeScanner()
        mock_exec = AsyncMock(return_value=_FakeProcRC(stdout=b'{"matches": []}'))
        with patch("asyncio.create_subprocess_exec", mock_exec):
            await scanner.refresh_db()
            await scanner.scan("node:22-alpine")

        env = mock_exec.call_args.kwargs["env"]
        assert env["GRYPE_DB_AUTO_UPDATE"] == "false"
        assert env["GRYPE_CHECK_FOR_APP_UPDATE"] == "false"

    @pytest.mark.asyncio
    async def test_failed_refresh_leaves_auto_update_on(self):
        """A failed pre-fetch must not leave scans running against a DB
        that was never updated with updates suppressed."""
        scanner = GrypeScanner()
        mock_exec = AsyncMock(return_value=_FakeProcRC(stderr=b"boom", returncode=1))
        with patch("asyncio.create_subprocess_exec", mock_exec):
            assert await scanner.refresh_db() is False
            await scanner.scan("node:22-alpine")

        assert mock_exec.call_args.kwargs["env"] is None


class TestCvssExtractionIsNullSafe:
    """Grype emits `"metrics": null` for advisories with no CVSS vector. A
    null there used to raise `AttributeError` mid-parse, turning an otherwise
    good scan of a real image into an ERROR result."""

    @pytest.mark.parametrize(
        "cvss",
        [
            pytest.param([{"source": "nvd", "metrics": None}], id="null_metrics"),
            pytest.param([{"source": "nvd", "metrics": []}], id="metrics_is_a_list"),
            pytest.param([{"source": "nvd", "metrics": {"baseScore": None}}], id="null_score"),
            pytest.param([{"source": "nvd", "metrics": {"baseScore": "n/a"}}], id="text_score"),
            pytest.param([{"source": "nvd"}], id="metrics_missing"),
        ],
    )
    def test_unscored_advisory_reads_as_zero(self, cvss):
        result = GrypeScanner()._parse_results(
            "node:22",
            {
                "matches": [
                    {
                        "vulnerability": {
                            "id": "CVE-2024-3333",
                            "severity": "High",
                            "fix": {"versions": []},
                            "cvss": cvss,
                        },
                        "artifact": {"name": "libz", "version": "1.0"},
                    }
                ]
            },
        )

        assert result.total_count == 1
        assert result.vulnerabilities[0].cvss_score == 0.0
