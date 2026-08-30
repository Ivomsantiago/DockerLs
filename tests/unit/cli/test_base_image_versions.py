"""`base-image --os-version`/`--runtime-version`/`--list-versions`.

The catalog in `base_recipe.py` hardcodes one version per (runtime,
family). These flags let a caller pin a different one without touching
that file, and default to exactly the catalog's own choice when omitted.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

from typer.testing import CliRunner

from dockerls.application.services.version_discovery import VersionChoice
from dockerls.cli.app import app
from dockerls.exit_codes import EXIT_ERROR, EXIT_OK

runner = CliRunner()


def _generate(tmp_path, *extra_args):
    out = tmp_path / "Dockerfile"
    result = runner.invoke(
        app,
        [
            "base-image",
            "--os",
            "alpine",
            "--runtime",
            "node",
            "--with",
            "",
            "--no-pin",
            "-o",
            str(out),
            "--force",
            *extra_args,
        ],
    )
    return result, out


class TestRuntimeVersionOverride:
    def test_overrides_the_catalog_default(self, tmp_path):
        result, out = _generate(tmp_path, "--runtime-version", "24")

        assert result.exit_code == EXIT_OK
        assert "FROM node:24-alpine" in out.read_text()

    def test_omitting_it_keeps_the_catalog_default(self, tmp_path):
        result, out = _generate(tmp_path)

        assert result.exit_code == EXIT_OK
        assert "FROM node:22-alpine" in out.read_text()

    def test_an_unsupported_combination_is_reported_not_raised(self, tmp_path):
        out = tmp_path / "Dockerfile"
        result = runner.invoke(
            app,
            [
                "base-image",
                "--os",
                "distroless",
                "--runtime",
                "node",
                "--with",
                "",
                "--no-pin",
                "-o",
                str(out),
                "--force",
                "--runtime-version",
                "22",
            ],
        )

        assert result.exit_code == EXIT_ERROR
        assert "does not take an explicit version override" in result.stdout


class TestOsVersionOverride:
    def test_applies_only_when_runtime_is_none(self, tmp_path):
        out = tmp_path / "Dockerfile"
        result = runner.invoke(
            app,
            [
                "base-image",
                "--os",
                "alpine",
                "--runtime",
                "none",
                "--with",
                "",
                "--no-pin",
                "-o",
                str(out),
                "--force",
                "--os-version",
                "3.22",
            ],
        )

        assert result.exit_code == EXIT_OK
        assert "FROM alpine:3.22" in out.read_text()

    def test_is_ignored_when_a_runtime_is_selected(self, tmp_path):
        """`--os-version` only makes sense with `--runtime none`; passing it
        alongside a runtime must not silently corrupt the runtime's tag."""
        result, out = _generate(tmp_path, "--os-version", "3.22")

        assert result.exit_code == EXIT_OK
        assert "FROM node:22-alpine" in out.read_text()


class TestListVersions:
    def test_prints_discovered_versions_and_writes_nothing(self, tmp_path):
        out = tmp_path / "Dockerfile"
        choices = [
            VersionChoice(version="24", tag="24-alpine"),
            VersionChoice(version="22", tag="22-alpine"),
        ]
        with patch(
            "dockerls.application.services.version_discovery.discover_versions",
            AsyncMock(return_value=choices),
        ):
            result = runner.invoke(
                app,
                [
                    "base-image",
                    "--os",
                    "alpine",
                    "--runtime",
                    "node",
                    "-o",
                    str(out),
                    "--list-versions",
                ],
            )

        assert result.exit_code == EXIT_OK
        assert "24" in result.stdout
        assert "22" in result.stdout
        assert not out.exists()

    def test_an_unresolvable_registry_says_so_and_does_not_crash(self, tmp_path):
        out = tmp_path / "Dockerfile"
        with patch(
            "dockerls.application.services.version_discovery.discover_versions",
            AsyncMock(return_value=[]),
        ):
            result = runner.invoke(
                app,
                [
                    "base-image",
                    "--os",
                    "alpine",
                    "--runtime",
                    "node",
                    "-o",
                    str(out),
                    "--list-versions",
                ],
            )

        assert result.exit_code == EXIT_OK
        assert "Could not resolve versions" in result.stdout

    def test_a_combination_with_no_discovery_source_says_so(self, tmp_path):
        out = tmp_path / "Dockerfile"
        result = runner.invoke(
            app,
            [
                "base-image",
                "--os",
                "distroless",
                "--runtime",
                "node",
                "-o",
                str(out),
                "--list-versions",
            ],
        )

        assert result.exit_code == EXIT_OK
        assert "No version discovery known" in result.stdout
