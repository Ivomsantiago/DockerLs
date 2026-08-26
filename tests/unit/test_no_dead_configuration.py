"""Structural guard against the bug class that keeps recurring here.

Four separate times this codebase shipped something declared, documented,
and never reached at runtime: `authenticate()` (1.1.0), the threshold
settings, `validate_threshold`, `SecurityTier.production_ready`, and the
whole NVD client. Twice the fix itself was partial -- `export` kept the
shadowed defaults after `recommend` was fixed, and three settings were left
behind after the first pass.

Catching that by reading code has now failed repeatedly, so it is a test.
Both checks below are deliberately blunt: they answer "is this symbol
reached from anywhere in the package", not "is it reached correctly".
"""

from __future__ import annotations

import ast
import pathlib
import re

import pytest

from dockerls.cli.app import COMMANDS as APP_COMMANDS
from dockerls.infrastructure.config.settings import Settings

PACKAGE = pathlib.Path(__file__).resolve().parents[2] / "dockerls"
SOURCES = sorted(PACKAGE.rglob("*.py"))
ALL_SOURCE = "\n".join(p.read_text(encoding="utf-8") for p in SOURCES)
SETTINGS_MODULE = PACKAGE / "infrastructure" / "config" / "settings.py"
# Everything except the declarations themselves, so a field that is only
# declared reads as zero rather than as one.
SOURCE_OUTSIDE_SETTINGS = "\n".join(
    p.read_text(encoding="utf-8") for p in SOURCES if p != SETTINGS_MODULE
)


def _reads_of(name: str, haystack: str = ALL_SOURCE) -> int:
    """Count call sites and attribute accesses for `name`."""
    calls = len(re.findall(rf"\b{re.escape(name)}\s*\(", haystack))
    attrs = len(re.findall(rf"\.{re.escape(name)}\b", haystack))
    kwargs = len(re.findall(rf"\b{re.escape(name)}\s*=(?!=)", haystack))
    return calls + attrs + kwargs


# Settings fields consumed indirectly rather than by attribute access.
SETTINGS_READ_INDIRECTLY = {
    # Read by pydantic-settings itself to locate the credentials.
    "dockerhub_username",
    "dockerhub_token",
    # Consumed via the `db_path` property rather than directly.
    "cache_dir",
}


class TestEverySettingIsRead:
    """A setting that nothing reads is a documented lie.

    `DOCKERLS_MAX_TAGS=200` was in the README as the worked example while
    having no possible effect, because the CLI's `typer.Option` defaults
    shadowed `Settings` entirely.
    """

    @pytest.mark.parametrize("field", sorted(Settings.model_fields))
    def test_setting_is_consumed_somewhere(self, field):
        if field in SETTINGS_READ_INDIRECTLY:
            pytest.skip(f"{field} is consumed indirectly")

        assert _reads_of(field, SOURCE_OUTSIDE_SETTINGS) > 0, (
            f"Settings.{field} is declared and documented but never read on "
            f"the real execution path -- configuring it would do nothing"
        )

    def test_no_setting_is_only_mentioned_in_its_own_module(self):
        orphans = [
            field
            for field in Settings.model_fields
            if field not in SETTINGS_READ_INDIRECTLY and SOURCE_OUTSIDE_SETTINGS.count(field) == 0
        ]
        assert orphans == [], f"settings never referenced outside settings.py: {orphans}"


def _public_definitions() -> dict[str, list[str]]:
    """Public functions, methods and properties defined in the package."""
    found: dict[str, list[str]] = {}
    for path in SOURCES:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(
                node, ast.FunctionDef | ast.AsyncFunctionDef
            ) and not node.name.startswith("_"):
                found.setdefault(node.name, []).append(f"{path.relative_to(PACKAGE)}:{node.lineno}")
    return found


# Reached by a framework rather than by a call in our own source.
FRAMEWORK_INVOKED = {
    "main",  # console_scripts entry point
    "get_command",  # click.Group override, called by click/typer
    "list_commands",  # click.Group override, called by click/typer
    "model_post_init",  # pydantic hook
    "settings_customise_sources",  # pydantic-settings hook
    "cache_clear",  # typer subcommand
    "cache_cleanup",  # typer subcommand
    "cache_stats",  # typer subcommand
    "recommend",
    "analyze",
    "advisor",
    "alternatives",
    "compare",
    "search",
    "export",
    "login",
    "logout",
    "version",
    "doctor",
    "health",
    "sbom",
}

# Referenced from pyproject.toml's [project.scripts] rather than by an
# import inside the package.
ENTRY_POINT_MODULES = {"cli.app"}

# Os subcomandos da CLI são importados sob demanda por `cli/app.py`, que os
# nomeia numa tabela (`COMMANDS`) em vez de num `import`. Continuam
# alcançáveis -- só que por `importlib`, que uma varredura estática não vê.
LAZY_COMMAND_MODULES = {f"cli.commands.{spec.module}" for spec in APP_COMMANDS}

# Implemented against an interface and dispatched dynamically via getattr,
# so a static scan cannot see the call site.
DYNAMICALLY_DISPATCHED = {
    "tag_exists",  # getattr(repo, "tag_exists", None) in the use case
    "refresh_db",  # getattr(scanner, "refresh_db", None)
    "close",  # getattr(scanner, "close", None)
}


class TestNoUnreachablePublicCode:
    """Anything public that nothing in the package reaches is either dead
    or a call site someone forgot to add -- which is exactly how
    `authenticate()` and the NVD client shipped."""

    def test_every_public_symbol_is_reachable(self):
        definitions = _public_definitions()
        unreachable = []
        for name, locations in sorted(definitions.items()):
            if name in FRAMEWORK_INVOKED or name in DYNAMICALLY_DISPATCHED:
                continue
            if _reads_of(name) - len(locations) <= 0:
                unreachable.append(f"{name} ({locations[0]})")

        assert unreachable == [], (
            f"public symbols defined but never reached from anywhere in the package: {unreachable}"
        )

    def test_no_module_is_orphaned(self):
        """A whole module nobody imports is the NVD client all over again."""
        orphans = []
        for path in SOURCES:
            if path.name == "__init__.py":
                continue
            module = path.relative_to(PACKAGE).with_suffix("").as_posix().replace("/", ".")
            if module in ENTRY_POINT_MODULES or module in LAZY_COMMAND_MODULES:
                continue
            importers = len(re.findall(rf"\bdockerls\.{re.escape(module)}\b", ALL_SOURCE))
            # Its own module docstring/imports do not count as an importer.
            if importers == 0:
                orphans.append(module)

        assert orphans == [], f"modules under dockerls/ that nothing imports: {orphans}"
