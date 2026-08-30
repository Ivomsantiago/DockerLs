"""The tag being released and `project.version` in pyproject.toml, checked
against each other.

`release.yml` builds with `python -m build`, which reads the version
statically from `pyproject.toml` -- it never looks at the git tag that
triggered the workflow. Nothing stopped `v1.0.0` from being pushed while
pyproject.toml still said `3.0.0`, and the package that came out of that
build would say `dockerls-3.0.0` forever, with no way to fix it after
publish. This script is the one place that check happens, so it cannot
silently stop happening in a future edit to the workflow.

Usage:
    python scripts/check_version.py            # tag from GITHUB_REF_NAME,
                                                 # or `git describe` locally
    python scripts/check_version.py v1.0.0      # tag given explicitly
"""

from __future__ import annotations

import os
import subprocess  # nosec B404  # noqa: S404 -- argv fixo, sem shell
import sys
import tomllib
from pathlib import Path


def _pyproject_version() -> str:
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    return str(data["project"]["version"])


def _current_tag() -> str | None:
    ref_name = os.environ.get("GITHUB_REF_NAME", "").strip()
    if ref_name:
        return ref_name
    result = subprocess.run(  # nosec B603 B607 -- argv fixo, sem shell
        ["git", "describe", "--tags", "--exact-match"],  # noqa: S603, S607
        capture_output=True,
        text=True,
        check=False,
    )
    tag = result.stdout.strip()
    return tag or None


def main() -> int:
    tag = sys.argv[1] if len(sys.argv) > 1 else _current_tag()
    if not tag:
        print(
            "check_version: HEAD is not exactly on a tag, and GITHUB_REF_NAME is not "
            "set. Nothing to check.",
            file=sys.stderr,
        )
        return 1

    pkg_version = _pyproject_version()
    expected_tag = f"v{pkg_version}"
    if tag != expected_tag:
        print(
            f"check_version: tag {tag!r} does not match pyproject.toml's "
            f"project.version ({pkg_version!r}, expected tag {expected_tag!r}). "
            "Update pyproject.toml (and CHANGELOG.md) before tagging.",
            file=sys.stderr,
        )
        return 1

    print(f"check_version: {tag} matches pyproject.toml ({pkg_version}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
