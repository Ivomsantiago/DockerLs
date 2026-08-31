"""`scripts/check_version.py` -- the release-time guard that stops a pushed
tag from silently diverging from `pyproject.toml`'s `project.version`.

Run as a subprocess rather than imported: the script is a standalone CLI
entry point (not part of the `dockerls` package), and exercising it the
same way the release workflow does -- as a process, reading
`GITHUB_REF_NAME` from the environment -- is what actually matters here.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tomllib
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "check_version.py"
# Read once, dynamically, instead of hard-coding "v1.0.0": a literal here
# goes stale every time pyproject.toml's version is bumped, which is exactly
# what happened -- these tests kept asserting against 1.0.0 long after the
# project moved past it.
_PYPROJECT_VERSION = tomllib.loads(
    (_SCRIPT.parent.parent / "pyproject.toml").read_text(encoding="utf-8")
)["project"]["version"]
_MATCHING_TAG = f"v{_PYPROJECT_VERSION}"


def _run(tag_arg: str | None = None, *, ref_name: str | None = None) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env.pop("GITHUB_REF_NAME", None)
    if ref_name is not None:
        env["GITHUB_REF_NAME"] = ref_name
    args = [sys.executable, str(_SCRIPT)]
    if tag_arg is not None:
        args.append(tag_arg)
    return subprocess.run(  # noqa: S603 -- argv fixo, sem shell; caminho do script é constante
        args,
        capture_output=True,
        text=True,
        env=env,
        cwd=str(_SCRIPT.parent.parent),
        check=False,
    )


class TestCheckVersionScript:
    def test_a_matching_tag_passed_explicitly_exits_zero(self):
        result = _run(_MATCHING_TAG)

        assert result.returncode == 0
        assert "matches pyproject.toml" in result.stdout

    def test_a_matching_tag_from_github_ref_name_exits_zero(self):
        result = _run(ref_name=_MATCHING_TAG)

        assert result.returncode == 0

    def test_a_mismatched_tag_exits_one_and_names_both_versions(self):
        result = _run("v3.0.0")

        assert result.returncode == 1
        assert "v3.0.0" in result.stderr
        assert _PYPROJECT_VERSION in result.stderr
        assert _MATCHING_TAG in result.stderr

    def test_a_tag_missing_the_v_prefix_is_rejected(self):
        """`1.0.0` is not `v1.0.0` -- the release workflow only ever
        triggers on `v*` tags, and a mismatch here would mean the check
        itself accepts a shape the workflow never produces."""
        result = _run("1.0.0")

        assert result.returncode == 1

    def test_no_tag_available_exits_one_without_a_traceback(self):
        result = _run()

        assert result.returncode == 1
        assert "Traceback" not in result.stderr
        assert "Nothing to check" in result.stderr
