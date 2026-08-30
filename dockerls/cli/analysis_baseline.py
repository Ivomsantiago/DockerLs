"""Cross-referencing a `build` run against an earlier `analyze-dockerfile`.

`analyze-dockerfile` and `build` both validate the same Dockerfile -- build
always does it as its first step -- but the two commands ran as two
separate documents, with no way to say whether what `analyze-dockerfile`
found earlier was actually fixed by the time `build` ran. This closes that
gap for whoever passes `analyze-dockerfile --output <file>` into `build
--compare-to-analysis <file>`: nothing is inferred that either command did
not already measure, this only compares the two results check by check.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from dockerls.domain.entities.dockerfile_analysis import DockerfileValidationResult


class BaselineLoadError(ValueError):
    """The file at `--compare-to-analysis` is not a usable analyze-dockerfile report."""


@dataclass(frozen=True)
class AnalysisComparison:
    """What changed, check by check, between the earlier report and now."""

    #: Checks that were FAIL or WARN in the baseline and still are now.
    still_present: tuple[str, ...] = ()
    #: Checks that were FAIL or WARN in the baseline and are PASS now.
    resolved: tuple[str, ...] = ()
    #: Checks that are FAIL or WARN now but were not flagged in the baseline.
    newly_introduced: tuple[str, ...] = ()

    @property
    def baseline_total(self) -> int:
        return len(self.still_present) + len(self.resolved)

    def model_dump(self) -> dict[str, object]:
        return {
            "still_present": list(self.still_present),
            "resolved": list(self.resolved),
            "newly_introduced": list(self.newly_introduced),
        }


def load_baseline_findings(path: str | Path) -> dict[str, str]:
    """The FAIL/WARN check names from a report `analyze-dockerfile --output`
    wrote, as `{check_name: status}`.

    Raises `BaselineLoadError` for anything that is not that document --
    missing file, invalid JSON, or JSON that is valid but is not an
    analyze-dockerfile report -- so the caller can report one clear cause
    instead of a `KeyError` three lines deep.
    """
    try:
        raw = Path(path).read_text(encoding="utf-8")
    except OSError as e:
        raise BaselineLoadError(f"could not read {path}: {e}") from e
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as e:
        raise BaselineLoadError(f"{path} is not valid JSON: {e}") from e

    validation = document.get("validation") if isinstance(document, dict) else None
    if not isinstance(validation, dict):
        raise BaselineLoadError(
            f"{path} does not look like an analyze-dockerfile report (no 'validation' key)"
        )
    checks = validation.get("checks")
    if not isinstance(checks, list):
        raise BaselineLoadError(f"{path} has no 'validation.checks' list to compare against")

    return {
        check["check"]: check["status"]
        for check in checks
        if isinstance(check, dict)
        and check.get("status") in ("FAIL", "WARN")
        and isinstance(check.get("check"), str)
    }


def compare(baseline: dict[str, str], current: DockerfileValidationResult) -> AnalysisComparison:
    """Baseline FAIL/WARN checks against the checks in `current`."""
    current_bad = {
        c.check: c.status.value for c in current.checks if c.status.value in ("FAIL", "WARN")
    }

    still_present = tuple(sorted(name for name in baseline if name in current_bad))
    resolved = tuple(sorted(name for name in baseline if name not in current_bad))
    newly_introduced = tuple(sorted(name for name in current_bad if name not in baseline))

    return AnalysisComparison(
        still_present=still_present, resolved=resolved, newly_introduced=newly_introduced
    )
