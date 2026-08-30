"""Cross-referencing a `build` run against an earlier `analyze-dockerfile`
report -- `load_baseline_findings` and `compare` from
`dockerls.cli.analysis_baseline`.
"""

from __future__ import annotations

import json

import pytest

from dockerls.cli.analysis_baseline import BaselineLoadError, compare, load_baseline_findings
from dockerls.domain.entities.dockerfile_analysis import (
    DockerfileValidationResult,
    SeverityLevel,
    ValidationCheck,
    ValidationStatus,
)


def _report(checks: list[dict[str, str]]) -> dict:
    return {"validation": {"checks": checks}}


class TestLoadBaselineFindings:
    def test_only_fail_and_warn_checks_are_kept(self, tmp_path):
        path = tmp_path / "report.json"
        path.write_text(
            json.dumps(
                _report(
                    [
                        {"check": "no_sudo", "status": "PASS"},
                        {"check": "package_cache_clean", "status": "WARN"},
                        {"check": "non_root_user", "status": "FAIL"},
                    ]
                )
            )
        )

        findings = load_baseline_findings(path)

        assert findings == {"package_cache_clean": "WARN", "non_root_user": "FAIL"}

    def test_a_missing_file_raises_a_clear_error(self, tmp_path):
        with pytest.raises(BaselineLoadError, match="could not read"):
            load_baseline_findings(tmp_path / "nope.json")

    def test_invalid_json_raises_a_clear_error(self, tmp_path):
        path = tmp_path / "report.json"
        path.write_text("{not json")

        with pytest.raises(BaselineLoadError, match="not valid JSON"):
            load_baseline_findings(path)

    def test_a_document_that_is_not_an_analyze_report_raises(self, tmp_path):
        path = tmp_path / "report.json"
        path.write_text(json.dumps({"unrelated": True}))

        with pytest.raises(BaselineLoadError, match="does not look like"):
            load_baseline_findings(path)


def _validation(checks: list[ValidationCheck]) -> DockerfileValidationResult:
    result = DockerfileValidationResult(dockerfile_path="Dockerfile")
    for check in checks:
        result.add_check(check)
    return result


class TestCompare:
    def test_a_check_still_failing_is_still_present(self):
        baseline = {"non_root_user": "FAIL"}
        current = _validation(
            [
                ValidationCheck(
                    check="non_root_user",
                    status=ValidationStatus.FAIL,
                    message="still root",
                    severity=SeverityLevel.HIGH,
                )
            ]
        )

        result = compare(baseline, current)

        assert result.still_present == ("non_root_user",)
        assert result.resolved == ()
        assert result.baseline_total == 1

    def test_a_check_now_passing_is_resolved(self):
        baseline = {"non_root_user": "FAIL"}
        current = _validation(
            [
                ValidationCheck(
                    check="non_root_user",
                    status=ValidationStatus.PASS,
                    message="fixed",
                    severity=SeverityLevel.INFO,
                )
            ]
        )

        result = compare(baseline, current)

        assert result.resolved == ("non_root_user",)
        assert result.still_present == ()

    def test_a_check_absent_from_the_baseline_is_newly_introduced(self):
        baseline: dict[str, str] = {}
        current = _validation(
            [
                ValidationCheck(
                    check="package_versions_pinned",
                    status=ValidationStatus.WARN,
                    message="unpinned",
                    severity=SeverityLevel.MEDIUM,
                )
            ]
        )

        result = compare(baseline, current)

        assert result.newly_introduced == ("package_versions_pinned",)
        assert result.baseline_total == 0
