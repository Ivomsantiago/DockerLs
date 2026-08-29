"""The SARIF document is validated against the real OASIS 2.1.0 schema.

`tests/fixtures/sarif-schema-2.1.0.json` is the schema as published at
https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json
-- vendored rather than fetched so the suite stays offline and
deterministic. It is a draft-04 schema, hence `Draft4Validator`.

Schema validity is necessary and not sufficient: the schema types
`security-severity` as a free string and `artifactLocation.uri` as any
string, so a document can satisfy it and still be rejected by GitHub code
scanning. The assertions below therefore cover both -- the schema, and the
shape the consumer actually requires.
"""

from __future__ import annotations

import json
import math
import sys
from pathlib import Path

import pytest
from jsonschema import Draft4Validator

from dockerls import __version__
from dockerls.application.dto.analysis import AnalysisResult, ImageAnalysis
from dockerls.domain.entities.image import DockerImage
from dockerls.domain.entities.scan_result import ScanResult
from dockerls.domain.entities.vulnerability import Severity, Vulnerability
from dockerls.exporters.sarif_exporter import SARIFExporter

_SCHEMA_PATH = Path(__file__).resolve().parents[2] / "fixtures" / "sarif-schema-2.1.0.json"

#: The only values SARIF 2.1.0 allows in `result.level`.
_SARIF_LEVELS = {"none", "note", "warning", "error"}


@pytest.fixture(scope="module")
def validator() -> Draft4Validator:
    return Draft4Validator(json.loads(_SCHEMA_PATH.read_text(encoding="utf-8")))


def _analysis(*vulns: Vulnerability, image: DockerImage | None = None, **kwargs: object):
    img = image or DockerImage(name="node", tag="22-alpine", is_official=True)
    scan = ScanResult(image_reference=img.full_reference, vulnerabilities=list(vulns))
    return ImageAnalysis(
        image=img,
        scan=scan,
        security_score=kwargs.pop("security_score", 80.0),  # type: ignore[arg-type]
        tier="B",
        remediation_score=100,
        **kwargs,  # type: ignore[arg-type]
    )


def _result(*analyses: ImageAnalysis) -> AnalysisResult:
    return AnalysisResult(
        query="node",
        total_tags_scanned=len(analyses),
        baseline_met=False,
        alternatives=list(analyses),
    )


def _vuln(**kwargs: object) -> Vulnerability:
    payload: dict[str, object] = {
        "cve_id": "CVE-2024-0001",
        "severity": Severity.HIGH,
        "package_name": "openssl",
        "installed_version": "1.0",
        "description": "A description.",
    }
    payload.update(kwargs)
    return Vulnerability(**payload)  # type: ignore[arg-type]


def _export(result: AnalysisResult) -> tuple[str, dict]:
    text = SARIFExporter().export_string(result)
    return text, json.loads(text)


def _reject_constant(token: str) -> float:
    raise AssertionError(f"emitted the non-JSON constant {token!r}")


# --------------------------------------------------------------------------
# Schema validity
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "case",
    [
        "empty",
        "typical",
        "no-cve-id",
        "no-description",
        "digest-pinned",
        "every-severity",
        "hostile-strings",
    ],
)
def test_document_validates_against_the_official_schema(validator, case):
    if case == "empty":
        result = _result()
    elif case == "typical":
        result = _result(_analysis(_vuln(fixed_version="1.1", cvss_score=7.5)))
    elif case == "no-cve-id":
        result = _result(_analysis(_vuln(cve_id="")))
    elif case == "no-description":
        result = _result(_analysis(_vuln(description="")))
    elif case == "digest-pinned":
        image = DockerImage(name="node", tag="22-alpine", digest="sha256:" + "a" * 64)
        result = _result(_analysis(_vuln(), image=image))
    elif case == "every-severity":
        result = _result(_analysis(*(_vuln(cve_id=f"CVE-9-{s}", severity=s) for s in Severity)))
    else:
        result = _result(
            _analysis(
                _vuln(
                    cve_id="CVE-" + chr(0) + '-"}\n',
                    package_name='</script>{"a":1}\\',
                    description="null\x00  ퟿ quoted \" and ' and \\",
                    installed_version="1\n2",
                )
            )
        )

    text, doc = _export(result)
    # Strict JSON first: `NaN`/`Infinity` parse in Python but are not JSON,
    # and a schema validator never sees them because it runs on the object.
    json.loads(text, parse_constant=_reject_constant)
    errors = sorted(validator.iter_errors(doc), key=lambda e: list(e.path))
    assert errors == [], [f"{list(e.path)}: {e.message}" for e in errors]


# --------------------------------------------------------------------------
# Required fields, explicitly
# --------------------------------------------------------------------------


def test_top_level_required_fields():
    _, doc = _export(_result(_analysis(_vuln())))
    assert doc["version"] == "2.1.0"
    assert isinstance(doc["$schema"], str) and doc["$schema"].startswith("https://")
    assert isinstance(doc["runs"], list) and doc["runs"]


def test_driver_name_and_version_are_present_and_non_empty():
    _, doc = _export(_result(_analysis(_vuln())))
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "DockerLs"
    assert driver["version"] == __version__
    assert isinstance(driver["version"], str) and driver["version"].strip()


def test_every_result_carries_ruleid_message_level_and_location():
    result = _result(_analysis(*(_vuln(cve_id=f"CVE-9-{s}", severity=s) for s in Severity)))
    _, doc = _export(result)
    rule_ids = {rule["id"] for rule in doc["runs"][0]["tool"]["driver"]["rules"]}
    assert doc["runs"][0]["results"]

    for entry in doc["runs"][0]["results"]:
        assert isinstance(entry["ruleId"], str) and entry["ruleId"].strip()
        # A `ruleId` with no matching `reportingDescriptor` is a dangling
        # reference: schema-valid, and unresolvable to the consumer.
        assert entry["ruleId"] in rule_ids
        assert isinstance(entry["message"]["text"], str) and entry["message"]["text"].strip()
        assert entry["level"] in _SARIF_LEVELS

        locations = entry["locations"]
        assert isinstance(locations, list) and locations
        for location in locations:
            uri = location["physicalLocation"]["artifactLocation"]["uri"]
            assert isinstance(uri, str) and uri.strip()
            assert uri.strip(":")


def test_rule_ids_are_unique():
    result = _result(_analysis(_vuln(), _vuln(), _vuln(cve_id="", package_name="zlib")))
    _, doc = _export(result)
    ids = [rule["id"] for rule in doc["runs"][0]["tool"]["driver"]["rules"]]
    assert len(ids) == len(set(ids))


def test_a_finding_with_no_cve_id_still_gets_a_non_empty_rule_id():
    _, doc = _export(_result(_analysis(_vuln(cve_id="", package_name=""))))
    rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["id"].strip()
    assert rule["shortDescription"]["text"].strip()
    # No advisory ID means no NVD page; a bare detail URL would 404.
    assert "helpUri" not in rule


# --------------------------------------------------------------------------
# Regressions
# --------------------------------------------------------------------------


def test_a_non_finite_score_does_not_make_the_document_invalid_json():
    """Regression: a `NaN` score used to be written as the bare token `NaN`.

    That is not JSON. GitHub's ingester parses strictly, so one non-finite
    float anywhere discarded every finding in the upload at once.
    """
    for score in (math.nan, math.inf, -math.inf):
        text, doc = _export(_result(_analysis(_vuln(), security_score=score)))
        assert "NaN" not in text and "Infinity" not in text
        json.loads(text, parse_constant=_reject_constant)
        # Published as "no value", never as a number a threshold can pass.
        assert doc["runs"][0]["results"][0]["properties"]["securityScore"] is None


@pytest.mark.parametrize(
    ("cvss", "expected_source"),
    [
        (7.5, "cvss"),
        (10.0, "cvss"),
        (0.0, "severity-band"),
        (-5.0, "severity-band"),
        (99.0, "severity-band"),
        (math.nan, "severity-band"),
        (math.inf, "severity-band"),
    ],
)
def test_security_severity_is_always_a_parsable_number(cvss, expected_source):
    """Regression: an out-of-range CVSS reached GitHub as "inf" or "nan"."""
    _, doc = _export(_result(_analysis(_vuln(severity=Severity.HIGH, cvss_score=cvss))))
    properties = doc["runs"][0]["tool"]["driver"]["rules"][0]["properties"]
    value = float(properties["security-severity"])
    assert math.isfinite(value)
    assert 0.0 <= value <= 10.0
    assert properties["severity-source"] == expected_source


def test_an_image_with_no_usable_reference_does_not_emit_a_bare_colon():
    """Regression: `f"{name}:{tag}"` over two empty strings produced `":"`."""
    _, doc = _export(_result(_analysis(_vuln(), image=DockerImage(name="", tag=""))))
    location = doc["runs"][0]["results"][0]["locations"][0]
    assert location["physicalLocation"]["artifactLocation"]["uri"] == "unknown-image"


def test_the_declared_schema_url_is_the_one_that_resolves():
    """Regression: `$schema` pointed at a path that 404s.

    The OASIS repository renamed its default branch and moved the schema
    under `sarif-2.1/schema/`; the old `master/Schemata/` URL is gone, so a
    consumer dereferencing `$schema` to validate got nothing back.
    """
    _, doc = _export(_result())
    assert doc["$schema"] == (
        "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/"
        "sarif-2.1/schema/sarif-schema-2.1.0.json"
    )


def test_the_exporter_never_builds_json_by_string_concatenation():
    """A hostile description must be escaped, not interpolated."""
    source = Path(sys.modules[SARIFExporter.__module__].__file__ or "")
    assert "json.dumps" in source.read_text(encoding="utf-8")
    payload = '", "level": "none", "x": "'
    _, doc = _export(_result(_analysis(_vuln(description=payload))))
    assert doc["runs"][0]["tool"]["driver"]["rules"][0]["shortDescription"]["text"] == payload
    assert doc["runs"][0]["results"][0]["level"] == "error"
