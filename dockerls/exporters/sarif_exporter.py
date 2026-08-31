from __future__ import annotations

import hashlib
import json
import math
from typing import TYPE_CHECKING, Any

from dockerls import __version__
from dockerls.domain.entities.vulnerability import Severity
from dockerls.exporters.base import ExporterInterface

if TYPE_CHECKING:
    from pathlib import Path

    from dockerls.application.dto.analysis import AnalysisResult, ImageAnalysis

_SEVERITY_TO_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.UNKNOWN: "note",
}

# GitHub code scanning reads `security-severity` as a number and buckets it:
# >= 9.0 critical, >= 7.0 high, >= 4.0 medium, > 0.0 low. These are the floor
# of each bucket, used only when the scanner classified a finding without
# publishing a CVSS score -- which is the *normal* case for Debian, Alpine and
# Ubuntu advisories, as `TrivyScanner._extract_cvss` documents.
#
# Emitting the literal 0.0 for those, as this exporter used to, filed every
# unscored CRITICAL in the security dashboard at the bottom of the scale. The
# severity the scanner actually assigned was thrown away on the way out.
#
# This is a translation of a category into GitHub's numeric channel, not an
# invented measurement, so the rule records which of the two it was in
# `properties.severity-source`.
_SEVERITY_FLOOR = {
    Severity.CRITICAL: 9.0,
    Severity.HIGH: 7.0,
    Severity.MEDIUM: 4.0,
    Severity.LOW: 1.0,
    Severity.UNKNOWN: 0.0,
}

# SARIF requires `reportingDescriptor.id` to be a non-empty string, and a
# scanner can report a finding with no advisory ID at all (Trivy leaves
# `VulnerabilityID` empty). Grouping those by package keeps the document
# valid and keeps unrelated unnamed findings from collapsing into one rule.
_UNIDENTIFIED_PREFIX = "DOCKERLS-UNIDENTIFIED"

# The URL published in `$schema`. The document points a consumer at the
# schema it claims to satisfy, so the URL has to resolve: the previous one
# (`.../sarif-spec/master/Schemata/...`) 404s -- the repository's default
# branch was renamed and the schema moved under `sarif-2.1/schema/`.
_SCHEMA_URL = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/"
    "sarif-2.1/schema/sarif-schema-2.1.0.json"
)

# `artifactLocation.uri` is required to be a URI reference, and a SARIF
# consumer keys findings by it. An analysis carrying no usable reference
# would otherwise render as `":"` -- `f"{name}:{tag}"` over two empty
# strings -- which is neither a URI reference nor an identifier.
_UNKNOWN_ARTIFACT = "unknown-image"

# The upper bound of the CVSS v3 base-score range. Anything outside
# `0 < score <= 10` did not come from a CVSS calculator.
_CVSS_MAX = 10.0


class SARIFExporter(ExporterInterface):
    """Exports scan findings as SARIF 2.1.0 for consumption by GitHub code
    scanning and other SARIF-aware tooling."""

    def export(self, result: AnalysisResult, output_path: Path) -> None:
        output_path.write_bytes(self.export_string(result).encode("utf-8"))

    def export_string(self, result: AnalysisResult) -> str:
        images: list[ImageAnalysis] = [*result.recommendations, *result.alternatives]
        rules: dict[str, dict[str, Any]] = {}
        sarif_results: list[dict[str, Any]] = []

        for analysis in images:
            for vuln in analysis.scan.vulnerabilities:
                rule_id = _rule_id(vuln)
                if rule_id not in rules:
                    rules[rule_id] = _rule_for(vuln, rule_id)
                sarif_results.append(
                    {
                        "ruleId": rule_id,
                        "level": _SEVERITY_TO_LEVEL.get(vuln.severity, "warning"),
                        "message": {
                            "text": (
                                f"{vuln.severity.value} vulnerability in "
                                f"{vuln.package_name} {vuln.installed_version}"
                                + (f" (fix: {vuln.fixed_version})" if vuln.fixed_version else "")
                            )
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": _artifact_uri(analysis)}
                                }
                            }
                        ],
                        # Per-result rather than per-run: a SARIF file can
                        # carry findings from several images, and a consumer
                        # gating on confidence needs to know which image an
                        # UNVERIFIED verdict belongs to. `properties` is the
                        # spec's extension point, so nothing existing moves.
                        "properties": _image_properties(analysis),
                        "partialFingerprints": {
                            "dockerlsFindingId/v1": _finding_fingerprint(vuln, analysis)
                        },
                    }
                )

        sarif = {
            "version": "2.1.0",
            "$schema": _SCHEMA_URL,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "DockerLs",
                            "informationUri": "https://github.com/Ivomsantiago/DockerLs",
                            "version": __version__,
                            "rules": list(rules.values()),
                        }
                    },
                    "results": sarif_results,
                }
            ],
        }
        # `allow_nan=False` is the assertion, `_json_safe` is what keeps it
        # from firing. Python's default is to emit the bare tokens `NaN` and
        # `Infinity`, which RFC 8259 does not allow: a single non-finite
        # score anywhere in the document makes the *whole file* unparseable
        # to a strict reader, and GitHub code scanning's ingester is one.
        # Every finding in the upload is then discarded together -- the
        # failure mode this project exists to refuse, a security report that
        # silently reports nothing.
        return json.dumps(_json_safe(sarif), indent=2, allow_nan=False, default=str)


def _json_safe(value: Any) -> Any:
    """Replace non-finite floats with `None`, recursively.

    A `NaN` score is not a measurement, so it is not published as one: the
    property is emitted as JSON `null`, which a consumer reads as "no value"
    rather than as a number that happens to compare falsely against every
    threshold.
    """
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, dict):
        return {key: _json_safe(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_json_safe(item) for item in value]
    return value


def _artifact_uri(analysis: ImageAnalysis) -> str:
    """A non-empty URI reference naming the scanned image."""
    for candidate in (analysis.image.full_reference, analysis.scan.image_reference):
        text = (candidate or "").strip().strip(":")
        if text:
            return text
    return _UNKNOWN_ARTIFACT


def _image_properties(analysis: ImageAnalysis) -> dict[str, Any]:
    """Image-level context attached to every finding from that image.

    The digest is included whenever one was resolved: a SARIF file that
    names only a tag cannot be matched back to the bytes that were scanned.
    """
    properties: dict[str, Any] = {
        "image": analysis.image.full_reference,
        "source": analysis.image.source,
        "securityScore": analysis.security_score,
        "tier": analysis.tier,
        "confidence": analysis.confidence.value,
        "productionReady": analysis.production_ready,
        "eolStatus": analysis.eol_status.value,
        "crossValidation": analysis.cross_validation,
    }
    if analysis.readiness_blockers:
        properties["readinessBlockers"] = list(analysis.readiness_blockers)
    if analysis.image.digest_known:
        properties["digest"] = analysis.image.digest
        properties["pinnedReference"] = analysis.pinned_reference
    if analysis.hardening.reportable:
        properties["hardeningScore"] = analysis.hardening.score
        properties["hardeningCoverage"] = analysis.hardening.coverage
    if analysis.attack_surface.reportable:
        properties["attackSurfaceScore"] = analysis.attack_surface.score
    return properties


def _finding_fingerprint(vuln: Any, analysis: ImageAnalysis) -> str:
    """A stable identity for this finding, so GitHub code scanning can track
    it across separate scans instead of marking it resolved-then-reopened
    on every run.

    Without a `partialFingerprints` entry, GitHub falls back to matching by
    location + rule, which shifts under this exporter's own `ruleId` when a
    finding has no CVE (`DOCKERLS-UNIDENTIFIED-<package>`) and shifts under
    the artifact URI whenever a tag is re-resolved. The tuple here --
    CVE-ID, package name, image digest -- is what actually names "the same
    vulnerability, in the same package, in the same immutable image" across
    runs; a tag or a rule-grouping detail changing must not reset it.

    SHA-256, truncated to 16 hex characters: enough entropy that two
    distinct findings colliding is not a practical concern, short enough
    that the field reads as an identifier rather than a raw digest.
    """
    identity = "|".join(
        [
            (vuln.cve_id or "").strip().upper(),
            (vuln.package_name or "").strip().lower(),
            analysis.image.digest or "",
        ]
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]


def _rule_id(vuln: Any) -> str:
    """A stable, non-empty rule identifier for a finding."""
    cve_id = (vuln.cve_id or "").strip()
    if cve_id:
        return cve_id
    package = (vuln.package_name or "").strip() or "unknown-package"
    return f"{_UNIDENTIFIED_PREFIX}-{package}"


def _security_severity(vuln: Any) -> tuple[str, str]:
    """Return (value, source) for GitHub's `security-severity` property.

    `cvss` means the number is the scanner's measured CVSS base score.
    `severity-band` means the advisory carried no score, so the floor of the
    bucket matching the severity the scanner assigned is used instead --
    otherwise an unscored CRITICAL is published to code scanning as 0.0.
    """
    try:
        score = float(vuln.cvss_score)
    except (TypeError, ValueError):
        score = 0.0
    # GitHub parses `security-severity` as a number. A score that is not a
    # finite value inside the CVSS range never came from a calculator, and
    # publishing it verbatim put the strings "inf" and "nan" in that channel
    # -- the same "unusable value spent as evidence" that `_probability`
    # refuses on the way in. The severity the scanner assigned is the better
    # answer, and `severity-source` says that is what this is.
    if math.isfinite(score) and 0.0 < score <= _CVSS_MAX:
        return str(score), "cvss"
    return str(_SEVERITY_FLOOR.get(vuln.severity, 0.0)), "severity-band"


def _rule_for(vuln: Any, rule_id: str) -> dict[str, Any]:
    severity_value, severity_source = _security_severity(vuln)
    rule: dict[str, Any] = {
        "id": rule_id,
        "shortDescription": {"text": vuln.description or rule_id},
        "properties": {
            "security-severity": severity_value,
            "severity-source": severity_source,
            "tags": ["security", vuln.severity.value],
        },
    }
    # Only link to NVD for a real advisory ID -- the bare detail URL for an
    # empty ID is a 404 pointing nowhere.
    if (vuln.cve_id or "").strip():
        rule["helpUri"] = f"https://nvd.nist.gov/vuln/detail/{vuln.cve_id.strip()}"
    return rule
