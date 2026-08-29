"""Property tests for the invariants the whole tool rests on.

Each class here corresponds to a way the tool could lie. They are written as
sweeps rather than examples because the failure mode is never the case
somebody thought of -- it is the combination nobody did. The audit that
preceded this file found four of these violated in code that had 2000
passing tests.
"""

from __future__ import annotations

import itertools

import pytest

from dockerls.application.dto.analysis import ImageAnalysis
from dockerls.application.services.verdict import apply_facts, finalize_verdict, rank
from dockerls.domain.entities.image import DockerImage
from dockerls.domain.entities.image_facts import HardeningFacts
from dockerls.domain.entities.scan_result import ScanErrorKind, ScanResult, ScanStatus
from dockerls.domain.entities.vulnerability import Severity, Vulnerability
from dockerls.domain.value_objects.confidence import Confidence
from dockerls.domain.value_objects.production_readiness import (
    BlockingReason,
    ProductionReadiness,
    ReadinessInputs,
)
from dockerls.domain.value_objects.security_score import SecurityScore
from dockerls.domain.value_objects.security_tier import Tier
from dockerls.domain.value_objects.tristate import Tristate

_ALL_STATUSES = (ScanStatus.OK, ScanStatus.ERROR, ScanStatus.TIMEOUT, ScanStatus.PARTIAL)
_ALL_TIERS = (Tier.A, Tier.B, Tier.C, Tier.D, Tier.E, Tier.F)
_ALL_CONFIDENCE = (Confidence.UNVERIFIED, Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH)


def _analysis(
    *,
    status: ScanStatus = ScanStatus.OK,
    timestamp: str = "2026-01-01T00:00:00Z",
    vulns: list[Vulnerability] | None = None,
    eol: Tristate = Tristate.FALSE,
    digest: str = "sha256:" + "a" * 64,
    tier: str = "A",
    score: float = 100.0,
) -> ImageAnalysis:
    return ImageAnalysis(
        image=DockerImage(name="node", tag="22", digest=digest),
        scan=ScanResult(
            image_reference="node:22",
            status=status,
            scan_timestamp=timestamp,
            vulnerabilities=vulns or [],
        ),
        security_score=score,
        tier=tier,
        remediation_score=100,
        eol_status=eol,
    )


def _finalized(analysis: ImageAnalysis, **kwargs) -> ImageAnalysis:
    analysis.hub_tag_verified = kwargs.pop("registry_verified", True)
    apply_facts(analysis, kwargs.pop("facts", HardeningFacts()))
    finalize_verdict(analysis, cross_validated=kwargs.pop("cross_validated", True))
    return analysis


class TestFailureIsNeverSafety:
    """A scan that did not complete may not become a security statement."""

    @pytest.mark.parametrize("status", [s for s in _ALL_STATUSES if s is not ScanStatus.OK])
    def test_no_incomplete_status_is_verified(self, status):
        scan = ScanResult(image_reference="node:22", status=status, scan_timestamp="2026-01-01")
        assert scan.is_verified is False

    def test_ok_without_a_timestamp_is_not_verified(self):
        """A result with no timestamp cannot be placed in time, so it cannot
        be evidence of anything current."""
        scan = ScanResult(image_reference="node:22", status=ScanStatus.OK, scan_timestamp="")
        assert scan.is_verified is False

    @pytest.mark.parametrize("status", [s for s in _ALL_STATUSES if s is not ScanStatus.OK])
    def test_an_incomplete_scan_is_never_production_ready(self, status):
        analysis = _finalized(_analysis(status=status))
        assert analysis.confidence is Confidence.UNVERIFIED
        assert analysis.production_ready is False
        assert BlockingReason.NOT_MEASURED.value in analysis.readiness_blockers

    @pytest.mark.parametrize(
        "kind",
        [
            ScanErrorKind.SCANNER_MISSING,
            ScanErrorKind.DB_INIT_FAILED,
            ScanErrorKind.TIMEOUT,
            ScanErrorKind.RATE_LIMITED,
            ScanErrorKind.INVALID_OUTPUT,
            ScanErrorKind.AUTH_REQUIRED,
            ScanErrorKind.NOT_FOUND,
        ],
    )
    def test_no_error_kind_produces_a_clean_verdict(self, kind):
        analysis = _analysis(status=ScanStatus.ERROR)
        analysis.scan.error_kind = kind
        _finalized(analysis)
        assert analysis.production_ready is False
        assert analysis.confidence.is_recommendable is False

    def test_an_unverified_candidate_never_outranks_a_measured_one(self):
        unverified = _finalized(_analysis(status=ScanStatus.PARTIAL, score=100.0))
        measured = _finalized(_analysis(status=ScanStatus.OK, score=1.0))
        assert rank([unverified, measured])[0] is measured


class TestUnknownIsNotFalse:
    """Absence of evidence is never spent as evidence."""

    def test_unknown_eol_does_not_claim_the_release_is_supported(self):
        analysis = _finalized(_analysis(eol=Tristate.UNKNOWN))
        assert "not end-of-life" not in analysis.why
        assert any("end-of-life status could not be determined" in c for c in analysis.trade_offs)

    def test_known_good_eol_does_claim_it(self):
        analysis = _finalized(_analysis(eol=Tristate.FALSE))
        assert "not end-of-life" in analysis.why

    def test_unknown_eol_does_not_block_production(self):
        """Unknown blocks nothing by itself -- it is not evidence of death
        either. It is reported, and it costs confidence."""
        readiness = ProductionReadiness.evaluate(
            ReadinessInputs(
                tier=Tier.A,
                confidence=Confidence.HIGH,
                scan_verified=True,
                eol=Tristate.UNKNOWN,
            )
        )
        assert readiness.is_ready is True

    def test_confirmed_eol_always_blocks_production(self):
        for tier, confidence in itertools.product(_ALL_TIERS, _ALL_CONFIDENCE):
            readiness = ProductionReadiness.evaluate(
                ReadinessInputs(
                    tier=tier, confidence=confidence, scan_verified=True, eol=Tristate.TRUE
                )
            )
            assert readiness.is_ready is False
            assert BlockingReason.END_OF_LIFE in readiness.blockers

    def test_an_unqueried_kev_status_makes_no_claim(self):
        """The strongest sentence this tool prints, withheld when the
        catalogue was never consulted."""
        vulns = [
            Vulnerability(cve_id="CVE-1", severity=Severity.HIGH, package_name="openssl"),
        ]
        analysis = _finalized(_analysis(vulns=vulns))
        assert all("known-exploited" not in reason for reason in analysis.why)
        assert any("CISA KEV" in cost for cost in analysis.trade_offs)

    def test_a_queried_kev_status_does_make_the_claim(self):
        vulns = [
            Vulnerability(
                cve_id="CVE-1",
                severity=Severity.HIGH,
                package_name="openssl",
                kev_status=Tristate.FALSE,
            ),
        ]
        analysis = _finalized(_analysis(vulns=vulns))
        assert any("no known-exploited" in reason for reason in analysis.why)

    def test_a_known_exploited_vulnerability_is_never_a_selling_point(self):
        """Exploitation observed in the wild belongs in trade_offs, never
        in why -- the regression this reproduces printed a log4j RCE under
        active exploitation (CVE-2021-44228, CISA KEV) as a `+` reason to
        pick the image."""
        vulns = [
            Vulnerability(
                cve_id="CVE-2021-44228",
                severity=Severity.CRITICAL,
                package_name="log4j-core",
                kev_status=Tristate.TRUE,
                exploit_known=True,
            ),
        ]
        analysis = _finalized(_analysis(vulns=vulns))
        assert all("known-exploited" not in reason for reason in analysis.why)
        assert any("known-exploited" in cost for cost in analysis.trade_offs)


class TestProductionReadinessPolicy:
    @pytest.mark.parametrize(
        ("tier", "confidence"), list(itertools.product(_ALL_TIERS, _ALL_CONFIDENCE))
    )
    def test_low_confidence_never_reaches_production(self, tier, confidence):
        readiness = ProductionReadiness.evaluate(
            ReadinessInputs(tier=tier, confidence=confidence, scan_verified=True)
        )
        if confidence in (Confidence.UNVERIFIED, Confidence.LOW):
            assert readiness.is_ready is False
            assert BlockingReason.LOW_CONFIDENCE in readiness.blockers

    def test_material_divergence_blocks_production(self):
        readiness = ProductionReadiness.evaluate(
            ReadinessInputs(
                tier=Tier.A,
                confidence=Confidence.HIGH,
                scan_verified=True,
                eol=Tristate.FALSE,
                has_material_divergence=True,
            )
        )
        assert readiness.is_ready is False
        assert BlockingReason.SCANNER_DIVERGENCE in readiness.blockers

    def test_an_unfixable_critical_blocks_production(self):
        readiness = ProductionReadiness.evaluate(
            ReadinessInputs(
                tier=Tier.A,
                confidence=Confidence.HIGH,
                scan_verified=True,
                critical_count=1,
                unfixable_critical_count=1,
                max_critical=5,
            )
        )
        assert readiness.is_ready is False
        assert BlockingReason.UNFIXABLE_CRITICAL in readiness.blockers

    def test_every_blocker_has_a_human_explanation(self):
        """A code nobody can read is a code nobody acts on."""
        for reason in BlockingReason:
            readiness = ProductionReadiness(inputs=_any_inputs(), blockers=[reason])
            assert readiness.reasons and readiness.reasons[0].strip()
            assert readiness.codes == [reason.value]

    def test_a_clean_measured_image_is_ready(self):
        readiness = ProductionReadiness.evaluate(
            ReadinessInputs(
                tier=Tier.A, confidence=Confidence.HIGH, scan_verified=True, eol=Tristate.FALSE
            )
        )
        assert readiness.is_ready is True
        assert readiness.reasons == []


def _any_inputs() -> ReadinessInputs:
    return ReadinessInputs(tier=Tier.A, confidence=Confidence.HIGH, scan_verified=True)


class TestHardeningNeverMasksVulnerabilities:
    @pytest.mark.parametrize("critical", [1, 2, 5, 20])
    def test_no_amount_of_hardening_offsets_a_critical(self, critical):
        """Swept rather than exampled: the guarantee is about every count."""
        vulns = [
            Vulnerability(cve_id=f"CVE-{i}", severity=Severity.CRITICAL, package_name="openssl")
            for i in range(critical)
        ]
        perfect = HardeningFacts(
            runs_as_non_root=Tristate.TRUE,
            has_shell=Tristate.FALSE,
            has_package_manager=Tristate.FALSE,
            has_debug_tools=Tristate.FALSE,
            has_setuid=Tristate.FALSE,
            has_healthcheck=Tristate.TRUE,
            package_count=5,
            entrypoint=["/app"],
            config_verified=True,
        )
        hardened = _finalized(_analysis(vulns=vulns, tier="A"), facts=perfect)
        assert hardened.hardening.score == 100.0
        assert hardened.production_ready is False
        assert BlockingReason.CRITICAL_FINDINGS.value in hardened.readiness_blockers


class TestEpssIsContinuous:
    def test_a_higher_probability_always_costs_at_least_as_much(self):
        previous = 101.0
        for probability in (0.0, 0.1, 0.3, 0.49, 0.5, 0.6, 0.8, 0.97, 1.0):
            vuln = Vulnerability(
                cve_id="CVE-1",
                severity=Severity.HIGH,
                package_name="openssl",
                epss_score=probability,
                epss_known=True,
            )
            scan = ScanResult(
                image_reference="node:22",
                status=ScanStatus.OK,
                scan_timestamp="2026-01-01T00:00:00Z",
                vulnerabilities=[vuln],
            )
            score = SecurityScore(DockerImage(name="node", tag="22"), scan).value
            assert score <= previous, f"EPSS {probability} scored higher than the step below it"
            previous = score

    def test_the_extremes_are_actually_distinguished(self):
        """The defect this replaced: 0.51 and 0.97 cost exactly the same."""

        def score_for(probability: float) -> float:
            vuln = Vulnerability(
                cve_id="CVE-1",
                severity=Severity.HIGH,
                package_name="openssl",
                epss_score=probability,
                epss_known=True,
            )
            scan = ScanResult(
                image_reference="node:22",
                status=ScanStatus.OK,
                scan_timestamp="2026-01-01T00:00:00Z",
                vulnerabilities=[vuln],
            )
            return SecurityScore(DockerImage(name="node", tag="22"), scan).value

        assert score_for(0.97) < score_for(0.51)
